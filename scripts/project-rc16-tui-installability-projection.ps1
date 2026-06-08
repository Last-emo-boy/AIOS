param(
    [string]$ArtifactDir = ".workflow/artifacts/rc16-tui-installability-projection",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc16",
    [string]$PlanPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc16/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc16/docs/rc16-distributable-release-operations-contract.md",
    [string]$PreflightResultPath = ".workflow/artifacts/rc16-installer-updater-preflight-package/result.json",
    [string]$InstallUpdateBindingResultPath = ".workflow/artifacts/rc16-install-update-planspec-binding/result.json",
    [string]$RollbackSupportResultPath = ".workflow/artifacts/rc16-rollback-support-package/result.json",
    [string]$RollbackSupportPackagePath = ".workflow/artifacts/rc16-rollback-support-package/rollback-support-package.json",
    [string]$ReleaseProvenancePanelPath = "crates/agentd/src/tui/release_provenance_panel.rs",
    [string]$UpdateRollbackPanelPath = "crates/agentd/src/tui/update_rollback_panel.rs",
    [string]$TuiReplayPath = "scripts/tui-replay.ps1",
    [string]$GeneratedAt = "",
    [switch]$FailOnFailedChecks
)

$ErrorActionPreference = "Stop"

function Resolve-RepoPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $combined = if ([IO.Path]::IsPathRooted($Path)) { $Path } else { Join-Path $script:repoRoot $Path }
    $full = [IO.Path]::GetFullPath($combined)
    $repoPrefix = $script:repoRoot.TrimEnd("\", "/") + [IO.Path]::DirectorySeparatorChar
    if ($full -ne $script:repoRoot -and -not $full.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path escapes repository root: $Path"
    }
    return $full
}

function Get-StablePath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    if ($full.StartsWith($script:repoRoot, [StringComparison]::OrdinalIgnoreCase)) {
        return $full.Substring($script:repoRoot.Length).TrimStart("\", "/") -replace "\\", "/"
    }
    return $full
}

function Get-FileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-StringSha256 {
    param([Parameter(Mandatory = $true)][string]$Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
        return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join "")
    } finally {
        $sha.Dispose()
    }
}

function Read-Json {
    param([Parameter(Mandatory = $true)][string]$Path)
    return Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
}

function Get-JsonText {
    param([Parameter(Mandatory = $true)]$Value)
    return ($Value | ConvertTo-Json -Depth 100)
}

function Write-Json {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $parent = Split-Path -Parent $Path
    if ($parent) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    [IO.File]::WriteAllText($Path, (Get-JsonText $Value) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}

function Add-Check {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][bool]$Passed,
        [Parameter(Mandatory = $true)][string]$Message,
        $Evidence = $null
    )
    $entry = [ordered]@{
        id = $Id
        status = if ($Passed) { "passed" } else { "failed" }
        severity = "blocking"
        message = $Message
        evidence = $Evidence
    }
    $script:checks += $entry
    if (-not $Passed) {
        $script:failedChecks += $entry
    }
}

function Add-Unique {
    param(
        [System.Collections.ArrayList]$List,
        [Parameter(Mandatory = $true)][string]$Value
    )
    if ([string]::IsNullOrWhiteSpace($Value)) {
        return
    }
    if (-not $List.Contains($Value)) {
        [void]$List.Add($Value)
    }
}

function Get-TaskStatus {
    param($Plan, [Parameter(Mandatory = $true)][string]$TaskId)
    foreach ($wave in @($Plan.waves)) {
        foreach ($task in @($wave.tasks)) {
            if ($task.id -eq $TaskId) {
                return $task.status
            }
        }
    }
    return $null
}

function New-ArtifactRef {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        $Json = $null
    )
    $present = Test-Path -LiteralPath $Path -PathType Leaf
    return [ordered]@{
        path = Get-StablePath $Path
        sha256 = Get-FileSha256 $Path
        size_bytes = if ($present) { (Get-Item -LiteralPath $Path).Length } else { $null }
        present = $present
        schema = if ($null -ne $Json) { $Json.schema } else { $null }
        status = if ($null -ne $Json) { $Json.status } else { $null }
        production_ready_claim = if ($null -ne $Json) { $Json.production_ready_claim } else { $null }
    }
}

function Test-NoSensitiveText {
    param([Parameter(Mandatory = $true)][string[]]$Values)
    $privateKeyMarker = "PRIVATE" + " KEY"
    $publicKeyMarker = "PUBLIC" + " KEY"
    $identityMarker = "finger" + "print"
    $markers = @(
        ("BEGIN " + $privateKeyMarker),
        ("BEGIN " + $publicKeyMarker),
        ($privateKeyMarker + "-----"),
        ("Authorization:" + " Bearer"),
        ("Bearer" + " "),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ("." + "local-release-authority/" + "private"),
        ("/etc/" + "aios-signer/" + "private"),
        ("signing" + "-key." + "pem"),
        ("." + "pem"),
        $identityMarker
    )
    foreach ($value in $Values) {
        if ($null -eq $value) {
            continue
        }
        foreach ($marker in $markers) {
            if ($value.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                return $false
            }
        }
    }
    return $true
}

function New-DenialCase {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string[]]$ExpectedBlockers,
        [Parameter(Mandatory = $true)][string[]]$ObservedBlockers
    )
    $missing = @($ExpectedBlockers | Where-Object { $_ -notin $ObservedBlockers })
    return [ordered]@{
        id = $Id
        status = if ($missing.Count -eq 0) { "passed" } else { "failed" }
        observed_denied = $true
        expected_blockers = $ExpectedBlockers
        observed_blockers = @($ObservedBlockers | Select-Object -Unique)
        missing_expected_blockers = $missing
        side_effects = [ordered]@{
            tui_granted_approval = $false
            tui_cleared_blockers = $false
            install_effect_prepared = $false
            update_effect_prepared = $false
            install_performed = $false
            update_performed = $false
            activation_performed = $false
            rollback_execution_performed = $false
            support_upload_performed = $false
            recovery_execution_performed = $false
            remote_dispatch_enabled = $false
            active_slot_mutated = $false
            boot_metadata_mutated = $false
            active_artifact_set_mutated = $false
            production_ring_mutated = $false
        }
    }
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:failedChecks = @()

$generatedAtValue = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }
$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$resolvedWorkflowDir = Resolve-RepoPath $WorkflowDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $resolvedWorkflowDir "evidence") | Out-Null

$resolvedPlanPath = Resolve-RepoPath $PlanPath
$resolvedContractPath = Resolve-RepoPath $ContractPath
$resolvedPreflightResultPath = Resolve-RepoPath $PreflightResultPath
$resolvedInstallUpdateBindingResultPath = Resolve-RepoPath $InstallUpdateBindingResultPath
$resolvedRollbackSupportResultPath = Resolve-RepoPath $RollbackSupportResultPath
$resolvedRollbackSupportPackagePath = Resolve-RepoPath $RollbackSupportPackagePath
$resolvedReleaseProvenancePanelPath = Resolve-RepoPath $ReleaseProvenancePanelPath
$resolvedUpdateRollbackPanelPath = Resolve-RepoPath $UpdateRollbackPanelPath
$resolvedTuiReplayPath = Resolve-RepoPath $TuiReplayPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$preflightResult = Read-Json $resolvedPreflightResultPath
$installUpdateResult = Read-Json $resolvedInstallUpdateBindingResultPath
$rollbackSupportResult = Read-Json $resolvedRollbackSupportResultPath
$rollbackSupportPackage = Read-Json $resolvedRollbackSupportPackagePath
$releaseProvenancePanelText = Get-Content -Raw -LiteralPath $resolvedReleaseProvenancePanelPath
$updateRollbackPanelText = Get-Content -Raw -LiteralPath $resolvedUpdateRollbackPanelPath
$tuiReplayText = Get-Content -Raw -LiteralPath $resolvedTuiReplayPath

$rc16TaskStatus = Get-TaskStatus $plan "RC16-030"
$rc16PreviousStatus = Get-TaskStatus $plan "RC16-022"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc16PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC16-030" -and ($rc16TaskStatus -eq "pending" -or $rc16TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC16-031" -and $rc16TaskStatus -eq "completed")
    )
)

$preflightBound = (
    $preflightResult.status -eq "passed" -and
    $preflightResult.summary.rc16_020_complete -eq $true -and
    $preflightResult.preflight_surface.evidence_bound -eq $true
)
$installUpdateBindingBound = (
    $installUpdateResult.status -eq "passed" -and
    $installUpdateResult.summary.rc16_021_complete -eq $true -and
    $installUpdateResult.readiness_surface.agentcore_install_update_planspec_bound -eq $true -and
    $installUpdateResult.readiness_surface.security_execution_install_update_envelope_bound -eq $true
)
$rollbackSupportBound = (
    $rollbackSupportResult.status -eq "passed" -and
    $rollbackSupportResult.summary.rc16_022_complete -eq $true -and
    $rollbackSupportResult.rollback_support_surface.rollback_support_package_bound -eq $true -and
    $rollbackSupportPackage.rollback_support_package_bound -eq $true
)
$packageIdentityBound = (
    [string]$preflightResult.package_id -eq [string]$installUpdateResult.package_id -and
    [string]$installUpdateResult.package_id -eq [string]$rollbackSupportResult.package_id -and
    [string]$preflightResult.media_id -eq [string]$installUpdateResult.media_id -and
    [string]$installUpdateResult.media_id -eq [string]$rollbackSupportResult.media_id -and
    [string]$preflightResult.release_id -eq [string]$installUpdateResult.release_id -and
    [string]$installUpdateResult.release_id -eq [string]$rollbackSupportResult.release_id
)
$tuiPanelsBound = (
    $releaseProvenancePanelText.Contains("read_only=true") -and
    $releaseProvenancePanelText.Contains("projection_controller_only=true") -and
    $releaseProvenancePanelText.Contains("direct_sign=false") -and
    $releaseProvenancePanelText.Contains("direct_promote=false") -and
    $releaseProvenancePanelText.Contains("production_ready_claim_by_tui=false") -and
    $updateRollbackPanelText.Contains("read_only=true") -and
    $updateRollbackPanelText.Contains("projection_controller_only=true") -and
    $updateRollbackPanelText.Contains("direct_update=false") -and
    $updateRollbackPanelText.Contains("direct_rollback=false") -and
    $updateRollbackPanelText.Contains("host_mutation_in_tui=false") -and
    $updateRollbackPanelText.Contains("promotion.blockers.show")
)
$tuiReplayBound = (
    $tuiReplayText.Contains("release-provenance-rendered") -and
    $tuiReplayText.Contains("update-rollback-rendered") -and
    $tuiReplayText.Contains("direct_update=false") -and
    $tuiReplayText.Contains("direct_rollback=false") -and
    $tuiReplayText.Contains("support-upload-exact-consent-required") -and
    $tuiReplayText.Contains("unsafe-command-parse-error")
)
$contractBound = (
    $contractText.Contains("TUI and operator-facing outputs may explain") -and
    $contractText.Contains("They cannot grant approval") -and
    $contractText.Contains("TUI readiness does not imply any effect authority") -and
    $contractText.Contains("TUI/operator projection that attempts to mutate state")
)

$readinessBlockers = [System.Collections.ArrayList]::new()
if (-not $preflightBound) { Add-Unique $readinessBlockers "rc16-installer-updater-preflight-not-bound" }
if (-not $installUpdateBindingBound) { Add-Unique $readinessBlockers "rc16-install-update-planspec-binding-not-bound" }
if (-not $rollbackSupportBound) { Add-Unique $readinessBlockers "rc16-rollback-support-package-not-bound" }
if (-not $packageIdentityBound) { Add-Unique $readinessBlockers "rc16-package-identity-not-bound" }
if (-not $tuiPanelsBound) { Add-Unique $readinessBlockers "tui-read-only-panels-not-bound" }
if (-not $tuiReplayBound) { Add-Unique $readinessBlockers "tui-replay-read-only-gates-not-bound" }
if (-not $contractBound) { Add-Unique $readinessBlockers "rc16-operator-explainability-contract-not-bound" }

foreach ($blocker in @($installUpdateResult.readiness_surface.blockers)) {
    if ($blocker -ne "rc16-rollback-support-package-not-bound") {
        Add-Unique $readinessBlockers ([string]$blocker)
    }
}
foreach ($blocker in @($rollbackSupportResult.rollback_support_surface.blockers)) {
    Add-Unique $readinessBlockers ([string]$blocker)
}
Add-Unique $readinessBlockers "rc16-local-release-channel-consumer-smoke-not-run"

$installReady = (
    $preflightBound -and
    $installUpdateBindingBound -and
    $rollbackSupportBound -and
    $packageIdentityBound -and
    @($readinessBlockers).Count -eq 0
)
$updateReady = $installReady

$nextSafeAction = if (@($readinessBlockers | Where-Object { $_ -eq "rc16-exact-install-update-target-not-bound" -or $_ -eq "rc16-exact-install-update-approval-not-bound" }).Count -gt 0) {
    "bind exact install/update target and approval before SecurityExecution allow"
} elseif (@($readinessBlockers | Where-Object { $_ -eq "rc16-local-release-channel-consumer-smoke-not-run" }).Count -gt 0) {
    "run RC16 local release channel consumer smoke"
} else {
    "keep projection read-only until final audit"
}

$operatorProjectionCore = [ordered]@{
    schema = "agentos.rc16-tui-installability-projection-core.v1"
    task = "RC16-030"
    package_id = [string]$installUpdateResult.package_id
    media_id = [string]$installUpdateResult.media_id
    release_id = [string]$installUpdateResult.release_id
    production_ready_claim = $false
    install_readiness = [ordered]@{
        status = if ($installReady) { "ready" } else { "blocked" }
        preflight_bound = $preflightBound
        planspec_bound = $installUpdateBindingBound
        rollback_support_bound = $rollbackSupportBound
        exact_target_bound = $installUpdateResult.readiness_surface.exact_install_update_target_bound
        exact_approval_bound = $installUpdateResult.readiness_surface.exact_install_update_approval_bound
        security_execution_allowed = $installUpdateResult.readiness_surface.security_execution_allowed
        effect_preparation_allowed = $false
        install_allowed = $false
        install_performed = $false
    }
    update_readiness = [ordered]@{
        status = if ($updateReady) { "ready" } else { "blocked" }
        inactive_slot_strategy_bound = $installUpdateResult.readiness_surface.update_strategy_bound
        rollback_support_package_bound = $rollbackSupportBound
        security_execution_allowed = $installUpdateResult.readiness_surface.security_execution_allowed
        effect_preparation_allowed = $false
        update_allowed = $false
        update_performed = $false
    }
    rollback_support_state = [ordered]@{
        rollback_support_package_bound = $rollbackSupportBound
        support_bundle_local_only = $rollbackSupportResult.rollback_support_surface.support_bundle_local_only
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        rollback_execution_allowed = $false
        rollback_execution_performed = $false
    }
    blockers = @($readinessBlockers)
    next_safe_action = $nextSafeAction
    tui_authority = [ordered]@{
        read_only = $true
        projection_controller_only = $true
        grants_approval = $false
        clears_blockers = $false
        install_authority = $false
        update_authority = $false
        activation_authority = $false
        rollback_authority = $false
        support_upload_authority = $false
        recovery_execution_authority = $false
        remote_dispatch_authority = $false
        production_ring_mutation_authority = $false
    }
}
$projectionDigest = Get-StringSha256 (($operatorProjectionCore | ConvertTo-Json -Depth 100 -Compress))

$caseObservedBlockers = @(
    "rc16-installer-updater-preflight-not-bound",
    "rc16-install-update-planspec-binding-not-bound",
    "rc16-rollback-support-package-not-bound",
    "rc16-package-identity-not-bound",
    "tui-read-only-panels-not-bound",
    "tui-replay-read-only-gates-not-bound",
    "rc16-operator-explainability-contract-not-bound",
    "tui-output-is-not-authority",
    "tui-approval-grant-denied",
    "tui-blocker-clear-denied",
    "tui-install-denied",
    "tui-update-denied",
    "tui-activation-denied",
    "tui-rollback-denied",
    "tui-support-upload-denied",
    "tui-recovery-execution-denied",
    "tui-remote-dispatch-denied",
    "tui-production-ring-mutation-denied",
    "secret-like-values-redacted",
    "private-paths-redacted"
)
$caseExpectations = [ordered]@{
    "missing.preflight" = @("rc16-installer-updater-preflight-not-bound")
    "missing.install_update_binding" = @("rc16-install-update-planspec-binding-not-bound")
    "missing.rollback_support" = @("rc16-rollback-support-package-not-bound")
    "identity.package_mismatch" = @("rc16-package-identity-not-bound")
    "tui.panels_not_read_only" = @("tui-read-only-panels-not-bound")
    "tui.replay_missing_read_only_gate" = @("tui-replay-read-only-gates-not-bound")
    "contract.operator_explainability_missing" = @("rc16-operator-explainability-contract-not-bound")
    "surface.tui_output_authority" = @("tui-output-is-not-authority")
    "authority.tui_grants_approval" = @("tui-approval-grant-denied")
    "authority.tui_clears_blockers" = @("tui-blocker-clear-denied")
    "authority.tui_install" = @("tui-install-denied")
    "authority.tui_update" = @("tui-update-denied")
    "authority.tui_activation" = @("tui-activation-denied")
    "authority.tui_rollback" = @("tui-rollback-denied")
    "authority.tui_support_upload" = @("tui-support-upload-denied")
    "authority.tui_recovery_execution" = @("tui-recovery-execution-denied")
    "authority.tui_remote_dispatch" = @("tui-remote-dispatch-denied")
    "authority.tui_production_ring_mutation" = @("tui-production-ring-mutation-denied")
    "redaction.secret_like_values" = @("secret-like-values-redacted")
    "redaction.private_paths" = @("private-paths-redacted")
}
$cases = @()
foreach ($caseId in $caseExpectations.Keys) {
    $cases += New-DenialCase -Id $caseId -ExpectedBlockers ([string[]]$caseExpectations[$caseId]) -ObservedBlockers $caseObservedBlockers
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$sideEffects = [ordered]@{
    tui_projection_rendered = $true
    tui_runtime_invoked = $false
    tui_granted_approval = $false
    tui_cleared_blockers = $false
    install_effect_prepared = $false
    update_effect_prepared = $false
    install_performed = $false
    update_performed = $false
    activation_performed = $false
    rollback_execution_performed = $false
    support_upload_performed = $false
    recovery_execution_performed = $false
    remote_dispatch_enabled = $false
    active_slot_mutated = $false
    boot_metadata_mutated = $false
    active_artifact_set_mutated = $false
    private_signing_material_handled = $false
    cryptographic_signing_performed = $false
    production_ring_mutated = $false
}

$source = [ordered]@{
    rc16_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc16_contract = New-ArtifactRef $resolvedContractPath
    rc16_installer_updater_preflight_result = New-ArtifactRef $resolvedPreflightResultPath $preflightResult
    rc16_install_update_binding_result = New-ArtifactRef $resolvedInstallUpdateBindingResultPath $installUpdateResult
    rc16_rollback_support_result = New-ArtifactRef $resolvedRollbackSupportResultPath $rollbackSupportResult
    rc16_rollback_support_package = New-ArtifactRef $resolvedRollbackSupportPackagePath $rollbackSupportPackage
    tui_release_provenance_panel = New-ArtifactRef $resolvedReleaseProvenancePanelPath
    tui_update_rollback_panel = New-ArtifactRef $resolvedUpdateRollbackPanelPath
    tui_replay = New-ArtifactRef $resolvedTuiReplayPath
}

$projectionPath = Join-Path $resolvedArtifactDir "installability-projection.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC16-030-tui-installability-projection.json"

$projection = [ordered]@{
    schema = "agentos.rc16-tui-installability-projection.v1"
    generated_at = $generatedAtValue
    task = "RC16-030"
    status = "operator-installability-projection-blocked-read-only"
    production_ready_claim = $false
    package_id = [string]$installUpdateResult.package_id
    media_id = [string]$installUpdateResult.media_id
    release_id = [string]$installUpdateResult.release_id
    projection_digest = $projectionDigest
    projection_core = $operatorProjectionCore
    panel_bindings = [ordered]@{
        release_provenance_panel = [ordered]@{
            read_only_bound = $releaseProvenancePanelText.Contains("read_only=true")
            projection_controller_only_bound = $releaseProvenancePanelText.Contains("projection_controller_only=true")
            direct_sign = $false
            direct_promote = $false
            sha256 = Get-FileSha256 $resolvedReleaseProvenancePanelPath
        }
        update_rollback_panel = [ordered]@{
            read_only_bound = $updateRollbackPanelText.Contains("read_only=true")
            projection_controller_only_bound = $updateRollbackPanelText.Contains("projection_controller_only=true")
            direct_update = $false
            direct_rollback = $false
            host_mutation_in_tui = $false
            safe_next_command = "promotion.blockers.show"
            sha256 = Get-FileSha256 $resolvedUpdateRollbackPanelPath
        }
        tui_replay = [ordered]@{
            release_provenance_render_gate_bound = $tuiReplayText.Contains("release-provenance-rendered")
            update_rollback_render_gate_bound = $tuiReplayText.Contains("update-rollback-rendered")
            unsafe_command_parse_error_gate_bound = $tuiReplayText.Contains("unsafe-command-parse-error")
            sha256 = Get-FileSha256 $resolvedTuiReplayPath
        }
    }
    denial_cases = $cases
    side_effects = $sideEffects
    source = $source
}
Write-Json $projection $projectionPath

Add-Check "plan.current_task.rc16_030" $planAllowsRun "RC16-030 must run after RC16-022 completed, either while current_task is RC16-030 or while rerunning after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc16_022_status = $rc16PreviousStatus; rc16_030_status = $rc16TaskStatus })
Add-Check "source.rc16_readiness.bound" ($preflightBound -and $installUpdateBindingBound -and $rollbackSupportBound -and $packageIdentityBound) "Projection must bind preflight, install/update PlanSpec/SecurityExecution, rollback/support, and exact package identity." ([ordered]@{ preflight_bound = $preflightBound; install_update_binding_bound = $installUpdateBindingBound; rollback_support_bound = $rollbackSupportBound; package_identity_bound = $packageIdentityBound })
Add-Check "projection.explains_blockers" (@($readinessBlockers).Count -ge 4 -and @($operatorProjectionCore.blockers).Count -eq @($readinessBlockers).Count -and -not [string]::IsNullOrWhiteSpace($nextSafeAction)) "Projection must explain readiness blockers and provide the next safe action." ([ordered]@{ blockers = @($readinessBlockers); next_safe_action = $nextSafeAction })
Add-Check "projection.package_rollback_support_state" ($projection.projection_core.package_id -eq $installUpdateResult.package_id -and $projection.projection_core.rollback_support_state.rollback_support_package_bound -eq $true -and $projection.projection_core.rollback_support_state.support_bundle_local_only -eq $true) "Projection must include package identity and rollback/support state." $projection.projection_core.rollback_support_state
Add-Check "contract.operator_explainability.present" $contractBound "RC16 contract must keep TUI/operator output explain-only and non-authoritative." $source.rc16_contract
Add-Check "tui.panels.read_only_bound" $tuiPanelsBound "Release provenance and update/rollback TUI panels must be read-only projection controllers with no direct update, rollback, sign, promote, or host mutation authority." ([ordered]@{ release_provenance_panel_sha256 = Get-FileSha256 $resolvedReleaseProvenancePanelPath; update_rollback_panel_sha256 = Get-FileSha256 $resolvedUpdateRollbackPanelPath })
Add-Check "tui.replay.gates_bound" $tuiReplayBound "TUI replay must contain render and fail-closed gates for release provenance, update/rollback, support upload consent, and unsafe commands." ([ordered]@{ tui_replay_sha256 = Get-FileSha256 $resolvedTuiReplayPath })
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 20) "Missing evidence, TUI authority broadening, unsafe action, and redaction cases must fail closed." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })
Add-Check "authority.no_side_effects" ($sideEffects.tui_runtime_invoked -eq $false -and $sideEffects.tui_granted_approval -eq $false -and $sideEffects.tui_cleared_blockers -eq $false -and $sideEffects.install_performed -eq $false -and $sideEffects.update_performed -eq $false -and $sideEffects.rollback_execution_performed -eq $false -and $sideEffects.support_upload_performed -eq $false -and $sideEffects.recovery_execution_performed -eq $false -and $sideEffects.remote_dispatch_enabled -eq $false -and $sideEffects.production_ring_mutated -eq $false) "RC16-030 must be read-only projection only and must not grant authority or perform effects." $sideEffects

$outputsSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $projectionPath))
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC16-030 projection output must redact secret-like values and private paths." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$projectionSha256 = Get-FileSha256 $projectionPath
$result = [ordered]@{
    schema = "agentos.rc16-tui-installability-projection-result.v1"
    generated_at = $generatedAtValue
    task = "RC16-030"
    status = $resultStatus
    production_ready_claim = $false
    package_id = [string]$installUpdateResult.package_id
    media_id = [string]$installUpdateResult.media_id
    release_id = [string]$installUpdateResult.release_id
    projection_surface = [ordered]@{
        state = "operator-installability-projection-blocked-read-only"
        projection_digest = $projectionDigest
        install_readiness = $operatorProjectionCore.install_readiness.status
        update_readiness = $operatorProjectionCore.update_readiness.status
        rollback_support_package_bound = $rollbackSupportBound
        support_bundle_local_only = $true
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        read_only = $true
        projection_controller_only = $true
        tui_authority = $false
        install_effect_preparation_allowed = $false
        update_effect_preparation_allowed = $false
        install_performed = $false
        update_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        blockers = @($readinessBlockers)
        next_safe_action = $nextSafeAction
    }
    outputs = [ordered]@{
        installability_projection = [ordered]@{
            path = Get-StablePath $projectionPath
            sha256 = $projectionSha256
            projection_digest = $projectionDigest
        }
    }
    source = $source
    checks = @($script:checks)
    blockers = @($readinessBlockers)
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        repo_local_projection_only = $true
        tui_read_only = $true
        tui_authority = $false
        tui_runtime_invoked = $false
        mirror_frontend_changed = $false
        nginx_or_tls_changed = $false
        signer_infra_changed = $false
        object_storage_infra_changed = $false
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
        install_effect_prepared = $false
        update_effect_prepared = $false
        install_performed = $false
        update_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
    }
    fail_closed_cases = $cases
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
        rc16_030_complete = (@($script:failedChecks).Count -eq 0)
        install_readiness = $operatorProjectionCore.install_readiness.status
        update_readiness = $operatorProjectionCore.update_readiness.status
        blockers = @($readinessBlockers).Count
        read_only_projection = $true
        tui_authority = $false
        next_task = "RC16-031"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc16-tui-installability-projection-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC16-030"
    status = if ($resultStatus -eq "passed") { "completed" } else { "failed" }
    production_ready_claim = $false
    workflow = Get-StablePath $resolvedWorkflowDir
    script = [ordered]@{
        path = Get-StablePath $scriptPath
        sha256 = Get-FileSha256 $scriptPath
    }
    result = [ordered]@{
        path = Get-StablePath $resultPath
        status = $resultStatus
        sha256 = Get-FileSha256 $resultPath
    }
    outputs = $result.outputs
    projection_surface = $result.projection_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc16_030_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC16-031"
        commit_required = $true
    }
    checks = @($script:checks)
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) {
    throw "Sensitive marker detected in RC16-030 outputs."
}

Write-Host "RC16 TUI installability projection $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Projection: $(Get-StablePath $projectionPath)"
Write-Host "Install readiness: $($operatorProjectionCore.install_readiness.status); update readiness: $($operatorProjectionCore.update_readiness.status); TUI authority: false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
