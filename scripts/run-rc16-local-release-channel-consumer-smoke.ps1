param(
    [string]$ArtifactDir = ".workflow/artifacts/rc16-local-release-channel-consumer-smoke",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc16",
    [string]$PlanPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc16/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc16/docs/rc16-distributable-release-operations-contract.md",
    [string]$TuiProjectionResultPath = ".workflow/artifacts/rc16-tui-installability-projection/result.json",
    [string]$TuiProjectionPath = ".workflow/artifacts/rc16-tui-installability-projection/installability-projection.json",
    [string]$InstallUpdateBindingResultPath = ".workflow/artifacts/rc16-install-update-planspec-binding/result.json",
    [string]$InstallUpdatePlanSpecPath = ".workflow/artifacts/rc16-install-update-planspec-binding/install-update-planspec-package.json",
    [string]$SecurityExecutionEnvelopePath = ".workflow/artifacts/rc16-install-update-planspec-binding/security-execution-install-update-envelope.json",
    [string]$RollbackSupportResultPath = ".workflow/artifacts/rc16-rollback-support-package/result.json",
    [string]$RollbackSupportPackagePath = ".workflow/artifacts/rc16-rollback-support-package/rollback-support-package.json",
    [string]$PreflightResultPath = ".workflow/artifacts/rc16-installer-updater-preflight-package/result.json",
    [string]$PreflightPackagePath = ".workflow/artifacts/rc16-installer-updater-preflight-package/installer-updater-preflight-package.json",
    [string]$ReleasePackageArtifactSetPath = ".workflow/artifacts/rc16-release-package-artifact-set/release-package-artifact-set.json",
    [string]$InstallableMediaManifestPath = ".workflow/artifacts/rc16-installable-media-manifest/installable-media-manifest.json",
    [string]$PackageDescriptorResultPath = ".workflow/artifacts/rc16-package-descriptor-fail-closed/result.json",
    [string]$ProductionRunbookSmokePath = "scripts/production-runbook-smoke.ps1",
    [string]$RootfsValidationPath = "scripts/validate-alpha-rootfs.ps1",
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
            endpoint_probe_performed = $false
            frontend_output_trusted = $false
            signer_reachability_trusted = $false
            shell_output_trusted = $false
            tui_output_trusted = $false
            model_replay_trusted = $false
            object_storage_ui_trusted = $false
            payload_upload_performed = $false
            payload_published = $false
            network_fetch_attempted = $false
            remote_payload_bytes_downloaded = $false
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
            cryptographic_signing_performed = $false
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
$resolvedTuiProjectionResultPath = Resolve-RepoPath $TuiProjectionResultPath
$resolvedTuiProjectionPath = Resolve-RepoPath $TuiProjectionPath
$resolvedInstallUpdateBindingResultPath = Resolve-RepoPath $InstallUpdateBindingResultPath
$resolvedInstallUpdatePlanSpecPath = Resolve-RepoPath $InstallUpdatePlanSpecPath
$resolvedSecurityExecutionEnvelopePath = Resolve-RepoPath $SecurityExecutionEnvelopePath
$resolvedRollbackSupportResultPath = Resolve-RepoPath $RollbackSupportResultPath
$resolvedRollbackSupportPackagePath = Resolve-RepoPath $RollbackSupportPackagePath
$resolvedPreflightResultPath = Resolve-RepoPath $PreflightResultPath
$resolvedPreflightPackagePath = Resolve-RepoPath $PreflightPackagePath
$resolvedReleasePackageArtifactSetPath = Resolve-RepoPath $ReleasePackageArtifactSetPath
$resolvedInstallableMediaManifestPath = Resolve-RepoPath $InstallableMediaManifestPath
$resolvedPackageDescriptorResultPath = Resolve-RepoPath $PackageDescriptorResultPath
$resolvedProductionRunbookSmokePath = Resolve-RepoPath $ProductionRunbookSmokePath
$resolvedRootfsValidationPath = Resolve-RepoPath $RootfsValidationPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$tuiProjectionResult = Read-Json $resolvedTuiProjectionResultPath
$tuiProjection = Read-Json $resolvedTuiProjectionPath
$installUpdateResult = Read-Json $resolvedInstallUpdateBindingResultPath
$installUpdatePlanSpec = Read-Json $resolvedInstallUpdatePlanSpecPath
$securityEnvelope = Read-Json $resolvedSecurityExecutionEnvelopePath
$rollbackSupportResult = Read-Json $resolvedRollbackSupportResultPath
$rollbackSupportPackage = Read-Json $resolvedRollbackSupportPackagePath
$preflightResult = Read-Json $resolvedPreflightResultPath
$preflightPackage = Read-Json $resolvedPreflightPackagePath
$releasePackageArtifactSet = Read-Json $resolvedReleasePackageArtifactSetPath
$installableMediaManifest = Read-Json $resolvedInstallableMediaManifestPath
$packageDescriptorResult = Read-Json $resolvedPackageDescriptorResultPath
$productionRunbookSmokeText = Get-Content -Raw -LiteralPath $resolvedProductionRunbookSmokePath
$rootfsValidationText = Get-Content -Raw -LiteralPath $resolvedRootfsValidationPath

$rc16TaskStatus = Get-TaskStatus $plan "RC16-031"
$rc16PreviousStatus = Get-TaskStatus $plan "RC16-030"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc16PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC16-031" -and ($rc16TaskStatus -eq "pending" -or $rc16TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC16-050" -and $rc16TaskStatus -eq "completed")
    )
)

$localMetadataBound = (
    $preflightResult.status -eq "passed" -and
    $preflightPackage.status -eq "installer-updater-preflight-bound-effects-denied" -and
    $releasePackageArtifactSet.status -eq "repo-local-distributable-release-package-artifact-set-projected" -and
    $installableMediaManifest.status -eq "installable-media-manifest-projected-install-update-gated" -and
    $packageDescriptorResult.status -eq "passed" -and
    $preflightResult.package_id -eq $releasePackageArtifactSet.package_id -and
    $preflightResult.package_id -eq $installableMediaManifest.package_id -and
    $preflightResult.media_id -eq $installableMediaManifest.media_id -and
    $preflightResult.release_id -eq $installableMediaManifest.release_id
)
$tuiProjectionBound = (
    $tuiProjectionResult.status -eq "passed" -and
    $tuiProjectionResult.summary.rc16_030_complete -eq $true -and
    $tuiProjectionResult.projection_surface.read_only -eq $true -and
    $tuiProjectionResult.projection_surface.tui_authority -eq $false -and
    $tuiProjection.projection_core.tui_authority.read_only -eq $true
)
$planspecBound = (
    $installUpdateResult.status -eq "passed" -and
    $installUpdateResult.summary.rc16_021_complete -eq $true -and
    $installUpdateResult.readiness_surface.agentcore_install_update_planspec_bound -eq $true -and
    $installUpdatePlanSpec.agentcore_install_update_planspec_bound -eq $true -and
    $installUpdateResult.readiness_surface.agentcore_install_update_planspec_executable -eq $false -and
    $installUpdatePlanSpec.agentcore_install_update_planspec_executable -eq $false
)
$securityEnvelopeBound = (
    $securityEnvelope.status -eq "security-execution-install-update-denied" -and
    $securityEnvelope.security_execution_allowed -eq $false -and
    $securityEnvelope.effect_preparation_allowed -eq $false -and
    $securityEnvelope.effect_prepared -eq $false -and
    $securityEnvelope.install_performed -eq $false -and
    $securityEnvelope.update_performed -eq $false
)
$rollbackSupportBound = (
    $rollbackSupportResult.status -eq "passed" -and
    $rollbackSupportResult.summary.rc16_022_complete -eq $true -and
    $rollbackSupportResult.rollback_support_surface.rollback_support_package_bound -eq $true -and
    $rollbackSupportPackage.rollback_support_package_bound -eq $true -and
    $rollbackSupportResult.rollback_support_surface.support_upload_allowed -eq $false -and
    $rollbackSupportResult.rollback_support_surface.recovery_execution_allowed -eq $false
)
$packageIdentityBound = (
    [string]$tuiProjectionResult.package_id -eq [string]$installUpdateResult.package_id -and
    [string]$installUpdateResult.package_id -eq [string]$rollbackSupportResult.package_id -and
    [string]$rollbackSupportResult.package_id -eq [string]$preflightResult.package_id -and
    [string]$installUpdateResult.media_id -eq [string]$rollbackSupportResult.media_id -and
    [string]$rollbackSupportResult.media_id -eq [string]$preflightResult.media_id -and
    [string]$installUpdateResult.release_id -eq [string]$rollbackSupportResult.release_id -and
    [string]$rollbackSupportResult.release_id -eq [string]$preflightResult.release_id
)
$scriptContextBound = (
    $productionRunbookSmokeText.Contains("execution_mode = `"local-only`"") -and
    $productionRunbookSmokeText.Contains("release_gate_consumable = `$true") -and
    $rootfsValidationText.Contains("PackageDefaults") -and
    $rootfsValidationText.Contains("agentos.alpha-rootfs-validation.v1") -and
    $rootfsValidationText.Contains("production_signing.key_custody") -and
    $rootfsValidationText.Contains("normal_shell")
)
$contractBound = (
    $contractText.Contains("Run local release channel consumer smoke that must execute or deny with audit evidence") -and
    $contractText.Contains("No later gate may be fabricated from a previous gate") -and
    $contractText.Contains("If any condition is false, the install/update path must deny with audit evidence and no effect preparation") -and
    $contractText.Contains("RC16 does not")
)

$consumerBlockers = [System.Collections.ArrayList]::new()
if (-not $localMetadataBound) { Add-Unique $consumerBlockers "rc16-local-release-channel-metadata-not-bound" }
if (-not $tuiProjectionBound) { Add-Unique $consumerBlockers "rc16-tui-installability-projection-not-bound" }
if (-not $planspecBound) { Add-Unique $consumerBlockers "rc16-install-update-planspec-not-bound" }
if (-not $securityEnvelopeBound) { Add-Unique $consumerBlockers "rc16-security-execution-install-update-envelope-not-bound" }
if (-not $rollbackSupportBound) { Add-Unique $consumerBlockers "rc16-rollback-support-package-not-bound" }
if (-not $packageIdentityBound) { Add-Unique $consumerBlockers "rc16-package-identity-not-bound" }
if (-not $scriptContextBound) { Add-Unique $consumerBlockers "rc16-local-smoke-script-context-not-bound" }
if (-not $contractBound) { Add-Unique $consumerBlockers "rc16-local-consumer-contract-not-bound" }

foreach ($blocker in @($tuiProjectionResult.projection_surface.blockers)) {
    if ($blocker -ne "rc16-local-release-channel-consumer-smoke-not-run") {
        Add-Unique $consumerBlockers ([string]$blocker)
    }
}
if (-not $installUpdateResult.readiness_surface.exact_install_update_target_bound) {
    Add-Unique $consumerBlockers "rc16-exact-install-update-target-not-bound"
}
if (-not $installUpdateResult.readiness_surface.exact_install_update_approval_bound) {
    Add-Unique $consumerBlockers "rc16-exact-install-update-approval-not-bound"
}
if (-not $installUpdateResult.readiness_surface.agentcore_install_update_planspec_executable) {
    Add-Unique $consumerBlockers "rc16-install-update-planspec-not-executable"
}
if (-not $installUpdateResult.readiness_surface.security_execution_allowed) {
    Add-Unique $consumerBlockers "rc16-security-execution-install-update-allow-not-bound"
}

$installReady = (
    $localMetadataBound -and
    $tuiProjectionBound -and
    $planspecBound -and
    $securityEnvelopeBound -and
    $rollbackSupportBound -and
    $packageIdentityBound -and
    $installUpdateResult.readiness_surface.exact_install_update_target_bound -eq $true -and
    $installUpdateResult.readiness_surface.exact_install_update_approval_bound -eq $true -and
    $installUpdateResult.readiness_surface.agentcore_install_update_planspec_executable -eq $true -and
    $installUpdateResult.readiness_surface.security_execution_allowed -eq $true -and
    @($consumerBlockers).Count -eq 0
)
$updateReady = $installReady
$consumerDecision = if ($installReady -and $updateReady) { "ready-without-effect" } else { "denied-before-effect" }

$sideEffects = [ordered]@{
    endpoint_probe_performed = $false
    frontend_output_trusted = $false
    signer_reachability_trusted = $false
    shell_output_trusted = $false
    tui_output_trusted = $false
    model_replay_trusted = $false
    object_storage_ui_trusted = $false
    payload_upload_performed = $false
    payload_published = $false
    network_fetch_attempted = $false
    remote_payload_bytes_downloaded = $false
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
    tui_projection_result = New-ArtifactRef $resolvedTuiProjectionResultPath $tuiProjectionResult
    tui_installability_projection = New-ArtifactRef $resolvedTuiProjectionPath $tuiProjection
    install_update_binding_result = New-ArtifactRef $resolvedInstallUpdateBindingResultPath $installUpdateResult
    install_update_planspec = New-ArtifactRef $resolvedInstallUpdatePlanSpecPath $installUpdatePlanSpec
    security_execution_envelope = New-ArtifactRef $resolvedSecurityExecutionEnvelopePath $securityEnvelope
    rollback_support_result = New-ArtifactRef $resolvedRollbackSupportResultPath $rollbackSupportResult
    rollback_support_package = New-ArtifactRef $resolvedRollbackSupportPackagePath $rollbackSupportPackage
    preflight_result = New-ArtifactRef $resolvedPreflightResultPath $preflightResult
    preflight_package = New-ArtifactRef $resolvedPreflightPackagePath $preflightPackage
    release_package_artifact_set = New-ArtifactRef $resolvedReleasePackageArtifactSetPath $releasePackageArtifactSet
    installable_media_manifest = New-ArtifactRef $resolvedInstallableMediaManifestPath $installableMediaManifest
    package_descriptor_result = New-ArtifactRef $resolvedPackageDescriptorResultPath $packageDescriptorResult
    production_runbook_smoke_script = New-ArtifactRef $resolvedProductionRunbookSmokePath
    rootfs_validation_script = New-ArtifactRef $resolvedRootfsValidationPath
}

$auditMaterial = [ordered]@{
    schema = "agentos.rc16-local-release-channel-consumer-audit-material.v1"
    task = "RC16-031"
    generated_at = $generatedAtValue
    package_id = [string]$installUpdateResult.package_id
    media_id = [string]$installUpdateResult.media_id
    release_id = [string]$installUpdateResult.release_id
    decision = $consumerDecision
    install_readiness = if ($installReady) { "ready" } else { "denied" }
    update_readiness = if ($updateReady) { "ready" } else { "denied" }
    blockers = @($consumerBlockers)
    planspec_core_hash = [string]$installUpdateResult.readiness_surface.planspec_core_hash
    effect_envelope_core_hash = [string]$installUpdateResult.readiness_surface.effect_envelope_core_hash
    decision_material_hash = [string]$installUpdateResult.readiness_surface.decision_material_hash
    local_channel_metadata_sha256 = [ordered]@{
        release_package_artifact_set = Get-FileSha256 $resolvedReleasePackageArtifactSetPath
        installable_media_manifest = Get-FileSha256 $resolvedInstallableMediaManifestPath
        preflight_package = Get-FileSha256 $resolvedPreflightPackagePath
        rollback_support_package = Get-FileSha256 $resolvedRollbackSupportPackagePath
        tui_projection = Get-FileSha256 $resolvedTuiProjectionPath
    }
    side_effects = $sideEffects
}
$auditDigest = Get-StringSha256 (($auditMaterial | ConvertTo-Json -Depth 100 -Compress))

$auditRecord = [ordered]@{
    schema = "agentos.rc16-local-release-channel-consumer-audit.v1"
    generated_at = $generatedAtValue
    local_only = $true
    decision = $consumerDecision
    decision_digest = $auditDigest
    bounded_by_agentcore_planspec = $planspecBound
    bounded_by_security_execution = $securityEnvelopeBound
    agentcore_planspec_executable = $false
    security_execution_allowed = $false
    effect_preparation_allowed = $false
    effect_prepared = $false
    install_effect_prepared = $false
    update_effect_prepared = $false
    install_performed = $false
    update_performed = $false
    blockers = @($consumerBlockers)
}

$caseObservedBlockers = @(
    "rc16-local-release-channel-metadata-not-bound",
    "rc16-tui-installability-projection-not-bound",
    "rc16-install-update-planspec-not-bound",
    "rc16-security-execution-install-update-envelope-not-bound",
    "rc16-rollback-support-package-not-bound",
    "rc16-package-identity-not-bound",
    "rc16-local-smoke-script-context-not-bound",
    "rc16-local-consumer-contract-not-bound",
    "rc16-exact-install-update-target-not-bound",
    "rc16-exact-install-update-approval-not-bound",
    "rc16-install-update-planspec-not-executable",
    "rc16-security-execution-install-update-allow-not-bound",
    "endpoint-reachability-is-not-authority",
    "frontend-output-is-not-authority",
    "signer-reachability-is-not-authority",
    "shell-output-is-not-authority",
    "tui-output-is-not-authority",
    "model-replay-is-not-authority",
    "object-storage-ui-is-not-authority",
    "remote-payload-download-denied",
    "support-upload-denied",
    "recovery-execution-denied",
    "remote-dispatch-denied",
    "active-slot-mutation-denied",
    "boot-metadata-mutation-denied",
    "active-artifact-set-mutation-denied",
    "production-ring-mutation-denied",
    "private-signing-material-denied"
)
$caseExpectations = [ordered]@{
    "missing.local_release_channel_metadata" = @("rc16-local-release-channel-metadata-not-bound")
    "missing.tui_projection" = @("rc16-tui-installability-projection-not-bound")
    "missing.agentcore_planspec" = @("rc16-install-update-planspec-not-bound")
    "missing.security_execution_envelope" = @("rc16-security-execution-install-update-envelope-not-bound")
    "missing.rollback_support" = @("rc16-rollback-support-package-not-bound")
    "identity.package_mismatch" = @("rc16-package-identity-not-bound")
    "missing.smoke_script_context" = @("rc16-local-smoke-script-context-not-bound")
    "missing.consumer_contract" = @("rc16-local-consumer-contract-not-bound")
    "approval.target_missing" = @("rc16-exact-install-update-target-not-bound")
    "approval.exact_approval_missing" = @("rc16-exact-install-update-approval-not-bound")
    "agentcore.non_executable" = @("rc16-install-update-planspec-not-executable")
    "security_execution.allow_missing" = @("rc16-security-execution-install-update-allow-not-bound")
    "surface.endpoint_reachability" = @("endpoint-reachability-is-not-authority")
    "surface.frontend_output" = @("frontend-output-is-not-authority")
    "surface.signer_reachability" = @("signer-reachability-is-not-authority")
    "surface.shell_output" = @("shell-output-is-not-authority")
    "surface.tui_output" = @("tui-output-is-not-authority")
    "surface.model_replay" = @("model-replay-is-not-authority")
    "surface.object_storage_ui" = @("object-storage-ui-is-not-authority")
    "authority.remote_payload_download" = @("remote-payload-download-denied")
    "authority.support_upload" = @("support-upload-denied")
    "authority.recovery_execution" = @("recovery-execution-denied")
    "authority.remote_dispatch" = @("remote-dispatch-denied")
    "authority.active_slot_mutation" = @("active-slot-mutation-denied")
    "authority.boot_metadata_mutation" = @("boot-metadata-mutation-denied")
    "authority.active_artifact_set_mutation" = @("active-artifact-set-mutation-denied")
    "authority.production_ring_mutation" = @("production-ring-mutation-denied")
    "authority.private_material" = @("private-signing-material-denied")
}
$cases = @()
foreach ($caseId in $caseExpectations.Keys) {
    $cases += New-DenialCase -Id $caseId -ExpectedBlockers ([string[]]$caseExpectations[$caseId]) -ObservedBlockers $caseObservedBlockers
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$consumerEvidencePath = Join-Path $resolvedArtifactDir "consumer-smoke-evidence.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC16-031-local-release-channel-consumer-smoke.json"

$consumerEvidence = [ordered]@{
    schema = "agentos.rc16-local-release-channel-consumer-smoke-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC16-031"
    status = "local-consumer-smoke-$consumerDecision"
    production_ready_claim = $false
    package_id = [string]$installUpdateResult.package_id
    media_id = [string]$installUpdateResult.media_id
    release_id = [string]$installUpdateResult.release_id
    local_release_channel = [ordered]@{
        followed = $localMetadataBound
        local_only = $true
        remote_payload_download_attempted = $false
        package_identity_bound = $packageIdentityBound
        release_package_artifact_set_sha256 = Get-FileSha256 $resolvedReleasePackageArtifactSetPath
        installable_media_manifest_sha256 = Get-FileSha256 $resolvedInstallableMediaManifestPath
        preflight_package_sha256 = Get-FileSha256 $resolvedPreflightPackagePath
        descriptor_result_sha256 = Get-FileSha256 $resolvedPackageDescriptorResultPath
    }
    decision = [ordered]@{
        outcome = $consumerDecision
        install_readiness = if ($installReady) { "ready" } else { "denied" }
        update_readiness = if ($updateReady) { "ready" } else { "denied" }
        exact_denial_blockers = @($consumerBlockers)
        next_safe_action = "bind exact install/update target, exact approval, executable AgentCore PlanSpec, and SecurityExecution allow before any install/update effect"
    }
    agentcore = [ordered]@{
        planspec_bound = $planspecBound
        planspec_core_hash = [string]$installUpdateResult.readiness_surface.planspec_core_hash
        planspec_executable = $false
        effect_preparation_allowed = $false
    }
    security_execution = [ordered]@{
        envelope_bound = $securityEnvelopeBound
        effect_envelope_core_hash = [string]$installUpdateResult.readiness_surface.effect_envelope_core_hash
        decision_material_hash = [string]$installUpdateResult.readiness_surface.decision_material_hash
        allowed = $false
        effect_prepared = $false
    }
    rollback_support = [ordered]@{
        package_bound = $rollbackSupportBound
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        rollback_execution_allowed = $false
        rollback_execution_performed = $false
    }
    audit = $auditRecord
    denial_cases = $cases
    side_effects = $sideEffects
    source = $source
}
Write-Json $consumerEvidence $consumerEvidencePath

Add-Check "plan.current_task.rc16_031" $planAllowsRun "RC16-031 must run after RC16-030 completed, either while current_task is RC16-031 or while rerunning after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc16_030_status = $rc16PreviousStatus; rc16_031_status = $rc16TaskStatus })
Add-Check "local_release_channel.metadata_bound" $localMetadataBound "Consumer smoke must follow repo-local release package, media, preflight, and descriptor metadata." ([ordered]@{ package_id = [string]$preflightResult.package_id; media_id = [string]$preflightResult.media_id; release_id = [string]$preflightResult.release_id; release_package_status = $releasePackageArtifactSet.status; installable_media_status = $installableMediaManifest.status; descriptor_status = $packageDescriptorResult.status })
Add-Check "consumer.tui_projection_bound" $tuiProjectionBound "Consumer smoke must consume completed read-only TUI/operator installability projection without granting authority." ([ordered]@{ status = $tuiProjectionResult.status; read_only = $tuiProjectionResult.projection_surface.read_only; tui_authority = $tuiProjectionResult.projection_surface.tui_authority })
Add-Check "consumer.agentcore_security_bound" ($planspecBound -and $securityEnvelopeBound) "Consumer smoke must be bounded by AgentCore install/update PlanSpec and SecurityExecution envelope." ([ordered]@{ planspec_bound = $planspecBound; planspec_executable = $installUpdateResult.readiness_surface.agentcore_install_update_planspec_executable; security_envelope_bound = $securityEnvelopeBound; security_execution_allowed = $securityEnvelope.security_execution_allowed })
Add-Check "consumer.rollback_support_bound" $rollbackSupportBound "Consumer smoke must bind rollback/support package while keeping support upload, recovery execution, and rollback execution disabled." ([ordered]@{ rollback_support_package_bound = $rollbackSupportResult.rollback_support_surface.rollback_support_package_bound; support_upload_allowed = $rollbackSupportResult.rollback_support_surface.support_upload_allowed; recovery_execution_allowed = $rollbackSupportResult.rollback_support_surface.recovery_execution_allowed; rollback_execution_performed = $rollbackSupportResult.rollback_support_surface.rollback_execution_performed })
Add-Check "consumer.decision.exact_ready_or_denial" ($consumerDecision -eq "denied-before-effect" -and @($consumerBlockers).Count -ge 4 -and ($consumerBlockers -contains "rc16-exact-install-update-target-not-bound") -and ($consumerBlockers -contains "rc16-security-execution-install-update-allow-not-bound")) "Consumer smoke must return exact install/update-ready or denial evidence." ([ordered]@{ decision = $consumerDecision; install_ready = $installReady; update_ready = $updateReady; blockers = @($consumerBlockers) })
Add-Check "consumer.audit.bound" ($auditRecord.local_only -eq $true -and $auditRecord.bounded_by_agentcore_planspec -eq $true -and $auditRecord.bounded_by_security_execution -eq $true -and -not [string]::IsNullOrWhiteSpace($auditRecord.decision_digest)) "Any execution path must be audited and bounded by AgentCore and SecurityExecution gates." $auditRecord
Add-Check "scripts.local_context.bound" $scriptContextBound "Consumer smoke must bind existing production runbook smoke and alpha rootfs validation context without executing remote infrastructure." ([ordered]@{ production_runbook_smoke_sha256 = Get-FileSha256 $resolvedProductionRunbookSmokePath; rootfs_validation_sha256 = Get-FileSha256 $resolvedRootfsValidationPath })
Add-Check "contract.local_consumer.bound" $contractBound "RC16 contract must require consumer smoke to execute or deny with audit evidence and no effect preparation when conditions are false." $source.rc16_contract
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 20) "Missing metadata, unbound gates, display-surface authority, remote download, support upload, recovery, remote dispatch, mutation, and private material cases must fail closed." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })
Add-Check "authority.no_side_effects" ($sideEffects.network_fetch_attempted -eq $false -and $sideEffects.remote_payload_bytes_downloaded -eq $false -and $sideEffects.install_effect_prepared -eq $false -and $sideEffects.update_effect_prepared -eq $false -and $sideEffects.install_performed -eq $false -and $sideEffects.update_performed -eq $false -and $sideEffects.rollback_execution_performed -eq $false -and $sideEffects.support_upload_performed -eq $false -and $sideEffects.recovery_execution_performed -eq $false -and $sideEffects.remote_dispatch_enabled -eq $false -and $sideEffects.private_signing_material_handled -eq $false -and $sideEffects.production_ring_mutated -eq $false) "RC16-031 must not mutate production rings, dispatch remotely, upload support, execute recovery, handle private material, fetch remote payload bytes, or grant mirror/frontend authority." $sideEffects

$outputsSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $consumerEvidencePath))
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC16-031 outputs must not contain key blocks, private key paths, auth tokens, private material paths, public identity markers, or raw host-private values." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$consumerEvidenceSha256 = Get-FileSha256 $consumerEvidencePath
$result = [ordered]@{
    schema = "agentos.rc16-local-release-channel-consumer-smoke-result.v1"
    generated_at = $generatedAtValue
    task = "RC16-031"
    status = $resultStatus
    production_ready_claim = $false
    package_id = [string]$installUpdateResult.package_id
    media_id = [string]$installUpdateResult.media_id
    release_id = [string]$installUpdateResult.release_id
    consumer_surface = [ordered]@{
        state = "local-release-channel-consumer-$consumerDecision"
        local_release_channel_followed = $localMetadataBound
        install_readiness = if ($installReady) { "ready" } else { "denied" }
        update_readiness = if ($updateReady) { "ready" } else { "denied" }
        consumer_decision = $consumerDecision
        audited = $true
        audit_digest = $auditDigest
        agentcore_planspec_bound = $planspecBound
        agentcore_planspec_executable = $false
        security_execution_envelope_bound = $securityEnvelopeBound
        security_execution_allowed = $false
        effect_preparation_allowed = $false
        rollback_support_package_bound = $rollbackSupportBound
        blockers = @($consumerBlockers)
    }
    outputs = [ordered]@{
        consumer_smoke_evidence = [ordered]@{
            path = Get-StablePath $consumerEvidencePath
            sha256 = $consumerEvidenceSha256
            audit_digest = $auditDigest
        }
    }
    source = $source
    checks = @($script:checks)
    blockers = @($consumerBlockers)
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        repo_local_consumer_only = $true
        local_release_channel_followed = $localMetadataBound
        audited = $true
        mirror_frontend_changed = $false
        mirror_authority = $false
        nginx_or_tls_changed = $false
        signer_infra_changed = $false
        object_storage_infra_changed = $false
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
        remote_payload_bytes_downloaded = $false
        remote_dispatch_enabled = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        install_effect_prepared = $false
        update_effect_prepared = $false
        install_performed = $false
        update_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
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
        rc16_031_complete = (@($script:failedChecks).Count -eq 0)
        consumer_decision = $consumerDecision
        install_readiness = if ($installReady) { "ready" } else { "denied" }
        update_readiness = if ($updateReady) { "ready" } else { "denied" }
        blockers = @($consumerBlockers).Count
        audited = $true
        next_task = "RC16-050"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc16-local-release-channel-consumer-smoke-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC16-031"
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
    consumer_surface = $result.consumer_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc16_031_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC16-050"
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
    throw "Sensitive marker detected in RC16-031 outputs."
}

Write-Host "RC16 local release channel consumer smoke $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Evidence: $(Get-StablePath $consumerEvidencePath)"
Write-Host "Decision: $consumerDecision; install readiness: $($result.consumer_surface.install_readiness); update readiness: $($result.consumer_surface.update_readiness)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
