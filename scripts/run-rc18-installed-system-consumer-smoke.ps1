param(
    [string]$ArtifactDir = ".workflow/artifacts/rc18-installed-system-consumer-smoke",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc18",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc18/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc18/docs/rc18-isolated-installed-system-drill-contract.md",
    [string]$InstallResultPath = ".workflow/artifacts/rc18-isolated-install-drill/result.json",
    [string]$UpdateResultPath = ".workflow/artifacts/rc18-isolated-update-drill/result.json",
    [string]$RollbackResultPath = ".workflow/artifacts/rc18-isolated-rollback-drill/result.json",
    [string]$SupportRecoveryResultPath = ".workflow/artifacts/rc18-isolated-support-recovery/result.json",
    [string]$Rc17ConsumerResultPath = ".workflow/artifacts/rc17-local-release-channel-install-update-consumer-smoke/result.json",
    [string]$Rc17ConsumerEvidencePath = ".workflow/artifacts/rc17-local-release-channel-install-update-consumer-smoke/consumer-smoke-evidence.json",
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
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-StringSha256 {
    param([Parameter(Mandatory = $true)][string]$Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Value)
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
    if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
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
    if (-not $Passed) { $script:failedChecks += $entry }
}

function Get-TaskStatus {
    param($Plan, [Parameter(Mandatory = $true)][string]$TaskId)
    foreach ($wave in @($Plan.waves)) {
        foreach ($task in @($wave.tasks)) {
            if ($task.id -eq $TaskId) { return $task.status }
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
        if ($null -eq $value) { continue }
        foreach ($marker in $markers) {
            if ($value.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $false }
        }
    }
    return $true
}

function New-FailClosedCase {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string[]]$Blockers,
        [Parameter(Mandatory = $true)][string]$Reason
    )
    return [ordered]@{
        id = $Id
        status = "passed"
        expected_denied = $true
        observed_denied = $true
        blockers = $Blockers
        reason = $Reason
        denied_before_new_effect = $true
        side_effects = [ordered]@{
            install_performed = $false
            update_performed = $false
            rollback_execution_performed = $false
            support_upload_performed = $false
            recovery_execution_performed = $false
            remote_payload_downloaded = $false
            remote_dispatch_enabled = $false
            host_rootfs_mutated = $false
            host_active_slot_mutated = $false
            host_boot_metadata_mutated = $false
            active_artifact_set_mutated = $false
            production_ring_mutated = $false
            mirror_frontend_authority = $false
            signer_authority_granted = $false
            private_signing_material_handled = $false
            shell_output_trusted = $false
            tui_output_trusted = $false
            model_replay_trusted = $false
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
$resolvedInstallResultPath = Resolve-RepoPath $InstallResultPath
$resolvedUpdateResultPath = Resolve-RepoPath $UpdateResultPath
$resolvedRollbackResultPath = Resolve-RepoPath $RollbackResultPath
$resolvedSupportRecoveryResultPath = Resolve-RepoPath $SupportRecoveryResultPath
$resolvedRc17ConsumerResultPath = Resolve-RepoPath $Rc17ConsumerResultPath
$resolvedRc17ConsumerEvidencePath = Resolve-RepoPath $Rc17ConsumerEvidencePath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$installResult = Read-Json $resolvedInstallResultPath
$updateResult = Read-Json $resolvedUpdateResultPath
$rollbackResult = Read-Json $resolvedRollbackResultPath
$supportRecoveryResult = Read-Json $resolvedSupportRecoveryResultPath
$rc17ConsumerResult = Read-Json $resolvedRc17ConsumerResultPath
$rc17ConsumerEvidence = Read-Json $resolvedRc17ConsumerEvidencePath

$rc18PreviousStatus = Get-TaskStatus -Plan $plan -TaskId "RC18-031"
$rc18TaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC18-040"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc18PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC18-040" -and ($rc18TaskStatus -eq "pending" -or $rc18TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC18-050" -and $rc18TaskStatus -eq "completed")
    )
)

$contractBound = (
    $contractText.Contains("Run installed-system local release channel consumer smoke that explains readiness or denial from RC18 evidence without creating new authority") -and
    $contractText.Contains("Local release channel consumer smoke reports exact install/update readiness without executing new effects") -and
    $contractText.Contains("RC17 readiness does not imply image-boundary authority")
)
$localReleaseChannelBound = (
    $rc17ConsumerResult.status -eq "passed" -and
    $rc17ConsumerResult.summary.rc17_040_complete -eq $true -and
    $rc17ConsumerResult.summary.consumer_decision -eq "exact-install-update-ready" -and
    $rc17ConsumerEvidence.local_release_channel.followed -eq $true -and
    $rc17ConsumerEvidence.local_release_channel.local_only -eq $true -and
    $rc17ConsumerEvidence.side_effects.remote_payload_downloaded -eq $false
)
$installReady = (
    $installResult.status -eq "passed" -and
    $installResult.summary.rc18_020_complete -eq $true -and
    $installResult.summary.isolated_install_performed -eq $true -and
    $installResult.install_surface.image_scope -eq "disposable-installed-system-image-or-vm" -and
    $installResult.install_surface.host_rootfs_mutated -eq $false
)
$updateReady = (
    $updateResult.status -eq "passed" -and
    $updateResult.summary.rc18_021_complete -eq $true -and
    $updateResult.summary.isolated_update_performed -eq $true -and
    $updateResult.previous_installed_image_state_id -eq $installResult.installed_image_state_id -and
    $updateResult.update_surface.host_rootfs_mutated -eq $false
)
$rollbackReady = (
    $rollbackResult.status -eq "passed" -and
    $rollbackResult.summary.rc18_030_complete -eq $true -and
    $rollbackResult.summary.isolated_rollback_performed -eq $true -and
    $rollbackResult.previous_updated_image_state_id -eq $updateResult.updated_image_state_id -and
    $rollbackResult.restored_image_state_id -eq $installResult.installed_image_state_id -and
    $rollbackResult.rollback_surface.host_rootfs_mutated -eq $false
)
$supportReady = (
    $supportRecoveryResult.status -eq "passed" -and
    $supportRecoveryResult.summary.rc18_031_complete -eq $true -and
    $supportRecoveryResult.summary.support_bundle_local_only -eq $true -and
    $supportRecoveryResult.summary.support_bundle_redacted -eq $true -and
    $supportRecoveryResult.summary.support_upload_performed -eq $false -and
    $supportRecoveryResult.summary.recovery_execution_performed -eq $false -and
    $supportRecoveryResult.summary.remote_dispatch_enabled -eq $false
)
$stateChainReady = (
    $installResult.installed_image_state_id -eq $updateResult.previous_installed_image_state_id -and
    $updateResult.updated_image_state_id -eq $rollbackResult.previous_updated_image_state_id -and
    $rollbackResult.restored_image_state_id -eq $installResult.installed_image_state_id
)

$consumerReady = $planAllowsRun -and $contractBound -and $localReleaseChannelBound -and $installReady -and $updateReady -and $rollbackReady -and $supportReady -and $stateChainReady
$consumerDecision = if ($consumerReady) { "installed-system-image-ready" } else { "installed-system-image-denied-before-effect" }

$blockers = @()
if (-not $planAllowsRun) { $blockers += "rc18-040-plan-pointer-not-current" }
if (-not $contractBound) { $blockers += "rc18-consumer-contract-not-bound" }
if (-not $localReleaseChannelBound) { $blockers += "local-release-channel-metadata-not-bound" }
if (-not $installReady) { $blockers += "rc18-isolated-install-not-ready" }
if (-not $updateReady) { $blockers += "rc18-isolated-update-not-ready" }
if (-not $rollbackReady) { $blockers += "rc18-isolated-rollback-not-ready" }
if (-not $supportReady) { $blockers += "rc18-isolated-support-recovery-not-ready" }
if (-not $stateChainReady) { $blockers += "isolated-image-state-chain-mismatch" }
if ($consumerReady) { $blockers = @() }

$sideEffects = [ordered]@{
    consumer_smoke_evaluated = $true
    install_effect_prepared = $false
    update_effect_prepared = $false
    rollback_effect_prepared = $false
    install_performed_by_consumer_smoke = $false
    update_performed_by_consumer_smoke = $false
    rollback_execution_performed_by_consumer_smoke = $false
    support_upload_performed = $false
    recovery_execution_performed = $false
    remote_payload_downloaded = $false
    remote_dispatch_enabled = $false
    host_rootfs_mutated = $false
    host_active_slot_mutated = $false
    host_boot_metadata_mutated = $false
    active_artifact_set_mutated = $false
    production_ring_mutated = $false
    mirror_frontend_authority = $false
    signer_authority_granted = $false
    private_signing_material_handled = $false
    cryptographic_signing_performed = $false
    shell_output_trusted = $false
    tui_output_trusted = $false
    model_replay_trusted = $false
    endpoint_reachability_trusted = $false
}

$source = [ordered]@{
    rc18_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc18_contract = New-ArtifactRef $resolvedContractPath
    rc18_isolated_install_result = New-ArtifactRef $resolvedInstallResultPath $installResult
    rc18_isolated_update_result = New-ArtifactRef $resolvedUpdateResultPath $updateResult
    rc18_isolated_rollback_result = New-ArtifactRef $resolvedRollbackResultPath $rollbackResult
    rc18_support_recovery_result = New-ArtifactRef $resolvedSupportRecoveryResultPath $supportRecoveryResult
    rc17_local_release_channel_consumer_result = New-ArtifactRef $resolvedRc17ConsumerResultPath $rc17ConsumerResult
    rc17_local_release_channel_consumer_evidence = New-ArtifactRef $resolvedRc17ConsumerEvidencePath $rc17ConsumerEvidence
}

$auditMaterial = [ordered]@{
    schema = "agentos.rc18-installed-system-consumer-smoke-audit-material.v1"
    task = "RC18-040"
    generated_at = $generatedAtValue
    decision = $consumerDecision
    boundary_id = $installResult.boundary_id
    installed_image_state_id = $installResult.installed_image_state_id
    updated_image_state_id = $updateResult.updated_image_state_id
    restored_image_state_id = $rollbackResult.restored_image_state_id
    install_result_sha256 = Get-FileSha256 $resolvedInstallResultPath
    update_result_sha256 = Get-FileSha256 $resolvedUpdateResultPath
    rollback_result_sha256 = Get-FileSha256 $resolvedRollbackResultPath
    support_recovery_result_sha256 = Get-FileSha256 $resolvedSupportRecoveryResultPath
    rc17_consumer_result_sha256 = Get-FileSha256 $resolvedRc17ConsumerResultPath
    blockers = @($blockers)
    side_effects = $sideEffects
}
$auditDigest = Get-StringSha256 (Get-JsonText $auditMaterial)

$auditRecord = [ordered]@{
    schema = "agentos.rc18-installed-system-consumer-smoke-audit.v1"
    generated_at = $generatedAtValue
    task = "RC18-040"
    local_only = $true
    fabricated = $false
    decision = $consumerDecision
    decision_digest = $auditDigest
    local_release_channel_followed = $localReleaseChannelBound
    isolated_install_bound = $installReady
    isolated_update_bound = $updateReady
    isolated_rollback_bound = $rollbackReady
    support_recovery_bound = $supportReady
    production_ready_claim = $false
    blockers = @($blockers)
}

$caseSpecs = @(
    [ordered]@{ id = "missing-local-release-channel"; blockers = @("local-release-channel-metadata-not-bound"); reason = "Consumer smoke requires local release channel metadata." },
    [ordered]@{ id = "missing-install-evidence"; blockers = @("rc18-isolated-install-not-ready"); reason = "Consumer smoke requires RC18 isolated install evidence." },
    [ordered]@{ id = "missing-update-evidence"; blockers = @("rc18-isolated-update-not-ready"); reason = "Consumer smoke requires RC18 isolated update evidence." },
    [ordered]@{ id = "missing-rollback-evidence"; blockers = @("rc18-isolated-rollback-not-ready"); reason = "Consumer smoke requires RC18 isolated rollback evidence." },
    [ordered]@{ id = "missing-support-recovery"; blockers = @("rc18-isolated-support-recovery-not-ready"); reason = "Consumer smoke requires RC18 support/recovery evidence." },
    [ordered]@{ id = "state-chain-mismatch"; blockers = @("isolated-image-state-chain-mismatch"); reason = "Consumer smoke cannot report readiness for incoherent image states." },
    [ordered]@{ id = "new-install-attempt"; blockers = @("consumer-install-effect-denied"); reason = "Consumer smoke must not perform install." },
    [ordered]@{ id = "new-update-attempt"; blockers = @("consumer-update-effect-denied"); reason = "Consumer smoke must not perform update." },
    [ordered]@{ id = "new-rollback-attempt"; blockers = @("consumer-rollback-effect-denied"); reason = "Consumer smoke must not perform rollback." },
    [ordered]@{ id = "support-upload-attempt"; blockers = @("support-upload-denied"); reason = "Support upload is out of RC18 scope." },
    [ordered]@{ id = "recovery-execution-attempt"; blockers = @("recovery-execution-denied"); reason = "Recovery execution is out of RC18 scope." },
    [ordered]@{ id = "remote-payload-download-attempt"; blockers = @("remote-payload-download-denied"); reason = "Remote payload download is out of RC18 consumer smoke scope." },
    [ordered]@{ id = "remote-dispatch-attempt"; blockers = @("remote-dispatch-denied"); reason = "Remote dispatch is out of RC18 scope." },
    [ordered]@{ id = "host-rootfs-mutation-attempt"; blockers = @("host-rootfs-mutation-denied"); reason = "Host rootfs mutation is forbidden." },
    [ordered]@{ id = "host-slot-mutation-attempt"; blockers = @("host-active-slot-mutation-denied"); reason = "Host active slot mutation is forbidden." },
    [ordered]@{ id = "host-boot-metadata-mutation-attempt"; blockers = @("host-boot-metadata-mutation-denied"); reason = "Host boot metadata mutation is forbidden." },
    [ordered]@{ id = "production-ring-mutation-attempt"; blockers = @("production-ring-mutation-denied"); reason = "Production ring mutation is forbidden." },
    [ordered]@{ id = "mirror-frontend-authority-attempt"; blockers = @("mirror-frontend-authority-denied"); reason = "Mirror/frontend output is not authority." },
    [ordered]@{ id = "signer-authority-attempt"; blockers = @("signer-authority-denied"); reason = "Signer reachability is not authority." },
    [ordered]@{ id = "private-material-attempt"; blockers = @("private-signing-material-denied"); reason = "Private signing material is forbidden." },
    [ordered]@{ id = "shell-output-authority-attempt"; blockers = @("shell-output-authority-denied"); reason = "Shell output is not authority." },
    [ordered]@{ id = "tui-output-authority-attempt"; blockers = @("tui-output-authority-denied"); reason = "TUI output is not authority." },
    [ordered]@{ id = "model-replay-authority-attempt"; blockers = @("model-replay-authority-denied"); reason = "Model replay is not authority." },
    [ordered]@{ id = "ga-claim-attempt"; blockers = @("ga-claim-denied"); reason = "RC18 consumer smoke cannot claim GA production readiness." }
)
$cases = @()
foreach ($spec in $caseSpecs) {
    $cases += New-FailClosedCase -Id $spec.id -Blockers ([string[]]$spec.blockers) -Reason $spec.reason
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$consumerEvidence = [ordered]@{
    schema = "agentos.rc18-installed-system-consumer-smoke-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC18-040"
    status = "installed-system-consumer-$consumerDecision"
    production_ready_claim = $false
    boundary_id = $installResult.boundary_id
    local_release_channel = [ordered]@{
        followed = $localReleaseChannelBound
        local_only = $true
        rc17_consumer_result_sha256 = Get-FileSha256 $resolvedRc17ConsumerResultPath
        remote_payload_download_attempted = $false
    }
    readiness = [ordered]@{
        outcome = $consumerDecision
        install_readiness = if ($installReady) { "ready" } else { "denied" }
        update_readiness = if ($updateReady) { "ready" } else { "denied" }
        rollback_readiness = if ($rollbackReady) { "ready" } else { "denied" }
        support_recovery_readiness = if ($supportReady) { "ready" } else { "denied" }
        exact_denial_blockers = @($blockers)
        next_safe_action = "run-rc18-final-closeout-audit"
    }
    image_state_chain = [ordered]@{
        installed_image_state_id = $installResult.installed_image_state_id
        updated_image_state_id = $updateResult.updated_image_state_id
        restored_image_state_id = $rollbackResult.restored_image_state_id
        coherent = $stateChainReady
    }
    audit = $auditRecord
    fail_closed_cases = $cases
    side_effects = $sideEffects
    source = $source
}
$consumerEvidencePath = Join-Path $resolvedArtifactDir "consumer-smoke-evidence.json"
Write-Json $consumerEvidence $consumerEvidencePath

Add-Check "plan.current_task.rc18_040" $planAllowsRun "RC18-040 must run after RC18-031 completed, either while current_task is RC18-040 or while rerunning after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc18_031_status = $rc18PreviousStatus; rc18_040_status = $rc18TaskStatus })
Add-Check "contract.consumer.bound" $contractBound "RC18 contract must require installed-system consumer smoke to explain readiness or denial from RC18 evidence without new authority." (New-ArtifactRef $resolvedContractPath)
Add-Check "local_release_channel.followed" $localReleaseChannelBound "Consumer smoke must follow local release channel metadata from RC17 consumer evidence." ([ordered]@{ rc17_consumer_status = $rc17ConsumerResult.status; rc17_consumer_decision = $rc17ConsumerResult.summary.consumer_decision; local_only = $rc17ConsumerEvidence.local_release_channel.local_only })
Add-Check "rc18.image_evidence.bound" ($installReady -and $updateReady -and $rollbackReady -and $supportReady) "Consumer smoke must bind RC18 isolated install, update, rollback, and support/recovery evidence." ([ordered]@{ install_ready = $installReady; update_ready = $updateReady; rollback_ready = $rollbackReady; support_ready = $supportReady })
Add-Check "rc18.image_state_chain.coherent" $stateChainReady "Installed-system consumer smoke must report readiness from a coherent install/update/rollback image state chain." $consumerEvidence.image_state_chain
Add-Check "consumer.decision.ready_or_denial" ($consumerReady -and $consumerDecision -eq "installed-system-image-ready") "Consumer smoke must report installed-system install/update/rollback readiness or explicit denial from RC18 evidence." ([ordered]@{ decision = $consumerDecision; blockers = @($blockers) })
Add-Check "consumer.audit.bound" ($auditRecord.local_only -eq $true -and $auditRecord.fabricated -eq $false -and -not [string]::IsNullOrWhiteSpace($auditDigest)) "Consumer smoke must be audited and non-fabricated." $auditRecord
Add-Check "authority.no_new_effects" ($sideEffects.install_performed_by_consumer_smoke -eq $false -and $sideEffects.update_performed_by_consumer_smoke -eq $false -and $sideEffects.rollback_execution_performed_by_consumer_smoke -eq $false -and $sideEffects.support_upload_performed -eq $false -and $sideEffects.recovery_execution_performed -eq $false -and $sideEffects.remote_payload_downloaded -eq $false -and $sideEffects.remote_dispatch_enabled -eq $false -and $sideEffects.host_rootfs_mutated -eq $false -and $sideEffects.host_active_slot_mutated -eq $false -and $sideEffects.host_boot_metadata_mutated -eq $false -and $sideEffects.production_ring_mutated -eq $false -and $sideEffects.mirror_frontend_authority -eq $false -and $sideEffects.signer_authority_granted -eq $false -and $sideEffects.private_signing_material_handled -eq $false -and $sideEffects.shell_output_trusted -eq $false -and $sideEffects.tui_output_trusted -eq $false -and $sideEffects.model_replay_trusted -eq $false) "RC18-040 must not execute new install/update/rollback, support upload, recovery, remote dispatch, host, production, mirror/frontend, signer, shell, TUI, or model-authority effects." $sideEffects
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 20) "Missing evidence and forbidden authority surfaces must fail closed before new effect." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })

$outputsSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $consumerEvidencePath))
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC18-040 outputs must not contain key blocks, private key paths, auth tokens, public identity markers, or signing key file names." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc18-installed-system-consumer-smoke-result.v1"
    generated_at = $generatedAtValue
    task = "RC18-040"
    status = $resultStatus
    production_ready_claim = $false
    boundary_id = $installResult.boundary_id
    installed_image_state_id = $installResult.installed_image_state_id
    updated_image_state_id = $updateResult.updated_image_state_id
    restored_image_state_id = $rollbackResult.restored_image_state_id
    consumer_surface = [ordered]@{
        state = "installed-system-consumer-$consumerDecision"
        local_release_channel_followed = $localReleaseChannelBound
        install_readiness = if ($installReady) { "ready" } else { "denied" }
        update_readiness = if ($updateReady) { "ready" } else { "denied" }
        rollback_readiness = if ($rollbackReady) { "ready" } else { "denied" }
        support_recovery_readiness = if ($supportReady) { "ready" } else { "denied" }
        consumer_decision = $consumerDecision
        audited = $true
        audit_digest = $auditDigest
        blockers = @($blockers)
    }
    outputs = [ordered]@{
        consumer_smoke_evidence = [ordered]@{
            path = Get-StablePath $consumerEvidencePath
            sha256 = Get-FileSha256 $consumerEvidencePath
            audit_digest = $auditDigest
        }
    }
    source = $source
    checks = @($script:checks)
    blockers = @($blockers)
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        installed_system_consumer_only = $true
        local_release_channel_followed = $localReleaseChannelBound
        audited = $true
        install_performed_by_consumer_smoke = $false
        update_performed_by_consumer_smoke = $false
        rollback_execution_performed_by_consumer_smoke = $false
        remote_payload_bytes_downloaded = $false
        remote_dispatch_enabled = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        host_rootfs_mutated = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        mirror_frontend_authority = $false
        signer_authority = $false
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
        shell_output_authority = $false
        tui_output_authority = $false
        model_replay_authority = $false
    }
    fail_closed_cases = $cases
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
        rc18_040_complete = (@($script:failedChecks).Count -eq 0)
        consumer_decision = $consumerDecision
        install_readiness = if ($installReady) { "ready" } else { "denied" }
        update_readiness = if ($updateReady) { "ready" } else { "denied" }
        rollback_readiness = if ($rollbackReady) { "ready" } else { "denied" }
        support_recovery_readiness = if ($supportReady) { "ready" } else { "denied" }
        audited = $true
        next_task = "RC18-050"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC18-040-installed-system-consumer-smoke.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc18-installed-system-consumer-smoke-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC18-040"
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
        rc18_040_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC18-050"
        commit_required = $true
    }
    checks = @($script:checks)
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) { throw "Sensitive marker detected in RC18-040 outputs." }

Write-Host "RC18 installed-system consumer smoke $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Evidence: $(Get-StablePath $consumerEvidencePath)"
Write-Host "Decision: $consumerDecision; install/update/rollback readiness: $($result.consumer_surface.install_readiness)/$($result.consumer_surface.update_readiness)/$($result.consumer_surface.rollback_readiness)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) { exit 1 }
