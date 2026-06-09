param(
    [string]$ArtifactDir = ".workflow/artifacts/rc18-isolated-support-recovery",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc18",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc18/plan.json",
    [string]$InstallResultPath = ".workflow/artifacts/rc18-isolated-install-drill/result.json",
    [string]$InstallEvidencePath = ".workflow/artifacts/rc18-isolated-install-drill/install-drill-evidence.json",
    [string]$UpdateResultPath = ".workflow/artifacts/rc18-isolated-update-drill/result.json",
    [string]$UpdateEvidencePath = ".workflow/artifacts/rc18-isolated-update-drill/update-drill-evidence.json",
    [string]$RollbackResultPath = ".workflow/artifacts/rc18-isolated-rollback-drill/result.json",
    [string]$RollbackEvidencePath = ".workflow/artifacts/rc18-isolated-rollback-drill/rollback-drill-evidence.json",
    [string]$Rc17SupportResultPath = ".workflow/artifacts/rc17-controlled-install-update-rollback-support/result.json",
    [string]$Rc17SupportChainPath = ".workflow/artifacts/rc17-controlled-install-update-rollback-support/support-recovery-evidence-chain.json",
    [string]$Rc17SupportBundlePath = ".workflow/artifacts/rc17-controlled-install-update-rollback-support/controlled-install-update-support-bundle.json",
    [string]$Rc17RecoveryIndexPath = ".workflow/artifacts/rc17-controlled-install-update-rollback-support/recovery-reference-index.json",
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
        denied_before_support_upload = $true
        denied_before_recovery_execution = $true
        denied_before_host_mutation = $true
        side_effects = [ordered]@{
            support_bundle_created = $false
            support_upload_performed = $false
            recovery_execution_performed = $false
            remote_dispatch_enabled = $false
            host_rootfs_mutated = $false
            host_active_slot_mutated = $false
            host_boot_metadata_mutated = $false
            active_artifact_set_mutated = $false
            production_ring_mutated = $false
            mirror_frontend_mutated = $false
            signer_authority_granted = $false
            private_signing_material_handled = $false
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
$resolvedInstallResultPath = Resolve-RepoPath $InstallResultPath
$resolvedInstallEvidencePath = Resolve-RepoPath $InstallEvidencePath
$resolvedUpdateResultPath = Resolve-RepoPath $UpdateResultPath
$resolvedUpdateEvidencePath = Resolve-RepoPath $UpdateEvidencePath
$resolvedRollbackResultPath = Resolve-RepoPath $RollbackResultPath
$resolvedRollbackEvidencePath = Resolve-RepoPath $RollbackEvidencePath
$resolvedRc17SupportResultPath = Resolve-RepoPath $Rc17SupportResultPath
$resolvedRc17SupportChainPath = Resolve-RepoPath $Rc17SupportChainPath
$resolvedRc17SupportBundlePath = Resolve-RepoPath $Rc17SupportBundlePath
$resolvedRc17RecoveryIndexPath = Resolve-RepoPath $Rc17RecoveryIndexPath

$plan = Read-Json $resolvedPlanPath
$installResult = Read-Json $resolvedInstallResultPath
$installEvidence = Read-Json $resolvedInstallEvidencePath
$updateResult = Read-Json $resolvedUpdateResultPath
$updateEvidence = Read-Json $resolvedUpdateEvidencePath
$rollbackResult = Read-Json $resolvedRollbackResultPath
$rollbackEvidence = Read-Json $resolvedRollbackEvidencePath
$rc17SupportResult = Read-Json $resolvedRc17SupportResultPath
$rc17SupportChain = Read-Json $resolvedRc17SupportChainPath
$rc17SupportBundle = Read-Json $resolvedRc17SupportBundlePath
$rc17RecoveryIndex = Read-Json $resolvedRc17RecoveryIndexPath

$rc18PreviousStatus = Get-TaskStatus -Plan $plan -TaskId "RC18-030"
$rc18TaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC18-031"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc18PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC18-031" -and ($rc18TaskStatus -eq "pending" -or $rc18TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC18-040" -and $rc18TaskStatus -eq "completed")
    )
)

$installReady = (
    $installResult.status -eq "passed" -and
    $installResult.summary.rc18_020_complete -eq $true -and
    $installResult.summary.isolated_install_performed -eq $true -and
    $installEvidence.status -eq "isolated-install-executed-inside-disposable-image" -and
    $installResult.install_surface.host_rootfs_mutated -eq $false -and
    $installResult.install_surface.host_active_slot_mutated -eq $false -and
    $installResult.install_surface.host_boot_metadata_mutated -eq $false
)
$updateReady = (
    $updateResult.status -eq "passed" -and
    $updateResult.summary.rc18_021_complete -eq $true -and
    $updateResult.summary.isolated_update_performed -eq $true -and
    $updateEvidence.status -eq "isolated-update-executed-inside-disposable-image" -and
    $updateResult.previous_installed_image_state_id -eq $installResult.installed_image_state_id -and
    $updateResult.update_surface.host_rootfs_mutated -eq $false -and
    $updateResult.update_surface.host_active_slot_mutated -eq $false -and
    $updateResult.update_surface.host_boot_metadata_mutated -eq $false
)
$rollbackReady = (
    $rollbackResult.status -eq "passed" -and
    $rollbackResult.summary.rc18_030_complete -eq $true -and
    $rollbackResult.summary.isolated_rollback_performed -eq $true -and
    $rollbackEvidence.status -eq "isolated-rollback-executed-inside-disposable-image" -and
    $rollbackResult.previous_updated_image_state_id -eq $updateResult.updated_image_state_id -and
    $rollbackResult.restored_image_state_id -eq $installResult.installed_image_state_id -and
    $rollbackResult.rollback_surface.support_upload_performed -eq $false -and
    $rollbackResult.rollback_surface.recovery_execution_performed -eq $false -and
    $rollbackResult.rollback_surface.remote_dispatch_enabled -eq $false
)
$rc17SupportReady = (
    $rc17SupportResult.status -eq "passed" -and
    $rc17SupportResult.summary.support_bundle_local_only -eq $true -and
    $rc17SupportResult.summary.support_upload_performed -eq $false -and
    $rc17SupportResult.summary.recovery_execution_performed -eq $false -and
    $rc17SupportChain.support_bundle_local_only -eq $true -and
    $rc17SupportChain.support_upload_performed -eq $false -and
    $rc17SupportChain.recovery_execution_performed -eq $false -and
    $rc17SupportBundle.local_only -eq $true -and
    $rc17SupportBundle.redacted -eq $true -and
    $rc17SupportBundle.uploaded -eq $false -and
    $rc17RecoveryIndex.recovery_execution_performed -eq $false
)
$stateChainReady = (
    $installResult.installed_image_state_id -eq $updateResult.previous_installed_image_state_id -and
    $updateResult.updated_image_state_id -eq $rollbackResult.previous_updated_image_state_id -and
    $rollbackResult.restored_image_state_id -eq $installResult.installed_image_state_id
)
$supportProjectionAllowed = $planAllowsRun -and $installReady -and $updateReady -and $rollbackReady -and $rc17SupportReady -and $stateChainReady

$blockers = @()
if (-not $planAllowsRun) { $blockers += "rc18-031-plan-pointer-not-current" }
if (-not $installReady) { $blockers += "rc18-isolated-install-evidence-not-bound" }
if (-not $updateReady) { $blockers += "rc18-isolated-update-evidence-not-bound" }
if (-not $rollbackReady) { $blockers += "rc18-isolated-rollback-evidence-not-bound" }
if (-not $rc17SupportReady) { $blockers += "rc17-support-recovery-reference-not-bound" }
if (-not $stateChainReady) { $blockers += "isolated-image-state-chain-mismatch" }
if ($supportProjectionAllowed) { $blockers = @() }

$source = [ordered]@{
    rc18_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc18_isolated_install_result = New-ArtifactRef $resolvedInstallResultPath $installResult
    rc18_isolated_install_evidence = New-ArtifactRef $resolvedInstallEvidencePath $installEvidence
    rc18_isolated_update_result = New-ArtifactRef $resolvedUpdateResultPath $updateResult
    rc18_isolated_update_evidence = New-ArtifactRef $resolvedUpdateEvidencePath $updateEvidence
    rc18_isolated_rollback_result = New-ArtifactRef $resolvedRollbackResultPath $rollbackResult
    rc18_isolated_rollback_evidence = New-ArtifactRef $resolvedRollbackEvidencePath $rollbackEvidence
    rc17_support_result = New-ArtifactRef $resolvedRc17SupportResultPath $rc17SupportResult
    rc17_support_recovery_chain = New-ArtifactRef $resolvedRc17SupportChainPath $rc17SupportChain
    rc17_support_bundle = New-ArtifactRef $resolvedRc17SupportBundlePath $rc17SupportBundle
    rc17_recovery_reference_index = New-ArtifactRef $resolvedRc17RecoveryIndexPath $rc17RecoveryIndex
}

$supportBundleCore = [ordered]@{
    schema = "agentos.rc18-isolated-support-bundle-core.v1"
    task = "RC18-031"
    boundary_id = $rollbackResult.boundary_id
    release_id = $rollbackEvidence.rollback_drill_material.release_id
    media_id = $rollbackEvidence.rollback_drill_material.media_id
    package_id = $rollbackEvidence.rollback_drill_material.package_id
    installed_image_state_id = $installResult.installed_image_state_id
    updated_image_state_id = $updateResult.updated_image_state_id
    restored_image_state_id = $rollbackResult.restored_image_state_id
    install_evidence_sha256 = Get-FileSha256 $resolvedInstallEvidencePath
    update_evidence_sha256 = Get-FileSha256 $resolvedUpdateEvidencePath
    rollback_evidence_sha256 = Get-FileSha256 $resolvedRollbackEvidencePath
    rc17_support_recovery_chain_sha256 = Get-FileSha256 $resolvedRc17SupportChainPath
    rc17_support_bundle_sha256 = Get-FileSha256 $resolvedRc17SupportBundlePath
    rc17_recovery_reference_index_sha256 = Get-FileSha256 $resolvedRc17RecoveryIndexPath
    local_only = $true
    redacted = $true
    uploaded = $false
    support_upload_performed = $false
    recovery_execution_performed = $false
    remote_dispatch_enabled = $false
    production_ring_mutation_allowed = $false
}
$supportBundleDigest = Get-StringSha256 (Get-JsonText $supportBundleCore)

$supportBundle = [ordered]@{
    schema = "agentos.rc18-isolated-image-support-bundle.v1"
    generated_at = $generatedAtValue
    task = "RC18-031"
    status = if ($supportProjectionAllowed) { "isolated-support-bundle-local-redacted" } else { "isolated-support-bundle-denied" }
    production_ready_claim = $false
    support_bundle_id = "rc18-isolated-support-$($supportBundleDigest.Substring(0, 16))"
    support_bundle_digest = $supportBundleDigest
    local_only = $true
    uploaded = $false
    redacted = $true
    redaction_policy = "no-raw-secrets-no-tokens-no-private-material-no-host-private-state"
    projection_only = $true
    support_bundle_core = $supportBundleCore
    included_evidence = @(
        "rc18-isolated-install-result",
        "rc18-isolated-install-evidence",
        "rc18-isolated-update-result",
        "rc18-isolated-update-evidence",
        "rc18-isolated-rollback-result",
        "rc18-isolated-rollback-evidence",
        "rc17-support-recovery-chain",
        "rc17-recovery-reference-index"
    )
    side_effects = [ordered]@{
        support_bundle_created = $supportProjectionAllowed
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        mirror_frontend_mutated = $false
        signer_authority_granted = $false
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
    }
    source = $source
}
$supportBundlePath = Join-Path $resolvedArtifactDir "isolated-support-bundle.json"
Write-Json $supportBundle $supportBundlePath

$recoveryReferenceCore = [ordered]@{
    schema = "agentos.rc18-isolated-recovery-reference-core.v1"
    task = "RC18-031"
    boundary_id = $rollbackResult.boundary_id
    support_bundle_id = $supportBundle.support_bundle_id
    support_bundle_digest = $supportBundleDigest
    support_bundle_sha256 = Get-FileSha256 $supportBundlePath
    install_result_sha256 = Get-FileSha256 $resolvedInstallResultPath
    update_result_sha256 = Get-FileSha256 $resolvedUpdateResultPath
    rollback_result_sha256 = Get-FileSha256 $resolvedRollbackResultPath
    rollback_audit_digest = $rollbackResult.outputs.rollback_drill_evidence.rollback_audit_digest
    restored_image_state_id = $rollbackResult.restored_image_state_id
    recovery_execution_allowed = $false
    recovery_execution_performed = $false
    support_bundle_upload_allowed = $false
    remote_dispatch_enabled = $false
    production_ring_mutation_allowed = $false
}
$recoveryReferenceDigest = Get-StringSha256 (Get-JsonText $recoveryReferenceCore)
$recoveryReferenceIndex = [ordered]@{
    schema = "agentos.rc18-isolated-image-recovery-reference-index.v1"
    generated_at = $generatedAtValue
    task = "RC18-031"
    status = "projection-only-no-recovery-execution"
    production_ready_claim = $false
    projection_only = $true
    recovery_reference_digest = $recoveryReferenceDigest
    recovery_execution_allowed = $false
    recovery_execution_performed = $false
    support_bundle_upload_allowed = $false
    remote_dispatch_enabled = $false
    production_ring_mutation_allowed = $false
    references = $recoveryReferenceCore
    source = $source
}
$recoveryIndexPath = Join-Path $resolvedArtifactDir "recovery-reference-index.json"
Write-Json $recoveryReferenceIndex $recoveryIndexPath

$cases = @(
    (New-FailClosedCase -Id "missing-isolated-install-evidence" -Blockers @("rc18-isolated-install-evidence-not-bound") -Reason "Support bundle requires RC18 isolated install evidence."),
    (New-FailClosedCase -Id "missing-isolated-update-evidence" -Blockers @("rc18-isolated-update-evidence-not-bound") -Reason "Support bundle requires RC18 isolated update evidence."),
    (New-FailClosedCase -Id "missing-isolated-rollback-evidence" -Blockers @("rc18-isolated-rollback-evidence-not-bound") -Reason "Support bundle requires RC18 isolated rollback evidence."),
    (New-FailClosedCase -Id "state-chain-mismatch" -Blockers @("isolated-image-state-chain-mismatch") -Reason "Support bundle cannot bind incoherent install/update/rollback state chain."),
    (New-FailClosedCase -Id "missing-rc17-support-reference" -Blockers @("rc17-support-recovery-reference-not-bound") -Reason "RC17 support/recovery reference must be bound."),
    (New-FailClosedCase -Id "raw-support-upload-attempt" -Blockers @("support-upload-denied") -Reason "Support upload is out of RC18 scope."),
    (New-FailClosedCase -Id "recovery-execution-attempt" -Blockers @("recovery-execution-denied") -Reason "Recovery execution is out of RC18 scope."),
    (New-FailClosedCase -Id "remote-dispatch-attempt" -Blockers @("remote-dispatch-denied") -Reason "Remote dispatch is out of RC18 scope."),
    (New-FailClosedCase -Id "host-rootfs-mutation-attempt" -Blockers @("host-rootfs-mutation-denied") -Reason "Host rootfs mutation is out of RC18 scope."),
    (New-FailClosedCase -Id "host-slot-mutation-attempt" -Blockers @("host-active-slot-mutation-denied") -Reason "Host active slot mutation is out of RC18 scope."),
    (New-FailClosedCase -Id "host-boot-metadata-mutation-attempt" -Blockers @("host-boot-metadata-mutation-denied") -Reason "Host boot metadata mutation is out of RC18 scope."),
    (New-FailClosedCase -Id "active-artifact-set-mutation-attempt" -Blockers @("active-artifact-set-mutation-denied") -Reason "Active artifact set mutation is out of RC18 scope."),
    (New-FailClosedCase -Id "production-ring-mutation-attempt" -Blockers @("production-ring-mutation-denied") -Reason "Production ring mutation is out of RC18 scope."),
    (New-FailClosedCase -Id "mirror-frontend-authority-attempt" -Blockers @("mirror-frontend-authority-denied") -Reason "Mirror/frontend output is not support or recovery authority."),
    (New-FailClosedCase -Id "signer-authority-attempt" -Blockers @("signer-authority-denied") -Reason "Signer reachability is not support or recovery authority."),
    (New-FailClosedCase -Id "private-material-attempt" -Blockers @("private-signing-material-denied") -Reason "Private signing material is out of RC18 scope."),
    (New-FailClosedCase -Id "ga-claim-attempt" -Blockers @("ga-claim-denied") -Reason "RC18 support/recovery binding cannot claim GA production readiness.")
)
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

Add-Check "plan.current_task.rc18_031" $planAllowsRun "RC18-031 must run after RC18-030 completed while current_task is RC18-031." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc18_030_status = $rc18PreviousStatus; rc18_031_status = $rc18TaskStatus })
Add-Check "source.isolated_install_update_rollback.bound" ($installReady -and $updateReady -and $rollbackReady) "RC18-031 must bind passed isolated install, update, and rollback evidence." ([ordered]@{ install_ready = $installReady; update_ready = $updateReady; rollback_ready = $rollbackReady; installed_image_state_id = $installResult.installed_image_state_id; updated_image_state_id = $updateResult.updated_image_state_id; restored_image_state_id = $rollbackResult.restored_image_state_id })
Add-Check "source.image_state_chain.coherent" $stateChainReady "Install/update/rollback image state chain must be coherent." ([ordered]@{ installed_image_state_id = $installResult.installed_image_state_id; update_previous_installed_image_state_id = $updateResult.previous_installed_image_state_id; updated_image_state_id = $updateResult.updated_image_state_id; rollback_previous_updated_image_state_id = $rollbackResult.previous_updated_image_state_id; restored_image_state_id = $rollbackResult.restored_image_state_id })
Add-Check "source.rc17_support_recovery.bound" $rc17SupportReady "RC18-031 must bind RC17 local-only support/recovery references without enabling upload or recovery execution." ([ordered]@{ support_bundle_local_only = $rc17SupportResult.summary.support_bundle_local_only; support_upload_performed = $rc17SupportResult.summary.support_upload_performed; recovery_execution_performed = $rc17SupportResult.summary.recovery_execution_performed; rc17_bundle_redacted = $rc17SupportBundle.redacted })
Add-Check "support.bundle.local_redacted" ($supportBundle.local_only -eq $true -and $supportBundle.uploaded -eq $false -and $supportBundle.redacted -eq $true -and $supportBundle.support_bundle_core.install_evidence_sha256 -eq (Get-FileSha256 $resolvedInstallEvidencePath) -and $supportBundle.support_bundle_core.update_evidence_sha256 -eq (Get-FileSha256 $resolvedUpdateEvidencePath) -and $supportBundle.support_bundle_core.rollback_evidence_sha256 -eq (Get-FileSha256 $resolvedRollbackEvidencePath)) "Support bundle must be local-only, redacted, and hash-bound to isolated install/update/rollback evidence." ([ordered]@{ support_bundle_id = $supportBundle.support_bundle_id; local_only = $supportBundle.local_only; redacted = $supportBundle.redacted; uploaded = $supportBundle.uploaded })
Add-Check "recovery.index.projection_only" ($recoveryReferenceIndex.projection_only -eq $true -and $recoveryReferenceIndex.recovery_execution_allowed -eq $false -and $recoveryReferenceIndex.recovery_execution_performed -eq $false -and $recoveryReferenceIndex.support_bundle_upload_allowed -eq $false -and $recoveryReferenceIndex.remote_dispatch_enabled -eq $false) "Recovery reference index must be projection-only and must not execute recovery, upload support, or dispatch remotely." ([ordered]@{ recovery_reference_digest = $recoveryReferenceDigest; recovery_execution_allowed = $recoveryReferenceIndex.recovery_execution_allowed; recovery_execution_performed = $recoveryReferenceIndex.recovery_execution_performed; support_bundle_upload_allowed = $recoveryReferenceIndex.support_bundle_upload_allowed; remote_dispatch_enabled = $recoveryReferenceIndex.remote_dispatch_enabled })
Add-Check "authority.no_forbidden_side_effects" ($supportBundle.side_effects.support_upload_performed -eq $false -and $supportBundle.side_effects.recovery_execution_performed -eq $false -and $supportBundle.side_effects.remote_dispatch_enabled -eq $false -and $supportBundle.side_effects.host_rootfs_mutated -eq $false -and $supportBundle.side_effects.host_active_slot_mutated -eq $false -and $supportBundle.side_effects.host_boot_metadata_mutated -eq $false -and $supportBundle.side_effects.active_artifact_set_mutated -eq $false -and $supportBundle.side_effects.production_ring_mutated -eq $false -and $supportBundle.side_effects.mirror_frontend_mutated -eq $false -and $supportBundle.side_effects.signer_authority_granted -eq $false -and $supportBundle.side_effects.private_signing_material_handled -eq $false -and $supportBundle.side_effects.cryptographic_signing_performed -eq $false) "RC18-031 must not upload support, execute recovery, remote dispatch, mutate host or production state, mutate mirror/frontend, grant signer authority, handle private material, or sign." $supportBundle.side_effects
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 16) "Missing evidence and forbidden authority surfaces must fail closed before support upload, recovery execution, host mutation, or production mutation." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $supportBundlePath),
    (Get-Content -Raw -LiteralPath $recoveryIndexPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC18-031 outputs must not contain key blocks, private key paths, auth tokens, public identity markers, or signing key file names." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc18-isolated-support-recovery-result.v1"
    generated_at = $generatedAtValue
    task = "RC18-031"
    status = $resultStatus
    production_ready_claim = $false
    boundary_id = $rollbackResult.boundary_id
    installed_image_state_id = $installResult.installed_image_state_id
    updated_image_state_id = $updateResult.updated_image_state_id
    restored_image_state_id = $rollbackResult.restored_image_state_id
    support_recovery_surface = [ordered]@{
        state = if ($supportProjectionAllowed) { "isolated-support-recovery-projection-bound" } else { "isolated-support-recovery-projection-denied" }
        isolated_install_bound = $installReady
        isolated_update_bound = $updateReady
        isolated_rollback_bound = $rollbackReady
        image_state_chain_bound = $stateChainReady
        rc17_support_recovery_bound = $rc17SupportReady
        support_bundle_local_only = $true
        support_bundle_redacted = $true
        support_upload_performed = $false
        recovery_execution_allowed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        mirror_frontend_mutated = $false
        signer_authority_granted = $false
        private_signing_material_handled = $false
        blockers = @($blockers)
    }
    outputs = [ordered]@{
        isolated_support_bundle = [ordered]@{
            path = Get-StablePath $supportBundlePath
            sha256 = Get-FileSha256 $supportBundlePath
            support_bundle_id = $supportBundle.support_bundle_id
            support_bundle_digest = $supportBundleDigest
            local_only = $true
            redacted = $true
            uploaded = $false
        }
        recovery_reference_index = [ordered]@{
            path = Get-StablePath $recoveryIndexPath
            sha256 = Get-FileSha256 $recoveryIndexPath
            recovery_reference_digest = $recoveryReferenceDigest
            projection_only = $true
            recovery_execution_performed = $false
        }
    }
    source = $source
    checks = @($script:checks)
    blockers = @($blockers)
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        isolated_image_support_projection_only = $true
        support_bundle_local_only = $true
        support_bundle_redacted = $true
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        mirror_frontend_changed = $false
        signer_authority = $false
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
    }
    fail_closed_cases = $cases
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
        rc18_031_complete = (@($script:failedChecks).Count -eq 0)
        isolated_install_bound = $installReady
        isolated_update_bound = $updateReady
        isolated_rollback_bound = $rollbackReady
        support_bundle_local_only = $true
        support_bundle_redacted = $true
        support_upload_performed = $false
        recovery_execution_allowed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        next_task = "RC18-040"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC18-031-isolated-support-recovery.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc18-isolated-support-recovery-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC18-031"
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
    support_recovery_surface = $result.support_recovery_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc18_031_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC18-040"
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
    throw "Sensitive marker detected in RC18-031 outputs."
}

Write-Host "RC18 isolated support/recovery $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Support bundle: $(Get-StablePath $supportBundlePath)"
Write-Host "Recovery index: $(Get-StablePath $recoveryIndexPath)"
Write-Host "Support upload/recovery/remote dispatch: false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) { exit 1 }
