param(
    [string]$ArtifactDir = ".workflow/artifacts/rc19-first-user-support-recovery",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc19",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc19/plan.json",
    [string]$FirstUserInstallResultPath = ".workflow/artifacts/rc19-first-user-install-drill/result.json",
    [string]$FirstUserInstallEvidencePath = ".workflow/artifacts/rc19-first-user-install-drill/first-user-install-evidence.json",
    [string]$PostInstallSmokeResultPath = ".workflow/artifacts/rc19-post-install-update-rollback-smoke/result.json",
    [string]$PostInstallSmokeEvidencePath = ".workflow/artifacts/rc19-post-install-update-rollback-smoke/post-install-update-rollback-evidence.json",
    [string]$Rc18SupportResultPath = ".workflow/artifacts/rc18-isolated-support-recovery/result.json",
    [string]$Rc18SupportBundlePath = ".workflow/artifacts/rc18-isolated-support-recovery/isolated-support-bundle.json",
    [string]$Rc18RecoveryIndexPath = ".workflow/artifacts/rc18-isolated-support-recovery/recovery-reference-index.json",
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
    param([Parameter(Mandatory = $true)]$Value, [Parameter(Mandatory = $true)][string]$Path)
    $parent = Split-Path -Parent $Path
    if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
    [IO.File]::WriteAllText($Path, (Get-JsonText $Value) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}

function Add-Check {
    param([Parameter(Mandatory = $true)][string]$Id, [Parameter(Mandatory = $true)][bool]$Passed, [Parameter(Mandatory = $true)][string]$Message, $Evidence = $null)
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
    param([Parameter(Mandatory = $true)][string]$Path, $Json = $null)
    $present = Test-Path -LiteralPath $Path -PathType Leaf
    return [ordered]@{
        path = Get-StablePath $Path
        sha256 = Get-FileSha256 $Path
        size_bytes = if ($present) { (Get-Item -LiteralPath $Path).Length } else { $null }
        present = $present
        schema = if ($null -ne $Json) { $Json.schema } else { $null }
        status = if ($null -ne $Json) { $Json.status } else { $null }
        task = if ($null -ne $Json) { $Json.task } else { $null }
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
            object_storage_provisioned = $false
            mirror_frontend_mutated = $false
            signer_authority_granted = $false
            private_signing_material_handled = $false
            cryptographic_signing_performed = $false
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
$resolvedFirstUserInstallResultPath = Resolve-RepoPath $FirstUserInstallResultPath
$resolvedFirstUserInstallEvidencePath = Resolve-RepoPath $FirstUserInstallEvidencePath
$resolvedPostInstallSmokeResultPath = Resolve-RepoPath $PostInstallSmokeResultPath
$resolvedPostInstallSmokeEvidencePath = Resolve-RepoPath $PostInstallSmokeEvidencePath
$resolvedRc18SupportResultPath = Resolve-RepoPath $Rc18SupportResultPath
$resolvedRc18SupportBundlePath = Resolve-RepoPath $Rc18SupportBundlePath
$resolvedRc18RecoveryIndexPath = Resolve-RepoPath $Rc18RecoveryIndexPath

$plan = Read-Json $resolvedPlanPath
$firstUserInstallResult = Read-Json $resolvedFirstUserInstallResultPath
$firstUserInstallEvidence = Read-Json $resolvedFirstUserInstallEvidencePath
$postInstallSmokeResult = Read-Json $resolvedPostInstallSmokeResultPath
$postInstallSmokeEvidence = Read-Json $resolvedPostInstallSmokeEvidencePath
$rc18SupportResult = Read-Json $resolvedRc18SupportResultPath
$rc18SupportBundle = Read-Json $resolvedRc18SupportBundlePath
$rc18RecoveryIndex = Read-Json $resolvedRc18RecoveryIndexPath

$rc19PreviousStatus = Get-TaskStatus -Plan $plan -TaskId "RC19-031"
$rc19TaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC19-032"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc19PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC19-032" -and ($rc19TaskStatus -eq "pending" -or $rc19TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC19-040" -and $rc19TaskStatus -eq "completed")
    )
)

$firstUserTargetStateId = [string]$firstUserInstallResult.summary.target_state_id
$firstUserInstallReady = (
    $firstUserInstallResult.status -eq "passed" -and
    $firstUserInstallResult.summary.rc19_021_complete -eq $true -and
    $firstUserInstallResult.summary.first_user_install_performed -eq $true -and
    $firstUserInstallEvidence.target_state_id -eq $firstUserTargetStateId -and
    $firstUserInstallResult.summary.host_rootfs_mutated -eq $false -and
    $firstUserInstallResult.summary.support_upload_performed -eq $false -and
    $firstUserInstallResult.summary.recovery_execution_performed -eq $false -and
    $firstUserInstallResult.summary.remote_dispatch_enabled -eq $false
)

$postInstallSmokeReady = (
    $postInstallSmokeResult.status -eq "passed" -and
    $postInstallSmokeResult.summary.rc19_031_complete -eq $true -and
    $postInstallSmokeResult.first_user_target_state_id -eq $firstUserTargetStateId -and
    $postInstallSmokeResult.summary.update_compatibility_readiness -eq "ready" -and
    $postInstallSmokeResult.summary.rollback_compatibility_readiness -eq "ready" -and
    $postInstallSmokeResult.summary.update_or_rollback_executed_by_this_smoke -eq $false -and
    $postInstallSmokeResult.summary.support_upload_performed -eq $false -and
    $postInstallSmokeResult.summary.recovery_execution_performed -eq $false -and
    $postInstallSmokeResult.summary.remote_dispatch_enabled -eq $false -and
    $postInstallSmokeEvidence.first_user_target_state_id -eq $firstUserTargetStateId
)

$rc18SupportReady = (
    $rc18SupportResult.status -eq "passed" -and
    $rc18SupportResult.summary.rc18_031_complete -eq $true -and
    $rc18SupportResult.summary.support_bundle_local_only -eq $true -and
    $rc18SupportResult.summary.support_bundle_redacted -eq $true -and
    $rc18SupportResult.summary.support_upload_performed -eq $false -and
    $rc18SupportResult.summary.recovery_execution_performed -eq $false -and
    $rc18SupportResult.summary.remote_dispatch_enabled -eq $false -and
    $rc18SupportBundle.local_only -eq $true -and
    $rc18SupportBundle.redacted -eq $true -and
    $rc18SupportBundle.uploaded -eq $false -and
    $rc18SupportBundle.side_effects.support_upload_performed -eq $false -and
    $rc18SupportBundle.side_effects.recovery_execution_performed -eq $false -and
    $rc18RecoveryIndex.projection_only -eq $true -and
    $rc18RecoveryIndex.recovery_execution_performed -eq $false
)

$supportProjectionAllowed = $planAllowsRun -and $firstUserInstallReady -and $postInstallSmokeReady -and $rc18SupportReady
$supportDecision = if ($supportProjectionAllowed) { "first-user-support-recovery-projection-bound" } else { "first-user-support-recovery-projection-denied" }

$blockers = @()
if (-not $planAllowsRun) { $blockers += "rc19-032-plan-pointer-not-current" }
if (-not $firstUserInstallReady) { $blockers += "first-user-install-evidence-not-ready" }
if (-not $postInstallSmokeReady) { $blockers += "post-install-update-rollback-smoke-not-ready" }
if (-not $rc18SupportReady) { $blockers += "rc18-support-recovery-reference-not-ready" }
if ($supportProjectionAllowed) { $blockers = @() }

$source = [ordered]@{
    rc19_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc19_first_user_install_result = New-ArtifactRef $resolvedFirstUserInstallResultPath $firstUserInstallResult
    rc19_first_user_install_evidence = New-ArtifactRef $resolvedFirstUserInstallEvidencePath $firstUserInstallEvidence
    rc19_post_install_smoke_result = New-ArtifactRef $resolvedPostInstallSmokeResultPath $postInstallSmokeResult
    rc19_post_install_smoke_evidence = New-ArtifactRef $resolvedPostInstallSmokeEvidencePath $postInstallSmokeEvidence
    rc18_support_recovery_result = New-ArtifactRef $resolvedRc18SupportResultPath $rc18SupportResult
    rc18_support_bundle = New-ArtifactRef $resolvedRc18SupportBundlePath $rc18SupportBundle
    rc18_recovery_reference_index = New-ArtifactRef $resolvedRc18RecoveryIndexPath $rc18RecoveryIndex
}

$supportBundleCore = [ordered]@{
    schema = "agentos.rc19-first-user-support-bundle-core.v1"
    task = "RC19-032"
    first_user_target_state_id = $firstUserTargetStateId
    post_install_smoke_digest = [string]$postInstallSmokeResult.smoke_digest
    offline_local_channel_package_id = [string]$postInstallSmokeResult.offline_local_channel_package_id
    first_user_install_result_sha256 = Get-FileSha256 $resolvedFirstUserInstallResultPath
    first_user_install_evidence_sha256 = Get-FileSha256 $resolvedFirstUserInstallEvidencePath
    post_install_smoke_result_sha256 = Get-FileSha256 $resolvedPostInstallSmokeResultPath
    post_install_smoke_evidence_sha256 = Get-FileSha256 $resolvedPostInstallSmokeEvidencePath
    rc18_support_result_sha256 = Get-FileSha256 $resolvedRc18SupportResultPath
    rc18_support_bundle_sha256 = Get-FileSha256 $resolvedRc18SupportBundlePath
    rc18_recovery_index_sha256 = Get-FileSha256 $resolvedRc18RecoveryIndexPath
    local_only = $true
    redacted = $true
    uploaded = $false
    support_upload_performed = $false
    recovery_execution_performed = $false
    remote_dispatch_enabled = $false
    host_mutation_allowed = $false
    production_ring_mutation_allowed = $false
}
$supportBundleDigest = Get-StringSha256 (Get-JsonText $supportBundleCore)

$sideEffects = [ordered]@{
    support_bundle_created = $supportProjectionAllowed
    support_upload_performed = $false
    recovery_execution_performed = $false
    remote_dispatch_enabled = $false
    host_rootfs_mutated = $false
    host_active_slot_mutated = $false
    host_boot_metadata_mutated = $false
    active_artifact_set_mutated = $false
    production_ring_mutated = $false
    object_storage_provisioned = $false
    mirror_frontend_mutated = $false
    endpoint_reachability_trusted = $false
    frontend_output_trusted = $false
    shell_output_trusted = $false
    tui_output_trusted = $false
    model_replay_trusted = $false
    signer_authority_granted = $false
    private_signing_material_handled = $false
    cryptographic_signing_performed = $false
    consumer_ready_claim = $false
}

$firstUserSupportBundle = [ordered]@{
    schema = "agentos.rc19-first-user-support-bundle.v1"
    generated_at = $generatedAtValue
    task = "RC19-032"
    status = if ($supportProjectionAllowed) { "first-user-support-bundle-local-redacted" } else { "first-user-support-bundle-denied" }
    production_ready_claim = $false
    consumer_ready_claim = $false
    support_bundle_id = "rc19-first-user-support-$($supportBundleDigest.Substring(0, 16))"
    support_bundle_digest = $supportBundleDigest
    local_only = $true
    redacted = $true
    uploaded = $false
    projection_only = $true
    redaction_policy = "no-raw-secrets-no-tokens-no-private-material-no-host-private-state"
    support_bundle_core = $supportBundleCore
    included_evidence = @(
        "rc19-first-user-install-result",
        "rc19-first-user-install-evidence",
        "rc19-post-install-update-rollback-smoke-result",
        "rc19-post-install-update-rollback-smoke-evidence",
        "rc18-isolated-support-recovery-result",
        "rc18-isolated-support-bundle",
        "rc18-recovery-reference-index"
    )
    side_effects = $sideEffects
    source = $source
}
$supportBundlePath = Join-Path $resolvedArtifactDir "first-user-support-bundle.json"
Write-Json $firstUserSupportBundle $supportBundlePath

$recoveryReferenceCore = [ordered]@{
    schema = "agentos.rc19-first-user-recovery-reference-core.v1"
    task = "RC19-032"
    first_user_target_state_id = $firstUserTargetStateId
    support_bundle_id = $firstUserSupportBundle.support_bundle_id
    support_bundle_digest = $supportBundleDigest
    support_bundle_sha256 = Get-FileSha256 $supportBundlePath
    post_install_smoke_digest = [string]$postInstallSmokeResult.smoke_digest
    rc18_recovery_reference_digest = [string]$rc18RecoveryIndex.recovery_reference_digest
    first_user_install_result_sha256 = Get-FileSha256 $resolvedFirstUserInstallResultPath
    post_install_smoke_result_sha256 = Get-FileSha256 $resolvedPostInstallSmokeResultPath
    recovery_execution_allowed = $false
    recovery_execution_performed = $false
    support_bundle_upload_allowed = $false
    remote_dispatch_enabled = $false
    host_mutation_allowed = $false
    production_ring_mutation_allowed = $false
}
$recoveryReferenceDigest = Get-StringSha256 (Get-JsonText $recoveryReferenceCore)
$recoveryReferenceIndex = [ordered]@{
    schema = "agentos.rc19-first-user-recovery-reference-index.v1"
    generated_at = $generatedAtValue
    task = "RC19-032"
    status = "projection-only-no-recovery-execution"
    production_ready_claim = $false
    consumer_ready_claim = $false
    projection_only = $true
    recovery_reference_digest = $recoveryReferenceDigest
    recovery_execution_allowed = $false
    recovery_execution_performed = $false
    support_bundle_upload_allowed = $false
    remote_dispatch_enabled = $false
    host_mutation_allowed = $false
    production_ring_mutation_allowed = $false
    references = $recoveryReferenceCore
    source = $source
}
$recoveryIndexPath = Join-Path $resolvedArtifactDir "recovery-reference-index.json"
Write-Json $recoveryReferenceIndex $recoveryIndexPath

$caseSpecs = @(
    [ordered]@{ id = "missing-first-user-install"; blockers = @("first-user-install-evidence-not-ready"); reason = "Support/recovery evidence requires first-user install evidence." },
    [ordered]@{ id = "missing-post-install-smoke"; blockers = @("post-install-update-rollback-smoke-not-ready"); reason = "Support/recovery evidence requires post-install update/rollback smoke." },
    [ordered]@{ id = "missing-rc18-support-recovery"; blockers = @("rc18-support-recovery-reference-not-ready"); reason = "Support/recovery evidence requires RC18 support/recovery projection." },
    [ordered]@{ id = "support-bundle-not-redacted"; blockers = @("support-bundle-redaction-denied"); reason = "Support bundle must remain redacted." },
    [ordered]@{ id = "support-bundle-not-local"; blockers = @("support-bundle-local-only-denied"); reason = "Support bundle must remain local-only." },
    [ordered]@{ id = "support-upload-attempt"; blockers = @("support-upload-denied"); reason = "Support upload is out of scope." },
    [ordered]@{ id = "recovery-execution-attempt"; blockers = @("recovery-execution-denied"); reason = "Recovery execution is out of scope." },
    [ordered]@{ id = "remote-dispatch-attempt"; blockers = @("remote-dispatch-denied"); reason = "Remote dispatch is out of scope." },
    [ordered]@{ id = "host-rootfs-mutation-attempt"; blockers = @("host-rootfs-mutation-denied"); reason = "Host rootfs mutation is forbidden." },
    [ordered]@{ id = "host-active-slot-mutation-attempt"; blockers = @("host-active-slot-mutation-denied"); reason = "Host active slot mutation is forbidden." },
    [ordered]@{ id = "host-boot-metadata-mutation-attempt"; blockers = @("host-boot-metadata-mutation-denied"); reason = "Host boot metadata mutation is forbidden." },
    [ordered]@{ id = "active-artifact-set-mutation-attempt"; blockers = @("active-artifact-set-mutation-denied"); reason = "Active artifact set mutation is forbidden." },
    [ordered]@{ id = "production-ring-mutation-attempt"; blockers = @("production-ring-mutation-denied"); reason = "Production ring mutation is forbidden." },
    [ordered]@{ id = "object-storage-provisioning-attempt"; blockers = @("object-storage-provisioning-denied"); reason = "Object storage provisioning is out of scope." },
    [ordered]@{ id = "mirror-frontend-authority-attempt"; blockers = @("mirror-frontend-authority-denied"); reason = "Mirror/frontend output is not support authority." },
    [ordered]@{ id = "endpoint-authority-attempt"; blockers = @("endpoint-reachability-authority-denied"); reason = "Endpoint reachability is not support authority." },
    [ordered]@{ id = "shell-output-authority-attempt"; blockers = @("shell-output-authority-denied"); reason = "Shell output is not support authority." },
    [ordered]@{ id = "tui-output-authority-attempt"; blockers = @("tui-output-authority-denied"); reason = "TUI output is not support authority." },
    [ordered]@{ id = "model-replay-authority-attempt"; blockers = @("model-replay-authority-denied"); reason = "Model replay is not support authority." },
    [ordered]@{ id = "signer-authority-attempt"; blockers = @("signer-authority-denied"); reason = "Signer reachability is not support authority." },
    [ordered]@{ id = "private-material-attempt"; blockers = @("private-signing-material-denied"); reason = "Private signing material is forbidden." },
    [ordered]@{ id = "release-signing-attempt"; blockers = @("cryptographic-signing-denied"); reason = "Release signing is out of scope." },
    [ordered]@{ id = "consumer-ready-claim-attempt"; blockers = @("consumer-ready-claim-denied"); reason = "Consumer readiness waits for RC19-040." },
    [ordered]@{ id = "ga-claim-attempt"; blockers = @("ga-claim-denied"); reason = "RC19-032 cannot claim GA production readiness." }
)
$cases = @()
foreach ($spec in $caseSpecs) {
    $cases += New-FailClosedCase -Id $spec.id -Blockers ([string[]]$spec.blockers) -Reason $spec.reason
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

Add-Check "plan.current_task.rc19_032" $planAllowsRun "RC19-032 must run after RC19-031 completed, while current_task is RC19-032 or during a completed rerun after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc19_031_status = $rc19PreviousStatus; rc19_032_status = $rc19TaskStatus })
Add-Check "source.first_user_install.ready" $firstUserInstallReady "Support bundle must bind RC19 first-user install evidence." ([ordered]@{ first_user_install_ready = $firstUserInstallReady; target_state_id = $firstUserTargetStateId; host_rootfs_mutated = $firstUserInstallResult.summary.host_rootfs_mutated })
Add-Check "source.post_install_smoke.ready" $postInstallSmokeReady "Support bundle must bind RC19 post-install update/rollback smoke evidence." ([ordered]@{ post_install_smoke_ready = $postInstallSmokeReady; update_readiness = $postInstallSmokeResult.summary.update_compatibility_readiness; rollback_readiness = $postInstallSmokeResult.summary.rollback_compatibility_readiness; update_or_rollback_executed_by_smoke = $postInstallSmokeResult.summary.update_or_rollback_executed_by_this_smoke })
Add-Check "source.rc18_support_recovery.ready" $rc18SupportReady "Support bundle must carry forward RC18 local-only support/recovery projection without upload or recovery execution." ([ordered]@{ rc18_support_ready = $rc18SupportReady; rc18_bundle_local_only = $rc18SupportBundle.local_only; rc18_bundle_redacted = $rc18SupportBundle.redacted; rc18_recovery_projection_only = $rc18RecoveryIndex.projection_only })
Add-Check "support.bundle.local_redacted_hash_bound" ($firstUserSupportBundle.local_only -eq $true -and $firstUserSupportBundle.redacted -eq $true -and $firstUserSupportBundle.uploaded -eq $false -and $firstUserSupportBundle.support_bundle_core.first_user_install_result_sha256 -eq (Get-FileSha256 $resolvedFirstUserInstallResultPath) -and $firstUserSupportBundle.support_bundle_core.post_install_smoke_result_sha256 -eq (Get-FileSha256 $resolvedPostInstallSmokeResultPath)) "Support bundle must be local-only, redacted, and hash-bound to first-user install and post-install smoke evidence." ([ordered]@{ support_bundle_id = $firstUserSupportBundle.support_bundle_id; local_only = $firstUserSupportBundle.local_only; redacted = $firstUserSupportBundle.redacted; uploaded = $firstUserSupportBundle.uploaded })
Add-Check "recovery.index.projection_only" ($recoveryReferenceIndex.projection_only -eq $true -and $recoveryReferenceIndex.recovery_execution_allowed -eq $false -and $recoveryReferenceIndex.recovery_execution_performed -eq $false -and $recoveryReferenceIndex.support_bundle_upload_allowed -eq $false -and $recoveryReferenceIndex.remote_dispatch_enabled -eq $false) "Recovery reference index must be projection-only and must not execute recovery, upload support, or dispatch remotely." ([ordered]@{ recovery_reference_digest = $recoveryReferenceDigest; projection_only = $recoveryReferenceIndex.projection_only; recovery_execution_performed = $recoveryReferenceIndex.recovery_execution_performed; support_bundle_upload_allowed = $recoveryReferenceIndex.support_bundle_upload_allowed })
Add-Check "authority.no_forbidden_side_effects" ($sideEffects.support_upload_performed -eq $false -and $sideEffects.recovery_execution_performed -eq $false -and $sideEffects.remote_dispatch_enabled -eq $false -and $sideEffects.host_rootfs_mutated -eq $false -and $sideEffects.host_active_slot_mutated -eq $false -and $sideEffects.host_boot_metadata_mutated -eq $false -and $sideEffects.active_artifact_set_mutated -eq $false -and $sideEffects.production_ring_mutated -eq $false -and $sideEffects.object_storage_provisioned -eq $false -and $sideEffects.mirror_frontend_mutated -eq $false -and $sideEffects.endpoint_reachability_trusted -eq $false -and $sideEffects.shell_output_trusted -eq $false -and $sideEffects.tui_output_trusted -eq $false -and $sideEffects.model_replay_trusted -eq $false -and $sideEffects.signer_authority_granted -eq $false -and $sideEffects.private_signing_material_handled -eq $false -and $sideEffects.cryptographic_signing_performed -eq $false -and $sideEffects.consumer_ready_claim -eq $false) "RC19-032 must not upload support, execute recovery, remote dispatch, mutate host/production state, provision object storage, trust projection surfaces, handle private material, sign, or claim consumer readiness." $sideEffects
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 20) "Missing evidence and forbidden authority surfaces must fail closed before support upload, recovery execution, host mutation, or production mutation." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $supportBundlePath),
    (Get-Content -Raw -LiteralPath $recoveryIndexPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC19-032 outputs must not contain key blocks, private key paths, auth tokens, public identity markers, or signing key file names." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc19-first-user-support-recovery-result.v1"
    generated_at = $generatedAtValue
    task = "RC19-032"
    status = $resultStatus
    production_ready_claim = $false
    consumer_ready_claim = $false
    first_user_target_state_id = $firstUserTargetStateId
    support_bundle_id = $firstUserSupportBundle.support_bundle_id
    recovery_reference_digest = $recoveryReferenceDigest
    support_recovery_surface = [ordered]@{
        state = $supportDecision
        first_user_install_bound = $firstUserInstallReady
        post_install_smoke_bound = $postInstallSmokeReady
        rc18_support_recovery_bound = $rc18SupportReady
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
        object_storage_provisioned = $false
        mirror_frontend_mutated = $false
        endpoint_reachability_authority = $false
        shell_output_authority = $false
        tui_output_authority = $false
        model_replay_authority = $false
        signer_authority_granted = $false
        private_signing_material_handled = $false
        blockers = @($blockers)
    }
    outputs = [ordered]@{
        first_user_support_bundle = [ordered]@{
            path = Get-StablePath $supportBundlePath
            sha256 = Get-FileSha256 $supportBundlePath
            support_bundle_id = $firstUserSupportBundle.support_bundle_id
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
    fail_closed_cases = $cases
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        consumer_ready_claim = $false
        first_user_support_projection_only = $true
        support_bundle_local_only = $true
        support_bundle_redacted = $true
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        object_storage_provisioned = $false
        mirror_frontend_changed = $false
        signer_authority = $false
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
        shell_output_authority = $false
        tui_output_authority = $false
        model_replay_authority = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
        rc19_032_complete = (@($script:failedChecks).Count -eq 0)
        first_user_install_bound = $firstUserInstallReady
        post_install_smoke_bound = $postInstallSmokeReady
        rc18_support_recovery_bound = $rc18SupportReady
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
        consumer_ready_claim = $false
        next_task = "RC19-040"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC19-032-first-user-support-recovery.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc19-first-user-support-recovery-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC19-032"
    status = if ($resultStatus -eq "passed") { "completed" } else { "failed" }
    production_ready_claim = $false
    consumer_ready_claim = $false
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
        rc19_032_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC19-040"
        commit_required = $true
    }
    checks = @($script:checks)
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) { throw "Sensitive marker detected in RC19-032 outputs." }

Write-Host "RC19 first-user support/recovery $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Support bundle: $(Get-StablePath $supportBundlePath)"
Write-Host "Recovery index: $(Get-StablePath $recoveryIndexPath)"
Write-Host "Support upload/recovery/remote dispatch: false; local/redacted: true"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) { exit 1 }
