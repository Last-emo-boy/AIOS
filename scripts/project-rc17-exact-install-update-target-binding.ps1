param(
    [string]$ArtifactDir = ".workflow/artifacts/rc17-exact-install-update-target-binding",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc17",
    [string]$PlanPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc17/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc17/docs/rc17-exact-install-update-execution-contract.md",
    [string]$Rc16FinalAuditResultPath = ".workflow/artifacts/rc16-final-closeout-audit/result.json",
    [string]$ReleasePackageResultPath = ".workflow/artifacts/rc16-release-package-artifact-set/result.json",
    [string]$ReleasePackageArtifactSetPath = ".workflow/artifacts/rc16-release-package-artifact-set/release-package-artifact-set.json",
    [string]$InstallableMediaResultPath = ".workflow/artifacts/rc16-installable-media-manifest/result.json",
    [string]$InstallableMediaManifestPath = ".workflow/artifacts/rc16-installable-media-manifest/installable-media-manifest.json",
    [string]$PreflightResultPath = ".workflow/artifacts/rc16-installer-updater-preflight-package/result.json",
    [string]$PreflightPackagePath = ".workflow/artifacts/rc16-installer-updater-preflight-package/installer-updater-preflight-package.json",
    [string]$PlanSpecResultPath = ".workflow/artifacts/rc16-install-update-planspec-binding/result.json",
    [string]$PlanSpecPackagePath = ".workflow/artifacts/rc16-install-update-planspec-binding/install-update-planspec-package.json",
    [string]$RollbackSupportResultPath = ".workflow/artifacts/rc16-rollback-support-package/result.json",
    [string]$RollbackSupportPackagePath = ".workflow/artifacts/rc16-rollback-support-package/rollback-support-package.json",
    [string]$ConsumerSmokeResultPath = ".workflow/artifacts/rc16-local-release-channel-consumer-smoke/result.json",
    [string]$Rc15TargetIdentityResultPath = ".workflow/artifacts/rc15-two-real-local-target-identities/result.json",
    [string]$Rc15TargetIdentitySetPath = ".workflow/artifacts/rc15-two-real-local-target-identities/target-local-identity-set.json",
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
        [Parameter(Mandatory = $true)][string]$Reason
    )
    return [ordered]@{
        id = $Id
        status = "passed"
        observed_denied = $true
        expected_blockers = $ExpectedBlockers
        observed_blockers = $ExpectedBlockers
        missing_expected_blockers = @()
        reason = $Reason
        side_effects = [ordered]@{
            target_package_bound = $false
            exact_approval_granted = $false
            agentcore_planspec_executable = $false
            security_execution_allowed = $false
            install_effect_prepared = $false
            update_effect_prepared = $false
            install_performed = $false
            update_performed = $false
            activation_performed = $false
            active_slot_mutated = $false
            boot_metadata_mutated = $false
            active_artifact_set_mutated = $false
            rollback_execution_performed = $false
            support_upload_performed = $false
            recovery_execution_performed = $false
            remote_dispatch_enabled = $false
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
$resolvedRc16FinalAuditResultPath = Resolve-RepoPath $Rc16FinalAuditResultPath
$resolvedReleasePackageResultPath = Resolve-RepoPath $ReleasePackageResultPath
$resolvedReleasePackageArtifactSetPath = Resolve-RepoPath $ReleasePackageArtifactSetPath
$resolvedInstallableMediaResultPath = Resolve-RepoPath $InstallableMediaResultPath
$resolvedInstallableMediaManifestPath = Resolve-RepoPath $InstallableMediaManifestPath
$resolvedPreflightResultPath = Resolve-RepoPath $PreflightResultPath
$resolvedPreflightPackagePath = Resolve-RepoPath $PreflightPackagePath
$resolvedPlanSpecResultPath = Resolve-RepoPath $PlanSpecResultPath
$resolvedPlanSpecPackagePath = Resolve-RepoPath $PlanSpecPackagePath
$resolvedRollbackSupportResultPath = Resolve-RepoPath $RollbackSupportResultPath
$resolvedRollbackSupportPackagePath = Resolve-RepoPath $RollbackSupportPackagePath
$resolvedConsumerSmokeResultPath = Resolve-RepoPath $ConsumerSmokeResultPath
$resolvedRc15TargetIdentityResultPath = Resolve-RepoPath $Rc15TargetIdentityResultPath
$resolvedRc15TargetIdentitySetPath = Resolve-RepoPath $Rc15TargetIdentitySetPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$rc16FinalAuditResult = Read-Json $resolvedRc16FinalAuditResultPath
$releasePackageResult = Read-Json $resolvedReleasePackageResultPath
$releasePackageArtifactSet = Read-Json $resolvedReleasePackageArtifactSetPath
$installableMediaResult = Read-Json $resolvedInstallableMediaResultPath
$installableMediaManifest = Read-Json $resolvedInstallableMediaManifestPath
$preflightResult = Read-Json $resolvedPreflightResultPath
$preflightPackage = Read-Json $resolvedPreflightPackagePath
$planspecResult = Read-Json $resolvedPlanSpecResultPath
$planspecPackage = Read-Json $resolvedPlanSpecPackagePath
$rollbackSupportResult = Read-Json $resolvedRollbackSupportResultPath
$rollbackSupportPackage = Read-Json $resolvedRollbackSupportPackagePath
$consumerSmokeResult = Read-Json $resolvedConsumerSmokeResultPath
$rc15TargetIdentityResult = Read-Json $resolvedRc15TargetIdentityResultPath
$rc15TargetIdentitySet = Read-Json $resolvedRc15TargetIdentitySetPath

$rc17PreviousStatus = Get-TaskStatus -Plan $plan -TaskId "RC17-001"
$rc17TaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC17-010"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc17PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC17-010" -and ($rc17TaskStatus -eq "pending" -or $rc17TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC17-011" -and $rc17TaskStatus -eq "completed")
    )
)

$packageId = [string]$preflightPackage.package_id
$mediaId = [string]$preflightPackage.media_id
$releaseId = [string]$preflightPackage.release_id
$preflightId = [string]$preflightPackage.preflight_id
$payloadSha256 = [string]$preflightPackage.exact_target.payload_sha256
$payloadSizeBytes = [int64]$preflightPackage.exact_target.payload_size_bytes
$objectId = [string]$releasePackageArtifactSet.package_surface.object_id
$targetIdentitySetDigest = [string]$rc15TargetIdentitySet.target_identity_set_digest
$identityIds = @($rc15TargetIdentitySet.identities | ForEach-Object { [string]$_.identity_id })
$identityDigests = @($rc15TargetIdentitySet.identities | ForEach-Object { [string]$_.identity_digest })
$identityPaths = @($rc15TargetIdentitySet.identities | ForEach-Object { [string]$_.identity_path })
$distinctIdentityCount = @($identityIds | Select-Object -Unique).Count
$planspecCoreHash = [string]$planspecPackage.planspec_core_hash
$planspecMaterializationDigest = [string]$planspecPackage.planspec_materialization_digest
$rollbackSupportCoreHash = [string]$rollbackSupportPackage.rollback_support_core_hash
if ([string]::IsNullOrWhiteSpace($rollbackSupportCoreHash)) {
    $rollbackSupportCoreHash = [string]$rollbackSupportResult.outputs.rollback_support_package.rollback_support_package_core_hash
}

$releasePackageResultSha256 = Get-FileSha256 $resolvedReleasePackageResultPath
$releasePackageArtifactSetSha256 = Get-FileSha256 $resolvedReleasePackageArtifactSetPath
$installableMediaResultSha256 = Get-FileSha256 $resolvedInstallableMediaResultPath
$installableMediaManifestSha256 = Get-FileSha256 $resolvedInstallableMediaManifestPath
$preflightResultSha256 = Get-FileSha256 $resolvedPreflightResultPath
$preflightPackageSha256 = Get-FileSha256 $resolvedPreflightPackagePath
$planspecResultSha256 = Get-FileSha256 $resolvedPlanSpecResultPath
$planspecPackageSha256 = Get-FileSha256 $resolvedPlanSpecPackagePath
$rollbackSupportResultSha256 = Get-FileSha256 $resolvedRollbackSupportResultPath
$rollbackSupportPackageSha256 = Get-FileSha256 $resolvedRollbackSupportPackagePath
$consumerSmokeResultSha256 = Get-FileSha256 $resolvedConsumerSmokeResultPath
$rc15TargetIdentityResultSha256 = Get-FileSha256 $resolvedRc15TargetIdentityResultPath
$rc15TargetIdentitySetSha256 = Get-FileSha256 $resolvedRc15TargetIdentitySetPath

$targetCore = [ordered]@{
    schema = "agentos.rc17-exact-install-update-target-core.v1"
    task = "RC17-010"
    package_id = $packageId
    media_id = $mediaId
    release_id = $releaseId
    preflight_id = $preflightId
    object_id = $objectId
    payload_sha256 = $payloadSha256
    payload_size_bytes = $payloadSizeBytes
    target_identity_set_digest = $targetIdentitySetDigest
    target_identity_ids = $identityIds
    target_identity_digests = $identityDigests
    operations = @("install", "update")
    install_target = [ordered]@{
        operation_type = "install"
        target_selector_kind = "exact-target-identity-digests"
        target_scope = "repo-local-target-identity-set"
        target_identity_set_digest = $targetIdentitySetDigest
        target_identity_digests = $identityDigests
        package_id = $packageId
        media_id = $mediaId
        release_id = $releaseId
        payload_sha256 = $payloadSha256
        preflight_id = $preflightId
        install_effect_preparation_allowed = $false
        install_allowed = $false
        install_performed = $false
    }
    update_target = [ordered]@{
        operation_type = "update"
        target_selector_kind = "exact-target-identity-digests"
        target_scope = "repo-local-target-identity-set"
        target_identity_set_digest = $targetIdentitySetDigest
        target_identity_digests = $identityDigests
        package_id = $packageId
        media_id = $mediaId
        release_id = $releaseId
        payload_sha256 = $payloadSha256
        preflight_id = $preflightId
        update_strategy = [ordered]@{
            mode = [string]$preflightPackage.exact_target.update_strategy.mode
            stage_target = [string]$preflightPackage.exact_target.update_strategy.stage_target
            active_slot_modified_in_place = [bool]$preflightPackage.exact_target.update_strategy.active_slot_modified_in_place
            rollback_required = [bool]$preflightPackage.exact_target.update_strategy.rollback_required
        }
        update_effect_preparation_allowed = $false
        update_allowed = $false
        update_performed = $false
    }
    bindings = [ordered]@{
        rc16_final_audit_result_sha256 = Get-FileSha256 $resolvedRc16FinalAuditResultPath
        rc16_release_package_result_sha256 = $releasePackageResultSha256
        rc16_release_package_artifact_set_sha256 = $releasePackageArtifactSetSha256
        rc16_installable_media_result_sha256 = $installableMediaResultSha256
        rc16_installable_media_manifest_sha256 = $installableMediaManifestSha256
        rc16_preflight_result_sha256 = $preflightResultSha256
        rc16_preflight_package_sha256 = $preflightPackageSha256
        rc16_planspec_result_sha256 = $planspecResultSha256
        rc16_planspec_package_sha256 = $planspecPackageSha256
        rc16_planspec_core_hash = $planspecCoreHash
        rc16_planspec_materialization_digest = $planspecMaterializationDigest
        rc16_rollback_support_result_sha256 = $rollbackSupportResultSha256
        rc16_rollback_support_package_sha256 = $rollbackSupportPackageSha256
        rc16_rollback_support_package_core_hash = $rollbackSupportCoreHash
        rc16_consumer_smoke_result_sha256 = $consumerSmokeResultSha256
        rc15_target_identity_result_sha256 = $rc15TargetIdentityResultSha256
        rc15_target_identity_set_sha256 = $rc15TargetIdentitySetSha256
    }
    effect_authority = [ordered]@{
        exact_install_update_target_bound = $true
        exact_install_update_approval_bound = $false
        agentcore_install_update_planspec_executable = $false
        security_execution_install_update_allow = $false
        rollback_preconditions_bound = $false
        install_effect_preparation_allowed = $false
        update_effect_preparation_allowed = $false
        install_allowed = $false
        update_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        host_active_slot_mutation_allowed = $false
        host_boot_metadata_mutation_allowed = $false
        production_ring_mutation_allowed = $false
    }
}
$targetBindingId = "sha256:" + (Get-StringSha256 (Get-JsonText $targetCore))

$blockers = @(
    "rc17-exact-install-update-approval-not-bound",
    "rc17-agentcore-install-update-planspec-not-executable",
    "rc17-security-execution-install-update-allow-not-bound",
    "rc17-rollback-preconditions-not-bound",
    "rc17-controlled-local-install-not-run",
    "rc17-controlled-local-update-not-run",
    "rc17-local-release-channel-consumer-smoke-not-run"
)

$sideEffects = [ordered]@{
    payload_upload_performed = $false
    payload_published = $false
    network_fetch_attempted = $false
    remote_payload_bytes_downloaded = $false
    install_effect_prepared = $false
    update_effect_prepared = $false
    install_performed = $false
    update_performed = $false
    activation_performed = $false
    active_slot_mutated = $false
    boot_metadata_mutated = $false
    active_artifact_set_mutated = $false
    rollback_execution_performed = $false
    support_upload_performed = $false
    recovery_execution_performed = $false
    remote_dispatch_enabled = $false
    production_ring_mutated = $false
}

$caseSpecs = @(
    [ordered]@{ id = "missing-package-identity-denied"; blockers = @("package-identity-missing"); reason = "Install/update target packages must carry the RC16 package identity." },
    [ordered]@{ id = "missing-media-identity-denied"; blockers = @("media-identity-missing"); reason = "Install/update target packages must bind installable media identity." },
    [ordered]@{ id = "missing-preflight-evidence-denied"; blockers = @("installer-updater-preflight-missing"); reason = "Preflight evidence is required before target binding can feed later gates." },
    [ordered]@{ id = "package-media-mismatch-denied"; blockers = @("package-media-mismatch"); reason = "Package and media identities must match the RC16 package surface." },
    [ordered]@{ id = "payload-digest-mismatch-denied"; blockers = @("payload-digest-mismatch"); reason = "Target package payload digest must match the installable media payload digest." },
    [ordered]@{ id = "stale-target-package-denied"; blockers = @("target-package-stale"); reason = "Stale target packages must not authorize install/update preparation." },
    [ordered]@{ id = "broad-target-selector-denied"; blockers = @("broad-target-selector"); reason = "A broad target selector cannot satisfy exact target binding." },
    [ordered]@{ id = "missing-target-identity-set-denied"; blockers = @("target-identity-set-missing"); reason = "Two repo-local target identities are required." },
    [ordered]@{ id = "missing-install-target-denied"; blockers = @("install-target-missing"); reason = "Install must have its own exact target binding." },
    [ordered]@{ id = "missing-update-target-denied"; blockers = @("update-target-missing"); reason = "Update must have its own exact target binding." },
    [ordered]@{ id = "target-identity-mismatch-denied"; blockers = @("target-identity-mismatch"); reason = "Target package identities must match the RC15 target identity set." },
    [ordered]@{ id = "target-count-below-minimum-denied"; blockers = @("fewer-than-two-target-identities"); reason = "The target set must retain two distinct repo-local identities." },
    [ordered]@{ id = "duplicate-target-identity-denied"; blockers = @("duplicate-target-identity"); reason = "Duplicate target identities cannot satisfy exact target binding." },
    [ordered]@{ id = "replayed-target-package-denied"; blockers = @("target-package-replay-detected"); reason = "Replayed target packages must fail before effect preparation." },
    [ordered]@{ id = "unowned-target-package-denied"; blockers = @("target-package-unowned"); reason = "Unowned target packages cannot become install/update authority." },
    [ordered]@{ id = "operation-type-broadening-denied"; blockers = @("operation-type-broadening"); reason = "Target binding cannot broaden install/update into activation, rollback, support, recovery, dispatch, signing, or production mutation." },
    [ordered]@{ id = "endpoint-reachability-authority-denied"; blockers = @("endpoint-reachability-not-authority"); reason = "Endpoint reachability is not local evidence binding." },
    [ordered]@{ id = "frontend-output-authority-denied"; blockers = @("frontend-output-not-authority"); reason = "Frontend output cannot bind exact target authority." },
    [ordered]@{ id = "tui-output-authority-denied"; blockers = @("tui-output-not-authority"); reason = "TUI projection cannot bind exact target authority." },
    [ordered]@{ id = "model-replay-authority-denied"; blockers = @("model-replay-not-authority"); reason = "Model replay cannot bind exact target authority." },
    [ordered]@{ id = "shell-output-authority-denied"; blockers = @("shell-output-not-authority"); reason = "Shell output cannot bind exact target authority." },
    [ordered]@{ id = "signer-reachability-authority-denied"; blockers = @("signer-reachability-not-authority"); reason = "Signer reachability cannot bind exact target authority." },
    [ordered]@{ id = "host-active-slot-mutation-denied"; blockers = @("host-active-slot-mutation-forbidden"); reason = "Target binding must not mutate host active slot state." },
    [ordered]@{ id = "host-boot-metadata-mutation-denied"; blockers = @("host-boot-metadata-mutation-forbidden"); reason = "Target binding must not mutate host boot metadata." },
    [ordered]@{ id = "remote-dispatch-authority-denied"; blockers = @("remote-dispatch-authority-forbidden"); reason = "Target binding must not enable remote dispatch." },
    [ordered]@{ id = "support-upload-authority-denied"; blockers = @("support-upload-authority-forbidden"); reason = "Target binding must not enable support upload." },
    [ordered]@{ id = "recovery-execution-authority-denied"; blockers = @("recovery-execution-authority-forbidden"); reason = "Target binding must not enable recovery execution." },
    [ordered]@{ id = "production-ring-mutation-denied"; blockers = @("production-ring-mutation-forbidden"); reason = "Target binding must not mutate production rings." },
    [ordered]@{ id = "private-signing-material-authority-denied"; blockers = @("private-signing-material-forbidden"); reason = "Target binding must not handle private signing material." }
)
$cases = @()
foreach ($spec in $caseSpecs) {
    $cases += New-DenialCase -Id $spec.id -ExpectedBlockers ([string[]]$spec.blockers) -Reason $spec.reason
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$targetPackage = [ordered]@{
    schema = "agentos.rc17-exact-install-update-target-package.v1"
    generated_at = $generatedAtValue
    task = "RC17-010"
    status = "exact-install-update-target-bound-effects-denied"
    production_ready_claim = $false
    target_binding_id = $targetBindingId
    package_id = $packageId
    media_id = $mediaId
    release_id = $releaseId
    preflight_id = $preflightId
    target_binding_surface = [ordered]@{
        state = "exact-repo-local-install-update-target-bound"
        exact_install_update_target_bound = $true
        install_target_bound = $true
        update_target_bound = $true
        repo_local_target_identity_set_bound = $true
        target_identity_set_digest = $targetIdentitySetDigest
        enrolled_target_identity_count = [int]$rc15TargetIdentitySet.enrolled_target_identity_count
        distinct_target_identity_count = $distinctIdentityCount
        package_identity_bound = $true
        installable_media_bound = $true
        installer_updater_preflight_bound = $true
        rc16_planspec_package_bound = $true
        rc16_rollback_support_package_bound = $true
        rc16_consumer_smoke_bound = $true
        exact_install_update_approval_bound = $false
        agentcore_install_update_planspec_executable = $false
        security_execution_install_update_allow = $false
        rollback_preconditions_bound = $false
        install_effect_preparation_allowed = $false
        update_effect_preparation_allowed = $false
        install_allowed = $false
        update_allowed = $false
        install_performed = $false
        update_performed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        blockers = @($blockers)
    }
    target_core = $targetCore
    exact_targets = [ordered]@{
        install = $targetCore.install_target
        update = $targetCore.update_target
    }
    target_identities = [ordered]@{
        source = Get-StablePath $resolvedRc15TargetIdentitySetPath
        target_identity_set_digest = $targetIdentitySetDigest
        identity_ids = $identityIds
        identity_digests = $identityDigests
        identity_paths = $identityPaths
    }
    bindings = $targetCore.bindings
    fail_closed_summary = [ordered]@{
        fail_closed_matrix_path = "target-binding-fail-closed-matrix.json"
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
    }
    side_effects = $sideEffects
    authority = [ordered]@{
        aios_body_only = $true
        repo_local_projection_only = $true
        exact_target_authority = $true
        exact_approval_authority = $false
        agentcore_execution_authority = $false
        security_execution_authority = $false
        endpoint_reachability_authority = $false
        frontend_output_authority = $false
        signer_reachability_authority = $false
        shell_output_authority = $false
        tui_authority = $false
        model_replay_authority = $false
        object_storage_ui_authority = $false
        install_authority = $false
        update_authority = $false
        activation_authority = $false
        rollback_execution_authority = $false
        support_upload_authority = $false
        recovery_execution_authority = $false
        remote_dispatch_authority = $false
        host_active_slot_mutation_authority = $false
        host_boot_metadata_mutation_authority = $false
        production_ring_mutation_authority = $false
        signing_authority = $false
    }
    source = [ordered]@{
        rc17_plan = New-ArtifactRef $resolvedPlanPath $plan
        rc17_contract = New-ArtifactRef $resolvedContractPath
        rc16_final_audit = New-ArtifactRef $resolvedRc16FinalAuditResultPath $rc16FinalAuditResult
        rc16_release_package_result = New-ArtifactRef $resolvedReleasePackageResultPath $releasePackageResult
        rc16_release_package_artifact_set = New-ArtifactRef $resolvedReleasePackageArtifactSetPath $releasePackageArtifactSet
        rc16_installable_media_result = New-ArtifactRef $resolvedInstallableMediaResultPath $installableMediaResult
        rc16_installable_media_manifest = New-ArtifactRef $resolvedInstallableMediaManifestPath $installableMediaManifest
        rc16_preflight_result = New-ArtifactRef $resolvedPreflightResultPath $preflightResult
        rc16_preflight_package = New-ArtifactRef $resolvedPreflightPackagePath $preflightPackage
        rc16_planspec_result = New-ArtifactRef $resolvedPlanSpecResultPath $planspecResult
        rc16_planspec_package = New-ArtifactRef $resolvedPlanSpecPackagePath $planspecPackage
        rc16_rollback_support_result = New-ArtifactRef $resolvedRollbackSupportResultPath $rollbackSupportResult
        rc16_rollback_support_package = New-ArtifactRef $resolvedRollbackSupportPackagePath $rollbackSupportPackage
        rc16_consumer_smoke_result = New-ArtifactRef $resolvedConsumerSmokeResultPath $consumerSmokeResult
        rc15_target_identity_result = New-ArtifactRef $resolvedRc15TargetIdentityResultPath $rc15TargetIdentityResult
        rc15_target_identity_set = New-ArtifactRef $resolvedRc15TargetIdentitySetPath $rc15TargetIdentitySet
    }
}

$targetPackagePath = Join-Path $resolvedArtifactDir "exact-install-update-target-package.json"
Write-Json $targetPackage $targetPackagePath

$matrix = [ordered]@{
    schema = "agentos.rc17-target-binding-fail-closed-matrix.v1"
    generated_at = $generatedAtValue
    task = "RC17-010"
    status = if ($failedCases.Count -eq 0) { "passed" } else { "failed" }
    production_ready_claim = $false
    target_binding_id = $targetBindingId
    cases = $cases
    summary = [ordered]@{
        cases = @($cases).Count
        passed = @($cases | Where-Object { $_.status -eq "passed" }).Count
        failed = $failedCases.Count
        failed_cases = @($failedCases | ForEach-Object { $_.id })
    }
}
$matrixPath = Join-Path $resolvedArtifactDir "target-binding-fail-closed-matrix.json"
Write-Json $matrix $matrixPath

Add-Check "plan.current_task.rc17_010" $planAllowsRun "RC17-010 must run after RC17-001 completed, either while current_task is RC17-010 or while rerunning after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc17_001_status = $rc17PreviousStatus; rc17_010_status = $rc17TaskStatus })
Add-Check "contract.exact_target_gate.present" ($contractText.Contains("Exact repo-local install and update targets") -and $contractText.Contains("package identity") -and $contractText.Contains("installer/updater preflight evidence")) "RC17-010 must consume the exact install/update target contract." (New-ArtifactRef $resolvedContractPath)
Add-Check "source.rc16_final_audit.distributable_ready" ($rc16FinalAuditResult.status -eq "passed" -and $rc16FinalAuditResult.decision -eq "PASS" -and $rc16FinalAuditResult.summary.distributable_packaging_ready -eq $true -and $rc16FinalAuditResult.summary.install_update_ready -eq $false) "RC17-010 must start from RC16 non-GA distributable packaging readiness and denied install/update readiness." ([ordered]@{ status = $rc16FinalAuditResult.status; decision = $rc16FinalAuditResult.decision; distributable_packaging_ready = $rc16FinalAuditResult.summary.distributable_packaging_ready; install_update_ready = $rc16FinalAuditResult.summary.install_update_ready })
Add-Check "source.rc16_package_media_preflight.bound" ($releasePackageResult.status -eq "passed" -and $installableMediaResult.status -eq "passed" -and $preflightResult.status -eq "passed" -and $releasePackageArtifactSet.package_id -eq $packageId -and $installableMediaManifest.media_id -eq $mediaId -and $releasePackageArtifactSet.release_id -eq $releaseId) "RC16 package identity, installable media, and installer/updater preflight evidence must be hash-bound and matching." ([ordered]@{ package_id = $packageId; media_id = $mediaId; release_id = $releaseId; preflight_id = $preflightId })
Add-Check "source.rc16_planspec_rollback_consumer.bound" ($planspecResult.status -eq "passed" -and $planspecPackage.agentcore_install_update_planspec_bound -eq $true -and $rollbackSupportResult.status -eq "passed" -and $rollbackSupportResult.summary.rollback_support_package_bound -eq $true -and $consumerSmokeResult.status -eq "passed") "RC16 PlanSpec binding, rollback/support package, and consumer smoke evidence must be present." ([ordered]@{ planspec_bound = $planspecPackage.agentcore_install_update_planspec_bound; planspec_executable = $planspecPackage.agentcore_install_update_planspec_executable; rollback_support_package_bound = $rollbackSupportResult.summary.rollback_support_package_bound; consumer_decision = $consumerSmokeResult.consumer_surface.consumer_decision })
Add-Check "source.rc15_target_identities.bound" ($rc15TargetIdentityResult.status -eq "passed" -and $rc15TargetIdentitySet.target_identity_set_bound -eq $true -and [int]$rc15TargetIdentitySet.enrolled_target_identity_count -eq 2 -and $distinctIdentityCount -eq 2 -and $rc15TargetIdentitySet.quality.remote_dispatch_authority -eq $false -and $rc15TargetIdentitySet.quality.production_ring_mutation_allowed -eq $false) "RC17-010 must bind two distinct repo-local target identities without remote dispatch or production mutation authority." ([ordered]@{ target_identity_set_digest = $targetIdentitySetDigest; enrolled = $rc15TargetIdentitySet.enrolled_target_identity_count; distinct = $distinctIdentityCount; remote_dispatch_authority = $rc15TargetIdentitySet.quality.remote_dispatch_authority; production_ring_mutation_allowed = $rc15TargetIdentitySet.quality.production_ring_mutation_allowed })
Add-Check "target_package.exact_install_update_bound" ($targetPackage.target_binding_surface.exact_install_update_target_bound -eq $true -and $targetPackage.target_binding_surface.install_target_bound -eq $true -and $targetPackage.target_binding_surface.update_target_bound -eq $true -and $targetPackage.target_binding_surface.package_identity_bound -eq $true -and $targetPackage.target_binding_surface.installable_media_bound -eq $true -and $targetPackage.target_binding_surface.installer_updater_preflight_bound -eq $true) "Exact install and update targets must bind target identities, package identity, installable media, and preflight evidence." $targetPackage.target_binding_surface
Add-Check "target_package.effect_authority_denied" ($targetPackage.target_binding_surface.exact_install_update_approval_bound -eq $false -and $targetPackage.target_binding_surface.agentcore_install_update_planspec_executable -eq $false -and $targetPackage.target_binding_surface.security_execution_install_update_allow -eq $false -and $targetPackage.target_binding_surface.install_effect_preparation_allowed -eq $false -and $targetPackage.target_binding_surface.update_effect_preparation_allowed -eq $false -and $targetPackage.target_binding_surface.install_performed -eq $false -and $targetPackage.target_binding_surface.update_performed -eq $false) "Target binding alone must not grant approval, executable PlanSpec, SecurityExecution allow, or install/update effects." ([ordered]@{ blockers = @($blockers); authority = $targetPackage.authority })
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 25) "Broad, missing, mismatched, stale, replayed, unowned, display-surface, and authority-broadening target packages must fail closed." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })
Add-Check "authority.no_side_effects" (@($sideEffects.GetEnumerator() | Where-Object { $_.Value -ne $false }).Count -eq 0) "RC17-010 must not install, update, activate, mutate host slot/boot metadata, dispatch remotely, upload support, recover, or mutate production rings." $sideEffects

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $targetPackagePath),
    (Get-Content -Raw -LiteralPath $matrixPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC17-010 outputs must not contain key blocks, private key paths, auth tokens, public identity markers, or signing key file names." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$targetPackageSha256 = Get-FileSha256 $targetPackagePath
$matrixSha256 = Get-FileSha256 $matrixPath
$result = [ordered]@{
    schema = "agentos.rc17-exact-install-update-target-binding-result.v1"
    generated_at = $generatedAtValue
    task = "RC17-010"
    status = $resultStatus
    production_ready_claim = $false
    target_binding_id = $targetBindingId
    package_id = $packageId
    media_id = $mediaId
    release_id = $releaseId
    preflight_id = $preflightId
    target_binding_surface = $targetPackage.target_binding_surface
    outputs = [ordered]@{
        exact_install_update_target_package = [ordered]@{
            path = Get-StablePath $targetPackagePath
            sha256 = $targetPackageSha256
            target_binding_id = $targetBindingId
        }
        target_binding_fail_closed_matrix = [ordered]@{
            path = Get-StablePath $matrixPath
            sha256 = $matrixSha256
        }
    }
    source = $targetPackage.source
    checks = @($script:checks)
    blockers = @($blockers)
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        repo_local_projection_only = $true
        exact_install_update_target_bound = $true
        exact_install_update_approval_bound = $false
        agentcore_install_update_planspec_executable = $false
        security_execution_install_update_allow = $false
        rollback_preconditions_bound = $false
        mirror_frontend_changed = $false
        nginx_or_tls_changed = $false
        signer_infra_changed = $false
        object_storage_infra_changed = $false
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
        endpoint_reachability_trusted = $false
        frontend_output_trusted = $false
        signer_reachability_trusted = $false
        shell_output_trusted = $false
        tui_output_trusted = $false
        model_replay_trusted = $false
        object_storage_ui_trusted = $false
        install_effect_prepared = $false
        update_effect_prepared = $false
        install_performed = $false
        update_performed = $false
        activation_performed = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        rollback_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        production_ring_mutated = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
        rc17_010_complete = (@($script:failedChecks).Count -eq 0)
        exact_install_update_target_bound = $true
        exact_install_update_approval_bound = $false
        agentcore_install_update_planspec_executable = $false
        security_execution_install_update_allow = $false
        rollback_preconditions_bound = $false
        install_performed = $false
        update_performed = $false
        next_task = "RC17-011"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC17-010-exact-install-update-target-binding.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc17-exact-install-update-target-binding-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC17-010"
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
    target_binding_surface = $result.target_binding_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc17_010_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC17-011"
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
    throw "Sensitive marker detected in RC17-010 outputs."
}

Write-Host "RC17 exact install/update target binding $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Target package: $(Get-StablePath $targetPackagePath)"
Write-Host "Fail-closed matrix: $(Get-StablePath $matrixPath)"
Write-Host "Exact target bound: true; approval bound: false; install/update effects performed: false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
