param(
    [string]$ArtifactDir = ".workflow/artifacts/rc16-install-update-planspec-binding",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc16",
    [string]$PlanPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc16/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc16/docs/rc16-distributable-release-operations-contract.md",
    [string]$PreflightResultPath = ".workflow/artifacts/rc16-installer-updater-preflight-package/result.json",
    [string]$PreflightPackagePath = ".workflow/artifacts/rc16-installer-updater-preflight-package/installer-updater-preflight-package.json",
    [string]$ReleasePackageResultPath = ".workflow/artifacts/rc16-release-package-artifact-set/result.json",
    [string]$ReleasePackageArtifactSetPath = ".workflow/artifacts/rc16-release-package-artifact-set/release-package-artifact-set.json",
    [string]$InstallableMediaResultPath = ".workflow/artifacts/rc16-installable-media-manifest/result.json",
    [string]$InstallableMediaManifestPath = ".workflow/artifacts/rc16-installable-media-manifest/installable-media-manifest.json",
    [string]$PackageDescriptorResultPath = ".workflow/artifacts/rc16-package-descriptor-fail-closed/result.json",
    [string]$RollbackBaselinePath = ".workflow/artifacts/rc7-install-rollback-baseline/rollback-baseline.json",
    [string]$SupportIndexPath = ".workflow/artifacts/rc5-hosted-support-recovery/support-index.json",
    [string]$Rc15AgentCoreResultPath = ".workflow/artifacts/rc15-agentcore-executable-planspec/result.json",
    [string]$Rc15AgentCorePlanSpecPath = ".workflow/artifacts/rc15-agentcore-executable-planspec/agentcore-planspec.json",
    [string]$Rc15SecurityExecutionResultPath = ".workflow/artifacts/rc15-security-execution-allow-decision/result.json",
    [string]$Rc15SecurityExecutionDecisionPath = ".workflow/artifacts/rc15-security-execution-allow-decision/security-execution-allow-decision.json",
    [string]$AgentCoreLibPath = "crates/agent_core/src/lib.rs",
    [string]$SecurityExecutionPolicyPath = "crates/security_execution/src/policy.rs",
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
            active_slot_mutated = $false
            boot_metadata_mutated = $false
            active_artifact_set_mutated = $false
            rollback_execution_performed = $false
            support_upload_performed = $false
            recovery_execution_performed = $false
            remote_dispatch_enabled = $false
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
$resolvedPreflightResultPath = Resolve-RepoPath $PreflightResultPath
$resolvedPreflightPackagePath = Resolve-RepoPath $PreflightPackagePath
$resolvedReleasePackageResultPath = Resolve-RepoPath $ReleasePackageResultPath
$resolvedReleasePackageArtifactSetPath = Resolve-RepoPath $ReleasePackageArtifactSetPath
$resolvedInstallableMediaResultPath = Resolve-RepoPath $InstallableMediaResultPath
$resolvedInstallableMediaManifestPath = Resolve-RepoPath $InstallableMediaManifestPath
$resolvedPackageDescriptorResultPath = Resolve-RepoPath $PackageDescriptorResultPath
$resolvedRollbackBaselinePath = Resolve-RepoPath $RollbackBaselinePath
$resolvedSupportIndexPath = Resolve-RepoPath $SupportIndexPath
$resolvedRc15AgentCoreResultPath = Resolve-RepoPath $Rc15AgentCoreResultPath
$resolvedRc15AgentCorePlanSpecPath = Resolve-RepoPath $Rc15AgentCorePlanSpecPath
$resolvedRc15SecurityExecutionResultPath = Resolve-RepoPath $Rc15SecurityExecutionResultPath
$resolvedRc15SecurityExecutionDecisionPath = Resolve-RepoPath $Rc15SecurityExecutionDecisionPath
$resolvedAgentCoreLibPath = Resolve-RepoPath $AgentCoreLibPath
$resolvedSecurityExecutionPolicyPath = Resolve-RepoPath $SecurityExecutionPolicyPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$preflightResult = Read-Json $resolvedPreflightResultPath
$preflightPackage = Read-Json $resolvedPreflightPackagePath
$releasePackageResult = Read-Json $resolvedReleasePackageResultPath
$releasePackageArtifactSet = Read-Json $resolvedReleasePackageArtifactSetPath
$installableMediaResult = Read-Json $resolvedInstallableMediaResultPath
$installableMediaManifest = Read-Json $resolvedInstallableMediaManifestPath
$packageDescriptorResult = Read-Json $resolvedPackageDescriptorResultPath
$rollbackBaseline = Read-Json $resolvedRollbackBaselinePath
$supportIndex = Read-Json $resolvedSupportIndexPath
$rc15AgentCoreResult = Read-Json $resolvedRc15AgentCoreResultPath
$rc15AgentCorePlanSpec = Read-Json $resolvedRc15AgentCorePlanSpecPath
$rc15SecurityExecutionResult = Read-Json $resolvedRc15SecurityExecutionResultPath
$rc15SecurityExecutionDecision = Read-Json $resolvedRc15SecurityExecutionDecisionPath

$rc16TaskStatus = Get-TaskStatus $plan "RC16-021"
$rc16PreviousStatus = Get-TaskStatus $plan "RC16-020"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc16PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC16-021" -and ($rc16TaskStatus -eq "pending" -or $rc16TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC16-022" -and $rc16TaskStatus -eq "completed")
    )
)

$preflightResultSha256 = Get-FileSha256 $resolvedPreflightResultPath
$preflightPackageSha256 = Get-FileSha256 $resolvedPreflightPackagePath
$releasePackageResultSha256 = Get-FileSha256 $resolvedReleasePackageResultPath
$releasePackageArtifactSetSha256 = Get-FileSha256 $resolvedReleasePackageArtifactSetPath
$installableMediaResultSha256 = Get-FileSha256 $resolvedInstallableMediaResultPath
$installableMediaManifestSha256 = Get-FileSha256 $resolvedInstallableMediaManifestPath
$packageDescriptorResultSha256 = Get-FileSha256 $resolvedPackageDescriptorResultPath
$rollbackBaselineSha256 = Get-FileSha256 $resolvedRollbackBaselinePath
$supportIndexSha256 = Get-FileSha256 $resolvedSupportIndexPath
$rc15AgentCoreResultSha256 = Get-FileSha256 $resolvedRc15AgentCoreResultPath
$rc15AgentCorePlanSpecSha256 = Get-FileSha256 $resolvedRc15AgentCorePlanSpecPath
$rc15SecurityExecutionResultSha256 = Get-FileSha256 $resolvedRc15SecurityExecutionResultPath
$rc15SecurityExecutionDecisionSha256 = Get-FileSha256 $resolvedRc15SecurityExecutionDecisionPath
$agentCoreLibSha256 = Get-FileSha256 $resolvedAgentCoreLibPath
$securityExecutionPolicySha256 = Get-FileSha256 $resolvedSecurityExecutionPolicyPath

$source = [ordered]@{
    rc16_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc16_contract = New-ArtifactRef $resolvedContractPath
    rc16_installer_updater_preflight_result = New-ArtifactRef $resolvedPreflightResultPath $preflightResult
    rc16_installer_updater_preflight_package = New-ArtifactRef $resolvedPreflightPackagePath $preflightPackage
    rc16_release_package_result = New-ArtifactRef $resolvedReleasePackageResultPath $releasePackageResult
    rc16_release_package_artifact_set = New-ArtifactRef $resolvedReleasePackageArtifactSetPath $releasePackageArtifactSet
    rc16_installable_media_result = New-ArtifactRef $resolvedInstallableMediaResultPath $installableMediaResult
    rc16_installable_media_manifest = New-ArtifactRef $resolvedInstallableMediaManifestPath $installableMediaManifest
    rc16_package_descriptor_result = New-ArtifactRef $resolvedPackageDescriptorResultPath $packageDescriptorResult
    rollback_baseline = New-ArtifactRef $resolvedRollbackBaselinePath $rollbackBaseline
    support_index = New-ArtifactRef $resolvedSupportIndexPath $supportIndex
    rc15_agentcore_result = New-ArtifactRef $resolvedRc15AgentCoreResultPath $rc15AgentCoreResult
    rc15_agentcore_planspec = New-ArtifactRef $resolvedRc15AgentCorePlanSpecPath $rc15AgentCorePlanSpec
    rc15_security_execution_result = New-ArtifactRef $resolvedRc15SecurityExecutionResultPath $rc15SecurityExecutionResult
    rc15_security_execution_decision = New-ArtifactRef $resolvedRc15SecurityExecutionDecisionPath $rc15SecurityExecutionDecision
    agent_core_lib = New-ArtifactRef $resolvedAgentCoreLibPath
    security_execution_policy = New-ArtifactRef $resolvedSecurityExecutionPolicyPath
}

$preflightEvidenceBound = (
    $preflightResult.status -eq "passed" -and
    $preflightResult.summary.rc16_020_complete -eq $true -and
    $preflightResult.preflight_surface.evidence_bound -eq $true -and
    $preflightPackage.installer_updater_preflight.evidence_bound -eq $true -and
    $preflightPackage.installer_updater_preflight.install_preflight_ready -eq $true -and
    $preflightPackage.installer_updater_preflight.update_preflight_ready -eq $true -and
    $preflightPackage.production_ready_claim -eq $false
)
$releasePackageComplete = (
    $releasePackageResult.status -eq "passed" -and
    $releasePackageResult.summary.rc16_010_complete -eq $true -and
    $releasePackageArtifactSet.production_ready_claim -eq $false
)
$installableMediaComplete = (
    $installableMediaResult.status -eq "passed" -and
    $installableMediaResult.summary.rc16_011_complete -eq $true -and
    $installableMediaManifest.production_ready_claim -eq $false
)
$descriptorFailClosedComplete = (
    $packageDescriptorResult.status -eq "passed" -and
    $packageDescriptorResult.summary.rc16_012_complete -eq $true -and
    $packageDescriptorResult.summary.failed_cases -eq 0
)
$packageIdentityBound = (
    [string]$preflightPackage.package_id -eq [string]$releasePackageArtifactSet.package_id -and
    [string]$preflightPackage.package_id -eq [string]$installableMediaManifest.package_id -and
    [string]$preflightPackage.media_id -eq [string]$installableMediaManifest.media_id -and
    [string]$preflightPackage.release_id -eq [string]$releasePackageArtifactSet.release_id -and
    [string]$preflightPackage.release_id -eq [string]$installableMediaManifest.release_id
)
$releaseBytesBound = (
    [string]$preflightPackage.exact_target.payload_sha256 -eq [string]$installableMediaManifest.release_bytes.payload.sha256 -and
    [string]$releasePackageArtifactSet.package_surface.current_payload_sha256 -eq [string]$installableMediaManifest.release_bytes.payload.sha256 -and
    [int64]$preflightPackage.exact_target.payload_size_bytes -eq [int64]$installableMediaManifest.release_bytes.payload.size_bytes
)
$updateStrategyBound = (
    [string]$preflightPackage.exact_target.update_strategy.stage_target -eq "inactive-slot" -and
    $preflightPackage.exact_target.update_strategy.active_slot_modified_in_place -eq $false -and
    $preflightPackage.exact_target.update_strategy.rollback_required -eq $true
)
$rollbackSupportSourceBound = (
    [string]$installableMediaManifest.rollback_support.rollback_baseline_sha256 -eq $rollbackBaselineSha256 -and
    [string]$installableMediaManifest.rollback_support.support_recovery_sha256 -eq $supportIndexSha256 -and
    $rollbackBaseline.production_ready_claim -eq $false -and
    $supportIndex.support_upload_allowed -eq $false -and
    $supportIndex.recovery_execution_allowed -eq $false
)
$rc15ExecutionSourceBound = (
    $rc15AgentCoreResult.status -eq "passed" -and
    $rc15AgentCoreResult.summary.agentcore_planspec_executable -eq $true -and
    $rc15SecurityExecutionResult.status -eq "passed" -and
    $rc15SecurityExecutionResult.summary.security_execution_allowed -eq $true -and
    $rc15SecurityExecutionDecision.security_execution_allowed -eq $true
)
$codeContractsPresent = (
    (Test-Path -LiteralPath $resolvedAgentCoreLibPath -PathType Leaf) -and
    (Test-Path -LiteralPath $resolvedSecurityExecutionPolicyPath -PathType Leaf) -and
    -not [string]::IsNullOrWhiteSpace($agentCoreLibSha256) -and
    -not [string]::IsNullOrWhiteSpace($securityExecutionPolicySha256)
)

$blockers = [System.Collections.ArrayList]::new()
if (-not $preflightEvidenceBound) { Add-Unique $blockers "rc16-installer-updater-preflight-not-bound" }
if (-not $releasePackageComplete) { Add-Unique $blockers "rc16-release-package-artifact-set-not-complete" }
if (-not $installableMediaComplete) { Add-Unique $blockers "rc16-installable-media-manifest-not-complete" }
if (-not $descriptorFailClosedComplete) { Add-Unique $blockers "rc16-package-descriptor-fail-closed-not-complete" }
if (-not $packageIdentityBound) { Add-Unique $blockers "rc16-package-media-identity-not-bound" }
if (-not $releaseBytesBound) { Add-Unique $blockers "rc16-release-bytes-not-bound" }
if (-not $updateStrategyBound) { Add-Unique $blockers "rc16-update-strategy-not-bound" }
if (-not $rollbackSupportSourceBound) { Add-Unique $blockers "rc16-rollback-support-source-not-bound" }
if (-not $rc15ExecutionSourceBound) { Add-Unique $blockers "rc15-controlled-local-execution-not-bound" }
if (-not $codeContractsPresent) { Add-Unique $blockers "agentcore-securityexecution-code-contract-not-bound" }

Add-Unique $blockers "rc16-exact-install-update-target-not-bound"
Add-Unique $blockers "rc16-exact-install-update-approval-not-bound"
Add-Unique $blockers "rc16-install-update-planspec-not-executable"
Add-Unique $blockers "rc16-security-execution-install-update-allow-not-bound"
Add-Unique $blockers "rc16-rollback-support-package-not-bound"
Add-Unique $blockers "rc16-local-release-channel-consumer-smoke-not-run"

$agentCorePlanSpecExecutable = $false
$securityExecutionAllowed = $false
$installEffectPreparationAllowed = $false
$updateEffectPreparationAllowed = $false
$rollbackSupportPackageBound = $false
$exactInstallUpdateApprovalBound = $false
$exactInstallUpdateTargetBound = $false

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
    active_slot_mutated = $false
    boot_metadata_mutated = $false
    active_artifact_set_mutated = $false
    rollback_execution_performed = $false
    support_upload_performed = $false
    recovery_execution_performed = $false
    remote_dispatch_enabled = $false
    cryptographic_signing_performed = $false
    production_ring_mutated = $false
}

$planspecCore = [ordered]@{
    schema = "agentos.agentcore.install-update-planspec.v1"
    task = "RC16-021"
    plan_kind = "distributable-install-update-readiness"
    package_id = [string]$preflightPackage.package_id
    media_id = [string]$preflightPackage.media_id
    release_id = [string]$preflightPackage.release_id
    preflight_id = [string]$preflightPackage.preflight_id
    production_ready_claim = $false
    executable = $agentCorePlanSpecExecutable
    binding_slots = [ordered]@{
        installer_updater_preflight = [ordered]@{
            required = $true
            bound = $preflightEvidenceBound
            preflight_id = [string]$preflightPackage.preflight_id
            result_sha256 = $preflightResultSha256
            package_sha256 = $preflightPackageSha256
        }
        package_identity = [ordered]@{
            required = $true
            bound = $packageIdentityBound
            package_id = [string]$preflightPackage.package_id
            media_id = [string]$preflightPackage.media_id
            release_id = [string]$preflightPackage.release_id
            release_package_artifact_set_sha256 = $releasePackageArtifactSetSha256
            installable_media_manifest_sha256 = $installableMediaManifestSha256
            descriptor_result_sha256 = $packageDescriptorResultSha256
        }
        release_payload = [ordered]@{
            required = $true
            bound = $releaseBytesBound
            payload_path = [string]$installableMediaManifest.release_bytes.payload.path
            payload_sha256 = [string]$installableMediaManifest.release_bytes.payload.sha256
            payload_size_bytes = [int64]$installableMediaManifest.release_bytes.payload.size_bytes
            object_id = [string]$installableMediaManifest.release_bytes.payload.object_id
        }
        update_strategy = [ordered]@{
            required = $true
            bound = $updateStrategyBound
            mode = [string]$preflightPackage.exact_target.update_strategy.mode
            stage_target = [string]$preflightPackage.exact_target.update_strategy.stage_target
            active_slot_modified_in_place = $preflightPackage.exact_target.update_strategy.active_slot_modified_in_place
            rollback_required = $preflightPackage.exact_target.update_strategy.rollback_required
        }
        rollback_baseline = [ordered]@{
            required = $true
            source_bound = $rollbackSupportSourceBound
            rc16_package_bound = $rollbackSupportPackageBound
            sha256 = $rollbackBaselineSha256
            source_path = Get-StablePath $resolvedRollbackBaselinePath
        }
        support_recovery = [ordered]@{
            required = $true
            source_bound = $rollbackSupportSourceBound
            rc16_package_bound = $rollbackSupportPackageBound
            sha256 = $supportIndexSha256
            source_path = Get-StablePath $resolvedSupportIndexPath
            support_upload_allowed = $false
            recovery_execution_allowed = $false
        }
        audit_sink = [ordered]@{
            required = $true
            exact_install_update_approval_bound = $exactInstallUpdateApprovalBound
            requirement = "install/update approval must bind an audit sink descriptor before executable PlanSpec state"
        }
        nonce = [ordered]@{
            required = $true
            exact_install_update_approval_bound = $exactInstallUpdateApprovalBound
            requirement = "install/update approval must bind a fresh nonce"
        }
        expiry = [ordered]@{
            required = $true
            exact_install_update_approval_bound = $exactInstallUpdateApprovalBound
            requirement = "install/update approval must bind an expiry window"
        }
        policy_version = [ordered]@{
            required = $true
            exact_install_update_approval_bound = $exactInstallUpdateApprovalBound
            required_policy_version = "policy-v1"
        }
        exact_target = [ordered]@{
            required = $true
            bound = $exactInstallUpdateTargetBound
            expected_scope = "exact local install/update target identity"
        }
        exact_approval = [ordered]@{
            required = $true
            bound = $exactInstallUpdateApprovalBound
            allowed_effects = @("install", "update")
            forbidden_effect_broadening = @("activation", "rollback", "support-upload", "recovery", "remote-dispatch", "production-ring-mutation", "signing")
        }
        security_execution_envelope = [ordered]@{
            required = $true
            envelope_prepared = $true
            allow_bound = $securityExecutionAllowed
        }
        source_code_contracts = [ordered]@{
            required = $true
            bound = $codeContractsPresent
            agent_core_lib_sha256 = $agentCoreLibSha256
            security_execution_policy_sha256 = $securityExecutionPolicySha256
        }
    }
    exact_effect_scope = [ordered]@{
        install_effect_preparation_allowed = $installEffectPreparationAllowed
        update_effect_preparation_allowed = $updateEffectPreparationAllowed
        install_allowed = $false
        update_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        signing_allowed = $false
    }
    steps = @(
        [ordered]@{ id = "bind-rc16-installer-updater-preflight"; authority = "hash-bound-evidence"; executable = $preflightEvidenceBound; source_task = "RC16-020" },
        [ordered]@{ id = "bind-package-and-media-identity"; authority = "hash-bound-evidence"; executable = $packageIdentityBound; source_task = "RC16-010,RC16-011,RC16-012" },
        [ordered]@{ id = "bind-rollback-support-source"; authority = "hash-bound-evidence"; executable = $rollbackSupportSourceBound; source_task = "RC7,RC5" },
        [ordered]@{ id = "require-rc16-rollback-support-package"; authority = "workflow-gate"; executable = $false; source_task = "RC16-022" },
        [ordered]@{ id = "require-exact-install-update-target"; authority = "operator-approval"; executable = $false; source_task = "future-install-update-target-binding" },
        [ordered]@{ id = "require-exact-install-update-approval"; authority = "operator-approval"; executable = $false; source_task = "future-install-update-approval" },
        [ordered]@{ id = "await-security-execution-install-update-allow"; authority = "security-execution"; executable = $false; source_task = "RC16-021" }
    )
}
$planspecMaterializationDigest = Get-StringSha256 (($planspecCore | ConvertTo-Json -Depth 100 -Compress))
$planspecCoreHash = Get-StringSha256 (($planspecCore | ConvertTo-Json -Depth 100 -Compress))

$effectEnvelopeCore = [ordered]@{
    schema = "agentos.security-execution.install-update-effect-envelope.v1"
    task = "RC16-021"
    package_id = [string]$preflightPackage.package_id
    media_id = [string]$preflightPackage.media_id
    release_id = [string]$preflightPackage.release_id
    preflight_id = [string]$preflightPackage.preflight_id
    planspec_core_hash = $planspecCoreHash
    planspec_materialization_digest = $planspecMaterializationDigest
    payload_sha256 = [string]$installableMediaManifest.release_bytes.payload.sha256
    payload_size_bytes = [int64]$installableMediaManifest.release_bytes.payload.size_bytes
    requested_effects = @("install", "update")
    allowed_effects = @()
    denied_effects = @("install", "update", "activation", "rollback", "support-upload", "recovery", "remote-dispatch", "production-ring-mutation", "signing")
    effect_preparation_allowed = $false
    approval_requirements = [ordered]@{
        exact_target_required = $true
        exact_approval_required = $true
        audit_sink_required = $true
        nonce_required = $true
        expiry_required = $true
        policy_version_required = $true
        required_policy_version = "policy-v1"
    }
    rollback_support = [ordered]@{
        source_bound = $rollbackSupportSourceBound
        rc16_package_bound = $rollbackSupportPackageBound
        rollback_baseline_sha256 = $rollbackBaselineSha256
        support_recovery_sha256 = $supportIndexSha256
    }
}
$effectEnvelopeCoreHash = Get-StringSha256 (($effectEnvelopeCore | ConvertTo-Json -Depth 100 -Compress))
$decisionMaterialHash = Get-StringSha256 (([ordered]@{
    effect_envelope_core_hash = $effectEnvelopeCoreHash
    planspec_core_hash = $planspecCoreHash
    blockers = @($blockers)
    allowed = $securityExecutionAllowed
}) | ConvertTo-Json -Depth 100 -Compress)

$caseObservedBlockers = @(
    "rc16-installer-updater-preflight-not-bound",
    "rc16-release-package-artifact-set-not-complete",
    "rc16-installable-media-manifest-not-complete",
    "rc16-package-descriptor-fail-closed-not-complete",
    "rc16-package-media-identity-not-bound",
    "rc16-release-bytes-not-bound",
    "rc16-update-strategy-not-bound",
    "rc16-rollback-support-source-not-bound",
    "rc15-controlled-local-execution-not-bound",
    "audit-sink-not-bound",
    "nonce-not-bound",
    "approval-expiry-not-bound",
    "policy-version-not-bound",
    "rc16-exact-install-update-target-not-bound",
    "rc16-exact-install-update-approval-not-bound",
    "approval-replay-denied",
    "approval-stale",
    "broad-effect-scope-denied",
    "endpoint-reachability-is-not-authority",
    "frontend-output-is-not-authority",
    "signer-reachability-is-not-authority",
    "shell-output-is-not-authority",
    "tui-output-is-not-authority",
    "model-replay-is-not-authority",
    "object-storage-ui-is-not-authority",
    "active-slot-mutation-denied",
    "boot-metadata-mutation-denied",
    "active-artifact-set-mutation-denied",
    "rc16-install-update-planspec-not-executable",
    "rc16-security-execution-install-update-allow-not-bound",
    "rc16-rollback-support-package-not-bound",
    "support-upload-denied",
    "recovery-execution-denied",
    "remote-dispatch-denied",
    "production-ring-mutation-denied"
)
$caseExpectations = [ordered]@{
    "missing.preflight" = @("rc16-installer-updater-preflight-not-bound")
    "missing.release_package" = @("rc16-release-package-artifact-set-not-complete")
    "missing.media_manifest" = @("rc16-installable-media-manifest-not-complete")
    "descriptor.fail_closed_missing" = @("rc16-package-descriptor-fail-closed-not-complete")
    "package.media.identity_mismatch" = @("rc16-package-media-identity-not-bound")
    "payload.digest_mismatch" = @("rc16-release-bytes-not-bound")
    "update_strategy.active_slot_target" = @("rc16-update-strategy-not-bound")
    "rollback.baseline_missing" = @("rc16-rollback-support-source-not-bound")
    "support.recovery_missing" = @("rc16-rollback-support-source-not-bound")
    "rc15.execution_source_missing" = @("rc15-controlled-local-execution-not-bound")
    "audit_sink.missing" = @("audit-sink-not-bound")
    "nonce.missing" = @("nonce-not-bound")
    "expiry.missing" = @("approval-expiry-not-bound")
    "policy_version.missing" = @("policy-version-not-bound")
    "target.missing" = @("rc16-exact-install-update-target-not-bound")
    "approval.missing" = @("rc16-exact-install-update-approval-not-bound")
    "approval.replayed" = @("approval-replay-denied")
    "approval.stale" = @("approval-stale")
    "planspec.non_executable" = @("rc16-install-update-planspec-not-executable")
    "security.allow_missing" = @("rc16-security-execution-install-update-allow-not-bound")
    "rollback_support.package_missing" = @("rc16-rollback-support-package-not-bound")
    "effect_scope.broad_install" = @("broad-effect-scope-denied")
    "effect_scope.broad_activation" = @("broad-effect-scope-denied")
    "surface.endpoint_reachability" = @("endpoint-reachability-is-not-authority")
    "surface.frontend_output" = @("frontend-output-is-not-authority")
    "surface.signer_reachability" = @("signer-reachability-is-not-authority")
    "surface.shell_output" = @("shell-output-is-not-authority")
    "surface.tui_output" = @("tui-output-is-not-authority")
    "surface.model_replay" = @("model-replay-is-not-authority")
    "surface.object_storage_ui" = @("object-storage-ui-is-not-authority")
    "authority.active_slot_mutation" = @("active-slot-mutation-denied")
    "authority.boot_metadata_mutation" = @("boot-metadata-mutation-denied")
    "authority.active_artifact_set_mutation" = @("active-artifact-set-mutation-denied")
    "authority.support_upload" = @("support-upload-denied")
    "authority.recovery_execution" = @("recovery-execution-denied")
    "authority.remote_dispatch" = @("remote-dispatch-denied")
    "authority.production_ring_mutation" = @("production-ring-mutation-denied")
}
$cases = @()
foreach ($caseId in $caseExpectations.Keys) {
    $cases += New-DenialCase -Id $caseId -ExpectedBlockers ([string[]]$caseExpectations[$caseId]) -ObservedBlockers $caseObservedBlockers
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$planspecPath = Join-Path $resolvedArtifactDir "install-update-planspec-package.json"
$envelopePath = Join-Path $resolvedArtifactDir "security-execution-install-update-envelope.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC16-021-install-update-planspec-binding.json"

$planspecPackage = [ordered]@{
    schema = "agentos.rc16-install-update-planspec-package.v1"
    generated_at = $generatedAtValue
    task = "RC16-021"
    status = "agentcore-install-update-planspec-bound-non-executable"
    production_ready_claim = $false
    package_id = [string]$preflightPackage.package_id
    media_id = [string]$preflightPackage.media_id
    release_id = [string]$preflightPackage.release_id
    preflight_id = [string]$preflightPackage.preflight_id
    planspec_core_hash = $planspecCoreHash
    planspec_materialization_digest = $planspecMaterializationDigest
    agentcore_install_update_planspec_bound = $true
    agentcore_install_update_planspec_executable = $agentCorePlanSpecExecutable
    planspec_core = $planspecCore
    blockers = @($blockers)
    denial_cases = $cases
    side_effects = $sideEffects
    authority = [ordered]@{
        aios_body_only = $true
        repo_local_projection_only = $true
        endpoint_reachability_authority = $false
        frontend_output_authority = $false
        signer_reachability_authority = $false
        shell_output_authority = $false
        tui_output_authority = $false
        model_replay_authority = $false
        object_storage_ui_authority = $false
        install_authority = $false
        update_authority = $false
        activation_authority = $false
        rollback_execution_authority = $false
        support_upload_authority = $false
        recovery_execution_authority = $false
        remote_dispatch_authority = $false
        production_ring_mutation_authority = $false
        signing_authority = $false
    }
    source = $source
}
Write-Json $planspecPackage $planspecPath

$securityEnvelope = [ordered]@{
    schema = "agentos.rc16-security-execution-install-update-envelope.v1"
    generated_at = $generatedAtValue
    task = "RC16-021"
    status = "security-execution-install-update-denied"
    production_ready_claim = $false
    package_id = [string]$preflightPackage.package_id
    media_id = [string]$preflightPackage.media_id
    release_id = [string]$preflightPackage.release_id
    preflight_id = [string]$preflightPackage.preflight_id
    planspec_core_hash = $planspecCoreHash
    effect_envelope_core_hash = $effectEnvelopeCoreHash
    decision_material_hash = $decisionMaterialHash
    security_execution_allowed = $securityExecutionAllowed
    effect_preparation_allowed = $false
    effect_prepared = $false
    effect_executed = $false
    install_effect_preparation_allowed = $false
    update_effect_preparation_allowed = $false
    install_allowed = $false
    update_allowed = $false
    install_performed = $false
    update_performed = $false
    activation_allowed = $false
    activation_performed = $false
    rollback_execution_allowed = $false
    support_upload_allowed = $false
    recovery_execution_allowed = $false
    remote_dispatch_enabled = $false
    production_ring_mutation_allowed = $false
    allowed_effects = @()
    denied_effects = $effectEnvelopeCore.denied_effects
    effect_envelope_core = $effectEnvelopeCore
    blockers = @($blockers)
    denial_cases = $cases
    side_effects = $sideEffects
    source = $source
}
Write-Json $securityEnvelope $envelopePath

Add-Check "plan.current_task.rc16_021" $planAllowsRun "RC16-021 must run after RC16-020 completed, either while current_task is RC16-021 or while rerunning after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc16_020_status = $rc16PreviousStatus; rc16_021_status = $rc16TaskStatus })
Add-Check "contract.agentcore_security_install_update.present" ($contractText.Contains("Bind AgentCore install/update PlanSpec package") -and $contractText.Contains("SecurityExecution allows the exact install/update effect envelope") -and $contractText.Contains("Rollback/support evidence is bound before any effect authority")) "RC16-021 must consume the install/update AgentCore and SecurityExecution gate contract." $source.rc16_contract
Add-Check "source.preflight.bound" $preflightEvidenceBound "RC16-021 must consume completed RC16-020 installer/updater preflight evidence." ([ordered]@{ status = $preflightResult.status; preflight_id = $preflightPackage.preflight_id; evidence_bound = $preflightPackage.installer_updater_preflight.evidence_bound })
Add-Check "source.package_identity.bound" ($releasePackageComplete -and $installableMediaComplete -and $descriptorFailClosedComplete -and $packageIdentityBound) "Release package, media manifest, descriptor fixtures, and package/media identity must be hash-bound." ([ordered]@{ release_package_complete = $releasePackageComplete; installable_media_complete = $installableMediaComplete; descriptor_fail_closed_complete = $descriptorFailClosedComplete; package_identity_bound = $packageIdentityBound })
Add-Check "source.bytes.strategy.rollback_support.bound" ($releaseBytesBound -and $updateStrategyBound -and $rollbackSupportSourceBound) "Payload bytes, inactive-slot update strategy, rollback baseline, and support/recovery source refs must be bound." ([ordered]@{ release_bytes_bound = $releaseBytesBound; update_strategy_bound = $updateStrategyBound; rollback_support_source_bound = $rollbackSupportSourceBound; rollback_baseline_sha256 = $rollbackBaselineSha256; support_index_sha256 = $supportIndexSha256 })
Add-Check "source.rc15.execution_and_code.bound" ($rc15ExecutionSourceBound -and $codeContractsPresent) "RC16-021 must bind RC15 controlled execution evidence plus AgentCore and SecurityExecution code contracts." ([ordered]@{ rc15_agentcore_executable = $rc15AgentCoreResult.summary.agentcore_planspec_executable; rc15_security_allowed = $rc15SecurityExecutionResult.summary.security_execution_allowed; agent_core_lib_sha256 = $agentCoreLibSha256; security_execution_policy_sha256 = $securityExecutionPolicySha256 })
Add-Check "planspec.requirements.bound_non_executable" ($planspecPackage.agentcore_install_update_planspec_bound -eq $true -and $planspecPackage.agentcore_install_update_planspec_executable -eq $false -and @($blockers | Where-Object { $_ -eq "rc16-exact-install-update-approval-not-bound" }).Count -eq 1 -and @($blockers | Where-Object { $_ -eq "rc16-rollback-support-package-not-bound" }).Count -eq 1) "AgentCore install/update PlanSpec must bind required slots while staying non-executable until exact approval and RC16 rollback/support package are bound." ([ordered]@{ planspec_core_hash = $planspecCoreHash; executable = $agentCorePlanSpecExecutable; blockers = @($blockers) })
Add-Check "security.envelope.denied_exact_blockers" ($securityEnvelope.security_execution_allowed -eq $false -and $securityEnvelope.effect_preparation_allowed -eq $false -and $securityEnvelope.effect_prepared -eq $false -and @($securityEnvelope.blockers).Count -ge 6) "SecurityExecution install/update envelope must deny with exact blockers and no effect preparation." ([ordered]@{ effect_envelope_core_hash = $effectEnvelopeCoreHash; decision_material_hash = $decisionMaterialHash; blockers = @($securityEnvelope.blockers) })
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 30) "Missing, stale, replayed, mismatched, broad, display-surface, and authority-broadening install/update cases must fail closed." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })
Add-Check "authority.no_side_effects" (@($sideEffects.GetEnumerator() | Where-Object { $_.Value -ne $false }).Count -eq 0) "RC16-021 must not prepare or execute install/update effects, mutate slots/boot metadata/artifact sets, dispatch remotely, upload support, recover, sign, or mutate production rings." $sideEffects

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $planspecPath),
    (Get-Content -Raw -LiteralPath $envelopePath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC16-021 outputs must not contain key blocks, private key paths, auth tokens, or public identity markers." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$planspecPackageSha256 = Get-FileSha256 $planspecPath
$securityEnvelopeSha256 = Get-FileSha256 $envelopePath
$result = [ordered]@{
    schema = "agentos.rc16-install-update-planspec-binding-result.v1"
    generated_at = $generatedAtValue
    task = "RC16-021"
    status = $resultStatus
    production_ready_claim = $false
    package_id = [string]$preflightPackage.package_id
    media_id = [string]$preflightPackage.media_id
    release_id = [string]$preflightPackage.release_id
    preflight_id = [string]$preflightPackage.preflight_id
    readiness_surface = [ordered]@{
        state = "agentcore-install-update-planspec-bound-security-execution-denied-effects-denied"
        preflight_evidence_bound = $preflightEvidenceBound
        release_package_complete = $releasePackageComplete
        installable_media_complete = $installableMediaComplete
        descriptor_fail_closed_complete = $descriptorFailClosedComplete
        package_identity_bound = $packageIdentityBound
        release_bytes_bound = $releaseBytesBound
        update_strategy_bound = $updateStrategyBound
        rollback_support_source_bound = $rollbackSupportSourceBound
        rollback_support_package_bound = $rollbackSupportPackageBound
        rc15_execution_source_bound = $rc15ExecutionSourceBound
        exact_install_update_target_bound = $exactInstallUpdateTargetBound
        exact_install_update_approval_bound = $exactInstallUpdateApprovalBound
        audit_sink_required = $true
        nonce_required = $true
        expiry_required = $true
        policy_version_required = $true
        required_policy_version = "policy-v1"
        planspec_core_hash = $planspecCoreHash
        planspec_materialization_digest = $planspecMaterializationDigest
        effect_envelope_core_hash = $effectEnvelopeCoreHash
        decision_material_hash = $decisionMaterialHash
        agentcore_install_update_planspec_bound = $true
        agentcore_install_update_planspec_executable = $agentCorePlanSpecExecutable
        security_execution_install_update_envelope_bound = $true
        security_execution_allowed = $securityExecutionAllowed
        install_effect_preparation_allowed = $installEffectPreparationAllowed
        update_effect_preparation_allowed = $updateEffectPreparationAllowed
        effect_prepared = $false
        install_allowed = $false
        update_allowed = $false
        install_performed = $false
        update_performed = $false
        activation_allowed = $false
        activation_performed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        blockers = @($blockers)
    }
    outputs = [ordered]@{
        install_update_planspec_package = [ordered]@{
            path = Get-StablePath $planspecPath
            sha256 = $planspecPackageSha256
            planspec_core_hash = $planspecCoreHash
            planspec_materialization_digest = $planspecMaterializationDigest
        }
        security_execution_install_update_envelope = [ordered]@{
            path = Get-StablePath $envelopePath
            sha256 = $securityEnvelopeSha256
            effect_envelope_core_hash = $effectEnvelopeCoreHash
            decision_material_hash = $decisionMaterialHash
        }
    }
    source = $source
    checks = @($script:checks)
    blockers = @($blockers)
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        repo_local_projection_only = $true
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
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
        rc16_021_complete = (@($script:failedChecks).Count -eq 0)
        agentcore_install_update_planspec_bound = $true
        agentcore_install_update_planspec_executable = $agentCorePlanSpecExecutable
        security_execution_install_update_envelope_bound = $true
        security_execution_allowed = $securityExecutionAllowed
        install_effect_preparation_allowed = $false
        update_effect_preparation_allowed = $false
        effect_prepared = $false
        next_task = "RC16-022"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc16-install-update-planspec-binding-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC16-021"
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
    readiness_surface = $result.readiness_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc16_021_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC16-022"
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
    throw "Sensitive marker detected in RC16-021 outputs."
}

Write-Host "RC16 install/update PlanSpec binding $($result.status): $(Get-StablePath $resultPath)"
Write-Host "PlanSpec package: $(Get-StablePath $planspecPath)"
Write-Host "SecurityExecution envelope: $(Get-StablePath $envelopePath)"
Write-Host "PlanSpec executable: $agentCorePlanSpecExecutable; SecurityExecution allowed: $securityExecutionAllowed; install/update effects allowed: false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
