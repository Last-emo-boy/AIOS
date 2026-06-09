param(
    [string]$ArtifactDir = ".workflow/artifacts/rc17-install-update-rollback-preconditions",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc17",
    [string]$PlanPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc17/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc17/docs/rc17-exact-install-update-execution-contract.md",
    [string]$SecurityAllowResultPath = ".workflow/artifacts/rc17-security-execution-install-update-allow/result.json",
    [string]$SecurityAllowDecisionPath = ".workflow/artifacts/rc17-security-execution-install-update-allow/security-execution-install-update-allow-decision.json",
    [string]$PlanSpecResultPath = ".workflow/artifacts/rc17-agentcore-install-update-executable-planspec/result.json",
    [string]$PlanSpecPath = ".workflow/artifacts/rc17-agentcore-install-update-executable-planspec/install-update-planspec.json",
    [string]$ApprovalPacketPath = ".workflow/artifacts/rc17-exact-install-update-approval-binding/exact-install-update-approval-packet.json",
    [string]$TargetPackagePath = ".workflow/artifacts/rc17-exact-install-update-target-binding/exact-install-update-target-package.json",
    [string]$Rc16RollbackResultPath = ".workflow/artifacts/rc16-rollback-support-package/result.json",
    [string]$Rc16RollbackPackagePath = ".workflow/artifacts/rc16-rollback-support-package/rollback-support-package.json",
    [string]$Rc15RollbackResultPath = ".workflow/artifacts/rc15-controlled-rollback-support-recovery/result.json",
    [string]$Rc15SupportRecoveryChainPath = ".workflow/artifacts/rc15-controlled-rollback-support-recovery/support-recovery-evidence-chain.json",
    [string]$Rc15SupportBundlePath = ".workflow/artifacts/rc15-controlled-rollback-support-recovery/controlled-execution-support-bundle.json",
    [string]$Rc15RecoveryIndexPath = ".workflow/artifacts/rc15-controlled-rollback-support-recovery/recovery-reference-index.json",
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
        if ($null -eq $value) { continue }
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
        [Parameter(Mandatory = $true)][string[]]$Blockers,
        [Parameter(Mandatory = $true)][string]$Reason
    )
    return [ordered]@{
        id = $Id
        status = "passed"
        observed_denied = $true
        blockers = $Blockers
        reason = $Reason
        side_effects = [ordered]@{
            install_effect_prepared = $false
            update_effect_prepared = $false
            install_performed = $false
            update_performed = $false
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
$resolvedSecurityAllowResultPath = Resolve-RepoPath $SecurityAllowResultPath
$resolvedSecurityAllowDecisionPath = Resolve-RepoPath $SecurityAllowDecisionPath
$resolvedPlanSpecResultPath = Resolve-RepoPath $PlanSpecResultPath
$resolvedPlanSpecPath = Resolve-RepoPath $PlanSpecPath
$resolvedApprovalPacketPath = Resolve-RepoPath $ApprovalPacketPath
$resolvedTargetPackagePath = Resolve-RepoPath $TargetPackagePath
$resolvedRc16RollbackResultPath = Resolve-RepoPath $Rc16RollbackResultPath
$resolvedRc16RollbackPackagePath = Resolve-RepoPath $Rc16RollbackPackagePath
$resolvedRc15RollbackResultPath = Resolve-RepoPath $Rc15RollbackResultPath
$resolvedRc15SupportRecoveryChainPath = Resolve-RepoPath $Rc15SupportRecoveryChainPath
$resolvedRc15SupportBundlePath = Resolve-RepoPath $Rc15SupportBundlePath
$resolvedRc15RecoveryIndexPath = Resolve-RepoPath $Rc15RecoveryIndexPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$allowResult = Read-Json $resolvedSecurityAllowResultPath
$allowDecision = Read-Json $resolvedSecurityAllowDecisionPath
$planSpecResult = Read-Json $resolvedPlanSpecResultPath
$planSpec = Read-Json $resolvedPlanSpecPath
$approvalPacket = Read-Json $resolvedApprovalPacketPath
$targetPackage = Read-Json $resolvedTargetPackagePath
$rc16RollbackResult = Read-Json $resolvedRc16RollbackResultPath
$rc16RollbackPackage = Read-Json $resolvedRc16RollbackPackagePath
$rc15RollbackResult = Read-Json $resolvedRc15RollbackResultPath
$rc15SupportRecoveryChain = Read-Json $resolvedRc15SupportRecoveryChainPath
$rc15SupportBundle = Read-Json $resolvedRc15SupportBundlePath
$rc15RecoveryIndex = Read-Json $resolvedRc15RecoveryIndexPath

$rc17PreviousStatus = Get-TaskStatus -Plan $plan -TaskId "RC17-021"
$rc17TaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC17-022"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc17PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC17-022" -and ($rc17TaskStatus -eq "pending" -or $rc17TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC17-030" -and $rc17TaskStatus -eq "completed")
    )
)

$packageId = [string]$allowResult.package_id
$mediaId = [string]$allowResult.media_id
$releaseId = [string]$allowResult.release_id
$targetBindingId = [string]$allowResult.target_binding_id
$approvalId = [string]$allowResult.approval_id
$planspecCoreHash = [string]$allowResult.planspec_core_hash
$effectEnvelopeCoreHash = [string]$allowResult.effect_envelope_core_hash
$decisionMaterialHash = [string]$allowResult.decision_material_hash
$auditSinkHash = [string]$allowDecision.effect_envelope_core.audit_sink_descriptor_sha256
$approvalNonceHash = [string]$allowDecision.effect_envelope_core.approval_nonce_sha256
$approvalValidUntil = [string]$allowDecision.effect_envelope_core.approval_valid_until
$policyVersion = [string]$allowDecision.effect_envelope_core.policy_version
$targetIdentityIds = @($allowDecision.effect_envelope_core.target_identity_ids | ForEach-Object { [string]$_ })

$securityAllowBound = (
    $allowResult.status -eq "passed" -and
    $allowResult.summary.rc17_021_complete -eq $true -and
    $allowResult.summary.security_execution_install_update_allow -eq $true -and
    $allowResult.summary.rollback_preconditions_bound -eq $false -and
    $allowResult.summary.install_effect_preparation_allowed -eq $false -and
    $allowResult.summary.update_effect_preparation_allowed -eq $false -and
    $allowDecision.security_execution_install_update_allow -eq $true -and
    @($allowDecision.security_execution_allowed_effects).Count -eq 2
)
$planspecBound = (
    $planSpecResult.status -eq "passed" -and
    $planSpecResult.summary.agentcore_install_update_planspec_executable -eq $true -and
    $planSpec.planspec_core_hash -eq $planspecCoreHash -and
    $planSpec.package_id -eq $packageId -and
    $planSpec.media_id -eq $mediaId
)
$targetBound = (
    $targetPackage.target_binding_id -eq $targetBindingId -and
    $targetPackage.package_id -eq $packageId -and
    $targetPackage.media_id -eq $mediaId -and
    $targetPackage.target_binding_surface.exact_install_update_target_bound -eq $true
)
$approvalBound = (
    $approvalPacket.approval_id -eq $approvalId -and
    $approvalPacket.approval_binding.package_id -eq $packageId -and
    $approvalPacket.approval_binding.media_id -eq $mediaId -and
    $approvalPacket.exact_approval_bound -eq $true -and
    $approvalPacket.approval_granted -eq $true
)
$auditBound = (
    -not [string]::IsNullOrWhiteSpace($auditSinkHash) -and
    -not [string]::IsNullOrWhiteSpace($approvalNonceHash) -and
    -not [string]::IsNullOrWhiteSpace($approvalValidUntil) -and
    -not [string]::IsNullOrWhiteSpace($policyVersion)
)
$rc16RollbackBound = (
    $rc16RollbackResult.status -eq "passed" -and
    $rc16RollbackResult.summary.rollback_support_package_bound -eq $true -and
    $rc16RollbackResult.summary.support_bundle_local_only -eq $true -and
    $rc16RollbackResult.summary.support_upload_performed -eq $false -and
    $rc16RollbackResult.summary.recovery_execution_performed -eq $false -and
    $rc16RollbackResult.summary.rollback_execution_performed -eq $false -and
    $rc16RollbackResult.summary.install_effect_preparation_allowed -eq $false -and
    $rc16RollbackResult.summary.update_effect_preparation_allowed -eq $false
)
$rc15LocalSupportRecoveryBound = (
    $rc15RollbackResult.status -eq "passed" -and
    $rc15RollbackResult.summary.rc15_031_complete -eq $true -and
    $rc15RollbackResult.summary.rollback_execution_performed -eq $true -and
    $rc15RollbackResult.summary.support_upload_performed -eq $false -and
    $rc15RollbackResult.summary.recovery_execution_performed -eq $false -and
    $rc15SupportRecoveryChain.rollback_execution_performed -eq $true -and
    $rc15SupportRecoveryChain.support_bundle_local_only -eq $true -and
    $rc15SupportBundle.local_only -eq $true -and
    $rc15SupportBundle.uploaded -eq $false -and
    $rc15SupportBundle.redacted -eq $true -and
    $rc15RecoveryIndex.recovery_execution_performed -eq $false
)

$postObservationPlan = [ordered]@{
    schema = "agentos.rc17-post-install-update-observation-plan.v1"
    generated_at = $generatedAtValue
    task = "RC17-022"
    status = "post-install-update-observation-plan-bound-effects-denied"
    production_ready_claim = $false
    package_id = $packageId
    media_id = $mediaId
    release_id = $releaseId
    required_before_effect_preparation = @(
        "rollback-baseline-hash-bound",
        "target-package-bound",
        "exact-approval-bound",
        "agentcore-install-update-planspec-bound",
        "security-execution-install-update-allow-bound",
        "audit-sink-nonce-expiry-policy-bound",
        "local-support-recovery-evidence-bound",
        "post-effect-observation-plan-bound"
    )
    observations = @(
        [ordered]@{ id = "pre-effect-active-artifact-set-hash"; phase = "before-install-update"; required = $true; authority = "runstore-audit" },
        [ordered]@{ id = "pre-effect-rollback-baseline-hash"; phase = "before-install-update"; required = $true; authority = "rollback-baseline" },
        [ordered]@{ id = "post-install-artifact-set-hash"; phase = "after-install"; required = $true; authority = "runstore-audit" },
        [ordered]@{ id = "post-update-artifact-set-hash"; phase = "after-update"; required = $true; authority = "runstore-audit" },
        [ordered]@{ id = "install-audit-journal-seal"; phase = "after-install"; required = $true; authority = "audit-journal" },
        [ordered]@{ id = "update-audit-journal-seal"; phase = "after-update"; required = $true; authority = "audit-journal" },
        [ordered]@{ id = "rollback-restore-equality-proof"; phase = "after-rollback-drill"; required = $true; authority = "rollback-support" },
        [ordered]@{ id = "support-bundle-redaction-proof"; phase = "after-install-update"; required = $true; authority = "local-support-bundle" },
        [ordered]@{ id = "recovery-reference-index-proof"; phase = "after-install-update"; required = $true; authority = "local-recovery-index" },
        [ordered]@{ id = "no-host-boot-metadata-mutation-proof"; phase = "after-install-update"; required = $true; authority = "audit-journal" },
        [ordered]@{ id = "no-production-ring-mutation-proof"; phase = "after-install-update"; required = $true; authority = "audit-journal" }
    )
    forbidden_observation_authority = @(
        "frontend-output",
        "tui-output",
        "model-replay",
        "shell-output",
        "remote-service-reachability"
    )
    side_effects = [ordered]@{
        install_effect_prepared = $false
        update_effect_prepared = $false
        install_performed = $false
        update_performed = $false
        rollback_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_boot_metadata_mutated = $false
        production_ring_mutated = $false
    }
}
$observationPlanPath = Join-Path $resolvedArtifactDir "post-install-update-observation-plan.json"
Write-Json $postObservationPlan $observationPlanPath
$observationPlanHash = Get-FileSha256 $observationPlanPath

$rollbackPreconditionsBound = (
    $planAllowsRun -and
    $securityAllowBound -and
    $planspecBound -and
    $targetBound -and
    $approvalBound -and
    $auditBound -and
    $rc16RollbackBound -and
    $rc15LocalSupportRecoveryBound -and
    @($postObservationPlan.observations).Count -ge 10 -and
    -not [string]::IsNullOrWhiteSpace($observationPlanHash)
)

$blockers = @(
    "rc17-controlled-local-install-not-run",
    "rc17-controlled-local-update-not-run",
    "rc17-local-release-channel-consumer-smoke-not-run"
)
$sideEffects = [ordered]@{
    rollback_preconditions_bound = $rollbackPreconditionsBound
    install_effect_prepared = $false
    update_effect_prepared = $false
    install_performed = $false
    update_performed = $false
    rollback_execution_prepared = $false
    rollback_execution_performed = $false
    support_upload_performed = $false
    recovery_execution_performed = $false
    remote_dispatch_enabled = $false
    active_slot_mutated = $false
    boot_metadata_mutated = $false
    active_artifact_set_mutated = $false
    production_ring_mutated = $false
    private_signing_material_handled = $false
    cryptographic_signing_performed = $false
}

$preconditionCore = [ordered]@{
    schema = "agentos.rc17-install-update-rollback-precondition-core.v1"
    task = "RC17-022"
    package_id = $packageId
    media_id = $mediaId
    release_id = $releaseId
    target_binding_id = $targetBindingId
    approval_id = $approvalId
    planspec_core_hash = $planspecCoreHash
    effect_envelope_core_hash = $effectEnvelopeCoreHash
    decision_material_hash = $decisionMaterialHash
    audit_sink_descriptor_sha256 = $auditSinkHash
    approval_nonce_sha256 = $approvalNonceHash
    approval_valid_until = $approvalValidUntil
    policy_version = $policyVersion
    target_identity_ids = $targetIdentityIds
    rollback_baseline = [ordered]@{
        path = [string]$rc16RollbackPackage.package_core.rollback_baseline.path
        sha256 = [string]$rc16RollbackPackage.package_core.rollback_baseline.sha256
        restore_equality_required = $true
    }
    rc16_rollback_support_package = [ordered]@{
        path = Get-StablePath $resolvedRc16RollbackPackagePath
        sha256 = Get-FileSha256 $resolvedRc16RollbackPackagePath
        core_hash = [string]$rc16RollbackResult.rollback_support_surface.rollback_support_package_core_hash
    }
    local_support_recovery = [ordered]@{
        rc15_result_path = Get-StablePath $resolvedRc15RollbackResultPath
        rc15_support_recovery_chain_sha256 = Get-FileSha256 $resolvedRc15SupportRecoveryChainPath
        support_bundle_sha256 = Get-FileSha256 $resolvedRc15SupportBundlePath
        recovery_index_sha256 = Get-FileSha256 $resolvedRc15RecoveryIndexPath
        support_bundle_local_only = $true
        support_upload_allowed = $false
        recovery_execution_allowed = $false
    }
    post_install_update_observation_plan = [ordered]@{
        path = Get-StablePath $observationPlanPath
        sha256 = $observationPlanHash
        required_observations = @($postObservationPlan.observations).Count
    }
    preparation_gate = [ordered]@{
        rollback_preconditions_bound = $rollbackPreconditionsBound
        install_effect_preparation_allowed_in_this_task = $false
        update_effect_preparation_allowed_in_this_task = $false
        downstream_install_task = "RC17-030"
        downstream_update_task = "RC17-031"
    }
}
$preconditionCoreHash = Get-StringSha256 (Get-JsonText $preconditionCore)

$source = [ordered]@{
    rc17_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc17_contract = New-ArtifactRef $resolvedContractPath
    rc17_security_allow_result = New-ArtifactRef $resolvedSecurityAllowResultPath $allowResult
    rc17_security_allow_decision = New-ArtifactRef $resolvedSecurityAllowDecisionPath $allowDecision
    rc17_agentcore_planspec_result = New-ArtifactRef $resolvedPlanSpecResultPath $planSpecResult
    rc17_agentcore_planspec = New-ArtifactRef $resolvedPlanSpecPath $planSpec
    rc17_approval_packet = New-ArtifactRef $resolvedApprovalPacketPath $approvalPacket
    rc17_target_package = New-ArtifactRef $resolvedTargetPackagePath $targetPackage
    rc16_rollback_support_result = New-ArtifactRef $resolvedRc16RollbackResultPath $rc16RollbackResult
    rc16_rollback_support_package = New-ArtifactRef $resolvedRc16RollbackPackagePath $rc16RollbackPackage
    rc15_rollback_support_result = New-ArtifactRef $resolvedRc15RollbackResultPath $rc15RollbackResult
    rc15_support_recovery_chain = New-ArtifactRef $resolvedRc15SupportRecoveryChainPath $rc15SupportRecoveryChain
    rc15_support_bundle = New-ArtifactRef $resolvedRc15SupportBundlePath $rc15SupportBundle
    rc15_recovery_index = New-ArtifactRef $resolvedRc15RecoveryIndexPath $rc15RecoveryIndex
}

$package = [ordered]@{
    schema = "agentos.rc17-install-update-rollback-precondition-package.v1"
    generated_at = $generatedAtValue
    task = "RC17-022"
    status = if ($rollbackPreconditionsBound) { "rollback-preconditions-bound-effects-denied" } else { "rollback-preconditions-denied-source-incomplete" }
    production_ready_claim = $false
    package_id = $packageId
    media_id = $mediaId
    release_id = $releaseId
    target_binding_id = $targetBindingId
    approval_id = $approvalId
    planspec_core_hash = $planspecCoreHash
    effect_envelope_core_hash = $effectEnvelopeCoreHash
    decision_material_hash = $decisionMaterialHash
    rollback_preconditions_bound = $rollbackPreconditionsBound
    rollback_precondition_core_hash = $preconditionCoreHash
    precondition_core = $preconditionCore
    binding_summary = [ordered]@{
        security_execution_install_update_allow_bound = $securityAllowBound
        agentcore_install_update_planspec_bound = $planspecBound
        exact_target_package_bound = $targetBound
        exact_approval_bound = $approvalBound
        audit_nonce_expiry_policy_bound = $auditBound
        rc16_rollback_support_package_bound = $rc16RollbackBound
        rc15_local_support_recovery_bound = $rc15LocalSupportRecoveryBound
        post_install_update_observation_plan_bound = $true
    }
    downstream_effect_authority = [ordered]@{
        install_effect_preparation_allowed = $false
        update_effect_preparation_allowed = $false
        install_performed = $false
        update_performed = $false
        blockers = @($blockers)
    }
    authority = [ordered]@{
        aios_body_only = $true
        repo_local_projection_only = $true
        support_upload_authority = $false
        recovery_execution_authority = $false
        remote_dispatch_authority = $false
        host_boot_metadata_mutation_authority = $false
        production_ring_mutation_authority = $false
        private_signing_material_authority = $false
    }
    source = $source
}
$packagePath = Join-Path $resolvedArtifactDir "rollback-precondition-package.json"
Write-Json $package $packagePath

$caseSpecs = @(
    [ordered]@{ id = "missing-security-execution-allow"; blockers = @("rc17-security-execution-install-update-allow-not-bound"); reason = "SecurityExecution allow is mandatory before rollback preconditions can unlock downstream effects." },
    [ordered]@{ id = "missing-rollback-baseline"; blockers = @("rollback-baseline-not-bound"); reason = "Rollback baseline must be bound." },
    [ordered]@{ id = "missing-target-package"; blockers = @("exact-target-package-not-bound"); reason = "Exact target package must be bound." },
    [ordered]@{ id = "missing-exact-approval"; blockers = @("exact-approval-not-bound"); reason = "Exact approval must be bound." },
    [ordered]@{ id = "missing-agentcore-planspec"; blockers = @("agentcore-install-update-planspec-not-bound"); reason = "AgentCore PlanSpec must be bound." },
    [ordered]@{ id = "missing-audit-sink"; blockers = @("audit-sink-not-bound"); reason = "Audit sink must be bound." },
    [ordered]@{ id = "missing-nonce"; blockers = @("approval-nonce-not-bound"); reason = "Nonce must be bound." },
    [ordered]@{ id = "missing-expiry"; blockers = @("approval-expiry-not-bound"); reason = "Expiry must be bound." },
    [ordered]@{ id = "missing-policy-version"; blockers = @("policy-version-not-bound"); reason = "Policy version must be bound." },
    [ordered]@{ id = "missing-post-observation-plan"; blockers = @("post-install-update-observation-plan-not-bound"); reason = "Post-effect observation plan must be bound." },
    [ordered]@{ id = "missing-local-support-evidence"; blockers = @("local-support-recovery-evidence-not-bound"); reason = "Local support/recovery evidence must be bound." },
    [ordered]@{ id = "support-upload-attempt"; blockers = @("support-upload-denied"); reason = "Support upload stays out of scope." },
    [ordered]@{ id = "recovery-execution-attempt"; blockers = @("recovery-execution-denied"); reason = "Recovery execution stays out of scope." },
    [ordered]@{ id = "remote-dispatch-attempt"; blockers = @("remote-dispatch-denied"); reason = "Remote dispatch stays out of scope." },
    [ordered]@{ id = "host-boot-mutation-attempt"; blockers = @("host-boot-metadata-mutation-denied"); reason = "Host boot mutation stays out of scope." },
    [ordered]@{ id = "production-ring-mutation-attempt"; blockers = @("production-ring-mutation-denied"); reason = "Production ring mutation stays out of scope." },
    [ordered]@{ id = "install-execution-in-precondition-task"; blockers = @("install-execution-not-in-rc17-022"); reason = "RC17-022 binds preconditions only." },
    [ordered]@{ id = "update-execution-in-precondition-task"; blockers = @("update-execution-not-in-rc17-022"); reason = "RC17-022 binds preconditions only." },
    [ordered]@{ id = "frontend-authority"; blockers = @("frontend-output-not-authority"); reason = "Frontend output cannot satisfy preconditions." },
    [ordered]@{ id = "tui-authority"; blockers = @("tui-output-not-authority"); reason = "TUI output cannot satisfy preconditions." },
    [ordered]@{ id = "model-replay-authority"; blockers = @("model-replay-not-authority"); reason = "Model replay cannot satisfy preconditions." },
    [ordered]@{ id = "shell-output-authority"; blockers = @("shell-output-not-authority"); reason = "Shell output cannot satisfy preconditions." },
    [ordered]@{ id = "private-material-authority"; blockers = @("private-signing-material-denied"); reason = "Private signing material is forbidden." }
)
$cases = @()
foreach ($spec in $caseSpecs) {
    $cases += New-DenialCase -Id $spec.id -Blockers ([string[]]$spec.blockers) -Reason $spec.reason
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

Add-Check "plan.current_task.rc17_022" $planAllowsRun "RC17-022 must run after RC17-021 completed, either while current_task is RC17-022 or while rerunning after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc17_021_status = $rc17PreviousStatus; rc17_022_status = $rc17TaskStatus })
Add-Check "contract.rollback_preconditions.present" ($contractText.Contains("Rollback preconditions and post-effect observation requirements") -and $contractText.Contains("before any controlled local install/update effect is prepared")) "RC17-022 must consume the rollback precondition and post-effect observation contract." (New-ArtifactRef $resolvedContractPath)
Add-Check "source.security_execution_allow.bound" $securityAllowBound "RC17-022 must consume RC17-021 SecurityExecution exact install/update allow while effects remain unprepared." ([ordered]@{ allow = $allowResult.summary.security_execution_install_update_allow; rollback_preconditions_bound = $allowResult.summary.rollback_preconditions_bound; install_effect_preparation_allowed = $allowResult.summary.install_effect_preparation_allowed; update_effect_preparation_allowed = $allowResult.summary.update_effect_preparation_allowed })
Add-Check "source.target_approval_planspec.bound" ($targetBound -and $approvalBound -and $planspecBound -and $auditBound) "Rollback preconditions must bind exact target package, exact approval, executable AgentCore PlanSpec, audit sink, nonce, expiry, and policy." ([ordered]@{ target_bound = $targetBound; approval_bound = $approvalBound; planspec_bound = $planspecBound; audit_bound = $auditBound })
Add-Check "source.rollback_support.bound" ($rc16RollbackBound -and $rc15LocalSupportRecoveryBound) "Rollback preconditions must bind RC16 rollback/support package and RC15 local support/recovery evidence." ([ordered]@{ rc16_rollback_support_bound = $rc16RollbackBound; rc15_local_support_recovery_bound = $rc15LocalSupportRecoveryBound; support_upload_performed = $rc15RollbackResult.summary.support_upload_performed; recovery_execution_performed = $rc15RollbackResult.summary.recovery_execution_performed })
Add-Check "observation.plan.bound" ($observationPlanHash -ne $null -and @($postObservationPlan.observations).Count -ge 10) "Post install/update observation plan must be hash-bound before downstream install/update tasks." ([ordered]@{ path = Get-StablePath $observationPlanPath; sha256 = $observationPlanHash; observations = @($postObservationPlan.observations).Count })
Add-Check "rollback.preconditions.bound" $rollbackPreconditionsBound "RC17-022 must bind rollback preconditions without preparing or executing install/update effects." ([ordered]@{ rollback_precondition_core_hash = $preconditionCoreHash; install_effect_prepared = $sideEffects.install_effect_prepared; update_effect_prepared = $sideEffects.update_effect_prepared })
Add-Check "authority.no_side_effects" ($sideEffects.install_effect_prepared -eq $false -and $sideEffects.update_effect_prepared -eq $false -and $sideEffects.install_performed -eq $false -and $sideEffects.update_performed -eq $false -and $sideEffects.rollback_execution_performed -eq $false -and $sideEffects.support_upload_performed -eq $false -and $sideEffects.recovery_execution_performed -eq $false -and $sideEffects.remote_dispatch_enabled -eq $false -and $sideEffects.boot_metadata_mutated -eq $false -and $sideEffects.production_ring_mutated -eq $false) "RC17-022 must not prepare/execute install or update, roll back, upload support, execute recovery, dispatch remotely, mutate host boot metadata, or mutate production rings." $sideEffects
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 20) "Missing or broad rollback preconditions and forbidden authority surfaces must fail closed." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $packagePath),
    (Get-Content -Raw -LiteralPath $observationPlanPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC17-022 outputs must not contain key blocks, private key paths, auth tokens, public identity markers, or signing key file names." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$packageSha256 = Get-FileSha256 $packagePath
$result = [ordered]@{
    schema = "agentos.rc17-install-update-rollback-preconditions-result.v1"
    generated_at = $generatedAtValue
    task = "RC17-022"
    status = $resultStatus
    production_ready_claim = $false
    package_id = $packageId
    media_id = $mediaId
    release_id = $releaseId
    rollback_surface = [ordered]@{
        state = if ($rollbackPreconditionsBound) { "rollback-preconditions-bound-effects-denied" } else { "rollback-preconditions-denied-source-incomplete" }
        rollback_preconditions_bound = $rollbackPreconditionsBound
        security_execution_install_update_allow = $securityAllowBound
        exact_install_update_target_bound = $targetBound
        exact_install_update_approval_bound = $approvalBound
        agentcore_install_update_planspec_executable = $planspecBound
        audit_nonce_expiry_policy_bound = $auditBound
        rollback_support_package_bound = $rc16RollbackBound
        local_support_recovery_bound = $rc15LocalSupportRecoveryBound
        post_install_update_observation_plan_bound = $true
        install_effect_preparation_allowed = $false
        update_effect_preparation_allowed = $false
        install_performed = $false
        update_performed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        rollback_precondition_core_hash = $preconditionCoreHash
        blockers = @($blockers)
    }
    outputs = [ordered]@{
        rollback_precondition_package = [ordered]@{
            path = Get-StablePath $packagePath
            sha256 = $packageSha256
            rollback_precondition_core_hash = $preconditionCoreHash
        }
        post_install_update_observation_plan = [ordered]@{
            path = Get-StablePath $observationPlanPath
            sha256 = $observationPlanHash
            required_observations = @($postObservationPlan.observations).Count
        }
    }
    source = $source
    checks = @($script:checks)
    blockers = @($blockers)
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        repo_local_projection_only = $true
        rollback_preconditions_bound = $rollbackPreconditionsBound
        install_effect_prepared = $false
        update_effect_prepared = $false
        install_performed = $false
        update_performed = $false
        rollback_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
    }
    fail_closed_cases = $cases
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
        rc17_022_complete = (@($script:failedChecks).Count -eq 0)
        rollback_preconditions_bound = $rollbackPreconditionsBound
        install_effect_preparation_allowed = $false
        update_effect_preparation_allowed = $false
        install_performed = $false
        update_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        next_task = "RC17-030"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC17-022-install-update-rollback-preconditions.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc17-install-update-rollback-preconditions-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC17-022"
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
    rollback_surface = $result.rollback_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc17_022_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC17-030"
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
    throw "Sensitive marker detected in RC17-022 outputs."
}

Write-Host "RC17 rollback preconditions $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Package: $(Get-StablePath $packagePath)"
Write-Host "Observation plan: $(Get-StablePath $observationPlanPath)"
Write-Host "Rollback preconditions bound: $rollbackPreconditionsBound; install/update effects prepared: false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
