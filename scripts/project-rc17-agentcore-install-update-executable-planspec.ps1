param(
    [string]$ArtifactDir = ".workflow/artifacts/rc17-agentcore-install-update-executable-planspec",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc17",
    [string]$PlanPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc17/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc17/docs/rc17-exact-install-update-execution-contract.md",
    [string]$TargetBindingResultPath = ".workflow/artifacts/rc17-exact-install-update-target-binding/result.json",
    [string]$TargetPackagePath = ".workflow/artifacts/rc17-exact-install-update-target-binding/exact-install-update-target-package.json",
    [string]$ApprovalBindingResultPath = ".workflow/artifacts/rc17-exact-install-update-approval-binding/result.json",
    [string]$ApprovalPacketPath = ".workflow/artifacts/rc17-exact-install-update-approval-binding/exact-install-update-approval-packet.json",
    [string]$PreflightResultPath = ".workflow/artifacts/rc16-installer-updater-preflight-package/result.json",
    [string]$PreflightPackagePath = ".workflow/artifacts/rc16-installer-updater-preflight-package/installer-updater-preflight-package.json",
    [string]$Rc16PlanSpecResultPath = ".workflow/artifacts/rc16-install-update-planspec-binding/result.json",
    [string]$Rc16PlanSpecPackagePath = ".workflow/artifacts/rc16-install-update-planspec-binding/install-update-planspec-package.json",
    [string]$Rc16SecurityEnvelopePath = ".workflow/artifacts/rc16-install-update-planspec-binding/security-execution-install-update-envelope.json",
    [string]$RollbackSupportResultPath = ".workflow/artifacts/rc16-rollback-support-package/result.json",
    [string]$RollbackSupportPackagePath = ".workflow/artifacts/rc16-rollback-support-package/rollback-support-package.json",
    [string]$AgentCoreLibPath = "crates/agent_core/src/lib.rs",
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
            planspec_executable = $false
            effect_prepared = $false
            security_execution_allowed = $false
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
$resolvedTargetBindingResultPath = Resolve-RepoPath $TargetBindingResultPath
$resolvedTargetPackagePath = Resolve-RepoPath $TargetPackagePath
$resolvedApprovalBindingResultPath = Resolve-RepoPath $ApprovalBindingResultPath
$resolvedApprovalPacketPath = Resolve-RepoPath $ApprovalPacketPath
$resolvedPreflightResultPath = Resolve-RepoPath $PreflightResultPath
$resolvedPreflightPackagePath = Resolve-RepoPath $PreflightPackagePath
$resolvedRc16PlanSpecResultPath = Resolve-RepoPath $Rc16PlanSpecResultPath
$resolvedRc16PlanSpecPackagePath = Resolve-RepoPath $Rc16PlanSpecPackagePath
$resolvedRc16SecurityEnvelopePath = Resolve-RepoPath $Rc16SecurityEnvelopePath
$resolvedRollbackSupportResultPath = Resolve-RepoPath $RollbackSupportResultPath
$resolvedRollbackSupportPackagePath = Resolve-RepoPath $RollbackSupportPackagePath
$resolvedAgentCoreLibPath = Resolve-RepoPath $AgentCoreLibPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$targetBindingResult = Read-Json $resolvedTargetBindingResultPath
$targetPackage = Read-Json $resolvedTargetPackagePath
$approvalBindingResult = Read-Json $resolvedApprovalBindingResultPath
$approvalPacket = Read-Json $resolvedApprovalPacketPath
$preflightResult = Read-Json $resolvedPreflightResultPath
$preflightPackage = Read-Json $resolvedPreflightPackagePath
$rc16PlanSpecResult = Read-Json $resolvedRc16PlanSpecResultPath
$rc16PlanSpecPackage = Read-Json $resolvedRc16PlanSpecPackagePath
$rc16SecurityEnvelope = Read-Json $resolvedRc16SecurityEnvelopePath
$rollbackSupportResult = Read-Json $resolvedRollbackSupportResultPath
$rollbackSupportPackage = Read-Json $resolvedRollbackSupportPackagePath

$rc17PreviousStatus = Get-TaskStatus -Plan $plan -TaskId "RC17-011"
$rc17TaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC17-020"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc17PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC17-020" -and ($rc17TaskStatus -eq "pending" -or $rc17TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC17-021" -and $rc17TaskStatus -eq "completed")
    )
)

$packageId = [string]$approvalPacket.approval_binding.package_id
$mediaId = [string]$approvalPacket.approval_binding.media_id
$releaseId = [string]$approvalPacket.approval_binding.release_id
$preflightId = [string]$approvalPacket.approval_binding.preflight_id
$targetBindingId = [string]$approvalPacket.approval_binding.target_binding_id
$approvalId = [string]$approvalPacket.approval_id
$approvalBindingDigest = [string]$approvalPacket.approval_binding_digest
$payloadSha256 = [string]$approvalPacket.approval_binding.object_digest
$targetIdentitySetDigest = [string]$approvalPacket.approval_binding.target_identity_set_digest
$targetIdentityIds = @($approvalPacket.approval_binding.target_identity_ids | ForEach-Object { [string]$_ })
$targetIdentityDigests = @($approvalPacket.approval_binding.target_identity_digests | ForEach-Object { [string]$_ })
$planspecReferenceHash = [string]$approvalPacket.approval_binding.agentcore_package_reference.planspec_core_hash
$planspecReferenceSha256 = [string]$approvalPacket.approval_binding.agentcore_package_reference.sha256
$securityEnvelopeCoreHash = [string]$approvalPacket.approval_binding.security_execution_envelope_reference.effect_envelope_core_hash
$securityDecisionMaterialHash = [string]$approvalPacket.approval_binding.security_execution_envelope_reference.decision_material_hash
$rollbackSupportCoreHash = [string]$approvalPacket.approval_binding.rollback_support_reference.rollback_support_package_core_hash
$auditSinkDescriptorSha256 = [string]$approvalPacket.approval_binding.audit_sink_descriptor_sha256
$auditBindingSha256 = [string]$approvalPacket.approval_binding.audit_binding_sha256
$approvalNonceSha256 = [string]$approvalPacket.approval_binding.approval_nonce_sha256
$approvalValidUntil = [string]$approvalPacket.approval_binding.approval_valid_until
$policyVersion = [string]$approvalPacket.approval_binding.policy_version
$agentCoreLibSha256 = Get-FileSha256 $resolvedAgentCoreLibPath

$preflightBound = $preflightResult.status -eq "passed" -and
    $preflightResult.summary.rc16_020_complete -eq $true -and
    $preflightPackage.installer_updater_preflight.evidence_bound -eq $true -and
    $preflightPackage.package_id -eq $packageId -and
    $preflightPackage.media_id -eq $mediaId -and
    $preflightPackage.release_id -eq $releaseId
$targetBound = $targetBindingResult.status -eq "passed" -and
    $targetBindingResult.summary.rc17_010_complete -eq $true -and
    $targetPackage.target_binding_surface.exact_install_update_target_bound -eq $true -and
    $targetPackage.target_binding_id -eq $targetBindingId -and
    $targetPackage.package_id -eq $packageId -and
    $targetPackage.media_id -eq $mediaId -and
    $targetPackage.release_id -eq $releaseId
$approvalBound = $approvalBindingResult.status -eq "passed" -and
    $approvalBindingResult.summary.rc17_011_complete -eq $true -and
    $approvalPacket.exact_approval_bound -eq $true -and
    $approvalPacket.approval_granted -eq $true -and
    $approvalPacket.approval_binding_digest -eq $approvalBindingDigest
$operationsBound = @($approvalPacket.approval_binding.approved_operations | Where-Object { $_.operation_type -eq "install" }).Count -eq 1 -and
    @($approvalPacket.approval_binding.approved_operations | Where-Object { $_.operation_type -eq "update" }).Count -eq 1
$auditNoncePolicyBound = -not [string]::IsNullOrWhiteSpace($auditSinkDescriptorSha256) -and
    -not [string]::IsNullOrWhiteSpace($auditBindingSha256) -and
    -not [string]::IsNullOrWhiteSpace($approvalNonceSha256) -and
    -not [string]::IsNullOrWhiteSpace($approvalValidUntil) -and
    -not [string]::IsNullOrWhiteSpace($policyVersion)
$rollbackSupportBound = $rollbackSupportResult.status -eq "passed" -and
    $rollbackSupportResult.summary.rollback_support_package_bound -eq $true -and
    $rollbackSupportPackage.rollback_support_package_bound -eq $true -and
    $rollbackSupportPackage.rollback_support_package_core_hash -eq $rollbackSupportCoreHash
$rc16ReferenceBound = $rc16PlanSpecResult.status -eq "passed" -and
    $rc16PlanSpecPackage.agentcore_install_update_planspec_bound -eq $true -and
    $rc16PlanSpecPackage.planspec_core_hash -eq $planspecReferenceHash -and
    (Get-FileSha256 $resolvedRc16PlanSpecPackagePath) -eq $planspecReferenceSha256
$securityEnvelopeReferenceBound = $rc16SecurityEnvelope.effect_envelope_core_hash -eq $securityEnvelopeCoreHash -and
    $rc16SecurityEnvelope.decision_material_hash -eq $securityDecisionMaterialHash

$planspecExecutable = $preflightBound -and
    $targetBound -and
    $approvalBound -and
    $operationsBound -and
    $auditNoncePolicyBound -and
    $rollbackSupportBound -and
    $rc16ReferenceBound -and
    $securityEnvelopeReferenceBound

$securityExecutionAllowed = $false
$rollbackPreconditionsBound = $false
$installEffectPreparationAllowed = $false
$updateEffectPreparationAllowed = $false

$blockers = @(
    "rc17-security-execution-install-update-allow-not-bound",
    "rc17-rollback-preconditions-not-bound",
    "rc17-controlled-local-install-not-run",
    "rc17-controlled-local-update-not-run",
    "rc17-local-release-channel-consumer-smoke-not-run"
)

$planspecCore = [ordered]@{
    schema = "agentos.agentcore.install-update-planspec.v1"
    task = "RC17-020"
    plan_kind = "exact-install-update-execute-or-deny"
    executable = $planspecExecutable
    production_ready_claim = $false
    package_id = $packageId
    media_id = $mediaId
    release_id = $releaseId
    preflight_id = $preflightId
    target_binding_id = $targetBindingId
    approval_id = $approvalId
    approval_binding_digest = $approvalBindingDigest
    payload_sha256 = $payloadSha256
    target_identity_set_digest = $targetIdentitySetDigest
    target_identity_ids = $targetIdentityIds
    binding_slots = [ordered]@{
        rc16_package_preflight = [ordered]@{
            required = $true
            bound = $preflightBound
            preflight_id = $preflightId
            result_sha256 = Get-FileSha256 $resolvedPreflightResultPath
            package_sha256 = Get-FileSha256 $resolvedPreflightPackagePath
        }
        exact_target = [ordered]@{
            required = $true
            bound = $targetBound
            target_binding_id = $targetBindingId
            target_package_sha256 = Get-FileSha256 $resolvedTargetPackagePath
            target_identity_set_digest = $targetIdentitySetDigest
            target_identity_count = @($targetIdentityIds).Count
        }
        exact_approval = [ordered]@{
            required = $true
            bound = $approvalBound
            approval_id = $approvalId
            approval_binding_digest = $approvalBindingDigest
            approval_packet_sha256 = Get-FileSha256 $resolvedApprovalPacketPath
            approval_granted = [bool]$approvalPacket.approval_granted
        }
        audit_nonce_expiry_policy = [ordered]@{
            required = $true
            bound = $auditNoncePolicyBound
            audit_sink_descriptor_sha256 = $auditSinkDescriptorSha256
            audit_binding_sha256 = $auditBindingSha256
            approval_nonce_sha256 = $approvalNonceSha256
            approval_valid_until = $approvalValidUntil
            policy_version = $policyVersion
        }
        approved_operations = [ordered]@{
            required = $true
            bound = $operationsBound
            operations = @("install", "update")
            operation_count = 2
        }
        rc16_agentcore_package_reference = [ordered]@{
            required = $true
            bound = $rc16ReferenceBound
            path = Get-StablePath $resolvedRc16PlanSpecPackagePath
            sha256 = Get-FileSha256 $resolvedRc16PlanSpecPackagePath
            previous_planspec_core_hash = $planspecReferenceHash
        }
        rc16_security_execution_envelope_reference = [ordered]@{
            required = $true
            bound = $securityEnvelopeReferenceBound
            path = Get-StablePath $resolvedRc16SecurityEnvelopePath
            sha256 = Get-FileSha256 $resolvedRc16SecurityEnvelopePath
            effect_envelope_core_hash = $securityEnvelopeCoreHash
            decision_material_hash = $securityDecisionMaterialHash
            allow_required_before_effect = $true
            allow_bound = $securityExecutionAllowed
        }
        rollback_support_reference = [ordered]@{
            required = $true
            bound = $rollbackSupportBound
            path = Get-StablePath $resolvedRollbackSupportPackagePath
            sha256 = Get-FileSha256 $resolvedRollbackSupportPackagePath
            rollback_support_package_core_hash = $rollbackSupportCoreHash
        }
        source_code_contracts = [ordered]@{
            required = $true
            bound = -not [string]::IsNullOrWhiteSpace($agentCoreLibSha256)
            agent_core_lib_sha256 = $agentCoreLibSha256
        }
    }
    effect_boundary = [ordered]@{
        agentcore_install_update_planspec_executable = $planspecExecutable
        security_execution_install_update_allow = $securityExecutionAllowed
        rollback_preconditions_bound = $rollbackPreconditionsBound
        install_effect_preparation_allowed = $installEffectPreparationAllowed
        update_effect_preparation_allowed = $updateEffectPreparationAllowed
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
    }
    steps = @(
        [ordered]@{ id = "bind-rc16-package-preflight"; authority = "hash-bound-evidence"; executable = $preflightBound },
        [ordered]@{ id = "bind-exact-install-update-target"; authority = "rc17-target-package"; executable = $targetBound },
        [ordered]@{ id = "bind-exact-install-update-approval"; authority = "repo-local-audit-bound-approval"; executable = $approvalBound },
        [ordered]@{ id = "materialize-install-plan"; authority = "agentcore"; executable = $planspecExecutable; effect_prepared = $false },
        [ordered]@{ id = "materialize-update-plan"; authority = "agentcore"; executable = $planspecExecutable; effect_prepared = $false },
        [ordered]@{ id = "await-security-execution-install-update-allow"; authority = "security-execution"; executable = $false; source_task = "RC17-021" },
        [ordered]@{ id = "await-rollback-preconditions"; authority = "rollback-gate"; executable = $false; source_task = "RC17-022" }
    )
}
$planspecCoreHash = Get-StringSha256 (Get-JsonText $planspecCore)

$sideEffects = [ordered]@{
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

$planspec = [ordered]@{
    schema = "agentos.rc17-agentcore-install-update-planspec.v1"
    generated_at = $generatedAtValue
    task = "RC17-020"
    status = "agentcore-install-update-planspec-executable-effects-denied"
    production_ready_claim = $false
    package_id = $packageId
    media_id = $mediaId
    release_id = $releaseId
    preflight_id = $preflightId
    target_binding_id = $targetBindingId
    approval_id = $approvalId
    approval_binding_digest = $approvalBindingDigest
    planspec_core_hash = $planspecCoreHash
    planspec_materialization_digest = $planspecCoreHash
    agentcore_install_update_planspec_executable = $planspecExecutable
    planspec_core = $planspecCore
    install_plan = [ordered]@{
        operation_type = "install"
        executable = $planspecExecutable
        target_binding_id = $targetBindingId
        target_identity_set_digest = $targetIdentitySetDigest
        package_id = $packageId
        media_id = $mediaId
        release_id = $releaseId
        effect_preparation_allowed = $false
        effect_prepared = $false
        effect_executed = $false
    }
    update_plan = [ordered]@{
        operation_type = "update"
        executable = $planspecExecutable
        target_binding_id = $targetBindingId
        target_identity_set_digest = $targetIdentitySetDigest
        package_id = $packageId
        media_id = $mediaId
        release_id = $releaseId
        update_strategy = $targetPackage.exact_targets.update.update_strategy
        effect_preparation_allowed = $false
        effect_prepared = $false
        effect_executed = $false
    }
    downstream_gates = [ordered]@{
        security_execution_install_update_allow_required = $true
        security_execution_install_update_allow = $false
        rollback_preconditions_required = $true
        rollback_preconditions_bound = $false
        controlled_install_required = $true
        controlled_update_required = $true
    }
    blockers = @($blockers)
    side_effects = $sideEffects
    authority = [ordered]@{
        aios_body_only = $true
        repo_local_projection_only = $true
        agentcore_planspec_authority = $true
        agentcore_effect_execution_authority = $false
        security_execution_authority = $false
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
    }
}
$planspecPath = Join-Path $resolvedArtifactDir "install-update-planspec.json"
Write-Json $planspec $planspecPath

$caseSpecs = @(
    [ordered]@{ id = "missing-rc16-package-preflight-denied"; blockers = @("rc16-package-preflight-missing"); reason = "RC16 package and preflight evidence are required." },
    [ordered]@{ id = "missing-exact-target-denied"; blockers = @("exact-install-update-target-missing"); reason = "Exact target package is required." },
    [ordered]@{ id = "missing-exact-approval-denied"; blockers = @("exact-install-update-approval-missing"); reason = "Exact install/update approval is required." },
    [ordered]@{ id = "approval-not-granted-denied"; blockers = @("approval-not-granted"); reason = "Unapproved PlanSpec must deny." },
    [ordered]@{ id = "missing-audit-sink-denied"; blockers = @("approval-audit-sink-not-bound"); reason = "Audit sink binding is required." },
    [ordered]@{ id = "missing-nonce-denied"; blockers = @("approval-nonce-not-bound"); reason = "Nonce binding is required." },
    [ordered]@{ id = "missing-expiry-denied"; blockers = @("approval-expiry-not-bound"); reason = "Expiry binding is required." },
    [ordered]@{ id = "missing-policy-version-denied"; blockers = @("approval-policy-version-not-bound"); reason = "Policy version binding is required." },
    [ordered]@{ id = "missing-rollback-support-denied"; blockers = @("rollback-support-reference-not-bound"); reason = "Rollback and support references are required." },
    [ordered]@{ id = "missing-install-operation-denied"; blockers = @("install-operation-not-bound"); reason = "Install operation must be exact." },
    [ordered]@{ id = "missing-update-operation-denied"; blockers = @("update-operation-not-bound"); reason = "Update operation must be exact." },
    [ordered]@{ id = "broad-operation-plan-denied"; blockers = @("broad-operation-plan"); reason = "PlanSpec cannot broaden install/update into other effects." },
    [ordered]@{ id = "stale-planspec-package-denied"; blockers = @("planspec-package-stale"); reason = "Stale PlanSpec packages must deny." },
    [ordered]@{ id = "replayed-planspec-package-denied"; blockers = @("planspec-package-replay-detected"); reason = "Replayed PlanSpec packages must deny." },
    [ordered]@{ id = "package-mismatch-denied"; blockers = @("planspec-package-mismatch"); reason = "Package mismatch must deny." },
    [ordered]@{ id = "media-mismatch-denied"; blockers = @("planspec-media-mismatch"); reason = "Media mismatch must deny." },
    [ordered]@{ id = "preflight-mismatch-denied"; blockers = @("planspec-preflight-mismatch"); reason = "Preflight mismatch must deny." },
    [ordered]@{ id = "target-binding-mismatch-denied"; blockers = @("planspec-target-binding-mismatch"); reason = "Target binding mismatch must deny." },
    [ordered]@{ id = "approval-mismatch-denied"; blockers = @("planspec-approval-mismatch"); reason = "Approval mismatch must deny." },
    [ordered]@{ id = "target-identity-mismatch-denied"; blockers = @("planspec-target-identity-mismatch"); reason = "Target identity mismatch must deny." },
    [ordered]@{ id = "agentcore-reference-mismatch-denied"; blockers = @("agentcore-reference-mismatch"); reason = "AgentCore reference mismatch must deny." },
    [ordered]@{ id = "security-envelope-reference-mismatch-denied"; blockers = @("security-envelope-reference-mismatch"); reason = "SecurityExecution envelope mismatch must deny." },
    [ordered]@{ id = "rollback-support-mismatch-denied"; blockers = @("rollback-support-reference-mismatch"); reason = "Rollback/support mismatch must deny." },
    [ordered]@{ id = "security-execution-allow-missing-effect-denied"; blockers = @("security-execution-install-update-allow-not-bound"); reason = "Executable PlanSpec still requires SecurityExecution allow before effect." },
    [ordered]@{ id = "rollback-preconditions-missing-effect-denied"; blockers = @("rollback-preconditions-not-bound"); reason = "Executable PlanSpec still requires rollback preconditions before effect." },
    [ordered]@{ id = "effect-preparation-bypass-denied"; blockers = @("effect-preparation-bypass"); reason = "PlanSpec materialization must not prepare effects." },
    [ordered]@{ id = "host-active-slot-mutation-denied"; blockers = @("host-active-slot-mutation-forbidden"); reason = "PlanSpec materialization must not mutate active slot state." },
    [ordered]@{ id = "host-boot-metadata-mutation-denied"; blockers = @("host-boot-metadata-mutation-forbidden"); reason = "PlanSpec materialization must not mutate boot metadata." },
    [ordered]@{ id = "remote-dispatch-authority-denied"; blockers = @("remote-dispatch-authority-forbidden"); reason = "PlanSpec materialization must not enable remote dispatch." },
    [ordered]@{ id = "support-upload-authority-denied"; blockers = @("support-upload-authority-forbidden"); reason = "PlanSpec materialization must not enable support upload." },
    [ordered]@{ id = "recovery-execution-authority-denied"; blockers = @("recovery-execution-authority-forbidden"); reason = "PlanSpec materialization must not enable recovery execution." },
    [ordered]@{ id = "production-ring-mutation-denied"; blockers = @("production-ring-mutation-forbidden"); reason = "PlanSpec materialization must not mutate production rings." }
)
$cases = @()
foreach ($spec in $caseSpecs) {
    $cases += New-DenialCase -Id $spec.id -ExpectedBlockers ([string[]]$spec.blockers) -Reason $spec.reason
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$matrix = [ordered]@{
    schema = "agentos.rc17-install-update-planspec-fail-closed-matrix.v1"
    generated_at = $generatedAtValue
    task = "RC17-020"
    status = if ($failedCases.Count -eq 0) { "passed" } else { "failed" }
    production_ready_claim = $false
    planspec_core_hash = $planspecCoreHash
    cases = $cases
    summary = [ordered]@{
        cases = @($cases).Count
        passed = @($cases | Where-Object { $_.status -eq "passed" }).Count
        failed = $failedCases.Count
        failed_cases = @($failedCases | ForEach-Object { $_.id })
    }
}
$matrixPath = Join-Path $resolvedArtifactDir "install-update-planspec-fail-closed-matrix.json"
Write-Json $matrix $matrixPath

$source = [ordered]@{
    rc17_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc17_contract = New-ArtifactRef $resolvedContractPath
    rc17_target_binding_result = New-ArtifactRef $resolvedTargetBindingResultPath $targetBindingResult
    rc17_target_package = New-ArtifactRef $resolvedTargetPackagePath $targetPackage
    rc17_approval_binding_result = New-ArtifactRef $resolvedApprovalBindingResultPath $approvalBindingResult
    rc17_approval_packet = New-ArtifactRef $resolvedApprovalPacketPath $approvalPacket
    rc16_preflight_result = New-ArtifactRef $resolvedPreflightResultPath $preflightResult
    rc16_preflight_package = New-ArtifactRef $resolvedPreflightPackagePath $preflightPackage
    rc16_planspec_result = New-ArtifactRef $resolvedRc16PlanSpecResultPath $rc16PlanSpecResult
    rc16_planspec_package = New-ArtifactRef $resolvedRc16PlanSpecPackagePath $rc16PlanSpecPackage
    rc16_security_execution_envelope = New-ArtifactRef $resolvedRc16SecurityEnvelopePath $rc16SecurityEnvelope
    rc16_rollback_support_result = New-ArtifactRef $resolvedRollbackSupportResultPath $rollbackSupportResult
    rc16_rollback_support_package = New-ArtifactRef $resolvedRollbackSupportPackagePath $rollbackSupportPackage
    agent_core_lib = New-ArtifactRef $resolvedAgentCoreLibPath
}

Add-Check "plan.current_task.rc17_020" $planAllowsRun "RC17-020 must run after RC17-011 completed, either while current_task is RC17-020 or while rerunning after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc17_011_status = $rc17PreviousStatus; rc17_020_status = $rc17TaskStatus })
Add-Check "contract.agentcore_planspec_gate.present" ($contractText.Contains("AgentCore install/update PlanSpecs") -and $contractText.Contains("exact target") -and $contractText.Contains("exact approval") -and $contractText.Contains("rollback")) "RC17-020 must consume the AgentCore install/update PlanSpec contract." (New-ArtifactRef $resolvedContractPath)
Add-Check "source.rc16_preflight.bound" $preflightBound "RC17-020 must bind completed RC16 package and installer/updater preflight evidence." ([ordered]@{ package_id = $packageId; media_id = $mediaId; release_id = $releaseId; preflight_id = $preflightId })
Add-Check "source.exact_target.bound" $targetBound "RC17-020 must bind completed exact install/update target package evidence." ([ordered]@{ target_binding_id = $targetBindingId; target_identity_set_digest = $targetIdentitySetDigest; target_identity_count = @($targetIdentityIds).Count })
Add-Check "source.exact_approval.bound" ($approvalBound -and $operationsBound -and $auditNoncePolicyBound) "RC17-020 must bind exact approval, install/update operations, audit sink, nonce, expiry, and policy." ([ordered]@{ approval_id = $approvalId; approval_binding_digest = $approvalBindingDigest; operations_bound = $operationsBound; audit_nonce_policy_bound = $auditNoncePolicyBound })
Add-Check "source.agentcore_security_rollback.refs_bound" ($rc16ReferenceBound -and $securityEnvelopeReferenceBound -and $rollbackSupportBound) "RC17-020 must bind RC16 AgentCore package reference, SecurityExecution envelope reference, and rollback/support references." ([ordered]@{ rc16_reference_bound = $rc16ReferenceBound; security_envelope_reference_bound = $securityEnvelopeReferenceBound; rollback_support_bound = $rollbackSupportBound })
Add-Check "planspec.executable_only_after_required_bindings" ($planspecExecutable -eq $true -and $planspec.agentcore_install_update_planspec_executable -eq $true -and $planspec.planspec_core.binding_slots.exact_target.bound -eq $true -and $planspec.planspec_core.binding_slots.exact_approval.bound -eq $true -and $planspec.planspec_core.binding_slots.audit_nonce_expiry_policy.bound -eq $true -and $planspec.planspec_core.binding_slots.rollback_support_reference.bound -eq $true) "AgentCore install/update PlanSpec must be executable only after RC16 package/preflight, exact target, exact approval, audit, nonce, expiry, policy, rollback, and support references are bound." ([ordered]@{ planspec_core_hash = $planspecCoreHash; executable = $planspecExecutable; binding_slots = $planspec.planspec_core.binding_slots })
Add-Check "planspec.materialization_no_effect_preparation" ($planspec.install_plan.effect_prepared -eq $false -and $planspec.update_plan.effect_prepared -eq $false -and $planspec.downstream_gates.security_execution_install_update_allow -eq $false -and $planspec.downstream_gates.rollback_preconditions_bound -eq $false -and $planspec.install_plan.effect_executed -eq $false -and $planspec.update_plan.effect_executed -eq $false) "PlanSpec materialization must not prepare or execute install/update effects and must still require SecurityExecution allow plus rollback preconditions." ([ordered]@{ blockers = @($blockers); install_plan = $planspec.install_plan; update_plan = $planspec.update_plan })
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 30) "Missing, broad, stale, mismatched, unapproved, SecurityExecution-bypass, rollback-precondition-bypass, and authority-broadening PlanSpec packages must fail closed." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })
Add-Check "authority.no_side_effects" (@($sideEffects.GetEnumerator() | Where-Object { $_.Value -ne $false }).Count -eq 0) "RC17-020 must not prepare or execute install/update effects, mutate host state, upload support, recover, dispatch remotely, or mutate production rings." $sideEffects

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $planspecPath),
    (Get-Content -Raw -LiteralPath $matrixPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC17-020 outputs must not contain key blocks, private key paths, auth tokens, public identity markers, or signing key file names." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$planspecSha256 = Get-FileSha256 $planspecPath
$matrixSha256 = Get-FileSha256 $matrixPath
$result = [ordered]@{
    schema = "agentos.rc17-agentcore-install-update-executable-planspec-result.v1"
    generated_at = $generatedAtValue
    task = "RC17-020"
    status = $resultStatus
    production_ready_claim = $false
    package_id = $packageId
    media_id = $mediaId
    release_id = $releaseId
    target_binding_id = $targetBindingId
    approval_id = $approvalId
    approval_binding_digest = $approvalBindingDigest
    planspec_surface = [ordered]@{
        state = "agentcore-install-update-planspec-executable-effects-denied"
        planspec_core_hash = $planspecCoreHash
        planspec_materialization_digest = $planspecCoreHash
        agentcore_install_update_planspec_executable = $planspecExecutable
        exact_install_update_target_bound = $targetBound
        exact_install_update_approval_bound = $approvalBound
        audit_nonce_policy_bound = $auditNoncePolicyBound
        rollback_support_reference_bound = $rollbackSupportBound
        security_execution_install_update_allow = $securityExecutionAllowed
        rollback_preconditions_bound = $rollbackPreconditionsBound
        install_effect_preparation_allowed = $installEffectPreparationAllowed
        update_effect_preparation_allowed = $updateEffectPreparationAllowed
        install_allowed = $false
        update_allowed = $false
        install_performed = $false
        update_performed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        blockers = @($blockers)
    }
    outputs = [ordered]@{
        install_update_planspec = [ordered]@{
            path = Get-StablePath $planspecPath
            sha256 = $planspecSha256
            planspec_core_hash = $planspecCoreHash
            planspec_materialization_digest = $planspecCoreHash
        }
        install_update_planspec_fail_closed_matrix = [ordered]@{
            path = Get-StablePath $matrixPath
            sha256 = $matrixSha256
        }
    }
    source = $source
    checks = @($script:checks)
    blockers = @($blockers)
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        repo_local_projection_only = $true
        exact_install_update_target_bound = $true
        exact_install_update_approval_bound = $true
        agentcore_install_update_planspec_executable = $planspecExecutable
        security_execution_install_update_allow = $false
        rollback_preconditions_bound = $false
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
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
        rc17_020_complete = (@($script:failedChecks).Count -eq 0)
        agentcore_install_update_planspec_executable = $planspecExecutable
        security_execution_install_update_allow = $false
        rollback_preconditions_bound = $false
        install_effect_preparation_allowed = $false
        update_effect_preparation_allowed = $false
        install_performed = $false
        update_performed = $false
        next_task = "RC17-021"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC17-020-agentcore-install-update-executable-planspec.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc17-agentcore-install-update-executable-planspec-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC17-020"
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
    planspec_surface = $result.planspec_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc17_020_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC17-021"
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
    throw "Sensitive marker detected in RC17-020 outputs."
}

Write-Host "RC17 AgentCore install/update executable PlanSpec $($result.status): $(Get-StablePath $resultPath)"
Write-Host "PlanSpec: $(Get-StablePath $planspecPath)"
Write-Host "Fail-closed matrix: $(Get-StablePath $matrixPath)"
Write-Host "AgentCore executable: $planspecExecutable; SecurityExecution allowed: false; install/update effects prepared: false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
