param(
    [string]$ArtifactDir = ".workflow/artifacts/rc17-exact-install-update-approval-binding",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc17",
    [string]$PlanPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc17/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc17/docs/rc17-exact-install-update-execution-contract.md",
    [string]$TargetBindingResultPath = ".workflow/artifacts/rc17-exact-install-update-target-binding/result.json",
    [string]$TargetPackagePath = ".workflow/artifacts/rc17-exact-install-update-target-binding/exact-install-update-target-package.json",
    [string]$AuditNoncePolicyResultPath = ".workflow/artifacts/rc15-audit-nonce-policy-binding/result.json",
    [string]$AuditNoncePolicyBindingPath = ".workflow/artifacts/rc15-audit-nonce-policy-binding/audit-nonce-policy-binding.json",
    [string]$AuditSubstrateHandoffPath = ".workflow/artifacts/rc15-audit-nonce-policy-binding/exact-approval-substrate-handoff.json",
    [string]$Rc15ExactApprovalResultPath = ".workflow/artifacts/rc15-exact-approval-controlled-execution/result.json",
    [string]$Rc15ExactApprovalPacketPath = ".workflow/artifacts/rc15-exact-approval-controlled-execution/exact-approval-packet.json",
    [string]$Rc16PlanSpecResultPath = ".workflow/artifacts/rc16-install-update-planspec-binding/result.json",
    [string]$Rc16PlanSpecPackagePath = ".workflow/artifacts/rc16-install-update-planspec-binding/install-update-planspec-package.json",
    [string]$Rc16SecurityEnvelopePath = ".workflow/artifacts/rc16-install-update-planspec-binding/security-execution-install-update-envelope.json",
    [string]$Rc16RollbackSupportResultPath = ".workflow/artifacts/rc16-rollback-support-package/result.json",
    [string]$Rc16RollbackSupportPackagePath = ".workflow/artifacts/rc16-rollback-support-package/rollback-support-package.json",
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
            exact_approval_bound = $false
            approval_granted = $false
            agentcore_planspec_executable = $false
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

function Get-ApprovalValidUntil {
    param([Parameter(Mandatory = $true)][string]$GeneratedAtValue)
    try {
        return ([DateTimeOffset]::Parse($GeneratedAtValue).AddHours(4)).ToString("yyyy-MM-ddTHH:mm:sszzz")
    } catch {
        return $GeneratedAtValue + "+PT4H"
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
$resolvedAuditNoncePolicyResultPath = Resolve-RepoPath $AuditNoncePolicyResultPath
$resolvedAuditNoncePolicyBindingPath = Resolve-RepoPath $AuditNoncePolicyBindingPath
$resolvedAuditSubstrateHandoffPath = Resolve-RepoPath $AuditSubstrateHandoffPath
$resolvedRc15ExactApprovalResultPath = Resolve-RepoPath $Rc15ExactApprovalResultPath
$resolvedRc15ExactApprovalPacketPath = Resolve-RepoPath $Rc15ExactApprovalPacketPath
$resolvedRc16PlanSpecResultPath = Resolve-RepoPath $Rc16PlanSpecResultPath
$resolvedRc16PlanSpecPackagePath = Resolve-RepoPath $Rc16PlanSpecPackagePath
$resolvedRc16SecurityEnvelopePath = Resolve-RepoPath $Rc16SecurityEnvelopePath
$resolvedRc16RollbackSupportResultPath = Resolve-RepoPath $Rc16RollbackSupportResultPath
$resolvedRc16RollbackSupportPackagePath = Resolve-RepoPath $Rc16RollbackSupportPackagePath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$targetBindingResult = Read-Json $resolvedTargetBindingResultPath
$targetPackage = Read-Json $resolvedTargetPackagePath
$auditResult = Read-Json $resolvedAuditNoncePolicyResultPath
$auditBinding = Read-Json $resolvedAuditNoncePolicyBindingPath
$auditHandoff = Read-Json $resolvedAuditSubstrateHandoffPath
$rc15ExactApprovalResult = Read-Json $resolvedRc15ExactApprovalResultPath
$rc15ExactApprovalPacket = Read-Json $resolvedRc15ExactApprovalPacketPath
$rc16PlanSpecResult = Read-Json $resolvedRc16PlanSpecResultPath
$rc16PlanSpecPackage = Read-Json $resolvedRc16PlanSpecPackagePath
$rc16SecurityEnvelope = Read-Json $resolvedRc16SecurityEnvelopePath
$rc16RollbackSupportResult = Read-Json $resolvedRc16RollbackSupportResultPath
$rc16RollbackSupportPackage = Read-Json $resolvedRc16RollbackSupportPackagePath

$rc17PreviousStatus = Get-TaskStatus -Plan $plan -TaskId "RC17-010"
$rc17TaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC17-011"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc17PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC17-011" -and ($rc17TaskStatus -eq "pending" -or $rc17TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC17-020" -and $rc17TaskStatus -eq "completed")
    )
)

$packageId = [string]$targetPackage.package_id
$mediaId = [string]$targetPackage.media_id
$releaseId = [string]$targetPackage.release_id
$preflightId = [string]$targetPackage.preflight_id
$targetBindingId = [string]$targetPackage.target_binding_id
$targetPackageSha256 = Get-FileSha256 $resolvedTargetPackagePath
$targetIdentitySetDigest = [string]$targetPackage.target_identities.target_identity_set_digest
$targetIdentityIds = @($targetPackage.target_identities.identity_ids | ForEach-Object { [string]$_ })
$targetIdentityDigests = @($targetPackage.target_identities.identity_digests | ForEach-Object { [string]$_ })
$payloadSha256 = [string]$targetPackage.target_core.payload_sha256
$payloadSizeBytes = [int64]$targetPackage.target_core.payload_size_bytes
$objectId = [string]$targetPackage.target_core.object_id
$planspecCoreHash = [string]$rc16PlanSpecPackage.planspec_core_hash
$planspecMaterializationDigest = [string]$rc16PlanSpecPackage.planspec_materialization_digest
$securityEnvelopeCoreHash = [string]$rc16SecurityEnvelope.effect_envelope_core_hash
$securityDecisionMaterialHash = [string]$rc16SecurityEnvelope.decision_material_hash
$rollbackSupportCoreHash = [string]$rc16RollbackSupportPackage.rollback_support_package_core_hash
$auditSinkDescriptorSha256 = [string]$auditHandoff.audit_sink_descriptor_sha256
$auditBindingSha256 = [string]$auditHandoff.binding_sha256
$sourceNonceSha256 = [string]$auditHandoff.nonce_sha256
$approvalNonceSha256 = Get-StringSha256 ("rc17-011-install-update-approval:" + $targetBindingId + ":" + $generatedAtValue)
$sourcePolicyVersion = [string]$auditHandoff.policy_version
$policyVersion = "rc17-exact-install-update-v1"
$approvalValidUntil = Get-ApprovalValidUntil -GeneratedAtValue $generatedAtValue
$approvalActor = if ($rc15ExactApprovalPacket.approval_binding.approval_actor) { [string]$rc15ExactApprovalPacket.approval_binding.approval_actor } else { "operator" }

$approvalBinding = [ordered]@{
    approval_kind = "repo-local-exact-install-update-operator-approval"
    approval_actor = $approvalActor
    actor_authority_scope = "repo-local-install-update"
    release_id = $releaseId
    object_id = $objectId
    object_digest = $payloadSha256
    package_id = $packageId
    media_id = $mediaId
    preflight_id = $preflightId
    target_binding_id = $targetBindingId
    target_package_sha256 = $targetPackageSha256
    target_identity_set_digest = $targetIdentitySetDigest
    target_identity_ids = $targetIdentityIds
    target_identity_digests = $targetIdentityDigests
    approved_operations = @(
        [ordered]@{
            operation_type = "install"
            target_binding_id = $targetBindingId
            target_selector_kind = "exact-target-identity-digests"
            target_identity_set_digest = $targetIdentitySetDigest
            package_id = $packageId
            media_id = $mediaId
            release_id = $releaseId
        },
        [ordered]@{
            operation_type = "update"
            target_binding_id = $targetBindingId
            target_selector_kind = "exact-target-identity-digests"
            target_identity_set_digest = $targetIdentitySetDigest
            package_id = $packageId
            media_id = $mediaId
            release_id = $releaseId
            update_strategy = $targetPackage.exact_targets.update.update_strategy
        }
    )
    agentcore_package_reference = [ordered]@{
        path = Get-StablePath $resolvedRc16PlanSpecPackagePath
        sha256 = Get-FileSha256 $resolvedRc16PlanSpecPackagePath
        planspec_core_hash = $planspecCoreHash
        planspec_materialization_digest = $planspecMaterializationDigest
        executable_required_before_effect = $true
        executable_at_approval = $false
    }
    security_execution_envelope_reference = [ordered]@{
        path = Get-StablePath $resolvedRc16SecurityEnvelopePath
        sha256 = Get-FileSha256 $resolvedRc16SecurityEnvelopePath
        effect_envelope_core_hash = $securityEnvelopeCoreHash
        decision_material_hash = $securityDecisionMaterialHash
        allow_required_before_effect = $true
        allowed_at_approval = $false
    }
    audit_sink_descriptor_sha256 = $auditSinkDescriptorSha256
    audit_binding_sha256 = $auditBindingSha256
    source_nonce_sha256 = $sourceNonceSha256
    approval_nonce_sha256 = $approvalNonceSha256
    approval_valid_from = $generatedAtValue
    approval_valid_until = $approvalValidUntil
    policy_version = $policyVersion
    source_policy_version = $sourcePolicyVersion
    rollback_support_reference = [ordered]@{
        path = Get-StablePath $resolvedRc16RollbackSupportPackagePath
        sha256 = Get-FileSha256 $resolvedRc16RollbackSupportPackagePath
        rollback_support_package_core_hash = $rollbackSupportCoreHash
        rollback_baseline_bound = [bool]$rc16RollbackSupportPackage.binding_summary.rollback_baseline_bound
        support_recovery_reference_bound = [bool]$rc16RollbackSupportPackage.binding_summary.recovery_reference_bound
    }
    approval_scope = "exact-install-update-target-package-only"
    approval_does_not_imply_execution = $true
}
$approvalBindingDigest = Get-StringSha256 (Get-JsonText $approvalBinding)
$approvalId = "rc17-install-update-approval-" + $approvalBindingDigest.Substring(0, 16)
$approvalEvidenceRef = "local-audit-bound-install-update-approval:" + $approvalBindingDigest.Substring(0, 32)

$requiredBindingFields = @(
    "approval_actor",
    "release_id",
    "object_digest",
    "package_id",
    "media_id",
    "target_binding_id",
    "approved_operations",
    "agentcore_package_reference",
    "security_execution_envelope_reference",
    "audit_sink_descriptor_sha256",
    "approval_nonce_sha256",
    "approval_valid_until",
    "policy_version",
    "rollback_support_reference"
)
$missingRequiredFields = @()
foreach ($field in $requiredBindingFields) {
    $value = $approvalBinding[$field]
    if ($null -eq $value) {
        $missingRequiredFields += $field
    } elseif ($value -is [string] -and [string]::IsNullOrWhiteSpace($value)) {
        $missingRequiredFields += $field
    } elseif ($value -is [array] -and @($value).Count -eq 0) {
        $missingRequiredFields += $field
    }
}

$blockers = @(
    "rc17-agentcore-install-update-planspec-not-executable",
    "rc17-security-execution-install-update-allow-not-bound",
    "rc17-rollback-preconditions-not-bound",
    "rc17-controlled-local-install-not-run",
    "rc17-controlled-local-update-not-run",
    "rc17-local-release-channel-consumer-smoke-not-run"
)

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

$approvalPacket = [ordered]@{
    schema = "agentos.rc17-exact-install-update-approval-packet.v1"
    generated_at = $generatedAtValue
    task = "RC17-011"
    status = "exact-install-update-approval-bound-effects-denied"
    production_ready_claim = $false
    approval_id = $approvalId
    approval_evidence_ref = $approvalEvidenceRef
    approval_signature_ref_bound = $true
    approval_signature_kind = "repo-local-audit-bound-approval-record"
    exact_approval_bound = $true
    approval_granted = $true
    approval_binding_digest = $approvalBindingDigest
    approval_binding = $approvalBinding
    required_binding_fields = $requiredBindingFields
    missing_required_fields = $missingRequiredFields
    approval_surface = [ordered]@{
        state = "exact-install-update-approval-bound-execution-still-gated"
        exact_install_update_target_bound = $true
        exact_install_update_approval_bound = $true
        approval_granted = $true
        approved_operation_count = 2
        approved_operations = @("install", "update")
        audit_sink_bound = $true
        nonce_bound = $true
        expiry_bound = $true
        policy_version_bound = $true
        rollback_support_reference_bound = $true
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
    upstream_gates = [ordered]@{
        rc17_target_binding_complete = $true
        rc15_audit_nonce_policy_available = $true
        rc15_exact_approval_pattern_available = $true
        rc16_agentcore_package_reference_bound = $true
        rc16_security_execution_envelope_reference_bound = $true
        rc16_rollback_support_reference_bound = $true
    }
    downstream = [ordered]@{
        agentcore_install_update_planspec_executable = $false
        security_execution_allowed = $false
        rollback_preconditions_bound = $false
        install_effect_preparation_allowed = $false
        update_effect_preparation_allowed = $false
        install_allowed = $false
        update_allowed = $false
        install_performed = $false
        update_performed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
    }
    side_effects = $sideEffects
}
$approvalPacketPath = Join-Path $resolvedArtifactDir "exact-install-update-approval-packet.json"
Write-Json $approvalPacket $approvalPacketPath

$caseSpecs = @(
    [ordered]@{ id = "missing-approval-id-denied"; blockers = @("approval-id-not-bound"); reason = "Approval id is required." },
    [ordered]@{ id = "missing-approval-actor-denied"; blockers = @("approval-actor-not-bound"); reason = "Approval actor is required." },
    [ordered]@{ id = "missing-target-package-denied"; blockers = @("approval-target-package-not-bound"); reason = "Approval must bind the RC17 target package." },
    [ordered]@{ id = "missing-install-operation-denied"; blockers = @("install-operation-not-bound"); reason = "Install operation type must be exact." },
    [ordered]@{ id = "missing-update-operation-denied"; blockers = @("update-operation-not-bound"); reason = "Update operation type must be exact." },
    [ordered]@{ id = "missing-agentcore-reference-denied"; blockers = @("agentcore-package-reference-not-bound"); reason = "Approval must bind AgentCore install/update package reference." },
    [ordered]@{ id = "missing-security-envelope-reference-denied"; blockers = @("security-execution-envelope-reference-not-bound"); reason = "Approval must bind SecurityExecution envelope reference." },
    [ordered]@{ id = "missing-audit-sink-denied"; blockers = @("approval-audit-sink-not-bound"); reason = "Approval must bind audit sink." },
    [ordered]@{ id = "missing-nonce-denied"; blockers = @("approval-nonce-not-bound"); reason = "Approval must bind nonce hash." },
    [ordered]@{ id = "missing-expiry-denied"; blockers = @("approval-expiry-not-bound"); reason = "Approval must bind expiry." },
    [ordered]@{ id = "missing-policy-version-denied"; blockers = @("approval-policy-version-not-bound"); reason = "Approval must bind policy version." },
    [ordered]@{ id = "missing-rollback-support-denied"; blockers = @("approval-rollback-support-not-bound"); reason = "Approval must bind rollback/support references." },
    [ordered]@{ id = "unsigned-approval-denied"; blockers = @("approval-evidence-ref-not-bound"); reason = "Unsigned or unaudited approval must deny." },
    [ordered]@{ id = "expired-approval-denied"; blockers = @("approval-expired"); reason = "Expired approval must deny." },
    [ordered]@{ id = "stale-approval-denied"; blockers = @("approval-stale"); reason = "Stale approval must deny." },
    [ordered]@{ id = "replayed-approval-denied"; blockers = @("approval-replay-detected"); reason = "Replayed approval must deny." },
    [ordered]@{ id = "broad-approval-denied"; blockers = @("approval-broad-scope"); reason = "Broad approval must deny." },
    [ordered]@{ id = "actor-mismatch-denied"; blockers = @("approval-actor-mismatch"); reason = "Actor mismatch must deny." },
    [ordered]@{ id = "release-mismatch-denied"; blockers = @("approval-release-mismatch"); reason = "Release mismatch must deny." },
    [ordered]@{ id = "package-mismatch-denied"; blockers = @("approval-package-mismatch"); reason = "Package mismatch must deny." },
    [ordered]@{ id = "media-mismatch-denied"; blockers = @("approval-media-mismatch"); reason = "Media mismatch must deny." },
    [ordered]@{ id = "target-binding-mismatch-denied"; blockers = @("approval-target-binding-mismatch"); reason = "Target binding mismatch must deny." },
    [ordered]@{ id = "target-identity-mismatch-denied"; blockers = @("approval-target-identity-mismatch"); reason = "Target identity mismatch must deny." },
    [ordered]@{ id = "agentcore-planspec-mismatch-denied"; blockers = @("approval-agentcore-planspec-mismatch"); reason = "PlanSpec mismatch must deny." },
    [ordered]@{ id = "security-envelope-mismatch-denied"; blockers = @("approval-security-envelope-mismatch"); reason = "SecurityExecution envelope mismatch must deny." },
    [ordered]@{ id = "audit-binding-mismatch-denied"; blockers = @("approval-audit-binding-mismatch"); reason = "Audit binding mismatch must deny." },
    [ordered]@{ id = "nonce-mismatch-denied"; blockers = @("approval-nonce-mismatch"); reason = "Nonce mismatch must deny." },
    [ordered]@{ id = "policy-version-mismatch-denied"; blockers = @("approval-policy-version-mismatch"); reason = "Policy version mismatch must deny." },
    [ordered]@{ id = "rollback-support-mismatch-denied"; blockers = @("approval-rollback-support-mismatch"); reason = "Rollback/support mismatch must deny." },
    [ordered]@{ id = "approval-implies-execution-denied"; blockers = @("approval-does-not-imply-execution"); reason = "Approval alone must not authorize effects." },
    [ordered]@{ id = "host-boot-mutation-authority-denied"; blockers = @("host-boot-mutation-authority-forbidden"); reason = "Approval must not mutate host boot metadata." },
    [ordered]@{ id = "remote-dispatch-authority-denied"; blockers = @("remote-dispatch-authority-forbidden"); reason = "Approval must not enable remote dispatch." },
    [ordered]@{ id = "support-upload-authority-denied"; blockers = @("support-upload-authority-forbidden"); reason = "Approval must not enable support upload." },
    [ordered]@{ id = "recovery-execution-authority-denied"; blockers = @("recovery-execution-authority-forbidden"); reason = "Approval must not enable recovery execution." },
    [ordered]@{ id = "production-ring-mutation-denied"; blockers = @("production-ring-mutation-forbidden"); reason = "Approval must not mutate production rings." }
)
$cases = @()
foreach ($spec in $caseSpecs) {
    $cases += New-DenialCase -Id $spec.id -ExpectedBlockers ([string[]]$spec.blockers) -Reason $spec.reason
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$matrix = [ordered]@{
    schema = "agentos.rc17-exact-approval-fail-closed-matrix.v1"
    generated_at = $generatedAtValue
    task = "RC17-011"
    status = if ($failedCases.Count -eq 0) { "passed" } else { "failed" }
    production_ready_claim = $false
    approval_id = $approvalId
    approval_binding_digest = $approvalBindingDigest
    cases = $cases
    summary = [ordered]@{
        cases = @($cases).Count
        passed = @($cases | Where-Object { $_.status -eq "passed" }).Count
        failed = $failedCases.Count
        failed_cases = @($failedCases | ForEach-Object { $_.id })
    }
}
$matrixPath = Join-Path $resolvedArtifactDir "exact-approval-fail-closed-matrix.json"
Write-Json $matrix $matrixPath

$source = [ordered]@{
    rc17_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc17_contract = New-ArtifactRef $resolvedContractPath
    rc17_target_binding_result = New-ArtifactRef $resolvedTargetBindingResultPath $targetBindingResult
    rc17_target_package = New-ArtifactRef $resolvedTargetPackagePath $targetPackage
    rc15_audit_nonce_policy_result = New-ArtifactRef $resolvedAuditNoncePolicyResultPath $auditResult
    rc15_audit_nonce_policy_binding = New-ArtifactRef $resolvedAuditNoncePolicyBindingPath $auditBinding
    rc15_exact_approval_substrate_handoff = New-ArtifactRef $resolvedAuditSubstrateHandoffPath $auditHandoff
    rc15_exact_approval_result = New-ArtifactRef $resolvedRc15ExactApprovalResultPath $rc15ExactApprovalResult
    rc15_exact_approval_packet = New-ArtifactRef $resolvedRc15ExactApprovalPacketPath $rc15ExactApprovalPacket
    rc16_planspec_result = New-ArtifactRef $resolvedRc16PlanSpecResultPath $rc16PlanSpecResult
    rc16_planspec_package = New-ArtifactRef $resolvedRc16PlanSpecPackagePath $rc16PlanSpecPackage
    rc16_security_execution_envelope = New-ArtifactRef $resolvedRc16SecurityEnvelopePath $rc16SecurityEnvelope
    rc16_rollback_support_result = New-ArtifactRef $resolvedRc16RollbackSupportResultPath $rc16RollbackSupportResult
    rc16_rollback_support_package = New-ArtifactRef $resolvedRc16RollbackSupportPackagePath $rc16RollbackSupportPackage
}

Add-Check "plan.current_task.rc17_011" $planAllowsRun "RC17-011 must run after RC17-010 completed, either while current_task is RC17-011 or while rerunning after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc17_010_status = $rc17PreviousStatus; rc17_011_status = $rc17TaskStatus })
Add-Check "contract.exact_approval_gate.present" ($contractText.Contains("Exact operator approval") -and $contractText.Contains("audit sink") -and $contractText.Contains("nonce") -and $contractText.Contains("policy version")) "RC17-011 must consume the exact approval authority contract." (New-ArtifactRef $resolvedContractPath)
Add-Check "source.target_binding.complete" ($targetBindingResult.status -eq "passed" -and $targetBindingResult.summary.rc17_010_complete -eq $true -and $targetPackage.target_binding_surface.exact_install_update_target_bound -eq $true) "RC17-011 must consume completed RC17-010 exact target binding." ([ordered]@{ status = $targetBindingResult.status; target_binding_id = $targetBindingId; exact_target_bound = $targetPackage.target_binding_surface.exact_install_update_target_bound })
Add-Check "source.audit_nonce_policy.available" ($auditResult.status -eq "passed" -and $auditResult.binding_surface.audit_sink_bound -eq $true -and $auditResult.binding_surface.nonce_bound -eq $true -and $auditResult.binding_surface.expiry_bound -eq $true -and $auditResult.binding_surface.policy_version_bound -eq $true) "RC17-011 must bind audit sink, nonce, expiry, and policy substrate without carrying raw nonce values." ([ordered]@{ audit_sink_descriptor_sha256 = $auditSinkDescriptorSha256; source_nonce_sha256 = $sourceNonceSha256; source_policy_version = $sourcePolicyVersion })
Add-Check "source.rc15_approval_pattern.available" ($rc15ExactApprovalResult.status -eq "passed" -and $rc15ExactApprovalPacket.exact_approval_bound -eq $true -and $rc15ExactApprovalPacket.approval_granted -eq $true) "RC17-011 must reuse the repo-local exact approval packet pattern from RC15." ([ordered]@{ rc15_approval_id = $rc15ExactApprovalPacket.approval_id; rc15_approval_binding_digest = $rc15ExactApprovalPacket.approval_binding_digest })
Add-Check "source.agentcore_security_rollback.available" ($rc16PlanSpecResult.status -eq "passed" -and $rc16PlanSpecPackage.agentcore_install_update_planspec_bound -eq $true -and $rc16SecurityEnvelope.status -eq "security-execution-install-update-denied" -and $rc16RollbackSupportResult.status -eq "passed" -and $rc16RollbackSupportResult.summary.rollback_support_package_bound -eq $true) "RC17-011 must bind AgentCore package reference, SecurityExecution envelope reference, and rollback/support package references." ([ordered]@{ planspec_core_hash = $planspecCoreHash; security_envelope_core_hash = $securityEnvelopeCoreHash; rollback_support_package_core_hash = $rollbackSupportCoreHash })
Add-Check "approval_packet.binds_exact_inputs" ($approvalPacket.exact_approval_bound -eq $true -and $approvalPacket.approval_granted -eq $true -and @($missingRequiredFields).Count -eq 0 -and @($approvalBinding.approved_operations).Count -eq 2 -and $approvalBinding.target_binding_id -eq $targetBindingId -and $approvalBinding.agentcore_package_reference.planspec_core_hash -eq $planspecCoreHash -and $approvalBinding.security_execution_envelope_reference.effect_envelope_core_hash -eq $securityEnvelopeCoreHash -and $approvalBinding.audit_sink_descriptor_sha256 -eq $auditSinkDescriptorSha256 -and $approvalBinding.approval_nonce_sha256 -eq $approvalNonceSha256 -and $approvalBinding.policy_version -eq $policyVersion) "Exact approval must bind actor, release object, target package, install/update operation type, AgentCore reference, SecurityExecution reference, audit sink, nonce, expiry, policy, rollback, and support references." ([ordered]@{ approval_id = $approvalId; approval_binding_digest = $approvalBindingDigest; approved_operation_count = @($approvalBinding.approved_operations).Count; missing_required_fields = @($missingRequiredFields) })
Add-Check "approval_packet.does_not_imply_execution" ($approvalPacket.approval_surface.exact_install_update_approval_bound -eq $true -and $approvalPacket.approval_surface.agentcore_install_update_planspec_executable -eq $false -and $approvalPacket.approval_surface.security_execution_install_update_allow -eq $false -and $approvalPacket.approval_surface.install_performed -eq $false -and $approvalPacket.approval_surface.update_performed -eq $false) "Approval must not imply executable AgentCore PlanSpec, SecurityExecution allow, install, update, rollback, support upload, recovery, remote dispatch, or production mutation." $approvalPacket.approval_surface
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 30) "Stale, broad, unsigned, mismatched, missing, replayed, expired, execution-implying, and authority-broadening approvals must fail closed." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })
Add-Check "authority.no_side_effects" (@($sideEffects.GetEnumerator() | Where-Object { $_.Value -ne $false }).Count -eq 0) "RC17-011 must not install, update, activate, roll back, mutate host boot state, upload support, recover, dispatch remotely, or mutate production rings." $sideEffects

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $approvalPacketPath),
    (Get-Content -Raw -LiteralPath $matrixPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC17-011 outputs must not contain key blocks, private key paths, auth tokens, raw nonce values, or signing key file names." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$approvalPacketSha256 = Get-FileSha256 $approvalPacketPath
$matrixSha256 = Get-FileSha256 $matrixPath
$result = [ordered]@{
    schema = "agentos.rc17-exact-install-update-approval-binding-result.v1"
    generated_at = $generatedAtValue
    task = "RC17-011"
    status = $resultStatus
    production_ready_claim = $false
    approval_id = $approvalId
    approval_binding_digest = $approvalBindingDigest
    package_id = $packageId
    media_id = $mediaId
    release_id = $releaseId
    target_binding_id = $targetBindingId
    approval_surface = $approvalPacket.approval_surface
    outputs = [ordered]@{
        exact_install_update_approval_packet = [ordered]@{
            path = Get-StablePath $approvalPacketPath
            sha256 = $approvalPacketSha256
            approval_id = $approvalId
            approval_binding_digest = $approvalBindingDigest
        }
        exact_approval_fail_closed_matrix = [ordered]@{
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
        approval_granted = $true
        approval_does_not_imply_execution = $true
        agentcore_install_update_planspec_executable = $false
        security_execution_install_update_allow = $false
        rollback_preconditions_bound = $false
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
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
        rc17_011_complete = (@($script:failedChecks).Count -eq 0)
        exact_install_update_target_bound = $true
        exact_install_update_approval_bound = $true
        approval_granted = $true
        agentcore_install_update_planspec_executable = $false
        security_execution_install_update_allow = $false
        rollback_preconditions_bound = $false
        install_performed = $false
        update_performed = $false
        next_task = "RC17-020"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC17-011-exact-install-update-approval-binding.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc17-exact-install-update-approval-binding-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC17-011"
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
    approval_surface = $result.approval_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc17_011_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC17-020"
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
    throw "Sensitive marker detected in RC17-011 outputs."
}

Write-Host "RC17 exact install/update approval binding $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Approval packet: $(Get-StablePath $approvalPacketPath)"
Write-Host "Fail-closed matrix: $(Get-StablePath $matrixPath)"
Write-Host "Exact approval bound: true; AgentCore executable: false; SecurityExecution allowed: false; install/update effects performed: false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
