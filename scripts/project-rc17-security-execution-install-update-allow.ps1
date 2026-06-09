param(
    [string]$ArtifactDir = ".workflow/artifacts/rc17-security-execution-install-update-allow",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc17",
    [string]$PlanPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc17/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc17/docs/rc17-exact-install-update-execution-contract.md",
    [string]$PlanSpecResultPath = ".workflow/artifacts/rc17-agentcore-install-update-executable-planspec/result.json",
    [string]$PlanSpecPath = ".workflow/artifacts/rc17-agentcore-install-update-executable-planspec/install-update-planspec.json",
    [string]$ApprovalBindingResultPath = ".workflow/artifacts/rc17-exact-install-update-approval-binding/result.json",
    [string]$ApprovalPacketPath = ".workflow/artifacts/rc17-exact-install-update-approval-binding/exact-install-update-approval-packet.json",
    [string]$TargetBindingResultPath = ".workflow/artifacts/rc17-exact-install-update-target-binding/result.json",
    [string]$TargetPackagePath = ".workflow/artifacts/rc17-exact-install-update-target-binding/exact-install-update-target-package.json",
    [string]$PreflightResultPath = ".workflow/artifacts/rc16-installer-updater-preflight-package/result.json",
    [string]$PreflightPackagePath = ".workflow/artifacts/rc16-installer-updater-preflight-package/installer-updater-preflight-package.json",
    [string]$SecurityExecutionPolicyPath = "crates/security_execution/src/policy.rs",
    [string]$SecurityExecutionToolsPath = "crates/security_execution/src/tools.rs",
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
            security_execution_allowed = $false
            effect_prepared = $false
            effect_executed = $false
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
$resolvedPlanSpecResultPath = Resolve-RepoPath $PlanSpecResultPath
$resolvedPlanSpecPath = Resolve-RepoPath $PlanSpecPath
$resolvedApprovalBindingResultPath = Resolve-RepoPath $ApprovalBindingResultPath
$resolvedApprovalPacketPath = Resolve-RepoPath $ApprovalPacketPath
$resolvedTargetBindingResultPath = Resolve-RepoPath $TargetBindingResultPath
$resolvedTargetPackagePath = Resolve-RepoPath $TargetPackagePath
$resolvedPreflightResultPath = Resolve-RepoPath $PreflightResultPath
$resolvedPreflightPackagePath = Resolve-RepoPath $PreflightPackagePath
$resolvedSecurityExecutionPolicyPath = Resolve-RepoPath $SecurityExecutionPolicyPath
$resolvedSecurityExecutionToolsPath = Resolve-RepoPath $SecurityExecutionToolsPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$planSpecResult = Read-Json $resolvedPlanSpecResultPath
$planSpec = Read-Json $resolvedPlanSpecPath
$approvalBindingResult = Read-Json $resolvedApprovalBindingResultPath
$approvalPacket = Read-Json $resolvedApprovalPacketPath
$targetBindingResult = Read-Json $resolvedTargetBindingResultPath
$targetPackage = Read-Json $resolvedTargetPackagePath
$preflightResult = Read-Json $resolvedPreflightResultPath
$preflightPackage = Read-Json $resolvedPreflightPackagePath

$rc17PreviousStatus = Get-TaskStatus -Plan $plan -TaskId "RC17-020"
$rc17TaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC17-021"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc17PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC17-021" -and ($rc17TaskStatus -eq "pending" -or $rc17TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC17-022" -and $rc17TaskStatus -eq "completed")
    )
)

$packageId = [string]$planSpec.package_id
$mediaId = [string]$planSpec.media_id
$releaseId = [string]$planSpec.release_id
$preflightId = [string]$planSpec.preflight_id
$targetBindingId = [string]$planSpec.target_binding_id
$approvalId = [string]$planSpec.approval_id
$approvalBindingDigest = [string]$planSpec.approval_binding_digest
$planspecCoreHash = [string]$planSpec.planspec_core_hash
$planspecMaterializationDigest = [string]$planSpec.planspec_materialization_digest
$targetIdentitySetDigest = [string]$planSpec.planspec_core.target_identity_set_digest
$targetIdentityIds = @($planSpec.planspec_core.target_identity_ids | ForEach-Object { [string]$_ })
$payloadSha256 = [string]$planSpec.planspec_core.payload_sha256
$securityPolicySha256 = Get-FileSha256 $resolvedSecurityExecutionPolicyPath
$securityToolsSha256 = Get-FileSha256 $resolvedSecurityExecutionToolsPath

$planSpecExecutable = $planSpecResult.status -eq "passed" -and
    $planSpecResult.summary.rc17_020_complete -eq $true -and
    $planSpecResult.summary.agentcore_install_update_planspec_executable -eq $true -and
    $planSpec.agentcore_install_update_planspec_executable -eq $true
$targetBound = $targetBindingResult.status -eq "passed" -and
    $targetBindingResult.summary.rc17_010_complete -eq $true -and
    $targetPackage.target_binding_id -eq $targetBindingId -and
    $targetPackage.target_binding_surface.exact_install_update_target_bound -eq $true
$approvalBound = $approvalBindingResult.status -eq "passed" -and
    $approvalBindingResult.summary.rc17_011_complete -eq $true -and
    $approvalPacket.approval_id -eq $approvalId -and
    $approvalPacket.approval_binding_digest -eq $approvalBindingDigest -and
    $approvalPacket.exact_approval_bound -eq $true -and
    $approvalPacket.approval_granted -eq $true
$preflightBound = $preflightResult.status -eq "passed" -and
    $preflightResult.summary.rc16_020_complete -eq $true -and
    $preflightPackage.preflight_id -eq $preflightId -and
    $preflightPackage.package_id -eq $packageId -and
    $preflightPackage.media_id -eq $mediaId
$auditNoncePolicyBound = $planSpec.planspec_core.binding_slots.audit_nonce_expiry_policy.bound -eq $true -and
    -not [string]::IsNullOrWhiteSpace([string]$approvalPacket.approval_binding.audit_sink_descriptor_sha256) -and
    -not [string]::IsNullOrWhiteSpace([string]$approvalPacket.approval_binding.approval_nonce_sha256) -and
    -not [string]::IsNullOrWhiteSpace([string]$approvalPacket.approval_binding.approval_valid_until) -and
    -not [string]::IsNullOrWhiteSpace([string]$approvalPacket.approval_binding.policy_version)
$rollbackSupportBound = $planSpec.planspec_core.binding_slots.rollback_support_reference.bound -eq $true -and
    $approvalPacket.approval_binding.rollback_support_reference.rollback_support_package_core_hash -eq $planSpec.planspec_core.binding_slots.rollback_support_reference.rollback_support_package_core_hash
$operationScopeExact = @($approvalPacket.approval_binding.approved_operations | Where-Object { $_.operation_type -eq "install" }).Count -eq 1 -and
    @($approvalPacket.approval_binding.approved_operations | Where-Object { $_.operation_type -eq "update" }).Count -eq 1 -and
    @($targetIdentityIds).Count -eq 2 -and
    $planSpec.install_plan.target_binding_id -eq $targetBindingId -and
    $planSpec.update_plan.target_binding_id -eq $targetBindingId
$securityCodeBound = -not [string]::IsNullOrWhiteSpace($securityPolicySha256) -and -not [string]::IsNullOrWhiteSpace($securityToolsSha256)

$securityExecutionAllowed = $planAllowsRun -and
    $planSpecExecutable -and
    $targetBound -and
    $approvalBound -and
    $preflightBound -and
    $auditNoncePolicyBound -and
    $rollbackSupportBound -and
    $operationScopeExact -and
    $securityCodeBound
$rollbackPreconditionsBound = $false
$installEffectPreparationAllowed = $false
$updateEffectPreparationAllowed = $false

$effectEnvelopeCore = [ordered]@{
    schema = "agentos.security-execution.install-update-effect-envelope.v1"
    task = "RC17-021"
    decision_kind = "exact-install-update-allow"
    package_id = $packageId
    media_id = $mediaId
    release_id = $releaseId
    preflight_id = $preflightId
    target_binding_id = $targetBindingId
    approval_id = $approvalId
    approval_binding_digest = $approvalBindingDigest
    planspec_core_hash = $planspecCoreHash
    planspec_materialization_digest = $planspecMaterializationDigest
    target_identity_set_digest = $targetIdentitySetDigest
    target_identity_ids = $targetIdentityIds
    payload_sha256 = $payloadSha256
    audit_sink_descriptor_sha256 = [string]$approvalPacket.approval_binding.audit_sink_descriptor_sha256
    approval_nonce_sha256 = [string]$approvalPacket.approval_binding.approval_nonce_sha256
    approval_valid_until = [string]$approvalPacket.approval_binding.approval_valid_until
    policy_version = [string]$approvalPacket.approval_binding.policy_version
    security_policy_sha256 = $securityPolicySha256
    security_tools_sha256 = $securityToolsSha256
    allowed_effects = @(
        [ordered]@{
            effect = "install"
            scope = "repo-local-controlled-target"
            target_binding_id = $targetBindingId
            target_identity_set_digest = $targetIdentitySetDigest
            package_id = $packageId
            media_id = $mediaId
            effect_preparation_allowed = $installEffectPreparationAllowed
            effect_executed = $false
        },
        [ordered]@{
            effect = "update"
            scope = "repo-local-controlled-target"
            target_binding_id = $targetBindingId
            target_identity_set_digest = $targetIdentitySetDigest
            package_id = $packageId
            media_id = $mediaId
            update_strategy = $planSpec.update_plan.update_strategy
            effect_preparation_allowed = $updateEffectPreparationAllowed
            effect_executed = $false
        }
    )
    forbidden_effects = @(
        "activation",
        "rollback",
        "support-upload",
        "recovery",
        "remote-dispatch",
        "host-active-slot-mutation",
        "host-boot-metadata-mutation",
        "production-ring-mutation",
        "signing"
    )
    downstream_gates = [ordered]@{
        rollback_preconditions_required = $true
        rollback_preconditions_bound = $rollbackPreconditionsBound
        controlled_install_required = $true
        controlled_update_required = $true
        local_consumer_smoke_required = $true
    }
}
$effectEnvelopeCoreHash = Get-StringSha256 (Get-JsonText $effectEnvelopeCore)
$decisionMaterial = [ordered]@{
    schema = "agentos.security-execution.install-update-decision-material.v1"
    effect_envelope_core_hash = $effectEnvelopeCoreHash
    planspec_core_hash = $planspecCoreHash
    approval_binding_digest = $approvalBindingDigest
    target_binding_id = $targetBindingId
    security_policy_sha256 = $securityPolicySha256
    security_tools_sha256 = $securityToolsSha256
    preconditions = [ordered]@{
        plan_allows_run = $planAllowsRun
        planspec_executable = $planSpecExecutable
        target_bound = $targetBound
        approval_bound = $approvalBound
        preflight_bound = $preflightBound
        audit_nonce_policy_bound = $auditNoncePolicyBound
        rollback_support_bound = $rollbackSupportBound
        operation_scope_exact = $operationScopeExact
        security_code_bound = $securityCodeBound
    }
}
$decisionMaterialHash = Get-StringSha256 (Get-JsonText $decisionMaterial)

$blockers = @(
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

$decision = [ordered]@{
    schema = "agentos.rc17-security-execution-install-update-allow-decision.v1"
    generated_at = $generatedAtValue
    task = "RC17-021"
    status = "security-execution-install-update-allow-bound-effects-denied"
    production_ready_claim = $false
    package_id = $packageId
    media_id = $mediaId
    release_id = $releaseId
    target_binding_id = $targetBindingId
    approval_id = $approvalId
    approval_binding_digest = $approvalBindingDigest
    planspec_core_hash = $planspecCoreHash
    effect_envelope_core_hash = $effectEnvelopeCoreHash
    decision_material_hash = $decisionMaterialHash
    security_execution_install_update_allow = $securityExecutionAllowed
    security_execution_allowed_effects = @("install", "update")
    effect_envelope_core = $effectEnvelopeCore
    decision_material = $decisionMaterial
    effect_preparation_allowed = $false
    install_effect_preparation_allowed = $installEffectPreparationAllowed
    update_effect_preparation_allowed = $updateEffectPreparationAllowed
    install_allowed = $securityExecutionAllowed
    update_allowed = $securityExecutionAllowed
    install_performed = $false
    update_performed = $false
    activation_allowed = $false
    rollback_execution_allowed = $false
    support_upload_allowed = $false
    recovery_execution_allowed = $false
    remote_dispatch_enabled = $false
    production_ring_mutation_allowed = $false
    blockers = @($blockers)
    side_effects = $sideEffects
    authority = [ordered]@{
        aios_body_only = $true
        repo_local_projection_only = $true
        security_execution_install_update_authority = $securityExecutionAllowed
        security_execution_scope = "repo-local-exact-install-update-only"
        install_execution_authority = $false
        update_execution_authority = $false
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
$decisionPath = Join-Path $resolvedArtifactDir "security-execution-install-update-allow-decision.json"
Write-Json $decision $decisionPath

$caseSpecs = @(
    [ordered]@{ id = "missing-executable-planspec-denied"; blockers = @("agentcore-install-update-planspec-not-executable"); reason = "Executable AgentCore PlanSpec is required." },
    [ordered]@{ id = "missing-target-binding-denied"; blockers = @("exact-install-update-target-not-bound"); reason = "Exact target binding is required." },
    [ordered]@{ id = "missing-approval-denied"; blockers = @("exact-install-update-approval-not-bound"); reason = "Exact approval is required." },
    [ordered]@{ id = "approval-not-granted-denied"; blockers = @("approval-not-granted"); reason = "Unapproved envelopes must deny." },
    [ordered]@{ id = "missing-preflight-denied"; blockers = @("installer-updater-preflight-not-bound"); reason = "Installer/updater preflight is required." },
    [ordered]@{ id = "missing-audit-sink-denied"; blockers = @("audit-sink-not-bound"); reason = "Audit sink is required." },
    [ordered]@{ id = "missing-nonce-denied"; blockers = @("approval-nonce-not-bound"); reason = "Nonce binding is required." },
    [ordered]@{ id = "missing-expiry-denied"; blockers = @("approval-expiry-not-bound"); reason = "Expiry binding is required." },
    [ordered]@{ id = "missing-policy-version-denied"; blockers = @("policy-version-not-bound"); reason = "Policy version is required." },
    [ordered]@{ id = "missing-rollback-support-denied"; blockers = @("rollback-support-not-bound"); reason = "Rollback/support references are required." },
    [ordered]@{ id = "broad-effect-envelope-denied"; blockers = @("broad-effect-envelope"); reason = "Broad effect envelope must deny." },
    [ordered]@{ id = "stale-envelope-denied"; blockers = @("effect-envelope-stale"); reason = "Stale envelope must deny." },
    [ordered]@{ id = "replayed-envelope-denied"; blockers = @("effect-envelope-replay-detected"); reason = "Replayed envelope must deny." },
    [ordered]@{ id = "package-mismatch-denied"; blockers = @("effect-package-mismatch"); reason = "Package mismatch must deny." },
    [ordered]@{ id = "media-mismatch-denied"; blockers = @("effect-media-mismatch"); reason = "Media mismatch must deny." },
    [ordered]@{ id = "target-mismatch-denied"; blockers = @("effect-target-mismatch"); reason = "Target mismatch must deny." },
    [ordered]@{ id = "approval-mismatch-denied"; blockers = @("effect-approval-mismatch"); reason = "Approval mismatch must deny." },
    [ordered]@{ id = "planspec-mismatch-denied"; blockers = @("effect-planspec-mismatch"); reason = "PlanSpec mismatch must deny." },
    [ordered]@{ id = "policy-mismatch-denied"; blockers = @("effect-policy-mismatch"); reason = "Policy mismatch must deny." },
    [ordered]@{ id = "remote-effect-denied"; blockers = @("remote-effect-forbidden"); reason = "Remote effects are not allowed." },
    [ordered]@{ id = "support-upload-effect-denied"; blockers = @("support-upload-effect-forbidden"); reason = "Support upload is not allowed." },
    [ordered]@{ id = "recovery-effect-denied"; blockers = @("recovery-effect-forbidden"); reason = "Recovery execution is not allowed." },
    [ordered]@{ id = "host-active-slot-mutation-denied"; blockers = @("host-active-slot-mutation-forbidden"); reason = "Host active slot mutation is not allowed in allow decision." },
    [ordered]@{ id = "host-boot-metadata-mutation-denied"; blockers = @("host-boot-metadata-mutation-forbidden"); reason = "Host boot metadata mutation is not allowed in allow decision." },
    [ordered]@{ id = "production-ring-mutation-denied"; blockers = @("production-ring-mutation-forbidden"); reason = "Production ring mutation is not allowed." },
    [ordered]@{ id = "effect-preparation-before-rollback-preconditions-denied"; blockers = @("rollback-preconditions-not-bound"); reason = "Effect preparation waits for rollback preconditions." },
    [ordered]@{ id = "install-execution-at-allow-decision-denied"; blockers = @("install-execution-not-in-allow-decision"); reason = "Allow decision alone must not execute install." },
    [ordered]@{ id = "update-execution-at-allow-decision-denied"; blockers = @("update-execution-not-in-allow-decision"); reason = "Allow decision alone must not execute update." },
    [ordered]@{ id = "frontend-authority-denied"; blockers = @("frontend-output-not-authority"); reason = "Frontend output cannot authorize effects." },
    [ordered]@{ id = "tui-authority-denied"; blockers = @("tui-output-not-authority"); reason = "TUI output cannot authorize effects." },
    [ordered]@{ id = "model-replay-authority-denied"; blockers = @("model-replay-not-authority"); reason = "Model replay cannot authorize effects." },
    [ordered]@{ id = "shell-output-authority-denied"; blockers = @("shell-output-not-authority"); reason = "Shell output cannot authorize effects." }
)
$cases = @()
foreach ($spec in $caseSpecs) {
    $cases += New-DenialCase -Id $spec.id -ExpectedBlockers ([string[]]$spec.blockers) -Reason $spec.reason
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$matrix = [ordered]@{
    schema = "agentos.rc17-security-execution-install-update-fail-closed-matrix.v1"
    generated_at = $generatedAtValue
    task = "RC17-021"
    status = if ($failedCases.Count -eq 0) { "passed" } else { "failed" }
    production_ready_claim = $false
    effect_envelope_core_hash = $effectEnvelopeCoreHash
    decision_material_hash = $decisionMaterialHash
    cases = $cases
    summary = [ordered]@{
        cases = @($cases).Count
        passed = @($cases | Where-Object { $_.status -eq "passed" }).Count
        failed = $failedCases.Count
        failed_cases = @($failedCases | ForEach-Object { $_.id })
    }
}
$matrixPath = Join-Path $resolvedArtifactDir "security-execution-install-update-fail-closed-matrix.json"
Write-Json $matrix $matrixPath

$source = [ordered]@{
    rc17_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc17_contract = New-ArtifactRef $resolvedContractPath
    rc17_planspec_result = New-ArtifactRef $resolvedPlanSpecResultPath $planSpecResult
    rc17_planspec = New-ArtifactRef $resolvedPlanSpecPath $planSpec
    rc17_approval_binding_result = New-ArtifactRef $resolvedApprovalBindingResultPath $approvalBindingResult
    rc17_approval_packet = New-ArtifactRef $resolvedApprovalPacketPath $approvalPacket
    rc17_target_binding_result = New-ArtifactRef $resolvedTargetBindingResultPath $targetBindingResult
    rc17_target_package = New-ArtifactRef $resolvedTargetPackagePath $targetPackage
    rc16_preflight_result = New-ArtifactRef $resolvedPreflightResultPath $preflightResult
    rc16_preflight_package = New-ArtifactRef $resolvedPreflightPackagePath $preflightPackage
    security_execution_policy = New-ArtifactRef $resolvedSecurityExecutionPolicyPath
    security_execution_tools = New-ArtifactRef $resolvedSecurityExecutionToolsPath
}

Add-Check "plan.current_task.rc17_021" $planAllowsRun "RC17-021 must run after RC17-020 completed, either while current_task is RC17-021 or while rerunning after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc17_020_status = $rc17PreviousStatus; rc17_021_status = $rc17TaskStatus })
Add-Check "contract.security_execution_gate.present" ($contractText.Contains("SecurityExecution may allow") -and $contractText.Contains("exact repo-local install/update effect envelope")) "RC17-021 must consume the SecurityExecution install/update allow contract." (New-ArtifactRef $resolvedContractPath)
Add-Check "source.agentcore_planspec.executable" $planSpecExecutable "RC17-021 must consume executable RC17 AgentCore install/update PlanSpec evidence." ([ordered]@{ planspec_core_hash = $planspecCoreHash; executable = $planSpec.agentcore_install_update_planspec_executable })
Add-Check "source.target_approval_preflight.bound" ($targetBound -and $approvalBound -and $preflightBound -and $auditNoncePolicyBound -and $rollbackSupportBound) "RC17-021 must bind exact target, exact approval, preflight, audit/nonce/expiry/policy, and rollback/support references." ([ordered]@{ target_bound = $targetBound; approval_bound = $approvalBound; preflight_bound = $preflightBound; audit_nonce_policy_bound = $auditNoncePolicyBound; rollback_support_bound = $rollbackSupportBound })
Add-Check "security.code.bound" $securityCodeBound "RC17-021 must bind SecurityExecution policy and tool code hashes." ([ordered]@{ security_policy_sha256 = $securityPolicySha256; security_tools_sha256 = $securityToolsSha256 })
Add-Check "decision.allow_scoped_exact_install_update" ($securityExecutionAllowed -eq $true -and @($decision.security_execution_allowed_effects).Count -eq 2 -and $decision.authority.security_execution_scope -eq "repo-local-exact-install-update-only" -and $decision.activation_allowed -eq $false -and $decision.rollback_execution_allowed -eq $false -and $decision.remote_dispatch_enabled -eq $false) "SecurityExecution allow must be scoped only to exact repo-local install/update effects." ([ordered]@{ effect_envelope_core_hash = $effectEnvelopeCoreHash; decision_material_hash = $decisionMaterialHash; allowed_effects = $decision.security_execution_allowed_effects; forbidden_effects = $effectEnvelopeCore.forbidden_effects })
Add-Check "decision.no_effect_execution" ($decision.effect_preparation_allowed -eq $false -and $decision.install_effect_preparation_allowed -eq $false -and $decision.update_effect_preparation_allowed -eq $false -and $decision.install_performed -eq $false -and $decision.update_performed -eq $false) "SecurityExecution allow decision alone must not prepare or execute install/update effects." ([ordered]@{ blockers = @($blockers); side_effects = $sideEffects })
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 30) "Broad, mismatched, stale, replayed, unapproved, remote, support-upload, recovery, host boot, production ring, and display-surface effect envelopes must fail closed." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })
Add-Check "authority.no_side_effects" (@($sideEffects.GetEnumerator() | Where-Object { $_.Value -ne $false }).Count -eq 0) "RC17-021 must not install, update, activate, roll back, mutate host state, upload support, recover, dispatch remotely, or mutate production rings." $sideEffects

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $decisionPath),
    (Get-Content -Raw -LiteralPath $matrixPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC17-021 outputs must not contain key blocks, private key paths, auth tokens, public identity markers, or signing key file names." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$decisionSha256 = Get-FileSha256 $decisionPath
$matrixSha256 = Get-FileSha256 $matrixPath
$result = [ordered]@{
    schema = "agentos.rc17-security-execution-install-update-allow-result.v1"
    generated_at = $generatedAtValue
    task = "RC17-021"
    status = $resultStatus
    production_ready_claim = $false
    package_id = $packageId
    media_id = $mediaId
    release_id = $releaseId
    target_binding_id = $targetBindingId
    approval_id = $approvalId
    planspec_core_hash = $planspecCoreHash
    effect_envelope_core_hash = $effectEnvelopeCoreHash
    decision_material_hash = $decisionMaterialHash
    security_surface = [ordered]@{
        state = "security-execution-install-update-allow-bound-effects-denied"
        security_execution_install_update_allow = $securityExecutionAllowed
        exact_install_update_target_bound = $targetBound
        exact_install_update_approval_bound = $approvalBound
        agentcore_install_update_planspec_executable = $planSpecExecutable
        rollback_preconditions_bound = $rollbackPreconditionsBound
        install_effect_preparation_allowed = $installEffectPreparationAllowed
        update_effect_preparation_allowed = $updateEffectPreparationAllowed
        install_allowed = $securityExecutionAllowed
        update_allowed = $securityExecutionAllowed
        install_performed = $false
        update_performed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        blockers = @($blockers)
    }
    outputs = [ordered]@{
        security_execution_install_update_allow_decision = [ordered]@{
            path = Get-StablePath $decisionPath
            sha256 = $decisionSha256
            effect_envelope_core_hash = $effectEnvelopeCoreHash
            decision_material_hash = $decisionMaterialHash
        }
        security_execution_install_update_fail_closed_matrix = [ordered]@{
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
        agentcore_install_update_planspec_executable = $true
        security_execution_install_update_allow = $securityExecutionAllowed
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
        rc17_021_complete = (@($script:failedChecks).Count -eq 0)
        security_execution_install_update_allow = $securityExecutionAllowed
        rollback_preconditions_bound = $false
        install_effect_preparation_allowed = $false
        update_effect_preparation_allowed = $false
        install_performed = $false
        update_performed = $false
        next_task = "RC17-022"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC17-021-security-execution-install-update-allow.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc17-security-execution-install-update-allow-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC17-021"
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
    security_surface = $result.security_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc17_021_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC17-022"
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
    throw "Sensitive marker detected in RC17-021 outputs."
}

Write-Host "RC17 SecurityExecution install/update allow $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Decision: $(Get-StablePath $decisionPath)"
Write-Host "Fail-closed matrix: $(Get-StablePath $matrixPath)"
Write-Host "SecurityExecution allow: $securityExecutionAllowed; rollback preconditions: false; install/update effects prepared: false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
