param(
    [string]$ArtifactDir = ".workflow/artifacts/rc9-exact-approval-execution-binding",
    [string]$GeneratedAt = "",
    [string]$BindingContractPath = ".workflow/active/WFS-20260608-agentos-production-distro-rc9/docs/controlled-execution-binding-contract.md",
    [string]$PublicationResultPath = ".workflow/artifacts/rc9-external-object-publication/result.json",
    [string]$DriftResultPath = ".workflow/artifacts/rc9-artifact-drift-reconciliation/result.json",
    [string]$InstallerFetchResultPath = ".workflow/artifacts/rc9-external-object-installer-fetch/result.json",
    [string]$TargetEnrollmentResultPath = ".workflow/artifacts/rc9-two-node-canary-enrollment/result.json",
    [string]$TargetSetPath = ".workflow/artifacts/rc9-two-node-canary-enrollment/canary-target-set.json",
    [string]$TargetHandoffPath = ".workflow/artifacts/rc9-two-node-canary-enrollment/controlled-execution-handoff.json",
    [string]$DescriptorPath = ".workflow/artifacts/rc8-real-payload-object-descriptor/payload-object-descriptor.json",
    [string]$CompatibilityPath = ".workflow/artifacts/rc7-install-rollback-baseline/compatibility.json",
    [string]$RollbackBaselinePath = ".workflow/artifacts/rc7-install-rollback-baseline/rollback-baseline.json",
    [string]$SupportRecoveryPath = ".workflow/artifacts/rc5-hosted-support-recovery/support-index.json",
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
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace("-", "").ToLowerInvariant()
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
    $script:checks += [ordered]@{
        id = $Id
        status = if ($Passed) { "passed" } else { "failed" }
        severity = "blocking"
        message = $Message
        evidence = $Evidence
    }
}

function Add-UniqueBlocker {
    param([Parameter(Mandatory = $true)][string]$Blocker)
    if ($script:blockers -notcontains $Blocker) {
        $script:blockers += $Blocker
    }
}

function New-ArtifactRef {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        $Json = $null
    )
    return [ordered]@{
        path = Get-StablePath $Path
        sha256 = Get-FileSha256 $Path
        size_bytes = if (Test-Path -LiteralPath $Path -PathType Leaf) { (Get-Item -LiteralPath $Path).Length } else { $null }
        present = Test-Path -LiteralPath $Path -PathType Leaf
        schema = if ($null -ne $Json) { $Json.schema } else { $null }
        status = if ($null -ne $Json) { $Json.status } else { $null }
    }
}

function Test-NoSensitiveText {
    param([Parameter(Mandatory = $true)][string[]]$Values)
    $privateKeyMarker = "PRIVATE" + " KEY"
    $markers = @(
        ("BEGIN " + $privateKeyMarker),
        ($privateKeyMarker + "-----"),
        ("Authorization:" + " Bearer"),
        ("Bearer" + " "),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ("." + "local-release-authority"),
        ("signing" + "-key.pem"),
        ("/etc/" + "aios-signer")
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

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:blockers = @()

$generatedAt = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }
$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null

$resolvedBindingContractPath = Resolve-RepoPath $BindingContractPath
$resolvedPublicationResultPath = Resolve-RepoPath $PublicationResultPath
$resolvedDriftResultPath = Resolve-RepoPath $DriftResultPath
$resolvedInstallerFetchResultPath = Resolve-RepoPath $InstallerFetchResultPath
$resolvedTargetEnrollmentResultPath = Resolve-RepoPath $TargetEnrollmentResultPath
$resolvedTargetSetPath = Resolve-RepoPath $TargetSetPath
$resolvedTargetHandoffPath = Resolve-RepoPath $TargetHandoffPath
$resolvedDescriptorPath = Resolve-RepoPath $DescriptorPath
$resolvedCompatibilityPath = Resolve-RepoPath $CompatibilityPath
$resolvedRollbackBaselinePath = Resolve-RepoPath $RollbackBaselinePath
$resolvedSupportRecoveryPath = Resolve-RepoPath $SupportRecoveryPath

$publicationResult = Read-Json $resolvedPublicationResultPath
$driftResult = Read-Json $resolvedDriftResultPath
$installerFetchResult = Read-Json $resolvedInstallerFetchResultPath
$targetEnrollmentResult = Read-Json $resolvedTargetEnrollmentResultPath
$targetSet = Read-Json $resolvedTargetSetPath
$targetHandoff = Read-Json $resolvedTargetHandoffPath
$descriptor = Read-Json $resolvedDescriptorPath
$compatibility = Read-Json $resolvedCompatibilityPath
$rollbackBaseline = Read-Json $resolvedRollbackBaselinePath
$supportRecovery = Read-Json $resolvedSupportRecoveryPath

$releaseId = [string]$descriptor.release_id
$descriptorSha256 = Get-FileSha256 $resolvedDescriptorPath
$publicationResultSha256 = Get-FileSha256 $resolvedPublicationResultPath
$driftResultSha256 = Get-FileSha256 $resolvedDriftResultPath
$installerFetchResultSha256 = Get-FileSha256 $resolvedInstallerFetchResultPath
$targetEnrollmentResultSha256 = Get-FileSha256 $resolvedTargetEnrollmentResultPath
$targetSetFileSha256 = Get-FileSha256 $resolvedTargetSetPath
$targetSetDigest = if (-not [string]::IsNullOrWhiteSpace([string]$targetSet.target_set_digest)) { [string]$targetSet.target_set_digest } else { [string]$targetHandoff.target_set.digest }
$compatibilitySha256 = Get-FileSha256 $resolvedCompatibilityPath
$rollbackBaselineSha256 = Get-FileSha256 $resolvedRollbackBaselinePath
$supportRecoverySha256 = Get-FileSha256 $resolvedSupportRecoveryPath

$publicationReady = $publicationResult.status -eq "passed" -and $publicationResult.publication_surface.external_object_url_published -eq $true
$driftReady = $driftResult.status -eq "passed" -and $driftResult.reconciliation_surface.state -eq "reconciled-current-artifact"
$fetchReady = $installerFetchResult.status -eq "passed" -and $installerFetchResult.fetch_surface.fetch_allowed -eq $true
$targetSetEnrolled = $targetEnrollmentResult.status -eq "passed" -and $targetEnrollmentResult.enrollment_surface.target_set_enrolled -eq $true
$remoteFleetEnabled = $targetEnrollmentResult.enrollment_surface.remote_dispatch_enabled -eq $true
$observedTargetCount = [int]$targetEnrollmentResult.enrollment_surface.observed_candidate_node_count
$enrolledTargetCount = [int]$targetEnrollmentResult.enrollment_surface.enrolled_target_count
$requiredTargetCount = [int]$targetEnrollmentResult.enrollment_surface.required_minimum_target_count
$targetNodeIds = @($targetSet.ordered_targets | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.node_id) } | ForEach-Object { [string]$_.node_id })

foreach ($blocker in @($targetEnrollmentResult.blockers)) {
    if ([string]$blocker -eq "exact-operator-approval-pending") {
        Add-UniqueBlocker "exact-operator-approval-not-granted"
    } else {
        Add-UniqueBlocker ([string]$blocker)
    }
}
if (-not $publicationReady) { Add-UniqueBlocker "external-https-object-uri-not-published" }
if (-not $driftReady) { Add-UniqueBlocker "declared-current-artifact-drift-denied" }
if (-not $fetchReady) { Add-UniqueBlocker "installer-quarantine-fetch-not-run" }
if (-not $targetSetEnrolled) { Add-UniqueBlocker "target-set-not-enrolled" }
if ($enrolledTargetCount -lt $requiredTargetCount) { Add-UniqueBlocker "two-or-more-enrolled-canary-target-nodes-required" }
if (-not $remoteFleetEnabled) { Add-UniqueBlocker "remote-fleet-execution-not-enabled" }
Add-UniqueBlocker "exact-operator-approval-not-granted"
Add-UniqueBlocker "AgentCore-PlanSpec-not-bound"
Add-UniqueBlocker "SecurityExecutionEngine-approval-not-bound"
Add-UniqueBlocker "controlled-execution-not-authorized"

$requestedEffectSet = @(
    "controlled-canary-activation"
)
$policyVersion = "rc9-controlled-execution-binding-v1"
$planSpecId = "rc9-controlled-canary-activation-planspec-required"
$securityPolicyId = "rc9-controlled-canary-activation-policy"
$securityDecisionId = "rc9-controlled-canary-activation-decision-denied"
$effectEnvelopeId = "rc9-controlled-canary-activation-effect-envelope-denied"

$planSpecCore = [ordered]@{
    planspec_id = $planSpecId
    plan_kind = "controlled-canary-activation"
    release_id = $releaseId
    payload_object_digest = [string]$descriptor.sha256
    object_descriptor_digest = $descriptorSha256
    external_object_publication_digest = $publicationResultSha256
    declared_current_reconciliation_digest = $driftResultSha256
    installer_fetch_digest = $installerFetchResultSha256
    target_set_digest = $targetSetDigest
    exact_approval_digest = "not-bound"
    security_execution_policy_decision_digest = "not-bound"
    rollback_baseline_digest = $rollbackBaselineSha256
    support_recovery_digest = $supportRecoverySha256
    expected_observations = @(
        "activation-denied-while-target-set-not-enrolled",
        "activation-denied-while-exact-approval-not-granted",
        "no-side-effects-observed"
    )
    rollback_path = "required-before-execution"
    audit_journal_path = "required-before-execution"
    expiry = "required-before-execution"
    policy_version = $policyVersion
}
$planSpecCoreHash = Get-StringSha256 (($planSpecCore | ConvertTo-Json -Depth 100 -Compress))

$approvalBinding = [ordered]@{
    approval_id = $null
    approving_actor = $null
    actor_authority_scope = $null
    release_id = $releaseId
    payload_object_digest = [string]$descriptor.sha256
    object_descriptor_digest = $descriptorSha256
    declared_current_reconciliation_digest = $driftResultSha256
    target_set_digest = $targetSetDigest
    target_node_ids = $targetNodeIds
    requested_effect_set = $requestedEffectSet
    agentcore_planspec_id = $planSpecId
    agentcore_planspec_hash = $planSpecCoreHash
    security_execution_policy_id = $securityPolicyId
    security_execution_decision_id = $securityDecisionId
    rollback_baseline_digest = $rollbackBaselineSha256
    support_recovery_digest = $supportRecoverySha256
    expiry = $null
    nonce = $null
    policy_version = $policyVersion
    audit_sink = $null
}

$missingApprovalFields = @(
    "approval_id",
    "approving_actor",
    "actor_authority_scope",
    "target_node_ids",
    "expiry",
    "nonce",
    "audit_sink"
)

$exactApproval = [ordered]@{
    schema = "agentos.rc9-exact-approval-binding.v1"
    generated_at = $generatedAt
    task = "RC9-021"
    status = "exact-approval-denied"
    production_ready_claim = $false
    projection_only = $true
    exact_approval_required = $true
    exact_approval_bound = $false
    approval_granted = $false
    executable = $false
    approval_binding = $approvalBinding
    missing_required_fields = $missingApprovalFields
    upstream_gates = [ordered]@{
        external_object_url_published = $publicationReady
        declared_current_artifact_drift_reconciled = $driftReady
        installer_quarantine_fetch_verified = $fetchReady
        target_set_enrolled = $targetSetEnrolled
        observed_target_count = $observedTargetCount
        enrolled_target_count = $enrolledTargetCount
        required_target_count = $requiredTargetCount
        remote_fleet_execution_enabled = $remoteFleetEnabled
    }
    denial_reasons = $script:blockers
    authority = [ordered]@{
        mirror_authority = $false
        object_storage_authority = $false
        signer_authority = $false
        frontend_authority = $false
        tui_authority = $false
        shell_authority = $false
        model_replay_authority = $false
    }
}
$exactApprovalDigest = Get-StringSha256 (($exactApproval | ConvertTo-Json -Depth 100 -Compress))

$securityDecision = [ordered]@{
    schema = "agentos.rc9-security-execution-decision.v1"
    generated_at = $generatedAt
    task = "RC9-021"
    status = "security-execution-denied"
    production_ready_claim = $false
    projection_only = $true
    policy_id = $securityPolicyId
    decision_id = $securityDecisionId
    effect_envelope_id = $effectEnvelopeId
    planspec_id = $planSpecId
    planspec_hash = $planSpecCoreHash
    exact_approval_digest = $exactApprovalDigest
    target_set_digest = $targetSetDigest
    release_id = $releaseId
    payload_object_digest = [string]$descriptor.sha256
    allowed_effect_set = @()
    denied_effect_set = $requestedEffectSet
    filesystem_mutation_scope = "none"
    boot_metadata_mutation_scope = "none"
    active_slot_mutation_scope = "none"
    rollback_scope = "none"
    support_recovery_scope = "metadata-reference-only"
    audit_sink = "required-before-execution"
    expiry = "not-granted"
    denial_reason = "exact-approval-and-target-set-gates-not-bound"
    denial_reasons = $script:blockers
    side_effects = [ordered]@{
        effect_prepared = $false
        effect_executed = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        boot_metadata_mutated = $false
        active_slot_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        remote_dispatch_enabled = $false
    }
}
$securityDecisionDigest = Get-StringSha256 (($securityDecision | ConvertTo-Json -Depth 100 -Compress))

$planSpecBinding = [ordered]@{
    schema = "agentos.rc9-agentcore-planspec-binding.v1"
    generated_at = $generatedAt
    task = "RC9-021"
    status = "planspec-binding-denied"
    production_ready_claim = $false
    projection_only = $true
    planspec_required = $true
    planspec_bound = $false
    executable = $false
    planspec_core_hash = $planSpecCoreHash
    planspec_core = $planSpecCore
    exact_approval_binding_sha256 = $exactApprovalDigest
    security_execution_decision_sha256 = $securityDecisionDigest
    denied_because = $script:blockers
    forbidden_authority_scan = [ordered]@{
        shell_commands_embedded = $false
        private_material_embedded = $false
        broad_target_selectors_embedded = $false
        mutable_object_references_embedded = $false
        support_upload_authority_embedded = $false
        production_ring_mutation_authority_embedded = $false
        model_authority_embedded = $false
        tui_authority_embedded = $false
        mirror_authority_embedded = $false
    }
}

$denial = [ordered]@{
    schema = "agentos.rc9-execution-binding-denial.v1"
    generated_at = $generatedAt
    task = "RC9-021"
    status = "execution-binding-denied"
    production_ready_claim = $false
    denied = $true
    release_id = $releaseId
    target_set_digest = $targetSetDigest
    exact_approval_digest = $exactApprovalDigest
    planspec_hash = $planSpecCoreHash
    security_execution_decision_digest = $securityDecisionDigest
    denial_cases = @(
        [ordered]@{ id = "external-https-object-uri-not-published"; status = "passed"; execution_allowed = $false },
        [ordered]@{ id = "declared-current-artifact-drift-denied"; status = "passed"; execution_allowed = $false },
        [ordered]@{ id = "installer-quarantine-fetch-not-run"; status = "passed"; execution_allowed = $false },
        [ordered]@{ id = "target-set-not-enrolled"; status = "passed"; execution_allowed = $false },
        [ordered]@{ id = "exact-operator-approval-not-granted"; status = "passed"; execution_allowed = $false },
        [ordered]@{ id = "agentcore-planspec-not-bound"; status = "passed"; execution_allowed = $false },
        [ordered]@{ id = "security-execution-approval-not-bound"; status = "passed"; execution_allowed = $false },
        [ordered]@{ id = "remote-fleet-execution-disabled"; status = "passed"; execution_allowed = $false }
    )
    preserved_boundaries = [ordered]@{
        exact_approval_granted = $false
        agentcore_planspec_executable = $false
        security_execution_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        production_ring_mutation_allowed = $false
        remote_dispatch_enabled = $false
    }
    blockers = $script:blockers
    next_task = "RC9-022"
}

$exactApprovalPath = Join-Path $resolvedArtifactDir "exact-approval-binding.json"
$planSpecPath = Join-Path $resolvedArtifactDir "agentcore-planspec-binding.json"
$securityDecisionPath = Join-Path $resolvedArtifactDir "security-execution-decision.json"
$denialPath = Join-Path $resolvedArtifactDir "execution-binding-denial.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"

Write-Json $exactApproval $exactApprovalPath
Write-Json $planSpecBinding $planSpecPath
Write-Json $securityDecision $securityDecisionPath
Write-Json $denial $denialPath

Add-Check "source.rc9_020.target_enrollment_denied" ($targetEnrollmentResult.status -eq "passed" -and $targetEnrollmentResult.summary.rc9_020_complete -eq $true -and $targetEnrollmentResult.enrollment_surface.target_set_enrolled -eq $false) "RC9-021 must consume completed RC9-020 target-set denial evidence." ([ordered]@{ status = $targetEnrollmentResult.status; state = $targetEnrollmentResult.enrollment_surface.state; enrolled = $targetEnrollmentResult.enrollment_surface.enrolled_target_count; required = $requiredTargetCount })
Add-Check "exact_approval.denied" ($exactApproval.exact_approval_bound -eq $false -and $exactApproval.approval_granted -eq $false -and $exactApproval.executable -eq $false) "Exact approval must remain denied when approval fields and target enrollment are missing." ([ordered]@{ status = $exactApproval.status; missing = $missingApprovalFields; blockers = $script:blockers })
Add-Check "planspec.non_executable" ($planSpecBinding.planspec_bound -eq $false -and $planSpecBinding.executable -eq $false -and -not [string]::IsNullOrWhiteSpace($planSpecBinding.planspec_core_hash)) "AgentCore PlanSpec binding must be projected but non-executable until exact approval and SecurityExecutionEngine bind." ([ordered]@{ planspec_id = $planSpecId; planspec_hash = $planSpecCoreHash; exact_approval_binding_sha256 = $exactApprovalDigest })
Add-Check "security_execution.denied" ($securityDecision.status -eq "security-execution-denied" -and @($securityDecision.allowed_effect_set).Count -eq 0 -and @($securityDecision.denied_effect_set).Count -gt 0) "SecurityExecutionEngine decision must deny the effect envelope when approval and target gates are not bound." ([ordered]@{ decision_id = $securityDecisionId; allowed_effects = @($securityDecision.allowed_effect_set).Count; denied_effects = $securityDecision.denied_effect_set })
Add-Check "binding_denial.fail_closed" ($denial.denied -eq $true -and $denial.preserved_boundaries.activation_allowed -eq $false -and $denial.preserved_boundaries.remote_dispatch_enabled -eq $false) "Execution binding denial must keep activation, rollback, support upload, production mutation, and remote dispatch disabled." $denial.preserved_boundaries
Add-Check "side_effects.none" ($securityDecision.side_effects.effect_prepared -eq $false -and $securityDecision.side_effects.activation_performed -eq $false -and $securityDecision.side_effects.rollback_execution_performed -eq $false -and $securityDecision.side_effects.production_ring_mutated -eq $false -and $securityDecision.side_effects.remote_dispatch_enabled -eq $false) "RC9-021 must not prepare or execute side effects." $securityDecision.side_effects

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $exactApprovalPath),
    (Get-Content -Raw -LiteralPath $planSpecPath),
    (Get-Content -Raw -LiteralPath $securityDecisionPath),
    (Get-Content -Raw -LiteralPath $denialPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC9-021 outputs must not contain secret paths, PEM blocks, auth tokens, or signer host internals." $null

$source = [ordered]@{
    binding_contract = New-ArtifactRef $resolvedBindingContractPath
    publication_result = New-ArtifactRef $resolvedPublicationResultPath $publicationResult
    drift_result = New-ArtifactRef $resolvedDriftResultPath $driftResult
    installer_fetch_result = New-ArtifactRef $resolvedInstallerFetchResultPath $installerFetchResult
    target_enrollment_result = New-ArtifactRef $resolvedTargetEnrollmentResultPath $targetEnrollmentResult
    target_set = New-ArtifactRef $resolvedTargetSetPath $targetSet
    target_handoff = New-ArtifactRef $resolvedTargetHandoffPath $targetHandoff
    descriptor = New-ArtifactRef $resolvedDescriptorPath $descriptor
    compatibility = New-ArtifactRef $resolvedCompatibilityPath $compatibility
    rollback_baseline = New-ArtifactRef $resolvedRollbackBaselinePath $rollbackBaseline
    support_recovery = New-ArtifactRef $resolvedSupportRecoveryPath $supportRecovery
}

$failedChecks = @($script:checks | Where-Object { $_.status -ne "passed" })
$result = [ordered]@{
    schema = "agentos.rc9-exact-approval-execution-binding-result.v1"
    generated_at = $generatedAt
    task = "RC9-021"
    status = if ($failedChecks.Count -eq 0) { "passed" } else { "failed" }
    production_ready_claim = $false
    release_id = $releaseId
    binding_surface = [ordered]@{
        state = "execution-binding-denied"
        exact_approval_required = $true
        exact_approval_bound = $false
        exact_approval_granted = $false
        agentcore_planspec_required = $true
        agentcore_planspec_bound = $false
        agentcore_planspec_hash = $planSpecCoreHash
        security_execution_required = $true
        security_execution_decision_bound = $false
        security_execution_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        remote_dispatch_enabled = $false
        blockers = $script:blockers
    }
    outputs = [ordered]@{
        exact_approval_binding = [ordered]@{
            path = Get-StablePath $exactApprovalPath
            sha256 = Get-FileSha256 $exactApprovalPath
            binding_digest = $exactApprovalDigest
        }
        agentcore_planspec_binding = [ordered]@{
            path = Get-StablePath $planSpecPath
            sha256 = Get-FileSha256 $planSpecPath
            planspec_core_hash = $planSpecCoreHash
        }
        security_execution_decision = [ordered]@{
            path = Get-StablePath $securityDecisionPath
            sha256 = Get-FileSha256 $securityDecisionPath
            decision_digest = $securityDecisionDigest
        }
        execution_binding_denial = [ordered]@{
            path = Get-StablePath $denialPath
            sha256 = Get-FileSha256 $denialPath
        }
    }
    source = $source
    checks = $script:checks
    blockers = $script:blockers
    invariants = [ordered]@{
        local_projection_only = $true
        exact_approval_fabricated = $false
        approval_granted = $false
        executable_planspec_created = $false
        security_execution_effect_allowed = $false
        external_payload_bytes_uploaded = $false
        network_fetch_attempted = $false
        quarantine_payload_written = $false
        payload_interpreted = $false
        cryptographic_signing_performed = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        persistent_state_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        remote_dispatch_enabled = $false
        model_replay_authority = $false
        normal_shell_authority = $false
        tui_authority = $false
        mirror_authority = $false
        signer_authority = $false
        production_ready_claim = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = $failedChecks.Count
        rc9_021_complete = ($failedChecks.Count -eq 0)
        binding_state = "execution-binding-denied"
        exact_approval_granted = $false
        agentcore_planspec_bound = $false
        security_execution_approval_bound = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        remote_dispatch_enabled = $false
        next_task = "RC9-022"
    }
}

Write-Json $result $resultPath

if (-not (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath)))) {
    throw "Sensitive marker detected in RC9-021 result."
}

Write-Host "RC9 exact approval execution binding $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Binding state: $($result.binding_surface.state)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $($failedChecks.Count), blockers: $(@($script:blockers).Count)"

if ($FailOnFailedChecks -and $failedChecks.Count -gt 0) {
    exit 1
}
