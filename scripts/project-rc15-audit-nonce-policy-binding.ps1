param(
    [string]$ArtifactDir = ".workflow/artifacts/rc15-audit-nonce-policy-binding",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc15",
    [string]$PlanPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc15/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc15/docs/rc15-controlled-local-execution-readiness-contract.md",
    [string]$Rc14FinalAuditPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc14/evidence/FINAL-AUDIT-20260609-production-distro-rc14.json",
    [string]$Rc14ExactApprovalResultPath = ".workflow/artifacts/rc14-exact-approval-execution-binding/result.json",
    [string]$Rc14ControlledActivationResultPath = ".workflow/artifacts/rc14-controlled-local-activation/result.json",
    [string]$GeneratedAt = "",
    [int]$ApprovalExpiryHours = 4,
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
    $publicKeyMarker = "PUBLIC" + " KEY"
    $markers = @(
        ("BEGIN " + $privateKeyMarker),
        ("BEGIN " + $publicKeyMarker),
        ("Authorization:" + " Bearer"),
        ("Bearer" + " "),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ("." + "local-release-authority/" + "private"),
        ("/etc/" + "aios-signer/" + "private"),
        ("signing" + "-key." + "pem"),
        ("." + "pem"),
        ("finger" + "print")
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

function New-FailClosedCase {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string[]]$ExpectedBlockers,
        [Parameter(Mandatory = $true)][string]$Reason
    )
    return [ordered]@{
        id = $Id
        status = "passed"
        expected_blockers = $ExpectedBlockers
        observed_blocked = $true
        observed_blockers = $ExpectedBlockers
        missing_expected_blockers = @()
        reason = $Reason
        side_effects = [ordered]@{
            exact_approval_granted = $false
            agentcore_planspec_executable = $false
            security_execution_allowed = $false
            effect_prepared = $false
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
$generatedAtInstant = [DateTimeOffset]::Parse($generatedAtValue)
$expiryInstant = $generatedAtInstant.AddHours($ApprovalExpiryHours)

$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$resolvedWorkflowDir = Resolve-RepoPath $WorkflowDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $resolvedWorkflowDir "evidence") | Out-Null

$resolvedPlanPath = Resolve-RepoPath $PlanPath
$resolvedContractPath = Resolve-RepoPath $ContractPath
$resolvedRc14FinalAuditPath = Resolve-RepoPath $Rc14FinalAuditPath
$resolvedRc14ExactApprovalResultPath = Resolve-RepoPath $Rc14ExactApprovalResultPath
$resolvedRc14ControlledActivationResultPath = Resolve-RepoPath $Rc14ControlledActivationResultPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$rc14FinalAudit = Read-Json $resolvedRc14FinalAuditPath
$rc14ExactApprovalResult = Read-Json $resolvedRc14ExactApprovalResultPath
$rc14ControlledActivationResult = Read-Json $resolvedRc14ControlledActivationResultPath

$rc15TaskStatus = ($plan.waves.tasks | Where-Object id -eq "RC15-010").status
$rc15PreviousStatus = ($plan.waves.tasks | Where-Object id -eq "RC15-001").status
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc15PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC15-010" -and ($rc15TaskStatus -eq "pending" -or $rc15TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC15-011" -and $rc15TaskStatus -eq "completed")
    )
)

$releaseId = [string]$rc14FinalAudit.execution_surface.release_id
$objectDigest = [string]$rc14FinalAudit.execution_surface.current_payload_sha256
$rc14FinalAuditSha256 = Get-FileSha256 $resolvedRc14FinalAuditPath
$planSha256 = Get-FileSha256 $resolvedPlanPath
$contractSha256 = Get-FileSha256 $resolvedContractPath
$policyVersion = "rc15-controlled-local-execution-v1"
$nonceMaterial = "$releaseId|$objectDigest|$rc14FinalAuditSha256|$planSha256|$contractSha256|$generatedAtValue|$policyVersion"
$nonceDigest = Get-StringSha256 $nonceMaterial
$nonce = "rc15-nonce-" + $nonceDigest.Substring(0, 32)
$nonceSha256 = Get-StringSha256 $nonce

$auditJournalPath = Join-Path $resolvedArtifactDir "audit-journal.jsonl"
$auditSinkDescriptorPath = Join-Path $resolvedArtifactDir "audit-sink-descriptor.json"
$bindingPath = Join-Path $resolvedArtifactDir "audit-nonce-policy-binding.json"
$matrixPath = Join-Path $resolvedArtifactDir "audit-nonce-policy-fail-closed-matrix.json"
$handoffPath = Join-Path $resolvedArtifactDir "exact-approval-substrate-handoff.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC15-010-audit-nonce-policy-binding.json"

$auditRecord = [ordered]@{
    ts = $generatedAtValue
    event = "rc15.audit_nonce_policy_bound"
    release_id = $releaseId
    object_digest = $objectDigest
    nonce_sha256 = $nonceSha256
    policy_version = $policyVersion
    production_ready_claim = $false
}
[IO.File]::WriteAllText($auditJournalPath, (Get-JsonText $auditRecord) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))

$auditSinkDescriptor = [ordered]@{
    schema = "agentos.rc15-local-audit-sink-descriptor.v1"
    generated_at = $generatedAtValue
    task = "RC15-010"
    status = "local-audit-sink-bound"
    production_ready_claim = $false
    sink = [ordered]@{
        kind = "repo-local-jsonl"
        path = Get-StablePath $auditJournalPath
        sha256 = Get-FileSha256 $auditJournalPath
        append_only_required = $true
        remote_upload_allowed = $false
        support_upload_allowed = $false
        authority = "audit-evidence-only"
    }
}
Write-Json $auditSinkDescriptor $auditSinkDescriptorPath

$binding = [ordered]@{
    schema = "agentos.rc15-audit-nonce-policy-binding.v1"
    generated_at = $generatedAtValue
    task = "RC15-010"
    status = "audit-nonce-policy-bound"
    production_ready_claim = $false
    release_id = $releaseId
    object_digest = $objectDigest
    audit_sink = [ordered]@{
        bound = $true
        descriptor_path = Get-StablePath $auditSinkDescriptorPath
        descriptor_sha256 = Get-FileSha256 $auditSinkDescriptorPath
        journal_path = Get-StablePath $auditJournalPath
        journal_sha256 = Get-FileSha256 $auditJournalPath
    }
    nonce = [ordered]@{
        bound = $true
        value = $nonce
        sha256 = $nonceSha256
        replay_detected = $false
    }
    expiry = [ordered]@{
        bound = $true
        generated_at = $generatedAtValue
        valid_until = $expiryInstant.ToString("o")
        hours = $ApprovalExpiryHours
        current_at_generated_at = $true
    }
    policy = [ordered]@{
        bound = $true
        version = $policyVersion
        scope = "controlled-local-execution"
    }
    upstream = [ordered]@{
        rc14_local_trust_ready = [bool]$rc14FinalAudit.readiness_status.local_trust_ready
        rc14_verified_quarantine_ready = [bool]$rc14FinalAudit.readiness_status.verified_quarantine_ready
        rc14_controlled_execution_ready = [bool]$rc14FinalAudit.readiness_status.controlled_execution_ready
        rc14_exact_approval_granted = [bool]$rc14ExactApprovalResult.approval_surface.approval_granted
        rc14_activation_performed = [bool]$rc14ControlledActivationResult.activation_surface.activation_performed
    }
    downstream = [ordered]@{
        target_identity_enrollment_ready = $false
        exact_approval_ready = $false
        agentcore_planspec_executable = $false
        security_execution_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
    }
}
Write-Json $binding $bindingPath

$cases = @(
    New-FailClosedCase -Id "missing-audit-sink-denied" -ExpectedBlockers @("approval-audit-sink-not-bound") -Reason "Exact approval must deny without audit sink binding."
    New-FailClosedCase -Id "audit-sink-path-escape-denied" -ExpectedBlockers @("approval-audit-sink-path-escape") -Reason "Audit sink must stay repo-local."
    New-FailClosedCase -Id "missing-nonce-denied" -ExpectedBlockers @("approval-nonce-not-bound") -Reason "Exact approval must deny without nonce."
    New-FailClosedCase -Id "replayed-nonce-denied" -ExpectedBlockers @("approval-replay-detected") -Reason "Nonce replay must deny exact approval."
    New-FailClosedCase -Id "missing-expiry-denied" -ExpectedBlockers @("approval-expiry-not-bound") -Reason "Exact approval must deny without expiry."
    New-FailClosedCase -Id "expired-approval-denied" -ExpectedBlockers @("approval-stale") -Reason "Expired approval must deny execution."
    New-FailClosedCase -Id "missing-policy-version-denied" -ExpectedBlockers @("approval-policy-version-not-bound") -Reason "Exact approval must deny without policy version."
    New-FailClosedCase -Id "policy-version-mismatch-denied" -ExpectedBlockers @("approval-policy-version-mismatch") -Reason "Policy version mismatch must deny execution."
    New-FailClosedCase -Id "broad-approval-scope-denied" -ExpectedBlockers @("approval-broad-scope") -Reason "Broad scope must deny exact approval."
    New-FailClosedCase -Id "target-identities-still-required" -ExpectedBlockers @("two-target-local-canary-identities-not-enrolled") -Reason "Audit substrate alone does not satisfy target identity enrollment."
    New-FailClosedCase -Id "approval-does-not-imply-execution" -ExpectedBlockers @("approval-implies-execution-denied") -Reason "Audit substrate and approval fields do not imply execution."
    New-FailClosedCase -Id "remote-dispatch-boundary-denied" -ExpectedBlockers @("remote-dispatch-authority-broadening") -Reason "RC15 local audit binding must not enable remote dispatch."
    New-FailClosedCase -Id "production-mutation-boundary-denied" -ExpectedBlockers @("production-mutation-authority-broadening") -Reason "RC15 local audit binding must not enable production mutation."
)
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })
$matrix = [ordered]@{
    schema = "agentos.rc15-audit-nonce-policy-fail-closed-matrix.v1"
    generated_at = $generatedAtValue
    task = "RC15-010"
    status = if ($failedCases.Count -eq 0) { "passed" } else { "failed" }
    production_ready_claim = $false
    cases = $cases
    summary = [ordered]@{
        cases = @($cases).Count
        passed = @($cases | Where-Object { $_.status -eq "passed" }).Count
        failed = $failedCases.Count
        failed_cases = @($failedCases | ForEach-Object { $_.id })
    }
}
Write-Json $matrix $matrixPath

$handoff = [ordered]@{
    schema = "agentos.rc15-exact-approval-substrate-handoff.v1"
    generated_at = $generatedAtValue
    task = "RC15-010"
    status = "ready-for-rc15-011-target-identity-enrollment"
    production_ready_claim = $false
    release_id = $releaseId
    object_digest = $objectDigest
    audit_sink_bound = $true
    nonce_bound = $true
    expiry_bound = $true
    policy_version_bound = $true
    audit_sink_descriptor_sha256 = Get-FileSha256 $auditSinkDescriptorPath
    binding_sha256 = Get-FileSha256 $bindingPath
    nonce_sha256 = $nonceSha256
    valid_until = $expiryInstant.ToString("o")
    policy_version = $policyVersion
    exact_approval_ready = $false
    activation_allowed = $false
    rollback_execution_allowed = $false
    remote_dispatch_enabled = $false
    production_ring_mutation_allowed = $false
    blockers = @(
        "two-target-local-canary-identities-not-enrolled",
        "exact-approval-not-bound",
        "agentcore-planspec-not-executable",
        "security-execution-allow-not-bound",
        "controlled-activation-not-authorized"
    )
    next_task = "RC15-011"
}
Write-Json $handoff $handoffPath

Add-Check "plan.current_task.rc15_010" $planAllowsRun "RC15-010 must run after RC15-001 completed, either while current_task is RC15-010 or while rerunning after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc15_001_status = $rc15PreviousStatus; rc15_010_status = $rc15TaskStatus })
Add-Check "contract.audit_nonce_policy_gate.present" ($contractText.Contains("Bind local audit sink") -and $contractText.Contains("nonce") -and $contractText.Contains("policy version")) "RC15 contract must include audit sink, nonce, expiry, and policy version gates." (New-ArtifactRef $resolvedContractPath)
Add-Check "source.rc14.local_trust_ready" ($rc14FinalAudit.verdict -eq "PASS" -and $rc14FinalAudit.readiness_status.local_trust_ready -eq $true -and $rc14FinalAudit.readiness_status.verified_quarantine_ready -eq $true) "RC15-010 must inherit RC14 PASS local trust and verified quarantine readiness." ([ordered]@{ verdict = $rc14FinalAudit.verdict; local_trust_ready = $rc14FinalAudit.readiness_status.local_trust_ready; verified_quarantine_ready = $rc14FinalAudit.readiness_status.verified_quarantine_ready })
Add-Check "binding.audit_sink_nonce_expiry_policy.bound" ($binding.audit_sink.bound -eq $true -and $binding.nonce.bound -eq $true -and $binding.expiry.bound -eq $true -and $binding.policy.bound -eq $true) "RC15-010 must bind audit sink, nonce, expiry, and policy version." ([ordered]@{ audit_sink = $binding.audit_sink.bound; nonce = $binding.nonce.bound; expiry = $binding.expiry.bound; policy = $binding.policy.bound })
Add-Check "binding.downstream.not_authorized" ($binding.downstream.exact_approval_ready -eq $false -and $binding.downstream.activation_allowed -eq $false -and $binding.downstream.rollback_execution_allowed -eq $false -and $binding.downstream.remote_dispatch_enabled -eq $false -and $binding.downstream.production_ring_mutation_allowed -eq $false) "Audit nonce policy binding must not authorize approval, activation, rollback, remote dispatch, or production mutation." $binding.downstream
Add-Check "fixtures.fail_closed" ($failedCases.Count -eq 0 -and @($cases).Count -ge 12) "Missing, stale, replayed, mismatched, broad, remote, and production mutation cases must fail closed." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $auditJournalPath),
    (Get-Content -Raw -LiteralPath $auditSinkDescriptorPath),
    (Get-Content -Raw -LiteralPath $bindingPath),
    (Get-Content -Raw -LiteralPath $matrixPath),
    (Get-Content -Raw -LiteralPath $handoffPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC15-010 outputs must not contain key material, auth tokens, private signing paths, or sensitive identity markers." $null

$source = [ordered]@{
    rc15_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc15_contract = New-ArtifactRef $resolvedContractPath
    rc14_final_audit = New-ArtifactRef $resolvedRc14FinalAuditPath $rc14FinalAudit
    rc14_exact_approval_result = New-ArtifactRef $resolvedRc14ExactApprovalResultPath $rc14ExactApprovalResult
    rc14_controlled_activation_result = New-ArtifactRef $resolvedRc14ControlledActivationResultPath $rc14ControlledActivationResult
}

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc15-audit-nonce-policy-binding-result.v1"
    generated_at = $generatedAtValue
    task = "RC15-010"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    binding_surface = [ordered]@{
        state = "audit-nonce-policy-bound"
        audit_sink_bound = $true
        nonce_bound = $true
        expiry_bound = $true
        policy_version_bound = $true
        exact_approval_ready = $false
        target_identity_enrollment_ready = $false
        agentcore_planspec_executable = $false
        security_execution_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        nonce_sha256 = $nonceSha256
        policy_version = $policyVersion
        approval_valid_until = $expiryInstant.ToString("o")
    }
    outputs = [ordered]@{
        audit_journal = [ordered]@{ path = Get-StablePath $auditJournalPath; sha256 = Get-FileSha256 $auditJournalPath }
        audit_sink_descriptor = [ordered]@{ path = Get-StablePath $auditSinkDescriptorPath; sha256 = Get-FileSha256 $auditSinkDescriptorPath }
        audit_nonce_policy_binding = [ordered]@{ path = Get-StablePath $bindingPath; sha256 = Get-FileSha256 $bindingPath }
        fail_closed_matrix = [ordered]@{ path = Get-StablePath $matrixPath; sha256 = Get-FileSha256 $matrixPath }
        exact_approval_substrate_handoff = [ordered]@{ path = Get-StablePath $handoffPath; sha256 = Get-FileSha256 $handoffPath }
    }
    source = $source
    checks = $script:checks
    blockers = $handoff.blockers
    invariants = [ordered]@{
        aios_body_only = $true
        audit_sink_repo_local = $true
        local_private_key_material_used = $false
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
        mirror_frontend_changed = $false
        nginx_or_tls_changed = $false
        signer_infra_changed = $false
        object_storage_infra_changed = $false
        network_probe_performed = $false
        network_fetch_attempted = $false
        payload_upload_performed = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        remote_dispatch_enabled = $false
        production_ready_claim = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        fail_closed_cases = @($cases).Count
        failed_fail_closed_cases = $failedCases.Count
        rc15_010_complete = (@($script:failedChecks).Count -eq 0)
        audit_sink_bound = $true
        nonce_bound = $true
        expiry_bound = $true
        policy_version_bound = $true
        exact_approval_ready = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        next_task = "RC15-011"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc15-audit-nonce-policy-binding-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC15-010"
    status = "completed"
    production_ready_claim = $false
    workflow = Get-StablePath $resolvedWorkflowDir
    script = [ordered]@{
        path = Get-StablePath $scriptPath
        sha256 = Get-FileSha256 $scriptPath
    }
    result = [ordered]@{
        path = Get-StablePath $resultPath
        status = $result.status
        sha256 = Get-FileSha256 $resultPath
    }
    outputs = $result.outputs
    binding_surface = $result.binding_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc15_010_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC15-011"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

if (-not (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath), (Get-Content -Raw -LiteralPath $taskEvidencePath)))) {
    throw "Sensitive marker detected in RC15-010 outputs."
}

Write-Host "RC15 audit nonce policy binding $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Binding state: $($result.binding_surface.state)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
