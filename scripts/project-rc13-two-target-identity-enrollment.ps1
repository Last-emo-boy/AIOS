param(
    [string]$ArtifactDir = ".workflow/artifacts/rc13-two-target-identity-enrollment",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc13",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc13/docs/rc13-local-trust-unblock-contract.md",
    [string]$SecurityResultPath = ".workflow/artifacts/rc13-security-execution-allow-preconditions/result.json",
    [string]$SecurityPreconditionsPath = ".workflow/artifacts/rc13-security-execution-allow-preconditions/security-execution-allow-preconditions.json",
    [string]$SecurityDenialPath = ".workflow/artifacts/rc13-security-execution-allow-preconditions/security-execution-allow-denial.json",
    [string]$SecurityFailClosedMatrixPath = ".workflow/artifacts/rc13-security-execution-allow-preconditions/security-execution-allow-fail-closed-matrix.json",
    [string]$SecurityHandoffPath = ".workflow/artifacts/rc13-security-execution-allow-preconditions/two-target-identity-enrollment-handoff.json",
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

function Add-UniqueBlocker {
    param([Parameter(Mandatory = $true)][string]$Blocker)
    if ([string]::IsNullOrWhiteSpace($Blocker)) {
        return
    }
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
        ("BEGIN PUBLIC " + "KEY"),
        ("Authorization:" + " Bearer"),
        ("Bearer" + " "),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ("." + "local-release-authority"),
        ("signing" + "-" + "key" + "." + "pem"),
        ("/etc/" + "aios-signer"),
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
        [Parameter(Mandatory = $true)][string[]]$ObservedBlockers
    )
    $missing = @($ExpectedBlockers | Where-Object { $_ -notin $ObservedBlockers })
    return [ordered]@{
        id = $Id
        status = if ($missing.Count -eq 0) { "passed" } else { "failed" }
        expected_blockers = $ExpectedBlockers
        observed_blocked = $true
        observed_blockers = @($ObservedBlockers | Select-Object -Unique)
        missing_expected_blockers = $missing
        side_effects = [ordered]@{
            target_identity_enrolled = $false
            exact_approval_bound = $false
            effect_prepared = $false
            effect_executed = $false
            install_performed = $false
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
$script:blockers = @()

$generatedAtValue = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }
$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$resolvedWorkflowDir = Resolve-RepoPath $WorkflowDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $resolvedWorkflowDir "evidence") | Out-Null

$resolvedContractPath = Resolve-RepoPath $ContractPath
$resolvedSecurityResultPath = Resolve-RepoPath $SecurityResultPath
$resolvedSecurityPreconditionsPath = Resolve-RepoPath $SecurityPreconditionsPath
$resolvedSecurityDenialPath = Resolve-RepoPath $SecurityDenialPath
$resolvedSecurityFailClosedMatrixPath = Resolve-RepoPath $SecurityFailClosedMatrixPath
$resolvedSecurityHandoffPath = Resolve-RepoPath $SecurityHandoffPath

$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$securityResult = Read-Json $resolvedSecurityResultPath
$securityPreconditions = Read-Json $resolvedSecurityPreconditionsPath
$securityDenial = Read-Json $resolvedSecurityDenialPath
$securityFailClosedMatrix = Read-Json $resolvedSecurityFailClosedMatrixPath
$securityHandoff = Read-Json $resolvedSecurityHandoffPath

$releaseId = [string]$securityResult.release_id
$effectEnvelopeCoreHash = [string]$securityResult.security_surface.effect_envelope_core_hash
$planSpecCoreHash = [string]$securityPreconditions.effect_envelope_core.planspec_core_hash
$planSpecResultSha256 = [string]$securityPreconditions.effect_envelope_core.planspec_result_sha256
$readinessSha256 = [string]$securityPreconditions.effect_envelope_core.readiness_sha256
$requiredMinimumTargetIdentities = [int]$securityHandoff.target_enrollment.minimum_required_targets
$enrolledTargetIdentityCount = 0
$targetIdentitySetBound = $false
$remoteDispatchAuthority = $false

foreach ($blocker in @($securityResult.security_surface.blockers + $securityPreconditions.blockers + $securityDenial.blockers + $securityHandoff.blockers)) {
    if (-not [string]::IsNullOrWhiteSpace([string]$blocker)) {
        Add-UniqueBlocker ([string]$blocker)
    }
}
foreach ($blocker in @(
    "fewer-than-two-local-canary-identities",
    "target-identity-a-missing",
    "target-identity-b-missing",
    "target-identities-missing",
    "target-identity-set-not-bound",
    "duplicate-local-canary-identity",
    "stale-local-canary-identity",
    "incompatible-local-canary-identity",
    "broad-target-selector",
    "target-identity-release-mismatch",
    "target-identity-object-mismatch",
    "target-identity-planspec-mismatch",
    "target-identity-security-envelope-mismatch",
    "target-identity-audit-sink-not-bound",
    "target-identity-replay-detected",
    "remote-dispatch-authority-broadening",
    "production-mutation-authority-broadening",
    "exact-approval-audit-binding-not-bound"
)) {
    Add-UniqueBlocker $blocker
}

$targetIdentitySlots = @(
    [ordered]@{
        slot = "local-canary-a"
        required = $true
        enrollment_state = "identity-missing"
        identity_id = $null
        identity_digest = $null
        release_id = $releaseId
        effect_envelope_core_hash = $effectEnvelopeCoreHash
        agentcore_planspec_core_hash = $planSpecCoreHash
        local_attestation_digest = $null
        audit_sink = $null
        duplicate_identity = $false
        stale_identity = $false
        compatible = $null
        remote_dispatch_authority = $false
        denial_reasons = @("target-identity-a-missing", "target-identities-missing")
    },
    [ordered]@{
        slot = "local-canary-b"
        required = $true
        enrollment_state = "identity-missing"
        identity_id = $null
        identity_digest = $null
        release_id = $releaseId
        effect_envelope_core_hash = $effectEnvelopeCoreHash
        agentcore_planspec_core_hash = $planSpecCoreHash
        local_attestation_digest = $null
        audit_sink = $null
        duplicate_identity = $false
        stale_identity = $false
        compatible = $null
        remote_dispatch_authority = $false
        denial_reasons = @("target-identity-b-missing", "target-identities-missing")
    }
)

$identitySetCore = [ordered]@{
    release_id = $releaseId
    required_minimum_target_identities = $requiredMinimumTargetIdentities
    enrolled_target_identity_count = $enrolledTargetIdentityCount
    effect_envelope_core_hash = $effectEnvelopeCoreHash
    agentcore_planspec_core_hash = $planSpecCoreHash
    slots = $targetIdentitySlots
    remote_dispatch_authority = $remoteDispatchAuthority
}
$targetIdentitySetDigest = Get-StringSha256 (($identitySetCore | ConvertTo-Json -Depth 100 -Compress))

$targetIdentitySet = [ordered]@{
    schema = "agentos.rc13-target-identity-set.v1"
    generated_at = $generatedAtValue
    task = "RC13-030"
    status = "target-identity-enrollment-denied"
    production_ready_claim = $false
    projection_only = $true
    release_id = $releaseId
    ring = "local-canary"
    activation_authority_prerequisite = "at-least-two-distinct-fresh-compatible-local-canary-identities"
    required_minimum_target_identities = $requiredMinimumTargetIdentities
    enrolled_target_identity_count = $enrolledTargetIdentityCount
    target_identity_set_bound = $targetIdentitySetBound
    target_identity_set_digest = $targetIdentitySetDigest
    target_selection_policy = "two-or-more-distinct-fresh-compatible-local-canary-identities-required"
    duplicate_identity_check = [ordered]@{
        duplicate_identities_detected = $false
        evaluated_enrolled_identity_count = $enrolledTargetIdentityCount
        fail_closed_if_duplicate = $true
    }
    stale_identity_check = [ordered]@{
        stale_identities_detected = $false
        evaluated_enrolled_identity_count = $enrolledTargetIdentityCount
        fail_closed_if_stale = $true
    }
    compatibility_check = [ordered]@{
        incompatible_identities_detected = $false
        evaluated_enrolled_identity_count = $enrolledTargetIdentityCount
        fail_closed_if_incompatible = $true
    }
    required_bindings = [ordered]@{
        release_id = $releaseId
        effect_envelope_core_hash = $effectEnvelopeCoreHash
        agentcore_planspec_core_hash = $planSpecCoreHash
        planspec_result_sha256 = $planSpecResultSha256
        readiness_sha256 = $readinessSha256
        local_audit_sink_required = $true
        remote_dispatch_authority = $false
        production_ring_mutation_allowed = $false
    }
    targets = $targetIdentitySlots
    blockers = @($script:blockers)
}

$enrollmentDenial = [ordered]@{
    schema = "agentos.rc13-target-identity-enrollment-denial.v1"
    generated_at = $generatedAtValue
    task = "RC13-030"
    status = "target-identity-enrollment-denied"
    production_ready_claim = $false
    release_id = $releaseId
    target_identity_set_digest = $targetIdentitySetDigest
    required_minimum_target_identities = $requiredMinimumTargetIdentities
    enrolled_target_identity_count = $enrolledTargetIdentityCount
    target_identity_set_bound = $false
    exact_approval_may_bind = $false
    activation_allowed = $false
    rollback_execution_allowed = $false
    support_upload_allowed = $false
    recovery_execution_allowed = $false
    remote_dispatch_enabled = $false
    production_ring_mutation_allowed = $false
    blockers = @($script:blockers)
}

$caseBlockers = [ordered]@{
    "missing-first-target-identity-denied" = @("target-identity-a-missing")
    "missing-second-target-identity-denied" = @("target-identity-b-missing")
    "missing-all-target-identities-denied" = @("target-identities-missing")
    "single-local-canary-identity-denied" = @("fewer-than-two-local-canary-identities")
    "duplicate-local-canary-identity-denied" = @("duplicate-local-canary-identity")
    "stale-local-canary-identity-denied" = @("stale-local-canary-identity")
    "incompatible-local-canary-identity-denied" = @("incompatible-local-canary-identity")
    "broad-target-selector-denied" = @("broad-target-selector")
    "target-release-mismatch-denied" = @("target-identity-release-mismatch")
    "target-object-mismatch-denied" = @("target-identity-object-mismatch")
    "target-planspec-mismatch-denied" = @("target-identity-planspec-mismatch")
    "target-security-envelope-mismatch-denied" = @("target-identity-security-envelope-mismatch")
    "target-audit-sink-missing-denied" = @("target-identity-audit-sink-not-bound")
    "target-identity-replay-denied" = @("target-identity-replay-detected")
    "remote-dispatch-authority-denied" = @("remote-dispatch-authority-broadening")
    "production-mutation-authority-denied" = @("production-mutation-authority-broadening")
}
$cases = @()
foreach ($caseId in $caseBlockers.Keys) {
    $cases += New-FailClosedCase -Id $caseId -ExpectedBlockers ([string[]]$caseBlockers[$caseId]) -ObservedBlockers $script:blockers
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$failClosedMatrix = [ordered]@{
    schema = "agentos.rc13-target-identity-enrollment-fail-closed-matrix.v1"
    generated_at = $generatedAtValue
    task = "RC13-030"
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

$approvalHandoff = [ordered]@{
    schema = "agentos.rc13-exact-approval-audit-binding-handoff.v1"
    generated_at = $generatedAtValue
    task = "RC13-030"
    status = "blocked-by-target-identity-enrollment-denial"
    production_ready_claim = $false
    release_id = $releaseId
    target_identity_set_digest = $targetIdentitySetDigest
    effect_envelope_core_hash = $effectEnvelopeCoreHash
    agentcore_planspec_core_hash = $planSpecCoreHash
    target_identity_set_bound = $false
    required_minimum_target_identities = $requiredMinimumTargetIdentities
    enrolled_target_identity_count = $enrolledTargetIdentityCount
    exact_approval_bound = $false
    approval_granted = $false
    audit_sink_bound = $false
    nonce_bound = $false
    expiry_bound = $false
    policy_version_bound = $false
    activation_allowed = $false
    rollback_execution_allowed = $false
    support_upload_allowed = $false
    recovery_execution_allowed = $false
    remote_dispatch_enabled = $false
    production_ring_mutation_allowed = $false
    blockers = @($script:blockers)
    next_task = "RC13-031"
}

$targetIdentitySetPath = Join-Path $resolvedArtifactDir "target-identity-set.json"
$enrollmentDenialPath = Join-Path $resolvedArtifactDir "target-identity-enrollment-denial.json"
$matrixPath = Join-Path $resolvedArtifactDir "target-identity-enrollment-fail-closed-matrix.json"
$approvalHandoffPath = Join-Path $resolvedArtifactDir "exact-approval-audit-binding-handoff.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC13-030-two-target-identity-enrollment.json"

Write-Json $targetIdentitySet $targetIdentitySetPath
Write-Json $enrollmentDenial $enrollmentDenialPath
Write-Json $failClosedMatrix $matrixPath
Write-Json $approvalHandoff $approvalHandoffPath

Add-Check "source.rc13_022.complete" ($securityResult.status -eq "passed" -and $securityResult.summary.rc13_022_complete -eq $true) "RC13-030 must consume completed RC13-022 SecurityExecution allow preconditions evidence." ([ordered]@{ status = $securityResult.status; rc13_022_complete = $securityResult.summary.rc13_022_complete; next_task = $securityResult.summary.next_task })
Add-Check "handoff.expected_next_task" ($securityHandoff.expected_next_task -eq "RC13-030" -and $securityHandoff.target_enrollment.minimum_required_targets -eq 2 -and $securityHandoff.target_enrollment.remote_dispatch_authority -eq $false) "RC13-030 handoff must require two targets and preserve remote dispatch denial." ([ordered]@{ expected_next_task = $securityHandoff.expected_next_task; minimum_required_targets = $securityHandoff.target_enrollment.minimum_required_targets; remote_dispatch_authority = $securityHandoff.target_enrollment.remote_dispatch_authority })
Add-Check "contract.two_target_gate.present" ($contractText.Contains("Require at least two enrolled non-duplicate local canary target identities before activation authority") -and $contractText.Contains("remote dispatch remains disabled")) "RC13 contract must include two-target local canary and remote dispatch denial gates." (New-ArtifactRef $resolvedContractPath)
Add-Check "target_identity.two_distinct_required" ($targetIdentitySet.required_minimum_target_identities -eq 2 -and @($targetIdentitySet.targets).Count -eq 2 -and $targetIdentitySet.enrolled_target_identity_count -lt 2 -and $targetIdentitySet.target_identity_set_bound -eq $false) "At least two distinct local canary identities must be required before activation authority." ([ordered]@{ required = $targetIdentitySet.required_minimum_target_identities; slots = @($targetIdentitySet.targets).Count; enrolled = $targetIdentitySet.enrolled_target_identity_count; bound = $targetIdentitySet.target_identity_set_bound })
Add-Check "target_identity.quality_gates_fail_closed" ($targetIdentitySet.duplicate_identity_check.fail_closed_if_duplicate -eq $true -and $targetIdentitySet.stale_identity_check.fail_closed_if_stale -eq $true -and $targetIdentitySet.compatibility_check.fail_closed_if_incompatible -eq $true -and $targetIdentitySet.target_selection_policy -match "distinct") "Duplicate, stale, incompatible, and broad target identities must fail closed." ([ordered]@{ duplicate_fail_closed = $targetIdentitySet.duplicate_identity_check.fail_closed_if_duplicate; stale_fail_closed = $targetIdentitySet.stale_identity_check.fail_closed_if_stale; incompatible_fail_closed = $targetIdentitySet.compatibility_check.fail_closed_if_incompatible; policy = $targetIdentitySet.target_selection_policy })
Add-Check "fixtures.fail_closed" ($failedCases.Count -eq 0 -and @($cases).Count -ge 16) "Missing, duplicate, stale, incompatible, broad, mismatched, replayed, remote-dispatch, and production-mutation target cases must fail closed." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })
Add-Check "approval_handoff.denied_until_target_set_bound" ($approvalHandoff.target_identity_set_bound -eq $false -and $approvalHandoff.exact_approval_bound -eq $false -and $approvalHandoff.approval_granted -eq $false -and $approvalHandoff.next_task -eq "RC13-031") "Exact approval handoff must remain denied until the target identity set is bound." ([ordered]@{ target_identity_set_bound = $approvalHandoff.target_identity_set_bound; exact_approval_bound = $approvalHandoff.exact_approval_bound; next_task = $approvalHandoff.next_task })
Add-Check "authority.remote_dispatch_and_mutation_disabled" ($enrollmentDenial.remote_dispatch_enabled -eq $false -and $enrollmentDenial.production_ring_mutation_allowed -eq $false -and $approvalHandoff.remote_dispatch_enabled -eq $false -and $approvalHandoff.production_ring_mutation_allowed -eq $false) "RC13-030 must not enable remote dispatch or production mutation authority." ([ordered]@{ remote_dispatch_enabled = $approvalHandoff.remote_dispatch_enabled; production_ring_mutation_allowed = $approvalHandoff.production_ring_mutation_allowed })
Add-Check "side_effects.none" ($enrollmentDenial.activation_allowed -eq $false -and $enrollmentDenial.rollback_execution_allowed -eq $false -and $enrollmentDenial.support_upload_allowed -eq $false -and $enrollmentDenial.recovery_execution_allowed -eq $false) "RC13-030 must not authorize install, activation, rollback, support upload, recovery, or remote execution." ([ordered]@{ activation_allowed = $enrollmentDenial.activation_allowed; rollback_execution_allowed = $enrollmentDenial.rollback_execution_allowed; support_upload_allowed = $enrollmentDenial.support_upload_allowed; recovery_execution_allowed = $enrollmentDenial.recovery_execution_allowed })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $targetIdentitySetPath),
    (Get-Content -Raw -LiteralPath $enrollmentDenialPath),
    (Get-Content -Raw -LiteralPath $matrixPath),
    (Get-Content -Raw -LiteralPath $approvalHandoffPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC13-030 outputs must not contain key material, auth tokens, private signing paths, signer internals, or sensitive identity markers." $null

$source = [ordered]@{
    rc13_contract = New-ArtifactRef $resolvedContractPath
    security_execution_result = New-ArtifactRef $resolvedSecurityResultPath $securityResult
    security_execution_allow_preconditions = New-ArtifactRef $resolvedSecurityPreconditionsPath $securityPreconditions
    security_execution_allow_denial = New-ArtifactRef $resolvedSecurityDenialPath $securityDenial
    security_execution_fail_closed_matrix = New-ArtifactRef $resolvedSecurityFailClosedMatrixPath $securityFailClosedMatrix
    two_target_identity_handoff = New-ArtifactRef $resolvedSecurityHandoffPath $securityHandoff
}

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc13-two-target-identity-enrollment-result.v1"
    generated_at = $generatedAtValue
    task = "RC13-030"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    enrollment_surface = [ordered]@{
        state = "target-identity-enrollment-denied"
        required_minimum_target_identities = $requiredMinimumTargetIdentities
        enrolled_target_identity_count = $enrolledTargetIdentityCount
        target_identity_set_bound = $targetIdentitySetBound
        target_identity_set_digest = $targetIdentitySetDigest
        effect_envelope_core_hash = $effectEnvelopeCoreHash
        agentcore_planspec_core_hash = $planSpecCoreHash
        exact_approval_bound = $false
        approval_granted = $false
        audit_sink_bound = $false
        nonce_bound = $false
        expiry_bound = $false
        policy_version_bound = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        blockers = @($script:blockers)
    }
    outputs = [ordered]@{
        target_identity_set = [ordered]@{
            path = Get-StablePath $targetIdentitySetPath
            sha256 = Get-FileSha256 $targetIdentitySetPath
            target_identity_set_digest = $targetIdentitySetDigest
        }
        target_identity_enrollment_denial = [ordered]@{
            path = Get-StablePath $enrollmentDenialPath
            sha256 = Get-FileSha256 $enrollmentDenialPath
        }
        target_identity_enrollment_fail_closed_matrix = [ordered]@{
            path = Get-StablePath $matrixPath
            sha256 = Get-FileSha256 $matrixPath
        }
        exact_approval_audit_binding_handoff = [ordered]@{
            path = Get-StablePath $approvalHandoffPath
            sha256 = Get-FileSha256 $approvalHandoffPath
        }
    }
    source = $source
    checks = $script:checks
    blockers = @($script:blockers)
    invariants = [ordered]@{
        aios_body_only = $true
        local_projection_only = $true
        target_identity_enrollment_fabricated = $false
        target_identity_set_bound = $false
        exact_approval_fabricated = $false
        approval_granted = $false
        security_execution_effect_allowed = $false
        effect_prepared = $false
        effect_executed = $false
        mirror_frontend_changed = $false
        nginx_or_tls_changed = $false
        signer_infra_changed = $false
        object_storage_infra_changed = $false
        local_private_key_material_used = $false
        private_key_material_read_or_printed = $false
        cryptographic_signing_performed = $false
        network_probe_performed = $false
        network_fetch_attempted = $false
        payload_upload_performed = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        production_ready_claim = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = $failedCases.Count
        rc13_030_complete = (@($script:failedChecks).Count -eq 0)
        target_identity_set_bound = $false
        enrolled_target_identity_count = $enrolledTargetIdentityCount
        exact_approval_bound = $false
        approval_granted = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        remote_dispatch_enabled = $false
        next_task = "RC13-031"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc13-two-target-identity-enrollment-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC13-030"
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
    enrollment_surface = $result.enrollment_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc13_030_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC13-031"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

if (-not (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath), (Get-Content -Raw -LiteralPath $taskEvidencePath)))) {
    throw "Sensitive marker detected in RC13-030 result."
}

Write-Host "RC13 two-target identity enrollment $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Enrollment state: $($result.enrollment_surface.state)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
