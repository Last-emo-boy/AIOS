param(
    [string]$ArtifactDir = ".workflow/artifacts/rc13-declared-current-drift-zero",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc13",
    [string]$PlanPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc13/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc13/docs/rc13-local-trust-unblock-contract.md",
    [string]$Rc12FinalAuditPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc12/evidence/FINAL-AUDIT-20260609-production-distro-rc12.json",
    [string]$Rc12DriftResultPath = ".workflow/artifacts/rc12-declared-current-drift-zero/result.json",
    [string]$Rc12DriftReconciliationPath = ".workflow/artifacts/rc12-declared-current-drift-zero/declared-current-drift-zero-reconciliation.json",
    [string]$Rc12DriftDenialPath = ".workflow/artifacts/rc12-declared-current-drift-zero/drift-zero-denial.json",
    [string]$Rc12DriftHandoffPath = ".workflow/artifacts/rc12-declared-current-drift-zero/object-trust-verification-handoff.json",
    [string]$Rc12TaskEvidencePath = ".workflow/active/WFS-20260609-agentos-production-distro-rc12/evidence/RC12-011-declared-current-drift-zero.json",
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

function Read-Json {
    param([Parameter(Mandatory = $true)][string]$Path)
    return Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
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
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 100) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
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

function Add-Comparison {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [AllowNull()]$Expected,
        [AllowNull()]$Actual,
        [Parameter(Mandatory = $true)][string]$ExpectedSource,
        [Parameter(Mandatory = $true)][string]$ActualSource,
        [string]$DenialReason = "declared-current-drift"
    )
    $expectedText = if ($null -eq $Expected) { $null } else { [string]$Expected }
    $actualText = if ($null -eq $Actual) { $null } else { [string]$Actual }
    $matched = ($expectedText -eq $actualText)
    $entry = [ordered]@{
        id = $Id
        status = if ($matched) { "matched" } else { "drift" }
        expected = $expectedText
        actual = $actualText
        expected_source = $ExpectedSource
        actual_source = $ActualSource
        denial_reason = if ($matched) { $null } else { $DenialReason }
    }
    $script:comparisons += $entry
    if (-not $matched) {
        $script:drifts += $entry
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
        ("signing" + "-key." + "pem"),
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
$script:failedChecks = @()
$script:comparisons = @()
$script:drifts = @()

$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$resolvedWorkflowDir = Resolve-RepoPath $WorkflowDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $resolvedWorkflowDir "evidence") | Out-Null

$resolvedPlanPath = Resolve-RepoPath $PlanPath
$resolvedContractPath = Resolve-RepoPath $ContractPath
$resolvedRc12FinalAuditPath = Resolve-RepoPath $Rc12FinalAuditPath
$resolvedRc12DriftResultPath = Resolve-RepoPath $Rc12DriftResultPath
$resolvedRc12DriftReconciliationPath = Resolve-RepoPath $Rc12DriftReconciliationPath
$resolvedRc12DriftDenialPath = Resolve-RepoPath $Rc12DriftDenialPath
$resolvedRc12DriftHandoffPath = Resolve-RepoPath $Rc12DriftHandoffPath
$resolvedRc12TaskEvidencePath = Resolve-RepoPath $Rc12TaskEvidencePath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$rc12FinalAudit = Read-Json $resolvedRc12FinalAuditPath
$rc12DriftResult = Read-Json $resolvedRc12DriftResultPath
$rc12DriftReconciliation = Read-Json $resolvedRc12DriftReconciliationPath
$rc12DriftDenial = Read-Json $resolvedRc12DriftDenialPath
$rc12DriftHandoff = Read-Json $resolvedRc12DriftHandoffPath
$rc12TaskEvidence = Read-Json $resolvedRc12TaskEvidencePath

$generatedAtValue = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }
$releaseId = [string]$rc12DriftResult.release_id
$sourceArtifactPath = Resolve-RepoPath ([string]$rc12DriftReconciliation.source.current_payload_bytes.path)
$sourceArtifactSha256 = Get-FileSha256 $sourceArtifactPath
$sourceArtifactSize = if (Test-Path -LiteralPath $sourceArtifactPath -PathType Leaf) { (Get-Item -LiteralPath $sourceArtifactPath).Length } else { $null }

$rc12ReconciliationSha256 = Get-FileSha256 $resolvedRc12DriftReconciliationPath
$rc12DenialSha256 = Get-FileSha256 $resolvedRc12DriftDenialPath
$rc12HandoffSha256 = Get-FileSha256 $resolvedRc12DriftHandoffPath
$rc12ResultSha256 = Get-FileSha256 $resolvedRc12DriftResultPath
$rc12TaskEvidenceSha256 = Get-FileSha256 $resolvedRc12TaskEvidencePath
$rc12FinalAuditSha256 = Get-FileSha256 $resolvedRc12FinalAuditPath

$source = [ordered]@{
    rc13_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc13_contract = New-ArtifactRef $resolvedContractPath
    rc12_final_audit = New-ArtifactRef $resolvedRc12FinalAuditPath $rc12FinalAudit
    rc12_drift_result = New-ArtifactRef $resolvedRc12DriftResultPath $rc12DriftResult
    rc12_drift_reconciliation = New-ArtifactRef $resolvedRc12DriftReconciliationPath $rc12DriftReconciliation
    rc12_drift_denial = New-ArtifactRef $resolvedRc12DriftDenialPath $rc12DriftDenial
    rc12_object_trust_handoff = New-ArtifactRef $resolvedRc12DriftHandoffPath $rc12DriftHandoff
    rc12_task_evidence = New-ArtifactRef $resolvedRc12TaskEvidencePath $rc12TaskEvidence
    current_payload_bytes = New-ArtifactRef $sourceArtifactPath
}

$rc13TaskStatus = ($plan.waves.tasks | Where-Object id -eq "RC13-010").status
$planAllowsRun = ($plan.status -eq "active" -and ($plan.current_task -eq "RC13-010" -or ($plan.current_task -eq "RC13-011" -and $rc13TaskStatus -eq "completed")))
Add-Check "plan.current_task.rc13_010" $planAllowsRun "RC13-010 must run while the RC13 plan points at RC13-010, or while rerunning after RC13-010 completed and the pointer advanced to RC13-011." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc13_010_status = $rc13TaskStatus })
Add-Check "contract.drift_zero_gate.present" ($contractText.Contains("declared/current drift-zero") -and $contractText.Contains("object trust and downstream execution remain denied")) "RC13-010 must consume the RC13 local trust unblock contract." $source.rc13_contract
Add-Check "source.rc12_final_audit.pass" ($rc12FinalAudit.verdict -eq "PASS" -and $rc12FinalAudit.production_ready_claim -eq $false -and $rc12FinalAudit.controlled_unblock_status.moved_beyond_fail_closed -eq $false) "RC13-010 must inherit a PASS, non-GA, fail-closed RC12 final audit." ([ordered]@{ verdict = $rc12FinalAudit.verdict; production_ready_claim = $rc12FinalAudit.production_ready_claim; moved_beyond_fail_closed = $rc12FinalAudit.controlled_unblock_status.moved_beyond_fail_closed })
Add-Check "source.rc12_drift_result.passed" ($rc12DriftResult.status -eq "passed" -and [int]$rc12DriftResult.reconciliation_surface.comparisons -gt 0) "RC13-010 must bind RC12 declared/current reconciliation evidence." ([ordered]@{ status = $rc12DriftResult.status; drift_count = $rc12DriftResult.reconciliation_surface.drift_count; comparisons = $rc12DriftResult.reconciliation_surface.comparisons })

Add-Comparison "rc13.current_payload.sha256.rc12_source_vs_current" $rc12DriftReconciliation.source.current_payload_bytes.sha256 $sourceArtifactSha256 "RC12 reconciliation source current_payload_bytes.sha256" "current payload file sha256" "rc13-current-payload-digest-drift"
Add-Comparison "rc13.current_payload.size.rc12_source_vs_current" $rc12DriftReconciliation.source.current_payload_bytes.size_bytes $sourceArtifactSize "RC12 reconciliation source current_payload_bytes.size_bytes" "current payload file size_bytes" "rc13-current-payload-size-drift"
Add-Comparison "rc13.rc12_result.sha256.evidence_vs_file" $rc12TaskEvidence.result.sha256 $rc12ResultSha256 "RC12 task evidence result sha256" "current RC12 drift result file sha256" "rc12-result-file-drift"
Add-Comparison "rc13.rc12_reconciliation.sha256.result_vs_file" $rc12DriftResult.outputs.reconciliation.sha256 $rc12ReconciliationSha256 "RC12 result reconciliation sha256" "current RC12 reconciliation file sha256" "rc12-reconciliation-file-drift"
Add-Comparison "rc13.rc12_denial.sha256.result_vs_file" $rc12DriftResult.outputs.denial.sha256 $rc12DenialSha256 "RC12 result denial sha256" "current RC12 denial file sha256" "rc12-denial-file-drift"
Add-Comparison "rc13.rc12_handoff.sha256.result_vs_file" $rc12DriftResult.outputs.object_trust_verification_handoff.sha256 $rc12HandoffSha256 "RC12 result handoff sha256" "current RC12 handoff file sha256" "rc12-handoff-file-drift"
Add-Comparison "rc13.rc12_final_audit.verdict.required" "PASS" $rc12FinalAudit.verdict "required RC12 final audit verdict" "RC12 final audit verdict" "rc12-final-audit-not-pass"
Add-Comparison "rc13.rc12_final_audit.production_ready_claim.required" "False" $rc12FinalAudit.production_ready_claim "required RC12 production_ready_claim" "RC12 final audit production_ready_claim" "rc12-ga-claim-drift"
Add-Comparison "rc13.rc12_final_audit.moved_beyond_fail_closed.required" "False" $rc12FinalAudit.controlled_unblock_status.moved_beyond_fail_closed "required RC12 moved_beyond_fail_closed" "RC12 final audit moved_beyond_fail_closed" "rc12-fail-closed-boundary-drift"
Add-Comparison "rc13.rc12_drift_zero.required" "True" $rc12DriftResult.reconciliation_surface.drift_zero "required RC12 drift_zero for RC13 object trust" "RC12 drift result drift_zero" "rc12-drift-zero-not-proved"
Add-Comparison "rc13.rc12_object_trust.required" "True" $rc12DriftResult.reconciliation_surface.object_trust_allowed "required RC12 object trust for RC13 downstream trust" "RC12 drift result object_trust_allowed" "rc12-object-trust-not-allowed"

foreach ($comparison in $rc12DriftReconciliation.comparisons) {
    $prefixed = [ordered]@{
        id = "rc12.carry_forward.$($comparison.id)"
        status = [string]$comparison.status
        expected = if ($null -eq $comparison.expected) { $null } else { [string]$comparison.expected }
        actual = if ($null -eq $comparison.actual) { $null } else { [string]$comparison.actual }
        expected_source = [string]$comparison.expected_source
        actual_source = [string]$comparison.actual_source
        denial_reason = $comparison.denial_reason
        source_task = "RC12-011"
    }
    $script:comparisons += $prefixed
    if ($comparison.status -ne "matched") {
        $script:drifts += $prefixed
    }
}

$comparisonCount = @($script:comparisons).Count
$driftCount = @($script:drifts).Count
$matchedCount = $comparisonCount - $driftCount
$rc13SelfDriftCount = @($script:drifts | Where-Object { $_.id -like "rc13.*" }).Count
$carriedForwardDriftCount = @($script:drifts | Where-Object { $_.id -like "rc12.carry_forward.*" }).Count
$driftZero = ($driftCount -eq 0 -and $rc12DriftResult.reconciliation_surface.drift_zero -eq $true -and $rc12DriftResult.reconciliation_surface.object_trust_allowed -eq $true)
$reconciliationState = if ($driftZero) { "declared-current-drift-zero" } else { "declared-current-drift-denied" }

Add-Check "comparisons.explicit_hash_bound" ($comparisonCount -ge 70 -and $rc12ResultSha256 -and $rc12ReconciliationSha256 -and $rc12FinalAuditSha256) "RC13-010 comparisons must be explicit and hash-bound to RC12 final audit, RC12 drift evidence, and current payload bytes." ([ordered]@{ comparisons = $comparisonCount; rc13_self_drifts = $rc13SelfDriftCount; carried_forward_drifts = $carriedForwardDriftCount })
Add-Check "current_payload.identity_bound" ($sourceArtifactSha256 -eq $rc12DriftReconciliation.source.current_payload_bytes.sha256 -and $sourceArtifactSize -eq $rc12DriftReconciliation.source.current_payload_bytes.size_bytes) "RC13-010 must confirm the current payload still matches the RC12 recorded payload identity before carrying forward drift." ([ordered]@{ current_sha256 = $sourceArtifactSha256; rc12_sha256 = $rc12DriftReconciliation.source.current_payload_bytes.sha256; current_size_bytes = $sourceArtifactSize; rc12_size_bytes = $rc12DriftReconciliation.source.current_payload_bytes.size_bytes })
Add-Check "reconciliation.zero_required" (($driftCount -eq 0 -and $driftZero) -or ($driftCount -gt 0 -and -not $driftZero)) "Any carried-forward drift or missing RC12 trust gate must deny object trust and downstream authority." ([ordered]@{ drift_count = $driftCount; drift_zero = $driftZero; rc12_drift_zero = $rc12DriftResult.reconciliation_surface.drift_zero; rc12_object_trust_allowed = $rc12DriftResult.reconciliation_surface.object_trust_allowed })

$repairBlockers = @()
if ($driftCount -gt 0) { $repairBlockers += "nonzero-declared-current-drift-count" }
if ($rc13SelfDriftCount -gt 0) { $repairBlockers += "rc13-local-trust-gate-drift" }
if ($carriedForwardDriftCount -gt 0) { $repairBlockers += "rc12-declared-current-drift-carried-forward" }
foreach ($blocker in @($rc12DriftResult.reconciliation_surface.repair_blockers)) {
    if ($repairBlockers -notcontains $blocker) { $repairBlockers += $blocker }
}
if ($rc12DriftResult.reconciliation_surface.drift_zero -ne $true) { $repairBlockers += "rc12-drift-zero-not-proved" }
if ($rc12DriftResult.reconciliation_surface.object_trust_allowed -ne $true) { $repairBlockers += "rc12-object-trust-not-allowed" }
if ($rc12FinalAudit.controlled_unblock_status.moved_beyond_fail_closed -ne $true) { $repairBlockers += "rc12-controlled-unblock-not-achieved" }

$downstreamBlockers = @(
    "object-manifest-descriptor-binding-not-allowed",
    "freshness-revocation-authority-not-bound",
    "quarantine-preflight-not-run",
    "agentcore-planspec-not-executable",
    "security-execution-allow-not-bound",
    "two-target-canary-not-enrolled",
    "exact-approval-not-bound",
    "controlled-activation-not-authorized",
    "controlled-rollback-not-authorized"
)
$allBlockers = @($repairBlockers + $downstreamBlockers | Select-Object -Unique)

$reconciliation = [ordered]@{
    schema = "agentos.rc13-declared-current-drift-zero-reconciliation.v1"
    generated_at = $generatedAtValue
    task = "RC13-010"
    release_id = $releaseId
    status = $reconciliationState
    production_ready_claim = $false
    source = $source
    binding = [ordered]@{
        rc12_final_audit_sha256 = $rc12FinalAuditSha256
        rc12_drift_result_sha256 = $rc12ResultSha256
        rc12_drift_reconciliation_sha256 = $rc12ReconciliationSha256
        rc12_drift_denial_sha256 = $rc12DenialSha256
        rc12_object_trust_handoff_sha256 = $rc12HandoffSha256
        rc12_task_evidence_sha256 = $rc12TaskEvidenceSha256
        current_payload_sha256 = $sourceArtifactSha256
        current_payload_size_bytes = $sourceArtifactSize
    }
    comparison_summary = [ordered]@{
        comparisons = $comparisonCount
        matched = $matchedCount
        drift = $driftCount
        rc13_self_drift = $rc13SelfDriftCount
        carried_forward_drift = $carriedForwardDriftCount
        drift_zero = $driftZero
        rc12_drift_zero = [bool]$rc12DriftResult.reconciliation_surface.drift_zero
        rc12_object_trust_allowed = [bool]$rc12DriftResult.reconciliation_surface.object_trust_allowed
        current_payload_matches_rc12 = ($sourceArtifactSha256 -eq $rc12DriftReconciliation.source.current_payload_bytes.sha256 -and $sourceArtifactSize -eq $rc12DriftReconciliation.source.current_payload_bytes.size_bytes)
    }
    comparisons = $script:comparisons
    drifts = $script:drifts
    repair_blockers = $repairBlockers
    blockers = $allBlockers
    trust_decision = [ordered]@{
        declared_current_drift_zero = $driftZero
        object_manifest_descriptor_binding_allowed = $driftZero
        freshness_revocation_authority_allowed = $driftZero
        object_trust_allowed = $driftZero
        quarantine_preflight_allowed = $driftZero
        agentcore_planspec_executable = $false
        security_execution_allowed = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        drift_repair_performed = $false
        declared_metadata_rewritten = $false
    }
}

$denial = [ordered]@{
    schema = "agentos.rc13-drift-zero-denial.v1"
    generated_at = $generatedAtValue
    task = "RC13-010"
    release_id = $releaseId
    status = if ($driftZero) { "not-denied" } else { "declared-current-drift-denied" }
    production_ready_claim = $false
    denied = (-not $driftZero)
    denial_reasons = $repairBlockers
    drift_count = $driftCount
    drift_ids = @($script:drifts | ForEach-Object { $_.id })
    downstream_gates_blocked = $downstreamBlockers
    side_effects = [ordered]@{
        drift_repair_performed = $false
        declared_metadata_rewritten = $false
        object_manifest_written_as_authority = $false
        object_trust_allowed = $false
        quarantine_payload_written = $false
        payload_bytes_uploaded = $false
        remote_payload_bytes_downloaded = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        production_ring_mutated = $false
    }
}

$handoff = [ordered]@{
    schema = "agentos.rc13-object-manifest-descriptor-binding-handoff.v1"
    generated_at = $generatedAtValue
    task = "RC13-010"
    release_id = $releaseId
    status = if ($driftZero) { "ready-for-rc13-011-object-manifest-descriptor-binding" } else { "blocked-by-declared-current-drift" }
    production_ready_claim = $false
    reconciliation = [ordered]@{
        path = $null
        sha256 = $null
        drift_zero = $driftZero
        drift_count = $driftCount
        expected_next_task = "RC13-011"
    }
    current_payload = [ordered]@{
        path = Get-StablePath $sourceArtifactPath
        sha256 = $sourceArtifactSha256
        size_bytes = $sourceArtifactSize
        matches_rc12_identity = ($sourceArtifactSha256 -eq $rc12DriftReconciliation.source.current_payload_bytes.sha256 -and $sourceArtifactSize -eq $rc12DriftReconciliation.source.current_payload_bytes.size_bytes)
    }
    blocked_authority = [ordered]@{
        object_manifest_descriptor_binding_allowed = $driftZero
        freshness_revocation_authority_allowed = $driftZero
        object_trust_allowed = $driftZero
        quarantine_preflight_allowed = $driftZero
        agentcore_planspec_executable = $false
        security_execution_allowed = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
    }
    blockers = $allBlockers
}

$reconciliationPath = Join-Path $resolvedArtifactDir "declared-current-drift-zero-reconciliation.json"
$denialPath = Join-Path $resolvedArtifactDir "drift-zero-denial.json"
$handoffPath = Join-Path $resolvedArtifactDir "object-manifest-descriptor-binding-handoff.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC13-010-declared-current-drift-zero.json"

Write-Json $reconciliation $reconciliationPath
$handoff.reconciliation.path = Get-StablePath $reconciliationPath
$handoff.reconciliation.sha256 = Get-FileSha256 $reconciliationPath
Write-Json $denial $denialPath
Write-Json $handoff $handoffPath

Add-Check "outputs.secret_safe" (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $reconciliationPath), (Get-Content -Raw -LiteralPath $denialPath), (Get-Content -Raw -LiteralPath $handoffPath))) "RC13-010 outputs must not contain PEM blocks, auth tokens, or signer internals." $null
Add-Check "outputs.side_effects_blocked" ($denial.side_effects.drift_repair_performed -eq $false -and $denial.side_effects.declared_metadata_rewritten -eq $false -and $denial.side_effects.object_manifest_written_as_authority -eq $false -and $denial.side_effects.quarantine_payload_written -eq $false -and $denial.side_effects.payload_bytes_uploaded -eq $false -and $denial.side_effects.remote_payload_bytes_downloaded -eq $false -and $denial.side_effects.install_performed -eq $false -and $denial.side_effects.activation_performed -eq $false -and $denial.side_effects.rollback_execution_performed -eq $false -and $denial.side_effects.support_upload_performed -eq $false -and $denial.side_effects.recovery_execution_performed -eq $false -and $denial.side_effects.remote_dispatch_enabled -eq $false -and $denial.side_effects.production_ring_mutated -eq $false) "RC13-010 must not repair drift, rewrite metadata, fetch payloads, install, activate, rollback, upload support, dispatch, recover, or mutate production rings." $denial.side_effects

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc13-declared-current-drift-zero-result.v1"
    generated_at = $generatedAtValue
    task = "RC13-010"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    reconciliation_surface = [ordered]@{
        state = $reconciliationState
        drift_zero = $driftZero
        drift_count = $driftCount
        comparisons = $comparisonCount
        matched = $matchedCount
        rc13_self_drift = $rc13SelfDriftCount
        carried_forward_drift = $carriedForwardDriftCount
        current_payload_matches_rc12 = ($sourceArtifactSha256 -eq $rc12DriftReconciliation.source.current_payload_bytes.sha256 -and $sourceArtifactSize -eq $rc12DriftReconciliation.source.current_payload_bytes.size_bytes)
        object_manifest_descriptor_binding_allowed = $driftZero
        freshness_revocation_authority_allowed = $driftZero
        object_trust_allowed = $driftZero
        quarantine_preflight_allowed = $driftZero
        agentcore_planspec_executable = $false
        security_execution_allowed = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        blockers = $allBlockers
        repair_blockers = $repairBlockers
    }
    outputs = [ordered]@{
        reconciliation = [ordered]@{ path = Get-StablePath $reconciliationPath; sha256 = Get-FileSha256 $reconciliationPath }
        denial = [ordered]@{ path = Get-StablePath $denialPath; sha256 = Get-FileSha256 $denialPath }
        object_manifest_descriptor_binding_handoff = [ordered]@{ path = Get-StablePath $handoffPath; sha256 = Get-FileSha256 $handoffPath }
    }
    source = $source
    invariants = [ordered]@{
        aios_body_only = $true
        mirror_frontend_changed = $false
        nginx_or_tls_changed = $false
        signer_infra_changed = $false
        object_storage_infra_changed = $false
        local_private_key_material_used = $false
        private_key_material_read_or_printed = $false
        cryptographic_signing_performed = $false
        payload_upload_performed = $false
        remote_payload_bytes_downloaded = $false
        quarantine_payload_written = $false
        drift_repair_performed = $false
        declared_metadata_rewritten = $false
        object_manifest_written_as_authority = $false
        object_trust_allowed = $driftZero
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        canary_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        production_ring_mutated = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        frontend_authority = $false
        mirror_authority = $false
        signer_reachability_authority = $false
        model_replay_authority = $false
        normal_shell_authority = $false
        tui_authority = $false
        production_ready_claim = $false
    }
    checks = $script:checks
    blockers = $allBlockers
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        drift_count = $driftCount
        drift_zero_denied_as_expected = (-not $driftZero)
        rc13_010_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC13-011"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc13-declared-current-drift-zero-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC13-010"
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
    reconciliation_surface = $result.reconciliation_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc13_010_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC13-011"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath), (Get-Content -Raw -LiteralPath $taskEvidencePath))
if (-not $finalSecretSafe) {
    throw "Sensitive marker detected in RC13-010 outputs."
}

Write-Host "RC13 declared/current drift-zero reconciliation $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Reconciliation state: $reconciliationState"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), drift count: $driftCount"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
