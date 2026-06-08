param(
    [string]$ArtifactDir = ".workflow/artifacts/rc11-declared-current-drift-zero",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc11",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc11/docs/real-object-trust-handoff-contract.md",
    [string]$ByteMapResultPath = ".workflow/artifacts/rc11-release-object-byte-map/result.json",
    [string]$ByteMapPath = ".workflow/artifacts/rc11-release-object-byte-map/release-object-byte-map.json",
    [string]$DescriptorCandidatePath = ".workflow/artifacts/rc11-release-object-byte-map/immutable-descriptor-candidate.json",
    [string]$DescriptorReportPath = ".workflow/artifacts/rc11-release-object-byte-map/descriptor-candidate-report.json",
    [string]$Rc10DriftResultPath = ".workflow/artifacts/rc10-artifact-drift-zero-reconciliation/result.json",
    [string]$Rc10DriftReconciliationPath = ".workflow/artifacts/rc10-artifact-drift-zero-reconciliation/artifact-drift-zero-reconciliation.json",
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
$script:failedChecks = @()
$script:comparisons = @()
$script:drifts = @()

$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$resolvedWorkflowDir = Resolve-RepoPath $WorkflowDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $resolvedWorkflowDir "evidence") | Out-Null

$resolvedContractPath = Resolve-RepoPath $ContractPath
$resolvedByteMapResultPath = Resolve-RepoPath $ByteMapResultPath
$resolvedByteMapPath = Resolve-RepoPath $ByteMapPath
$resolvedDescriptorCandidatePath = Resolve-RepoPath $DescriptorCandidatePath
$resolvedDescriptorReportPath = Resolve-RepoPath $DescriptorReportPath
$resolvedRc10DriftResultPath = Resolve-RepoPath $Rc10DriftResultPath
$resolvedRc10DriftReconciliationPath = Resolve-RepoPath $Rc10DriftReconciliationPath

$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$byteMapResult = Read-Json $resolvedByteMapResultPath
$byteMap = Read-Json $resolvedByteMapPath
$descriptorCandidate = Read-Json $resolvedDescriptorCandidatePath
$descriptorReport = Read-Json $resolvedDescriptorReportPath
$rc10DriftResult = Read-Json $resolvedRc10DriftResultPath
$rc10DriftReconciliation = Read-Json $resolvedRc10DriftReconciliationPath

$generatedAt = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }
$releaseId = [string]$byteMap.release_id
$sourceArtifactPath = Resolve-RepoPath ([string]$descriptorCandidate.source_build_artifact)
$sourceArtifactSha256 = Get-FileSha256 $sourceArtifactPath
$sourceArtifactSize = if (Test-Path -LiteralPath $sourceArtifactPath -PathType Leaf) { (Get-Item -LiteralPath $sourceArtifactPath).Length } else { $null }
$byteMapSha256 = Get-FileSha256 $resolvedByteMapPath
$descriptorCandidateSha256 = Get-FileSha256 $resolvedDescriptorCandidatePath
$descriptorReportSha256 = Get-FileSha256 $resolvedDescriptorReportPath
$byteMapResultSha256 = Get-FileSha256 $resolvedByteMapResultPath
$rc10DriftResultSha256 = Get-FileSha256 $resolvedRc10DriftResultPath
$rc10DriftReconciliationSha256 = Get-FileSha256 $resolvedRc10DriftReconciliationPath

$rc10DriftCount = [int]$rc10DriftResult.reconciliation_surface.drift_count
$rc10ComparisonCount = [int]$rc10DriftResult.reconciliation_surface.comparisons
$rc10MatchedCount = [int]$rc10DriftResult.reconciliation_surface.matched
$rc10DriftZero = [bool]$rc10DriftResult.reconciliation_surface.drift_zero

$source = [ordered]@{
    rc11_contract = New-ArtifactRef $resolvedContractPath
    rc11_byte_map_result = New-ArtifactRef $resolvedByteMapResultPath $byteMapResult
    rc11_byte_map = New-ArtifactRef $resolvedByteMapPath $byteMap
    rc11_descriptor_candidate = New-ArtifactRef $resolvedDescriptorCandidatePath $descriptorCandidate
    rc11_descriptor_report = New-ArtifactRef $resolvedDescriptorReportPath $descriptorReport
    rc10_drift_result = New-ArtifactRef $resolvedRc10DriftResultPath $rc10DriftResult
    rc10_drift_reconciliation = New-ArtifactRef $resolvedRc10DriftReconciliationPath $rc10DriftReconciliation
    current_payload_bytes = New-ArtifactRef $sourceArtifactPath
}

Add-Check "contract.drift_zero_gate.present" ($contractText.Contains("Drift-zero is a hard gate")) "RC11-011 must consume the RC11 drift-zero gate contract." $source.rc11_contract
Add-Check "source.rc11_byte_map.passed" ($byteMapResult.status -eq "passed" -and $byteMap.task -eq "RC11-010") "RC11-011 requires the RC11-010 byte map result." ([ordered]@{ result_status = $byteMapResult.status; byte_map_task = $byteMap.task })
Add-Check "source.rc10_drift.passed" ($rc10DriftResult.status -eq "passed" -and $rc10ComparisonCount -gt 0) "RC11-011 must bind prior declared/current drift evidence." ([ordered]@{ status = $rc10DriftResult.status; comparisons = $rc10ComparisonCount; drift_count = $rc10DriftCount })

Add-Comparison "rc11.release_id.byte_map_vs_descriptor_candidate" $byteMap.release_id $descriptorCandidate.release_id "rc11 byte map release_id" "rc11 descriptor candidate release_id" "rc11-release-id-drift"
Add-Comparison "rc11.payload.sha256.byte_map_vs_descriptor_candidate" $byteMap.current_payload.sha256 $descriptorCandidate.sha256 "rc11 byte map current_payload.sha256" "rc11 descriptor candidate sha256" "rc11-payload-digest-drift"
Add-Comparison "rc11.payload.size.byte_map_vs_descriptor_candidate" $byteMap.current_payload.size_bytes $descriptorCandidate.size_bytes "rc11 byte map current_payload.size_bytes" "rc11 descriptor candidate size_bytes" "rc11-payload-size-drift"
Add-Comparison "rc11.payload.sha256.current_bytes_vs_descriptor_candidate" $descriptorCandidate.sha256 $sourceArtifactSha256 "rc11 descriptor candidate sha256" "current source payload sha256" "current-payload-digest-drift"
Add-Comparison "rc11.payload.size.current_bytes_vs_descriptor_candidate" $descriptorCandidate.size_bytes $sourceArtifactSize "rc11 descriptor candidate size_bytes" "current source payload size_bytes" "current-payload-size-drift"
Add-Comparison "rc11.byte_map.sha256.result_vs_file" $byteMapResult.byte_map_surface.byte_map_sha256 $byteMapSha256 "rc11 byte map result byte_map_sha256" "current byte map file sha256" "rc11-byte-map-file-drift"
Add-Comparison "rc11.descriptor.sha256.result_vs_file" $byteMapResult.byte_map_surface.descriptor_candidate_sha256 $descriptorCandidateSha256 "rc11 byte map result descriptor_candidate_sha256" "current descriptor candidate file sha256" "rc11-descriptor-candidate-file-drift"
Add-Comparison "rc11.descriptor.byte_map_binding" $descriptorCandidate.byte_map_sha256 $byteMapSha256 "descriptor candidate byte_map_sha256" "current byte map file sha256" "descriptor-byte-map-binding-drift"
Add-Comparison "rc11.rc10_result_sha256.byte_map_vs_file" $byteMap.required_bindings.rc10_drift_result_sha256 $rc10DriftResultSha256 "rc11 byte map rc10_drift_result_sha256" "current rc10 drift result sha256" "rc10-drift-result-binding-drift"
Add-Comparison "rc11.rc10_reconciliation_sha256.descriptor_vs_file" $descriptorCandidate.declared_current_reconciliation_sha256 $rc10DriftReconciliationSha256 "descriptor candidate declared_current_reconciliation_sha256" "current rc10 reconciliation sha256" "rc10-reconciliation-binding-drift"

foreach ($comparison in $rc10DriftReconciliation.comparisons) {
    $prefixed = [ordered]@{
        id = "rc10.carry_forward.$($comparison.id)"
        status = [string]$comparison.status
        expected = if ($null -eq $comparison.expected) { $null } else { [string]$comparison.expected }
        actual = if ($null -eq $comparison.actual) { $null } else { [string]$comparison.actual }
        expected_source = [string]$comparison.expected_source
        actual_source = [string]$comparison.actual_source
        denial_reason = $comparison.denial_reason
        source_task = "RC10-011"
    }
    $script:comparisons += $prefixed
    if ($comparison.status -ne "matched") {
        $script:drifts += $prefixed
    }
}

$comparisonCount = @($script:comparisons).Count
$driftCount = @($script:drifts).Count
$matchedCount = $comparisonCount - $driftCount
$rc11SelfDriftCount = @($script:drifts | Where-Object { $_.id -like "rc11.*" }).Count
$carriedForwardDriftCount = @($script:drifts | Where-Object { $_.id -like "rc10.carry_forward.*" }).Count
$driftZero = ($driftCount -eq 0 -and $rc10DriftZero -eq $true)
$reconciliationState = if ($driftZero) { "declared-current-drift-zero" } else { "declared-current-drift-denied" }

Add-Check "comparisons.explicit_hash_bound" ($comparisonCount -ge 40 -and $byteMapSha256 -and $descriptorCandidateSha256 -and $rc10DriftReconciliationSha256) "RC11-011 comparisons must be explicit and hash-bound to RC11 and RC10 evidence." ([ordered]@{ comparisons = $comparisonCount; rc11_self_drifts = $rc11SelfDriftCount; carried_forward_drifts = $carriedForwardDriftCount })
Add-Check "reconciliation.zero_required" (($driftCount -eq 0 -and $driftZero) -or ($driftCount -gt 0 -and -not $driftZero)) "Any declared/current drift must deny object trust and downstream authority." ([ordered]@{ drift_count = $driftCount; drift_zero = $driftZero; rc10_drift_zero = $rc10DriftZero })

$driftBlockers = @()
if ($driftCount -gt 0) {
    $driftBlockers += "nonzero-declared-current-drift-count"
}
if ($rc11SelfDriftCount -gt 0) {
    $driftBlockers += "rc11-byte-map-binding-drift"
}
if ($carriedForwardDriftCount -gt 0) {
    $driftBlockers += "rc10-declared-current-drift-carried-forward"
}
if ($byteMapResult.byte_map_surface.external_https_object_uri_published -ne $true) {
    $driftBlockers += "external-https-object-uri-not-published"
}
$downstreamBlockers = @(
    "installer-quarantine-fetch-not-run",
    "two-target-canary-not-enrolled",
    "exact-approval-not-bound",
    "agentcore-planspec-not-bound",
    "security-execution-effect-envelope-not-bound",
    "controlled-activation-not-authorized",
    "controlled-rollback-not-authorized"
)
$allBlockers = @($driftBlockers + $downstreamBlockers | Select-Object -Unique)

$reconciliation = [ordered]@{
    schema = "agentos.rc11-declared-current-drift-zero-reconciliation.v1"
    generated_at = $generatedAt
    task = "RC11-011"
    release_id = $releaseId
    status = $reconciliationState
    production_ready_claim = $false
    source = $source
    byte_map_binding = [ordered]@{
        result_sha256 = $byteMapResultSha256
        byte_map_sha256 = $byteMapSha256
        descriptor_candidate_sha256 = $descriptorCandidateSha256
        descriptor_report_sha256 = $descriptorReportSha256
        rc10_drift_result_sha256 = $rc10DriftResultSha256
        rc10_drift_reconciliation_sha256 = $rc10DriftReconciliationSha256
    }
    comparison_summary = [ordered]@{
        comparisons = $comparisonCount
        matched = $matchedCount
        drift = $driftCount
        rc11_self_drift = $rc11SelfDriftCount
        carried_forward_drift = $carriedForwardDriftCount
        rc10_source_comparisons = $rc10ComparisonCount
        rc10_source_drift = $rc10DriftCount
        drift_zero = $driftZero
    }
    comparisons = $script:comparisons
    drifts = $script:drifts
    blockers = $allBlockers
    trust_decision = [ordered]@{
        external_object_trust_allowed = $driftZero
        external_object_descriptor_verification_allowed = $driftZero
        installer_quarantine_fetch_allowed = $driftZero
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        drift_repair_performed = $false
        declared_metadata_rewritten = $false
        descriptor_published = $false
        payload_bytes_uploaded = $false
    }
}

$denial = [ordered]@{
    schema = "agentos.rc11-drift-zero-denial.v1"
    generated_at = $generatedAt
    task = "RC11-011"
    release_id = $releaseId
    status = if ($driftZero) { "not-denied" } else { "declared-current-drift-denied" }
    production_ready_claim = $false
    denied = (-not $driftZero)
    denial_reasons = $driftBlockers
    drift_count = $driftCount
    drift_ids = @($script:drifts | ForEach-Object { $_.id })
    downstream_gates_blocked = $downstreamBlockers
    side_effects = [ordered]@{
        drift_repair_performed = $false
        declared_metadata_rewritten = $false
        descriptor_published = $false
        payload_bytes_uploaded = $false
        remote_payload_bytes_downloaded = $false
        quarantine_payload_written = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        support_upload_performed = $false
        remote_dispatch_enabled = $false
        production_ring_mutated = $false
    }
}

$handoff = [ordered]@{
    schema = "agentos.rc11-external-descriptor-verification-handoff.v1"
    generated_at = $generatedAt
    task = "RC11-011"
    release_id = $releaseId
    status = if ($driftZero) { "ready-for-rc11-012-external-descriptor-verification" } else { "blocked-by-declared-current-drift" }
    production_ready_claim = $false
    reconciliation = [ordered]@{
        path = $null
        sha256 = $null
        drift_zero = $driftZero
        drift_count = $driftCount
        expected_next_task = "RC11-012"
    }
    descriptor_candidate = [ordered]@{
        path = Get-StablePath $resolvedDescriptorCandidatePath
        sha256 = $descriptorCandidateSha256
        uri = $descriptorCandidate.uri
        uri_policy = $descriptorCandidate.uri_policy
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
    }
    blocked_authority = [ordered]@{
        object_trust_allowed = $driftZero
        descriptor_verification_allowed = $driftZero
        installer_quarantine_fetch_allowed = $driftZero
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
$handoffPath = Join-Path $resolvedArtifactDir "external-descriptor-verification-handoff.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC11-011-declared-current-drift-zero.json"

Write-Json $reconciliation $reconciliationPath
$handoff.reconciliation.path = Get-StablePath $reconciliationPath
$handoff.reconciliation.sha256 = Get-FileSha256 $reconciliationPath
Write-Json $denial $denialPath
Write-Json $handoff $handoffPath

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $reconciliationPath),
    (Get-Content -Raw -LiteralPath $denialPath),
    (Get-Content -Raw -LiteralPath $handoffPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC11-011 outputs must not contain PEM blocks, auth tokens, or signer internals." $null
Add-Check "outputs.side_effects_blocked" ($denial.side_effects.payload_bytes_uploaded -eq $false -and $denial.side_effects.remote_payload_bytes_downloaded -eq $false -and $denial.side_effects.quarantine_payload_written -eq $false -and $denial.side_effects.install_performed -eq $false -and $denial.side_effects.activation_performed -eq $false -and $denial.side_effects.rollback_execution_performed -eq $false -and $denial.side_effects.remote_dispatch_enabled -eq $false -and $denial.side_effects.production_ring_mutated -eq $false) "RC11-011 must not repair drift, publish descriptors, fetch payload bytes, install, activate, rollback, dispatch, or mutate production rings." $denial.side_effects

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc11-declared-current-drift-zero-result.v1"
    generated_at = $generatedAt
    task = "RC11-011"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    reconciliation_surface = [ordered]@{
        state = $reconciliationState
        drift_zero = $driftZero
        drift_count = $driftCount
        comparisons = $comparisonCount
        matched = $matchedCount
        rc11_self_drift = $rc11SelfDriftCount
        carried_forward_drift = $carriedForwardDriftCount
        external_https_object_uri_published = [bool]$byteMapResult.byte_map_surface.external_https_object_uri_published
        external_object_trust_allowed = $driftZero
        external_object_descriptor_verification_allowed = $driftZero
        installer_quarantine_fetch_allowed = $driftZero
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        blockers = $allBlockers
    }
    outputs = [ordered]@{
        reconciliation = [ordered]@{ path = Get-StablePath $reconciliationPath; sha256 = Get-FileSha256 $reconciliationPath }
        denial = [ordered]@{ path = Get-StablePath $denialPath; sha256 = Get-FileSha256 $denialPath }
        external_descriptor_verification_handoff = [ordered]@{ path = Get-StablePath $handoffPath; sha256 = Get-FileSha256 $handoffPath }
    }
    source = $source
    invariants = [ordered]@{
        aios_body_only = $true
        mirror_frontend_changed = $false
        nginx_or_tls_changed = $false
        signer_infra_changed = $false
        local_private_key_material_used = $false
        private_key_material_read_or_printed = $false
        cryptographic_signing_performed = $false
        payload_bytes_uploaded = $false
        remote_payload_bytes_downloaded = $false
        quarantine_payload_written = $false
        drift_repair_performed = $false
        declared_metadata_rewritten = $false
        descriptor_published = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        canary_execution_performed = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        production_ring_mutated = $false
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
        rc11_011_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC11-012"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc11-declared-current-drift-zero-evidence.v1"
    generated_at = $generatedAt
    task = "RC11-011"
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
        rc11_011_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC11-012"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) {
    throw "Sensitive marker detected in RC11-011 outputs."
}

Write-Host "RC11 declared/current drift-zero reconciliation $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Reconciliation state: $reconciliationState"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), drift count: $driftCount"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
