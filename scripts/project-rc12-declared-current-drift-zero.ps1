param(
    [string]$ArtifactDir = ".workflow/artifacts/rc12-declared-current-drift-zero",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc12",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc12/docs/rc12-real-object-controlled-unblock-contract.md",
    [string]$PublicationResultPath = ".workflow/artifacts/rc12-external-object-publication-binding/result.json",
    [string]$PublicationBindingPath = ".workflow/artifacts/rc12-external-object-publication-binding/publication-binding.json",
    [string]$PublicationHandoffPath = ".workflow/artifacts/rc12-external-object-publication-binding/publication-handoff.json",
    [string]$Rc11DriftResultPath = ".workflow/artifacts/rc11-declared-current-drift-zero/result.json",
    [string]$Rc11DriftReconciliationPath = ".workflow/artifacts/rc11-declared-current-drift-zero/declared-current-drift-zero-reconciliation.json",
    [string]$DescriptorCandidatePath = ".workflow/artifacts/rc11-release-object-byte-map/immutable-descriptor-candidate.json",
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
$resolvedPublicationResultPath = Resolve-RepoPath $PublicationResultPath
$resolvedPublicationBindingPath = Resolve-RepoPath $PublicationBindingPath
$resolvedPublicationHandoffPath = Resolve-RepoPath $PublicationHandoffPath
$resolvedRc11DriftResultPath = Resolve-RepoPath $Rc11DriftResultPath
$resolvedRc11DriftReconciliationPath = Resolve-RepoPath $Rc11DriftReconciliationPath
$resolvedDescriptorCandidatePath = Resolve-RepoPath $DescriptorCandidatePath

$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$publicationResult = Read-Json $resolvedPublicationResultPath
$publicationBinding = Read-Json $resolvedPublicationBindingPath
$publicationHandoff = Read-Json $resolvedPublicationHandoffPath
$rc11DriftResult = Read-Json $resolvedRc11DriftResultPath
$rc11DriftReconciliation = Read-Json $resolvedRc11DriftReconciliationPath
$descriptorCandidate = Read-Json $resolvedDescriptorCandidatePath

$generatedAtValue = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }
$releaseId = [string]$publicationResult.release_id
$sourceArtifactPath = Resolve-RepoPath ([string]$publicationBinding.current_release_bytes.source_path)
$sourceArtifactSha256 = Get-FileSha256 $sourceArtifactPath
$sourceArtifactSize = if (Test-Path -LiteralPath $sourceArtifactPath -PathType Leaf) { (Get-Item -LiteralPath $sourceArtifactPath).Length } else { $null }
$publicationResultSha256 = Get-FileSha256 $resolvedPublicationResultPath
$publicationBindingSha256 = Get-FileSha256 $resolvedPublicationBindingPath
$publicationHandoffSha256 = Get-FileSha256 $resolvedPublicationHandoffPath
$rc11DriftResultSha256 = Get-FileSha256 $resolvedRc11DriftResultPath
$rc11DriftReconciliationSha256 = Get-FileSha256 $resolvedRc11DriftReconciliationPath
$descriptorCandidateSha256 = Get-FileSha256 $resolvedDescriptorCandidatePath

$source = [ordered]@{
    rc12_contract = New-ArtifactRef $resolvedContractPath
    rc12_publication_result = New-ArtifactRef $resolvedPublicationResultPath $publicationResult
    rc12_publication_binding = New-ArtifactRef $resolvedPublicationBindingPath $publicationBinding
    rc12_publication_handoff = New-ArtifactRef $resolvedPublicationHandoffPath $publicationHandoff
    rc11_drift_result = New-ArtifactRef $resolvedRc11DriftResultPath $rc11DriftResult
    rc11_drift_reconciliation = New-ArtifactRef $resolvedRc11DriftReconciliationPath $rc11DriftReconciliation
    rc11_descriptor_candidate = New-ArtifactRef $resolvedDescriptorCandidatePath $descriptorCandidate
    current_payload_bytes = New-ArtifactRef $sourceArtifactPath
}

Add-Check "contract.drift_zero_gate.present" ($contractText.Contains("Reconcile declared metadata and current artifact evidence") -and $contractText.Contains("drift_count=0")) "RC12-011 must consume the RC12 drift-zero gate order." $source.rc12_contract
Add-Check "source.publication_result.passed" ($publicationResult.status -eq "passed" -and $publicationResult.task -eq "RC12-010") "RC12-011 requires RC12-010 publication binding evidence." ([ordered]@{ status = $publicationResult.status; task = $publicationResult.task; publication_allowed = $publicationResult.publication_surface.publication_allowed })
Add-Check "source.rc11_drift_result.passed" ($rc11DriftResult.status -eq "passed" -and [int]$rc11DriftResult.reconciliation_surface.comparisons -gt 0) "RC12-011 must carry forward RC11 declared/current reconciliation evidence." ([ordered]@{ status = $rc11DriftResult.status; drift_count = $rc11DriftResult.reconciliation_surface.drift_count; comparisons = $rc11DriftResult.reconciliation_surface.comparisons })

Add-Comparison "rc12.release_id.publication_vs_binding" $publicationResult.release_id $publicationBinding.release_id "rc12 publication result release_id" "rc12 publication binding release_id" "rc12-release-id-drift"
Add-Comparison "rc12.release_id.binding_vs_descriptor" $publicationBinding.release_id $descriptorCandidate.release_id "rc12 publication binding release_id" "rc11 descriptor candidate release_id" "rc12-release-id-drift"
Add-Comparison "rc12.payload.sha256.current_vs_publication" $sourceArtifactSha256 $publicationResult.publication_surface.current_payload_sha256 "current payload sha256" "rc12 publication result current_payload_sha256" "rc12-payload-digest-drift"
Add-Comparison "rc12.payload.size.current_vs_publication" $sourceArtifactSize $publicationResult.publication_surface.current_payload_size_bytes "current payload size_bytes" "rc12 publication result current_payload_size_bytes" "rc12-payload-size-drift"
Add-Comparison "rc12.payload.sha256.binding_vs_descriptor" $publicationBinding.current_release_bytes.sha256 $descriptorCandidate.sha256 "rc12 publication binding payload sha256" "rc11 descriptor candidate sha256" "rc12-payload-digest-drift"
Add-Comparison "rc12.payload.size.binding_vs_descriptor" $publicationBinding.current_release_bytes.size_bytes $descriptorCandidate.size_bytes "rc12 publication binding payload size" "rc11 descriptor candidate size" "rc12-payload-size-drift"
Add-Comparison "rc12.descriptor.sha256.result_vs_file" $publicationResult.publication_surface.descriptor_candidate_sha256 $descriptorCandidateSha256 "rc12 publication result descriptor_candidate_sha256" "current descriptor candidate file sha256" "rc12-descriptor-binding-drift"
Add-Comparison "rc12.publication_binding.sha256.result_vs_file" $publicationResult.publication_surface.publication_binding_sha256 $publicationBindingSha256 "rc12 publication result binding sha256" "current publication binding file sha256" "rc12-publication-binding-file-drift"
Add-Comparison "rc12.publication_binding.sha256.handoff_vs_file" $publicationHandoff.publication_binding.sha256 $publicationBindingSha256 "rc12 publication handoff binding sha256" "current publication binding file sha256" "rc12-publication-handoff-drift"
Add-Comparison "rc12.manifest.digest.binding_vs_descriptor" $publicationBinding.required_bindings.manifest_sha256 $descriptorCandidate.manifest_sha256 "rc12 publication binding manifest_sha256" "rc11 descriptor manifest_sha256" "rc12-manifest-digest-drift"
Add-Comparison "rc12.checksum_set.digest.binding_vs_descriptor" $publicationBinding.required_bindings.checksums_sha256 $descriptorCandidate.checksums_sha256 "rc12 publication binding checksums_sha256" "rc11 descriptor checksums_sha256" "rc12-checksum-set-digest-drift"
Add-Comparison "rc12.signature_target.digest.binding_vs_descriptor" $publicationBinding.required_bindings.public_signature_target_sha256 $descriptorCandidate.public_signature_target_sha256 "rc12 publication binding signature target" "rc11 descriptor signature target" "rc12-signature-target-drift"
Add-Comparison "rc12.revocation.digest.binding_vs_descriptor" $publicationBinding.required_bindings.revocation_snapshot_sha256 $descriptorCandidate.revocation_snapshot_sha256 "rc12 publication binding revocation" "rc11 descriptor revocation" "rc12-revocation-drift"
Add-Comparison "rc12.freshness.bound.required" "true" $publicationResult.publication_surface.freshness_window_bound "required freshness window bound" "rc12 publication result freshness_window_bound" "rc12-freshness-window-missing"
Add-Comparison "rc12.compatibility.digest.binding_vs_descriptor" $publicationBinding.required_bindings.compatibility_sha256 $descriptorCandidate.installer_compatibility_sha256 "rc12 publication binding compatibility" "rc11 descriptor compatibility" "rc12-compatibility-drift"
Add-Comparison "rc12.rollback.digest.binding_vs_descriptor" $publicationBinding.required_bindings.rollback_baseline_sha256 $descriptorCandidate.rollback_baseline_sha256 "rc12 publication binding rollback baseline" "rc11 descriptor rollback baseline" "rc12-rollback-baseline-drift"
Add-Comparison "rc12.support.digest.binding_vs_descriptor" $publicationBinding.required_bindings.support_recovery_sha256 $descriptorCandidate.support_recovery_sha256 "rc12 publication binding support recovery" "rc11 descriptor support recovery" "rc12-support-recovery-drift"
Add-Comparison "rc12.publication.allowed.required" "true" $publicationResult.publication_surface.publication_allowed "required external object publication allowed" "rc12 publication result publication_allowed" "rc12-external-object-publication-denied"
Add-Comparison "rc12.external_uri.published.required" "true" $publicationResult.publication_surface.external_object_uri_published "required external object URI published" "rc12 publication result external_object_uri_published" "rc12-external-object-uri-not-published"
Add-Comparison "rc12.rc11_drift_zero.required" "true" $rc11DriftResult.reconciliation_surface.drift_zero "required RC11 drift-zero" "rc11 drift result drift_zero" "rc11-drift-zero-not-proved"

foreach ($comparison in $rc11DriftReconciliation.comparisons) {
    $prefixed = [ordered]@{
        id = "rc11.carry_forward.$($comparison.id)"
        status = [string]$comparison.status
        expected = if ($null -eq $comparison.expected) { $null } else { [string]$comparison.expected }
        actual = if ($null -eq $comparison.actual) { $null } else { [string]$comparison.actual }
        expected_source = [string]$comparison.expected_source
        actual_source = [string]$comparison.actual_source
        denial_reason = $comparison.denial_reason
        source_task = "RC11-011"
    }
    $script:comparisons += $prefixed
    if ($comparison.status -ne "matched") {
        $script:drifts += $prefixed
    }
}

$comparisonCount = @($script:comparisons).Count
$driftCount = @($script:drifts).Count
$matchedCount = $comparisonCount - $driftCount
$rc12SelfDriftCount = @($script:drifts | Where-Object { $_.id -like "rc12.*" }).Count
$carriedForwardDriftCount = @($script:drifts | Where-Object { $_.id -like "rc11.carry_forward.*" }).Count
$driftZero = ($driftCount -eq 0 -and $publicationResult.publication_surface.publication_allowed -eq $true -and $publicationResult.publication_surface.freshness_window_bound -eq $true -and $rc11DriftResult.reconciliation_surface.drift_zero -eq $true)
$reconciliationState = if ($driftZero) { "declared-current-drift-zero" } else { "declared-current-drift-denied" }

$requiredIds = @(
    "rc12.release_id.publication_vs_binding",
    "rc12.payload.sha256.current_vs_publication",
    "rc12.descriptor.sha256.result_vs_file",
    "rc12.manifest.digest.binding_vs_descriptor",
    "rc12.checksum_set.digest.binding_vs_descriptor",
    "rc12.signature_target.digest.binding_vs_descriptor",
    "rc12.revocation.digest.binding_vs_descriptor",
    "rc12.freshness.bound.required",
    "rc12.compatibility.digest.binding_vs_descriptor",
    "rc12.rollback.digest.binding_vs_descriptor",
    "rc12.support.digest.binding_vs_descriptor",
    "rc12.publication_binding.sha256.result_vs_file"
)
$comparisonIds = @($script:comparisons | ForEach-Object { $_.id })
$missingRequiredIds = @($requiredIds | Where-Object { $comparisonIds -notcontains $_ })
Add-Check "comparisons.explicit_hash_bound" ($comparisonCount -ge 50 -and $publicationResultSha256 -and $publicationBindingSha256 -and $rc11DriftReconciliationSha256) "RC12-011 comparisons must be explicit and hash-bound to RC11 and RC12 source artifacts." ([ordered]@{ comparisons = $comparisonCount; rc12_self_drifts = $rc12SelfDriftCount; carried_forward_drifts = $carriedForwardDriftCount })
Add-Check "comparisons.required_identity_surface.present" ($missingRequiredIds.Count -eq 0) "Drift-zero can only be true after release, payload, descriptor, manifest, checksums, signature, revocation, freshness, compatibility, rollback, support, and publication binding comparisons exist." ([ordered]@{ missing = $missingRequiredIds })
Add-Check "reconciliation.zero_required" (($driftCount -eq 0 -and $driftZero) -or ($driftCount -gt 0 -and -not $driftZero)) "Any declared/current drift or missing publication/freshness gate must deny object trust and downstream authority." ([ordered]@{ drift_count = $driftCount; drift_zero = $driftZero; publication_allowed = $publicationResult.publication_surface.publication_allowed; freshness_window_bound = $publicationResult.publication_surface.freshness_window_bound })

$repairBlockers = @()
if ($driftCount -gt 0) { $repairBlockers += "nonzero-declared-current-drift-count" }
if ($rc12SelfDriftCount -gt 0) { $repairBlockers += "rc12-publication-binding-drift" }
if ($carriedForwardDriftCount -gt 0) { $repairBlockers += "rc11-declared-current-drift-carried-forward" }
foreach ($blocker in @($publicationResult.blockers)) {
    if ($repairBlockers -notcontains $blocker) { $repairBlockers += $blocker }
}
if ($publicationResult.publication_surface.publication_allowed -ne $true) { $repairBlockers += "external-object-publication-not-allowed" }
if ($publicationResult.publication_surface.freshness_window_bound -ne $true) { $repairBlockers += "freshness-window-not-bound" }
$downstreamBlockers = @(
    "object-trust-not-allowed",
    "installer-quarantine-fetch-not-run",
    "agentcore-planspec-not-bound",
    "security-execution-effect-envelope-not-bound",
    "two-target-canary-not-enrolled",
    "exact-approval-not-bound",
    "controlled-activation-not-authorized",
    "controlled-rollback-not-authorized"
)
$allBlockers = @($repairBlockers + $downstreamBlockers | Select-Object -Unique)

$reconciliation = [ordered]@{
    schema = "agentos.rc12-declared-current-drift-zero-reconciliation.v1"
    generated_at = $generatedAtValue
    task = "RC12-011"
    release_id = $releaseId
    status = $reconciliationState
    production_ready_claim = $false
    source = $source
    binding = [ordered]@{
        publication_result_sha256 = $publicationResultSha256
        publication_binding_sha256 = $publicationBindingSha256
        publication_handoff_sha256 = $publicationHandoffSha256
        rc11_drift_result_sha256 = $rc11DriftResultSha256
        rc11_drift_reconciliation_sha256 = $rc11DriftReconciliationSha256
        descriptor_candidate_sha256 = $descriptorCandidateSha256
    }
    comparison_summary = [ordered]@{
        comparisons = $comparisonCount
        matched = $matchedCount
        drift = $driftCount
        rc12_self_drift = $rc12SelfDriftCount
        carried_forward_drift = $carriedForwardDriftCount
        drift_zero = $driftZero
        publication_allowed = [bool]$publicationResult.publication_surface.publication_allowed
        freshness_window_bound = [bool]$publicationResult.publication_surface.freshness_window_bound
    }
    comparisons = $script:comparisons
    drifts = $script:drifts
    repair_blockers = $repairBlockers
    blockers = $allBlockers
    trust_decision = [ordered]@{
        object_trust_allowed = $driftZero
        descriptor_verification_allowed = $driftZero
        quarantine_fetch_allowed = $driftZero
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        drift_repair_performed = $false
        declared_metadata_rewritten = $false
        publication_binding_rewritten = $false
    }
}

$denial = [ordered]@{
    schema = "agentos.rc12-drift-zero-denial.v1"
    generated_at = $generatedAtValue
    task = "RC12-011"
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
        publication_binding_rewritten = $false
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
    schema = "agentos.rc12-object-trust-verification-handoff.v1"
    generated_at = $generatedAtValue
    task = "RC12-011"
    release_id = $releaseId
    status = if ($driftZero) { "ready-for-rc12-012-object-trust-verification" } else { "blocked-by-declared-current-drift" }
    production_ready_claim = $false
    reconciliation = [ordered]@{
        path = $null
        sha256 = $null
        drift_zero = $driftZero
        drift_count = $driftCount
        expected_next_task = "RC12-012"
    }
    publication_binding = [ordered]@{
        path = Get-StablePath $resolvedPublicationBindingPath
        sha256 = $publicationBindingSha256
        publication_allowed = [bool]$publicationResult.publication_surface.publication_allowed
        external_object_uri_published = [bool]$publicationResult.publication_surface.external_object_uri_published
    }
    blocked_authority = [ordered]@{
        object_trust_allowed = $driftZero
        quarantine_fetch_allowed = $driftZero
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
    }
    blockers = $allBlockers
}

$reconciliationPath = Join-Path $resolvedArtifactDir "declared-current-drift-zero-reconciliation.json"
$denialPath = Join-Path $resolvedArtifactDir "drift-zero-denial.json"
$handoffPath = Join-Path $resolvedArtifactDir "object-trust-verification-handoff.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC12-011-declared-current-drift-zero.json"

Write-Json $reconciliation $reconciliationPath
$handoff.reconciliation.path = Get-StablePath $reconciliationPath
$handoff.reconciliation.sha256 = Get-FileSha256 $reconciliationPath
Write-Json $denial $denialPath
Write-Json $handoff $handoffPath

Add-Check "outputs.secret_safe" (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $reconciliationPath), (Get-Content -Raw -LiteralPath $denialPath), (Get-Content -Raw -LiteralPath $handoffPath))) "RC12-011 outputs must not contain PEM blocks, auth tokens, or signer internals." $null
Add-Check "outputs.side_effects_blocked" ($denial.side_effects.drift_repair_performed -eq $false -and $denial.side_effects.declared_metadata_rewritten -eq $false -and $denial.side_effects.publication_binding_rewritten -eq $false -and $denial.side_effects.quarantine_payload_written -eq $false -and $denial.side_effects.payload_bytes_uploaded -eq $false -and $denial.side_effects.remote_payload_bytes_downloaded -eq $false -and $denial.side_effects.install_performed -eq $false -and $denial.side_effects.activation_performed -eq $false -and $denial.side_effects.rollback_execution_performed -eq $false -and $denial.side_effects.support_upload_performed -eq $false -and $denial.side_effects.recovery_execution_performed -eq $false -and $denial.side_effects.remote_dispatch_enabled -eq $false -and $denial.side_effects.production_ring_mutated -eq $false) "RC12-011 must not repair drift, rewrite metadata, fetch payloads, install, activate, rollback, upload support, dispatch, recover, or mutate production rings." $denial.side_effects

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc12-declared-current-drift-zero-result.v1"
    generated_at = $generatedAtValue
    task = "RC12-011"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    reconciliation_surface = [ordered]@{
        state = $reconciliationState
        drift_zero = $driftZero
        drift_count = $driftCount
        comparisons = $comparisonCount
        matched = $matchedCount
        rc12_self_drift = $rc12SelfDriftCount
        carried_forward_drift = $carriedForwardDriftCount
        publication_allowed = [bool]$publicationResult.publication_surface.publication_allowed
        external_object_uri_published = [bool]$publicationResult.publication_surface.external_object_uri_published
        freshness_window_bound = [bool]$publicationResult.publication_surface.freshness_window_bound
        object_trust_allowed = $driftZero
        quarantine_fetch_allowed = $driftZero
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
        object_trust_verification_handoff = [ordered]@{ path = Get-StablePath $handoffPath; sha256 = Get-FileSha256 $handoffPath }
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
        publication_binding_rewritten = $false
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
        rc12_011_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC12-012"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc12-declared-current-drift-zero-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC12-011"
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
        rc12_011_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC12-012"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath), (Get-Content -Raw -LiteralPath $taskEvidencePath))
if (-not $finalSecretSafe) {
    throw "Sensitive marker detected in RC12-011 outputs."
}

Write-Host "RC12 declared/current drift-zero reconciliation $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Reconciliation state: $reconciliationState"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), drift count: $driftCount"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
