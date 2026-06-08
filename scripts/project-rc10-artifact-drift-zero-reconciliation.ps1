param(
    [string]$ArtifactDir = ".workflow/artifacts/rc10-artifact-drift-zero-reconciliation",
    [string]$Rc10PublicationResultPath = ".workflow/artifacts/rc10-external-object-publication/result.json",
    [string]$Rc10PublicationReportPath = ".workflow/artifacts/rc10-external-object-publication/publication-report.json",
    [string]$Rc10DescriptorCandidatePath = ".workflow/artifacts/rc10-external-object-publication/external-object-descriptor-candidate.json",
    [string]$Rc10PublicationHandoffPath = ".workflow/artifacts/rc10-external-object-publication/installer-handoff.json",
    [string]$Rc9DriftReconciliationPath = ".workflow/artifacts/rc9-artifact-drift-reconciliation/artifact-drift-reconciliation.json",
    [string]$DriftZeroContractPath = ".workflow/active/WFS-20260608-agentos-production-distro-rc10/docs/drift-zero-external-object-publication-contract.md",
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
    $script:checks += [ordered]@{
        id = $Id
        status = if ($Passed) { "passed" } else { "failed" }
        severity = "blocking"
        message = $Message
        evidence = $Evidence
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

$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null

$resolvedPublicationResultPath = Resolve-RepoPath $Rc10PublicationResultPath
$resolvedPublicationReportPath = Resolve-RepoPath $Rc10PublicationReportPath
$resolvedDescriptorCandidatePath = Resolve-RepoPath $Rc10DescriptorCandidatePath
$resolvedPublicationHandoffPath = Resolve-RepoPath $Rc10PublicationHandoffPath
$resolvedRc9DriftPath = Resolve-RepoPath $Rc9DriftReconciliationPath
$resolvedContractPath = Resolve-RepoPath $DriftZeroContractPath

$publicationResult = Read-Json $resolvedPublicationResultPath
$publicationReport = Read-Json $resolvedPublicationReportPath
$descriptorCandidate = Read-Json $resolvedDescriptorCandidatePath
$publicationHandoff = Read-Json $resolvedPublicationHandoffPath
$rc9Drift = Read-Json $resolvedRc9DriftPath

$generatedAt = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }
$releaseId = [string]$publicationResult.release_id
$sourceDriftCount = [int]$rc9Drift.comparison_summary.drift
$sourceMatchedCount = [int]$rc9Drift.comparison_summary.matched
$sourceComparisonCount = [int]$rc9Drift.comparison_summary.comparisons
$publicationState = [string]$publicationResult.publication_surface.state
$publicationAllowed = [bool]$publicationResult.publication_surface.publication_allowed
$publishedDriftZero = [bool]$publicationResult.publication_surface.published_drift_zero
$uriClassification = [string]$publicationResult.publication_surface.external_object_uri_classification
$driftZero = ($sourceDriftCount -eq 0 -and $publishedDriftZero -eq $true -and $publicationAllowed -eq $true)
$reconciliationState = if ($driftZero) { "drift-zero-reconciled" } else { "drift-zero-denied" }

$source = [ordered]@{
    drift_zero_contract = New-ArtifactRef $resolvedContractPath
    publication_result = New-ArtifactRef $resolvedPublicationResultPath $publicationResult
    publication_report = New-ArtifactRef $resolvedPublicationReportPath $publicationReport
    descriptor_candidate = New-ArtifactRef $resolvedDescriptorCandidatePath $descriptorCandidate
    publication_handoff = New-ArtifactRef $resolvedPublicationHandoffPath $publicationHandoff
    rc9_drift_reconciliation = New-ArtifactRef $resolvedRc9DriftPath $rc9Drift
}

Add-Check "source.publication_result.passed" ($publicationResult.status -eq "passed" -and $publicationReport.task -eq "RC10-010") "RC10-011 requires RC10-010 publication evidence." ([ordered]@{ result_status = $publicationResult.status; publication_state = $publicationState })
Add-Check "source.drift_artifact.present" ($rc9Drift.schema -eq "agentos.rc9-artifact-drift-reconciliation.v1" -and $sourceComparisonCount -gt 0) "RC10-011 requires prior declared/current drift comparisons." ([ordered]@{ comparisons = $sourceComparisonCount; matched = $sourceMatchedCount; drift_count = $sourceDriftCount })
Add-Check "reconciliation.zero_required" (($sourceDriftCount -eq 0 -and $driftZero) -or ($sourceDriftCount -gt 0 -and -not $driftZero)) "Nonzero drift count must deny drift-zero reconciliation." ([ordered]@{ drift_count = $sourceDriftCount; publication_state = $publicationState; drift_zero = $driftZero })
Add-Check "reconciliation.publication_dependency" (($publicationAllowed -and $publishedDriftZero) -or (-not $publicationAllowed -and -not $publishedDriftZero)) "Drift-zero trust must depend on published-drift-zero publication evidence." ([ordered]@{ publication_allowed = $publicationAllowed; published_drift_zero = $publishedDriftZero; uri_classification = $uriClassification })

$downstreamBlockers = @(
    "installer-quarantine-fetch-not-run",
    "two-node-canary-target-set-not-enrolled",
    "exact-operator-approval-pending",
    "agentcore-planspec-not-bound",
    "security-execution-effect-envelope-not-bound",
    "controlled-activation-not-authorized",
    "controlled-rollback-not-authorized"
)
$driftBlockers = @()
if ($sourceDriftCount -gt 0) {
    $driftBlockers += "nonzero-declared-current-drift-count"
}
if (-not $publicationAllowed) {
    $driftBlockers += "publication-not-published-drift-zero"
}
if ($uriClassification -eq "missing") {
    $driftBlockers += "missing-external-https-object-uri"
}
$driftBlockers = @($driftBlockers | Select-Object -Unique)

$reconciliation = [ordered]@{
    schema = "agentos.rc10-artifact-drift-zero-reconciliation.v1"
    generated_at = $generatedAt
    task = "RC10-011"
    release_id = $releaseId
    status = $reconciliationState
    production_ready_claim = $false
    source = $source
    publication_dependency = [ordered]@{
        state = $publicationState
        publication_allowed = $publicationAllowed
        published_drift_zero = $publishedDriftZero
        external_object_uri_classification = $uriClassification
        descriptor_canonical_sha256 = [string]$publicationReport.publication_decision.descriptor_canonical_sha256
    }
    comparison_summary = [ordered]@{
        comparisons = $sourceComparisonCount
        matched = $sourceMatchedCount
        drift = $sourceDriftCount
        missing = [int]$rc9Drift.comparison_summary.missing
        drift_zero = $driftZero
    }
    comparisons = $rc9Drift.comparisons
    drifts = $rc9Drift.drifts
    blockers = @($driftBlockers + $downstreamBlockers)
    trust_decision = [ordered]@{
        external_object_trust_allowed = $driftZero
        installer_quarantine_fetch_allowed = $driftZero
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        drift_repair_performed = $false
        superseded_metadata_auto_rewritten = $false
        descriptor_publication_repaired = $false
    }
}

$denial = [ordered]@{
    schema = "agentos.rc10-drift-zero-denial.v1"
    generated_at = $generatedAt
    task = "RC10-011"
    release_id = $releaseId
    status = if ($driftZero) { "not-denied" } else { "drift-zero-denied" }
    production_ready_claim = $false
    denied = (-not $driftZero)
    denial_reasons = $driftBlockers
    drift_count = $sourceDriftCount
    drift_ids = @($rc9Drift.drifts | ForEach-Object { $_.id })
    downstream_gates_blocked = $downstreamBlockers
    side_effects = [ordered]@{
        drift_repair_performed = $false
        declared_metadata_rewritten = $false
        descriptor_published = $false
        payload_bytes_uploaded = $false
        remote_payload_bytes_downloaded = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        remote_dispatch_enabled = $false
    }
}

$handoff = [ordered]@{
    schema = "agentos.rc10-drift-zero-installer-handoff.v1"
    generated_at = $generatedAt
    task = "RC10-011"
    release_id = $releaseId
    status = if ($driftZero) { "ready-for-rc10-012-quarantine-fetch" } else { "blocked-by-drift-zero-denial" }
    production_ready_claim = $false
    publication_report = [ordered]@{
        path = Get-StablePath $resolvedPublicationReportPath
        sha256 = Get-FileSha256 $resolvedPublicationReportPath
    }
    reconciliation = [ordered]@{
        drift_zero = $driftZero
        drift_count = $sourceDriftCount
        expected_state = "published-drift-zero"
        observed_publication_state = $publicationState
    }
    expected_object = $publicationHandoff.expected_object
    quarantine_policy = [ordered]@{
        quarantine_fetch_allowed = $driftZero
        quarantine_root_policy = "installer-owned-temp-quarantine"
        allowed_network_policy = "external-https-only-after-published-drift-zero"
        interpret_before_size_digest_signature_verification = $false
    }
    denied_side_effects = @(
        "install",
        "activation",
        "rollback-execution",
        "boot-metadata-mutation",
        "active-slot-mutation",
        "active-artifact-set-mutation",
        "production-ring-mutation",
        "support-upload",
        "remote-dispatch"
    )
    blockers = @($driftBlockers + $downstreamBlockers)
    next_task = "RC10-012"
}

$reconciliationPath = Join-Path $resolvedArtifactDir "artifact-drift-zero-reconciliation.json"
$denialPath = Join-Path $resolvedArtifactDir "drift-zero-denial.json"
$handoffPath = Join-Path $resolvedArtifactDir "installer-handoff.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"

Write-Json $reconciliation $reconciliationPath
Write-Json $denial $denialPath
Write-Json $handoff $handoffPath

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $reconciliationPath),
    (Get-Content -Raw -LiteralPath $denialPath),
    (Get-Content -Raw -LiteralPath $handoffPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC10-011 outputs must not contain private key paths, PEM blocks, auth tokens, or signer internals." $null
Add-Check "outputs.side_effects_blocked" ($denial.side_effects.install_performed -eq $false -and $denial.side_effects.activation_performed -eq $false -and $denial.side_effects.rollback_execution_performed -eq $false -and $handoff.quarantine_policy.interpret_before_size_digest_signature_verification -eq $false) "RC10-011 must not repair drift, fetch, install, activate, rollback, or interpret payload bytes." ([ordered]@{ install_performed = $denial.side_effects.install_performed; activation_performed = $denial.side_effects.activation_performed; rollback_execution_performed = $denial.side_effects.rollback_execution_performed })

$failedChecks = @($script:checks | Where-Object { $_.status -ne "passed" })
$result = [ordered]@{
    schema = "agentos.rc10-artifact-drift-zero-reconciliation-result.v1"
    generated_at = $generatedAt
    task = "RC10-011"
    status = if ($failedChecks.Count -eq 0) { "passed" } else { "failed" }
    production_ready_claim = $false
    release_id = $releaseId
    reconciliation_surface = [ordered]@{
        state = $reconciliationState
        drift_zero = $driftZero
        drift_count = $sourceDriftCount
        comparisons = $sourceComparisonCount
        matched = $sourceMatchedCount
        publication_state = $publicationState
        external_object_trust_allowed = $driftZero
        installer_quarantine_fetch_allowed = $driftZero
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        blockers = $driftBlockers
        downstream_execution_blockers = $downstreamBlockers
    }
    outputs = [ordered]@{
        reconciliation = [ordered]@{
            path = Get-StablePath $reconciliationPath
            sha256 = Get-FileSha256 $reconciliationPath
        }
        denial = [ordered]@{
            path = Get-StablePath $denialPath
            sha256 = Get-FileSha256 $denialPath
        }
        installer_handoff = [ordered]@{
            path = Get-StablePath $handoffPath
            sha256 = Get-FileSha256 $handoffPath
        }
    }
    source = $source
    invariants = [ordered]@{
        mirror_metadata_only = $true
        mirror_large_payload_storage_used = $false
        signer_separate_from_mirror = $true
        local_private_key_material_used = $false
        private_key_material_read_or_printed = $false
        cryptographic_signing_performed = $false
        payload_bytes_uploaded = $false
        remote_payload_bytes_downloaded = $false
        drift_repair_performed = $false
        declared_metadata_rewritten = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        canary_execution_performed = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        frontend_authority = $false
        model_replay_authority = $false
        normal_shell_authority = $false
        tui_authority = $false
        production_ready_claim = $false
    }
    checks = $script:checks
    blockers = @($driftBlockers + $downstreamBlockers)
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = $failedChecks.Count
        drift_count = $sourceDriftCount
        drift_zero_denied_as_expected = (-not $driftZero)
        rc10_011_complete = ($failedChecks.Count -eq 0)
        next_task = "RC10-012"
    }
}

Write-Json $result $resultPath

$resultSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath))
if (-not $resultSecretSafe) {
    throw "Sensitive marker detected in RC10-011 result."
}

Write-Host "RC10 drift-zero reconciliation $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Reconciliation state: $reconciliationState"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $($failedChecks.Count), drift count: $sourceDriftCount"

if ($FailOnFailedChecks -and $failedChecks.Count -gt 0) {
    exit 1
}
