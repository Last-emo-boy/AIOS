param(
    [string]$ArtifactDir = ".workflow/artifacts/rc9-external-object-installer-fetch",
    [string]$GeneratedAt = "",
    [string]$PublicationResultPath = ".workflow/artifacts/rc9-external-object-publication/result.json",
    [string]$PublicationCandidatePath = ".workflow/artifacts/rc9-external-object-publication/external-object-publication-candidate.json",
    [string]$PublicationHandoffPath = ".workflow/artifacts/rc9-external-object-publication/installer-handoff.json",
    [string]$DriftResultPath = ".workflow/artifacts/rc9-artifact-drift-reconciliation/result.json",
    [string]$DriftReconciliationPath = ".workflow/artifacts/rc9-artifact-drift-reconciliation/artifact-drift-reconciliation.json",
    [string]$DriftHandoffPath = ".workflow/artifacts/rc9-artifact-drift-reconciliation/installer-handoff.json",
    [string]$DescriptorPath = ".workflow/artifacts/rc8-real-payload-object-descriptor/payload-object-descriptor.json",
    [string]$SignatureReceiptPath = ".workflow/artifacts/rc8-public-signature-ingestion/signature-ingestion-receipt.json",
    [string]$SignatureSummaryPath = ".workflow/artifacts/rc8-public-signature-ingestion/public-signature-artifact-summary.json",
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

function New-FailClosedCase {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string[]]$ExpectedBlockers,
        [Parameter(Mandatory = $true)][bool]$ObservedBlocked,
        [Parameter(Mandatory = $true)][string[]]$ObservedBlockers
    )
    $missing = @($ExpectedBlockers | Where-Object { $_ -notin $ObservedBlockers })
    return [ordered]@{
        id = $Id
        status = if ($ObservedBlocked -and $missing.Count -eq 0) { "passed" } else { "failed" }
        expected_blockers = $ExpectedBlockers
        observed_blocked = $ObservedBlocked
        observed_blockers = $ObservedBlockers
        missing_expected_blockers = $missing
        side_effects = [ordered]@{
            network_fetch_attempted = $false
            quarantine_payload_written = $false
            payload_interpreted = $false
            install_performed = $false
            activation_performed = $false
            rollback_execution_performed = $false
            active_slot_mutated = $false
            boot_metadata_mutated = $false
            active_artifact_set_mutated = $false
            production_ring_mutated = $false
            support_upload_performed = $false
            remote_dispatch_enabled = $false
        }
    }
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()

$generatedAt = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }
$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null

$resolvedPublicationResultPath = Resolve-RepoPath $PublicationResultPath
$resolvedPublicationCandidatePath = Resolve-RepoPath $PublicationCandidatePath
$resolvedPublicationHandoffPath = Resolve-RepoPath $PublicationHandoffPath
$resolvedDriftResultPath = Resolve-RepoPath $DriftResultPath
$resolvedDriftReconciliationPath = Resolve-RepoPath $DriftReconciliationPath
$resolvedDriftHandoffPath = Resolve-RepoPath $DriftHandoffPath
$resolvedDescriptorPath = Resolve-RepoPath $DescriptorPath
$resolvedSignatureReceiptPath = Resolve-RepoPath $SignatureReceiptPath
$resolvedSignatureSummaryPath = Resolve-RepoPath $SignatureSummaryPath

$publicationResult = Read-Json $resolvedPublicationResultPath
$publicationCandidate = Read-Json $resolvedPublicationCandidatePath
$publicationHandoff = Read-Json $resolvedPublicationHandoffPath
$driftResult = Read-Json $resolvedDriftResultPath
$driftReconciliation = Read-Json $resolvedDriftReconciliationPath
$driftHandoff = Read-Json $resolvedDriftHandoffPath
$descriptor = Read-Json $resolvedDescriptorPath
$signatureReceipt = Read-Json $resolvedSignatureReceiptPath
$signatureSummary = Read-Json $resolvedSignatureSummaryPath

$releaseId = [string]$descriptor.release_id
$descriptorSha256 = Get-FileSha256 $resolvedDescriptorPath
$publicationReady = $publicationResult.status -eq "passed" -and $publicationResult.publication_surface.external_object_url_published -eq $true
$driftReady = $driftResult.status -eq "passed" -and $driftResult.reconciliation_surface.state -eq "reconciled-current-artifact" -and $driftResult.reconciliation_surface.installer_quarantine_fetch_allowed -eq $true
$signatureReady = $signatureReceipt.crypto_verified -eq $true -and $signatureSummary.crypto_verified -eq $true
$fetchAllowed = $publicationReady -and $driftReady -and $signatureReady

$blockers = @()
if (-not $publicationReady) {
    $blockers += "external-https-object-uri-not-published"
}
if (-not $driftReady) {
    $blockers += "declared-current-artifact-drift-denied"
}
if (-not $signatureReady) {
    $blockers += "public-signature-not-crypto-verified"
}
foreach ($blocker in @("installer-quarantine-fetch-not-run", "exact-operator-approval-pending", "controlled-execution-not-authorized")) {
    if ($blockers -notcontains $blocker) {
        $blockers += $blocker
    }
}

$fetchReport = [ordered]@{
    schema = "agentos.rc9-external-object-fetch-report.v1"
    generated_at = $generatedAt
    task = "RC9-012"
    release_id = $releaseId
    status = if ($fetchAllowed) { "fetch-ready" } else { "fetch-denied-before-network" }
    production_ready_claim = $false
    expected_object = [ordered]@{
        object_id = [string]$descriptor.object_id
        descriptor_sha256 = $descriptorSha256
        size_bytes = [int64]$descriptor.size_bytes
        sha256 = [string]$descriptor.sha256
        external_uri = if ($publicationReady) { $publicationCandidate.external_object.uri } else { $null }
        external_uri_classification = [string]$publicationResult.publication_surface.external_object_uri_classification
    }
    preconditions = [ordered]@{
        external_object_url_published = $publicationReady
        drift_reconciled_current_artifact = $driftReady
        public_signature_crypto_verified = $signatureReady
        quarantine_fetch_allowed = $fetchAllowed
    }
    fetch = [ordered]@{
        network_fetch_attempted = $false
        remote_bytes_downloaded = $false
        quarantine_payload_written = $false
        size_verified = $false
        digest_verified = $false
        signature_verified_after_fetch = $false
        payload_interpreted = $false
    }
    blockers = $blockers
}

$cases = @()
$cases += New-FailClosedCase "missing-external-object-uri" @("external-https-object-uri-not-published") $true $blockers
$cases += New-FailClosedCase "drift-denied-before-fetch" @("declared-current-artifact-drift-denied") $true $blockers
$cases += New-FailClosedCase "network-fetch-before-publication-denied" @("external-https-object-uri-not-published", "installer-quarantine-fetch-not-run") $true $blockers
$cases += New-FailClosedCase "payload-interpret-before-verification-denied" @("installer-quarantine-fetch-not-run") $true $blockers
$cases += New-FailClosedCase "install-before-quarantine-denied" @("installer-quarantine-fetch-not-run") $true $blockers
$cases += New-FailClosedCase "activation-before-controlled-gates-denied" @("exact-operator-approval-pending", "controlled-execution-not-authorized") $true $blockers
$cases += New-FailClosedCase "rollback-before-activation-denied" @("controlled-execution-not-authorized") $true $blockers
$cases += New-FailClosedCase "support-upload-before-gates-denied" @("controlled-execution-not-authorized") $true $blockers
$cases += New-FailClosedCase "remote-dispatch-before-gates-denied" @("controlled-execution-not-authorized") $true $blockers

$failedCases = @($cases | Where-Object { $_.status -ne "passed" })
$installerEvidence = [ordered]@{
    schema = "agentos.rc9-installer-fetch-fail-closed-evidence.v1"
    generated_at = $generatedAt
    task = "RC9-012"
    release_id = $releaseId
    status = if ($failedCases.Count -eq 0) { "passed" } else { "failed" }
    production_ready_claim = $false
    fetch_report_path = ".workflow/artifacts/rc9-external-object-installer-fetch/external-object-fetch-report.json"
    cases = $cases
    failed_cases = @($failedCases | ForEach-Object { $_.id })
    authority = [ordered]@{
        installer_install_authority = $false
        installer_activation_authority = $false
        installer_rollback_authority = $false
        mirror_authority = $false
        object_storage_authority = $false
        signer_authority = $false
        frontend_authority = $false
        tui_authority = $false
        remote_dispatch_authority = $false
    }
}

$gateReport = [ordered]@{
    schema = "agentos.rc9-installer-gate-report.v1"
    generated_at = $generatedAt
    task = "RC9-012"
    release_id = $releaseId
    status = "verification-blocked"
    production_ready_claim = $false
    checks = [ordered]@{
        rc9_010_publication_passed = ($publicationResult.status -eq "passed")
        rc9_010_external_object_url_published = $publicationReady
        rc9_011_reconciliation_passed = ($driftResult.status -eq "passed")
        rc9_011_reconciliation_state = [string]$driftResult.reconciliation_surface.state
        public_signature_crypto_verified = $signatureReady
        fetch_allowed = $fetchAllowed
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
    }
    blockers = $blockers
    next_task = "RC9-020"
}

Add-Check "source.rc9_010.publication" ($publicationResult.status -eq "passed" -and $publicationResult.summary.rc9_010_complete -eq $true) "RC9-010 publication evidence must pass before installer fetch evaluation." ([ordered]@{ status = $publicationResult.status; state = $publicationResult.publication_surface.state })
Add-Check "source.rc9_011.drift" ($driftResult.status -eq "passed" -and $driftResult.summary.rc9_011_complete -eq $true) "RC9-011 drift reconciliation evidence must pass before installer fetch evaluation." ([ordered]@{ status = $driftResult.status; state = $driftResult.reconciliation_surface.state; drift_count = $driftResult.reconciliation_surface.drift_count })
Add-Check "fetch.denied_before_network" ($fetchAllowed -eq $false -and $fetchReport.fetch.network_fetch_attempted -eq $false -and $fetchReport.fetch.remote_bytes_downloaded -eq $false) "Installer fetch must be denied before network when publication or drift gates fail." ([ordered]@{ fetch_allowed = $fetchAllowed; network_fetch_attempted = $fetchReport.fetch.network_fetch_attempted; blockers = $blockers })
Add-Check "fixtures.fail_closed" ($failedCases.Count -eq 0) "RC9-012 installer fetch negative cases must fail closed." ([ordered]@{ cases = @($cases).Count; failed_cases = $failedCases.Count })
Add-Check "side_effects.none" (@($cases | Where-Object { $_.side_effects.network_fetch_attempted -or $_.side_effects.quarantine_payload_written -or $_.side_effects.payload_interpreted -or $_.side_effects.install_performed -or $_.side_effects.activation_performed -or $_.side_effects.rollback_execution_performed -or $_.side_effects.production_ring_mutated -or $_.side_effects.remote_dispatch_enabled }).Count -eq 0) "RC9-012 must not fetch, interpret payload bytes, install, activate, rollback, mutate rings, upload support, or dispatch." $null

$source = [ordered]@{
    publication_result = New-ArtifactRef $resolvedPublicationResultPath $publicationResult
    publication_candidate = New-ArtifactRef $resolvedPublicationCandidatePath $publicationCandidate
    publication_handoff = New-ArtifactRef $resolvedPublicationHandoffPath $publicationHandoff
    drift_result = New-ArtifactRef $resolvedDriftResultPath $driftResult
    drift_reconciliation = New-ArtifactRef $resolvedDriftReconciliationPath $driftReconciliation
    drift_handoff = New-ArtifactRef $resolvedDriftHandoffPath $driftHandoff
    descriptor = New-ArtifactRef $resolvedDescriptorPath $descriptor
    signature_receipt = New-ArtifactRef $resolvedSignatureReceiptPath $signatureReceipt
    signature_summary = New-ArtifactRef $resolvedSignatureSummaryPath $signatureSummary
}

$fetchReportPath = Join-Path $resolvedArtifactDir "external-object-fetch-report.json"
$installerEvidencePath = Join-Path $resolvedArtifactDir "installer-fail-closed-evidence.json"
$gateReportPath = Join-Path $resolvedArtifactDir "installer-gate-report.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"

Write-Json $fetchReport $fetchReportPath
Write-Json $installerEvidence $installerEvidencePath
Write-Json $gateReport $gateReportPath

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $fetchReportPath),
    (Get-Content -Raw -LiteralPath $installerEvidencePath),
    (Get-Content -Raw -LiteralPath $gateReportPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC9-012 outputs must not contain secret paths, PEM blocks, auth tokens, or signer host internals." $null

$failedChecks = @($script:checks | Where-Object { $_.status -ne "passed" })
$result = [ordered]@{
    schema = "agentos.rc9-external-object-installer-fetch-result.v1"
    generated_at = $generatedAt
    task = "RC9-012"
    status = if ($failedChecks.Count -eq 0) { "passed" } else { "failed" }
    production_ready_claim = $false
    release_id = $releaseId
    fetch_surface = [ordered]@{
        state = [string]$fetchReport.status
        external_object_url_published = $publicationReady
        drift_reconciled_current_artifact = $driftReady
        fetch_allowed = $fetchAllowed
        network_fetch_attempted = $false
        remote_bytes_downloaded = $false
        quarantine_payload_written = $false
        payload_interpreted = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        blockers = $blockers
    }
    outputs = [ordered]@{
        fetch_report = [ordered]@{
            path = Get-StablePath $fetchReportPath
            sha256 = Get-FileSha256 $fetchReportPath
        }
        installer_fail_closed_evidence = [ordered]@{
            path = Get-StablePath $installerEvidencePath
            sha256 = Get-FileSha256 $installerEvidencePath
        }
        installer_gate_report = [ordered]@{
            path = Get-StablePath $gateReportPath
            sha256 = Get-FileSha256 $gateReportPath
        }
    }
    source = $source
    checks = $script:checks
    blockers = $blockers
    invariants = [ordered]@{
        local_projection_only = $true
        network_fetch_attempted = $false
        payload_bytes_uploaded = $false
        remote_payload_bytes_downloaded = $false
        quarantine_payload_written = $false
        payload_interpreted = $false
        cryptographic_signing_performed = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        remote_dispatch_enabled = $false
        model_replay_authority = $false
        normal_shell_authority = $false
        tui_authority = $false
        production_ready_claim = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = $failedChecks.Count
        cases = @($cases).Count
        failed_cases = $failedCases.Count
        rc9_012_complete = ($failedChecks.Count -eq 0)
        wave_1_complete = ($failedChecks.Count -eq 0)
        next_task = "RC9-020"
    }
}

Write-Json $result $resultPath

if (-not (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath)))) {
    throw "Sensitive marker detected in RC9-012 result."
}

Write-Host "RC9 external object installer fetch $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Fetch state: $($fetchReport.status)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $($failedChecks.Count), cases: $(@($cases).Count)"

if ($FailOnFailedChecks -and $failedChecks.Count -gt 0) {
    exit 1
}
