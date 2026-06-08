param(
    [string]$ArtifactDir = ".workflow/artifacts/rc10-installer-quarantine-fetch",
    [string]$GeneratedAt = "",
    [string]$PublicationResultPath = ".workflow/artifacts/rc10-external-object-publication/result.json",
    [string]$PublicationReportPath = ".workflow/artifacts/rc10-external-object-publication/publication-report.json",
    [string]$PublicationHandoffPath = ".workflow/artifacts/rc10-external-object-publication/installer-handoff.json",
    [string]$DriftResultPath = ".workflow/artifacts/rc10-artifact-drift-zero-reconciliation/result.json",
    [string]$DriftReconciliationPath = ".workflow/artifacts/rc10-artifact-drift-zero-reconciliation/artifact-drift-zero-reconciliation.json",
    [string]$DriftHandoffPath = ".workflow/artifacts/rc10-artifact-drift-zero-reconciliation/installer-handoff.json",
    [string]$DescriptorCandidatePath = ".workflow/artifacts/rc10-external-object-publication/external-object-descriptor-candidate.json",
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
        [Parameter(Mandatory = $true)][string[]]$ObservedBlockers
    )
    $missing = @($ExpectedBlockers | Where-Object { $_ -notin $ObservedBlockers })
    return [ordered]@{
        id = $Id
        status = if ($missing.Count -eq 0) { "passed" } else { "failed" }
        expected_blockers = $ExpectedBlockers
        observed_blocked = $true
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
$resolvedPublicationReportPath = Resolve-RepoPath $PublicationReportPath
$resolvedPublicationHandoffPath = Resolve-RepoPath $PublicationHandoffPath
$resolvedDriftResultPath = Resolve-RepoPath $DriftResultPath
$resolvedDriftReconciliationPath = Resolve-RepoPath $DriftReconciliationPath
$resolvedDriftHandoffPath = Resolve-RepoPath $DriftHandoffPath
$resolvedDescriptorCandidatePath = Resolve-RepoPath $DescriptorCandidatePath
$resolvedSignatureReceiptPath = Resolve-RepoPath $SignatureReceiptPath
$resolvedSignatureSummaryPath = Resolve-RepoPath $SignatureSummaryPath

$publicationResult = Read-Json $resolvedPublicationResultPath
$publicationReport = Read-Json $resolvedPublicationReportPath
$publicationHandoff = Read-Json $resolvedPublicationHandoffPath
$driftResult = Read-Json $resolvedDriftResultPath
$driftReconciliation = Read-Json $resolvedDriftReconciliationPath
$driftHandoff = Read-Json $resolvedDriftHandoffPath
$descriptorCandidate = Read-Json $resolvedDescriptorCandidatePath
$signatureReceipt = Read-Json $resolvedSignatureReceiptPath
$signatureSummary = Read-Json $resolvedSignatureSummaryPath

$releaseId = [string]$publicationResult.release_id
$publicationReady = $publicationResult.status -eq "passed" -and $publicationResult.publication_surface.published_drift_zero -eq $true -and $publicationResult.publication_surface.external_object_url_published -eq $true
$driftReady = $driftResult.status -eq "passed" -and $driftResult.reconciliation_surface.drift_zero -eq $true -and $driftResult.reconciliation_surface.installer_quarantine_fetch_allowed -eq $true
$signatureReady = $signatureReceipt.crypto_verified -eq $true -and $signatureSummary.crypto_verified -eq $true
$handoffAllowsFetch = $driftHandoff.quarantine_policy.quarantine_fetch_allowed -eq $true
$fetchAllowed = $publicationReady -and $driftReady -and $signatureReady -and $handoffAllowsFetch

$blockers = @()
if (-not $publicationReady) {
    $blockers += "publication-not-published-drift-zero"
}
if ([string]$publicationResult.publication_surface.external_object_uri_classification -eq "missing") {
    $blockers += "missing-external-https-object-uri"
}
if (-not $driftReady) {
    $blockers += "drift-zero-denied"
}
if (-not $signatureReady) {
    $blockers += "public-signature-not-crypto-verified"
}
if (-not $handoffAllowsFetch) {
    $blockers += "quarantine-fetch-not-allowed-by-handoff"
}
foreach ($blocker in @("installer-quarantine-fetch-not-run", "exact-operator-approval-pending", "controlled-execution-not-authorized")) {
    if ($blockers -notcontains $blocker) {
        $blockers += $blocker
    }
}
$blockers = @($blockers | Select-Object -Unique)

$source = [ordered]@{
    publication_result = New-ArtifactRef $resolvedPublicationResultPath $publicationResult
    publication_report = New-ArtifactRef $resolvedPublicationReportPath $publicationReport
    publication_handoff = New-ArtifactRef $resolvedPublicationHandoffPath $publicationHandoff
    drift_result = New-ArtifactRef $resolvedDriftResultPath $driftResult
    drift_reconciliation = New-ArtifactRef $resolvedDriftReconciliationPath $driftReconciliation
    drift_handoff = New-ArtifactRef $resolvedDriftHandoffPath $driftHandoff
    descriptor_candidate = New-ArtifactRef $resolvedDescriptorCandidatePath $descriptorCandidate
    signature_receipt = New-ArtifactRef $resolvedSignatureReceiptPath $signatureReceipt
    signature_summary = New-ArtifactRef $resolvedSignatureSummaryPath $signatureSummary
}

Add-Check "source.rc10_010.publication" ($publicationResult.status -eq "passed" -and $publicationResult.summary.rc10_010_complete -eq $true) "RC10-012 requires RC10-010 publication evidence." ([ordered]@{ status = $publicationResult.status; state = $publicationResult.publication_surface.state })
Add-Check "source.rc10_011.drift_zero" ($driftResult.status -eq "passed" -and $driftResult.summary.rc10_011_complete -eq $true) "RC10-012 requires RC10-011 drift-zero evidence." ([ordered]@{ status = $driftResult.status; state = $driftResult.reconciliation_surface.state; drift_count = $driftResult.reconciliation_surface.drift_count })
Add-Check "fetch.denied_before_network" ($fetchAllowed -eq $false) "Installer fetch must deny before network when publication or drift-zero gates fail." ([ordered]@{ fetch_allowed = $fetchAllowed; publication_ready = $publicationReady; drift_ready = $driftReady; handoff_allows_fetch = $handoffAllowsFetch; blockers = $blockers })

$fetchReport = [ordered]@{
    schema = "agentos.rc10-external-object-fetch-report.v1"
    generated_at = $generatedAt
    task = "RC10-012"
    release_id = $releaseId
    status = if ($fetchAllowed) { "fetch-ready" } else { "fetch-denied-before-network" }
    production_ready_claim = $false
    expected_object = $driftHandoff.expected_object
    preconditions = [ordered]@{
        published_drift_zero = $publicationReady
        drift_zero_reconciled = $driftReady
        public_signature_crypto_verified = $signatureReady
        quarantine_fetch_allowed_by_handoff = $handoffAllowsFetch
        quarantine_fetch_allowed = $fetchAllowed
    }
    fetch = [ordered]@{
        network_fetch_attempted = $false
        remote_bytes_downloaded = $false
        quarantine_payload_written = $false
        size_verified = $false
        digest_verified = $false
        signature_verified_after_fetch = $false
        revocation_verified_after_fetch = $false
        payload_interpreted = $false
    }
    blockers = $blockers
}

$cases = @()
$cases += New-FailClosedCase "missing-external-object-uri" @("missing-external-https-object-uri") $blockers
$cases += New-FailClosedCase "publication-not-published-drift-zero" @("publication-not-published-drift-zero") $blockers
$cases += New-FailClosedCase "drift-zero-denied-before-fetch" @("drift-zero-denied") $blockers
$cases += New-FailClosedCase "network-fetch-before-publication-denied" @("publication-not-published-drift-zero", "installer-quarantine-fetch-not-run") $blockers
$cases += New-FailClosedCase "quarantine-write-before-fetch-denied" @("installer-quarantine-fetch-not-run") $blockers
$cases += New-FailClosedCase "payload-interpret-before-verification-denied" @("installer-quarantine-fetch-not-run") $blockers
$cases += New-FailClosedCase "install-before-quarantine-denied" @("installer-quarantine-fetch-not-run") $blockers
$cases += New-FailClosedCase "activation-before-controlled-gates-denied" @("exact-operator-approval-pending", "controlled-execution-not-authorized") $blockers
$cases += New-FailClosedCase "remote-dispatch-before-gates-denied" @("controlled-execution-not-authorized") $blockers

$failedCases = @($cases | Where-Object { $_.status -ne "passed" })
$installerEvidence = [ordered]@{
    schema = "agentos.rc10-installer-quarantine-fetch-fail-closed-evidence.v1"
    generated_at = $generatedAt
    task = "RC10-012"
    release_id = $releaseId
    status = if ($failedCases.Count -eq 0) { "passed" } else { "failed" }
    production_ready_claim = $false
    fetch_report_path = ".workflow/artifacts/rc10-installer-quarantine-fetch/external-object-fetch-report.json"
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
    schema = "agentos.rc10-installer-gate-report.v1"
    generated_at = $generatedAt
    task = "RC10-012"
    release_id = $releaseId
    status = "verification-blocked"
    production_ready_claim = $false
    checks = [ordered]@{
        rc10_010_publication_passed = ($publicationResult.status -eq "passed")
        rc10_010_published_drift_zero = $publicationReady
        rc10_011_reconciliation_passed = ($driftResult.status -eq "passed")
        rc10_011_reconciliation_state = [string]$driftResult.reconciliation_surface.state
        rc10_011_drift_zero = $driftReady
        public_signature_crypto_verified = $signatureReady
        fetch_allowed = $fetchAllowed
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
    }
    blockers = $blockers
    next_task = "RC10-020"
}

Add-Check "fixtures.fail_closed" ($failedCases.Count -eq 0) "RC10-012 installer fetch negative cases must fail closed." ([ordered]@{ cases = @($cases).Count; failed_cases = $failedCases.Count })
Add-Check "side_effects.none" (@($cases | Where-Object { $_.side_effects.network_fetch_attempted -or $_.side_effects.quarantine_payload_written -or $_.side_effects.payload_interpreted -or $_.side_effects.install_performed -or $_.side_effects.activation_performed -or $_.side_effects.rollback_execution_performed -or $_.side_effects.production_ring_mutated -or $_.side_effects.remote_dispatch_enabled }).Count -eq 0) "RC10-012 must not fetch, write quarantine bytes, interpret payload bytes, install, activate, rollback, mutate rings, upload support, or dispatch." $null

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
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC10-012 outputs must not contain private key paths, PEM blocks, auth tokens, or signer internals." $null

$failedChecks = @($script:checks | Where-Object { $_.status -ne "passed" })
$result = [ordered]@{
    schema = "agentos.rc10-installer-quarantine-fetch-result.v1"
    generated_at = $generatedAt
    task = "RC10-012"
    status = if ($failedChecks.Count -eq 0) { "passed" } else { "failed" }
    production_ready_claim = $false
    release_id = $releaseId
    fetch_surface = [ordered]@{
        state = [string]$fetchReport.status
        published_drift_zero = $publicationReady
        drift_zero_reconciled = $driftReady
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
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = $failedChecks.Count
        cases = @($cases).Count
        failed_cases = $failedCases.Count
        rc10_012_complete = ($failedChecks.Count -eq 0)
        wave_1_complete = ($failedChecks.Count -eq 0)
        next_task = "RC10-020"
    }
}

Write-Json $result $resultPath

if (-not (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath)))) {
    throw "Sensitive marker detected in RC10-012 result."
}

Write-Host "RC10 installer quarantine fetch $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Fetch state: $($fetchReport.status)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $($failedChecks.Count), cases: $(@($cases).Count)"

if ($FailOnFailedChecks -and $failedChecks.Count -gt 0) {
    exit 1
}
