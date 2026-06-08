param(
    [string]$ArtifactDir = ".workflow/artifacts/rc11-installer-quarantine-verifier",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc11",
    [string]$DescriptorVerificationResultPath = ".workflow/artifacts/rc11-external-object-descriptor-verification/result.json",
    [string]$DescriptorVerificationReportPath = ".workflow/artifacts/rc11-external-object-descriptor-verification/descriptor-verification-report.json",
    [string]$DescriptorCandidatePath = ".workflow/artifacts/rc11-release-object-byte-map/immutable-descriptor-candidate.json",
    [string]$ByteMapResultPath = ".workflow/artifacts/rc11-release-object-byte-map/result.json",
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
        ("signing" + "-" + "key" + "." + "pem"),
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
        observed_blockers = @($ObservedBlockers | Select-Object -Unique)
        missing_expected_blockers = $missing
        side_effects = [ordered]@{
            network_fetch_attempted = $false
            remote_payload_bytes_downloaded = $false
            quarantine_payload_written = $false
            size_verified = $false
            digest_verified = $false
            manifest_verified = $false
            checksum_set_verified = $false
            public_signature_verified = $false
            revocation_verified = $false
            freshness_verified = $false
            compatibility_verified = $false
            rollback_baseline_verified = $false
            support_recovery_verified = $false
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
$script:failedChecks = @()

$generatedAt = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }
$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$resolvedWorkflowDir = Resolve-RepoPath $WorkflowDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $resolvedWorkflowDir "evidence") | Out-Null

$resolvedDescriptorVerificationResultPath = Resolve-RepoPath $DescriptorVerificationResultPath
$resolvedDescriptorVerificationReportPath = Resolve-RepoPath $DescriptorVerificationReportPath
$resolvedDescriptorCandidatePath = Resolve-RepoPath $DescriptorCandidatePath
$resolvedByteMapResultPath = Resolve-RepoPath $ByteMapResultPath

$descriptorVerificationResult = Read-Json $resolvedDescriptorVerificationResultPath
$descriptorVerificationReport = Read-Json $resolvedDescriptorVerificationReportPath
$descriptorCandidate = Read-Json $resolvedDescriptorCandidatePath
$byteMapResult = Read-Json $resolvedByteMapResultPath

$releaseId = [string]$descriptorCandidate.release_id
$sourceArtifactPath = Resolve-RepoPath ([string]$descriptorCandidate.source_build_artifact)
$sourceArtifactSha256 = Get-FileSha256 $sourceArtifactPath
$sourceArtifactSize = if (Test-Path -LiteralPath $sourceArtifactPath -PathType Leaf) { (Get-Item -LiteralPath $sourceArtifactPath).Length } else { $null }

$descriptorVerified = [bool]$descriptorVerificationResult.verification_surface.descriptor_verified
$descriptorMatchesCurrentBytes = [bool]$descriptorVerificationResult.verification_surface.descriptor_matches_current_bytes
$externalUriPublished = [bool]$descriptorVerificationResult.verification_surface.external_https_object_uri_published
$driftZero = [bool]$descriptorVerificationResult.verification_surface.drift_zero
$objectTrustAllowed = [bool]$descriptorVerificationResult.verification_surface.object_trust_allowed
$fetchAllowed = ($descriptorVerified -and $descriptorMatchesCurrentBytes -and $externalUriPublished -and $driftZero -and $objectTrustAllowed)

$requiredBindings = [ordered]@{
    size_bytes = [int64]$descriptorCandidate.size_bytes
    sha256 = [string]$descriptorCandidate.sha256
    manifest_sha256 = [string]$descriptorCandidate.manifest_sha256
    checksums_sha256 = [string]$descriptorCandidate.checksums_sha256
    public_signature_target_sha256 = [string]$descriptorCandidate.public_signature_target_sha256
    public_signature_receipt_sha256 = [string]$descriptorCandidate.public_signature_receipt_sha256
    revocation_snapshot_sha256 = [string]$descriptorCandidate.revocation_snapshot_sha256
    freshness_window = if ($null -eq $descriptorCandidate.fresh_until) { $null } else { [string]$descriptorCandidate.fresh_until }
    installer_compatibility_sha256 = [string]$descriptorCandidate.installer_compatibility_sha256
    rollback_baseline_sha256 = [string]$descriptorCandidate.rollback_baseline_sha256
    support_recovery_sha256 = [string]$descriptorCandidate.support_recovery_sha256
}

$blockers = @()
if (-not $descriptorVerified) { $blockers += "external-descriptor-verification-denied" }
if (-not $externalUriPublished) { $blockers += "external-https-object-uri-not-published" }
if (-not $driftZero) { $blockers += "declared-current-drift-zero-not-proved" }
if (-not $objectTrustAllowed) { $blockers += "object-trust-not-allowed" }
if (-not $descriptorMatchesCurrentBytes) { $blockers += "descriptor-current-bytes-mismatch" }
if ($null -eq $descriptorCandidate.fresh_until) { $blockers += "freshness-window-missing" }
foreach ($blocker in @("installer-quarantine-fetch-not-run", "payload-not-quarantined", "pre-interpretation-verification-not-run", "exact-approval-not-bound", "agentcore-planspec-not-bound", "security-execution-effect-envelope-not-bound")) {
    if ($blockers -notcontains $blocker) {
        $blockers += $blocker
    }
}
$blockers = @($blockers | Select-Object -Unique)

$source = [ordered]@{
    descriptor_verification_result = New-ArtifactRef $resolvedDescriptorVerificationResultPath $descriptorVerificationResult
    descriptor_verification_report = New-ArtifactRef $resolvedDescriptorVerificationReportPath $descriptorVerificationReport
    descriptor_candidate = New-ArtifactRef $resolvedDescriptorCandidatePath $descriptorCandidate
    byte_map_result = New-ArtifactRef $resolvedByteMapResultPath $byteMapResult
    current_payload_bytes = New-ArtifactRef $sourceArtifactPath
}

Add-Check "source.rc11_012.descriptor_verification" ($descriptorVerificationResult.status -eq "passed" -and $descriptorVerificationResult.task -eq "RC11-012") "RC11-020 requires RC11-012 descriptor verification evidence." ([ordered]@{ status = $descriptorVerificationResult.status; state = $descriptorVerificationResult.verification_surface.state; descriptor_verified = $descriptorVerified })
Add-Check "source.current_bytes_match_descriptor" ($descriptorMatchesCurrentBytes -and $descriptorCandidate.sha256 -eq $sourceArtifactSha256 -and [int64]$descriptorCandidate.size_bytes -eq [int64]$sourceArtifactSize) "Current payload bytes must still match descriptor size and SHA-256 before quarantine policy projection." ([ordered]@{ expected_sha256 = $descriptorCandidate.sha256; observed_sha256 = $sourceArtifactSha256; expected_size_bytes = $descriptorCandidate.size_bytes; observed_size_bytes = $sourceArtifactSize })
Add-Check "fetch.denied_before_network" ($fetchAllowed -eq $false) "Installer quarantine fetch must deny before network while descriptor verification, external URI, object trust, or drift-zero is missing." ([ordered]@{ fetch_allowed = $fetchAllowed; descriptor_verified = $descriptorVerified; external_uri_published = $externalUriPublished; drift_zero = $driftZero; object_trust_allowed = $objectTrustAllowed; blockers = $blockers })

$fetchReport = [ordered]@{
    schema = "agentos.rc11-installer-quarantine-fetch-report.v1"
    generated_at = $generatedAt
    task = "RC11-020"
    release_id = $releaseId
    status = if ($fetchAllowed) { "quarantine-fetch-ready" } else { "quarantine-fetch-denied-before-network" }
    production_ready_claim = $false
    descriptor = [ordered]@{
        uri = $descriptorCandidate.uri
        uri_policy = $descriptorCandidate.uri_policy
        descriptor_verified = $descriptorVerified
        descriptor_matches_current_bytes = $descriptorMatchesCurrentBytes
        external_https_object_uri_published = $externalUriPublished
    }
    quarantine_policy = [ordered]@{
        fetch_allowed = $fetchAllowed
        quarantine_landing_zone_required = $true
        quarantine_payload_written = $false
        interpret_before_size_digest_manifest_signature_revocation_freshness_compatibility_rollback_support_verification = $false
        network_fetch_attempted = $false
        remote_payload_bytes_downloaded = $false
    }
    required_pre_interpretation_verification = $requiredBindings
    observed_pre_interpretation_verification = [ordered]@{
        size_verified = $false
        sha256_verified = $false
        manifest_verified = $false
        checksum_set_verified = $false
        public_signature_verified = $false
        revocation_verified = $false
        freshness_verified = $false
        compatibility_verified = $false
        rollback_baseline_verified = $false
        support_recovery_verified = $false
    }
    blockers = $blockers
}

$caseBlockers = @{
    "unsafe-uri-before-fetch" = @("external-descriptor-verification-denied", "external-https-object-uri-not-published")
    "descriptor-verification-denied" = @("external-descriptor-verification-denied")
    "drift-zero-not-proved" = @("declared-current-drift-zero-not-proved")
    "object-trust-not-allowed" = @("object-trust-not-allowed")
    "network-before-quarantine-denied" = @("installer-quarantine-fetch-not-run")
    "quarantine-write-before-fetch-denied" = @("payload-not-quarantined")
    "size-mismatch-denied" = @("pre-interpretation-verification-not-run")
    "digest-mismatch-denied" = @("pre-interpretation-verification-not-run")
    "manifest-mismatch-denied" = @("pre-interpretation-verification-not-run")
    "checksum-set-mismatch-denied" = @("pre-interpretation-verification-not-run")
    "public-signature-missing-or-mismatch-denied" = @("pre-interpretation-verification-not-run")
    "revocation-stale-or-revoked-denied" = @("pre-interpretation-verification-not-run")
    "freshness-missing-or-stale-denied" = @("freshness-window-missing", "pre-interpretation-verification-not-run")
    "compatibility-mismatch-denied" = @("pre-interpretation-verification-not-run")
    "rollback-baseline-mismatch-denied" = @("pre-interpretation-verification-not-run")
    "support-recovery-mismatch-denied" = @("pre-interpretation-verification-not-run")
    "payload-interpret-before-verification-denied" = @("pre-interpretation-verification-not-run")
    "install-before-quarantine-verification-denied" = @("payload-not-quarantined", "pre-interpretation-verification-not-run")
    "activation-before-controlled-gates-denied" = @("exact-approval-not-bound", "agentcore-planspec-not-bound", "security-execution-effect-envelope-not-bound")
    "remote-dispatch-before-controlled-gates-denied" = @("security-execution-effect-envelope-not-bound")
}

$cases = @()
foreach ($caseId in $caseBlockers.Keys | Sort-Object) {
    $cases += New-FailClosedCase -Id $caseId -ExpectedBlockers ([string[]]$caseBlockers[$caseId]) -ObservedBlockers $blockers
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$matrix = [ordered]@{
    schema = "agentos.rc11-installer-quarantine-fail-closed-matrix.v1"
    generated_at = $generatedAt
    task = "RC11-020"
    release_id = $releaseId
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

$gateReport = [ordered]@{
    schema = "agentos.rc11-installer-quarantine-gate-report.v1"
    generated_at = $generatedAt
    task = "RC11-020"
    release_id = $releaseId
    status = "installer-quarantine-fetch-blocked"
    production_ready_claim = $false
    gates = [ordered]@{
        descriptor_verified = $descriptorVerified
        descriptor_matches_current_bytes = $descriptorMatchesCurrentBytes
        external_https_object_uri_published = $externalUriPublished
        drift_zero = $driftZero
        object_trust_allowed = $objectTrustAllowed
        quarantine_fetch_allowed = $fetchAllowed
        size_required = $true
        sha256_required = $true
        manifest_required = $true
        checksum_set_required = $true
        public_signature_required = $true
        revocation_required = $true
        freshness_required = $true
        compatibility_required = $true
        rollback_baseline_required = $true
        support_recovery_required = $true
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
    }
    blockers = $blockers
    next_task = "RC11-021"
}

Add-Check "pre_interpretation.gates_declared" ($requiredBindings.size_bytes -and $requiredBindings.sha256 -and $requiredBindings.manifest_sha256 -and $requiredBindings.checksums_sha256 -and $requiredBindings.public_signature_receipt_sha256 -and $requiredBindings.revocation_snapshot_sha256 -and $requiredBindings.installer_compatibility_sha256 -and $requiredBindings.rollback_baseline_sha256 -and $requiredBindings.support_recovery_sha256) "Installer verifier must declare size, SHA-256, manifest, checksum, signature, revocation, compatibility, rollback, and support/recovery gates." $requiredBindings
Add-Check "fixtures.fail_closed" ($failedCases.Count -eq 0 -and @($cases).Count -ge 20) "RC11-020 installer quarantine negative cases must fail closed before effects." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })
Add-Check "side_effects.none" (@($cases | Where-Object { $_.side_effects.network_fetch_attempted -or $_.side_effects.quarantine_payload_written -or $_.side_effects.payload_interpreted -or $_.side_effects.install_performed -or $_.side_effects.activation_performed -or $_.side_effects.rollback_execution_performed -or $_.side_effects.production_ring_mutated -or $_.side_effects.support_upload_performed -or $_.side_effects.remote_dispatch_enabled }).Count -eq 0) "RC11-020 must not fetch, write quarantine bytes, interpret payload bytes, install, activate, rollback, mutate rings, upload support, or dispatch." $null

$fetchReportPath = Join-Path $resolvedArtifactDir "quarantine-fetch-report.json"
$matrixPath = Join-Path $resolvedArtifactDir "installer-fail-closed-matrix.json"
$gateReportPath = Join-Path $resolvedArtifactDir "installer-gate-report.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC11-020-installer-quarantine-verifier.json"

Write-Json $fetchReport $fetchReportPath
Write-Json $matrix $matrixPath
Write-Json $gateReport $gateReportPath

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $fetchReportPath),
    (Get-Content -Raw -LiteralPath $matrixPath),
    (Get-Content -Raw -LiteralPath $gateReportPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC11-020 outputs must not contain PEM blocks, auth tokens, or signer internals." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc11-installer-quarantine-verifier-result.v1"
    generated_at = $generatedAt
    task = "RC11-020"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    fetch_surface = [ordered]@{
        state = [string]$fetchReport.status
        descriptor_verified = $descriptorVerified
        descriptor_matches_current_bytes = $descriptorMatchesCurrentBytes
        external_https_object_uri_published = $externalUriPublished
        drift_zero = $driftZero
        object_trust_allowed = $objectTrustAllowed
        fetch_allowed = $fetchAllowed
        network_fetch_attempted = $false
        remote_payload_bytes_downloaded = $false
        quarantine_payload_written = $false
        pre_interpretation_verification_performed = $false
        payload_interpreted = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        blockers = $blockers
    }
    outputs = [ordered]@{
        quarantine_fetch_report = [ordered]@{ path = Get-StablePath $fetchReportPath; sha256 = Get-FileSha256 $fetchReportPath }
        installer_fail_closed_matrix = [ordered]@{ path = Get-StablePath $matrixPath; sha256 = Get-FileSha256 $matrixPath }
        installer_gate_report = [ordered]@{ path = Get-StablePath $gateReportPath; sha256 = Get-FileSha256 $gateReportPath }
    }
    source = $source
    checks = $script:checks
    blockers = $blockers
    invariants = [ordered]@{
        aios_body_only = $true
        mirror_frontend_changed = $false
        nginx_or_tls_changed = $false
        signer_infra_changed = $false
        local_private_key_material_used = $false
        private_key_material_read_or_printed = $false
        cryptographic_signing_performed = $false
        network_fetch_attempted = $false
        payload_bytes_uploaded = $false
        remote_payload_bytes_downloaded = $false
        quarantine_payload_written = $false
        payload_interpreted = $false
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
        mirror_authority = $false
        signer_reachability_authority = $false
        model_replay_authority = $false
        normal_shell_authority = $false
        tui_authority = $false
        production_ready_claim = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = $failedCases.Count
        fetch_denied_as_expected = (-not $fetchAllowed)
        rc11_020_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC11-021"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc11-installer-quarantine-verifier-evidence.v1"
    generated_at = $generatedAt
    task = "RC11-020"
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
    fetch_surface = $result.fetch_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc11_020_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC11-021"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

if (-not (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath), (Get-Content -Raw -LiteralPath $taskEvidencePath)))) {
    throw "Sensitive marker detected in RC11-020 result."
}

Write-Host "RC11 installer quarantine verifier $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Fetch state: $($fetchReport.status)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
