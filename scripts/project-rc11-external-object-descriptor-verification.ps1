param(
    [string]$ArtifactDir = ".workflow/artifacts/rc11-external-object-descriptor-verification",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc11",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc11/docs/real-object-trust-handoff-contract.md",
    [string]$ByteMapResultPath = ".workflow/artifacts/rc11-release-object-byte-map/result.json",
    [string]$DescriptorCandidatePath = ".workflow/artifacts/rc11-release-object-byte-map/immutable-descriptor-candidate.json",
    [string]$DriftResultPath = ".workflow/artifacts/rc11-declared-current-drift-zero/result.json",
    [string]$DriftHandoffPath = ".workflow/artifacts/rc11-declared-current-drift-zero/external-descriptor-verification-handoff.json",
    [string]$Rc10PublicationResultPath = ".workflow/artifacts/rc10-external-object-publication/result.json",
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

function Copy-JsonObject {
    param([Parameter(Mandatory = $true)]$Value)
    return ($Value | ConvertTo-Json -Depth 100 | ConvertFrom-Json)
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

function Test-DescriptorReference {
    param(
        [Parameter(Mandatory = $true)]$Descriptor,
        [Parameter(Mandatory = $true)][string]$CaseId,
        [bool]$EndpointReachableClaimed = $false
    )

    $reasons = @()
    $uriText = if ($null -eq $Descriptor.uri) { $null } else { [string]$Descriptor.uri }
    $parsedUri = $null

    if ($Descriptor.schema -ne "agentos.payload-object-descriptor.v1") {
        $reasons += "descriptor-schema-invalid"
    }
    if ([string]::IsNullOrWhiteSpace($uriText)) {
        $reasons += "external-https-object-uri-not-published"
    } elseif (-not [Uri]::TryCreate($uriText, [UriKind]::Absolute, [ref]$parsedUri)) {
        $reasons += "object-uri-invalid"
    } else {
        if ($parsedUri.Scheme -ne "https") {
            $reasons += "object-uri-not-https"
        }
        if ($parsedUri.Scheme -eq "file" -or $parsedUri.Host -in @("localhost", "127.0.0.1", "::1")) {
            $reasons += "object-uri-local"
        }
        if ($parsedUri.UserInfo) {
            $reasons += "object-uri-credential-bearing"
        }
        if ($parsedUri.Query) {
            $queryLower = $parsedUri.Query.ToLowerInvariant()
            if ($queryLower.Contains("token") -or $queryLower.Contains("signature") -or $queryLower.Contains("credential") -or $queryLower.Contains("expires") -or $queryLower.Contains("access_key")) {
                $reasons += "object-uri-credential-bearing"
            }
        }
    }

    if ($Descriptor.immutable -ne $true) {
        $reasons += "descriptor-not-immutable"
    }

    if ([string]::IsNullOrWhiteSpace([string]$Descriptor.fresh_until)) {
        $reasons += "freshness-window-missing"
    } else {
        $freshUntil = [DateTimeOffset]::MinValue
        if (-not [DateTimeOffset]::TryParse([string]$Descriptor.fresh_until, [ref]$freshUntil)) {
            $reasons += "freshness-window-invalid"
        } elseif ($freshUntil -le $script:generatedAtOffset) {
            $reasons += "descriptor-stale"
        }
    }

    if ([int64]$Descriptor.size_bytes -ne [int64]$script:sourceArtifactSize) {
        $reasons += "object-size-mismatch"
    }
    if ([string]$Descriptor.sha256 -ne [string]$script:sourceArtifactSha256) {
        $reasons += "object-digest-mismatch"
    }
    if ($Descriptor.production_ready_claim -ne $false) {
        $reasons += "production-ready-claim-forbidden"
    }
    if ($Descriptor.install_allowed -ne $false -or $Descriptor.activation_allowed -ne $false -or $Descriptor.rollback_execution_allowed -ne $false) {
        $reasons += "descriptor-authority-bearing"
    }
    if ($script:driftZero -ne $true) {
        $reasons += "declared-current-drift-zero-not-proved"
    }
    if ($script:externalObjectPublished -ne $true) {
        $reasons += "source-publication-evidence-missing"
    }
    if ($EndpointReachableClaimed) {
        $reasons += "endpoint-reachability-is-not-trust"
    }

    $uniqueReasons = @($reasons | Select-Object -Unique)
    return [ordered]@{
        id = $CaseId
        status = if ($uniqueReasons.Count -eq 0) { "accepted" } else { "denied" }
        denied = ($uniqueReasons.Count -gt 0)
        uri = $uriText
        size_match = ([int64]$Descriptor.size_bytes -eq [int64]$script:sourceArtifactSize)
        digest_match = ([string]$Descriptor.sha256 -eq [string]$script:sourceArtifactSha256)
        drift_zero = $script:driftZero
        endpoint_reachable_claimed = $EndpointReachableClaimed
        denial_reasons = $uniqueReasons
    }
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:failedChecks = @()

$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$resolvedWorkflowDir = Resolve-RepoPath $WorkflowDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $resolvedWorkflowDir "evidence") | Out-Null

$resolvedContractPath = Resolve-RepoPath $ContractPath
$resolvedByteMapResultPath = Resolve-RepoPath $ByteMapResultPath
$resolvedDescriptorCandidatePath = Resolve-RepoPath $DescriptorCandidatePath
$resolvedDriftResultPath = Resolve-RepoPath $DriftResultPath
$resolvedDriftHandoffPath = Resolve-RepoPath $DriftHandoffPath
$resolvedRc10PublicationResultPath = Resolve-RepoPath $Rc10PublicationResultPath

$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$byteMapResult = Read-Json $resolvedByteMapResultPath
$descriptorCandidate = Read-Json $resolvedDescriptorCandidatePath
$driftResult = Read-Json $resolvedDriftResultPath
$driftHandoff = Read-Json $resolvedDriftHandoffPath
$rc10PublicationResult = Read-Json $resolvedRc10PublicationResultPath

$generatedAt = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }
$script:generatedAtOffset = [DateTimeOffset]::Parse($generatedAt)
$releaseId = [string]$descriptorCandidate.release_id
$sourceArtifactPath = Resolve-RepoPath ([string]$descriptorCandidate.source_build_artifact)
$script:sourceArtifactSha256 = Get-FileSha256 $sourceArtifactPath
$script:sourceArtifactSize = if (Test-Path -LiteralPath $sourceArtifactPath -PathType Leaf) { (Get-Item -LiteralPath $sourceArtifactPath).Length } else { $null }
$script:driftZero = [bool]$driftResult.reconciliation_surface.drift_zero
$script:externalObjectPublished = ([bool]$byteMapResult.byte_map_surface.external_https_object_uri_published -and [bool]$rc10PublicationResult.publication_surface.external_object_url_published)

$source = [ordered]@{
    rc11_contract = New-ArtifactRef $resolvedContractPath
    rc11_byte_map_result = New-ArtifactRef $resolvedByteMapResultPath $byteMapResult
    rc11_descriptor_candidate = New-ArtifactRef $resolvedDescriptorCandidatePath $descriptorCandidate
    rc11_drift_result = New-ArtifactRef $resolvedDriftResultPath $driftResult
    rc11_drift_handoff = New-ArtifactRef $resolvedDriftHandoffPath $driftHandoff
    rc10_publication_result = New-ArtifactRef $resolvedRc10PublicationResultPath $rc10PublicationResult
    current_payload_bytes = New-ArtifactRef $sourceArtifactPath
}

Add-Check "contract.descriptor_gate.present" ($contractText.Contains("descriptor URI") -and $contractText.Contains("endpoint reachability used as trust")) "RC11-012 must consume descriptor URI and endpoint-reachability fail-closed requirements." $source.rc11_contract
Add-Check "source.byte_map.passed" ($byteMapResult.status -eq "passed" -and $byteMapResult.task -eq "RC11-010") "RC11-012 requires RC11-010 byte map evidence." ([ordered]@{ status = $byteMapResult.status; task = $byteMapResult.task })
Add-Check "source.drift_result.passed" ($driftResult.status -eq "passed" -and $driftResult.task -eq "RC11-011") "RC11-012 requires RC11-011 drift evidence." ([ordered]@{ status = $driftResult.status; drift_zero = $driftResult.reconciliation_surface.drift_zero; drift_count = $driftResult.reconciliation_surface.drift_count })
Add-Check "source.current_bytes_match_candidate" ($descriptorCandidate.sha256 -eq $script:sourceArtifactSha256 -and [int64]$descriptorCandidate.size_bytes -eq [int64]$script:sourceArtifactSize) "Descriptor candidate must record the current payload bytes even when verification is denied." ([ordered]@{ expected_sha256 = $descriptorCandidate.sha256; observed_sha256 = $script:sourceArtifactSha256; expected_size_bytes = $descriptorCandidate.size_bytes; observed_size_bytes = $script:sourceArtifactSize })

$cases = @()
$cases += [ordered]@{ id = "current.missing_external_uri"; descriptor = $descriptorCandidate; endpoint = $false }

$nonHttps = Copy-JsonObject $descriptorCandidate
$nonHttps.uri = "http://objects.example.invalid/aios.cpio.gz"
$nonHttps.fresh_until = "2026-06-30T00:00:00+08:00"
$cases += [ordered]@{ id = "negative.non_https_uri"; descriptor = $nonHttps; endpoint = $false }

$localFile = Copy-JsonObject $descriptorCandidate
$localFile.uri = "file:///tmp/aios.cpio.gz"
$localFile.fresh_until = "2026-06-30T00:00:00+08:00"
$cases += [ordered]@{ id = "negative.local_file_uri"; descriptor = $localFile; endpoint = $false }

$credentialUserInfo = Copy-JsonObject $descriptorCandidate
$credentialUserInfo.uri = "https://user:pass@objects.example.invalid/aios.cpio.gz"
$credentialUserInfo.fresh_until = "2026-06-30T00:00:00+08:00"
$cases += [ordered]@{ id = "negative.credential_userinfo_uri"; descriptor = $credentialUserInfo; endpoint = $false }

$credentialQuery = Copy-JsonObject $descriptorCandidate
$credentialQuery.uri = "https://objects.example.invalid/aios.cpio.gz?token=redacted"
$credentialQuery.fresh_until = "2026-06-30T00:00:00+08:00"
$cases += [ordered]@{ id = "negative.credential_query_uri"; descriptor = $credentialQuery; endpoint = $false }

$mutable = Copy-JsonObject $descriptorCandidate
$mutable.uri = "https://objects.example.invalid/aios.cpio.gz"
$mutable.fresh_until = "2026-06-30T00:00:00+08:00"
$mutable.immutable = $false
$cases += [ordered]@{ id = "negative.mutable_descriptor"; descriptor = $mutable; endpoint = $false }

$stale = Copy-JsonObject $descriptorCandidate
$stale.uri = "https://objects.example.invalid/aios.cpio.gz"
$stale.fresh_until = "2020-01-01T00:00:00Z"
$cases += [ordered]@{ id = "negative.stale_descriptor"; descriptor = $stale; endpoint = $false }

$sizeMismatch = Copy-JsonObject $descriptorCandidate
$sizeMismatch.uri = "https://objects.example.invalid/aios.cpio.gz"
$sizeMismatch.fresh_until = "2026-06-30T00:00:00+08:00"
$sizeMismatch.size_bytes = [int64]$script:sourceArtifactSize + 1
$cases += [ordered]@{ id = "negative.size_mismatch"; descriptor = $sizeMismatch; endpoint = $false }

$digestMismatch = Copy-JsonObject $descriptorCandidate
$digestMismatch.uri = "https://objects.example.invalid/aios.cpio.gz"
$digestMismatch.fresh_until = "2026-06-30T00:00:00+08:00"
$digestMismatch.sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
$cases += [ordered]@{ id = "negative.digest_mismatch"; descriptor = $digestMismatch; endpoint = $false }

$authorityBearing = Copy-JsonObject $descriptorCandidate
$authorityBearing.uri = "https://objects.example.invalid/aios.cpio.gz"
$authorityBearing.fresh_until = "2026-06-30T00:00:00+08:00"
$authorityBearing.install_allowed = $true
$cases += [ordered]@{ id = "negative.authority_bearing_descriptor"; descriptor = $authorityBearing; endpoint = $false }

$reachableOnly = Copy-JsonObject $descriptorCandidate
$reachableOnly.uri = "https://objects.example.invalid/aios.cpio.gz"
$reachableOnly.fresh_until = "2026-06-30T00:00:00+08:00"
$cases += [ordered]@{ id = "negative.endpoint_reachability_only"; descriptor = $reachableOnly; endpoint = $true }

$validShapeButBlocked = Copy-JsonObject $descriptorCandidate
$validShapeButBlocked.uri = "https://objects.example.invalid/aios.cpio.gz"
$validShapeButBlocked.fresh_until = "2026-06-30T00:00:00+08:00"
$cases += [ordered]@{ id = "negative.valid_https_but_drift_nonzero"; descriptor = $validShapeButBlocked; endpoint = $false }

$caseResults = @()
foreach ($case in $cases) {
    $caseResults += Test-DescriptorReference -Descriptor $case.descriptor -CaseId $case.id -EndpointReachableClaimed ([bool]$case.endpoint)
}
$failedCases = @($caseResults | Where-Object { $_.denied -ne $true })

Add-Check "fail_closed_matrix.all_cases_denied" ($failedCases.Count -eq 0 -and @($caseResults).Count -ge 12) "Verifier must deny unsafe, stale, mismatched, authority-bearing, reachability-only, and drift-blocked descriptor cases." ([ordered]@{ cases = @($caseResults).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })
Add-Check "endpoint.reachability_not_trust" (@($caseResults | Where-Object { $_.id -eq "negative.endpoint_reachability_only" -and $_.denial_reasons -contains "endpoint-reachability-is-not-trust" }).Count -eq 1) "Endpoint reachability must be recorded as non-authoritative." $null

$currentCandidateVerification = Test-DescriptorReference -Descriptor $descriptorCandidate -CaseId "current_candidate" -EndpointReachableClaimed $false
$verificationAllowed = ($currentCandidateVerification.denied -eq $false)
$verificationState = if ($verificationAllowed) { "external-descriptor-verified" } else { "external-descriptor-verification-denied" }

$report = [ordered]@{
    schema = "agentos.rc11-external-object-descriptor-verification-report.v1"
    generated_at = $generatedAt
    task = "RC11-012"
    release_id = $releaseId
    status = $verificationState
    production_ready_claim = $false
    current_candidate = $currentCandidateVerification
    current_bytes = [ordered]@{
        path = Get-StablePath $sourceArtifactPath
        size_bytes = $script:sourceArtifactSize
        sha256 = $script:sourceArtifactSha256
        descriptor_size_match = ([int64]$descriptorCandidate.size_bytes -eq [int64]$script:sourceArtifactSize)
        descriptor_digest_match = ([string]$descriptorCandidate.sha256 -eq [string]$script:sourceArtifactSha256)
    }
    drift_gate = [ordered]@{
        drift_zero = $script:driftZero
        drift_count = [int]$driftResult.reconciliation_surface.drift_count
        external_object_descriptor_verification_allowed = [bool]$driftResult.reconciliation_surface.external_object_descriptor_verification_allowed
    }
    publication_gate = [ordered]@{
        external_object_uri_published = $script:externalObjectPublished
        rc11_external_uri_published = [bool]$byteMapResult.byte_map_surface.external_https_object_uri_published
        rc10_external_uri_published = [bool]$rc10PublicationResult.publication_surface.external_object_url_published
        endpoint_reachability_is_trust = $false
        network_probe_performed = $false
    }
    fail_closed_cases = $caseResults
    source = $source
    trust_decision = [ordered]@{
        descriptor_verified = $verificationAllowed
        object_trust_allowed = $false
        installer_quarantine_fetch_allowed = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
    }
}

$denial = [ordered]@{
    schema = "agentos.rc11-external-object-descriptor-verification-denial.v1"
    generated_at = $generatedAt
    task = "RC11-012"
    release_id = $releaseId
    status = if ($verificationAllowed) { "not-denied" } else { "external-descriptor-verification-denied" }
    production_ready_claim = $false
    denied = (-not $verificationAllowed)
    denial_reasons = $currentCandidateVerification.denial_reasons
    descriptor_matches_current_bytes = ($currentCandidateVerification.size_match -and $currentCandidateVerification.digest_match)
    drift_zero = $script:driftZero
    endpoint_reachability_is_trust = $false
    side_effects = [ordered]@{
        network_probe_performed = $false
        endpoint_reachability_trusted = $false
        payload_bytes_downloaded = $false
        quarantine_payload_written = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        support_upload_performed = $false
        remote_dispatch_enabled = $false
        production_ring_mutated = $false
    }
}

$matrix = [ordered]@{
    schema = "agentos.rc11-external-descriptor-fail-closed-matrix.v1"
    generated_at = $generatedAt
    task = "RC11-012"
    release_id = $releaseId
    status = if ($failedCases.Count -eq 0) { "passed" } else { "failed" }
    cases = $caseResults
    summary = [ordered]@{
        cases = @($caseResults).Count
        denied = @($caseResults | Where-Object { $_.denied -eq $true }).Count
        failed_cases = @($failedCases | ForEach-Object { $_.id })
    }
}

$reportPath = Join-Path $resolvedArtifactDir "descriptor-verification-report.json"
$denialPath = Join-Path $resolvedArtifactDir "descriptor-verification-denial.json"
$matrixPath = Join-Path $resolvedArtifactDir "descriptor-fail-closed-matrix.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC11-012-external-object-descriptor-verification.json"

Write-Json $report $reportPath
Write-Json $denial $denialPath
Write-Json $matrix $matrixPath

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $reportPath),
    (Get-Content -Raw -LiteralPath $denialPath),
    (Get-Content -Raw -LiteralPath $matrixPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC11-012 outputs must not contain PEM blocks, auth tokens, or signer internals." $null
Add-Check "outputs.side_effects_absent" ($denial.side_effects.network_probe_performed -eq $false -and $denial.side_effects.payload_bytes_downloaded -eq $false -and $denial.side_effects.quarantine_payload_written -eq $false -and $denial.side_effects.install_performed -eq $false -and $denial.side_effects.activation_performed -eq $false -and $denial.side_effects.rollback_execution_performed -eq $false -and $denial.side_effects.remote_dispatch_enabled -eq $false -and $denial.side_effects.production_ring_mutated -eq $false) "RC11-012 must not probe network, fetch bytes, quarantine, install, activate, rollback, dispatch, or mutate production rings." $denial.side_effects

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc11-external-object-descriptor-verification-result.v1"
    generated_at = $generatedAt
    task = "RC11-012"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    verification_surface = [ordered]@{
        state = $verificationState
        descriptor_matches_current_bytes = ($currentCandidateVerification.size_match -and $currentCandidateVerification.digest_match)
        current_uri = $descriptorCandidate.uri
        external_https_object_uri_published = $script:externalObjectPublished
        drift_zero = $script:driftZero
        drift_count = [int]$driftResult.reconciliation_surface.drift_count
        descriptor_verified = $verificationAllowed
        fail_closed_cases = @($caseResults).Count
        failed_fail_closed_cases = @($failedCases).Count
        endpoint_reachability_is_trust = $false
        network_probe_performed = $false
        object_trust_allowed = $false
        installer_quarantine_fetch_allowed = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        blockers = @($currentCandidateVerification.denial_reasons + $driftResult.reconciliation_surface.blockers | Select-Object -Unique)
    }
    outputs = [ordered]@{
        report = [ordered]@{ path = Get-StablePath $reportPath; sha256 = Get-FileSha256 $reportPath }
        denial = [ordered]@{ path = Get-StablePath $denialPath; sha256 = Get-FileSha256 $denialPath }
        fail_closed_matrix = [ordered]@{ path = Get-StablePath $matrixPath; sha256 = Get-FileSha256 $matrixPath }
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
        endpoint_reachability_trusted = $false
        network_probe_performed = $false
        payload_bytes_uploaded = $false
        remote_payload_bytes_downloaded = $false
        quarantine_payload_written = $false
        descriptor_published = $false
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
    blockers = @($currentCandidateVerification.denial_reasons + $driftResult.reconciliation_surface.blockers | Select-Object -Unique)
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        descriptor_verified = $verificationAllowed
        verification_denied_as_expected = (-not $verificationAllowed)
        fail_closed_cases = @($caseResults).Count
        failed_fail_closed_cases = @($failedCases).Count
        rc11_012_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC11-020"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc11-external-object-descriptor-verification-evidence.v1"
    generated_at = $generatedAt
    task = "RC11-012"
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
    verification_surface = $result.verification_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc11_012_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC11-020"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) {
    throw "Sensitive marker detected in RC11-012 outputs."
}

Write-Host "RC11 external object descriptor verification $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Verification state: $verificationState"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), fail-closed cases: $(@($caseResults).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
