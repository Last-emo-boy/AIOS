param(
    [string]$ArtifactDir = ".workflow/artifacts/rc8-installer-byte-fail-closed",
    [string]$ResultPath = "",
    [string]$DescriptorPath = ".workflow/artifacts/rc8-real-payload-object-descriptor/payload-object-descriptor.json",
    [string]$SignatureIngestionResultPath = ".workflow/artifacts/rc8-public-signature-ingestion/result.json",
    [string]$SignatureReceiptPath = ".workflow/artifacts/rc8-public-signature-ingestion/signature-ingestion-receipt.json",
    [string]$SignedDescriptorFailClosedResultPath = ".workflow/artifacts/rc8-signed-object-descriptor-fail-closed/result.json",
    [string]$InstallerVmPreflightResultPath = ".workflow/artifacts/rc8-installer-vm-preflight/result.json",
    [string]$InstallerVmPreflightReportPath = ".workflow/artifacts/rc8-installer-vm-preflight/preflight-report.json",
    [string]$ObjectFetchReportPath = ".workflow/artifacts/rc8-installer-vm-preflight/object-fetch-report.json",
    [switch]$FailOnBlocked
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
    $json = $Value | ConvertTo-Json -Depth 100
    [IO.File]::WriteAllText($Path, $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}

function Convert-JsonClone {
    param([Parameter(Mandatory = $true)]$Value)
    return ($Value | ConvertTo-Json -Depth 100 | ConvertFrom-Json)
}

function Has-Value {
    param($Value)
    if ($null -eq $Value) {
        return $false
    }
    if ($Value -is [string]) {
        return -not [string]::IsNullOrWhiteSpace($Value)
    }
    return $true
}

function Set-JsonProperty {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string]$Name,
        $Value
    )
    if ($Object.PSObject.Properties.Name -contains $Name) {
        $Object.$Name = $Value
    } else {
        $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -Force
    }
}

function Add-Reason {
    param(
        [System.Collections.Generic.List[string]]$Reasons,
        [Parameter(Mandatory = $true)][string]$Reason
    )
    if (-not $Reasons.Contains($Reason)) {
        $Reasons.Add($Reason)
    }
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
        $script:blockers += $entry
    }
}

function Test-NoSensitiveText {
    param([Parameter(Mandatory = $true)][string[]]$Values)
    $privateKeyMarker = "PRIVATE" + " KEY"
    $markers = @(
        ("BEGIN " + $privateKeyMarker),
        ("BEGIN RSA " + $privateKeyMarker),
        ("BEGIN OPENSSH " + $privateKeyMarker),
        ($privateKeyMarker + "-----"),
        ("Authorization:" + " Bearer"),
        ("Bearer" + " "),
        "access_token",
        "refresh_token",
        ("." + "local-release-authority"),
        ("signing" + "-key.pem")
    )
    foreach ($value in $Values) {
        foreach ($marker in $markers) {
            if ($value.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                return $false
            }
        }
    }
    return $true
}

function Test-QuarantinePath {
    param($ObjectFetch)
    if (-not (Has-Value $ObjectFetch.quarantine_payload_path)) {
        return $false
    }
    return ([string]$ObjectFetch.quarantine_payload_path).StartsWith(".workflow/artifacts/rc8-installer-vm-preflight/quarantine/", [StringComparison]::OrdinalIgnoreCase)
}

function Invoke-InstallerGateEvaluation {
    param(
        [Parameter(Mandatory = $true)]$Descriptor,
        [Parameter(Mandatory = $true)]$SignatureSurface,
        [Parameter(Mandatory = $true)]$SignatureReceipt,
        [Parameter(Mandatory = $true)]$Preflight,
        [Parameter(Mandatory = $true)]$ObjectFetch
    )

    $reasons = [System.Collections.Generic.List[string]]::new()

    if ($Descriptor.schema -ne "agentos.payload-object-descriptor.v1") {
        Add-Reason $reasons "bad-descriptor-schema"
    }
    if ($Descriptor.production_ready_claim -eq $true -or $Preflight.production_ready_claim -eq $true) {
        Add-Reason $reasons "production-ready-claim"
    }
    if ($Descriptor.install_allowed -eq $true -or $Descriptor.activation_allowed -eq $true -or $Descriptor.rollback_execution_allowed -eq $true) {
        Add-Reason $reasons "descriptor-authority-broadening"
    }
    if (-not (Has-Value $Descriptor.sha256)) {
        Add-Reason $reasons "missing-descriptor-object-digest"
    }
    if (-not (Has-Value $Descriptor.size_bytes) -or [int64]$Descriptor.size_bytes -le 0) {
        Add-Reason $reasons "missing-or-invalid-descriptor-size"
    }
    if ($Descriptor.immutable -ne $true) {
        Add-Reason $reasons "descriptor-not-immutable"
    }
    if ([string]$Descriptor.uri -match "^http://" -or [string]$Descriptor.uri -match "token=|sig=|X-Amz-Signature=") {
        Add-Reason $reasons "credential-or-insecure-object-uri"
    }

    if ($Preflight.installer_vm_smoke_run -ne $true) {
        Add-Reason $reasons "installer-vm-smoke-not-run"
    }
    if ($Preflight.preflight_state -ne "verification-blocked" -and $Preflight.preflight_state -ne "install-preflight-ready") {
        Add-Reason $reasons "unknown-preflight-state"
    }
    if ($Preflight.preflight_state -eq "install-preflight-ready" -and $ObjectFetch.external_https_object_uri_published -ne $true) {
        Add-Reason $reasons "preflight-ready-without-external-object"
    }
    if ($Preflight.side_effects.remote_publication_performed -eq $true -or $Preflight.side_effects.payload_bytes_uploaded -eq $true -or $Preflight.side_effects.remote_payload_bytes_downloaded -eq $true) {
        Add-Reason $reasons "storage-or-remote-transfer-authority-broadening"
    }

    if (-not (Test-QuarantinePath $ObjectFetch)) {
        Add-Reason $reasons "quarantine-path-not-approved"
    }
    if ($ObjectFetch.size_verified -ne $true -or [int64]$ObjectFetch.actual_size_bytes -ne [int64]$Descriptor.size_bytes) {
        Add-Reason $reasons "payload-size-mismatch"
    }
    if ($ObjectFetch.digest_verified -ne $true -or [string]$ObjectFetch.actual_sha256 -ne [string]$Descriptor.sha256) {
        Add-Reason $reasons "payload-digest-mismatch"
    }
    if ($ObjectFetch.external_https_object_uri_published -ne $true) {
        Add-Reason $reasons "external-https-object-uri-not-published"
    }
    if ($ObjectFetch.remote_download_attempted -eq $true -and $ObjectFetch.external_https_object_uri_published -ne $true) {
        Add-Reason $reasons "remote-download-before-external-object-uri"
    }
    if ($ObjectFetch.PSObject.Properties.Name -contains "large_payload_storage_enabled" -and $ObjectFetch.large_payload_storage_enabled -eq $true) {
        Add-Reason $reasons "large-payload-storage-enabled-on-mirror"
    }

    if ($SignatureSurface.signature_artifact_ingested -ne $true) {
        Add-Reason $reasons "public-signature-artifact-not-ingested"
    }
    if ($SignatureSurface.crypto_verified -ne $true) {
        Add-Reason $reasons "signature-crypto-verification-failed"
    }
    if ($SignatureSurface.descriptor_hash_bound -ne $true) {
        Add-Reason $reasons "signature-descriptor-hash-not-bound"
    }
    if ($SignatureSurface.canonical_payload_hash_bound -ne $true) {
        Add-Reason $reasons "signature-canonical-payload-not-bound"
    }
    if ($SignatureSurface.revocation_current -ne $true -or $SignatureReceipt.revocation_status -ne "not-revoked") {
        Add-Reason $reasons "signature-revocation-not-current"
    }
    if ($SignatureReceipt.descriptor_sha256 -ne $ObjectFetch.descriptor_sha256) {
        Add-Reason $reasons "receipt-descriptor-hash-mismatch"
    }
    if ($SignatureReceipt.signed_object_sha256 -ne $Descriptor.sha256) {
        Add-Reason $reasons "receipt-object-hash-mismatch"
    }
    if ($SignatureReceipt.crypto_verified -ne $true) {
        Add-Reason $reasons "receipt-not-crypto-verified"
    }
    if ($SignatureReceipt.public_key_identity -ne "redacted-public-identity-present") {
        Add-Reason $reasons "raw-public-identity-leak"
    }
    if ($SignatureReceipt.PSObject.Properties.Name -contains "signature_value") {
        Add-Reason $reasons "raw-signature-value-leak"
    }

    foreach ($field in @("installer_compatibility_sha256", "rollback_baseline_sha256", "revocation_snapshot_sha256", "signed_metadata_sha256")) {
        if (-not (Has-Value $Descriptor.$field)) {
            Add-Reason $reasons "missing-$field"
        }
    }
    if ($Descriptor.PSObject.Properties.Name -contains "declared_current_artifact_drift_resolved" -and $Descriptor.declared_current_artifact_drift_resolved -ne $true) {
        Add-Reason $reasons "declared-current-artifact-drift-unresolved"
    }
    if (@($Preflight.blockers | Where-Object { $_.id -eq "declared-current-artifact-drift-unresolved" }).Count -gt 0) {
        Add-Reason $reasons "declared-current-artifact-drift-unresolved"
    }
    foreach ($blocker in @($script:baselinePreflightResult.payload_blockers)) {
        Add-Reason $reasons ([string]$blocker)
    }

    if ($Preflight.side_effects.install_performed -eq $true -or $Preflight.side_effects.activation_performed -eq $true -or $Preflight.side_effects.rollback_execution_performed -eq $true -or $Preflight.side_effects.active_slot_mutated -eq $true -or $Preflight.side_effects.production_ring_mutated -eq $true -or $Preflight.side_effects.remote_dispatch_enabled -eq $true -or $Preflight.side_effects.tui_authority -eq $true) {
        Add-Reason $reasons "installer-side-effect-authority-broadening"
    }

    return [ordered]@{
        observed_state = if ($reasons.Count -eq 0) { "install-preflight-ready" } else { "verification-blocked" }
        install_allowed = $false
        observed_reasons = @($reasons)
        side_effects = [ordered]@{
            remote_publication_performed = $false
            payload_bytes_uploaded = $false
            remote_payload_bytes_downloaded = $false
            install_performed = $false
            activation_performed = $false
            rollback_execution_performed = $false
            active_slot_mutated = $false
            boot_metadata_mutated = $false
            active_artifact_set_mutated = $false
            production_ring_mutated = $false
            support_upload_performed = $false
            remote_dispatch_enabled = $false
            tui_authority = $false
        }
    }
}

function Invoke-Case {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string[]]$ExpectedReasons,
        [scriptblock]$Mutate
    )
    $descriptor = Convert-JsonClone $script:baselineDescriptor
    $signatureSurface = Convert-JsonClone $script:baselineSignatureSurface
    $signatureReceipt = Convert-JsonClone $script:baselineSignatureReceipt
    $preflight = Convert-JsonClone $script:baselinePreflightReport
    $objectFetch = Convert-JsonClone $script:baselineObjectFetch
    if ($null -ne $Mutate) {
        & $Mutate $descriptor $signatureSurface $signatureReceipt $preflight $objectFetch
    }
    $evaluation = Invoke-InstallerGateEvaluation -Descriptor $descriptor -SignatureSurface $signatureSurface -SignatureReceipt $signatureReceipt -Preflight $preflight -ObjectFetch $objectFetch
    $missing = @($ExpectedReasons | Where-Object { $_ -notin $evaluation.observed_reasons })
    $sideEffectsClear = (
        $evaluation.side_effects.remote_publication_performed -eq $false -and
        $evaluation.side_effects.payload_bytes_uploaded -eq $false -and
        $evaluation.side_effects.remote_payload_bytes_downloaded -eq $false -and
        $evaluation.side_effects.install_performed -eq $false -and
        $evaluation.side_effects.activation_performed -eq $false -and
        $evaluation.side_effects.rollback_execution_performed -eq $false -and
        $evaluation.side_effects.active_slot_mutated -eq $false -and
        $evaluation.side_effects.production_ring_mutated -eq $false -and
        $evaluation.side_effects.support_upload_performed -eq $false -and
        $evaluation.side_effects.remote_dispatch_enabled -eq $false -and
        $evaluation.side_effects.tui_authority -eq $false
    )
    return [ordered]@{
        id = $Id
        status = if ($missing.Count -eq 0 -and $evaluation.observed_state -eq "verification-blocked" -and $evaluation.install_allowed -eq $false -and $sideEffectsClear) { "passed" } else { "failed" }
        expected_reasons = $ExpectedReasons
        missing_expected_reasons = $missing
        observed_state = $evaluation.observed_state
        observed_reasons = $evaluation.observed_reasons
        install_allowed = $evaluation.install_allowed
        side_effects = $evaluation.side_effects
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
        present = Test-Path -LiteralPath $Path -PathType Leaf
        schema = if ($null -ne $Json) { $Json.schema } else { $null }
        status = if ($null -ne $Json) { $Json.status } else { $null }
    }
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:blockers = @()

$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
if (-not $ResultPath) {
    $ResultPath = Join-Path $ArtifactDir "result.json"
}
$resolvedResultPath = Resolve-RepoPath $ResultPath

$resolvedDescriptorPath = Resolve-RepoPath $DescriptorPath
$resolvedSignatureIngestionResultPath = Resolve-RepoPath $SignatureIngestionResultPath
$resolvedSignatureReceiptPath = Resolve-RepoPath $SignatureReceiptPath
$resolvedSignedDescriptorFailClosedResultPath = Resolve-RepoPath $SignedDescriptorFailClosedResultPath
$resolvedInstallerVmPreflightResultPath = Resolve-RepoPath $InstallerVmPreflightResultPath
$resolvedInstallerVmPreflightReportPath = Resolve-RepoPath $InstallerVmPreflightReportPath
$resolvedObjectFetchReportPath = Resolve-RepoPath $ObjectFetchReportPath

$script:baselineDescriptor = Read-Json $resolvedDescriptorPath
$signatureIngestionResult = Read-Json $resolvedSignatureIngestionResultPath
$script:baselineSignatureSurface = $signatureIngestionResult.signature_surface
$script:baselineSignatureReceipt = Read-Json $resolvedSignatureReceiptPath
$signedDescriptorFailClosed = Read-Json $resolvedSignedDescriptorFailClosedResultPath
$script:baselinePreflightResult = Read-Json $resolvedInstallerVmPreflightResultPath
$script:baselinePreflightReport = Read-Json $resolvedInstallerVmPreflightReportPath
$script:baselineObjectFetch = Read-Json $resolvedObjectFetchReportPath

Add-Check "source.rc8_011.signature" ($signatureIngestionResult.status -eq "passed" -and $signatureIngestionResult.signature_surface.crypto_verified -eq $true) "RC8-011 signature ingestion must be passed before installer fail-closed fixtures." $signatureIngestionResult.summary
Add-Check "source.rc8_012.fail_closed" ($signedDescriptorFailClosed.status -eq "passed" -and $signedDescriptorFailClosed.summary.failed_cases -eq 0) "RC8-012 signed descriptor fail-closed fixtures must pass before installer fail-closed fixtures." $signedDescriptorFailClosed.summary
Add-Check "source.rc8_020.preflight" ($script:baselinePreflightResult.status -eq "passed" -and $script:baselinePreflightResult.vm_surface.qemu_boot_smoke_completed -eq $true -and $script:baselinePreflightResult.object_fetch_surface.quarantine_digest_verified -eq $true) "RC8-020 VM preflight and quarantine smoke must pass before installer fail-closed fixtures." $script:baselinePreflightResult.summary

$cases = @()
$cases += Invoke-Case "base-current-installer-remains-blocked" @("external-https-object-uri-not-published", "declared-current-artifact-drift-unresolved")
$cases += Invoke-Case "payload-size-mismatch" @("payload-size-mismatch") { param($d,$s,$r,$p,$o) $o.actual_size_bytes = 378; $o.size_verified = $false }
$cases += Invoke-Case "payload-digest-mismatch" @("payload-digest-mismatch") { param($d,$s,$r,$p,$o) $o.actual_sha256 = "0000"; $o.digest_verified = $false }
$cases += Invoke-Case "quarantine-path-escape" @("quarantine-path-not-approved") { param($d,$s,$r,$p,$o) $o.quarantine_payload_path = "../active-slot/payload.cpio.gz" }
$cases += Invoke-Case "remote-download-before-external-uri" @("remote-download-before-external-object-uri") { param($d,$s,$r,$p,$o) $o.remote_download_attempted = $true; $o.external_https_object_uri_published = $false }
$cases += Invoke-Case "descriptor-http-uri" @("credential-or-insecure-object-uri") { param($d,$s,$r,$p,$o) $d.uri = "http://objects.example.invalid/payload.cpio.gz" }
$cases += Invoke-Case "descriptor-credential-uri" @("credential-or-insecure-object-uri") { param($d,$s,$r,$p,$o) $d.uri = "https://objects.example.invalid/payload.cpio.gz?token=redacted" }
$cases += Invoke-Case "descriptor-mutable" @("descriptor-not-immutable") { param($d,$s,$r,$p,$o) $d.immutable = $false }
$cases += Invoke-Case "descriptor-authority-broadening" @("descriptor-authority-broadening") { param($d,$s,$r,$p,$o) $d.install_allowed = $true }
$cases += Invoke-Case "signature-not-ingested" @("public-signature-artifact-not-ingested") { param($d,$s,$r,$p,$o) $s.signature_artifact_ingested = $false }
$cases += Invoke-Case "signature-crypto-failed" @("signature-crypto-verification-failed") { param($d,$s,$r,$p,$o) $s.crypto_verified = $false }
$cases += Invoke-Case "signature-descriptor-not-bound" @("signature-descriptor-hash-not-bound") { param($d,$s,$r,$p,$o) $s.descriptor_hash_bound = $false }
$cases += Invoke-Case "signature-canonical-not-bound" @("signature-canonical-payload-not-bound") { param($d,$s,$r,$p,$o) $s.canonical_payload_hash_bound = $false }
$cases += Invoke-Case "signature-revoked" @("signature-revocation-not-current") { param($d,$s,$r,$p,$o) $s.revocation_current = $false; $r.revocation_status = "revoked" }
$cases += Invoke-Case "receipt-descriptor-hash-mismatch" @("receipt-descriptor-hash-mismatch") { param($d,$s,$r,$p,$o) $r.descriptor_sha256 = "0000" }
$cases += Invoke-Case "receipt-object-hash-mismatch" @("receipt-object-hash-mismatch") { param($d,$s,$r,$p,$o) $r.signed_object_sha256 = "0000" }
$cases += Invoke-Case "receipt-not-crypto-verified" @("receipt-not-crypto-verified") { param($d,$s,$r,$p,$o) $r.crypto_verified = $false }
$cases += Invoke-Case "raw-public-identity-leak" @("raw-public-identity-leak") { param($d,$s,$r,$p,$o) $r.public_key_identity = "fixture-raw-public-identity" }
$cases += Invoke-Case "raw-signature-value-leak" @("raw-signature-value-leak") { param($d,$s,$r,$p,$o) Set-JsonProperty $r "signature_value" "fixture-signature-value" }
$cases += Invoke-Case "missing-compatibility" @("missing-installer_compatibility_sha256") { param($d,$s,$r,$p,$o) $d.installer_compatibility_sha256 = $null }
$cases += Invoke-Case "missing-rollback-baseline" @("missing-rollback_baseline_sha256") { param($d,$s,$r,$p,$o) $d.rollback_baseline_sha256 = $null }
$cases += Invoke-Case "missing-revocation-snapshot" @("missing-revocation_snapshot_sha256") { param($d,$s,$r,$p,$o) $d.revocation_snapshot_sha256 = $null }
$cases += Invoke-Case "missing-signed-metadata" @("missing-signed_metadata_sha256") { param($d,$s,$r,$p,$o) $d.signed_metadata_sha256 = $null }
$cases += Invoke-Case "installer-vm-smoke-not-run" @("installer-vm-smoke-not-run") { param($d,$s,$r,$p,$o) $p.installer_vm_smoke_run = $false }
$cases += Invoke-Case "preflight-ready-without-external-object" @("preflight-ready-without-external-object") { param($d,$s,$r,$p,$o) $p.preflight_state = "install-preflight-ready"; $o.external_https_object_uri_published = $false }
$cases += Invoke-Case "storage-authority-broadening" @("storage-or-remote-transfer-authority-broadening") { param($d,$s,$r,$p,$o) $p.side_effects.payload_bytes_uploaded = $true }
$cases += Invoke-Case "mirror-large-payload-storage-enabled" @("large-payload-storage-enabled-on-mirror") { param($d,$s,$r,$p,$o) Set-JsonProperty $o "large_payload_storage_enabled" $true }
$cases += Invoke-Case "installer-side-effect-authority" @("installer-side-effect-authority-broadening") { param($d,$s,$r,$p,$o) $p.side_effects.install_performed = $true }

$failedCases = @($cases | Where-Object { $_.status -ne "passed" })
Add-Check "fixtures.all_cases_passed" ($failedCases.Count -eq 0) "All RC8 installer byte/signature/storage/compatibility negative fixtures must fail closed." ([ordered]@{ cases = @($cases).Count; failed_cases = $failedCases.Count })
Add-Check "fixtures.no_side_effects" (@($cases | Where-Object { $_.side_effects.install_performed -or $_.side_effects.activation_performed -or $_.side_effects.rollback_execution_performed -or $_.side_effects.active_slot_mutated -or $_.side_effects.production_ring_mutated -or $_.side_effects.remote_dispatch_enabled -or $_.side_effects.tui_authority }).Count -eq 0) "Fixtures must not perform install, activation, rollback, active slot mutation, production ring mutation, dispatch, or TUI authority." $null

$resultPreviewText = $cases | ConvertTo-Json -Depth 100
Add-Check "fixtures.secret_safe" (Test-NoSensitiveText -Values @($resultPreviewText)) "Fixture results must not contain private key or token markers." $null

$result = [ordered]@{
    schema = "agentos.rc8-installer-byte-fail-closed-result.v1"
    generated_at = (Get-Date).ToString("o")
    task = "RC8-021"
    status = if (@($script:blockers).Count -eq 0) { "passed" } else { "blocked" }
    production_ready_claim = $false
    source = [ordered]@{
        descriptor = New-ArtifactRef $resolvedDescriptorPath $script:baselineDescriptor
        signature_ingestion_result = New-ArtifactRef $resolvedSignatureIngestionResultPath $signatureIngestionResult
        signature_receipt = New-ArtifactRef $resolvedSignatureReceiptPath $script:baselineSignatureReceipt
        signed_descriptor_fail_closed = New-ArtifactRef $resolvedSignedDescriptorFailClosedResultPath $signedDescriptorFailClosed
        installer_vm_preflight_result = New-ArtifactRef $resolvedInstallerVmPreflightResultPath $script:baselinePreflightResult
        installer_vm_preflight_report = New-ArtifactRef $resolvedInstallerVmPreflightReportPath $script:baselinePreflightReport
        object_fetch_report = New-ArtifactRef $resolvedObjectFetchReportPath $script:baselineObjectFetch
    }
    cases = $cases
    failed_cases = @($failedCases | ForEach-Object { $_.id })
    invariants = [ordered]@{
        local_fixture_only = $true
        remote_publication_performed = $false
        payload_bytes_uploaded = $false
        remote_payload_bytes_downloaded = $false
        local_private_key_material_used = $false
        private_key_material_read_or_printed = $false
        cryptographic_signing_performed = $false
        install_allowed = $false
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
    }
    checks = $script:checks
    blockers = $script:blockers
    summary = [ordered]@{
        checks = @($script:checks).Count
        blockers = @($script:blockers).Count
        cases = @($cases).Count
        passed_cases = @($cases | Where-Object { $_.status -eq "passed" }).Count
        failed_cases = $failedCases.Count
        rc8_021_complete = @($script:blockers).Count -eq 0
        next_task = "RC8-022"
    }
}

Write-Json -Value $result -Path $resolvedResultPath
$resultText = Get-Content -Raw -LiteralPath $resolvedResultPath
if (-not (Test-NoSensitiveText -Values @($resultText))) {
    throw "Sensitive marker detected in RC8-021 result."
}

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}

Write-Host "RC8 installer byte/signature/storage/compatibility fail-closed fixtures $($result.status): $(Get-StablePath $resolvedResultPath)"
Write-Host "Cases: $(@($cases).Count), failed: $($failedCases.Count)"
