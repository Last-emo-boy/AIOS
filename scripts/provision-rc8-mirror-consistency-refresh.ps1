param(
    [string]$RemoteHost = "47.101.11.109",
    [string]$RemoteUser = "root",
    [string]$Domain = "aios.w33d.xyz",
    [string]$ArtifactDir = ".workflow/artifacts/rc8-mirror-consistency-refresh",
    [string]$ResultPath = "",
    [string]$DescriptorPath = ".workflow/artifacts/rc8-real-payload-object-descriptor/payload-object-descriptor.json",
    [string]$DescriptorResultPath = ".workflow/artifacts/rc8-real-payload-object-descriptor/result.json",
    [string]$SignatureIngestionResultPath = ".workflow/artifacts/rc8-public-signature-ingestion/result.json",
    [string]$SignatureReceiptPath = ".workflow/artifacts/rc8-public-signature-ingestion/signature-ingestion-receipt.json",
    [string]$SignatureSummaryPath = ".workflow/artifacts/rc8-public-signature-ingestion/public-signature-artifact-summary.json",
    [string]$SignedDescriptorFailClosedResultPath = ".workflow/artifacts/rc8-signed-object-descriptor-fail-closed/result.json",
    [string]$InstallerVmPreflightResultPath = ".workflow/artifacts/rc8-installer-vm-preflight/result.json",
    [string]$InstallerVmPreflightReportPath = ".workflow/artifacts/rc8-installer-vm-preflight/preflight-report.json",
    [string]$ObjectFetchReportPath = ".workflow/artifacts/rc8-installer-vm-preflight/object-fetch-report.json",
    [string]$InstallerByteFailClosedResultPath = ".workflow/artifacts/rc8-installer-byte-fail-closed/result.json",
    [string]$TlsHardeningResultPath = ".workflow/artifacts/rc7-tls-nginx-hardening/result.json",
    [int]$SshConnectTimeoutSeconds = 10,
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

function ConvertFrom-JsonTextSafe {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }
    try {
        return ($Text | ConvertFrom-Json)
    } catch {
        return $null
    }
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
    $json = Get-JsonText $Value
    [IO.File]::WriteAllText($Path, $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}

function Write-TextFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Text
    )
    $parent = Split-Path -Parent $Path
    if ($parent) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    [IO.File]::WriteAllText($Path, $Text, [Text.UTF8Encoding]::new($false))
}

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [string]$Stdin = $null
    )
    $process = [Diagnostics.Process]::new()
    $process.StartInfo.FileName = $FilePath
    foreach ($argument in $Arguments) {
        [void]$process.StartInfo.ArgumentList.Add($argument)
    }
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true
    $process.StartInfo.RedirectStandardInput = $null -ne $Stdin
    $process.StartInfo.StandardOutputEncoding = [Text.UTF8Encoding]::new($false)
    $process.StartInfo.StandardErrorEncoding = [Text.UTF8Encoding]::new($false)
    [void]$process.Start()
    if ($null -ne $Stdin) {
        $process.StandardInput.Write($Stdin)
        $process.StandardInput.Close()
    }
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    return [ordered]@{
        exit_code = $process.ExitCode
        stdout = $stdout
        stderr = $stderr
        text = (($stdout + $stderr).Trim())
    }
}

function Invoke-Remote {
    param([Parameter(Mandatory = $true)][string]$Command)
    $target = "$RemoteUser@$RemoteHost"
    $args = @(
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=$SshConnectTimeoutSeconds",
        $target,
        $Command
    )
    $result = Invoke-Native -FilePath "ssh" -Arguments $args
    if ($result.exit_code -ne 0) {
        throw "Remote command failed ($($result.exit_code)): $($result.text)"
    }
    return $result.text
}

function Set-RemoteTextFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Text,
        [string]$Mode = "0644"
    )
    $parent = [IO.Path]::GetDirectoryName($Path) -replace "\\", "/"
    $target = "$RemoteUser@$RemoteHost"
    $args = @(
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=$SshConnectTimeoutSeconds",
        $target,
        "set -eu; install -d -m 0755 '$parent'; cat > '$Path'; chmod '$Mode' '$Path'"
    )
    $result = Invoke-Native -FilePath "ssh" -Arguments $args -Stdin $Text
    if ($result.exit_code -ne 0) {
        throw "Remote file write failed ($($result.exit_code)): $($result.text)"
    }
}

function Invoke-Curl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Method = "GET"
    )
    $url = if ($Path.StartsWith("https://", [StringComparison]::OrdinalIgnoreCase)) { $Path } else { "https://$Domain$Path" }
    $args = @(
        "--noproxy", "*",
        "--max-time", "20",
        "--resolve", "$Domain`:443`:$RemoteHost",
        "-sS",
        "-X", $Method,
        "-w", "`n%{http_code}",
        $url
    )
    $result = Invoke-Native -FilePath "curl.exe" -Arguments $args
    $exitCode = $result.exit_code
    $text = ($result.stdout + $result.stderr).TrimEnd()
    $parts = [regex]::Split($text, "\r?\n")
    $statusText = $parts[-1]
    $body = if ($parts.Count -gt 1) { ($parts[0..($parts.Count - 2)] -join "`n") } else { "" }
    $statusCode = 0
    [void][int]::TryParse($statusText, [ref]$statusCode)
    return [ordered]@{
        path = $Path
        url = $url
        method = $Method
        exit_code = $exitCode
        status_code = $statusCode
        body = $body
        sha256 = Get-StringSha256 $body
        json = if ($statusCode -eq 200) { ConvertFrom-JsonTextSafe $body } else { $null }
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
        foreach ($marker in $markers) {
            if ($value.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                return $false
            }
        }
    }
    return $true
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
$resolvedDescriptorResultPath = Resolve-RepoPath $DescriptorResultPath
$resolvedSignatureIngestionResultPath = Resolve-RepoPath $SignatureIngestionResultPath
$resolvedSignatureReceiptPath = Resolve-RepoPath $SignatureReceiptPath
$resolvedSignatureSummaryPath = Resolve-RepoPath $SignatureSummaryPath
$resolvedSignedDescriptorFailClosedResultPath = Resolve-RepoPath $SignedDescriptorFailClosedResultPath
$resolvedInstallerVmPreflightResultPath = Resolve-RepoPath $InstallerVmPreflightResultPath
$resolvedInstallerVmPreflightReportPath = Resolve-RepoPath $InstallerVmPreflightReportPath
$resolvedObjectFetchReportPath = Resolve-RepoPath $ObjectFetchReportPath
$resolvedInstallerByteFailClosedResultPath = Resolve-RepoPath $InstallerByteFailClosedResultPath
$resolvedTlsHardeningResultPath = Resolve-RepoPath $TlsHardeningResultPath

$descriptor = Read-Json $resolvedDescriptorPath
$descriptorResult = Read-Json $resolvedDescriptorResultPath
$signatureIngestion = Read-Json $resolvedSignatureIngestionResultPath
$signatureReceipt = Read-Json $resolvedSignatureReceiptPath
$signatureSummary = Read-Json $resolvedSignatureSummaryPath
$signedDescriptorFailClosed = Read-Json $resolvedSignedDescriptorFailClosedResultPath
$installerVmPreflight = Read-Json $resolvedInstallerVmPreflightResultPath
$preflightReport = Read-Json $resolvedInstallerVmPreflightReportPath
$objectFetchReport = Read-Json $resolvedObjectFetchReportPath
$installerByteFailClosed = Read-Json $resolvedInstallerByteFailClosedResultPath
$tlsHardening = Read-Json $resolvedTlsHardeningResultPath

$generatedAt = (Get-Date).ToString("o")
$releaseId = [string]$descriptor.release_id
$payloadBasePath = "/payloads/aios/$releaseId"
$descriptorText = Get-Content -Raw -LiteralPath $resolvedDescriptorPath
$signatureReceiptText = Get-Content -Raw -LiteralPath $resolvedSignatureReceiptPath
$signatureSummaryText = Get-Content -Raw -LiteralPath $resolvedSignatureSummaryPath
$preflightResultText = Get-Content -Raw -LiteralPath $resolvedInstallerVmPreflightResultPath
$preflightReportText = Get-Content -Raw -LiteralPath $resolvedInstallerVmPreflightReportPath
$objectFetchReportText = Get-Content -Raw -LiteralPath $resolvedObjectFetchReportPath
$installerFailClosedText = Get-Content -Raw -LiteralPath $resolvedInstallerByteFailClosedResultPath

Add-Check "source.rc8_010.descriptor" ($descriptorResult.status -eq "passed" -and $descriptor.schema -eq "agentos.payload-object-descriptor.v1" -and $descriptor.immutable -eq $true) "RC8-010 descriptor projection must be passed and immutable." $descriptorResult.summary
Add-Check "source.rc8_011.signature" ($signatureIngestion.status -eq "passed" -and $signatureIngestion.signature_surface.crypto_verified -eq $true -and $signatureReceipt.crypto_verified -eq $true) "RC8-011 public signature ingestion must be passed with crypto verification." $signatureIngestion.summary
Add-Check "source.rc8_012.fail_closed" ($signedDescriptorFailClosed.status -eq "passed" -and $signedDescriptorFailClosed.summary.failed_cases -eq 0) "RC8-012 signed descriptor fail-closed fixtures must pass." $signedDescriptorFailClosed.summary
Add-Check "source.rc8_020.preflight" ($installerVmPreflight.status -eq "passed" -and $installerVmPreflight.vm_surface.qemu_boot_smoke_completed -eq $true) "RC8-020 installer VM preflight must pass while external object fetch remains blocked." $installerVmPreflight.summary
Add-Check "source.rc8_021.fail_closed" ($installerByteFailClosed.status -eq "passed" -and $installerByteFailClosed.summary.failed_cases -eq 0) "RC8-021 installer byte/signature/storage/compatibility fail-closed fixtures must pass." $installerByteFailClosed.summary
Add-Check "source.rc7_tls.https" ($tlsHardening.status -eq "passed" -and $tlsHardening.nginx.reloaded -eq $true -and $tlsHardening.endpoint_status.https_root -eq 200) "RC7 HTTPS/Nginx hardening must be passed before RC8 mirror refresh." $tlsHardening.summary

$before = [ordered]@{
    health = Invoke-Curl "/health.json"
    mirror_descriptor = Invoke-Curl "/.well-known/aios/mirror.json"
    compatibility = Invoke-Curl "/install/compatibility.json"
    rollback_baseline = Invoke-Curl "/install/rollback-baseline.json"
    support_index = Invoke-Curl "/support/index.json"
}
$preservedBefore = [ordered]@{}
foreach ($key in $before.Keys) {
    $preservedBefore[$key] = $before[$key].sha256
}
Add-Check "remote.preserved_metadata.before" (@($before.Values | Where-Object { $_.status_code -ne 200 -or $null -eq $_.json }).Count -eq 0) "Existing mirror health, descriptor, compatibility, rollback, and support metadata must be reachable before RC8 refresh." (@($before.Keys))

$payloadIndex = [ordered]@{
    schema = "agentos.rc8-hosted-payload-index.v1"
    generated_at = $generatedAt
    status = "verification-blocked"
    production_ready_claim = $false
    domain = $Domain
    storage_mode = "metadata-only"
    large_payload_bytes_hosted_on_mirror = $false
    entries = @(
        [ordered]@{
            id = $releaseId
            release_id = $releaseId
            status = "verification-blocked"
            object_descriptor_path = "$payloadBasePath/object-descriptor.json"
            object_descriptor_sha256 = Get-FileSha256 $resolvedDescriptorPath
            object_id = $descriptor.object_id
            object_uri = $descriptor.uri
            object_uri_external_https = $false
            object_size_bytes = $descriptor.size_bytes
            object_sha256 = $descriptor.sha256
            signature_receipt_path = "$payloadBasePath/signature-receipt.json"
            signature_receipt_sha256 = Get-FileSha256 $resolvedSignatureReceiptPath
            signature_summary_path = "$payloadBasePath/signature-summary.json"
            signature_summary_sha256 = Get-FileSha256 $resolvedSignatureSummaryPath
            public_signature_ingested = $true
            cryptographic_signature_present = $true
            crypto_verified = $true
            installer_preflight_result_path = "$payloadBasePath/installer-vm-preflight.json"
            installer_preflight_result_sha256 = Get-FileSha256 $resolvedInstallerVmPreflightResultPath
            installer_preflight_report_path = "$payloadBasePath/preflight-report.json"
            object_fetch_report_path = "$payloadBasePath/object-fetch-report.json"
            installer_fail_closed_result_path = "$payloadBasePath/installer-byte-fail-closed.json"
            installer_fail_closed_result_sha256 = Get-FileSha256 $resolvedInstallerByteFailClosedResultPath
            signed_metadata_sha256 = $descriptor.signed_metadata_sha256
            revocation_snapshot_sha256 = $descriptor.revocation_snapshot_sha256
            compatibility_sha256 = $descriptor.installer_compatibility_sha256
            rollback_baseline_sha256 = $descriptor.rollback_baseline_sha256
            support_recovery_sha256 = $descriptor.support_recovery_sha256
            payload_blockers = @(
                "external-https-object-uri-not-published",
                "declared-current-artifact-drift-unresolved"
            )
            install_allowed = $false
            activation_allowed = $false
            rollback_execution_allowed = $false
        }
    )
    authority = [ordered]@{
        mirror_is_root_of_trust = $false
        signing_authority = $false
        install_authority = $false
        activation_authority = $false
        rollback_execution_authority = $false
        production_ring_mutation_authority = $false
        remote_dispatch_authority = $false
        support_upload_authority = $false
        tui_authority = $false
    }
}
$payloadIndexText = Get-JsonText $payloadIndex
$payloadIndexHash = Get-StringSha256 $payloadIndexText

$installBootstrap = [ordered]@{
    schema = "agentos.rc8-install-bootstrap.v1"
    generated_at = $generatedAt
    status = "verification-blocked"
    production_ready_claim = $false
    domain = $Domain
    default_release_id = $releaseId
    current_state = "verification-blocked"
    install_allowed = $false
    activation_allowed = $false
    rollback_execution_allowed = $false
    installer_vm_smoke_run = $true
    payload_signature_required = $true
    payload_signature_crypto_verified = $true
    external_https_object_uri_published = $false
    remote_payload_bytes_downloaded = $false
    payload_bytes_hosted_on_mirror = $false
    payload_index_path = "/payloads/index.json"
    endpoints = [ordered]@{
        payload_index = "/payloads/index.json"
        object_descriptor = "$payloadBasePath/object-descriptor.json"
        signature_receipt = "$payloadBasePath/signature-receipt.json"
        signature_summary = "$payloadBasePath/signature-summary.json"
        installer_preflight = "$payloadBasePath/installer-vm-preflight.json"
        preflight_report = "$payloadBasePath/preflight-report.json"
        object_fetch_report = "$payloadBasePath/object-fetch-report.json"
        fail_closed_result = "$payloadBasePath/installer-byte-fail-closed.json"
        compatibility = "/install/compatibility.json"
        rollback_baseline = "/install/rollback-baseline.json"
    }
    blockers = @(
        "external-https-object-fetch",
        "external-https-object-uri-not-published",
        "declared-current-artifact-drift-unresolved",
        "exact-operator-approval-pending",
        "controlled-execution-not-authorized"
    )
    projection = [ordered]@{
        payload_index_sha256 = $payloadIndexHash
        object_descriptor_sha256 = Get-FileSha256 $resolvedDescriptorPath
        signature_receipt_sha256 = Get-FileSha256 $resolvedSignatureReceiptPath
        installer_preflight_result_sha256 = Get-FileSha256 $resolvedInstallerVmPreflightResultPath
        installer_byte_fail_closed_sha256 = Get-FileSha256 $resolvedInstallerByteFailClosedResultPath
        installer_compatibility_sha256 = $descriptor.installer_compatibility_sha256
        rollback_baseline_sha256 = $descriptor.rollback_baseline_sha256
    }
    forbidden_authority = @(
        "signing",
        "payload-upload",
        "remote-payload-download-before-external-object",
        "install",
        "activation",
        "rollback-execution",
        "active-slot-mutation",
        "production-ring-mutation",
        "support-upload",
        "remote-dispatch",
        "tui-authority"
    )
}
$installBootstrapText = Get-JsonText $installBootstrap
$installBootstrapHash = Get-StringSha256 $installBootstrapText

$channelIndex = [ordered]@{
    schema = "agentos.rc8-mirror-channel-index.v1"
    generated_at = $generatedAt
    status = "metadata-only"
    production_ready_claim = $false
    domain = $Domain
    current_release_id = $releaseId
    payload_channel = [ordered]@{
        index_path = "/payloads/index.json"
        default_release_id = $releaseId
        payload_index_sha256 = $payloadIndexHash
        install_bootstrap_path = "/install/bootstrap.json"
        install_bootstrap_sha256 = $installBootstrapHash
        object_descriptor_path = "$payloadBasePath/object-descriptor.json"
        object_descriptor_sha256 = Get-FileSha256 $resolvedDescriptorPath
        public_signature_ingested = $true
        cryptographic_signature_present = $true
        installer_vm_smoke_completed = $true
        installer_fail_closed_cases = $installerByteFailClosed.summary.cases
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        payload_bytes_hosted_on_mirror = $false
    }
    entries = @(
        [ordered]@{
            id = "rc8-payload-index"
            path = "/payloads/index.json"
            kind = "payload-index"
            sha256 = $payloadIndexHash
            status = "verification-blocked"
        },
        [ordered]@{
            id = "rc8-install-bootstrap"
            path = "/install/bootstrap.json"
            kind = "installer-bootstrap"
            sha256 = $installBootstrapHash
            status = "verification-blocked"
        },
        [ordered]@{
            id = "rc8-object-descriptor"
            path = "$payloadBasePath/object-descriptor.json"
            kind = "object-descriptor"
            sha256 = Get-FileSha256 $resolvedDescriptorPath
            status = "candidate-verification-blocked"
        },
        [ordered]@{
            id = "rc8-signature-receipt"
            path = "$payloadBasePath/signature-receipt.json"
            kind = "public-signature-receipt"
            sha256 = Get-FileSha256 $resolvedSignatureReceiptPath
            status = "public-signature-ingested"
        },
        [ordered]@{
            id = "rc8-installer-preflight"
            path = "$payloadBasePath/installer-vm-preflight.json"
            kind = "installer-vm-preflight"
            sha256 = Get-FileSha256 $resolvedInstallerVmPreflightResultPath
            status = "verification-blocked"
        },
        [ordered]@{
            id = "rc8-installer-fail-closed"
            path = "$payloadBasePath/installer-byte-fail-closed.json"
            kind = "fail-closed-fixtures"
            sha256 = Get-FileSha256 $resolvedInstallerByteFailClosedResultPath
            status = "passed"
        }
    )
    authority = [ordered]@{
        signing_authority = $false
        install_authority = $false
        activation_authority = $false
        rollback_execution_authority = $false
        support_upload_authority = $false
        production_ring_mutation_authority = $false
        remote_dispatch_authority = $false
        tui_authority = $false
    }
}
$channelIndexText = Get-JsonText $channelIndex
$channelIndexHash = Get-StringSha256 $channelIndexText

$mirrorStatus = [ordered]@{
    schema = "agentos.rc8-mirror-status.v1"
    generated_at = $generatedAt
    status = "verification-blocked"
    production_ready_claim = $false
    release_id = $releaseId
    domain = $Domain
    payload_bytes_hosted_on_mirror = $false
    public_signature_ingested = $true
    signature_crypto_verified = $true
    installer_vm_smoke_completed = $true
    fail_closed_cases = $installerByteFailClosed.summary.cases
    fail_closed_failed_cases = $installerByteFailClosed.summary.failed_cases
    blockers = @(
        "external-https-object-uri-not-published",
        "declared-current-artifact-drift-unresolved",
        "exact-operator-approval-pending",
        "controlled-execution-not-authorized"
    )
}
$mirrorStatusText = Get-JsonText $mirrorStatus

$indexHtml = @'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <title>AIOS RC8 Mirror</title>
  <link rel="stylesheet" href="/assets/mirror.css">
</head>
<body>
  <div class="shell">
    <header class="topbar">
      <a class="brand" href="/" aria-label="AIOS mirror home">
        <canvas id="brand-sigil" width="44" height="44" aria-hidden="true"></canvas>
        <span><strong>AIOS Mirror</strong><small>aios.w33d.xyz</small></span>
      </a>
      <nav class="nav" aria-label="Mirror navigation">
        <a href="/channel/index.json">Channel</a>
        <a href="/payloads/index.json">Payloads</a>
        <a href="/install/bootstrap.json">Install</a>
        <a href="/.well-known/aios/rc8-mirror-status.json">Status</a>
      </nav>
    </header>
    <main>
      <section class="hero" aria-labelledby="hero-title">
        <div>
          <p class="eyebrow">Production Distro RC8</p>
          <h1 id="hero-title">AIOS real payload mirror</h1>
        </div>
        <div class="hero-status">
          <span id="status-service" class="status-pill neutral">loading</span>
          <span id="status-ga" class="status-pill caution">non-GA</span>
          <span id="status-install" class="status-pill caution">install blocked</span>
        </div>
      </section>
      <section class="summary-grid" aria-label="RC8 mirror summary">
        <article class="metric"><span>Release</span><strong id="metric-release">-</strong><small id="metric-state">-</small></article>
        <article class="metric"><span>Payload Object</span><strong id="metric-object">-</strong><small id="metric-size">-</small></article>
        <article class="metric"><span>Signature</span><strong id="metric-signature">-</strong><small id="metric-signature-detail">-</small></article>
        <article class="metric"><span>Installer Gate</span><strong id="metric-install">-</strong><small id="metric-blockers">-</small></article>
      </section>
      <section class="main-grid">
        <section class="panel map-panel">
          <div class="panel-head"><h2>Trust Path</h2><span id="map-caption">metadata transport, local verification</span></div>
          <canvas id="trust-map" width="980" height="360" aria-label="RC8 mirror trust path"></canvas>
        </section>
        <section class="panel">
          <div class="panel-head"><h2>Verification Gates</h2><span id="checks-count">0 gates</span></div>
          <ul id="checks-list" class="checks-list"></ul>
        </section>
      </section>
      <section class="lower-grid">
        <section class="panel">
          <div class="panel-head"><h2>Mirror Directory</h2><span id="directory-count">0 entries</span></div>
          <div class="table-wrap">
            <table><thead><tr><th>Path</th><th>Type</th><th>Status</th><th>Policy</th></tr></thead><tbody id="directory-body"></tbody></table>
          </div>
        </section>
        <section class="panel">
          <div class="panel-head"><h2>Hash Bindings</h2><span id="hash-count">0 hashes</span></div>
          <dl id="hash-list" class="hash-list"></dl>
        </section>
      </section>
    </main>
  </div>
  <script src="/assets/mirror.js" defer></script>
</body>
</html>
'@

$css = @'
:root {
  --paper: #f7f8f2;
  --surface: #ffffff;
  --ink: #17211d;
  --muted: #63736b;
  --line: #d8ded3;
  --green: #20794f;
  --teal: #2f6f78;
  --blue: #315f9d;
  --amber: #ad6a19;
  --red: #a33a31;
  --shadow: 0 16px 36px rgba(24, 33, 29, 0.08);
}
* { box-sizing: border-box; }
body {
  margin: 0;
  color: var(--ink);
  background:
    linear-gradient(180deg, rgba(255,255,255,.92), rgba(247,248,242,.98)),
    linear-gradient(90deg, rgba(47,111,120,.08) 1px, transparent 1px),
    linear-gradient(0deg, rgba(49,95,157,.06) 1px, transparent 1px);
  background-size: auto, 72px 72px, 72px 72px;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  letter-spacing: 0;
}
a { color: inherit; text-decoration: none; }
.shell { width: min(1220px, calc(100vw - 32px)); margin: 0 auto; padding: 18px 0 44px; }
.topbar { min-height: 64px; display: flex; align-items: center; justify-content: space-between; gap: 18px; border-bottom: 1px solid var(--line); }
.brand { display: flex; align-items: center; gap: 12px; }
#brand-sigil { width: 44px; height: 44px; border-radius: 8px; border: 1px solid rgba(24,33,29,.12); background: #f9fbf6; }
.brand strong, .brand small { display: block; }
.brand small { color: var(--muted); margin-top: 2px; }
.nav { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 6px; }
.nav a { min-height: 34px; padding: 8px 11px; border-radius: 8px; border: 1px solid transparent; color: var(--muted); font-weight: 800; font-size: .88rem; }
.nav a:hover, .nav a:focus-visible { border-color: var(--line); color: var(--ink); background: rgba(255,255,255,.86); }
.hero { min-height: 154px; display: flex; align-items: end; justify-content: space-between; gap: 24px; padding: 30px 0 22px; }
.eyebrow, .metric span { margin: 0 0 8px; color: var(--muted); font-size: .78rem; font-weight: 800; text-transform: uppercase; }
h1, h2 { margin: 0; letter-spacing: 0; }
h1 { max-width: 850px; font-size: clamp(2.15rem, 6.8vw, 5.15rem); line-height: .96; }
h2 { font-size: 1rem; }
.hero-status { display: flex; justify-content: flex-end; flex-wrap: wrap; gap: 8px; }
.status-pill { display: inline-flex; align-items: center; min-height: 30px; padding: 6px 10px; border-radius: 999px; border: 1px solid var(--line); background: var(--surface); color: var(--muted); font-size: .82rem; font-weight: 800; white-space: nowrap; }
.status-pill.ok { color: var(--green); border-color: rgba(32,121,79,.28); background: #edf7f1; }
.status-pill.caution { color: var(--amber); border-color: rgba(173,106,25,.3); background: #fff5e7; }
.status-pill.bad { color: var(--red); border-color: rgba(163,58,49,.3); background: #fff0ed; }
.summary-grid, .main-grid, .lower-grid { display: grid; gap: 12px; }
.summary-grid { grid-template-columns: repeat(4, minmax(0, 1fr)); margin-bottom: 12px; }
.main-grid { grid-template-columns: minmax(0, 1.5fr) minmax(318px, .78fr); margin-bottom: 12px; }
.lower-grid { grid-template-columns: minmax(0, 1.1fr) minmax(340px, .8fr); }
.metric, .panel { background: rgba(255,255,255,.92); border: 1px solid var(--line); border-radius: 8px; box-shadow: var(--shadow); }
.metric { min-height: 132px; padding: 16px; }
.metric strong { display: block; min-height: 32px; font-size: 1.22rem; line-height: 1.18; overflow-wrap: anywhere; }
.metric small { display: block; margin-top: 10px; color: var(--muted); overflow-wrap: anywhere; }
.panel { padding: 16px; }
.panel-head { min-height: 36px; display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 12px; }
.panel-head span { color: var(--muted); font-size: .86rem; font-weight: 800; }
#trust-map { width: 100%; height: 318px; display: block; border: 1px solid var(--line); border-radius: 8px; background: #fbfcf8; }
.checks-list { display: grid; gap: 9px; padding: 0; margin: 0; list-style: none; }
.checks-list li { display: grid; grid-template-columns: 10px minmax(0, 1fr); gap: 10px; align-items: start; min-height: 28px; color: var(--muted); }
.checks-list li::before { content: ""; width: 10px; height: 10px; margin-top: 6px; border-radius: 999px; background: var(--green); }
.checks-list li.warn::before { background: var(--amber); }
.checks-list li.block::before { background: var(--red); }
.checks-list strong { display: block; color: var(--ink); font-size: .92rem; overflow-wrap: anywhere; }
.checks-list span { display: block; margin-top: 2px; overflow-wrap: anywhere; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 11px 10px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; font-size: .9rem; overflow-wrap: anywhere; }
th { color: var(--muted); font-size: .78rem; text-transform: uppercase; }
.hash-list { display: grid; grid-template-columns: minmax(150px, .42fr) minmax(0, 1fr); gap: 9px 12px; margin: 0; }
.hash-list dt { color: var(--muted); font-weight: 800; }
.hash-list dd { margin: 0; font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace; font-size: .82rem; overflow-wrap: anywhere; }
@media (max-width: 920px) { .topbar, .hero { align-items: flex-start; flex-direction: column; } .nav { justify-content: flex-start; } .summary-grid, .main-grid, .lower-grid { grid-template-columns: 1fr; } h1 { font-size: clamp(2.2rem, 13vw, 4.2rem); } }
@media (max-width: 560px) { .shell { width: min(100% - 20px, 1220px); padding-top: 10px; } .hero { min-height: 0; } .metric, .panel { padding: 13px; } #trust-map { height: 260px; } .hash-list { grid-template-columns: 1fr; } }
'@

$js = @'
const state = {};
const endpoints = {
  status: "/.well-known/aios/rc8-mirror-status.json",
  channel: "/channel/index.json",
  payloadIndex: "/payloads/index.json",
  install: "/install/bootstrap.json",
  compatibility: "/install/compatibility.json",
  rollback: "/install/rollback-baseline.json"
};
const byId = (id) => document.getElementById(id);
const text = (id, value) => { const node = byId(id); if (node) node.textContent = value == null || value === "" ? "-" : String(value); };
const setPill = (id, value, kind) => { const node = byId(id); if (node) { node.textContent = value; node.className = `status-pill ${kind || "neutral"}`; } };
async function getJson(path) {
  const res = await fetch(path, { cache: "no-store" });
  if (!res.ok) throw new Error(`${path} ${res.status}`);
  return res.json();
}
function firstEntry() { return (state.payloadIndex?.entries || [])[0] || {}; }
function shortHash(value) { return value ? String(value).slice(0, 12) : "-"; }
function boolWord(value) { return value ? "true" : "false"; }
async function loadData() {
  const base = await Promise.allSettled(Object.entries(endpoints).map(async ([key, path]) => [key, await getJson(path)]));
  base.forEach((item) => { if (item.status === "fulfilled") state[item.value[0]] = item.value[1]; });
  const entry = firstEntry();
  const detailPaths = {
    descriptor: entry.object_descriptor_path,
    signature: entry.signature_receipt_path,
    signatureSummary: entry.signature_summary_path,
    preflight: entry.installer_preflight_result_path,
    failClosed: entry.installer_fail_closed_result_path
  };
  const details = await Promise.allSettled(Object.entries(detailPaths).filter(([, path]) => path).map(async ([key, path]) => [key, await getJson(path)]));
  details.forEach((item) => { if (item.status === "fulfilled") state[item.value[0]] = item.value[1]; });
}
function renderSummary() {
  const entry = firstEntry();
  const install = state.install || {};
  setPill("status-service", state.status ? "online" : "metadata unavailable", state.status ? "ok" : "bad");
  setPill("status-ga", state.channel?.production_ready_claim ? "GA claim" : "non-GA", state.channel?.production_ready_claim ? "bad" : "caution");
  setPill("status-install", install.install_allowed ? "install allowed" : "install blocked", install.install_allowed ? "bad" : "caution");
  text("metric-release", entry.release_id || install.default_release_id);
  text("metric-state", entry.status || state.status?.status);
  text("metric-object", shortHash(entry.object_sha256 || state.descriptor?.sha256));
  text("metric-size", `${entry.object_size_bytes || state.descriptor?.size_bytes || "-"} bytes`);
  text("metric-signature", entry.crypto_verified ? "verified" : "blocked");
  text("metric-signature-detail", `public=${boolWord(entry.public_signature_ingested)} crypto=${boolWord(entry.crypto_verified)}`);
  text("metric-install", install.current_state || "verification-blocked");
  text("metric-blockers", `${(install.blockers || state.status?.blockers || []).length} blockers`);
}
function addCheck(list, label, detail, kind) {
  const li = document.createElement("li");
  li.className = kind || "";
  li.innerHTML = `<div><strong>${label}</strong><span>${detail}</span></div>`;
  list.appendChild(li);
}
function renderChecks() {
  const list = byId("checks-list");
  if (!list) return;
  list.innerHTML = "";
  const entry = firstEntry();
  const install = state.install || {};
  addCheck(list, "Immutable object descriptor", entry.object_descriptor_sha256 ? shortHash(entry.object_descriptor_sha256) : "missing", entry.object_descriptor_sha256 ? "" : "block");
  addCheck(list, "Public signature receipt", entry.signature_receipt_sha256 ? shortHash(entry.signature_receipt_sha256) : "missing", entry.signature_receipt_sha256 ? "" : "block");
  addCheck(list, "Signature crypto", entry.crypto_verified ? "verified" : "not verified", entry.crypto_verified ? "" : "block");
  addCheck(list, "Installer VM smoke", state.status?.installer_vm_smoke_completed ? "completed" : "missing", state.status?.installer_vm_smoke_completed ? "" : "block");
  addCheck(list, "Fail-closed fixtures", `${state.status?.fail_closed_cases || 0} cases`, state.status?.fail_closed_failed_cases ? "block" : "");
  addCheck(list, "External object URI", install.external_https_object_uri_published ? "published" : "not published", install.external_https_object_uri_published ? "" : "warn");
  addCheck(list, "Install authority", install.install_allowed ? "allowed" : "blocked", install.install_allowed ? "block" : "warn");
  text("checks-count", `${list.children.length} gates`);
}
function renderDirectory() {
  const body = byId("directory-body");
  if (!body) return;
  const entry = firstEntry();
  const rows = [
    ["/channel/index.json", "channel", state.channel?.status, "metadata-only"],
    ["/payloads/index.json", "payload index", state.payloadIndex?.status, "metadata-only"],
    [entry.object_descriptor_path, "object descriptor", state.descriptor?.descriptor_state, "hash-bound"],
    [entry.signature_receipt_path, "signature receipt", state.signature?.verification_status, "public artifact"],
    [entry.signature_summary_path, "signature summary", state.signatureSummary?.status, "redacted"],
    [entry.installer_preflight_result_path, "installer preflight", state.preflight?.summary?.preflight_state, "preflight-only"],
    [entry.installer_fail_closed_result_path, "fail-closed result", state.failClosed?.status, "negative fixtures"],
    ["/install/bootstrap.json", "install", state.install?.current_state, "blocked"],
    ["/install/compatibility.json", "compatibility", state.compatibility?.status, "published"],
    ["/install/rollback-baseline.json", "rollback", state.rollback?.status, "execution-blocked"]
  ].filter((row) => row[0]);
  body.innerHTML = rows.map(([path, type, status, policy]) => `<tr><td><a href="${path}">${path}</a></td><td>${type || "-"}</td><td>${status || "-"}</td><td>${policy || "-"}</td></tr>`).join("");
  text("directory-count", `${rows.length} entries`);
}
function renderHashes() {
  const entry = firstEntry();
  const pairs = [
    ["payload index", state.channel?.payload_channel?.payload_index_sha256],
    ["install bootstrap", state.channel?.payload_channel?.install_bootstrap_sha256],
    ["object descriptor", entry.object_descriptor_sha256],
    ["signature receipt", entry.signature_receipt_sha256],
    ["installer preflight", entry.installer_preflight_result_sha256],
    ["fail-closed", entry.installer_fail_closed_result_sha256],
    ["revocation", entry.revocation_snapshot_sha256],
    ["compatibility", entry.compatibility_sha256],
    ["rollback", entry.rollback_baseline_sha256]
  ].filter(([, value]) => value);
  const list = byId("hash-list");
  if (!list) return;
  list.innerHTML = pairs.map(([key, value]) => `<dt>${key}</dt><dd>${value}</dd>`).join("");
  text("hash-count", `${pairs.length} hashes`);
}
function drawSigil() {
  const canvas = byId("brand-sigil");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = "#f9fbf6"; ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.strokeStyle = "#2f6f78"; ctx.lineWidth = 3; ctx.beginPath(); ctx.moveTo(10, 30); ctx.lineTo(22, 9); ctx.lineTo(34, 30); ctx.closePath(); ctx.stroke();
  ctx.fillStyle = "#20794f"; ctx.fillRect(14, 29, 16, 4);
}
function drawTrustMap() {
  const canvas = byId("trust-map");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const nodes = [
    ["Mirror", "metadata-only", 120, 128, "#2f6f78"],
    ["Object", "hash-bound", 315, 92, "#315f9d"],
    ["Signature", "public verified", 520, 128, "#20794f"],
    ["Preflight", state.install?.current_state || "blocked", 725, 92, "#ad6a19"],
    ["Execution", "not authorized", 860, 235, "#a33a31"]
  ];
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = "#fbfcf8"; ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.lineWidth = 3; ctx.strokeStyle = "#c7d2ca"; ctx.beginPath(); ctx.moveTo(120, 128); ctx.bezierCurveTo(250, 60, 430, 60, 520, 128); ctx.bezierCurveTo(640, 188, 690, 120, 725, 92); ctx.bezierCurveTo(780, 150, 830, 195, 860, 235); ctx.stroke();
  nodes.forEach(([title, caption, x, y, color]) => {
    ctx.fillStyle = color; ctx.beginPath(); ctx.arc(x, y, 28, 0, Math.PI * 2); ctx.fill();
    ctx.fillStyle = "#fff"; ctx.font = "700 16px system-ui"; ctx.textAlign = "center"; ctx.fillText(title.slice(0, 2).toUpperCase(), x, y + 6);
    ctx.fillStyle = "#17211d"; ctx.font = "700 15px system-ui"; ctx.fillText(title, x, y + 52);
    ctx.fillStyle = "#61716a"; ctx.font = "13px system-ui"; ctx.fillText(caption, x, y + 72);
  });
}
function render() { renderSummary(); renderChecks(); renderDirectory(); renderHashes(); drawSigil(); drawTrustMap(); }
loadData().then(render).catch((error) => { setPill("status-service", "metadata error", "bad"); text("metric-release", error.message); drawSigil(); drawTrustMap(); });
'@

$payloadIndexPath = Join-Path $resolvedArtifactDir "hosted-payload-index.json"
$installBootstrapPath = Join-Path $resolvedArtifactDir "install-bootstrap.json"
$channelIndexPath = Join-Path $resolvedArtifactDir "hosted-channel-index.json"
$mirrorStatusPath = Join-Path $resolvedArtifactDir "mirror-status.json"
$indexPath = Join-Path $resolvedArtifactDir "index.html"
$cssPath = Join-Path $resolvedArtifactDir "mirror.css"
$jsPath = Join-Path $resolvedArtifactDir "mirror.js"
Write-Json $payloadIndex $payloadIndexPath
Write-Json $installBootstrap $installBootstrapPath
Write-Json $channelIndex $channelIndexPath
Write-Json $mirrorStatus $mirrorStatusPath
Write-TextFile $indexPath $indexHtml
Write-TextFile $cssPath $css
Write-TextFile $jsPath $js

$localSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $payloadIndexPath),
    (Get-Content -Raw -LiteralPath $installBootstrapPath),
    (Get-Content -Raw -LiteralPath $channelIndexPath),
    (Get-Content -Raw -LiteralPath $mirrorStatusPath),
    $descriptorText,
    $signatureReceiptText,
    $signatureSummaryText,
    $preflightResultText,
    $preflightReportText,
    $objectFetchReportText,
    $installerFailClosedText,
    $indexHtml,
    $css,
    $js
)
$localSizeBounded = (Get-Item $payloadIndexPath).Length -lt 262144 -and
    (Get-Item $installBootstrapPath).Length -lt 131072 -and
    (Get-Item $channelIndexPath).Length -lt 131072 -and
    (Get-Item $mirrorStatusPath).Length -lt 65536 -and
    (Get-Item $indexPath).Length -lt 65536 -and
    (Get-Item $cssPath).Length -lt 131072 -and
    (Get-Item $jsPath).Length -lt 131072

Add-Check "local.outputs.ready" ((Test-Path $payloadIndexPath) -and (Test-Path $installBootstrapPath) -and (Test-Path $channelIndexPath) -and (Test-Path $mirrorStatusPath) -and (Test-Path $indexPath) -and (Test-Path $cssPath) -and (Test-Path $jsPath)) "RC8 mirror metadata and frontend outputs must be generated locally." ([ordered]@{
    payload_index = Get-StablePath $payloadIndexPath
    install_bootstrap = Get-StablePath $installBootstrapPath
    channel_index = Get-StablePath $channelIndexPath
    mirror_status = Get-StablePath $mirrorStatusPath
    index = Get-StablePath $indexPath
    css = Get-StablePath $cssPath
    js = Get-StablePath $jsPath
})
Add-Check "local.outputs.secret_safe" $localSecretSafe "RC8 mirror metadata and frontend outputs must not contain private key paths, PEM private blocks, or tokens." $null
Add-Check "local.outputs.size_bounded" $localSizeBounded "RC8 mirror metadata and frontend outputs must stay bounded for the small mirror host." ([ordered]@{
    payload_index = (Get-Item $payloadIndexPath).Length
    install_bootstrap = (Get-Item $installBootstrapPath).Length
    channel_index = (Get-Item $channelIndexPath).Length
    mirror_status = (Get-Item $mirrorStatusPath).Length
    index_html = (Get-Item $indexPath).Length
    mirror_css = (Get-Item $cssPath).Length
    mirror_js = (Get-Item $jsPath).Length
})

Set-RemoteTextFile -Path "/srv/aios-mirror/payloads/index.json" -Text $payloadIndexText
Set-RemoteTextFile -Path "/srv/aios-mirror/install/bootstrap.json" -Text $installBootstrapText
Set-RemoteTextFile -Path "/srv/aios-mirror/channel/index.json" -Text $channelIndexText
Set-RemoteTextFile -Path "/srv/aios-mirror/.well-known/aios/rc8-mirror-status.json" -Text $mirrorStatusText
Set-RemoteTextFile -Path "/srv/aios-mirror$payloadBasePath/object-descriptor.json" -Text $descriptorText
Set-RemoteTextFile -Path "/srv/aios-mirror$payloadBasePath/signature-receipt.json" -Text $signatureReceiptText
Set-RemoteTextFile -Path "/srv/aios-mirror$payloadBasePath/signature-summary.json" -Text $signatureSummaryText
Set-RemoteTextFile -Path "/srv/aios-mirror$payloadBasePath/installer-vm-preflight.json" -Text $preflightResultText
Set-RemoteTextFile -Path "/srv/aios-mirror$payloadBasePath/preflight-report.json" -Text $preflightReportText
Set-RemoteTextFile -Path "/srv/aios-mirror$payloadBasePath/object-fetch-report.json" -Text $objectFetchReportText
Set-RemoteTextFile -Path "/srv/aios-mirror$payloadBasePath/installer-byte-fail-closed.json" -Text $installerFailClosedText
Set-RemoteTextFile -Path "/srv/aios-mirror/index.html" -Text $indexHtml
Set-RemoteTextFile -Path "/srv/aios-mirror/assets/mirror.css" -Text $css
Set-RemoteTextFile -Path "/srv/aios-mirror/assets/mirror.js" -Text $js

$remoteCheck = Invoke-Remote "set -eu; systemctl is-active nginx; cd /srv/aios-mirror; sha256sum index.html assets/mirror.css assets/mirror.js payloads/index.json install/bootstrap.json channel/index.json .well-known/aios/rc8-mirror-status.json $($payloadBasePath.TrimStart('/'))/object-descriptor.json $($payloadBasePath.TrimStart('/'))/signature-receipt.json $($payloadBasePath.TrimStart('/'))/installer-vm-preflight.json $($payloadBasePath.TrimStart('/'))/installer-byte-fail-closed.json"

$after = [ordered]@{
    root = Invoke-Curl "/"
    css = Invoke-Curl "/assets/mirror.css"
    js = Invoke-Curl "/assets/mirror.js"
    payload_index = Invoke-Curl "/payloads/index.json"
    install_bootstrap = Invoke-Curl "/install/bootstrap.json"
    channel = Invoke-Curl "/channel/index.json"
    mirror_status = Invoke-Curl "/.well-known/aios/rc8-mirror-status.json"
    object_descriptor = Invoke-Curl "$payloadBasePath/object-descriptor.json"
    signature_receipt = Invoke-Curl "$payloadBasePath/signature-receipt.json"
    signature_summary = Invoke-Curl "$payloadBasePath/signature-summary.json"
    installer_preflight = Invoke-Curl "$payloadBasePath/installer-vm-preflight.json"
    preflight_report = Invoke-Curl "$payloadBasePath/preflight-report.json"
    object_fetch_report = Invoke-Curl "$payloadBasePath/object-fetch-report.json"
    installer_fail_closed = Invoke-Curl "$payloadBasePath/installer-byte-fail-closed.json"
}
$preservedAfter = [ordered]@{
    health = Invoke-Curl "/health.json"
    mirror_descriptor = Invoke-Curl "/.well-known/aios/mirror.json"
    compatibility = Invoke-Curl "/install/compatibility.json"
    rollback_baseline = Invoke-Curl "/install/rollback-baseline.json"
    support_index = Invoke-Curl "/support/index.json"
}
$payloadDirResponse = Invoke-Curl "/payloads/"
$payloadReleaseDirResponse = Invoke-Curl "$payloadBasePath/"
$postResponse = Invoke-Curl "/payloads/index.json" -Method "POST"

$metadataReady = @($after.Values | Where-Object { $_.status_code -ne 200 }).Count -eq 0 -and
    @($after.Values | Where-Object { $_.path -notin @("/", "/assets/mirror.css", "/assets/mirror.js") -and $null -eq $_.json }).Count -eq 0
$frontendReady = $after.root.status_code -eq 200 -and $after.css.status_code -eq 200 -and $after.js.status_code -eq 200 -and $after.root.body.Contains("AIOS real payload mirror") -and $after.js.body.Contains("Immutable object descriptor")
$livePayload = $after.payload_index.json
$liveInstall = $after.install_bootstrap.json
$liveChannel = $after.channel.json
$liveStatus = $after.mirror_status.json
$liveDescriptor = $after.object_descriptor.json
$liveSignature = $after.signature_receipt.json
$livePreflight = $after.installer_preflight.json
$liveFailClosed = $after.installer_fail_closed.json
$semanticsReady = $null -ne $livePayload -and $null -ne $liveInstall -and $null -ne $liveChannel -and $null -ne $liveStatus -and
    $livePayload.entries[0].release_id -eq $releaseId -and
    $livePayload.entries[0].status -eq "verification-blocked" -and
    $livePayload.entries[0].install_allowed -eq $false -and
    $livePayload.entries[0].activation_allowed -eq $false -and
    $liveInstall.current_state -eq "verification-blocked" -and
    $liveInstall.install_allowed -eq $false -and
    $liveInstall.external_https_object_uri_published -eq $false -and
    $liveChannel.current_release_id -eq $releaseId -and
    $liveChannel.production_ready_claim -eq $false -and
    $liveStatus.payload_bytes_hosted_on_mirror -eq $false
$hashBindingsReady = $null -ne $livePayload -and $null -ne $liveInstall -and $null -ne $liveChannel -and
    $livePayload.entries[0].object_descriptor_sha256 -eq (Get-FileSha256 $resolvedDescriptorPath) -and
    $livePayload.entries[0].signature_receipt_sha256 -eq (Get-FileSha256 $resolvedSignatureReceiptPath) -and
    $livePayload.entries[0].installer_preflight_result_sha256 -eq (Get-FileSha256 $resolvedInstallerVmPreflightResultPath) -and
    $livePayload.entries[0].installer_fail_closed_result_sha256 -eq (Get-FileSha256 $resolvedInstallerByteFailClosedResultPath) -and
    $liveChannel.payload_channel.payload_index_sha256 -eq $payloadIndexHash -and
    $liveChannel.payload_channel.install_bootstrap_sha256 -eq $installBootstrapHash -and
    $liveInstall.projection.payload_index_sha256 -eq $payloadIndexHash
$sourceBindingReady = $null -ne $liveDescriptor -and $null -ne $liveSignature -and $null -ne $livePreflight -and $null -ne $liveFailClosed -and
    $liveDescriptor.sha256 -eq $descriptor.sha256 -and
    $liveSignature.crypto_verified -eq $true -and
    $livePreflight.status -eq "passed" -and
    $liveFailClosed.status -eq "passed"

$preservedAfterHashes = [ordered]@{}
foreach ($key in $preservedAfter.Keys) {
    $preservedAfterHashes[$key] = $preservedAfter[$key].sha256
}
$preservedMetadata = $true
foreach ($key in $preservedBefore.Keys) {
    if ($preservedBefore[$key] -ne $preservedAfterHashes[$key]) {
        $preservedMetadata = $false
    }
}
$remoteSecretSafe = Test-NoSensitiveText -Values @(
    $after.root.body,
    $after.css.body,
    $after.js.body,
    $after.payload_index.body,
    $after.install_bootstrap.body,
    $after.channel.body,
    $after.mirror_status.body,
    $after.object_descriptor.body,
    $after.signature_receipt.body,
    $after.signature_summary.body,
    $after.installer_preflight.body,
    $after.preflight_report.body,
    $after.object_fetch_report.body,
    $after.installer_fail_closed.body
)

Add-Check "remote.nginx.active" ($remoteCheck -match "active") "Nginx must remain active after RC8 mirror consistency refresh." ($remoteCheck -split "`n")
Add-Check "remote.https.metadata.ready" $metadataReady "RC8 frontend and metadata endpoints must be reachable over HTTPS through resolve-pinned validation." ([ordered]@{
    root = $after.root.status_code
    payload_index = $after.payload_index.status_code
    install_bootstrap = $after.install_bootstrap.status_code
    channel = $after.channel.status_code
    mirror_status = $after.mirror_status.status_code
    object_descriptor = $after.object_descriptor.status_code
    signature_receipt = $after.signature_receipt.status_code
    installer_preflight = $after.installer_preflight.status_code
    installer_fail_closed = $after.installer_fail_closed.status_code
})
Add-Check "remote.frontend.ready" $frontendReady "RC8 frontend must render the real payload mirror dashboard assets." ([ordered]@{ root = $after.root.status_code; css = $after.css.status_code; js = $after.js.status_code })
Add-Check "remote.rc8_semantics.blocked" $semanticsReady "Live RC8 mirror metadata must expose real payload evidence while keeping install, activation, and rollback blocked." ([ordered]@{
    release_id = if ($null -ne $livePayload) { $livePayload.entries[0].release_id } else { $null }
    install_state = if ($null -ne $liveInstall) { $liveInstall.current_state } else { $null }
    external_object = if ($null -ne $liveInstall) { $liveInstall.external_https_object_uri_published } else { $null }
})
Add-Check "remote.hash_bindings.match" $hashBindingsReady "Live RC8 channel, install bootstrap, and payload index hash bindings must match local artifacts." ([ordered]@{
    payload_index_sha256 = $payloadIndexHash
    install_bootstrap_sha256 = $installBootstrapHash
})
Add-Check "remote.source_evidence.visible" $sourceBindingReady "Live RC8 detail endpoints must expose descriptor, signature receipt, installer VM preflight, and fail-closed result evidence." ([ordered]@{
    descriptor_sha256 = if ($null -ne $liveDescriptor) { $liveDescriptor.sha256 } else { $null }
    signature_crypto_verified = if ($null -ne $liveSignature) { $liveSignature.crypto_verified } else { $null }
    preflight_status = if ($null -ne $livePreflight) { $livePreflight.status } else { $null }
    fail_closed_status = if ($null -ne $liveFailClosed) { $liveFailClosed.status } else { $null }
})
Add-Check "remote.preserved_metadata.unchanged" $preservedMetadata "RC8 refresh must not mutate health, mirror descriptor, compatibility, rollback baseline, or support metadata bytes." ([ordered]@{ before = $preservedBefore; after = $preservedAfterHashes })
Add-Check "remote.secret_safe" $remoteSecretSafe "Remote RC8 metadata and frontend responses must not expose private key paths, PEM private blocks, or tokens." $null
Add-Check "remote.directory_listing.blocked" ((@(403, 404) -contains $payloadDirResponse.status_code) -and (@(403, 404) -contains $payloadReleaseDirResponse.status_code)) "Payload directory listing must remain blocked." ([ordered]@{ payloads = $payloadDirResponse.status_code; release = $payloadReleaseDirResponse.status_code })
Add-Check "remote.write_methods.blocked" (@(403, 405) -contains $postResponse.status_code) "POST to RC8 payload metadata must remain blocked." $postResponse.status_code

$passed = @($script:blockers).Count -eq 0
$result = [ordered]@{
    schema = "agentos.rc8-mirror-consistency-refresh-result.v1"
    generated_at = $generatedAt
    checked_at = (Get-Date).ToString("o")
    task = "RC8-022"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    remote = [ordered]@{
        host = $RemoteHost
        user = $RemoteUser
        domain = $Domain
        static_root = "/srv/aios-mirror"
        validation_used_local_dns = $false
        https_resolve_override = "$Domain`:443`:$RemoteHost"
    }
    source = [ordered]@{
        descriptor = New-ArtifactRef $resolvedDescriptorPath $descriptor
        descriptor_result = New-ArtifactRef $resolvedDescriptorResultPath $descriptorResult
        signature_ingestion_result = New-ArtifactRef $resolvedSignatureIngestionResultPath $signatureIngestion
        signature_receipt = New-ArtifactRef $resolvedSignatureReceiptPath $signatureReceipt
        signature_summary = New-ArtifactRef $resolvedSignatureSummaryPath $signatureSummary
        signed_descriptor_fail_closed = New-ArtifactRef $resolvedSignedDescriptorFailClosedResultPath $signedDescriptorFailClosed
        installer_vm_preflight = New-ArtifactRef $resolvedInstallerVmPreflightResultPath $installerVmPreflight
        installer_byte_fail_closed = New-ArtifactRef $resolvedInstallerByteFailClosedResultPath $installerByteFailClosed
        tls_hardening = New-ArtifactRef $resolvedTlsHardeningResultPath $tlsHardening
    }
    local_outputs = [ordered]@{
        hosted_payload_index = Get-StablePath $payloadIndexPath
        install_bootstrap = Get-StablePath $installBootstrapPath
        hosted_channel_index = Get-StablePath $channelIndexPath
        mirror_status = Get-StablePath $mirrorStatusPath
        index_html = Get-StablePath $indexPath
        mirror_css = Get-StablePath $cssPath
        mirror_js = Get-StablePath $jsPath
    }
    published_files = [ordered]@{
        payload_index = "/srv/aios-mirror/payloads/index.json"
        install_bootstrap = "/srv/aios-mirror/install/bootstrap.json"
        channel_index = "/srv/aios-mirror/channel/index.json"
        mirror_status = "/srv/aios-mirror/.well-known/aios/rc8-mirror-status.json"
        object_descriptor = "/srv/aios-mirror$payloadBasePath/object-descriptor.json"
        signature_receipt = "/srv/aios-mirror$payloadBasePath/signature-receipt.json"
        signature_summary = "/srv/aios-mirror$payloadBasePath/signature-summary.json"
        installer_vm_preflight = "/srv/aios-mirror$payloadBasePath/installer-vm-preflight.json"
        preflight_report = "/srv/aios-mirror$payloadBasePath/preflight-report.json"
        object_fetch_report = "/srv/aios-mirror$payloadBasePath/object-fetch-report.json"
        installer_byte_fail_closed = "/srv/aios-mirror$payloadBasePath/installer-byte-fail-closed.json"
        index_html = "/srv/aios-mirror/index.html"
        mirror_css = "/srv/aios-mirror/assets/mirror.css"
        mirror_js = "/srv/aios-mirror/assets/mirror.js"
    }
    output_hashes = [ordered]@{
        hosted_payload_index_sha256 = $payloadIndexHash
        install_bootstrap_sha256 = $installBootstrapHash
        hosted_channel_index_sha256 = $channelIndexHash
        mirror_status_sha256 = Get-StringSha256 $mirrorStatusText
        index_html_sha256 = Get-FileSha256 $indexPath
        mirror_css_sha256 = Get-FileSha256 $cssPath
        mirror_js_sha256 = Get-FileSha256 $jsPath
    }
    preserved_metadata_hashes = [ordered]@{
        before = $preservedBefore
        after = $preservedAfterHashes
    }
    payload_surface = [ordered]@{
        release_id = $releaseId
        base_path = $payloadBasePath
        status = "verification-blocked"
        storage_mode = "metadata-only"
        payload_bytes_hosted_on_mirror = $false
        external_https_object_uri_published = $false
        public_signature_ingested = $true
        signature_crypto_verified = $true
        installer_vm_smoke_completed = $true
        fail_closed_cases = $installerByteFailClosed.summary.cases
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        blockers = @(
            "external-https-object-uri-not-published",
            "declared-current-artifact-drift-unresolved"
        )
    }
    invariants = [ordered]@{
        hosted_metadata_only = $true
        payload_bytes_uploaded = $false
        payload_bytes_hosted_on_mirror = $false
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
        production_ready_claim = $false
    }
    checks = $script:checks
    blockers = $script:blockers
    summary = [ordered]@{
        checks = @($script:checks).Count
        blockers = @($script:blockers).Count
        rc8_022_complete = $passed
        next_task = "RC8-030"
    }
}

Write-Json $result $resolvedResultPath
$resultText = Get-Content -Raw -LiteralPath $resolvedResultPath
if (-not (Test-NoSensitiveText -Values @($resultText))) {
    throw "Sensitive marker detected in RC8-022 result."
}

Write-Host "RC8 mirror consistency refresh $($result.status): $(Get-StablePath $resolvedResultPath)"
Write-Host "Checks: $(@($script:checks).Count), blockers: $(@($script:blockers).Count)"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
