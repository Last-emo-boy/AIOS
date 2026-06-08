param(
    [string]$RemoteHost = "47.101.11.109",
    [string]$RemoteUser = "root",
    [string]$Domain = "aios.w33d.xyz",
    [string]$ArtifactDir = ".workflow/artifacts/rc6-hosted-payload-metadata",
    [string]$ResultPath = "",
    [string]$PayloadProjectionDir = ".workflow/artifacts/rc6-installable-payload-manifest",
    [int]$SshConnectTimeoutSeconds = 10,
    [switch]$FailOnBlocked
)

$ErrorActionPreference = "Stop"

function Write-Json {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $parent = Split-Path -Parent $Path
    if ($parent) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    $Value | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Get-JsonText {
    param([Parameter(Mandatory = $true)]$Value)
    return ($Value | ConvertTo-Json -Depth 100)
}

function Get-StringSha256 {
    param([Parameter(Mandatory = $true)][string]$Value)
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Value)
    $hash = [Security.Cryptography.SHA256]::HashData($bytes)
    return ([BitConverter]::ToString($hash)).Replace("-", "").ToLowerInvariant()
}

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

function ConvertFrom-JsonTextSafe {
    param([Parameter(Mandatory = $true)][string]$Text)
    try {
        return ($Text | ConvertFrom-Json)
    } catch {
        return $null
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
    $output = & ssh @args 2>&1
    $exitCode = $LASTEXITCODE
    $text = ($output | Out-String).Trim()
    if ($exitCode -ne 0) {
        throw "Remote command failed ($exitCode): $text"
    }
    return $text
}

function Set-RemoteTextFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Text,
        [string]$Mode = "0644"
    )
    $encoded = [Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes($Text))
    $parent = [IO.Path]::GetDirectoryName($Path) -replace "\\", "/"
    $command = "set -eu; install -d -m 0755 '$parent'; printf '%s' '$encoded' | base64 -d > '$Path'; chmod '$Mode' '$Path'"
    Invoke-Remote $command | Out-Null
}

function Invoke-Curl {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [string]$Method = "GET"
    )
    $args = @(
        "--noproxy", "*",
        "--max-time", "15",
        "--resolve", "$Domain`:80`:$RemoteHost",
        "-sS",
        "-X", $Method,
        "-w", "`n%{http_code}",
        $Url
    )
    $output = & curl.exe @args 2>&1
    $exitCode = $LASTEXITCODE
    $text = ($output | Out-String).TrimEnd()
    $parts = [regex]::Split($text, "\r?\n")
    $statusText = $parts[-1]
    $body = if ($parts.Count -gt 1) { ($parts[0..($parts.Count - 2)] -join "`n") } else { "" }
    $statusCode = 0
    [void][int]::TryParse($statusText, [ref]$statusCode)
    return [ordered]@{
        exit_code = $exitCode
        status_code = $statusCode
        body = $body
        url = $Url
        method = $Method
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
    $markers = @(
        ("BEGIN " + "PRIVATE KEY"),
        ("PRIVATE KEY" + "-----"),
        ("Authorization:" + " Bearer"),
        ("Bearer" + " "),
        "access_token",
        "refresh_token",
        ".local-release-authority",
        ("signing" + "-key.pem")
    )
    foreach ($value in $Values) {
        foreach ($marker in $markers) {
            if ($value.Contains($marker, [StringComparison]::OrdinalIgnoreCase)) {
                return $false
            }
        }
    }
    return $true
}

function Has-FalseHostedAuthority {
    param($Value)
    if ($null -eq $Value) {
        return $false
    }
    return $Value.signing_authority -eq $false -and
        $Value.activation_authority -eq $false -and
        $Value.rollback_execution_authority -eq $false -and
        $Value.remote_dispatch_authority -eq $false -and
        $Value.tui_authority -eq $false
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
$resolvedProjectionDir = Resolve-RepoPath $PayloadProjectionDir

$projectionResultPath = Join-Path $resolvedProjectionDir "result.json"
$projectionIndexPath = Join-Path $resolvedProjectionDir "payload-index.json"
$projectionManifestPath = Join-Path $resolvedProjectionDir "payload-manifest.json"
$projectionChecksumsPath = Join-Path $resolvedProjectionDir "payload-checksums.json"
$projectionSignaturesPath = Join-Path $resolvedProjectionDir "payload-signatures.json"

$projectionResult = Read-Json $projectionResultPath
$projectionIndex = Read-Json $projectionIndexPath
$payloadManifest = Read-Json $projectionManifestPath
$payloadChecksums = Read-Json $projectionChecksumsPath
$payloadSignatures = Read-Json $projectionSignaturesPath

$generatedAt = (Get-Date).ToString("o")
$releaseId = $projectionResult.release_id
$payloadBasePath = "/payloads/aios/$releaseId"

$manifestText = Get-Content -Raw -LiteralPath $projectionManifestPath
$checksumsText = Get-Content -Raw -LiteralPath $projectionChecksumsPath
$signaturesText = Get-Content -Raw -LiteralPath $projectionSignaturesPath
$manifestFileHash = Get-FileSha256 $projectionManifestPath
$checksumsFileHash = Get-FileSha256 $projectionChecksumsPath
$signaturesFileHash = Get-FileSha256 $projectionSignaturesPath
$manifestContentHash = $projectionResult.outputs.payload_manifest.content_sha256
$checksumsContentHash = $projectionResult.outputs.payload_checksums.content_sha256
$signaturesContentHash = $projectionResult.outputs.payload_signatures.content_sha256

Add-Check "projection.result.passed" ($projectionResult.status -eq "passed" -and $projectionResult.summary.blockers -eq 0) "RC6-010 payload projection must be passed before publication." $projectionResult.summary
Add-Check "projection.surface.blocked" ($projectionResult.payload_surface.status -eq "verification-blocked" -and $projectionResult.payload_surface.install_allowed -eq $false -and $projectionResult.payload_surface.signature_available -eq $false) "Projected payload surface must remain verification-blocked." $projectionResult.payload_surface
Add-Check "projection.files.present" ((Test-Path -LiteralPath $projectionIndexPath -PathType Leaf) -and (Test-Path -LiteralPath $projectionManifestPath -PathType Leaf) -and (Test-Path -LiteralPath $projectionChecksumsPath -PathType Leaf) -and (Test-Path -LiteralPath $projectionSignaturesPath -PathType Leaf)) "Projection output files must exist." $resolvedProjectionDir
Add-Check "projection.no_authority" ($payloadManifest.install_policy.install_allowed -eq $false -and $payloadManifest.install_policy.activation_allowed -eq $false -and $payloadSignatures.signature_available -eq $false -and $payloadSignatures.signing_authority_on_mirror -eq $false) "Projected payload metadata must not grant signing, install, or activation authority." ([ordered]@{ install = $payloadManifest.install_policy; signatures = $payloadSignatures.status })

$hostedPayloadIndex = [ordered]@{
    schema = "agentos.rc6-hosted-payload-index.v1"
    generated_at = $generatedAt
    status = "metadata-projected"
    production_ready_claim = $false
    domain = $Domain
    channel = "production-candidate-rc6"
    storage_mode = "metadata-only"
    large_artifact_storage_deferred = $true
    tls_required_before_ga_claim = $true
    entries = @(
        [ordered]@{
            id = $releaseId
            release_id = $releaseId
            status = "verification-blocked"
            reason = "Current artifact metadata is published, but install remains blocked by missing signature, deferred large payload storage, TLS GA gate, and declared/current hash drift."
            manifest_path = "$payloadBasePath/manifest.json"
            checksums_path = "$payloadBasePath/checksums.json"
            signatures_path = "$payloadBasePath/signatures.json"
            manifest_sha256 = $manifestContentHash
            manifest_file_sha256 = $manifestFileHash
            checksums_sha256 = $checksumsContentHash
            checksums_file_sha256 = $checksumsFileHash
            signatures_sha256 = $signaturesContentHash
            signatures_file_sha256 = $signaturesFileHash
            install_allowed = $false
            activation_allowed = $false
            rollback_execution_allowed = $false
            large_payload_deferred = $true
            signature_available = $false
            installable_media_declared_hash_drift_count = $projectionResult.payload_surface.installable_media_declared_hash_drift_count
        }
    )
    source_bindings = $payloadManifest.source_bindings
    drift_policy = $payloadManifest.drift_policy
    authority = [ordered]@{
        mirror_is_root_of_trust = $false
        signing_authority = $false
        activation_authority = $false
        rollback_execution_authority = $false
        production_ring_mutation_authority = $false
        remote_dispatch_authority = $false
        support_upload_authority = $false
        tui_authority = $false
    }
}
$hostedPayloadIndexText = Get-JsonText $hostedPayloadIndex
$hostedPayloadIndexHash = Get-StringSha256 $hostedPayloadIndexText

$channelBeforeResponse = Invoke-Curl "http://$Domain/channel/index.json"
$installBeforeResponse = Invoke-Curl "http://$Domain/install/bootstrap.json"
$channelBefore = ConvertFrom-JsonTextSafe $channelBeforeResponse.body
$installBefore = ConvertFrom-JsonTextSafe $installBeforeResponse.body

Add-Check "remote.channel.before" ($channelBeforeResponse.status_code -eq 200 -and $null -ne $channelBefore) "Hosted channel index must be reachable before payload metadata publication." $channelBeforeResponse.status_code
Add-Check "remote.install.before" ($installBeforeResponse.status_code -eq 200 -and $null -ne $installBefore) "Hosted install bootstrap must be reachable before payload metadata publication." $installBeforeResponse.status_code

$installBootstrap = [ordered]@{
    schema = "agentos.rc6-install-bootstrap.v1"
    generated_at = $generatedAt
    status = "metadata-preflight-only"
    production_ready_claim = $false
    domain = $Domain
    channel = "production-candidate-rc6"
    default_release_id = $releaseId
    payload_index_path = "/payloads/index.json"
    installer_states = @("metadata-unavailable", "metadata-candidate", "verification-blocked", "install-preflight-ready", "install-authorized", "installed")
    rc6_allowed_states = @("metadata-unavailable", "metadata-candidate", "verification-blocked", "install-preflight-ready")
    current_state = "verification-blocked"
    install_allowed = $false
    activation_allowed = $false
    tls_required_before_ga_claim = $true
    storage_policy = "metadata-only"
    metadata_size_policy = if ($null -ne $installBefore) { $installBefore.metadata_size_policy } else { $null }
    endpoints = [ordered]@{
        health = "/health.json"
        mirror_descriptor = "/.well-known/aios/mirror.json"
        channel_index = "/channel/index.json"
        bootstrap_manifest = "/bootstrap/manifest.json"
        payload_index = "/payloads/index.json"
        payload_manifest = "$payloadBasePath/manifest.json"
        payload_checksums = "$payloadBasePath/checksums.json"
        payload_signatures = "$payloadBasePath/signatures.json"
        support_index = "/support/index.json"
        support_recovery = "/support/recovery.json"
    }
    blockers = @(
        "tls-not-yet-ga-gated",
        "large-payload-storage-deferred",
        "payload-signature-not-published",
        "revocation-snapshot-not-published",
        "installer-compatibility-contract-pending",
        "installable-media-declared-hash-drift",
        "rollback-execution-drill-pending",
        "exact-operator-approval-pending"
    )
    projection = [ordered]@{
        rc6_010_result = Get-StablePath $projectionResultPath
        payload_index_sha256 = $hostedPayloadIndexHash
        manifest_sha256 = $manifestContentHash
        checksums_sha256 = $checksumsContentHash
        signatures_sha256 = $signaturesContentHash
        drifted_components = @($payloadManifest.drift_policy.drifted_components)
    }
    forbidden_authority = @(
        "signing",
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

$preservedEntries = @()
if ($null -ne $channelBefore -and $null -ne $channelBefore.entries) {
    $preservedEntries = @($channelBefore.entries | Where-Object {
        $_.id -notin @("rc6-payload-index", "rc6-install-bootstrap", "rc6-payload-manifest", "rc6-payload-checksums", "rc6-payload-signatures", "rc6-current-payload-manifest", "rc6-current-payload-checksums", "rc6-current-payload-signatures")
    })
}
$rc6Entries = @(
    [ordered]@{
        id = "rc6-payload-index"
        status = "available"
        path = "/payloads/index.json"
        kind = "payload-metadata-index"
        sha256 = $hostedPayloadIndexHash
        install_allowed = $false
        activation_allowed = $false
        large_payload_deferred = $true
    },
    [ordered]@{
        id = "rc6-install-bootstrap"
        status = "available"
        path = "/install/bootstrap.json"
        kind = "installer-bootstrap-metadata"
        sha256 = $installBootstrapHash
        install_allowed = $false
        activation_allowed = $false
        large_payload_deferred = $true
    },
    [ordered]@{
        id = "rc6-current-payload-manifest"
        status = "verification-blocked"
        path = "$payloadBasePath/manifest.json"
        kind = "payload-manifest"
        sha256 = $manifestContentHash
        file_sha256 = $manifestFileHash
        install_allowed = $false
        activation_allowed = $false
        large_payload_deferred = $true
    },
    [ordered]@{
        id = "rc6-current-payload-checksums"
        status = "verification-blocked"
        path = "$payloadBasePath/checksums.json"
        kind = "payload-checksums"
        sha256 = $checksumsContentHash
        file_sha256 = $checksumsFileHash
        install_allowed = $false
        activation_allowed = $false
    },
    [ordered]@{
        id = "rc6-current-payload-signatures"
        status = "signature-required"
        path = "$payloadBasePath/signatures.json"
        kind = "payload-signature-metadata"
        sha256 = $signaturesContentHash
        file_sha256 = $signaturesFileHash
        signature_available = $false
        install_allowed = $false
        activation_allowed = $false
    }
)

$hostedChannel = [ordered]@{
    schema = "agentos.rc6-hosted-channel-index.v1"
    status = "metadata-only"
    channel = "production-candidate-rc6"
    domain = $Domain
    generated_at = $generatedAt
    production_ready_claim = $false
    storage_mode = "metadata-only"
    source_rc4_final_audit_sha256 = if ($null -ne $channelBefore) { $channelBefore.source_rc4_final_audit_sha256 } else { $null }
    hosted_transport_manifest_sha256 = if ($null -ne $channelBefore) { $channelBefore.hosted_transport_manifest_sha256 } else { $null }
    mirror_publication_sha256 = if ($null -ne $channelBefore) { $channelBefore.mirror_publication_sha256 } else { $null }
    freshness_window = "P7D"
    entries = @($preservedEntries + $rc6Entries)
    support_recovery = if ($null -ne $channelBefore) { $channelBefore.support_recovery } else { $null }
    payload_channel = [ordered]@{
        index_path = "/payloads/index.json"
        install_bootstrap_path = "/install/bootstrap.json"
        default_release_id = $releaseId
        payload_index_sha256 = $hostedPayloadIndexHash
        install_bootstrap_sha256 = $installBootstrapHash
        payload_manifest_sha256 = $manifestContentHash
        payload_checksums_sha256 = $checksumsContentHash
        payload_signatures_sha256 = $signaturesContentHash
        metadata_only = $true
        large_artifact_storage_deferred = $true
        signature_available = $false
        install_allowed = $false
        installable_media_declared_hash_drift_count = $projectionResult.payload_surface.installable_media_declared_hash_drift_count
    }
    authority = [ordered]@{
        signing_authority = $false
        activation_authority = $false
        rollback_execution_authority = $false
        support_upload_authority = $false
        recovery_authority = $false
        production_ring_mutation_authority = $false
        remote_dispatch_authority = $false
        tui_authority = $false
    }
}
$hostedChannelText = Get-JsonText $hostedChannel
$hostedChannelHash = Get-StringSha256 $hostedChannelText

$hostedPayloadIndexPath = Join-Path $resolvedArtifactDir "hosted-payload-index.json"
$installBootstrapPath = Join-Path $resolvedArtifactDir "install-bootstrap.json"
$hostedChannelPath = Join-Path $resolvedArtifactDir "hosted-channel-index-after-payload-metadata.json"
Write-Json -Value $hostedPayloadIndex -Path $hostedPayloadIndexPath
Write-Json -Value $installBootstrap -Path $installBootstrapPath
Write-Json -Value $hostedChannel -Path $hostedChannelPath

$localOutputsSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $hostedPayloadIndexPath),
    (Get-Content -Raw -LiteralPath $installBootstrapPath),
    (Get-Content -Raw -LiteralPath $hostedChannelPath),
    $manifestText,
    $checksumsText,
    $signaturesText
)

$metadataSizeReady = (Get-Item -LiteralPath $hostedPayloadIndexPath).Length -le 262144 -and
    (Get-Item -LiteralPath $installBootstrapPath).Length -le 131072 -and
    (Get-Item -LiteralPath $projectionManifestPath).Length -le 524288 -and
    (Get-Item -LiteralPath $projectionChecksumsPath).Length -le 524288 -and
    (Get-Item -LiteralPath $projectionSignaturesPath).Length -le 524288

Add-Check "local.outputs.secret_safe" $localOutputsSafe "Hosted payload metadata outputs must not contain private key or token markers." $null
Add-Check "local.metadata_size_bounded" $metadataSizeReady "Hosted payload metadata must remain within RC6 metadata-only size ceilings." ([ordered]@{
    hosted_payload_index = (Get-Item -LiteralPath $hostedPayloadIndexPath).Length
    install_bootstrap = (Get-Item -LiteralPath $installBootstrapPath).Length
    manifest = (Get-Item -LiteralPath $projectionManifestPath).Length
    checksums = (Get-Item -LiteralPath $projectionChecksumsPath).Length
    signatures = (Get-Item -LiteralPath $projectionSignaturesPath).Length
})
Add-Check "hosted.payload.no_authority" ($hostedPayloadIndex.entries[0].install_allowed -eq $false -and $hostedPayloadIndex.entries[0].signature_available -eq $false -and (Has-FalseHostedAuthority $hostedPayloadIndex.authority)) "Hosted payload index must remain metadata-only and non-authoritative." $hostedPayloadIndex.entries[0]
Add-Check "hosted.install.no_authority" ($installBootstrap.install_allowed -eq $false -and $installBootstrap.activation_allowed -eq $false -and $installBootstrap.current_state -eq "verification-blocked") "Hosted install bootstrap must remain preflight-only and blocked." $installBootstrap.blockers

Set-RemoteTextFile -Path "/srv/aios-mirror/payloads/index.json" -Text $hostedPayloadIndexText
Set-RemoteTextFile -Path "/srv/aios-mirror$payloadBasePath/manifest.json" -Text $manifestText
Set-RemoteTextFile -Path "/srv/aios-mirror$payloadBasePath/checksums.json" -Text $checksumsText
Set-RemoteTextFile -Path "/srv/aios-mirror$payloadBasePath/signatures.json" -Text $signaturesText
Set-RemoteTextFile -Path "/srv/aios-mirror/install/bootstrap.json" -Text $installBootstrapText
Set-RemoteTextFile -Path "/srv/aios-mirror/channel/index.json" -Text $hostedChannelText

$remoteCheck = Invoke-Remote "set -eu; systemctl is-active nginx; cd /srv/aios-mirror; find payloads install channel -maxdepth 5 -type f -printf '%P %s\n' | sort; sha256sum payloads/index.json install/bootstrap.json channel/index.json $($payloadBasePath.TrimStart('/'))/manifest.json $($payloadBasePath.TrimStart('/'))/checksums.json $($payloadBasePath.TrimStart('/'))/signatures.json"

$rootResponse = Invoke-Curl "http://$Domain/"
$payloadIndexResponse = Invoke-Curl "http://$Domain/payloads/index.json"
$payloadManifestResponse = Invoke-Curl "http://$Domain$payloadBasePath/manifest.json"
$payloadChecksumsResponse = Invoke-Curl "http://$Domain$payloadBasePath/checksums.json"
$payloadSignaturesResponse = Invoke-Curl "http://$Domain$payloadBasePath/signatures.json"
$installResponse = Invoke-Curl "http://$Domain/install/bootstrap.json"
$channelResponse = Invoke-Curl "http://$Domain/channel/index.json"
$payloadDirResponse = Invoke-Curl "http://$Domain/payloads/"
$postPayloadResponse = Invoke-Curl "http://$Domain/payloads/index.json" -Method "POST"

$payloadIndexLive = ConvertFrom-JsonTextSafe $payloadIndexResponse.body
$payloadManifestLive = ConvertFrom-JsonTextSafe $payloadManifestResponse.body
$payloadChecksumsLive = ConvertFrom-JsonTextSafe $payloadChecksumsResponse.body
$payloadSignaturesLive = ConvertFrom-JsonTextSafe $payloadSignaturesResponse.body
$installLive = ConvertFrom-JsonTextSafe $installResponse.body
$channelLive = ConvertFrom-JsonTextSafe $channelResponse.body

$remoteHttpReady = $rootResponse.status_code -eq 200 -and
    $payloadIndexResponse.status_code -eq 200 -and
    $payloadManifestResponse.status_code -eq 200 -and
    $payloadChecksumsResponse.status_code -eq 200 -and
    $payloadSignaturesResponse.status_code -eq 200 -and
    $installResponse.status_code -eq 200 -and
    $channelResponse.status_code -eq 200

$remoteSemanticsReady = $null -ne $payloadIndexLive -and
    $null -ne $payloadManifestLive -and
    $null -ne $payloadChecksumsLive -and
    $null -ne $payloadSignaturesLive -and
    $null -ne $installLive -and
    $null -ne $channelLive -and
    $payloadIndexLive.entries[0].release_id -eq $releaseId -and
    $payloadIndexLive.entries[0].status -eq "verification-blocked" -and
    $payloadIndexLive.entries[0].install_allowed -eq $false -and
    $payloadSignaturesLive.signature_available -eq $false -and
    $payloadSignaturesLive.signing_authority_on_mirror -eq $false -and
    $payloadManifestLive.install_policy.install_allowed -eq $false -and
    $installLive.default_release_id -eq $releaseId -and
    $installLive.current_state -eq "verification-blocked" -and
    $channelLive.payload_channel.default_release_id -eq $releaseId -and
    $channelLive.payload_channel.install_allowed -eq $false -and
    $channelLive.production_ready_claim -eq $false

$remoteHashBindingsReady = $null -ne $payloadIndexLive -and
    $null -ne $channelLive -and
    $null -ne $installLive -and
    $payloadIndexLive.entries[0].manifest_sha256 -eq $manifestContentHash -and
    $payloadIndexLive.entries[0].checksums_sha256 -eq $checksumsContentHash -and
    $payloadIndexLive.entries[0].signatures_sha256 -eq $signaturesContentHash -and
    $channelLive.payload_channel.payload_index_sha256 -eq $hostedPayloadIndexHash -and
    $channelLive.payload_channel.install_bootstrap_sha256 -eq $installBootstrapHash -and
    $installLive.projection.payload_index_sha256 -eq $hostedPayloadIndexHash

$remoteSecretSafe = Test-NoSensitiveText -Values @(
    $payloadIndexResponse.body,
    $payloadManifestResponse.body,
    $payloadChecksumsResponse.body,
    $payloadSignaturesResponse.body,
    $installResponse.body,
    $channelResponse.body
)

Add-Check "remote.nginx.active" ($remoteCheck -match "active") "Nginx must remain active after bounded payload metadata publication." ($remoteCheck -split "`n")
Add-Check "remote.http.ready" $remoteHttpReady "Hosted payload metadata, install bootstrap, channel index, and portal must be reachable." ([ordered]@{
    root = $rootResponse.status_code
    payload_index = $payloadIndexResponse.status_code
    manifest = $payloadManifestResponse.status_code
    checksums = $payloadChecksumsResponse.status_code
    signatures = $payloadSignaturesResponse.status_code
    install = $installResponse.status_code
    channel = $channelResponse.status_code
})
Add-Check "remote.semantics.blocked" $remoteSemanticsReady "Live hosted metadata must point at current artifacts while keeping install verification-blocked." ([ordered]@{
    release_id = if ($null -ne $payloadIndexLive) { $payloadIndexLive.entries[0].release_id } else { $null }
    payload_status = if ($null -ne $payloadIndexLive) { $payloadIndexLive.entries[0].status } else { $null }
    install_state = if ($null -ne $installLive) { $installLive.current_state } else { $null }
})
Add-Check "remote.hash_bindings.match" $remoteHashBindingsReady "Live hosted metadata must carry the local projection hashes and endpoint bindings." ([ordered]@{
    payload_index_expected = $hostedPayloadIndexHash
    channel_payload_index_live = if ($null -ne $channelLive) { $channelLive.payload_channel.payload_index_sha256 } else { $null }
    install_payload_index_live = if ($null -ne $installLive) { $installLive.projection.payload_index_sha256 } else { $null }
})
Add-Check "remote.secret_safe" $remoteSecretSafe "Remote payload metadata responses must not expose private key or token markers." $null
Add-Check "remote.directory_listing.blocked" (@(403, 404) -contains $payloadDirResponse.status_code) "Payload directory listing must remain blocked." $payloadDirResponse.status_code
Add-Check "remote.write_methods.blocked" (@(403, 405) -contains $postPayloadResponse.status_code) "POST to payload metadata must remain blocked." $postPayloadResponse.status_code

$passed = @($script:blockers).Count -eq 0
$result = [ordered]@{
    schema = "agentos.rc6-hosted-payload-metadata-result.v1"
    generated_at = $generatedAt
    checked_at = (Get-Date).ToString("o")
    task = "RC6-011"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    remote = [ordered]@{
        host = $RemoteHost
        user = $RemoteUser
        domain = $Domain
        static_root = "/srv/aios-mirror"
        validation_used_local_dns = $false
        validation_resolve_override = "$Domain`:80`:$RemoteHost"
    }
    source = [ordered]@{
        rc6_010_result = Get-StablePath $projectionResultPath
        rc6_010_result_sha256 = Get-FileSha256 $projectionResultPath
        payload_manifest = Get-StablePath $projectionManifestPath
        payload_checksums = Get-StablePath $projectionChecksumsPath
        payload_signatures = Get-StablePath $projectionSignaturesPath
    }
    local_outputs = [ordered]@{
        hosted_payload_index = Get-StablePath $hostedPayloadIndexPath
        install_bootstrap = Get-StablePath $installBootstrapPath
        hosted_channel_index = Get-StablePath $hostedChannelPath
    }
    published_endpoints = @(
        "http://$Domain/payloads/index.json",
        "http://$Domain$payloadBasePath/manifest.json",
        "http://$Domain$payloadBasePath/checksums.json",
        "http://$Domain$payloadBasePath/signatures.json",
        "http://$Domain/install/bootstrap.json",
        "http://$Domain/channel/index.json"
    )
    output_hashes = [ordered]@{
        hosted_payload_index_sha256 = $hostedPayloadIndexHash
        install_bootstrap_sha256 = $installBootstrapHash
        hosted_channel_index_sha256 = $hostedChannelHash
        payload_manifest_content_sha256 = $manifestContentHash
        payload_checksums_content_sha256 = $checksumsContentHash
        payload_signatures_content_sha256 = $signaturesContentHash
    }
    payload_surface = [ordered]@{
        release_id = $releaseId
        base_path = $payloadBasePath
        status = "verification-blocked"
        storage_mode = "metadata-only"
        large_payload_deferred = $true
        signature_available = $false
        installable_media_declared_hash_drift_count = $projectionResult.payload_surface.installable_media_declared_hash_drift_count
        install_allowed = $false
        activation_allowed = $false
    }
    invariants = [ordered]@{
        hosted_metadata_only = $true
        large_payload_storage_enabled = $false
        local_private_key_material_used = $false
        cryptographic_signing_performed = $false
        signature_available = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_performed = $false
        active_slot_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        remote_dispatch_enabled = $false
        tui_authority = $false
        tls_required_before_ga_claim = $true
    }
    checks = $script:checks
    blockers = $script:blockers
    summary = [ordered]@{
        checks = @($script:checks).Count
        blockers = @($script:blockers).Count
        rc6_011_complete = $passed
        next_task = "RC6-012"
    }
}

Write-Json -Value $result -Path $resolvedResultPath
Write-Host "RC6 hosted payload metadata $($result.status): $(Get-StablePath $resolvedResultPath)"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
