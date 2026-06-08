param(
    [string]$RemoteHost = "47.101.11.109",
    [string]$RemoteUser = "root",
    [string]$Domain = "aios.w33d.xyz",
    [string]$ArtifactDir = ".workflow/artifacts/rc5-user-release-channel",
    [string]$OutputPath = "",
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
    param([Parameter(Mandatory = $true)][string]$Url)
    $args = @(
        "--noproxy", "*",
        "--max-time", "15",
        "--resolve", "$Domain`:80`:$RemoteHost",
        "-sS",
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

function Test-NoSensitiveContent {
    param([Parameter(Mandatory = $true)][string[]]$Values)
    $markers = @(
        "BEGIN PRIVATE KEY",
        "AIOS_SIGNER_API_TOKEN",
        "Authorization: Bearer",
        "Bearer ",
        "access_token",
        "refresh_token",
        ".local-release-authority/private",
        "signing-key.pem"
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

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:blockers = @()

$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
if (-not $OutputPath) {
    $OutputPath = Join-Path $ArtifactDir "result.json"
}
$resolvedOutputPath = Resolve-RepoPath $OutputPath

$generatedAt = (Get-Date).ToString("o")
$bootstrapManifestPath = Resolve-RepoPath (Join-Path $ArtifactDir "bootstrap-manifest.json")
$userChannelPath = Resolve-RepoPath (Join-Path $ArtifactDir "user-release-channel.json")
$hostedChannelPath = Resolve-RepoPath (Join-Path $ArtifactDir "hosted-channel-index-after-user-release.json")

$rc4FinalAuditPath = Resolve-RepoPath ".workflow/active/WFS-20260608-agentos-production-distro-rc4/evidence/FINAL-AUDIT-20260608-production-distro-rc4.json"
$rc4HostedManifestPath = Resolve-RepoPath ".workflow/artifacts/rc4-hosted-release-transport/hosted-transport-manifest.json"
$rc4MirrorPublicationPath = Resolve-RepoPath ".workflow/artifacts/rc4-remote-registry-mirror-publication/mirror-publication.json"
$rc5FrontendResultPath = Resolve-RepoPath ".workflow/artifacts/rc5-mirror-frontend/result.json"
$rc5FailClosedPath = Resolve-RepoPath ".workflow/artifacts/rc5-hosted-metadata-fail-closed/result.json"

$rc4FinalAuditSha256 = Get-FileSha256 $rc4FinalAuditPath
$rc4HostedManifestSha256 = Get-FileSha256 $rc4HostedManifestPath
$rc4MirrorPublicationSha256 = Get-FileSha256 $rc4MirrorPublicationPath

$bootstrapManifest = [ordered]@{
    schema = "agentos.rc5-user-bootstrap-manifest.v1"
    generated_at = $generatedAt
    status = "metadata-only-preview"
    production_ready_claim = $false
    domain = $Domain
    channel = "production-candidate-rc5"
    mirror_root = "http://$Domain/"
    bootstrap_endpoints = [ordered]@{
        health = "/health.json"
        mirror_descriptor = "/.well-known/aios/mirror.json"
        channel_index = "/channel/index.json"
        user_release_channel = "/channel/user-release.json"
        release_placeholder = "/releases/README.txt"
    }
    trust_requirements = @(
        "schema-verification",
        "production-ready-false",
        "signature-verification-before-payload-trust",
        "hash-verification",
        "freshness-verification",
        "revocation-verification",
        "rollback-baseline-before-activation",
        "exact-operator-approval-before-canary"
    )
    blockers = @(
        "release-payload-storage-deferred",
        "payload-signature-bundle-deferred",
        "tls-not-yet-ga-gated",
        "rollback-execution-drill-pending",
        "multi-node-canary-execution-pending"
    )
    authority = [ordered]@{
        mirror_is_root_of_trust = $false
        signing_authority = $false
        activation_authority = $false
        rollback_execution_authority = $false
        production_ring_mutation_authority = $false
        tui_authority = $false
    }
}

$userReleaseChannel = [ordered]@{
    schema = "agentos.rc5-user-release-channel.v1"
    generated_at = $generatedAt
    status = "inspectable-metadata-only"
    production_ready_claim = $false
    channel = "production-candidate-rc5"
    domain = $Domain
    source_bindings = [ordered]@{
        rc4_final_audit_sha256 = $rc4FinalAuditSha256
        hosted_transport_manifest_sha256 = $rc4HostedManifestSha256
        mirror_publication_sha256 = $rc4MirrorPublicationSha256
        rc5_frontend_result_sha256 = Get-FileSha256 $rc5FrontendResultPath
        rc5_fail_closed_result_sha256 = Get-FileSha256 $rc5FailClosedPath
    }
    user_visible_entries = @(
        [ordered]@{
            id = "mirror-home"
            path = "/"
            kind = "frontend"
            status = "available"
            activation_allowed = $false
        }
        [ordered]@{
            id = "bootstrap-manifest"
            path = "/bootstrap/manifest.json"
            kind = "bootstrap-metadata"
            status = "available"
            activation_allowed = $false
        }
        [ordered]@{
            id = "release-placeholder"
            path = "/releases/README.txt"
            kind = "release-placeholder"
            status = "metadata-only"
            activation_allowed = $false
            large_payload_deferred = $true
        }
    )
    install_state = [ordered]@{
        bootstrap_metadata_available = $true
        release_payload_available = $false
        install_allowed = $false
        update_allowed = $false
        reason = "RC5 publishes metadata and bootstrap checks only; payload, signatures, rollback execution, TLS GA gate, and canary evidence are pending."
    }
}

$hostedChannel = [ordered]@{
    schema = "agentos.rc5-hosted-channel-index.v1"
    status = "metadata-only"
    channel = "production-candidate-rc5"
    domain = $Domain
    generated_at = $generatedAt
    production_ready_claim = $false
    storage_mode = "metadata-only"
    source_rc4_final_audit_sha256 = $rc4FinalAuditSha256
    hosted_transport_manifest_sha256 = $rc4HostedManifestSha256
    mirror_publication_sha256 = $rc4MirrorPublicationSha256
    freshness_window = "P7D"
    entries = @(
        [ordered]@{
            id = "rc5-metadata-only-framework"
            status = "placeholder"
            path = "/releases/README.txt"
            activation_allowed = $false
            large_payload_deferred = $true
        }
        [ordered]@{
            id = "rc5-user-bootstrap-manifest"
            status = "available"
            path = "/bootstrap/manifest.json"
            activation_allowed = $false
            large_payload_deferred = $true
        }
        [ordered]@{
            id = "rc5-user-release-channel"
            status = "available"
            path = "/channel/user-release.json"
            activation_allowed = $false
            large_payload_deferred = $true
        }
    )
    authority = [ordered]@{
        signing_authority = $false
        activation_authority = $false
        rollback_execution_authority = $false
        tui_authority = $false
    }
}

$descriptorText = Invoke-Curl "http://$Domain/.well-known/aios/mirror.json"
$descriptor = $descriptorText.body | ConvertFrom-Json
$allowedPaths = @($descriptor.allowed_paths)
if ($allowedPaths -notcontains "/bootstrap/") {
    $allowedPaths += "/bootstrap/"
}
$descriptor.allowed_paths = $allowedPaths
$descriptor.generated_at = $generatedAt

Write-Json -Value $bootstrapManifest -Path $bootstrapManifestPath
Write-Json -Value $userReleaseChannel -Path $userChannelPath
Write-Json -Value $hostedChannel -Path $hostedChannelPath

$bootstrapText = Get-JsonText $bootstrapManifest
$userChannelText = Get-JsonText $userReleaseChannel
$hostedChannelText = Get-JsonText $hostedChannel
$descriptorUpdatedText = Get-JsonText $descriptor

Set-RemoteTextFile -Path "/srv/aios-mirror/bootstrap/manifest.json" -Text $bootstrapText
Set-RemoteTextFile -Path "/srv/aios-mirror/channel/user-release.json" -Text $userChannelText
Set-RemoteTextFile -Path "/srv/aios-mirror/channel/index.json" -Text $hostedChannelText
Set-RemoteTextFile -Path "/srv/aios-mirror/.well-known/aios/mirror.json" -Text $descriptorUpdatedText

$remoteCheck = Invoke-Remote "set -eu; systemctl is-active nginx; find /srv/aios-mirror/bootstrap /srv/aios-mirror/channel -maxdepth 2 -type f -printf '%P %s\n' | sort; sha256sum /srv/aios-mirror/bootstrap/manifest.json /srv/aios-mirror/channel/user-release.json /srv/aios-mirror/channel/index.json"

$bootstrapResponse = Invoke-Curl "http://$Domain/bootstrap/manifest.json"
$userChannelResponse = Invoke-Curl "http://$Domain/channel/user-release.json"
$channelResponse = Invoke-Curl "http://$Domain/channel/index.json"
$frontendResponse = Invoke-Curl "http://$Domain/"

$bootstrapFetched = $bootstrapResponse.body | ConvertFrom-Json
$userChannelFetched = $userChannelResponse.body | ConvertFrom-Json
$channelFetched = $channelResponse.body | ConvertFrom-Json

Add-Check "remote.active" ($remoteCheck -match "active") "Remote nginx must remain active after user channel projection." ($remoteCheck -split "`n")
Add-Check "bootstrap.http_200" ($bootstrapResponse.status_code -eq 200) "Bootstrap manifest endpoint must return HTTP 200." $bootstrapResponse.status_code
Add-Check "bootstrap.non_ga" ($bootstrapFetched.production_ready_claim -eq $false) "Bootstrap manifest must remain non-GA." $bootstrapFetched.production_ready_claim
Add-Check "bootstrap.no_authority" ($bootstrapFetched.authority.activation_authority -eq $false -and $bootstrapFetched.authority.signing_authority -eq $false) "Bootstrap manifest must not grant activation or signing authority." $bootstrapFetched.authority
Add-Check "user_channel.http_200" ($userChannelResponse.status_code -eq 200) "User release channel endpoint must return HTTP 200." $userChannelResponse.status_code
Add-Check "user_channel.blocked_install" ($userChannelFetched.install_state.install_allowed -eq $false -and $userChannelFetched.install_state.update_allowed -eq $false) "User release channel must block install/update while payload evidence is deferred." $userChannelFetched.install_state
Add-Check "channel.entries" (@($channelFetched.entries | Where-Object { $_.path -eq "/bootstrap/manifest.json" }).Count -eq 1 -and @($channelFetched.entries | Where-Object { $_.path -eq "/channel/user-release.json" }).Count -eq 1) "Hosted channel index must expose bootstrap and user release channel metadata." $channelFetched.entries
Add-Check "channel.no_activation" ($channelFetched.authority.activation_authority -eq $false -and @($channelFetched.entries | Where-Object { $_.activation_allowed -ne $false }).Count -eq 0) "Hosted channel entries must not allow activation." $channelFetched.authority
Add-Check "frontend.still_served" ($frontendResponse.status_code -eq 200 -and $frontendResponse.body -match "AIOS Mirror") "Mirror frontend must remain available after channel projection." $frontendResponse.status_code
Add-Check "outputs.secret_safe" (Test-NoSensitiveContent -Values @($bootstrapResponse.body, $userChannelResponse.body, $channelResponse.body, $descriptorUpdatedText)) "Published user channel metadata must not contain private key or token markers." $null

$passed = @($script:blockers).Count -eq 0
$result = [ordered]@{
    schema = "agentos.rc5-user-release-channel-result.v1"
    generated_at = $generatedAt
    checked_at = (Get-Date).ToString("o")
    task = "RC5-020"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    remote = [ordered]@{
        host = $RemoteHost
        user = $RemoteUser
        domain = $Domain
        validation_used_local_dns = $false
        validation_resolve_override = "$Domain`:80`:$RemoteHost"
    }
    source_artifacts = [ordered]@{
        rc4_final_audit = [ordered]@{ path = Get-StablePath $rc4FinalAuditPath; sha256 = $rc4FinalAuditSha256 }
        rc4_hosted_transport_manifest = [ordered]@{ path = Get-StablePath $rc4HostedManifestPath; sha256 = $rc4HostedManifestSha256 }
        rc4_mirror_publication = [ordered]@{ path = Get-StablePath $rc4MirrorPublicationPath; sha256 = $rc4MirrorPublicationSha256 }
        rc5_frontend = [ordered]@{ path = Get-StablePath $rc5FrontendResultPath; sha256 = Get-FileSha256 $rc5FrontendResultPath }
        rc5_fail_closed = [ordered]@{ path = Get-StablePath $rc5FailClosedPath; sha256 = Get-FileSha256 $rc5FailClosedPath }
    }
    local_outputs = [ordered]@{
        bootstrap_manifest = [ordered]@{ path = Get-StablePath $bootstrapManifestPath; sha256 = Get-FileSha256 $bootstrapManifestPath }
        user_release_channel = [ordered]@{ path = Get-StablePath $userChannelPath; sha256 = Get-FileSha256 $userChannelPath }
        hosted_channel_index_after_user_release = [ordered]@{ path = Get-StablePath $hostedChannelPath; sha256 = Get-FileSha256 $hostedChannelPath }
    }
    hosted_outputs = [ordered]@{
        bootstrap_manifest_sha256 = Get-StringSha256 $bootstrapResponse.body
        user_release_channel_sha256 = Get-StringSha256 $userChannelResponse.body
        channel_index_sha256 = Get-StringSha256 $channelResponse.body
    }
    invariants = [ordered]@{
        metadata_only = $true
        large_artifact_storage_deferred = $true
        install_allowed = $false
        update_allowed = $false
        local_private_key_material_used = $false
        cryptographic_signing_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        active_slot_mutated = $false
        production_ring_mutated = $false
        remote_dispatch_enabled = $false
        tui_authority = $false
    }
    checks = $script:checks
    blockers = $script:blockers
    summary = [ordered]@{
        checks = @($script:checks).Count
        blockers = @($script:blockers).Count
        rc5_020_complete = $passed
        published_endpoints = @(
            "http://$Domain/bootstrap/manifest.json",
            "http://$Domain/channel/user-release.json",
            "http://$Domain/channel/index.json"
        )
        tls_required_before_ga_claim = $true
        production_ready_claim = $false
    }
}

Write-Json -Value $result -Path $resolvedOutputPath
Write-Host "RC5 user release channel $($result.status): $(Get-StablePath $resolvedOutputPath)"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
