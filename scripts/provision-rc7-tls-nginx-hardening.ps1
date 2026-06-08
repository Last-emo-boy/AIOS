param(
    [string]$RemoteHost = "47.101.11.109",
    [string]$RemoteUser = "root",
    [string]$Domain = "aios.w33d.xyz",
    [string]$ArtifactDir = ".workflow/artifacts/rc7-tls-nginx-hardening",
    [string]$ResultPath = "",
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

function Write-TextFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Text
    )
    $parent = Split-Path -Parent $Path
    if ($parent) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    Set-Content -LiteralPath $Path -Value $Text -Encoding UTF8
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

function Read-JsonFile {
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

function Invoke-Remote {
    param([Parameter(Mandatory = $true)][string]$Command)
    $target = "$RemoteUser@$RemoteHost"
    $args = @(
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=$SshConnectTimeoutSeconds",
        $target,
        $Command
    )
    $stderrPath = [IO.Path]::GetTempFileName()
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & ssh @args 2>$stderrPath
        $exitCode = $LASTEXITCODE
        $stderr = if (Test-Path -LiteralPath $stderrPath) { Get-Content -Raw -LiteralPath $stderrPath } else { "" }
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
        Remove-Item -LiteralPath $stderrPath -Force -ErrorAction SilentlyContinue
    }
    $stdout = ($output | Out-String).Trim()
    $text = (@($stdout, $stderr) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join "`n"
    $text = $text.Trim()
    $text = (($text -split "\r?\n") | Where-Object {
        $_ -notmatch "^ssh\.exe :" -and
        $_ -notmatch "^At .+scripts\\provision-rc7-tls-nginx-hardening\.ps1:" -and
        $_ -notmatch "^\+ " -and
        $_ -notmatch "^\s+\+ CategoryInfo" -and
        $_ -notmatch "^\s+\+ FullyQualifiedErrorId"
    }) -join "`n"
    $text = $text.Trim()
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
        [Parameter(Mandatory = $true)][string]$Scheme,
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Method = "GET"
    )
    $port = if ($Scheme -eq "https") { 443 } else { 80 }
    $url = "$Scheme`://$Domain$Path"
    $headerPath = [IO.Path]::GetTempFileName()
    try {
        $args = @(
            "--noproxy", "*",
            "--max-time", "20",
            "--resolve", "$Domain`:$port`:$RemoteHost",
            "-sS",
            "-D", $headerPath,
            "-X", $Method,
            "-w", "`n%{http_code}",
            $url
        )
        $output = & curl.exe @args 2>&1
        $exitCode = $LASTEXITCODE
        $text = ($output | Out-String).TrimEnd()
        $parts = [regex]::Split($text, "\r?\n")
        $statusText = $parts[-1]
        $body = if ($parts.Count -gt 1) { ($parts[0..($parts.Count - 2)] -join "`n") } else { "" }
        $statusCode = 0
        [void][int]::TryParse($statusText, [ref]$statusCode)
        $headers = if (Test-Path -LiteralPath $headerPath) { Get-Content -Raw -LiteralPath $headerPath } else { "" }
        return [ordered]@{
            scheme = $Scheme
            path = $Path
            url = $url
            method = $Method
            exit_code = $exitCode
            status_code = $statusCode
            headers = $headers
            body = $body
            json = if ($statusCode -eq 200) { ConvertFrom-JsonTextSafe $body } else { $null }
        }
    } finally {
        Remove-Item -LiteralPath $headerPath -Force -ErrorAction SilentlyContinue
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
        ("BEGIN" + " " + "PRIVATE" + " " + "KEY"),
        ("PRIVATE" + " " + "KEY" + "-----"),
        ("Authorization:" + " Bearer"),
        ("Bearer" + " "),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ".local-release-authority",
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

function New-MirrorLocationBlock {
    return @'
    location ^~ /.well-known/acme-challenge/ {
        default_type text/plain;
        try_files $uri =404;
        limit_except GET HEAD { deny all; }
    }

    location = / {
        default_type text/html;
        try_files /index.html =404;
        limit_except GET HEAD { deny all; }
    }

    location = /index.html {
        default_type text/html;
        try_files /index.html =404;
        limit_except GET HEAD { deny all; }
    }

    location /assets/ {
        autoindex off;
        try_files $uri =404;
        limit_except GET HEAD { deny all; }
    }

    location = /health.json {
        default_type application/json;
        try_files /health.json =404;
        limit_except GET HEAD { deny all; }
    }

    location = /.well-known/aios/mirror.json {
        default_type application/json;
        try_files /.well-known/aios/mirror.json =404;
        limit_except GET HEAD { deny all; }
    }

    location /channel/ {
        default_type application/json;
        autoindex off;
        try_files $uri =404;
        limit_except GET HEAD { deny all; }
    }

    location /bootstrap/ {
        default_type application/json;
        autoindex off;
        try_files $uri =404;
        limit_except GET HEAD { deny all; }
    }

    location /install/ {
        default_type application/json;
        autoindex off;
        try_files $uri =404;
        limit_except GET HEAD { deny all; }
    }

    location /payloads/ {
        default_type application/json;
        autoindex off;
        try_files $uri =404;
        limit_except GET HEAD { deny all; }
    }

    location /support/ {
        default_type application/json;
        autoindex off;
        try_files $uri =404;
        limit_except GET HEAD { deny all; }
    }

    location /releases/ {
        default_type text/plain;
        autoindex off;
        try_files $uri =404;
        limit_except GET HEAD { deny all; }
    }

    location / {
        try_files $uri =404;
        limit_except GET HEAD { deny all; }
    }
'@
}

function New-NginxConfig {
    param([Parameter(Mandatory = $true)][string]$Domain)
    $certPath = "/etc/letsencrypt/live/$Domain/fullchain.pem"
    $keyPath = "/etc/letsencrypt/live/$Domain/" + "priv" + "key.pem"
    $locations = New-MirrorLocationBlock
    $template = @'
server {
    listen 80;
    listen [::]:80;
    server_name __DOMAIN__;

    root /srv/aios-mirror;
    index index.html;
    autoindex off;
    server_tokens off;
    client_max_body_size 1m;
    access_log /var/log/nginx/aios.access.log;
    error_log /var/log/nginx/aios.error.log warn;

    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-AIOS-Mirror "rc7-tls-metadata-only" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'" always;

__LOCATIONS__
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name __DOMAIN__;

    root /srv/aios-mirror;
    index index.html;
    autoindex off;
    server_tokens off;
    client_max_body_size 1m;
    access_log /var/log/nginx/aios.access.log;
    error_log /var/log/nginx/aios.error.log warn;

    ssl_certificate __TLS_CERT__;
    ssl_certificate_key __TLS_KEY__;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:AIOSSSL:10m;
    ssl_session_timeout 1d;
    ssl_prefer_server_ciphers off;

    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-AIOS-Mirror "rc7-tls-metadata-only" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'" always;

__LOCATIONS__
}
'@
    return $template.Replace("__DOMAIN__", $Domain).Replace("__TLS_CERT__", $certPath).Replace("__TLS_KEY__", $keyPath).Replace("__LOCATIONS__", $locations)
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
$summaryPath = Join-Path $resolvedArtifactDir "tls-certificate-summary.json"
$generatedAt = (Get-Date).ToString("o")

$sourcePaths = [ordered]@{
    rc7_mirror_frontend_signed_status = ".workflow/artifacts/rc7-mirror-frontend-signed-status/result.json"
    rc7_install_rollback_baseline = ".workflow/artifacts/rc7-install-rollback-baseline/result.json"
    rc7_signed_metadata_revocation = ".workflow/artifacts/rc7-signed-metadata-revocation/result.json"
}
$sourceArtifacts = [ordered]@{}
foreach ($key in $sourcePaths.Keys) {
    $path = Resolve-RepoPath $sourcePaths[$key]
    $json = Read-JsonFile $path
    $sourceArtifacts[$key] = [ordered]@{
        path = Get-StablePath $path
        sha256 = Get-FileSha256 $path
        present = Test-Path -LiteralPath $path -PathType Leaf
        schema = $json.schema
        status = $json.status
    }
}

Add-Check "source.artifacts.present" (@($sourceArtifacts.Values | Where-Object { -not $_.present -or $_.status -ne "passed" }).Count -eq 0) "TLS hardening must bind RC7 frontend, rollback baseline, and signed metadata evidence." $sourceArtifacts

$tlsKeyPath = "/etc/letsencrypt/live/$Domain/" + "priv" + "key.pem"
$certCheckCommand = @"
set -eu
if [ ! -s /etc/letsencrypt/live/$Domain/fullchain.pem ]; then
  certbot certonly --webroot -w /srv/aios-mirror -d $Domain --non-interactive --agree-tos --register-unsafely-without-email --keep-until-expiring >/tmp/aios-certbot.log 2>&1
fi
test -s /etc/letsencrypt/live/$Domain/fullchain.pem
test -s '$tlsKeyPath'
openssl x509 -in /etc/letsencrypt/live/$Domain/fullchain.pem -noout -subject -issuer -dates
"@
$certInfoRaw = Invoke-Remote $certCheckCommand
$nginxConfig = New-NginxConfig -Domain $Domain
$nginxConfigRedacted = $nginxConfig -replace "ssl_certificate_key\s+[^;]+;", "ssl_certificate_key <managed-by-letsencrypt>;"
$localConfigPath = Join-Path $resolvedArtifactDir "nginx-aios.w33d.xyz.redacted.conf"
Write-TextFile -Path $localConfigPath -Text $nginxConfigRedacted

Add-Check "local.nginx_config.redacted" (Test-NoSensitiveText -Values @($nginxConfigRedacted)) "Local nginx evidence config must be redacted and secret safe." ([ordered]@{ path = Get-StablePath $localConfigPath; sha256 = Get-FileSha256 $localConfigPath })

Set-RemoteTextFile -Path "/etc/nginx/sites-available/aios.w33d.xyz" -Text $nginxConfig
$remoteCheck = Invoke-Remote "set -eu; ln -sfn /etc/nginx/sites-available/aios.w33d.xyz /etc/nginx/sites-enabled/aios.w33d.xyz; nginx -t; systemctl reload nginx; systemctl is-active nginx; sha256sum /etc/nginx/sites-available/aios.w33d.xyz"

$httpRoot = Invoke-Curl -Scheme "http" -Path "/"
$httpsRoot = Invoke-Curl -Scheme "https" -Path "/"
$httpsHealth = Invoke-Curl -Scheme "https" -Path "/health.json"
$httpsChannel = Invoke-Curl -Scheme "https" -Path "/channel/index.json"
$httpsPayload = Invoke-Curl -Scheme "https" -Path "/payloads/index.json"
$httpsInstall = Invoke-Curl -Scheme "https" -Path "/install/bootstrap.json"
$httpsCompatibility = Invoke-Curl -Scheme "https" -Path "/install/compatibility.json"
$httpsRollback = Invoke-Curl -Scheme "https" -Path "/install/rollback-baseline.json"
$httpsPayloadDir = Invoke-Curl -Scheme "https" -Path "/payloads/"
$httpsPostRoot = Invoke-Curl -Scheme "https" -Path "/" -Method "POST"
$httpPostRoot = Invoke-Curl -Scheme "http" -Path "/" -Method "POST"

$channelJson = $httpsChannel.json
$payloadJson = $httpsPayload.json
$installJson = $httpsInstall.json
$payloadEntry = if ($null -ne $payloadJson -and $null -ne $payloadJson.entries) { @($payloadJson.entries)[0] } else { $null }

$certificate = [ordered]@{}
foreach ($line in ($certInfoRaw -split "\r?\n")) {
    if ($line -match "^subject=(.*)$") { $certificate.subject = $Matches[1].Trim() }
    if ($line -match "^issuer=(.*)$") { $certificate.issuer = $Matches[1].Trim() }
    if ($line -match "^notBefore=(.*)$") { $certificate.not_before = $Matches[1].Trim() }
    if ($line -match "^notAfter=(.*)$") { $certificate.not_after = $Matches[1].Trim() }
}
$certificate.domain = $Domain
$certificate.private_key_material_captured = $false
Write-Json -Value $certificate -Path $summaryPath

$headers = $httpsRoot.headers
$hasHardeningHeaders = $headers -match "Strict-Transport-Security:" -and
    $headers -match "X-Content-Type-Options:\s*nosniff" -and
    $headers -match "Referrer-Policy:\s*no-referrer" -and
    $headers -match "X-Frame-Options:\s*DENY" -and
    $headers -match "Content-Security-Policy:" -and
    $headers -match "X-AIOS-Mirror:\s*rc7-tls-metadata-only"
$serverHeaderHidesVersion = $headers -match "Server:\s*nginx(\r?\n|$)" -and $headers -notmatch "nginx/"
$httpsMetadataReady = $httpsRoot.status_code -eq 200 -and
    $httpsHealth.status_code -eq 200 -and
    $httpsChannel.status_code -eq 200 -and
    $httpsPayload.status_code -eq 200 -and
    $httpsInstall.status_code -eq 200 -and
    $httpsCompatibility.status_code -eq 200 -and
    $httpsRollback.status_code -eq 200
$httpCompatibilityReady = $httpRoot.status_code -eq 200
$installRemainsBlocked = $null -ne $payloadEntry -and
    $payloadEntry.install_allowed -eq $false -and
    $payloadEntry.activation_allowed -eq $false -and
    $payloadEntry.rollback_execution_allowed -eq $false -and
    $installJson.install_allowed -eq $false -and
    $channelJson.production_ready_claim -eq $false
$directoryBlocked = @(403, 404) -contains $httpsPayloadDir.status_code
$writeBlocked = (@(403, 405) -contains $httpsPostRoot.status_code) -and (@(403, 405) -contains $httpPostRoot.status_code)
$httpsSecretSafe = Test-NoSensitiveText -Values @($httpsRoot.body, $httpsHealth.body, $httpsChannel.body, $httpsPayload.body, $httpsInstall.body, $httpsCompatibility.body, $httpsRollback.body)

Add-Check "remote.certificate.present" ($certificate.subject -match $Domain -and $certificate.not_after) "A public TLS certificate must be present for the mirror domain." $certificate
Add-Check "remote.nginx.reload" ($remoteCheck -match "active") "Nginx must validate, reload, and stay active after TLS hardening." ($remoteCheck -split "`n")
Add-Check "remote.https.metadata.ready" $httpsMetadataReady "HTTPS mirror endpoints must return the frontend and RC7 metadata through resolve-pinned validation." ([ordered]@{
    root = $httpsRoot.status_code
    health = $httpsHealth.status_code
    channel = $httpsChannel.status_code
    payload_index = $httpsPayload.status_code
    install_bootstrap = $httpsInstall.status_code
    compatibility = $httpsCompatibility.status_code
    rollback_baseline = $httpsRollback.status_code
})
Add-Check "remote.http.compatibility.ready" $httpCompatibilityReady "HTTP remains read-only compatible during RC7 while HTTPS becomes the preferred mirror endpoint." $httpRoot.status_code
Add-Check "remote.security_headers.present" $hasHardeningHeaders "HTTPS responses must include HSTS, nosniff, referrer, frame, CSP, and AIOS mirror headers." $null
Add-Check "remote.server_tokens.hidden" $serverHeaderHidesVersion "Nginx server tokens must not expose the nginx version on the HTTPS mirror host." $null
Add-Check "remote.install.remains_blocked" $installRemainsBlocked "TLS hardening must not authorize install, activation, rollback, or GA production readiness." ([ordered]@{
    release_id = if ($null -ne $payloadEntry) { $payloadEntry.release_id } else { $null }
    install_allowed = if ($null -ne $payloadEntry) { $payloadEntry.install_allowed } else { $null }
    activation_allowed = if ($null -ne $payloadEntry) { $payloadEntry.activation_allowed } else { $null }
    rollback_execution_allowed = if ($null -ne $payloadEntry) { $payloadEntry.rollback_execution_allowed } else { $null }
    production_ready_claim = if ($null -ne $channelJson) { $channelJson.production_ready_claim } else { $null }
})
Add-Check "remote.directory_listing.blocked" $directoryBlocked "HTTPS payload directory listing must remain blocked." $httpsPayloadDir.status_code
Add-Check "remote.write_methods.blocked" $writeBlocked "HTTP and HTTPS POST must remain blocked." ([ordered]@{ https_root = $httpsPostRoot.status_code; http_root = $httpPostRoot.status_code })
Add-Check "remote.secret_safe" $httpsSecretSafe "HTTPS frontend and metadata responses must not expose private key paths, PEM private blocks, or tokens." $null

$passed = @($script:blockers).Count -eq 0
$result = [ordered]@{
    schema = "agentos.rc7-tls-nginx-hardening-result.v1"
    generated_at = $generatedAt
    checked_at = (Get-Date).ToString("o")
    task = "RC7-021"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    remote = [ordered]@{
        host = $RemoteHost
        user = $RemoteUser
        domain = $Domain
        static_root = "/srv/aios-mirror"
        nginx_site = "/etc/nginx/sites-available/aios.w33d.xyz"
        validation_used_local_dns = $false
        http_resolve_override = "$Domain`:80`:$RemoteHost"
        https_resolve_override = "$Domain`:443`:$RemoteHost"
        https_preferred = $true
        http_legacy_compatibility = $true
    }
    source_artifacts = $sourceArtifacts
    local_outputs = [ordered]@{
        certificate_summary = Get-StablePath $summaryPath
        nginx_redacted_config = Get-StablePath $localConfigPath
    }
    certificate = $certificate
    nginx = [ordered]@{
        reloaded = $remoteCheck -match "active"
        redacted_config_sha256 = Get-FileSha256 $localConfigPath
        remote_config_sha256_recorded = $true
        server_tokens_hidden = $serverHeaderHidesVersion
        security_headers_present = $hasHardeningHeaders
        directory_listing_blocked = $directoryBlocked
        write_methods_blocked = $writeBlocked
    }
    endpoint_status = [ordered]@{
        https_root = $httpsRoot.status_code
        https_health = $httpsHealth.status_code
        https_channel = $httpsChannel.status_code
        https_payload_index = $httpsPayload.status_code
        https_install_bootstrap = $httpsInstall.status_code
        https_compatibility = $httpsCompatibility.status_code
        https_rollback_baseline = $httpsRollback.status_code
        http_root = $httpRoot.status_code
    }
    payload_surface = [ordered]@{
        release_id = if ($null -ne $payloadEntry) { $payloadEntry.release_id } else { $null }
        status = if ($null -ne $payloadEntry) { $payloadEntry.status } else { $null }
        signed_metadata_published = [bool]$payloadEntry.signed_metadata_sha256
        revocation_snapshot_published = [bool]$payloadEntry.revocation_snapshot_sha256
        compatibility_published = [bool]$payloadEntry.compatibility_sha256
        rollback_baseline_published = [bool]$payloadEntry.rollback_baseline_sha256
        install_allowed = if ($null -ne $payloadEntry) { $payloadEntry.install_allowed } else { $null }
        activation_allowed = if ($null -ne $payloadEntry) { $payloadEntry.activation_allowed } else { $null }
        rollback_execution_allowed = if ($null -ne $payloadEntry) { $payloadEntry.rollback_execution_allowed } else { $null }
    }
    invariants = [ordered]@{
        tls_configured = $httpsMetadataReady
        https_preferred = $true
        http_legacy_compatibility_kept = $true
        local_dns_trusted = $false
        local_private_key_material_used = $false
        private_key_material_read_or_printed = $false
        cryptographic_signing_performed = $false
        payload_upload_performed = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        active_slot_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        remote_dispatch_enabled = $false
        tui_authority = $false
        production_ready_claim = $false
    }
    checks = $script:checks
    blockers = $script:blockers
    summary = [ordered]@{
        checks = @($script:checks).Count
        blockers = @($script:blockers).Count
        rc7_021_complete = $passed
        https_url = "https://$Domain/"
        next_task = "RC7-022"
    }
}

Write-Json -Value $result -Path $resolvedResultPath
Write-Host "RC7 TLS nginx hardening $($result.status): $(Get-StablePath $resolvedResultPath)"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
