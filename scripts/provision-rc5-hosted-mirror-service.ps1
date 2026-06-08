param(
    [string]$RemoteHost = "47.101.11.109",
    [string]$RemoteUser = "root",
    [string]$Domain = "aios.w33d.xyz",
    [string]$ArtifactDir = ".workflow/artifacts/rc5-hosted-mirror-service",
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

function Invoke-CurlText {
    param([Parameter(Mandatory = $true)][string]$Url)
    $args = @(
        "--noproxy", "*",
        "--max-time", "15",
        "--resolve", "$Domain`:80`:$RemoteHost",
        "-fsS",
        $Url
    )
    $output = & curl.exe @args 2>&1
    $exitCode = $LASTEXITCODE
    $text = ($output | Out-String).Trim()
    if ($exitCode -ne 0) {
        throw "curl failed ($exitCode) for ${Url}: $text"
    }
    return $text
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
    $patterns = @(
        "-----BEGIN [A-Z ]*PRIVATE KEY-----",
        "\bAIOS_SIGNER_API_TOKEN\b\s*[:=]",
        "\bAuthorization\b\s*:\s*Bearer\s+\S+",
        "\bBearer\s+[A-Za-z0-9._~+/-]+",
        "\baccess[_-]?token\b\s*[:=]\s*[""']?[^""'\s,}]+",
        "\brefresh[_-]?token\b\s*[:=]\s*[""']?[^""'\s,}]+",
        "\bprivate[_-]?key[_-]?pem\b\s*[:=]",
        "\.local-release-authority/private",
        "signing-key\.pem"
    )
    foreach ($value in $Values) {
        foreach ($pattern in $patterns) {
            if ($value -match $pattern) {
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
$rc4FinalAuditPath = Resolve-RepoPath ".workflow/active/WFS-20260608-agentos-production-distro-rc4/evidence/FINAL-AUDIT-20260608-production-distro-rc4.json"
$rc4HostedManifestPath = Resolve-RepoPath ".workflow/artifacts/rc4-hosted-release-transport/hosted-transport-manifest.json"
$rc4MirrorPublicationPath = Resolve-RepoPath ".workflow/artifacts/rc4-remote-registry-mirror-publication/mirror-publication.json"
$rc5ContractEvidencePath = Resolve-RepoPath ".workflow/active/WFS-20260608-agentos-production-distro-rc5/evidence/RC5-001-controlled-hosted-mirror-service-contract.json"
$rc5BoundaryEvidencePath = Resolve-RepoPath ".workflow/active/WFS-20260608-agentos-production-distro-rc5/evidence/RC5-002-user-install-update-channel-boundary.json"
$rc5ThreatEvidencePath = Resolve-RepoPath ".workflow/active/WFS-20260608-agentos-production-distro-rc5/evidence/RC5-003-hosted-mirror-service-threat-model.json"

$rc4FinalAuditSha256 = Get-FileSha256 $rc4FinalAuditPath
$rc4HostedManifestSha256 = Get-FileSha256 $rc4HostedManifestPath
$rc4MirrorPublicationSha256 = Get-FileSha256 $rc4MirrorPublicationPath

$health = [ordered]@{
    schema = "agentos.rc5-hosted-mirror-health.v1"
    status = "framework-ready"
    service = "aios-hosted-mirror"
    domain = $Domain
    generated_at = $generatedAt
    workflow = "WFS-20260608-agentos-production-distro-rc5"
    production_ready_claim = $false
    storage_mode = "metadata-only"
    large_artifact_storage_deferred = $true
    signing_authority = $false
    activation_authority = $false
    rollback_execution_authority = $false
    active_slot_mutation_authority = $false
    production_ring_mutation_authority = $false
}

$descriptor = [ordered]@{
    schema = "agentos.rc5-hosted-mirror-descriptor.v1"
    status = "framework-ready"
    service = "aios-hosted-mirror"
    domain = $Domain
    generated_at = $generatedAt
    workflow = "WFS-20260608-agentos-production-distro-rc5"
    static_root = "/srv/aios-mirror"
    storage_mode = "metadata-only"
    allowed_paths = @(
        "/health.json",
        "/.well-known/aios/mirror.json",
        "/channel/index.json",
        "/releases/",
        "/support/"
    )
    disallowed_authority = @(
        "signing",
        "activation",
        "rollback-execution",
        "active-slot-mutation",
        "production-ring-mutation",
        "remote-dispatch",
        "tui-authority"
    )
    freshness_window = "P7D"
    production_ready_claim = $false
}

$channelIndex = [ordered]@{
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
    )
    authority = [ordered]@{
        signing_authority = $false
        activation_authority = $false
        rollback_execution_authority = $false
        tui_authority = $false
    }
}

$readme = @"
AIOS RC5 hosted mirror framework

This directory is metadata-only for RC5. Large release payload storage is deferred.
Trust requires local verification of signatures, hashes, freshness, revocation, and rollback metadata.
The mirror is transport, not a root of trust.
"@

$nginxConfig = @'
server {
    listen 80;
    listen [::]:80;
    server_name aios.w33d.xyz;

    root /srv/aios-mirror;
    autoindex off;
    server_tokens off;
    client_max_body_size 1m;
    access_log /var/log/nginx/aios.access.log;
    error_log /var/log/nginx/aios.error.log warn;

    add_header X-Content-Type-Options "nosniff" always;
    add_header X-AIOS-Mirror "rc5-metadata-only" always;

    location = /health.json {
        default_type application/json;
        add_header Cache-Control "no-store" always;
        try_files /health.json =404;
        limit_except GET HEAD { deny all; }
    }

    location = /.well-known/aios/mirror.json {
        default_type application/json;
        add_header Cache-Control "no-store" always;
        try_files /.well-known/aios/mirror.json =404;
        limit_except GET HEAD { deny all; }
    }

    location = /channel/index.json {
        default_type application/json;
        add_header Cache-Control "no-cache" always;
        try_files /channel/index.json =404;
        limit_except GET HEAD { deny all; }
    }

    location /releases/ {
        default_type text/plain;
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

    location / {
        try_files $uri =404;
        limit_except GET HEAD { deny all; }
    }
}
'@

Set-RemoteTextFile -Path "/srv/aios-mirror/health.json" -Text (Get-JsonText $health)
Set-RemoteTextFile -Path "/srv/aios-mirror/.well-known/aios/mirror.json" -Text (Get-JsonText $descriptor)
Set-RemoteTextFile -Path "/srv/aios-mirror/channel/index.json" -Text (Get-JsonText $channelIndex)
Set-RemoteTextFile -Path "/srv/aios-mirror/releases/README.txt" -Text $readme
Set-RemoteTextFile -Path "/etc/nginx/sites-available/aios.w33d.xyz" -Text $nginxConfig

$provisionOutput = Invoke-Remote "set -eu; ln -sfn /etc/nginx/sites-available/aios.w33d.xyz /etc/nginx/sites-enabled/aios.w33d.xyz; nginx -t; systemctl reload nginx; systemctl is-active nginx; find /srv/aios-mirror -maxdepth 4 -type f -printf '%P %s\n' | sort; sha256sum /srv/aios-mirror/health.json /srv/aios-mirror/.well-known/aios/mirror.json /srv/aios-mirror/channel/index.json /srv/aios-mirror/releases/README.txt"

$healthText = Invoke-CurlText "http://$Domain/health.json"
$descriptorText = Invoke-CurlText "http://$Domain/.well-known/aios/mirror.json"
$channelText = Invoke-CurlText "http://$Domain/channel/index.json"
$readmeText = Invoke-CurlText "http://$Domain/releases/README.txt"

$healthFetched = $healthText | ConvertFrom-Json
$descriptorFetched = $descriptorText | ConvertFrom-Json
$channelFetched = $channelText | ConvertFrom-Json

Add-Check "ssh.remote_access" ($provisionOutput -match "active") "Remote SSH provisioning must reload active nginx." ($provisionOutput -split "`n")
Add-Check "health.schema" ($healthFetched.schema -eq "agentos.rc5-hosted-mirror-health.v1") "Hosted health endpoint must return RC5 health schema." $healthFetched.schema
Add-Check "health.non_ga" ($healthFetched.production_ready_claim -eq $false) "Hosted health endpoint must remain non-GA." $healthFetched.production_ready_claim
Add-Check "health.no_authority" ($healthFetched.signing_authority -eq $false -and $healthFetched.activation_authority -eq $false) "Hosted health endpoint must not advertise signing or activation authority." ([ordered]@{ signing = $healthFetched.signing_authority; activation = $healthFetched.activation_authority })
Add-Check "descriptor.metadata_only" ($descriptorFetched.storage_mode -eq "metadata-only") "Mirror descriptor must be metadata-only." $descriptorFetched.storage_mode
Add-Check "channel.schema" ($channelFetched.schema -eq "agentos.rc5-hosted-channel-index.v1") "Hosted channel index must return RC5 channel schema." $channelFetched.schema
Add-Check "channel.hash_bound" ($channelFetched.source_rc4_final_audit_sha256 -eq $rc4FinalAuditSha256 -and $channelFetched.hosted_transport_manifest_sha256 -eq $rc4HostedManifestSha256 -and $channelFetched.mirror_publication_sha256 -eq $rc4MirrorPublicationSha256) "Hosted channel must bind RC4 final audit, hosted manifest, and mirror publication hashes." ([ordered]@{ rc4_final = $channelFetched.source_rc4_final_audit_sha256; hosted = $channelFetched.hosted_transport_manifest_sha256; mirror = $channelFetched.mirror_publication_sha256 })
Add-Check "channel.no_activation" ($channelFetched.authority.activation_authority -eq $false -and $channelFetched.authority.tui_authority -eq $false) "Hosted channel must not grant activation or TUI authority." $channelFetched.authority
Add-Check "release.placeholder" ($readmeText -match "metadata-only" -and $readmeText -match "not a root of trust") "Release directory must remain a metadata-only placeholder." $readmeText
Add-Check "outputs.secret_safe" (Test-NoSensitiveContent -Values @($healthText, $descriptorText, $channelText, $readmeText, $nginxConfig, $provisionOutput)) "Hosted outputs and captured evidence must not contain private key or token markers." $null

$passed = @($script:blockers).Count -eq 0
$result = [ordered]@{
    schema = "agentos.rc5-hosted-mirror-service-result.v1"
    generated_at = $generatedAt
    checked_at = (Get-Date).ToString("o")
    task = "RC5-010"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    remote = [ordered]@{
        host = $RemoteHost
        user = $RemoteUser
        domain = $Domain
        static_root = "/srv/aios-mirror"
        nginx_site = "/etc/nginx/sites-available/aios.w33d.xyz"
        tls_verified = $false
        validation_used_local_dns = $false
        validation_resolve_override = "$Domain`:80`:$RemoteHost"
    }
    source_artifacts = [ordered]@{
        rc4_final_audit = [ordered]@{ path = Get-StablePath $rc4FinalAuditPath; sha256 = $rc4FinalAuditSha256 }
        rc4_hosted_transport_manifest = [ordered]@{ path = Get-StablePath $rc4HostedManifestPath; sha256 = $rc4HostedManifestSha256 }
        rc4_mirror_publication = [ordered]@{ path = Get-StablePath $rc4MirrorPublicationPath; sha256 = $rc4MirrorPublicationSha256 }
        rc5_contract = [ordered]@{ path = Get-StablePath $rc5ContractEvidencePath; sha256 = Get-FileSha256 $rc5ContractEvidencePath }
        rc5_boundary = [ordered]@{ path = Get-StablePath $rc5BoundaryEvidencePath; sha256 = Get-FileSha256 $rc5BoundaryEvidencePath }
        rc5_threat_model = [ordered]@{ path = Get-StablePath $rc5ThreatEvidencePath; sha256 = Get-FileSha256 $rc5ThreatEvidencePath }
    }
    hosted_outputs = [ordered]@{
        health_json_sha256 = Get-StringSha256 $healthText
        mirror_descriptor_sha256 = Get-StringSha256 $descriptorText
        channel_index_sha256 = Get-StringSha256 $channelText
        releases_readme_sha256 = Get-StringSha256 $readmeText
    }
    invariants = [ordered]@{
        metadata_only = $true
        large_artifact_storage_deferred = $true
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
        rc5_010_complete = $passed
        endpoints_verified = @(
            "http://$Domain/health.json",
            "http://$Domain/.well-known/aios/mirror.json",
            "http://$Domain/channel/index.json",
            "http://$Domain/releases/README.txt"
        )
        tls_required_before_ga_claim = $true
        production_ready_claim = $false
    }
}

Write-Json -Value $result -Path $resolvedOutputPath
Write-Host "RC5 hosted mirror service $($result.status): $(Get-StablePath $resolvedOutputPath)"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
