param(
    [string]$RemoteHost = "47.101.11.109",
    [string]$Domain = "aios.w33d.xyz",
    [string]$ArtifactDir = ".workflow/artifacts/rc5-hosted-endpoint-verifier",
    [string]$OutputPath = "",
    [switch]$RequireTls,
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
    $hash = [Security.Cryptography.SHA256]::HashData($bytes)
    return ([BitConverter]::ToString($hash)).Replace("-", "").ToLowerInvariant()
}

function Invoke-Curl {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [string]$Method = "GET",
        [int]$Port = 80
    )
    $args = @(
        "--noproxy", "*",
        "--max-time", "15",
        "--resolve", "$Domain`:$Port`:$RemoteHost",
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

$rc4FinalAuditPath = Resolve-RepoPath ".workflow/active/WFS-20260608-agentos-production-distro-rc4/evidence/FINAL-AUDIT-20260608-production-distro-rc4.json"
$rc4HostedManifestPath = Resolve-RepoPath ".workflow/artifacts/rc4-hosted-release-transport/hosted-transport-manifest.json"
$rc4MirrorPublicationPath = Resolve-RepoPath ".workflow/artifacts/rc4-remote-registry-mirror-publication/mirror-publication.json"
$rc5ProvisionResultPath = Resolve-RepoPath ".workflow/artifacts/rc5-hosted-mirror-service/result.json"

$expectedRc4FinalAudit = Get-FileSha256 $rc4FinalAuditPath
$expectedHostedManifest = Get-FileSha256 $rc4HostedManifestPath
$expectedMirrorPublication = Get-FileSha256 $rc4MirrorPublicationPath

$healthResponse = Invoke-Curl "http://$Domain/health.json"
$descriptorResponse = Invoke-Curl "http://$Domain/.well-known/aios/mirror.json"
$channelResponse = Invoke-Curl "http://$Domain/channel/index.json"
$readmeResponse = Invoke-Curl "http://$Domain/releases/README.txt"
$directoryResponse = Invoke-Curl "http://$Domain/releases/"
$postHealthResponse = Invoke-Curl "http://$Domain/health.json" -Method "POST"

$health = if ($healthResponse.status_code -eq 200) { $healthResponse.body | ConvertFrom-Json } else { $null }
$descriptor = if ($descriptorResponse.status_code -eq 200) { $descriptorResponse.body | ConvertFrom-Json } else { $null }
$channel = if ($channelResponse.status_code -eq 200) { $channelResponse.body | ConvertFrom-Json } else { $null }

Add-Check "health.http_200" ($healthResponse.status_code -eq 200) "Health endpoint must return HTTP 200." $healthResponse.status_code
Add-Check "health.schema" ($null -ne $health -and $health.schema -eq "agentos.rc5-hosted-mirror-health.v1") "Health endpoint must return RC5 health schema." $(if ($null -ne $health) { $health.schema } else { $null })
Add-Check "health.non_ga" ($null -ne $health -and $health.production_ready_claim -eq $false) "Health endpoint must remain non-GA." $(if ($null -ne $health) { $health.production_ready_claim } else { $null })
Add-Check "health.no_authority" ($null -ne $health -and $health.signing_authority -eq $false -and $health.activation_authority -eq $false -and $health.production_ring_mutation_authority -eq $false) "Health endpoint must not advertise signing, activation, or production ring authority." $(if ($null -ne $health) { [ordered]@{ signing = $health.signing_authority; activation = $health.activation_authority; production_ring = $health.production_ring_mutation_authority } } else { $null })

Add-Check "descriptor.http_200" ($descriptorResponse.status_code -eq 200) "Mirror descriptor must return HTTP 200." $descriptorResponse.status_code
Add-Check "descriptor.metadata_only" ($null -ne $descriptor -and $descriptor.storage_mode -eq "metadata-only") "Mirror descriptor must remain metadata-only." $(if ($null -ne $descriptor) { $descriptor.storage_mode } else { $null })
Add-Check "descriptor.no_forbidden_authority" ($null -ne $descriptor -and @($descriptor.disallowed_authority) -contains "signing" -and @($descriptor.disallowed_authority) -contains "activation" -and @($descriptor.disallowed_authority) -contains "remote-dispatch") "Mirror descriptor must explicitly disallow signing, activation, and remote dispatch." $(if ($null -ne $descriptor) { $descriptor.disallowed_authority } else { $null })

Add-Check "channel.http_200" ($channelResponse.status_code -eq 200) "Channel index must return HTTP 200." $channelResponse.status_code
Add-Check "channel.schema" ($null -ne $channel -and $channel.schema -eq "agentos.rc5-hosted-channel-index.v1") "Channel index must return RC5 channel schema." $(if ($null -ne $channel) { $channel.schema } else { $null })
Add-Check "channel.non_ga" ($null -ne $channel -and $channel.production_ready_claim -eq $false) "Channel index must remain non-GA." $(if ($null -ne $channel) { $channel.production_ready_claim } else { $null })
Add-Check "channel.hash_bound" ($null -ne $channel -and $channel.source_rc4_final_audit_sha256 -eq $expectedRc4FinalAudit -and $channel.hosted_transport_manifest_sha256 -eq $expectedHostedManifest -and $channel.mirror_publication_sha256 -eq $expectedMirrorPublication) "Channel index must bind expected RC4 hashes." $(if ($null -ne $channel) { [ordered]@{ rc4 = $channel.source_rc4_final_audit_sha256; hosted = $channel.hosted_transport_manifest_sha256; mirror = $channel.mirror_publication_sha256 } } else { $null })
Add-Check "channel.no_authority" ($null -ne $channel -and $channel.authority.signing_authority -eq $false -and $channel.authority.activation_authority -eq $false -and $channel.authority.tui_authority -eq $false) "Channel index must not grant signing, activation, or TUI authority." $(if ($null -ne $channel) { $channel.authority } else { $null })

Add-Check "releases.placeholder" ($readmeResponse.status_code -eq 200 -and $readmeResponse.body -match "metadata-only" -and $readmeResponse.body -match "not a root of trust") "Release README must be metadata-only placeholder." ([ordered]@{ status = $readmeResponse.status_code; sha256 = Get-StringSha256 $readmeResponse.body })
Add-Check "directory_listing.blocked" (@(403, 404) -contains $directoryResponse.status_code) "Release directory listing must be blocked." $directoryResponse.status_code
Add-Check "post.blocked" (@(403, 405) -contains $postHealthResponse.status_code) "POST to health endpoint must be blocked." $postHealthResponse.status_code
Add-Check "fetched_content.secret_safe" (Test-NoSensitiveContent -Values @($healthResponse.body, $descriptorResponse.body, $channelResponse.body, $readmeResponse.body)) "Fetched endpoint content must not contain secret markers." $null
Add-Check "tls.not_required_for_rc5" (-not $RequireTls) "TLS is not required for RC5 verifier unless RequireTls is set; TLS remains a GA gate." ([ordered]@{ require_tls = [bool]$RequireTls; tls_required_before_ga = $true })

if ($RequireTls) {
    $tlsHealthResponse = Invoke-Curl "https://$Domain/health.json" -Port 443
    Add-Check "tls.health_200" ($tlsHealthResponse.status_code -eq 200) "TLS health endpoint must return HTTP 200 when RequireTls is set." $tlsHealthResponse.status_code
}

$passed = @($script:blockers).Count -eq 0
$result = [ordered]@{
    schema = "agentos.rc5-hosted-endpoint-verifier-result.v1"
    generated_at = (Get-Date).ToString("o")
    task = "RC5-011"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    target = [ordered]@{
        domain = $Domain
        remote_host = $RemoteHost
        validation_used_local_dns = $false
        resolve_override = "$Domain`:80`:$RemoteHost"
        require_tls = [bool]$RequireTls
    }
    source_artifacts = [ordered]@{
        rc4_final_audit = [ordered]@{ path = Get-StablePath $rc4FinalAuditPath; sha256 = $expectedRc4FinalAudit }
        rc4_hosted_transport_manifest = [ordered]@{ path = Get-StablePath $rc4HostedManifestPath; sha256 = $expectedHostedManifest }
        rc4_mirror_publication = [ordered]@{ path = Get-StablePath $rc4MirrorPublicationPath; sha256 = $expectedMirrorPublication }
        rc5_hosted_mirror_service = [ordered]@{ path = Get-StablePath $rc5ProvisionResultPath; sha256 = Get-FileSha256 $rc5ProvisionResultPath }
    }
    endpoint_hashes = [ordered]@{
        health_body_sha256 = Get-StringSha256 $healthResponse.body
        descriptor_body_sha256 = Get-StringSha256 $descriptorResponse.body
        channel_body_sha256 = Get-StringSha256 $channelResponse.body
        release_readme_body_sha256 = Get-StringSha256 $readmeResponse.body
    }
    checks = $script:checks
    blockers = $script:blockers
    summary = [ordered]@{
        checks = @($script:checks).Count
        blockers = @($script:blockers).Count
        rc5_011_complete = $passed
        tls_required_before_ga_claim = $true
        production_ready_claim = $false
    }
}

Write-Json -Value $result -Path $resolvedOutputPath
Write-Host "RC5 hosted endpoint verifier $($result.status): $(Get-StablePath $resolvedOutputPath)"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
