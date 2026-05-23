param(
    [string]$KeyringPath = ".workflow/artifacts/production-signing/key-custody.json",
    [string]$RotationLogPath = ".workflow/artifacts/production-signing/key-rotation-log.json",
    [string]$RevocationLogPath = ".workflow/artifacts/production-signing/key-revocation-log.json",
    [string]$OutputPath = ".workflow/artifacts/production-signing/keyring-verification.json",
    [string]$ProductionKeyId = "agentos-production-root-v1",
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
    $Value | ConvertTo-Json -Depth 32 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Read-OptionalJson {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
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

function Resolve-RepoPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ([IO.Path]::IsPathRooted($Path)) {
        return [IO.Path]::GetFullPath($Path)
    }
    return [IO.Path]::GetFullPath((Join-Path $script:repoRoot $Path))
}

function Add-Check {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][bool]$Passed,
        [Parameter(Mandatory = $true)][string]$Message,
        [string]$Severity = "blocking",
        $Evidence = $null
    )
    $entry = [ordered]@{
        id = $Id
        status = if ($Passed) { "passed" } else { "failed" }
        severity = $Severity
        message = $Message
        evidence = $Evidence
    }
    $script:checks += $entry
    if (-not $Passed -and $Severity -eq "blocking") {
        $script:blockers += $entry
    }
}

function Get-PemFingerprint {
    param([Parameter(Mandatory = $true)][string]$Pem)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Pem.Trim())
        return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join "")
    } finally {
        $sha.Dispose()
    }
}

function Test-NoPrivateMaterial {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        $Value
    )
    $json = if ($null -eq $Value) { "" } else { $Value | ConvertTo-Json -Depth 32 -Compress }
    $containsPrivateField = $json -match '(?i)private[_-]?key|secret|seed|passphrase|password|token'
    $containsPrivatePem = $json -match '-----BEGIN ([A-Z ]*)PRIVATE KEY-----'
    Add-Check "$Id.no_private_fields" (-not $containsPrivateField) "Production keyring public metadata must not contain private/secret-like fields." "blocking" $Id
    Add-Check "$Id.no_private_pem" (-not $containsPrivatePem) "Production keyring public metadata must not contain private key PEM blocks." "blocking" $Id
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:blockers = @()

$resolvedKeyringPath = Resolve-RepoPath $KeyringPath
$resolvedRotationLogPath = Resolve-RepoPath $RotationLogPath
$resolvedRevocationLogPath = Resolve-RepoPath $RevocationLogPath

$keyring = Read-OptionalJson $resolvedKeyringPath
$rotationLog = Read-OptionalJson $resolvedRotationLogPath
$revocationLog = Read-OptionalJson $resolvedRevocationLogPath

Add-Check "production_ready_claim.false" $true "Production keyring verifier does not claim Production ready." "info" $false
Add-Check "keyring.present" ($null -ne $keyring) "Public production key custody metadata must exist." "blocking" $KeyringPath
if ($null -ne $keyring) {
    Test-NoPrivateMaterial "keyring" $keyring
    Add-Check "keyring.schema" ($keyring.schema -eq "agentos.production-key-custody.v1") "Production keyring schema must be exact." "blocking" $keyring.schema
    Add-Check "keyring.keys.present" (@($keyring.keys).Count -gt 0) "Production keyring must contain at least one public key entry." "blocking" @($keyring.keys).Count

    $entries = @($keyring.keys | Where-Object { $_.key_id -eq $ProductionKeyId })
    Add-Check "keyring.production_key.present" ($entries.Count -gt 0) "Production keyring must contain the configured production key id." "blocking" $ProductionKeyId
    Add-Check "keyring.production_key.unique" ($entries.Count -le 1) "Production key id must be unique in the public keyring." "blocking" $entries.Count

    if ($entries.Count -eq 1) {
        $entry = $entries[0]
        Add-Check "keyring.production_key.status" ($entry.status -eq "active") "Production key must be active for new release decisions." "blocking" $entry.status
        Add-Check "keyring.production_key.revocation_status" ($entry.revocation_status -eq "not-revoked") "Production key must not be revoked." "blocking" $entry.revocation_status
        Add-Check "keyring.production_key.public_fingerprint" (Has-Value $entry.public_fingerprint) "Production key must include public fingerprint." "blocking" $entry.public_fingerprint
        Add-Check "keyring.production_key.public_key_pem" (Has-Value $entry.public_key_pem) "Production key must include public key PEM or an accepted verification certificate chain." "blocking" $entry.public_key_pem
        Add-Check "keyring.production_key.rotation_epoch" (Has-Value $entry.rotation_epoch) "Production key must include rotation epoch." "blocking" $entry.rotation_epoch
        Add-Check "keyring.production_key.custody_owner_role" (Has-Value $entry.custody_owner_role) "Production key custody owner role must be recorded." "blocking" $entry.custody_owner_role
        Add-Check "keyring.production_key.rotation_policy" (Has-Value $entry.rotation_policy) "Production key rotation policy must be recorded." "blocking" $entry.rotation_policy
        if (Has-Value $entry.public_key_pem -and Has-Value $entry.public_fingerprint) {
            $fingerprint = Get-PemFingerprint $entry.public_key_pem
            Add-Check "keyring.production_key.fingerprint_matches_pem" ($fingerprint -eq $entry.public_fingerprint) "Production key fingerprint must match public PEM." "blocking" $fingerprint
        }
    }
}

Add-Check "rotation_log.present" ($null -ne $rotationLog) "Production key rotation log must exist." "blocking" $RotationLogPath
if ($null -ne $rotationLog) {
    Test-NoPrivateMaterial "rotation_log" $rotationLog
    Add-Check "rotation_log.schema" ($rotationLog.schema -eq "agentos.production-key-rotation-log.v1") "Rotation log schema must be exact." "blocking" $rotationLog.schema
    Add-Check "rotation_log.events.present" (@($rotationLog.events).Count -gt 0) "Rotation log must contain at least one event." "blocking" @($rotationLog.events).Count
}

Add-Check "revocation_log.present" ($null -ne $revocationLog) "Production key revocation log must exist." "blocking" $RevocationLogPath
if ($null -ne $revocationLog) {
    Test-NoPrivateMaterial "revocation_log" $revocationLog
    Add-Check "revocation_log.schema" ($revocationLog.schema -eq "agentos.production-key-revocation-log.v1") "Revocation log schema must be exact." "blocking" $revocationLog.schema
}

$result = [ordered]@{
    schema = "agentos.production-keyring-verification.v1"
    checked_at = (Get-Date).ToString("o")
    status = if ($script:blockers.Count -eq 0) { "passed" } else { "blocked" }
    production_ready_claim = $false
    production_key_id = $ProductionKeyId
    inputs = [ordered]@{
        keyring = $KeyringPath
        rotation_log = $RotationLogPath
        revocation_log = $RevocationLogPath
    }
    checks = @($script:checks)
    blockers = @($script:blockers)
    summary = [ordered]@{
        checks = $script:checks.Count
        blockers = $script:blockers.Count
    }
}

Write-Json -Value $result -Path $OutputPath
if ($script:blockers.Count -gt 0) {
    Write-Host "Production keyring verification blocked: $OutputPath"
    if ($FailOnBlocked) {
        exit 1
    }
} else {
    Write-Host "Production keyring verification passed: $OutputPath"
}
