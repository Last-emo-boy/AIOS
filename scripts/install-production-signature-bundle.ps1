param(
    [string]$SigningRequestPath = ".workflow/artifacts/production-signing/signing-request-decision-evidence.json",
    [string]$SignatureBundlePath = ".workflow/artifacts/production-signing/signature-bundle.json",
    [string]$BundleVerificationPath = ".workflow/artifacts/production-signing/signature-bundle-verification.json",
    [string]$OutputPath = ".workflow/artifacts/production-signing/signature-bundle-installation.json",
    [switch]$AllowOverwrite,
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

function Get-OptionalFileHash {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Test-InsideRepoPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $resolved = Resolve-RepoPath $Path
    $repoPrefix = $script:repoRoot.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    return $resolved.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)
}

function Test-ProductionSignaturePath {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Resolve-RepoPath $Path).EndsWith(".prod.sig.json", [StringComparison]::OrdinalIgnoreCase)
}

function Get-DuplicateValues {
    param([object[]]$Values)
    $normalized = @($Values | Where-Object { Has-Value $_ } | ForEach-Object { [string]$_ })
    return @($normalized | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })
}

function Get-MissingValues {
    param(
        [object[]]$Expected,
        [object[]]$Actual
    )
    $actualSet = @($Actual | Where-Object { Has-Value $_ } | ForEach-Object { [string]$_ })
    return @($Expected | Where-Object {
        (Has-Value $_) -and ([string]$_ -notin $actualSet)
    } | ForEach-Object { [string]$_ })
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

function Get-BundleSignature {
    param(
        $Bundle,
        [Parameter(Mandatory = $true)][string]$Name
    )
    if ($null -eq $Bundle -or $null -eq $Bundle.signatures) {
        return $null
    }
    return @($Bundle.signatures | Where-Object { $_.artifact.name -eq $Name }) | Select-Object -First 1
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:blockers = @()
$installed = @()
$installPlan = @()

$signingRequest = Read-OptionalJson (Resolve-RepoPath $SigningRequestPath)
$bundle = Read-OptionalJson (Resolve-RepoPath $SignatureBundlePath)
$verification = Read-OptionalJson (Resolve-RepoPath $BundleVerificationPath)

Add-Check "production_ready_claim.false" $true "Signature bundle installer does not claim Production ready." "info" $false
Add-Check "signing_request.present" ($null -ne $signingRequest) "Signing request must exist before installing signatures." "blocking" $SigningRequestPath
Add-Check "signature_bundle.present" ($null -ne $bundle) "Signature bundle must exist before installing signatures." "blocking" $SignatureBundlePath
Add-Check "bundle_verification.present" ($null -ne $verification) "Signature bundle verification result must exist before installation." "blocking" $BundleVerificationPath

if ($null -ne $signingRequest) {
    $requestNames = @($signingRequest.signing_requests | ForEach-Object { $_.artifact.name })
    $duplicateRequestNames = Get-DuplicateValues $requestNames
    Add-Check "signing_request.artifact_names_unique" ($duplicateRequestNames.Count -eq 0) "Signing request artifact names must be unique before installation." "blocking" $duplicateRequestNames
}

if ($null -ne $verification) {
    Add-Check "bundle_verification.schema" ($verification.schema -eq "agentos.production-signature-bundle-verification.v1") "Bundle verification schema must be exact." "blocking" $verification.schema
    Add-Check "bundle_verification.status" ($verification.status -eq "ready-for-cryptographic-verification") "Bundle verification must be ready for cryptographic verification before installation." "blocking" $verification.status
    Add-Check "bundle_verification.no_blockers" (@($verification.blockers).Count -eq 0) "Bundle verification must have zero blockers before installation." "blocking" @($verification.blockers).Count
    Add-Check "bundle_verification.binds_signing_request" ($verification.inputs.signing_request -eq $SigningRequestPath) "Bundle verification must bind the signing request path being installed." "blocking" $verification.inputs.signing_request
    Add-Check "bundle_verification.binds_signature_bundle" ($verification.inputs.signature_bundle -eq $SignatureBundlePath) "Bundle verification must bind the signature bundle path being installed." "blocking" $verification.inputs.signature_bundle
    Add-Check "bundle_verification.request_count" ($verification.summary.requested_signatures -eq @($signingRequest.signing_requests).Count) "Bundle verification requested signature count must match signing request." "blocking" $verification.summary.requested_signatures
    Add-Check "bundle_verification.match_count" ($verification.summary.matched_signatures -eq @($signingRequest.signing_requests).Count) "Bundle verification matched signature count must match signing request." "blocking" $verification.summary.matched_signatures
    $requestNames = @($signingRequest.signing_requests | ForEach-Object { $_.artifact.name })
    $matchedNames = @($verification.matched_signatures)
    $duplicateMatchedNames = Get-DuplicateValues $matchedNames
    $missingMatchedNames = Get-MissingValues -Expected $requestNames -Actual $matchedNames
    $unexpectedMatchedNames = Get-MissingValues -Expected $matchedNames -Actual $requestNames
    Add-Check "bundle_verification.matched_names_unique" ($duplicateMatchedNames.Count -eq 0) "Bundle verification matched signatures must be unique." "blocking" $duplicateMatchedNames
    Add-Check "bundle_verification.matched_names_complete" ($missingMatchedNames.Count -eq 0) "Bundle verification matched signatures must include every requested artifact." "blocking" $missingMatchedNames
    Add-Check "bundle_verification.matched_names_no_unexpected" ($unexpectedMatchedNames.Count -eq 0) "Bundle verification matched signatures must not include unrequested artifacts." "blocking" $unexpectedMatchedNames
}

if ($script:blockers.Count -eq 0) {
    foreach ($request in @($signingRequest.signing_requests)) {
        $name = $request.artifact.name
        $signature = Get-BundleSignature -Bundle $bundle -Name $name
        Add-Check "install.$name.signature_present" ($null -ne $signature) "Verified signature bundle must include $name." "blocking" $name
        if ($null -eq $signature) {
            continue
        }

        $targetPath = $request.artifact.production_signature_path
        Add-Check "install.$name.target_path" (-not [string]::IsNullOrWhiteSpace($targetPath)) "Signing request must provide production signature target path." "blocking" $targetPath
        if ([string]::IsNullOrWhiteSpace($targetPath)) {
            continue
        }
        Add-Check "install.$name.target_inside_repo" (Test-InsideRepoPath $targetPath) "Production signature target path must stay inside the repository." "blocking" $targetPath
        Add-Check "install.$name.target_suffix" (Test-ProductionSignaturePath $targetPath) "Production signature target path must end with .prod.sig.json." "blocking" $targetPath
        if (-not (Test-InsideRepoPath $targetPath) -or -not (Test-ProductionSignaturePath $targetPath)) {
            continue
        }

        $targetExists = Test-Path -LiteralPath $targetPath -PathType Leaf
        Add-Check "install.$name.no_overwrite" ((-not $targetExists) -or $AllowOverwrite) "Existing production signature files are not overwritten unless -AllowOverwrite is explicit." "blocking" $targetPath
        if (-not ($targetExists -and -not $AllowOverwrite)) {
            $installPlan += [ordered]@{
                artifact = $name
                target_path = $targetPath
                signature = $signature
            }
        }
    }
}

if ($script:blockers.Count -eq 0) {
    foreach ($entry in @($installPlan)) {
        Write-Json -Value $entry.signature -Path $entry.target_path
        $resolvedTargetPath = Resolve-RepoPath $entry.target_path
        $installedHash = Get-OptionalFileHash $resolvedTargetPath
        Add-Check "install.$($entry.artifact).installed_hash" (Has-Value $installedHash) "Installed production signature hash must be recorded for cleanup binding." "blocking" $installedHash
        $installed += [ordered]@{
            artifact = $entry.artifact
            path = $entry.target_path
            sha256 = $installedHash
        }
    }
}

$result = [ordered]@{
    schema = "agentos.production-signature-bundle-installation.v1"
    installed_at = (Get-Date).ToString("o")
    status = if ($script:blockers.Count -eq 0) { "installed-for-cryptographic-verification" } else { "blocked" }
    production_ready_claim = $false
    inputs = [ordered]@{
        signing_request = $SigningRequestPath
        signature_bundle = $SignatureBundlePath
        bundle_verification = $BundleVerificationPath
    }
    installed_signatures = @($installed)
    checks = @($script:checks)
    blockers = @($script:blockers)
    summary = [ordered]@{
        requested_signatures = if ($null -ne $signingRequest) { @($signingRequest.signing_requests).Count } else { 0 }
        installed_signatures = @($installed).Count
        checks = $script:checks.Count
        blockers = $script:blockers.Count
    }
}

Write-Json -Value $result -Path $OutputPath
Write-Host "Production signature bundle installation $($result.status): $OutputPath"
if ($FailOnBlocked -and $script:blockers.Count -gt 0) {
    exit 1
}
