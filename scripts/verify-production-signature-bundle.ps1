param(
    [string]$SigningRequestPath = ".workflow/artifacts/production-signing/signing-request-decision-evidence.json",
    [string]$SignatureBundlePath = ".workflow/artifacts/production-signing/signature-bundle.json",
    [string]$OutputPath = ".workflow/artifacts/production-signing/signature-bundle-verification.json",
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

function Test-NoPrivateMaterial {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        $Value
    )
    $json = if ($null -eq $Value) { "" } else { $Value | ConvertTo-Json -Depth 64 -Compress }
    $containsPrivateField = $json -match '(?i)private[_-]?key|seed|passphrase|password|token'
    $containsPrivatePem = $json -match '-----BEGIN ([A-Z ]*)PRIVATE KEY-----'
    Add-Check "$Id.no_private_fields" (-not $containsPrivateField) "Signature bundle must not contain private/secret-like fields." "blocking" $Id
    Add-Check "$Id.no_private_pem" (-not $containsPrivatePem) "Signature bundle must not contain private key PEM blocks." "blocking" $Id
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

function Test-Base64Value {
    param($Value)
    if (-not (Has-Value $Value)) {
        return $false
    }
    try {
        [Convert]::FromBase64String($Value) | Out-Null
        return $true
    } catch {
        return $false
    }
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

function Get-ResolvedTargetPaths {
    param([object[]]$Requests)
    return @($Requests | ForEach-Object {
        $path = $_.artifact.production_signature_path
        if (Has-Value $path) {
            Resolve-RepoPath ([string]$path)
        }
    })
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:blockers = @()
$matchedSignatures = @()

$resolvedSigningRequestPath = Resolve-RepoPath $SigningRequestPath
$resolvedSignatureBundlePath = Resolve-RepoPath $SignatureBundlePath
$signingRequestSha256 = Get-OptionalFileHash $resolvedSigningRequestPath
$signatureBundleSha256 = Get-OptionalFileHash $resolvedSignatureBundlePath

$signingRequest = Read-OptionalJson $resolvedSigningRequestPath
$bundle = Read-OptionalJson $resolvedSignatureBundlePath

Add-Check "production_ready_claim.false" $true "Signature bundle verifier does not claim Production ready." "info" $false
Add-Check "signing_request.present" ($null -ne $signingRequest) "Signing request manifest must exist." "blocking" $SigningRequestPath
Add-Check "signature_bundle.present" ($null -ne $bundle) "External production signature bundle must exist." "blocking" $SignatureBundlePath
Add-Check "signing_request.sha256_recorded" (Has-Value $signingRequestSha256) "Signing request input hash must be recorded for stale verification protection." "blocking" $signingRequestSha256
Add-Check "signature_bundle.sha256_recorded" (Has-Value $signatureBundleSha256) "Signature bundle input hash must be recorded for stale verification protection." "blocking" $signatureBundleSha256

if ($null -ne $signingRequest) {
    Test-NoPrivateMaterial "signing_request" $signingRequest
    Add-Check "signing_request.schema" ($signingRequest.schema -eq "agentos.production-signing-request.v1") "Signing request schema must be exact." "blocking" $signingRequest.schema
    Add-Check "signing_request.status" ($signingRequest.status -eq "ready-for-external-signer") "Signing request must be ready for external signer." "blocking" $signingRequest.status
    $requestNames = @($signingRequest.signing_requests | ForEach-Object { $_.artifact.name })
    $requestTargets = Get-ResolvedTargetPaths @($signingRequest.signing_requests)
    $duplicateRequestNames = Get-DuplicateValues $requestNames
    $duplicateRequestTargets = Get-DuplicateValues $requestTargets
    Add-Check "signing_request.signatures.present" (@($signingRequest.signing_requests).Count -gt 0) "Signing request must include requested signatures." "blocking" @($signingRequest.signing_requests).Count
    Add-Check "signing_request.artifact_names.present" (@($requestNames | Where-Object { -not (Has-Value $_) }).Count -eq 0) "Every signing request entry must include an artifact name." "blocking" $requestNames
    Add-Check "signing_request.artifact_names_unique" ($duplicateRequestNames.Count -eq 0) "Signing request artifact names must be unique." "blocking" $duplicateRequestNames
    Add-Check "signing_request.target_paths_unique" ($duplicateRequestTargets.Count -eq 0) "Signing request production signature target paths must be unique." "blocking" $duplicateRequestTargets
}

if ($null -ne $bundle) {
    Test-NoPrivateMaterial "signature_bundle" $bundle
    Add-Check "signature_bundle.schema" ($bundle.schema -eq "agentos.production-signature-bundle.v1") "Signature bundle schema must be exact." "blocking" $bundle.schema
    Add-Check "signature_bundle.production_ready_false" ($bundle.production_ready_claim -eq $false) "Signature bundle must not claim Production ready." "blocking" $bundle.production_ready_claim
    Add-Check "signature_bundle.signatures.present" (@($bundle.signatures).Count -gt 0) "Signature bundle must contain signatures." "blocking" @($bundle.signatures).Count
    $bundleNames = @($bundle.signatures | ForEach-Object { $_.artifact.name })
    $duplicateBundleNames = Get-DuplicateValues $bundleNames
    Add-Check "signature_bundle.artifact_names.present" (@($bundleNames | Where-Object { -not (Has-Value $_) }).Count -eq 0) "Every signature bundle entry must include an artifact name." "blocking" $bundleNames
    Add-Check "signature_bundle.artifact_names_unique" ($duplicateBundleNames.Count -eq 0) "Signature bundle artifact names must be unique." "blocking" $duplicateBundleNames
}

if ($null -ne $signingRequest -and $null -ne $bundle) {
    Add-Check "bundle.binds.source_branch" ($bundle.source.git_branch -eq $signingRequest.source.git_branch) "Signature bundle must bind signing request source branch." "blocking" $bundle.source.git_branch
    Add-Check "bundle.binds.source_commit" ($bundle.source.git_commit -eq $signingRequest.source.git_commit) "Signature bundle must bind signing request source commit." "blocking" $bundle.source.git_commit
    $requestNames = @($signingRequest.signing_requests | ForEach-Object { $_.artifact.name })
    $bundleNames = @($bundle.signatures | ForEach-Object { $_.artifact.name })
    $missingBundleNames = Get-MissingValues -Expected $requestNames -Actual $bundleNames
    $unrequestedBundleNames = Get-MissingValues -Expected $bundleNames -Actual $requestNames
    Add-Check "bundle.no_missing_signatures" ($missingBundleNames.Count -eq 0) "Signature bundle must include every requested artifact exactly once." "blocking" $missingBundleNames
    Add-Check "bundle.no_unrequested_signatures" ($unrequestedBundleNames.Count -eq 0) "Signature bundle must not include unrequested artifacts." "blocking" $unrequestedBundleNames

    foreach ($request in @($signingRequest.signing_requests)) {
        $name = $request.artifact.name
        $signature = Get-BundleSignature -Bundle $bundle -Name $name
        Add-Check "bundle.$name.present" ($null -ne $signature) "Signature bundle must include artifact $name." "blocking" $name
        if ($null -eq $signature) {
            continue
        }

        Add-Check "bundle.$name.schema" ($signature.schema -eq "agentos.production-detached-signature.v1") "Detached signature schema must be production v1." "blocking" $signature.schema
        Add-Check "bundle.$name.path" ($signature.artifact.path -eq $request.artifact.path) "Detached signature must bind requested artifact path." "blocking" $signature.artifact.path
        Add-Check "bundle.$name.sha256" ($signature.artifact.sha256 -eq $request.artifact.sha256) "Detached signature must bind requested artifact sha256." "blocking" $signature.artifact.sha256
        Add-Check "bundle.$name.source_branch" ($signature.source.git_branch -eq $request.source.git_branch) "Detached signature must bind requested source branch." "blocking" $signature.source.git_branch
        Add-Check "bundle.$name.source_commit" ($signature.source.git_commit -eq $request.source.git_commit) "Detached signature must bind requested source commit." "blocking" $signature.source.git_commit
        Add-Check "bundle.$name.policy_version" ($signature.policy.policy_version -eq $request.policy.policy_version) "Detached signature must bind requested policy version." "blocking" $signature.policy.policy_version
        Add-Check "bundle.$name.tool_manifest_version" ($signature.policy.tool_manifest_version -eq $request.policy.tool_manifest_version) "Detached signature must bind requested tool manifest version." "blocking" $signature.policy.tool_manifest_version
        Add-Check "bundle.$name.key_id" ($signature.key.key_id -eq $request.key.key_id) "Detached signature must bind requested key id." "blocking" $signature.key.key_id
        Add-Check "bundle.$name.public_fingerprint" ($signature.key.public_fingerprint -eq $request.key.public_fingerprint) "Detached signature must bind requested public fingerprint." "blocking" $signature.key.public_fingerprint
        Add-Check "bundle.$name.rotation_epoch" ($signature.key.rotation_epoch -eq $request.key.rotation_epoch) "Detached signature must bind requested rotation epoch." "blocking" $signature.key.rotation_epoch
        Add-Check "bundle.$name.algorithm" ($signature.signature.algorithm -eq $request.signature.algorithm) "Detached signature must use requested algorithm." "blocking" $signature.signature.algorithm
        Add-Check "bundle.$name.value" (Has-Value $signature.signature.value) "Detached signature must include signature value." "blocking" $signature.signature.value
        Add-Check "bundle.$name.value_base64" (Test-Base64Value $signature.signature.value) "Detached signature value must be base64 for cryptographic verification." "blocking" $signature.signature.value
        Add-Check "bundle.$name.revocation_status" ($signature.verification.revocation_status -eq "not-revoked") "Detached signature key must not be revoked." "blocking" $signature.verification.revocation_status
        $matchedSignatures += $name
    }

    Add-Check "bundle.no_extra_signatures" (@($bundle.signatures).Count -eq @($signingRequest.signing_requests).Count) "Signature bundle must not contain extra signatures outside the request." "blocking" @($bundle.signatures).Count
}

$result = [ordered]@{
    schema = "agentos.production-signature-bundle-verification.v1"
    checked_at = (Get-Date).ToString("o")
    status = if ($script:blockers.Count -eq 0) { "ready-for-cryptographic-verification" } else { "blocked" }
    production_ready_claim = $false
    inputs = [ordered]@{
        signing_request = $SigningRequestPath
        signing_request_sha256 = $signingRequestSha256
        signature_bundle = $SignatureBundlePath
        signature_bundle_sha256 = $signatureBundleSha256
    }
    matched_signatures = @($matchedSignatures)
    checks = @($script:checks)
    blockers = @($script:blockers)
    summary = [ordered]@{
        requested_signatures = if ($null -ne $signingRequest) { @($signingRequest.signing_requests).Count } else { 0 }
        matched_signatures = @($matchedSignatures).Count
        checks = $script:checks.Count
        blockers = $script:blockers.Count
    }
}

Write-Json -Value $result -Path $OutputPath
Write-Host "Production signature bundle verification $($result.status): $OutputPath"
if ($FailOnBlocked -and $script:blockers.Count -gt 0) {
    exit 1
}
