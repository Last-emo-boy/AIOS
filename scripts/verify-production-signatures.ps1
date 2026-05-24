param(
    [string]$ProvenancePath = ".workflow/artifacts/release/provenance.json",
    [string]$PolicyPath = "packaging/agentos/rootfs/etc/agentos/policy/policy-pack.json",
    [string]$ToolManifestPath = "packaging/agentos/rootfs/etc/agentos/tools/semantic-tools.json",
    [string]$KeyringPath = ".workflow/artifacts/production-signing/key-custody.json",
    [string]$OutputPath = ".workflow/artifacts/production-signature-verification/result.json",
    [string]$KeyringVerifierPath = "scripts/verify-production-keyring.ps1",
    [string]$KeyringVerificationPath = ".workflow/artifacts/production-signing/keyring-verification.json",
    [string]$ReproducibilityPath = ".workflow/artifacts/release-reproducibility-fast/result.json",
    [string]$PromotionPath = ".workflow/artifacts/candidate-promotion/default-result.json",
    [string]$ProductionRunbookPath = ".workflow/artifacts/production-runbook-smoke/result.json",
    [string]$QemuDistroSmokePath = ".workflow/artifacts/signing-aware-replay/qemu-distro-smoke/result.json",
    [string]$ProductionKeyId = "agentos-production-root-v1",
    [switch]$RequireDecisionEvidence,
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

function Read-RequiredJson {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing required JSON artifact: $Path"
    }
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
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

function Get-OptionalFileHash {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Resolve-RepoPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ([IO.Path]::IsPathRooted($Path)) {
        return [IO.Path]::GetFullPath($Path)
    }
    return [IO.Path]::GetFullPath((Join-Path $script:repoRoot $Path))
}

function Resolve-ArtifactPath {
    param($Artifact)
    if (-not (Has-Value $Artifact.path)) {
        return $null
    }
    if ([IO.Path]::IsPathRooted($Artifact.path)) {
        return $Artifact.path
    }
    $releaseRelativePath = [IO.Path]::GetFullPath((Join-Path $script:releaseArtifactDir $Artifact.path))
    if (Test-Path -LiteralPath $releaseRelativePath -PathType Leaf) {
        return $releaseRelativePath
    }
    return Resolve-RepoPath $Artifact.path
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

function Get-CanonicalPayload {
    param(
        [Parameter(Mandatory = $true)]$Signature
    )
    return @(
        "agentos.production-detached-signature.v1",
        "artifact.name=$($Signature.artifact.name)",
        "artifact.sha256=$($Signature.artifact.sha256)",
        "source.git_branch=$($Signature.source.git_branch)",
        "source.git_commit=$($Signature.source.git_commit)",
        "policy.policy_version=$($Signature.policy.policy_version)",
        "policy.tool_manifest_version=$($Signature.policy.tool_manifest_version)",
        "key.key_id=$($Signature.key.key_id)",
        "key.public_fingerprint=$($Signature.key.public_fingerprint)",
        "key.rotation_epoch=$($Signature.key.rotation_epoch)"
    ) -join "`n"
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

function Test-RsaPkcs1Sha256Signature {
    param(
        [Parameter(Mandatory = $true)][string]$PublicKeyPem,
        [Parameter(Mandatory = $true)][string]$Payload,
        [Parameter(Mandatory = $true)][string]$SignatureBase64
    )
    $rsa = [Security.Cryptography.RSA]::Create()
    try {
        $rsa.ImportFromPem($PublicKeyPem)
        $payloadBytes = [Text.Encoding]::UTF8.GetBytes($Payload)
        $signatureBytes = [Convert]::FromBase64String($SignatureBase64)
        return $rsa.VerifyData(
            $payloadBytes,
            $signatureBytes,
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
    } finally {
        $rsa.Dispose()
    }
}

function Get-KeyringEntry {
    param(
        $Keyring,
        [Parameter(Mandatory = $true)][string]$KeyId,
        [Parameter(Mandatory = $true)][string]$Fingerprint
    )
    if (-not $Keyring -or -not $Keyring.keys) {
        return $null
    }
    return @($Keyring.keys | Where-Object {
        $_.key_id -eq $KeyId -and $_.public_fingerprint -eq $Fingerprint
    }) | Select-Object -First 1
}

function Test-ProductionSignature {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)]$Artifact,
        $Keyring
    )

    $artifactPath = Resolve-ArtifactPath $Artifact
    Add-Check "artifact.$Name.file_present" ($artifactPath -and (Test-Path -LiteralPath $artifactPath -PathType Leaf)) "Artifact $Name file must exist." "blocking" $Artifact.path
    if (-not ($artifactPath -and (Test-Path -LiteralPath $artifactPath -PathType Leaf))) {
        return
    }

    $actualArtifactHash = Get-OptionalFileHash $artifactPath
    Add-Check "artifact.$Name.hash_matches" ($actualArtifactHash -eq $Artifact.sha256) "Artifact $Name sha256 must match retained file." "blocking" $actualArtifactHash

    $productionSignaturePath = "$artifactPath.prod.sig.json"
    $candidateSignaturePath = "$artifactPath.sig.json"
    $productionSignature = Read-OptionalJson $productionSignaturePath
    $candidateSignaturePresent = Test-Path -LiteralPath $candidateSignaturePath -PathType Leaf

    Add-Check "signature.$Name.candidate_not_accepted" (-not ($null -eq $productionSignature -and $candidateSignaturePresent)) "Candidate hash-bound signature cannot satisfy production verification." "blocking" $candidateSignaturePath
    Add-Check "signature.$Name.production_present" ($null -ne $productionSignature) "Production signature must exist next to retained artifact." "blocking" $productionSignaturePath
    if ($null -eq $productionSignature) {
        return
    }

    Add-Check "signature.$Name.schema" ($productionSignature.schema -eq "agentos.production-detached-signature.v1") "Production signature schema must be exact." "blocking" $productionSignature.schema
    Add-Check "signature.$Name.artifact_name" ($productionSignature.artifact.name -eq $Name) "Signature must bind expected artifact name." "blocking" $productionSignature.artifact.name
    Add-Check "signature.$Name.artifact_sha256" ($productionSignature.artifact.sha256 -eq $Artifact.sha256) "Signature must bind artifact sha256." "blocking" $productionSignature.artifact.sha256
    Add-Check "signature.$Name.source_branch" ($productionSignature.source.git_branch -eq $script:sourceBranch) "Signature must bind authoritative source branch." "blocking" $productionSignature.source.git_branch
    Add-Check "signature.$Name.source_commit" ($productionSignature.source.git_commit -eq $script:sourceCommit) "Signature must bind authoritative source commit." "blocking" $productionSignature.source.git_commit
    Add-Check "signature.$Name.policy_version" ($productionSignature.policy.policy_version -eq $script:policyVersion) "Signature must bind policy version." "blocking" $productionSignature.policy.policy_version
    Add-Check "signature.$Name.tool_manifest_version" ($productionSignature.policy.tool_manifest_version -eq $script:toolManifestVersion) "Signature must bind tool manifest version." "blocking" $productionSignature.policy.tool_manifest_version
    Add-Check "signature.$Name.key_id" ($productionSignature.key.key_id -eq $ProductionKeyId) "Signature must use production key id." "blocking" $productionSignature.key.key_id
    Add-Check "signature.$Name.public_fingerprint" (Has-Value $productionSignature.key.public_fingerprint) "Signature must include public fingerprint." "blocking" $productionSignature.key.public_fingerprint
    Add-Check "signature.$Name.rotation_epoch" (Has-Value $productionSignature.key.rotation_epoch) "Signature must include rotation epoch." "blocking" $productionSignature.key.rotation_epoch
    Add-Check "signature.$Name.revocation_status" ($productionSignature.verification.revocation_status -eq "not-revoked") "Signature key must not be revoked." "blocking" $productionSignature.verification.revocation_status
    Add-Check "signature.$Name.algorithm" ($productionSignature.signature.algorithm -eq "rsa-pkcs1-sha256") "Production signature algorithm must be supported." "blocking" $productionSignature.signature.algorithm
    Add-Check "signature.$Name.value" (Has-Value $productionSignature.signature.value) "Production signature value must be present." "blocking" $productionSignature.signature.value

    $keyringEntry = Get-KeyringEntry -Keyring $Keyring -KeyId $productionSignature.key.key_id -Fingerprint $productionSignature.key.public_fingerprint
    Add-Check "signature.$Name.keyring_entry" ($null -ne $keyringEntry) "Production key must exist in public keyring." "blocking" $productionSignature.key.public_fingerprint
    if ($null -eq $keyringEntry) {
        return
    }

    Add-Check "signature.$Name.key_status" ($keyringEntry.status -eq "active") "Production key must be active." "blocking" $keyringEntry.status
    Add-Check "signature.$Name.key_not_revoked" ($keyringEntry.revocation_status -eq "not-revoked") "Production key must not be revoked." "blocking" $keyringEntry.revocation_status
    Add-Check "signature.$Name.key_public_pem" (Has-Value $keyringEntry.public_key_pem) "Public key PEM must be available for verification." "blocking" $keyringEntry.public_key_pem
    if (-not (Has-Value $keyringEntry.public_key_pem)) {
        return
    }

    $fingerprint = Get-PemFingerprint $keyringEntry.public_key_pem
    Add-Check "signature.$Name.key_fingerprint_matches_pem" ($fingerprint -eq $productionSignature.key.public_fingerprint) "Public key fingerprint must match keyring PEM." "blocking" $fingerprint
    $payload = Get-CanonicalPayload $productionSignature
    $verified = $false
    try {
        $verified = Test-RsaPkcs1Sha256Signature -PublicKeyPem $keyringEntry.public_key_pem -Payload $payload -SignatureBase64 $productionSignature.signature.value
    } catch {
        Add-Check "signature.$Name.crypto_verification_error" $false "Production signature cryptographic verification must not error." "blocking" $_.Exception.Message
        return
    }
    Add-Check "signature.$Name.crypto_verified" $verified "Production signature must verify against canonical payload." "blocking" $productionSignature.signature.algorithm
}

function Test-KeyringVerification {
    $verifierPath = Resolve-RepoPath $KeyringVerifierPath
    $verifierPresent = Test-Path -LiteralPath $verifierPath -PathType Leaf
    Add-Check "keyring_verifier.script_present" $verifierPresent "Production signature verification requires keyring verifier script." "blocking" $KeyringVerifierPath
    if (-not $verifierPresent) {
        return
    }

    try {
        & $verifierPath `
            -KeyringPath $KeyringPath `
            -OutputPath $KeyringVerificationPath `
            -ProductionKeyId $ProductionKeyId
        Add-Check "keyring_verifier.invoked" $true "Production keyring verifier must run before signature verification." "blocking" $KeyringVerificationPath
    } catch {
        Add-Check "keyring_verifier.invoked" $false "Production keyring verifier must run without execution errors." "blocking" $_.Exception.Message
        return
    }

    $resultPath = Resolve-RepoPath $KeyringVerificationPath
    $resultPresent = Test-Path -LiteralPath $resultPath -PathType Leaf
    Add-Check "keyring_verification.result_present" $resultPresent "Production keyring verifier must emit result artifact." "blocking" $KeyringVerificationPath
    if (-not $resultPresent) {
        return
    }
    $keyringVerification = Read-OptionalJson $resultPath
    $blockerCount = @($keyringVerification.blockers).Count
    Add-Check "keyring_verification.schema" ($keyringVerification.schema -eq "agentos.production-keyring-verification.v1") "Production keyring verification schema must be exact." "blocking" $keyringVerification.schema
    Add-Check "keyring_verification.production_ready_false" ($keyringVerification.production_ready_claim -eq $false) "Production keyring verification must not claim Production ready." "blocking" $keyringVerification.production_ready_claim
    Add-Check "keyring_verification.status" ($keyringVerification.status -eq "passed") "Production keyring verification must pass before signature verification can pass." "blocking" $keyringVerification.status
    Add-Check "keyring_verification.no_blockers" ($blockerCount -eq 0) "Production keyring verification must have zero blockers." "blocking" $blockerCount
}

function New-PathArtifact {
    param([Parameter(Mandatory = $true)][string]$Path)
    $resolvedPath = Resolve-RepoPath $Path
    return [ordered]@{
        path = $Path
        sha256 = Get-OptionalFileHash $resolvedPath
    }
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:blockers = @()

$resolvedProvenancePath = Resolve-RepoPath $ProvenancePath
$script:releaseArtifactDir = Split-Path -Parent $resolvedProvenancePath
$provenance = Read-RequiredJson $resolvedProvenancePath
$policy = Read-RequiredJson (Resolve-RepoPath $PolicyPath)
$tools = Read-RequiredJson (Resolve-RepoPath $ToolManifestPath)
$keyring = Read-OptionalJson (Resolve-RepoPath $KeyringPath)

$script:sourceBranch = $provenance.source.git_branch
$script:sourceCommit = $provenance.source.git_commit
$script:policyVersion = $policy.policy_version
$script:toolManifestVersion = $tools.manifest_version

Add-Check "production_ready_claim.false" $true "Production signature verifier does not claim Production ready." "info" $false
Add-Check "source.branch.present" (Has-Value $script:sourceBranch) "Source branch must be present." "blocking" $script:sourceBranch
Add-Check "source.commit.present" (Has-Value $script:sourceCommit) "Source commit must be present." "blocking" $script:sourceCommit
Add-Check "policy.version.present" (Has-Value $script:policyVersion) "Policy version must be present." "blocking" $script:policyVersion
Add-Check "tools.version.present" (Has-Value $script:toolManifestVersion) "Tool manifest version must be present." "blocking" $script:toolManifestVersion
Add-Check "keyring.present" ($null -ne $keyring) "Public production keyring must be present." "blocking" $KeyringPath
Test-KeyringVerification

$provenanceArtifact = [ordered]@{
    path = $ProvenancePath
    sha256 = Get-OptionalFileHash $resolvedProvenancePath
}
$requiredArtifacts = [ordered]@{
    provenance = $provenanceArtifact
    dependency_inventory = $provenance.artifacts.dependency_inventory
    sbom = $provenance.artifacts.sbom
    update_metadata = $provenance.artifacts.update_metadata
    initramfs = $provenance.artifacts.initramfs
    alpha_rootfs_manifest = $provenance.artifacts.alpha_rootfs_manifest
    rootfs_runtime_manifest = $provenance.artifacts.rootfs_runtime_manifest
    qemu_runtime_smoke = $provenance.artifacts.qemu_runtime_smoke
    alpha_service_recovery_smoke = $provenance.artifacts.alpha_service_recovery_smoke
}

if ($RequireDecisionEvidence) {
    $requiredArtifacts.release_reproducibility = New-PathArtifact $ReproducibilityPath
    $requiredArtifacts.promotion_verifier = New-PathArtifact $PromotionPath
    $requiredArtifacts.production_runbook_smoke = New-PathArtifact $ProductionRunbookPath
    $requiredArtifacts.qemu_distro_smoke = New-PathArtifact $QemuDistroSmokePath
}

foreach ($name in $requiredArtifacts.Keys) {
    Test-ProductionSignature -Name $name -Artifact $requiredArtifacts[$name] -Keyring $keyring
}

$result = [ordered]@{
    schema = "agentos.production-signature-verification.v1"
    checked_at = (Get-Date).ToString("o")
    status = if ($script:blockers.Count -eq 0) { "passed" } else { "blocked" }
    production_ready_claim = $false
    production_key_id = $ProductionKeyId
    source = [ordered]@{
        git_branch = $script:sourceBranch
        git_commit = $script:sourceCommit
    }
    inputs = [ordered]@{
        provenance = $ProvenancePath
        policy = $PolicyPath
        tool_manifest = $ToolManifestPath
        keyring = $KeyringPath
        keyring_verification = $KeyringVerificationPath
        reproducibility = if ($RequireDecisionEvidence) { $ReproducibilityPath } else { $null }
        promotion = if ($RequireDecisionEvidence) { $PromotionPath } else { $null }
        production_runbook = if ($RequireDecisionEvidence) { $ProductionRunbookPath } else { $null }
        qemu_distro_smoke = if ($RequireDecisionEvidence) { $QemuDistroSmokePath } else { $null }
    }
    decision_evidence_required = [bool]$RequireDecisionEvidence
    required_artifacts = @($requiredArtifacts.Keys)
    checks = @($script:checks)
    blockers = @($script:blockers)
    summary = [ordered]@{
        checks = $script:checks.Count
        blockers = $script:blockers.Count
    }
}

Write-Json -Value $result -Path $OutputPath
if ($script:blockers.Count -gt 0) {
    Write-Host "Production signature verification blocked: $OutputPath"
    if ($FailOnBlocked) {
        exit 1
    }
} else {
    Write-Host "Production signature verification passed: $OutputPath"
}
