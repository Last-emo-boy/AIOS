param(
    [string]$ProvenancePath = ".workflow/artifacts/release/provenance.json",
    [string]$PolicyPath = "packaging/agentos/rootfs/etc/agentos/policy/policy-pack.json",
    [string]$ToolManifestPath = "packaging/agentos/rootfs/etc/agentos/tools/semantic-tools.json",
    [string]$OutputPath = ".workflow/artifacts/production-signing/signing-request.json",
    [string]$ReproducibilityPath = ".workflow/artifacts/release-reproducibility-fast/result.json",
    [string]$PromotionPath = ".workflow/artifacts/candidate-promotion/default-result.json",
    [string]$ProductionRunbookPath = ".workflow/artifacts/production-runbook-smoke/result.json",
    [string]$QemuDistroSmokePath = ".workflow/artifacts/signing-aware-replay/qemu-distro-smoke/result.json",
    [string]$ProductionKeyId = "agentos-production-root-v1",
    [string]$PublicFingerprint = "<release-authority-public-fingerprint>",
    [string]$RotationEpoch = "<release-authority-rotation-epoch>",
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

function Get-CanonicalPayload {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Sha256
    )
    return @(
        "agentos.production-detached-signature.v1",
        "artifact.name=$Name",
        "artifact.sha256=$Sha256",
        "source.git_branch=$script:sourceBranch",
        "source.git_commit=$script:sourceCommit",
        "policy.policy_version=$script:policyVersion",
        "policy.tool_manifest_version=$script:toolManifestVersion",
        "key.key_id=$ProductionKeyId",
        "key.public_fingerprint=$PublicFingerprint",
        "key.rotation_epoch=$RotationEpoch"
    ) -join "`n"
}

function Add-ArtifactRequest {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)]$Artifact
    )

    $hasPath = Has-Value $Artifact.path
    $hasHash = Has-Value $Artifact.sha256
    Add-Check "artifact.$Name.path" $hasPath "Signing request artifact $Name must include path." "blocking" $Artifact.path
    Add-Check "artifact.$Name.sha256" $hasHash "Signing request artifact $Name must include sha256." "blocking" $Artifact.sha256
    if (-not ($hasPath -and $hasHash)) {
        return
    }

    $artifactPath = Resolve-ArtifactPath $Artifact
    Add-Check "artifact.$Name.file_present" ($artifactPath -and (Test-Path -LiteralPath $artifactPath -PathType Leaf)) "Signing request artifact $Name file must exist." "blocking" $Artifact.path
    if (-not ($artifactPath -and (Test-Path -LiteralPath $artifactPath -PathType Leaf))) {
        return
    }

    $actualHash = Get-OptionalFileHash $artifactPath
    Add-Check "artifact.$Name.hash_matches" ($actualHash -eq $Artifact.sha256) "Signing request artifact $Name hash must match retained file." "blocking" $actualHash

    $canonicalPayload = Get-CanonicalPayload -Name $Name -Sha256 $Artifact.sha256
    $script:requests += [ordered]@{
        artifact = [ordered]@{
            name = $Name
            path = $Artifact.path
            resolved_path = $artifactPath
            sha256 = $Artifact.sha256
            production_signature_path = "$artifactPath.prod.sig.json"
        }
        source = [ordered]@{
            git_branch = $script:sourceBranch
            git_commit = $script:sourceCommit
        }
        policy = [ordered]@{
            policy_version = $script:policyVersion
            tool_manifest_version = $script:toolManifestVersion
        }
        key = [ordered]@{
            key_id = $ProductionKeyId
            public_fingerprint = $PublicFingerprint
            rotation_epoch = $RotationEpoch
        }
        signature = [ordered]@{
            schema = "agentos.production-detached-signature.v1"
            algorithm = "rsa-pkcs1-sha256"
            canonical_payload = $canonicalPayload
        }
    }
}

function New-PathArtifact {
    param([Parameter(Mandatory = $true)][string]$Path)
    return [ordered]@{
        path = $Path
        sha256 = Get-OptionalFileHash (Resolve-RepoPath $Path)
    }
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:blockers = @()
$script:requests = @()

$resolvedProvenancePath = Resolve-RepoPath $ProvenancePath
$script:releaseArtifactDir = Split-Path -Parent $resolvedProvenancePath
$provenance = Read-RequiredJson $resolvedProvenancePath
$policy = Read-RequiredJson (Resolve-RepoPath $PolicyPath)
$tools = Read-RequiredJson (Resolve-RepoPath $ToolManifestPath)

$script:sourceBranch = $provenance.source.git_branch
$script:sourceCommit = $provenance.source.git_commit
$script:policyVersion = $policy.policy_version
$script:toolManifestVersion = $tools.manifest_version

Add-Check "production_ready_claim.false" $true "Signing request generator does not claim Production ready." "info" $false
Add-Check "source.branch.present" (Has-Value $script:sourceBranch) "Signing request must bind source branch." "blocking" $script:sourceBranch
Add-Check "source.commit.present" (Has-Value $script:sourceCommit) "Signing request must bind source commit." "blocking" $script:sourceCommit
Add-Check "policy.version.present" (Has-Value $script:policyVersion) "Signing request must bind policy version." "blocking" $script:policyVersion
Add-Check "tools.version.present" (Has-Value $script:toolManifestVersion) "Signing request must bind tool manifest version." "blocking" $script:toolManifestVersion
Add-Check "key.id.present" (Has-Value $ProductionKeyId) "Signing request must bind production key id." "blocking" $ProductionKeyId
Add-Check "key.public_fingerprint.provided" ($PublicFingerprint -notmatch '^<.*>$' -and (Has-Value $PublicFingerprint)) "Signing request must be generated with the release authority public fingerprint." "blocking" $PublicFingerprint
Add-Check "key.rotation_epoch.provided" ($RotationEpoch -notmatch '^<.*>$' -and (Has-Value $RotationEpoch)) "Signing request must be generated with the release authority rotation epoch." "blocking" $RotationEpoch

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
    Add-ArtifactRequest -Name $name -Artifact $requiredArtifacts[$name]
}

$result = [ordered]@{
    schema = "agentos.production-signing-request.v1"
    generated_at = (Get-Date).ToString("o")
    status = if ($script:blockers.Count -eq 0) { "ready-for-external-signer" } else { "blocked" }
    production_ready_claim = $false
    decision_evidence_required = [bool]$RequireDecisionEvidence
    production_key_id = $ProductionKeyId
    source = [ordered]@{
        git_branch = $script:sourceBranch
        git_commit = $script:sourceCommit
    }
    inputs = [ordered]@{
        provenance = $ProvenancePath
        policy = $PolicyPath
        tool_manifest = $ToolManifestPath
        reproducibility = if ($RequireDecisionEvidence) { $ReproducibilityPath } else { $null }
        promotion = if ($RequireDecisionEvidence) { $PromotionPath } else { $null }
        production_runbook = if ($RequireDecisionEvidence) { $ProductionRunbookPath } else { $null }
        qemu_distro_smoke = if ($RequireDecisionEvidence) { $QemuDistroSmokePath } else { $null }
    }
    required_artifacts = @($requiredArtifacts.Keys)
    signing_requests = @($script:requests)
    checks = @($script:checks)
    blockers = @($script:blockers)
    summary = [ordered]@{
        required_artifacts = @($requiredArtifacts.Keys).Count
        signing_requests = @($script:requests).Count
        checks = $script:checks.Count
        blockers = $script:blockers.Count
    }
}

Write-Json -Value $result -Path $OutputPath
Write-Host "Production signing request $($result.status): $OutputPath"
if ($FailOnBlocked -and $script:blockers.Count -gt 0) {
    exit 1
}
