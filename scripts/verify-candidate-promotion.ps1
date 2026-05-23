param(
    [string]$ProvenancePath = ".workflow/artifacts/release/provenance.json",
    [string]$DependencyInventoryPath = ".workflow/artifacts/release/dependency-inventory.json",
    [string]$ReproducibilityPath = ".workflow/artifacts/release-reproducibility-fast/result.json",
    [string]$OutputPath = ".workflow/artifacts/candidate-promotion/result.json",
    [string]$ProductionSignatureVerifierPath = "scripts/verify-production-signatures.ps1",
    [string]$ProductionSignatureVerificationPath = ".workflow/artifacts/candidate-promotion/production-signature-verification.json",
    [switch]$RequireProductionSignatures,
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

function Get-OptionalFileHash {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-StringSha256 {
    param([Parameter(Mandatory = $true)][string]$Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
        return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join "")
    } finally {
        $sha.Dispose()
    }
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

function Test-ArtifactHash {
    param(
        $Artifact,
        [Parameter(Mandatory = $true)][string]$Name
    )
    $hasPath = Has-Value $Artifact.path
    $hasHash = Has-Value $Artifact.sha256
    Add-Check "artifact.$Name.path" $hasPath "Artifact $Name must include path." "blocking" $Artifact.path
    Add-Check "artifact.$Name.sha256" $hasHash "Artifact $Name must include sha256." "blocking" $Artifact.sha256
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
    return [IO.Path]::GetFullPath((Join-Path $script:repoRoot $Artifact.path))
}

function Test-ArtifactFileHash {
    param(
        $Artifact,
        [Parameter(Mandatory = $true)][string]$Name
    )
    $path = Resolve-ArtifactPath $Artifact
    Add-Check "artifact.$Name.file_present" ($path -and (Test-Path -LiteralPath $path -PathType Leaf)) "Artifact $Name file must exist." "blocking" $Artifact.path
    if ($path -and (Test-Path -LiteralPath $path -PathType Leaf) -and (Has-Value $Artifact.sha256)) {
        $actual = Get-OptionalFileHash $path
        Add-Check "artifact.$Name.hash_matches_file" ($actual -eq $Artifact.sha256) "Artifact $Name sha256 must match referenced file." "blocking" $actual
    }
}

function Test-DetachedSignature {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)]$Artifact,
        [Parameter(Mandatory = $true)]$SignatureArtifact
    )
    $hasSignature = $null -ne $SignatureArtifact
    Add-Check "signature.$Name.present" $hasSignature "Artifact $Name must include a detached signature." "blocking" $SignatureArtifact
    if (-not $hasSignature) {
        return
    }

    Test-ArtifactHash $SignatureArtifact "$Name`_signature"
    Test-ArtifactFileHash $SignatureArtifact "$Name`_signature"
    $signaturePath = Resolve-ArtifactPath $SignatureArtifact
    if (-not ($signaturePath -and (Test-Path -LiteralPath $signaturePath -PathType Leaf))) {
        return
    }

    $signature = Read-RequiredJson $signaturePath
    Add-Check "signature.$Name.schema" ($signature.schema -eq "agentos.release-detached-signature.v1") "Detached signature schema must be agentos.release-detached-signature.v1." "blocking" $signature.schema
    Add-Check "signature.$Name.artifact_name" ($signature.artifact.name -eq $Name) "Detached signature must bind the expected artifact class." "blocking" $signature.artifact.name
    Add-Check "signature.$Name.artifact_sha256" ($signature.artifact.sha256 -eq $Artifact.sha256) "Detached signature must bind the artifact sha256." "blocking" $signature.artifact.sha256
    Add-Check "signature.$Name.algorithm" ($signature.signature.algorithm -eq "sha256-hash-bound-candidate-signature-v1") "Detached signature algorithm must be candidate hash-bound v1." "blocking" $signature.signature.algorithm
    Add-Check "signature.$Name.value" (Has-Value $signature.signature.value) "Detached signature value must be present." "blocking" $signature.signature.value
    $expectedSignature = Get-StringSha256 (@($signature.signature.algorithm, $signature.key.key_id, $Name, $Artifact.sha256, $script:sourceCommit) -join "`n")
    Add-Check "signature.$Name.value_matches_payload" ($signature.signature.value -eq $expectedSignature) "Detached signature value must match the canonical candidate payload." "blocking" $signature.signature.value
    Add-Check "signature.$Name.key_id" ($signature.key.key_id -eq "agentos-candidate-release-hash-bound-v1") "Detached signature key id must be recorded." "blocking" $signature.key.key_id
    Add-Check "signature.$Name.key_provenance" (Has-Value $signature.key.provenance) "Detached signature key provenance must be recorded." "blocking" $signature.key.provenance
    Add-Check "signature.$Name.rotation_policy" (Has-Value $signature.key.rotation_policy) "Detached signature key rotation policy must be referenced." "blocking" $signature.key.rotation_policy
    Add-Check "signature.$Name.fail_closed" ($signature.policy.fail_closed -eq $true) "Detached signature policy must fail closed." "blocking" $signature.policy.fail_closed
}

function Test-ProductionSignatureGate {
    param([Parameter(Mandatory = $true)]$Provenance)

    $verifierPath = Resolve-RepoPath $ProductionSignatureVerifierPath
    $verifierPresent = Test-Path -LiteralPath $verifierPath -PathType Leaf
    Add-Check "production_signature_verifier.script_present" $verifierPresent "Production mode requires the production signature verifier script." "blocking" $ProductionSignatureVerifierPath
    if (-not $verifierPresent) {
        return
    }

    try {
        & $verifierPath `
            -ProvenancePath $ProvenancePath `
            -OutputPath $ProductionSignatureVerificationPath `
            -RequireDecisionEvidence
        Add-Check "production_signature_verifier.invoked" $true "Production signature verifier must run in promotion production mode." "blocking" $ProductionSignatureVerificationPath
    } catch {
        Add-Check "production_signature_verifier.invoked" $false "Production signature verifier must run without execution errors." "blocking" $_.Exception.Message
        return
    }

    $resultPath = Resolve-RepoPath $ProductionSignatureVerificationPath
    $resultPresent = Test-Path -LiteralPath $resultPath -PathType Leaf
    Add-Check "production_signature_verification.result_present" $resultPresent "Production signature verifier must emit a result artifact." "blocking" $ProductionSignatureVerificationPath
    if (-not $resultPresent) {
        return
    }

    try {
        $productionSignatureVerification = Read-RequiredJson $resultPath
    } catch {
        Add-Check "production_signature_verification.parse" $false "Production signature verification result must be valid JSON." "blocking" $_.Exception.Message
        return
    }

    $blockerCount = @($productionSignatureVerification.blockers).Count
    Add-Check "production_signature_verification.schema" ($productionSignatureVerification.schema -eq "agentos.production-signature-verification.v1") "Production signature verification schema must be exact." "blocking" $productionSignatureVerification.schema
    Add-Check "production_signature_verification.production_ready_false" ($productionSignatureVerification.production_ready_claim -eq $false) "Production signature verification must not claim Production ready." "blocking" $productionSignatureVerification.production_ready_claim
    Add-Check "production_signature_verification.decision_evidence_required" ($productionSignatureVerification.decision_evidence_required -eq $true) "Production promotion mode requires production signatures over release artifacts and final decision evidence." "blocking" $productionSignatureVerification.decision_evidence_required
    Add-Check "production_signature_verification.source_branch" ($productionSignatureVerification.source.git_branch -eq $Provenance.source.git_branch) "Production signature verification must bind the promoted source branch." "blocking" $productionSignatureVerification.source.git_branch
    Add-Check "production_signature_verification.source_commit" ($productionSignatureVerification.source.git_commit -eq $Provenance.source.git_commit) "Production signature verification must bind the promoted source commit." "blocking" $productionSignatureVerification.source.git_commit
    Add-Check "production_signature_verification.status" ($productionSignatureVerification.status -eq "passed") "Production promotion mode requires production signature verification to pass." "blocking" $productionSignatureVerification.status
    Add-Check "production_signature_verification.no_blockers" ($blockerCount -eq 0) "Production promotion mode requires zero production signature blockers." "blocking" $blockerCount
}

$script:checks = @()
$script:blockers = @()
$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:releaseArtifactDir = Split-Path -Parent ([IO.Path]::GetFullPath((Join-Path $script:repoRoot $ProvenancePath)))

try {
    $provenance = Read-RequiredJson $ProvenancePath
    $inventory = Read-RequiredJson $DependencyInventoryPath
    $reproducibility = if (Test-Path -LiteralPath $ReproducibilityPath -PathType Leaf) {
        Read-RequiredJson $ReproducibilityPath
    } else {
        $null
    }

    Add-Check "production_ready_claim.false" $true "Candidate promotion verifier never claims Production ready." "info" $false
    Add-Check "schema.provenance.present" (Has-Value $provenance.schema) "Provenance schema must be present." "blocking" $provenance.schema
    Add-Check "schema.provenance.candidate" ($provenance.schema -match "candidate|production") "Candidate promotion should not rely only on Alpha provenance schema." "blocking" $provenance.schema
    Add-Check "schema.provenance.exact_candidate" ($provenance.schema -eq "agentos.production-candidate.provenance.v1") "Candidate provenance schema must be exact." "blocking" $provenance.schema
    Add-Check "source.commit.present" (Has-Value $provenance.source.git_commit) "Source commit must be present." "blocking" $provenance.source.git_commit
    $script:sourceCommit = $provenance.source.git_commit
    Add-Check "source.branch.present" (Has-Value $provenance.source.git_branch) "Source branch must be present." "blocking" $provenance.source.git_branch
    Add-Check "toolchain.cargo.present" (Has-Value $provenance.toolchain.cargo) "Cargo version must be present." "blocking" $provenance.toolchain.cargo
    Add-Check "toolchain.rustc.present" (Has-Value $provenance.toolchain.rustc) "Rustc version must be present." "blocking" $provenance.toolchain.rustc

    $requiredGateNames = @(
        "cargo test -p agentd",
        "cargo test -p agentd safety::",
        "cargo test -p agentd agent_core::",
        "cargo test -p agentd agent_core::adversarial",
        "cargo build -p agentd --release",
        "image/build-initramfs.ps1",
        "alpha service recovery smoke",
        "QEMU runtime smoke"
    )
    $gateNames = @($provenance.gates | ForEach-Object { $_.name })
    foreach ($gateName in $requiredGateNames) {
        $gate = @($provenance.gates | Where-Object { $_.name -eq $gateName }) | Select-Object -First 1
        Add-Check "gate.$gateName.present" ($null -ne $gate) "Gate $gateName must be present." "blocking" $gateName
        if ($gate) {
            Add-Check "gate.$gateName.passed" ($gate.status -eq "passed" -and $gate.exit_code -eq 0) "Gate $gateName must pass." "blocking" $gate
        }
    }

    Test-ArtifactHash $provenance.artifacts.agentd_binary "agentd_binary"
    Test-ArtifactHash $provenance.artifacts.initramfs "initramfs"
    Add-Check "artifact.initramfs.manifest_sha256" (Has-Value $provenance.artifacts.initramfs.manifest_sha256) "Initramfs manifest hash must be present." "blocking" $provenance.artifacts.initramfs.manifest_sha256
    Test-ArtifactHash $provenance.artifacts.alpha_rootfs_manifest "alpha_rootfs_manifest"
    Test-ArtifactHash $provenance.artifacts.rootfs_runtime_manifest "rootfs_runtime_manifest"
    Test-ArtifactHash $provenance.artifacts.qemu_runtime_smoke "qemu_runtime_smoke"
    Test-ArtifactHash $provenance.artifacts.alpha_service_recovery_smoke "alpha_service_recovery_smoke"
    Test-ArtifactHash $provenance.artifacts.dependency_inventory "dependency_inventory"
    Test-ArtifactFileHash $provenance.artifacts.dependency_inventory "dependency_inventory"

    Add-Check "dependency_inventory.schema" (Has-Value $inventory.schema) "Dependency inventory schema must be present." "blocking" $inventory.schema
    Add-Check "dependency_inventory.lockfile_hash" (Has-Value $inventory.lockfile.sha256) "Dependency inventory must include lockfile hash." "blocking" $inventory.lockfile.sha256

    $qemu = $provenance.image_inputs.qemu_runtime_smoke
    Add-Check "qemu.observed_all_markers" ($qemu.observed_all_markers -eq $true) "QEMU runtime smoke must observe all required markers." "blocking" $qemu
    Add-Check "qemu.runtime_marker" (Has-Value $qemu.runtime_marker -or Has-Value $provenance.alpha_runtime.runtime_marker) "Runtime marker must be recorded." "blocking" $provenance.alpha_runtime.runtime_marker
    Add-Check "qemu.runtime_manifest_marker" (Has-Value $qemu.runtime_manifest_marker -or Has-Value $provenance.alpha_runtime.runtime_manifest_marker) "Runtime manifest marker must be recorded." "blocking" $provenance.alpha_runtime.runtime_manifest_marker

    Add-Check "promotion.alpha_status" ($provenance.promotion.status -eq "promotable") "Underlying release gate must be promotable." "blocking" $provenance.promotion
    Add-Check "signing.schema" ($provenance.signing.signature_schema -eq "agentos.release-detached-signature.v1") "Provenance must declare detached signature schema." "blocking" $provenance.signing.signature_schema
    Add-Check "signing.algorithm" ($provenance.signing.algorithm -eq "sha256-hash-bound-candidate-signature-v1") "Provenance must declare candidate signature algorithm." "blocking" $provenance.signing.algorithm
    Add-Check "signing.key_provenance" (Has-Value $provenance.signing.key_provenance) "Provenance must declare signing key provenance." "blocking" $provenance.signing.key_provenance
    Add-Check "signing.rotation_policy" (Has-Value $provenance.signing.key_rotation_policy) "Provenance must declare signing key rotation policy." "blocking" $provenance.signing.key_rotation_policy
    Add-Check "signing.fail_closed" ($provenance.signing.fail_closed -eq $true) "Provenance signing policy must fail closed." "blocking" $provenance.signing.fail_closed
    Test-DetachedSignature -Name "dependency_inventory" -Artifact $provenance.artifacts.dependency_inventory -SignatureArtifact $provenance.artifacts.dependency_inventory_signature

    $sbomArtifact = $provenance.artifacts.sbom
    $hasSbom = $null -ne $sbomArtifact
    Add-Check "candidate.sbom.present" $hasSbom "Candidate promotion requires SBOM artifact reference." "blocking" $sbomArtifact
    if ($hasSbom) {
        Test-ArtifactHash $sbomArtifact "sbom"
        Test-ArtifactFileHash $sbomArtifact "sbom"
        Test-DetachedSignature -Name "sbom" -Artifact $sbomArtifact -SignatureArtifact $provenance.artifacts.sbom_signature
        $sbomPath = Resolve-ArtifactPath $sbomArtifact
        if ($sbomPath -and (Test-Path -LiteralPath $sbomPath -PathType Leaf)) {
            $sbom = Read-RequiredJson $sbomPath
            Add-Check "candidate.sbom.schema" ($sbom.schema -eq "agentos.candidate-sbom.v1") "Candidate SBOM schema must be agentos.candidate-sbom.v1." "blocking" $sbom.schema
            Add-Check "candidate.sbom.packages.present" (@($sbom.packages).Count -gt 0) "Candidate SBOM must include package entries." "blocking" @($sbom.packages).Count
        }
    }

    $updateMetadataArtifact = $provenance.artifacts.update_metadata
    $hasUpdateMetadata = $null -ne $updateMetadataArtifact
    Add-Check "candidate.update_metadata.present" $hasUpdateMetadata "Candidate promotion requires update metadata artifact reference." "blocking" $updateMetadataArtifact
    if ($hasUpdateMetadata) {
        Test-ArtifactHash $updateMetadataArtifact "update_metadata"
        Test-ArtifactFileHash $updateMetadataArtifact "update_metadata"
        Test-DetachedSignature -Name "update_metadata" -Artifact $updateMetadataArtifact -SignatureArtifact $provenance.artifacts.update_metadata_signature
        $updateMetadataPath = Resolve-ArtifactPath $updateMetadataArtifact
        if ($updateMetadataPath -and (Test-Path -LiteralPath $updateMetadataPath -PathType Leaf)) {
            $updateMetadata = Read-RequiredJson $updateMetadataPath
            Add-Check "candidate.update_metadata.schema" ($updateMetadata.schema -eq "agentos.candidate-update-metadata.v1") "Candidate update metadata schema must be agentos.candidate-update-metadata.v1." "blocking" $updateMetadata.schema
            Add-Check "candidate.update_metadata.inactive_slot" ($updateMetadata.update_strategy.stage_target -eq "inactive-slot") "Candidate update metadata must stage updates to the inactive slot." "blocking" $updateMetadata.update_strategy.stage_target
            Add-Check "candidate.update_metadata.rollback_required" ($updateMetadata.update_strategy.rollback_required -eq $true) "Candidate update metadata must require rollback." "blocking" $updateMetadata.update_strategy.rollback_required
            Add-Check "candidate.update_metadata.production_ready_false" ($updateMetadata.production_ready_claim -eq $false) "Candidate update metadata must not claim Production ready." "blocking" $updateMetadata.production_ready_claim
            Add-Check "candidate.update_metadata.sbom_hash" ($updateMetadata.artifacts.sbom.sha256 -eq $sbomArtifact.sha256) "Candidate update metadata must bind the SBOM sha256." "blocking" $updateMetadata.artifacts.sbom.sha256
        }
    }

    $provenanceArtifact = [ordered]@{
        path = $ProvenancePath
        sha256 = Get-OptionalFileHash $ProvenancePath
    }
    Test-DetachedSignature -Name "provenance" -Artifact $provenanceArtifact -SignatureArtifact ([ordered]@{
        path = "$ProvenancePath.sig.json"
        sha256 = Get-OptionalFileHash "$ProvenancePath.sig.json"
    })

    if ($reproducibility) {
        Add-Check "reproducibility.present" $true "Release reproducibility result is present." "info" $ReproducibilityPath
        Add-Check "reproducibility.passed" ($reproducibility.status -eq "passed") "Release reproducibility must pass before candidate go." "blocking" $reproducibility.status
        Add-Check "reproducibility.production_ready_false" ($reproducibility.production_ready_claim -eq $false) "Reproducibility verifier must not claim Production ready." "blocking" $reproducibility.production_ready_claim
    } else {
        Add-Check "reproducibility.present" $false "Release reproducibility result is required before candidate go." "blocking" $ReproducibilityPath
    }

    if ($RequireProductionSignatures) {
        Test-ProductionSignatureGate -Provenance $provenance
    }

    $status = if ($script:blockers.Count -eq 0) { "passed" } else { "blocked" }
    $inputs = [ordered]@{
        provenance = $ProvenancePath
        dependency_inventory = $DependencyInventoryPath
        reproducibility = $ReproducibilityPath
    }
    $requiredArtifactClasses = @(
        "agentd_binary",
        "initramfs",
        "initramfs_manifest",
        "alpha_rootfs_manifest",
        "rootfs_runtime_manifest",
        "qemu_runtime_smoke",
        "alpha_service_recovery_smoke",
        "dependency_inventory",
        "dependency_inventory_signature",
        "sbom",
        "sbom_signature",
        "update_metadata",
        "update_metadata_signature",
        "provenance_signature",
        "release_reproducibility"
    )
    if ($RequireProductionSignatures) {
        $inputs["production_signature_verifier"] = $ProductionSignatureVerifierPath
        $inputs["production_signature_verification"] = $ProductionSignatureVerificationPath
        $requiredArtifactClasses += "production_signature_verification"
    }
    $manifest = [ordered]@{
        schema = "agentos.candidate-promotion-manifest.v1"
        checked_at = (Get-Date).ToString("o")
        status = $status
        production_ready_claim = $false
        production_signature_required = [bool]$RequireProductionSignatures
        source = [ordered]@{
            git_commit = $provenance.source.git_commit
            git_branch = $provenance.source.git_branch
            git_status_porcelain = $provenance.source.git_status_porcelain
        }
        inputs = $inputs
        required_artifact_classes = $requiredArtifactClasses
        checks = @($script:checks)
        blockers = @($script:blockers)
        summary = [ordered]@{
            checks = $script:checks.Count
            blockers = $script:blockers.Count
        }
    }
    Write-Json -Value $manifest -Path $OutputPath
    Write-Host "Candidate promotion verification $status`: $OutputPath"
    if ($FailOnBlocked -and $status -ne "passed") {
        exit 1
    }
} catch {
    $blocked = [ordered]@{
        schema = "agentos.candidate-promotion-manifest.v1"
        checked_at = (Get-Date).ToString("o")
        status = "blocked"
        production_ready_claim = $false
        production_signature_required = [bool]$RequireProductionSignatures
        error = $_.Exception.Message
        checks = @($script:checks)
        blockers = @($script:blockers)
    }
    Write-Json -Value $blocked -Path $OutputPath
    throw
}
