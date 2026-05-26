param(
    [string]$ArtifactDir = ".workflow/artifacts/release",
    [string]$QemuPath = "E:\qemu\qemu-system-x86_64.exe",
    [int]$QemuTimeoutSeconds = 60,
    [switch]$SkipBootSmoke,
    [switch]$SkipTests,
    [switch]$SkipFunctionalReplay,
    [switch]$SkipEcosystemReplay,
    [switch]$SkipTuiReplay,
    [switch]$RequireProductionSignatures
)

$ErrorActionPreference = "Stop"

function Write-Json {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $Value | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Get-ReproducibleTimestamp {
    if ($env:SOURCE_DATE_EPOCH) {
        try {
            $epochSeconds = [Int64]::Parse($env:SOURCE_DATE_EPOCH, [Globalization.CultureInfo]::InvariantCulture)
            return [DateTimeOffset]::FromUnixTimeSeconds($epochSeconds).UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ", [Globalization.CultureInfo]::InvariantCulture)
        } catch {
            throw "SOURCE_DATE_EPOCH must be a Unix timestamp in seconds: $env:SOURCE_DATE_EPOCH"
        }
    }
    return "1970-01-01T00:00:00Z"
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][scriptblock]$Script
    )
    Write-Host "==> $Name"
    $started = if ($script:releaseGeneratedAt) { $script:releaseGeneratedAt } else { (Get-Date).ToString("o") }
    & $Script
    if ($LASTEXITCODE -ne 0) {
        $script:gateResults += [ordered]@{
            name = $Name
            command = $Command
            status = "failed"
            exit_code = $LASTEXITCODE
            started_at = $started
            completed_at = if ($script:releaseGeneratedAt) { $script:releaseGeneratedAt } else { (Get-Date).ToString("o") }
        }
        throw "$Name failed with exit code $LASTEXITCODE"
    }
    $script:gateResults += [ordered]@{
        name = $Name
        command = $Command
        status = "passed"
        exit_code = 0
        started_at = $started
        completed_at = if ($script:releaseGeneratedAt) { $script:releaseGeneratedAt } else { (Get-Date).ToString("o") }
    }
}

function Get-GitValue {
    param([Parameter(Mandatory = $true)][string[]]$Args)
    $value = & git @Args 2>$null
    if ($LASTEXITCODE -ne 0) {
        return $null
    }
    return ($value -join "`n").Trim()
}

function Get-OptionalFileHash {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Read-OptionalJson {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Get-RelativeOrNull {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }
    $resolvedPath = (Resolve-Path -LiteralPath $Path).Path
    $rootWithSeparator = $repoRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if ($resolvedPath.StartsWith($rootWithSeparator, [StringComparison]::OrdinalIgnoreCase)) {
        return $resolvedPath.Substring($rootWithSeparator.Length)
    }
    return $resolvedPath
}

function Test-SecretFreeContent {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $true
    }
    $content = Get-Content -LiteralPath $Path -Raw
    $patterns = @(
        "password\s*=",
        "passwd\s*=",
        "api[_-]?key\s*=",
        "access_token\s*=",
        "refresh_token\s*=",
        "BEGIN RSA PRIVATE KEY",
        "BEGIN OPENSSH PRIVATE KEY"
    )
    foreach ($pattern in $patterns) {
        if ($content -match $pattern) {
            return $false
        }
    }
    return $true
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

function New-DependencyInventory {
    param([Parameter(Mandatory = $true)][string]$GeneratedAt)
    $cargoMetadata = & cargo metadata --format-version 1 --locked --no-deps 2>$null | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) {
        throw "cargo metadata failed"
    }
    $packages = @()
    foreach ($package in $cargoMetadata.packages) {
        $packages += [ordered]@{
            name = $package.name
            version = $package.version
            manifest_path = $package.manifest_path
            license = $package.license
        }
    }
    return [ordered]@{
        schema = "aios.dependency-inventory.v1"
        generated_at = $GeneratedAt
        packages = $packages
        lockfile = [ordered]@{
            path = "Cargo.lock"
            sha256 = Get-OptionalFileHash "Cargo.lock"
        }
    }
}

function New-CandidateSbom {
    param(
        [Parameter(Mandatory = $true)]$Inventory,
        [Parameter(Mandatory = $true)][string]$GeneratedAt
    )
    return [ordered]@{
        schema = "agentos.candidate-sbom.v1"
        generated_at = $GeneratedAt
        format = "agentos-minimal-spdx-like"
        packages = @($Inventory.packages | Sort-Object name, version | ForEach-Object {
            [ordered]@{
                name = $_.name
                version = $_.version
                license = $_.license
                manifest_path = $_.manifest_path
            }
        })
        lockfile = $Inventory.lockfile
    }
}

function New-CandidateDetachedSignature {
    param(
        [Parameter(Mandatory = $true)][string]$ArtifactName,
        [Parameter(Mandatory = $true)]$Artifact,
        [Parameter(Mandatory = $true)][string]$GeneratedAt,
        [Parameter(Mandatory = $true)][string]$SourceCommit
    )
    $algorithm = "sha256-hash-bound-candidate-signature-v1"
    $keyId = "agentos-candidate-release-hash-bound-v1"
    $artifactLeafPath = if (-not [string]::IsNullOrWhiteSpace($Artifact.path)) { Split-Path -Leaf $Artifact.path } else { "$ArtifactName.json" }
    $payload = @($algorithm, $keyId, $ArtifactName, $Artifact.sha256, $SourceCommit) -join "`n"
    return [ordered]@{
        schema = "agentos.release-detached-signature.v1"
        signed_at = $GeneratedAt
        artifact = [ordered]@{
            name = $ArtifactName
            path = $artifactLeafPath
            sha256 = $Artifact.sha256
        }
        signature = [ordered]@{
            algorithm = $algorithm
            value = Get-StringSha256 $payload
        }
        key = [ordered]@{
            key_id = $keyId
            provenance = "scripts/build-release.ps1 deterministic candidate signing record"
            rotation_policy = "docs/release-artifacts.md#signature-and-key-policy"
            production_key_required = $false
        }
        policy = [ordered]@{
            detached = $true
            fail_closed = $true
        }
    }
}

function Write-CandidateDetachedSignature {
    param(
        [Parameter(Mandatory = $true)][string]$ArtifactName,
        [Parameter(Mandatory = $true)]$Artifact,
        [Parameter(Mandatory = $true)][string]$ArtifactPath,
        [Parameter(Mandatory = $true)][string]$GeneratedAt,
        [Parameter(Mandatory = $true)][string]$SourceCommit
    )
    $signature = New-CandidateDetachedSignature `
        -ArtifactName $ArtifactName `
        -Artifact $Artifact `
        -GeneratedAt $GeneratedAt `
        -SourceCommit $SourceCommit
    $signaturePath = "$ArtifactPath.sig.json"
    Write-Json -Value $signature -Path $signaturePath
    return [ordered]@{
        path = Split-Path -Leaf $signaturePath
        sha256 = Get-OptionalFileHash $signaturePath
    }
}

function New-CandidateUpdateMetadata {
    param(
        [Parameter(Mandatory = $true)][string]$GeneratedAt,
        [Parameter(Mandatory = $true)][string]$SourceCommit,
        [Parameter(Mandatory = $true)][string]$SourceBranch,
        [Parameter(Mandatory = $true)]$Artifacts,
        [Parameter(Mandatory = $true)]$ActiveArtifactReadiness,
        [Parameter(Mandatory = $true)][string]$SbomPath,
        [Parameter(Mandatory = $true)][string]$SbomSha256
    )
    return [ordered]@{
        schema = "agentos.candidate-update-metadata.v1"
        generated_at = $GeneratedAt
        production_ready_claim = $false
        source = [ordered]@{
            git_commit = $SourceCommit
            git_branch = $SourceBranch
        }
        update_strategy = [ordered]@{
            mode = "ab-rootfs"
            stage_target = "inactive-slot"
            active_slot_modified_in_place = $false
            health_gate_required = $true
            rollback_required = $true
        }
        artifacts = [ordered]@{
            agentd_binary_sha256 = $Artifacts.agentd_binary.sha256
            initramfs_sha256 = $Artifacts.initramfs.sha256
            initramfs_manifest_sha256 = $Artifacts.initramfs.manifest_sha256
            alpha_rootfs_manifest_sha256 = $Artifacts.alpha_rootfs_manifest.sha256
            rootfs_runtime_manifest_sha256 = $Artifacts.rootfs_runtime_manifest.sha256
            active_artifact_set = [ordered]@{
                path = $Artifacts.ecosystem_active_set.path
                sha256 = $Artifacts.ecosystem_active_set.sha256
                required = $true
            }
            ecosystem_replay = [ordered]@{
                path = $Artifacts.ecosystem_replay.path
                sha256 = $Artifacts.ecosystem_replay.sha256
                required = $Artifacts.ecosystem_replay.required
            }
            sbom = [ordered]@{
                path = $SbomPath
                sha256 = $SbomSha256
            }
        }
        update_readiness = [ordered]@{
            active_artifact_set_hash = $ActiveArtifactReadiness.active_artifact_set_hash
            active_artifact_set_path = $ActiveArtifactReadiness.active_artifact_set_path
            active_artifact_set_present = $ActiveArtifactReadiness.active_artifact_set_present
            runtime_contract_compatibility_checked = $ActiveArtifactReadiness.runtime_contract_compatibility_checked
            incompatible_active_artifacts = @($ActiveArtifactReadiness.incompatible_active_artifacts)
            rollback_preserves_previous_active_set = $ActiveArtifactReadiness.rollback_preserves_previous_active_set
            previous_active_set_hash = $ActiveArtifactReadiness.previous_active_set_hash
            restored_active_set_hash = $ActiveArtifactReadiness.restored_active_set_hash
            ecosystem_replay_status = $ActiveArtifactReadiness.ecosystem_replay_status
            promotion_allowed = $ActiveArtifactReadiness.promotion_allowed
        }
        signature_policy = [ordered]@{
            status = "candidate-hash-bound"
            note = "Candidate metadata is hash-bound for promotion verification; production key management remains a separate release decision."
        }
    }
}

function New-ActiveArtifactUpdateReadiness {
    param(
        [Parameter(Mandatory = $true)]$Artifacts,
        $EcosystemReplayResult
    )
    $incompatible = @()
    $activeSetPresent = [bool]$Artifacts.ecosystem_active_set.present
    $activeSetHash = $Artifacts.ecosystem_active_set.sha256
    if (-not $activeSetPresent) {
        $incompatible += "active-artifact-set-missing"
    }
    if ([string]::IsNullOrWhiteSpace($activeSetHash)) {
        $incompatible += "active-artifact-set-hash-missing"
    }
    $replayStatus = if ($EcosystemReplayResult) { $EcosystemReplayResult.status } else { "missing" }
    $compatibilityChecked = ($replayStatus -eq "passed")
    if (-not $compatibilityChecked) {
        $incompatible += "ecosystem-replay-compatibility-missing"
    }
    $rollback = if ($EcosystemReplayResult) { $EcosystemReplayResult.rollback_revocation } else { $null }
    $rollbackPreserves = ($rollback -and $rollback.rollback_restored_previous -eq $true)
    if (-not $rollbackPreserves) {
        $incompatible += "active-artifact-rollback-evidence-missing"
    }
    return [ordered]@{
        schema = "agentos.active-artifact-update-readiness.v1"
        active_artifact_set_path = $Artifacts.ecosystem_active_set.path
        active_artifact_set_hash = $activeSetHash
        active_artifact_set_present = $activeSetPresent
        runtime_contract_compatibility_checked = $compatibilityChecked
        incompatible_active_artifacts = @($incompatible)
        rollback_preserves_previous_active_set = $rollbackPreserves
        previous_active_set_hash = if ($rollback) { $rollback.previous_active_set_hash } else { $null }
        restored_active_set_hash = if ($rollback) { $rollback.restored_active_set_hash } else { $null }
        ecosystem_replay_status = $replayStatus
        promotion_allowed = ($incompatible.Count -eq 0)
    }
}

$repoRoot = (Resolve-Path -LiteralPath ".").Path
$artifactRoot = Join-Path $repoRoot $ArtifactDir
New-Item -ItemType Directory -Force -Path $artifactRoot | Out-Null
$script:gateResults = @()
$candidateGeneratedAt = Get-ReproducibleTimestamp
$script:releaseGeneratedAt = $candidateGeneratedAt

if (-not $SkipTests) {
    Invoke-Checked "cargo test -p agentd" "cargo test -p agentd" { cargo test -p agentd }
    Invoke-Checked "cargo test -p agentd safety::" "cargo test -p agentd safety::" { cargo test -p agentd safety:: }
    Invoke-Checked "cargo test -p agentd agent_core::" "cargo test -p agentd agent_core::" { cargo test -p agentd agent_core:: }
    Invoke-Checked "cargo test -p agentd agent_core::adversarial" "cargo test -p agentd agent_core::adversarial" { cargo test -p agentd agent_core::adversarial }
}

if (-not $SkipFunctionalReplay) {
    Invoke-Checked "functional capability replay" "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/functional-capability-replay.ps1" {
        pwsh -NoProfile -ExecutionPolicy Bypass -File "scripts/functional-capability-replay.ps1"
    }
}

if (-not $SkipEcosystemReplay) {
    Invoke-Checked "ecosystem replay" "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/ecosystem-replay.ps1" {
        pwsh -NoProfile -ExecutionPolicy Bypass -File "scripts/ecosystem-replay.ps1"
    }
}

if (-not $SkipTuiReplay) {
    Invoke-Checked "TUI replay" "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/tui-replay.ps1" {
        pwsh -NoProfile -ExecutionPolicy Bypass -File "scripts/tui-replay.ps1"
    }
}

function Get-RelativePathForHash {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $rootPath = (Resolve-Path -LiteralPath $Root).Path.TrimEnd('\', '/')
    $entryPath = (Resolve-Path -LiteralPath $Path).Path
    $rootPrefix = $rootPath + [IO.Path]::DirectorySeparatorChar
    if ($entryPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        return $entryPath.Substring($rootPrefix.Length).Replace('\', '/')
    }
    return (Split-Path -Leaf $entryPath)
}

function Get-OptionalPathHash {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        return Get-OptionalFileHash $Path
    }
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $entries = @()
    foreach ($entry in Get-ChildItem -LiteralPath $resolved -Recurse -File | Sort-Object FullName) {
        $relative = Get-RelativePathForHash -Root $resolved -Path $entry.FullName
        $hash = (Get-FileHash -LiteralPath $entry.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        $entries += "$relative`t$hash"
    }
    return Get-StringSha256 ($entries -join "`n")
}

function New-EcosystemPathProjection {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [bool]$Required = $false
    )
    return [ordered]@{
        path = Get-RelativeOrNull $Path
        sha256 = Get-OptionalPathHash $Path
        present = Test-Path -LiteralPath $Path
        required = $Required
    }
}

Invoke-Checked "cargo build -p agentd --release" "cargo build -p agentd --release" { cargo build -p agentd --release }
Invoke-Checked "image/build-initramfs.ps1" "pwsh -NoProfile -ExecutionPolicy Bypass -File image/build-initramfs.ps1" {
    pwsh -NoProfile -ExecutionPolicy Bypass -File "image/build-initramfs.ps1"
}

Invoke-Checked "alpha service recovery smoke" "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/alpha-service-recovery-smoke.ps1 -SkipCargoTests -SkipRootfsAssembly" {
    pwsh -NoProfile -ExecutionPolicy Bypass -File "scripts/alpha-service-recovery-smoke.ps1" -SkipCargoTests -SkipRootfsAssembly
}

if (-not $SkipBootSmoke) {
    Invoke-Checked "QEMU runtime smoke" "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/boot-smoke-test.ps1 -QemuPath $QemuPath -TimeoutSeconds $QemuTimeoutSeconds" {
        pwsh -NoProfile -ExecutionPolicy Bypass -File "scripts/boot-smoke-test.ps1" `
            -QemuPath $QemuPath `
            -TimeoutSeconds $QemuTimeoutSeconds
    }
}

$binaryPath = Join-Path $repoRoot "target/release/agentd.exe"
if (-not (Test-Path -LiteralPath $binaryPath)) {
    $binaryPath = Join-Path $repoRoot "target/release/agentd"
}
$initramfsManifestPath = Join-Path $repoRoot "image/out/agentos-initramfs.manifest.json"
$initramfsManifest = Read-OptionalJson $initramfsManifestPath
$alphaRootfsManifestPath = if ($initramfsManifest -and $initramfsManifest.alpha_rootfs.manifest) {
    Join-Path $repoRoot $initramfsManifest.alpha_rootfs.manifest
} else {
    Join-Path $repoRoot "image/out/agentos-alpha-rootfs.manifest.json"
}
$alphaRootfsManifest = Read-OptionalJson $alphaRootfsManifestPath
$rootfsRuntimeManifestPath = if ($initramfsManifest -and $initramfsManifest.alpha_rootfs.rootfs_runtime_manifest) {
    Join-Path $repoRoot $initramfsManifest.alpha_rootfs.rootfs_runtime_manifest
} else {
    Join-Path $repoRoot "image/out/agentos-alpha-rootfs/usr/lib/agentos/release/rootfs-runtime-manifest.json"
}
$rootfsRuntimeManifest = Read-OptionalJson $rootfsRuntimeManifestPath
$bootSmokeResultPath = Join-Path $repoRoot ".workflow/artifacts/boot/boot-smoke-result.json"
$bootSmokeResult = Read-OptionalJson $bootSmokeResultPath
$serviceRecoveryResultPath = Join-Path $repoRoot ".workflow/artifacts/alpha-service-recovery/result.json"
$serviceRecoveryResult = Read-OptionalJson $serviceRecoveryResultPath
$functionalReplayResultPath = Join-Path $repoRoot ".workflow/artifacts/functional-replay/result.json"
$functionalReplayResult = Read-OptionalJson $functionalReplayResultPath
$capabilityMatrixPath = Join-Path $repoRoot ".workflow/active/WFS-20260524-agentos-functional-iteration/docs/functional-capability-matrix.md"
$ecosystemRegistrySnapshotPath = Join-Path $repoRoot "packaging/agentos/rootfs/etc/agentos/ecosystem/registry-snapshot.json"
$ecosystemLockfilePath = Join-Path $repoRoot ".workflow/artifacts/aom/ecosystem-lock.json"
$ecosystemStagedRootPath = Join-Path $repoRoot ".workflow/artifacts/aom/staged"
$ecosystemActiveSetPath = Join-Path $repoRoot ".workflow/artifacts/aom/active-set.json"
$ecosystemReplayResultPath = Join-Path $repoRoot ".workflow/artifacts/ecosystem-replay/result.json"
$ecosystemReplayResult = Read-OptionalJson $ecosystemReplayResultPath
$tuiReplayResultPath = Join-Path $repoRoot ".workflow/artifacts/tui-replay/result.json"
$tuiReplayResult = Read-OptionalJson $tuiReplayResultPath
$tuiConfigPath = Join-Path $repoRoot "packaging/agentos/rootfs/etc/agentos/tui.toml"
$operatorCommandsPath = Join-Path $repoRoot "packaging/agentos/rootfs/etc/agentos/operator-commands.json"

$inventory = New-DependencyInventory -GeneratedAt $candidateGeneratedAt
$inventoryPath = Join-Path $artifactRoot "dependency-inventory.json"
Write-Json -Value $inventory -Path $inventoryPath

$sourceCommit = Get-GitValue @("rev-parse", "HEAD")
$sourceBranch = Get-GitValue @("branch", "--show-current")

$releaseArtifacts = [ordered]@{
    agentd_binary = [ordered]@{
        path = Get-RelativeOrNull $binaryPath
        sha256 = Get-OptionalFileHash $binaryPath
    }
    initramfs = [ordered]@{
        path = "image/out/agentos-initramfs.cpio.gz"
        sha256 = Get-OptionalFileHash "image/out/agentos-initramfs.cpio.gz"
        manifest_path = Get-RelativeOrNull $initramfsManifestPath
        manifest_sha256 = Get-OptionalFileHash $initramfsManifestPath
    }
    alpha_rootfs_manifest = [ordered]@{
        path = Get-RelativeOrNull $alphaRootfsManifestPath
        sha256 = Get-OptionalFileHash $alphaRootfsManifestPath
    }
    rootfs_runtime_manifest = [ordered]@{
        path = Get-RelativeOrNull $rootfsRuntimeManifestPath
        sha256 = Get-OptionalFileHash $rootfsRuntimeManifestPath
    }
    qemu_runtime_smoke = [ordered]@{
        path = Get-RelativeOrNull $bootSmokeResultPath
        sha256 = Get-OptionalFileHash $bootSmokeResultPath
    }
    alpha_service_recovery_smoke = [ordered]@{
        path = Get-RelativeOrNull $serviceRecoveryResultPath
        sha256 = Get-OptionalFileHash $serviceRecoveryResultPath
    }
    functional_capability_replay = [ordered]@{
        path = Get-RelativeOrNull $functionalReplayResultPath
        sha256 = Get-OptionalFileHash $functionalReplayResultPath
    }
    functional_capability_matrix = [ordered]@{
        path = Get-RelativeOrNull $capabilityMatrixPath
        sha256 = Get-OptionalFileHash $capabilityMatrixPath
    }
    ecosystem_registry_snapshot = New-EcosystemPathProjection -Path $ecosystemRegistrySnapshotPath -Required $true
    ecosystem_lockfile = New-EcosystemPathProjection -Path $ecosystemLockfilePath -Required $false
    ecosystem_staged_set = New-EcosystemPathProjection -Path $ecosystemStagedRootPath -Required $false
    ecosystem_active_set = New-EcosystemPathProjection -Path $ecosystemActiveSetPath -Required $false
    ecosystem_replay = New-EcosystemPathProjection -Path $ecosystemReplayResultPath -Required (-not $SkipEcosystemReplay)
    tui_config = [ordered]@{
        path = Get-RelativeOrNull $tuiConfigPath
        sha256 = Get-OptionalFileHash $tuiConfigPath
    }
    operator_commands = [ordered]@{
        path = Get-RelativeOrNull $operatorCommandsPath
        sha256 = Get-OptionalFileHash $operatorCommandsPath
    }
    tui_replay = New-EcosystemPathProjection -Path $tuiReplayResultPath -Required (-not $SkipTuiReplay)
    dependency_inventory = [ordered]@{
        path = "dependency-inventory.json"
        sha256 = Get-OptionalFileHash $inventoryPath
    }
}

$sbom = New-CandidateSbom -Inventory $inventory -GeneratedAt $candidateGeneratedAt
$sbomPath = Join-Path $artifactRoot "sbom.json"
Write-Json -Value $sbom -Path $sbomPath
$releaseArtifacts.sbom = [ordered]@{
    path = "sbom.json"
    sha256 = Get-OptionalFileHash $sbomPath
}

$activeArtifactUpdateReadiness = New-ActiveArtifactUpdateReadiness `
    -Artifacts $releaseArtifacts `
    -EcosystemReplayResult $ecosystemReplayResult

$updateMetadata = New-CandidateUpdateMetadata `
    -GeneratedAt $candidateGeneratedAt `
    -SourceCommit $sourceCommit `
    -SourceBranch $sourceBranch `
    -Artifacts $releaseArtifacts `
    -ActiveArtifactReadiness $activeArtifactUpdateReadiness `
    -SbomPath "sbom.json" `
    -SbomSha256 $releaseArtifacts.sbom.sha256
$updateMetadataPath = Join-Path $artifactRoot "update-metadata.json"
Write-Json -Value $updateMetadata -Path $updateMetadataPath
$releaseArtifacts.update_metadata = [ordered]@{
    path = "update-metadata.json"
    sha256 = Get-OptionalFileHash $updateMetadataPath
}
$releaseArtifacts.dependency_inventory_signature = Write-CandidateDetachedSignature `
    -ArtifactName "dependency_inventory" `
    -Artifact $releaseArtifacts.dependency_inventory `
    -ArtifactPath $inventoryPath `
    -GeneratedAt $candidateGeneratedAt `
    -SourceCommit $sourceCommit
$releaseArtifacts.sbom_signature = Write-CandidateDetachedSignature `
    -ArtifactName "sbom" `
    -Artifact $releaseArtifacts.sbom `
    -ArtifactPath $sbomPath `
    -GeneratedAt $candidateGeneratedAt `
    -SourceCommit $sourceCommit
$releaseArtifacts.update_metadata_signature = Write-CandidateDetachedSignature `
    -ArtifactName "update_metadata" `
    -Artifact $releaseArtifacts.update_metadata `
    -ArtifactPath $updateMetadataPath `
    -GeneratedAt $candidateGeneratedAt `
    -SourceCommit $sourceCommit

$requiredRuntimeArtifactIds = @(
    "policy.pack",
    "tools.semantic",
    "operator.commands",
    "ecosystem.registry_snapshot",
    "model_broker.config",
    "tui.config",
    "state.runs",
    "state.audit",
    "state.rollback",
    "state.memory"
)
$runtimeArtifacts = if ($initramfsManifest) { @($initramfsManifest.alpha_rootfs.artifacts) } else { @() }
$runtimeArtifactIds = @($runtimeArtifacts | ForEach-Object { $_.id })
$missingRuntimeArtifactIds = @($requiredRuntimeArtifactIds | Where-Object { $runtimeArtifactIds -notcontains $_ })
$failedRuntimeArtifactIds = @($runtimeArtifacts | Where-Object { $_.status -ne "passed" } | ForEach-Object { $_.id })
$ecosystemReplayGateStatus = if ($SkipEcosystemReplay) {
    "skipped"
} elseif ($ecosystemReplayResult -and $ecosystemReplayResult.status -eq "passed") {
    "passed"
} else {
    "missing-or-failed"
}
$tuiReplayGateStatus = if ($SkipTuiReplay) {
    "skipped"
} elseif ($tuiReplayResult -and $tuiReplayResult.status -eq "passed") {
    "passed"
} else {
    "missing-or-failed"
}

$promotionBlockers = @()
if ($SkipTests) { $promotionBlockers += "tests-skipped" }
if ($SkipBootSmoke) { $promotionBlockers += "qemu-runtime-smoke-skipped" }
if ($SkipFunctionalReplay) { $promotionBlockers += "functional-replay-skipped" }
if ($SkipEcosystemReplay) { $promotionBlockers += "ecosystem-replay-skipped" }
if ($SkipTuiReplay) { $promotionBlockers += "tui-replay-skipped" }
if (-not $initramfsManifest) { $promotionBlockers += "initramfs-manifest-missing" }
if (-not $alphaRootfsManifest) { $promotionBlockers += "alpha-rootfs-manifest-missing" }
if (-not $rootfsRuntimeManifest) { $promotionBlockers += "rootfs-runtime-manifest-missing" }
if ($missingRuntimeArtifactIds.Count -gt 0) { $promotionBlockers += @($missingRuntimeArtifactIds | ForEach-Object { "runtime-artifact-missing:$_" }) }
if ($failedRuntimeArtifactIds.Count -gt 0) { $promotionBlockers += @($failedRuntimeArtifactIds | ForEach-Object { "runtime-artifact-failed:$_" }) }
if (-not $serviceRecoveryResult -or $serviceRecoveryResult.result -ne "passed") { $promotionBlockers += "alpha-service-recovery-smoke-missing-or-failed" }
if (-not $functionalReplayResult -or $functionalReplayResult.status -ne "passed") { $promotionBlockers += "functional-capability-replay-missing-or-failed" }
if (-not $releaseArtifacts.ecosystem_registry_snapshot.present) { $promotionBlockers += "ecosystem-registry-snapshot-missing" }
if ($ecosystemReplayGateStatus -eq "missing-or-failed") { $promotionBlockers += "ecosystem-replay-missing-or-failed" }
if ($tuiReplayGateStatus -eq "missing-or-failed") { $promotionBlockers += "tui-replay-missing-or-failed" }
if (-not $activeArtifactUpdateReadiness.promotion_allowed) {
    $promotionBlockers += "active-artifact-update-readiness-failed"
    $promotionBlockers += @($activeArtifactUpdateReadiness.incompatible_active_artifacts | ForEach-Object { "active-artifact-incompatible:$_" })
}
if (-not $SkipBootSmoke) {
    if (-not $bootSmokeResult -or $bootSmokeResult.status -ne "completed" -or $bootSmokeResult.observed_all_markers -ne $true) {
        $promotionBlockers += "qemu-runtime-smoke-missing-or-failed"
    }
}
$failedGates = @($script:gateResults | Where-Object { $_.status -ne "passed" })
if ($failedGates.Count -gt 0) {
    $promotionBlockers += @($failedGates | ForEach-Object { "gate-failed:$($_.name)" })
}

$provenance = [ordered]@{
    schema = "agentos.production-candidate.provenance.v1"
    generated_at = $candidateGeneratedAt
    source = [ordered]@{
        git_commit = $sourceCommit
        git_branch = $sourceBranch
        git_status_porcelain = Get-GitValue @("status", "--porcelain")
    }
    toolchain = [ordered]@{
        cargo = (& cargo --version)
        rustc = (& rustc --version)
        powershell = $PSVersionTable.PSVersion.ToString()
    }
    gates = @($script:gateResults)
    required_gate_commands = @(
        "cargo test -p agentd",
        "cargo test -p agentd safety::",
        "cargo test -p agentd agent_core::",
        "cargo test -p agentd agent_core::adversarial",
        "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/functional-capability-replay.ps1",
        "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/ecosystem-replay.ps1",
        "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/tui-replay.ps1",
        "cargo build -p agentd --release",
        "pwsh -NoProfile -ExecutionPolicy Bypass -File image/build-initramfs.ps1",
        "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/alpha-service-recovery-smoke.ps1 -SkipCargoTests -SkipRootfsAssembly",
        "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/boot-smoke-test.ps1 -QemuPath <qemu> -TimeoutSeconds <seconds>"
    )
    artifacts = $releaseArtifacts
    image_inputs = [ordered]@{
        initramfs_manifest = $initramfsManifest
        alpha_rootfs_manifest = $alphaRootfsManifest
        rootfs_runtime_manifest_schema = if ($rootfsRuntimeManifest) { $rootfsRuntimeManifest.schema } else { $null }
        qemu_runtime_smoke = $bootSmokeResult
        service_recovery_smoke = $serviceRecoveryResult
        functional_capability_replay = $functionalReplayResult
        ecosystem_replay = $ecosystemReplayResult
        tui_replay = $tuiReplayResult
    }
    functional_iteration = [ordered]@{
        capability_matrix_sha256 = $releaseArtifacts.functional_capability_matrix.sha256
        replay_result_sha256 = $releaseArtifacts.functional_capability_replay.sha256
        local_only_replay = $true
        external_llm_required = $false
        host_package_manager_required = $false
        firecracker_required = $false
    }
    ecosystem = [ordered]@{
        registry_snapshot = $releaseArtifacts.ecosystem_registry_snapshot
        lockfile = $releaseArtifacts.ecosystem_lockfile
        staged_set = $releaseArtifacts.ecosystem_staged_set
        active_set = $releaseArtifacts.ecosystem_active_set
        replay = $releaseArtifacts.ecosystem_replay
        staged_and_active_separated = $true
        install_stage_is_activation = $false
        activation_authority = "AgentCore PlanSpec + SecurityExecutionEngine"
        agentd_resolver_logic = $false
        resolver_owner = "agent_core::ecosystem"
        local_only_baseline = $true
        network_required = $false
        replay_gate_required_after = "TASK-VERIFY-041"
        replay_gate_current_status = $ecosystemReplayGateStatus
        update_readiness = $activeArtifactUpdateReadiness
    }
    tui = [ordered]@{
        config = $releaseArtifacts.tui_config
        replay = $releaseArtifacts.tui_replay
        replay_status = $tuiReplayGateStatus
        command_registry = $releaseArtifacts.operator_commands
        default_mode = "durable"
        projection_controller_only = $true
        runtime_authority = "AgentCore PlanSpec + SecurityExecutionEngine"
        normal_shell_available = $false
        local_only_baseline = $true
        external_llm_required = $false
        network_required = $false
        firecracker_required = $false
        host_package_manager_required = $false
    }
    alpha_runtime = [ordered]@{
        runtime_artifact_ids = @($runtimeArtifactIds)
        missing_runtime_artifact_ids = @($missingRuntimeArtifactIds)
        failed_runtime_artifact_ids = @($failedRuntimeArtifactIds)
        runtime_marker = if ($initramfsManifest) { $initramfsManifest.runtime_marker } else { $null }
        tui_marker = if ($initramfsManifest) { $initramfsManifest.tui_marker } else { $null }
        runtime_manifest_marker = if ($initramfsManifest) { $initramfsManifest.runtime_manifest_marker } else { $null }
        rootfs_runtime_manifest_sha256 = if ($initramfsManifest) { $initramfsManifest.alpha_rootfs.rootfs_runtime_manifest_sha256 } else { $null }
        qemu_path = $QemuPath
        qemu_timeout_seconds = $QemuTimeoutSeconds
        external_llm_required = $false
    }
    policy = [ordered]@{
        safety_gate = "cargo test -p agentd safety::; cargo test -p agentd agent_core::; cargo test -p agentd agent_core::adversarial"
        service_recovery_gate = "scripts/alpha-service-recovery-smoke.ps1 -SkipRootfsAssembly"
        boot_gate = "scripts/boot-smoke-test.ps1 requires handoff, runtime, TUI console, and runtime manifest markers"
        secret_policy = "handle-only; release metadata stores hashes and paths, not secret values"
        promotion = "Promote Production Candidate only after tests, safety gates, AgentCore gates, service recovery smoke, dependency inventory, SBOM, update metadata, detached signatures, provenance, image manifest, reproducibility, and full QEMU runtime smoke pass."
    }
    signing = [ordered]@{
        signature_schema = "agentos.release-detached-signature.v1"
        algorithm = "sha256-hash-bound-candidate-signature-v1"
        key_id = "agentos-candidate-release-hash-bound-v1"
        key_provenance = "scripts/build-release.ps1 deterministic candidate signing record"
        key_rotation_policy = "docs/release-artifacts.md#signature-and-key-policy"
        detached_signature_suffix = ".sig.json"
        required_detached_signatures = @(
            "dependency_inventory",
            "sbom",
            "update_metadata",
            "provenance"
        )
        production_key_required = $false
        fail_closed = $true
    }
    promotion = [ordered]@{
        status = if ($promotionBlockers.Count -eq 0) { "promotable" } else { "blocked" }
        blockers = @($promotionBlockers)
    }
}

$provenancePath = Join-Path $artifactRoot "provenance.json"
Write-Json -Value $provenance -Path $provenancePath
$provenanceArtifact = [ordered]@{
    path = "provenance.json"
    sha256 = Get-OptionalFileHash $provenancePath
}
$provenanceSignatureArtifact = Write-CandidateDetachedSignature `
    -ArtifactName "provenance" `
    -Artifact $provenanceArtifact `
    -ArtifactPath $provenancePath `
    -GeneratedAt $candidateGeneratedAt `
    -SourceCommit $sourceCommit

if (-not (Test-SecretFreeContent $inventoryPath)) {
    throw "Dependency inventory contains secret-like content: $inventoryPath"
}
if (-not (Test-SecretFreeContent $provenancePath)) {
    throw "Provenance contains secret-like content: $provenancePath"
}
foreach ($path in @($sbomPath, $updateMetadataPath, "$inventoryPath.sig.json", "$sbomPath.sig.json", "$updateMetadataPath.sig.json", "$provenancePath.sig.json")) {
    if (-not (Test-SecretFreeContent $path)) {
        throw "Release artifact contains secret-like content: $path"
    }
}

if ($RequireProductionSignatures) {
    Invoke-Checked "production signature verification" "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/verify-production-signatures.ps1 -ProvenancePath $provenancePath -RequireDecisionEvidence -FailOnBlocked" {
        pwsh -NoProfile -ExecutionPolicy Bypass -File "scripts/verify-production-signatures.ps1" `
            -ProvenancePath $provenancePath `
            -OutputPath ".workflow/artifacts/production-signature-verification/result.json" `
            -RequireDecisionEvidence `
            -FailOnBlocked
    }
}

if ($promotionBlockers.Count -gt 0 -and -not ($SkipTests -or $SkipBootSmoke)) {
    throw "Distribution Alpha promotion gate blocked: $($promotionBlockers -join ', ')"
}

Write-Host "Release artifacts written:"
Write-Host "  $inventoryPath"
Write-Host "  $sbomPath"
Write-Host "  $updateMetadataPath"
Write-Host "  $provenancePath"
Write-Host "  $($provenanceSignatureArtifact.path)"
