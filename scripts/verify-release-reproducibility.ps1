param(
    [string]$ArtifactRoot = ".workflow/artifacts/release-reproducibility",
    [string]$OutputPath = ".workflow/artifacts/release-reproducibility/result.json",
    [string]$QemuPath = "E:\qemu\qemu-system-x86_64.exe",
    [int]$QemuTimeoutSeconds = 45,
    [switch]$SkipBootSmoke,
    [switch]$SkipTests,
    [switch]$FailOnDivergence
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

function Get-GitValue {
    param([Parameter(Mandatory = $true)][string[]]$Args)
    $value = & git @Args 2>$null
    if ($LASTEXITCODE -ne 0) {
        return $null
    }
    return ($value -join "`n").Trim()
}

function Resolve-RepoChildPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ([IO.Path]::IsPathRooted($Path)) {
        return [IO.Path]::GetFullPath($Path)
    }
    return [IO.Path]::GetFullPath((Join-Path $script:repoRoot $Path))
}

function Clear-SafeArtifactDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    $resolved = Resolve-RepoChildPath $Path
    $artifactBase = [IO.Path]::GetFullPath((Join-Path $script:repoRoot ".workflow/artifacts"))
    if (-not $resolved.StartsWith($artifactBase, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to clear non-artifact path: $resolved"
    }
    if (Test-Path -LiteralPath $resolved) {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $resolved | Out-Null
}

function Read-Json {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing JSON artifact: $Path"
    }
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function ConvertTo-CanonicalJson {
    param($Value)
    return ($Value | ConvertTo-Json -Depth 32 -Compress)
}

function Add-Comparison {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        $First,
        $Second,
        [string]$IgnoredReason = $null
    )
    $firstJson = ConvertTo-CanonicalJson $First
    $secondJson = ConvertTo-CanonicalJson $Second
    $entry = [ordered]@{
        field = $Name
        first = $First
        second = $Second
    }
    if ($firstJson -eq $secondJson) {
        $script:matchedFields += $entry
        return
    }
    if ($IgnoredReason) {
        $entry.reason = $IgnoredReason
        $script:ignoredFields += $entry
        return
    }
    $script:divergentFields += $entry
}

function Select-DependencyInventoryCanonical {
    param($Inventory)
    return [ordered]@{
        schema = $Inventory.schema
        packages = @($Inventory.packages | Sort-Object name, version | ForEach-Object {
            [ordered]@{
                name = $_.name
                version = $_.version
                license = $_.license
            }
        })
        lockfile = [ordered]@{
            path = $Inventory.lockfile.path
            sha256 = $Inventory.lockfile.sha256
        }
    }
}

function Select-ReleaseMetadataCanonical {
    param($Metadata)
    return [ordered]@{
        schema = $Metadata.schema
        source = $Metadata.source
        update_strategy = $Metadata.update_strategy
        artifacts = $Metadata.artifacts
        signature_policy = $Metadata.signature_policy
        production_ready_claim = $Metadata.production_ready_claim
    }
}

function Select-DetachedSignatureCanonical {
    param($Signature)
    return [ordered]@{
        schema = $Signature.schema
        artifact = $Signature.artifact
        signature = $Signature.signature
        key = $Signature.key
        policy = $Signature.policy
    }
}

function Select-GateStatusCanonical {
    param($Provenance)
    return @($Provenance.gates | Sort-Object name | ForEach-Object {
        [ordered]@{
            name = $_.name
            command = $_.command
            status = $_.status
            exit_code = $_.exit_code
        }
    })
}

function Select-QemuCanonical {
    param($Provenance)
    $qemu = $Provenance.image_inputs.qemu_runtime_smoke
    return [ordered]@{
        status = $qemu.status
        observed_all_markers = $qemu.observed_all_markers
        required_markers = @($qemu.required_markers)
        observed_markers = $qemu.observed_markers
        initramfs_sha256 = $qemu.initramfs_sha256
        rootfs_runtime_manifest_sha256 = $qemu.rootfs_runtime_manifest_sha256
        boot_args = $qemu.boot_args
    }
}

function Select-ServiceRecoveryCanonical {
    param($Provenance)
    $smoke = $Provenance.image_inputs.service_recovery_smoke
    return [ordered]@{
        schema = $smoke.schema
        result = $smoke.result
        execution_surface = $smoke.execution_surface
        assertions = $smoke.assertions
    }
}

function Invoke-ReleaseBuild {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$ArtifactDir
    )
    $args = @(
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        "scripts/build-release.ps1",
        "-ArtifactDir",
        $ArtifactDir,
        "-QemuPath",
        $QemuPath,
        "-QemuTimeoutSeconds",
        $QemuTimeoutSeconds
    )
    if ($SkipBootSmoke) {
        $args += "-SkipBootSmoke"
    }
    if ($SkipTests) {
        $args += "-SkipTests"
    }

    $started = Get-Date
    & pwsh @args
    $exitCode = $LASTEXITCODE
    $script:builds += [ordered]@{
        name = $Name
        command = "pwsh $($args -join ' ')"
        artifact_dir = $ArtifactDir
        started_at = $started.ToString("o")
        completed_at = (Get-Date).ToString("o")
        exit_code = $exitCode
        status = if ($exitCode -eq 0) { "passed" } else { "failed" }
    }
    if ($exitCode -ne 0) {
        throw "$Name release build failed with exit code $exitCode"
    }
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:matchedFields = @()
$script:ignoredFields = @()
$script:divergentFields = @()
$script:builds = @()

$sourceCommit = Get-GitValue @("rev-parse", "HEAD")
$sourceBranch = Get-GitValue @("branch", "--show-current")

try {
    Clear-SafeArtifactDirectory -Path $ArtifactRoot
    $firstArtifactDir = (Join-Path $ArtifactRoot "first/release").Replace("\", "/")
    $secondArtifactDir = (Join-Path $ArtifactRoot "second/release").Replace("\", "/")

    Invoke-ReleaseBuild -Name "first" -ArtifactDir $firstArtifactDir
    Invoke-ReleaseBuild -Name "second" -ArtifactDir $secondArtifactDir

    $firstProvenancePath = Resolve-RepoChildPath (Join-Path $firstArtifactDir "provenance.json")
    $secondProvenancePath = Resolve-RepoChildPath (Join-Path $secondArtifactDir "provenance.json")
    $firstInventoryPath = Resolve-RepoChildPath (Join-Path $firstArtifactDir "dependency-inventory.json")
    $secondInventoryPath = Resolve-RepoChildPath (Join-Path $secondArtifactDir "dependency-inventory.json")
    $firstSbomPath = Resolve-RepoChildPath (Join-Path $firstArtifactDir "sbom.json")
    $secondSbomPath = Resolve-RepoChildPath (Join-Path $secondArtifactDir "sbom.json")
    $firstUpdateMetadataPath = Resolve-RepoChildPath (Join-Path $firstArtifactDir "update-metadata.json")
    $secondUpdateMetadataPath = Resolve-RepoChildPath (Join-Path $secondArtifactDir "update-metadata.json")
    $firstInventorySignaturePath = Resolve-RepoChildPath (Join-Path $firstArtifactDir "dependency-inventory.json.sig.json")
    $secondInventorySignaturePath = Resolve-RepoChildPath (Join-Path $secondArtifactDir "dependency-inventory.json.sig.json")
    $firstSbomSignaturePath = Resolve-RepoChildPath (Join-Path $firstArtifactDir "sbom.json.sig.json")
    $secondSbomSignaturePath = Resolve-RepoChildPath (Join-Path $secondArtifactDir "sbom.json.sig.json")
    $firstUpdateMetadataSignaturePath = Resolve-RepoChildPath (Join-Path $firstArtifactDir "update-metadata.json.sig.json")
    $secondUpdateMetadataSignaturePath = Resolve-RepoChildPath (Join-Path $secondArtifactDir "update-metadata.json.sig.json")
    $firstProvenanceSignaturePath = Resolve-RepoChildPath (Join-Path $firstArtifactDir "provenance.json.sig.json")
    $secondProvenanceSignaturePath = Resolve-RepoChildPath (Join-Path $secondArtifactDir "provenance.json.sig.json")

    $firstProvenance = Read-Json $firstProvenancePath
    $secondProvenance = Read-Json $secondProvenancePath
    $firstInventory = Read-Json $firstInventoryPath
    $secondInventory = Read-Json $secondInventoryPath
    $firstSbom = Read-Json $firstSbomPath
    $secondSbom = Read-Json $secondSbomPath
    $firstUpdateMetadata = Read-Json $firstUpdateMetadataPath
    $secondUpdateMetadata = Read-Json $secondUpdateMetadataPath
    $firstInventorySignature = Read-Json $firstInventorySignaturePath
    $secondInventorySignature = Read-Json $secondInventorySignaturePath
    $firstSbomSignature = Read-Json $firstSbomSignaturePath
    $secondSbomSignature = Read-Json $secondSbomSignaturePath
    $firstUpdateMetadataSignature = Read-Json $firstUpdateMetadataSignaturePath
    $secondUpdateMetadataSignature = Read-Json $secondUpdateMetadataSignaturePath
    $firstProvenanceSignature = Read-Json $firstProvenanceSignaturePath
    $secondProvenanceSignature = Read-Json $secondProvenanceSignaturePath

    Add-Comparison "provenance.generated_at" $firstProvenance.generated_at $secondProvenance.generated_at "wall-clock timestamp"
    Add-Comparison "source.git_commit" $firstProvenance.source.git_commit $secondProvenance.source.git_commit
    Add-Comparison "source.git_branch" $firstProvenance.source.git_branch $secondProvenance.source.git_branch
    Add-Comparison "source.git_status_porcelain" $firstProvenance.source.git_status_porcelain $secondProvenance.source.git_status_porcelain
    Add-Comparison "toolchain" $firstProvenance.toolchain $secondProvenance.toolchain
    Add-Comparison "required_gate_commands" $firstProvenance.required_gate_commands $secondProvenance.required_gate_commands
    Add-Comparison "gate_statuses" (Select-GateStatusCanonical $firstProvenance) (Select-GateStatusCanonical $secondProvenance)
    Add-Comparison "dependency_inventory.generated_at" $firstInventory.generated_at $secondInventory.generated_at "wall-clock timestamp"
    Add-Comparison "dependency_inventory.canonical" (Select-DependencyInventoryCanonical $firstInventory) (Select-DependencyInventoryCanonical $secondInventory)
    Add-Comparison "candidate.sbom.canonical" (Select-DependencyInventoryCanonical $firstSbom) (Select-DependencyInventoryCanonical $secondSbom)
    Add-Comparison "candidate.update_metadata.canonical" (Select-ReleaseMetadataCanonical $firstUpdateMetadata) (Select-ReleaseMetadataCanonical $secondUpdateMetadata)
    Add-Comparison "candidate.dependency_inventory_signature.canonical" (Select-DetachedSignatureCanonical $firstInventorySignature) (Select-DetachedSignatureCanonical $secondInventorySignature)
    Add-Comparison "candidate.sbom_signature.canonical" (Select-DetachedSignatureCanonical $firstSbomSignature) (Select-DetachedSignatureCanonical $secondSbomSignature)
    Add-Comparison "candidate.update_metadata_signature.canonical" (Select-DetachedSignatureCanonical $firstUpdateMetadataSignature) (Select-DetachedSignatureCanonical $secondUpdateMetadataSignature)
    Add-Comparison "candidate.provenance_signature.canonical" (Select-DetachedSignatureCanonical $firstProvenanceSignature) (Select-DetachedSignatureCanonical $secondProvenanceSignature)
    Add-Comparison "artifacts.agentd_binary.sha256" $firstProvenance.artifacts.agentd_binary.sha256 $secondProvenance.artifacts.agentd_binary.sha256
    Add-Comparison "artifacts.initramfs.sha256" $firstProvenance.artifacts.initramfs.sha256 $secondProvenance.artifacts.initramfs.sha256
    Add-Comparison "artifacts.initramfs.manifest_sha256" $firstProvenance.artifacts.initramfs.manifest_sha256 $secondProvenance.artifacts.initramfs.manifest_sha256
    Add-Comparison "artifacts.alpha_rootfs_manifest.sha256" $firstProvenance.artifacts.alpha_rootfs_manifest.sha256 $secondProvenance.artifacts.alpha_rootfs_manifest.sha256
    Add-Comparison "artifacts.rootfs_runtime_manifest.sha256" $firstProvenance.artifacts.rootfs_runtime_manifest.sha256 $secondProvenance.artifacts.rootfs_runtime_manifest.sha256
    Add-Comparison "artifacts.sbom.sha256" $firstProvenance.artifacts.sbom.sha256 $secondProvenance.artifacts.sbom.sha256
    Add-Comparison "artifacts.update_metadata.sha256" $firstProvenance.artifacts.update_metadata.sha256 $secondProvenance.artifacts.update_metadata.sha256
    Add-Comparison "artifacts.dependency_inventory_signature.sha256" $firstProvenance.artifacts.dependency_inventory_signature.sha256 $secondProvenance.artifacts.dependency_inventory_signature.sha256
    Add-Comparison "artifacts.sbom_signature.sha256" $firstProvenance.artifacts.sbom_signature.sha256 $secondProvenance.artifacts.sbom_signature.sha256
    Add-Comparison "artifacts.update_metadata_signature.sha256" $firstProvenance.artifacts.update_metadata_signature.sha256 $secondProvenance.artifacts.update_metadata_signature.sha256
    Add-Comparison "signing" $firstProvenance.signing $secondProvenance.signing
    Add-Comparison "alpha_runtime" $firstProvenance.alpha_runtime $secondProvenance.alpha_runtime
    Add-Comparison "promotion" $firstProvenance.promotion $secondProvenance.promotion
    Add-Comparison "qemu_runtime_smoke.canonical" (Select-QemuCanonical $firstProvenance) (Select-QemuCanonical $secondProvenance)
    Add-Comparison "service_recovery_smoke.canonical" (Select-ServiceRecoveryCanonical $firstProvenance) (Select-ServiceRecoveryCanonical $secondProvenance)

    $status = if ($script:divergentFields.Count -eq 0) { "passed" } else { "diverged" }
    $result = [ordered]@{
        schema = "agentos.release-reproducibility.v1"
        checked_at = (Get-Date).ToString("o")
        status = $status
        production_ready_claim = $false
        source_commit = $sourceCommit
        source_branch = $sourceBranch
        artifact_root = $ArtifactRoot
        build_commands = @($script:builds)
        first_artifacts = [ordered]@{
            provenance = [IO.Path]::GetRelativePath($script:repoRoot, $firstProvenancePath)
            dependency_inventory = [IO.Path]::GetRelativePath($script:repoRoot, $firstInventoryPath)
            sbom = [IO.Path]::GetRelativePath($script:repoRoot, $firstSbomPath)
            update_metadata = [IO.Path]::GetRelativePath($script:repoRoot, $firstUpdateMetadataPath)
        }
        second_artifacts = [ordered]@{
            provenance = [IO.Path]::GetRelativePath($script:repoRoot, $secondProvenancePath)
            dependency_inventory = [IO.Path]::GetRelativePath($script:repoRoot, $secondInventoryPath)
            sbom = [IO.Path]::GetRelativePath($script:repoRoot, $secondSbomPath)
            update_metadata = [IO.Path]::GetRelativePath($script:repoRoot, $secondUpdateMetadataPath)
        }
        matched_fields = @($script:matchedFields)
        ignored_fields = @($script:ignoredFields)
        divergent_fields = @($script:divergentFields)
        summary = [ordered]@{
            matched = $script:matchedFields.Count
            ignored = $script:ignoredFields.Count
            divergent = $script:divergentFields.Count
        }
    }
    Write-Json -Value $result -Path (Resolve-RepoChildPath $OutputPath)
    Write-Host "Release reproducibility verification $status`: $OutputPath"
    if ($FailOnDivergence -and $status -ne "passed") {
        exit 1
    }
} catch {
    $blocked = [ordered]@{
        schema = "agentos.release-reproducibility.v1"
        checked_at = (Get-Date).ToString("o")
        status = "blocked"
        production_ready_claim = $false
        source_commit = $sourceCommit
        source_branch = $sourceBranch
        artifact_root = $ArtifactRoot
        build_commands = @($script:builds)
        error = $_.Exception.Message
        matched_fields = @($script:matchedFields)
        ignored_fields = @($script:ignoredFields)
        divergent_fields = @($script:divergentFields)
    }
    Write-Json -Value $blocked -Path (Resolve-RepoChildPath $OutputPath)
    throw
}
