param(
    [string]$SourceRootfs = "packaging/agentos/rootfs",
    [string]$OutDir = "image/out",
    [string]$StagingName = "agentos-alpha-rootfs",
    [switch]$Clean
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
    $Value | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Get-OptionalSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-ChildPath {
    param(
        [Parameter(Mandatory = $true)][string]$Parent,
        [Parameter(Mandatory = $true)][string]$Child
    )
    $resolvedParent = (Resolve-Path -LiteralPath $Parent).Path
    $resolvedChild = if (Test-Path -LiteralPath $Child) {
        (Resolve-Path -LiteralPath $Child).Path
    } else {
        $Child
    }
    $fullChild = [IO.Path]::GetFullPath($resolvedChild)
    if (-not $fullChild.StartsWith($resolvedParent, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to operate outside $resolvedParent`: $fullChild"
    }
}

function Copy-DirectoryContents {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    foreach ($entry in Get-ChildItem -LiteralPath $Source -Force) {
        Copy-Item -LiteralPath $entry.FullName -Destination $Destination -Recurse -Force
    }
}

$repoRoot = (Resolve-Path -LiteralPath ".").Path
$sourceRoot = (Resolve-Path -LiteralPath $SourceRootfs).Path
$outRoot = Join-Path $repoRoot $OutDir
$stagingRoot = Join-Path $outRoot $StagingName

New-Item -ItemType Directory -Force -Path $outRoot | Out-Null

if ($Clean -and (Test-Path -LiteralPath $stagingRoot)) {
    Assert-ChildPath -Parent $outRoot -Child $stagingRoot
    Remove-Item -LiteralPath $stagingRoot -Recurse -Force
}

$validationPath = Join-Path $outRoot "agentos-alpha-rootfs.validation.json"
& pwsh -NoProfile -ExecutionPolicy Bypass -File "scripts/validate-alpha-rootfs.ps1" `
    -RootfsPath $sourceRoot `
    -Stage PackageDefaults `
    -OutputPath $validationPath
if ($LASTEXITCODE -ne 0) {
    throw "Alpha rootfs validation failed with exit code $LASTEXITCODE"
}
$validation = Get-Content -LiteralPath $validationPath -Raw | ConvertFrom-Json
if ($validation.result -ne "passed") {
    throw "Alpha rootfs validation did not pass: $($validation.result)"
}

if (Test-Path -LiteralPath $stagingRoot) {
    Assert-ChildPath -Parent $outRoot -Child $stagingRoot
    Remove-Item -LiteralPath $stagingRoot -Recurse -Force
}
Copy-DirectoryContents -Source $sourceRoot -Destination $stagingRoot

$releaseDir = Join-Path $stagingRoot "usr/lib/agentos/release"
New-Item -ItemType Directory -Force -Path $releaseDir | Out-Null

$artifactRows = @()
foreach ($artifact in @($validation.artifacts)) {
    $artifactRows += [ordered]@{
        id = $artifact.id
        kind = $artifact.kind
        rootfs_path = $artifact.path
        expected_owner = $artifact.expected_owner
        expected_mode = $artifact.expected_mode
        sha256 = $artifact.sha256
        status = $artifact.status
    }
}

$rootfsRuntimeManifest = [ordered]@{
    schema = "agentos.rootfs-runtime-manifest.v1"
    generated_at = (Get-Date).ToString("o")
    source_rootfs = [IO.Path]::GetRelativePath($repoRoot, $sourceRoot)
    staged_rootfs = [IO.Path]::GetRelativePath($repoRoot, $stagingRoot)
    validation = [ordered]@{
        path = [IO.Path]::GetRelativePath($repoRoot, $validationPath)
        schema = $validation.schema
        stage = $validation.stage
        result = $validation.result
        failed_ids = @($validation.summary.failed_ids)
    }
    runtime_contract = [ordered]@{
        requires_runtime_foundation_final_audit = "TASK-RTF-005"
        requires_security_execution_final_verification = "TASK-SEF-010"
        requires_generic_service_recovery = "TASK-ACR-009"
    }
    artifacts = $artifactRows
    blocking_alpha_risks = @(
        "FullRootfs validation still requires agentd.boot, agentd.runtime, release.provenance, and release.rootfs_manifest after runtime binary installation.",
        "This staging step validates package defaults and persistent state paths; QEMU runtime smoke is required before Alpha promotion."
    )
}

$rootfsRuntimeManifestPath = Join-Path $releaseDir "rootfs-runtime-manifest.json"
Write-Json -Value $rootfsRuntimeManifest -Path $rootfsRuntimeManifestPath

$manifest = [ordered]@{
    schema = "agentos.alpha-rootfs-assembly.v1"
    generated_at = (Get-Date).ToString("o")
    source_rootfs = [IO.Path]::GetRelativePath($repoRoot, $sourceRoot)
    staged_rootfs = [IO.Path]::GetRelativePath($repoRoot, $stagingRoot)
    validation_result = [IO.Path]::GetRelativePath($repoRoot, $validationPath)
    rootfs_runtime_manifest = [IO.Path]::GetRelativePath($repoRoot, $rootfsRuntimeManifestPath)
    rootfs_runtime_manifest_sha256 = Get-OptionalSha256 $rootfsRuntimeManifestPath
    artifacts = $artifactRows
    builder = "image/build-alpha-rootfs.ps1"
}

$manifestPath = Join-Path $outRoot "agentos-alpha-rootfs.manifest.json"
Write-Json -Value $manifest -Path $manifestPath

Write-Host "Built $stagingRoot"
Write-Host "Manifest $manifestPath"
