param(
    [string]$ArtifactDir = ".workflow/artifacts/release",
    [string]$QemuPath = "E:\qemu\qemu-system-x86_64.exe",
    [switch]$SkipBootSmoke,
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"

function Write-Json {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $Value | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Script
    )
    Write-Host "==> $Name"
    & $Script
    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed with exit code $LASTEXITCODE"
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
    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function New-DependencyInventory {
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
        generated_at = (Get-Date).ToString("o")
        packages = $packages
        lockfile = [ordered]@{
            path = "Cargo.lock"
            sha256 = Get-OptionalFileHash "Cargo.lock"
        }
    }
}

$repoRoot = (Resolve-Path -LiteralPath ".").Path
$artifactRoot = Join-Path $repoRoot $ArtifactDir
New-Item -ItemType Directory -Force -Path $artifactRoot | Out-Null

if (-not $SkipTests) {
    Invoke-Checked "cargo test -p agentd" { cargo test -p agentd }
    Invoke-Checked "cargo test -p agentd safety::" { cargo test -p agentd safety:: }
}

Invoke-Checked "cargo build -p agentd --release" { cargo build -p agentd --release }
Invoke-Checked "image/build-initramfs.ps1" {
    pwsh -NoProfile -ExecutionPolicy Bypass -File "image/build-initramfs.ps1"
}

if (-not $SkipBootSmoke) {
    Invoke-Checked "boot smoke dependency check" {
        pwsh -NoProfile -ExecutionPolicy Bypass -File "scripts/boot-smoke-test.ps1" `
            -QemuPath $QemuPath `
            -DependencyCheckOnly
    }
}

$binaryPath = Join-Path $repoRoot "target/release/agentd.exe"
if (-not (Test-Path -LiteralPath $binaryPath)) {
    $binaryPath = Join-Path $repoRoot "target/release/agentd"
}
$initramfsManifestPath = Join-Path $repoRoot "image/out/agentos-initramfs.manifest.json"
$initramfsManifest = $null
if (Test-Path -LiteralPath $initramfsManifestPath) {
    $initramfsManifest = Get-Content -LiteralPath $initramfsManifestPath -Raw | ConvertFrom-Json
}

$inventory = New-DependencyInventory
$inventoryPath = Join-Path $artifactRoot "dependency-inventory.json"
Write-Json -Value $inventory -Path $inventoryPath

$provenance = [ordered]@{
    schema = "aios.provenance.v1"
    generated_at = (Get-Date).ToString("o")
    source = [ordered]@{
        git_commit = Get-GitValue @("rev-parse", "HEAD")
        git_branch = Get-GitValue @("branch", "--show-current")
        git_status_porcelain = Get-GitValue @("status", "--porcelain")
    }
    toolchain = [ordered]@{
        cargo = (& cargo --version)
        rustc = (& rustc --version)
        powershell = $PSVersionTable.PSVersion.ToString()
    }
    commands = @(
        "cargo test -p agentd",
        "cargo test -p agentd safety::",
        "cargo build -p agentd --release",
        "pwsh -NoProfile -ExecutionPolicy Bypass -File image/build-initramfs.ps1",
        "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/boot-smoke-test.ps1 -DependencyCheckOnly"
    )
    artifacts = [ordered]@{
        agentd_binary = [ordered]@{
            path = if (Test-Path -LiteralPath $binaryPath) { [IO.Path]::GetRelativePath($repoRoot, $binaryPath) } else { $null }
            sha256 = Get-OptionalFileHash $binaryPath
        }
        initramfs = [ordered]@{
            path = "image/out/agentos-initramfs.cpio.gz"
            sha256 = Get-OptionalFileHash "image/out/agentos-initramfs.cpio.gz"
            manifest = $initramfsManifest
        }
        dependency_inventory = [ordered]@{
            path = [IO.Path]::GetRelativePath($repoRoot, $inventoryPath)
            sha256 = Get-OptionalFileHash $inventoryPath
        }
    }
    policy = [ordered]@{
        safety_gate = "cargo test -p agentd safety::"
        boot_gate = "scripts/boot-smoke-test.ps1"
        secret_policy = "handle-only; release metadata stores hashes and paths, not secret values"
        promotion = "Promote only after tests, safety gate, dependency inventory, provenance, and boot smoke dependency check pass."
    }
}

$provenancePath = Join-Path $artifactRoot "provenance.json"
Write-Json -Value $provenance -Path $provenancePath

Write-Host "Release artifacts written:"
Write-Host "  $inventoryPath"
Write-Host "  $provenancePath"
