param(
    [string]$ArtifactDir = ".workflow/artifacts/release",
    [string]$QemuPath = "E:\qemu\qemu-system-x86_64.exe",
    [int]$QemuTimeoutSeconds = 30,
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
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][scriptblock]$Script
    )
    Write-Host "==> $Name"
    $started = Get-Date
    & $Script
    if ($LASTEXITCODE -ne 0) {
        $script:gateResults += [ordered]@{
            name = $Name
            command = $Command
            status = "failed"
            exit_code = $LASTEXITCODE
            started_at = $started.ToString("o")
            completed_at = (Get-Date).ToString("o")
        }
        throw "$Name failed with exit code $LASTEXITCODE"
    }
    $script:gateResults += [ordered]@{
        name = $Name
        command = $Command
        status = "passed"
        exit_code = 0
        started_at = $started.ToString("o")
        completed_at = (Get-Date).ToString("o")
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
    return [IO.Path]::GetRelativePath($repoRoot, (Resolve-Path -LiteralPath $Path).Path)
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
$script:gateResults = @()

if (-not $SkipTests) {
    Invoke-Checked "cargo test -p agentd" "cargo test -p agentd" { cargo test -p agentd }
    Invoke-Checked "cargo test -p agentd safety::" "cargo test -p agentd safety::" { cargo test -p agentd safety:: }
    Invoke-Checked "cargo test -p agentd agent_core::" "cargo test -p agentd agent_core::" { cargo test -p agentd agent_core:: }
    Invoke-Checked "cargo test -p agentd agent_core::adversarial" "cargo test -p agentd agent_core::adversarial" { cargo test -p agentd agent_core::adversarial }
}

Invoke-Checked "cargo build -p agentd --release" "cargo build -p agentd --release" { cargo build -p agentd --release }
Invoke-Checked "image/build-initramfs.ps1" "pwsh -NoProfile -ExecutionPolicy Bypass -File image/build-initramfs.ps1" {
    pwsh -NoProfile -ExecutionPolicy Bypass -File "image/build-initramfs.ps1"
}

Invoke-Checked "alpha service recovery smoke" "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/alpha-service-recovery-smoke.ps1 -SkipCargoTests" {
    pwsh -NoProfile -ExecutionPolicy Bypass -File "scripts/alpha-service-recovery-smoke.ps1" -SkipCargoTests
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

$inventory = New-DependencyInventory
$inventoryPath = Join-Path $artifactRoot "dependency-inventory.json"
Write-Json -Value $inventory -Path $inventoryPath

$requiredRuntimeArtifactIds = @(
    "policy.pack",
    "tools.semantic",
    "model_broker.config",
    "state.runs",
    "state.audit",
    "state.rollback",
    "state.memory"
)
$runtimeArtifacts = if ($initramfsManifest) { @($initramfsManifest.alpha_rootfs.artifacts) } else { @() }
$runtimeArtifactIds = @($runtimeArtifacts | ForEach-Object { $_.id })
$missingRuntimeArtifactIds = @($requiredRuntimeArtifactIds | Where-Object { $runtimeArtifactIds -notcontains $_ })
$failedRuntimeArtifactIds = @($runtimeArtifacts | Where-Object { $_.status -ne "passed" } | ForEach-Object { $_.id })

$promotionBlockers = @()
if ($SkipTests) { $promotionBlockers += "tests-skipped" }
if ($SkipBootSmoke) { $promotionBlockers += "qemu-runtime-smoke-skipped" }
if (-not $initramfsManifest) { $promotionBlockers += "initramfs-manifest-missing" }
if (-not $alphaRootfsManifest) { $promotionBlockers += "alpha-rootfs-manifest-missing" }
if (-not $rootfsRuntimeManifest) { $promotionBlockers += "rootfs-runtime-manifest-missing" }
if ($missingRuntimeArtifactIds.Count -gt 0) { $promotionBlockers += @($missingRuntimeArtifactIds | ForEach-Object { "runtime-artifact-missing:$_" }) }
if ($failedRuntimeArtifactIds.Count -gt 0) { $promotionBlockers += @($failedRuntimeArtifactIds | ForEach-Object { "runtime-artifact-failed:$_" }) }
if (-not $serviceRecoveryResult -or $serviceRecoveryResult.result -ne "passed") { $promotionBlockers += "alpha-service-recovery-smoke-missing-or-failed" }
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
    schema = "agentos.distribution-alpha.provenance.v1"
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
    gates = @($script:gateResults)
    required_gate_commands = @(
        "cargo test -p agentd",
        "cargo test -p agentd safety::",
        "cargo test -p agentd agent_core::",
        "cargo test -p agentd agent_core::adversarial",
        "cargo build -p agentd --release",
        "pwsh -NoProfile -ExecutionPolicy Bypass -File image/build-initramfs.ps1",
        "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/alpha-service-recovery-smoke.ps1 -SkipCargoTests",
        "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/boot-smoke-test.ps1 -QemuPath <qemu> -TimeoutSeconds <seconds>"
    )
    artifacts = [ordered]@{
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
        dependency_inventory = [ordered]@{
            path = Get-RelativeOrNull $inventoryPath
            sha256 = Get-OptionalFileHash $inventoryPath
        }
    }
    image_inputs = [ordered]@{
        initramfs_manifest = $initramfsManifest
        alpha_rootfs_manifest = $alphaRootfsManifest
        rootfs_runtime_manifest_schema = if ($rootfsRuntimeManifest) { $rootfsRuntimeManifest.schema } else { $null }
        qemu_runtime_smoke = $bootSmokeResult
        service_recovery_smoke = $serviceRecoveryResult
    }
    alpha_runtime = [ordered]@{
        runtime_artifact_ids = @($runtimeArtifactIds)
        missing_runtime_artifact_ids = @($missingRuntimeArtifactIds)
        failed_runtime_artifact_ids = @($failedRuntimeArtifactIds)
        runtime_marker = if ($initramfsManifest) { $initramfsManifest.runtime_marker } else { $null }
        runtime_manifest_marker = if ($initramfsManifest) { $initramfsManifest.runtime_manifest_marker } else { $null }
        rootfs_runtime_manifest_sha256 = if ($initramfsManifest) { $initramfsManifest.alpha_rootfs.rootfs_runtime_manifest_sha256 } else { $null }
        qemu_path = $QemuPath
        qemu_timeout_seconds = $QemuTimeoutSeconds
        external_llm_required = $false
    }
    policy = [ordered]@{
        safety_gate = "cargo test -p agentd safety::; cargo test -p agentd agent_core::; cargo test -p agentd agent_core::adversarial"
        service_recovery_gate = "scripts/alpha-service-recovery-smoke.ps1"
        boot_gate = "scripts/boot-smoke-test.ps1 requires handoff plus runtime markers"
        secret_policy = "handle-only; release metadata stores hashes and paths, not secret values"
        promotion = "Promote Distribution Alpha only after tests, safety gates, AgentCore gates, service recovery smoke, dependency inventory, provenance, image manifest, and full QEMU runtime smoke pass."
    }
    promotion = [ordered]@{
        status = if ($promotionBlockers.Count -eq 0) { "promotable" } else { "blocked" }
        blockers = @($promotionBlockers)
    }
}

$provenancePath = Join-Path $artifactRoot "provenance.json"
Write-Json -Value $provenance -Path $provenancePath

if (-not (Test-SecretFreeContent $inventoryPath)) {
    throw "Dependency inventory contains secret-like content: $inventoryPath"
}
if (-not (Test-SecretFreeContent $provenancePath)) {
    throw "Provenance contains secret-like content: $provenancePath"
}

if ($promotionBlockers.Count -gt 0 -and -not ($SkipTests -or $SkipBootSmoke)) {
    throw "Distribution Alpha promotion gate blocked: $($promotionBlockers -join ', ')"
}

Write-Host "Release artifacts written:"
Write-Host "  $inventoryPath"
Write-Host "  $provenancePath"
