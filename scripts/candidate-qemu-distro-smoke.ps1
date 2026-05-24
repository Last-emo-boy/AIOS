param(
    [string]$QemuPath = "E:\qemu\qemu-system-x86_64.exe",
    [string]$ArtifactDir = ".workflow/artifacts/candidate-qemu-distro-smoke",
    [int]$TimeoutSeconds = 45,
    [switch]$SkipRequiredQemu
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

function Get-OptionalSha256 {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Read-JsonFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Invoke-LoggedCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string[]]$Command,
        [Parameter(Mandatory = $true)][string]$StdoutPath,
        [Parameter(Mandatory = $true)][string]$StderrPath
    )
    $parent = Split-Path -Parent $StdoutPath
    if ($parent) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    $exe = $Command[0]
    $args = if ($Command.Count -gt 1) { $Command[1..($Command.Count - 1)] } else { @() }
    & $exe @args 1> $StdoutPath 2> $StderrPath
    $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { $LASTEXITCODE }
    return [ordered]@{
        name = $Name
        command = ($Command -join " ")
        exit_code = $exitCode
        stdout = $StdoutPath
        stderr = $StderrPath
        status = if ($exitCode -eq 0) { "passed" } else { "failed" }
    }
}

function Add-OptionalFirecrackerHostFeatureCase {
    $missing = @()
    if (-not (Test-Path -LiteralPath "/dev/kvm")) {
        $missing += "kvm-device"
    }
    if (-not (Get-Command "firecracker" -ErrorAction SilentlyContinue)) {
        $missing += "firecracker-binary"
    }
    if (-not (Get-Command "jailer" -ErrorAction SilentlyContinue)) {
        $missing += "jailer-binary"
    }
    if (-not $env:AGENTOS_FIRECRACKER_KERNEL -or -not (Test-Path -LiteralPath $env:AGENTOS_FIRECRACKER_KERNEL -PathType Leaf)) {
        $missing += "kernel-image-env:AGENTOS_FIRECRACKER_KERNEL"
    }
    if (-not $env:AGENTOS_FIRECRACKER_ROOTFS -or -not (Test-Path -LiteralPath $env:AGENTOS_FIRECRACKER_ROOTFS -PathType Leaf)) {
        $missing += "rootfs-image-env:AGENTOS_FIRECRACKER_ROOTFS"
    }

    return [ordered]@{
        id = "optional-firecracker-kvm-host-feature"
        required = $false
        status = if ($missing.Count -eq 0) { "available" } else { "skipped" }
        policy_reason = if ($missing.Count -eq 0) {
            "Host feature dependencies appear available; runtime execution remains governed by Firecracker SEF policy tests."
        } else {
            "Optional host-feature dependencies are absent and do not count as required QEMU baseline failure."
        }
        missing_dependencies = @($missing)
    }
}

New-Item -ItemType Directory -Force -Path $ArtifactDir | Out-Null
$resultPath = Join-Path $ArtifactDir "result.json"
$cases = @()
$commands = @()
$requiredFailures = @()

if ($SkipRequiredQemu) {
    $case = [ordered]@{
        id = "required-qemu-local-only-boot-runtime"
        required = $true
        status = "failed"
        policy_reason = "Required QEMU baseline was explicitly skipped."
    }
    $cases += $case
    $requiredFailures += $case
} else {
    $bootDir = Join-Path $ArtifactDir "required-qemu-baseline"
    Remove-Item -LiteralPath $bootDir -Recurse -Force -ErrorAction SilentlyContinue
    $stdoutPath = Join-Path $ArtifactDir "required-qemu-baseline.stdout.txt"
    $stderrPath = Join-Path $ArtifactDir "required-qemu-baseline.stderr.txt"
    $command = Invoke-LoggedCommand `
        -Name "required-qemu-local-only-boot-runtime" `
        -Command @(
            "pwsh",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            "scripts/boot-smoke-test.ps1",
            "-QemuPath",
            $QemuPath,
            "-TimeoutSeconds",
            [string]$TimeoutSeconds,
            "-ArtifactDir",
            $bootDir
        ) `
        -StdoutPath $stdoutPath `
        -StderrPath $stderrPath
    $commands += $command

    $bootResultPath = Join-Path $bootDir "boot-smoke-result.json"
    $dependencyPath = Join-Path $bootDir "dependency-check.json"
    $bootResult = if (Test-Path -LiteralPath $bootResultPath -PathType Leaf) { Read-JsonFile $bootResultPath } else { $null }
    $dependency = if (Test-Path -LiteralPath $dependencyPath -PathType Leaf) { Read-JsonFile $dependencyPath } else { $null }
    $passed = $command.exit_code -eq 0 -and $bootResult -and $bootResult.observed_all_markers -eq $true
    $case = [ordered]@{
        id = "required-qemu-local-only-boot-runtime"
        required = $true
        status = if ($passed) { "passed" } else { "failed" }
        command = $command.command
        exit_code = $command.exit_code
        qemu_path = $QemuPath
        timeout_seconds = $TimeoutSeconds
        required_markers = if ($bootResult) { @($bootResult.required_markers) } else { @() }
        observed_markers = if ($bootResult) { $bootResult.observed_markers } else { $null }
        observed_all_markers = if ($bootResult) { $bootResult.observed_all_markers } else { $false }
        initramfs_path = if ($bootResult) { $bootResult.initramfs_path } else { $null }
        initramfs_sha256 = if ($bootResult) { $bootResult.initramfs_sha256 } else { $null }
        initramfs_manifest_path = if ($bootResult) { $bootResult.initramfs_manifest_path } else { $null }
        initramfs_manifest_sha256 = if ($bootResult) { Get-OptionalSha256 $bootResult.initramfs_manifest_path } else { $null }
        rootfs_runtime_manifest_sha256 = if ($bootResult) { $bootResult.rootfs_runtime_manifest_sha256 } else { $null }
        boot_log = if ($bootResult) { $bootResult.log_path } else { $null }
        boot_log_sha256 = if ($bootResult) { Get-OptionalSha256 $bootResult.log_path } else { $null }
        result_artifact = $bootResultPath
        dependency_artifact = $dependencyPath
        dependency_missing = if ($dependency) { @($dependency.missing) } else { @("dependency-artifact-missing") }
    }
    $cases += $case
    if (-not $passed) {
        $requiredFailures += $case
    }
}

$cases += Add-OptionalFirecrackerHostFeatureCase

$status = if ($requiredFailures.Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.candidate-qemu-distro-smoke-matrix.v1"
    checked_at = (Get-Date).ToString("o")
    status = $status
    execution_mode = "local-only"
    production_ready_claim = $false
    qemu_path = $QemuPath
    timeout_seconds = $TimeoutSeconds
    summary = [ordered]@{
        total = $cases.Count
        required = @($cases | Where-Object { $_.required -eq $true }).Count
        optional = @($cases | Where-Object { $_.required -eq $false }).Count
        passed = @($cases | Where-Object { $_.status -eq "passed" }).Count
        failed = @($cases | Where-Object { $_.status -eq "failed" }).Count
        skipped = @($cases | Where-Object { $_.status -eq "skipped" }).Count
        available = @($cases | Where-Object { $_.status -eq "available" }).Count
        required_failures = $requiredFailures.Count
    }
    cases = @($cases)
    commands = @($commands)
    artifacts = [ordered]@{
        result = $resultPath
        artifact_dir = $ArtifactDir
    }
}

Write-Json -Value $result -Path $resultPath
Write-Host "Candidate QEMU/distro smoke matrix $status`: $resultPath"

if ($requiredFailures.Count -gt 0) {
    exit 1
}
