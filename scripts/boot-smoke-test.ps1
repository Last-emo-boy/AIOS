param(
    [string]$QemuPath = "E:\qemu\qemu-system-x86_64.exe",
    [string]$KernelPath = "",
    [string]$InitramfsPath = "image/out/agentos-initramfs.cpio.gz",
    [string]$KernelUrl = "https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/x86_64/netboot/vmlinuz-virt",
    [string]$KernelCachePath = "image/cache/vmlinuz-virt",
    [string]$ArtifactDir = ".workflow/artifacts/boot",
    [int]$TimeoutSeconds = 20,
    [switch]$DependencyCheckOnly,
    [switch]$SkipKernelDownload
)

$ErrorActionPreference = "Stop"

function Resolve-OptionalPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $null
    }
    if (Test-Path -LiteralPath $Path) {
        return (Resolve-Path -LiteralPath $Path).Path
    }
    return $null
}

function Write-Json {
    param([Parameter(Mandatory = $true)]$Value, [Parameter(Mandatory = $true)][string]$Path)
    $Value | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Path -Encoding UTF8
}

$repoRoot = (Resolve-Path -LiteralPath ".").Path
$artifactRoot = Join-Path $repoRoot $ArtifactDir
New-Item -ItemType Directory -Force -Path $artifactRoot | Out-Null

if (-not (Test-Path -LiteralPath $InitramfsPath)) {
    & pwsh -NoProfile -ExecutionPolicy Bypass -File "image/build-initramfs.ps1"
}

$resolvedQemu = Resolve-OptionalPath $QemuPath
$resolvedInitramfs = Resolve-OptionalPath $InitramfsPath
$resolvedKernel = Resolve-OptionalPath $KernelPath

if (-not $resolvedKernel -and -not $SkipKernelDownload) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $KernelCachePath) | Out-Null
    if (-not (Test-Path -LiteralPath $KernelCachePath)) {
        Invoke-WebRequest -Uri $KernelUrl -OutFile $KernelCachePath
    }
    $resolvedKernel = Resolve-OptionalPath $KernelCachePath
}

$dependency = [ordered]@{
    qemu_path = $resolvedQemu
    qemu_expected = $QemuPath
    kernel_path = $resolvedKernel
    kernel_url = $KernelUrl
    initramfs_path = $resolvedInitramfs
    dependency_check_only = [bool]$DependencyCheckOnly
    skip_kernel_download = [bool]$SkipKernelDownload
    checked_at = (Get-Date).ToString("o")
    missing = @()
}

if (-not $resolvedQemu) { $dependency.missing += "qemu-system-x86_64" }
if (-not $resolvedKernel) { $dependency.missing += "linux-kernel" }
if (-not $resolvedInitramfs) { $dependency.missing += "agentos-initramfs.cpio.gz" }

$dependencyPath = Join-Path $artifactRoot "dependency-check.json"
Write-Json -Value $dependency -Path $dependencyPath

if ($dependency.missing.Count -gt 0) {
    $dependency.missing -join ", " | Write-Error
    exit 2
}

if ($DependencyCheckOnly) {
    Write-Host "Dependency check passed"
    exit 0
}

$bootLog = Join-Path $artifactRoot "boot-smoke.log"
$resultPath = Join-Path $artifactRoot "boot-smoke-result.json"
$bootArgs = "console=ttyS0 rdinit=/sbin/agentd panic=-1"
$qemuArgs = @(
    "-M", "microvm",
    "-nodefaults",
    "-no-reboot",
    "-display", "none",
    "-serial", "stdio",
    "-kernel", $resolvedKernel,
    "-initrd", $resolvedInitramfs,
    "-append", $bootArgs
)

$outputBuilder = New-Object System.Text.StringBuilder
$process = New-Object System.Diagnostics.Process
$process.StartInfo.FileName = $resolvedQemu
foreach ($arg in $qemuArgs) {
    $process.StartInfo.ArgumentList.Add($arg)
}
$process.StartInfo.RedirectStandardOutput = $true
$process.StartInfo.RedirectStandardError = $true
$process.StartInfo.UseShellExecute = $false
$process.StartInfo.CreateNoWindow = $true

$null = $process.Start()
$deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
$marker = "AGENTD_HANDOFF_OK"
$observed = $false

while (-not $process.HasExited -and [DateTime]::UtcNow -lt $deadline) {
    while ($process.StandardOutput.Peek() -ge 0) {
        $line = $process.StandardOutput.ReadLine()
        $null = $outputBuilder.AppendLine($line)
        if ($line -match [regex]::Escape($marker)) {
            $observed = $true
            break
        }
    }
    while ($process.StandardError.Peek() -ge 0) {
        $line = $process.StandardError.ReadLine()
        $null = $outputBuilder.AppendLine($line)
        if ($line -match [regex]::Escape($marker)) {
            $observed = $true
            break
        }
    }
    if ($observed) { break }
    Start-Sleep -Milliseconds 100
}

if (-not $process.HasExited) {
    $process.Kill()
    $process.WaitForExit()
}

$outputBuilder.ToString() | Set-Content -LiteralPath $bootLog -Encoding UTF8
$result = [ordered]@{
    status = if ($observed) { "completed" } else { "failed" }
    observed_marker = $observed
    marker = $marker
    qemu_path = $resolvedQemu
    kernel_path = $resolvedKernel
    initramfs_path = $resolvedInitramfs
    boot_args = $bootArgs
    timeout_seconds = $TimeoutSeconds
    log_path = $bootLog
    checked_at = (Get-Date).ToString("o")
}
Write-Json -Value $result -Path $resultPath

if (-not $observed) {
    Write-Error "Boot smoke test did not observe $marker. See $bootLog"
    exit 1
}

Write-Host "Boot smoke test observed $marker"
