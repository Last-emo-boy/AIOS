param(
    [string]$QemuPath = "E:\qemu\qemu-system-x86_64.exe",
    [string]$KernelPath = "",
    [string]$InitramfsPath = "image/out/agentos-initramfs.cpio.gz",
    [string]$InitramfsManifestPath = "image/out/agentos-initramfs.manifest.json",
    [string]$KernelUrl = "https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/x86_64/netboot/vmlinuz-virt",
    [string]$KernelCachePath = "image/cache/vmlinuz-virt",
    [string]$ArtifactDir = ".workflow/artifacts/boot",
    [string[]]$MachineCandidates = @("microvm", "pc"),
    [int]$TimeoutSeconds = 20,
    [switch]$DependencyCheckOnly,
    [switch]$SkipKernelDownload,
    [switch]$AllowHandoffOnly
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

function Invoke-InitramfsBuild {
    & pwsh -NoProfile -ExecutionPolicy Bypass -File "image/build-initramfs.ps1" -Clean
    if ($LASTEXITCODE -ne 0) {
        throw "image/build-initramfs.ps1 failed with exit code $LASTEXITCODE"
    }
}

function Read-InitramfsManifest {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Add-BootLine {
    param(
        [Parameter(Mandatory = $true)]$OutputBuilder,
        [Parameter(Mandatory = $true)][string]$Line,
        [Parameter(Mandatory = $true)]$ObservedMarkers
    )
    $null = $OutputBuilder.AppendLine($Line)
    foreach ($marker in @($ObservedMarkers.Keys)) {
        if ($Line -match [regex]::Escape($marker)) {
            $ObservedMarkers[$marker] = $true
        }
    }
}

function Test-AllMarkersObserved {
    param([Parameter(Mandatory = $true)]$ObservedMarkers)
    foreach ($value in $ObservedMarkers.Values) {
        if (-not $value) {
            return $false
        }
    }
    return $true
}

function Read-SharedText {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return ""
    }
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
        $reader = [IO.StreamReader]::new($stream)
        try {
            return $reader.ReadToEnd()
        } finally {
            $reader.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

function Update-ObservedMarkers {
    param(
        [Parameter(Mandatory = $true)][string]$Content,
        [Parameter(Mandatory = $true)]$ObservedMarkers
    )
    foreach ($marker in @($ObservedMarkers.Keys)) {
        if ($Content -match [regex]::Escape($marker)) {
            $ObservedMarkers[$marker] = $true
        }
    }
}

function Format-ProcessArgument {
    param([Parameter(Mandatory = $true)][string]$Value)
    if ($Value -notmatch '[\s"]') {
        return $Value
    }
    return '"' + ($Value -replace '"', '\"') + '"'
}

$repoRoot = (Resolve-Path -LiteralPath ".").Path
$artifactRoot = Join-Path $repoRoot $ArtifactDir
New-Item -ItemType Directory -Force -Path $artifactRoot | Out-Null
$checkedAt = Get-ReproducibleTimestamp

$needsBuild = (-not (Test-Path -LiteralPath $InitramfsPath -PathType Leaf)) -or
    (-not (Test-Path -LiteralPath $InitramfsManifestPath -PathType Leaf))
if ($needsBuild) {
    Invoke-InitramfsBuild
}

$initramfsManifest = Read-InitramfsManifest -Path $InitramfsManifestPath
if (-not $initramfsManifest) {
    throw "Initramfs manifest missing after build: $InitramfsManifestPath"
}

if (-not $AllowHandoffOnly -and [string]::IsNullOrWhiteSpace($initramfsManifest.runtime_marker)) {
    Invoke-InitramfsBuild
    $initramfsManifest = Read-InitramfsManifest -Path $InitramfsManifestPath
}

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
$runtimeArtifacts = @($initramfsManifest.alpha_rootfs.artifacts)
$runtimeArtifactIds = @($runtimeArtifacts | ForEach-Object { $_.id })
$missingRuntimeArtifactIds = @($requiredRuntimeArtifactIds | Where-Object { $runtimeArtifactIds -notcontains $_ })
$failedRuntimeArtifactIds = @($runtimeArtifacts | Where-Object { $_.status -ne "passed" } | ForEach-Object { $_.id })
$handoffMarker = if ([string]::IsNullOrWhiteSpace($initramfsManifest.handoff_marker)) {
    "AGENTD_HANDOFF_OK"
} else {
    $initramfsManifest.handoff_marker
}
$runtimeMarker = $initramfsManifest.runtime_marker
$tuiMarker = $initramfsManifest.tui_marker
$runtimeManifestMarker = $initramfsManifest.runtime_manifest_marker
$requiredMarkers = @($handoffMarker)
if (-not $AllowHandoffOnly) {
    if (-not [string]::IsNullOrWhiteSpace($runtimeMarker)) {
        $requiredMarkers += $runtimeMarker
    }
    if (-not [string]::IsNullOrWhiteSpace($tuiMarker)) {
        $requiredMarkers += $tuiMarker
    }
    if (-not [string]::IsNullOrWhiteSpace($runtimeManifestMarker)) {
        $requiredMarkers += $runtimeManifestMarker
    }
}

$resolvedQemu = Resolve-OptionalPath $QemuPath
$resolvedInitramfs = Resolve-OptionalPath $InitramfsPath
$resolvedInitramfsManifest = Resolve-OptionalPath $InitramfsManifestPath
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
    initramfs_manifest_path = $resolvedInitramfsManifest
    handoff_marker = $handoffMarker
    runtime_marker = $runtimeMarker
    tui_marker = $tuiMarker
    runtime_manifest_marker = $runtimeManifestMarker
    required_markers = @($requiredMarkers)
    runtime_artifact_ids = @($runtimeArtifactIds)
    missing_runtime_artifact_ids = @($missingRuntimeArtifactIds)
    failed_runtime_artifact_ids = @($failedRuntimeArtifactIds)
    allow_handoff_only = [bool]$AllowHandoffOnly
    dependency_check_only = [bool]$DependencyCheckOnly
    skip_kernel_download = [bool]$SkipKernelDownload
    checked_at = $checkedAt
    missing = @()
}

if (-not $resolvedQemu) { $dependency.missing += "qemu-system-x86_64" }
if (-not $resolvedKernel) { $dependency.missing += "linux-kernel" }
if (-not $resolvedInitramfs) { $dependency.missing += "agentos-initramfs.cpio.gz" }
if (-not $resolvedInitramfsManifest) { $dependency.missing += "agentos-initramfs.manifest.json" }
if (-not $AllowHandoffOnly) {
    if ([string]::IsNullOrWhiteSpace($runtimeMarker)) { $dependency.missing += "runtime-marker" }
    if ([string]::IsNullOrWhiteSpace($tuiMarker)) { $dependency.missing += "tui-marker" }
    if ([string]::IsNullOrWhiteSpace($runtimeManifestMarker)) { $dependency.missing += "runtime-manifest-marker" }
    foreach ($id in $missingRuntimeArtifactIds) { $dependency.missing += "runtime-artifact:$id" }
    foreach ($id in $failedRuntimeArtifactIds) { $dependency.missing += "runtime-artifact-failed:$id" }
}

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
$bootStdoutLog = Join-Path $artifactRoot "boot-smoke.stdout.log"
$bootStderrLog = Join-Path $artifactRoot "boot-smoke.stderr.log"
$resultPath = Join-Path $artifactRoot "boot-smoke-result.json"
Remove-Item -LiteralPath $bootLog, $bootStdoutLog, $bootStderrLog -ErrorAction SilentlyContinue
$bootArgs = "console=ttyS0 rdinit=/sbin/agentd panic=-1"

$normalizedMachineCandidates = @(
    $MachineCandidates |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { $_.Trim() } |
        Select-Object -Unique
)
if ($normalizedMachineCandidates.Count -eq 0) {
    throw "At least one QEMU machine candidate is required"
}

$attempts = @()
$selectedAttempt = $null

foreach ($machine in $normalizedMachineCandidates) {
    $machineLogName = $machine -replace '[^A-Za-z0-9_.-]', '_'
    $attemptStdoutLog = Join-Path $artifactRoot "boot-smoke.$machineLogName.stdout.log"
    $attemptStderrLog = Join-Path $artifactRoot "boot-smoke.$machineLogName.stderr.log"
    $attemptBootLog = Join-Path $artifactRoot "boot-smoke.$machineLogName.log"
    Remove-Item -LiteralPath $attemptStdoutLog, $attemptStderrLog, $attemptBootLog -ErrorAction SilentlyContinue

    $qemuArgs = @(
        "-M", $machine,
        "-nodefaults",
        "-no-reboot",
        "-display", "none",
        "-serial", "stdio",
        "-kernel", $resolvedKernel,
        "-initrd", $resolvedInitramfs,
        "-append", $bootArgs
    )

    $formattedQemuArgs = @($qemuArgs | ForEach-Object { Format-ProcessArgument $_ })
    $process = Start-Process `
        -FilePath $resolvedQemu `
        -ArgumentList $formattedQemuArgs `
        -RedirectStandardOutput $attemptStdoutLog `
        -RedirectStandardError $attemptStderrLog `
        -WindowStyle Hidden `
        -PassThru
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $observedMarkers = [ordered]@{}
    foreach ($marker in $requiredMarkers) {
        $observedMarkers[$marker] = $false
    }

    while (-not $process.HasExited -and [DateTime]::UtcNow -lt $deadline) {
        $currentOutput = (Read-SharedText $attemptStdoutLog) + "`n" + (Read-SharedText $attemptStderrLog)
        Update-ObservedMarkers -Content $currentOutput -ObservedMarkers $observedMarkers
        if (Test-AllMarkersObserved -ObservedMarkers $observedMarkers) { break }
        Start-Sleep -Milliseconds 100
    }

    if (-not $process.HasExited) {
        $process.Kill()
        $process.WaitForExit()
    } else {
        $process.WaitForExit()
    }
    $finalOutput = (Read-SharedText $attemptStdoutLog) + "`n" + (Read-SharedText $attemptStderrLog)
    Update-ObservedMarkers -Content $finalOutput -ObservedMarkers $observedMarkers
    $finalOutput | Set-Content -LiteralPath $attemptBootLog -Encoding UTF8

    $observed = Test-AllMarkersObserved -ObservedMarkers $observedMarkers
    $missingMarkers = @($observedMarkers.GetEnumerator() | Where-Object { -not $_.Value } | ForEach-Object { $_.Key })
    $attempt = [ordered]@{
        machine = $machine
        status = if ($observed) { "completed" } else { "failed" }
        observed_all_markers = $observed
        observed_markers = $observedMarkers
        missing_markers = @($missingMarkers)
        exit_code = $process.ExitCode
        stdout_log_path = $attemptStdoutLog
        stderr_log_path = $attemptStderrLog
        log_path = $attemptBootLog
    }
    $attempts += $attempt

    if ($observed) {
        $selectedAttempt = $attempt
        Copy-Item -LiteralPath $attemptStdoutLog -Destination $bootStdoutLog -Force
        Copy-Item -LiteralPath $attemptStderrLog -Destination $bootStderrLog -Force
        Copy-Item -LiteralPath $attemptBootLog -Destination $bootLog -Force
        break
    }
}

if (-not $selectedAttempt) {
    $combinedLog = [Text.StringBuilder]::new()
    foreach ($attempt in $attempts) {
        $null = $combinedLog.AppendLine("=== QEMU machine: $($attempt.machine) ===")
        $null = $combinedLog.AppendLine((Read-SharedText $attempt.log_path))
    }
    $combinedLog.ToString() | Set-Content -LiteralPath $bootLog -Encoding UTF8
    if ($attempts.Count -gt 0) {
        $lastAttempt = $attempts[$attempts.Count - 1]
        Copy-Item -LiteralPath $lastAttempt.stdout_log_path -Destination $bootStdoutLog -Force
        Copy-Item -LiteralPath $lastAttempt.stderr_log_path -Destination $bootStderrLog -Force
    }
}

$observed = [bool]$selectedAttempt
$observedMarkers = if ($selectedAttempt) { $selectedAttempt.observed_markers } else { $attempts[$attempts.Count - 1].observed_markers }
$result = [ordered]@{
    status = if ($observed) { "completed" } else { "failed" }
    observed_all_markers = $observed
    observed_markers = $observedMarkers
    required_markers = @($requiredMarkers)
    marker = $handoffMarker
    runtime_marker = $runtimeMarker
    tui_marker = $tuiMarker
    runtime_manifest_marker = $runtimeManifestMarker
    runtime_artifact_ids = @($runtimeArtifactIds)
    missing_runtime_artifact_ids = @($missingRuntimeArtifactIds)
    failed_runtime_artifact_ids = @($failedRuntimeArtifactIds)
    qemu_path = $resolvedQemu
    kernel_path = $resolvedKernel
    initramfs_path = $resolvedInitramfs
    initramfs_manifest_path = $resolvedInitramfsManifest
    initramfs_sha256 = $initramfsManifest.artifact_sha256
    rootfs_runtime_manifest_sha256 = $initramfsManifest.alpha_rootfs.rootfs_runtime_manifest_sha256
    boot_args = $bootArgs
    machine_candidates = @($normalizedMachineCandidates)
    attempted_machines = @($attempts | ForEach-Object { $_.machine })
    selected_machine = if ($selectedAttempt) { $selectedAttempt.machine } else { $null }
    attempts = @($attempts)
    timeout_seconds = $TimeoutSeconds
    log_path = $bootLog
    checked_at = $checkedAt
}
Write-Json -Value $result -Path $resultPath

if (-not $observed) {
    $missingMarkers = @($observedMarkers.GetEnumerator() | Where-Object { -not $_.Value } | ForEach-Object { $_.Key })
    Write-Error "Boot smoke test did not observe required markers: $($missingMarkers -join ', '). See $bootLog"
    exit 1
}

Write-Host "Boot smoke test observed required markers on QEMU machine '$($selectedAttempt.machine)': $($requiredMarkers -join ', ')"
