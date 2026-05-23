param(
    [string]$ArtifactDir = ".workflow/artifacts/candidate-security-adapter-regression"
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

function ConvertTo-SafeFileName {
    param([Parameter(Mandatory = $true)][string]$Value)
    return ($Value -replace "[^A-Za-z0-9._-]", "-").Trim("-")
}

function Invoke-MatrixCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Surface,
        [Parameter(Mandatory = $true)][string[]]$Command,
        [string[]]$Assertions = @()
    )

    $safe = ConvertTo-SafeFileName $Id
    $stdoutPath = Join-Path $ArtifactDir "$safe.stdout.txt"
    $stderrPath = Join-Path $ArtifactDir "$safe.stderr.txt"
    New-Item -ItemType Directory -Force -Path $ArtifactDir | Out-Null

    $exe = $Command[0]
    $args = if ($Command.Count -gt 1) { $Command[1..($Command.Count - 1)] } else { @() }
    & $exe @args 1> $stdoutPath 2> $stderrPath
    $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { $LASTEXITCODE }

    $case = [ordered]@{
        id = $Id
        surface = $Surface
        required = $true
        optional_dependency = $false
        status = if ($exitCode -eq 0) { "passed" } else { "failed" }
        command = ($Command -join " ")
        exit_code = $exitCode
        stdout = $stdoutPath
        stderr = $stderrPath
        assertions = @($Assertions)
    }
    $script:cases += $case
    if ($exitCode -ne 0) {
        $script:requiredFailures += $case
    }
}

function Add-OptionalFirecrackerHostProbe {
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

    $reason = if ($missing.Count -gt 0) {
        "optional host-feature dependency absent; local-only Firecracker policy regression remains required"
    } else {
        "optional host-feature execution smoke is separated into TASK-PCAND-032 QEMU/distro matrix"
    }
    $script:cases += [ordered]@{
        id = "optional-firecracker-host-feature-probe"
        surface = "firecracker-host-feature"
        required = $false
        optional_dependency = $true
        status = "skipped"
        command = $null
        exit_code = $null
        stdout = $null
        stderr = $null
        assertions = @(
            "optional dependencies do not gate local-only candidate baseline",
            "missing host features must be explicit rather than hidden"
        )
        policy_reason = $reason
        missing_dependencies = @($missing)
    }
}

New-Item -ItemType Directory -Force -Path $ArtifactDir | Out-Null
$resultPath = Join-Path $ArtifactDir "result.json"
$script:cases = @()
$script:requiredFailures = @()

Invoke-MatrixCommand `
    -Id "package-manager-adapter" `
    -Surface "package-manager" `
    -Command @("cargo", "test", "-p", "agent_core", "package_install") `
    -Assertions @(
        "semantic package tool chain only",
        "raw apt/dpkg/shell bypass denied",
        "host promotion requires isolation evidence, exact approval, and rollback"
    )

Invoke-MatrixCommand `
    -Id "untrusted-content-adapter" `
    -Surface "untrusted-content" `
    -Command @("cargo", "test", "-p", "agent_core", "untrusted_content") `
    -Assertions @(
        "external content remains untrusted",
        "sanitize output is replanning-only",
        "direct high-risk sink attempts are denied"
    )

Invoke-MatrixCommand `
    -Id "firecracker-profile-local-policy" `
    -Surface "firecracker" `
    -Command @("cargo", "test", "-p", "security_execution", "firecracker") `
    -Assertions @(
        "Firecracker profile requires policy approval",
        "missing dependencies fail before EffectPrepared",
        "planner hints cannot broaden profile authority"
    )

Invoke-MatrixCommand `
    -Id "host-promotion-rollback" `
    -Surface "host-promotion" `
    -Command @("cargo", "test", "-p", "agent_core", "host_promotion") `
    -Assertions @(
        "host promotion requires exact approval",
        "rollback handle and host checkpoint are mandatory",
        "failed verification enters rollback-pending"
    )

Invoke-MatrixCommand `
    -Id "sandbox-regression" `
    -Surface "sandbox" `
    -Command @("cargo", "test", "-p", "security_execution", "sandbox") `
    -Assertions @(
        "lease-derived sandbox profile",
        "persistent host writes denied for read-only",
        "resource abuse hits configured limits"
    )

Invoke-MatrixCommand `
    -Id "rollback-regression" `
    -Surface "rollback" `
    -Command @("cargo", "test", "-p", "security_execution", "rollback") `
    -Assertions @(
        "write-with-diff requires rollback handle",
        "stale base hash blocks prepare/commit",
        "failed verification rolls back"
    )

Invoke-MatrixCommand `
    -Id "agentd-safety-bypass-mutation" `
    -Surface "safety" `
    -Command @("cargo", "test", "-p", "agentd", "safety::") `
    -Assertions @(
        "package host-promotion bypass denied",
        "untrusted content direct sink bypass denied",
        "broad approval and parameter mutation remain paused/denied",
        "rollback half-committed recovery remains human-confirmed"
    )

Invoke-MatrixCommand `
    -Id "agent-core-adversarial-runtime" `
    -Surface "adversarial-runtime" `
    -Command @("cargo", "test", "-p", "agentd", "agent_core::adversarial") `
    -Assertions @(
        "model output cannot prepare shell or secret side effects",
        "observation injection cannot execute commands",
        "memory poisoning cannot grant capabilities"
    )

Add-OptionalFirecrackerHostProbe

$required = @($script:cases | Where-Object { $_.required -eq $true })
$optional = @($script:cases | Where-Object { $_.required -eq $false })
$status = if ($script:requiredFailures.Count -eq 0) { "passed" } else { "failed" }

$result = [ordered]@{
    schema = "agentos.candidate-security-adapter-regression.v1"
    checked_at = (Get-Date).ToString("o")
    status = $status
    execution_mode = "local-only"
    external_llm_required = $false
    production_ready_claim = $false
    result = $resultPath
    coverage = [ordered]@{
        required_surfaces = @(
            "package-manager",
            "untrusted-content",
            "firecracker",
            "host-promotion",
            "sandbox",
            "rollback",
            "safety",
            "adversarial-runtime"
        )
        optional_surfaces = @("firecracker-host-feature")
        bypass_and_mutation_covered = $true
    }
    summary = [ordered]@{
        total = $script:cases.Count
        required = $required.Count
        optional = $optional.Count
        passed = @($script:cases | Where-Object { $_.status -eq "passed" }).Count
        failed = @($script:cases | Where-Object { $_.status -eq "failed" }).Count
        skipped = @($script:cases | Where-Object { $_.status -eq "skipped" }).Count
        required_failures = $script:requiredFailures.Count
    }
    cases = @($script:cases)
}

Write-Json -Value $result -Path $resultPath
Write-Host "Candidate security adapter regression $status`: $resultPath"

if ($script:requiredFailures.Count -gt 0) {
    exit 1
}
