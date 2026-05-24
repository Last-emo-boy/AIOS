param(
    [string]$OutputPath = ".workflow/artifacts/functional-replay/result.json",
    [string]$CapabilityMatrixPath = ".workflow/active/WFS-20260524-agentos-functional-iteration/docs/functional-capability-matrix.md",
    [switch]$SkipCargoTests
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

function Add-Result {
    param(
        [System.Collections.ArrayList]$Results,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][scriptblock]$Script
    )
    $started = (Get-Date).ToString("o")
    $status = "passed"
    $errorMessage = ""
    try {
        & $Script
        if ($LASTEXITCODE -ne 0) {
            $status = "failed"
            $errorMessage = "exit code $LASTEXITCODE"
        }
    } catch {
        $status = "failed"
        $errorMessage = $_.Exception.Message
    }
    [void]$Results.Add([ordered]@{
        name = $Name
        command = $Command
        status = $status
        error = $errorMessage
        started_at = $started
        completed_at = (Get-Date).ToString("o")
    })
}

$results = [System.Collections.ArrayList]::new()

if (-not $SkipCargoTests) {
    Add-Result $results "runtime_contracts capability contracts" "cargo test -p runtime_contracts capability" {
        cargo test -p runtime_contracts capability
    }
}

Add-Result $results "service recovery approved/denied" "cargo test -p agentd service_recovery::" {
    cargo test -p agentd service_recovery::
}

Add-Result $results "package manager fixtures" "cargo test -p agent_core package_install" {
    cargo test -p agent_core package_install
}

Add-Result $results "untrusted content fixtures" "cargo test -p agent_core untrusted_content" {
    cargo test -p agent_core untrusted_content
}

Add-Result $results "firecracker fail-closed fixtures" "cargo test -p security_execution firecracker" {
    cargo test -p security_execution firecracker
}

Add-Result $results "operator support bundle manifest" "cargo test -p agentd support_bundle" {
    cargo test -p agentd support_bundle
}

Add-Result $results "operator projection" "cargo test -p agentd operator_projection" {
    cargo test -p agentd operator_projection
}

Add-Result $results "safety regression fixtures" "cargo test -p agentd safety::" {
    cargo test -p agentd safety::
}

$failed = @($results | Where-Object { $_.status -ne "passed" })
$matrixHash = Get-OptionalSha256 $CapabilityMatrixPath

$result = [ordered]@{
    schema = "agentos.functional-capability-replay.v1"
    generated_at = (Get-Date).ToString("o")
    local_only = $true
    external_dependencies_required = [ordered]@{
        network = $false
        external_llm = $false
        firecracker = $false
        host_package_manager = $false
    }
    capability_matrix = [ordered]@{
        path = $CapabilityMatrixPath
        sha256 = $matrixHash
    }
    capabilities = @($results)
    summary = [ordered]@{
        total = $results.Count
        passed = $results.Count - $failed.Count
        failed = $failed.Count
        failed_names = @($failed | ForEach-Object { $_.name })
    }
    status = if ($failed.Count -eq 0) { "passed" } else { "failed" }
}

Write-Json -Value $result -Path $OutputPath

if ($failed.Count -gt 0) {
    Write-Error "Functional capability replay failed: $($result.summary.failed_names -join ', ')"
    exit 1
}

Write-Host "Functional capability replay passed: $OutputPath"
