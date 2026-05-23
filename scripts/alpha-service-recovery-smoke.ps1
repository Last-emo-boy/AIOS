param(
    [string]$ArtifactDir = ".workflow/artifacts/alpha-service-recovery",
    [string]$RootfsManifestPath = "image/out/agentos-alpha-rootfs.manifest.json",
    [switch]$SkipRootfsAssembly,
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
    $Value | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $Path -Encoding UTF8
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
    $result = [ordered]@{
        name = $Name
        command = ($Command -join " ")
        exit_code = $exitCode
        stdout = $StdoutPath
        stderr = $StderrPath
        status = if ($exitCode -eq 0) { "passed" } else { "failed" }
    }
    if ($exitCode -ne 0) {
        throw "Command failed ($Name) with exit code $exitCode. See $StdoutPath and $StderrPath"
    }
    return $result
}

function Read-JsonFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Assert-ChildPath {
    param(
        [Parameter(Mandatory = $true)][string]$Parent,
        [Parameter(Mandatory = $true)][string]$Child
    )
    $parentFull = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $Parent).Path)
    $childFull = [IO.Path]::GetFullPath($Child)
    if (-not $childFull.StartsWith($parentFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove path outside $parentFull`: $childFull"
    }
}

function Clear-GeneratedPath {
    param(
        [Parameter(Mandatory = $true)][string]$BaseDir,
        [Parameter(Mandatory = $true)][string]$Path
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    Assert-ChildPath -Parent $BaseDir -Child $Path
    Remove-Item -LiteralPath $Path -Recurse -Force
}

function Read-JsonLines {
    param([Parameter(Mandatory = $true)][string]$Path)
    return @(Get-Content -LiteralPath $Path | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_ | ConvertFrom-Json })
}

function Assert-True {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw $Message
    }
}

function Get-Step {
    param(
        [Parameter(Mandatory = $true)]$Projection,
        [Parameter(Mandatory = $true)][string]$StepId
    )
    $matches = @($Projection.steps | Where-Object { $_.step_id -eq $StepId })
    if ($matches.Count -ne 1) {
        throw "Expected exactly one projection step '$StepId', found $($matches.Count)"
    }
    return $matches[0]
}

function Test-SecretFreeFiles {
    param([Parameter(Mandatory = $true)][string[]]$Paths)
    $patterns = @(
        "password\s*=",
        "passwd\s*=",
        "api[_-]?key\s*=",
        "access_token\s*=",
        "refresh_token\s*=",
        "BEGIN RSA PRIVATE KEY",
        "BEGIN OPENSSH PRIVATE KEY"
    )
    foreach ($path in $Paths) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            continue
        }
        $content = Get-Content -LiteralPath $path -Raw
        foreach ($pattern in $patterns) {
            if ($content -match $pattern) {
                throw "Secret-like content matched '$pattern' in $path"
            }
        }
    }
    return $true
}

function Test-ModelBrokerLocalOnly {
    param([Parameter(Mandatory = $true)][string]$StagedRootfs)
    $configPath = Join-Path $StagedRootfs "etc/agentos/model-broker.toml"
    Assert-True (Test-Path -LiteralPath $configPath -PathType Leaf) "ModelBroker config missing from staged rootfs: $configPath"
    $content = Get-Content -LiteralPath $configPath -Raw
    Assert-True ($content -match '(?m)^\s*mode\s*=\s*"stub"\s*$') "ModelBroker default mode must be stub"
    Assert-True ($content -match '(?m)^\s*network_required\s*=\s*false\s*$') "ModelBroker smoke must not require network"
    Assert-True ($content -match '(?m)^\s*requires_credentials\s*=\s*false\s*$') "ModelBroker stub provider must not require credentials"
    return [ordered]@{
        config = $configPath
        mode = "stub"
        network_required = $false
        credentials_required = $false
    }
}

$repoRoot = (Resolve-Path -LiteralPath ".").Path
New-Item -ItemType Directory -Force -Path $ArtifactDir | Out-Null
$checkedAt = Get-ReproducibleTimestamp

$approvedJournal = Join-Path $ArtifactDir "approved.jsonl"
$deniedJournal = Join-Path $ArtifactDir "denied.jsonl"
$approvedReportPath = Join-Path $ArtifactDir "approved-report.json"
$deniedReportPath = Join-Path $ArtifactDir "denied-report.json"
$approvedProjectionPath = Join-Path $ArtifactDir "approved-projection.json"
$deniedProjectionPath = Join-Path $ArtifactDir "denied-projection.json"
$resultPath = Join-Path $ArtifactDir "result.json"

foreach ($path in @(
    $approvedJournal,
    $deniedJournal,
    $approvedReportPath,
    $deniedReportPath,
    $approvedProjectionPath,
    $deniedProjectionPath,
    $resultPath
)) {
    Clear-GeneratedPath -BaseDir $ArtifactDir -Path $path
}

foreach ($runStorePath in @(
    ([IO.Path]::ChangeExtension($approvedJournal, ".runs")),
    ([IO.Path]::ChangeExtension($deniedJournal, ".runs"))
)) {
    Clear-GeneratedPath -BaseDir $ArtifactDir -Path $runStorePath
}

$commands = @()

if (-not $SkipRootfsAssembly) {
    $commands += Invoke-LoggedCommand `
        -Name "alpha-rootfs-assembly" `
        -Command @("pwsh", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "image/build-alpha-rootfs.ps1", "-Clean") `
        -StdoutPath (Join-Path $ArtifactDir "alpha-rootfs-assembly.stdout.txt") `
        -StderrPath (Join-Path $ArtifactDir "alpha-rootfs-assembly.stderr.txt")
}

Assert-True (Test-Path -LiteralPath $RootfsManifestPath -PathType Leaf) "Alpha rootfs manifest missing: $RootfsManifestPath"
$rootfsManifest = Read-JsonFile $RootfsManifestPath
$stagedRootfs = Join-Path $repoRoot ($rootfsManifest.staged_rootfs -replace '/', [IO.Path]::DirectorySeparatorChar)
Assert-True (Test-Path -LiteralPath $stagedRootfs -PathType Container) "Staged rootfs missing: $stagedRootfs"
$modelBrokerLocalOnly = Test-ModelBrokerLocalOnly -StagedRootfs $stagedRootfs

if (-not $SkipCargoTests) {
    $commands += Invoke-LoggedCommand `
        -Name "agent-core-service-recovery-tests" `
        -Command @("cargo", "test", "-p", "agentd", "agent_core::service_recovery") `
        -StdoutPath (Join-Path $ArtifactDir "cargo-test-agent-core-service-recovery.stdout.txt") `
        -StderrPath (Join-Path $ArtifactDir "cargo-test-agent-core-service-recovery.stderr.txt")
}

$commands += Invoke-LoggedCommand `
    -Name "approved-service-recovery-demo" `
    -Command @("cargo", "run", "-q", "-p", "agentd", "--", "--service-recovery-demo", "approved", $approvedJournal) `
    -StdoutPath $approvedReportPath `
    -StderrPath (Join-Path $ArtifactDir "approved-service-recovery.stderr.txt")

$commands += Invoke-LoggedCommand `
    -Name "denied-service-recovery-demo" `
    -Command @("cargo", "run", "-q", "-p", "agentd", "--", "--service-recovery-demo", "denied", $deniedJournal) `
    -StdoutPath $deniedReportPath `
    -StderrPath (Join-Path $ArtifactDir "denied-service-recovery.stderr.txt")

$commands += Invoke-LoggedCommand `
    -Name "approved-audit-projection" `
    -Command @("cargo", "run", "-q", "-p", "agentd", "--", "--audit-project", $approvedJournal, "latest") `
    -StdoutPath $approvedProjectionPath `
    -StderrPath (Join-Path $ArtifactDir "approved-audit-projection.stderr.txt")

$commands += Invoke-LoggedCommand `
    -Name "denied-audit-projection" `
    -Command @("cargo", "run", "-q", "-p", "agentd", "--", "--audit-project", $deniedJournal, "latest") `
    -StdoutPath $deniedProjectionPath `
    -StderrPath (Join-Path $ArtifactDir "denied-audit-projection.stderr.txt")

$approvedReport = Read-JsonFile $approvedReportPath
$deniedReport = Read-JsonFile $deniedReportPath
$approvedProjection = Read-JsonFile $approvedProjectionPath
$deniedProjection = Read-JsonFile $deniedProjectionPath
$approvedEvents = Read-JsonLines $approvedJournal
$deniedEvents = Read-JsonLines $deniedJournal
$approvedRestart = Get-Step -Projection $approvedProjection -StepId "restart-service"
$deniedRestart = Get-Step -Projection $deniedProjection -StepId "restart-service"
$approvedPlan = Get-Step -Projection $approvedProjection -StepId "plan"
$deniedPlan = Get-Step -Projection $deniedProjection -StepId "plan"

Assert-True ($approvedReport.restart_executed -eq $true) "Approved report must execute restart"
Assert-True ($approvedReport.final_health_ok -eq $true) "Approved report must finish healthy"
Assert-True ($approvedReport.restart_policy_decision -eq "allow") "Approved restart policy decision must be allow"
Assert-True ($approvedReport.summary -match "through AgentCore") "Approved report must identify AgentCore execution"
Assert-True ($approvedRestart.status -eq "sealed") "Approved restart projection must be sealed"
Assert-True ($approvedRestart.effect_prepared -eq $true) "Approved restart must prepare effect"
Assert-True ($approvedRestart.effect_observed -eq $true) "Approved restart must observe effect"
Assert-True ($approvedRestart.commit_sealed -eq $true) "Approved restart must reach CommitSealed"
Assert-True ($approvedRestart.policy_summary -match "decision=allow") "Approved projection must explain policy allow"
Assert-True ($approvedRestart.approval_summary -match "approval granted") "Approved projection must explain approval"
Assert-True ($approvedRestart.verification_summary -match "success") "Approved projection must explain verification"
Assert-True ($approvedPlan.final_summary -match "plan frozen") "Approved projection must explain plan freeze"

Assert-True ($deniedReport.restart_executed -eq $false) "Denied report must not execute restart"
Assert-True ($deniedReport.final_health_ok -eq $false) "Denied report must not claim final health"
Assert-True ($deniedReport.restart_policy_decision -eq "pause-for-approval") "Denied policy decision must pause for approval"
Assert-True ($deniedReport.summary -match "no restart effect was prepared") "Denied report must state no restart effect was prepared"
Assert-True ($deniedRestart.status -eq "denied") "Denied restart projection must be denied"
Assert-True ($deniedRestart.effect_prepared -eq $false) "Denied restart must not prepare effect"
Assert-True ($deniedRestart.effect_state -eq "none") "Denied restart effect state must be none"
Assert-True ($deniedRestart.commit_sealed -eq $false) "Denied restart must not be sealed"
Assert-True ($deniedRestart.policy_summary -match "pause-for-approval") "Denied projection must explain policy pause"
Assert-True ($deniedRestart.approval_summary -match "approval denied") "Denied projection must explain denial"
Assert-True ($deniedPlan.final_summary -match "plan frozen") "Denied projection must explain plan freeze"

$deniedRestartPolicyEvents = @($deniedEvents | Where-Object { $_.step_id -eq "restart-service" -and $_.event_type -eq "PolicyEvaluated" })
$deniedRestartPreparedEvents = @($deniedEvents | Where-Object { $_.step_id -eq "restart-service" -and $_.event_type -eq "EffectPrepared" })
$approvedRestartCommitEvents = @($approvedEvents | Where-Object { $_.step_id -eq "restart-service" -and $_.event_type -eq "CommitSealed" })
Assert-True ($deniedRestartPolicyEvents.Count -ge 1) "Denied restart must record PolicyEvaluated"
Assert-True ($deniedRestartPreparedEvents.Count -eq 0) "Denied restart must not record EffectPrepared"
Assert-True ($approvedRestartCommitEvents.Count -ge 1) "Approved restart must record CommitSealed"

Test-SecretFreeFiles -Paths @(
    $approvedJournal,
    $deniedJournal,
    $approvedReportPath,
    $deniedReportPath,
    $approvedProjectionPath,
    $deniedProjectionPath
) | Out-Null

$result = [ordered]@{
    schema = "agentos.alpha-service-recovery-smoke.v1"
    checked_at = $checkedAt
    result = "passed"
    execution_surface = "host cargo binary against staged Alpha rootfs runtime contracts"
    staged_rootfs = $stagedRootfs
    rootfs_manifest = $RootfsManifestPath
    model_broker = $modelBrokerLocalOnly
    commands = $commands
    artifacts = [ordered]@{
        approved_journal = $approvedJournal
        denied_journal = $deniedJournal
        approved_report = $approvedReportPath
        denied_report = $deniedReportPath
        approved_projection = $approvedProjectionPath
        denied_projection = $deniedProjectionPath
        result = $resultPath
    }
    assertions = [ordered]@{
        approved_restart_executed = $approvedReport.restart_executed
        approved_final_health_ok = $approvedReport.final_health_ok
        approved_restart_status = $approvedRestart.status
        approved_restart_effect_prepared = $approvedRestart.effect_prepared
        approved_restart_commit_sealed = $approvedRestart.commit_sealed
        denied_restart_executed = $deniedReport.restart_executed
        denied_restart_status = $deniedRestart.status
        denied_restart_policy_events = $deniedRestartPolicyEvents.Count
        denied_restart_effect_prepared_events = $deniedRestartPreparedEvents.Count
        denied_restart_effect_prepared = $deniedRestart.effect_prepared
        denied_restart_effect_state = $deniedRestart.effect_state
        projection_explains_plan_policy_approval_effect_verification_terminal_state = $true
        no_external_llm_required = $true
        no_raw_secrets_detected = $true
    }
}

Write-Json -Value $result -Path $resultPath
Write-Host "Alpha service recovery smoke passed: $resultPath"
