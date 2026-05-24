param(
    [string]$ArtifactDir = ".workflow/artifacts/production-runbook-smoke",
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

function Assert-True {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw $Message
    }
}

function New-Case {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Status,
        [Parameter(Mandatory = $true)][string]$Summary,
        [object[]]$Commands = @(),
        [hashtable]$Assertions = @{},
        [hashtable]$Artifacts = @{}
    )
    return [ordered]@{
        name = $Name
        status = $Status
        summary = $Summary
        commands = @($Commands)
        assertions = $Assertions
        artifacts = $Artifacts
    }
}

function ConvertTo-SafeFileName {
    param([Parameter(Mandatory = $true)][string]$Value)
    return ($Value -replace "[^A-Za-z0-9._-]", "-").Trim("-")
}

New-Item -ItemType Directory -Force -Path $ArtifactDir | Out-Null
$resultPath = Join-Path $ArtifactDir "result.json"
Remove-Item -LiteralPath $resultPath -ErrorAction SilentlyContinue

$cases = @()
$commands = @()

$approvedJournal = Join-Path $ArtifactDir "service-approved.jsonl"
$approvedReportPath = Join-Path $ArtifactDir "service-approved-report.json"
$operatorProjectionPath = Join-Path $ArtifactDir "operator-projection.json"
$operatorProjectionTuiPath = Join-Path $ArtifactDir "operator-projection.txt"
$approvedRunsDir = Join-Path $ArtifactDir "service-approved.runs"
Remove-Item -LiteralPath $approvedRunsDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $approvedJournal, $approvedReportPath, $operatorProjectionPath, $operatorProjectionTuiPath -Force -ErrorAction SilentlyContinue

$serviceCommand = Invoke-LoggedCommand `
    -Name "service-recovery-approved" `
    -Command @("cargo", "run", "-q", "-p", "agentd", "--", "--service-recovery-demo", "approved", $approvedJournal) `
    -StdoutPath $approvedReportPath `
    -StderrPath (Join-Path $ArtifactDir "service-approved.stderr.txt")
$commands += $serviceCommand

$projectionCommand = Invoke-LoggedCommand `
    -Name "operator-projection-json" `
    -Command @("cargo", "run", "-q", "-p", "agentd", "--", "--operator-project", $approvedJournal, "latest") `
    -StdoutPath $operatorProjectionPath `
    -StderrPath (Join-Path $ArtifactDir "operator-projection.stderr.txt")
$commands += $projectionCommand

$projectionTuiCommand = Invoke-LoggedCommand `
    -Name "operator-projection-tui" `
    -Command @("cargo", "run", "-q", "-p", "agentd", "--", "--operator-project-tui", $approvedJournal, "latest") `
    -StdoutPath $operatorProjectionTuiPath `
    -StderrPath (Join-Path $ArtifactDir "operator-projection-tui.stderr.txt")
$commands += $projectionTuiCommand

$serviceReport = Read-JsonFile $approvedReportPath
$projection = Read-JsonFile $operatorProjectionPath
$projectionText = Get-Content -LiteralPath $operatorProjectionTuiPath -Raw

Assert-True ($serviceReport.restart_executed -eq $true) "Approved runbook must execute restart."
Assert-True ($projection.read_only -eq $true) "Operator projection must be read-only."
Assert-True ($projection.runtime.state -eq "running") "Operator projection must include runtime state."
Assert-True ($projection.audit.audit_seal_status -eq "sealed") "Operator projection must assert sealed audit status."
Assert-True ($projection.audit.commit_sealed_count -gt 0) "Operator projection must count sealed commits."
Assert-True ($projection.audit.remote_mirror_status -eq "not-observed") "Baseline operator projection must surface remote mirror field."
Assert-True ($projection.update.slot_strategy -eq "ab-rootfs-contract") "Baseline operator projection must surface update strategy."
Assert-True ($projection.update.status -eq "not-configured") "Baseline runbook must not invent update state."
Assert-True ($projection.adapters.package_manager_status -eq "available") "Package adapter status must be projected."
Assert-True ($projection.adapters.untrusted_content_status -eq "available") "Untrusted content adapter status must be projected."
Assert-True ($projection.adapters.audit_projection_status -eq "available") "Audit projection adapter status must be projected."
Assert-True ($projection.safety.fail_closed -eq $true) "Safety gate must be projected as fail-closed."
Assert-True ($projectionText -match "Operator Projection") "TUI projection rendering must consume projection output."
Assert-True (-not ($projectionText -match "password=")) "Projection TUI output must not leak secret-like values."

$cases += New-Case `
    -Name "operator-projection-runbook-assertions" `
    -Status "passed" `
    -Summary "runbook consumes read-only redacted operator projection across runtime, audit, update, adapters, and safety fields" `
    -Commands @($serviceCommand, $projectionCommand, $projectionTuiCommand) `
    -Assertions @{
        read_only = $projection.read_only
        runtime_state = $projection.runtime.state
        audit_seal_status = $projection.audit.audit_seal_status
        remote_mirror_status = $projection.audit.remote_mirror_status
        update_strategy = $projection.update.slot_strategy
        update_status = $projection.update.status
        package_manager_status = $projection.adapters.package_manager_status
        untrusted_content_status = $projection.adapters.untrusted_content_status
        audit_projection_status = $projection.adapters.audit_projection_status
        safety_fail_closed = $projection.safety.fail_closed
    } `
    -Artifacts @{
        approved_journal = $approvedJournal
        operator_projection = $operatorProjectionPath
        operator_projection_tui = $operatorProjectionTuiPath
    }

$remoteAuditDir = Join-Path $ArtifactDir "remote-audit-fail-closed"
Remove-Item -LiteralPath $remoteAuditDir -Recurse -Force -ErrorAction SilentlyContinue
$remoteAuditCommand = Invoke-LoggedCommand `
    -Name "remote-audit-fail-closed" `
    -Command @("pwsh", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "scripts/remote-audit-mirror-smoke.ps1", "-ArtifactDir", $remoteAuditDir, "-FailurePolicy", "fail-closed", "-SimulateMirrorFailure") `
    -StdoutPath (Join-Path $ArtifactDir "remote-audit.stdout.txt") `
    -StderrPath (Join-Path $ArtifactDir "remote-audit.stderr.txt")
$commands += $remoteAuditCommand
$remoteAuditResultPath = Join-Path $remoteAuditDir "result.json"
$remoteAudit = Read-JsonFile $remoteAuditResultPath
Assert-True ($remoteAudit.result -eq "passed") "Remote audit failure smoke must pass."
Assert-True ($remoteAudit.local_audit_source_of_truth -eq $true) "Remote audit smoke must preserve local audit source-of-truth."
Assert-True ($remoteAudit.mirror_failure_action -eq "fail-closed-before-non-local-side-effect") "Remote audit fail-closed policy must be asserted."
$cases += New-Case `
    -Name "remote-audit-runbook-policy" `
    -Status "passed" `
    -Summary "runbook asserts remote audit mirror failure policy without making remote mirror authoritative" `
    -Commands @($remoteAuditCommand) `
    -Assertions @{
        result = $remoteAudit.result
        local_audit_source_of_truth = $remoteAudit.local_audit_source_of_truth
        mirror_failure_action = $remoteAudit.mirror_failure_action
    } `
    -Artifacts @{ result = $remoteAuditResultPath }

$deniedJournal = Join-Path $ArtifactDir "service-denied.jsonl"
$deniedReportPath = Join-Path $ArtifactDir "service-denied-report.json"
$deniedRunsDir = Join-Path $ArtifactDir "service-denied.runs"
Remove-Item -LiteralPath $deniedRunsDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $deniedJournal, $deniedReportPath -Force -ErrorAction SilentlyContinue
$deniedServiceCommand = Invoke-LoggedCommand `
    -Name "service-recovery-denied" `
    -Command @("cargo", "run", "-q", "-p", "agentd", "--", "--service-recovery-demo", "denied", $deniedJournal) `
    -StdoutPath $deniedReportPath `
    -StderrPath (Join-Path $ArtifactDir "service-denied.stderr.txt")
$commands += $deniedServiceCommand
$deniedReport = Read-JsonFile $deniedReportPath
Assert-True ($deniedReport.restart_executed -eq $false) "Denied service recovery must not execute restart."
Assert-True ($deniedReport.restart_policy_decision -eq "pause-for-approval") "Denied service recovery must remain approval-gated."
Assert-True ($deniedReport.summary -match "denied") "Denied service recovery summary must record denial."
Assert-True ($deniedReport.summary -match "no restart effect was prepared") "Denied service recovery must prepare no restart effect."
$cases += New-Case `
    -Name "service-recovery-denied-runbook" `
    -Status "passed" `
    -Summary "runbook asserts denied service recovery prepares no restart effect" `
    -Commands @($deniedServiceCommand) `
    -Assertions @{
        restart_executed = $deniedReport.restart_executed
        restart_policy_decision = $deniedReport.restart_policy_decision
        denied_recorded = $true
        no_restart_effect_prepared = $true
    } `
    -Artifacts @{ report = $deniedReportPath; journal = $deniedJournal }

$writeDiffDir = Join-Path $ArtifactDir "write-diff-rollback"
Remove-Item -LiteralPath $writeDiffDir -Recurse -Force -ErrorAction SilentlyContinue
$writeDiffReportPath = Join-Path $ArtifactDir "write-diff-report.json"
$writeDiffCommand = Invoke-LoggedCommand `
    -Name "write-diff-rollback" `
    -Command @("cargo", "run", "-q", "-p", "agentd", "--", "--write-diff-demo", $writeDiffDir) `
    -StdoutPath $writeDiffReportPath `
    -StderrPath (Join-Path $ArtifactDir "write-diff.stderr.txt")
$commands += $writeDiffCommand
$writeDiff = Read-JsonFile $writeDiffReportPath
Assert-True ($writeDiff.untouched_before_commit -eq "port=80`n") "Write diff must not mutate target before commit."
Assert-True ($writeDiff.after_commit -eq "port=8080`n") "Write diff commit must apply proposed content."
Assert-True ($writeDiff.rollback.restored -eq $true) "Write diff rollback must restore prior content."
Assert-True ($writeDiff.after_rollback -eq "port=80`n") "Write diff rollback must restore original target."
$cases += New-Case `
    -Name "write-diff-rollback-runbook" `
    -Status "passed" `
    -Summary "runbook asserts write-with-diff commit and rollback evidence" `
    -Commands @($writeDiffCommand) `
    -Assertions @{
        untouched_before_commit = $writeDiff.untouched_before_commit
        after_commit = $writeDiff.after_commit
        rollback_restored = $writeDiff.rollback.restored
        after_rollback = $writeDiff.after_rollback
    } `
    -Artifacts @{ report = $writeDiffReportPath; root = $writeDiffDir }

$recoveryJournal = Join-Path $ArtifactDir "crash-recovery.jsonl"
$recoveryReportPath = Join-Path $ArtifactDir "crash-recovery-report.txt"
Remove-Item -LiteralPath $recoveryJournal, $recoveryReportPath -Force -ErrorAction SilentlyContinue
$recoveryCommand = Invoke-LoggedCommand `
    -Name "crash-recovery-demo" `
    -Command @("cargo", "run", "-q", "-p", "agentd", "--", "--recovery-demo", $recoveryJournal) `
    -StdoutPath $recoveryReportPath `
    -StderrPath (Join-Path $ArtifactDir "crash-recovery.stderr.txt")
$commands += $recoveryCommand
$recoveryText = Get-Content -LiteralPath $recoveryReportPath -Raw
Assert-True ($recoveryText -match '"requires_human_confirmation":true') "Crash recovery must require human confirmation for write effects."
Assert-True ($recoveryText -match 'needs-rollback') "Crash recovery must classify unresolved write effects as needs-rollback."
$cases += New-Case `
    -Name "crash-recovery-runbook" `
    -Status "passed" `
    -Summary "runbook asserts crash recovery classifies unfinished effects without model replay" `
    -Commands @($recoveryCommand) `
    -Assertions @{
        requires_human_confirmation = $true
        contains_needs_rollback = $true
    } `
    -Artifacts @{ report = $recoveryReportPath; journal = $recoveryJournal }

$sandboxJournal = Join-Path $ArtifactDir "sandbox.jsonl"
$sandboxReportPath = Join-Path $ArtifactDir "sandbox-report.json"
Remove-Item -LiteralPath $sandboxJournal, $sandboxReportPath -Force -ErrorAction SilentlyContinue
$sandboxCommand = Invoke-LoggedCommand `
    -Name "sandbox-local-baseline" `
    -Command @("cargo", "run", "-q", "-p", "agentd", "--", "--sandbox-demo", $sandboxJournal) `
    -StdoutPath $sandboxReportPath `
    -StderrPath (Join-Path $ArtifactDir "sandbox.stderr.txt")
$commands += $sandboxCommand
$sandbox = Read-JsonFile $sandboxReportPath
Assert-True ($sandbox.write_denied.decision -eq "denied") "Sandbox must deny persistent host write."
Assert-True ($sandbox.fork_denied.decision -eq "denied") "Sandbox must deny resource abuse."
Assert-True ($sandbox.syscall_denied.decision -eq "denied") "Sandbox must deny unsupported syscall."
$cases += New-Case `
    -Name "sandbox-local-baseline-runbook" `
    -Status "passed" `
    -Summary "runbook asserts lease-derived sandbox denies persistent write, fork abuse, and denied syscall" `
    -Commands @($sandboxCommand) `
    -Assertions @{
        write_denied = $sandbox.write_denied.decision
        fork_denied = $sandbox.fork_denied.decision
        syscall_denied = $sandbox.syscall_denied.decision
    } `
    -Artifacts @{ report = $sandboxReportPath; journal = $sandboxJournal }

if (-not $SkipCargoTests) {
    foreach ($runbookCase in @(
        @{
            name = "candidate-update-rollback-runtime"
            args = @("cargo", "test", "-p", "agent_core", "rootfs_update")
            assertions = @{
                update_stages_inactive_slot = $true
                failed_health_rolls_back = $true
                active_slot_write_fails_closed = $true
            }
            summary = "candidate runbook covers A/B update staging, health, and rollback runtime"
        },
        @{
            name = "candidate-package-install-isolation"
            args = @("cargo", "test", "-p", "agent_core", "package_install")
            assertions = @{
                package_isolation_required = $true
                host_promotion_requires_exact_approval = $true
                rollback_required = $true
            }
            summary = "candidate runbook covers package isolation before host promotion"
        },
        @{
            name = "candidate-untrusted-content-summary"
            args = @("cargo", "test", "-p", "agent_core", "untrusted_content")
            assertions = @{
                external_content_untrusted = $true
                sanitized_summary_replanning_only = $true
                direct_high_risk_sink_denied = $true
            }
            summary = "candidate runbook covers untrusted content fetch, sanitize, and direct sink denial"
        }
    )) {
        $safeName = ConvertTo-SafeFileName $runbookCase.name
        $command = Invoke-LoggedCommand `
            -Name $runbookCase.name `
            -Command $runbookCase.args `
            -StdoutPath (Join-Path $ArtifactDir "$safeName.stdout.txt") `
            -StderrPath (Join-Path $ArtifactDir "$safeName.stderr.txt")
        $commands += $command
        $cases += New-Case `
            -Name $runbookCase.name `
            -Status "passed" `
            -Summary $runbookCase.summary `
            -Commands @($command) `
            -Assertions $runbookCase.assertions
    }
}

if (-not $SkipCargoTests) {
    foreach ($testCase in @(
        @{ name = "operator-projection-tests"; args = @("cargo", "test", "-p", "agentd", "operator_projection") },
        @{ name = "tui-tests"; args = @("cargo", "test", "-p", "agentd", "tui") }
    )) {
        $command = Invoke-LoggedCommand `
            -Name $testCase.name `
            -Command $testCase.args `
            -StdoutPath (Join-Path $ArtifactDir "$($testCase.name).stdout.txt") `
            -StderrPath (Join-Path $ArtifactDir "$($testCase.name).stderr.txt")
        $commands += $command
        $cases += New-Case `
            -Name $testCase.name `
            -Status "passed" `
            -Summary "$($testCase.name) passed" `
            -Commands @($command) `
            -Assertions @{ cargo_test_passed = $true; external_llm_required = $false }
    }
}

$result = [ordered]@{
    schema = "agentos.production-runbook-smoke.v1"
    checked_at = (Get-Date).ToString("o")
    result = "passed"
    execution_mode = "local-only"
    external_llm_required = $false
    release_gate_consumable = $true
    cases = @($cases)
    summary = [ordered]@{
        total = $cases.Count
        passed = @($cases | Where-Object { $_.status -eq "passed" }).Count
        skipped = @($cases | Where-Object { $_.status -eq "skipped" }).Count
        failed = @($cases | Where-Object { $_.status -eq "failed" }).Count
    }
    commands = @($commands)
    artifacts = [ordered]@{
        result = $resultPath
        artifact_dir = $ArtifactDir
    }
}

Write-Json -Value $result -Path $resultPath
Write-Host "Production runbook smoke passed: $resultPath"
