param(
    [string]$OutputPath = ".workflow/artifacts/tui-replay/result.json",
    [string]$RunStore = ".workflow/artifacts/tui-replay/runs",
    [string]$AuditJournal = ".workflow/artifacts/tui-replay/audit.jsonl",
    [string]$SupportBundle = ".workflow/artifacts/tui-replay/support-bundle.json",
    [string]$ScriptPath = ".workflow/artifacts/tui-replay/script.tui",
    [string]$CatalogReplayOutput = ".workflow/artifacts/catalog-replay/result.json",
    [switch]$SkipCatalogReplay
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
    $Value | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Resolve-RepoPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ([IO.Path]::IsPathRooted($Path)) {
        return [IO.Path]::GetFullPath($Path)
    }
    return [IO.Path]::GetFullPath((Join-Path $script:repoRoot $Path))
}

function Assert-UnderRepo {
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    $prefix = $script:repoRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "refusing to operate outside repo: $full"
    }
}

function Get-StringSha256 {
    param([Parameter(Mandatory = $true)][string]$Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
        return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join "")
    } finally {
        $sha.Dispose()
    }
}

function Get-OptionalFileHash {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Add-Check {
    param(
        [System.Collections.ArrayList]$Checks,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][bool]$Passed,
        [string]$Message = ""
    )
    [void]$Checks.Add([ordered]@{
        name = $Name
        status = if ($Passed) { "passed" } else { "failed" }
        message = $Message
    })
}

function Count-RunSnapshots {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        return 0
    }
    return @(Get-ChildItem -LiteralPath $Path -Recurse -File -Filter "*.json").Count
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$resolvedOutput = Resolve-RepoPath $OutputPath
$resolvedRunStore = Resolve-RepoPath $RunStore
$resolvedAuditJournal = Resolve-RepoPath $AuditJournal
$resolvedSupportBundle = Resolve-RepoPath $SupportBundle
$resolvedScriptPath = Resolve-RepoPath $ScriptPath
$artifactRoot = Split-Path -Parent $resolvedOutput

foreach ($path in @($resolvedOutput, $resolvedRunStore, $resolvedAuditJournal, $resolvedSupportBundle, $resolvedScriptPath, $artifactRoot)) {
    Assert-UnderRepo $path
}

New-Item -ItemType Directory -Force -Path $artifactRoot | Out-Null
Remove-Item -LiteralPath $resolvedRunStore -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $resolvedAuditJournal, $resolvedSupportBundle -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $resolvedRunStore | Out-Null
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $resolvedAuditJournal), (Split-Path -Parent $resolvedSupportBundle) | Out-Null

$commands = @(
    "dashboard.show",
    "intent.submit recover nginx service",
    "run.advance latest",
    "run.advance latest",
    "run.advance latest",
    "run.advance latest",
    "run.advance latest",
    "approvals.show latest",
    "recovery.show latest",
    "events.show 8",
    "run.deny latest restart-service actor=operator reason=operator declined",
    "audit.show latest",
    "support.bundle export",
    "aom.search",
    "aom.activate.preview agentos:workflow-pack/agentos/service-recovery@1.0.0",
    "release.provenance.show",
    "promotion.blockers.show",
    "update.rollback.show",
    "gate.status.show",
    "signing.status.show",
    "rollout.rings.show",
    "dashboard.show | sh",
    "shell.exec cmd=id",
    "intent.submit recover nginx token=abc123",
    "aom.stage agentos:workflow-pack/agentos/service-recovery@1.0.0 && aom.activate.preview agentos:workflow-pack/agentos/service-recovery@1.0.0"
)

$commands -join "`n" | Set-Content -LiteralPath $resolvedScriptPath -Encoding UTF8
$stdoutPath = Join-Path $artifactRoot "output.txt"
$stderrPath = Join-Path $artifactRoot "stderr.txt"
Remove-Item -LiteralPath $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue

$startedAt = (Get-Date).ToString("o")
$stdout = & cargo run -q -p agentd -- --tui-scripted $resolvedScriptPath --run-store $resolvedRunStore --audit-journal $resolvedAuditJournal --support-bundle $resolvedSupportBundle 2>$stderrPath
$exitCode = $LASTEXITCODE
$outputText = ($stdout | Out-String)
$outputText | Set-Content -LiteralPath $stdoutPath -Encoding UTF8
$stderrText = if (Test-Path -LiteralPath $stderrPath -PathType Leaf) { Get-Content -LiteralPath $stderrPath -Raw } else { "" }

$checks = [System.Collections.ArrayList]::new()
Add-Check $checks "command-exit-zero" ($exitCode -eq 0) "agentd --tui-scripted must exit successfully"
Add-Check $checks "dashboard-rendered" ($outputText.Contains("TUI Dashboard")) "dashboard projection is required"
Add-Check $checks "durable-mode" ($outputText.Contains("mode=durable projection_controller=true")) "TUI must run durable projection-controller mode"
Add-Check $checks "run-rendered" ($outputText.Contains("TUI Run")) "run projection is required"
Add-Check $checks "planned-state" ($outputText.Contains("state=Planned")) "intent.submit must plan a run"
Add-Check $checks "approval-state" ($outputText.Contains("state=AwaitingApproval")) "run.advance must reach approval gate"
Add-Check $checks "approval-queue-rendered" ($outputText.Contains("TUI Approvals") -and $outputText.Contains("panel=approval-center") -and $outputText.Contains("exact_binding_required=true") -and $outputText.Contains("policy_version=policy-v1")) "approval queue must render exact binding context"
Add-Check $checks "recovery-rendered" ($outputText.Contains("TUI Recovery") -and $outputText.Contains("source=run-store+audit-journal") -and $outputText.Contains("no-model-replay=true")) "recovery view must render durable recovery source"
Add-Check $checks "event-feed-rendered" ($outputText.Contains("TUI Event Feed") -and $outputText.Contains("cursor_authority=") -and $outputText.Contains("source=projection-snapshot+audit-journal")) "event feed must render durable projection and audit cursor"
Add-Check $checks "denied-state" ($outputText.Contains("state=Denied")) "run.deny must deny through AgentCore"
Add-Check $checks "audit-rendered" ($outputText.Contains("TUI Audit")) "audit projection is required"
Add-Check $checks "support-exported" ((Test-Path -LiteralPath $resolvedSupportBundle -PathType Leaf) -and $outputText.Contains("TUI Support Bundle")) "support bundle must be exported"
Add-Check $checks "ecosystem-rendered" ($outputText.Contains("TUI Ecosystem")) "aom lifecycle projection is required"
Add-Check $checks "activation-preview-rendered" ($outputText.Contains("activation_plan_preview") -and $outputText.Contains('"activation_prepared":false') -and $outputText.Contains('"security_execution_required":true')) "activation preview must remain gated and unprepared"
Add-Check $checks "release-provenance-rendered" ($outputText.Contains("TUI Release Provenance") -and $outputText.Contains("release_provenance_panel") -and $outputText.Contains("read_only=true") -and $outputText.Contains("direct_sign=false") -and $outputText.Contains("direct_promote=false")) "release provenance panel must render as a read-only projection"
Add-Check $checks "promotion-blockers-rendered" ($outputText.Contains("TUI Promotion Blockers") -and $outputText.Contains("promotion_blocker_panel") -and $outputText.Contains("blocker_group category=provenance") -and $outputText.Contains("clear_blocker_allowed=false") -and $outputText.Contains("direct_promote=false")) "promotion blockers panel must render as a read-only blocker projection"
Add-Check $checks "update-rollback-rendered" ($outputText.Contains("TUI Update Rollback") -and $outputText.Contains("update_rollback_panel") -and $outputText.Contains("direct_update=false") -and $outputText.Contains("direct_rollback=false") -and $outputText.Contains("host_mutation_in_tui=false") -and $outputText.Contains("promotion.blockers.show")) "update rollback panel must render as a read-only update and rollback evidence projection"
Add-Check $checks "gate-status-rendered" ($outputText.Contains("TUI Gate Status") -and $outputText.Contains("gate_status_panel") -and $outputText.Contains("AGENTOS_TUI_CONSOLE_READY") -and $outputText.Contains("qemu_execution_in_tui=false") -and $outputText.Contains("rootfs_validation_in_tui=false") -and $outputText.Contains("replay_execution_in_tui=false")) "gate status panel must render QEMU/rootfs/replay gate evidence as a read-only projection"
Add-Check $checks "signing-status-rendered" ($outputText.Contains("TUI Signing Status") -and $outputText.Contains("signing_status_panel") -and $outputText.Contains("scope=candidate-only") -and $outputText.Contains("candidate_is_production_signature=false") -and $outputText.Contains("production_ready_claim=false") -and $outputText.Contains("production_signing_authority=false")) "signing status panel must render candidate signatures without claiming production signing authority"
Add-Check $checks "rollout-rings-rendered" ($outputText.Contains("TUI Rollout Rings") -and $outputText.Contains("rollout_ring_panel") -and $outputText.Contains("preview_only=true") -and $outputText.Contains("remote_rollout_authority=false") -and $outputText.Contains("direct_rollout=false") -and $outputText.Contains("remote_command_dispatch=false")) "rollout ring panel must render as a preview-only projection without remote rollout authority"
Add-Check $checks "unsafe-command-parse-error" ($outputText.Contains("TUI Error") -and $outputText.Contains("kind=parse")) "shell-like command must fail closed"
Add-Check $checks "direct-shell-rejected" ($outputText.Contains("direct shell.exec authority is not accepted by TUI")) "direct shell.exec command must be rejected"
Add-Check $checks "secret-like-command-redacted" (-not $outputText.Contains("token=abc123")) "secret-like command input must not be echoed raw"
Add-Check $checks "no-demo-plan-preview" (-not $outputText.Contains("Plan Preview")) "scripted replay must not use demo session renderer"
Add-Check $checks "run-store-snapshots" ((Count-RunSnapshots $resolvedRunStore) -gt 0) "RunStore snapshots must be persisted"
Add-Check $checks "audit-journal-present" (Test-Path -LiteralPath $resolvedAuditJournal -PathType Leaf) "AuditJournal must be persisted"

$auditText = if (Test-Path -LiteralPath $resolvedAuditJournal -PathType Leaf) {
    Get-Content -LiteralPath $resolvedAuditJournal -Raw
} else {
    ""
}
$restartPrepared = $auditText -match '"event_type":"EffectPrepared".*"step_id":"restart-service"' -or
    $auditText -match '"step_id":"restart-service".*"event_type":"EffectPrepared"'
Add-Check $checks "denied-restart-no-effect-prepared" (-not $restartPrepared) "denied restart must not prepare side effects"

$catalogReplayStatus = "skipped"
$catalogReplaySummary = $null
$resolvedCatalogReplayOutput = Resolve-RepoPath $CatalogReplayOutput
Assert-UnderRepo $resolvedCatalogReplayOutput
if (-not $SkipCatalogReplay) {
    $catalogStdoutPath = Join-Path $artifactRoot "catalog-replay-stdout.txt"
    $catalogStderrPath = Join-Path $artifactRoot "catalog-replay-stderr.txt"
    Remove-Item -LiteralPath $catalogStdoutPath, $catalogStderrPath -Force -ErrorAction SilentlyContinue
    $catalogStdout = & pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/catalog-replay.ps1 -OutputPath $CatalogReplayOutput 2>$catalogStderrPath
    $catalogExitCode = $LASTEXITCODE
    ($catalogStdout | Out-String) | Set-Content -LiteralPath $catalogStdoutPath -Encoding UTF8
    $catalogStderrText = if (Test-Path -LiteralPath $catalogStderrPath -PathType Leaf) { Get-Content -LiteralPath $catalogStderrPath -Raw } else { "" }
    $catalogReplayStatus = if ($catalogExitCode -eq 0) { "passed" } else { "failed" }
    if (Test-Path -LiteralPath $resolvedCatalogReplayOutput -PathType Leaf) {
        $catalogReplaySummary = (Get-Content -LiteralPath $resolvedCatalogReplayOutput -Raw | ConvertFrom-Json).summary
    }
    Add-Check $checks "catalog-replay-gate" ($catalogExitCode -eq 0) "catalog replay must pass: $catalogStderrText"
}

$failed = @($checks | Where-Object { $_.status -ne "passed" })
$failedNames = @()
if ($failed.Count -gt 0) {
    $failedNames = @($failed | ForEach-Object { $_.name })
}
$outputSha256 = Get-StringSha256 -Value $outputText
$auditJournalSha256 = Get-OptionalFileHash -Path $resolvedAuditJournal
$supportBundleSha256 = Get-OptionalFileHash -Path $resolvedSupportBundle
$runStoreSnapshotCount = Count-RunSnapshots -Path $resolvedRunStore
$stderrSummary = if ($null -eq $stderrText) { "" } else { $stderrText.Trim() }
$result = [ordered]@{
    schema = "agentos.tui-replay.v1"
    generated_at = (Get-Date).ToString("o")
    started_at = $startedAt
    local_only = $true
    projection_controller_only = $true
    external_dependencies_required = [ordered]@{
        network = $false
        external_llm = $false
        firecracker = $false
        host_package_manager = $false
    }
    command = "cargo run -q -p agentd -- --tui-scripted <script> --run-store <path> --audit-journal <path> --support-bundle <path>"
    commands = @($commands)
    artifacts = [ordered]@{
        script = $resolvedScriptPath
        output = $stdoutPath
        stderr = $stderrPath
        run_store = $resolvedRunStore
        audit_journal = $resolvedAuditJournal
        support_bundle = $resolvedSupportBundle
        catalog_replay = $resolvedCatalogReplayOutput
        output_sha256 = $outputSha256
        audit_journal_sha256 = $auditJournalSha256
        support_bundle_sha256 = $supportBundleSha256
        run_store_snapshot_count = $runStoreSnapshotCount
    }
    catalog_replay = [ordered]@{
        status = $catalogReplayStatus
        output = $resolvedCatalogReplayOutput
        summary = $catalogReplaySummary
    }
    checks = @($checks)
    summary = [ordered]@{
        total = $checks.Count
        passed = $checks.Count - $failed.Count
        failed = $failed.Count
        failed_names = @($failedNames)
    }
    stderr = $stderrSummary
    status = if ($failed.Count -eq 0) { "passed" } else { "failed" }
}

Write-Json -Value $result -Path $resolvedOutput

if ($failed.Count -gt 0) {
    Write-Error "TUI replay failed: $($failedNames -join ', ')"
    exit 1
}

Write-Host "TUI replay passed: $resolvedOutput"
