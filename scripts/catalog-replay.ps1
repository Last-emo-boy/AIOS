param(
    [string]$OutputPath = ".workflow/artifacts/catalog-replay/result.json",
    [string]$RunStore = ".workflow/artifacts/catalog-replay/runs",
    [string]$AuditJournal = ".workflow/artifacts/catalog-replay/audit.jsonl",
    [string]$SupportBundle = ".workflow/artifacts/catalog-replay/support-bundle.json",
    [string]$ScriptPath = ".workflow/artifacts/catalog-replay/script.tui"
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

$ArtifactCoordinate = "agentos:workflow-pack/agentos/service-recovery@1.0.0"
$commands = @(
    "capabilities.show",
    "workflows.show",
    "workflows.show package.install",
    "launch.preview service.recovery service=nginx",
    "launch.preview package.install package_identity=nginx package_digest=sha256:catalog rollback_id=rb-catalog",
    "aom.artifact.show $ArtifactCoordinate",
    "palette.preview aom.artifact.show $ArtifactCoordinate",
    "palette.preview aom.activate.preview $ArtifactCoordinate",
    "launch.preview service.recovery cmd=powershell",
    "dashboard.show | sh"
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
Add-Check $checks "capability-catalog-rendered" ($outputText.Contains("TUI Capability Catalog") -and $outputText.Contains("schema=agentos.tui-capability-index.v1") -and $outputText.Contains("id=service.recovery")) "capability index must render core operational capabilities"
Add-Check $checks "workflow-catalog-rendered" ($outputText.Contains("TUI Workflow Catalog") -and $outputText.Contains("workflow_detail id=package.install") -and $outputText.Contains("rollback id before host mutation")) "workflow catalog and high-risk detail must render"
Add-Check $checks "launch-preview-rendered" ($outputText.Contains("TUI Launch Intent Preview") -and $outputText.Contains("workflow=service.recovery") -and $outputText.Contains("direct_execute=false") -and $outputText.Contains("plan_spec_created=false") -and $outputText.Contains("side_effects_prepared=false")) "launch preview must remain preview-only"
Add-Check $checks "high-risk-launch-preview-rendered" ($outputText.Contains("workflow=package.install") -and $outputText.Contains("exact approval token for pkg.host.install") -and $outputText.Contains("rollback_id")) "high-risk launch preview must show approval and rollback expectations"
Add-Check $checks "aom-artifact-panel-rendered" ($outputText.Contains("TUI AOM Artifact") -and $outputText.Contains("schema=agentos.tui-aom-artifact-panel.v1") -and $outputText.Contains("trust_tier=core")) "AOM artifact trust panel must render"
Add-Check $checks "aom-artifact-activation-gated" ($outputText.Contains("activation_prepared=false") -and $outputText.Contains("security_execution_required=true") -and $outputText.Contains("agent_core_plan_spec_required=true") -and $outputText.Contains("direct_activate=false")) "AOM artifact activation must remain runtime-gated"
Add-Check $checks "aom-resolver-not-in-tui" ($outputText.Contains("resolver_logic=false") -and $outputText.Contains("resolver_owner=agent_core::ecosystem") -and $outputText.Contains("agentd_resolver_logic=false")) "TUI must not own ecosystem resolver logic"
Add-Check $checks "catalog-palette-preview-read-only" ($outputText.Contains("read-only artifact trust and activation gate projection") -and $outputText.Contains("risk=read-only")) "catalog palette preview must be read-only"
Add-Check $checks "unsafe-catalog-input-fails-closed" ($outputText.Contains("TUI Error") -and $outputText.Contains("kind=parse") -and $outputText.Contains("host shell command names are not accepted in launch preview input")) "unsafe catalog launch input must fail closed"
Add-Check $checks "catalog-does-not-create-run" ((Count-RunSnapshots $resolvedRunStore) -eq 0) "catalog replay must not create PlanRun snapshots"
Add-Check $checks "catalog-does-not-prepare-effects" (-not $outputText.Contains("EffectPrepared")) "catalog replay must not prepare effects"
Add-Check $checks "no-direct-shell" (-not $outputText.Contains("shell.exec cmd=id")) "direct shell content must not be echoed raw"
Add-Check $checks "local-only" (-not $outputText.Contains("http://") -and -not $outputText.Contains("https://")) "catalog replay must remain local-only"

$failed = @($checks | Where-Object { $_.status -ne "passed" })
$failedNames = @()
if ($failed.Count -gt 0) {
    $failedNames = @($failed | ForEach-Object { $_.name })
}

$result = [ordered]@{
    schema = "agentos.catalog-replay.v1"
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
    command = "cargo run -q -p agentd -- --tui-scripted <catalog-script> --run-store <path> --audit-journal <path> --support-bundle <path>"
    commands = @($commands)
    artifacts = [ordered]@{
        script = $resolvedScriptPath
        output = $stdoutPath
        stderr = $stderrPath
        run_store = $resolvedRunStore
        audit_journal = $resolvedAuditJournal
        support_bundle = $resolvedSupportBundle
        output_sha256 = Get-StringSha256 -Value $outputText
        audit_journal_sha256 = Get-OptionalFileHash -Path $resolvedAuditJournal
        support_bundle_sha256 = Get-OptionalFileHash -Path $resolvedSupportBundle
        run_store_snapshot_count = Count-RunSnapshots -Path $resolvedRunStore
    }
    checks = @($checks)
    summary = [ordered]@{
        total = $checks.Count
        passed = $checks.Count - $failed.Count
        failed = $failed.Count
        failed_names = @($failedNames)
    }
    stderr = if ($null -eq $stderrText) { "" } else { $stderrText.Trim() }
    status = if ($failed.Count -eq 0) { "passed" } else { "failed" }
}

Write-Json -Value $result -Path $resolvedOutput

if ($failed.Count -gt 0) {
    Write-Error "Catalog replay failed: $($failedNames -join ', ')"
    exit 1
}

Write-Host "Catalog replay passed: $resolvedOutput"
