param(
    [string]$ArtifactDir = ".workflow/artifacts/rc15-final-closeout-audit",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc15",
    [string]$PlanPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc15/plan.json",
    [string]$GeneratedAt = "",
    [switch]$FailOnBlocked
)

$ErrorActionPreference = "Stop"

function Resolve-RepoPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $combined = if ([IO.Path]::IsPathRooted($Path)) { $Path } else { Join-Path $script:repoRoot $Path }
    $full = [IO.Path]::GetFullPath($combined)
    $repoPrefix = $script:repoRoot.TrimEnd("\", "/") + [IO.Path]::DirectorySeparatorChar
    if ($full -ne $script:repoRoot -and -not $full.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path escapes repository root: $Path"
    }
    return $full
}

function Get-StablePath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    if ($full.StartsWith($script:repoRoot, [StringComparison]::OrdinalIgnoreCase)) {
        return $full.Substring($script:repoRoot.Length).TrimStart("\", "/") -replace "\\", "/"
    }
    return $full
}

function Get-FileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Read-Json {
    param([Parameter(Mandatory = $true)][string]$Path)
    return Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
}

function Write-Json {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $parent = Split-Path -Parent $Path
    if ($parent) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 100) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}

function Write-Text {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $parent = Split-Path -Parent $Path
    if ($parent) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    [IO.File]::WriteAllText($Path, $Value, [Text.UTF8Encoding]::new($false))
}

function Get-TaskStatus {
    param($Plan, [Parameter(Mandatory = $true)][string]$TaskId)
    foreach ($wave in @($Plan.waves)) {
        foreach ($task in @($wave.tasks)) {
            if ($task.id -eq $TaskId) { return $task.status }
        }
    }
    return $null
}

function Add-Check {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][bool]$Passed,
        [Parameter(Mandatory = $true)][string]$Message,
        $Evidence = $null
    )
    $entry = [ordered]@{
        id = $Id
        status = if ($Passed) { "passed" } else { "failed" }
        severity = "blocking"
        message = $Message
        evidence = $Evidence
    }
    $script:checks += $entry
    if (-not $Passed) { $script:blockers += $entry }
}

function New-ArtifactRef {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        $Json = $null
    )
    return [ordered]@{
        path = Get-StablePath $Path
        sha256 = Get-FileSha256 $Path
        size_bytes = if (Test-Path -LiteralPath $Path -PathType Leaf) { (Get-Item -LiteralPath $Path).Length } else { $null }
        present = Test-Path -LiteralPath $Path -PathType Leaf
        schema = if ($null -ne $Json) { $Json.schema } else { $null }
        status = if ($null -ne $Json) { $Json.status } else { $null }
    }
}

function Test-NoSensitiveText {
    param([Parameter(Mandatory = $true)][string[]]$Values)
    $privateKeyMarker = "PRIVATE" + " KEY"
    $publicKeyMarker = "PUBLIC" + " KEY"
    $identityWord = "finger" + "print"
    $markers = @(
        ("BEGIN " + $privateKeyMarker),
        ("BEGIN " + $publicKeyMarker),
        ($privateKeyMarker + "-----"),
        ("Authorization:" + " Bearer"),
        ("Bearer" + " "),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ("." + "local-release-authority"),
        ("signing" + "-key." + "pem"),
        ("/etc/" + "aios-signer/" + "private"),
        ("." + "pem"),
        $identityWord
    )
    foreach ($value in $Values) {
        if ($null -eq $value) { continue }
        foreach ($marker in $markers) {
            if ($value.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                return $false
            }
        }
    }
    return $true
}

function Get-SummaryNumber {
    param($Json, [string]$Name)
    if ($null -eq $Json.summary) { return 0 }
    $prop = $Json.summary.PSObject.Properties[$Name]
    if ($null -eq $prop) { return 0 }
    return [int]$prop.Value
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:blockers = @()

$generatedAtValue = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }
$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$resolvedWorkflowDir = Resolve-RepoPath $WorkflowDir
$resolvedPlanPath = Resolve-RepoPath $PlanPath
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $resolvedWorkflowDir "evidence") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $resolvedWorkflowDir "docs") | Out-Null

$plan = Read-Json $resolvedPlanPath
$paths = [ordered]@{
    "RC15-010" = ".workflow/artifacts/rc15-audit-nonce-policy-binding/result.json"
    "RC15-011" = ".workflow/artifacts/rc15-two-real-local-target-identities/result.json"
    "RC15-020" = ".workflow/artifacts/rc15-exact-approval-controlled-execution/result.json"
    "RC15-021" = ".workflow/artifacts/rc15-agentcore-executable-planspec/result.json"
    "RC15-022" = ".workflow/artifacts/rc15-security-execution-allow-decision/result.json"
    "RC15-030" = ".workflow/artifacts/rc15-controlled-local-activation/result.json"
    "RC15-031" = ".workflow/artifacts/rc15-controlled-rollback-support-recovery/result.json"
}

$results = @()
foreach ($taskId in $paths.Keys) {
    $path = Resolve-RepoPath $paths[$taskId]
    $json = Read-Json $path
    $results += [ordered]@{
        task = $taskId
        path = Get-StablePath $path
        sha256 = Get-FileSha256 $path
        json = $json
    }
}

$taskIds = @("RC15-000", "RC15-001", "RC15-010", "RC15-011", "RC15-020", "RC15-021", "RC15-022", "RC15-030", "RC15-031")
$completedStatuses = @($taskIds | ForEach-Object { [ordered]@{ task = $_; status = Get-TaskStatus $plan $_ } })
$allPreviousTasksCompleted = @($completedStatuses | Where-Object { $_.status -ne "completed" }).Count -eq 0
$finalTaskStatus = Get-TaskStatus $plan "RC15-050"
$planPointerReady = $plan.status -eq "active" -and
    $plan.current_task -eq "RC15-050" -and
    ($finalTaskStatus -eq "pending" -or $finalTaskStatus -eq "completed")
$planPointerClosed = $plan.status -eq "completed" -and
    $null -eq $plan.current_task -and
    $finalTaskStatus -eq "completed"
$planPointerValid = $planPointerReady -or $planPointerClosed

$allResultsPassed = @($results | Where-Object { $_.json.status -ne "passed" }).Count -eq 0
$productionReadyClaimsFalse = @($results | Where-Object { $_.json.production_ready_claim -ne $false }).Count -eq 0
$failClosedCases = 0
$failedFailClosedCases = 0
foreach ($entry in $results) {
    $failClosedCases += Get-SummaryNumber $entry.json "fail_closed_cases"
    $failedFailClosedCases += Get-SummaryNumber $entry.json "failed_fail_closed_cases"
}

$audit = ($results | Where-Object { $_.task -eq "RC15-010" }).json
$targets = ($results | Where-Object { $_.task -eq "RC15-011" }).json
$approval = ($results | Where-Object { $_.task -eq "RC15-020" }).json
$planspec = ($results | Where-Object { $_.task -eq "RC15-021" }).json
$security = ($results | Where-Object { $_.task -eq "RC15-022" }).json
$activation = ($results | Where-Object { $_.task -eq "RC15-030" }).json
$rollback = ($results | Where-Object { $_.task -eq "RC15-031" }).json

$controlledExecutionReady = $audit.summary.rc15_010_complete -eq $true -and
    $targets.summary.rc15_011_complete -eq $true -and
    $approval.summary.rc15_020_complete -eq $true -and
    $planspec.summary.rc15_021_complete -eq $true -and
    $security.summary.rc15_022_complete -eq $true -and
    $activation.summary.rc15_030_complete -eq $true -and
    $rollback.summary.rc15_031_complete -eq $true -and
    $planspec.readiness_surface.agentcore_planspec_executable -eq $true -and
    $security.readiness_surface.security_execution_allowed -eq $true -and
    $activation.activation_surface.activation_performed -eq $true -and
    $rollback.rollback_surface.rollback_execution_performed -eq $true

$forbiddenAuthorityPreserved = $security.invariants.remote_dispatch_enabled -eq $false -and
    $security.invariants.production_ring_mutated -eq $false -and
    $activation.invariants.active_slot_mutated -eq $false -and
    $activation.invariants.boot_metadata_mutated -eq $false -and
    $activation.invariants.active_artifact_set_mutated -eq $false -and
    $activation.invariants.production_ring_mutated -eq $false -and
    $rollback.invariants.support_upload_performed -eq $false -and
    $rollback.invariants.recovery_execution_performed -eq $false -and
    $rollback.invariants.remote_dispatch_enabled -eq $false -and
    $rollback.invariants.production_ring_mutated -eq $false -and
    $rollback.invariants.private_signing_material_handled -eq $false -and
    $rollback.invariants.cryptographic_release_signing_performed -eq $false

Add-Check "plan.pointer.rc15_050" $planPointerValid "RC15 final audit must run at RC15-050 after all prior RC15 tasks." ([ordered]@{ plan_status = $plan.status; current_task = $plan.current_task; final_task_status = $finalTaskStatus })
Add-Check "tasks.previous.completed" $allPreviousTasksCompleted "RC15-000 through RC15-031 must be completed before final closeout." $completedStatuses
Add-Check "results.all_passed" $allResultsPassed "All RC15 executable task results must be passed." (@($results | ForEach-Object { [ordered]@{ task = $_.task; status = $_.json.status; path = $_.path } }))
Add-Check "audit_nonce_policy.bound" ($audit.summary.rc15_010_complete -eq $true -and $audit.binding_surface.audit_sink_bound -eq $true -and $audit.binding_surface.nonce_bound -eq $true -and $audit.binding_surface.expiry_bound -eq $true -and $audit.binding_surface.policy_version_bound -eq $true) "Audit sink, nonce, expiry, and policy version must be bound." $audit.binding_surface
Add-Check "target_identities.two_real_local" ($targets.summary.rc15_011_complete -eq $true -and $targets.target_surface.enrolled_target_identity_count -eq 2 -and $targets.target_surface.distinct_identity_count -eq 2) "Two distinct repo-local canary target identities must be enrolled." $targets.target_surface
Add-Check "exact_approval.bound" ($approval.summary.rc15_020_complete -eq $true -and $approval.approval_surface.exact_approval_bound -eq $true -and $approval.approval_surface.approval_granted -eq $true) "Exact approval must be bound and granted before execution." $approval.approval_surface
Add-Check "agentcore.executable" ($planspec.summary.rc15_021_complete -eq $true -and $planspec.readiness_surface.agentcore_planspec_executable -eq $true) "AgentCore PlanSpec must be executable before effects." $planspec.readiness_surface
Add-Check "security.allow.bound" ($security.summary.rc15_022_complete -eq $true -and $security.readiness_surface.security_execution_allowed -eq $true) "SecurityExecution allow decision must be bound before activation." $security.readiness_surface
Add-Check "activation.executed.audited" ($activation.summary.rc15_030_complete -eq $true -and $activation.activation_surface.activation_performed -eq $true -and $activation.activation_surface.activation_audit_fabricated -eq $false) "Controlled local activation must execute with non-fabricated audit evidence." $activation.activation_surface
Add-Check "rollback.executed.support_bound" ($rollback.summary.rc15_031_complete -eq $true -and $rollback.rollback_surface.rollback_execution_performed -eq $true -and $rollback.rollback_surface.support_bundle_local_only -eq $true -and $rollback.rollback_surface.support_upload_performed -eq $false) "Separate rollback must execute with support/recovery evidence while support upload remains disabled." $rollback.rollback_surface
Add-Check "fixtures.fail_closed.coverage" ($failClosedCases -ge 100 -and $failedFailClosedCases -eq 0) "RC15 fail-closed coverage must remain broad and fully passing." ([ordered]@{ fail_closed_cases = $failClosedCases; failed_fail_closed_cases = $failedFailClosedCases })
Add-Check "authority.boundaries.preserved" $forbiddenAuthorityPreserved "RC15 must not broaden mirror, frontend, nginx, signer, object storage, remote dispatch, support upload, recovery execution, slot, boot, active artifact set, production ring, private signing, or release signing authority." ([ordered]@{ remote_dispatch = $rollback.invariants.remote_dispatch_enabled; support_upload = $rollback.invariants.support_upload_performed; recovery_execution = $rollback.invariants.recovery_execution_performed; production_ring_mutated = $rollback.invariants.production_ring_mutated; private_signing_material_handled = $rollback.invariants.private_signing_material_handled })
Add-Check "production_ready_claim.false" $productionReadyClaimsFalse "RC15 must remain non-GA and must not claim production readiness." $null
Add-Check "controlled_execution.ready_non_ga" $controlledExecutionReady "RC15 may close only as controlled local execution ready, not GA." ([ordered]@{ controlled_execution_ready = $controlledExecutionReady; production_ready_claim = $false })

$decision = if (@($script:blockers).Count -eq 0) { "PASS" } else { "BLOCKED" }
$result = [ordered]@{
    schema = "agentos.rc15-final-closeout-audit-result.v1"
    generated_at = $generatedAtValue
    task = "RC15-050"
    status = if ($decision -eq "PASS") { "passed" } else { "blocked" }
    decision = $decision
    production_ready_claim = $false
    milestone = "Production Distro RC15"
    milestone_status = if ($decision -eq "PASS") { "rc15-controlled-local-execution-ready-non-ga" } else { "rc15-blocked" }
    controlled_local_execution_ready = $controlledExecutionReady -and $decision -eq "PASS"
    source = [ordered]@{
        rc15_plan = New-ArtifactRef $resolvedPlanPath $plan
        task_results = @($results | ForEach-Object { [ordered]@{ task = $_.task; path = $_.path; sha256 = $_.sha256; status = $_.json.status } })
    }
    checks = @($script:checks)
    blockers = @($script:blockers | ForEach-Object { $_.id })
    remaining_non_ga_boundaries = @(
        "GA production-ready claim remains false",
        "mirror/frontend/nginx/TLS work remains out of RC15 body scope",
        "remote signer and private signing material handling remain out of scope",
        "large object storage provisioning remains out of scope",
        "remote dispatch and production ring mutation remain disabled",
        "support upload and recovery execution remain disabled"
    )
    next_milestone_direction = "Plan RC16 around distributable user-facing packaging/release operations without weakening RC15 local execution evidence boundaries."
    summary = [ordered]@{
        checks = @($script:checks).Count
        blockers = @($script:blockers).Count
        fail_closed_cases = $failClosedCases
        failed_fail_closed_cases = $failedFailClosedCases
        controlled_local_execution_ready = $controlledExecutionReady -and $decision -eq "PASS"
        production_ready_claim = $false
    }
}

$resultPath = Join-Path $resolvedArtifactDir "result.json"
$finalEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "FINAL-AUDIT-20260609-production-distro-rc15.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC15-050-final-closeout-audit.json"
$summaryPath = Join-Path (Join-Path $resolvedWorkflowDir "docs") "final-rc15-closeout-summary.md"

Write-Json $result $resultPath
Write-Json $result $finalEvidencePath

$summaryText = @"
# RC15 Final Closeout Summary

Decision: $decision

RC15 closes as controlled local execution ready and non-GA. The milestone proved audit/nonce/policy binding, two real local target identities, exact approval, executable AgentCore PlanSpec, SecurityExecution allow, controlled local activation, separate rollback approval/execution, and local support/recovery evidence.

Boundary: production_ready_claim remains false. RC15 did not provision mirror frontend, Nginx/TLS, remote signer, object storage, remote dispatch, private signing material handling, support upload, recovery execution, or production ring mutation.

Next: plan RC16 around distributable user-facing packaging/release operations while preserving RC15 controlled execution evidence boundaries.
"@
Write-Text $summaryText $summaryPath

$taskEvidence = [ordered]@{
    schema = "agentos.rc15-final-closeout-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC15-050"
    status = if ($decision -eq "PASS") { "completed" } else { "blocked" }
    production_ready_claim = $false
    workflow = Get-StablePath $resolvedWorkflowDir
    script = [ordered]@{
        path = Get-StablePath $PSCommandPath
        sha256 = Get-FileSha256 $PSCommandPath
    }
    result = [ordered]@{
        path = Get-StablePath $resultPath
        status = $result.status
        sha256 = Get-FileSha256 $resultPath
    }
    final_audit = [ordered]@{
        path = Get-StablePath $finalEvidencePath
        sha256 = Get-FileSha256 $finalEvidencePath
    }
    summary = [ordered]@{
        path = Get-StablePath $summaryPath
        sha256 = Get-FileSha256 $summaryPath
    }
    checks = @($script:checks)
}
Write-Json $taskEvidence $taskEvidencePath

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $finalEvidencePath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath),
    (Get-Content -Raw -LiteralPath $summaryPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC15 final audit outputs must not contain key blocks, auth tokens, private paths, signer internals, or raw public identity markers." $null

$decision = if (@($script:blockers).Count -eq 0) { "PASS" } else { "BLOCKED" }
$result["status"] = if ($decision -eq "PASS") { "passed" } else { "blocked" }
$result["decision"] = $decision
$result["milestone_status"] = if ($decision -eq "PASS") { "rc15-controlled-local-execution-ready-non-ga" } else { "rc15-blocked" }
$result["controlled_local_execution_ready"] = $controlledExecutionReady -and $decision -eq "PASS"
$result["checks"] = @($script:checks)
$result["blockers"] = @($script:blockers | ForEach-Object { $_.id })
$result["summary"]["checks"] = @($script:checks).Count
$result["summary"]["blockers"] = @($script:blockers).Count
Write-Json $result $resultPath
Write-Json $result $finalEvidencePath

$taskEvidence["status"] = if ($decision -eq "PASS") { "completed" } else { "blocked" }
$taskEvidence["result"]["status"] = $result.status
$taskEvidence["result"]["sha256"] = Get-FileSha256 $resultPath
$taskEvidence["final_audit"]["sha256"] = Get-FileSha256 $finalEvidencePath
$taskEvidence["summary"]["sha256"] = Get-FileSha256 $summaryPath
$taskEvidence["checks"] = @($script:checks)
Write-Json $taskEvidence $taskEvidencePath

if (-not $outputsSecretSafe) {
    throw "Sensitive marker detected in RC15 final audit outputs."
}

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    $ids = @($script:blockers | ForEach-Object { $_.id }) -join ", "
    throw "RC15 final closeout blocked: $ids"
}

Write-Host "RC15 final closeout audit ${decision}: $(Get-StablePath $resultPath)"
Write-Host "Checks: $(@($script:checks).Count), blockers: $(@($script:blockers).Count), fail-closed cases: $failClosedCases"
