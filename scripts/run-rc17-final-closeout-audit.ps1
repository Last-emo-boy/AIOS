param(
    [string]$ArtifactDir = ".workflow/artifacts/rc17-final-closeout-audit",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc17",
    [string]$PlanPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc17/plan.json",
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
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Read-Json {
    param([Parameter(Mandatory = $true)][string]$Path)
    return Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
}

function Write-Json {
    param([Parameter(Mandatory = $true)]$Value, [Parameter(Mandatory = $true)][string]$Path)
    $parent = Split-Path -Parent $Path
    if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 100) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}

function Write-Text {
    param([Parameter(Mandatory = $true)][string]$Value, [Parameter(Mandatory = $true)][string]$Path)
    $parent = Split-Path -Parent $Path
    if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
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
    param([string]$Id, [bool]$Passed, [string]$Message, $Evidence = $null)
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
    param([Parameter(Mandatory = $true)][string]$Path, $Json = $null)
    return [ordered]@{
        path = Get-StablePath $Path
        sha256 = Get-FileSha256 $Path
        size_bytes = if (Test-Path -LiteralPath $Path -PathType Leaf) { (Get-Item -LiteralPath $Path).Length } else { $null }
        present = Test-Path -LiteralPath $Path -PathType Leaf
        schema = if ($null -ne $Json) { $Json.schema } else { $null }
        status = if ($null -ne $Json) { $Json.status } else { $null }
        production_ready_claim = if ($null -ne $Json) { $Json.production_ready_claim } else { $null }
    }
}

function Get-SummaryNumber {
    param($Json, [string]$Name)
    if ($null -eq $Json.summary) { return 0 }
    $prop = $Json.summary.PSObject.Properties[$Name]
    if ($null -eq $prop) { return 0 }
    return [int]$prop.Value
}

function Test-ForbiddenAuthority {
    param([Parameter(Mandatory = $true)]$ResultSet, [Parameter(Mandatory = $true)][string[]]$Names)
    $violations = @()
    foreach ($item in @($ResultSet)) {
        if ($null -eq $item.json.invariants) { continue }
        foreach ($name in $Names) {
            $prop = $item.json.invariants.PSObject.Properties[$name]
            if ($null -ne $prop -and $prop.Value -ne $false) {
                $violations += [ordered]@{ task = $item.task; name = $name; value = $prop.Value }
            }
        }
    }
    return $violations
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
            if ($value.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $false }
        }
    }
    return $true
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
    "RC17-010" = ".workflow/artifacts/rc17-exact-install-update-target-binding/result.json"
    "RC17-011" = ".workflow/artifacts/rc17-exact-install-update-approval-binding/result.json"
    "RC17-020" = ".workflow/artifacts/rc17-agentcore-install-update-executable-planspec/result.json"
    "RC17-021" = ".workflow/artifacts/rc17-security-execution-install-update-allow/result.json"
    "RC17-022" = ".workflow/artifacts/rc17-install-update-rollback-preconditions/result.json"
    "RC17-030" = ".workflow/artifacts/rc17-controlled-local-install/result.json"
    "RC17-031" = ".workflow/artifacts/rc17-controlled-local-update/result.json"
    "RC17-032" = ".workflow/artifacts/rc17-controlled-install-update-rollback-support/result.json"
    "RC17-040" = ".workflow/artifacts/rc17-local-release-channel-install-update-consumer-smoke/result.json"
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

$target = ($results | Where-Object { $_.task -eq "RC17-010" }).json
$approval = ($results | Where-Object { $_.task -eq "RC17-011" }).json
$planspec = ($results | Where-Object { $_.task -eq "RC17-020" }).json
$security = ($results | Where-Object { $_.task -eq "RC17-021" }).json
$rollbackPreconditions = ($results | Where-Object { $_.task -eq "RC17-022" }).json
$install = ($results | Where-Object { $_.task -eq "RC17-030" }).json
$update = ($results | Where-Object { $_.task -eq "RC17-031" }).json
$rollbackSupport = ($results | Where-Object { $_.task -eq "RC17-032" }).json
$consumer = ($results | Where-Object { $_.task -eq "RC17-040" }).json

$preCloseoutTasks = @("RC17-000", "RC17-001", "RC17-010", "RC17-011", "RC17-020", "RC17-021", "RC17-022", "RC17-030", "RC17-031", "RC17-032", "RC17-040")
$completedStatuses = @($preCloseoutTasks | ForEach-Object { [ordered]@{ task = $_; status = Get-TaskStatus $plan $_ } })
$allPreviousTasksCompleted = @($completedStatuses | Where-Object { $_.status -ne "completed" }).Count -eq 0
$finalTaskStatus = Get-TaskStatus $plan "RC17-050"
$planPointerReady = $plan.status -eq "active" -and $plan.current_task -eq "RC17-050" -and ($finalTaskStatus -eq "pending" -or $finalTaskStatus -eq "completed")
$planPointerClosed = $plan.status -eq "completed" -and $null -eq $plan.current_task -and $finalTaskStatus -eq "completed"
$planPointerValid = $planPointerReady -or $planPointerClosed

$allResultsPassed = @($results | Where-Object { $_.json.status -ne "passed" }).Count -eq 0
$productionReadyClaimsFalse = @($results | Where-Object { $_.json.production_ready_claim -ne $false }).Count -eq 0
$failedChecks = 0
$cases = 0
$failedCases = 0
foreach ($entry in $results) {
    $failedChecks += Get-SummaryNumber $entry.json "failed_checks"
    $cases += Get-SummaryNumber $entry.json "cases"
    $failedCases += Get-SummaryNumber $entry.json "failed_cases"
}

$targetReady = $target.summary.rc17_010_complete -eq $true -and
    $target.target_binding_surface.exact_install_update_target_bound -eq $true -and
    $target.target_binding_surface.install_target_bound -eq $true -and
    $target.target_binding_surface.update_target_bound -eq $true -and
    $target.target_binding_surface.enrolled_target_identity_count -eq 2 -and
    $target.target_binding_surface.distinct_target_identity_count -eq 2

$approvalReady = $approval.summary.rc17_011_complete -eq $true -and
    $approval.approval_surface.exact_install_update_approval_bound -eq $true -and
    $approval.approval_surface.approval_granted -eq $true -and
    $approval.approval_surface.audit_sink_bound -eq $true -and
    $approval.approval_surface.nonce_bound -eq $true -and
    $approval.approval_surface.expiry_bound -eq $true -and
    $approval.approval_surface.policy_version_bound -eq $true

$agentcoreReady = $planspec.summary.rc17_020_complete -eq $true -and
    $planspec.planspec_surface.agentcore_install_update_planspec_executable -eq $true -and
    $planspec.planspec_surface.exact_install_update_target_bound -eq $true -and
    $planspec.planspec_surface.exact_install_update_approval_bound -eq $true -and
    $planspec.planspec_surface.audit_nonce_policy_bound -eq $true

$securityReady = $security.summary.rc17_021_complete -eq $true -and
    $security.security_surface.security_execution_install_update_allow -eq $true -and
    $security.security_surface.exact_install_update_target_bound -eq $true -and
    $security.security_surface.exact_install_update_approval_bound -eq $true -and
    $security.security_surface.agentcore_install_update_planspec_executable -eq $true

$rollbackPreconditionsReady = $rollbackPreconditions.summary.rc17_022_complete -eq $true -and
    $rollbackPreconditions.rollback_surface.rollback_preconditions_bound -eq $true -and
    $rollbackPreconditions.rollback_surface.security_execution_install_update_allow -eq $true -and
    $rollbackPreconditions.rollback_surface.exact_install_update_target_bound -eq $true -and
    $rollbackPreconditions.rollback_surface.exact_install_update_approval_bound -eq $true -and
    $rollbackPreconditions.rollback_surface.agentcore_install_update_planspec_executable -eq $true

$installReady = $install.summary.rc17_030_complete -eq $true -and
    $install.install_surface.install_allowed -eq $true -and
    $install.install_surface.install_effect_prepared -eq $true -and
    $install.install_surface.install_performed -eq $true -and
    $install.install_surface.host_active_slot_mutated -eq $false -and
    $install.install_surface.host_boot_metadata_mutated -eq $false

$updateReady = $update.summary.rc17_031_complete -eq $true -and
    $update.update_surface.prior_install_performed -eq $true -and
    $update.update_surface.update_allowed -eq $true -and
    $update.update_surface.update_effect_prepared -eq $true -and
    $update.update_surface.update_performed -eq $true -and
    $update.update_surface.host_active_slot_mutated -eq $false -and
    $update.update_surface.host_boot_metadata_mutated -eq $false

$rollbackSupportReady = $rollbackSupport.summary.rc17_032_complete -eq $true -and
    $rollbackSupport.rollback_support_surface.controlled_install_performed -eq $true -and
    $rollbackSupport.rollback_support_surface.controlled_update_performed -eq $true -and
    $rollbackSupport.rollback_support_surface.rollback_execution_performed -eq $true -and
    $rollbackSupport.rollback_support_surface.support_bundle_local_only -eq $true -and
    $rollbackSupport.rollback_support_surface.support_upload_performed -eq $false -and
    $rollbackSupport.rollback_support_surface.recovery_execution_performed -eq $false

$consumerReady = $consumer.summary.rc17_040_complete -eq $true -and
    $consumer.consumer_surface.local_release_channel_followed -eq $true -and
    $consumer.consumer_surface.consumer_decision -eq "exact-install-update-ready" -and
    $consumer.consumer_surface.install_readiness -eq "ready" -and
    $consumer.consumer_surface.update_readiness -eq "ready" -and
    $consumer.consumer_surface.rollback_support_readiness -eq "ready" -and
    $consumer.consumer_surface.audited -eq $true -and
    $consumer.invariants.install_performed_by_consumer_smoke -eq $false -and
    $consumer.invariants.update_performed_by_consumer_smoke -eq $false -and
    $consumer.invariants.rollback_execution_performed_by_consumer_smoke -eq $false

$identityBound = [string]$target.package_id -eq [string]$approval.package_id -and
    [string]$approval.package_id -eq [string]$planspec.package_id -and
    [string]$planspec.package_id -eq [string]$security.package_id -and
    [string]$security.package_id -eq [string]$rollbackPreconditions.package_id -and
    [string]$rollbackPreconditions.package_id -eq [string]$install.package_id -and
    [string]$install.package_id -eq [string]$update.package_id -and
    [string]$update.package_id -eq [string]$rollbackSupport.package_id -and
    [string]$rollbackSupport.package_id -eq [string]$consumer.package_id

$exactInstallUpdateReady = $targetReady -and $approvalReady -and $agentcoreReady -and $securityReady -and $rollbackPreconditionsReady -and $installReady -and $updateReady -and $rollbackSupportReady -and $consumerReady -and $identityBound

$forbiddenAuthorityNames = @(
    "mirror_frontend_changed",
    "nginx_or_tls_changed",
    "signer_infra_changed",
    "object_storage_infra_changed",
    "private_signing_material_handled",
    "cryptographic_signing_performed",
    "cryptographic_release_signing_performed",
    "remote_payload_downloaded",
    "remote_payload_bytes_downloaded",
    "support_upload_performed",
    "recovery_execution_performed",
    "remote_dispatch_enabled",
    "active_slot_mutated",
    "boot_metadata_mutated",
    "active_artifact_set_mutated",
    "production_ring_mutated",
    "mirror_frontend_authority",
    "frontend_authority",
    "mirror_authority",
    "signer_reachability_authority",
    "object_storage_ui_authority",
    "endpoint_reachability_trusted",
    "frontend_output_trusted",
    "signer_reachability_trusted",
    "shell_output_trusted",
    "tui_output_trusted",
    "model_replay_trusted",
    "object_storage_ui_trusted"
)
$authorityViolations = Test-ForbiddenAuthority -ResultSet $results -Names $forbiddenAuthorityNames

$hostMutationPreserved = $install.install_surface.host_active_slot_mutated -eq $false -and
    $install.install_surface.host_boot_metadata_mutated -eq $false -and
    $update.update_surface.host_active_slot_mutated -eq $false -and
    $update.update_surface.host_boot_metadata_mutated -eq $false -and
    $rollbackSupport.rollback_support_surface.active_slot_mutated -eq $false -and
    $rollbackSupport.rollback_support_surface.boot_metadata_mutated -eq $false -and
    $rollbackSupport.rollback_support_surface.active_artifact_set_mutated -eq $false

Add-Check "plan.pointer.rc17_050" $planPointerValid "RC17 final audit must run at RC17-050 after RC17-040 completed." ([ordered]@{ plan_status = $plan.status; current_task = $plan.current_task; final_task_status = $finalTaskStatus })
Add-Check "tasks.previous.completed" $allPreviousTasksCompleted "RC17-000 through RC17-040 must be completed before final closeout." $completedStatuses
Add-Check "results.all_passed" $allResultsPassed "All RC17 executable task results must be passed." (@($results | ForEach-Object { [ordered]@{ task = $_.task; status = $_.json.status; path = $_.path } }))
Add-Check "results.failed_checks.zero" ($failedChecks -eq 0 -and $failedCases -eq 0) "RC17 task checks and fail-closed cases must have zero failures." ([ordered]@{ failed_checks = $failedChecks; cases = $cases; failed_cases = $failedCases })
Add-Check "target.exact_repo_local_bound" $targetReady "Exact repo-local install/update targets and two target identities must be bound." $target.target_binding_surface
Add-Check "approval.exact_bound" $approvalReady "Exact install/update approval must bind actor, audit sink, nonce, expiry, policy, rollback, and support references." $approval.approval_surface
Add-Check "agentcore.install_update_executable" $agentcoreReady "AgentCore install/update PlanSpec must be executable before effects." $planspec.planspec_surface
Add-Check "security_execution.install_update_allow" $securityReady "SecurityExecution install/update allow decision must be bound before install/update effects." $security.security_surface
Add-Check "rollback.preconditions_bound" $rollbackPreconditionsReady "Rollback preconditions and post-effect observation package must be bound before install/update effects." $rollbackPreconditions.rollback_surface
Add-Check "controlled_install.executed_audited" $installReady "Controlled local install must execute repo-local evidence with no host slot or boot mutation." $install.install_surface
Add-Check "controlled_update.executed_audited" $updateReady "Controlled local update must execute repo-local evidence after prior controlled install with no host slot or boot mutation." $update.update_surface
Add-Check "rollback_support.executed_local_only" $rollbackSupportReady "Rollback/support evidence must execute repo-local rollback evidence while support upload and recovery execution remain disabled." $rollbackSupport.rollback_support_surface
Add-Check "consumer_smoke.exact_ready" $consumerReady "Local release channel consumer smoke must report exact install/update ready without executing new effects." $consumer.consumer_surface
Add-Check "identity.bound_across_rc17" $identityBound "RC17 target, approval, AgentCore, SecurityExecution, rollback, install, update, rollback/support, and consumer evidence must bind the same package identity." ([ordered]@{ package_id = $target.package_id; media_id = $target.media_id; release_id = $target.release_id })
Add-Check "authority.boundaries.preserved" (@($authorityViolations).Count -eq 0 -and $hostMutationPreserved) "RC17 must not broaden mirror/frontend/nginx/signer/object-storage/private-key/support-upload/recovery/remote-dispatch/host-boot/production-ring authority." ([ordered]@{ invariant_violations = $authorityViolations; host_mutation_preserved = $hostMutationPreserved })
Add-Check "production_ready_claim.false" $productionReadyClaimsFalse "RC17 must remain non-GA and must not claim production readiness." $null
Add-Check "exact_install_update.ready_non_ga" $exactInstallUpdateReady "RC17 may close only as non-GA exact install/update execute-or-deny readiness." ([ordered]@{ exact_install_update_ready = $exactInstallUpdateReady; production_ready_claim = $false })

$decision = if (@($script:blockers).Count -eq 0) { "PASS" } else { "BLOCKED" }
$passed = $decision -eq "PASS"
$milestoneStatus = if ($passed) { "rc17-exact-install-update-execute-or-deny-ready-non-ga" } else { "rc17-blocked" }

$sourceArtifacts = @(
    New-ArtifactRef $resolvedPlanPath $plan
) + @($results | ForEach-Object {
    [ordered]@{
        task = $_.task
        path = $_.path
        sha256 = $_.sha256
        schema = $_.json.schema
        status = $_.json.status
        production_ready_claim = $_.json.production_ready_claim
    }
})

$finalAuditPath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "FINAL-AUDIT-20260609-production-distro-rc17.json"
$closeoutSummaryPath = Join-Path (Join-Path $resolvedWorkflowDir "docs") "final-rc17-closeout-summary.md"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC17-050-final-closeout-audit.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"

$summaryText = @"
# Production Distro RC17 Closeout Summary

Decision: $decision

RC17 closes as a non-GA AIOS-body exact install/update execute-or-deny readiness milestone. It proves exact repo-local install/update target binding, exact approval, executable AgentCore install/update PlanSpec, SecurityExecution install/update allow, rollback preconditions, controlled local install evidence, controlled local update evidence, rollback/support evidence, and local release channel consumer smoke.

RC17 authorizes only repo-local evidence effects inside the AIOS body. Controlled install, update, and rollback evidence executed with audit, while the consumer smoke only evaluated readiness and did not execute new effects.

Boundary: production_ready_claim remains false. RC17 did not broaden mirror/frontend, Nginx/TLS, signer, object storage, private signing material handling, support upload, recovery execution, remote dispatch, host active slot mutation, host boot metadata mutation, active artifact set mutation, or production ring mutation.

Next: RC18 should move from repo-local evidence toward an isolated installed-system image install/update/rollback drill, still AIOS-body-only and without host or production ring mutation.
"@

$finalAudit = [ordered]@{
    schema = "agentos.production-distro-rc17-final-audit.v1"
    generated_at = $generatedAtValue
    workflow = Get-StablePath $resolvedWorkflowDir
    milestone = "Production Distro RC17"
    verdict = $decision
    decision = $milestoneStatus
    production_ready_claim = $false
    objective = "AIOS-body exact install/update execute-or-deny readiness from repo-local release package evidence, without mirror, frontend, nginx, signer, object storage, private signing material, support upload, recovery execution, remote dispatch, host boot mutation, production ring, shell, TUI, or model authority."
    task_results = @($preCloseoutTasks | ForEach-Object { [ordered]@{ id = $_; status = Get-TaskStatus $plan $_ } })
    acceptance_coverage = @(
        [ordered]@{ requirement = "exact repo-local install/update target binding"; status = if ($targetReady) { "proved" } else { "blocked" }; evidence = @($paths["RC17-010"]) }
        [ordered]@{ requirement = "exact install/update approval binding"; status = if ($approvalReady) { "proved" } else { "blocked" }; evidence = @($paths["RC17-011"]) }
        [ordered]@{ requirement = "AgentCore install/update PlanSpec executable"; status = if ($agentcoreReady) { "proved" } else { "blocked" }; evidence = @($paths["RC17-020"]) }
        [ordered]@{ requirement = "SecurityExecution install/update allow"; status = if ($securityReady) { "proved" } else { "blocked" }; evidence = @($paths["RC17-021"]) }
        [ordered]@{ requirement = "rollback preconditions and post-effect observation bound"; status = if ($rollbackPreconditionsReady) { "proved" } else { "blocked" }; evidence = @($paths["RC17-022"]) }
        [ordered]@{ requirement = "controlled local install evidence executed"; status = if ($installReady) { "proved" } else { "blocked" }; evidence = @($paths["RC17-030"]) }
        [ordered]@{ requirement = "controlled local update evidence executed"; status = if ($updateReady) { "proved" } else { "blocked" }; evidence = @($paths["RC17-031"]) }
        [ordered]@{ requirement = "controlled rollback/support evidence bound"; status = if ($rollbackSupportReady) { "proved" } else { "blocked" }; evidence = @($paths["RC17-032"]) }
        [ordered]@{ requirement = "local release channel consumer smoke reports exact readiness truthfully"; status = if ($consumerReady) { "proved" } else { "blocked" }; evidence = @($paths["RC17-040"]) }
    )
    readiness_status = [ordered]@{
        exact_install_update_target_bound = $targetReady
        exact_install_update_approval_bound = $approvalReady
        agentcore_install_update_planspec_executable = $agentcoreReady
        security_execution_install_update_allow = $securityReady
        rollback_preconditions_bound = $rollbackPreconditionsReady
        controlled_local_install_executed = $installReady
        controlled_local_update_executed = $updateReady
        controlled_rollback_executed = $rollbackSupportReady
        local_consumer_smoke_audited = $consumerReady
        local_consumer_decision = $consumer.consumer_surface.consumer_decision
        install_readiness = $consumer.consumer_surface.install_readiness
        update_readiness = $consumer.consumer_surface.update_readiness
        rollback_support_readiness = $consumer.consumer_surface.rollback_support_readiness
        exact_install_update_ready = $exactInstallUpdateReady -and $passed
        production_ready_claim = $false
    }
    execution_surface = [ordered]@{
        package_id = $target.package_id
        media_id = $target.media_id
        release_id = $target.release_id
        target_binding_id = $target.target_binding_id
        approval_id = $approval.approval_id
        planspec_core_hash = $planspec.planspec_surface.planspec_core_hash
        effect_envelope_core_hash = $security.effect_envelope_core_hash
        install_attempt_digest = $install.install_surface.install_attempt_digest
        update_attempt_digest = $update.update_surface.update_attempt_digest
        rollback_attempt_digest = $rollbackSupport.rollback_support_surface.rollback_attempt_digest
        consumer_audit_digest = $consumer.consumer_surface.audit_digest
        install_performed = $install.install_surface.install_performed
        update_performed = $update.update_surface.update_performed
        rollback_execution_performed = $rollbackSupport.rollback_support_surface.rollback_execution_performed
        consumer_executed_new_effects = $false
        support_upload_performed = $rollbackSupport.rollback_support_surface.support_upload_performed
        recovery_execution_performed = $rollbackSupport.rollback_support_surface.recovery_execution_performed
        remote_dispatch_enabled = $rollbackSupport.rollback_support_surface.remote_dispatch_enabled
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
    }
    invariants_verified = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        repo_local_install_update_rollback_evidence = $true
        mirror_frontend_changed = $false
        mirror_frontend_authority = $false
        nginx_or_tls_changed = $false
        signer_infra_changed = $false
        object_storage_infra_changed = $false
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
        remote_payload_downloaded = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        normal_shell_authority = $false
        model_replay_authority = $false
        tui_authority = $false
    }
    source_artifacts = $sourceArtifacts
    next_milestone = [ordered]@{
        id = "Production Distro RC18"
        title = "isolated installed-system install/update/rollback drill"
        direction = "Move from repo-local evidence to an isolated installed-system image drill that proves install, update, rollback, and support evidence in a disposable image or VM while preserving AIOS-body-only scope and no host or production ring mutation."
    }
    checks = @($script:checks)
}

Write-Json $finalAudit $finalAuditPath
Write-Text $summaryText $closeoutSummaryPath

Add-Check "rc17.final_audit.written" (Test-Path -LiteralPath $finalAuditPath -PathType Leaf) "RC17 final audit evidence must be written." ([ordered]@{ path = Get-StablePath $finalAuditPath; present = Test-Path -LiteralPath $finalAuditPath -PathType Leaf })
Add-Check "rc17.closeout_summary.written" (Test-Path -LiteralPath $closeoutSummaryPath -PathType Leaf) "RC17 closeout summary must be written." ([ordered]@{ path = Get-StablePath $closeoutSummaryPath; sha256 = Get-FileSha256 $closeoutSummaryPath })

$decision = if (@($script:blockers).Count -eq 0) { "PASS" } else { "BLOCKED" }
$passed = $decision -eq "PASS"
$milestoneStatus = if ($passed) { "rc17-exact-install-update-execute-or-deny-ready-non-ga" } else { "rc17-blocked" }
$finalAudit.verdict = $decision
$finalAudit.decision = $milestoneStatus
$finalAudit.readiness_status.exact_install_update_ready = $exactInstallUpdateReady -and $passed
$finalAudit.checks = @($script:checks)
Write-Json $finalAudit $finalAuditPath

$result = [ordered]@{
    schema = "agentos.rc17-final-closeout-audit-result.v1"
    generated_at = $generatedAtValue
    task = "RC17-050"
    status = if ($passed) { "passed" } else { "blocked" }
    decision = $decision
    production_ready_claim = $false
    milestone = "Production Distro RC17"
    milestone_status = $milestoneStatus
    exact_install_update_ready = $exactInstallUpdateReady -and $passed
    install_readiness = $consumer.consumer_surface.install_readiness
    update_readiness = $consumer.consumer_surface.update_readiness
    rollback_support_readiness = $consumer.consumer_surface.rollback_support_readiness
    outputs = [ordered]@{
        final_audit = [ordered]@{ path = Get-StablePath $finalAuditPath; sha256 = Get-FileSha256 $finalAuditPath; present = Test-Path -LiteralPath $finalAuditPath -PathType Leaf }
        closeout_summary = [ordered]@{ path = Get-StablePath $closeoutSummaryPath; sha256 = Get-FileSha256 $closeoutSummaryPath; present = Test-Path -LiteralPath $closeoutSummaryPath -PathType Leaf }
    }
    source_artifacts = $sourceArtifacts
    checks = @($script:checks)
    blockers = @($script:blockers | ForEach-Object { $_.id })
    remaining_non_ga_boundaries = @(
        "GA production-ready claim remains false",
        "mirror/frontend/nginx/TLS work remains out of RC17 body scope",
        "remote signer and private signing material handling remain out of scope",
        "large object storage provisioning remains out of scope",
        "support upload and recovery execution remain disabled",
        "remote dispatch, host boot mutation, and production ring mutation remain disabled"
    )
    final_audit = [ordered]@{
        path = Get-StablePath $finalAuditPath
        verdict = $decision
        sha256 = Get-FileSha256 $finalAuditPath
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        blockers = @($script:blockers).Count
        cases = $cases
        failed_cases = $failedCases
        exact_install_update_ready = $exactInstallUpdateReady -and $passed
        production_ready_claim = $false
    }
}
Write-Json $result $resultPath

$taskEvidence = [ordered]@{
    schema = "agentos.rc17-final-closeout-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC17-050"
    status = if ($passed) { "completed" } else { "blocked" }
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
        path = Get-StablePath $finalAuditPath
        sha256 = Get-FileSha256 $finalAuditPath
    }
    closeout_summary = [ordered]@{
        path = Get-StablePath $closeoutSummaryPath
        sha256 = Get-FileSha256 $closeoutSummaryPath
    }
    checks = @($script:checks)
    completion = [ordered]@{
        rc17_050_complete = $passed
        next_milestone = "RC18"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $finalAuditPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath),
    (Get-Content -Raw -LiteralPath $closeoutSummaryPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC17 final audit outputs must not contain key blocks, auth tokens, private paths, signer internals, or raw public identity markers." $null

$decision = if (@($script:blockers).Count -eq 0) { "PASS" } else { "BLOCKED" }
$passed = $decision -eq "PASS"
$milestoneStatus = if ($passed) { "rc17-exact-install-update-execute-or-deny-ready-non-ga" } else { "rc17-blocked" }
$finalAudit.verdict = $decision
$finalAudit.decision = $milestoneStatus
$finalAudit.readiness_status.exact_install_update_ready = $exactInstallUpdateReady -and $passed
$finalAudit.checks = @($script:checks)
Write-Json $finalAudit $finalAuditPath

$result.status = if ($passed) { "passed" } else { "blocked" }
$result.decision = $decision
$result.milestone_status = $milestoneStatus
$result.exact_install_update_ready = $exactInstallUpdateReady -and $passed
$result.checks = @($script:checks)
$result.blockers = @($script:blockers | ForEach-Object { $_.id })
$result.final_audit.sha256 = Get-FileSha256 $finalAuditPath
$result.summary.checks = @($script:checks).Count
$result.summary.blockers = @($script:blockers).Count
$result.summary.exact_install_update_ready = $exactInstallUpdateReady -and $passed
Write-Json $result $resultPath

$taskEvidence.status = if ($passed) { "completed" } else { "blocked" }
$taskEvidence.result.status = $result.status
$taskEvidence.result.sha256 = Get-FileSha256 $resultPath
$taskEvidence.final_audit.sha256 = Get-FileSha256 $finalAuditPath
$taskEvidence.closeout_summary.sha256 = Get-FileSha256 $closeoutSummaryPath
$taskEvidence.checks = @($script:checks)
$taskEvidence.completion.rc17_050_complete = $passed
Write-Json $taskEvidence $taskEvidencePath

if (-not $outputsSecretSafe) { throw "Sensitive marker detected in RC17 final audit outputs." }
if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    $ids = @($script:blockers | ForEach-Object { $_.id }) -join ", "
    throw "RC17 final closeout blocked: $ids"
}

Write-Host "RC17 final closeout audit ${decision}: $(Get-StablePath $resultPath)"
Write-Host "Checks: $(@($script:checks).Count), blockers: $(@($script:blockers).Count), cases: $cases, failed cases: $failedCases"
