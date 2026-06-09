param(
    [string]$ArtifactDir = ".workflow/artifacts/rc18-final-closeout-audit",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc18",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc18/plan.json",
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
    $present = Test-Path -LiteralPath $Path -PathType Leaf
    return [ordered]@{
        path = Get-StablePath $Path
        sha256 = Get-FileSha256 $Path
        size_bytes = if ($present) { (Get-Item -LiteralPath $Path).Length } else { $null }
        present = $present
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

function Test-InvariantFalse {
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
        ("." + "local-release-authority/" + "private"),
        ("/etc/" + "aios-signer/" + "private"),
        ("signing" + "-key." + "pem"),
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
    "RC18-010" = ".workflow/artifacts/rc18-disposable-installed-system-boundary/result.json"
    "RC18-011" = ".workflow/artifacts/rc18-installed-system-baseline/result.json"
    "RC18-012" = ".workflow/artifacts/rc18-image-boundary-fail-closed/result.json"
    "RC18-020" = ".workflow/artifacts/rc18-isolated-install-drill/result.json"
    "RC18-021" = ".workflow/artifacts/rc18-isolated-update-drill/result.json"
    "RC18-022" = ".workflow/artifacts/rc18-image-rollback-preconditions/result.json"
    "RC18-030" = ".workflow/artifacts/rc18-isolated-rollback-drill/result.json"
    "RC18-031" = ".workflow/artifacts/rc18-isolated-support-recovery/result.json"
    "RC18-040" = ".workflow/artifacts/rc18-installed-system-consumer-smoke/result.json"
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

$boundary = ($results | Where-Object { $_.task -eq "RC18-010" }).json
$baseline = ($results | Where-Object { $_.task -eq "RC18-011" }).json
$failClosed = ($results | Where-Object { $_.task -eq "RC18-012" }).json
$install = ($results | Where-Object { $_.task -eq "RC18-020" }).json
$update = ($results | Where-Object { $_.task -eq "RC18-021" }).json
$rollbackPreconditions = ($results | Where-Object { $_.task -eq "RC18-022" }).json
$rollback = ($results | Where-Object { $_.task -eq "RC18-030" }).json
$support = ($results | Where-Object { $_.task -eq "RC18-031" }).json
$consumer = ($results | Where-Object { $_.task -eq "RC18-040" }).json

$preCloseoutTasks = @("RC18-000", "RC18-001", "RC18-010", "RC18-011", "RC18-012", "RC18-020", "RC18-021", "RC18-022", "RC18-030", "RC18-031", "RC18-040")
$completedStatuses = @($preCloseoutTasks | ForEach-Object { [ordered]@{ task = $_; status = Get-TaskStatus $plan $_ } })
$allPreviousTasksCompleted = @($completedStatuses | Where-Object { $_.status -ne "completed" }).Count -eq 0
$finalTaskStatus = Get-TaskStatus $plan "RC18-050"
$planPointerReady = $plan.status -eq "active" -and $plan.current_task -eq "RC18-050" -and ($finalTaskStatus -eq "pending" -or $finalTaskStatus -eq "completed")
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

$boundaryReady = $boundary.summary.rc18_010_complete -eq $true -and
    $boundary.summary.image_boundary_bound -eq $true -and
    $boundary.summary.state_root_bound -eq $true -and
    $boundary.summary.rc17_exact_evidence_bound -eq $true -and
    $boundary.summary.image_mutation_performed_before_boundary_bound -eq $false -and
    $boundary.boundary_surface.host_rootfs_mutated -eq $false -and
    $boundary.boundary_surface.host_active_slot_mutated -eq $false -and
    $boundary.boundary_surface.host_boot_metadata_mutated -eq $false -and
    $boundary.boundary_surface.production_ring_mutated -eq $false

$baselineReady = $baseline.summary.rc18_011_complete -eq $true -and
    $baseline.summary.baseline_identity_bound -eq $true -and
    $baseline.summary.boot_state_projection_bound -eq $true -and
    $baseline.summary.agentcore_bound -eq $true -and
    $baseline.summary.security_execution_bound -eq $true -and
    $baseline.summary.rollback_support_bound -eq $true -and
    $baseline.image_local_projection_only -eq $true -and
    $baseline.invariants.boot_state_projection_authoritative_for_host -eq $false -and
    $baseline.baseline_surface.host_rootfs_mutated -eq $false -and
    $baseline.baseline_surface.host_boot_metadata_mutated -eq $false

$failClosedReady = $failClosed.summary.rc18_012_complete -eq $true -and
    $failClosed.summary.side_effect_fail_closed_verified -eq $true -and
    $failClosed.summary.failed_cases -eq 0 -and
    $failClosed.fail_closed_surface.local_only_fixture_execution -eq $true -and
    $failClosed.fail_closed_surface.image_mutation_performed -eq $false -and
    $failClosed.fail_closed_surface.host_rootfs_mutated -eq $false -and
    $failClosed.fail_closed_surface.host_boot_metadata_mutated -eq $false

$installReady = $install.summary.rc18_020_complete -eq $true -and
    $install.summary.isolated_install_allowed -eq $true -and
    $install.summary.isolated_install_performed -eq $true -and
    $install.summary.disposable_image_state_mutated -eq $true -and
    $install.install_surface.image_scope -eq "disposable-installed-system-image-or-vm" -and
    $install.install_surface.image_boundary_bound -eq $true -and
    $install.install_surface.baseline_identity_bound -eq $true -and
    $install.install_surface.host_rootfs_mutated -eq $false -and
    $install.install_surface.host_active_slot_mutated -eq $false -and
    $install.install_surface.host_boot_metadata_mutated -eq $false

$updateReady = $update.summary.rc18_021_complete -eq $true -and
    $update.summary.isolated_update_allowed -eq $true -and
    $update.summary.isolated_update_performed -eq $true -and
    $update.summary.disposable_image_state_mutated -eq $true -and
    $update.previous_installed_image_state_id -eq $install.installed_image_state_id -and
    $update.update_surface.prior_isolated_install_bound -eq $true -and
    $update.update_surface.identity_matches_isolated_install -eq $true -and
    $update.update_surface.host_rootfs_mutated -eq $false -and
    $update.update_surface.host_active_slot_mutated -eq $false -and
    $update.update_surface.host_boot_metadata_mutated -eq $false

$rollbackPreconditionsReady = $rollbackPreconditions.summary.rc18_022_complete -eq $true -and
    $rollbackPreconditions.summary.rollback_preconditions_bound -eq $true -and
    $rollbackPreconditions.summary.post_update_observation_bound -eq $true -and
    $rollbackPreconditions.summary.rollback_execution_allowed -eq $false -and
    $rollbackPreconditions.summary.rollback_execution_performed -eq $false -and
    $rollbackPreconditions.updated_image_state_id -eq $update.updated_image_state_id -and
    $rollbackPreconditions.rollback_precondition_surface.isolated_install_bound -eq $true -and
    $rollbackPreconditions.rollback_precondition_surface.isolated_update_bound -eq $true

$rollbackReady = $rollback.summary.rc18_030_complete -eq $true -and
    $rollback.summary.isolated_rollback_allowed -eq $true -and
    $rollback.summary.isolated_rollback_performed -eq $true -and
    $rollback.summary.disposable_image_state_mutated -eq $true -and
    $rollback.previous_updated_image_state_id -eq $update.updated_image_state_id -and
    $rollback.restored_image_state_id -eq $install.installed_image_state_id -and
    $rollback.rollback_surface.host_rootfs_mutated -eq $false -and
    $rollback.rollback_surface.host_active_slot_mutated -eq $false -and
    $rollback.rollback_surface.host_boot_metadata_mutated -eq $false

$supportReady = $support.summary.rc18_031_complete -eq $true -and
    $support.summary.isolated_install_bound -eq $true -and
    $support.summary.isolated_update_bound -eq $true -and
    $support.summary.isolated_rollback_bound -eq $true -and
    $support.summary.support_bundle_local_only -eq $true -and
    $support.summary.support_bundle_redacted -eq $true -and
    $support.summary.support_upload_performed -eq $false -and
    $support.summary.recovery_execution_performed -eq $false -and
    $support.summary.remote_dispatch_enabled -eq $false

$consumerReady = $consumer.summary.rc18_040_complete -eq $true -and
    $consumer.consumer_surface.local_release_channel_followed -eq $true -and
    $consumer.consumer_surface.consumer_decision -eq "installed-system-image-ready" -and
    $consumer.consumer_surface.install_readiness -eq "ready" -and
    $consumer.consumer_surface.update_readiness -eq "ready" -and
    $consumer.consumer_surface.rollback_readiness -eq "ready" -and
    $consumer.consumer_surface.support_recovery_readiness -eq "ready" -and
    $consumer.consumer_surface.audited -eq $true -and
    $consumer.invariants.install_performed_by_consumer_smoke -eq $false -and
    $consumer.invariants.update_performed_by_consumer_smoke -eq $false -and
    $consumer.invariants.rollback_execution_performed_by_consumer_smoke -eq $false

$stateChainReady = $install.installed_image_state_id -eq $update.previous_installed_image_state_id -and
    $update.updated_image_state_id -eq $rollback.previous_updated_image_state_id -and
    $rollback.restored_image_state_id -eq $install.installed_image_state_id -and
    $support.installed_image_state_id -eq $install.installed_image_state_id -and
    $support.updated_image_state_id -eq $update.updated_image_state_id -and
    $support.restored_image_state_id -eq $rollback.restored_image_state_id -and
    $consumer.installed_image_state_id -eq $install.installed_image_state_id -and
    $consumer.updated_image_state_id -eq $update.updated_image_state_id -and
    $consumer.restored_image_state_id -eq $rollback.restored_image_state_id

$boundaryIdentityBound = $boundary.boundary_id -eq $baseline.boundary_id -and
    $baseline.boundary_id -eq $install.boundary_id -and
    $install.boundary_id -eq $update.boundary_id -and
    $update.boundary_id -eq $rollbackPreconditions.boundary_id -and
    $rollbackPreconditions.boundary_id -eq $rollback.boundary_id -and
    $rollback.boundary_id -eq $support.boundary_id -and
    $support.boundary_id -eq $consumer.boundary_id

$forbiddenInvariantNames = @(
    "mirror_frontend_changed",
    "mirror_frontend_authority",
    "signer_authority",
    "private_signing_material_handled",
    "cryptographic_signing_performed",
    "support_upload_performed",
    "recovery_execution_performed",
    "remote_payload_downloaded",
    "remote_payload_bytes_downloaded",
    "remote_dispatch_enabled",
    "host_rootfs_mutated",
    "active_slot_mutated",
    "boot_metadata_mutated",
    "active_artifact_set_mutated",
    "production_ring_mutated",
    "boot_state_projection_authoritative_for_host",
    "shell_output_authority",
    "tui_output_authority",
    "model_replay_authority",
    "normal_shell_authority",
    "tui_authority"
)
$authorityViolations = Test-InvariantFalse -ResultSet $results -Names $forbiddenInvariantNames

$hostMutationPreserved = $boundary.summary.host_rootfs_mutated -eq $false -and
    $boundary.summary.host_active_slot_mutated -eq $false -and
    $boundary.summary.host_boot_metadata_mutated -eq $false -and
    $baseline.summary.host_boot_metadata_mutated -eq $false -and
    $install.summary.host_rootfs_mutated -eq $false -and
    $install.summary.host_active_slot_mutated -eq $false -and
    $install.summary.host_boot_metadata_mutated -eq $false -and
    $update.summary.host_rootfs_mutated -eq $false -and
    $update.summary.host_active_slot_mutated -eq $false -and
    $update.summary.host_boot_metadata_mutated -eq $false -and
    $rollback.summary.host_rootfs_mutated -eq $false -and
    $rollback.summary.host_active_slot_mutated -eq $false -and
    $rollback.summary.host_boot_metadata_mutated -eq $false -and
    $support.summary.host_rootfs_mutated -eq $false -and
    $support.summary.host_active_slot_mutated -eq $false -and
    $support.summary.host_boot_metadata_mutated -eq $false

$installedSystemImageReady = $boundaryReady -and
    $baselineReady -and
    $failClosedReady -and
    $installReady -and
    $updateReady -and
    $rollbackPreconditionsReady -and
    $rollbackReady -and
    $supportReady -and
    $consumerReady -and
    $stateChainReady -and
    $boundaryIdentityBound

Add-Check "plan.pointer.rc18_050" $planPointerValid "RC18 final audit must run at RC18-050 after RC18-040 completed." ([ordered]@{ plan_status = $plan.status; current_task = $plan.current_task; final_task_status = $finalTaskStatus })
Add-Check "tasks.previous.completed" $allPreviousTasksCompleted "RC18-000 through RC18-040 must be completed before final closeout." $completedStatuses
Add-Check "results.all_passed" $allResultsPassed "All RC18 executable task results must be passed." (@($results | ForEach-Object { [ordered]@{ task = $_.task; status = $_.json.status; path = $_.path } }))
Add-Check "results.failed_checks.zero" ($failedChecks -eq 0 -and $failedCases -eq 0) "RC18 task checks and fail-closed cases must have zero failures." ([ordered]@{ failed_checks = $failedChecks; cases = $cases; failed_cases = $failedCases })
Add-Check "boundary.disposable_image_bound" $boundaryReady "Disposable installed-system image boundary, state root, allowed write surface, and RC17 exact evidence must be bound before image effects." $boundary.boundary_surface
Add-Check "baseline.identity_projection_bound" $baselineReady "Installed-system baseline identity and boot-state projection must be image-local and non-authoritative for host boot state." $baseline.baseline_surface
Add-Check "boundary.fail_closed_verified" $failClosedReady "Image boundary side-effect fixtures must fail closed before image or host mutation." $failClosed.fail_closed_surface
Add-Check "isolated_install.executed_in_image" $installReady "Isolated install drill must execute only inside the disposable image boundary." $install.install_surface
Add-Check "isolated_update.executed_after_install" $updateReady "Isolated update drill must execute after the prior isolated install image state." $update.update_surface
Add-Check "rollback.preconditions_bound" $rollbackPreconditionsReady "Post-update observation and rollback preconditions must be bound inside the image before rollback drill." $rollbackPreconditions.rollback_precondition_surface
Add-Check "isolated_rollback.executed_restored" $rollbackReady "Isolated rollback drill must execute inside the disposable image and restore the installed image state." $rollback.rollback_surface
Add-Check "support_recovery.local_projection_bound" $supportReady "Support/recovery evidence must be local-only, redacted, projection-only, and keep upload/recovery/remote dispatch disabled." $support.support_recovery_surface
Add-Check "consumer_smoke.installed_system_ready" $consumerReady "Installed-system consumer smoke must follow the local release channel and truthfully report install/update/rollback/support readiness without new effects." $consumer.consumer_surface
Add-Check "image_state_chain.bound" $stateChainReady "Install, update, rollback, support, and consumer evidence must bind the same image state chain." ([ordered]@{ installed_image_state_id = $install.installed_image_state_id; updated_image_state_id = $update.updated_image_state_id; restored_image_state_id = $rollback.restored_image_state_id })
Add-Check "boundary.identity.bound_across_rc18" $boundaryIdentityBound "RC18 boundary identity must remain consistent across baseline, install, update, rollback, support, and consumer evidence." ([ordered]@{ boundary_id = $boundary.boundary_id; baseline_id = $baseline.baseline_id; state_root_id = $boundary.state_root_id })
Add-Check "authority.boundaries.preserved" (@($authorityViolations).Count -eq 0 -and $hostMutationPreserved) "RC18 must not broaden mirror/frontend/nginx/signer/object-storage/private-key/support-upload/recovery/remote-dispatch/host-boot/production-ring authority." ([ordered]@{ invariant_violations = $authorityViolations; host_mutation_preserved = $hostMutationPreserved })
Add-Check "production_ready_claim.false" $productionReadyClaimsFalse "RC18 must remain non-GA and must not claim production readiness." $null
Add-Check "installed_system_image.ready_non_ga" $installedSystemImageReady "RC18 may close only as non-GA isolated installed-system image install/update/rollback readiness." ([ordered]@{ installed_system_image_ready = $installedSystemImageReady; production_ready_claim = $false })

$decision = if (@($script:blockers).Count -eq 0) { "PASS" } else { "BLOCKED" }
$passed = $decision -eq "PASS"
$milestoneStatus = if ($passed) { "rc18-isolated-installed-system-image-ready-non-ga" } else { "rc18-blocked" }

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

$finalAuditPath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "FINAL-AUDIT-20260610-production-distro-rc18.json"
$closeoutSummaryPath = Join-Path (Join-Path $resolvedWorkflowDir "docs") "final-rc18-closeout-summary.md"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC18-050-final-closeout-audit.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"

$summaryText = @"
# Production Distro RC18 Closeout Summary

Decision: $decision

RC18 closes as a non-GA AIOS-body isolated installed-system image drill milestone. It proves disposable image boundary binding, installed-system baseline identity, image-boundary fail-closed fixtures, isolated install, isolated update, rollback preconditions, isolated rollback, local-only support/recovery evidence, and installed-system consumer smoke.

RC18 executes install, update, and rollback only inside the disposable installed-system image boundary. Consumer smoke evaluates readiness from the already produced RC18 evidence and does not execute new install, update, rollback, support upload, recovery, remote dispatch, host, production, mirror/frontend, signer, shell, TUI, endpoint, or model-authority effects.

Boundary: production_ready_claim remains false. RC18 did not broaden mirror/frontend, Nginx/TLS, signer, object storage, private signing material handling, support upload, recovery execution, remote dispatch, host rootfs mutation, host active slot mutation, host boot metadata mutation, active artifact set mutation, or production ring mutation.

Next: RC19 should move from isolated installed-system image readiness toward a reproducible installable image artifact and first-user installation path, still AIOS-body-only and without GA or production ring claims.
"@

$finalAudit = [ordered]@{
    schema = "agentos.production-distro-rc18-final-audit.v1"
    generated_at = $generatedAtValue
    workflow = Get-StablePath $resolvedWorkflowDir
    milestone = "Production Distro RC18"
    verdict = $decision
    decision = $milestoneStatus
    production_ready_claim = $false
    objective = "AIOS-body isolated installed-system image install/update/rollback drill readiness, without mirror frontend, nginx/TLS, signer, object storage, private signing material, support upload, recovery execution, remote dispatch, host boot mutation, production ring, shell, TUI, endpoint, or model authority."
    task_results = @($preCloseoutTasks | ForEach-Object { [ordered]@{ id = $_; status = Get-TaskStatus $plan $_ } })
    acceptance_coverage = @(
        [ordered]@{ requirement = "disposable installed-system image boundary and state root bound"; status = if ($boundaryReady) { "proved" } else { "blocked" }; evidence = @($paths["RC18-010"]) }
        [ordered]@{ requirement = "installed-system baseline identity and boot-state projection bound"; status = if ($baselineReady) { "proved" } else { "blocked" }; evidence = @($paths["RC18-011"]) }
        [ordered]@{ requirement = "image-boundary side-effect fail-closed fixtures verified"; status = if ($failClosedReady) { "proved" } else { "blocked" }; evidence = @($paths["RC18-012"]) }
        [ordered]@{ requirement = "isolated installed-system install drill executed"; status = if ($installReady) { "proved" } else { "blocked" }; evidence = @($paths["RC18-020"]) }
        [ordered]@{ requirement = "isolated installed-system update drill executed"; status = if ($updateReady) { "proved" } else { "blocked" }; evidence = @($paths["RC18-021"]) }
        [ordered]@{ requirement = "post-update observation and rollback preconditions bound inside the image"; status = if ($rollbackPreconditionsReady) { "proved" } else { "blocked" }; evidence = @($paths["RC18-022"]) }
        [ordered]@{ requirement = "isolated rollback drill executed and restored installed image state"; status = if ($rollbackReady) { "proved" } else { "blocked" }; evidence = @($paths["RC18-030"]) }
        [ordered]@{ requirement = "support/recovery evidence local-only and projection-only"; status = if ($supportReady) { "proved" } else { "blocked" }; evidence = @($paths["RC18-031"]) }
        [ordered]@{ requirement = "installed-system consumer smoke reports readiness truthfully"; status = if ($consumerReady) { "proved" } else { "blocked" }; evidence = @($paths["RC18-040"]) }
    )
    readiness_status = [ordered]@{
        disposable_image_boundary_bound = $boundaryReady
        baseline_identity_bound = $baselineReady
        image_boundary_fail_closed_verified = $failClosedReady
        isolated_install_performed = $installReady
        isolated_update_performed = $updateReady
        rollback_preconditions_bound = $rollbackPreconditionsReady
        isolated_rollback_performed = $rollbackReady
        support_recovery_local_projection_bound = $supportReady
        local_consumer_smoke_audited = $consumerReady
        local_consumer_decision = $consumer.consumer_surface.consumer_decision
        install_readiness = $consumer.consumer_surface.install_readiness
        update_readiness = $consumer.consumer_surface.update_readiness
        rollback_readiness = $consumer.consumer_surface.rollback_readiness
        support_recovery_readiness = $consumer.consumer_surface.support_recovery_readiness
        installed_system_image_ready = $installedSystemImageReady -and $passed
        production_ready_claim = $false
    }
    execution_surface = [ordered]@{
        boundary_id = $boundary.boundary_id
        state_root_id = $boundary.state_root_id
        baseline_id = $baseline.baseline_id
        installed_image_state_id = $install.installed_image_state_id
        updated_image_state_id = $update.updated_image_state_id
        restored_image_state_id = $rollback.restored_image_state_id
        rollback_precondition_id = $rollbackPreconditions.rollback_precondition_id
        consumer_audit_digest = $consumer.consumer_surface.audit_digest
        isolated_install_performed = $install.summary.isolated_install_performed
        isolated_update_performed = $update.summary.isolated_update_performed
        isolated_rollback_performed = $rollback.summary.isolated_rollback_performed
        disposable_image_state_mutated = $install.summary.disposable_image_state_mutated -and $update.summary.disposable_image_state_mutated -and $rollback.summary.disposable_image_state_mutated
        consumer_executed_new_effects = $false
        support_bundle_local_only = $support.summary.support_bundle_local_only
        support_bundle_redacted = $support.summary.support_bundle_redacted
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
    }
    invariants_verified = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        disposable_image_or_vm_only = $true
        isolated_install_update_rollback_performed = $true
        consumer_smoke_new_effects = $false
        mirror_frontend_changed = $false
        mirror_frontend_authority = $false
        nginx_or_tls_changed = $false
        signer_infra_changed = $false
        signer_authority = $false
        object_storage_infra_changed = $false
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_payload_downloaded = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        normal_shell_authority = $false
        tui_authority = $false
        model_replay_authority = $false
        endpoint_reachability_authority = $false
    }
    source_artifacts = $sourceArtifacts
    next_milestone = [ordered]@{
        id = "Production Distro RC19"
        title = "reproducible installable image artifact and first-user installation path"
        direction = "Move from isolated installed-system image readiness to a reproducible installable image artifact, installer media manifest, first-user install path, and offline/local mirror consumption evidence while preserving non-GA and no production-ring authority."
    }
    checks = @($script:checks)
}

Write-Json $finalAudit $finalAuditPath
Write-Text $summaryText $closeoutSummaryPath

Add-Check "rc18.final_audit.written" (Test-Path -LiteralPath $finalAuditPath -PathType Leaf) "RC18 final audit evidence must be written." ([ordered]@{ path = Get-StablePath $finalAuditPath; present = Test-Path -LiteralPath $finalAuditPath -PathType Leaf })
Add-Check "rc18.closeout_summary.written" (Test-Path -LiteralPath $closeoutSummaryPath -PathType Leaf) "RC18 closeout summary must be written." ([ordered]@{ path = Get-StablePath $closeoutSummaryPath; sha256 = Get-FileSha256 $closeoutSummaryPath })

$decision = if (@($script:blockers).Count -eq 0) { "PASS" } else { "BLOCKED" }
$passed = $decision -eq "PASS"
$milestoneStatus = if ($passed) { "rc18-isolated-installed-system-image-ready-non-ga" } else { "rc18-blocked" }
$finalAudit.verdict = $decision
$finalAudit.decision = $milestoneStatus
$finalAudit.readiness_status.installed_system_image_ready = $installedSystemImageReady -and $passed
$finalAudit.checks = @($script:checks)
Write-Json $finalAudit $finalAuditPath

$result = [ordered]@{
    schema = "agentos.rc18-final-closeout-audit-result.v1"
    generated_at = $generatedAtValue
    task = "RC18-050"
    status = if ($passed) { "passed" } else { "blocked" }
    decision = $decision
    production_ready_claim = $false
    milestone = "Production Distro RC18"
    milestone_status = $milestoneStatus
    installed_system_image_ready = $installedSystemImageReady -and $passed
    install_readiness = $consumer.consumer_surface.install_readiness
    update_readiness = $consumer.consumer_surface.update_readiness
    rollback_readiness = $consumer.consumer_surface.rollback_readiness
    support_recovery_readiness = $consumer.consumer_surface.support_recovery_readiness
    outputs = [ordered]@{
        final_audit = [ordered]@{ path = Get-StablePath $finalAuditPath; sha256 = Get-FileSha256 $finalAuditPath; present = Test-Path -LiteralPath $finalAuditPath -PathType Leaf }
        closeout_summary = [ordered]@{ path = Get-StablePath $closeoutSummaryPath; sha256 = Get-FileSha256 $closeoutSummaryPath; present = Test-Path -LiteralPath $closeoutSummaryPath -PathType Leaf }
    }
    source_artifacts = $sourceArtifacts
    checks = @($script:checks)
    blockers = @($script:blockers | ForEach-Object { $_.id })
    remaining_non_ga_boundaries = @(
        "GA production-ready claim remains false",
        "mirror/frontend/nginx/TLS work remains outside RC18 body scope",
        "remote signer and private signing material handling remain out of scope",
        "object storage provisioning remains out of scope",
        "support upload and recovery execution remain disabled",
        "remote dispatch, host boot mutation, host rootfs mutation, and production ring mutation remain disabled"
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
        installed_system_image_ready = $installedSystemImageReady -and $passed
        production_ready_claim = $false
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc18-final-closeout-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC18-050"
    status = if ($passed) { "completed" } else { "blocked" }
    production_ready_claim = $false
    workflow = Get-StablePath $resolvedWorkflowDir
    script = [ordered]@{
        path = Get-StablePath $scriptPath
        sha256 = Get-FileSha256 $scriptPath
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
        rc18_050_complete = $passed
        next_task = "RC19-planning"
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
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC18 final audit outputs must not contain key blocks, auth tokens, private paths, signer internals, or raw public identity markers." $null

$decision = if (@($script:blockers).Count -eq 0) { "PASS" } else { "BLOCKED" }
$passed = $decision -eq "PASS"
$milestoneStatus = if ($passed) { "rc18-isolated-installed-system-image-ready-non-ga" } else { "rc18-blocked" }
$finalAudit.verdict = $decision
$finalAudit.decision = $milestoneStatus
$finalAudit.readiness_status.installed_system_image_ready = $installedSystemImageReady -and $passed
$finalAudit.checks = @($script:checks)
Write-Json $finalAudit $finalAuditPath

$result.status = if ($passed) { "passed" } else { "blocked" }
$result.decision = $decision
$result.milestone_status = $milestoneStatus
$result.installed_system_image_ready = $installedSystemImageReady -and $passed
$result.checks = @($script:checks)
$result.blockers = @($script:blockers | ForEach-Object { $_.id })
$result.final_audit.sha256 = Get-FileSha256 $finalAuditPath
$result.summary.checks = @($script:checks).Count
$result.summary.blockers = @($script:blockers).Count
$result.summary.installed_system_image_ready = $installedSystemImageReady -and $passed
Write-Json $result $resultPath

$taskEvidence.status = if ($passed) { "completed" } else { "blocked" }
$taskEvidence.result.status = $result.status
$taskEvidence.result.sha256 = Get-FileSha256 $resultPath
$taskEvidence.final_audit.sha256 = Get-FileSha256 $finalAuditPath
$taskEvidence.closeout_summary.sha256 = Get-FileSha256 $closeoutSummaryPath
$taskEvidence.checks = @($script:checks)
$taskEvidence.completion.rc18_050_complete = $passed
Write-Json $taskEvidence $taskEvidencePath

if (-not $outputsSecretSafe) { throw "Sensitive marker detected in RC18 final audit outputs." }
if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    $ids = @($script:blockers | ForEach-Object { $_.id }) -join ", "
    throw "RC18 final closeout blocked: $ids"
}

Write-Host "RC18 final closeout audit ${decision}: $(Get-StablePath $resultPath)"
Write-Host "Checks: $(@($script:checks).Count), blockers: $(@($script:blockers).Count), cases: $cases, failed cases: $failedCases"
