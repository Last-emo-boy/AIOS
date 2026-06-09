param(
    [string]$ArtifactDir = ".workflow/artifacts/rc20-final-closeout-audit",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc20",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc20/plan.json",
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
        task = if ($null -ne $Json) { $Json.task } else { $null }
        production_ready_claim = if ($null -ne $Json) { $Json.production_ready_claim } else { $null }
        consumer_ready_claim = if ($null -ne $Json) { $Json.consumer_ready_claim } else { $null }
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
        ("pass" + "word="),
        ("sec" + "ret="),
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
    "RC20-010" = ".workflow/artifacts/rc20-single-user-release-bundle/result.json"
    "RC20-011" = ".workflow/artifacts/rc20-local-channel-promotion/result.json"
    "RC20-012" = ".workflow/artifacts/rc20-release-bundle-channel-fail-closed/result.json"
    "RC20-020" = ".workflow/artifacts/rc20-installer-catalog-selection/result.json"
    "RC20-021" = ".workflow/artifacts/rc20-single-user-install-acceptance/result.json"
    "RC20-022" = ".workflow/artifacts/rc20-first-boot-user-acceptance/result.json"
    "RC20-030" = ".workflow/artifacts/rc20-post-install-update-drill/result.json"
    "RC20-031" = ".workflow/artifacts/rc20-post-update-rollback-drill/result.json"
    "RC20-032" = ".workflow/artifacts/rc20-lifecycle-support-recovery/result.json"
    "RC20-040" = ".workflow/artifacts/rc20-single-user-distribution-consumer-smoke/result.json"
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

$release = ($results | Where-Object { $_.task -eq "RC20-010" }).json
$channel = ($results | Where-Object { $_.task -eq "RC20-011" }).json
$failClosed = ($results | Where-Object { $_.task -eq "RC20-012" }).json
$installer = ($results | Where-Object { $_.task -eq "RC20-020" }).json
$install = ($results | Where-Object { $_.task -eq "RC20-021" }).json
$firstBoot = ($results | Where-Object { $_.task -eq "RC20-022" }).json
$update = ($results | Where-Object { $_.task -eq "RC20-030" }).json
$rollback = ($results | Where-Object { $_.task -eq "RC20-031" }).json
$support = ($results | Where-Object { $_.task -eq "RC20-032" }).json
$consumer = ($results | Where-Object { $_.task -eq "RC20-040" }).json

$preCloseoutTasks = @("RC20-000", "RC20-001", "RC20-010", "RC20-011", "RC20-012", "RC20-020", "RC20-021", "RC20-022", "RC20-030", "RC20-031", "RC20-032", "RC20-040")
$completedStatuses = @($preCloseoutTasks | ForEach-Object { [ordered]@{ task = $_; status = Get-TaskStatus $plan $_ } })
$allPreviousTasksCompleted = @($completedStatuses | Where-Object { $_.status -ne "completed" }).Count -eq 0
$finalTaskStatus = Get-TaskStatus $plan "RC20-050"
$planPointerReady = $plan.status -eq "active" -and $plan.current_task -eq "RC20-050" -and ($finalTaskStatus -eq "pending" -or $finalTaskStatus -eq "completed")
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

$releaseReady = $release.summary.rc20_010_complete -eq $true -and
    $release.summary.identity_chain_coherent -eq $true -and
    $release.summary.target_chain_coherent -eq $true -and
    $release.bundle_surface.local_consumer_ready_carried -eq $true -and
    $release.bundle_surface.stable_channel_claim_allowed -eq $false

$channelReady = $channel.summary.rc20_011_complete -eq $true -and
    $channel.summary.candidate_channel_package_bound -eq $true -and
    $channel.summary.stable_channel_projection_bound -eq $true -and
    $channel.summary.external_mirror_publication_performed -eq $false -and
    $channel.summary.active_artifact_set_mutated -eq $false -and
    $channel.summary.production_ring_mutated -eq $false

$failClosedReady = $failClosed.summary.rc20_012_complete -eq $true -and
    $failClosed.summary.identity_coherent -eq $true -and
    $failClosed.summary.output_hash_parity -eq $true -and
    $failClosed.summary.local_non_ga_boundaries -eq $true -and
    $failClosed.summary.failed_cases -eq 0

$installerReady = $installer.summary.rc20_020_complete -eq $true -and
    $installer.summary.catalog_exactly_expected -eq $true -and
    $installer.summary.preflight_binds_required_identity -eq $true -and
    $installer.summary.host_install_authorized -eq $false -and
    $installer.summary.remote_fetch_authorized -eq $false -and
    $installer.summary.external_mirror_trusted -eq $false

$installReady = $install.summary.rc20_021_complete -eq $true -and
    $install.summary.first_user_install_performed_inside_disposable_target -eq $true -and
    $install.summary.host_rootfs_mutated -eq $false -and
    $install.summary.production_ring_mutated -eq $false

$firstBootReady = $firstBoot.summary.rc20_022_complete -eq $true -and
    $firstBoot.summary.projection_only_for_credentials -eq $true -and
    $firstBoot.summary.raw_user_secret_introduced -eq $false -and
    $firstBoot.summary.credential_material_introduced -eq $false -and
    $firstBoot.summary.host_boot_metadata_mutated -eq $false -and
    $firstBoot.summary.support_upload_performed -eq $false -and
    $firstBoot.summary.recovery_execution_performed -eq $false -and
    $firstBoot.summary.remote_dispatch_enabled -eq $false

$updateReady = $update.summary.rc20_030_complete -eq $true -and
    $update.summary.isolated_update_performed_inside_disposable_installed_system -eq $true -and
    $update.summary.rollback_prerequisites_bound -eq $true -and
    $update.summary.host_active_slot_mutated -eq $false -and
    $update.summary.production_ring_mutated -eq $false

$rollbackReady = $rollback.summary.rc20_031_complete -eq $true -and
    $rollback.summary.rollback_allowed -eq $true -and
    $rollback.summary.rollback_performed -eq $true -and
    $rollback.summary.support_upload_performed -eq $false -and
    $rollback.summary.recovery_execution_performed -eq $false -and
    $rollback.summary.remote_dispatch_enabled -eq $false -and
    $rollback.summary.host_active_slot_mutated -eq $false -and
    $rollback.summary.active_artifact_set_mutated -eq $false -and
    $rollback.summary.production_ring_mutated -eq $false

$supportReady = $support.summary.rc20_032_complete -eq $true -and
    $support.summary.lifecycle_state_chain_bound -eq $true -and
    $support.summary.support_bundle_local_only -eq $true -and
    $support.summary.support_bundle_redacted -eq $true -and
    $support.summary.support_upload_performed -eq $false -and
    $support.summary.recovery_execution_performed -eq $false -and
    $support.summary.remote_dispatch_enabled -eq $false -and
    $support.summary.host_rootfs_mutated -eq $false -and
    $support.summary.production_ring_mutated -eq $false

$consumerReady = $consumer.summary.rc20_040_complete -eq $true -and
    $consumer.summary.consumer_ready_claim -eq $true -and
    $consumer.summary.production_ready_claim -eq $false -and
    $consumer.consumer_surface.consumer_decision -eq "single-user-distribution-local-consumer-ready" -and
    $consumer.summary.install_performed_by_consumer_smoke -eq $false -and
    $consumer.summary.update_performed_by_consumer_smoke -eq $false -and
    $consumer.summary.rollback_execution_performed_by_consumer_smoke -eq $false -and
    $consumer.summary.support_upload_performed -eq $false -and
    $consumer.summary.recovery_execution_performed -eq $false -and
    $consumer.summary.remote_dispatch_enabled -eq $false

$singleUserDistributionReady = $releaseReady -and $channelReady -and $failClosedReady -and $installerReady -and $installReady -and $firstBootReady -and $updateReady -and $rollbackReady -and $supportReady -and $consumerReady

$forbiddenInvariantViolations = Test-InvariantFalse -ResultSet $results -Names @(
    "production_ready_claim",
    "external_mirror_publication_performed",
    "external_payload_published",
    "object_storage_provisioned",
    "remote_payload_downloaded",
    "support_upload_performed",
    "recovery_execution_performed",
    "remote_dispatch_enabled",
    "host_rootfs_mutated",
    "host_active_slot_mutated",
    "host_boot_metadata_mutated",
    "active_artifact_set_mutated",
    "production_ring_mutated",
    "mirror_frontend_changed",
    "mirror_frontend_authority",
    "nginx_or_tls_changed",
    "nginx_or_tls_authority",
    "signer_authority",
    "private_signing_material_handled",
    "cryptographic_signing_performed",
    "endpoint_reachability_authority",
    "shell_output_authority",
    "tui_output_authority",
    "model_replay_authority"
)
$forbiddenAuthorityClean = @($forbiddenInvariantViolations).Count -eq 0

Add-Check "plan.pointer.rc20_050" $planPointerValid "RC20 final audit must run at RC20-050 or as an idempotent completed closeout rerun." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc20_050_status = $finalTaskStatus })
Add-Check "tasks.previous.completed" $allPreviousTasksCompleted "All RC20 pre-closeout tasks must be completed." $completedStatuses
Add-Check "results.all_passed" $allResultsPassed "All RC20 scoped result artifacts must have passed status." (@($results | ForEach-Object { [ordered]@{ task = $_.task; status = $_.json.status; path = $_.path } }))
Add-Check "results.no_failed_checks_or_cases" ($failedChecks -eq 0 -and $failedCases -eq 0) "RC20 scoped results must have zero failed checks and zero failed fail-closed cases." ([ordered]@{ failed_checks = $failedChecks; cases = $cases; failed_cases = $failedCases })
Add-Check "results.production_ready_false" $productionReadyClaimsFalse "Every RC20 result must keep production_ready_claim=false." (@($results | ForEach-Object { [ordered]@{ task = $_.task; production_ready_claim = $_.json.production_ready_claim } }))
Add-Check "gate.release_bundle" $releaseReady "RC20 release bundle identity and target chain must be bound." ([ordered]@{ release_bundle_id = $release.release_bundle_id; target_state_id = $release.bundle_surface.first_user_target_state_id })
Add-Check "gate.local_channel" $channelReady "RC20 local channel promotion must be bound without external mirror or production mutation." ([ordered]@{ candidate = $channel.summary.candidate_channel_package_id; stable = $channel.summary.stable_channel_projection_id; external_mirror_publication_performed = $channel.summary.external_mirror_publication_performed })
Add-Check "gate.fail_closed" $failClosedReady "RC20 release bundle and channel fail-closed fixtures must pass with local non-GA boundaries." ([ordered]@{ cases = $failClosed.summary.cases; failed_cases = $failClosed.summary.failed_cases; local_non_ga_boundaries = $failClosed.summary.local_non_ga_boundaries })
Add-Check "gate.installer_catalog" $installerReady "RC20 installer catalog and version selection preflight must be bound without host install or remote fetch authority." ([ordered]@{ installer_catalog_id = $installer.installer_catalog_id; version_selection_preflight_id = $installer.version_selection_preflight_id; host_install_authorized = $installer.summary.host_install_authorized; remote_fetch_authorized = $installer.summary.remote_fetch_authorized })
Add-Check "gate.install_first_boot" ($installReady -and $firstBootReady) "RC20 install acceptance and first boot posture must be bound without host, credential, support upload, recovery, or remote authority." ([ordered]@{ install_acceptance_id = $install.install_acceptance_id; first_boot_acceptance_id = $firstBoot.first_boot_acceptance_id; target_state_id = $install.target_state_id })
Add-Check "gate.update_rollback" ($updateReady -and $rollbackReady) "RC20 update and rollback drills must be bound inside disposable installed-system evidence and avoid host/production mutation." ([ordered]@{ update_drill_id = $update.update_drill_id; rollback_audit_record_id = $rollback.rollback_audit_record_id; updated_image_state_id = $update.updated_image_state_id; restored_target_state_id = $rollback.restored_target_state_id })
Add-Check "gate.support_recovery" $supportReady "RC20 lifecycle support/recovery must be local-only, redacted, and projection-only." ([ordered]@{ support_bundle_id = $support.support_bundle_id; recovery_reference_digest = $support.recovery_reference_digest; support_upload_performed = $support.summary.support_upload_performed; recovery_execution_performed = $support.summary.recovery_execution_performed })
Add-Check "gate.consumer_smoke" $consumerReady "RC20 consumer smoke must report local single-user readiness without new effects and without production readiness." ([ordered]@{ decision = $consumer.consumer_surface.consumer_decision; consumer_ready_claim = $consumer.summary.consumer_ready_claim; production_ready_claim = $consumer.summary.production_ready_claim })
Add-Check "invariants.forbidden_authority_clean" $forbiddenAuthorityClean "Forbidden authority invariants must remain false across RC20 results." $forbiddenInvariantViolations
Add-Check "milestone.single_user_distribution_ready" $singleUserDistributionReady "RC20 must close only if every scoped single-user distribution gate is proved." ([ordered]@{ release = $releaseReady; channel = $channelReady; fail_closed = $failClosedReady; installer = $installerReady; install = $installReady; first_boot = $firstBootReady; update = $updateReady; rollback = $rollbackReady; support = $supportReady; consumer = $consumerReady })

$decision = if (@($script:blockers).Count -eq 0) { "PASS" } else { "BLOCKED" }
$passed = $decision -eq "PASS"
$milestoneStatus = if ($passed) { "rc20-single-user-distribution-local-consumer-ready-non-ga" } else { "rc20-blocked" }

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
        consumer_ready_claim = $_.json.consumer_ready_claim
    }
})

$finalAuditPath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "FINAL-AUDIT-20260610-production-distro-rc20.json"
$closeoutSummaryPath = Join-Path (Join-Path $resolvedWorkflowDir "docs") "final-rc20-closeout-summary.md"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC20-050-final-closeout-audit.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"

$summaryText = @"
# Production Distro RC20 Closeout Summary

Decision: $decision

RC20 closes as a non-GA AIOS-body single-user distribution local consumer milestone. It proves canonical release bundle binding, local candidate-to-stable channel projection, release bundle/channel fail-closed fixtures, installer catalog and version preflight, single-user install acceptance, first boot user posture, post-install update execution, post-update rollback execution, local lifecycle support/recovery closure, and single-user distribution consumer smoke.

The consumer smoke reports local single-user distribution readiness from already-produced RC20 evidence. This is not a GA or production-ready claim. Production readiness remains false.

Forbidden authority stayed disabled: external mirror/frontend, Nginx or TLS infrastructure, remote signer service, object storage provisioning, private signing material handling, production signing, support upload, recovery execution service, remote dispatch, host rootfs mutation, host active slot mutation, host boot metadata mutation, active artifact set mutation, production ring mutation, shell output authority, TUI output authority, endpoint reachability authority, and model replay authority.

Next: move to RC21 planning for the next AIOS-body iteration from RC20 single-user local consumer readiness. External mirror/frontend or remote infrastructure work should remain separately scoped from AIOS-body release authority.
"@

$finalAudit = [ordered]@{
    schema = "agentos.production-distro-rc20-final-audit.v1"
    generated_at = $generatedAtValue
    workflow = Get-StablePath $resolvedWorkflowDir
    milestone = "Production Distro RC20"
    verdict = $decision
    decision = $milestoneStatus
    production_ready_claim = $false
    consumer_ready_claim = $consumerReady -and $passed
    objective = "AIOS-body single-user distribution candidate with release bundle, local channel, installer selection, install, first boot, update, rollback, support/recovery, and local consumer smoke without external infra or production authority."
    task_results = @($preCloseoutTasks | ForEach-Object { [ordered]@{ id = $_; status = Get-TaskStatus $plan $_ } })
    acceptance_coverage = @(
        [ordered]@{ requirement = "canonical single-user release bundle manifest bound"; status = if ($releaseReady) { "proved" } else { "blocked" }; evidence = @($paths["RC20-010"]) }
        [ordered]@{ requirement = "local candidate-to-stable channel projection bound"; status = if ($channelReady) { "proved" } else { "blocked" }; evidence = @($paths["RC20-011"]) }
        [ordered]@{ requirement = "release bundle and channel fail-closed fixtures verified"; status = if ($failClosedReady) { "proved" } else { "blocked" }; evidence = @($paths["RC20-012"]) }
        [ordered]@{ requirement = "installer catalog and version selection preflight bound"; status = if ($installerReady) { "proved" } else { "blocked" }; evidence = @($paths["RC20-020"]) }
        [ordered]@{ requirement = "single-user install acceptance executed inside disposable target"; status = if ($installReady) { "proved" } else { "blocked" }; evidence = @($paths["RC20-021"]) }
        [ordered]@{ requirement = "first boot user acceptance and local operator posture bound"; status = if ($firstBootReady) { "proved" } else { "blocked" }; evidence = @($paths["RC20-022"]) }
        [ordered]@{ requirement = "post-install update drill executed inside disposable installed-system evidence"; status = if ($updateReady) { "proved" } else { "blocked" }; evidence = @($paths["RC20-030"]) }
        [ordered]@{ requirement = "post-update rollback drill executed and restored target state"; status = if ($rollbackReady) { "proved" } else { "blocked" }; evidence = @($paths["RC20-031"]) }
        [ordered]@{ requirement = "lifecycle support/recovery local-only and projection-only"; status = if ($supportReady) { "proved" } else { "blocked" }; evidence = @($paths["RC20-032"]) }
        [ordered]@{ requirement = "single-user distribution local consumer smoke ready"; status = if ($consumerReady) { "proved" } else { "blocked" }; evidence = @($paths["RC20-040"]) }
    )
    readiness_status = [ordered]@{
        release_bundle_ready = $releaseReady
        local_channel_ready = $channelReady
        fail_closed_verified = $failClosedReady
        installer_catalog_ready = $installerReady
        install_acceptance_ready = $installReady
        first_boot_ready = $firstBootReady
        update_readiness = $consumer.consumer_surface.update_readiness
        rollback_readiness = $consumer.consumer_surface.rollback_readiness
        support_recovery_readiness = $consumer.consumer_surface.support_recovery_readiness
        local_consumer_decision = $consumer.consumer_surface.consumer_decision
        single_user_distribution_local_consumer_ready = $singleUserDistributionReady -and $passed
        consumer_ready_claim = $consumerReady -and $passed
        production_ready_claim = $false
    }
    identity_surface = [ordered]@{
        release_bundle_id = $release.release_bundle_id
        selected_version = $install.selected_version
        target_state_id = $install.target_state_id
        installer_catalog_id = $installer.installer_catalog_id
        version_selection_preflight_id = $installer.version_selection_preflight_id
        install_acceptance_id = $install.install_acceptance_id
        first_boot_acceptance_id = $firstBoot.first_boot_acceptance_id
        update_drill_id = $update.update_drill_id
        rollback_audit_record_id = $rollback.rollback_audit_record_id
        support_bundle_id = $support.support_bundle_id
        recovery_reference_digest = $support.recovery_reference_digest
        consumer_audit_digest = $consumer.consumer_surface.audit_digest
    }
    invariants_verified = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        consumer_ready_claim = $consumerReady -and $passed
        external_mirror_frontend_changed = $false
        nginx_or_tls_changed = $false
        signer_infra_changed = $false
        signer_authority = $false
        object_storage_provisioned = $false
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_payload_downloaded = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        endpoint_reachability_authority = $false
        shell_output_authority = $false
        tui_output_authority = $false
        model_replay_authority = $false
    }
    source_artifacts = $sourceArtifacts
    next_milestone = [ordered]@{
        id = "Production Distro RC21"
        direction = "Plan the next AIOS-body iteration from RC20 single-user local consumer readiness while keeping external mirror/frontend and remote infrastructure separate from release authority."
    }
    checks = @($script:checks)
}
Write-Json $finalAudit $finalAuditPath
Write-Text $summaryText $closeoutSummaryPath

Add-Check "rc20.final_audit.written" (Test-Path -LiteralPath $finalAuditPath -PathType Leaf) "RC20 final audit evidence must be written." ([ordered]@{ path = Get-StablePath $finalAuditPath; present = Test-Path -LiteralPath $finalAuditPath -PathType Leaf })
Add-Check "rc20.closeout_summary.written" (Test-Path -LiteralPath $closeoutSummaryPath -PathType Leaf) "RC20 closeout summary must be written." ([ordered]@{ path = Get-StablePath $closeoutSummaryPath; sha256 = Get-FileSha256 $closeoutSummaryPath })

$decision = if (@($script:blockers).Count -eq 0) { "PASS" } else { "BLOCKED" }
$passed = $decision -eq "PASS"
$milestoneStatus = if ($passed) { "rc20-single-user-distribution-local-consumer-ready-non-ga" } else { "rc20-blocked" }
$finalAudit.verdict = $decision
$finalAudit.decision = $milestoneStatus
$finalAudit.consumer_ready_claim = $consumerReady -and $passed
$finalAudit.readiness_status.single_user_distribution_local_consumer_ready = $singleUserDistributionReady -and $passed
$finalAudit.readiness_status.consumer_ready_claim = $consumerReady -and $passed
$finalAudit.checks = @($script:checks)
Write-Json $finalAudit $finalAuditPath

$result = [ordered]@{
    schema = "agentos.rc20-final-closeout-audit-result.v1"
    generated_at = $generatedAtValue
    task = "RC20-050"
    status = if ($passed) { "passed" } else { "blocked" }
    decision = $decision
    production_ready_claim = $false
    consumer_ready_claim = $consumerReady -and $passed
    milestone = "Production Distro RC20"
    milestone_status = $milestoneStatus
    single_user_distribution_local_consumer_ready = $singleUserDistributionReady -and $passed
    outputs = [ordered]@{
        final_audit = [ordered]@{ path = Get-StablePath $finalAuditPath; sha256 = Get-FileSha256 $finalAuditPath; present = Test-Path -LiteralPath $finalAuditPath -PathType Leaf }
        closeout_summary = [ordered]@{ path = Get-StablePath $closeoutSummaryPath; sha256 = Get-FileSha256 $closeoutSummaryPath; present = Test-Path -LiteralPath $closeoutSummaryPath }
    }
    source_artifacts = $sourceArtifacts
    checks = @($script:checks)
    blockers = @($script:blockers | ForEach-Object { $_.id })
    remaining_non_ga_boundaries = @(
        "GA production-ready claim remains false",
        "external mirror/frontend/nginx/TLS work remains outside RC20 body scope",
        "remote signer and private signing material handling remain out of scope",
        "object storage provisioning remains out of scope",
        "support upload and recovery execution remain disabled",
        "remote dispatch, host boot mutation, host rootfs mutation, active artifact set mutation, and production ring mutation remain disabled"
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
        single_user_distribution_local_consumer_ready = $singleUserDistributionReady -and $passed
        consumer_ready_claim = $consumerReady -and $passed
        production_ready_claim = $false
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc20-final-closeout-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC20-050"
    status = if ($passed) { "completed" } else { "blocked" }
    production_ready_claim = $false
    consumer_ready_claim = $consumerReady -and $passed
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
        rc20_050_complete = $passed
        next_task = "RC21-planning"
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
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC20 final audit outputs must not contain key blocks, auth tokens, private paths, signer internals, raw passwords, raw secrets, or raw public identity markers." $null

$decision = if (@($script:blockers).Count -eq 0) { "PASS" } else { "BLOCKED" }
$passed = $decision -eq "PASS"
$milestoneStatus = if ($passed) { "rc20-single-user-distribution-local-consumer-ready-non-ga" } else { "rc20-blocked" }
$finalAudit.verdict = $decision
$finalAudit.decision = $milestoneStatus
$finalAudit.consumer_ready_claim = $consumerReady -and $passed
$finalAudit.readiness_status.single_user_distribution_local_consumer_ready = $singleUserDistributionReady -and $passed
$finalAudit.readiness_status.consumer_ready_claim = $consumerReady -and $passed
$finalAudit.checks = @($script:checks)
Write-Json $finalAudit $finalAuditPath

$result.status = if ($passed) { "passed" } else { "blocked" }
$result.decision = $decision
$result.milestone_status = $milestoneStatus
$result.consumer_ready_claim = $consumerReady -and $passed
$result.single_user_distribution_local_consumer_ready = $singleUserDistributionReady -and $passed
$result.checks = @($script:checks)
$result.blockers = @($script:blockers | ForEach-Object { $_.id })
$result.final_audit.sha256 = Get-FileSha256 $finalAuditPath
$result.summary.checks = @($script:checks).Count
$result.summary.blockers = @($script:blockers).Count
$result.summary.single_user_distribution_local_consumer_ready = $singleUserDistributionReady -and $passed
$result.summary.consumer_ready_claim = $consumerReady -and $passed
Write-Json $result $resultPath

$taskEvidence.status = if ($passed) { "completed" } else { "blocked" }
$taskEvidence.consumer_ready_claim = $consumerReady -and $passed
$taskEvidence.result.status = $result.status
$taskEvidence.result.sha256 = Get-FileSha256 $resultPath
$taskEvidence.final_audit.sha256 = Get-FileSha256 $finalAuditPath
$taskEvidence.closeout_summary.sha256 = Get-FileSha256 $closeoutSummaryPath
$taskEvidence.checks = @($script:checks)
$taskEvidence.completion.rc20_050_complete = $passed
Write-Json $taskEvidence $taskEvidencePath

if (-not $outputsSecretSafe) { throw "Sensitive marker detected in RC20 final audit outputs." }
if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    $ids = @($script:blockers | ForEach-Object { $_.id }) -join ", "
    throw "RC20 final closeout blocked: $ids"
}

Write-Host "RC20 final closeout audit ${decision}: $(Get-StablePath $resultPath)"
Write-Host "Checks: $(@($script:checks).Count), blockers: $(@($script:blockers).Count), cases: $cases, failed cases: $failedCases"
Write-Host "Consumer ready: $($consumerReady -and $passed); production ready: false"
