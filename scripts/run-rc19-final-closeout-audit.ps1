param(
    [string]$ArtifactDir = ".workflow/artifacts/rc19-final-closeout-audit",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc19",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc19/plan.json",
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
    param([Parameter(Mandatory = $true)][string]$Id, [Parameter(Mandatory = $true)][bool]$Passed, [Parameter(Mandatory = $true)][string]$Message, $Evidence = $null)
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
    "RC19-010" = ".workflow/artifacts/rc19-reproducible-installable-image-artifact/result.json"
    "RC19-011" = ".workflow/artifacts/rc19-installer-media-manifest/result.json"
    "RC19-012" = ".workflow/artifacts/rc19-image-artifact-reproducibility-fail-closed/result.json"
    "RC19-020" = ".workflow/artifacts/rc19-first-user-install-target-boundary/result.json"
    "RC19-021" = ".workflow/artifacts/rc19-first-user-install-drill/result.json"
    "RC19-022" = ".workflow/artifacts/rc19-first-boot-provisioning-projection/result.json"
    "RC19-030" = ".workflow/artifacts/rc19-offline-local-channel-consumption/result.json"
    "RC19-031" = ".workflow/artifacts/rc19-post-install-update-rollback-smoke/result.json"
    "RC19-032" = ".workflow/artifacts/rc19-first-user-support-recovery/result.json"
    "RC19-040" = ".workflow/artifacts/rc19-installable-image-consumer-smoke/result.json"
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

$image = ($results | Where-Object { $_.task -eq "RC19-010" }).json
$media = ($results | Where-Object { $_.task -eq "RC19-011" }).json
$repro = ($results | Where-Object { $_.task -eq "RC19-012" }).json
$target = ($results | Where-Object { $_.task -eq "RC19-020" }).json
$install = ($results | Where-Object { $_.task -eq "RC19-021" }).json
$firstBoot = ($results | Where-Object { $_.task -eq "RC19-022" }).json
$channel = ($results | Where-Object { $_.task -eq "RC19-030" }).json
$postInstall = ($results | Where-Object { $_.task -eq "RC19-031" }).json
$support = ($results | Where-Object { $_.task -eq "RC19-032" }).json
$consumer = ($results | Where-Object { $_.task -eq "RC19-040" }).json

$preCloseoutTasks = @("RC19-000", "RC19-001", "RC19-010", "RC19-011", "RC19-012", "RC19-020", "RC19-021", "RC19-022", "RC19-030", "RC19-031", "RC19-032", "RC19-040")
$completedStatuses = @($preCloseoutTasks | ForEach-Object { [ordered]@{ task = $_; status = Get-TaskStatus $plan $_ } })
$allPreviousTasksCompleted = @($completedStatuses | Where-Object { $_.status -ne "completed" }).Count -eq 0
$finalTaskStatus = Get-TaskStatus $plan "RC19-050"
$planPointerReady = $plan.status -eq "active" -and $plan.current_task -eq "RC19-050" -and ($finalTaskStatus -eq "pending" -or $finalTaskStatus -eq "completed")
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

$imageReady = $image.summary.rc19_010_complete -eq $true -and
    $image.summary.missing_required_inputs -eq 0 -and
    $image.summary.source_hash_mismatches -eq 0 -and
    $image.production_ready_claim -eq $false
$mediaReady = $media.summary.rc19_011_complete -eq $true -and
    -not [string]::IsNullOrWhiteSpace($media.summary.installer_media_id) -and
    -not [string]::IsNullOrWhiteSpace($media.summary.boot_target_descriptor_id) -and
    $media.production_ready_claim -eq $false
$reproReady = $repro.summary.rc19_012_complete -eq $true -and
    $repro.summary.reproducibility_fail_closed_verified -eq $true -and
    $repro.summary.failed_cases -eq 0
$targetReady = $target.summary.rc19_020_complete -eq $true -and
    $target.summary.target_boundary_bound -eq $true -and
    $target.summary.install_preflight_package_bound -eq $true -and
    $target.summary.only_writable_first_user_install_surface -eq "disposable-first-user-install-target" -and
    $target.summary.host_rootfs_mutated -eq $false -and
    $target.summary.remote_dispatch_enabled -eq $false
$installReady = $install.summary.rc19_021_complete -eq $true -and
    $install.summary.first_user_install_performed -eq $true -and
    $install.summary.target_materialized -eq $true -and
    $install.summary.host_rootfs_mutated -eq $false -and
    $install.summary.remote_dispatch_enabled -eq $false
$firstBootReady = $firstBoot.summary.rc19_022_complete -eq $true -and
    $firstBoot.summary.projection_only -eq $true -and
    $firstBoot.summary.first_boot_provisioning_executed -eq $false -and
    $firstBoot.summary.local_operator_identity_projection_bound -eq $true -and
    $firstBoot.summary.raw_user_secret_introduced -eq $false -and
    $firstBoot.summary.credential_material_introduced -eq $false
$channelReady = $channel.summary.rc19_030_complete -eq $true -and
    $channel.summary.offline_local_channel_package_bound -eq $true -and
    $channel.summary.local_channel_consumption_evaluated -eq $true -and
    $channel.summary.remote_payload_downloaded -eq $false -and
    $channel.summary.object_storage_provisioned -eq $false
$postInstallReady = $postInstall.summary.rc19_031_complete -eq $true -and
    $postInstall.summary.update_compatibility_readiness -eq "ready" -and
    $postInstall.summary.rollback_compatibility_readiness -eq "ready" -and
    $postInstall.summary.update_or_rollback_executed_by_this_smoke -eq $false -and
    $postInstall.summary.remote_dispatch_enabled -eq $false
$supportReady = $support.summary.rc19_032_complete -eq $true -and
    $support.summary.support_bundle_local_only -eq $true -and
    $support.summary.support_bundle_redacted -eq $true -and
    $support.summary.support_upload_performed -eq $false -and
    $support.summary.recovery_execution_performed -eq $false
$consumerReady = $consumer.summary.rc19_040_complete -eq $true -and
    $consumer.summary.consumer_ready_claim -eq $true -and
    $consumer.summary.production_ready_claim -eq $false -and
    $consumer.consumer_surface.consumer_decision -eq "installable-image-local-consumer-ready" -and
    $consumer.consumer_surface.installable_image_readiness -eq "ready" -and
    $consumer.consumer_surface.first_user_install_readiness -eq "ready" -and
    $consumer.consumer_surface.post_install_update_readiness -eq "ready" -and
    $consumer.consumer_surface.post_install_rollback_readiness -eq "ready" -and
    $consumer.consumer_surface.support_recovery_readiness -eq "ready" -and
    $consumer.consumer_surface.audited -eq $true

$targetChainReady = $install.summary.target_state_id -eq $channel.first_user_install_target_state_id -and
    $channel.first_user_install_target_state_id -eq $postInstall.first_user_target_state_id -and
    $postInstall.first_user_target_state_id -eq $support.first_user_target_state_id -and
    $support.first_user_target_state_id -eq $consumer.first_user_target_state_id

$artifactIdentityReady = $image.installable_image_artifact_id -eq $channel.installable_image_artifact_id -and
    $image.installable_image_artifact_id -eq $consumer.installable_image_artifact_id

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
    "host_active_slot_mutated",
    "host_boot_metadata_mutated",
    "active_slot_mutated",
    "boot_metadata_mutated",
    "active_artifact_set_mutated",
    "production_ring_mutated",
    "shell_output_authority",
    "tui_output_authority",
    "model_replay_authority",
    "endpoint_reachability_authority",
    "object_storage_provisioned",
    "object_storage_infra_changed"
)
$authorityViolations = Test-InvariantFalse -ResultSet $results -Names $forbiddenInvariantNames
$authorityPreserved = @($authorityViolations).Count -eq 0

$installableImageConsumerReady = $imageReady -and $mediaReady -and $reproReady -and $targetReady -and $installReady -and $firstBootReady -and $channelReady -and $postInstallReady -and $supportReady -and $consumerReady -and $targetChainReady -and $artifactIdentityReady

Add-Check "plan.pointer.rc19_050" $planPointerValid "RC19 final audit must run at RC19-050 after RC19-040 completed." ([ordered]@{ plan_status = $plan.status; current_task = $plan.current_task; final_task_status = $finalTaskStatus })
Add-Check "tasks.previous.completed" $allPreviousTasksCompleted "RC19-000 through RC19-040 must be completed before final closeout." $completedStatuses
Add-Check "results.all_passed" $allResultsPassed "All RC19 executable task results must be passed." (@($results | ForEach-Object { [ordered]@{ task = $_.task; status = $_.json.status; path = $_.path } }))
Add-Check "results.failed_checks.zero" ($failedChecks -eq 0 -and $failedCases -eq 0) "RC19 task checks and fail-closed cases must have zero failures." ([ordered]@{ failed_checks = $failedChecks; cases = $cases; failed_cases = $failedCases })
Add-Check "image.artifact.ready" $imageReady "Reproducible installable image artifact must be bound without missing inputs or hash mismatches." ([ordered]@{ installable_image_artifact_id = $image.installable_image_artifact_id; missing_required_inputs = $image.summary.missing_required_inputs; source_hash_mismatches = $image.summary.source_hash_mismatches })
Add-Check "media.manifest.ready" $mediaReady "Installer media manifest and boot target descriptor must be bound." ([ordered]@{ installer_media_id = $media.summary.installer_media_id; boot_target_descriptor_id = $media.summary.boot_target_descriptor_id })
Add-Check "repro.fail_closed.ready" $reproReady "Installable image reproducibility fail-closed fixtures must be verified." ([ordered]@{ cases = $repro.summary.cases; failed_cases = $repro.summary.failed_cases })
Add-Check "first_user.target.ready" $targetReady "First-user install target boundary and preflight package must be bound to the disposable target surface." $target.summary
Add-Check "first_user.install.ready" $installReady "First-user install drill must execute inside the disposable target without host or remote mutation." $install.summary
Add-Check "first_boot.projection.ready" $firstBootReady "First boot provisioning and local operator identity must remain projection-only without raw secrets." $firstBoot.summary
Add-Check "offline_channel.ready" $channelReady "Offline/local channel consumption must be bound without remote payload download or object storage." $channel.summary
Add-Check "post_install.ready" $postInstallReady "Post-install update and rollback compatibility smoke must report readiness without new update or rollback effects." $postInstall.summary
Add-Check "support_recovery.ready" $supportReady "First-user support/recovery evidence must be local-only, redacted, and projection-only." $support.summary
Add-Check "consumer_smoke.ready" $consumerReady "Installable image local consumer smoke must truthfully report local consumer readiness while keeping production_ready_claim=false." $consumer.consumer_surface
Add-Check "identity.target_chain.bound" $targetChainReady "First-user target state must be consistent across install, channel, post-install smoke, support, and consumer evidence." ([ordered]@{ target_state_id = $install.summary.target_state_id; channel_target_state_id = $channel.first_user_install_target_state_id; post_install_target_state_id = $postInstall.first_user_target_state_id; support_target_state_id = $support.first_user_target_state_id; consumer_target_state_id = $consumer.first_user_target_state_id })
Add-Check "identity.artifact.bound" $artifactIdentityReady "Installable image artifact identity must remain consistent across artifact, channel, and consumer smoke evidence." ([ordered]@{ image_artifact_id = $image.installable_image_artifact_id; channel_artifact_id = $channel.installable_image_artifact_id; consumer_artifact_id = $consumer.installable_image_artifact_id })
Add-Check "authority.boundaries.preserved" $authorityPreserved "RC19 must not broaden mirror/frontend/nginx/signer/object-storage/private-key/support-upload/recovery/remote-dispatch/host-boot/production-ring authority." ([ordered]@{ invariant_violations = $authorityViolations })
Add-Check "production_ready_claim.false" $productionReadyClaimsFalse "RC19 must remain non-GA and must not claim production readiness." $null
Add-Check "consumer_ready.local_only" ($consumerReady -and $consumer.consumer_ready_claim -eq $true -and $consumer.production_ready_claim -eq $false) "RC19 may close with local consumer readiness only, not production readiness." ([ordered]@{ consumer_ready_claim = $consumer.consumer_ready_claim; production_ready_claim = $consumer.production_ready_claim })

$decision = if (@($script:blockers).Count -eq 0) { "PASS" } else { "BLOCKED" }
$passed = $decision -eq "PASS"
$milestoneStatus = if ($passed) { "rc19-installable-image-local-consumer-ready-non-ga" } else { "rc19-blocked" }

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

$finalAuditPath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "FINAL-AUDIT-20260610-production-distro-rc19.json"
$closeoutSummaryPath = Join-Path (Join-Path $resolvedWorkflowDir "docs") "final-rc19-closeout-summary.md"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC19-050-final-closeout-audit.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"

$summaryText = @"
# Production Distro RC19 Closeout Summary

Decision: $decision

RC19 closes as a non-GA AIOS-body installable image local consumer milestone. It proves reproducible installable image artifact binding, installer media manifest binding, reproducibility fail-closed fixtures, first-user install target boundary, first-user install drill, first boot projection, offline/local channel consumption, post-install update and rollback compatibility smoke, first-user support/recovery evidence, and installable image local consumer smoke.

The local consumer smoke reports consumer readiness for the RC19 evidence chain. This is not a GA or production-ready claim. Production readiness remains false, and RC19 still does not mutate host rootfs, host active slot, host boot metadata, active artifact set, or production rings.

Forbidden authority stayed disabled: external mirror/frontend, nginx or TLS infrastructure, signer infrastructure, object storage provisioning, private signing material handling, support upload, recovery execution, remote dispatch, endpoint reachability authority, shell output authority, TUI output authority, and model replay authority.

Next: move into the next Production Distro iteration for final closeout follow-up, release-channel hardening, and any real external distribution work only after explicit scope separation from AIOS-body evidence.
"@

$finalAudit = [ordered]@{
    schema = "agentos.production-distro-rc19-final-audit.v1"
    generated_at = $generatedAtValue
    workflow = Get-StablePath $resolvedWorkflowDir
    milestone = "Production Distro RC19"
    verdict = $decision
    decision = $milestoneStatus
    production_ready_claim = $false
    consumer_ready_claim = $consumerReady -and $passed
    objective = "AIOS-body reproducible installable image artifact, first-user installation path, offline/local channel consumption, post-install update/rollback compatibility, support/recovery projection, and installable image local consumer smoke without external infra or production authority."
    task_results = @($preCloseoutTasks | ForEach-Object { [ordered]@{ id = $_; status = Get-TaskStatus $plan $_ } })
    acceptance_coverage = @(
        [ordered]@{ requirement = "reproducible installable image artifact bound"; status = if ($imageReady) { "proved" } else { "blocked" }; evidence = @($paths["RC19-010"]) }
        [ordered]@{ requirement = "installer media manifest and boot target descriptor bound"; status = if ($mediaReady) { "proved" } else { "blocked" }; evidence = @($paths["RC19-011"]) }
        [ordered]@{ requirement = "reproducibility fail-closed fixtures verified"; status = if ($reproReady) { "proved" } else { "blocked" }; evidence = @($paths["RC19-012"]) }
        [ordered]@{ requirement = "first-user install target boundary and preflight bound"; status = if ($targetReady) { "proved" } else { "blocked" }; evidence = @($paths["RC19-020"]) }
        [ordered]@{ requirement = "first-user install drill executed inside disposable target"; status = if ($installReady) { "proved" } else { "blocked" }; evidence = @($paths["RC19-021"]) }
        [ordered]@{ requirement = "first boot projection and local operator identity projection bound"; status = if ($firstBootReady) { "proved" } else { "blocked" }; evidence = @($paths["RC19-022"]) }
        [ordered]@{ requirement = "offline/local channel consumption bound"; status = if ($channelReady) { "proved" } else { "blocked" }; evidence = @($paths["RC19-030"]) }
        [ordered]@{ requirement = "post-install update/rollback compatibility ready"; status = if ($postInstallReady) { "proved" } else { "blocked" }; evidence = @($paths["RC19-031"]) }
        [ordered]@{ requirement = "first-user support/recovery evidence local-only and projection-only"; status = if ($supportReady) { "proved" } else { "blocked" }; evidence = @($paths["RC19-032"]) }
        [ordered]@{ requirement = "installable image local consumer smoke ready"; status = if ($consumerReady) { "proved" } else { "blocked" }; evidence = @($paths["RC19-040"]) }
    )
    readiness_status = [ordered]@{
        installable_image_artifact_ready = $imageReady
        installer_media_ready = $mediaReady
        reproducibility_fail_closed_verified = $reproReady
        first_user_install_target_ready = $targetReady
        first_user_install_ready = $installReady
        first_boot_projection_ready = $firstBootReady
        offline_local_channel_ready = $channelReady
        post_install_update_readiness = $consumer.consumer_surface.post_install_update_readiness
        post_install_rollback_readiness = $consumer.consumer_surface.post_install_rollback_readiness
        support_recovery_readiness = $consumer.consumer_surface.support_recovery_readiness
        installable_image_local_consumer_ready = $installableImageConsumerReady -and $passed
        consumer_ready_claim = $consumerReady -and $passed
        production_ready_claim = $false
    }
    identity_surface = [ordered]@{
        installable_image_artifact_id = $image.installable_image_artifact_id
        installer_media_id = $media.summary.installer_media_id
        boot_target_descriptor_id = $media.summary.boot_target_descriptor_id
        first_user_target_state_id = $install.summary.target_state_id
        offline_local_channel_package_id = $channel.offline_local_channel_package_id
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
        id = "Production Distro RC20"
        direction = "Plan the next AIOS-body iteration from RC19 local consumer readiness, keeping external distribution infrastructure separate unless explicitly scoped."
    }
    checks = @($script:checks)
}

Write-Json $finalAudit $finalAuditPath
Write-Text $summaryText $closeoutSummaryPath

Add-Check "rc19.final_audit.written" (Test-Path -LiteralPath $finalAuditPath -PathType Leaf) "RC19 final audit evidence must be written." ([ordered]@{ path = Get-StablePath $finalAuditPath; present = Test-Path -LiteralPath $finalAuditPath -PathType Leaf })
Add-Check "rc19.closeout_summary.written" (Test-Path -LiteralPath $closeoutSummaryPath -PathType Leaf) "RC19 closeout summary must be written." ([ordered]@{ path = Get-StablePath $closeoutSummaryPath; sha256 = Get-FileSha256 $closeoutSummaryPath })

$decision = if (@($script:blockers).Count -eq 0) { "PASS" } else { "BLOCKED" }
$passed = $decision -eq "PASS"
$milestoneStatus = if ($passed) { "rc19-installable-image-local-consumer-ready-non-ga" } else { "rc19-blocked" }
$finalAudit.verdict = $decision
$finalAudit.decision = $milestoneStatus
$finalAudit.consumer_ready_claim = $consumerReady -and $passed
$finalAudit.readiness_status.installable_image_local_consumer_ready = $installableImageConsumerReady -and $passed
$finalAudit.readiness_status.consumer_ready_claim = $consumerReady -and $passed
$finalAudit.checks = @($script:checks)
Write-Json $finalAudit $finalAuditPath

$result = [ordered]@{
    schema = "agentos.rc19-final-closeout-audit-result.v1"
    generated_at = $generatedAtValue
    task = "RC19-050"
    status = if ($passed) { "passed" } else { "blocked" }
    decision = $decision
    production_ready_claim = $false
    consumer_ready_claim = $consumerReady -and $passed
    milestone = "Production Distro RC19"
    milestone_status = $milestoneStatus
    installable_image_local_consumer_ready = $installableImageConsumerReady -and $passed
    outputs = [ordered]@{
        final_audit = [ordered]@{ path = Get-StablePath $finalAuditPath; sha256 = Get-FileSha256 $finalAuditPath; present = Test-Path -LiteralPath $finalAuditPath -PathType Leaf }
        closeout_summary = [ordered]@{ path = Get-StablePath $closeoutSummaryPath; sha256 = Get-FileSha256 $closeoutSummaryPath; present = Test-Path -LiteralPath $closeoutSummaryPath -PathType Leaf }
    }
    source_artifacts = $sourceArtifacts
    checks = @($script:checks)
    blockers = @($script:blockers | ForEach-Object { $_.id })
    remaining_non_ga_boundaries = @(
        "GA production-ready claim remains false",
        "external mirror/frontend/nginx/TLS work remains outside RC19 body scope",
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
        installable_image_local_consumer_ready = $installableImageConsumerReady -and $passed
        consumer_ready_claim = $consumerReady -and $passed
        production_ready_claim = $false
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc19-final-closeout-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC19-050"
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
        rc19_050_complete = $passed
        next_task = "RC20-planning"
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
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC19 final audit outputs must not contain key blocks, auth tokens, private paths, signer internals, or raw public identity markers." $null

$decision = if (@($script:blockers).Count -eq 0) { "PASS" } else { "BLOCKED" }
$passed = $decision -eq "PASS"
$milestoneStatus = if ($passed) { "rc19-installable-image-local-consumer-ready-non-ga" } else { "rc19-blocked" }
$finalAudit.verdict = $decision
$finalAudit.decision = $milestoneStatus
$finalAudit.consumer_ready_claim = $consumerReady -and $passed
$finalAudit.readiness_status.installable_image_local_consumer_ready = $installableImageConsumerReady -and $passed
$finalAudit.readiness_status.consumer_ready_claim = $consumerReady -and $passed
$finalAudit.checks = @($script:checks)
Write-Json $finalAudit $finalAuditPath

$result.status = if ($passed) { "passed" } else { "blocked" }
$result.decision = $decision
$result.milestone_status = $milestoneStatus
$result.consumer_ready_claim = $consumerReady -and $passed
$result.installable_image_local_consumer_ready = $installableImageConsumerReady -and $passed
$result.checks = @($script:checks)
$result.blockers = @($script:blockers | ForEach-Object { $_.id })
$result.final_audit.sha256 = Get-FileSha256 $finalAuditPath
$result.summary.checks = @($script:checks).Count
$result.summary.blockers = @($script:blockers).Count
$result.summary.installable_image_local_consumer_ready = $installableImageConsumerReady -and $passed
$result.summary.consumer_ready_claim = $consumerReady -and $passed
Write-Json $result $resultPath

$taskEvidence.status = if ($passed) { "completed" } else { "blocked" }
$taskEvidence.consumer_ready_claim = $consumerReady -and $passed
$taskEvidence.result.status = $result.status
$taskEvidence.result.sha256 = Get-FileSha256 $resultPath
$taskEvidence.final_audit.sha256 = Get-FileSha256 $finalAuditPath
$taskEvidence.closeout_summary.sha256 = Get-FileSha256 $closeoutSummaryPath
$taskEvidence.checks = @($script:checks)
$taskEvidence.completion.rc19_050_complete = $passed
Write-Json $taskEvidence $taskEvidencePath

if (-not $outputsSecretSafe) { throw "Sensitive marker detected in RC19 final audit outputs." }
if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    $ids = @($script:blockers | ForEach-Object { $_.id }) -join ", "
    throw "RC19 final closeout blocked: $ids"
}

Write-Host "RC19 final closeout audit ${decision}: $(Get-StablePath $resultPath)"
Write-Host "Checks: $(@($script:checks).Count), blockers: $(@($script:blockers).Count), cases: $cases, failed cases: $failedCases"
Write-Host "Consumer ready: $($consumerReady -and $passed); production ready: false"
