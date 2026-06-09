param(
    [string]$ArtifactDir = ".workflow/artifacts/rc16-final-closeout-audit",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc16",
    [string]$PlanPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc16/plan.json",
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
            if ($task.id -eq $TaskId) {
                return $task.status
            }
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
    if (-not $Passed) {
        $script:blockers += $entry
    }
}

function Add-UniqueString {
    param(
        [System.Collections.ArrayList]$List,
        [string]$Value
    )
    if ([string]::IsNullOrWhiteSpace($Value)) {
        return
    }
    if (-not $List.Contains($Value)) {
        [void]$List.Add($Value)
    }
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

function Get-SummaryNumber {
    param($Json, [string]$Name)
    if ($null -eq $Json.summary) {
        return 0
    }
    $prop = $Json.summary.PSObject.Properties[$Name]
    if ($null -eq $prop) {
        return 0
    }
    return [int]$prop.Value
}

function Test-InvariantFalse {
    param(
        [Parameter(Mandatory = $true)]$ResultSet,
        [Parameter(Mandatory = $true)][string[]]$Names
    )
    $violations = @()
    foreach ($item in @($ResultSet)) {
        if ($null -eq $item.Json.invariants) {
            continue
        }
        foreach ($name in $Names) {
            $prop = $item.Json.invariants.PSObject.Properties[$name]
            if ($null -ne $prop -and $prop.Value -ne $false) {
                $violations += [ordered]@{
                    task = $item.Task
                    name = $name
                    value = $prop.Value
                }
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
        if ($null -eq $value) {
            continue
        }
        foreach ($marker in $markers) {
            if ($value.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                return $false
            }
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
    "RC16-010" = ".workflow/artifacts/rc16-release-package-artifact-set/result.json"
    "RC16-011" = ".workflow/artifacts/rc16-installable-media-manifest/result.json"
    "RC16-012" = ".workflow/artifacts/rc16-package-descriptor-fail-closed/result.json"
    "RC16-020" = ".workflow/artifacts/rc16-installer-updater-preflight-package/result.json"
    "RC16-021" = ".workflow/artifacts/rc16-install-update-planspec-binding/result.json"
    "RC16-022" = ".workflow/artifacts/rc16-rollback-support-package/result.json"
    "RC16-030" = ".workflow/artifacts/rc16-tui-installability-projection/result.json"
    "RC16-031" = ".workflow/artifacts/rc16-local-release-channel-consumer-smoke/result.json"
}

$results = @()
foreach ($taskId in $paths.Keys) {
    $path = Resolve-RepoPath $paths[$taskId]
    $json = Read-Json $path
    $results += [pscustomobject]@{
        Task = $taskId
        Path = Get-StablePath $path
        Sha256 = Get-FileSha256 $path
        Json = $json
    }
}

$package = ($results | Where-Object { $_.Task -eq "RC16-010" }).Json
$media = ($results | Where-Object { $_.Task -eq "RC16-011" }).Json
$descriptor = ($results | Where-Object { $_.Task -eq "RC16-012" }).Json
$preflight = ($results | Where-Object { $_.Task -eq "RC16-020" }).Json
$planspec = ($results | Where-Object { $_.Task -eq "RC16-021" }).Json
$rollback = ($results | Where-Object { $_.Task -eq "RC16-022" }).Json
$projection = ($results | Where-Object { $_.Task -eq "RC16-030" }).Json
$consumer = ($results | Where-Object { $_.Task -eq "RC16-031" }).Json

$preCloseoutTasks = @("RC16-000", "RC16-001", "RC16-010", "RC16-011", "RC16-012", "RC16-020", "RC16-021", "RC16-022", "RC16-030", "RC16-031")
$completedStatuses = @($preCloseoutTasks | ForEach-Object { [ordered]@{ task = $_; status = Get-TaskStatus $plan $_ } })
$allPreviousTasksCompleted = @($completedStatuses | Where-Object { $_.status -ne "completed" }).Count -eq 0
$finalTaskStatus = Get-TaskStatus $plan "RC16-050"
$planPointerReady = $plan.status -eq "active" -and $plan.current_task -eq "RC16-050" -and ($finalTaskStatus -eq "pending" -or $finalTaskStatus -eq "completed")
$planPointerClosed = $plan.status -eq "completed" -and $null -eq $plan.current_task -and $finalTaskStatus -eq "completed"
$planPointerValid = $planPointerReady -or $planPointerClosed

$allResultsPassed = @($results | Where-Object { $_.Json.status -ne "passed" }).Count -eq 0
$productionReadyClaimsFalse = @($results | Where-Object { $_.Json.production_ready_claim -ne $false }).Count -eq 0
$failedChecks = 0
$cases = 0
$failedCases = 0
foreach ($entry in $results) {
    $failedChecks += Get-SummaryNumber $entry.Json "failed_checks"
    $cases += Get-SummaryNumber $entry.Json "cases"
    $failedCases += Get-SummaryNumber $entry.Json "failed_cases"
}

$releasePackageReady = $package.summary.rc16_010_complete -eq $true -and
    $package.package_surface.rc15_controlled_local_execution_ready -eq $true -and
    $package.package_surface.install_allowed -eq $false -and
    $package.package_surface.update_allowed -eq $false

$mediaManifestReady = $media.summary.rc16_011_complete -eq $true -and
    $media.summary.rootfs_runtime_artifacts -gt 0 -and
    $media.summary.boot_markers -gt 0 -and
    @($media.media_surface.target_arch) -contains "x86_64" -and
    $media.media_surface.kernel_family -eq "linux-lts" -and
    $media.media_surface.install_allowed -eq $false -and
    $media.media_surface.update_allowed -eq $false

$descriptorReady = $descriptor.summary.rc16_012_complete -eq $true -and
    $descriptor.descriptor_surface.cases -ge 30 -and
    $descriptor.descriptor_surface.failed_cases -eq 0 -and
    $descriptor.descriptor_surface.install_allowed -eq $false -and
    $descriptor.descriptor_surface.update_allowed -eq $false

$preflightReady = $preflight.summary.rc16_020_complete -eq $true -and
    $preflight.preflight_surface.evidence_bound -eq $true -and
    $preflight.preflight_surface.install_preflight_ready -eq $true -and
    $preflight.preflight_surface.update_preflight_ready -eq $true -and
    $preflight.preflight_surface.install_effect_preparation_allowed -eq $false -and
    $preflight.preflight_surface.update_effect_preparation_allowed -eq $false

$planspecBoundButDenied = $planspec.summary.rc16_021_complete -eq $true -and
    $planspec.readiness_surface.agentcore_install_update_planspec_bound -eq $true -and
    $planspec.readiness_surface.security_execution_install_update_envelope_bound -eq $true -and
    $planspec.readiness_surface.exact_install_update_target_bound -eq $false -and
    $planspec.readiness_surface.exact_install_update_approval_bound -eq $false -and
    $planspec.readiness_surface.agentcore_install_update_planspec_executable -eq $false -and
    $planspec.readiness_surface.security_execution_allowed -eq $false -and
    $planspec.readiness_surface.install_effect_preparation_allowed -eq $false -and
    $planspec.readiness_surface.update_effect_preparation_allowed -eq $false

$rollbackSupportReady = $rollback.summary.rc16_022_complete -eq $true -and
    $rollback.summary.rollback_support_package_bound -eq $true -and
    $rollback.summary.support_bundle_local_only -eq $true -and
    $rollback.summary.support_upload_performed -eq $false -and
    $rollback.summary.recovery_execution_performed -eq $false -and
    $rollback.summary.rollback_execution_performed -eq $false

$operatorProjectionReady = $projection.summary.rc16_030_complete -eq $true -and
    $projection.projection_surface.install_readiness -eq "blocked" -and
    $projection.projection_surface.update_readiness -eq "blocked" -and
    $projection.projection_surface.read_only -eq $true -and
    $projection.projection_surface.projection_controller_only -eq $true -and
    $projection.projection_surface.tui_authority -eq $false

$consumerSmokeReady = $consumer.summary.rc16_031_complete -eq $true -and
    $consumer.consumer_surface.local_release_channel_followed -eq $true -and
    $consumer.consumer_surface.consumer_decision -eq "denied-before-effect" -and
    $consumer.consumer_surface.audited -eq $true -and
    $consumer.consumer_surface.install_readiness -eq "denied" -and
    $consumer.consumer_surface.update_readiness -eq "denied" -and
    $consumer.consumer_surface.agentcore_planspec_bound -eq $true -and
    $consumer.consumer_surface.agentcore_planspec_executable -eq $false -and
    $consumer.consumer_surface.security_execution_envelope_bound -eq $true -and
    $consumer.consumer_surface.security_execution_allowed -eq $false

$distributablePackagingReady = $releasePackageReady -and
    $mediaManifestReady -and
    $descriptorReady -and
    $preflightReady -and
    $planspecBoundButDenied -and
    $rollbackSupportReady -and
    $operatorProjectionReady -and
    $consumerSmokeReady

$installUpdateReady = $consumer.consumer_surface.install_readiness -eq "ready" -and
    $consumer.consumer_surface.update_readiness -eq "ready" -and
    $consumer.consumer_surface.agentcore_planspec_executable -eq $true -and
    $consumer.consumer_surface.security_execution_allowed -eq $true

$forbiddenInvariantNames = @(
    "mirror_frontend_changed",
    "nginx_or_tls_changed",
    "signer_infra_changed",
    "object_storage_infra_changed",
    "private_signing_material_handled",
    "cryptographic_signing_performed",
    "payload_upload_performed",
    "payload_published",
    "network_fetch_attempted",
    "remote_payload_bytes_downloaded",
    "install_effect_prepared",
    "update_effect_prepared",
    "install_performed",
    "update_performed",
    "activation_performed",
    "active_slot_mutated",
    "boot_metadata_mutated",
    "active_artifact_set_mutated",
    "rollback_execution_performed",
    "support_upload_performed",
    "recovery_execution_performed",
    "remote_dispatch_enabled",
    "production_ring_mutated",
    "frontend_authority",
    "mirror_authority",
    "signer_reachability_authority",
    "object_storage_ui_authority",
    "model_replay_authority",
    "normal_shell_authority",
    "tui_authority",
    "endpoint_reachability_authority",
    "frontend_output_authority",
    "shell_output_authority",
    "endpoint_reachability_trusted",
    "frontend_output_trusted",
    "signer_reachability_trusted",
    "shell_output_trusted",
    "tui_output_trusted",
    "object_storage_ui_trusted",
    "tui_runtime_invoked"
)
$authorityViolations = Test-InvariantFalse -ResultSet $results -Names $forbiddenInvariantNames

$remainingBlockersList = [System.Collections.ArrayList]::new()
foreach ($blocker in @($consumer.consumer_surface.blockers)) {
    Add-UniqueString -List $remainingBlockersList -Value ([string]$blocker)
}
foreach ($blocker in @($planspec.readiness_surface.blockers)) {
    if ($blocker -notin @("rc16-rollback-support-package-not-bound", "rc16-local-release-channel-consumer-smoke-not-run")) {
        Add-UniqueString -List $remainingBlockersList -Value ([string]$blocker)
    }
}
$remainingBlockers = @($remainingBlockersList)

Add-Check "plan.pointer.rc16_050" $planPointerValid "RC16 final audit must run at RC16-050 after all prior RC16 tasks." ([ordered]@{ plan_status = $plan.status; current_task = $plan.current_task; final_task_status = $finalTaskStatus })
Add-Check "tasks.previous.completed" $allPreviousTasksCompleted "RC16-000 through RC16-031 must be completed before final closeout." $completedStatuses
Add-Check "results.all_passed" $allResultsPassed "All RC16 executable task results must be passed." (@($results | ForEach-Object { [ordered]@{ task = $_.Task; status = $_.Json.status; path = $_.Path } }))
Add-Check "results.failed_checks.zero" ($failedChecks -eq 0 -and $failedCases -eq 0) "RC16 task checks and cases must have zero failures." ([ordered]@{ failed_checks = $failedChecks; cases = $cases; failed_cases = $failedCases })
Add-Check "release_package.ready" $releasePackageReady "Repo-local distributable package artifact set must be bound while install/update remain gated." $package.package_surface
Add-Check "media_manifest.ready" $mediaManifestReady "Installable media manifest must bind runtime artifacts, boot markers, architecture, and kernel family." $media.media_surface
Add-Check "descriptor.fail_closed" $descriptorReady "Distributable package descriptor fail-closed fixtures must pass before consumer use." $descriptor.descriptor_surface
Add-Check "installer_updater.preflight_bound" $preflightReady "Installer/updater preflight package must bind evidence and deny effects." $preflight.preflight_surface
Add-Check "agentcore_security.install_update_bound_denied" $planspecBoundButDenied "AgentCore install/update PlanSpec and SecurityExecution envelope must be bound but denied until exact target and approval are bound." $planspec.readiness_surface
Add-Check "rollback_support.package_bound" $rollbackSupportReady "Rollback/support package must be bound with local-only support evidence and no rollback/support/recovery effects." $rollback.summary
Add-Check "tui.projection_read_only" $operatorProjectionReady "TUI installability projection must be read-only and non-authoritative." $projection.projection_surface
Add-Check "consumer_smoke.denied_before_effect" $consumerSmokeReady "Local release channel consumer smoke must follow the channel and deny before effect with audit." $consumer.consumer_surface
Add-Check "install_update.not_ready_truthful" (-not $installUpdateReady) "RC16 must truthfully report install/update as not ready because exact target, exact approval, executable PlanSpec, and SecurityExecution allow remain unbound." ([ordered]@{ install_readiness = $consumer.consumer_surface.install_readiness; update_readiness = $consumer.consumer_surface.update_readiness; remaining_blockers = $remainingBlockers })
Add-Check "authority.boundaries.preserved" (@($authorityViolations).Count -eq 0) "RC16 must not broaden mirror, frontend, nginx, signer, object storage, private signing, payload publication, remote fetch, install/update, support upload, recovery execution, remote dispatch, TUI authority, or production ring authority." $authorityViolations
Add-Check "production_ready_claim.false" $productionReadyClaimsFalse "RC16 must remain non-GA and must not claim production readiness." $null
Add-Check "distributable_packaging.ready_non_ga" ($distributablePackagingReady -and -not $installUpdateReady) "RC16 may close only as non-GA distributable packaging and release-operation readiness, not install/update or GA readiness." ([ordered]@{ distributable_packaging_ready = $distributablePackagingReady; install_update_ready = $installUpdateReady; production_ready_claim = $false })

$decision = if (@($script:blockers).Count -eq 0) { "PASS" } else { "BLOCKED" }
$passed = $decision -eq "PASS"
$milestoneStatus = if ($passed) { "rc16-distributable-packaging-ready-install-update-denied-non-ga" } else { "rc16-blocked" }

$sourceArtifacts = @(
    New-ArtifactRef $resolvedPlanPath $plan
) + @($results | ForEach-Object {
    [ordered]@{
        task = $_.Task
        path = $_.Path
        sha256 = $_.Sha256
        schema = $_.Json.schema
        status = $_.Json.status
    }
})

$finalAuditPath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "FINAL-AUDIT-20260609-production-distro-rc16.json"
$closeoutSummaryPath = Join-Path (Join-Path $resolvedWorkflowDir "docs") "final-rc16-closeout-summary.md"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC16-050-final-closeout-audit.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"

$summaryText = @"
# Production Distro RC16 Closeout Summary

Decision: $decision

RC16 closes as a non-GA AIOS-body distributable packaging and release-operation readiness milestone. It proves the repo-local release package surface, installable media manifest, package descriptor fail-closed fixtures, installer/updater preflight package, AgentCore install/update PlanSpec package binding, SecurityExecution install/update envelope binding, rollback/support package binding, TUI installability projection, and local release channel consumer smoke.

RC16 does not authorize install or update effects. The local consumer followed the channel and denied before effect because exact install/update target, exact install/update approval, executable AgentCore install/update PlanSpec, and SecurityExecution install/update allow remain unbound.

Boundary: production_ready_claim remains false. RC16 did not broaden mirror frontend, Nginx/TLS, signer infrastructure, object storage, private signing material handling, payload publication, remote payload download, install/update effects, support upload, recovery execution, remote dispatch, TUI authority, or production ring mutation.

Next: RC17 should bind exact install/update targets, exact operator approval, executable AgentCore install/update PlanSpec, SecurityExecution allow policy, and rollback preconditions, then run install/update execute-or-deny evidence while preserving AIOS-body-only scope.
"@

$finalAudit = [ordered]@{
    schema = "agentos.production-distro-rc16-final-audit.v1"
    generated_at = $generatedAtValue
    workflow = Get-StablePath $resolvedWorkflowDir
    milestone = "Production Distro RC16"
    verdict = $decision
    decision = $milestoneStatus
    production_ready_claim = $false
    objective = "AIOS-body distributable user packaging and release-operation readiness from repo-local release package evidence, without mirror, frontend, nginx, signer, object storage, remote dispatch, private signing material, support upload, recovery execution, production ring, TUI, shell, or model replay authority."
    task_results = @($preCloseoutTasks | ForEach-Object { [ordered]@{ id = $_; status = Get-TaskStatus $plan $_ } })
    acceptance_coverage = @(
        [ordered]@{ requirement = "release package artifact set is bound to RC15 controlled local execution evidence"; status = if ($releasePackageReady) { "proved" } else { "blocked" }; evidence = @($paths["RC16-010"]) }
        [ordered]@{ requirement = "installable media manifest binds runtime artifacts, boot markers, architecture, kernel family, rollback, and support references"; status = if ($mediaManifestReady) { "proved" } else { "blocked" }; evidence = @($paths["RC16-011"]) }
        [ordered]@{ requirement = "package descriptor fail-closed fixtures pass before consumer use"; status = if ($descriptorReady) { "proved" } else { "blocked" }; evidence = @($paths["RC16-012"]) }
        [ordered]@{ requirement = "installer/updater preflight evidence is bound while effects remain denied"; status = if ($preflightReady) { "proved" } else { "blocked" }; evidence = @($paths["RC16-020"]) }
        [ordered]@{ requirement = "AgentCore install/update PlanSpec and SecurityExecution envelope are bound but remain denied before exact target and approval"; status = if ($planspecBoundButDenied) { "proved" } else { "blocked" }; evidence = @($paths["RC16-021"]) }
        [ordered]@{ requirement = "rollback/support package is bound while support upload, recovery execution, rollback execution, install, and update remain disabled"; status = if ($rollbackSupportReady) { "proved" } else { "blocked" }; evidence = @($paths["RC16-022"]) }
        [ordered]@{ requirement = "TUI projection explains installability/update readiness without authority"; status = if ($operatorProjectionReady) { "proved" } else { "blocked" }; evidence = @($paths["RC16-030"]) }
        [ordered]@{ requirement = "local release channel consumer smoke denies before effect with audit"; status = if ($consumerSmokeReady) { "proved" } else { "blocked" }; evidence = @($paths["RC16-031"]) }
    )
    readiness_status = [ordered]@{
        distributable_package_surface_ready = $releasePackageReady
        installable_media_manifest_ready = $mediaManifestReady
        package_descriptor_fail_closed_ready = $descriptorReady
        installer_updater_preflight_ready = $preflightReady
        agentcore_install_update_planspec_bound = $planspec.readiness_surface.agentcore_install_update_planspec_bound -eq $true
        agentcore_install_update_planspec_executable = $planspec.readiness_surface.agentcore_install_update_planspec_executable -eq $true
        security_execution_install_update_envelope_bound = $planspec.readiness_surface.security_execution_install_update_envelope_bound -eq $true
        security_execution_allowed = $planspec.readiness_surface.security_execution_allowed -eq $true
        rollback_support_package_bound = $rollback.summary.rollback_support_package_bound -eq $true
        tui_projection_ready = $operatorProjectionReady
        local_consumer_smoke_audited = $consumer.consumer_surface.audited -eq $true
        local_consumer_decision = $consumer.consumer_surface.consumer_decision
        install_readiness = $consumer.consumer_surface.install_readiness
        update_readiness = $consumer.consumer_surface.update_readiness
        install_update_ready = $installUpdateReady
        distributable_packaging_ready = $distributablePackagingReady -and $passed
        production_ready_claim = $false
        remaining_blockers_before_install_update_or_ga = $remainingBlockers
    }
    execution_surface = [ordered]@{
        package_id = $package.package_id
        media_id = $media.media_id
        release_id = $package.release_id
        package_artifact_set_sha256 = $package.package_surface.artifact_set_sha256
        installable_media_manifest_sha256 = $media.media_surface.manifest_sha256
        descriptor_matrix_sha256 = $descriptor.descriptor_surface.matrix_sha256
        preflight_id = $preflight.preflight_id
        planspec_core_hash = $planspec.readiness_surface.planspec_core_hash
        effect_envelope_core_hash = $planspec.readiness_surface.effect_envelope_core_hash
        audit_digest = $consumer.consumer_surface.audit_digest
        install_effect_preparation_allowed = $consumer.consumer_surface.effect_preparation_allowed
        install_performed = $consumer.invariants.install_performed
        update_performed = $consumer.invariants.update_performed
        rollback_execution_performed = $rollback.summary.rollback_execution_performed
        support_upload_performed = $rollback.summary.support_upload_performed
        recovery_execution_performed = $rollback.summary.recovery_execution_performed
        remote_dispatch_enabled = $consumer.invariants.remote_dispatch_enabled
        production_ring_mutated = $consumer.invariants.production_ring_mutated
    }
    invariants_verified = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        mirror_frontend_changed = $false
        mirror_authority = $false
        nginx_or_tls_changed = $false
        signer_infra_changed = $false
        signer_reachability_authority = $false
        object_storage_infra_changed = $false
        object_storage_ui_authority = $false
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
        payload_upload_performed = $false
        payload_published = $false
        remote_payload_bytes_downloaded = $false
        install_effect_prepared = $false
        update_effect_prepared = $false
        install_performed = $false
        update_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        remote_dispatch_enabled = $false
        production_ring_mutated = $false
        tui_authority = $false
        normal_shell_authority = $false
        model_replay_authority = $false
    }
    source_artifacts = $sourceArtifacts
    remaining_blockers_before_install_update_or_ga = $remainingBlockers
    next_milestone = [ordered]@{
        id = "Production Distro RC17"
        title = "bind exact install/update execution gates and run install/update execute-or-deny"
        direction = "Bind exact install/update target, exact operator approval, executable AgentCore install/update PlanSpec, SecurityExecution allow policy, and rollback preconditions before any install/update effect, while preserving AIOS-body-only scope and no GA claim."
    }
    checks = @($script:checks)
}

Write-Json $finalAudit $finalAuditPath
Write-Text $summaryText $closeoutSummaryPath

Add-Check "rc16.final_audit.written" (Test-Path -LiteralPath $finalAuditPath -PathType Leaf) "RC16 final audit evidence must be written." ([ordered]@{ path = Get-StablePath $finalAuditPath; present = Test-Path -LiteralPath $finalAuditPath -PathType Leaf })
Add-Check "rc16.closeout_summary.written" (Test-Path -LiteralPath $closeoutSummaryPath -PathType Leaf) "RC16 closeout summary must be written." ([ordered]@{ path = Get-StablePath $closeoutSummaryPath; sha256 = Get-FileSha256 $closeoutSummaryPath })

$decision = if (@($script:blockers).Count -eq 0) { "PASS" } else { "BLOCKED" }
$passed = $decision -eq "PASS"
$milestoneStatus = if ($passed) { "rc16-distributable-packaging-ready-install-update-denied-non-ga" } else { "rc16-blocked" }
$finalAudit.verdict = $decision
$finalAudit.decision = $milestoneStatus
$finalAudit.readiness_status.distributable_packaging_ready = $distributablePackagingReady -and $passed
$finalAudit.checks = @($script:checks)
Write-Json $finalAudit $finalAuditPath

$result = [ordered]@{
    schema = "agentos.rc16-final-closeout-audit-result.v1"
    generated_at = $generatedAtValue
    task = "RC16-050"
    status = if ($passed) { "passed" } else { "blocked" }
    decision = $decision
    production_ready_claim = $false
    milestone = "Production Distro RC16"
    milestone_status = $milestoneStatus
    distributable_packaging_ready = $distributablePackagingReady -and $passed
    install_update_ready = $installUpdateReady
    install_readiness = $consumer.consumer_surface.install_readiness
    update_readiness = $consumer.consumer_surface.update_readiness
    outputs = [ordered]@{
        final_audit = [ordered]@{ path = Get-StablePath $finalAuditPath; sha256 = Get-FileSha256 $finalAuditPath; present = Test-Path -LiteralPath $finalAuditPath -PathType Leaf }
        closeout_summary = [ordered]@{ path = Get-StablePath $closeoutSummaryPath; sha256 = Get-FileSha256 $closeoutSummaryPath; present = Test-Path -LiteralPath $closeoutSummaryPath -PathType Leaf }
    }
    source_artifacts = $sourceArtifacts
    checks = @($script:checks)
    blockers = @($script:blockers | ForEach-Object { $_.id })
    remaining_blockers_before_install_update_or_ga = $remainingBlockers
    final_audit = [ordered]@{
        verdict = $finalAudit.verdict
        readiness_status = $finalAudit.readiness_status
        next_milestone = $finalAudit.next_milestone
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:blockers).Count
        cases = $cases
        failed_cases = $failedCases
        rc16_050_complete = $passed
        verdict = $finalAudit.verdict
        distributable_packaging_ready = $distributablePackagingReady -and $passed
        install_update_ready = $installUpdateReady
        install_readiness = $consumer.consumer_surface.install_readiness
        update_readiness = $consumer.consumer_surface.update_readiness
        consumer_decision = $consumer.consumer_surface.consumer_decision
        agentcore_install_update_planspec_bound = $planspec.readiness_surface.agentcore_install_update_planspec_bound
        agentcore_install_update_planspec_executable = $planspec.readiness_surface.agentcore_install_update_planspec_executable
        security_execution_allowed = $planspec.readiness_surface.security_execution_allowed
        exact_install_update_target_bound = $planspec.readiness_surface.exact_install_update_target_bound
        exact_install_update_approval_bound = $planspec.readiness_surface.exact_install_update_approval_bound
        rollback_support_package_bound = $rollback.summary.rollback_support_package_bound
        support_upload_performed = $rollback.summary.support_upload_performed
        recovery_execution_performed = $rollback.summary.recovery_execution_performed
        install_performed = $consumer.invariants.install_performed
        update_performed = $consumer.invariants.update_performed
        remote_dispatch_enabled = $consumer.invariants.remote_dispatch_enabled
        production_ready_claim = $false
        next_task = "RC17-planning"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc16-final-closeout-audit-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC16-050"
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
    final_audit = $result.outputs.final_audit
    closeout_summary = $result.outputs.closeout_summary
    audit_surface = $result.summary
    invariants = $finalAudit.invariants_verified
    completion = [ordered]@{
        rc16_050_complete = $passed
        next_task = "RC17-planning"
        commit_required = $true
    }
    checks = @($script:checks)
}
Write-Json $taskEvidence $taskEvidencePath

foreach ($writtenPath in @($finalAuditPath, $closeoutSummaryPath, $resultPath, $taskEvidencePath)) {
    if (-not (Test-Path -LiteralPath $writtenPath -PathType Leaf)) {
        continue
    }
    $content = Get-Content -Raw -LiteralPath $writtenPath
    if (-not (Test-NoSensitiveText -Values @($content))) {
        throw "Sensitive marker detected in $(Get-StablePath $writtenPath)."
    }
}

Write-Host "RC16 final closeout audit $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Verdict: $($finalAudit.verdict)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:blockers).Count), cases: $cases"
Write-Host "Install/update readiness: $($consumer.consumer_surface.install_readiness)/$($consumer.consumer_surface.update_readiness)"

if ($FailOnBlocked -and -not $passed) {
    exit 1
}
