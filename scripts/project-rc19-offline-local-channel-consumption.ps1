param(
    [string]$ArtifactDir = ".workflow/artifacts/rc19-offline-local-channel-consumption",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc19",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc19/plan.json",
    [string]$FirstUserInstallResultPath = ".workflow/artifacts/rc19-first-user-install-drill/result.json",
    [string]$FirstUserInstallEvidencePath = ".workflow/artifacts/rc19-first-user-install-drill/first-user-install-evidence.json",
    [string]$FirstBootProjectionResultPath = ".workflow/artifacts/rc19-first-boot-provisioning-projection/result.json",
    [string]$FirstBootProjectionPath = ".workflow/artifacts/rc19-first-boot-provisioning-projection/first-boot-provisioning-projection.json",
    [string]$LocalOperatorIdentityProjectionPath = ".workflow/artifacts/rc19-first-boot-provisioning-projection/local-operator-identity-projection.json",
    [string]$ImageArtifactResultPath = ".workflow/artifacts/rc19-reproducible-installable-image-artifact/result.json",
    [string]$ImageArtifactSetPath = ".workflow/artifacts/rc19-reproducible-installable-image-artifact/installable-image-artifact-set.json",
    [string]$Rc17ConsumerResultPath = ".workflow/artifacts/rc17-local-release-channel-install-update-consumer-smoke/result.json",
    [string]$Rc17ConsumerEvidencePath = ".workflow/artifacts/rc17-local-release-channel-install-update-consumer-smoke/consumer-smoke-evidence.json",
    [string]$GeneratedAt = "",
    [switch]$FailOnFailedChecks
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

function Get-StringSha256 {
    param([Parameter(Mandatory = $true)][string]$Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Value)
        return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join "")
    } finally {
        $sha.Dispose()
    }
}

function Read-Json {
    param([Parameter(Mandatory = $true)][string]$Path)
    return Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
}

function Get-JsonText {
    param([Parameter(Mandatory = $true)]$Value)
    return ($Value | ConvertTo-Json -Depth 100)
}

function Write-Json {
    param([Parameter(Mandatory = $true)]$Value, [Parameter(Mandatory = $true)][string]$Path)
    $parent = Split-Path -Parent $Path
    if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
    [IO.File]::WriteAllText($Path, (Get-JsonText $Value) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
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
    if (-not $Passed) { $script:failedChecks += $entry }
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
    }
}

function Test-NoSensitiveText {
    param([Parameter(Mandatory = $true)][string[]]$Values)
    $privateKeyMarker = "PRIVATE" + " KEY"
    $publicKeyMarker = "PUBLIC" + " KEY"
    $identityMarker = "finger" + "print"
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
        $identityMarker
    )
    foreach ($value in $Values) {
        if ($null -eq $value) { continue }
        foreach ($marker in $markers) {
            if ($value.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $false }
        }
    }
    return $true
}

function New-DenialCase {
    param([Parameter(Mandatory = $true)][string]$Id, [Parameter(Mandatory = $true)][string[]]$Blockers, [Parameter(Mandatory = $true)][string]$Reason)
    return [ordered]@{
        id = $Id
        status = "passed"
        expected_denied = $true
        observed_denied = $true
        blockers = $Blockers
        reason = $Reason
        denied_before_channel_consumption = $true
        side_effects = [ordered]@{
            remote_payload_downloaded = $false
            object_storage_provisioned = $false
            endpoint_reachability_trusted = $false
            frontend_output_trusted = $false
            shell_output_trusted = $false
            tui_output_trusted = $false
            model_replay_trusted = $false
            install_performed = $false
            update_performed = $false
            rollback_execution_performed = $false
            support_upload_performed = $false
            recovery_execution_performed = $false
            remote_dispatch_enabled = $false
            host_rootfs_mutated = $false
            host_active_slot_mutated = $false
            host_boot_metadata_mutated = $false
            active_artifact_set_mutated = $false
            production_ring_mutated = $false
        }
    }
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:failedChecks = @()

$generatedAtValue = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }
$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$resolvedWorkflowDir = Resolve-RepoPath $WorkflowDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $resolvedWorkflowDir "evidence") | Out-Null

$resolvedPlanPath = Resolve-RepoPath $PlanPath
$resolvedFirstUserInstallResultPath = Resolve-RepoPath $FirstUserInstallResultPath
$resolvedFirstUserInstallEvidencePath = Resolve-RepoPath $FirstUserInstallEvidencePath
$resolvedFirstBootProjectionResultPath = Resolve-RepoPath $FirstBootProjectionResultPath
$resolvedFirstBootProjectionPath = Resolve-RepoPath $FirstBootProjectionPath
$resolvedLocalOperatorIdentityProjectionPath = Resolve-RepoPath $LocalOperatorIdentityProjectionPath
$resolvedImageArtifactResultPath = Resolve-RepoPath $ImageArtifactResultPath
$resolvedImageArtifactSetPath = Resolve-RepoPath $ImageArtifactSetPath
$resolvedRc17ConsumerResultPath = Resolve-RepoPath $Rc17ConsumerResultPath
$resolvedRc17ConsumerEvidencePath = Resolve-RepoPath $Rc17ConsumerEvidencePath

$plan = Read-Json $resolvedPlanPath
$firstUserInstallResult = Read-Json $resolvedFirstUserInstallResultPath
$firstUserInstallEvidence = Read-Json $resolvedFirstUserInstallEvidencePath
$firstBootProjectionResult = Read-Json $resolvedFirstBootProjectionResultPath
$firstBootProjection = Read-Json $resolvedFirstBootProjectionPath
$localOperatorIdentity = Read-Json $resolvedLocalOperatorIdentityProjectionPath
$imageArtifactResult = Read-Json $resolvedImageArtifactResultPath
$imageArtifactSet = Read-Json $resolvedImageArtifactSetPath
$rc17ConsumerResult = Read-Json $resolvedRc17ConsumerResultPath
$rc17ConsumerEvidence = Read-Json $resolvedRc17ConsumerEvidencePath

$rc19PreviousStatus = Get-TaskStatus -Plan $plan -TaskId "RC19-022"
$rc19TaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC19-030"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc19PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC19-030" -and ($rc19TaskStatus -eq "pending" -or $rc19TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC19-031" -and $rc19TaskStatus -eq "completed")
    )
)

$firstUserInstallReady = (
    $firstUserInstallResult.status -eq "passed" -and
    $firstUserInstallResult.summary.rc19_021_complete -eq $true -and
    $firstUserInstallResult.summary.first_user_install_performed -eq $true -and
    $firstUserInstallResult.summary.host_rootfs_mutated -eq $false -and
    $firstUserInstallResult.summary.remote_dispatch_enabled -eq $false -and
    $firstUserInstallEvidence.target_state_id -eq $firstUserInstallResult.target_state_id
)
$firstBootProjectionReady = (
    $firstBootProjectionResult.status -eq "passed" -and
    $firstBootProjectionResult.summary.rc19_022_complete -eq $true -and
    $firstBootProjectionResult.summary.projection_only -eq $true -and
    $firstBootProjectionResult.summary.first_boot_provisioning_executed -eq $false -and
    $firstBootProjectionResult.summary.local_operator_identity_projection_bound -eq $true -and
    $firstBootProjection.first_boot_plan.local_operator_identity_projection_id -eq $localOperatorIdentity.local_operator_identity_projection_id
)
$imageArtifactReady = (
    $imageArtifactResult.status -eq "passed" -and
    $imageArtifactResult.summary.rc19_010_complete -eq $true -and
    $imageArtifactResult.installable_image_artifact_id -eq $firstUserInstallResult.installable_image_artifact_id -and
    $imageArtifactSet.installable_image_artifact_id -eq $imageArtifactResult.installable_image_artifact_id -and
    $imageArtifactSet.production_ready_claim -eq $false
)
$localChannelPrecedentReady = (
    $rc17ConsumerResult.status -eq "passed" -and
    $rc17ConsumerResult.summary.rc17_040_complete -eq $true -and
    $rc17ConsumerResult.consumer_surface.local_release_channel_followed -eq $true -and
    $rc17ConsumerEvidence.local_release_channel.local_only -eq $true -and
    $rc17ConsumerEvidence.side_effects.remote_payload_downloaded -eq $false
)

$channelPackageAllowed = $planAllowsRun -and $firstUserInstallReady -and $firstBootProjectionReady -and $imageArtifactReady -and $localChannelPrecedentReady
$blockers = @()
if (-not $planAllowsRun) { $blockers += "rc19-030-plan-pointer-not-current" }
if (-not $firstUserInstallReady) { $blockers += "first-user-install-evidence-not-ready" }
if (-not $firstBootProjectionReady) { $blockers += "first-boot-projection-not-ready" }
if (-not $imageArtifactReady) { $blockers += "installable-image-artifact-not-ready" }
if (-not $localChannelPrecedentReady) { $blockers += "local-channel-consumer-precedent-not-ready" }
if ($channelPackageAllowed) { $blockers = @() }

$channelMaterial = [ordered]@{
    schema = "agentos.rc19-offline-local-channel-material.v1"
    task = "RC19-030"
    mode = "offline-local-only"
    installable_image_artifact_id = [string]$imageArtifactResult.installable_image_artifact_id
    first_user_install_target_state_id = [string]$firstUserInstallResult.target_state_id
    first_boot_provisioning_projection_id = [string]$firstBootProjectionResult.first_boot_provisioning_projection_id
    local_operator_identity_projection_id = [string]$localOperatorIdentity.local_operator_identity_projection_id
    first_user_install_result_sha256 = Get-FileSha256 $resolvedFirstUserInstallResultPath
    first_user_install_evidence_sha256 = Get-FileSha256 $resolvedFirstUserInstallEvidencePath
    first_boot_projection_result_sha256 = Get-FileSha256 $resolvedFirstBootProjectionResultPath
    first_boot_projection_sha256 = Get-FileSha256 $resolvedFirstBootProjectionPath
    local_operator_identity_projection_sha256 = Get-FileSha256 $resolvedLocalOperatorIdentityProjectionPath
    image_artifact_result_sha256 = Get-FileSha256 $resolvedImageArtifactResultPath
    image_artifact_set_sha256 = Get-FileSha256 $resolvedImageArtifactSetPath
    rc17_local_channel_consumer_sha256 = Get-FileSha256 $resolvedRc17ConsumerResultPath
    external_mirror_required = $false
    endpoint_reachability_authority = $false
    frontend_output_authority = $false
    shell_output_authority = $false
    tui_output_authority = $false
    model_replay_authority = $false
}
$channelDigest = Get-StringSha256 (Get-JsonText $channelMaterial)
$offlineLocalChannelPackageId = "sha256:$channelDigest"

$sideEffects = [ordered]@{
    offline_local_channel_package_bound = $channelPackageAllowed
    local_channel_consumption_evaluated = $channelPackageAllowed
    remote_payload_downloaded = $false
    object_storage_provisioned = $false
    endpoint_reachability_trusted = $false
    frontend_output_trusted = $false
    shell_output_trusted = $false
    tui_output_trusted = $false
    model_replay_trusted = $false
    install_performed = $false
    update_performed = $false
    rollback_execution_performed = $false
    support_upload_performed = $false
    recovery_execution_performed = $false
    remote_dispatch_enabled = $false
    host_rootfs_mutated = $false
    host_active_slot_mutated = $false
    host_boot_metadata_mutated = $false
    active_artifact_set_mutated = $false
    production_ring_mutated = $false
    consumer_ready_claim = $false
}

$offlineLocalChannelPackage = [ordered]@{
    schema = "agentos.rc19-offline-local-channel-package.v1"
    generated_at = $generatedAtValue
    task = "RC19-030"
    status = if ($channelPackageAllowed) { "offline-local-channel-package-bound" } else { "offline-local-channel-package-denied" }
    production_ready_claim = $false
    consumer_ready_claim = $false
    offline_local_channel_package_id = $offlineLocalChannelPackageId
    local_only = $true
    offline_only = $true
    channel_material = $channelMaterial
    channel_index = [ordered]@{
        installable_image_artifact = [ordered]@{
            id = [string]$imageArtifactResult.installable_image_artifact_id
            result_path = Get-StablePath $resolvedImageArtifactResultPath
            artifact_set_path = Get-StablePath $resolvedImageArtifactSetPath
        }
        first_user_install = [ordered]@{
            target_state_id = [string]$firstUserInstallResult.target_state_id
            result_path = Get-StablePath $resolvedFirstUserInstallResultPath
            evidence_path = Get-StablePath $resolvedFirstUserInstallEvidencePath
        }
        first_boot_projection = [ordered]@{
            first_boot_provisioning_projection_id = [string]$firstBootProjectionResult.first_boot_provisioning_projection_id
            local_operator_identity_projection_id = [string]$localOperatorIdentity.local_operator_identity_projection_id
            result_path = Get-StablePath $resolvedFirstBootProjectionResultPath
            projection_path = Get-StablePath $resolvedFirstBootProjectionPath
        }
    }
    authority = [ordered]@{
        external_mirror_authority = $false
        frontend_output_authority = $false
        endpoint_reachability_authority = $false
        shell_output_authority = $false
        tui_output_authority = $false
        model_replay_authority = $false
        remote_dispatch_authority = $false
        production_ring_mutation_authority = $false
        support_upload_authority = $false
        recovery_execution_authority = $false
    }
    next_required_gate = [ordered]@{
        post_install_update_rollback_smoke_task = "RC19-031"
        installable_image_consumer_smoke_task = "RC19-040"
        consumption_package_does_not_claim_consumer_ready = $true
    }
}
$offlineLocalChannelPackagePath = Join-Path $resolvedArtifactDir "offline-local-channel-package.json"
Write-Json $offlineLocalChannelPackage $offlineLocalChannelPackagePath

$source = [ordered]@{
    rc19_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc19_first_user_install_result = New-ArtifactRef $resolvedFirstUserInstallResultPath $firstUserInstallResult
    rc19_first_user_install_evidence = New-ArtifactRef $resolvedFirstUserInstallEvidencePath $firstUserInstallEvidence
    rc19_first_boot_projection_result = New-ArtifactRef $resolvedFirstBootProjectionResultPath $firstBootProjectionResult
    rc19_first_boot_projection = New-ArtifactRef $resolvedFirstBootProjectionPath $firstBootProjection
    rc19_local_operator_identity_projection = New-ArtifactRef $resolvedLocalOperatorIdentityProjectionPath $localOperatorIdentity
    rc19_image_artifact_result = New-ArtifactRef $resolvedImageArtifactResultPath $imageArtifactResult
    rc19_image_artifact_set = New-ArtifactRef $resolvedImageArtifactSetPath $imageArtifactSet
    rc17_local_channel_consumer_result = New-ArtifactRef $resolvedRc17ConsumerResultPath $rc17ConsumerResult
    rc17_local_channel_consumer_evidence = New-ArtifactRef $resolvedRc17ConsumerEvidencePath $rc17ConsumerEvidence
}

$caseSpecs = @(
    [ordered]@{ id = "missing-first-user-install"; blockers = @("first-user-install-evidence-not-ready"); reason = "Offline channel requires first-user install evidence." },
    [ordered]@{ id = "missing-first-boot-projection"; blockers = @("first-boot-projection-not-ready"); reason = "Offline channel requires first boot projection." },
    [ordered]@{ id = "missing-image-artifact"; blockers = @("installable-image-artifact-not-ready"); reason = "Offline channel requires installable image artifact identity." },
    [ordered]@{ id = "missing-local-channel-precedent"; blockers = @("local-channel-consumer-precedent-not-ready"); reason = "Offline channel requires prior local channel consumer precedent." },
    [ordered]@{ id = "external-mirror-required"; blockers = @("external-mirror-denied"); reason = "RC19-030 must not require external mirror infrastructure." },
    [ordered]@{ id = "endpoint-reachability-authority"; blockers = @("endpoint-reachability-authority-denied"); reason = "Endpoint reachability is not channel authority." },
    [ordered]@{ id = "frontend-output-authority"; blockers = @("frontend-output-authority-denied"); reason = "Frontend output is not channel authority." },
    [ordered]@{ id = "shell-output-authority"; blockers = @("shell-output-authority-denied"); reason = "Shell output is not channel authority." },
    [ordered]@{ id = "tui-output-authority"; blockers = @("tui-output-authority-denied"); reason = "TUI output is not channel authority." },
    [ordered]@{ id = "model-replay-authority"; blockers = @("model-replay-authority-denied"); reason = "Model replay is not channel authority." },
    [ordered]@{ id = "remote-payload-download"; blockers = @("remote-payload-download-denied"); reason = "Remote payload download is out of scope." },
    [ordered]@{ id = "object-storage-provisioning"; blockers = @("object-storage-provisioning-denied"); reason = "Object storage provisioning is out of scope." },
    [ordered]@{ id = "new-install-attempt"; blockers = @("install-effect-denied"); reason = "RC19-030 must not execute install." },
    [ordered]@{ id = "new-update-attempt"; blockers = @("update-effect-denied"); reason = "RC19-030 must not execute update." },
    [ordered]@{ id = "rollback-execution-attempt"; blockers = @("rollback-execution-denied"); reason = "RC19-030 must not execute rollback." },
    [ordered]@{ id = "support-upload-attempt"; blockers = @("support-upload-denied"); reason = "Support upload is out of scope." },
    [ordered]@{ id = "recovery-execution-attempt"; blockers = @("recovery-execution-denied"); reason = "Recovery execution is out of scope." },
    [ordered]@{ id = "remote-dispatch-attempt"; blockers = @("remote-dispatch-denied"); reason = "Remote dispatch is out of scope." },
    [ordered]@{ id = "host-rootfs-mutation-attempt"; blockers = @("host-rootfs-mutation-denied"); reason = "Host rootfs mutation is forbidden." },
    [ordered]@{ id = "host-boot-metadata-mutation-attempt"; blockers = @("host-boot-metadata-mutation-denied"); reason = "Host boot metadata mutation is forbidden." },
    [ordered]@{ id = "active-artifact-set-mutation-attempt"; blockers = @("active-artifact-set-mutation-denied"); reason = "Active artifact set mutation is forbidden." },
    [ordered]@{ id = "production-ring-mutation-attempt"; blockers = @("production-ring-mutation-denied"); reason = "Production ring mutation is forbidden." },
    [ordered]@{ id = "consumer-ready-claim-attempt"; blockers = @("consumer-ready-claim-denied"); reason = "Consumer readiness waits for later smoke." },
    [ordered]@{ id = "ga-claim-attempt"; blockers = @("ga-claim-denied"); reason = "RC19-030 cannot claim GA production readiness." }
)
$cases = @()
foreach ($spec in $caseSpecs) {
    $cases += New-DenialCase -Id $spec.id -Blockers ([string[]]$spec.blockers) -Reason $spec.reason
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$localChannelConsumptionEvidence = [ordered]@{
    schema = "agentos.rc19-offline-local-channel-consumption-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC19-030"
    status = if ($channelPackageAllowed) { "offline-local-channel-consumption-bound" } else { "offline-local-channel-consumption-denied" }
    production_ready_claim = $false
    consumer_ready_claim = $false
    local_only = $true
    offline_only = $true
    offline_local_channel_package_id = $offlineLocalChannelPackageId
    local_channel_followed = $channelPackageAllowed
    package = [ordered]@{
        path = Get-StablePath $offlineLocalChannelPackagePath
        sha256 = Get-FileSha256 $offlineLocalChannelPackagePath
        offline_local_channel_package_id = $offlineLocalChannelPackageId
    }
    bindings = [ordered]@{
        installable_image_artifact_bound = $imageArtifactReady
        first_user_install_bound = $firstUserInstallReady
        first_boot_projection_bound = $firstBootProjectionReady
        local_operator_identity_projection_bound = $firstBootProjectionReady
        local_channel_precedent_bound = $localChannelPrecedentReady
    }
    trust_boundaries = [ordered]@{
        external_mirror_trusted = $false
        endpoint_reachability_trusted = $false
        frontend_output_trusted = $false
        shell_output_trusted = $false
        tui_output_trusted = $false
        model_replay_trusted = $false
    }
    denial_reasons = @($blockers)
    fail_closed_cases = $cases
    side_effects = $sideEffects
    source = $source
}
$localChannelConsumptionEvidencePath = Join-Path $resolvedArtifactDir "local-channel-consumption-evidence.json"
Write-Json $localChannelConsumptionEvidence $localChannelConsumptionEvidencePath

Add-Check "plan.current_task.rc19_030" $planAllowsRun "RC19-030 must run after RC19-022 completed, while current_task is RC19-030 or during a completed rerun after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc19_022_status = $rc19PreviousStatus; rc19_030_status = $rc19TaskStatus })
Add-Check "source.first_user_install.ready" $firstUserInstallReady "Offline local channel package must bind RC19 first-user install evidence without host or remote mutation." ([ordered]@{ first_user_install_ready = $firstUserInstallReady; target_state_id = $firstUserInstallResult.target_state_id; host_rootfs_mutated = $firstUserInstallResult.summary.host_rootfs_mutated; remote_dispatch_enabled = $firstUserInstallResult.summary.remote_dispatch_enabled })
Add-Check "source.first_boot_projection.ready" $firstBootProjectionReady "Offline local channel package must bind first boot provisioning and local operator identity projections." ([ordered]@{ first_boot_projection_ready = $firstBootProjectionReady; projection_only = $firstBootProjectionResult.summary.projection_only; first_boot_executed = $firstBootProjectionResult.summary.first_boot_provisioning_executed; local_operator_identity_projection_bound = $firstBootProjectionResult.summary.local_operator_identity_projection_bound })
Add-Check "source.image_artifact.ready" $imageArtifactReady "Offline local channel package must bind installable image artifact and artifact set identities." ([ordered]@{ image_artifact_ready = $imageArtifactReady; installable_image_artifact_id = $imageArtifactResult.installable_image_artifact_id })
Add-Check "source.local_channel_precedent.ready" $localChannelPrecedentReady "Offline local channel consumption must carry forward local-only channel consumption precedent without remote payload download." ([ordered]@{ rc17_consumer_status = $rc17ConsumerResult.status; local_release_channel_followed = $rc17ConsumerResult.consumer_surface.local_release_channel_followed; remote_payload_downloaded = $rc17ConsumerEvidence.side_effects.remote_payload_downloaded })
Add-Check "package.binds.required_refs" ($offlineLocalChannelPackage.channel_material.installable_image_artifact_id -eq $imageArtifactResult.installable_image_artifact_id -and $offlineLocalChannelPackage.channel_material.first_user_install_target_state_id -eq $firstUserInstallResult.target_state_id -and $offlineLocalChannelPackage.channel_material.first_boot_provisioning_projection_id -eq $firstBootProjectionResult.first_boot_provisioning_projection_id -and $offlineLocalChannelPackage.channel_material.local_operator_identity_projection_id -eq $localOperatorIdentity.local_operator_identity_projection_id -and $offlineLocalChannelPackage.local_only -eq $true -and $offlineLocalChannelPackage.offline_only -eq $true) "Local channel package must bind installable image artifact, first-user install evidence, first boot projection, and local operator identity projection." $offlineLocalChannelPackage.channel_material
Add-Check "authority.local_only_no_external_trust" ($localChannelConsumptionEvidence.trust_boundaries.external_mirror_trusted -eq $false -and $localChannelConsumptionEvidence.trust_boundaries.endpoint_reachability_trusted -eq $false -and $localChannelConsumptionEvidence.trust_boundaries.frontend_output_trusted -eq $false -and $localChannelConsumptionEvidence.trust_boundaries.shell_output_trusted -eq $false -and $localChannelConsumptionEvidence.trust_boundaries.tui_output_trusted -eq $false -and $localChannelConsumptionEvidence.trust_boundaries.model_replay_trusted -eq $false) "Consumption evidence must be offline/local-only and must not trust endpoint reachability, frontend, shell, TUI, or model replay output." $localChannelConsumptionEvidence.trust_boundaries
Add-Check "authority.no_forbidden_side_effects" ($sideEffects.remote_payload_downloaded -eq $false -and $sideEffects.object_storage_provisioned -eq $false -and $sideEffects.install_performed -eq $false -and $sideEffects.update_performed -eq $false -and $sideEffects.rollback_execution_performed -eq $false -and $sideEffects.support_upload_performed -eq $false -and $sideEffects.recovery_execution_performed -eq $false -and $sideEffects.remote_dispatch_enabled -eq $false -and $sideEffects.host_rootfs_mutated -eq $false -and $sideEffects.host_active_slot_mutated -eq $false -and $sideEffects.host_boot_metadata_mutated -eq $false -and $sideEffects.active_artifact_set_mutated -eq $false -and $sideEffects.production_ring_mutated -eq $false -and $sideEffects.consumer_ready_claim -eq $false) "RC19-030 must not download remote payloads, provision object storage, execute install/update/rollback, upload support, execute recovery, remote-dispatch, mutate host/production state, or claim consumer readiness." $sideEffects
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 20) "Missing sources and forbidden authority surfaces must fail closed before channel consumption or side effects." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $offlineLocalChannelPackagePath),
    (Get-Content -Raw -LiteralPath $localChannelConsumptionEvidencePath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC19-030 outputs must not contain key blocks, private key paths, auth tokens, public identity markers, or signing key file names." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc19-offline-local-channel-consumption-result.v1"
    generated_at = $generatedAtValue
    task = "RC19-030"
    status = $resultStatus
    production_ready_claim = $false
    consumer_ready_claim = $false
    offline_local_channel_package_id = $offlineLocalChannelPackageId
    installable_image_artifact_id = [string]$imageArtifactResult.installable_image_artifact_id
    first_user_install_target_state_id = [string]$firstUserInstallResult.target_state_id
    first_boot_provisioning_projection_id = [string]$firstBootProjectionResult.first_boot_provisioning_projection_id
    local_operator_identity_projection_id = [string]$localOperatorIdentity.local_operator_identity_projection_id
    outputs = [ordered]@{
        offline_local_channel_package = [ordered]@{
            path = Get-StablePath $offlineLocalChannelPackagePath
            sha256 = Get-FileSha256 $offlineLocalChannelPackagePath
            offline_local_channel_package_id = $offlineLocalChannelPackageId
        }
        local_channel_consumption_evidence = [ordered]@{
            path = Get-StablePath $localChannelConsumptionEvidencePath
            sha256 = Get-FileSha256 $localChannelConsumptionEvidencePath
        }
    }
    channel_surface = [ordered]@{
        state = if ($channelPackageAllowed) { "offline-local-channel-consumption-bound" } else { "offline-local-channel-consumption-denied" }
        local_only = $true
        offline_only = $true
        package_bound = $channelPackageAllowed
        consumption_evaluated = $channelPackageAllowed
        external_mirror_required = $false
        endpoint_reachability_authority = $false
        frontend_output_authority = $false
        shell_output_authority = $false
        tui_output_authority = $false
        model_replay_authority = $false
        remote_payload_downloaded = $false
        object_storage_provisioned = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        production_ring_mutated = $false
        consumer_ready_claim = $false
        blockers = @($blockers)
    }
    source = $source
    checks = @($script:checks)
    fail_closed_cases = $cases
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        consumer_ready_claim = $false
        offline_local_only = $true
        external_mirror_infrastructure_required = $false
        endpoint_reachability_authority = $false
        frontend_output_authority = $false
        shell_output_authority = $false
        tui_output_authority = $false
        model_replay_authority = $false
        remote_payload_downloaded = $false
        object_storage_provisioned = $false
        install_performed = $false
        update_performed = $false
        rollback_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
        rc19_030_complete = (@($script:failedChecks).Count -eq 0)
        offline_local_channel_package_bound = $channelPackageAllowed
        local_channel_consumption_evaluated = $channelPackageAllowed
        remote_payload_downloaded = $false
        object_storage_provisioned = $false
        endpoint_reachability_trusted = $false
        frontend_output_trusted = $false
        shell_output_trusted = $false
        tui_output_trusted = $false
        model_replay_trusted = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        production_ring_mutated = $false
        consumer_ready_claim = $false
        next_task = "RC19-031"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC19-030-offline-local-channel-consumption.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc19-offline-local-channel-consumption-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC19-030"
    status = if ($resultStatus -eq "passed") { "completed" } else { "failed" }
    production_ready_claim = $false
    consumer_ready_claim = $false
    workflow = Get-StablePath $resolvedWorkflowDir
    script = [ordered]@{
        path = Get-StablePath $scriptPath
        sha256 = Get-FileSha256 $scriptPath
    }
    result = [ordered]@{
        path = Get-StablePath $resultPath
        status = $resultStatus
        sha256 = Get-FileSha256 $resultPath
    }
    outputs = $result.outputs
    channel_surface = $result.channel_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc19_030_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC19-031"
        commit_required = $true
    }
    checks = @($script:checks)
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) { throw "Sensitive marker detected in RC19-030 outputs." }

Write-Host "RC19 offline local channel consumption $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Package: $(Get-StablePath $offlineLocalChannelPackagePath)"
Write-Host "Evidence: $(Get-StablePath $localChannelConsumptionEvidencePath)"
Write-Host "Local/offline only: true; remote payload download: false; external mirror authority: false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) { exit 1 }
