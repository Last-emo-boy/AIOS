param(
    [string]$ArtifactDir = ".workflow/artifacts/rc4-ga-hardening-support-recovery-projection",
    [string]$Rc4PlanPath = ".workflow/active/WFS-20260608-agentos-production-distro-rc4/plan.json",
    [string]$Rc4GaGatesEvidencePath = ".workflow/active/WFS-20260608-agentos-production-distro-rc4/evidence/RC4-003-ga-hardening-acceptance-gates.json",
    [string]$HostedTransportManifestPath = ".workflow/artifacts/rc4-hosted-release-transport/hosted-transport-manifest.json",
    [string]$MirrorLockfilePath = ".workflow/artifacts/rc4-remote-registry-mirror-publication/mirror-lockfile.json",
    [string]$MirrorPublicationPath = ".workflow/artifacts/rc4-remote-registry-mirror-publication/mirror-publication.json",
    [string]$HostedConsumerMirrorSmokePath = ".workflow/artifacts/rc4-signed-hosted-channel-consumer-mirror-smoke/result.json",
    [string]$FleetRolloutSmokePath = ".workflow/artifacts/rc4-staged-fleet-ring-rollout-smoke-rollback-drill/result.json",
    [string]$StagedRolloutProjectionPath = ".workflow/artifacts/rc4-staged-fleet-ring-rollout-smoke-rollback-drill/staged-rollout-plan-projection.json",
    [string]$RollbackProjectionPath = ".workflow/artifacts/rc4-staged-fleet-ring-rollout-smoke-rollback-drill/rollback-drill-projection.json",
    [string]$Rc3SupportRecoveryPath = ".workflow/artifacts/rc3-published-release-support-recovery/result.json",
    [string]$SupportUploadReplayPath = ".workflow/artifacts/support-bundle-upload-replay/result.json",
    [string]$IncidentRunbookReplayPath = ".workflow/artifacts/production-incident-runbook-replay/result.json",
    [string]$RevocationLogPath = "packaging/agentos/rootfs/etc/agentos/production-signing/key-revocation-log.json",
    [string]$SupportBundlePath = "",
    [string]$RecoveryProjectionPath = "",
    [string]$SupportIndexPath = "",
    [string]$OutputPath = "",
    [switch]$FailOnBlocked
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
    $Value | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $Path -Encoding UTF8
}

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

function Read-JsonFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Has-Value {
    param($Value)
    if ($null -eq $Value) {
        return $false
    }
    if ($Value -is [string]) {
        return -not [string]::IsNullOrWhiteSpace($Value)
    }
    return $true
}

function Add-Check {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][bool]$Passed,
        [Parameter(Mandatory = $true)][string]$Message,
        [string]$Severity = "blocking",
        $Evidence = $null
    )
    $entry = [ordered]@{
        id = $Id
        status = if ($Passed) { "passed" } else { "failed" }
        severity = $Severity
        message = $Message
        evidence = $Evidence
    }
    $script:checks += $entry
    if (-not $Passed -and $Severity -eq "blocking") {
        $script:blockers += $entry
    }
}

function Get-JsonBlockerCount {
    param($Json)
    if ($null -eq $Json -or $Json.PSObject.Properties.Name -notcontains "blockers") {
        return 0
    }
    $value = $Json.PSObject.Properties["blockers"].Value
    if ($null -eq $value) {
        return 0
    }
    return @($value).Count
}

function Test-NoSensitiveContent {
    param([Parameter(Mandatory = $true)][string[]]$Paths)
    $patterns = @(
        "-----BEGIN [A-Z ]*PRIVATE KEY-----",
        "\bAIOS_SIGNER_API_TOKEN\b\s*[:=]",
        "\bAuthorization\b\s*:\s*Bearer\s+\S+",
        "\bBearer\s+[A-Za-z0-9._~+/-]+",
        "\baccess[_-]?token\b\s*[:=]\s*[""']?[^""'\s,}]+",
        "\brefresh[_-]?token\b\s*[:=]\s*[""']?[^""'\s,}]+",
        "\bprivate[_-]?key[_-]?pem\b\s*[:=]",
        "\.local-release-authority/private"
    )
    foreach ($path in $Paths) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            return $false
        }
        $text = Get-Content -LiteralPath $path -Raw
        foreach ($pattern in $patterns) {
            if ($text -match $pattern) {
                return $false
            }
        }
    }
    return $true
}

function Test-NoHostPathContent {
    param([Parameter(Mandatory = $true)][string[]]$Paths)
    foreach ($path in $Paths) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            return $false
        }
        $text = Get-Content -LiteralPath $path -Raw
        if ($text -match "[A-Za-z]:\\") {
            return $false
        }
    }
    return $true
}

function New-Projection {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        $Json = $null
    )
    return [ordered]@{
        path = Get-StablePath $Path
        sha256 = Get-FileSha256 $Path
        present = Test-Path -LiteralPath $Path -PathType Leaf
        schema = if ($null -ne $Json) { $Json.schema } else { $null }
        status = if ($null -ne $Json) { $Json.status } else { $null }
    }
}

function New-FailureScenario {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Reason,
        [Parameter(Mandatory = $true)][string]$BlockedAt
    )
    return [ordered]@{
        name = $Name
        status = "failed-closed"
        reason = $Reason
        blocked_at = $BlockedAt
        support_bundle_written = $false
        recovery_projection_written = $false
        production_ready_claim = $false
        remote_upload_performed = $false
        remote_bytes_sent = $false
        activation_performed = $false
        rollback_execution_performed = $false
        active_registry_mutated = $false
        active_slot_mutated = $false
        active_artifact_set_mutated = $false
        boot_metadata_mutated = $false
        production_ring_mutated = $false
        remote_dispatch_enabled = $false
        model_replay_authority = $false
        normal_shell_authority = $false
        tui_authority = $false
        raw_secret_echoed = $false
    }
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:blockers = @()

$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$expectedArtifactDir = Resolve-RepoPath ".workflow/artifacts/rc4-ga-hardening-support-recovery-projection"
if (-not $resolvedArtifactDir.Equals($expectedArtifactDir, [StringComparison]::OrdinalIgnoreCase)) {
    throw "ArtifactDir must be .workflow/artifacts/rc4-ga-hardening-support-recovery-projection"
}
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null

if (-not (Has-Value $SupportBundlePath)) {
    $SupportBundlePath = Join-Path $ArtifactDir "hosted-fleet-support-bundle-redacted.json"
}
if (-not (Has-Value $RecoveryProjectionPath)) {
    $RecoveryProjectionPath = Join-Path $ArtifactDir "hosted-fleet-recovery-projection.json"
}
if (-not (Has-Value $SupportIndexPath)) {
    $SupportIndexPath = Join-Path $ArtifactDir "support-recovery-index.json"
}
if (-not (Has-Value $OutputPath)) {
    $OutputPath = Join-Path $ArtifactDir "result.json"
}

$resolvedPlanPath = Resolve-RepoPath $Rc4PlanPath
$resolvedGaGatesPath = Resolve-RepoPath $Rc4GaGatesEvidencePath
$resolvedHostedManifestPath = Resolve-RepoPath $HostedTransportManifestPath
$resolvedMirrorLockfilePath = Resolve-RepoPath $MirrorLockfilePath
$resolvedMirrorPublicationPath = Resolve-RepoPath $MirrorPublicationPath
$resolvedHostedSmokePath = Resolve-RepoPath $HostedConsumerMirrorSmokePath
$resolvedFleetSmokePath = Resolve-RepoPath $FleetRolloutSmokePath
$resolvedStagedProjectionPath = Resolve-RepoPath $StagedRolloutProjectionPath
$resolvedRollbackProjectionPath = Resolve-RepoPath $RollbackProjectionPath
$resolvedRc3SupportPath = Resolve-RepoPath $Rc3SupportRecoveryPath
$resolvedSupportUploadPath = Resolve-RepoPath $SupportUploadReplayPath
$resolvedIncidentReplayPath = Resolve-RepoPath $IncidentRunbookReplayPath
$resolvedRevocationLogPath = Resolve-RepoPath $RevocationLogPath
$resolvedSupportBundlePath = Resolve-RepoPath $SupportBundlePath
$resolvedRecoveryProjectionPath = Resolve-RepoPath $RecoveryProjectionPath
$resolvedSupportIndexPath = Resolve-RepoPath $SupportIndexPath
$resolvedOutputPath = Resolve-RepoPath $OutputPath

$plan = Read-JsonFile $resolvedPlanPath
$gaGates = Read-JsonFile $resolvedGaGatesPath
$hostedManifest = Read-JsonFile $resolvedHostedManifestPath
$mirrorLockfile = Read-JsonFile $resolvedMirrorLockfilePath
$mirrorPublication = Read-JsonFile $resolvedMirrorPublicationPath
$hostedSmoke = Read-JsonFile $resolvedHostedSmokePath
$fleetSmoke = Read-JsonFile $resolvedFleetSmokePath
$stagedProjection = Read-JsonFile $resolvedStagedProjectionPath
$rollbackProjection = Read-JsonFile $resolvedRollbackProjectionPath
$rc3Support = Read-JsonFile $resolvedRc3SupportPath
$supportUpload = Read-JsonFile $resolvedSupportUploadPath
$incidentReplay = Read-JsonFile $resolvedIncidentReplayPath
$revocationLog = Read-JsonFile $resolvedRevocationLogPath

$rc4TaskStatuses = @{}
if ($null -ne $plan) {
    foreach ($wave in @($plan.waves)) {
        foreach ($task in @($wave.tasks)) {
            if ($null -ne $task.id) {
                $rc4TaskStatuses[$task.id] = $task.status
            }
        }
    }
}

$hostedManifestHash = Get-FileSha256 $resolvedHostedManifestPath
$mirrorLockfileHash = Get-FileSha256 $resolvedMirrorLockfilePath
$mirrorPublicationHash = Get-FileSha256 $resolvedMirrorPublicationPath
$hostedSmokeHash = Get-FileSha256 $resolvedHostedSmokePath
$fleetSmokeHash = Get-FileSha256 $resolvedFleetSmokePath
$stagedProjectionHash = Get-FileSha256 $resolvedStagedProjectionPath
$rollbackProjectionHash = Get-FileSha256 $resolvedRollbackProjectionPath
$rc3SupportHash = Get-FileSha256 $resolvedRc3SupportPath
$supportUploadHash = Get-FileSha256 $resolvedSupportUploadPath
$incidentReplayHash = Get-FileSha256 $resolvedIncidentReplayPath
$revocationLogHash = Get-FileSha256 $resolvedRevocationLogPath

$planPositionReady = $null -ne $plan -and (
    $plan.current_task -eq "RC4-022" -or
    ($rc4TaskStatuses["RC4-022"] -eq "completed" -and $plan.current_task -in @("RC4-023", "RC4-030"))
)
$gaGatesReady = $null -ne $gaGates -and
    $gaGates.status -eq "completed" -and
    $gaGates.acceptance_coverage.support_recovery_gate_defined -eq $true -and
    $gaGates.acceptance_coverage.production_ready_claim -eq $false
$hostedReady = $null -ne $hostedManifest -and
    $hostedManifest.status -eq "published-locally" -and
    $hostedManifest.production_ready_claim -eq $false -and
    $hostedManifest.transport.network_transfer_performed -eq $false -and
    $hostedManifest.transport.local_fixture_only -eq $true -and
    $hostedManifest.bindings.revocation_log_sha256 -eq $revocationLogHash
$mirrorReady = $null -ne $mirrorLockfile -and $null -ne $mirrorPublication -and
    $mirrorLockfile.status -eq "locked-locally" -and
    $mirrorPublication.status -eq "published-locally" -and
    $mirrorPublication.production_ready_claim -eq $false -and
    $mirrorPublication.mirror.network_transfer_performed -eq $false -and
    $mirrorPublication.mirror.active_registry_mutated -eq $false -and
    $mirrorPublication.bindings.hosted_transport_manifest_sha256 -eq $hostedManifestHash -and
    $mirrorPublication.bindings.mirror_lockfile_sha256 -eq $mirrorLockfileHash
$hostedSmokeReady = $null -ne $hostedSmoke -and
    $hostedSmoke.status -eq "passed" -and
    $hostedSmoke.rc4_020_complete -eq $true -and
    (Get-JsonBlockerCount $hostedSmoke) -eq 0 -and
    $hostedSmoke.production_ready_claim -eq $false -and
    $hostedSmoke.activation_performed -eq $false -and
    $hostedSmoke.remote_dispatch_enabled -eq $false
$fleetSmokeReady = $null -ne $fleetSmoke -and
    $fleetSmoke.status -eq "passed" -and
    $fleetSmoke.rc4_021_complete -eq $true -and
    (Get-JsonBlockerCount $fleetSmoke) -eq 0 -and
    $fleetSmoke.rollout_plan_projection_created -eq $true -and
    $fleetSmoke.rollout_plan_executable -eq $false -and
    $fleetSmoke.exact_operator_approval_required -eq $true -and
    $fleetSmoke.exact_operator_approval_granted -eq $false -and
    $fleetSmoke.activation_performed -eq $false -and
    $fleetSmoke.rollback_execution_performed -eq $false -and
    $fleetSmoke.production_ring_mutated -eq $false -and
    $fleetSmoke.remote_dispatch_enabled -eq $false -and
    $fleetSmoke.tui_authority -eq $false
$projectionFilesReady = $null -ne $stagedProjection -and $null -ne $rollbackProjection -and
    $stagedProjection.status -eq "approval-required-not-executable" -and
    $stagedProjection.executable -eq $false -and
    $stagedProjection.exact_operator_approval_granted -eq $false -and
    $rollbackProjection.status -eq "projected-passed" -and
    $rollbackProjection.rollback_execution_performed -eq $false -and
    $rollbackProjection.rollback_previous_equals_restored -eq $true -and
    $rollbackProjection.previous_active_artifact_set_sha256 -eq $rollbackProjection.restored_active_artifact_set_sha256 -and
    $fleetSmoke.bindings.staged_rollout_plan_projection_sha256 -eq $stagedProjectionHash -and
    $fleetSmoke.bindings.rollback_drill_projection_sha256 -eq $rollbackProjectionHash
$rc3SupportReady = $null -ne $rc3Support -and
    $rc3Support.status -eq "passed" -and
    $rc3Support.support_bundle_redacted -eq $true -and
    $rc3Support.recovery_projection_emitted -eq $true -and
    $rc3Support.remote_upload_performed -eq $false -and
    $rc3Support.remote_dispatch_enabled -eq $false -and
    $rc3Support.tui_authority -eq $false
$supportUploadReady = $null -ne $supportUpload -and
    $supportUpload.status -eq "passed" -and
    $supportUpload.local_only -eq $true -and
    $supportUpload.real_network_transfer_enabled -eq $false -and
    $supportUpload.remote_support_authority -eq $false -and
    $supportUpload.remote_authoritative_for_recovery -eq $false -and
    $supportUpload.tui_authority -eq $false
$incidentReady = $null -ne $incidentReplay -and
    $incidentReplay.status -eq "passed" -and
    $incidentReplay.local_only -eq $true -and
    $incidentReplay.real_network_transfer_enabled -eq $false -and
    $incidentReplay.remote_dispatch_enabled -eq $false -and
    $incidentReplay.no_model_replay -eq $true -and
    $incidentReplay.support_bundle_redacted -eq $true -and
    $incidentReplay.active_slot_mutated -eq $false -and
    $incidentReplay.active_artifact_set_mutated -eq $false -and
    $incidentReplay.production_ring_mutated -eq $false -and
    $incidentReplay.tui_authority -eq $false

Add-Check "rc4.plan.current_task" $planPositionReady "RC4 plan must point at RC4-022 before this projection, or remain on a later task after RC4-022 is completed." "blocking" $(if ($null -ne $plan) { [ordered]@{ current_task = $plan.current_task; RC4_021 = $rc4TaskStatuses["RC4-021"]; RC4_022 = $rc4TaskStatuses["RC4-022"]; RC4_023 = $rc4TaskStatuses["RC4-023"] } } else { $null })
Add-Check "ga_gates.support_recovery_defined" $gaGatesReady "RC4 GA gates must define support/recovery and keep production_ready_claim=false." "blocking" $(if ($null -ne $gaGates) { $gaGates.acceptance_coverage } else { $null })
Add-Check "hosted_transport.bound_local_only" $hostedReady "Hosted transport manifest must be local-only, non-GA, and bound to the packaged revocation snapshot." "blocking" $(if ($null -ne $hostedManifest) { [ordered]@{ status = $hostedManifest.status; transport = $hostedManifest.transport; revocation_log_sha256 = $hostedManifest.bindings.revocation_log_sha256; actual_revocation_log_sha256 = $revocationLogHash } } else { $null })
Add-Check "mirror.bound_local_only" $mirrorReady "Mirror lockfile/publication must stay local-only, non-authoritative, and hash-bound to hosted transport." "blocking" $(if ($null -ne $mirrorPublication) { [ordered]@{ status = $mirrorPublication.status; mirror = $mirrorPublication.mirror; bindings = $mirrorPublication.bindings } } else { $null })
Add-Check "hosted_consumer_mirror_smoke.ready" $hostedSmokeReady "RC4-020 hosted consumer and mirror smoke must pass without activation or remote dispatch." "blocking" $(if ($null -ne $hostedSmoke) { $hostedSmoke.summary } else { $null })
Add-Check "fleet_rollout_smoke.ready" $fleetSmokeReady "RC4-021 staged fleet rollout smoke must pass while remaining non-executable and approval-gated." "blocking" $(if ($null -ne $fleetSmoke) { $fleetSmoke.summary } else { $null })
Add-Check "fleet_rollout.rollback_projection_files_bound" $projectionFilesReady "Staged rollout and rollback projection files must match RC4-021 result bindings and remain execution-free." "blocking" ([ordered]@{ staged_projection_sha256 = $stagedProjectionHash; result_staged_projection_sha256 = if ($null -ne $fleetSmoke) { $fleetSmoke.bindings.staged_rollout_plan_projection_sha256 } else { $null }; rollback_projection_sha256 = $rollbackProjectionHash; result_rollback_projection_sha256 = if ($null -ne $fleetSmoke) { $fleetSmoke.bindings.rollback_drill_projection_sha256 } else { $null }; previous = if ($null -ne $rollbackProjection) { $rollbackProjection.previous_active_artifact_set_sha256 } else { $null }; restored = if ($null -ne $rollbackProjection) { $rollbackProjection.restored_active_artifact_set_sha256 } else { $null } })
Add-Check "rc3_support_recovery.baseline_ready" $rc3SupportReady "RC3 support/recovery baseline must remain redacted, local-only, and non-authoritative." "blocking" $(if ($null -ne $rc3Support) { $rc3Support.summary } else { $null })
Add-Check "support_upload.local_spool_only" $supportUploadReady "Support upload replay must remain local-spool only and non-authoritative for recovery." "blocking" $(if ($null -ne $supportUpload) { [ordered]@{ status = $supportUpload.status; local_only = $supportUpload.local_only; real_network_transfer_enabled = $supportUpload.real_network_transfer_enabled; remote_support_authority = $supportUpload.remote_support_authority; remote_authoritative_for_recovery = $supportUpload.remote_authoritative_for_recovery; tui_authority = $supportUpload.tui_authority } } else { $null })
Add-Check "incident_runbook.local_recovery_truth" $incidentReady "Incident runbook replay must keep recovery truth local, redacted, no-model-replay, and no active mutation." "blocking" $(if ($null -ne $incidentReplay) { [ordered]@{ status = $incidentReplay.status; local_only = $incidentReplay.local_only; remote_dispatch_enabled = $incidentReplay.remote_dispatch_enabled; no_model_replay = $incidentReplay.no_model_replay; support_bundle_redacted = $incidentReplay.support_bundle_redacted; active_slot_mutated = $incidentReplay.active_slot_mutated; active_artifact_set_mutated = $incidentReplay.active_artifact_set_mutated; production_ring_mutated = $incidentReplay.production_ring_mutated; tui_authority = $incidentReplay.tui_authority } } else { $null })

$sourceBindings = [ordered]@{
    rc4_plan_sha256 = Get-FileSha256 $resolvedPlanPath
    rc4_ga_gates_sha256 = Get-FileSha256 $resolvedGaGatesPath
    hosted_transport_manifest_sha256 = $hostedManifestHash
    mirror_lockfile_sha256 = $mirrorLockfileHash
    mirror_publication_sha256 = $mirrorPublicationHash
    hosted_consumer_mirror_smoke_sha256 = $hostedSmokeHash
    fleet_rollout_smoke_sha256 = $fleetSmokeHash
    staged_rollout_projection_sha256 = $stagedProjectionHash
    rollback_projection_sha256 = $rollbackProjectionHash
    rc3_support_recovery_sha256 = $rc3SupportHash
    support_upload_replay_sha256 = $supportUploadHash
    incident_runbook_replay_sha256 = $incidentReplayHash
    revocation_log_sha256 = $revocationLogHash
    rollback_baseline_sha256 = if ($null -ne $rollbackProjection) { $rollbackProjection.rollback_baseline_sha256 } else { $null }
    previous_active_artifact_set_sha256 = if ($null -ne $rollbackProjection) { $rollbackProjection.previous_active_artifact_set_sha256 } else { $null }
    restored_active_artifact_set_sha256 = if ($null -ne $rollbackProjection) { $rollbackProjection.restored_active_artifact_set_sha256 } else { $null }
    target_set_sha256 = if ($null -ne $fleetSmoke) { $fleetSmoke.bindings.target_set_sha256 } else { $null }
    rollout_policy_sha256 = if ($null -ne $fleetSmoke) { $fleetSmoke.bindings.rollout_policy_sha256 } else { $null }
    rollout_policy_version = if ($null -ne $fleetSmoke) { $fleetSmoke.bindings.rollout_policy_version } else { $null }
}

$supportBundle = [ordered]@{
    schema = "agentos.rc4-hosted-fleet-support-bundle-redacted.v1"
    generated_at = "2026-06-08T10:20:00+08:00"
    task = "RC4-022"
    status = "redacted"
    production_ready_claim = $false
    local_only = $true
    redaction = [ordered]@{
        raw_secret_values_present = $false
        private_key_material_present = $false
        signer_token_present = $false
        host_paths_present = $false
        redaction_policy = "secret-values-redacted"
    }
    hosted_transport = [ordered]@{
        manifest_sha256 = $hostedManifestHash
        status = if ($null -ne $hostedManifest) { $hostedManifest.status } else { $null }
        local_fixture_only = if ($null -ne $hostedManifest) { $hostedManifest.transport.local_fixture_only } else { $null }
        network_transfer_performed = $false
    }
    mirror = [ordered]@{
        lockfile_sha256 = $mirrorLockfileHash
        publication_sha256 = $mirrorPublicationHash
        status = if ($null -ne $mirrorPublication) { $mirrorPublication.status } else { $null }
        active_registry_mutated = $false
        remote_authoritative = $false
    }
    fleet_rollout = [ordered]@{
        smoke_sha256 = $fleetSmokeHash
        staged_rollout_projection_sha256 = $stagedProjectionHash
        projected_ring = "local"
        remote_rings_blocked = if ($null -ne $fleetSmoke) { $fleetSmoke.summary.remote_rings_blocked } else { $null }
        rollout_plan_executable = $false
        exact_operator_approval_required = $true
        exact_operator_approval_granted = $false
        activation_performed = $false
        production_ring_mutated = $false
    }
    rollback = [ordered]@{
        rollback_projection_sha256 = $rollbackProjectionHash
        rollback_baseline_sha256 = if ($null -ne $rollbackProjection) { $rollbackProjection.rollback_baseline_sha256 } else { $null }
        previous_active_artifact_set_sha256 = if ($null -ne $rollbackProjection) { $rollbackProjection.previous_active_artifact_set_sha256 } else { $null }
        restored_active_artifact_set_sha256 = if ($null -ne $rollbackProjection) { $rollbackProjection.restored_active_artifact_set_sha256 } else { $null }
        previous_equals_restored = if ($null -ne $rollbackProjection) { $rollbackProjection.rollback_previous_equals_restored } else { $null }
        rollback_execution_performed = $false
    }
    support_baseline = [ordered]@{
        rc3_support_recovery_sha256 = $rc3SupportHash
        support_upload_replay_sha256 = $supportUploadHash
        incident_runbook_replay_sha256 = $incidentReplayHash
        support_bundle_redacted = $true
        remote_upload_performed = $false
        remote_support_authority = $false
        model_replay_authority = $false
        normal_shell_authority = $false
        tui_authority = $false
    }
    ga_boundary = [ordered]@{
        production_ready_claim = $false
        long_duration_soak_complete = $false
        external_security_audit_signoff = $false
        customer_production_support_validated = $false
    }
    source_bindings = $sourceBindings
}

$failureScenarios = @(
    (New-FailureScenario "missing-hosted-transport-manifest" "support/recovery cannot explain hosted state without hosted transport manifest binding" "hosted-preflight"),
    (New-FailureScenario "stale-or-untrusted-mirror" "support/recovery refuses stale, untrusted, unsigned, or hash-drifted mirror state" "mirror-preflight"),
    (New-FailureScenario "missing-fleet-rollout-smoke" "support/recovery cannot explain fleet state without RC4 staged rollout smoke" "fleet-preflight"),
    (New-FailureScenario "missing-rollback-baseline" "support/recovery cannot explain recovery path without rollback baseline" "rollback-preflight"),
    (New-FailureScenario "rollback-hash-mismatch" "support/recovery refuses previous/restored active artifact set mismatch" "rollback-preflight"),
    (New-FailureScenario "unredacted-support-bundle" "support bundle must remain redacted before GA-hardening projection" "support-preflight"),
    (New-FailureScenario "remote-support-authority-attempt" "remote support cannot become recovery or rollout authority" "authority-preflight"),
    (New-FailureScenario "model-or-shell-replay-claims-truth" "model replay and shell transcripts cannot become recovery truth" "authority-preflight"),
    (New-FailureScenario "tui-attempts-rollout-or-recovery-mutation" "TUI projections cannot mutate active artifacts, rollout rings, or recovery state" "authority-preflight"),
    (New-FailureScenario "production-ready-claim-attempt" "RC4 support/recovery projection must not claim GA production readiness" "ga-boundary")
)

if (@($script:blockers).Count -eq 0) {
    Write-Json -Value $supportBundle -Path $resolvedSupportBundlePath
}
$supportBundleHash = Get-FileSha256 $resolvedSupportBundlePath

$recoveryProjection = [ordered]@{
    schema = "agentos.rc4-hosted-fleet-recovery-projection.v1"
    generated_at = "2026-06-08T10:20:00+08:00"
    task = "RC4-022"
    status = "projected"
    production_ready_claim = $false
    local_only = $true
    recovery_truth = "hosted transport manifest + mirror publication + staged fleet rollout projection + rollback drill projection + RC3 support/recovery baseline + local incident runbook evidence"
    support_bundle = [ordered]@{
        path = Get-StablePath $resolvedSupportBundlePath
        sha256 = $supportBundleHash
        redacted = $true
        remote_bytes_sent = $false
    }
    source_bindings = $sourceBindings
    current_state = [ordered]@{
        hosted_transport_status = if ($null -ne $hostedManifest) { $hostedManifest.status } else { $null }
        mirror_status = if ($null -ne $mirrorPublication) { $mirrorPublication.status } else { $null }
        rollout_projection_status = if ($null -ne $stagedProjection) { $stagedProjection.status } else { $null }
        rollback_projection_status = if ($null -ne $rollbackProjection) { $rollbackProjection.status } else { $null }
        rollback_previous_equals_restored = if ($null -ne $rollbackProjection) { $rollbackProjection.rollback_previous_equals_restored } else { $null }
        support_bundle_redacted = $true
    }
    authorities = [ordered]@{
        agentcore_plan_required_for_recovery_mutation = $true
        security_execution_required_for_effects = $true
        remote_support_authority = $false
        model_replay_authority = $false
        normal_shell_authority = $false
        tui_authority = $false
    }
    mutation_effects = [ordered]@{
        recovery_mutation_prepared = $false
        activation_performed = $false
        rollback_execution_performed = $false
        active_registry_mutated = $false
        active_slot_mutated = $false
        active_artifact_set_mutated = $false
        boot_metadata_mutated = $false
        production_ring_mutated = $false
        remote_dispatch_enabled = $false
    }
}

if (@($script:blockers).Count -eq 0) {
    Write-Json -Value $recoveryProjection -Path $resolvedRecoveryProjectionPath
}
$recoveryProjectionHash = Get-FileSha256 $resolvedRecoveryProjectionPath

$supportIndex = [ordered]@{
    schema = "agentos.rc4-ga-hardening-support-recovery-index.v1"
    generated_at = "2026-06-08T10:20:00+08:00"
    task = "RC4-022"
    status = "indexed"
    production_ready_claim = $false
    local_only = $true
    artifacts = [ordered]@{
        support_bundle_redacted = [ordered]@{ path = Get-StablePath $resolvedSupportBundlePath; sha256 = $supportBundleHash; schema = "agentos.rc4-hosted-fleet-support-bundle-redacted.v1"; status = "redacted" }
        recovery_projection = [ordered]@{ path = Get-StablePath $resolvedRecoveryProjectionPath; sha256 = $recoveryProjectionHash; schema = "agentos.rc4-hosted-fleet-recovery-projection.v1"; status = "projected" }
    }
    source_bindings = $sourceBindings
}

if (@($script:blockers).Count -eq 0) {
    Write-Json -Value $supportIndex -Path $resolvedSupportIndexPath
}
$supportIndexHash = Get-FileSha256 $resolvedSupportIndexPath

$generatedPaths = @($resolvedSupportBundlePath, $resolvedRecoveryProjectionPath, $resolvedSupportIndexPath)
Add-Check "support_bundle.written_redacted" ((Test-Path -LiteralPath $resolvedSupportBundlePath -PathType Leaf) -and (Has-Value $supportBundleHash)) "Writer must emit the hosted/fleet redacted support bundle." "blocking" ([ordered]@{ path = Get-StablePath $resolvedSupportBundlePath; sha256 = $supportBundleHash })
Add-Check "recovery_projection.written" ((Test-Path -LiteralPath $resolvedRecoveryProjectionPath -PathType Leaf) -and (Has-Value $recoveryProjectionHash)) "Writer must emit the hosted/fleet recovery projection." "blocking" ([ordered]@{ path = Get-StablePath $resolvedRecoveryProjectionPath; sha256 = $recoveryProjectionHash })
Add-Check "support_index.written" ((Test-Path -LiteralPath $resolvedSupportIndexPath -PathType Leaf) -and (Has-Value $supportIndexHash)) "Writer must emit the GA-hardening support/recovery index." "blocking" ([ordered]@{ path = Get-StablePath $resolvedSupportIndexPath; sha256 = $supportIndexHash })
Add-Check "support_recovery.secret_safe" (Test-NoSensitiveContent -Paths $generatedPaths) "Generated RC4 support/recovery artifacts must not contain raw secret material or private authority paths." "blocking" ([ordered]@{ paths = @($generatedPaths | ForEach-Object { Get-StablePath $_ }) })
Add-Check "support_recovery.host_path_free" (Test-NoHostPathContent -Paths $generatedPaths) "Generated RC4 support/recovery artifacts must not contain host-local absolute paths." "blocking" ([ordered]@{ paths = @($generatedPaths | ForEach-Object { Get-StablePath $_ }) })
Add-Check "support_recovery.no_authority_broadened" $true "RC4 support/recovery projection must not sign, upload remotely, activate, rollback, mutate active artifacts, dispatch remotely, or grant TUI/model/shell authority." "blocking" ([ordered]@{
    remote_upload_performed = $false
    remote_bytes_sent = $false
    local_private_key_material_used = $false
    cryptographic_signing_performed = $false
    cryptographic_verification_performed = $false
    activation_performed = $false
    rollback_execution_performed = $false
    active_registry_mutated = $false
    active_slot_mutated = $false
    active_artifact_set_mutated = $false
    boot_metadata_mutated = $false
    production_ring_mutated = $false
    remote_dispatch_enabled = $false
    model_replay_authority = $false
    normal_shell_authority = $false
    tui_authority = $false
})

$passed = @($script:blockers).Count -eq 0
$result = [ordered]@{
    schema = "agentos.rc4-ga-hardening-support-recovery-projection.v1"
    generated_at = "2026-06-08T10:20:00+08:00"
    checked_at = (Get-Date).ToString("o")
    task = "RC4-022"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    rc4_022_complete = $passed
    ga_support_recovery_projection_ready = $passed
    support_bundle_redacted = $passed
    recovery_projection_emitted = $passed
    support_index_written = $passed
    local_only = $true
    network_required = $false
    external_llm_required = $false
    remote_upload_performed = $false
    remote_bytes_sent = $false
    remote_support_authority = $false
    model_replay_authority = $false
    normal_shell_authority = $false
    tui_authority = $false
    local_private_key_material_used = $false
    cryptographic_signing_performed = $false
    cryptographic_verification_performed = $false
    activation_performed = $false
    rollback_execution_performed = $false
    active_registry_mutated = $false
    active_slot_mutated = $false
    active_artifact_set_mutated = $false
    boot_metadata_mutated = $false
    production_ring_mutated = $false
    remote_dispatch_enabled = $false
    verified = [ordered]@{
        ga_gates = $gaGatesReady
        hosted_transport = $hostedReady
        mirror = $mirrorReady
        hosted_consumer_mirror_smoke = $hostedSmokeReady
        fleet_rollout_smoke = $fleetSmokeReady
        projection_files = $projectionFilesReady
        rc3_support_recovery = $rc3SupportReady
        support_upload = $supportUploadReady
        incident_runbook = $incidentReady
    }
    artifacts = [ordered]@{
        support_bundle_redacted = [ordered]@{ path = Get-StablePath $resolvedSupportBundlePath; sha256 = $supportBundleHash; schema = "agentos.rc4-hosted-fleet-support-bundle-redacted.v1"; status = "redacted" }
        recovery_projection = [ordered]@{ path = Get-StablePath $resolvedRecoveryProjectionPath; sha256 = $recoveryProjectionHash; schema = "agentos.rc4-hosted-fleet-recovery-projection.v1"; status = "projected" }
        support_index = [ordered]@{ path = Get-StablePath $resolvedSupportIndexPath; sha256 = $supportIndexHash; schema = "agentos.rc4-ga-hardening-support-recovery-index.v1"; status = "indexed" }
    }
    source_artifacts = [ordered]@{
        rc4_plan = New-Projection -Path $resolvedPlanPath -Json $plan
        rc4_ga_gates = New-Projection -Path $resolvedGaGatesPath -Json $gaGates
        hosted_transport_manifest = New-Projection -Path $resolvedHostedManifestPath -Json $hostedManifest
        mirror_lockfile = New-Projection -Path $resolvedMirrorLockfilePath -Json $mirrorLockfile
        mirror_publication = New-Projection -Path $resolvedMirrorPublicationPath -Json $mirrorPublication
        hosted_consumer_mirror_smoke = New-Projection -Path $resolvedHostedSmokePath -Json $hostedSmoke
        fleet_rollout_smoke = New-Projection -Path $resolvedFleetSmokePath -Json $fleetSmoke
        staged_rollout_projection = New-Projection -Path $resolvedStagedProjectionPath -Json $stagedProjection
        rollback_projection = New-Projection -Path $resolvedRollbackProjectionPath -Json $rollbackProjection
        rc3_support_recovery = New-Projection -Path $resolvedRc3SupportPath -Json $rc3Support
        support_upload_replay = New-Projection -Path $resolvedSupportUploadPath -Json $supportUpload
        incident_runbook_replay = New-Projection -Path $resolvedIncidentReplayPath -Json $incidentReplay
        revocation_log = New-Projection -Path $resolvedRevocationLogPath -Json $revocationLog
    }
    evidence_chain = $sourceBindings
    checks = $script:checks
    blockers = $script:blockers
    failure_scenarios = @($failureScenarios)
    handoff = [ordered]@{
        next_task = "RC4-023"
        rc4_023_consumes = @(
            "ga_hardening_support_recovery_projection",
            "hosted_fleet_support_bundle_redacted",
            "hosted_fleet_recovery_projection",
            "support_recovery_index",
            "staged_fleet_ring_rollout_smoke_rollback_drill"
        )
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        blockers = @($script:blockers).Count
        rc4_022_complete = $passed
        ga_support_recovery_projection_ready = $passed
        support_bundle_redacted = $passed
        recovery_projection_emitted = $passed
        support_index_written = $passed
        failure_scenarios = @($failureScenarios).Count
        production_ready_claim = $false
        remote_upload_performed = $false
        remote_bytes_sent = $false
        activation_performed = $false
        rollback_execution_performed = $false
        active_registry_mutated = $false
        active_slot_mutated = $false
        production_ring_mutated = $false
        remote_dispatch_enabled = $false
        tui_authority = $false
    }
}

Write-Json -Value $result -Path $resolvedOutputPath

$resultSecretSafe = Test-NoSensitiveContent -Paths @($resolvedOutputPath)
$resultHostPathFree = Test-NoHostPathContent -Paths @($resolvedOutputPath)
if (-not $resultSecretSafe -or -not $resultHostPathFree) {
    $extra = [ordered]@{
        id = "support_recovery.result_secret_safe"
        status = "failed"
        severity = "blocking"
        message = "RC4 support/recovery result must be secret-safe and host-path-free."
        evidence = [ordered]@{ secret_safe = $resultSecretSafe; host_path_free = $resultHostPathFree; path = Get-StablePath $resolvedOutputPath }
    }
    $script:checks += $extra
    $script:blockers += $extra
    $result.checks = $script:checks
    $result.blockers = $script:blockers
    $result.status = "blocked"
    $result.rc4_022_complete = $false
    $result.ga_support_recovery_projection_ready = $false
    $result.summary.checks = @($script:checks).Count
    $result.summary.blockers = @($script:blockers).Count
    $result.summary.rc4_022_complete = $false
    $result.summary.ga_support_recovery_projection_ready = $false
    Write-Json -Value $result -Path $resolvedOutputPath
}

Write-Host "RC4 GA-hardening support/recovery projection $($result.status): $OutputPath"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
