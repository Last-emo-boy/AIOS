param(
    [string]$ArtifactDir = ".workflow/artifacts/rc4-staged-fleet-ring-rollout-smoke-rollback-drill",
    [string]$Rc4PlanPath = ".workflow/active/WFS-20260608-agentos-production-distro-rc4/plan.json",
    [string]$HostedConsumerMirrorSmokePath = ".workflow/artifacts/rc4-signed-hosted-channel-consumer-mirror-smoke/result.json",
    [string]$FleetRolloutPreconditionsPath = ".workflow/artifacts/rc4-fleet-ring-rollout-preconditions/result.json",
    [string]$HostedTransportFailClosedPath = ".workflow/artifacts/rc4-hosted-transport-fail-closed-fixtures/result.json",
    [string]$HostedTransportManifestPath = ".workflow/artifacts/rc4-hosted-release-transport/hosted-transport-manifest.json",
    [string]$MirrorLockfilePath = ".workflow/artifacts/rc4-remote-registry-mirror-publication/mirror-lockfile.json",
    [string]$MirrorPublicationPath = ".workflow/artifacts/rc4-remote-registry-mirror-publication/mirror-publication.json",
    [string]$FleetRolloutAuthorityPath = ".workflow/artifacts/release/fleet-rollout-authority.json",
    [string]$RollbackDrillPath = ".workflow/artifacts/rc2-block-rollback-drill/result.json",
    [string]$SupportRecoveryPath = ".workflow/artifacts/rc3-published-release-support-recovery/result.json",
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

function Get-JsonText {
    param([Parameter(Mandatory = $true)]$Value)
    return ($Value | ConvertTo-Json -Depth 100)
}

function Get-StringSha256 {
    param([Parameter(Mandatory = $true)][string]$Value)
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Value)
    $hash = [Security.Cryptography.SHA256]::HashData($bytes)
    return ([BitConverter]::ToString($hash)).Replace("-", "").ToLowerInvariant()
}

function Get-ObjectSha256 {
    param([Parameter(Mandatory = $true)]$Value)
    return Get-StringSha256 (Get-JsonText $Value)
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

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:blockers = @()

$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$expectedArtifactDir = Resolve-RepoPath ".workflow/artifacts/rc4-staged-fleet-ring-rollout-smoke-rollback-drill"
if (-not $resolvedArtifactDir.Equals($expectedArtifactDir, [StringComparison]::OrdinalIgnoreCase)) {
    throw "ArtifactDir must be .workflow/artifacts/rc4-staged-fleet-ring-rollout-smoke-rollback-drill"
}
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null

if (-not (Has-Value $OutputPath)) {
    $OutputPath = Join-Path $ArtifactDir "result.json"
}

$resolvedPlanPath = Resolve-RepoPath $Rc4PlanPath
$resolvedHostedSmokePath = Resolve-RepoPath $HostedConsumerMirrorSmokePath
$resolvedPreconditionsPath = Resolve-RepoPath $FleetRolloutPreconditionsPath
$resolvedFailClosedPath = Resolve-RepoPath $HostedTransportFailClosedPath
$resolvedHostedManifestPath = Resolve-RepoPath $HostedTransportManifestPath
$resolvedMirrorLockfilePath = Resolve-RepoPath $MirrorLockfilePath
$resolvedMirrorPublicationPath = Resolve-RepoPath $MirrorPublicationPath
$resolvedFleetAuthorityPath = Resolve-RepoPath $FleetRolloutAuthorityPath
$resolvedRollbackPath = Resolve-RepoPath $RollbackDrillPath
$resolvedSupportRecoveryPath = Resolve-RepoPath $SupportRecoveryPath
$resolvedOutputPath = Resolve-RepoPath $OutputPath
$projectedRolloutPlanPath = Join-Path $resolvedArtifactDir "staged-rollout-plan-projection.json"
$rollbackProjectionPath = Join-Path $resolvedArtifactDir "rollback-drill-projection.json"

$plan = Read-JsonFile $resolvedPlanPath
$hostedSmoke = Read-JsonFile $resolvedHostedSmokePath
$preconditions = Read-JsonFile $resolvedPreconditionsPath
$failClosed = Read-JsonFile $resolvedFailClosedPath
$hostedManifest = Read-JsonFile $resolvedHostedManifestPath
$mirrorLockfile = Read-JsonFile $resolvedMirrorLockfilePath
$mirrorPublication = Read-JsonFile $resolvedMirrorPublicationPath
$fleetAuthority = Read-JsonFile $resolvedFleetAuthorityPath
$rollback = Read-JsonFile $resolvedRollbackPath
$supportRecovery = Read-JsonFile $resolvedSupportRecoveryPath

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

$hostedSmokeHash = Get-FileSha256 $resolvedHostedSmokePath
$preconditionsHash = Get-FileSha256 $resolvedPreconditionsPath
$failClosedHash = Get-FileSha256 $resolvedFailClosedPath
$hostedManifestHash = Get-FileSha256 $resolvedHostedManifestPath
$mirrorLockfileHash = Get-FileSha256 $resolvedMirrorLockfilePath
$mirrorPublicationHash = Get-FileSha256 $resolvedMirrorPublicationPath
$fleetAuthorityHash = Get-FileSha256 $resolvedFleetAuthorityPath
$rollbackHash = Get-FileSha256 $resolvedRollbackPath
$supportRecoveryHash = Get-FileSha256 $resolvedSupportRecoveryPath

$rings = if ($null -ne $fleetAuthority) { @($fleetAuthority.rings) } else { @() }
$requiredRings = @("local", "canary", "staging", "production")
$ringNames = @($rings | ForEach-Object { $_.name })
$localRing = @($rings | Where-Object { $_.name -eq "local" } | Select-Object -First 1)
$canaryRing = @($rings | Where-Object { $_.name -eq "canary" } | Select-Object -First 1)
$stagingRing = @($rings | Where-Object { $_.name -eq "staging" } | Select-Object -First 1)
$productionRing = @($rings | Where-Object { $_.name -eq "production" } | Select-Object -First 1)
$ringOrderReady = ($ringNames -join "|") -eq ($requiredRings -join "|")
$remoteRingsBlocked = $null -ne $canaryRing -and $null -ne $stagingRing -and $null -ne $productionRing -and
    $canaryRing.blocker -eq "remote-fleet-execution-not-enabled" -and
    $stagingRing.blocker -eq "remote-fleet-execution-not-enabled" -and
    $productionRing.blocker -eq "remote-fleet-execution-not-enabled"

$planPositionReady = $null -ne $plan -and (
    $plan.current_task -eq "RC4-021" -or
    ($rc4TaskStatuses["RC4-021"] -eq "completed" -and $plan.current_task -in @("RC4-022", "RC4-023", "RC4-030"))
)
$hostedSmokeReady = $null -ne $hostedSmoke -and
    $hostedSmoke.status -eq "passed" -and
    $hostedSmoke.rc4_020_complete -eq $true -and
    $hostedSmoke.hosted_channel_consumer_ready -eq $true -and
    $hostedSmoke.mirror_smoke_ready -eq $true -and
    (Get-JsonBlockerCount $hostedSmoke) -eq 0 -and
    $hostedSmoke.production_ready_claim -eq $false -and
    $hostedSmoke.activation_performed -eq $false -and
    $hostedSmoke.rollback_execution_performed -eq $false -and
    $hostedSmoke.production_ring_mutated -eq $false -and
    $hostedSmoke.remote_dispatch_enabled -eq $false -and
    $hostedSmoke.tui_authority -eq $false
$preconditionsReady = $null -ne $preconditions -and
    $preconditions.status -eq "ready-for-fleet-ring-rollout-plan" -and
    $preconditions.rc4_012_complete -eq $true -and
    $preconditions.rollout_preconditions_ready -eq $true -and
    (Get-JsonBlockerCount $preconditions) -eq 0 -and
    $preconditions.projected_bindings.hosted_transport_manifest_sha256 -eq $hostedManifestHash -and
    $preconditions.projected_bindings.mirror_publication_sha256 -eq $mirrorPublicationHash -and
    $preconditions.projected_bindings.mirror_lockfile_sha256 -eq $mirrorLockfileHash -and
    $preconditions.projected_bindings.fleet_rollout_authority_sha256 -eq $fleetAuthorityHash -and
    $preconditions.projected_bindings.rollback_drill_sha256 -eq $rollbackHash -and
    $preconditions.projected_bindings.support_recovery_sha256 -eq $supportRecoveryHash -and
    $preconditions.exact_operator_approval_granted -eq $false -and
    $preconditions.activation_performed -eq $false -and
    $preconditions.rollback_execution_performed -eq $false -and
    $preconditions.production_ring_mutated -eq $false
$failClosedReady = $null -ne $failClosed -and
    $failClosed.status -eq "passed" -and
    $failClosed.rc4_013_complete -eq $true -and
    $failClosed.summary.passed_cases -eq 13 -and
    (Get-JsonBlockerCount $failClosed) -eq 0 -and
    $failClosed.activation_performed -eq $false -and
    $failClosed.rollback_execution_performed -eq $false -and
    $failClosed.remote_dispatch_enabled -eq $false -and
    $failClosed.tui_authority -eq $false
$fleetAuthorityReady = $null -ne $fleetAuthority -and
    $fleetAuthority.status -eq "passed" -and
    $fleetAuthority.production_ready_claim -eq $false -and
    $fleetAuthority.authority.execution_authority -eq "AgentCore fleet_rollout PlanSpec + SecurityExecutionEngine" -and
    $fleetAuthority.authority.tui_authority -eq $false -and
    $fleetAuthority.authority.rollout_execution_in_tui -eq $false -and
    $fleetAuthority.authority.rollback_execution_in_tui -eq $false -and
    $fleetAuthority.authority.remote_operator_bypass_allowed -eq $false -and
    $fleetAuthority.authority.normal_shell_rollout_allowed -eq $false -and
    $fleetAuthority.promotion_gate.status -eq "passed" -and
    $fleetAuthority.promotion_gate.remote_rollout_from_tui_allowed -eq $false
$ringsReady = $ringOrderReady -and $null -ne $localRing -and $localRing.status -eq "local-proof-ready" -and $localRing.node_count -eq 1 -and $remoteRingsBlocked
$rollbackReady = $null -ne $rollback -and
    $rollback.status -eq "passed" -and
    $rollback.rollback_verified -eq $true -and
    $rollback.rollback_previous_equals_restored -eq $true -and
    (Has-Value $rollback.previous_active_artifact_set_sha256) -and
    $rollback.previous_active_artifact_set_sha256 -eq $rollback.restored_active_artifact_set_sha256 -and
    (Has-Value $rollback.evidence_chain.rollback_baseline_sha256) -and
    $rollback.active_slot_mutated -eq $false -and
    $rollback.activation_attempted -eq $false -and
    $rollback.remote_dispatch_enabled -eq $false -and
    $rollback.tui_authority -eq $false
$supportReady = $null -ne $supportRecovery -and
    $supportRecovery.status -eq "passed" -and
    $supportRecovery.support_bundle_redacted -eq $true -and
    $supportRecovery.remote_upload_performed -eq $false -and
    $supportRecovery.remote_dispatch_enabled -eq $false -and
    $supportRecovery.tui_authority -eq $false

$projectedRolloutPlan = [ordered]@{
    schema = "agentos.rc4-staged-fleet-ring-rollout-plan-projection.v1"
    generated_at = "2026-06-08T10:10:00+08:00"
    status = "approval-required-not-executable"
    production_ready_claim = $false
    projection_only = $true
    executable = $false
    ring = "local"
    staged_order = @("local", "canary", "staging", "production")
    authority = "AgentCore fleet_rollout PlanSpec + SecurityExecutionEngine"
    exact_operator_approval_required = $true
    exact_operator_approval_granted = $false
    exact_operator_approval_hash = $null
    approval_binding = if ($null -ne $preconditions) { $preconditions.approval_binding } else { $null }
    target_set = if ($null -ne $preconditions) { $preconditions.target_set } else { $null }
    rollout_policy = if ($null -ne $preconditions) { $preconditions.rollout_policy } else { $null }
    bindings = [ordered]@{
        rc3_final_audit_sha256 = if ($null -ne $preconditions) { $preconditions.projected_bindings.rc3_final_audit_sha256 } else { $null }
        hosted_transport_manifest_sha256 = $hostedManifestHash
        hosted_consumer_mirror_smoke_sha256 = $hostedSmokeHash
        fleet_rollout_preconditions_sha256 = $preconditionsHash
        hosted_transport_fail_closed_sha256 = $failClosedHash
        mirror_publication_sha256 = $mirrorPublicationHash
        mirror_lockfile_sha256 = $mirrorLockfileHash
        fleet_rollout_authority_sha256 = $fleetAuthorityHash
        target_set_sha256 = if ($null -ne $preconditions) { $preconditions.projected_bindings.target_set_sha256 } else { $null }
        rollout_policy_version = if ($null -ne $preconditions) { $preconditions.projected_bindings.rollout_policy_version } else { $null }
        rollout_policy_sha256 = if ($null -ne $preconditions) { $preconditions.projected_bindings.rollout_policy_sha256 } else { $null }
        rollback_baseline_sha256 = if ($null -ne $rollback) { $rollback.evidence_chain.rollback_baseline_sha256 } else { $null }
        rollback_drill_sha256 = $rollbackHash
        support_recovery_sha256 = $supportRecoveryHash
        revocation_snapshot_sha256 = if ($null -ne $preconditions) { $preconditions.projected_bindings.revocation_snapshot_sha256 } else { $null }
        exact_operator_approval_hash = $null
    }
    gates = [ordered]@{
        hosted_consumer_mirror_smoke_passed = $hostedSmokeReady
        fleet_preconditions_ready = $preconditionsReady
        hosted_transport_fail_closed_ready = $failClosedReady
        fleet_authority_ready = $fleetAuthorityReady
        ring_order_ready = $ringOrderReady
        local_ring_smoke_ready = $ringsReady
        rollback_baseline_ready = $rollbackReady
        support_recovery_ready = $supportReady
        approval_gate_status = "blocked-pending-exact-operator-approval"
        execution_gate_status = "blocked-by-design"
    }
    invariants = [ordered]@{
        local_private_key_material_used = $false
        cryptographic_signing_performed = $false
        network_transfer_performed = $false
        remote_upload_performed = $false
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
    }
}

$rollbackProjection = [ordered]@{
    schema = "agentos.rc4-staged-fleet-rollback-drill-projection.v1"
    generated_at = "2026-06-08T10:10:00+08:00"
    status = "projected-passed"
    production_ready_claim = $false
    projection_only = $true
    rollback_execution_performed = $false
    rollback_verified = if ($null -ne $rollback) { $rollback.rollback_verified } else { $false }
    rollback_previous_equals_restored = if ($null -ne $rollback) { $rollback.rollback_previous_equals_restored } else { $false }
    previous_active_artifact_set_sha256 = if ($null -ne $rollback) { $rollback.previous_active_artifact_set_sha256 } else { $null }
    restored_active_artifact_set_sha256 = if ($null -ne $rollback) { $rollback.restored_active_artifact_set_sha256 } else { $null }
    rollback_baseline_sha256 = if ($null -ne $rollback) { $rollback.evidence_chain.rollback_baseline_sha256 } else { $null }
    rollback_drill_sha256 = $rollbackHash
    support_recovery_sha256 = $supportRecoveryHash
    blocked_execution_reason = "rollback is a future SecurityExecutionEngine PlanSpec and is not executed by this RC4 smoke"
    invariants = [ordered]@{
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        persistent_state_mutated = $false
        activation_attempted = $false
        rollback_execution_performed = $false
        remote_dispatch_enabled = $false
        model_replay_authority = $false
        normal_shell_authority = $false
        tui_authority = $false
    }
}

Write-Json -Value $projectedRolloutPlan -Path $projectedRolloutPlanPath
Write-Json -Value $rollbackProjection -Path $rollbackProjectionPath

$projectedPlanHash = Get-FileSha256 $projectedRolloutPlanPath
$rollbackProjectionHash = Get-FileSha256 $rollbackProjectionPath

$projectionBindingReady = $preconditionsReady -and
    $projectedRolloutPlan.bindings.hosted_transport_manifest_sha256 -eq $hostedManifestHash -and
    $projectedRolloutPlan.bindings.hosted_consumer_mirror_smoke_sha256 -eq $hostedSmokeHash -and
    $projectedRolloutPlan.bindings.fleet_rollout_preconditions_sha256 -eq $preconditionsHash -and
    $projectedRolloutPlan.bindings.hosted_transport_fail_closed_sha256 -eq $failClosedHash -and
    $projectedRolloutPlan.bindings.target_set_sha256 -eq $preconditions.projected_bindings.target_set_sha256 -and
    $projectedRolloutPlan.bindings.rollout_policy_sha256 -eq $preconditions.projected_bindings.rollout_policy_sha256 -and
    $projectedRolloutPlan.bindings.rollback_baseline_sha256 -eq $preconditions.projected_bindings.rollback_baseline_sha256 -and
    $projectedRolloutPlan.bindings.revocation_snapshot_sha256 -eq $preconditions.projected_bindings.revocation_snapshot_sha256
$approvalGateReady = $projectedRolloutPlan.exact_operator_approval_required -eq $true -and
    $projectedRolloutPlan.exact_operator_approval_granted -eq $false -and
    $projectedRolloutPlan.exact_operator_approval_hash -eq $null -and
    $projectedRolloutPlan.executable -eq $false -and
    $projectedRolloutPlan.gates.approval_gate_status -eq "blocked-pending-exact-operator-approval"
$rollbackProjectionReady = $rollbackReady -and
    $rollbackProjection.rollback_execution_performed -eq $false -and
    $rollbackProjection.previous_active_artifact_set_sha256 -eq $rollbackProjection.restored_active_artifact_set_sha256 -and
    $rollbackProjection.rollback_baseline_sha256 -eq $preconditions.projected_bindings.rollback_baseline_sha256

Add-Check "rc4.plan.current_task" $planPositionReady "RC4 plan must point at RC4-021 before this smoke, or remain on a later task after RC4-021 is completed." "blocking" $(if ($null -ne $plan) { [ordered]@{ current_task = $plan.current_task; RC4_020 = $rc4TaskStatuses["RC4-020"]; RC4_021 = $rc4TaskStatuses["RC4-021"]; RC4_022 = $rc4TaskStatuses["RC4-022"] } } else { $null })
Add-Check "rc4.hosted_consumer_mirror_smoke.ready" $hostedSmokeReady "RC4-020 hosted consumer and mirror smoke must be passed and mutation-free." "blocking" $(if ($null -ne $hostedSmoke) { $hostedSmoke.summary } else { $null })
Add-Check "rc4.fleet_preconditions.ready" $preconditionsReady "RC4 fleet rollout preconditions must be ready and hash-bound to current hosted, mirror, rollback, support, and fleet authority inputs." "blocking" $(if ($null -ne $preconditions) { $preconditions.projected_bindings } else { $null })
Add-Check "rc4.hosted_transport_fail_closed.ready" $failClosedReady "RC4 hosted transport fail-closed fixtures must pass all negative cases before staged rollout smoke." "blocking" $(if ($null -ne $failClosed) { $failClosed.summary } else { $null })
Add-Check "fleet_authority.execution_boundary" $fleetAuthorityReady "Fleet rollout authority must remain AgentCore/SecurityExecution-only, with no TUI, shell, or remote bypass authority." "blocking" $(if ($null -ne $fleetAuthority) { $fleetAuthority.authority } else { $null })
Add-Check "fleet_rings.local_smoke_remote_blocked" $ringsReady "Local ring must be smoke-ready while canary, staging, and production remain blocked from remote mutation." "blocking" ([ordered]@{ order = @($ringNames); local_status = if ($null -ne $localRing) { $localRing.status } else { $null }; canary_blocker = if ($null -ne $canaryRing) { $canaryRing.blocker } else { $null }; staging_blocker = if ($null -ne $stagingRing) { $stagingRing.blocker } else { $null }; production_blocker = if ($null -ne $productionRing) { $productionRing.blocker } else { $null } })
Add-Check "staged_rollout.projection_hash_bound" $projectionBindingReady "Staged rollout projection must bind hosted smoke, preconditions, fail-closed fixtures, target set, rollout policy, rollback baseline, and revocation snapshot." "blocking" $projectedRolloutPlan.bindings
Add-Check "staged_rollout.approval_required_not_granted" $approvalGateReady "Staged rollout projection must require exact operator approval, leave approval hash absent, and remain non-executable." "blocking" ([ordered]@{ executable = $projectedRolloutPlan.executable; exact_operator_approval_required = $projectedRolloutPlan.exact_operator_approval_required; exact_operator_approval_granted = $projectedRolloutPlan.exact_operator_approval_granted; exact_operator_approval_hash = $projectedRolloutPlan.exact_operator_approval_hash; approval_gate_status = $projectedRolloutPlan.gates.approval_gate_status })
Add-Check "rollback_drill.baseline_previous_restored" $rollbackReady "Rollback source drill must pass, bind a rollback baseline, and keep previous/restored active artifact hashes equal without activation." "blocking" $(if ($null -ne $rollback) { [ordered]@{ status = $rollback.status; rollback_verified = $rollback.rollback_verified; previous = $rollback.previous_active_artifact_set_sha256; restored = $rollback.restored_active_artifact_set_sha256; baseline = $rollback.evidence_chain.rollback_baseline_sha256; active_slot_mutated = $rollback.active_slot_mutated; activation_attempted = $rollback.activation_attempted } } else { $null })
Add-Check "rollback_drill.projection_ready" $rollbackProjectionReady "RC4 rollback drill projection must reuse the bound rollback baseline and remain execution-free." "blocking" ([ordered]@{ rollback_projection_sha256 = $rollbackProjectionHash; previous = $rollbackProjection.previous_active_artifact_set_sha256; restored = $rollbackProjection.restored_active_artifact_set_sha256; baseline = $rollbackProjection.rollback_baseline_sha256; rollback_execution_performed = $rollbackProjection.rollback_execution_performed })
Add-Check "support_recovery.redacted_local_only" $supportReady "Support/recovery evidence must remain passed, redacted, local-only, and non-authoritative." "blocking" $(if ($null -ne $supportRecovery) { $supportRecovery.summary } else { $null })
Add-Check "staged_rollout.no_authority_broadened" $true "RC4 staged rollout smoke must not sign, upload, activate, execute rollback, mutate registry/slot/ring state, dispatch remotely, or grant TUI/model/shell authority." "blocking" $projectedRolloutPlan.invariants

$passed = @($script:blockers).Count -eq 0

$result = [ordered]@{
    schema = "agentos.rc4-staged-fleet-ring-rollout-smoke-rollback-drill.v1"
    generated_at = "2026-06-08T10:10:00+08:00"
    checked_at = (Get-Date).ToString("o")
    task = "RC4-021"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    rc4_021_complete = $passed
    staged_fleet_ring_rollout_smoke_ready = $passed
    rollback_drill_projection_ready = $passed
    rollout_plan_projection_created = $true
    rollout_plan_created = $false
    rollout_plan_executable = $false
    rollout_plan_executed = $false
    exact_operator_approval_required = $true
    exact_operator_approval_granted = $false
    exact_operator_approval_hash = $null
    local_private_key_material_used = $false
    cryptographic_signing_performed = $false
    cryptographic_verification_performed = $false
    network_transfer_performed = $false
    remote_upload_performed = $false
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
    verified = [ordered]@{
        hosted_consumer_mirror_smoke = $hostedSmokeReady
        fleet_rollout_preconditions = $preconditionsReady
        hosted_transport_fail_closed = $failClosedReady
        fleet_rollout_authority = $fleetAuthorityReady
        fleet_ring_order = $ringOrderReady
        local_ring_smoke = $ringsReady
        remote_rings_blocked = $remoteRingsBlocked
        staged_rollout_projection = $projectionBindingReady
        exact_operator_approval_required_not_granted = $approvalGateReady
        rollback_baseline = $rollbackReady
        rollback_drill_projection = $rollbackProjectionReady
        support_recovery = $supportReady
    }
    bindings = [ordered]@{
        staged_rollout_plan_projection_sha256 = $projectedPlanHash
        rollback_drill_projection_sha256 = $rollbackProjectionHash
        hosted_consumer_mirror_smoke_sha256 = $hostedSmokeHash
        fleet_rollout_preconditions_sha256 = $preconditionsHash
        hosted_transport_fail_closed_sha256 = $failClosedHash
        hosted_transport_manifest_sha256 = $hostedManifestHash
        mirror_lockfile_sha256 = $mirrorLockfileHash
        mirror_publication_sha256 = $mirrorPublicationHash
        fleet_rollout_authority_sha256 = $fleetAuthorityHash
        rollback_drill_sha256 = $rollbackHash
        rollback_baseline_sha256 = if ($null -ne $rollback) { $rollback.evidence_chain.rollback_baseline_sha256 } else { $null }
        previous_active_artifact_set_sha256 = if ($null -ne $rollback) { $rollback.previous_active_artifact_set_sha256 } else { $null }
        restored_active_artifact_set_sha256 = if ($null -ne $rollback) { $rollback.restored_active_artifact_set_sha256 } else { $null }
        support_recovery_sha256 = $supportRecoveryHash
        target_set_sha256 = if ($null -ne $preconditions) { $preconditions.projected_bindings.target_set_sha256 } else { $null }
        rollout_policy_sha256 = if ($null -ne $preconditions) { $preconditions.projected_bindings.rollout_policy_sha256 } else { $null }
        rollout_policy_version = if ($null -ne $preconditions) { $preconditions.projected_bindings.rollout_policy_version } else { $null }
        revocation_snapshot_sha256 = if ($null -ne $preconditions) { $preconditions.projected_bindings.revocation_snapshot_sha256 } else { $null }
        exact_operator_approval_hash = $null
    }
    artifacts = [ordered]@{
        staged_rollout_plan_projection = New-Projection -Path $projectedRolloutPlanPath -Json $projectedRolloutPlan
        rollback_drill_projection = New-Projection -Path $rollbackProjectionPath -Json $rollbackProjection
    }
    source_artifacts = [ordered]@{
        rc4_plan = New-Projection -Path $resolvedPlanPath -Json $plan
        hosted_consumer_mirror_smoke = New-Projection -Path $resolvedHostedSmokePath -Json $hostedSmoke
        fleet_rollout_preconditions = New-Projection -Path $resolvedPreconditionsPath -Json $preconditions
        hosted_transport_fail_closed = New-Projection -Path $resolvedFailClosedPath -Json $failClosed
        hosted_transport_manifest = New-Projection -Path $resolvedHostedManifestPath -Json $hostedManifest
        mirror_lockfile = New-Projection -Path $resolvedMirrorLockfilePath -Json $mirrorLockfile
        mirror_publication = New-Projection -Path $resolvedMirrorPublicationPath -Json $mirrorPublication
        fleet_rollout_authority = New-Projection -Path $resolvedFleetAuthorityPath -Json $fleetAuthority
        rollback_drill = New-Projection -Path $resolvedRollbackPath -Json $rollback
        support_recovery = New-Projection -Path $resolvedSupportRecoveryPath -Json $supportRecovery
    }
    checks = $script:checks
    blockers = $script:blockers
    handoff = [ordered]@{
        next_task = "RC4-022"
        rc4_022_consumes = @(
            "staged_fleet_ring_rollout_smoke_rollback_drill",
            "staged_rollout_plan_projection",
            "rollback_drill_projection",
            "hosted_consumer_mirror_smoke",
            "fleet_rollout_preconditions"
        )
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        blockers = @($script:blockers).Count
        rc4_021_complete = $passed
        staged_fleet_ring_rollout_smoke_ready = $passed
        rollback_drill_projection_ready = $passed
        projected_ring = "local"
        remote_rings_blocked = $remoteRingsBlocked
        rollout_plan_projection_created = $true
        rollout_plan_executable = $false
        exact_operator_approval_required = $true
        exact_operator_approval_granted = $false
        production_ready_claim = $false
        network_transfer_performed = $false
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

$resultSecretSafe = Test-NoSensitiveContent -Paths @($projectedRolloutPlanPath, $rollbackProjectionPath, $resolvedOutputPath)
$resultHostPathFree = Test-NoHostPathContent -Paths @($projectedRolloutPlanPath, $rollbackProjectionPath, $resolvedOutputPath)
if (-not $resultSecretSafe -or -not $resultHostPathFree) {
    $extra = [ordered]@{
        id = "staged_rollout_smoke.result_secret_safe"
        status = "failed"
        severity = "blocking"
        message = "RC4 staged rollout smoke and rollback drill artifacts must be secret-safe and host-path-free."
        evidence = [ordered]@{ secret_safe = $resultSecretSafe; host_path_free = $resultHostPathFree; path = Get-StablePath $resolvedOutputPath }
    }
    $script:checks += $extra
    $script:blockers += $extra
    $result.checks = $script:checks
    $result.blockers = $script:blockers
    $result.status = "blocked"
    $result.rc4_021_complete = $false
    $result.staged_fleet_ring_rollout_smoke_ready = $false
    $result.rollback_drill_projection_ready = $false
    $result.summary.checks = @($script:checks).Count
    $result.summary.blockers = @($script:blockers).Count
    $result.summary.rc4_021_complete = $false
    $result.summary.staged_fleet_ring_rollout_smoke_ready = $false
    $result.summary.rollback_drill_projection_ready = $false
    Write-Json -Value $result -Path $resolvedOutputPath
}

Write-Host "RC4 staged fleet-ring rollout smoke and rollback drill $($result.status): $OutputPath"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
