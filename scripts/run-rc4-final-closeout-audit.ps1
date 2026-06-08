param(
    [string]$ArtifactDir = ".workflow/artifacts/rc4-final-closeout-audit",
    [string]$PlanPath = ".workflow/active/WFS-20260608-agentos-production-distro-rc4/plan.json",
    [string]$HostedTransportResultPath = ".workflow/artifacts/rc4-hosted-release-transport/result.json",
    [string]$HostedTransportManifestPath = ".workflow/artifacts/rc4-hosted-release-transport/hosted-transport-manifest.json",
    [string]$MirrorResultPath = ".workflow/artifacts/rc4-remote-registry-mirror-publication/result.json",
    [string]$MirrorPublicationPath = ".workflow/artifacts/rc4-remote-registry-mirror-publication/mirror-publication.json",
    [string]$MirrorLockfilePath = ".workflow/artifacts/rc4-remote-registry-mirror-publication/mirror-lockfile.json",
    [string]$FleetPreconditionsPath = ".workflow/artifacts/rc4-fleet-ring-rollout-preconditions/result.json",
    [string]$FailClosedPath = ".workflow/artifacts/rc4-hosted-transport-fail-closed-fixtures/result.json",
    [string]$HostedConsumerMirrorSmokePath = ".workflow/artifacts/rc4-signed-hosted-channel-consumer-mirror-smoke/result.json",
    [string]$FleetRolloutSmokePath = ".workflow/artifacts/rc4-staged-fleet-ring-rollout-smoke-rollback-drill/result.json",
    [string]$StagedRolloutProjectionPath = ".workflow/artifacts/rc4-staged-fleet-ring-rollout-smoke-rollback-drill/staged-rollout-plan-projection.json",
    [string]$RollbackProjectionPath = ".workflow/artifacts/rc4-staged-fleet-ring-rollout-smoke-rollback-drill/rollback-drill-projection.json",
    [string]$GaSupportRecoveryPath = ".workflow/artifacts/rc4-ga-hardening-support-recovery-projection/result.json",
    [string]$SupportBundlePath = ".workflow/artifacts/rc4-ga-hardening-support-recovery-projection/hosted-fleet-support-bundle-redacted.json",
    [string]$RecoveryProjectionPath = ".workflow/artifacts/rc4-ga-hardening-support-recovery-projection/hosted-fleet-recovery-projection.json",
    [string]$SupportIndexPath = ".workflow/artifacts/rc4-ga-hardening-support-recovery-projection/support-recovery-index.json",
    [string]$PromotionGateResultPath = ".workflow/artifacts/rc4-hosted-fleet-promotion-gate-integration/result.json",
    [string]$PromotionGatePath = ".workflow/artifacts/release/rc4-hosted-fleet-promotion-gate.json",
    [string]$FleetRolloutAuthorityPath = ".workflow/artifacts/release/fleet-rollout-authority.json",
    [string]$CandidatePromotionPath = ".workflow/artifacts/candidate-promotion/default-result.json",
    [string]$ReleaseProvenancePath = ".workflow/artifacts/release/provenance.json",
    [string]$Rc3FinalAuditPath = ".workflow/active/WFS-20260531-agentos-production-distro-rc3/evidence/FINAL-AUDIT-20260531-production-distro-rc3.json",
    [string]$Rc3SigningPublicationGatePath = ".workflow/artifacts/release/rc3-production-signing-publication-gate.json",
    [string]$FinalAuditPath = ".workflow/active/WFS-20260608-agentos-production-distro-rc4/evidence/FINAL-AUDIT-20260608-production-distro-rc4.json",
    [string]$CloseoutSummaryPath = ".workflow/active/WFS-20260608-agentos-production-distro-rc4/docs/final-rc4-closeout-summary.md",
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

function Get-SummaryValue {
    param($Json, [Parameter(Mandatory = $true)][string]$Name)
    if ($null -eq $Json -or $Json.PSObject.Properties.Name -notcontains "summary" -or $null -eq $Json.summary) {
        return $null
    }
    if ($Json.summary.PSObject.Properties.Name -notcontains $Name) {
        return $null
    }
    return $Json.summary.PSObject.Properties[$Name].Value
}

function Get-TaskStatus {
    param($Plan, [Parameter(Mandatory = $true)][string]$TaskId)
    if ($null -eq $Plan -or $Plan.PSObject.Properties.Name -notcontains "waves") {
        return $null
    }
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

function New-ArtifactProjection {
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

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:blockers = @()
$generatedAt = "2026-06-08T10:40:00+08:00"

$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$expectedArtifactDir = Resolve-RepoPath ".workflow/artifacts/rc4-final-closeout-audit"
if (-not $resolvedArtifactDir.Equals($expectedArtifactDir, [StringComparison]::OrdinalIgnoreCase)) {
    throw "ArtifactDir must be .workflow/artifacts/rc4-final-closeout-audit"
}
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null

if (-not $OutputPath) {
    $OutputPath = Join-Path $ArtifactDir "result.json"
}

$resolvedPlanPath = Resolve-RepoPath $PlanPath
$resolvedHostedTransportResultPath = Resolve-RepoPath $HostedTransportResultPath
$resolvedHostedTransportManifestPath = Resolve-RepoPath $HostedTransportManifestPath
$resolvedMirrorResultPath = Resolve-RepoPath $MirrorResultPath
$resolvedMirrorPublicationPath = Resolve-RepoPath $MirrorPublicationPath
$resolvedMirrorLockfilePath = Resolve-RepoPath $MirrorLockfilePath
$resolvedFleetPreconditionsPath = Resolve-RepoPath $FleetPreconditionsPath
$resolvedFailClosedPath = Resolve-RepoPath $FailClosedPath
$resolvedHostedConsumerMirrorSmokePath = Resolve-RepoPath $HostedConsumerMirrorSmokePath
$resolvedFleetRolloutSmokePath = Resolve-RepoPath $FleetRolloutSmokePath
$resolvedStagedRolloutProjectionPath = Resolve-RepoPath $StagedRolloutProjectionPath
$resolvedRollbackProjectionPath = Resolve-RepoPath $RollbackProjectionPath
$resolvedGaSupportRecoveryPath = Resolve-RepoPath $GaSupportRecoveryPath
$resolvedSupportBundlePath = Resolve-RepoPath $SupportBundlePath
$resolvedRecoveryProjectionPath = Resolve-RepoPath $RecoveryProjectionPath
$resolvedSupportIndexPath = Resolve-RepoPath $SupportIndexPath
$resolvedPromotionGateResultPath = Resolve-RepoPath $PromotionGateResultPath
$resolvedPromotionGatePath = Resolve-RepoPath $PromotionGatePath
$resolvedFleetRolloutAuthorityPath = Resolve-RepoPath $FleetRolloutAuthorityPath
$resolvedCandidatePromotionPath = Resolve-RepoPath $CandidatePromotionPath
$resolvedReleaseProvenancePath = Resolve-RepoPath $ReleaseProvenancePath
$resolvedRc3FinalAuditPath = Resolve-RepoPath $Rc3FinalAuditPath
$resolvedRc3SigningPublicationGatePath = Resolve-RepoPath $Rc3SigningPublicationGatePath
$resolvedFinalAuditPath = Resolve-RepoPath $FinalAuditPath
$resolvedCloseoutSummaryPath = Resolve-RepoPath $CloseoutSummaryPath
$resolvedOutputPath = Resolve-RepoPath $OutputPath

$plan = Read-JsonFile $resolvedPlanPath
$hostedTransportResult = Read-JsonFile $resolvedHostedTransportResultPath
$hostedTransportManifest = Read-JsonFile $resolvedHostedTransportManifestPath
$mirrorResult = Read-JsonFile $resolvedMirrorResultPath
$mirrorPublication = Read-JsonFile $resolvedMirrorPublicationPath
$mirrorLockfile = Read-JsonFile $resolvedMirrorLockfilePath
$fleetPreconditions = Read-JsonFile $resolvedFleetPreconditionsPath
$failClosed = Read-JsonFile $resolvedFailClosedPath
$hostedConsumerMirrorSmoke = Read-JsonFile $resolvedHostedConsumerMirrorSmokePath
$fleetRolloutSmoke = Read-JsonFile $resolvedFleetRolloutSmokePath
$stagedRolloutProjection = Read-JsonFile $resolvedStagedRolloutProjectionPath
$rollbackProjection = Read-JsonFile $resolvedRollbackProjectionPath
$gaSupportRecovery = Read-JsonFile $resolvedGaSupportRecoveryPath
$supportBundle = Read-JsonFile $resolvedSupportBundlePath
$recoveryProjection = Read-JsonFile $resolvedRecoveryProjectionPath
$supportIndex = Read-JsonFile $resolvedSupportIndexPath
$promotionGateResult = Read-JsonFile $resolvedPromotionGateResultPath
$promotionGate = Read-JsonFile $resolvedPromotionGatePath
$fleetRolloutAuthority = Read-JsonFile $resolvedFleetRolloutAuthorityPath
$candidatePromotion = Read-JsonFile $resolvedCandidatePromotionPath
$releaseProvenance = Read-JsonFile $resolvedReleaseProvenancePath
$rc3FinalAudit = Read-JsonFile $resolvedRc3FinalAuditPath
$rc3SigningPublicationGate = Read-JsonFile $resolvedRc3SigningPublicationGatePath

$preCloseoutTaskIds = @("RC4-001", "RC4-002", "RC4-003", "RC4-004", "RC4-010", "RC4-011", "RC4-012", "RC4-013", "RC4-020", "RC4-021", "RC4-022", "RC4-023")
$completedBeforeCloseout = 0
foreach ($taskId in $preCloseoutTaskIds) {
    if ((Get-TaskStatus $plan $taskId) -eq "completed") {
        $completedBeforeCloseout++
    }
}

$hostedTransportReady = $null -ne $hostedTransportResult -and $hostedTransportResult.status -eq "passed" -and
    (Get-SummaryValue $hostedTransportResult "rc4_010_complete") -eq $true -and
    (Get-SummaryValue $hostedTransportResult "blockers") -eq 0 -and
    $null -ne $hostedTransportManifest -and $hostedTransportManifest.status -eq "published-locally" -and
    $hostedTransportManifest.production_ready_claim -eq $false -and $hostedTransportManifest.transport.local_fixture_only -eq $true -and
    $hostedTransportManifest.transport.network_transfer_performed -eq $false
$mirrorReady = $null -ne $mirrorResult -and $mirrorResult.status -eq "passed" -and
    (Get-SummaryValue $mirrorResult "rc4_011_complete") -eq $true -and
    (Get-SummaryValue $mirrorResult "blockers") -eq 0 -and
    (Get-SummaryValue $mirrorResult "entry_hash_mismatches") -eq 0 -and
    $null -ne $mirrorPublication -and $mirrorPublication.status -eq "published-locally" -and
    $mirrorPublication.production_ready_claim -eq $false -and $mirrorPublication.mirror.active_registry_mutated -eq $false -and
    $mirrorPublication.bindings.hosted_transport_manifest_sha256 -eq (Get-FileSha256 $resolvedHostedTransportManifestPath)
$fleetPreconditionsReady = $null -ne $fleetPreconditions -and $fleetPreconditions.status -eq "ready-for-fleet-ring-rollout-plan" -and
    (Get-SummaryValue $fleetPreconditions "rc4_012_complete") -eq $true -and
    (Get-SummaryValue $fleetPreconditions "blockers") -eq 0 -and
    (Get-SummaryValue $fleetPreconditions "exact_operator_approval_required") -eq $true -and
    (Get-SummaryValue $fleetPreconditions "exact_operator_approval_granted") -eq $false
$failClosedReady = $null -ne $failClosed -and $failClosed.status -eq "passed" -and
    (Get-SummaryValue $failClosed "rc4_013_complete") -eq $true -and
    (Get-SummaryValue $failClosed "cases") -eq 13 -and
    (Get-SummaryValue $failClosed "passed_cases") -eq 13 -and
    (Get-SummaryValue $failClosed "failed_cases") -eq 0
$hostedSmokeReady = $null -ne $hostedConsumerMirrorSmoke -and $hostedConsumerMirrorSmoke.status -eq "passed" -and
    (Get-SummaryValue $hostedConsumerMirrorSmoke "rc4_020_complete") -eq $true -and
    (Get-SummaryValue $hostedConsumerMirrorSmoke "blockers") -eq 0 -and
    $hostedConsumerMirrorSmoke.bindings.hosted_transport_manifest_sha256 -eq (Get-FileSha256 $resolvedHostedTransportManifestPath) -and
    $hostedConsumerMirrorSmoke.bindings.mirror_publication_sha256 -eq (Get-FileSha256 $resolvedMirrorPublicationPath)
$fleetSmokeReady = $null -ne $fleetRolloutSmoke -and $fleetRolloutSmoke.status -eq "passed" -and
    (Get-SummaryValue $fleetRolloutSmoke "rc4_021_complete") -eq $true -and
    (Get-SummaryValue $fleetRolloutSmoke "blockers") -eq 0 -and
    (Get-SummaryValue $fleetRolloutSmoke "rollout_plan_executable") -eq $false -and
    (Get-SummaryValue $fleetRolloutSmoke "exact_operator_approval_granted") -eq $false
$rolloutProjectionReady = $null -ne $stagedRolloutProjection -and $stagedRolloutProjection.status -eq "approval-required-not-executable" -and
    $stagedRolloutProjection.executable -eq $false -and
    $stagedRolloutProjection.exact_operator_approval_required -eq $true -and
    $stagedRolloutProjection.exact_operator_approval_granted -eq $false -and
    $stagedRolloutProjection.invariants.activation_performed -eq $false -and
    $stagedRolloutProjection.invariants.production_ring_mutated -eq $false
$rollbackProjectionReady = $null -ne $rollbackProjection -and $rollbackProjection.status -eq "projected-passed" -and
    $rollbackProjection.rollback_verified -eq $true -and
    $rollbackProjection.rollback_execution_performed -eq $false -and
    $rollbackProjection.rollback_previous_equals_restored -eq $true
$supportReady = $null -ne $gaSupportRecovery -and $gaSupportRecovery.status -eq "passed" -and
    (Get-SummaryValue $gaSupportRecovery "rc4_022_complete") -eq $true -and
    (Get-SummaryValue $gaSupportRecovery "blockers") -eq 0 -and
    (Get-SummaryValue $gaSupportRecovery "support_bundle_redacted") -eq $true -and
    (Get-SummaryValue $gaSupportRecovery "recovery_projection_emitted") -eq $true -and
    $null -ne $supportBundle -and $supportBundle.status -eq "redacted" -and
    $null -ne $recoveryProjection -and $recoveryProjection.status -eq "projected" -and
    $null -ne $supportIndex -and $supportIndex.status -eq "indexed"
$promotionGateReady = $null -ne $promotionGateResult -and $promotionGateResult.status -eq "passed" -and
    (Get-SummaryValue $promotionGateResult "rc4_023_complete") -eq $true -and
    (Get-SummaryValue $promotionGateResult "blockers") -eq 0 -and
    $null -ne $promotionGate -and $promotionGate.status -eq "passed" -and
    $promotionGate.production_ready_claim -eq $false -and
    $promotionGateResult.gate_artifact_sha256 -eq (Get-FileSha256 $resolvedPromotionGatePath)
$authorityReady = $null -ne $fleetRolloutAuthority -and $fleetRolloutAuthority.status -eq "passed" -and
    $fleetRolloutAuthority.production_ready_claim -eq $false -and
    $fleetRolloutAuthority.authority.execution_authority -eq "AgentCore fleet_rollout PlanSpec + SecurityExecutionEngine" -and
    $fleetRolloutAuthority.authority.tui_authority -eq $false
$releaseGateReady = $null -ne $candidatePromotion -and $candidatePromotion.status -eq "passed" -and (Get-JsonBlockerCount $candidatePromotion) -eq 0 -and
    $null -ne $releaseProvenance -and $releaseProvenance.promotion.status -eq "promotable" -and @($releaseProvenance.promotion.blockers).Count -eq 0
$rc3ChainReady = $null -ne $rc3FinalAudit -and $rc3FinalAudit.verdict -eq "PASS" -and
    $null -ne $rc3SigningPublicationGate -and $rc3SigningPublicationGate.status -eq "passed" -and $rc3SigningPublicationGate.production_ready_claim -eq $false

Add-Check "plan.current_task.closeout_position" ($null -ne $plan -and ($plan.current_task -eq "RC4-030" -or ($null -eq $plan.current_task -and $plan.status -eq "completed"))) "RC4 plan must point at RC4-030 before closeout or be completed after closeout." "blocking" $(if ($null -ne $plan) { [ordered]@{ status = $plan.status; current_task = $plan.current_task } } else { $null })
Add-Check "plan.pre_closeout.completed" ($completedBeforeCloseout -eq @($preCloseoutTaskIds).Count) "RC4-001 through RC4-023 must be completed before closeout." "blocking" ([ordered]@{ completed = $completedBeforeCloseout; required = @($preCloseoutTaskIds).Count })
Add-Check "plan.rc4_030.closeout_position" (@("next", "completed") -contains (Get-TaskStatus $plan "RC4-030")) "RC4-030 must be the next or completed task for final closeout evidence." "blocking" (Get-TaskStatus $plan "RC4-030")
Add-Check "hosted_transport.ready" $hostedTransportReady "Hosted release transport must be hash-bound, local-only, and non-GA." "blocking" $(if ($null -ne $hostedTransportResult) { $hostedTransportResult.summary } else { $null })
Add-Check "remote_registry_mirror.ready" $mirrorReady "Remote registry mirror replay must be fresh, hash-bound, and non-mutating." "blocking" $(if ($null -ne $mirrorResult) { $mirrorResult.summary } else { $null })
Add-Check "fleet_preconditions.ready" $fleetPreconditionsReady "Fleet rollout preconditions must be ready and exact-approval gated." "blocking" $(if ($null -ne $fleetPreconditions) { $fleetPreconditions.summary } else { $null })
Add-Check "hosted_transport_fail_closed.ready" $failClosedReady "Hosted transport fail-closed fixtures must pass 13/13 negative cases." "blocking" $(if ($null -ne $failClosed) { $failClosed.summary } else { $null })
Add-Check "hosted_consumer_mirror_smoke.ready" $hostedSmokeReady "Hosted consumer and mirror smoke must pass and bind current hosted/mirror hashes." "blocking" $(if ($null -ne $hostedConsumerMirrorSmoke) { $hostedConsumerMirrorSmoke.summary } else { $null })
Add-Check "fleet_rollout_smoke.ready" $fleetSmokeReady "Staged fleet rollout smoke must pass without executable activation authority." "blocking" $(if ($null -ne $fleetRolloutSmoke) { $fleetRolloutSmoke.summary } else { $null })
Add-Check "staged_rollout_projection.approval_gated" $rolloutProjectionReady "Staged rollout projection must remain non-executable until exact approval." "blocking" $(if ($null -ne $stagedRolloutProjection) { [ordered]@{ status = $stagedRolloutProjection.status; executable = $stagedRolloutProjection.executable; approval_granted = $stagedRolloutProjection.exact_operator_approval_granted; invariants = $stagedRolloutProjection.invariants } } else { $null })
Add-Check "rollback_projection.projected" $rollbackProjectionReady "Rollback projection must prove previous/restored equality without executing rollback." "blocking" $(if ($null -ne $rollbackProjection) { [ordered]@{ status = $rollbackProjection.status; rollback_verified = $rollbackProjection.rollback_verified; rollback_execution_performed = $rollbackProjection.rollback_execution_performed; rollback_previous_equals_restored = $rollbackProjection.rollback_previous_equals_restored } } else { $null })
Add-Check "ga_support_recovery.ready" $supportReady "GA-hardening support/recovery projection must be redacted, indexed, and non-mutating." "blocking" $(if ($null -ne $gaSupportRecovery) { $gaSupportRecovery.summary } else { $null })
Add-Check "promotion_gate.ready" $promotionGateReady "Hosted/fleet promotion gate must pass and bind current RC4 evidence." "blocking" $(if ($null -ne $promotionGateResult) { $promotionGateResult.summary } else { $null })
Add-Check "fleet_authority.ready" $authorityReady "Fleet rollout authority must remain AgentCore + SecurityExecutionEngine with no TUI authority." "blocking" $(if ($null -ne $fleetRolloutAuthority) { $fleetRolloutAuthority.authority } else { $null })
Add-Check "release_gate.baseline_ready" $releaseGateReady "Candidate promotion and release provenance baselines must remain passing." "blocking" ([ordered]@{ candidate_promotion = if ($null -ne $candidatePromotion) { $candidatePromotion.status } else { $null }; candidate_blockers = Get-JsonBlockerCount $candidatePromotion; provenance_status = if ($null -ne $releaseProvenance) { $releaseProvenance.promotion.status } else { $null }; provenance_blockers = if ($null -ne $releaseProvenance) { @($releaseProvenance.promotion.blockers).Count } else { $null } })
Add-Check "rc3_chain.ready" $rc3ChainReady "RC4 closeout must remain chained to passed RC3 final audit and signing/publication gate." "blocking" ([ordered]@{ rc3_final_audit = if ($null -ne $rc3FinalAudit) { $rc3FinalAudit.verdict } else { $null }; rc3_gate = if ($null -ne $rc3SigningPublicationGate) { $rc3SigningPublicationGate.status } else { $null } })
Add-Check "closeout.no_authority_broadened" $true "Final closeout writes evidence only and must not sign, upload, activate, rollback, mutate active state, dispatch remotely, or grant TUI authority." "blocking" ([ordered]@{
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
    production_ring_mutated = $false
    remote_dispatch_enabled = $false
    tui_authority = $false
})

$passedBeforeWrite = @($script:blockers).Count -eq 0
$sourceArtifacts = [ordered]@{
    plan = New-ArtifactProjection -Path $resolvedPlanPath -Json $plan
    hosted_transport_result = New-ArtifactProjection -Path $resolvedHostedTransportResultPath -Json $hostedTransportResult
    hosted_transport_manifest = New-ArtifactProjection -Path $resolvedHostedTransportManifestPath -Json $hostedTransportManifest
    mirror_result = New-ArtifactProjection -Path $resolvedMirrorResultPath -Json $mirrorResult
    mirror_publication = New-ArtifactProjection -Path $resolvedMirrorPublicationPath -Json $mirrorPublication
    mirror_lockfile = New-ArtifactProjection -Path $resolvedMirrorLockfilePath -Json $mirrorLockfile
    fleet_preconditions = New-ArtifactProjection -Path $resolvedFleetPreconditionsPath -Json $fleetPreconditions
    hosted_transport_fail_closed = New-ArtifactProjection -Path $resolvedFailClosedPath -Json $failClosed
    hosted_consumer_mirror_smoke = New-ArtifactProjection -Path $resolvedHostedConsumerMirrorSmokePath -Json $hostedConsumerMirrorSmoke
    fleet_rollout_smoke = New-ArtifactProjection -Path $resolvedFleetRolloutSmokePath -Json $fleetRolloutSmoke
    staged_rollout_projection = New-ArtifactProjection -Path $resolvedStagedRolloutProjectionPath -Json $stagedRolloutProjection
    rollback_projection = New-ArtifactProjection -Path $resolvedRollbackProjectionPath -Json $rollbackProjection
    ga_support_recovery = New-ArtifactProjection -Path $resolvedGaSupportRecoveryPath -Json $gaSupportRecovery
    support_bundle = New-ArtifactProjection -Path $resolvedSupportBundlePath -Json $supportBundle
    recovery_projection = New-ArtifactProjection -Path $resolvedRecoveryProjectionPath -Json $recoveryProjection
    support_index = New-ArtifactProjection -Path $resolvedSupportIndexPath -Json $supportIndex
    promotion_gate_result = New-ArtifactProjection -Path $resolvedPromotionGateResultPath -Json $promotionGateResult
    promotion_gate = New-ArtifactProjection -Path $resolvedPromotionGatePath -Json $promotionGate
    fleet_rollout_authority = New-ArtifactProjection -Path $resolvedFleetRolloutAuthorityPath -Json $fleetRolloutAuthority
    candidate_promotion = New-ArtifactProjection -Path $resolvedCandidatePromotionPath -Json $candidatePromotion
    release_provenance = New-ArtifactProjection -Path $resolvedReleaseProvenancePath -Json $releaseProvenance
    rc3_final_audit = New-ArtifactProjection -Path $resolvedRc3FinalAuditPath -Json $rc3FinalAudit
    rc3_signing_publication_gate = New-ArtifactProjection -Path $resolvedRc3SigningPublicationGatePath -Json $rc3SigningPublicationGate
}

$audit = [ordered]@{
    schema = "agentos.production-distro-rc4-final-audit.v1"
    audit_id = "FINAL-AUDIT-20260608-production-distro-rc4"
    generated_at = $generatedAt
    production_ready_claim = $false
    decision = if ($passedBeforeWrite) { "rc4-closeout-pass-next-milestone-planning" } else { "rc4-closeout-blocked" }
    scope = [ordered]@{
        milestone = "Production Distro RC4"
        workflow = ".workflow/active/WFS-20260608-agentos-production-distro-rc4"
        task_chain = "RC4-001..RC4-023"
        completed_tasks_before_closeout = $completedBeforeCloseout
        total_tasks_before_closeout = @($preCloseoutTaskIds).Count
        closeout_task = "RC4-030"
        total_tasks_including_closeout = @($preCloseoutTaskIds).Count + 1
        goal = "prove hosted release transport, remote registry mirror replay, staged fleet rollout projection, rollback/support evidence, and promotion gate integration without claiming GA production readiness"
    }
    current_plan_state = [ordered]@{
        current_task = if ($null -ne $plan) { $plan.current_task } else { $null }
        rc4_023_status = Get-TaskStatus $plan "RC4-023"
        rc4_030_status = Get-TaskStatus $plan "RC4-030"
        state_update_performed_by_writer = $false
    }
    invariants_verified = [ordered]@{
        hosted_transport_hash_bound = $hostedTransportReady
        remote_registry_mirror_hash_bound = $mirrorReady
        hosted_transport_fail_closed = $failClosedReady
        fleet_rollout_authority = "AgentCore fleet_rollout PlanSpec + SecurityExecutionEngine"
        exact_operator_approval_required = $true
        exact_operator_approval_granted = $false
        rollback_baseline_required = $true
        rollback_projection_passed = $rollbackProjectionReady
        support_bundle_redacted = $supportReady
        promotion_gate_integrated = $promotionGateReady
        local_private_key_material_used = $false
        cryptographic_signing_performed_by_closeout = $false
        cryptographic_verification_performed_by_closeout = $false
        network_transfer_performed = $false
        remote_upload_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        active_registry_mutated = $false
        active_slot_mutated = $false
        production_ring_mutated = $false
        remote_dispatch_enabled = $false
        tui_authority = $false
        production_ready_claim = $false
    }
    hosted_transport = [ordered]@{
        result_path = Get-StablePath $resolvedHostedTransportResultPath
        result_sha256 = Get-FileSha256 $resolvedHostedTransportResultPath
        manifest_path = Get-StablePath $resolvedHostedTransportManifestPath
        manifest_sha256 = Get-FileSha256 $resolvedHostedTransportManifestPath
        status = if ($null -ne $hostedTransportResult) { $hostedTransportResult.status } else { $null }
        network_transfer_performed = if ($null -ne $hostedTransportManifest) { $hostedTransportManifest.transport.network_transfer_performed } else { $null }
        local_fixture_only = if ($null -ne $hostedTransportManifest) { $hostedTransportManifest.transport.local_fixture_only } else { $null }
    }
    remote_registry_mirror = [ordered]@{
        result_path = Get-StablePath $resolvedMirrorResultPath
        result_sha256 = Get-FileSha256 $resolvedMirrorResultPath
        publication_path = Get-StablePath $resolvedMirrorPublicationPath
        publication_sha256 = Get-FileSha256 $resolvedMirrorPublicationPath
        lockfile_path = Get-StablePath $resolvedMirrorLockfilePath
        lockfile_sha256 = Get-FileSha256 $resolvedMirrorLockfilePath
        status = if ($null -ne $mirrorResult) { $mirrorResult.status } else { $null }
        mirror_entries = Get-SummaryValue $mirrorResult "mirror_entries"
        entry_hash_mismatches = Get-SummaryValue $mirrorResult "entry_hash_mismatches"
        active_registry_mutated = if ($null -ne $mirrorPublication) { $mirrorPublication.mirror.active_registry_mutated } else { $null }
    }
    fleet_rollout = [ordered]@{
        preconditions_path = Get-StablePath $resolvedFleetPreconditionsPath
        preconditions_sha256 = Get-FileSha256 $resolvedFleetPreconditionsPath
        smoke_path = Get-StablePath $resolvedFleetRolloutSmokePath
        smoke_sha256 = Get-FileSha256 $resolvedFleetRolloutSmokePath
        staged_rollout_projection_path = Get-StablePath $resolvedStagedRolloutProjectionPath
        staged_rollout_projection_sha256 = Get-FileSha256 $resolvedStagedRolloutProjectionPath
        projected_ring = Get-SummaryValue $fleetRolloutSmoke "projected_ring"
        remote_rings_blocked = Get-SummaryValue $fleetRolloutSmoke "remote_rings_blocked"
        rollout_plan_executable = Get-SummaryValue $fleetRolloutSmoke "rollout_plan_executable"
        exact_operator_approval_required = Get-SummaryValue $fleetRolloutSmoke "exact_operator_approval_required"
        exact_operator_approval_granted = Get-SummaryValue $fleetRolloutSmoke "exact_operator_approval_granted"
    }
    rollback = [ordered]@{
        projection_path = Get-StablePath $resolvedRollbackProjectionPath
        projection_sha256 = Get-FileSha256 $resolvedRollbackProjectionPath
        rollback_verified = if ($null -ne $rollbackProjection) { $rollbackProjection.rollback_verified } else { $null }
        rollback_execution_performed = if ($null -ne $rollbackProjection) { $rollbackProjection.rollback_execution_performed } else { $null }
        previous_active_artifact_set_sha256 = if ($null -ne $rollbackProjection) { $rollbackProjection.previous_active_artifact_set_sha256 } else { $null }
        restored_active_artifact_set_sha256 = if ($null -ne $rollbackProjection) { $rollbackProjection.restored_active_artifact_set_sha256 } else { $null }
    }
    support_recovery = [ordered]@{
        result_path = Get-StablePath $resolvedGaSupportRecoveryPath
        result_sha256 = Get-FileSha256 $resolvedGaSupportRecoveryPath
        support_bundle_path = Get-StablePath $resolvedSupportBundlePath
        support_bundle_sha256 = Get-FileSha256 $resolvedSupportBundlePath
        recovery_projection_path = Get-StablePath $resolvedRecoveryProjectionPath
        recovery_projection_sha256 = Get-FileSha256 $resolvedRecoveryProjectionPath
        support_index_path = Get-StablePath $resolvedSupportIndexPath
        support_index_sha256 = Get-FileSha256 $resolvedSupportIndexPath
        support_bundle_redacted = Get-SummaryValue $gaSupportRecovery "support_bundle_redacted"
        remote_upload_performed = Get-SummaryValue $gaSupportRecovery "remote_upload_performed"
        remote_bytes_sent = Get-SummaryValue $gaSupportRecovery "remote_bytes_sent"
    }
    promotion_gate = [ordered]@{
        result_path = Get-StablePath $resolvedPromotionGateResultPath
        result_sha256 = Get-FileSha256 $resolvedPromotionGateResultPath
        gate_path = Get-StablePath $resolvedPromotionGatePath
        gate_sha256 = Get-FileSha256 $resolvedPromotionGatePath
        status = if ($null -ne $promotionGateResult) { $promotionGateResult.status } else { $null }
        failure_cases = Get-SummaryValue $promotionGateResult "failure_cases"
        release_provenance_mutated = Get-SummaryValue $promotionGateResult "release_provenance_mutated"
        candidate_promotion_mutated = Get-SummaryValue $promotionGateResult "candidate_promotion_mutated"
    }
    fail_closed_coverage = [ordered]@{
        hosted_transport_negative_cases = Get-SummaryValue $failClosed "cases"
        hosted_transport_negative_passed = Get-SummaryValue $failClosed "passed_cases"
        promotion_gate_failure_cases = Get-SummaryValue $promotionGateResult "failure_cases"
    }
    release_gate = [ordered]@{
        candidate_promotion_path = Get-StablePath $resolvedCandidatePromotionPath
        candidate_promotion_sha256 = Get-FileSha256 $resolvedCandidatePromotionPath
        candidate_promotion_status = if ($null -ne $candidatePromotion) { $candidatePromotion.status } else { $null }
        candidate_promotion_blockers = Get-JsonBlockerCount $candidatePromotion
        release_provenance_path = Get-StablePath $resolvedReleaseProvenancePath
        release_provenance_sha256 = Get-FileSha256 $resolvedReleaseProvenancePath
        release_provenance_status = if ($null -ne $releaseProvenance) { $releaseProvenance.promotion.status } else { $null }
        release_provenance_blockers = if ($null -ne $releaseProvenance) { @($releaseProvenance.promotion.blockers).Count } else { $null }
    }
    source_artifacts = $sourceArtifacts
    task_results = @(
        [ordered]@{ id = "RC4-001"; status = Get-TaskStatus $plan "RC4-001"; result = "hosted transport, registry mirror, and fleet-ring boundary" }
        [ordered]@{ id = "RC4-002"; status = Get-TaskStatus $plan "RC4-002"; result = "staged rollout authority and rollback boundary" }
        [ordered]@{ id = "RC4-003"; status = Get-TaskStatus $plan "RC4-003"; result = "GA hardening acceptance gates and non-GA boundary" }
        [ordered]@{ id = "RC4-004"; status = Get-TaskStatus $plan "RC4-004"; result = "hosted transport and fleet rollout threat model" }
        [ordered]@{ id = "RC4-010"; status = Get-TaskStatus $plan "RC4-010"; result = "hosted release transport manifest and local mirror fixture" }
        [ordered]@{ id = "RC4-011"; status = Get-TaskStatus $plan "RC4-011"; result = "remote registry mirror publication replay" }
        [ordered]@{ id = "RC4-012"; status = Get-TaskStatus $plan "RC4-012"; result = "fleet-ring rollout plan precondition audit" }
        [ordered]@{ id = "RC4-013"; status = Get-TaskStatus $plan "RC4-013"; result = "hosted transport fail-closed fixtures" }
        [ordered]@{ id = "RC4-020"; status = Get-TaskStatus $plan "RC4-020"; result = "signed hosted-channel consumer and mirror smoke" }
        [ordered]@{ id = "RC4-021"; status = Get-TaskStatus $plan "RC4-021"; result = "staged fleet-ring rollout smoke and rollback drill" }
        [ordered]@{ id = "RC4-022"; status = Get-TaskStatus $plan "RC4-022"; result = "GA-hardening support and recovery projection" }
        [ordered]@{ id = "RC4-023"; status = Get-TaskStatus $plan "RC4-023"; result = "hosted/fleet promotion gate integration" }
    )
    acceptance_coverage = @(
        [ordered]@{ requirement = "hosted release transport metadata is hash-bound to RC3 publication and signing gate evidence"; status = if ($hostedTransportReady) { "proved" } else { "blocked" }; evidence = Get-StablePath $resolvedHostedTransportManifestPath }
        [ordered]@{ requirement = "remote registry mirror replay proves mirror freshness, lockfile binding, and fail-closed handling"; status = if ($mirrorReady -and $failClosedReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolvedMirrorPublicationPath), (Get-StablePath $resolvedFailClosedPath)) }
        [ordered]@{ requirement = "fleet rollout remains staged, exact-approval gated, and routed through AgentCore/SecurityExecutionEngine"; status = if ($fleetPreconditionsReady -and $fleetSmokeReady -and $rolloutProjectionReady -and $authorityReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolvedFleetPreconditionsPath), (Get-StablePath $resolvedStagedRolloutProjectionPath)) }
        [ordered]@{ requirement = "rollback projection proves previous/restored equality without executing rollback"; status = if ($rollbackProjectionReady) { "proved" } else { "blocked" }; evidence = Get-StablePath $resolvedRollbackProjectionPath }
        [ordered]@{ requirement = "support/recovery bundle is redacted and explains hosted/fleet/mirror state"; status = if ($supportReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolvedSupportBundlePath), (Get-StablePath $resolvedSupportIndexPath)) }
        [ordered]@{ requirement = "promotion gate consumes hosted transport and fleet evidence and fails closed for missing/stale/mismatched inputs"; status = if ($promotionGateReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolvedPromotionGatePath), (Get-StablePath $resolvedPromotionGateResultPath)) }
    )
    non_ga_gaps = @(
        "RC4 uses local hosted transport and mirror fixtures; it does not prove real hosted multi-region release transport or service availability.",
        "Fleet rollout remains a projection/smoke. Exact operator approval is intentionally not granted, and no activation, active-slot mutation, production ring mutation, or rollback execution occurs.",
        "Remote registry mirroring is replayed locally; authoritative remote registry governance, production mirror availability, and continuous freshness monitoring remain future work.",
        "Support upload remains local/redacted evidence; real remote support upload policy, incident operations, and long-duration operational soak remain outside RC4.",
        "GA readiness still requires controlled real hosted transport, multi-node canary/staging rings, signed rollout execution under approval, rollback execution drill, secure boot/hardware matrix, upgrade compatibility, and production monitoring."
    )
    next_milestone = [ordered]@{
        id = "Production Distro RC5"
        title = "controlled hosted transport service and multi-node fleet canary execution proof"
        reason = "RC4 closes local hosted/fleet promotion evidence. The next gap is proving a controlled hosted release endpoint, authoritative mirror freshness, exact-approved multi-node canary/staging rollout execution, and rollback execution evidence without weakening signing, rollback, support, or TUI authority boundaries."
    }
    verdict = if ($passedBeforeWrite) { "PASS" } else { "BLOCKED" }
}

$summaryText = @"
# Production Distro RC4 Closeout Summary

RC4 closes the hosted release transport and fleet promotion evidence scope. Hosted transport, remote registry mirror replay, fleet rollout preconditions, fail-closed fixtures, hosted consumer/mirror smoke, staged fleet rollout smoke, rollback projection, GA support/recovery projection, and hosted/fleet promotion gate integration all passed with zero blockers.

This is not a GA production-ready claim. RC4 proves local hosted transport and mirror evidence, staged fleet rollout readiness, rollback/support projections, and promotion gate integration while preserving no-local-private-key, no-activation, no-rollback-execution, no-active-registry/slot mutation, no-production-ring mutation, no-remote-dispatch, and TUI projection-only boundaries.

## Evidence

- Hosted transport: `.workflow/artifacts/rc4-hosted-release-transport/result.json`
- Hosted transport manifest: `.workflow/artifacts/rc4-hosted-release-transport/hosted-transport-manifest.json`
- Remote registry mirror publication: `.workflow/artifacts/rc4-remote-registry-mirror-publication/result.json`
- Fleet rollout preconditions: `.workflow/artifacts/rc4-fleet-ring-rollout-preconditions/result.json`
- Hosted transport fail-closed fixtures: `.workflow/artifacts/rc4-hosted-transport-fail-closed-fixtures/result.json`
- Hosted consumer/mirror smoke: `.workflow/artifacts/rc4-signed-hosted-channel-consumer-mirror-smoke/result.json`
- Staged fleet rollout smoke: `.workflow/artifacts/rc4-staged-fleet-ring-rollout-smoke-rollback-drill/result.json`
- Rollback projection: `.workflow/artifacts/rc4-staged-fleet-ring-rollout-smoke-rollback-drill/rollback-drill-projection.json`
- GA support/recovery projection: `.workflow/artifacts/rc4-ga-hardening-support-recovery-projection/result.json`
- Hosted/fleet promotion gate: `.workflow/artifacts/release/rc4-hosted-fleet-promotion-gate.json`
- Final audit: `.workflow/active/WFS-20260608-agentos-production-distro-rc4/evidence/FINAL-AUDIT-20260608-production-distro-rc4.json`

## Verdict

Verdict PASS - Production Distro RC4 is closed for the hosted transport, mirror, staged fleet rollout, support/recovery, and promotion gate proof scope.

## Next Milestone

Production Distro RC5 should focus on a controlled hosted release endpoint, authoritative mirror freshness, exact-approved multi-node canary/staging rollout execution, rollback execution evidence, and GA operational hardening while preserving the RC2/RC3/RC4 signing, rollback, support, fleet authority, and TUI projection-only boundaries.
"@

if ($passedBeforeWrite) {
    Write-Json -Value $audit -Path $resolvedFinalAuditPath
    $parent = Split-Path -Parent $resolvedCloseoutSummaryPath
    if ($parent) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    Set-Content -LiteralPath $resolvedCloseoutSummaryPath -Value $summaryText -Encoding UTF8

    Add-Check "final_audit.written" (Test-Path -LiteralPath $resolvedFinalAuditPath -PathType Leaf) "Final RC4 audit artifact must be written." "blocking" ([ordered]@{ path = Get-StablePath $resolvedFinalAuditPath; sha256 = Get-FileSha256 $resolvedFinalAuditPath })
    Add-Check "closeout_summary.written" (Test-Path -LiteralPath $resolvedCloseoutSummaryPath -PathType Leaf) "Final RC4 closeout summary must be written." "blocking" ([ordered]@{ path = Get-StablePath $resolvedCloseoutSummaryPath; sha256 = Get-FileSha256 $resolvedCloseoutSummaryPath })
    Add-Check "closeout_outputs.secret_safe" (Test-NoSensitiveContent -Paths @($resolvedFinalAuditPath, $resolvedCloseoutSummaryPath)) "Final RC4 closeout outputs must not contain private keys, signer tokens, authorization token strings, or private authority paths." "blocking" ([ordered]@{ final_audit = Get-StablePath $resolvedFinalAuditPath; closeout_summary = Get-StablePath $resolvedCloseoutSummaryPath })
    Add-Check "closeout_outputs.host_path_free" (Test-NoHostPathContent -Paths @($resolvedFinalAuditPath, $resolvedCloseoutSummaryPath)) "Final RC4 closeout outputs must not contain host-local absolute paths." "blocking" ([ordered]@{ final_audit = Get-StablePath $resolvedFinalAuditPath; closeout_summary = Get-StablePath $resolvedCloseoutSummaryPath })
}

$passed = @($script:blockers).Count -eq 0
$result = [ordered]@{
    schema = "agentos.rc4-final-closeout-audit-result.v1"
    generated_at = $generatedAt
    checked_at = $generatedAt
    task = "RC4-030"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    rc4_030_complete = $passed
    final_audit_written = Test-Path -LiteralPath $resolvedFinalAuditPath -PathType Leaf
    closeout_summary_written = Test-Path -LiteralPath $resolvedCloseoutSummaryPath -PathType Leaf
    state_update_performed_by_writer = $false
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
    production_ring_mutated = $false
    remote_dispatch_enabled = $false
    tui_authority = $false
    source_artifacts = $sourceArtifacts
    outputs = [ordered]@{
        final_audit = [ordered]@{ path = Get-StablePath $resolvedFinalAuditPath; sha256 = Get-FileSha256 $resolvedFinalAuditPath; present = Test-Path -LiteralPath $resolvedFinalAuditPath -PathType Leaf }
        closeout_summary = [ordered]@{ path = Get-StablePath $resolvedCloseoutSummaryPath; sha256 = Get-FileSha256 $resolvedCloseoutSummaryPath; present = Test-Path -LiteralPath $resolvedCloseoutSummaryPath -PathType Leaf }
    }
    checks = $script:checks
    blockers = $script:blockers
    summary = [ordered]@{
        checks = @($script:checks).Count
        blockers = @($script:blockers).Count
        rc4_030_complete = $passed
        final_audit_written = Test-Path -LiteralPath $resolvedFinalAuditPath -PathType Leaf
        closeout_summary_written = Test-Path -LiteralPath $resolvedCloseoutSummaryPath -PathType Leaf
        hosted_transport_ready = $hostedTransportReady
        remote_registry_mirror_ready = $mirrorReady
        fleet_rollout_ready = $fleetPreconditionsReady -and $fleetSmokeReady -and $rolloutProjectionReady
        rollback_projection_ready = $rollbackProjectionReady
        support_recovery_ready = $supportReady
        promotion_gate_ready = $promotionGateReady
        production_ready_claim = $false
        state_update_performed_by_writer = $false
    }
}

Write-Json -Value $result -Path $resolvedOutputPath
Write-Host "RC4 final closeout audit $($result.status): $OutputPath"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
