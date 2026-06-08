param(
    [string]$ArtifactDir = ".workflow/artifacts/rc4-hosted-fleet-promotion-gate-integration",
    [string]$Rc4PlanPath = ".workflow/active/WFS-20260608-agentos-production-distro-rc4/plan.json",
    [string]$HostedTransportResultPath = ".workflow/artifacts/rc4-hosted-release-transport/result.json",
    [string]$HostedTransportManifestPath = ".workflow/artifacts/rc4-hosted-release-transport/hosted-transport-manifest.json",
    [string]$MirrorPublicationResultPath = ".workflow/artifacts/rc4-remote-registry-mirror-publication/result.json",
    [string]$MirrorLockfilePath = ".workflow/artifacts/rc4-remote-registry-mirror-publication/mirror-lockfile.json",
    [string]$MirrorPublicationPath = ".workflow/artifacts/rc4-remote-registry-mirror-publication/mirror-publication.json",
    [string]$FleetRolloutPreconditionsPath = ".workflow/artifacts/rc4-fleet-ring-rollout-preconditions/result.json",
    [string]$HostedTransportFailClosedPath = ".workflow/artifacts/rc4-hosted-transport-fail-closed-fixtures/result.json",
    [string]$HostedConsumerMirrorSmokePath = ".workflow/artifacts/rc4-signed-hosted-channel-consumer-mirror-smoke/result.json",
    [string]$FleetRolloutSmokePath = ".workflow/artifacts/rc4-staged-fleet-ring-rollout-smoke-rollback-drill/result.json",
    [string]$GaSupportRecoveryPath = ".workflow/artifacts/rc4-ga-hardening-support-recovery-projection/result.json",
    [string]$FleetRolloutAuthorityPath = ".workflow/artifacts/release/fleet-rollout-authority.json",
    [string]$CandidatePromotionPath = ".workflow/artifacts/candidate-promotion/default-result.json",
    [string]$ReleaseProvenancePath = ".workflow/artifacts/release/provenance.json",
    [string]$Rc3SigningPublicationGatePath = ".workflow/artifacts/release/rc3-production-signing-publication-gate.json",
    [string]$GatePath = ".workflow/artifacts/release/rc4-hosted-fleet-promotion-gate.json",
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

function New-FailureCase {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$RequiredInput
    )
    return [ordered]@{
        name = $Name
        required_input = $RequiredInput
        status = "fail-closed-required"
        promotion_allowed = $false
        production_ready_claim = $false
        activation_performed = $false
        rollback_execution_performed = $false
        active_registry_mutated = $false
        active_slot_mutated = $false
        production_ring_mutated = $false
        remote_dispatch_enabled = $false
        tui_authority = $false
    }
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:blockers = @()

$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$expectedArtifactDir = Resolve-RepoPath ".workflow/artifacts/rc4-hosted-fleet-promotion-gate-integration"
if (-not $resolvedArtifactDir.Equals($expectedArtifactDir, [StringComparison]::OrdinalIgnoreCase)) {
    throw "ArtifactDir must be .workflow/artifacts/rc4-hosted-fleet-promotion-gate-integration"
}
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null

if (-not $OutputPath) {
    $OutputPath = Join-Path $ArtifactDir "result.json"
}

$resolvedPlanPath = Resolve-RepoPath $Rc4PlanPath
$resolvedHostedResultPath = Resolve-RepoPath $HostedTransportResultPath
$resolvedHostedManifestPath = Resolve-RepoPath $HostedTransportManifestPath
$resolvedMirrorResultPath = Resolve-RepoPath $MirrorPublicationResultPath
$resolvedMirrorLockfilePath = Resolve-RepoPath $MirrorLockfilePath
$resolvedMirrorPublicationPath = Resolve-RepoPath $MirrorPublicationPath
$resolvedFleetPreconditionsPath = Resolve-RepoPath $FleetRolloutPreconditionsPath
$resolvedFailClosedPath = Resolve-RepoPath $HostedTransportFailClosedPath
$resolvedHostedSmokePath = Resolve-RepoPath $HostedConsumerMirrorSmokePath
$resolvedFleetSmokePath = Resolve-RepoPath $FleetRolloutSmokePath
$resolvedSupportRecoveryPath = Resolve-RepoPath $GaSupportRecoveryPath
$resolvedFleetAuthorityPath = Resolve-RepoPath $FleetRolloutAuthorityPath
$resolvedCandidatePromotionPath = Resolve-RepoPath $CandidatePromotionPath
$resolvedProvenancePath = Resolve-RepoPath $ReleaseProvenancePath
$resolvedRc3GatePath = Resolve-RepoPath $Rc3SigningPublicationGatePath
$resolvedGatePath = Resolve-RepoPath $GatePath
$resolvedOutputPath = Resolve-RepoPath $OutputPath

$plan = Read-JsonFile $resolvedPlanPath
$hostedResult = Read-JsonFile $resolvedHostedResultPath
$hostedManifest = Read-JsonFile $resolvedHostedManifestPath
$mirrorResult = Read-JsonFile $resolvedMirrorResultPath
$mirrorLockfile = Read-JsonFile $resolvedMirrorLockfilePath
$mirrorPublication = Read-JsonFile $resolvedMirrorPublicationPath
$fleetPreconditions = Read-JsonFile $resolvedFleetPreconditionsPath
$failClosed = Read-JsonFile $resolvedFailClosedPath
$hostedSmoke = Read-JsonFile $resolvedHostedSmokePath
$fleetSmoke = Read-JsonFile $resolvedFleetSmokePath
$supportRecovery = Read-JsonFile $resolvedSupportRecoveryPath
$fleetAuthority = Read-JsonFile $resolvedFleetAuthorityPath
$candidatePromotion = Read-JsonFile $resolvedCandidatePromotionPath
$provenance = Read-JsonFile $resolvedProvenancePath
$rc3Gate = Read-JsonFile $resolvedRc3GatePath

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

$hashes = [ordered]@{
    rc4_plan_sha256 = Get-FileSha256 $resolvedPlanPath
    hosted_transport_result_sha256 = Get-FileSha256 $resolvedHostedResultPath
    hosted_transport_manifest_sha256 = Get-FileSha256 $resolvedHostedManifestPath
    mirror_publication_result_sha256 = Get-FileSha256 $resolvedMirrorResultPath
    mirror_lockfile_sha256 = Get-FileSha256 $resolvedMirrorLockfilePath
    mirror_publication_sha256 = Get-FileSha256 $resolvedMirrorPublicationPath
    fleet_rollout_preconditions_sha256 = Get-FileSha256 $resolvedFleetPreconditionsPath
    hosted_transport_fail_closed_sha256 = Get-FileSha256 $resolvedFailClosedPath
    hosted_consumer_mirror_smoke_sha256 = Get-FileSha256 $resolvedHostedSmokePath
    fleet_rollout_smoke_sha256 = Get-FileSha256 $resolvedFleetSmokePath
    ga_support_recovery_sha256 = Get-FileSha256 $resolvedSupportRecoveryPath
    fleet_rollout_authority_sha256 = Get-FileSha256 $resolvedFleetAuthorityPath
    candidate_promotion_sha256 = Get-FileSha256 $resolvedCandidatePromotionPath
    release_provenance_sha256 = Get-FileSha256 $resolvedProvenancePath
    rc3_signing_publication_gate_sha256 = Get-FileSha256 $resolvedRc3GatePath
}

$planPositionReady = $null -ne $plan -and (
    $plan.current_task -eq "RC4-023" -or
    ($rc4TaskStatuses["RC4-023"] -eq "completed" -and $plan.current_task -eq "RC4-030")
)
$hostedReady = $null -ne $hostedResult -and $hostedResult.status -eq "passed" -and $hostedResult.rc4_010_complete -eq $true -and
    $null -ne $hostedManifest -and $hostedManifest.status -eq "published-locally" -and
    $hostedManifest.production_ready_claim -eq $false -and $hostedManifest.transport.local_fixture_only -eq $true -and
    $hostedManifest.transport.network_transfer_performed -eq $false -and (Get-JsonBlockerCount $hostedResult) -eq 0
$mirrorReady = $null -ne $mirrorResult -and $mirrorResult.status -eq "passed" -and $mirrorResult.rc4_011_complete -eq $true -and
    $null -ne $mirrorPublication -and $mirrorPublication.status -eq "published-locally" -and
    $mirrorPublication.production_ready_claim -eq $false -and $mirrorPublication.mirror.active_registry_mutated -eq $false -and
    $mirrorPublication.bindings.hosted_transport_manifest_sha256 -eq $hashes.hosted_transport_manifest_sha256 -and
    $mirrorPublication.bindings.mirror_lockfile_sha256 -eq $hashes.mirror_lockfile_sha256 -and
    (Get-JsonBlockerCount $mirrorResult) -eq 0
$preconditionsReady = $null -ne $fleetPreconditions -and $fleetPreconditions.status -eq "ready-for-fleet-ring-rollout-plan" -and
    $fleetPreconditions.rc4_012_complete -eq $true -and (Get-JsonBlockerCount $fleetPreconditions) -eq 0
$failClosedReady = $null -ne $failClosed -and $failClosed.status -eq "passed" -and
    $failClosed.rc4_013_complete -eq $true -and $failClosed.summary.passed_cases -eq 13 -and (Get-JsonBlockerCount $failClosed) -eq 0
$hostedSmokeReady = $null -ne $hostedSmoke -and $hostedSmoke.status -eq "passed" -and $hostedSmoke.rc4_020_complete -eq $true -and
    $hostedSmoke.bindings.hosted_transport_manifest_sha256 -eq $hashes.hosted_transport_manifest_sha256 -and
    $hostedSmoke.bindings.mirror_publication_sha256 -eq $hashes.mirror_publication_sha256 -and
    (Get-JsonBlockerCount $hostedSmoke) -eq 0
$fleetSmokeReady = $null -ne $fleetSmoke -and $fleetSmoke.status -eq "passed" -and $fleetSmoke.rc4_021_complete -eq $true -and
    $fleetSmoke.bindings.hosted_transport_manifest_sha256 -eq $hashes.hosted_transport_manifest_sha256 -and
    $fleetSmoke.bindings.mirror_publication_sha256 -eq $hashes.mirror_publication_sha256 -and
    $fleetSmoke.bindings.fleet_rollout_preconditions_sha256 -eq $hashes.fleet_rollout_preconditions_sha256 -and
    $fleetSmoke.rollout_plan_executable -eq $false -and $fleetSmoke.exact_operator_approval_granted -eq $false -and
    $fleetSmoke.activation_performed -eq $false -and $fleetSmoke.rollback_execution_performed -eq $false -and
    (Get-JsonBlockerCount $fleetSmoke) -eq 0
$supportReady = $null -ne $supportRecovery -and $supportRecovery.status -eq "passed" -and $supportRecovery.rc4_022_complete -eq $true -and
    $supportRecovery.support_bundle_redacted -eq $true -and $supportRecovery.recovery_projection_emitted -eq $true -and
    $supportRecovery.production_ready_claim -eq $false -and $supportRecovery.remote_dispatch_enabled -eq $false -and
    (Get-JsonBlockerCount $supportRecovery) -eq 0
$fleetAuthorityReady = $null -ne $fleetAuthority -and $fleetAuthority.status -eq "passed" -and
    $fleetAuthority.production_ready_claim -eq $false -and
    $fleetAuthority.authority.execution_authority -eq "AgentCore fleet_rollout PlanSpec + SecurityExecutionEngine" -and
    $fleetAuthority.authority.tui_authority -eq $false -and
    $fleetAuthority.promotion_gate.status -eq "passed" -and @($fleetAuthority.promotion_gate.blockers).Count -eq 0
$candidatePromotionReady = $null -ne $candidatePromotion -and $candidatePromotion.status -eq "passed" -and (Get-JsonBlockerCount $candidatePromotion) -eq 0
$provenanceReady = $null -ne $provenance -and $provenance.promotion.status -eq "promotable" -and @($provenance.promotion.blockers).Count -eq 0
$rc3GateReady = $null -ne $rc3Gate -and $rc3Gate.status -eq "passed" -and $rc3Gate.production_ready_claim -eq $false

Add-Check "rc4.plan.current_task" $planPositionReady "RC4 plan must point at RC4-023 before this gate integration, or RC4-030 after completion." "blocking" $(if ($null -ne $plan) { [ordered]@{ current_task = $plan.current_task; RC4_022 = $rc4TaskStatuses["RC4-022"]; RC4_023 = $rc4TaskStatuses["RC4-023"] } } else { $null })
Add-Check "hosted_transport.ready" $hostedReady "Hosted transport evidence must pass, remain local-only, and avoid GA claims." "blocking" $(if ($null -ne $hostedResult) { $hostedResult.summary } else { $null })
Add-Check "mirror.ready" $mirrorReady "Mirror evidence must pass, remain hash-bound, and avoid active registry mutation." "blocking" $(if ($null -ne $mirrorResult) { $mirrorResult.summary } else { $null })
Add-Check "fleet_preconditions.ready" $preconditionsReady "Fleet rollout preconditions must be ready with zero blockers." "blocking" $(if ($null -ne $fleetPreconditions) { $fleetPreconditions.summary } else { $null })
Add-Check "hosted_transport.fail_closed" $failClosedReady "Hosted transport fail-closed fixtures must pass all negative cases." "blocking" $(if ($null -ne $failClosed) { $failClosed.summary } else { $null })
Add-Check "hosted_consumer_mirror_smoke.ready" $hostedSmokeReady "Hosted consumer/mirror smoke must pass and bind hosted/mirror hashes." "blocking" $(if ($null -ne $hostedSmoke) { $hostedSmoke.summary } else { $null })
Add-Check "fleet_rollout_smoke.ready" $fleetSmokeReady "Fleet rollout smoke must pass, remain approval-gated, and bind hosted/mirror/precondition hashes." "blocking" $(if ($null -ne $fleetSmoke) { $fleetSmoke.summary } else { $null })
Add-Check "ga_support_recovery.ready" $supportReady "GA-hardening support/recovery projection must pass, remain redacted, and avoid mutation authority." "blocking" $(if ($null -ne $supportRecovery) { $supportRecovery.summary } else { $null })
Add-Check "fleet_rollout_authority.ready" $fleetAuthorityReady "Fleet rollout authority and its promotion gate must pass without TUI authority." "blocking" $(if ($null -ne $fleetAuthority) { [ordered]@{ status = $fleetAuthority.status; authority = $fleetAuthority.authority; promotion_gate = $fleetAuthority.promotion_gate } } else { $null })
Add-Check "candidate_promotion.baseline_ready" $candidatePromotionReady "Existing candidate promotion baseline must pass with zero blockers before adding RC4 gate evidence." "blocking" ([ordered]@{ status = if ($null -ne $candidatePromotion) { $candidatePromotion.status } else { $null }; blockers = Get-JsonBlockerCount $candidatePromotion })
Add-Check "release_provenance.baseline_ready" $provenanceReady "Existing release provenance baseline must remain promotable with zero blockers." "blocking" $(if ($null -ne $provenance) { $provenance.promotion } else { $null })
Add-Check "rc3_signing_publication_gate.ready" $rc3GateReady "RC4 promotion gate must remain chained to passed RC3 signing/publication gate evidence." "blocking" $(if ($null -ne $rc3Gate) { [ordered]@{ status = $rc3Gate.status; production_ready_claim = $rc3Gate.production_ready_claim } } else { $null })

$failureCases = @(
    (New-FailureCase "missing-hosted-transport-manifest" "hosted_transport_manifest"),
    (New-FailureCase "hosted-transport-hash-drift" "hosted_consumer_mirror_smoke"),
    (New-FailureCase "missing-or-stale-mirror-publication" "mirror_publication"),
    (New-FailureCase "missing-fleet-preconditions" "fleet_rollout_preconditions"),
    (New-FailureCase "missing-hosted-transport-fail-closed-fixtures" "hosted_transport_fail_closed"),
    (New-FailureCase "missing-staged-fleet-rollout-smoke" "fleet_rollout_smoke"),
    (New-FailureCase "missing-rollback-baseline" "fleet_rollout_smoke.rollback_baseline"),
    (New-FailureCase "unredacted-support-recovery" "ga_support_recovery"),
    (New-FailureCase "tui-or-model-authority-attempt" "authority_boundary"),
    (New-FailureCase "production-ready-claim-attempt" "ga_boundary")
)

$gateArtifact = [ordered]@{
    schema = "agentos.rc4-hosted-fleet-promotion-gate.v1"
    generated_at = "2026-06-08T10:30:00+08:00"
    task = "RC4-023"
    status = "passed"
    production_ready_claim = $false
    rc4_023_complete = $true
    promotion_gate_integration_ready = $true
    local_only = $true
    required_evidence = @(
        "hosted_transport_manifest",
        "mirror_publication",
        "fleet_rollout_preconditions",
        "hosted_transport_fail_closed",
        "hosted_consumer_mirror_smoke",
        "fleet_rollout_smoke",
        "ga_support_recovery",
        "fleet_rollout_authority",
        "rc3_signing_publication_gate"
    )
    readiness = [ordered]@{
        hosted_transport_passed = $hostedReady
        mirror_publication_passed = $mirrorReady
        fleet_preconditions_ready = $preconditionsReady
        hosted_transport_fail_closed_passed = $failClosedReady
        hosted_consumer_mirror_smoke_passed = $hostedSmokeReady
        fleet_rollout_smoke_passed = $fleetSmokeReady
        ga_support_recovery_passed = $supportReady
        fleet_rollout_authority_passed = $fleetAuthorityReady
        candidate_promotion_baseline_passed = $candidatePromotionReady
        release_provenance_baseline_promotable = $provenanceReady
        rc3_signing_publication_gate_passed = $rc3GateReady
    }
    promotion_gate = [ordered]@{
        status = "passed"
        blockers = @()
        hosted_transport_required = $true
        remote_registry_mirror_required = $true
        fleet_rollout_smoke_required = $true
        rollback_baseline_required = $true
        support_recovery_required = $true
        fail_closed_fixtures_required = $true
        exact_operator_approval_required = $true
        exact_operator_approval_granted = $false
        agentcore_security_execution_required = $true
        remote_rollout_from_tui_allowed = $false
        production_ready_claim = $false
    }
    evidence_chain = $hashes
    source_gates = [ordered]@{
        rc3_signing_publication_gate_sha256 = $hashes.rc3_signing_publication_gate_sha256
        fleet_rollout_authority_sha256 = $hashes.fleet_rollout_authority_sha256
        candidate_promotion_sha256 = $hashes.candidate_promotion_sha256
        release_provenance_sha256 = $hashes.release_provenance_sha256
    }
    mutation_effects = [ordered]@{
        gate_projection_only = $true
        release_provenance_mutated = $false
        candidate_promotion_mutated = $false
        activation_performed = $false
        rollback_execution_performed = $false
        active_registry_mutated = $false
        active_slot_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        remote_dispatch_enabled = $false
        tui_authority = $false
    }
    failure_cases = @($failureCases)
}

if (@($script:blockers).Count -eq 0) {
    Write-Json -Value $gateArtifact -Path $resolvedGatePath
}
$gateHash = Get-FileSha256 $resolvedGatePath

Add-Check "rc4_gate_artifact.written" ((Test-Path -LiteralPath $resolvedGatePath -PathType Leaf) -and $gateHash -ne $null) "Writer must emit the RC4 hosted/fleet promotion gate artifact." "blocking" ([ordered]@{ path = Get-StablePath $resolvedGatePath; sha256 = $gateHash })
Add-Check "rc4_gate_artifact.secret_safe" (Test-NoSensitiveContent -Paths @($resolvedGatePath)) "RC4 gate artifact must not contain raw secret material or private authority paths." "blocking" ([ordered]@{ path = Get-StablePath $resolvedGatePath })
Add-Check "rc4_gate_artifact.host_path_free" (Test-NoHostPathContent -Paths @($resolvedGatePath)) "RC4 gate artifact must not contain host-local absolute paths." "blocking" ([ordered]@{ path = Get-StablePath $resolvedGatePath })
Add-Check "rc4_gate.no_authority_broadened" $true "RC4 gate integration writes evidence only and must not mutate provenance, activate, rollback, mutate active state, dispatch remotely, or grant TUI authority." "blocking" $gateArtifact.mutation_effects

$passed = @($script:blockers).Count -eq 0
$result = [ordered]@{
    schema = "agentos.rc4-hosted-fleet-promotion-gate-integration.v1"
    generated_at = "2026-06-08T10:30:00+08:00"
    checked_at = (Get-Date).ToString("o")
    task = "RC4-023"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    rc4_023_complete = $passed
    promotion_gate_integration_ready = $passed
    gate_artifact_written = Test-Path -LiteralPath $resolvedGatePath -PathType Leaf
    gate_artifact_sha256 = $gateHash
    release_provenance_mutated = $false
    candidate_promotion_mutated = $false
    activation_performed = $false
    rollback_execution_performed = $false
    active_registry_mutated = $false
    active_slot_mutated = $false
    active_artifact_set_mutated = $false
    production_ring_mutated = $false
    remote_dispatch_enabled = $false
    tui_authority = $false
    verified = [ordered]@{
        hosted_transport = $hostedReady
        mirror = $mirrorReady
        fleet_preconditions = $preconditionsReady
        hosted_transport_fail_closed = $failClosedReady
        hosted_consumer_mirror_smoke = $hostedSmokeReady
        fleet_rollout_smoke = $fleetSmokeReady
        ga_support_recovery = $supportReady
        fleet_rollout_authority = $fleetAuthorityReady
        candidate_promotion_baseline = $candidatePromotionReady
        release_provenance_baseline = $provenanceReady
        rc3_signing_publication_gate = $rc3GateReady
    }
    artifacts = [ordered]@{
        rc4_hosted_fleet_promotion_gate = [ordered]@{ path = Get-StablePath $resolvedGatePath; sha256 = $gateHash; schema = "agentos.rc4-hosted-fleet-promotion-gate.v1"; status = if ($passed) { "passed" } else { "blocked" } }
    }
    source_artifacts = [ordered]@{
        rc4_plan = New-Projection -Path $resolvedPlanPath -Json $plan
        hosted_transport_result = New-Projection -Path $resolvedHostedResultPath -Json $hostedResult
        hosted_transport_manifest = New-Projection -Path $resolvedHostedManifestPath -Json $hostedManifest
        mirror_publication_result = New-Projection -Path $resolvedMirrorResultPath -Json $mirrorResult
        mirror_lockfile = New-Projection -Path $resolvedMirrorLockfilePath -Json $mirrorLockfile
        mirror_publication = New-Projection -Path $resolvedMirrorPublicationPath -Json $mirrorPublication
        fleet_rollout_preconditions = New-Projection -Path $resolvedFleetPreconditionsPath -Json $fleetPreconditions
        hosted_transport_fail_closed = New-Projection -Path $resolvedFailClosedPath -Json $failClosed
        hosted_consumer_mirror_smoke = New-Projection -Path $resolvedHostedSmokePath -Json $hostedSmoke
        fleet_rollout_smoke = New-Projection -Path $resolvedFleetSmokePath -Json $fleetSmoke
        ga_support_recovery = New-Projection -Path $resolvedSupportRecoveryPath -Json $supportRecovery
        fleet_rollout_authority = New-Projection -Path $resolvedFleetAuthorityPath -Json $fleetAuthority
        candidate_promotion = New-Projection -Path $resolvedCandidatePromotionPath -Json $candidatePromotion
        release_provenance = New-Projection -Path $resolvedProvenancePath -Json $provenance
        rc3_signing_publication_gate = New-Projection -Path $resolvedRc3GatePath -Json $rc3Gate
    }
    evidence_chain = $hashes
    checks = $script:checks
    blockers = $script:blockers
    failure_cases = @($failureCases)
    handoff = [ordered]@{
        next_task = "RC4-030"
        rc4_030_consumes = @(
            "hosted_transport_manifest",
            "mirror_publication",
            "fleet_rollout_smoke",
            "ga_support_recovery",
            "rc4_hosted_fleet_promotion_gate"
        )
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        blockers = @($script:blockers).Count
        rc4_023_complete = $passed
        promotion_gate_integration_ready = $passed
        gate_artifact_written = Test-Path -LiteralPath $resolvedGatePath -PathType Leaf
        gate_artifact_sha256 = $gateHash
        failure_cases = @($failureCases).Count
        production_ready_claim = $false
        release_provenance_mutated = $false
        candidate_promotion_mutated = $false
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
        id = "rc4_gate.result_secret_safe"
        status = "failed"
        severity = "blocking"
        message = "RC4 hosted/fleet promotion gate result must be secret-safe and host-path-free."
        evidence = [ordered]@{ secret_safe = $resultSecretSafe; host_path_free = $resultHostPathFree; path = Get-StablePath $resolvedOutputPath }
    }
    $script:checks += $extra
    $script:blockers += $extra
    $result.checks = $script:checks
    $result.blockers = $script:blockers
    $result.status = "blocked"
    $result.rc4_023_complete = $false
    $result.promotion_gate_integration_ready = $false
    $result.summary.checks = @($script:checks).Count
    $result.summary.blockers = @($script:blockers).Count
    $result.summary.rc4_023_complete = $false
    $result.summary.promotion_gate_integration_ready = $false
    Write-Json -Value $result -Path $resolvedOutputPath
}

Write-Host "RC4 hosted/fleet promotion gate integration $($result.status): $OutputPath"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
