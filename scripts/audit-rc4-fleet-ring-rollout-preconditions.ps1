param(
    [string]$ArtifactDir = ".workflow/artifacts/rc4-fleet-ring-rollout-preconditions",
    [string]$Rc4PlanPath = ".workflow/active/WFS-20260608-agentos-production-distro-rc4/plan.json",
    [string]$Rc4RolloutBoundaryEvidencePath = ".workflow/active/WFS-20260608-agentos-production-distro-rc4/evidence/RC4-002-staged-rollout-authority-rollback-boundary.json",
    [string]$Rc4GaGatesEvidencePath = ".workflow/active/WFS-20260608-agentos-production-distro-rc4/evidence/RC4-003-ga-hardening-acceptance-gates.json",
    [string]$HostedTransportResultPath = ".workflow/artifacts/rc4-hosted-release-transport/result.json",
    [string]$HostedTransportManifestPath = ".workflow/artifacts/rc4-hosted-release-transport/hosted-transport-manifest.json",
    [string]$MirrorPublicationResultPath = ".workflow/artifacts/rc4-remote-registry-mirror-publication/result.json",
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
$expectedArtifactDir = Resolve-RepoPath ".workflow/artifacts/rc4-fleet-ring-rollout-preconditions"
if (-not $resolvedArtifactDir.Equals($expectedArtifactDir, [StringComparison]::OrdinalIgnoreCase)) {
    throw "ArtifactDir must be .workflow/artifacts/rc4-fleet-ring-rollout-preconditions"
}
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null

if (-not (Has-Value $OutputPath)) {
    $OutputPath = Join-Path $ArtifactDir "result.json"
}

$resolvedPlanPath = Resolve-RepoPath $Rc4PlanPath
$resolvedRolloutBoundaryPath = Resolve-RepoPath $Rc4RolloutBoundaryEvidencePath
$resolvedGaGatesPath = Resolve-RepoPath $Rc4GaGatesEvidencePath
$resolvedHostedResultPath = Resolve-RepoPath $HostedTransportResultPath
$resolvedHostedManifestPath = Resolve-RepoPath $HostedTransportManifestPath
$resolvedMirrorResultPath = Resolve-RepoPath $MirrorPublicationResultPath
$resolvedMirrorLockfilePath = Resolve-RepoPath $MirrorLockfilePath
$resolvedMirrorPublicationPath = Resolve-RepoPath $MirrorPublicationPath
$resolvedFleetAuthorityPath = Resolve-RepoPath $FleetRolloutAuthorityPath
$resolvedRollbackPath = Resolve-RepoPath $RollbackDrillPath
$resolvedSupportRecoveryPath = Resolve-RepoPath $SupportRecoveryPath
$resolvedOutputPath = Resolve-RepoPath $OutputPath

$plan = Read-JsonFile $resolvedPlanPath
$rolloutBoundary = Read-JsonFile $resolvedRolloutBoundaryPath
$gaGates = Read-JsonFile $resolvedGaGatesPath
$hostedResult = Read-JsonFile $resolvedHostedResultPath
$hostedManifest = Read-JsonFile $resolvedHostedManifestPath
$mirrorResult = Read-JsonFile $resolvedMirrorResultPath
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
$planPositionReady = $null -ne $plan -and (
    $plan.current_task -eq "RC4-012" -or
    ($rc4TaskStatuses["RC4-012"] -eq "completed" -and $plan.current_task -in @("RC4-013", "RC4-020", "RC4-021", "RC4-022", "RC4-023", "RC4-030"))
)

$hostedManifestHash = Get-FileSha256 $resolvedHostedManifestPath
$mirrorPublicationHash = Get-FileSha256 $resolvedMirrorPublicationPath
$mirrorLockfileHash = Get-FileSha256 $resolvedMirrorLockfilePath
$fleetAuthorityHash = Get-FileSha256 $resolvedFleetAuthorityPath
$rollbackHash = Get-FileSha256 $resolvedRollbackPath
$supportRecoveryHash = Get-FileSha256 $resolvedSupportRecoveryPath

$requiredRings = @("local", "canary", "staging", "production")
$rings = if ($null -ne $fleetAuthority) { @($fleetAuthority.rings) } else { @() }
$ringNames = @($rings | ForEach-Object { $_.name })
$ringOrderReady = ($ringNames -join "|") -eq ($requiredRings -join "|")
$missingRings = @($requiredRings | Where-Object { $ringNames -notcontains $_ })
$ringAuthorityViolations = @($rings | Where-Object {
    $_.authority -ne "AgentCore fleet_rollout PlanSpec + SecurityExecutionEngine" -or
    $_.tui_projection_only -ne $true -or
    $_.rollout_dispatch_enabled_in_tui -ne $false -or
    $_.rollback_dispatch_enabled_in_tui -ne $false
} | ForEach-Object { $_.name })
$localRing = @($rings | Where-Object { $_.name -eq "local" } | Select-Object -First 1)
$canaryRing = @($rings | Where-Object { $_.name -eq "canary" } | Select-Object -First 1)

$targetSet = [ordered]@{
    ring = "local"
    target_selector = "local-proof-ready"
    node_count = if ($null -ne $localRing) { $localRing.node_count } else { $null }
    authority = "AgentCore fleet_rollout PlanSpec + SecurityExecutionEngine"
    remote_dispatch_enabled = $false
    production_ring_mutated = $false
}
$targetSetHash = Get-ObjectSha256 $targetSet

$rolloutPolicy = [ordered]@{
    id = "rc4-fleet-ring-rollout-preconditions"
    version = "rc4-rollout-policy-v1"
    staged_order = @("local", "canary", "staging", "production")
    required_hold_gates = @("local-proof", "canary-hold", "staging-hold", "production-approval")
    exact_operator_approval_required = $true
    rollback_baseline_required = $true
    revocation_snapshot_required = $true
    support_redaction_required = $true
    remote_dispatch_allowed = $false
    tui_authority = $false
}
$rolloutPolicyHash = Get-ObjectSha256 $rolloutPolicy

$approvalBinding = [ordered]@{
    status = "required-not-granted-by-audit"
    exact_operator_approval_required = $true
    approval_hash_present = $false
    approval_hash_pending = $true
    bound_fields = @(
        "release",
        "ring",
        "target_set_hash",
        "rollout_policy_version",
        "rollback_baseline_hash",
        "revocation_snapshot_hash",
        "operator",
        "expiry",
        "policy_version"
    )
}

$hostedReady = $null -ne $hostedResult -and
    $hostedResult.status -eq "passed" -and
    $hostedResult.rc4_010_complete -eq $true -and
    (Get-JsonBlockerCount $hostedResult) -eq 0 -and
    $null -ne $hostedManifest -and
    $hostedManifest.status -eq "published-locally" -and
    $hostedManifest.production_ready_claim -eq $false -and
    $hostedManifest.transport.network_transfer_performed -eq $false -and
    $hostedManifest.transport.local_fixture_only -eq $true -and
    $hostedManifest.invariants.activation_performed -eq $false -and
    $hostedManifest.invariants.production_ring_mutated -eq $false
$mirrorReady = $null -ne $mirrorResult -and
    $mirrorResult.status -eq "passed" -and
    $mirrorResult.rc4_011_complete -eq $true -and
    (Get-JsonBlockerCount $mirrorResult) -eq 0 -and
    $null -ne $mirrorPublication -and
    $mirrorPublication.status -eq "published-locally" -and
    $mirrorPublication.production_ready_claim -eq $false -and
    $mirrorPublication.mirror.network_transfer_performed -eq $false -and
    $mirrorPublication.mirror.active_registry_mutated -eq $false -and
    $mirrorPublication.mirror.snapshot_freshness_status -eq "fresh-fixture" -and
    $mirrorPublication.invariants.remote_dispatch_enabled -eq $false -and
    $mirrorPublication.invariants.tui_authority -eq $false -and
    $mirrorPublication.invariants.active_registry_mutated -eq $false -and
    $mirrorPublication.invariants.production_ring_mutated -eq $false -and
    $mirrorPublication.bindings.hosted_transport_manifest_sha256 -eq $hostedManifestHash -and
    $mirrorPublication.bindings.mirror_lockfile_sha256 -eq $mirrorLockfileHash
$mirrorLockReady = $null -ne $mirrorLockfile -and
    $mirrorLockfile.status -eq "locked-locally" -and
    $mirrorLockfile.production_ready_claim -eq $false -and
    $mirrorLockfile.lock_policy.rollback_baseline_required -eq $true -and
    $mirrorLockfile.lock_policy.revocation_snapshot_required -eq $true -and
    $mirrorLockfile.lock_policy.remote_authoritative -eq $false
$fleetAuthorityReady = $null -ne $fleetAuthority -and
    $fleetAuthority.status -eq "passed" -and
    $fleetAuthority.production_ready_claim -eq $false -and
    $fleetAuthority.authority.execution_authority -eq "AgentCore fleet_rollout PlanSpec + SecurityExecutionEngine" -and
    $fleetAuthority.authority.tui_authority -eq $false -and
    $fleetAuthority.authority.remote_operator_bypass_allowed -eq $false -and
    $fleetAuthority.authority.normal_shell_rollout_allowed -eq $false -and
    $fleetAuthority.promotion_gate.status -eq "passed" -and
    $fleetAuthority.promotion_gate.remote_rollout_from_tui_allowed -eq $false
$ringsReady = $missingRings.Count -eq 0 -and $ringAuthorityViolations.Count -eq 0 -and
    $ringOrderReady -and
    $null -ne $localRing -and $localRing.status -eq "local-proof-ready" -and $localRing.node_count -eq 1 -and
    $null -ne $canaryRing -and $canaryRing.blocker -eq "remote-fleet-execution-not-enabled"
$rolloutBoundaryReady = $null -ne $rolloutBoundary -and
    $rolloutBoundary.status -eq "completed" -and
    $rolloutBoundary.acceptance_coverage.fleet_rollout_authority -eq "AgentCore fleet_rollout PlanSpec + SecurityExecutionEngine" -and
    $rolloutBoundary.acceptance_coverage.exact_operator_approval_required -eq $true -and
    $rolloutBoundary.acceptance_coverage.rollback_baseline_required -eq $true -and
    $rolloutBoundary.acceptance_coverage.target_set_hash_bound -eq $true -and
    $rolloutBoundary.acceptance_coverage.tui_authority -eq $false -and
    $rolloutBoundary.acceptance_coverage.model_replay_authority -eq $false -and
    $rolloutBoundary.acceptance_coverage.remote_dispatch_enabled -eq $false
$gaGatesReady = $null -ne $gaGates -and
    $gaGates.status -eq "completed" -and
    $gaGates.acceptance_coverage.production_ready_claim -eq $false
$rollbackReady = $null -ne $rollback -and
    $rollback.status -eq "passed" -and
    $rollback.rollback_verified -eq $true -and
    $rollback.rollback_previous_equals_restored -eq $true -and
    $rollback.active_slot_mutated -eq $false -and
    $rollback.activation_attempted -eq $false -and
    $rollback.remote_dispatch_enabled -eq $false -and
    $rollback.tui_authority -eq $false -and
    (Has-Value $rollback.evidence_chain.rollback_baseline_sha256)
$supportReady = $null -ne $supportRecovery -and
    $supportRecovery.status -eq "passed" -and
    $supportRecovery.support_bundle_redacted -eq $true -and
    $supportRecovery.remote_upload_performed -eq $false -and
    $supportRecovery.remote_dispatch_enabled -eq $false -and
    $supportRecovery.tui_authority -eq $false
$bindingReady = $null -ne $hostedManifest -and
    (Has-Value $hostedManifest.bindings.rc3_final_audit_sha256) -and
    (Has-Value $hostedManifest.bindings.production_verification_sha256) -and
    (Has-Value $hostedManifest.bindings.publication_manifest_sha256) -and
    (Has-Value $hostedManifest.bindings.channel_index_sha256) -and
    (Has-Value $hostedManifest.bindings.signing_publication_gate_sha256) -and
    (Has-Value $hostedManifest.bindings.revocation_log_sha256) -and
    $null -ne $mirrorPublication -and
    $mirrorPublication.bindings.rc3_final_audit_sha256 -eq $hostedManifest.bindings.rc3_final_audit_sha256 -and
    $mirrorPublication.bindings.publication_manifest_sha256 -eq $hostedManifest.bindings.publication_manifest_sha256 -and
    $mirrorPublication.bindings.channel_index_sha256 -eq $hostedManifest.bindings.channel_index_sha256 -and
    $mirrorPublication.bindings.signing_publication_gate_sha256 -eq $hostedManifest.bindings.signing_publication_gate_sha256 -and
    $mirrorPublication.bindings.revocation_log_sha256 -eq $hostedManifest.bindings.revocation_log_sha256
$requiredFailClosedCases = @(
    "hosted-manifest-hash-drift",
    "missing-rc3-final-audit-binding",
    "stale-mirror-snapshot",
    "unsigned-mirror-metadata",
    "revoked-mirror-metadata",
    "registry-lockfile-mismatch",
    "rollback-baseline-missing",
    "remote-dispatch-mutation-attempt"
)
$presentFailClosedCases = if ($null -ne $mirrorPublication) { @($mirrorPublication.fail_closed_cases_required) } else { @() }
$missingFailClosedCases = @($requiredFailClosedCases | Where-Object { $presentFailClosedCases -notcontains $_ })
$mirrorFailClosedReady = $missingFailClosedCases.Count -eq 0

Add-Check "rc4.plan.current_task" $planPositionReady "RC4 plan must point at RC4-012 before the first audit run, or remain on a later RC4 task after RC4-012 is completed." "blocking" $(if ($null -ne $plan) { [ordered]@{ current_task = $plan.current_task; RC4_012 = $rc4TaskStatuses["RC4-012"]; RC4_013 = $rc4TaskStatuses["RC4-013"]; RC4_020 = $rc4TaskStatuses["RC4-020"]; RC4_021 = $rc4TaskStatuses["RC4-021"] } } else { $null })
Add-Check "rc4.rollout_boundary.ready" $rolloutBoundaryReady "RC4 rollout boundary must require AgentCore/SecurityExecution authority, exact approval, rollback baseline, target-set binding, and no TUI/remote authority." "blocking" $(if ($null -ne $rolloutBoundary) { $rolloutBoundary.acceptance_coverage } else { $null })
Add-Check "rc4.ga_gates.non_ga" $gaGatesReady "RC4 GA gates must keep production_ready_claim=false." "blocking" $(if ($null -ne $gaGates) { $gaGates.acceptance_coverage } else { $null })
Add-Check "hosted_transport.ready_no_mutation" $hostedReady "RC4-010 hosted transport must be passed, local-only, non-GA, and mutation-free." "blocking" $(if ($null -ne $hostedResult) { $hostedResult.summary } else { $null })
Add-Check "mirror_publication.ready_no_mutation" $mirrorReady "RC4-011 mirror publication must be passed, local-only, current-hash-bound, and mutation-free." "blocking" $(if ($null -ne $mirrorResult) { $mirrorResult.summary } else { $null })
Add-Check "mirror_publication.fresh_fixture" ($null -ne $mirrorPublication -and $mirrorPublication.mirror.snapshot_freshness_status -eq "fresh-fixture") "Mirror publication must present a fresh fixture snapshot before rollout preconditions may pass." "blocking" $(if ($null -ne $mirrorPublication) { $mirrorPublication.mirror } else { $null })
Add-Check "mirror_publication.fail_closed_cases_declared" $mirrorFailClosedReady "Mirror publication must declare required hosted transport fail-closed cases." "blocking" ([ordered]@{ missing = @($missingFailClosedCases); present = @($presentFailClosedCases) })
Add-Check "mirror_lockfile.rollback_revocation_required" $mirrorLockReady "Mirror lockfile must require rollback baseline and revocation snapshot, and must not make remote mirror authoritative." "blocking" $(if ($null -ne $mirrorLockfile) { $mirrorLockfile.lock_policy } else { $null })
Add-Check "hosted_mirror.release_bindings_consistent" $bindingReady "Hosted transport and mirror publication must agree on RC3 audit, publication, channel, signing gate, and revocation bindings." "blocking" $(if ($null -ne $mirrorPublication) { $mirrorPublication.bindings } else { $null })
Add-Check "fleet_authority.ready" $fleetAuthorityReady "Fleet rollout authority must pass and keep execution under AgentCore fleet_rollout PlanSpec + SecurityExecutionEngine." "blocking" $(if ($null -ne $fleetAuthority) { $fleetAuthority.authority } else { $null })
Add-Check "fleet_rings.staged_boundary_ready" $ringsReady "Fleet rings must define local/canary/staging/production, keep TUI projection-only, and leave remote rings blocked until remote fleet execution is explicitly enabled." "blocking" ([ordered]@{ missing_rings = @($missingRings); authority_violations = @($ringAuthorityViolations); local_status = if ($null -ne $localRing) { $localRing.status } else { $null }; canary_blocker = if ($null -ne $canaryRing) { $canaryRing.blocker } else { $null } })
Add-Check "fleet_rings.staged_order" $ringOrderReady "Fleet rings must keep local -> canary -> staging -> production order; ring skip attempts must fail closed." "blocking" ([ordered]@{ expected = @($requiredRings); actual = @($ringNames) })
Add-Check "rollback_baseline.ready_no_mutation" $rollbackReady "Rollback drill must be passed, previous/restored hashes must match, and no activation or remote/TUI authority may be present." "blocking" $(if ($null -ne $rollback) { [ordered]@{ status = $rollback.status; rollback_verified = $rollback.rollback_verified; previous = $rollback.previous_active_artifact_set_sha256; restored = $rollback.restored_active_artifact_set_sha256; rollback_baseline_sha256 = $rollback.evidence_chain.rollback_baseline_sha256; active_slot_mutated = $rollback.active_slot_mutated; activation_attempted = $rollback.activation_attempted; remote_dispatch_enabled = $rollback.remote_dispatch_enabled; tui_authority = $rollback.tui_authority } } else { $null })
Add-Check "support_recovery.redacted_local_only" $supportReady "Support/recovery evidence must pass, stay redacted, local-only, and non-authoritative for mutation." "blocking" $(if ($null -ne $supportRecovery) { $supportRecovery.summary } else { $null })
Add-Check "target_set.hash_projected" (Has-Value $targetSetHash) "Audit must project a deterministic target-set hash without enrolling or mutating nodes." "blocking" $targetSet
Add-Check "rollout_policy.hash_projected" (Has-Value $rolloutPolicyHash) "Audit must project a deterministic rollout policy hash without creating activation authority." "blocking" $rolloutPolicy
Add-Check "operator_approval.required_not_granted" ($approvalBinding.exact_operator_approval_required -eq $true -and $approvalBinding.approval_hash_present -eq $false) "Audit must require exact operator approval but must not grant or fake approval." "blocking" $approvalBinding
Add-Check "rollout_preconditions.no_authority_broadened" $true "Precondition audit must not sign, verify production crypto, upload, activate, rollback, mutate registry, mutate slot, mutate ring state, or grant TUI/model/shell authority." "blocking" ([ordered]@{
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
    model_replay_authority = $false
    normal_shell_authority = $false
    tui_authority = $false
})

$passed = @($script:blockers).Count -eq 0
$generatedAt = "2026-06-08T09:40:00+08:00"

$result = [ordered]@{
    schema = "agentos.rc4-fleet-ring-rollout-preconditions.v1"
    generated_at = $generatedAt
    checked_at = (Get-Date).ToString("o")
    task = "RC4-012"
    status = if ($passed) { "ready-for-fleet-ring-rollout-plan" } else { "blocked" }
    production_ready_claim = $false
    rc4_012_complete = $passed
    rollout_preconditions_ready = $passed
    rollout_plan_created = $false
    rollout_plan_executed = $false
    exact_operator_approval_granted = $false
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
    projected_bindings = [ordered]@{
        rc3_final_audit_sha256 = if ($null -ne $hostedManifest) { $hostedManifest.bindings.rc3_final_audit_sha256 } else { $null }
        hosted_transport_manifest_sha256 = $hostedManifestHash
        publication_manifest_sha256 = if ($null -ne $hostedManifest) { $hostedManifest.bindings.publication_manifest_sha256 } else { $null }
        channel_index_sha256 = if ($null -ne $hostedManifest) { $hostedManifest.bindings.channel_index_sha256 } else { $null }
        production_verification_sha256 = if ($null -ne $hostedManifest) { $hostedManifest.bindings.production_verification_sha256 } else { $null }
        signing_publication_gate_sha256 = if ($null -ne $hostedManifest) { $hostedManifest.bindings.signing_publication_gate_sha256 } else { $null }
        mirror_publication_sha256 = $mirrorPublicationHash
        mirror_lockfile_sha256 = $mirrorLockfileHash
        fleet_rollout_authority_sha256 = $fleetAuthorityHash
        fleet_ring_id = "local"
        target_set_sha256 = $targetSetHash
        rollout_policy_version = $rolloutPolicy.version
        rollout_policy_sha256 = $rolloutPolicyHash
        rollback_baseline_sha256 = if ($null -ne $rollback) { $rollback.evidence_chain.rollback_baseline_sha256 } else { $null }
        rollback_drill_sha256 = $rollbackHash
        support_recovery_sha256 = $supportRecoveryHash
        revocation_snapshot_sha256 = if ($null -ne $hostedManifest) { $hostedManifest.bindings.revocation_log_sha256 } else { $null }
        exact_operator_approval_hash = $null
        exact_operator_approval_required = $true
    }
    target_set = $targetSet
    rollout_policy = $rolloutPolicy
    approval_binding = $approvalBinding
    source_artifacts = [ordered]@{
        rc4_plan = New-Projection -Path $resolvedPlanPath -Json $plan
        rc4_rollout_boundary = New-Projection -Path $resolvedRolloutBoundaryPath -Json $rolloutBoundary
        rc4_ga_gates = New-Projection -Path $resolvedGaGatesPath -Json $gaGates
        hosted_transport_result = New-Projection -Path $resolvedHostedResultPath -Json $hostedResult
        hosted_transport_manifest = New-Projection -Path $resolvedHostedManifestPath -Json $hostedManifest
        mirror_publication_result = New-Projection -Path $resolvedMirrorResultPath -Json $mirrorResult
        mirror_lockfile = New-Projection -Path $resolvedMirrorLockfilePath -Json $mirrorLockfile
        mirror_publication = New-Projection -Path $resolvedMirrorPublicationPath -Json $mirrorPublication
        fleet_rollout_authority = New-Projection -Path $resolvedFleetAuthorityPath -Json $fleetAuthority
        rollback_drill = New-Projection -Path $resolvedRollbackPath -Json $rollback
        support_recovery = New-Projection -Path $resolvedSupportRecoveryPath -Json $supportRecovery
    }
    checks = $script:checks
    blockers = $script:blockers
    fail_closed_cases_required = @(
        "missing-hosted-transport-binding",
        "target-set-hash-drift-after-approval",
        "rollout-policy-version-drift-after-approval",
        "rollback-baseline-missing-or-mismatched",
        "revocation-or-advisory-state-stale",
        "model-or-tui-direct-rollout-authority",
        "remote-control-plane-active-mutation",
        "support-bundle-unredacted",
        "ring-promotion-skips-canary-or-hold-gate"
    )
    handoff = [ordered]@{
        next_task = "RC4-013"
        rc4_013_consumes = @(
            "fleet_ring_rollout_preconditions",
            "hosted_transport_manifest",
            "mirror_publication",
            "fleet_rollout_authority",
            "rollback_drill",
            "support_recovery"
        )
        later_rollout_smoke_task = "RC4-021"
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        blockers = @($script:blockers).Count
        rc4_012_complete = $passed
        rollout_preconditions_ready = $passed
        projected_ring = "local"
        target_set_sha256 = $targetSetHash
        rollout_policy_version = $rolloutPolicy.version
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

$resultSecretSafe = Test-NoSensitiveContent -Paths @($resolvedOutputPath)
$resultHostPathFree = Test-NoHostPathContent -Paths @($resolvedOutputPath)
if (-not $resultSecretSafe -or -not $resultHostPathFree) {
    $extra = [ordered]@{
        id = "fleet_rollout_preconditions.result_secret_safe"
        status = "failed"
        severity = "blocking"
        message = "RC4 fleet-ring rollout precondition result must be secret-safe and host-path-free."
        evidence = [ordered]@{ secret_safe = $resultSecretSafe; host_path_free = $resultHostPathFree; path = Get-StablePath $resolvedOutputPath }
    }
    $script:checks += $extra
    $script:blockers += $extra
    $result.checks = $script:checks
    $result.blockers = $script:blockers
    $result.status = "blocked"
    $result.rc4_012_complete = $false
    $result.rollout_preconditions_ready = $false
    $result.summary.checks = @($script:checks).Count
    $result.summary.blockers = @($script:blockers).Count
    $result.summary.rc4_012_complete = $false
    $result.summary.rollout_preconditions_ready = $false
    Write-Json -Value $result -Path $resolvedOutputPath
}

Write-Host "RC4 fleet-ring rollout preconditions $($result.status): $OutputPath"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
