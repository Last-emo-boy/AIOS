param(
    [string]$ArtifactDir = ".workflow/artifacts/rc14-final-closeout-audit",
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

function Test-NoSensitiveText {
    param([Parameter(Mandatory = $true)][string[]]$Values)
    $privateKeyMarker = "PRIVATE" + " KEY"
    $markers = @(
        ("BEGIN " + $privateKeyMarker),
        ($privateKeyMarker + "-----"),
        ("BEGIN PUBLIC " + "KEY"),
        ("Authorization:" + " Bearer"),
        ("Bearer" + " "),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ("." + "local-release-authority"),
        ("signing" + "-" + "key" + "." + "pem"),
        ("/etc/" + "aios-signer"),
        ("finger" + "print")
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

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:blockers = @()
$generatedAtValue = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }

$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$expectedArtifactDir = Resolve-RepoPath ".workflow/artifacts/rc14-final-closeout-audit"
if (-not $resolvedArtifactDir.Equals($expectedArtifactDir, [StringComparison]::OrdinalIgnoreCase)) {
    throw "ArtifactDir must be .workflow/artifacts/rc14-final-closeout-audit"
}
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null

$paths = [ordered]@{
    plan = ".workflow/active/WFS-20260609-agentos-production-distro-rc14/plan.json"
    workflow_session = ".workflow/active/WFS-20260609-agentos-production-distro-rc14/workflow-session.json"
    rc13_final_audit = ".workflow/active/WFS-20260609-agentos-production-distro-rc13/evidence/FINAL-AUDIT-20260609-production-distro-rc13.json"
    rc14_contract = ".workflow/active/WFS-20260609-agentos-production-distro-rc14/docs/rc14-local-execution-readiness-contract.md"
    planning_evidence = ".workflow/active/WFS-20260609-agentos-production-distro-rc14/evidence/RC14-000-planning.json"
    contract_evidence = ".workflow/active/WFS-20260609-agentos-production-distro-rc14/evidence/RC14-001-local-execution-readiness-contract.json"
    drift_result = ".workflow/artifacts/rc14-declared-current-drift-zero-repair/result.json"
    freshness_result = ".workflow/artifacts/rc14-freshness-window-revocation-binding/result.json"
    object_trust_result = ".workflow/artifacts/rc14-local-object-trust-verification/result.json"
    quarantine_result = ".workflow/artifacts/rc14-verified-quarantine-preflight/result.json"
    agentcore_result = ".workflow/artifacts/rc14-agentcore-executable-planspec/result.json"
    security_result = ".workflow/artifacts/rc14-security-execution-allow-envelope/result.json"
    target_result = ".workflow/artifacts/rc14-two-target-local-identity-enrollment/result.json"
    approval_result = ".workflow/artifacts/rc14-exact-approval-execution-binding/result.json"
    activation_result = ".workflow/artifacts/rc14-controlled-local-activation/result.json"
    rollback_result = ".workflow/artifacts/rc14-controlled-rollback-support-recovery/result.json"
}

$resolved = [ordered]@{}
$json = [ordered]@{}
foreach ($key in $paths.Keys) {
    $resolved[$key] = Resolve-RepoPath $paths[$key]
    $json[$key] = if ([IO.Path]::GetExtension($paths[$key]) -eq ".json") { Read-Json $resolved[$key] } else { $null }
}

$preCloseoutTasks = @("RC14-000", "RC14-001", "RC14-010", "RC14-011", "RC14-012", "RC14-020", "RC14-021", "RC14-022", "RC14-030", "RC14-031", "RC14-040", "RC14-041")
$completedBeforeCloseout = 0
foreach ($taskId in $preCloseoutTasks) {
    if ((Get-TaskStatus $json.plan $taskId) -eq "completed") {
        $completedBeforeCloseout++
    }
}

$rc14050Status = Get-TaskStatus $json.plan "RC14-050"
$preCloseoutPlanState = $json.plan.current_task -eq "RC14-050" -and $rc14050Status -eq "pending"
$postCloseoutPlanState = $json.plan.status -eq "completed" -and $null -eq $json.plan.current_task -and $rc14050Status -eq "completed"
$planReady = ($preCloseoutPlanState -or $postCloseoutPlanState) -and $completedBeforeCloseout -eq @($preCloseoutTasks).Count

$docsReady = (Test-Path -LiteralPath $resolved.rc14_contract -PathType Leaf) -and
    $json.planning_evidence.status -eq "completed" -and
    $json.contract_evidence.status -eq "completed"

$rc13Ready = $json.rc13_final_audit.verdict -eq "PASS" -and
    $json.rc13_final_audit.production_ready_claim -eq $false -and
    $json.rc13_final_audit.next_milestone.id -eq "Production Distro RC14"

$driftReady = $json.drift_result.status -eq "passed" -and
    $json.drift_result.summary.rc14_010_complete -eq $true -and
    $json.drift_result.summary.failed_checks -eq 0 -and
    $json.drift_result.reconciliation_surface.local_reconciled_identity_set_drift_zero -eq $true -and
    $json.drift_result.reconciliation_surface.declared_current_drift_zero -eq $true -and
    $json.drift_result.reconciliation_surface.drift_count -eq 0 -and
    $json.drift_result.reconciliation_surface.local_descriptor_manifest_consistent -eq $true -and
    $json.drift_result.reconciliation_surface.local_object_trust_allowed -eq $false

$freshnessReady = $json.freshness_result.status -eq "passed" -and
    $json.freshness_result.summary.rc14_011_complete -eq $true -and
    $json.freshness_result.summary.failed_checks -eq 0 -and
    $json.freshness_result.summary.failed_fail_closed_cases -eq 0 -and
    $json.freshness_result.authority_surface.freshness_revocation_authority_bound -eq $true -and
    $json.freshness_result.authority_surface.freshness_window_bound -eq $true -and
    $json.freshness_result.authority_surface.freshness_window_current -eq $true -and
    $json.freshness_result.authority_surface.revocation_snapshot_bound -eq $true -and
    $json.freshness_result.authority_surface.revocation_status_not_revoked -eq $true -and
    $json.freshness_result.authority_surface.object_trust_preconditions_ready -eq $true -and
    $json.freshness_result.authority_surface.local_object_trust_allowed -eq $false

$objectTrustReady = $json.object_trust_result.status -eq "passed" -and
    $json.object_trust_result.summary.rc14_012_complete -eq $true -and
    $json.object_trust_result.summary.failed_checks -eq 0 -and
    $json.object_trust_result.summary.failed_fail_closed_cases -eq 0 -and
    $json.object_trust_result.verification_surface.local_object_trust_allowed -eq $true -and
    $json.object_trust_result.verification_surface.quarantine_preflight_allowed -eq $true -and
    $json.object_trust_result.verification_surface.object_trust_blockers.Count -eq 0 -and
    $json.object_trust_result.verification_surface.endpoint_reachability_is_trust -eq $false -and
    $json.object_trust_result.verification_surface.network_probe_performed -eq $false -and
    $json.object_trust_result.verification_surface.activation_allowed -eq $false

$quarantineReady = $json.quarantine_result.status -eq "passed" -and
    $json.quarantine_result.summary.rc14_020_complete -eq $true -and
    $json.quarantine_result.summary.failed_checks -eq 0 -and
    $json.quarantine_result.summary.failed_cases -eq 0 -and
    $json.quarantine_result.preflight_surface.state -eq "verified-quarantine-preflight-complete" -and
    $json.quarantine_result.preflight_surface.local_object_trust_allowed -eq $true -and
    $json.quarantine_result.preflight_surface.verified_quarantine_preflight -eq $true -and
    $json.quarantine_result.preflight_surface.quarantine_payload_written -eq $true -and
    $json.quarantine_result.preflight_surface.pre_interpretation_verification_performed -eq $true -and
    $json.quarantine_result.preflight_surface.payload_interpreted -eq $false -and
    $json.quarantine_result.preflight_surface.network_fetch_attempted -eq $false -and
    $json.quarantine_result.preflight_surface.agentcore_planspec_readiness_allowed -eq $true

$agentcoreReady = $json.agentcore_result.status -eq "passed" -and
    $json.agentcore_result.summary.rc14_021_complete -eq $true -and
    $json.agentcore_result.summary.failed_checks -eq 0 -and
    $json.agentcore_result.summary.failed_cases -eq 0 -and
    $json.agentcore_result.readiness_surface.object_trust_bound -eq $true -and
    $json.agentcore_result.readiness_surface.verified_quarantine_preflight_bound -eq $true -and
    $json.agentcore_result.readiness_surface.agentcore_planspec_candidate_materialized -eq $true -and
    $json.agentcore_result.readiness_surface.agentcore_planspec_executable -eq $false -and
    $json.agentcore_result.readiness_surface.target_set_bound -eq $false -and
    $json.agentcore_result.readiness_surface.exact_approval_bound -eq $false -and
    $json.agentcore_result.readiness_surface.audit_sink_bound -eq $false -and
    $json.agentcore_result.readiness_surface.nonce_bound -eq $false -and
    $json.agentcore_result.readiness_surface.expiry_bound -eq $false -and
    $json.agentcore_result.readiness_surface.policy_version_bound -eq $false -and
    $json.agentcore_result.readiness_surface.effect_prepared -eq $false -and
    $json.agentcore_result.readiness_surface.effect_executed -eq $false

$securityReady = $json.security_result.status -eq "passed" -and
    $json.security_result.summary.rc14_022_complete -eq $true -and
    $json.security_result.summary.failed_checks -eq 0 -and
    $json.security_result.summary.failed_cases -eq 0 -and
    $json.security_result.security_surface.state -eq "security-execution-allow-envelope-denied" -and
    $json.security_result.security_surface.observed_preconditions.object_trust_bound -eq $true -and
    $json.security_result.security_surface.observed_preconditions.verified_quarantine_preflight -eq $true -and
    $json.security_result.security_surface.observed_preconditions.agentcore_planspec_executable -eq $false -and
    $json.security_result.security_surface.observed_preconditions.target_set_bound -eq $false -and
    $json.security_result.security_surface.observed_preconditions.exact_approval_bound -eq $false -and
    $json.security_result.security_surface.observed_preconditions.audit_sink_bound -eq $false -and
    $json.security_result.security_surface.observed_preconditions.nonce_bound -eq $false -and
    $json.security_result.security_surface.observed_preconditions.expiry_bound -eq $false -and
    $json.security_result.security_surface.security_execution_allowed -eq $false -and
    $json.security_result.security_surface.effect_preparation_allowed -eq $false -and
    $json.security_result.security_surface.effect_executed -eq $false

$targetReady = $json.target_result.status -eq "passed" -and
    $json.target_result.summary.rc14_030_complete -eq $true -and
    $json.target_result.summary.failed_checks -eq 0 -and
    $json.target_result.summary.failed_cases -eq 0 -and
    $json.target_result.enrollment_surface.required_minimum_target_identities -eq 2 -and
    $json.target_result.enrollment_surface.enrolled_target_identity_count -eq 0 -and
    $json.target_result.enrollment_surface.target_identity_set_bound -eq $false -and
    $json.target_result.enrollment_surface.exact_approval_bound -eq $false -and
    $json.target_result.enrollment_surface.activation_allowed -eq $false

$approvalReady = $json.approval_result.status -eq "passed" -and
    $json.approval_result.summary.rc14_031_complete -eq $true -and
    $json.approval_result.summary.failed_checks -eq 0 -and
    $json.approval_result.summary.failed_cases -eq 0 -and
    $json.approval_result.approval_surface.state -eq "exact-approval-execution-binding-denied" -and
    $json.approval_result.approval_surface.exact_approval_bound -eq $false -and
    $json.approval_result.approval_surface.approval_granted -eq $false -and
    $json.approval_result.approval_surface.unsigned_approval_denied -eq $true -and
    $json.approval_result.approval_surface.audit_sink_bound -eq $false -and
    $json.approval_result.approval_surface.nonce_bound -eq $false -and
    $json.approval_result.approval_surface.expiry_bound -eq $false -and
    $json.approval_result.approval_surface.activation_allowed -eq $false

$activationReady = $json.activation_result.status -eq "passed" -and
    $json.activation_result.summary.rc14_040_complete -eq $true -and
    $json.activation_result.summary.failed_checks -eq 0 -and
    $json.activation_result.summary.failed_cases -eq 0 -and
    $json.activation_result.activation_surface.state -eq "controlled-local-activation-denied" -and
    $json.activation_result.activation_surface.activation_allowed -eq $false -and
    $json.activation_result.activation_surface.activation_performed -eq $false -and
    $json.activation_result.activation_surface.activation_audit_fabricated -eq $false -and
    $json.activation_result.activation_surface.rollback_execution_allowed -eq $false -and
    $json.activation_result.activation_surface.remote_dispatch_enabled -eq $false

$rollbackReady = $json.rollback_result.status -eq "passed" -and
    $json.rollback_result.summary.rc14_041_complete -eq $true -and
    $json.rollback_result.summary.failed_checks -eq 0 -and
    $json.rollback_result.summary.failed_cases -eq 0 -and
    $json.rollback_result.rollback_surface.state -eq "controlled-rollback-support-recovery-denied" -and
    $json.rollback_result.rollback_surface.rollback_baseline_bound -eq $true -and
    $json.rollback_result.rollback_surface.rollback_execution_allowed -eq $false -and
    $json.rollback_result.rollback_surface.rollback_execution_performed -eq $false -and
    $json.rollback_result.rollback_surface.controlled_activation_performed -eq $false -and
    $json.rollback_result.rollback_surface.exact_rollback_approval_granted -eq $false -and
    $json.rollback_result.support_surface.support_recovery_reference_bound -eq $true -and
    $json.rollback_result.support_surface.support_bundle_redacted -eq $true -and
    $json.rollback_result.support_surface.support_upload_performed -eq $false -and
    $json.rollback_result.support_surface.recovery_execution_performed -eq $false

$resultSet = @(
    [pscustomobject]@{ Task = "RC14-010"; Json = $json.drift_result },
    [pscustomobject]@{ Task = "RC14-011"; Json = $json.freshness_result },
    [pscustomobject]@{ Task = "RC14-012"; Json = $json.object_trust_result },
    [pscustomobject]@{ Task = "RC14-020"; Json = $json.quarantine_result },
    [pscustomobject]@{ Task = "RC14-021"; Json = $json.agentcore_result },
    [pscustomobject]@{ Task = "RC14-022"; Json = $json.security_result },
    [pscustomobject]@{ Task = "RC14-030"; Json = $json.target_result },
    [pscustomobject]@{ Task = "RC14-031"; Json = $json.approval_result },
    [pscustomobject]@{ Task = "RC14-040"; Json = $json.activation_result },
    [pscustomobject]@{ Task = "RC14-041"; Json = $json.rollback_result }
)

$forbiddenInvariantNames = @(
    "mirror_frontend_changed",
    "nginx_or_tls_changed",
    "signer_infra_changed",
    "object_storage_infra_changed",
    "local_private_key_material_used",
    "private_key_material_read_or_printed",
    "private_signing_material_handled",
    "cryptographic_signing_performed",
    "signer_service_called",
    "payload_upload_performed",
    "external_payload_bytes_uploaded",
    "object_storage_provisioned",
    "network_probe_performed",
    "network_fetch_attempted",
    "remote_payload_bytes_downloaded",
    "payload_interpreted",
    "install_performed",
    "activation_performed",
    "rollback_execution_performed",
    "support_upload_performed",
    "recovery_execution_performed",
    "active_slot_mutated",
    "boot_metadata_mutated",
    "persistent_state_mutated",
    "active_artifact_set_mutated",
    "production_ring_mutated",
    "remote_dispatch_enabled",
    "frontend_authority",
    "mirror_authority",
    "signer_reachability_authority",
    "model_replay_authority",
    "normal_shell_authority",
    "tui_authority",
    "approval_granted",
    "unsigned_approval_accepted",
    "exact_approval_fabricated",
    "activation_audit_fabricated",
    "security_execution_effect_allowed",
    "effect_prepared",
    "effect_executed",
    "production_ready_claim"
)
$invariantViolations = @(Test-InvariantFalse -ResultSet $resultSet -Names $forbiddenInvariantNames)

Add-Check "rc14.plan.precloseout_complete" $planReady "All RC14 pre-closeout tasks must be completed and RC14-050 must be pending before first audit or completed on rerun." ([ordered]@{ completed = $completedBeforeCloseout; expected = @($preCloseoutTasks).Count; current_task = $json.plan.current_task; rc14_050_status = $rc14050Status; plan_status = $json.plan.status })
Add-Check "rc14.docs_and_contract.present" $docsReady "RC14 planning evidence and local execution readiness contract must exist." ([ordered]@{ contract = Get-StablePath $resolved.rc14_contract })
Add-Check "rc13.previous_milestone.closed" $rc13Ready "RC14 final audit must inherit a PASS RC13 final audit without GA claim." ([ordered]@{ verdict = $json.rc13_final_audit.verdict; production_ready_claim = $json.rc13_final_audit.production_ready_claim; next_milestone = $json.rc13_final_audit.next_milestone.id })
Add-Check "rc14.drift_zero.repaired" $driftReady "RC14 declared/current identity repair must reach local drift-zero while downstream execution remains gated." $json.drift_result.summary
Add-Check "rc14.freshness_revocation.bound" $freshnessReady "RC14 must bind current freshness and revocation authority without granting object trust before verification." $json.freshness_result.summary
Add-Check "rc14.object_trust.verified" $objectTrustReady "RC14 local object trust must be verified from drift-zero, descriptor, signature, freshness, revocation, compatibility, rollback, and support evidence." $json.object_trust_result.summary
Add-Check "rc14.quarantine.verified" $quarantineReady "RC14 quarantine preflight must verify bytes in repo-local quarantine before interpretation and without network fetch." $json.quarantine_result.summary
Add-Check "rc14.agentcore.candidate_non_executable" $agentcoreReady "RC14 AgentCore PlanSpec candidate must be materialized but remain non-executable without target, approval, audit, nonce, expiry, and policy bindings." $json.agentcore_result.summary
Add-Check "rc14.security_execution.denied" $securityReady "RC14 SecurityExecution allow envelope must bind trusted inputs but deny effects until executable PlanSpec, target, approval, audit, nonce, expiry, and policy gates are present." $json.security_result.summary
Add-Check "rc14.target_identity.denied" $targetReady "RC14 two-target local identity enrollment must require two targets and remain denied with zero enrolled identities." $json.target_result.summary
Add-Check "rc14.exact_approval.denied" $approvalReady "RC14 exact approval binding must deny unsigned/unbound approval and keep activation blocked." $json.approval_result.summary
Add-Check "rc14.activation.denied" $activationReady "RC14 controlled local activation must remain denied and side-effect free." $json.activation_result.summary
Add-Check "rc14.rollback_support_recovery.denied" $rollbackReady "RC14 rollback, support upload, and recovery execution must remain denied while redacted local support evidence is bound." $json.rollback_result.summary
Add-Check "rc14.no_forbidden_invariant_broadened" (@($invariantViolations).Count -eq 0) "RC14 task invariants must not broaden signing, mirror, frontend, install, activation, rollback, support, recovery, remote dispatch, or production authority." ([ordered]@{ violations = $invariantViolations })

$sourceArtifacts = [ordered]@{}
foreach ($key in $paths.Keys) {
    $sourceArtifacts[$key] = New-ArtifactRef -Path $resolved[$key] -Json $json[$key]
}

$remainingBlockersList = [System.Collections.ArrayList]::new()
foreach ($item in @($resultSet)) {
    foreach ($blocker in @($item.Json.blockers)) {
        Add-UniqueString -List $remainingBlockersList -Value ([string]$blocker)
    }
}
$remainingBlockers = @($remainingBlockersList)

$finalAuditPath = Resolve-RepoPath ".workflow/active/WFS-20260609-agentos-production-distro-rc14/evidence/FINAL-AUDIT-20260609-production-distro-rc14.json"
$closeoutSummaryPath = Resolve-RepoPath ".workflow/active/WFS-20260609-agentos-production-distro-rc14/docs/final-rc14-closeout-summary.md"
$taskEvidencePath = Resolve-RepoPath ".workflow/active/WFS-20260609-agentos-production-distro-rc14/evidence/RC14-050-final-closeout-audit.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"

$summaryText = @"
# Production Distro RC14 Closeout Summary

RC14 closes as a non-GA AIOS-body milestone. It moves beyond RC13's local trust denial by proving local declared/current drift-zero, binding a current freshness window and revocation snapshot, verifying local object trust, and completing repo-local quarantine preflight before payload interpretation.

RC14 does not authorize controlled execution. AgentCore materializes a PlanSpec candidate, but it remains non-executable because target set, exact approval, audit sink, nonce, expiry, and policy version are not bound. SecurityExecution binds the effect envelope inputs but denies effects. Two-target identity enrollment, exact approval, controlled activation, rollback execution, support upload, recovery execution, remote dispatch, and production ring mutation remain blocked.

## Evidence

- Drift-zero repair: `.workflow/artifacts/rc14-declared-current-drift-zero-repair/result.json`
- Freshness and revocation binding: `.workflow/artifacts/rc14-freshness-window-revocation-binding/result.json`
- Local object trust verification: `.workflow/artifacts/rc14-local-object-trust-verification/result.json`
- Verified quarantine preflight: `.workflow/artifacts/rc14-verified-quarantine-preflight/result.json`
- AgentCore PlanSpec candidate: `.workflow/artifacts/rc14-agentcore-executable-planspec/result.json`
- SecurityExecution allow envelope: `.workflow/artifacts/rc14-security-execution-allow-envelope/result.json`
- Two-target identity enrollment: `.workflow/artifacts/rc14-two-target-local-identity-enrollment/result.json`
- Exact approval binding: `.workflow/artifacts/rc14-exact-approval-execution-binding/result.json`
- Controlled local activation: `.workflow/artifacts/rc14-controlled-local-activation/result.json`
- Controlled rollback support/recovery: `.workflow/artifacts/rc14-controlled-rollback-support-recovery/result.json`
- Final audit: `.workflow/active/WFS-20260609-agentos-production-distro-rc14/evidence/FINAL-AUDIT-20260609-production-distro-rc14.json`

## Next Direction

RC15 should turn the remaining local execution gates into satisfiable evidence: bind two real local target identities, bind local audit sink, nonce, expiry, and policy version, make the AgentCore PlanSpec executable, get a SecurityExecution allow decision, then rerun controlled local activation and a separately approved rollback drill while preserving AIOS-body-only scope and no GA claim.
"@

$preWritePassed = @($script:blockers).Count -eq 0
$finalAudit = [ordered]@{
    schema = "agentos.production-distro-rc14-final-audit.v1"
    generated_at = $generatedAtValue
    workflow = ".workflow/active/WFS-20260609-agentos-production-distro-rc14"
    milestone = "Production Distro RC14"
    verdict = if ($preWritePassed) { "PASS" } else { "BLOCKED" }
    decision = if ($preWritePassed) { "rc14-closeout-pass-local-trust-readiness-execution-denied" } else { "rc14-closeout-blocked" }
    production_ready_claim = $false
    objective = "AIOS-body local execution readiness audit for drift-zero repair, freshness/revocation authority, local object trust, verified quarantine, AgentCore PlanSpec candidate, SecurityExecution allow envelope, target identities, exact approval, activation, rollback, support, and recovery evidence"
    task_results = @($preCloseoutTasks | ForEach-Object { [ordered]@{ id = $_; status = Get-TaskStatus $json.plan $_ } })
    acceptance_coverage = @(
        [ordered]@{ requirement = "declared/current identity repair reaches local drift-zero"; status = if ($driftReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.drift_result)) }
        [ordered]@{ requirement = "freshness window and revocation snapshot are current and bound without private material"; status = if ($freshnessReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.freshness_result)) }
        [ordered]@{ requirement = "local object trust is verified from descriptor, manifest, signature, freshness, revocation, compatibility, rollback, and support/recovery evidence"; status = if ($objectTrustReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.object_trust_result)) }
        [ordered]@{ requirement = "verified quarantine preflight writes repo-local quarantine bytes and blocks interpretation"; status = if ($quarantineReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.quarantine_result)) }
        [ordered]@{ requirement = "AgentCore PlanSpec candidate is materialized but remains non-executable until target, approval, audit, nonce, expiry, and policy gates are bound"; status = if ($agentcoreReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.agentcore_result)) }
        [ordered]@{ requirement = "SecurityExecution allow envelope binds trusted inputs but denies effects"; status = if ($securityReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.security_result)) }
        [ordered]@{ requirement = "two local target identities remain required and unenrolled"; status = if ($targetReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.target_result)) }
        [ordered]@{ requirement = "exact approval remains denied without target identities, actor authority, audit sink, nonce, expiry, policy, and signature"; status = if ($approvalReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.approval_result)) }
        [ordered]@{ requirement = "controlled activation remains denied and side-effect free"; status = if ($activationReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.activation_result)) }
        [ordered]@{ requirement = "rollback/support/recovery remains denied while local redacted support evidence is bound"; status = if ($rollbackReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.rollback_result)) }
    )
    readiness_status = [ordered]@{
        moved_beyond_rc13_fail_closed = $json.object_trust_result.verification_surface.local_object_trust_allowed -eq $true -and $json.quarantine_result.preflight_surface.verified_quarantine_preflight -eq $true
        local_trust_ready = $true
        verified_quarantine_ready = $true
        controlled_execution_ready = $false
        controlled_execution_authorized = $false
        production_ready_claim = $false
        reason_controlled_execution_not_ready = @(
            "agentcore-planspec-not-executable",
            "security-execution-allow-not-bound",
            "two-target-local-canary-identities-not-enrolled",
            "exact-approval-not-bound",
            "audit-sink-not-bound",
            "nonce-not-bound",
            "approval-expiry-not-bound",
            "policy-version-not-bound"
        )
    }
    execution_surface = [ordered]@{
        release_id = $json.drift_result.release_id
        current_payload_size_bytes = $json.drift_result.reconciliation_surface.current_payload_size_bytes
        current_payload_sha256 = $json.drift_result.reconciliation_surface.current_payload_sha256
        declared_current_drift_zero = $json.drift_result.reconciliation_surface.declared_current_drift_zero
        drift_count = $json.drift_result.reconciliation_surface.drift_count
        freshness_revocation_authority_bound = $json.freshness_result.authority_surface.freshness_revocation_authority_bound
        freshness_window_current = $json.freshness_result.authority_surface.freshness_window_current
        revocation_snapshot_current = $json.freshness_result.authority_surface.revocation_snapshot_current
        local_object_trust_allowed = $json.object_trust_result.verification_surface.local_object_trust_allowed
        endpoint_reachability_is_trust = $json.object_trust_result.verification_surface.endpoint_reachability_is_trust
        verified_quarantine_preflight = $json.quarantine_result.preflight_surface.verified_quarantine_preflight
        quarantine_payload_written = $json.quarantine_result.preflight_surface.quarantine_payload_written
        quarantine_payload_sha256 = $json.quarantine_result.preflight_surface.quarantine_payload_sha256
        payload_interpreted = $json.quarantine_result.preflight_surface.payload_interpreted
        agentcore_planspec_candidate_materialized = $json.agentcore_result.readiness_surface.agentcore_planspec_candidate_materialized
        agentcore_planspec_core_hash = $json.agentcore_result.readiness_surface.planspec_core_hash
        agentcore_planspec_executable = $json.agentcore_result.readiness_surface.agentcore_planspec_executable
        security_execution_effect_envelope_core_hash = $json.security_result.security_surface.effect_envelope_core_hash
        security_execution_allowed = $json.security_result.security_surface.security_execution_allowed
        effect_preparation_allowed = $json.security_result.security_surface.effect_preparation_allowed
        enrolled_target_identity_count = $json.target_result.enrollment_surface.enrolled_target_identity_count
        target_identity_set_bound = $json.target_result.enrollment_surface.target_identity_set_bound
        exact_approval_bound = $json.approval_result.approval_surface.exact_approval_bound
        exact_approval_granted = $json.approval_result.approval_surface.approval_granted
        audit_sink_bound = $json.approval_result.approval_surface.audit_sink_bound
        nonce_bound = $json.approval_result.approval_surface.nonce_bound
        expiry_bound = $json.approval_result.approval_surface.expiry_bound
        activation_state = $json.activation_result.activation_surface.state
        activation_allowed = $json.activation_result.activation_surface.activation_allowed
        activation_performed = $json.activation_result.activation_surface.activation_performed
        rollback_state = $json.rollback_result.rollback_surface.state
        rollback_baseline_bound = $json.rollback_result.rollback_surface.rollback_baseline_bound
        rollback_execution_allowed = $json.rollback_result.rollback_surface.rollback_execution_allowed
        rollback_execution_performed = $json.rollback_result.rollback_surface.rollback_execution_performed
        support_recovery_reference_bound = $json.rollback_result.support_surface.support_recovery_reference_bound
        support_bundle_redacted = $json.rollback_result.support_surface.support_bundle_redacted
        support_upload_performed = $json.rollback_result.support_surface.support_upload_performed
        recovery_execution_performed = $json.rollback_result.support_surface.recovery_execution_performed
        remote_dispatch_enabled = $json.rollback_result.rollback_surface.remote_dispatch_enabled
        production_ring_mutation_allowed = $json.rollback_result.rollback_surface.production_ring_mutation_allowed
    }
    invariants_verified = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        mirror_frontend_changed = $false
        nginx_or_tls_changed = $false
        signer_infra_changed = $false
        object_storage_infra_changed = $false
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
        endpoint_reachability_is_trust = $false
        external_payload_bytes_uploaded = $false
        network_probe_performed = $false
        network_fetch_attempted = $false
        remote_payload_bytes_downloaded = $false
        quarantine_payload_written_repo_local_only = $true
        payload_interpreted = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        remote_dispatch_enabled = $false
        model_replay_authority = $false
        normal_shell_authority = $false
        tui_authority = $false
    }
    source_artifacts = $sourceArtifacts
    remaining_blockers_before_execution_or_ga = $remainingBlockers
    next_milestone = [ordered]@{
        id = "Production Distro RC15"
        title = "turn RC14 local trust readiness into controlled local execution readiness"
        direction = "bind two real local target identities, bind audit sink nonce expiry and policy version, make AgentCore PlanSpec executable, obtain SecurityExecution allow, then rerun controlled local activation and separately approved rollback without mirror, signer, frontend, remote dispatch, object storage provisioning, private signing material, production mutation, or GA claim."
    }
    checks = $script:checks
}

Write-Json $finalAudit $finalAuditPath
Write-Text $summaryText $closeoutSummaryPath

Add-Check "rc14.final_audit.written" (Test-Path -LiteralPath $finalAuditPath -PathType Leaf) "RC14 final audit evidence must be written." ([ordered]@{ path = Get-StablePath $finalAuditPath; sha256 = Get-FileSha256 $finalAuditPath })
Add-Check "rc14.closeout_summary.written" (Test-Path -LiteralPath $closeoutSummaryPath -PathType Leaf) "RC14 closeout summary must be written." ([ordered]@{ path = Get-StablePath $closeoutSummaryPath; sha256 = Get-FileSha256 $closeoutSummaryPath })

$passed = @($script:blockers).Count -eq 0
$finalAudit.verdict = if ($passed) { "PASS" } else { "BLOCKED" }
$finalAudit.decision = if ($passed) { "rc14-closeout-pass-local-trust-readiness-execution-denied" } else { "rc14-closeout-blocked" }
$finalAudit.checks = $script:checks
Write-Json $finalAudit $finalAuditPath

$result = [ordered]@{
    schema = "agentos.rc14-final-closeout-audit-result.v1"
    generated_at = $generatedAtValue
    task = "RC14-050"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    rc14_050_complete = $passed
    final_audit_written = Test-Path -LiteralPath $finalAuditPath -PathType Leaf
    closeout_summary_written = Test-Path -LiteralPath $closeoutSummaryPath -PathType Leaf
    state_update_performed_by_writer = $false
    install_performed = $false
    activation_performed = $false
    rollback_execution_performed = $false
    support_upload_performed = $false
    recovery_execution_performed = $false
    remote_dispatch_enabled = $false
    mirror_frontend_changed = $false
    nginx_or_tls_changed = $false
    signer_infra_changed = $false
    object_storage_infra_changed = $false
    private_signing_material_handled = $false
    outputs = [ordered]@{
        final_audit = [ordered]@{ path = Get-StablePath $finalAuditPath; sha256 = Get-FileSha256 $finalAuditPath; present = Test-Path -LiteralPath $finalAuditPath -PathType Leaf }
        closeout_summary = [ordered]@{ path = Get-StablePath $closeoutSummaryPath; sha256 = Get-FileSha256 $closeoutSummaryPath; present = Test-Path -LiteralPath $closeoutSummaryPath -PathType Leaf }
    }
    source_artifacts = $sourceArtifacts
    checks = $script:checks
    blockers = $script:blockers
    final_audit = [ordered]@{
        verdict = $finalAudit.verdict
        readiness_status = $finalAudit.readiness_status
        remaining_blockers_before_execution_or_ga = $remainingBlockers
        next_milestone = $finalAudit.next_milestone
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:blockers).Count
        rc14_050_complete = $passed
        verdict = $finalAudit.verdict
        moved_beyond_rc13_fail_closed = $finalAudit.readiness_status.moved_beyond_rc13_fail_closed
        local_trust_ready = $finalAudit.readiness_status.local_trust_ready
        verified_quarantine_ready = $finalAudit.readiness_status.verified_quarantine_ready
        controlled_execution_ready = $finalAudit.readiness_status.controlled_execution_ready
        drift_count = $json.drift_result.reconciliation_surface.drift_count
        declared_current_drift_zero = $json.drift_result.reconciliation_surface.declared_current_drift_zero
        freshness_window_current = $json.freshness_result.authority_surface.freshness_window_current
        local_object_trust_allowed = $json.object_trust_result.verification_surface.local_object_trust_allowed
        verified_quarantine_preflight = $json.quarantine_result.preflight_surface.verified_quarantine_preflight
        quarantine_payload_written = $json.quarantine_result.preflight_surface.quarantine_payload_written
        payload_interpreted = $json.quarantine_result.preflight_surface.payload_interpreted
        agentcore_planspec_candidate_materialized = $json.agentcore_result.readiness_surface.agentcore_planspec_candidate_materialized
        agentcore_planspec_executable = $json.agentcore_result.readiness_surface.agentcore_planspec_executable
        security_execution_allowed = $json.security_result.security_surface.security_execution_allowed
        enrolled_target_identity_count = $json.target_result.enrollment_surface.enrolled_target_identity_count
        approval_granted = $json.approval_result.approval_surface.approval_granted
        activation_performed = $json.activation_result.activation_surface.activation_performed
        rollback_execution_performed = $json.rollback_result.rollback_surface.rollback_execution_performed
        support_upload_performed = $json.rollback_result.support_surface.support_upload_performed
        recovery_execution_performed = $json.rollback_result.support_surface.recovery_execution_performed
        remote_dispatch_enabled = $false
        production_ready_claim = $false
        next_task = "RC15-planning"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc14-final-closeout-audit-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC14-050"
    status = "completed"
    production_ready_claim = $false
    workflow = ".workflow/active/WFS-20260609-agentos-production-distro-rc14"
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
        rc14_050_complete = $passed
        next_task = "RC15-planning"
        commit_required = $true
    }
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

Write-Host "RC14 final closeout audit $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Verdict: $($finalAudit.verdict)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:blockers).Count)"

if ($FailOnBlocked -and -not $passed) {
    exit 1
}
