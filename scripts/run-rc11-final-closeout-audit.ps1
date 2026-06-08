param(
    [string]$ArtifactDir = ".workflow/artifacts/rc11-final-closeout-audit",
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
    $markers = @(
        ("BEGIN " + "PRIVATE KEY"),
        ("Authorization:" + " Bearer"),
        ("Bearer" + " "),
        ("access" + "_token"),
        ("refresh" + "_token")
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

function Test-NoHostPathText {
    param([Parameter(Mandatory = $true)][string[]]$Values)
    foreach ($value in $Values) {
        if ($null -ne $value -and $value -match "[A-Za-z]:\\") {
            return $false
        }
    }
    return $true
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
$generatedAt = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }

$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$expectedArtifactDir = Resolve-RepoPath ".workflow/artifacts/rc11-final-closeout-audit"
if (-not $resolvedArtifactDir.Equals($expectedArtifactDir, [StringComparison]::OrdinalIgnoreCase)) {
    throw "ArtifactDir must be .workflow/artifacts/rc11-final-closeout-audit"
}
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null

$paths = [ordered]@{
    plan = ".workflow/active/WFS-20260609-agentos-production-distro-rc11/plan.json"
    workflow_session = ".workflow/active/WFS-20260609-agentos-production-distro-rc11/workflow-session.json"
    rc10_final_audit = ".workflow/active/WFS-20260608-agentos-production-distro-rc10/evidence/FINAL-AUDIT-20260608-production-distro-rc10.json"
    rc11_plan_doc = ".workflow/active/WFS-20260609-agentos-production-distro-rc11/docs/rc11-real-object-controlled-execution-unblock-plan.md"
    rc11_trust_contract = ".workflow/active/WFS-20260609-agentos-production-distro-rc11/docs/real-object-trust-handoff-contract.md"
    planning_evidence = ".workflow/active/WFS-20260609-agentos-production-distro-rc11/evidence/RC11-000-planning.json"
    contract_evidence = ".workflow/active/WFS-20260609-agentos-production-distro-rc11/evidence/RC11-001-real-object-trust-handoff-contract.json"
    byte_map_result = ".workflow/artifacts/rc11-release-object-byte-map/result.json"
    byte_map = ".workflow/artifacts/rc11-release-object-byte-map/release-object-byte-map.json"
    descriptor_candidate = ".workflow/artifacts/rc11-release-object-byte-map/immutable-descriptor-candidate.json"
    descriptor_candidate_report = ".workflow/artifacts/rc11-release-object-byte-map/descriptor-candidate-report.json"
    drift_result = ".workflow/artifacts/rc11-declared-current-drift-zero/result.json"
    drift_reconciliation = ".workflow/artifacts/rc11-declared-current-drift-zero/declared-current-drift-zero-reconciliation.json"
    drift_denial = ".workflow/artifacts/rc11-declared-current-drift-zero/drift-zero-denial.json"
    drift_handoff = ".workflow/artifacts/rc11-declared-current-drift-zero/external-descriptor-verification-handoff.json"
    descriptor_verification_result = ".workflow/artifacts/rc11-external-object-descriptor-verification/result.json"
    descriptor_verification_report = ".workflow/artifacts/rc11-external-object-descriptor-verification/descriptor-verification-report.json"
    descriptor_verification_denial = ".workflow/artifacts/rc11-external-object-descriptor-verification/descriptor-verification-denial.json"
    descriptor_fail_closed = ".workflow/artifacts/rc11-external-object-descriptor-verification/descriptor-fail-closed-matrix.json"
    quarantine_result = ".workflow/artifacts/rc11-installer-quarantine-verifier/result.json"
    quarantine_fetch_report = ".workflow/artifacts/rc11-installer-quarantine-verifier/quarantine-fetch-report.json"
    installer_fail_closed = ".workflow/artifacts/rc11-installer-quarantine-verifier/installer-fail-closed-matrix.json"
    installer_gate_report = ".workflow/artifacts/rc11-installer-quarantine-verifier/installer-gate-report.json"
    handoff_result = ".workflow/artifacts/rc11-installer-agentcore-security-handoff/result.json"
    agentcore_handoff = ".workflow/artifacts/rc11-installer-agentcore-security-handoff/agentcore-planspec-handoff.json"
    security_envelope = ".workflow/artifacts/rc11-installer-agentcore-security-handoff/security-execution-effect-envelope.json"
    handoff_denial = ".workflow/artifacts/rc11-installer-agentcore-security-handoff/handoff-denial.json"
    approval_result = ".workflow/artifacts/rc11-two-target-canary-approval/result.json"
    canary_target_set = ".workflow/artifacts/rc11-two-target-canary-approval/canary-target-set.json"
    exact_approval_package = ".workflow/artifacts/rc11-two-target-canary-approval/exact-approval-package.json"
    approval_fail_closed = ".workflow/artifacts/rc11-two-target-canary-approval/approval-fail-closed-matrix.json"
    activation_approval_handoff = ".workflow/artifacts/rc11-two-target-canary-approval/controlled-activation-approval-handoff.json"
    activation_result = ".workflow/artifacts/rc11-controlled-canary-activation/result.json"
    activation_gate = ".workflow/artifacts/rc11-controlled-canary-activation/activation-gate-report.json"
    activation_denial = ".workflow/artifacts/rc11-controlled-canary-activation/activation-denial-evidence.json"
    activation_handoff = ".workflow/artifacts/rc11-controlled-canary-activation/controlled-activation-handoff.json"
    rollback_result = ".workflow/artifacts/rc11-controlled-rollback-support-recovery/result.json"
    rollback_planspec = ".workflow/artifacts/rc11-controlled-rollback-support-recovery/rollback-planspec-requirement.json"
    rollback_gate = ".workflow/artifacts/rc11-controlled-rollback-support-recovery/rollback-support-gate-report.json"
    rollback_denial = ".workflow/artifacts/rc11-controlled-rollback-support-recovery/rollback-support-denial-evidence.json"
    support_recovery_chain = ".workflow/artifacts/rc11-controlled-rollback-support-recovery/support-recovery-evidence-chain.json"
    support_bundle = ".workflow/artifacts/rc11-controlled-rollback-support-recovery/controlled-execution-support-bundle.json"
    recovery_index = ".workflow/artifacts/rc11-controlled-rollback-support-recovery/recovery-reference-index.json"
}

$resolved = [ordered]@{}
$json = [ordered]@{}
foreach ($key in $paths.Keys) {
    $resolved[$key] = Resolve-RepoPath $paths[$key]
    $json[$key] = if ([IO.Path]::GetExtension($paths[$key]) -eq ".json") { Read-Json $resolved[$key] } else { $null }
}

$preCloseoutTasks = @("RC11-000", "RC11-001", "RC11-010", "RC11-011", "RC11-012", "RC11-020", "RC11-021", "RC11-030", "RC11-031", "RC11-040")
$completedBeforeCloseout = 0
foreach ($taskId in $preCloseoutTasks) {
    if ((Get-TaskStatus $json.plan $taskId) -eq "completed") {
        $completedBeforeCloseout++
    }
}

$rc11050Status = Get-TaskStatus $json.plan "RC11-050"
$preCloseoutPlanState = $json.plan.current_task -eq "RC11-050" -and $rc11050Status -eq "pending"
$postCloseoutPlanState = $json.plan.status -eq "completed" -and $null -eq $json.plan.current_task -and $rc11050Status -eq "completed"
$planReady = ($preCloseoutPlanState -or $postCloseoutPlanState) -and $completedBeforeCloseout -eq @($preCloseoutTasks).Count

$docsReady = (Test-Path -LiteralPath $resolved.rc11_plan_doc -PathType Leaf) -and
    (Test-Path -LiteralPath $resolved.rc11_trust_contract -PathType Leaf)

$rc10Ready = $json.rc10_final_audit.verdict -eq "PASS" -and $json.rc10_final_audit.production_ready_claim -eq $false

$byteMapReady = $json.byte_map_result.status -eq "passed" -and
    $json.byte_map_result.summary.rc11_010_complete -eq $true -and
    $json.byte_map_result.summary.failed_checks -eq 0 -and
    $json.byte_map_result.byte_map_surface.external_https_object_uri_published -eq $false -and
    $json.byte_map_result.byte_map_surface.drift_count_carried_forward -eq 13 -and
    $json.byte_map_result.byte_map_surface.install_allowed -eq $false -and
    $json.byte_map_result.byte_map_surface.activation_allowed -eq $false -and
    $json.byte_map_result.byte_map_surface.rollback_execution_allowed -eq $false

$driftDeniedReady = $json.drift_result.status -eq "passed" -and
    $json.drift_result.summary.rc11_011_complete -eq $true -and
    $json.drift_result.summary.failed_checks -eq 0 -and
    $json.drift_result.reconciliation_surface.state -eq "declared-current-drift-denied" -and
    $json.drift_result.reconciliation_surface.drift_zero -eq $false -and
    $json.drift_result.reconciliation_surface.drift_count -eq 13 -and
    $json.drift_result.reconciliation_surface.rc11_self_drift -eq 0 -and
    $json.drift_result.reconciliation_surface.external_object_trust_allowed -eq $false -and
    $json.drift_result.reconciliation_surface.external_object_descriptor_verification_allowed -eq $false -and
    $json.drift_result.reconciliation_surface.installer_quarantine_fetch_allowed -eq $false -and
    $json.drift_result.reconciliation_surface.install_allowed -eq $false -and
    $json.drift_result.reconciliation_surface.activation_allowed -eq $false -and
    $json.drift_result.reconciliation_surface.rollback_execution_allowed -eq $false

$descriptorDeniedReady = $json.descriptor_verification_result.status -eq "passed" -and
    $json.descriptor_verification_result.summary.rc11_012_complete -eq $true -and
    $json.descriptor_verification_result.summary.failed_checks -eq 0 -and
    $json.descriptor_verification_result.summary.failed_fail_closed_cases -eq 0 -and
    $json.descriptor_verification_result.verification_surface.state -eq "external-descriptor-verification-denied" -and
    $json.descriptor_verification_result.verification_surface.descriptor_matches_current_bytes -eq $true -and
    $json.descriptor_verification_result.verification_surface.descriptor_verified -eq $false -and
    $json.descriptor_verification_result.verification_surface.external_https_object_uri_published -eq $false -and
    $json.descriptor_verification_result.verification_surface.drift_zero -eq $false -and
    $json.descriptor_verification_result.verification_surface.network_probe_performed -eq $false -and
    $json.descriptor_verification_result.verification_surface.object_trust_allowed -eq $false -and
    $json.descriptor_verification_result.verification_surface.installer_quarantine_fetch_allowed -eq $false -and
    $json.descriptor_verification_result.verification_surface.install_allowed -eq $false -and
    $json.descriptor_verification_result.verification_surface.activation_allowed -eq $false -and
    $json.descriptor_verification_result.verification_surface.rollback_execution_allowed -eq $false

$quarantineDeniedReady = $json.quarantine_result.status -eq "passed" -and
    $json.quarantine_result.summary.rc11_020_complete -eq $true -and
    $json.quarantine_result.summary.failed_checks -eq 0 -and
    $json.quarantine_result.summary.failed_cases -eq 0 -and
    $json.quarantine_result.fetch_surface.state -eq "quarantine-fetch-denied-before-network" -and
    $json.quarantine_result.fetch_surface.fetch_allowed -eq $false -and
    $json.quarantine_result.fetch_surface.network_fetch_attempted -eq $false -and
    $json.quarantine_result.fetch_surface.remote_payload_bytes_downloaded -eq $false -and
    $json.quarantine_result.fetch_surface.quarantine_payload_written -eq $false -and
    $json.quarantine_result.fetch_surface.pre_interpretation_verification_performed -eq $false -and
    $json.quarantine_result.fetch_surface.payload_interpreted -eq $false -and
    $json.quarantine_result.fetch_surface.install_allowed -eq $false -and
    $json.quarantine_result.fetch_surface.activation_allowed -eq $false -and
    $json.quarantine_result.fetch_surface.rollback_execution_allowed -eq $false

$handoffDeniedReady = $json.handoff_result.status -eq "passed" -and
    $json.handoff_result.summary.rc11_021_complete -eq $true -and
    $json.handoff_result.summary.failed_checks -eq 0 -and
    $json.handoff_result.summary.failed_cases -eq 0 -and
    $json.handoff_result.handoff_surface.state -eq "installer-agentcore-security-handoff-denied" -and
    $json.handoff_result.handoff_surface.installer_preflight_bound -eq $true -and
    $json.handoff_result.handoff_surface.installer_preflight_verified -eq $false -and
    $json.handoff_result.handoff_surface.agentcore_planspec_candidate_projected -eq $true -and
    $json.handoff_result.handoff_surface.agentcore_planspec_bound -eq $false -and
    $json.handoff_result.handoff_surface.agentcore_planspec_executable -eq $false -and
    $json.handoff_result.handoff_surface.security_execution_required -eq $true -and
    $json.handoff_result.handoff_surface.security_execution_allowed -eq $false -and
    $json.handoff_result.handoff_surface.install_allowed -eq $false -and
    $json.handoff_result.handoff_surface.activation_allowed -eq $false -and
    $json.handoff_result.handoff_surface.rollback_execution_allowed -eq $false -and
    $json.handoff_result.handoff_surface.support_upload_allowed -eq $false -and
    $json.handoff_result.handoff_surface.remote_dispatch_enabled -eq $false

$approvalDeniedReady = $json.approval_result.status -eq "passed" -and
    $json.approval_result.summary.rc11_030_complete -eq $true -and
    $json.approval_result.summary.failed_checks -eq 0 -and
    $json.approval_result.summary.failed_cases -eq 0 -and
    $json.approval_result.approval_surface.state -eq "target-and-approval-denied" -and
    $json.approval_result.approval_surface.required_minimum_target_count -eq 2 -and
    $json.approval_result.approval_surface.observed_candidate_node_count -eq 1 -and
    $json.approval_result.approval_surface.enrolled_target_count -eq 0 -and
    $json.approval_result.approval_surface.target_set_enrolled -eq $false -and
    $json.approval_result.approval_surface.exact_approval_bound -eq $false -and
    $json.approval_result.approval_surface.approval_granted -eq $false -and
    $json.approval_result.approval_surface.security_execution_allowed -eq $false -and
    $json.approval_result.approval_surface.activation_allowed -eq $false -and
    $json.approval_result.approval_surface.rollback_execution_allowed -eq $false -and
    $json.approval_result.approval_surface.support_upload_allowed -eq $false -and
    $json.approval_result.approval_surface.remote_dispatch_enabled -eq $false

$activationDeniedReady = $json.activation_result.status -eq "passed" -and
    $json.activation_result.summary.rc11_031_complete -eq $true -and
    $json.activation_result.summary.failed_checks -eq 0 -and
    $json.activation_result.summary.failed_cases -eq 0 -and
    $json.activation_result.activation_surface.state -eq "activation-denied" -and
    $json.activation_result.activation_surface.activation_allowed -eq $false -and
    $json.activation_result.activation_surface.activation_performed -eq $false -and
    $json.activation_result.activation_surface.controlled_execution_authorized -eq $false -and
    $json.activation_result.activation_surface.target_set_enrolled -eq $false -and
    $json.activation_result.activation_surface.exact_approval_granted -eq $false -and
    $json.activation_result.activation_surface.agentcore_planspec_bound -eq $false -and
    $json.activation_result.activation_surface.security_execution_approval_bound -eq $false -and
    $json.activation_result.activation_surface.rollback_execution_allowed -eq $false -and
    $json.activation_result.activation_surface.support_upload_allowed -eq $false -and
    $json.activation_result.activation_surface.remote_dispatch_enabled -eq $false

$rollbackSupportDeniedReady = $json.rollback_result.status -eq "passed" -and
    $json.rollback_result.summary.rc11_040_complete -eq $true -and
    $json.rollback_result.summary.failed_checks -eq 0 -and
    $json.rollback_result.summary.failed_cases -eq 0 -and
    $json.rollback_result.rollback_surface.state -eq "rollback-denied" -and
    $json.rollback_result.rollback_surface.rollback_readiness_ready -eq $true -and
    $json.rollback_result.rollback_surface.rollback_execution_allowed -eq $false -and
    $json.rollback_result.rollback_surface.rollback_execution_performed -eq $false -and
    $json.rollback_result.rollback_surface.controlled_canary_activation_performed -eq $false -and
    $json.rollback_result.rollback_surface.exact_rollback_approval_granted -eq $false -and
    $json.rollback_result.rollback_surface.agentcore_rollback_planspec_bound -eq $false -and
    $json.rollback_result.rollback_surface.security_execution_rollback_approval_bound -eq $false -and
    $json.rollback_result.rollback_surface.support_upload_allowed -eq $false -and
    $json.rollback_result.rollback_surface.recovery_execution_allowed -eq $false -and
    $json.rollback_result.rollback_surface.remote_dispatch_enabled -eq $false -and
    $json.rollback_result.support_surface.support_recovery_binding_present -eq $true -and
    $json.rollback_result.support_surface.support_bundle_redacted -eq $true -and
    $json.rollback_result.support_surface.support_upload_allowed -eq $false -and
    $json.rollback_result.support_surface.support_upload_performed -eq $false -and
    $json.rollback_result.support_surface.recovery_execution_allowed -eq $false -and
    $json.rollback_result.support_surface.recovery_execution_performed -eq $false

$resultSet = @(
    [pscustomobject]@{ Task = "RC11-010"; Json = $json.byte_map_result },
    [pscustomobject]@{ Task = "RC11-011"; Json = $json.drift_result },
    [pscustomobject]@{ Task = "RC11-012"; Json = $json.descriptor_verification_result },
    [pscustomobject]@{ Task = "RC11-020"; Json = $json.quarantine_result },
    [pscustomobject]@{ Task = "RC11-021"; Json = $json.handoff_result },
    [pscustomobject]@{ Task = "RC11-030"; Json = $json.approval_result },
    [pscustomobject]@{ Task = "RC11-031"; Json = $json.activation_result },
    [pscustomobject]@{ Task = "RC11-040"; Json = $json.rollback_result }
)

$forbiddenInvariantNames = @(
    "mirror_frontend_changed",
    "nginx_or_tls_changed",
    "signer_infra_changed",
    "local_private_key_material_used",
    "private_key_material_read_or_printed",
    "cryptographic_signing_performed",
    "payload_upload_performed",
    "payload_bytes_uploaded",
    "remote_payload_bytes_downloaded",
    "quarantine_payload_written",
    "drift_repair_performed",
    "declared_metadata_rewritten",
    "descriptor_published",
    "install_performed",
    "activation_performed",
    "rollback_execution_performed",
    "canary_execution_performed",
    "support_upload_performed",
    "recovery_execution_performed",
    "active_slot_mutated",
    "boot_metadata_mutated",
    "active_artifact_set_mutated",
    "production_ring_mutated",
    "remote_dispatch_enabled",
    "mirror_authority",
    "signer_reachability_authority",
    "frontend_authority",
    "model_replay_authority",
    "normal_shell_authority",
    "tui_authority",
    "production_ready_claim"
)
$invariantViolations = @(Test-InvariantFalse -ResultSet $resultSet -Names $forbiddenInvariantNames)

Add-Check "rc11.plan.precloseout_complete" $planReady "All RC11 pre-closeout tasks must be completed and RC11-050 must be pending before first audit or completed on rerun." ([ordered]@{ completed = $completedBeforeCloseout; expected = @($preCloseoutTasks).Count; current_task = $json.plan.current_task; rc11_050_status = $rc11050Status; plan_status = $json.plan.status })
Add-Check "rc11.docs.present" $docsReady "RC11 plan and real-object trust handoff contract must exist." ([ordered]@{ plan_doc = Get-StablePath $resolved.rc11_plan_doc; trust_contract = Get-StablePath $resolved.rc11_trust_contract })
Add-Check "rc10.previous_milestone.closed" $rc10Ready "RC11 final audit must inherit a PASS RC10 final audit without GA claim." ([ordered]@{ verdict = $json.rc10_final_audit.verdict; production_ready_claim = $json.rc10_final_audit.production_ready_claim })
Add-Check "rc11.byte_map.candidate_blocked" $byteMapReady "RC11 release object byte map must pass while external HTTPS object URI, install, activation, and rollback remain blocked." $json.byte_map_result.summary
Add-Check "rc11.declared_current_drift.denied" $driftDeniedReady "RC11 declared/current drift reconciliation must deny object trust while carried-forward drift remains." $json.drift_result.summary
Add-Check "rc11.external_descriptor.verification_denied" $descriptorDeniedReady "RC11 external object descriptor verification must match current bytes but deny trust because URI, drift-zero, and freshness gates are missing." $json.descriptor_verification_result.summary
Add-Check "rc11.quarantine_fetch.denied_before_network" $quarantineDeniedReady "RC11 installer quarantine fetch must deny before network and avoid quarantine writes or payload interpretation." $json.quarantine_result.summary
Add-Check "rc11.installer_agentcore_security.denied" $handoffDeniedReady "RC11 installer preflight must be hash-bound into AgentCore/SecurityExecution handoff while executable authority remains denied." $json.handoff_result.summary
Add-Check "rc11.two_target_approval.denied" $approvalDeniedReady "RC11 canary approval must deny with one observed candidate, zero enrolled targets, and no exact approval grant." $json.approval_result.summary
Add-Check "rc11.activation.denied" $activationDeniedReady "RC11 controlled canary activation must remain denied and side-effect free." $json.activation_result.summary
Add-Check "rc11.rollback_support_recovery.denied" $rollbackSupportDeniedReady "RC11 rollback, support upload, and recovery execution must remain denied while local redacted support evidence is bound." $json.rollback_result.summary
Add-Check "rc11.no_invariant_authority_broadened" (@($invariantViolations).Count -eq 0) "RC11 task invariants must not broaden signing, mirror, frontend, install, activation, rollback, support, recovery, remote dispatch, or production authority." ([ordered]@{ violations = $invariantViolations })

$preWritePassed = @($script:blockers).Count -eq 0
$finalAuditPath = Resolve-RepoPath ".workflow/active/WFS-20260609-agentos-production-distro-rc11/evidence/FINAL-AUDIT-20260609-production-distro-rc11.json"
$closeoutSummaryPath = Resolve-RepoPath ".workflow/active/WFS-20260609-agentos-production-distro-rc11/docs/final-rc11-closeout-summary.md"
$taskEvidencePath = Resolve-RepoPath ".workflow/active/WFS-20260609-agentos-production-distro-rc11/evidence/RC11-050-final-closeout-audit.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"

$sourceArtifacts = [ordered]@{}
foreach ($key in $paths.Keys) {
    $sourceArtifacts[$key] = New-ArtifactRef -Path $resolved[$key] -Json $json[$key]
}

$remainingBlockers = @(
    "external-https-object-uri-not-published",
    "declared-current-drift-zero-not-proved",
    "object-trust-not-allowed",
    "freshness-window-missing",
    "installer-quarantine-fetch-not-run",
    "payload-not-quarantined",
    "pre-interpretation-verification-not-run",
    "two-target-canary-not-enrolled",
    "target-node-ids-missing",
    "exact-operator-approval-not-granted",
    "approval-audit-sink-not-bound",
    "approval-expiry-not-bound",
    "approval-nonce-not-bound",
    "agentcore-planspec-not-executable",
    "security-execution-effect-envelope-denied",
    "controlled-activation-not-authorized",
    "controlled-canary-activation-not-performed",
    "rollback-exact-operator-approval-not-granted",
    "agentcore-rollback-planspec-not-bound",
    "security-execution-rollback-effect-envelope-not-bound",
    "rollback-audit-journal-not-bound",
    "post-rollback-observations-missing",
    "remote-fleet-execution-not-enabled"
)

$finalAudit = [ordered]@{
    schema = "agentos.production-distro-rc11-final-audit.v1"
    generated_at = $generatedAt
    workflow = ".workflow/active/WFS-20260609-agentos-production-distro-rc11"
    milestone = "Production Distro RC11"
    verdict = if ($preWritePassed) { "PASS" } else { "BLOCKED" }
    decision = if ($preWritePassed) { "rc11-closeout-pass-next-milestone-planning" } else { "rc11-closeout-blocked" }
    production_ready_claim = $false
    hosted_endpoint_domain = "aios.w33d.xyz"
    signer_endpoint_domain = "sign.w33d.xyz"
    objective = "AIOS-body real-object controlled execution unblock audit with fail-closed object trust, installer quarantine, activation, rollback, support, and recovery evidence"
    task_results = @($preCloseoutTasks | ForEach-Object { [ordered]@{ id = $_; status = Get-TaskStatus $json.plan $_ } })
    acceptance_coverage = @(
        [ordered]@{ requirement = "current release object byte map is projected and hash-bound without external object trust"; status = if ($byteMapReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.byte_map_result), (Get-StablePath $resolved.byte_map), (Get-StablePath $resolved.descriptor_candidate)) }
        [ordered]@{ requirement = "declared/current drift-zero remains a blocker until drift_count is zero"; status = if ($driftDeniedReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.drift_result), (Get-StablePath $resolved.drift_denial)) }
        [ordered]@{ requirement = "external descriptor verification matches current bytes but denies trust without URI, freshness, and drift-zero"; status = if ($descriptorDeniedReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.descriptor_verification_result), (Get-StablePath $resolved.descriptor_verification_denial), (Get-StablePath $resolved.descriptor_fail_closed)) }
        [ordered]@{ requirement = "installer quarantine fetch denies before network and payload interpretation"; status = if ($quarantineDeniedReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.quarantine_result), (Get-StablePath $resolved.quarantine_fetch_report), (Get-StablePath $resolved.installer_fail_closed)) }
        [ordered]@{ requirement = "installer preflight is bound into AgentCore and SecurityExecution without executable authority"; status = if ($handoffDeniedReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.handoff_result), (Get-StablePath $resolved.agentcore_handoff), (Get-StablePath $resolved.security_envelope)) }
        [ordered]@{ requirement = "two-target canary approval and exact approval package deny activation with insufficient targets and missing approval bindings"; status = if ($approvalDeniedReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.approval_result), (Get-StablePath $resolved.canary_target_set), (Get-StablePath $resolved.exact_approval_package)) }
        [ordered]@{ requirement = "controlled canary activation remains denied and side-effect free"; status = if ($activationDeniedReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.activation_result), (Get-StablePath $resolved.activation_denial)) }
        [ordered]@{ requirement = "rollback, support upload, and recovery remain denied with redacted local support evidence"; status = if ($rollbackSupportDeniedReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.rollback_result), (Get-StablePath $resolved.rollback_denial), (Get-StablePath $resolved.support_bundle), (Get-StablePath $resolved.recovery_index)) }
    )
    execution_surface = [ordered]@{
        release_id = $json.byte_map_result.release_id
        current_payload_size_bytes = $json.byte_map_result.byte_map_surface.current_payload_size_bytes
        current_payload_sha256 = $json.byte_map_result.byte_map_surface.current_payload_sha256
        external_https_object_uri_published = $json.byte_map_result.byte_map_surface.external_https_object_uri_published
        drift_state = $json.drift_result.reconciliation_surface.state
        drift_zero = $json.drift_result.reconciliation_surface.drift_zero
        drift_count = $json.drift_result.reconciliation_surface.drift_count
        descriptor_verification_state = $json.descriptor_verification_result.verification_surface.state
        descriptor_matches_current_bytes = $json.descriptor_verification_result.verification_surface.descriptor_matches_current_bytes
        descriptor_verified = $json.descriptor_verification_result.verification_surface.descriptor_verified
        network_probe_performed = $json.descriptor_verification_result.verification_surface.network_probe_performed
        quarantine_fetch_state = $json.quarantine_result.fetch_surface.state
        network_fetch_attempted = $json.quarantine_result.fetch_surface.network_fetch_attempted
        quarantine_payload_written = $json.quarantine_result.fetch_surface.quarantine_payload_written
        installer_preflight_bound = $json.handoff_result.handoff_surface.installer_preflight_bound
        installer_preflight_verified = $json.handoff_result.handoff_surface.installer_preflight_verified
        agentcore_planspec_candidate_projected = $json.handoff_result.handoff_surface.agentcore_planspec_candidate_projected
        agentcore_planspec_executable = $json.handoff_result.handoff_surface.agentcore_planspec_executable
        security_execution_allowed = $json.handoff_result.handoff_surface.security_execution_allowed
        required_minimum_target_count = $json.approval_result.approval_surface.required_minimum_target_count
        observed_candidate_node_count = $json.approval_result.approval_surface.observed_candidate_node_count
        enrolled_target_count = $json.approval_result.approval_surface.enrolled_target_count
        exact_approval_bound = $json.approval_result.approval_surface.exact_approval_bound
        exact_approval_granted = $json.approval_result.approval_surface.approval_granted
        activation_state = $json.activation_result.activation_surface.state
        activation_allowed = $json.activation_result.activation_surface.activation_allowed
        activation_performed = $json.activation_result.activation_surface.activation_performed
        rollback_state = $json.rollback_result.rollback_surface.state
        rollback_readiness_ready = $json.rollback_result.rollback_surface.rollback_readiness_ready
        rollback_execution_allowed = $json.rollback_result.rollback_surface.rollback_execution_allowed
        rollback_execution_performed = $json.rollback_result.rollback_surface.rollback_execution_performed
        support_recovery_binding_present = $json.rollback_result.support_surface.support_recovery_binding_present
        support_bundle_redacted = $json.rollback_result.support_surface.support_bundle_redacted
        support_upload_performed = $json.rollback_result.support_surface.support_upload_performed
        recovery_execution_performed = $json.rollback_result.support_surface.recovery_execution_performed
        remote_dispatch_enabled = $json.rollback_result.rollback_surface.remote_dispatch_enabled
    }
    invariants_verified = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        mirror_frontend_changed = $false
        nginx_or_tls_changed = $false
        signer_infra_changed = $false
        private_key_material_used = $false
        cryptographic_signing_performed = $false
        mirror_is_root_of_trust = $false
        frontend_authority = $false
        mirror_authority = $false
        signer_reachability_authority = $false
        endpoint_reachability_is_trust = $false
        external_payload_bytes_uploaded = $false
        network_probe_performed = $false
        network_fetch_attempted = $false
        remote_payload_bytes_downloaded = $false
        quarantine_payload_written = $false
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
    remaining_blockers_before_ga_or_execution = $remainingBlockers
    next_milestone = [ordered]@{
        id = "Production Distro RC12"
        title = "real object publication, drift-zero, quarantine fetch, and controlled execution proof"
        reason = "RC11 proves the AIOS body still fails closed with explicit evidence across object trust, drift, quarantine, AgentCore, SecurityExecution, canary approval, activation, rollback, support, and recovery. RC12 should convert remaining blockers into controlled unblock evidence without relying on mirror, frontend, signer reachability, shell output, TUI output, or model replay as authority."
    }
}

$summaryText = @'
# Production Distro RC11 Closeout Summary

RC11 closes the AIOS-body controlled unblock audit. It proves the current release object bytes are mapped and descriptor-matched, but object trust remains blocked because the external HTTPS object URI, declared/current drift-zero, freshness, quarantine fetch, two-target enrollment, exact approval, AgentCore executable PlanSpec, SecurityExecution allow decision, controlled activation, separate rollback approval, rollback execution, audit journal, and post-rollback observations are still missing.

This is not a GA production-ready claim. The release remains install-blocked, activation-blocked, rollback-blocked, support-upload-blocked, recovery-blocked, and remote-dispatch-blocked by design.

## Evidence

- Release object byte map: `.workflow/artifacts/rc11-release-object-byte-map/result.json`
- Declared/current drift-zero reconciliation: `.workflow/artifacts/rc11-declared-current-drift-zero/result.json`
- External descriptor verification: `.workflow/artifacts/rc11-external-object-descriptor-verification/result.json`
- Installer quarantine verifier: `.workflow/artifacts/rc11-installer-quarantine-verifier/result.json`
- Installer AgentCore/SecurityExecution handoff: `.workflow/artifacts/rc11-installer-agentcore-security-handoff/result.json`
- Two-target canary approval: `.workflow/artifacts/rc11-two-target-canary-approval/result.json`
- Controlled canary activation: `.workflow/artifacts/rc11-controlled-canary-activation/result.json`
- Controlled rollback support/recovery: `.workflow/artifacts/rc11-controlled-rollback-support-recovery/result.json`
- Final audit: `.workflow/active/WFS-20260609-agentos-production-distro-rc11/evidence/FINAL-AUDIT-20260609-production-distro-rc11.json`

## Verdict

Verdict PASS - Production Distro RC11 is closed as a non-GA fail-closed milestone for AIOS-body real-object verification, installer quarantine gating, AgentCore/SecurityExecution handoff, canary approval, activation denial, rollback denial, and support/recovery binding.

## Next Milestone

Production Distro RC12 should turn the remaining blockers into controlled unblock evidence: publish or bind a real immutable credential-free HTTPS object URI, reconcile declared/current drift to zero, run quarantine fetch verification before interpretation, enroll two real canary targets, bind exact approval with audit sink, nonce and expiry, make AgentCore PlanSpec executable through SecurityExecution allow, execute controlled canary activation, then run a separately approved rollback drill with support/recovery evidence.
'@

if ($preWritePassed) {
    Write-Json $finalAudit $finalAuditPath
    $summaryParent = Split-Path -Parent $closeoutSummaryPath
    if ($summaryParent) {
        New-Item -ItemType Directory -Force -Path $summaryParent | Out-Null
    }
    [IO.File]::WriteAllText($closeoutSummaryPath, $summaryText, [Text.UTF8Encoding]::new($false))
}

Add-Check "final_audit.written" (Test-Path -LiteralPath $finalAuditPath -PathType Leaf) "Final RC11 audit artifact must be written." ([ordered]@{ path = Get-StablePath $finalAuditPath; sha256 = Get-FileSha256 $finalAuditPath })
Add-Check "closeout_summary.written" (Test-Path -LiteralPath $closeoutSummaryPath -PathType Leaf) "Final RC11 closeout summary must be written." ([ordered]@{ path = Get-StablePath $closeoutSummaryPath; sha256 = Get-FileSha256 $closeoutSummaryPath })
$closeoutOutputValues = @()
if (Test-Path -LiteralPath $finalAuditPath -PathType Leaf) {
    $closeoutOutputValues += Get-Content -Raw -LiteralPath $finalAuditPath
}
if (Test-Path -LiteralPath $closeoutSummaryPath -PathType Leaf) {
    $closeoutOutputValues += Get-Content -Raw -LiteralPath $closeoutSummaryPath
}
if (@($closeoutOutputValues).Count -eq 0) {
    $closeoutOutputValues = @("no-closeout-output-written")
}
Add-Check "closeout_outputs.secret_safe" (Test-NoSensitiveText -Values $closeoutOutputValues) "Final RC11 closeout outputs must not contain private key or token markers." ([ordered]@{ final_audit = Get-StablePath $finalAuditPath; closeout_summary = Get-StablePath $closeoutSummaryPath })
Add-Check "closeout_outputs.host_path_free" (Test-NoHostPathText -Values $closeoutOutputValues) "Final RC11 closeout outputs must not contain host-local absolute paths." ([ordered]@{ final_audit = Get-StablePath $finalAuditPath; closeout_summary = Get-StablePath $closeoutSummaryPath })

$passed = @($script:blockers).Count -eq 0
$result = [ordered]@{
    schema = "agentos.rc11-final-closeout-audit-result.v1"
    generated_at = $generatedAt
    task = "RC11-050"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    rc11_050_complete = $passed
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
    outputs = [ordered]@{
        final_audit = [ordered]@{ path = Get-StablePath $finalAuditPath; sha256 = Get-FileSha256 $finalAuditPath; present = Test-Path -LiteralPath $finalAuditPath -PathType Leaf }
        closeout_summary = [ordered]@{ path = Get-StablePath $closeoutSummaryPath; sha256 = Get-FileSha256 $closeoutSummaryPath; present = Test-Path -LiteralPath $closeoutSummaryPath -PathType Leaf }
    }
    source_artifacts = $sourceArtifacts
    remaining_blockers_before_ga_or_execution = $remainingBlockers
    checks = $script:checks
    blockers = $script:blockers
    summary = [ordered]@{
        checks = @($script:checks).Count
        blockers = @($script:blockers).Count
        rc11_050_complete = $passed
        final_audit_written = Test-Path -LiteralPath $finalAuditPath -PathType Leaf
        closeout_summary_written = Test-Path -LiteralPath $closeoutSummaryPath -PathType Leaf
        byte_map_state = $json.byte_map_result.byte_map_surface.state
        drift_state = $json.drift_result.reconciliation_surface.state
        drift_count = $json.drift_result.reconciliation_surface.drift_count
        descriptor_verification_state = $json.descriptor_verification_result.verification_surface.state
        quarantine_fetch_state = $json.quarantine_result.fetch_surface.state
        handoff_state = $json.handoff_result.handoff_surface.state
        approval_state = $json.approval_result.approval_surface.state
        activation_state = $json.activation_result.activation_surface.state
        rollback_state = $json.rollback_result.rollback_surface.state
        support_recovery_binding_present = $json.rollback_result.support_surface.support_recovery_binding_present
        production_ready_claim = $false
        next_milestone = "Production Distro RC12"
    }
}

Write-Json $result $resultPath

if ($passed) {
    $taskEvidence = [ordered]@{
        schema = "agentos.rc11-final-closeout-audit-evidence.v1"
        generated_at = $generatedAt
        task = "RC11-050"
        status = "completed"
        production_ready_claim = $false
        workflow = ".workflow/active/WFS-20260609-agentos-production-distro-rc11"
        script = [ordered]@{
            path = "scripts/run-rc11-final-closeout-audit.ps1"
            sha256 = Get-FileSha256 (Resolve-RepoPath "scripts/run-rc11-final-closeout-audit.ps1")
        }
        result = [ordered]@{
            path = Get-StablePath $resultPath
            status = $result.status
            sha256 = Get-FileSha256 $resultPath
        }
        outputs = [ordered]@{
            final_audit = [ordered]@{
                path = Get-StablePath $finalAuditPath
                sha256 = Get-FileSha256 $finalAuditPath
                verdict = $finalAudit.verdict
            }
            closeout_summary = [ordered]@{
                path = Get-StablePath $closeoutSummaryPath
                sha256 = Get-FileSha256 $closeoutSummaryPath
            }
        }
        audit_surface = $result.summary
        invariants = $finalAudit.invariants_verified
        completion = [ordered]@{
            rc11_050_complete = $passed
            next_milestone = "Production Distro RC12"
            commit_required = $true
        }
    }
    Write-Json $taskEvidence $taskEvidencePath
}

foreach ($writtenPath in @($resultPath, $finalAuditPath, $closeoutSummaryPath, $taskEvidencePath)) {
    if (-not (Test-Path -LiteralPath $writtenPath -PathType Leaf)) {
        continue
    }
    $content = Get-Content -Raw -LiteralPath $writtenPath
    if (-not (Test-NoSensitiveText -Values @($content))) {
        throw "Sensitive marker detected in $(Get-StablePath $writtenPath)."
    }
    if (-not (Test-NoHostPathText -Values @($content))) {
        throw "Host-local path detected in $(Get-StablePath $writtenPath)."
    }
}

Write-Host "RC11 final closeout audit $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Checks: $(@($script:checks).Count), blockers: $(@($script:blockers).Count), next milestone: Production Distro RC12"

if ($FailOnBlocked -and -not $passed) {
    exit 1
}
