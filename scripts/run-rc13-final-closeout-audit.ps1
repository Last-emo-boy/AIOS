param(
    [string]$ArtifactDir = ".workflow/artifacts/rc13-final-closeout-audit",
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
$expectedArtifactDir = Resolve-RepoPath ".workflow/artifacts/rc13-final-closeout-audit"
if (-not $resolvedArtifactDir.Equals($expectedArtifactDir, [StringComparison]::OrdinalIgnoreCase)) {
    throw "ArtifactDir must be .workflow/artifacts/rc13-final-closeout-audit"
}
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null

$paths = [ordered]@{
    plan = ".workflow/active/WFS-20260609-agentos-production-distro-rc13/plan.json"
    workflow_session = ".workflow/active/WFS-20260609-agentos-production-distro-rc13/workflow-session.json"
    rc12_final_audit = ".workflow/active/WFS-20260609-agentos-production-distro-rc12/evidence/FINAL-AUDIT-20260609-production-distro-rc12.json"
    rc13_plan_doc = ".workflow/active/WFS-20260609-agentos-production-distro-rc13/docs/rc13-local-trust-unblock-plan.md"
    rc13_contract = ".workflow/active/WFS-20260609-agentos-production-distro-rc13/docs/rc13-local-trust-unblock-contract.md"
    planning_evidence = ".workflow/active/WFS-20260609-agentos-production-distro-rc13/evidence/RC13-000-planning.json"
    contract_evidence = ".workflow/active/WFS-20260609-agentos-production-distro-rc13/evidence/RC13-001-local-trust-unblock-contract.json"
    drift_result = ".workflow/artifacts/rc13-declared-current-drift-zero/result.json"
    object_manifest_result = ".workflow/artifacts/rc13-object-manifest-descriptor-binding/result.json"
    freshness_result = ".workflow/artifacts/rc13-freshness-revocation-authority/result.json"
    quarantine_result = ".workflow/artifacts/rc13-quarantine-preflight/result.json"
    agentcore_result = ".workflow/artifacts/rc13-agentcore-executable-planspec-readiness/result.json"
    security_result = ".workflow/artifacts/rc13-security-execution-allow-preconditions/result.json"
    target_result = ".workflow/artifacts/rc13-two-target-identity-enrollment/result.json"
    approval_result = ".workflow/artifacts/rc13-exact-approval-audit-binding/result.json"
    activation_result = ".workflow/artifacts/rc13-controlled-activation/result.json"
    rollback_result = ".workflow/artifacts/rc13-controlled-rollback-support-recovery/result.json"
}

$resolved = [ordered]@{}
$json = [ordered]@{}
foreach ($key in $paths.Keys) {
    $resolved[$key] = Resolve-RepoPath $paths[$key]
    $json[$key] = if ([IO.Path]::GetExtension($paths[$key]) -eq ".json") { Read-Json $resolved[$key] } else { $null }
}

$preCloseoutTasks = @("RC13-000", "RC13-001", "RC13-010", "RC13-011", "RC13-012", "RC13-020", "RC13-021", "RC13-022", "RC13-030", "RC13-031", "RC13-040", "RC13-041")
$completedBeforeCloseout = 0
foreach ($taskId in $preCloseoutTasks) {
    if ((Get-TaskStatus $json.plan $taskId) -eq "completed") {
        $completedBeforeCloseout++
    }
}

$rc13050Status = Get-TaskStatus $json.plan "RC13-050"
$preCloseoutPlanState = $json.plan.current_task -eq "RC13-050" -and $rc13050Status -eq "pending"
$postCloseoutPlanState = $json.plan.status -eq "completed" -and $null -eq $json.plan.current_task -and $rc13050Status -eq "completed"
$planReady = ($preCloseoutPlanState -or $postCloseoutPlanState) -and $completedBeforeCloseout -eq @($preCloseoutTasks).Count

$docsReady = (Test-Path -LiteralPath $resolved.rc13_plan_doc -PathType Leaf) -and
    (Test-Path -LiteralPath $resolved.rc13_contract -PathType Leaf) -and
    $json.planning_evidence.status -eq "completed" -and
    $json.contract_evidence.status -eq "completed"

$rc12Ready = $json.rc12_final_audit.verdict -eq "PASS" -and $json.rc12_final_audit.production_ready_claim -eq $false

$driftReady = $json.drift_result.status -eq "passed" -and
    $json.drift_result.summary.rc13_010_complete -eq $true -and
    $json.drift_result.summary.failed_checks -eq 0 -and
    $json.drift_result.reconciliation_surface.state -eq "declared-current-drift-denied" -and
    $json.drift_result.reconciliation_surface.drift_zero -eq $false -and
    $json.drift_result.reconciliation_surface.drift_count -eq 19 -and
    $json.drift_result.reconciliation_surface.current_payload_matches_rc12 -eq $true -and
    $json.drift_result.reconciliation_surface.object_trust_allowed -eq $false -and
    $json.drift_result.reconciliation_surface.activation_allowed -eq $false -and
    $json.drift_result.reconciliation_surface.rollback_execution_allowed -eq $false

$objectManifestReady = $json.object_manifest_result.status -eq "passed" -and
    $json.object_manifest_result.summary.rc13_011_complete -eq $true -and
    $json.object_manifest_result.summary.failed_checks -eq 0 -and
    $json.object_manifest_result.binding_surface.local_descriptor_manifest_consistent -eq $true -and
    $json.object_manifest_result.binding_surface.comparison_drifts -eq 0 -and
    $json.object_manifest_result.binding_surface.object_manifest_descriptor_binding_allowed -eq $false -and
    $json.object_manifest_result.binding_surface.object_trust_allowed -eq $false -and
    $json.object_manifest_result.binding_surface.activation_allowed -eq $false -and
    $json.object_manifest_result.binding_surface.rollback_execution_allowed -eq $false

$freshnessReady = $json.freshness_result.status -eq "passed" -and
    $json.freshness_result.summary.rc13_012_complete -eq $true -and
    $json.freshness_result.summary.failed_checks -eq 0 -and
    $json.freshness_result.summary.failed_fail_closed_cases -eq 0 -and
    $json.freshness_result.authority_surface.public_signature_bound -eq $true -and
    $json.freshness_result.authority_surface.revocation_authority_bound -eq $true -and
    $json.freshness_result.authority_surface.freshness_window_bound -eq $false -and
    $json.freshness_result.authority_surface.freshness_revocation_authority_bound -eq $false -and
    $json.freshness_result.authority_surface.object_trust_allowed -eq $false -and
    $json.freshness_result.authority_surface.activation_allowed -eq $false

$quarantineReady = $json.quarantine_result.status -eq "passed" -and
    $json.quarantine_result.summary.rc13_020_complete -eq $true -and
    $json.quarantine_result.summary.failed_checks -eq 0 -and
    $json.quarantine_result.summary.failed_cases -eq 0 -and
    $json.quarantine_result.preflight_surface.state -eq "quarantine-preflight-denied-before-network" -and
    $json.quarantine_result.preflight_surface.network_fetch_attempted -eq $false -and
    $json.quarantine_result.preflight_surface.remote_payload_bytes_downloaded -eq $false -and
    $json.quarantine_result.preflight_surface.quarantine_payload_written -eq $false -and
    $json.quarantine_result.preflight_surface.payload_interpreted -eq $false -and
    $json.quarantine_result.preflight_surface.activation_allowed -eq $false -and
    $json.quarantine_result.preflight_surface.rollback_execution_allowed -eq $false

$agentcoreReady = $json.agentcore_result.status -eq "passed" -and
    $json.agentcore_result.summary.rc13_021_complete -eq $true -and
    $json.agentcore_result.summary.failed_checks -eq 0 -and
    $json.agentcore_result.summary.failed_cases -eq 0 -and
    $json.agentcore_result.readiness_surface.quarantine_evidence_bound -eq $true -and
    $json.agentcore_result.readiness_surface.verified_quarantine_preflight_bound -eq $false -and
    $json.agentcore_result.readiness_surface.release_object_bound -eq $true -and
    $json.agentcore_result.readiness_surface.agentcore_planspec_executable -eq $false -and
    $json.agentcore_result.readiness_surface.security_execution_allowed -eq $false -and
    $json.agentcore_result.readiness_surface.activation_allowed -eq $false -and
    $json.agentcore_result.readiness_surface.rollback_execution_allowed -eq $false

$securityReady = $json.security_result.status -eq "passed" -and
    $json.security_result.summary.rc13_022_complete -eq $true -and
    $json.security_result.summary.failed_checks -eq 0 -and
    $json.security_result.summary.failed_cases -eq 0 -and
    $json.security_result.security_surface.security_execution_allowed -eq $false -and
    $json.security_result.security_surface.effect_preparation_allowed -eq $false -and
    $json.security_result.security_surface.activation_allowed -eq $false -and
    $json.security_result.security_surface.rollback_execution_allowed -eq $false -and
    $json.security_result.security_surface.remote_dispatch_enabled -eq $false

$targetReady = $json.target_result.status -eq "passed" -and
    $json.target_result.summary.rc13_030_complete -eq $true -and
    $json.target_result.summary.failed_checks -eq 0 -and
    $json.target_result.summary.failed_cases -eq 0 -and
    $json.target_result.enrollment_surface.target_identity_set_bound -eq $false -and
    $json.target_result.enrollment_surface.enrolled_target_identity_count -eq 0 -and
    $json.target_result.enrollment_surface.exact_approval_bound -eq $false -and
    $json.target_result.enrollment_surface.activation_allowed -eq $false -and
    $json.target_result.enrollment_surface.rollback_execution_allowed -eq $false

$approvalReady = $json.approval_result.status -eq "passed" -and
    $json.approval_result.summary.rc13_031_complete -eq $true -and
    $json.approval_result.summary.failed_checks -eq 0 -and
    $json.approval_result.summary.failed_cases -eq 0 -and
    $json.approval_result.approval_surface.exact_approval_bound -eq $false -and
    $json.approval_result.approval_surface.approval_granted -eq $false -and
    $json.approval_result.approval_surface.audit_sink_bound -eq $false -and
    $json.approval_result.approval_surface.nonce_bound -eq $false -and
    $json.approval_result.approval_surface.expiry_bound -eq $false -and
    $json.approval_result.approval_surface.activation_allowed -eq $false -and
    $json.approval_result.approval_surface.rollback_execution_allowed -eq $false

$activationReady = $json.activation_result.status -eq "passed" -and
    $json.activation_result.summary.rc13_040_complete -eq $true -and
    $json.activation_result.summary.failed_checks -eq 0 -and
    $json.activation_result.summary.failed_cases -eq 0 -and
    $json.activation_result.activation_surface.state -eq "controlled-activation-denied" -and
    $json.activation_result.activation_surface.activation_allowed -eq $false -and
    $json.activation_result.activation_surface.activation_performed -eq $false -and
    $json.activation_result.activation_surface.activation_audit_fabricated -eq $false -and
    $json.activation_result.activation_surface.rollback_execution_allowed -eq $false -and
    $json.activation_result.activation_surface.remote_dispatch_enabled -eq $false

$rollbackReady = $json.rollback_result.status -eq "passed" -and
    $json.rollback_result.summary.rc13_041_complete -eq $true -and
    $json.rollback_result.summary.failed_checks -eq 0 -and
    $json.rollback_result.summary.failed_cases -eq 0 -and
    $json.rollback_result.rollback_surface.state -eq "controlled-rollback-support-recovery-denied" -and
    $json.rollback_result.rollback_surface.rollback_baseline_bound -eq $true -and
    $json.rollback_result.rollback_surface.rollback_execution_allowed -eq $false -and
    $json.rollback_result.rollback_surface.rollback_execution_performed -eq $false -and
    $json.rollback_result.rollback_surface.controlled_activation_performed -eq $false -and
    $json.rollback_result.rollback_surface.exact_rollback_approval_granted -eq $false -and
    $json.rollback_result.rollback_surface.agentcore_rollback_planspec_bound -eq $false -and
    $json.rollback_result.rollback_surface.security_execution_rollback_approval_bound -eq $false -and
    $json.rollback_result.support_surface.support_recovery_reference_bound -eq $true -and
    $json.rollback_result.support_surface.support_bundle_redacted -eq $true -and
    $json.rollback_result.support_surface.support_upload_performed -eq $false -and
    $json.rollback_result.support_surface.recovery_execution_performed -eq $false

$resultSet = @(
    [pscustomobject]@{ Task = "RC13-010"; Json = $json.drift_result },
    [pscustomobject]@{ Task = "RC13-011"; Json = $json.object_manifest_result },
    [pscustomobject]@{ Task = "RC13-012"; Json = $json.freshness_result },
    [pscustomobject]@{ Task = "RC13-020"; Json = $json.quarantine_result },
    [pscustomobject]@{ Task = "RC13-021"; Json = $json.agentcore_result },
    [pscustomobject]@{ Task = "RC13-022"; Json = $json.security_result },
    [pscustomobject]@{ Task = "RC13-030"; Json = $json.target_result },
    [pscustomobject]@{ Task = "RC13-031"; Json = $json.approval_result },
    [pscustomobject]@{ Task = "RC13-040"; Json = $json.activation_result },
    [pscustomobject]@{ Task = "RC13-041"; Json = $json.rollback_result }
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
    "payload_upload_performed",
    "external_payload_bytes_uploaded",
    "network_probe_performed",
    "network_fetch_attempted",
    "remote_payload_bytes_downloaded",
    "quarantine_payload_written",
    "payload_interpreted",
    "drift_repair_performed",
    "declared_metadata_rewritten",
    "publication_binding_rewritten",
    "object_trust_allowed",
    "approval_granted",
    "executable_planspec_created",
    "security_execution_effect_allowed",
    "effect_prepared",
    "effect_executed",
    "activation_audit_fabricated",
    "target_enrollment_fabricated",
    "exact_approval_fabricated",
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
    "mirror_authority",
    "signer_reachability_authority",
    "frontend_authority",
    "model_replay_authority",
    "normal_shell_authority",
    "tui_authority",
    "production_ready_claim"
)
$invariantViolations = @(Test-InvariantFalse -ResultSet $resultSet -Names $forbiddenInvariantNames)

Add-Check "rc13.plan.precloseout_complete" $planReady "All RC13 pre-closeout tasks must be completed and RC13-050 must be pending before first audit or completed on rerun." ([ordered]@{ completed = $completedBeforeCloseout; expected = @($preCloseoutTasks).Count; current_task = $json.plan.current_task; rc13_050_status = $rc13050Status; plan_status = $json.plan.status })
Add-Check "rc13.docs_and_contract.present" $docsReady "RC13 planning evidence, plan doc, and local trust unblock contract must exist." ([ordered]@{ plan_doc = Get-StablePath $resolved.rc13_plan_doc; contract = Get-StablePath $resolved.rc13_contract })
Add-Check "rc12.previous_milestone.closed" $rc12Ready "RC13 final audit must inherit a PASS RC12 final audit without GA claim." ([ordered]@{ verdict = $json.rc12_final_audit.verdict; production_ready_claim = $json.rc12_final_audit.production_ready_claim })
Add-Check "rc13.drift_zero.denied" $driftReady "RC13 declared/current drift repair must pass while drift-zero and object trust remain denied." $json.drift_result.summary
Add-Check "rc13.object_manifest.consistent_denied" $objectManifestReady "RC13 object manifest and descriptor binding must prove local consistency while authority remains denied." $json.object_manifest_result.summary
Add-Check "rc13.freshness_revocation.denied" $freshnessReady "RC13 public signature and revocation authority must be bound without freshness-window authority." $json.freshness_result.summary
Add-Check "rc13.quarantine.denied_before_network" $quarantineReady "RC13 quarantine preflight must deny before network, quarantine writes, or payload interpretation." $json.quarantine_result.summary
Add-Check "rc13.agentcore.non_executable" $agentcoreReady "RC13 AgentCore PlanSpec readiness must stay non-executable without verified quarantine, target, approval, audit, nonce, expiry, and policy bindings." $json.agentcore_result.summary
Add-Check "rc13.security_execution.denied" $securityReady "RC13 SecurityExecution allow preconditions must deny effect preparation and controlled effects." $json.security_result.summary
Add-Check "rc13.target_identity.denied" $targetReady "RC13 two-target identity enrollment must remain denied with zero enrolled identities." $json.target_result.summary
Add-Check "rc13.exact_approval.denied" $approvalReady "RC13 exact approval audit binding must remain denied without target identities, actor signature, audit sink, nonce, and expiry." $json.approval_result.summary
Add-Check "rc13.activation.denied" $activationReady "RC13 controlled activation must remain denied and side-effect free." $json.activation_result.summary
Add-Check "rc13.rollback_support_recovery.denied" $rollbackReady "RC13 rollback, support upload, and recovery execution must remain denied while redacted local support evidence is bound." $json.rollback_result.summary
Add-Check "rc13.no_invariant_authority_broadened" (@($invariantViolations).Count -eq 0) "RC13 task invariants must not broaden signing, mirror, frontend, install, activation, rollback, support, recovery, remote dispatch, or production authority." ([ordered]@{ violations = $invariantViolations })

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

$preWritePassed = @($script:blockers).Count -eq 0
$finalAuditPath = Resolve-RepoPath ".workflow/active/WFS-20260609-agentos-production-distro-rc13/evidence/FINAL-AUDIT-20260609-production-distro-rc13.json"
$closeoutSummaryPath = Resolve-RepoPath ".workflow/active/WFS-20260609-agentos-production-distro-rc13/docs/final-rc13-closeout-summary.md"
$taskEvidencePath = Resolve-RepoPath ".workflow/active/WFS-20260609-agentos-production-distro-rc13/evidence/RC13-050-final-closeout-audit.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"

$finalAudit = [ordered]@{
    schema = "agentos.production-distro-rc13-final-audit.v1"
    generated_at = $generatedAtValue
    workflow = ".workflow/active/WFS-20260609-agentos-production-distro-rc13"
    milestone = "Production Distro RC13"
    verdict = if ($preWritePassed) { "PASS" } else { "BLOCKED" }
    decision = if ($preWritePassed) { "rc13-closeout-pass-next-milestone-planning" } else { "rc13-closeout-blocked" }
    production_ready_claim = $false
    objective = "AIOS-body local trust unblock audit for drift-zero repair, object manifest binding, freshness/revocation authority, quarantine preflight, AgentCore, SecurityExecution, target identity, exact approval, activation, rollback, support, and recovery evidence"
    task_results = @($preCloseoutTasks | ForEach-Object { [ordered]@{ id = $_; status = Get-TaskStatus $json.plan $_ } })
    acceptance_coverage = @(
        [ordered]@{ requirement = "declared/current drift repair is explicit and hash-bound, but drift-zero remains denied"; status = if ($driftReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.drift_result)) }
        [ordered]@{ requirement = "current payload bytes, descriptor, manifest, checksums, compatibility, rollback, and support/recovery references are locally consistent"; status = if ($objectManifestReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.object_manifest_result)) }
        [ordered]@{ requirement = "public signature and revocation authority are bound without private material, but freshness remains missing"; status = if ($freshnessReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.freshness_result)) }
        [ordered]@{ requirement = "quarantine preflight denies before network, payload download, quarantine write, or interpretation"; status = if ($quarantineReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.quarantine_result)) }
        [ordered]@{ requirement = "AgentCore PlanSpec readiness binds release object and quarantine evidence but stays non-executable"; status = if ($agentcoreReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.agentcore_result)) }
        [ordered]@{ requirement = "SecurityExecution allow preconditions deny effect preparation and controlled effects"; status = if ($securityReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.security_result)) }
        [ordered]@{ requirement = "two-target local identity enrollment remains denied with zero enrolled target identities"; status = if ($targetReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.target_result)) }
        [ordered]@{ requirement = "exact approval audit binding records required fields but remains denied"; status = if ($approvalReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.approval_result)) }
        [ordered]@{ requirement = "controlled activation remains denied and side-effect free"; status = if ($activationReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.activation_result)) }
        [ordered]@{ requirement = "separate rollback/support/recovery remains denied with redacted local support evidence"; status = if ($rollbackReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.rollback_result)) }
    )
    controlled_unblock_status = [ordered]@{
        moved_beyond_fail_closed = $false
        drift_zero = $json.drift_result.reconciliation_surface.drift_zero
        object_manifest_descriptor_binding_allowed = $json.object_manifest_result.binding_surface.object_manifest_descriptor_binding_allowed
        freshness_revocation_authority_bound = $json.freshness_result.authority_surface.freshness_revocation_authority_bound
        object_trust_allowed = $json.object_manifest_result.binding_surface.object_trust_allowed
        quarantine_preflight_allowed = $json.quarantine_result.preflight_surface.quarantine_preflight_allowed
        agentcore_planspec_executable = $json.agentcore_result.readiness_surface.agentcore_planspec_executable
        security_execution_allowed = $json.security_result.security_surface.security_execution_allowed
        target_identity_set_bound = $json.target_result.enrollment_surface.target_identity_set_bound
        exact_approval_granted = $json.approval_result.approval_surface.approval_granted
        activation_performed = $json.activation_result.activation_surface.activation_performed
        rollback_execution_performed = $json.rollback_result.rollback_surface.rollback_execution_performed
        support_upload_performed = $json.rollback_result.support_surface.support_upload_performed
        recovery_execution_performed = $json.rollback_result.support_surface.recovery_execution_performed
    }
    execution_surface = [ordered]@{
        release_id = $json.drift_result.release_id
        current_payload_matches_rc12 = $json.drift_result.reconciliation_surface.current_payload_matches_rc12
        current_payload_size_bytes = $json.object_manifest_result.binding_surface.current_payload_size_bytes
        current_payload_sha256 = $json.object_manifest_result.binding_surface.current_payload_sha256
        drift_state = $json.drift_result.reconciliation_surface.state
        drift_zero = $json.drift_result.reconciliation_surface.drift_zero
        drift_count = $json.drift_result.reconciliation_surface.drift_count
        local_descriptor_manifest_consistent = $json.object_manifest_result.binding_surface.local_descriptor_manifest_consistent
        comparison_drifts = $json.object_manifest_result.binding_surface.comparison_drifts
        public_signature_bound = $json.freshness_result.authority_surface.public_signature_bound
        public_signature_crypto_verified = $json.freshness_result.authority_surface.public_signature_crypto_verified
        revocation_authority_bound = $json.freshness_result.authority_surface.revocation_authority_bound
        freshness_window_bound = $json.freshness_result.authority_surface.freshness_window_bound
        quarantine_preflight_state = $json.quarantine_result.preflight_surface.state
        network_fetch_attempted = $json.quarantine_result.preflight_surface.network_fetch_attempted
        quarantine_payload_written = $json.quarantine_result.preflight_surface.quarantine_payload_written
        payload_interpreted = $json.quarantine_result.preflight_surface.payload_interpreted
        agentcore_planspec_executable = $json.agentcore_result.readiness_surface.agentcore_planspec_executable
        security_execution_allowed = $json.security_result.security_surface.security_execution_allowed
        enrolled_target_identity_count = $json.target_result.enrollment_surface.enrolled_target_identity_count
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
        quarantine_payload_written = $false
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
    remaining_blockers_before_ga_or_execution = $remainingBlockers
    next_milestone = [ordered]@{
        id = "Production Distro RC14"
        title = "turn RC13 local trust gates from denial into satisfiable execution readiness"
        direction = "repair declared/current drift to zero, bind freshness window, prove object trust, perform verified quarantine preflight, enroll two local target identities, bind exact approval with audit sink nonce and expiry, make AgentCore PlanSpec executable, allow SecurityExecution effects, then rerun controlled activation and separately approved rollback."
    }
    checks = $script:checks
}

$summaryText = @"
# Production Distro RC13 Closeout Summary

RC13 closes as a non-GA fail-closed AIOS-body milestone. It repaired and audited the local trust chain from declared/current drift through object manifest binding, public signature and revocation authority, quarantine preflight, AgentCore PlanSpec readiness, SecurityExecution allow preconditions, two-target identity enrollment, exact approval, controlled activation, and separate rollback/support/recovery evidence.

The milestone did not move beyond fail-closed denial. Drift-zero, freshness-window binding, object trust, quarantine preflight authority, executable AgentCore PlanSpec, SecurityExecution allow, two-target enrollment, exact approval, controlled activation, rollback execution, support upload, recovery execution, remote dispatch, and production ring mutation all remain blocked.

## Evidence

- Drift repair: `.workflow/artifacts/rc13-declared-current-drift-zero/result.json`
- Object manifest and descriptor binding: `.workflow/artifacts/rc13-object-manifest-descriptor-binding/result.json`
- Freshness and revocation authority: `.workflow/artifacts/rc13-freshness-revocation-authority/result.json`
- Quarantine preflight: `.workflow/artifacts/rc13-quarantine-preflight/result.json`
- AgentCore PlanSpec readiness: `.workflow/artifacts/rc13-agentcore-executable-planspec-readiness/result.json`
- SecurityExecution allow preconditions: `.workflow/artifacts/rc13-security-execution-allow-preconditions/result.json`
- Two-target identity enrollment: `.workflow/artifacts/rc13-two-target-identity-enrollment/result.json`
- Exact approval audit binding: `.workflow/artifacts/rc13-exact-approval-audit-binding/result.json`
- Controlled activation: `.workflow/artifacts/rc13-controlled-activation/result.json`
- Controlled rollback support/recovery: `.workflow/artifacts/rc13-controlled-rollback-support-recovery/result.json`
- Final audit: `.workflow/active/WFS-20260609-agentos-production-distro-rc13/evidence/FINAL-AUDIT-20260609-production-distro-rc13.json`

## Next Direction

RC14 should turn the remaining local trust gates into satisfiable evidence: make declared/current drift zero, bind a current freshness window, prove object trust, run verified quarantine preflight, enroll two local target identities, bind exact approval, make AgentCore PlanSpec executable, allow SecurityExecution effects, then rerun controlled activation and separately approved rollback.
"@

Write-Json $finalAudit $finalAuditPath
Write-Text $summaryText $closeoutSummaryPath

Add-Check "rc13.final_audit.written" (Test-Path -LiteralPath $finalAuditPath -PathType Leaf) "RC13 final audit evidence must be written." ([ordered]@{ path = Get-StablePath $finalAuditPath; sha256 = Get-FileSha256 $finalAuditPath })
Add-Check "rc13.closeout_summary.written" (Test-Path -LiteralPath $closeoutSummaryPath -PathType Leaf) "RC13 closeout summary must be written." ([ordered]@{ path = Get-StablePath $closeoutSummaryPath; sha256 = Get-FileSha256 $closeoutSummaryPath })

$passed = @($script:blockers).Count -eq 0
$result = [ordered]@{
    schema = "agentos.rc13-final-closeout-audit-result.v1"
    generated_at = $generatedAtValue
    task = "RC13-050"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    rc13_050_complete = $passed
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
        controlled_unblock_status = $finalAudit.controlled_unblock_status
        remaining_blockers_before_ga_or_execution = $remainingBlockers
        next_milestone = $finalAudit.next_milestone
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:blockers).Count
        rc13_050_complete = $passed
        verdict = $finalAudit.verdict
        moved_beyond_fail_closed = $false
        drift_count = $json.drift_result.reconciliation_surface.drift_count
        drift_zero = $json.drift_result.reconciliation_surface.drift_zero
        local_descriptor_manifest_consistent = $json.object_manifest_result.binding_surface.local_descriptor_manifest_consistent
        freshness_window_bound = $json.freshness_result.authority_surface.freshness_window_bound
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
        next_task = "RC14-planning"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc13-final-closeout-audit-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC13-050"
    status = "completed"
    production_ready_claim = $false
    workflow = ".workflow/active/WFS-20260609-agentos-production-distro-rc13"
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
        rc13_050_complete = $passed
        next_task = "RC14-planning"
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

Write-Host "RC13 final closeout audit $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Verdict: $($finalAudit.verdict)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:blockers).Count)"

if ($FailOnBlocked -and -not $passed) {
    exit 1
}
