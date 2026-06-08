param(
    [string]$ArtifactDir = ".workflow/artifacts/rc12-final-closeout-audit",
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
        ("Authorization:" + " Bearer"),
        ("Bearer" + " "),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ("." + "local-release-authority"),
        ("signing" + "-" + "key" + "." + "pem"),
        ("/etc/" + "aios-signer")
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

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:blockers = @()
$generatedAt = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }

$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$expectedArtifactDir = Resolve-RepoPath ".workflow/artifacts/rc12-final-closeout-audit"
if (-not $resolvedArtifactDir.Equals($expectedArtifactDir, [StringComparison]::OrdinalIgnoreCase)) {
    throw "ArtifactDir must be .workflow/artifacts/rc12-final-closeout-audit"
}
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null

$paths = [ordered]@{
    plan = ".workflow/active/WFS-20260609-agentos-production-distro-rc12/plan.json"
    workflow_session = ".workflow/active/WFS-20260609-agentos-production-distro-rc12/workflow-session.json"
    rc11_final_audit = ".workflow/active/WFS-20260609-agentos-production-distro-rc11/evidence/FINAL-AUDIT-20260609-production-distro-rc11.json"
    rc12_plan_doc = ".workflow/active/WFS-20260609-agentos-production-distro-rc12/docs/rc12-real-object-controlled-unblock-plan.md"
    rc12_contract = ".workflow/active/WFS-20260609-agentos-production-distro-rc12/docs/rc12-real-object-controlled-unblock-contract.md"
    planning_evidence = ".workflow/active/WFS-20260609-agentos-production-distro-rc12/evidence/RC12-000-planning.json"
    contract_evidence = ".workflow/active/WFS-20260609-agentos-production-distro-rc12/evidence/RC12-001-real-object-controlled-unblock-contract.json"
    publication_result = ".workflow/artifacts/rc12-external-object-publication-binding/result.json"
    drift_result = ".workflow/artifacts/rc12-declared-current-drift-zero/result.json"
    object_trust_result = ".workflow/artifacts/rc12-object-trust-verification/result.json"
    quarantine_result = ".workflow/artifacts/rc12-quarantine-fetch-verification/result.json"
    execution_package_result = ".workflow/artifacts/rc12-agentcore-security-execution-package/result.json"
    approval_result = ".workflow/artifacts/rc12-canary-target-approval-binding/result.json"
    activation_result = ".workflow/artifacts/rc12-controlled-canary-activation/result.json"
    rollback_result = ".workflow/artifacts/rc12-controlled-rollback-drill/result.json"
}

$resolved = [ordered]@{}
$json = [ordered]@{}
foreach ($key in $paths.Keys) {
    $resolved[$key] = Resolve-RepoPath $paths[$key]
    $json[$key] = if ([IO.Path]::GetExtension($paths[$key]) -eq ".json") { Read-Json $resolved[$key] } else { $null }
}

$preCloseoutTasks = @("RC12-000", "RC12-001", "RC12-010", "RC12-011", "RC12-012", "RC12-020", "RC12-021", "RC12-030", "RC12-040", "RC12-041")
$completedBeforeCloseout = 0
foreach ($taskId in $preCloseoutTasks) {
    if ((Get-TaskStatus $json.plan $taskId) -eq "completed") {
        $completedBeforeCloseout++
    }
}

$rc12050Status = Get-TaskStatus $json.plan "RC12-050"
$preCloseoutPlanState = $json.plan.current_task -eq "RC12-050" -and $rc12050Status -eq "pending"
$postCloseoutPlanState = $json.plan.status -eq "completed" -and $null -eq $json.plan.current_task -and $rc12050Status -eq "completed"
$planReady = ($preCloseoutPlanState -or $postCloseoutPlanState) -and $completedBeforeCloseout -eq @($preCloseoutTasks).Count

$docsReady = (Test-Path -LiteralPath $resolved.rc12_plan_doc -PathType Leaf) -and
    (Test-Path -LiteralPath $resolved.rc12_contract -PathType Leaf) -and
    $json.planning_evidence.status -eq "completed" -and
    $json.contract_evidence.status -eq "completed"

$rc11Ready = $json.rc11_final_audit.verdict -eq "PASS" -and $json.rc11_final_audit.production_ready_claim -eq $false

$publicationReady = $json.publication_result.status -eq "passed" -and
    $json.publication_result.summary.rc12_010_complete -eq $true -and
    $json.publication_result.summary.failed_checks -eq 0 -and
    $json.publication_result.publication_surface.state -eq "external-object-publication-denied" -and
    $json.publication_result.publication_surface.publication_allowed -eq $false -and
    $json.publication_result.publication_surface.external_object_uri_published -eq $false -and
    $json.publication_result.publication_surface.object_trust_allowed -eq $false -and
    $json.publication_result.publication_surface.install_allowed -eq $false -and
    $json.publication_result.publication_surface.activation_allowed -eq $false -and
    $json.publication_result.publication_surface.rollback_execution_allowed -eq $false

$driftReady = $json.drift_result.status -eq "passed" -and
    $json.drift_result.summary.rc12_011_complete -eq $true -and
    $json.drift_result.summary.failed_checks -eq 0 -and
    $json.drift_result.reconciliation_surface.state -eq "declared-current-drift-denied" -and
    $json.drift_result.reconciliation_surface.drift_zero -eq $false -and
    $json.drift_result.reconciliation_surface.drift_count -eq 17 -and
    $json.drift_result.reconciliation_surface.object_trust_allowed -eq $false -and
    $json.drift_result.reconciliation_surface.install_allowed -eq $false -and
    $json.drift_result.reconciliation_surface.activation_allowed -eq $false -and
    $json.drift_result.reconciliation_surface.rollback_execution_allowed -eq $false

$objectTrustReady = $json.object_trust_result.status -eq "passed" -and
    $json.object_trust_result.summary.rc12_012_complete -eq $true -and
    $json.object_trust_result.summary.failed_checks -eq 0 -and
    $json.object_trust_result.summary.failed_fail_closed_cases -eq 0 -and
    $json.object_trust_result.verification_surface.state -eq "object-trust-denied" -and
    $json.object_trust_result.verification_surface.object_trust_allowed -eq $false -and
    $json.object_trust_result.verification_surface.endpoint_reachability_is_trust -eq $false -and
    $json.object_trust_result.verification_surface.network_probe_performed -eq $false -and
    $json.object_trust_result.verification_surface.quarantine_fetch_allowed -eq $false -and
    $json.object_trust_result.verification_surface.install_allowed -eq $false -and
    $json.object_trust_result.verification_surface.activation_allowed -eq $false -and
    $json.object_trust_result.verification_surface.rollback_execution_allowed -eq $false

$quarantineReady = $json.quarantine_result.status -eq "passed" -and
    $json.quarantine_result.summary.rc12_020_complete -eq $true -and
    $json.quarantine_result.summary.failed_checks -eq 0 -and
    $json.quarantine_result.summary.failed_cases -eq 0 -and
    $json.quarantine_result.fetch_surface.state -eq "quarantine-fetch-denied-before-network" -and
    $json.quarantine_result.fetch_surface.quarantine_fetch_allowed -eq $false -and
    $json.quarantine_result.fetch_surface.network_fetch_attempted -eq $false -and
    $json.quarantine_result.fetch_surface.remote_payload_bytes_downloaded -eq $false -and
    $json.quarantine_result.fetch_surface.quarantine_payload_written -eq $false -and
    $json.quarantine_result.fetch_surface.payload_interpreted -eq $false -and
    $json.quarantine_result.fetch_surface.install_allowed -eq $false -and
    $json.quarantine_result.fetch_surface.activation_allowed -eq $false -and
    $json.quarantine_result.fetch_surface.rollback_execution_allowed -eq $false

$executionPackageReady = $json.execution_package_result.status -eq "passed" -and
    $json.execution_package_result.summary.rc12_021_complete -eq $true -and
    $json.execution_package_result.summary.failed_checks -eq 0 -and
    $json.execution_package_result.summary.failed_cases -eq 0 -and
    $json.execution_package_result.package_surface.state -eq "agentcore-security-execution-package-denied" -and
    $json.execution_package_result.package_surface.quarantine_evidence_bound -eq $true -and
    $json.execution_package_result.package_surface.installer_preflight_verified -eq $false -and
    $json.execution_package_result.package_surface.agentcore_planspec_candidate_projected -eq $true -and
    $json.execution_package_result.package_surface.agentcore_planspec_executable -eq $false -and
    $json.execution_package_result.package_surface.security_execution_allowed -eq $false -and
    $json.execution_package_result.package_surface.install_allowed -eq $false -and
    $json.execution_package_result.package_surface.activation_allowed -eq $false -and
    $json.execution_package_result.package_surface.rollback_execution_allowed -eq $false

$approvalReady = $json.approval_result.status -eq "passed" -and
    $json.approval_result.summary.rc12_030_complete -eq $true -and
    $json.approval_result.summary.failed_checks -eq 0 -and
    $json.approval_result.summary.failed_cases -eq 0 -and
    $json.approval_result.approval_surface.state -eq "target-identity-and-exact-approval-denied" -and
    $json.approval_result.approval_surface.required_minimum_target_identities -eq 2 -and
    $json.approval_result.approval_surface.enrolled_target_identity_count -eq 0 -and
    $json.approval_result.approval_surface.target_set_enrolled -eq $false -and
    $json.approval_result.approval_surface.exact_approval_bound -eq $false -and
    $json.approval_result.approval_surface.approval_granted -eq $false -and
    $json.approval_result.approval_surface.audit_sink_bound -eq $false -and
    $json.approval_result.approval_surface.nonce_bound -eq $false -and
    $json.approval_result.approval_surface.expiry_bound -eq $false -and
    $json.approval_result.approval_surface.activation_allowed -eq $false -and
    $json.approval_result.approval_surface.rollback_execution_allowed -eq $false

$activationReady = $json.activation_result.status -eq "passed" -and
    $json.activation_result.summary.rc12_040_complete -eq $true -and
    $json.activation_result.summary.failed_checks -eq 0 -and
    $json.activation_result.summary.failed_cases -eq 0 -and
    $json.activation_result.activation_surface.state -eq "activation-denied" -and
    $json.activation_result.activation_surface.activation_allowed -eq $false -and
    $json.activation_result.activation_surface.activation_performed -eq $false -and
    $json.activation_result.activation_surface.activation_audit_recorded -eq $false -and
    $json.activation_result.activation_surface.controlled_execution_authorized -eq $false -and
    $json.activation_result.activation_surface.agentcore_planspec_executable -eq $false -and
    $json.activation_result.activation_surface.security_execution_allowed -eq $false -and
    $json.activation_result.activation_surface.rollback_execution_allowed -eq $false -and
    $json.activation_result.activation_surface.remote_dispatch_enabled -eq $false

$rollbackReady = $json.rollback_result.status -eq "passed" -and
    $json.rollback_result.summary.rc12_041_complete -eq $true -and
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
    $json.rollback_result.rollback_surface.remote_dispatch_enabled -eq $false -and
    $json.rollback_result.support_surface.support_recovery_binding_present -eq $true -and
    $json.rollback_result.support_surface.support_bundle_redacted -eq $true -and
    $json.rollback_result.support_surface.support_upload_allowed -eq $false -and
    $json.rollback_result.support_surface.support_upload_performed -eq $false -and
    $json.rollback_result.support_surface.recovery_execution_allowed -eq $false -and
    $json.rollback_result.support_surface.recovery_execution_performed -eq $false

$resultSet = @(
    [pscustomobject]@{ Task = "RC12-010"; Json = $json.publication_result },
    [pscustomobject]@{ Task = "RC12-011"; Json = $json.drift_result },
    [pscustomobject]@{ Task = "RC12-012"; Json = $json.object_trust_result },
    [pscustomobject]@{ Task = "RC12-020"; Json = $json.quarantine_result },
    [pscustomobject]@{ Task = "RC12-021"; Json = $json.execution_package_result },
    [pscustomobject]@{ Task = "RC12-030"; Json = $json.approval_result },
    [pscustomobject]@{ Task = "RC12-040"; Json = $json.activation_result },
    [pscustomobject]@{ Task = "RC12-041"; Json = $json.rollback_result }
)

$forbiddenInvariantNames = @(
    "mirror_frontend_changed",
    "nginx_or_tls_changed",
    "signer_infra_changed",
    "object_storage_infra_changed",
    "local_private_key_material_used",
    "private_key_material_read_or_printed",
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
    "activation_audit_fabricated",
    "target_enrollment_fabricated",
    "exact_approval_fabricated",
    "install_performed",
    "activation_performed",
    "rollback_execution_performed",
    "canary_execution_performed",
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

Add-Check "rc12.plan.precloseout_complete" $planReady "All RC12 pre-closeout tasks must be completed and RC12-050 must be pending before first audit or completed on rerun." ([ordered]@{ completed = $completedBeforeCloseout; expected = @($preCloseoutTasks).Count; current_task = $json.plan.current_task; rc12_050_status = $rc12050Status; plan_status = $json.plan.status })
Add-Check "rc12.docs_and_contract.present" $docsReady "RC12 planning evidence, plan doc, and real-object controlled unblock contract must exist." ([ordered]@{ plan_doc = Get-StablePath $resolved.rc12_plan_doc; contract = Get-StablePath $resolved.rc12_contract })
Add-Check "rc11.previous_milestone.closed" $rc11Ready "RC12 final audit must inherit a PASS RC11 final audit without GA claim." ([ordered]@{ verdict = $json.rc11_final_audit.verdict; production_ready_claim = $json.rc11_final_audit.production_ready_claim })
Add-Check "rc12.publication.binding_denied" $publicationReady "RC12 external object publication binding must pass while publication, object trust, install, activation, and rollback remain blocked." $json.publication_result.summary
Add-Check "rc12.declared_current_drift.denied" $driftReady "RC12 declared/current drift reconciliation must deny object trust while drift_count is nonzero." $json.drift_result.summary
Add-Check "rc12.object_trust.denied" $objectTrustReady "RC12 object trust verification must deny trust and not use endpoint reachability as authority." $json.object_trust_result.summary
Add-Check "rc12.quarantine_fetch.denied_before_network" $quarantineReady "RC12 quarantine fetch must deny before network, quarantine writes, or payload interpretation." $json.quarantine_result.summary
Add-Check "rc12.agentcore_security_package.denied" $executionPackageReady "RC12 AgentCore/SecurityExecution package must stay non-executable and deny install, activation, and rollback effects." $json.execution_package_result.summary
Add-Check "rc12.canary_exact_approval.denied" $approvalReady "RC12 canary target and exact approval package must deny activation with missing target identities and approval bindings." $json.approval_result.summary
Add-Check "rc12.activation.denied" $activationReady "RC12 controlled canary activation must remain denied and side-effect free." $json.activation_result.summary
Add-Check "rc12.rollback_support_recovery.denied" $rollbackReady "RC12 rollback, support upload, and recovery execution must remain denied while local redacted support evidence is bound." $json.rollback_result.summary
Add-Check "rc12.no_invariant_authority_broadened" (@($invariantViolations).Count -eq 0) "RC12 task invariants must not broaden signing, mirror, frontend, install, activation, rollback, support, recovery, remote dispatch, or production authority." ([ordered]@{ violations = $invariantViolations })

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
$finalAuditPath = Resolve-RepoPath ".workflow/active/WFS-20260609-agentos-production-distro-rc12/evidence/FINAL-AUDIT-20260609-production-distro-rc12.json"
$closeoutSummaryPath = Resolve-RepoPath ".workflow/active/WFS-20260609-agentos-production-distro-rc12/docs/final-rc12-closeout-summary.md"
$taskEvidencePath = Resolve-RepoPath ".workflow/active/WFS-20260609-agentos-production-distro-rc12/evidence/RC12-050-final-closeout-audit.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"

$finalAudit = [ordered]@{
    schema = "agentos.production-distro-rc12-final-audit.v1"
    generated_at = $generatedAt
    workflow = ".workflow/active/WFS-20260609-agentos-production-distro-rc12"
    milestone = "Production Distro RC12"
    verdict = if ($preWritePassed) { "PASS" } else { "BLOCKED" }
    decision = if ($preWritePassed) { "rc12-closeout-pass-next-milestone-planning" } else { "rc12-closeout-blocked" }
    production_ready_claim = $false
    objective = "AIOS-body real-object controlled unblock audit with fail-closed object trust, quarantine, AgentCore, SecurityExecution, approval, activation, rollback, support, and recovery evidence"
    task_results = @($preCloseoutTasks | ForEach-Object { [ordered]@{ id = $_; status = Get-TaskStatus $json.plan $_ } })
    acceptance_coverage = @(
        [ordered]@{ requirement = "real object publication binding is hash-bound but denied without external HTTPS object URI, freshness, and drift-zero"; status = if ($publicationReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.publication_result)) }
        [ordered]@{ requirement = "declared/current drift-zero remains a blocker until drift_count is zero"; status = if ($driftReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.drift_result)) }
        [ordered]@{ requirement = "object trust verification denies trust and treats endpoint reachability as non-authoritative"; status = if ($objectTrustReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.object_trust_result)) }
        [ordered]@{ requirement = "quarantine fetch denies before network, payload download, quarantine write, or interpretation"; status = if ($quarantineReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.quarantine_result)) }
        [ordered]@{ requirement = "AgentCore PlanSpec and SecurityExecution package stay non-executable without verified preflight and exact approval"; status = if ($executionPackageReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.execution_package_result)) }
        [ordered]@{ requirement = "two-target enrollment and exact approval deny activation with missing target identities, audit sink, nonce, and expiry"; status = if ($approvalReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.approval_result)) }
        [ordered]@{ requirement = "controlled canary activation remains denied and does not fabricate activation audit"; status = if ($activationReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.activation_result)) }
        [ordered]@{ requirement = "separate rollback drill remains denied while support bundle is redacted and local-only"; status = if ($rollbackReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.rollback_result)) }
    )
    controlled_unblock_status = [ordered]@{
        moved_beyond_fail_closed = $false
        object_publication_allowed = $json.publication_result.publication_surface.publication_allowed
        drift_zero = $json.drift_result.reconciliation_surface.drift_zero
        object_trust_allowed = $json.object_trust_result.verification_surface.object_trust_allowed
        quarantine_fetch_allowed = $json.quarantine_result.fetch_surface.quarantine_fetch_allowed
        agentcore_planspec_executable = $json.execution_package_result.package_surface.agentcore_planspec_executable
        security_execution_allowed = $json.execution_package_result.package_surface.security_execution_allowed
        target_set_enrolled = $json.approval_result.approval_surface.target_set_enrolled
        exact_approval_granted = $json.approval_result.approval_surface.approval_granted
        activation_performed = $json.activation_result.activation_surface.activation_performed
        rollback_execution_performed = $json.rollback_result.rollback_surface.rollback_execution_performed
        support_upload_performed = $json.rollback_result.support_surface.support_upload_performed
        recovery_execution_performed = $json.rollback_result.support_surface.recovery_execution_performed
    }
    execution_surface = [ordered]@{
        release_id = $json.publication_result.release_id
        current_payload_size_bytes = $json.publication_result.publication_surface.current_payload_size_bytes
        current_payload_sha256 = $json.publication_result.publication_surface.current_payload_sha256
        external_https_object_uri_published = $json.publication_result.publication_surface.external_object_uri_published
        drift_state = $json.drift_result.reconciliation_surface.state
        drift_zero = $json.drift_result.reconciliation_surface.drift_zero
        drift_count = $json.drift_result.reconciliation_surface.drift_count
        object_trust_state = $json.object_trust_result.verification_surface.state
        object_trust_allowed = $json.object_trust_result.verification_surface.object_trust_allowed
        quarantine_fetch_state = $json.quarantine_result.fetch_surface.state
        network_fetch_attempted = $json.quarantine_result.fetch_surface.network_fetch_attempted
        quarantine_payload_written = $json.quarantine_result.fetch_surface.quarantine_payload_written
        agentcore_planspec_executable = $json.execution_package_result.package_surface.agentcore_planspec_executable
        security_execution_allowed = $json.execution_package_result.package_surface.security_execution_allowed
        required_minimum_target_identities = $json.approval_result.approval_surface.required_minimum_target_identities
        enrolled_target_identity_count = $json.approval_result.approval_surface.enrolled_target_identity_count
        exact_approval_bound = $json.approval_result.approval_surface.exact_approval_bound
        exact_approval_granted = $json.approval_result.approval_surface.approval_granted
        audit_sink_bound = $json.approval_result.approval_surface.audit_sink_bound
        nonce_bound = $json.approval_result.approval_surface.nonce_bound
        expiry_bound = $json.approval_result.approval_surface.expiry_bound
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
        object_storage_infra_changed = $false
        private_key_material_used = $false
        cryptographic_signing_performed = $false
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
        id = "Production Distro RC13"
        title = "convert RC12 fail-closed blockers into satisfiable local AIOS execution gates"
        direction = "publish a real immutable HTTPS object URI, repair declared/current drift to zero, bind freshness and revocation, perform verified quarantine fetch, enroll two target identities, bind exact approval with audit sink nonce and expiry, make AgentCore PlanSpec executable, allow SecurityExecution effects, then rerun controlled activation and separate rollback drills."
    }
    checks = $script:checks
}

$summaryText = @"
# Production Distro RC12 Closeout Summary

RC12 closes as a non-GA fail-closed milestone. It bound the current payload object publication candidate, reconciled declared/current drift, verified object trust gates, projected quarantine fetch, bound AgentCore/SecurityExecution packages, projected target enrollment and exact approval, and ran controlled activation plus separate rollback drill evidence.

The milestone did not move beyond fail-closed denial. Object publication, drift-zero, object trust, quarantine fetch, executable AgentCore PlanSpec, SecurityExecution allow, two-target enrollment, exact approval, controlled activation, rollback execution, support upload, recovery execution, remote dispatch, and production ring mutation all remain blocked.

## Evidence

- Publication binding: `.workflow/artifacts/rc12-external-object-publication-binding/result.json`
- Drift-zero reconciliation: `.workflow/artifacts/rc12-declared-current-drift-zero/result.json`
- Object trust verification: `.workflow/artifacts/rc12-object-trust-verification/result.json`
- Quarantine fetch verification: `.workflow/artifacts/rc12-quarantine-fetch-verification/result.json`
- AgentCore/SecurityExecution package: `.workflow/artifacts/rc12-agentcore-security-execution-package/result.json`
- Canary target and exact approval: `.workflow/artifacts/rc12-canary-target-approval-binding/result.json`
- Controlled canary activation: `.workflow/artifacts/rc12-controlled-canary-activation/result.json`
- Controlled rollback drill: `.workflow/artifacts/rc12-controlled-rollback-drill/result.json`
- Final audit: `.workflow/active/WFS-20260609-agentos-production-distro-rc12/evidence/FINAL-AUDIT-20260609-production-distro-rc12.json`

## Remaining Blockers

- Real immutable HTTPS object URI is not published.
- Declared/current drift is not zero.
- Freshness window is missing.
- Object trust is not allowed.
- Quarantine fetch is denied before network.
- Installer preflight is not verified into executable authority.
- AgentCore PlanSpec is not executable.
- SecurityExecution allow decision is denied.
- Two canary target identities are not enrolled.
- Exact approval lacks actor/audit/nonce/expiry bindings.
- Controlled activation was not performed.
- Separate rollback approval, rollback PlanSpec, rollback SecurityExecution allow, rollback audit journal, and post-rollback observations are missing.

## Next Direction

RC13 should convert the remaining blockers into satisfiable local AIOS gates without using mirror reachability, frontend output, signer reachability, shell output, TUI output, or model replay as authority.
"@

Write-Json $finalAudit $finalAuditPath
Write-Text $summaryText $closeoutSummaryPath

Add-Check "rc12.final_audit.written" (Test-Path -LiteralPath $finalAuditPath -PathType Leaf) "RC12 final audit evidence must be written." ([ordered]@{ path = Get-StablePath $finalAuditPath; sha256 = Get-FileSha256 $finalAuditPath })
Add-Check "rc12.closeout_summary.written" (Test-Path -LiteralPath $closeoutSummaryPath -PathType Leaf) "RC12 closeout summary must be written." ([ordered]@{ path = Get-StablePath $closeoutSummaryPath; sha256 = Get-FileSha256 $closeoutSummaryPath })

$resultStatus = if (@($script:blockers).Count -eq 0) { "passed" } else { "blocked" }
$result = [ordered]@{
    schema = "agentos.rc12-final-closeout-audit-result.v1"
    generated_at = $generatedAt
    task = "RC12-050"
    status = $resultStatus
    production_ready_claim = $false
    rc12_050_complete = (@($script:blockers).Count -eq 0)
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
        rc12_050_complete = (@($script:blockers).Count -eq 0)
        verdict = $finalAudit.verdict
        moved_beyond_fail_closed = $false
        production_ready_claim = $false
        next_task = "RC13-planning"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc12-final-closeout-audit-evidence.v1"
    generated_at = $generatedAt
    task = "RC12-050"
    status = "completed"
    production_ready_claim = $false
    workflow = ".workflow/active/WFS-20260609-agentos-production-distro-rc12"
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
    completion = [ordered]@{
        rc12_050_complete = $result.rc12_050_complete
        next_task = "RC13-planning"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

if (-not (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $finalAuditPath), (Get-Content -Raw -LiteralPath $closeoutSummaryPath), (Get-Content -Raw -LiteralPath $resultPath), (Get-Content -Raw -LiteralPath $taskEvidencePath)))) {
    throw "Sensitive marker detected in RC12 final closeout outputs."
}

Write-Host "RC12 final closeout audit $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Verdict: $($finalAudit.verdict)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:blockers).Count)"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
