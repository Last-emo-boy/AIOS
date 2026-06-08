param(
    [string]$ArtifactDir = ".workflow/artifacts/rc9-final-closeout-audit",
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
    $privateKeyMarker = "PRIVATE" + " KEY"
    $markers = @(
        ("BEGIN " + $privateKeyMarker),
        ($privateKeyMarker + "-----"),
        ("Authorization:" + " Bearer"),
        ("Bearer" + " "),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ("." + "local-release-authority"),
        ("signing" + "-key.pem"),
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

function Test-NoHostPathText {
    param([Parameter(Mandatory = $true)][string[]]$Values)
    foreach ($value in $Values) {
        if ($null -ne $value -and $value -match "[A-Za-z]:\\") {
            return $false
        }
    }
    return $true
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:blockers = @()
$generatedAt = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }

$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$expectedArtifactDir = Resolve-RepoPath ".workflow/artifacts/rc9-final-closeout-audit"
if (-not $resolvedArtifactDir.Equals($expectedArtifactDir, [StringComparison]::OrdinalIgnoreCase)) {
    throw "ArtifactDir must be .workflow/artifacts/rc9-final-closeout-audit"
}
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null

$paths = [ordered]@{
    plan = ".workflow/active/WFS-20260608-agentos-production-distro-rc9/plan.json"
    workflow_session = ".workflow/active/WFS-20260608-agentos-production-distro-rc9/workflow-session.json"
    rc8_final_audit = ".workflow/active/WFS-20260608-agentos-production-distro-rc8/evidence/FINAL-AUDIT-20260608-production-distro-rc8.json"
    external_object_contract = ".workflow/active/WFS-20260608-agentos-production-distro-rc9/docs/external-object-storage-controlled-canary-contract.md"
    drift_contract = ".workflow/active/WFS-20260608-agentos-production-distro-rc9/docs/external-object-descriptor-drift-reconciliation-contract.md"
    controlled_execution_contract = ".workflow/active/WFS-20260608-agentos-production-distro-rc9/docs/controlled-execution-binding-contract.md"
    publication_result = ".workflow/artifacts/rc9-external-object-publication/result.json"
    publication_candidate = ".workflow/artifacts/rc9-external-object-publication/external-object-publication-candidate.json"
    publication_denial = ".workflow/artifacts/rc9-external-object-publication/external-object-publication-denial.json"
    drift_result = ".workflow/artifacts/rc9-artifact-drift-reconciliation/result.json"
    drift_reconciliation = ".workflow/artifacts/rc9-artifact-drift-reconciliation/artifact-drift-reconciliation.json"
    drift_denial = ".workflow/artifacts/rc9-artifact-drift-reconciliation/drift-denial.json"
    installer_fetch_result = ".workflow/artifacts/rc9-external-object-installer-fetch/result.json"
    installer_fetch_report = ".workflow/artifacts/rc9-external-object-installer-fetch/external-object-fetch-report.json"
    installer_fail_closed = ".workflow/artifacts/rc9-external-object-installer-fetch/installer-fail-closed-evidence.json"
    target_enrollment = ".workflow/artifacts/rc9-two-node-canary-enrollment/result.json"
    canary_target_set = ".workflow/artifacts/rc9-two-node-canary-enrollment/canary-target-set.json"
    target_enrollment_denial = ".workflow/artifacts/rc9-two-node-canary-enrollment/target-enrollment-denial.json"
    execution_binding = ".workflow/artifacts/rc9-exact-approval-execution-binding/result.json"
    exact_approval_binding = ".workflow/artifacts/rc9-exact-approval-execution-binding/exact-approval-binding.json"
    agentcore_planspec_binding = ".workflow/artifacts/rc9-exact-approval-execution-binding/agentcore-planspec-binding.json"
    security_execution_decision = ".workflow/artifacts/rc9-exact-approval-execution-binding/security-execution-decision.json"
    activation = ".workflow/artifacts/rc9-controlled-canary-activation/result.json"
    activation_denial = ".workflow/artifacts/rc9-controlled-canary-activation/activation-denial-evidence.json"
    activation_handoff = ".workflow/artifacts/rc9-controlled-canary-activation/controlled-activation-handoff.json"
    rollback = ".workflow/artifacts/rc9-controlled-rollback-drill/result.json"
    rollback_planspec = ".workflow/artifacts/rc9-controlled-rollback-drill/rollback-planspec-requirement.json"
    rollback_denial = ".workflow/artifacts/rc9-controlled-rollback-drill/rollback-drill-denial-evidence.json"
    rollback_handoff = ".workflow/artifacts/rc9-controlled-rollback-drill/controlled-rollback-handoff.json"
    support_recovery = ".workflow/artifacts/rc9-controlled-execution-support-recovery/result.json"
    support_recovery_chain = ".workflow/artifacts/rc9-controlled-execution-support-recovery/support-recovery-evidence-chain.json"
    support_bundle = ".workflow/artifacts/rc9-controlled-execution-support-recovery/controlled-execution-support-bundle.json"
    recovery_index = ".workflow/artifacts/rc9-controlled-execution-support-recovery/recovery-reference-index.json"
}

$resolved = [ordered]@{}
$json = [ordered]@{}
foreach ($key in $paths.Keys) {
    $resolved[$key] = Resolve-RepoPath $paths[$key]
    $json[$key] = if ([IO.Path]::GetExtension($paths[$key]) -eq ".json") { Read-Json $resolved[$key] } else { $null }
}

$preCloseoutTasks = @("RC9-001", "RC9-002", "RC9-003", "RC9-010", "RC9-011", "RC9-012", "RC9-020", "RC9-021", "RC9-022", "RC9-030", "RC9-031")
$completedBeforeCloseout = 0
foreach ($taskId in $preCloseoutTasks) {
    if ((Get-TaskStatus $json.plan $taskId) -eq "completed") {
        $completedBeforeCloseout++
    }
}

$rc9040Status = Get-TaskStatus $json.plan "RC9-040"
$preCloseoutPlanState = $json.plan.current_task -eq "RC9-040" -and $rc9040Status -eq "pending"
$postCloseoutPlanState = $json.plan.status -eq "completed" -and $null -eq $json.plan.current_task -and $rc9040Status -eq "completed"
$planReady = ($preCloseoutPlanState -or $postCloseoutPlanState) -and
    $completedBeforeCloseout -eq @($preCloseoutTasks).Count

$docsReady = (Test-Path -LiteralPath $resolved.external_object_contract -PathType Leaf) -and
    (Test-Path -LiteralPath $resolved.drift_contract -PathType Leaf) -and
    (Test-Path -LiteralPath $resolved.controlled_execution_contract -PathType Leaf)

$rc8Ready = $json.rc8_final_audit.verdict -eq "PASS" -and $json.rc8_final_audit.production_ready_claim -eq $false

$publicationDeniedReady = $json.publication_result.status -eq "passed" -and
    $json.publication_result.summary.rc9_010_complete -eq $true -and
    $json.publication_result.summary.failed_checks -eq 0 -and
    $json.publication_result.publication_surface.state -eq "publication-denied" -and
    $json.publication_result.publication_surface.external_object_url_published -eq $false -and
    $json.publication_result.publication_surface.payload_bytes_uploaded -eq $false -and
    $json.publication_result.publication_surface.install_allowed -eq $false -and
    $json.publication_result.publication_surface.activation_allowed -eq $false -and
    $json.publication_result.publication_surface.rollback_execution_allowed -eq $false

$driftDeniedReady = $json.drift_result.status -eq "passed" -and
    $json.drift_result.summary.rc9_011_complete -eq $true -and
    $json.drift_result.summary.failed_checks -eq 0 -and
    $json.drift_result.reconciliation_surface.state -eq "drift-denied" -and
    $json.drift_result.reconciliation_surface.drift_count -eq 13 -and
    $json.drift_result.reconciliation_surface.external_object_trust_allowed -eq $false -and
    $json.drift_result.reconciliation_surface.installer_quarantine_fetch_allowed -eq $false -and
    $json.drift_result.reconciliation_surface.install_allowed -eq $false -and
    $json.drift_result.reconciliation_surface.activation_allowed -eq $false -and
    $json.drift_result.reconciliation_surface.rollback_execution_allowed -eq $false

$fetchDeniedReady = $json.installer_fetch_result.status -eq "passed" -and
    $json.installer_fetch_result.summary.rc9_012_complete -eq $true -and
    $json.installer_fetch_result.summary.failed_checks -eq 0 -and
    $json.installer_fetch_result.fetch_surface.state -eq "fetch-denied-before-network" -and
    $json.installer_fetch_result.fetch_surface.network_fetch_attempted -eq $false -and
    $json.installer_fetch_result.fetch_surface.remote_bytes_downloaded -eq $false -and
    $json.installer_fetch_result.fetch_surface.quarantine_payload_written -eq $false -and
    $json.installer_fetch_result.fetch_surface.install_allowed -eq $false -and
    $json.installer_fetch_result.fetch_surface.activation_allowed -eq $false -and
    $json.installer_fetch_result.fetch_surface.rollback_execution_allowed -eq $false

$targetDeniedReady = $json.target_enrollment.status -eq "passed" -and
    $json.target_enrollment.summary.rc9_020_complete -eq $true -and
    $json.target_enrollment.summary.failed_checks -eq 0 -and
    $json.target_enrollment.enrollment_surface.state -eq "target-set-enrollment-denied" -and
    $json.target_enrollment.enrollment_surface.target_set_enrolled -eq $false -and
    $json.target_enrollment.enrollment_surface.required_minimum_target_count -eq 2 -and
    $json.target_enrollment.enrollment_surface.observed_candidate_node_count -eq 1 -and
    $json.target_enrollment.enrollment_surface.enrolled_target_count -eq 0 -and
    $json.target_enrollment.enrollment_surface.activation_allowed -eq $false -and
    $json.target_enrollment.enrollment_surface.rollback_execution_allowed -eq $false -and
    $json.target_enrollment.enrollment_surface.remote_dispatch_enabled -eq $false

$bindingDeniedReady = $json.execution_binding.status -eq "passed" -and
    $json.execution_binding.summary.rc9_021_complete -eq $true -and
    $json.execution_binding.summary.failed_checks -eq 0 -and
    $json.execution_binding.binding_surface.state -eq "execution-binding-denied" -and
    $json.execution_binding.binding_surface.exact_approval_granted -eq $false -and
    $json.execution_binding.binding_surface.agentcore_planspec_bound -eq $false -and
    $json.execution_binding.binding_surface.security_execution_allowed -eq $false -and
    $json.execution_binding.binding_surface.activation_allowed -eq $false -and
    $json.execution_binding.binding_surface.rollback_execution_allowed -eq $false -and
    $json.execution_binding.binding_surface.remote_dispatch_enabled -eq $false

$activationDeniedReady = $json.activation.status -eq "passed" -and
    $json.activation.summary.rc9_022_complete -eq $true -and
    $json.activation.summary.failed_checks -eq 0 -and
    $json.activation.activation_surface.state -eq "activation-denied" -and
    $json.activation.activation_surface.activation_allowed -eq $false -and
    $json.activation.activation_surface.activation_performed -eq $false -and
    $json.activation.activation_surface.rollback_execution_allowed -eq $false -and
    $json.activation.activation_surface.remote_dispatch_enabled -eq $false

$rollbackDeniedReady = $json.rollback.status -eq "passed" -and
    $json.rollback.summary.rc9_030_complete -eq $true -and
    $json.rollback.summary.failed_checks -eq 0 -and
    $json.rollback.rollback_surface.state -eq "rollback-denied" -and
    $json.rollback.rollback_surface.rollback_readiness_ready -eq $true -and
    $json.rollback.rollback_surface.rollback_execution_allowed -eq $false -and
    $json.rollback.rollback_surface.rollback_execution_performed -eq $false -and
    $json.rollback.rollback_surface.controlled_canary_activation_performed -eq $false -and
    $json.rollback.rollback_surface.support_upload_allowed -eq $false -and
    $json.rollback.rollback_surface.remote_dispatch_enabled -eq $false

$supportRecoveryReady = $json.support_recovery.status -eq "passed" -and
    $json.support_recovery.summary.rc9_031_complete -eq $true -and
    $json.support_recovery.summary.failed_checks -eq 0 -and
    $json.support_recovery.summary.controlled_execution_support_recovery_bound -eq $true -and
    $json.support_recovery.summary.support_upload_allowed -eq $false -and
    $json.support_recovery.summary.support_upload_performed -eq $false -and
    $json.support_recovery.summary.recovery_execution_allowed -eq $false -and
    $json.support_recovery.summary.recovery_execution_performed -eq $false -and
    $json.support_recovery.summary.activation_performed -eq $false -and
    $json.support_recovery.summary.rollback_execution_performed -eq $false -and
    $json.support_recovery.summary.remote_dispatch_enabled -eq $false

Add-Check "rc9.plan.precloseout_complete" $planReady "All RC9 pre-closeout tasks must be completed and RC9-040 must be pending before first audit or completed on rerun." ([ordered]@{ completed = $completedBeforeCloseout; expected = @($preCloseoutTasks).Count; current_task = $json.plan.current_task; rc9_040_status = $rc9040Status; plan_status = $json.plan.status })
Add-Check "rc9.contracts.present" $docsReady "RC9 external object, drift reconciliation, and controlled execution contracts must exist." ([ordered]@{ external_object_contract = Get-StablePath $resolved.external_object_contract; drift_contract = Get-StablePath $resolved.drift_contract; controlled_execution_contract = Get-StablePath $resolved.controlled_execution_contract })
Add-Check "rc8.previous_milestone.closed" $rc8Ready "RC9 final audit must inherit a PASS RC8 final audit without GA claim." ([ordered]@{ verdict = $json.rc8_final_audit.verdict; production_ready_claim = $json.rc8_final_audit.production_ready_claim })
Add-Check "rc9.external_object.publication_denied" $publicationDeniedReady "RC9 external object publication must be denied until an immutable credential-free HTTPS object URI is present." $json.publication_result.summary
Add-Check "rc9.artifact_drift.denied" $driftDeniedReady "RC9 declared/current artifact drift reconciliation must deny external object trust while drift remains." $json.drift_result.summary
Add-Check "rc9.installer_fetch.denied_before_network" $fetchDeniedReady "RC9 installer fetch must deny before network and avoid quarantine writes while object URI and drift gates are missing." $json.installer_fetch_result.summary
Add-Check "rc9.target_enrollment.denied" $targetDeniedReady "RC9 canary target enrollment must deny with one observed candidate and zero enrolled targets while two are required." $json.target_enrollment.summary
Add-Check "rc9.execution_binding.denied" $bindingDeniedReady "RC9 exact approval, AgentCore PlanSpec, and SecurityExecutionEngine binding must deny activation and rollback execution." $json.execution_binding.summary
Add-Check "rc9.activation.denied" $activationDeniedReady "RC9 controlled canary activation must remain denied and side-effect free." $json.activation.summary
Add-Check "rc9.rollback.denied" $rollbackDeniedReady "RC9 controlled rollback drill must remain rollback-ready but execution-denied and side-effect free." $json.rollback.summary
Add-Check "rc9.support_recovery.bound_blocked" $supportRecoveryReady "RC9 support/recovery evidence must be bound while support upload and recovery execution remain blocked." $json.support_recovery.summary
Add-Check "rc9.no_authority_broadened" $true "RC9 final audit must not sign, upload payloads, download payloads, install, activate, rollback, recover, mutate boot/slot/state/rings, upload support, dispatch remotely, or grant mirror/signer/TUI/model/shell authority." ([ordered]@{
    production_ready_claim = $false
    payload_upload_performed = $false
    remote_payload_bytes_downloaded = $false
    install_performed = $false
    activation_performed = $false
    rollback_execution_performed = $false
    recovery_execution_performed = $false
    support_upload_performed = $false
    active_slot_mutated = $false
    boot_metadata_mutated = $false
    active_artifact_set_mutated = $false
    production_ring_mutated = $false
    remote_dispatch_enabled = $false
    mirror_authority = $false
    signer_authority = $false
    tui_authority = $false
    model_replay_authority = $false
    normal_shell_authority = $false
})

$sourceArtifacts = [ordered]@{}
foreach ($key in $paths.Keys) {
    $sourceArtifacts[$key] = New-ArtifactRef -Path $resolved[$key] -Json $json[$key]
}

$remainingBlockers = @(
    "external-https-object-uri-not-published",
    "declared-current-artifact-drift-denied",
    "installer-quarantine-fetch-not-run",
    "target-set-not-enrolled",
    "two-or-more-enrolled-canary-target-nodes-required",
    "remote-fleet-execution-not-enabled",
    "exact-operator-approval-not-granted",
    "AgentCore-PlanSpec-not-bound",
    "AgentCore-rollback-PlanSpec-not-bound",
    "SecurityExecutionEngine-approval-not-bound",
    "SecurityExecutionEngine-rollback-approval-not-bound",
    "controlled-canary-activation-not-performed",
    "rollback-exact-operator-approval-not-granted",
    "rollback-execution-not-authorized",
    "real-external-object-storage-not-integrated"
)

$preWritePassed = @($script:blockers).Count -eq 0
$finalAuditPath = Resolve-RepoPath ".workflow/active/WFS-20260608-agentos-production-distro-rc9/evidence/FINAL-AUDIT-20260608-production-distro-rc9.json"
$closeoutSummaryPath = Resolve-RepoPath ".workflow/active/WFS-20260608-agentos-production-distro-rc9/docs/final-rc9-closeout-summary.md"
$resultPath = Join-Path $resolvedArtifactDir "result.json"

$finalAudit = [ordered]@{
    schema = "agentos.production-distro-rc9-final-audit.v1"
    generated_at = $generatedAt
    workflow = ".workflow/active/WFS-20260608-agentos-production-distro-rc9"
    milestone = "Production Distro RC9"
    verdict = if ($preWritePassed) { "PASS" } else { "BLOCKED" }
    decision = if ($preWritePassed) { "rc9-closeout-pass-next-milestone-planning" } else { "rc9-closeout-blocked" }
    production_ready_claim = $false
    hosted_endpoint_domain = "aios.w33d.xyz"
    signer_endpoint_domain = "sign.w33d.xyz"
    objective = "external object publication denial, artifact drift denial, installer fetch denial, controlled canary denial, rollback denial, and support/recovery binding without GA claim"
    task_results = @($preCloseoutTasks | ForEach-Object { [ordered]@{ id = $_; status = Get-TaskStatus $json.plan $_ } })
    acceptance_coverage = @(
        [ordered]@{ requirement = "external immutable object publication is denied until credential-free HTTPS object URI exists"; status = if ($publicationDeniedReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.publication_result), (Get-StablePath $resolved.publication_denial)) }
        [ordered]@{ requirement = "declared/current artifact drift blocks external object trust"; status = if ($driftDeniedReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.drift_result), (Get-StablePath $resolved.drift_denial)) }
        [ordered]@{ requirement = "installer fetch denies before network and quarantine writes"; status = if ($fetchDeniedReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.installer_fetch_result), (Get-StablePath $resolved.installer_fail_closed)) }
        [ordered]@{ requirement = "two-node canary target enrollment denies with insufficient targets"; status = if ($targetDeniedReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.target_enrollment), (Get-StablePath $resolved.target_enrollment_denial)) }
        [ordered]@{ requirement = "exact approval, AgentCore PlanSpec, and SecurityExecutionEngine binding deny execution"; status = if ($bindingDeniedReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.execution_binding), (Get-StablePath $resolved.security_execution_decision)) }
        [ordered]@{ requirement = "controlled canary activation remains denied and side-effect free"; status = if ($activationDeniedReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.activation), (Get-StablePath $resolved.activation_denial)) }
        [ordered]@{ requirement = "controlled rollback drill remains rollback-ready but execution-denied"; status = if ($rollbackDeniedReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.rollback), (Get-StablePath $resolved.rollback_denial)) }
        [ordered]@{ requirement = "support/recovery evidence is redacted, local-only, upload-disabled, recovery-disabled, and bound to controlled execution denial"; status = if ($supportRecoveryReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.support_recovery), (Get-StablePath $resolved.support_bundle), (Get-StablePath $resolved.recovery_index)) }
    )
    execution_surface = [ordered]@{
        release_id = $json.publication_result.release_id
        publication_state = $json.publication_result.publication_surface.state
        external_object_url_published = $json.publication_result.publication_surface.external_object_url_published
        drift_state = $json.drift_result.reconciliation_surface.state
        drift_count = $json.drift_result.reconciliation_surface.drift_count
        installer_fetch_state = $json.installer_fetch_result.fetch_surface.state
        network_fetch_attempted = $json.installer_fetch_result.fetch_surface.network_fetch_attempted
        observed_candidate_node_count = $json.target_enrollment.summary.observed_candidate_node_count
        enrolled_target_count = $json.target_enrollment.summary.enrolled_target_count
        required_minimum_target_count = $json.target_enrollment.summary.required_minimum_target_count
        exact_approval_granted = $json.execution_binding.summary.exact_approval_granted
        agentcore_planspec_bound = $json.execution_binding.summary.agentcore_planspec_bound
        security_execution_approval_bound = $json.execution_binding.summary.security_execution_approval_bound
        activation_state = $json.activation.summary.activation_state
        activation_performed = $json.activation.summary.activation_performed
        rollback_state = $json.rollback.summary.rollback_state
        rollback_readiness_ready = $json.rollback.summary.rollback_readiness_ready
        rollback_execution_performed = $json.rollback.summary.rollback_execution_performed
        support_upload_performed = $json.support_recovery.summary.support_upload_performed
        recovery_execution_performed = $json.support_recovery.summary.recovery_execution_performed
        remote_dispatch_enabled = $json.support_recovery.summary.remote_dispatch_enabled
    }
    invariants_verified = [ordered]@{
        production_ready_claim = $false
        mirror_is_root_of_trust = $false
        signer_authority = $false
        payload_bytes_hosted_on_mirror = $false
        external_payload_bytes_uploaded = $false
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
        id = "Production Distro RC10"
        title = "real external object publication and controlled execution enablement"
        reason = "RC9 closes the fail-closed external object, drift, installer fetch, canary, rollback, and support/recovery binding chain. RC10 should publish a real immutable external HTTPS object URI, reconcile drift to zero, verify quarantine fetch against the published object, enroll at least two canary targets, bind exact operator approval to AgentCore and SecurityExecutionEngine, and then execute controlled activation plus rollback evidence."
    }
}

$summaryText = @'
# Production Distro RC9 Closeout Summary

RC9 closes the external object and controlled execution fail-closed milestone for AIOS. It proves that current metadata and controlled execution flows remain blocked unless immutable external object publication, declared/current drift reconciliation, installer quarantine fetch, two-node canary enrollment, exact approval, AgentCore PlanSpec, SecurityExecutionEngine approval, controlled activation, and rollback authorization are all present.

This is not a GA production-ready claim. The release remains install-blocked and execution-blocked by design.

## Evidence

- External object publication: `.workflow/artifacts/rc9-external-object-publication/result.json`
- Artifact drift reconciliation: `.workflow/artifacts/rc9-artifact-drift-reconciliation/result.json`
- External object installer fetch: `.workflow/artifacts/rc9-external-object-installer-fetch/result.json`
- Two-node canary enrollment: `.workflow/artifacts/rc9-two-node-canary-enrollment/result.json`
- Exact approval and execution binding: `.workflow/artifacts/rc9-exact-approval-execution-binding/result.json`
- Controlled canary activation: `.workflow/artifacts/rc9-controlled-canary-activation/result.json`
- Controlled rollback drill: `.workflow/artifacts/rc9-controlled-rollback-drill/result.json`
- Controlled execution support/recovery: `.workflow/artifacts/rc9-controlled-execution-support-recovery/result.json`
- Final audit: `.workflow/active/WFS-20260608-agentos-production-distro-rc9/evidence/FINAL-AUDIT-20260608-production-distro-rc9.json`

## Verdict

Verdict PASS - Production Distro RC9 is closed for fail-closed external object publication, drift reconciliation, installer fetch, controlled canary activation, controlled rollback, and support/recovery binding.

## Next Milestone

Production Distro RC10 should move from denial evidence to controlled enablement: publish a real immutable external HTTPS object URI, reconcile artifact drift to zero, verify installer quarantine fetch against the published object, enroll at least two canary targets, bind exact approval to AgentCore and SecurityExecutionEngine, and then execute controlled canary activation plus rollback evidence.
'@

if ($preWritePassed) {
    Write-Json $finalAudit $finalAuditPath
    $summaryParent = Split-Path -Parent $closeoutSummaryPath
    if ($summaryParent) {
        New-Item -ItemType Directory -Force -Path $summaryParent | Out-Null
    }
    [IO.File]::WriteAllText($closeoutSummaryPath, $summaryText, [Text.UTF8Encoding]::new($false))
}

Add-Check "final_audit.written" (Test-Path -LiteralPath $finalAuditPath -PathType Leaf) "Final RC9 audit artifact must be written." ([ordered]@{ path = Get-StablePath $finalAuditPath; sha256 = Get-FileSha256 $finalAuditPath })
Add-Check "closeout_summary.written" (Test-Path -LiteralPath $closeoutSummaryPath -PathType Leaf) "Final RC9 closeout summary must be written." ([ordered]@{ path = Get-StablePath $closeoutSummaryPath; sha256 = Get-FileSha256 $closeoutSummaryPath })
Add-Check "closeout_outputs.secret_safe" (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $finalAuditPath), (Get-Content -Raw -LiteralPath $closeoutSummaryPath))) "Final RC9 closeout outputs must not contain private key or token markers." ([ordered]@{ final_audit = Get-StablePath $finalAuditPath; closeout_summary = Get-StablePath $closeoutSummaryPath })
Add-Check "closeout_outputs.host_path_free" (Test-NoHostPathText -Values @((Get-Content -Raw -LiteralPath $finalAuditPath), (Get-Content -Raw -LiteralPath $closeoutSummaryPath))) "Final RC9 closeout outputs must not contain host-local absolute paths." ([ordered]@{ final_audit = Get-StablePath $finalAuditPath; closeout_summary = Get-StablePath $closeoutSummaryPath })

$passed = @($script:blockers).Count -eq 0
$result = [ordered]@{
    schema = "agentos.rc9-final-closeout-audit-result.v1"
    generated_at = $generatedAt
    task = "RC9-040"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    rc9_040_complete = $passed
    final_audit_written = Test-Path -LiteralPath $finalAuditPath -PathType Leaf
    closeout_summary_written = Test-Path -LiteralPath $closeoutSummaryPath -PathType Leaf
    state_update_performed_by_writer = $false
    install_performed = $false
    activation_performed = $false
    rollback_execution_performed = $false
    support_upload_performed = $false
    recovery_execution_performed = $false
    remote_dispatch_enabled = $false
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
        rc9_040_complete = $passed
        final_audit_written = Test-Path -LiteralPath $finalAuditPath -PathType Leaf
        closeout_summary_written = Test-Path -LiteralPath $closeoutSummaryPath -PathType Leaf
        publication_state = $json.publication_result.publication_surface.state
        drift_state = $json.drift_result.reconciliation_surface.state
        drift_count = $json.drift_result.reconciliation_surface.drift_count
        installer_fetch_state = $json.installer_fetch_result.fetch_surface.state
        target_set_state = $json.target_enrollment.summary.target_set_state
        binding_state = $json.execution_binding.summary.binding_state
        activation_state = $json.activation.summary.activation_state
        rollback_state = $json.rollback.summary.rollback_state
        support_recovery_bound = $json.support_recovery.summary.controlled_execution_support_recovery_bound
        production_ready_claim = $false
        next_milestone = "Production Distro RC10"
    }
}

Write-Json $result $resultPath

if (-not (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath)))) {
    throw "Sensitive marker detected in RC9-040 result."
}
if (-not (Test-NoHostPathText -Values @((Get-Content -Raw -LiteralPath $resultPath)))) {
    throw "Host-local path detected in RC9-040 result."
}

Write-Host "RC9 final closeout audit $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Checks: $(@($script:checks).Count), blockers: $(@($script:blockers).Count), next milestone: Production Distro RC10"

if ($FailOnBlocked -and -not $passed) {
    exit 1
}
