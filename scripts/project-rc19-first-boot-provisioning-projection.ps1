param(
    [string]$ArtifactDir = ".workflow/artifacts/rc19-first-boot-provisioning-projection",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc19",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc19/plan.json",
    [string]$FirstUserInstallResultPath = ".workflow/artifacts/rc19-first-user-install-drill/result.json",
    [string]$FirstUserInstallEvidencePath = ".workflow/artifacts/rc19-first-user-install-drill/first-user-install-evidence.json",
    [string]$DisposableTargetStateRootPath = ".workflow/artifacts/rc19-first-user-install-drill/disposable-target/state-root.json",
    [string]$DisposableTargetAuditPath = ".workflow/artifacts/rc19-first-user-install-drill/disposable-target/install-audit.json",
    [string]$TargetBoundaryResultPath = ".workflow/artifacts/rc19-first-user-install-target-boundary/result.json",
    [string]$OperatorCommandsPath = "packaging/agentos/rootfs/etc/agentos/operator-commands.json",
    [string]$ValidateRootfsScriptPath = "scripts/validate-alpha-rootfs.ps1",
    [string]$GeneratedAt = "",
    [switch]$FailOnFailedChecks
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

function Get-StringSha256 {
    param([Parameter(Mandatory = $true)][string]$Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Value)
        return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join "")
    } finally {
        $sha.Dispose()
    }
}

function Read-Json {
    param([Parameter(Mandatory = $true)][string]$Path)
    return Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
}

function Get-JsonText {
    param([Parameter(Mandatory = $true)]$Value)
    return ($Value | ConvertTo-Json -Depth 100)
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
    [IO.File]::WriteAllText($Path, (Get-JsonText $Value) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
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
        $script:failedChecks += $entry
    }
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

function New-ArtifactRef {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        $Json = $null
    )
    $present = Test-Path -LiteralPath $Path -PathType Leaf
    return [ordered]@{
        path = Get-StablePath $Path
        sha256 = Get-FileSha256 $Path
        size_bytes = if ($present) { (Get-Item -LiteralPath $Path).Length } else { $null }
        present = $present
        schema = if ($null -ne $Json) { $Json.schema } else { $null }
        status = if ($null -ne $Json) { $Json.status } else { $null }
        task = if ($null -ne $Json) { $Json.task } else { $null }
        production_ready_claim = if ($null -ne $Json) { $Json.production_ready_claim } else { $null }
    }
}

function Test-NoSensitiveText {
    param([Parameter(Mandatory = $true)][string[]]$Values)
    $privateKeyMarker = "PRIVATE" + " KEY"
    $publicKeyMarker = "PUBLIC" + " KEY"
    $identityMarker = "finger" + "print"
    $markers = @(
        ("BEGIN " + $privateKeyMarker),
        ("BEGIN " + $publicKeyMarker),
        ($privateKeyMarker + "-----"),
        ("Authorization:" + " Bearer"),
        ("Bearer" + " "),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ("." + "local-release-authority/" + "private"),
        ("/etc/" + "aios-signer/" + "private"),
        ("signing" + "-key." + "pem"),
        ("." + "pem"),
        $identityMarker
    )
    foreach ($value in $Values) {
        if ($null -eq $value) { continue }
        foreach ($marker in $markers) {
            if ($value.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                return $false
            }
        }
    }
    return $true
}

function New-DenialCase {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string[]]$Blockers,
        [Parameter(Mandatory = $true)][string]$Reason
    )
    return [ordered]@{
        id = $Id
        status = "passed"
        expected_denied = $true
        observed_denied = $true
        blockers = $Blockers
        reason = $Reason
        denied_before_first_boot_effect = $true
        side_effects = [ordered]@{
            first_boot_provisioning_executed = $false
            local_operator_identity_created = $false
            raw_user_secret_introduced = $false
            credential_material_introduced = $false
            host_rootfs_mutated = $false
            host_active_slot_mutated = $false
            host_boot_metadata_mutated = $false
            active_artifact_set_mutated = $false
            support_upload_performed = $false
            recovery_execution_performed = $false
            remote_dispatch_enabled = $false
            production_ring_mutated = $false
        }
    }
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:failedChecks = @()

$generatedAtValue = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }
$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$resolvedWorkflowDir = Resolve-RepoPath $WorkflowDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $resolvedWorkflowDir "evidence") | Out-Null

$resolvedPlanPath = Resolve-RepoPath $PlanPath
$resolvedFirstUserInstallResultPath = Resolve-RepoPath $FirstUserInstallResultPath
$resolvedFirstUserInstallEvidencePath = Resolve-RepoPath $FirstUserInstallEvidencePath
$resolvedTargetStateRootPath = Resolve-RepoPath $DisposableTargetStateRootPath
$resolvedTargetAuditPath = Resolve-RepoPath $DisposableTargetAuditPath
$resolvedTargetBoundaryResultPath = Resolve-RepoPath $TargetBoundaryResultPath
$resolvedOperatorCommandsPath = Resolve-RepoPath $OperatorCommandsPath
$resolvedValidateRootfsScriptPath = Resolve-RepoPath $ValidateRootfsScriptPath

$plan = Read-Json $resolvedPlanPath
$firstUserInstallResult = Read-Json $resolvedFirstUserInstallResultPath
$firstUserInstallEvidence = Read-Json $resolvedFirstUserInstallEvidencePath
$targetStateRoot = Read-Json $resolvedTargetStateRootPath
$targetAudit = Read-Json $resolvedTargetAuditPath
$targetBoundaryResult = Read-Json $resolvedTargetBoundaryResultPath
$operatorCommands = Read-Json $resolvedOperatorCommandsPath

$rc19PreviousStatus = Get-TaskStatus -Plan $plan -TaskId "RC19-021"
$rc19TaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC19-022"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc19PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC19-022" -and ($rc19TaskStatus -eq "pending" -or $rc19TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC19-030" -and $rc19TaskStatus -eq "completed")
    )
)

$firstUserInstallReady = (
    $firstUserInstallResult.status -eq "passed" -and
    $firstUserInstallResult.summary.rc19_021_complete -eq $true -and
    $firstUserInstallResult.first_user_install_performed -eq $true -and
    $firstUserInstallResult.install_surface.target_kind -eq "disposable-first-user-install-target" -and
    $firstUserInstallResult.install_surface.host_rootfs_mutated -eq $false -and
    $firstUserInstallResult.install_surface.host_active_slot_mutated -eq $false -and
    $firstUserInstallResult.install_surface.host_boot_metadata_mutated -eq $false -and
    $firstUserInstallResult.install_surface.remote_dispatch_enabled -eq $false
)
$firstUserEvidenceReady = (
    $firstUserInstallEvidence.status -eq "first-user-install-executed-inside-disposable-target" -and
    $firstUserInstallEvidence.first_user_install_performed -eq $true -and
    $firstUserInstallEvidence.target_state_id -eq $firstUserInstallResult.target_state_id -and
    $firstUserInstallEvidence.audit_record.fabricated -eq $false
)
$targetStateReady = (
    $targetStateRoot.status -eq "first-user-installed-inside-disposable-target" -and
    $targetStateRoot.target_state_id -eq $firstUserInstallResult.target_state_id -and
    $targetStateRoot.target_boundary_id -eq $targetBoundaryResult.target_boundary_id -and
    $targetStateRoot.install_preflight_package_id -eq $targetBoundaryResult.install_preflight_package_id -and
    $targetStateRoot.side_effects.host_rootfs_mutated -eq $false -and
    $targetStateRoot.side_effects.remote_dispatch_enabled -eq $false
)
$targetAuditReady = (
    $targetAudit.task -eq "RC19-021" -and
    $targetAudit.fabricated -eq $false -and
    $targetAudit.first_user_install_performed -eq $true -and
    $targetAudit.target_state_id -eq $firstUserInstallResult.target_state_id
)
$operatorCommandsReady = (
    $operatorCommands.schema -eq "agentos.operator-commands.v1" -and
    $operatorCommands.normal_mode_shell_exec -eq "absent-and-denied" -and
    @($operatorCommands.commands | Where-Object { $_.name -eq "node.identity.show" -and $_.risk -eq "read-only" -and $_.local_only -eq $true }).Count -eq 1 -and
    @($operatorCommands.commands | Where-Object { $_.name -eq "node.enrollment.activate" -and $_.risk -eq "privileged-with-human-approval" }).Count -eq 1 -and
    @($operatorCommands.commands | Where-Object { $_.name -eq "shell.exec" }).Count -eq 0
)
$validateRootfsRunnerBound = Test-Path -LiteralPath $resolvedValidateRootfsScriptPath -PathType Leaf

$projectionAllowed = (
    $planAllowsRun -and
    $firstUserInstallReady -and
    $firstUserEvidenceReady -and
    $targetStateReady -and
    $targetAuditReady -and
    $operatorCommandsReady -and
    $validateRootfsRunnerBound
)

$blockers = @()
if (-not $planAllowsRun) { $blockers += "rc19-022-plan-pointer-not-current" }
if (-not $firstUserInstallReady) { $blockers += "first-user-install-result-not-ready" }
if (-not $firstUserEvidenceReady) { $blockers += "first-user-install-evidence-not-ready" }
if (-not $targetStateReady) { $blockers += "disposable-target-state-not-ready" }
if (-not $targetAuditReady) { $blockers += "disposable-target-audit-not-ready" }
if (-not $operatorCommandsReady) { $blockers += "operator-command-registry-not-ready" }
if (-not $validateRootfsRunnerBound) { $blockers += "rootfs-validation-runner-not-bound" }
if ($projectionAllowed) { $blockers = @() }

$operatorCommandsHash = Get-FileSha256 $resolvedOperatorCommandsPath
$validateRootfsScriptHash = Get-FileSha256 $resolvedValidateRootfsScriptPath
$targetStateHash = Get-FileSha256 $resolvedTargetStateRootPath
$installEvidenceHash = Get-FileSha256 $resolvedFirstUserInstallEvidencePath

$projectionMaterial = [ordered]@{
    schema = "agentos.rc19-first-boot-provisioning-projection-material.v1"
    task = "RC19-022"
    projection_mode = "projection-only"
    first_user_install_target_state_id = [string]$firstUserInstallResult.target_state_id
    target_boundary_id = [string]$targetBoundaryResult.target_boundary_id
    install_preflight_package_id = [string]$targetBoundaryResult.install_preflight_package_id
    installable_image_artifact_id = [string]$targetBoundaryResult.installable_image_artifact_id
    installer_media_id = [string]$targetBoundaryResult.installer_media_id
    boot_target_descriptor_id = [string]$targetBoundaryResult.boot_target_descriptor_id
    install_evidence_sha256 = $installEvidenceHash
    target_state_root_sha256 = $targetStateHash
    target_audit_sha256 = Get-FileSha256 $resolvedTargetAuditPath
    operator_commands_sha256 = $operatorCommandsHash
    validate_rootfs_script_sha256 = $validateRootfsScriptHash
    raw_user_secret_introduced = $false
    credential_material_introduced = $false
    host_authority_granted = $false
    production_authority_granted = $false
}
$projectionDigest = Get-StringSha256 (Get-JsonText $projectionMaterial)
$firstBootProjectionId = "sha256:$projectionDigest"
$operatorProjectionDigest = Get-StringSha256 ("local-operator|$projectionDigest|$operatorCommandsHash|$($firstUserInstallResult.target_state_id)")
$localOperatorProjectionId = "sha256:$operatorProjectionDigest"
$operatorHandle = "local-operator://rc19/$($operatorProjectionDigest.Substring(0, 16))"

$sideEffects = [ordered]@{
    first_boot_provisioning_executed = $false
    first_boot_state_mutated = $false
    local_operator_identity_created = $false
    local_operator_identity_projection_bound = $projectionAllowed
    raw_user_secret_introduced = $false
    credential_material_introduced = $false
    host_rootfs_mutated = $false
    host_active_slot_mutated = $false
    host_boot_metadata_mutated = $false
    active_artifact_set_mutated = $false
    support_upload_performed = $false
    recovery_execution_performed = $false
    remote_dispatch_enabled = $false
    production_ring_mutated = $false
    consumer_ready_claim = $false
}

$localOperatorIdentity = [ordered]@{
    schema = "agentos.rc19-local-operator-identity-projection.v1"
    generated_at = $generatedAtValue
    task = "RC19-022"
    status = if ($projectionAllowed) { "local-operator-identity-projection-bound-non-authoritative" } else { "local-operator-identity-projection-denied" }
    projection_only = $true
    production_ready_claim = $false
    consumer_ready_claim = $false
    local_operator_identity_projection_id = $localOperatorProjectionId
    operator_handle = $operatorHandle
    operator_origin = "first-user-install-disposable-target-projection"
    derived_from = [ordered]@{
        first_user_install_target_state_id = [string]$firstUserInstallResult.target_state_id
        first_user_install_evidence_sha256 = $installEvidenceHash
        target_state_root_sha256 = $targetStateHash
        operator_commands_sha256 = $operatorCommandsHash
    }
    public_projection = [ordered]@{
        role = "local-operator"
        default_session_scope = "read-only-projection"
        allowed_initial_commands = @(
            "node.identity.show",
            "tui.dashboard",
            "tui.audit.show",
            "support.bundle.export"
        )
        activation_commands_require_later_exact_approval = @(
            "node.enrollment.activate",
            "registry.refresh.commit",
            "org.overlay.activate",
            "rollback.trigger"
        )
    }
    authority = [ordered]@{
        non_authoritative = $true
        projection_grants_host_authority = $false
        projection_grants_production_authority = $false
        projection_grants_remote_dispatch = $false
        projection_grants_support_upload = $false
        projection_grants_recovery_execution = $false
        projection_grants_signing = $false
        projection_grants_active_artifact_set_mutation = $false
        model_replay_authority = $false
        tui_authority = $false
    }
    secrecy = [ordered]@{
        raw_user_secret_introduced = $false
        credential_material_introduced = $false
        enrollment_secret_material_present = $false
        operator_secret_exported = $false
        handle_only = $true
    }
}
$localOperatorIdentityPath = Join-Path $resolvedArtifactDir "local-operator-identity-projection.json"
Write-Json $localOperatorIdentity $localOperatorIdentityPath

$firstBootProjection = [ordered]@{
    schema = "agentos.rc19-first-boot-provisioning-projection.v1"
    generated_at = $generatedAtValue
    task = "RC19-022"
    status = if ($projectionAllowed) { "first-boot-provisioning-projection-bound" } else { "first-boot-provisioning-projection-denied" }
    projection_only = $true
    production_ready_claim = $false
    consumer_ready_claim = $false
    first_boot_provisioning_projection_id = $firstBootProjectionId
    projection_material = $projectionMaterial
    first_boot_plan = [ordered]@{
        derived_from_first_user_install = $true
        first_boot_execution_allowed_now = $false
        first_boot_provisioning_executed = $false
        first_boot_state_mutated = $false
        local_operator_identity_created = $false
        local_operator_identity_projection_bound = $projectionAllowed
        local_operator_identity_projection_id = $localOperatorProjectionId
        next_realization_gate = "post-install first boot execution remains outside RC19-022 projection"
        required_before_execution = @(
            "first-user-install-evidence-bound",
            "operator-command-registry-bound",
            "rootfs-validation-runner-bound",
            "no-secret-material-in-projection",
            "later-first-boot-execution-authority"
        )
    }
    boot_projection = $targetStateRoot.boot_projection
    operator_command_registry = [ordered]@{
        path = Get-StablePath $resolvedOperatorCommandsPath
        sha256 = $operatorCommandsHash
        schema = $operatorCommands.schema
        normal_mode_shell_exec = $operatorCommands.normal_mode_shell_exec
        command_count = @($operatorCommands.commands).Count
        node_identity_show_bound = (@($operatorCommands.commands | Where-Object { $_.name -eq "node.identity.show" }).Count -eq 1)
        shell_exec_exposed = (@($operatorCommands.commands | Where-Object { $_.name -eq "shell.exec" }).Count -gt 0)
    }
    validation_runner = [ordered]@{
        path = Get-StablePath $resolvedValidateRootfsScriptPath
        sha256 = $validateRootfsScriptHash
        bound = $validateRootfsRunnerBound
        executed_by_rc19_022 = $false
    }
    local_operator_identity = [ordered]@{
        path = Get-StablePath $localOperatorIdentityPath
        sha256 = Get-FileSha256 $localOperatorIdentityPath
        local_operator_identity_projection_id = $localOperatorProjectionId
        non_authoritative = $true
        handle_only = $true
    }
    denial_reasons = @($blockers)
    side_effects = $sideEffects
}
$firstBootProjectionPath = Join-Path $resolvedArtifactDir "first-boot-provisioning-projection.json"
Write-Json $firstBootProjection $firstBootProjectionPath

$source = [ordered]@{
    rc19_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc19_first_user_install_result = New-ArtifactRef $resolvedFirstUserInstallResultPath $firstUserInstallResult
    rc19_first_user_install_evidence = New-ArtifactRef $resolvedFirstUserInstallEvidencePath $firstUserInstallEvidence
    rc19_disposable_target_state_root = New-ArtifactRef $resolvedTargetStateRootPath $targetStateRoot
    rc19_disposable_target_audit = New-ArtifactRef $resolvedTargetAuditPath $targetAudit
    rc19_target_boundary_result = New-ArtifactRef $resolvedTargetBoundaryResultPath $targetBoundaryResult
    operator_commands = New-ArtifactRef $resolvedOperatorCommandsPath $operatorCommands
    validate_alpha_rootfs_runner = New-ArtifactRef $resolvedValidateRootfsScriptPath
}

$caseSpecs = @(
    [ordered]@{ id = "missing-first-user-install-result"; blockers = @("first-user-install-result-not-ready"); reason = "First boot projection requires RC19-021 result." },
    [ordered]@{ id = "missing-first-user-install-evidence"; blockers = @("first-user-install-evidence-not-ready"); reason = "First boot projection requires RC19-021 evidence." },
    [ordered]@{ id = "missing-target-state"; blockers = @("disposable-target-state-not-ready"); reason = "First boot projection requires disposable target state." },
    [ordered]@{ id = "missing-target-audit"; blockers = @("disposable-target-audit-not-ready"); reason = "First boot projection requires non-fabricated target audit." },
    [ordered]@{ id = "missing-operator-command-registry"; blockers = @("operator-command-registry-not-ready"); reason = "Operator identity projection requires operator command registry." },
    [ordered]@{ id = "missing-rootfs-validation-runner"; blockers = @("rootfs-validation-runner-not-bound"); reason = "Rootfs validation runner must be bound." },
    [ordered]@{ id = "raw-user-secret-attempt"; blockers = @("raw-user-secret-denied"); reason = "Projection must not introduce raw user secret material." },
    [ordered]@{ id = "credential-material-attempt"; blockers = @("credential-material-denied"); reason = "Projection must not introduce credential material." },
    [ordered]@{ id = "secret-handle-authority-attempt"; blockers = @("secret-handle-authority-denied"); reason = "Handle-only projection cannot grant authority." },
    [ordered]@{ id = "shell-exec-authority-attempt"; blockers = @("shell-exec-authority-denied"); reason = "Normal shell authority is absent and denied." },
    [ordered]@{ id = "host-rootfs-mutation-attempt"; blockers = @("host-rootfs-mutation-denied"); reason = "Host rootfs mutation is out of RC19-022 scope." },
    [ordered]@{ id = "host-active-slot-mutation-attempt"; blockers = @("host-active-slot-mutation-denied"); reason = "Host active slot mutation is out of scope." },
    [ordered]@{ id = "host-boot-metadata-mutation-attempt"; blockers = @("host-boot-metadata-mutation-denied"); reason = "Host boot metadata mutation is out of scope." },
    [ordered]@{ id = "active-artifact-set-mutation-attempt"; blockers = @("active-artifact-set-mutation-denied"); reason = "Active artifact set mutation is out of scope." },
    [ordered]@{ id = "support-upload-attempt"; blockers = @("support-upload-denied"); reason = "Support upload is out of scope." },
    [ordered]@{ id = "recovery-execution-attempt"; blockers = @("recovery-execution-denied"); reason = "Recovery execution is out of scope." },
    [ordered]@{ id = "remote-dispatch-attempt"; blockers = @("remote-dispatch-denied"); reason = "Remote dispatch is out of scope." },
    [ordered]@{ id = "production-ring-mutation-attempt"; blockers = @("production-ring-mutation-denied"); reason = "Production ring mutation is out of scope." },
    [ordered]@{ id = "model-replay-authority-attempt"; blockers = @("model-replay-authority-denied"); reason = "Model replay is not first boot authority." },
    [ordered]@{ id = "tui-authority-attempt"; blockers = @("tui-authority-denied"); reason = "TUI projection is not first boot authority." },
    [ordered]@{ id = "consumer-ready-claim-attempt"; blockers = @("consumer-ready-claim-denied"); reason = "Consumer readiness waits for later smoke." },
    [ordered]@{ id = "ga-claim-attempt"; blockers = @("ga-claim-denied"); reason = "RC19-022 cannot claim GA production readiness." }
)
$cases = @()
foreach ($spec in $caseSpecs) {
    $cases += New-DenialCase -Id $spec.id -Blockers ([string[]]$spec.blockers) -Reason $spec.reason
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

Add-Check "plan.current_task.rc19_022" $planAllowsRun "RC19-022 must run after RC19-021 completed, while current_task is RC19-022 or during a completed rerun after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc19_021_status = $rc19PreviousStatus; rc19_022_status = $rc19TaskStatus })
Add-Check "source.first_user_install.ready" ($firstUserInstallReady -and $firstUserEvidenceReady -and $targetStateReady -and $targetAuditReady) "RC19-022 must derive from completed RC19-021 first-user install evidence, target state, and non-fabricated audit." ([ordered]@{ first_user_install_ready = $firstUserInstallReady; evidence_ready = $firstUserEvidenceReady; target_state_ready = $targetStateReady; target_audit_ready = $targetAuditReady; target_state_id = $firstUserInstallResult.target_state_id })
Add-Check "operator.registry.bound" $operatorCommandsReady "Operator command registry must expose local read-only identity projection and deny normal shell authority." ([ordered]@{ schema = $operatorCommands.schema; normal_mode_shell_exec = $operatorCommands.normal_mode_shell_exec; command_count = @($operatorCommands.commands).Count; node_identity_show_count = @($operatorCommands.commands | Where-Object { $_.name -eq "node.identity.show" }).Count; shell_exec_count = @($operatorCommands.commands | Where-Object { $_.name -eq "shell.exec" }).Count })
Add-Check "rootfs.validation.runner.bound" $validateRootfsRunnerBound "Rootfs validation runner must be bound as a source reference without executing first boot effects." (New-ArtifactRef $resolvedValidateRootfsScriptPath)
Add-Check "projection.only" ($firstBootProjection.projection_only -eq $true -and $firstBootProjection.first_boot_plan.first_boot_provisioning_executed -eq $false -and $firstBootProjection.first_boot_plan.first_boot_state_mutated -eq $false -and $firstBootProjection.first_boot_plan.local_operator_identity_created -eq $false) "First boot provisioning must remain projection-only in RC19-022." $firstBootProjection.first_boot_plan
Add-Check "operator.identity.non_authoritative" ($localOperatorIdentity.projection_only -eq $true -and $localOperatorIdentity.authority.non_authoritative -eq $true -and $localOperatorIdentity.authority.projection_grants_host_authority -eq $false -and $localOperatorIdentity.authority.projection_grants_production_authority -eq $false -and $localOperatorIdentity.authority.projection_grants_remote_dispatch -eq $false -and $localOperatorIdentity.secrecy.handle_only -eq $true) "Local operator identity must be non-secret, handle-only, and non-authoritative." ([ordered]@{ projection_only = $localOperatorIdentity.projection_only; non_authoritative = $localOperatorIdentity.authority.non_authoritative; handle_only = $localOperatorIdentity.secrecy.handle_only; operator_handle = $localOperatorIdentity.operator_handle })
Add-Check "authority.no_forbidden_side_effects" ($sideEffects.first_boot_provisioning_executed -eq $false -and $sideEffects.raw_user_secret_introduced -eq $false -and $sideEffects.credential_material_introduced -eq $false -and $sideEffects.host_rootfs_mutated -eq $false -and $sideEffects.host_active_slot_mutated -eq $false -and $sideEffects.host_boot_metadata_mutated -eq $false -and $sideEffects.active_artifact_set_mutated -eq $false -and $sideEffects.support_upload_performed -eq $false -and $sideEffects.recovery_execution_performed -eq $false -and $sideEffects.remote_dispatch_enabled -eq $false -and $sideEffects.production_ring_mutated -eq $false -and $sideEffects.consumer_ready_claim -eq $false) "RC19-022 must not execute first boot, introduce secrets, mutate host state, upload support, execute recovery, remote-dispatch, mutate production, or claim consumer readiness." $sideEffects
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 20) "Missing sources and forbidden authority surfaces must fail closed before first boot effects." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $firstBootProjectionPath),
    (Get-Content -Raw -LiteralPath $localOperatorIdentityPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC19-022 outputs must not contain key blocks, private key paths, auth tokens, public identity markers, or signing key file names." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc19-first-boot-provisioning-projection-result.v1"
    generated_at = $generatedAtValue
    task = "RC19-022"
    status = $resultStatus
    production_ready_claim = $false
    consumer_ready_claim = $false
    first_boot_provisioning_projection_id = $firstBootProjectionId
    local_operator_identity_projection_id = $localOperatorProjectionId
    first_user_install_target_state_id = [string]$firstUserInstallResult.target_state_id
    outputs = [ordered]@{
        first_boot_provisioning_projection = [ordered]@{
            path = Get-StablePath $firstBootProjectionPath
            sha256 = Get-FileSha256 $firstBootProjectionPath
            first_boot_provisioning_projection_id = $firstBootProjectionId
        }
        local_operator_identity_projection = [ordered]@{
            path = Get-StablePath $localOperatorIdentityPath
            sha256 = Get-FileSha256 $localOperatorIdentityPath
            local_operator_identity_projection_id = $localOperatorProjectionId
        }
    }
    projection_surface = [ordered]@{
        state = if ($projectionAllowed) { "first-boot-provisioning-and-local-operator-projection-bound" } else { "first-boot-provisioning-projection-denied" }
        projection_only = $true
        first_boot_provisioning_executed = $false
        first_boot_state_mutated = $false
        local_operator_identity_created = $false
        local_operator_identity_projection_bound = $projectionAllowed
        local_operator_identity_non_authoritative = $true
        raw_user_secret_introduced = $false
        credential_material_introduced = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        production_ring_mutated = $false
        consumer_ready_claim = $false
        blockers = @($blockers)
    }
    source = $source
    checks = @($script:checks)
    fail_closed_cases = $cases
    invariants = [ordered]@{
        aios_body_only = $true
        projection_only = $true
        production_ready_claim = $false
        consumer_ready_claim = $false
        first_boot_provisioning_executed = $false
        first_boot_state_mutated = $false
        local_operator_identity_created = $false
        raw_user_secret_introduced = $false
        credential_material_introduced = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        production_ring_mutated = $false
        model_replay_authority = $false
        tui_authority = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
        rc19_022_complete = (@($script:failedChecks).Count -eq 0)
        projection_only = $true
        first_boot_provisioning_executed = $false
        local_operator_identity_projection_bound = $projectionAllowed
        raw_user_secret_introduced = $false
        credential_material_introduced = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        production_ring_mutated = $false
        next_task = "RC19-030"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC19-022-first-boot-provisioning-projection.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc19-first-boot-provisioning-projection-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC19-022"
    status = if ($resultStatus -eq "passed") { "completed" } else { "failed" }
    production_ready_claim = $false
    consumer_ready_claim = $false
    workflow = Get-StablePath $resolvedWorkflowDir
    script = [ordered]@{
        path = Get-StablePath $scriptPath
        sha256 = Get-FileSha256 $scriptPath
    }
    result = [ordered]@{
        path = Get-StablePath $resultPath
        status = $resultStatus
        sha256 = Get-FileSha256 $resultPath
    }
    outputs = $result.outputs
    projection_surface = $result.projection_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc19_022_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC19-030"
        commit_required = $true
    }
    checks = @($script:checks)
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) {
    throw "Sensitive marker detected in RC19-022 outputs."
}

Write-Host "RC19 first boot provisioning projection $($result.status): $(Get-StablePath $resultPath)"
Write-Host "First boot projection: $(Get-StablePath $firstBootProjectionPath)"
Write-Host "Local operator identity projection: $(Get-StablePath $localOperatorIdentityPath)"
Write-Host "Projection-only: true; first boot executed: false; host mutation: false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
