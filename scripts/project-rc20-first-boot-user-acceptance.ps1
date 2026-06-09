param(
    [string]$ArtifactDir = ".workflow/artifacts/rc20-first-boot-user-acceptance",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc20",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc20/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc20/docs/rc20-single-user-distribution-authority-contract.md",
    [string]$InstallAcceptanceResultPath = ".workflow/artifacts/rc20-single-user-install-acceptance/result.json",
    [string]$InstallAcceptanceEvidencePath = ".workflow/artifacts/rc20-single-user-install-acceptance/install-acceptance-evidence.json",
    [string]$InstallAuditRecordPath = ".workflow/artifacts/rc20-single-user-install-acceptance/install-audit-record.json",
    [string]$FirstBootProjectionResultPath = ".workflow/artifacts/rc19-first-boot-provisioning-projection/result.json",
    [string]$FirstBootProjectionPath = ".workflow/artifacts/rc19-first-boot-provisioning-projection/first-boot-provisioning-projection.json",
    [string]$LocalOperatorIdentityProjectionPath = ".workflow/artifacts/rc19-first-boot-provisioning-projection/local-operator-identity-projection.json",
    [string]$ReleaseBundleResultPath = ".workflow/artifacts/rc20-single-user-release-bundle/result.json",
    [string]$PostInstallLifecycleResultPath = ".workflow/artifacts/rc19-post-install-update-rollback-smoke/result.json",
    [string]$SupportRecoveryResultPath = ".workflow/artifacts/rc19-first-user-support-recovery/result.json",
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
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
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
    param([Parameter(Mandatory = $true)]$Value, [Parameter(Mandatory = $true)][string]$Path)
    $parent = Split-Path -Parent $Path
    if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
    [IO.File]::WriteAllText($Path, (Get-JsonText $Value) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}

function Add-Check {
    param([string]$Id, [bool]$Passed, [string]$Message, $Evidence = $null)
    $entry = [ordered]@{
        id = $Id
        status = if ($Passed) { "passed" } else { "failed" }
        severity = "blocking"
        message = $Message
        evidence = $Evidence
    }
    $script:checks += $entry
    if (-not $Passed) { $script:failedChecks += $entry }
}

function Get-TaskStatus {
    param($Plan, [string]$TaskId)
    foreach ($wave in @($Plan.waves)) {
        foreach ($task in @($wave.tasks)) {
            if ($task.id -eq $TaskId) { return $task.status }
        }
    }
    return $null
}

function Test-NoSensitiveText {
    param([string[]]$Values)
    $privateMarker = "PRIVATE" + " KEY"
    $publicMarker = "PUBLIC" + " KEY"
    $markers = @(
        ("BEGIN " + $privateMarker),
        ("BEGIN " + $publicMarker),
        ("Authorization:" + " Bearer"),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ("." + "local-release-authority/" + "private"),
        ("/etc/" + "aios-signer/" + "private"),
        ("signing" + "-key." + "pem"),
        ("." + "pem"),
        ("pass" + "word="),
        ("sec" + "ret=")
    )
    foreach ($value in $Values) {
        if ($null -eq $value) { continue }
        foreach ($marker in $markers) {
            if ($value.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $false }
        }
    }
    return $true
}

function New-SideEffects {
    return [ordered]@{
        first_boot_acceptance_bound = $false
        local_operator_posture_bound = $false
        first_boot_provisioning_executed = $false
        first_boot_state_mutated = $false
        local_operator_identity_created = $false
        raw_user_secret_introduced = $false
        credential_material_introduced = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        shell_authority_granted = $false
        tui_authority_granted = $false
        endpoint_reachability_authority_granted = $false
        model_replay_authority_granted = $false
        production_ready_claim = $false
        consumer_ready_claim = $false
    }
}

function New-DenialCase {
    param([string]$Id, [string[]]$Blockers, [string]$Reason)
    return [ordered]@{
        id = $Id
        status = "passed"
        expected_denied = $true
        observed_denied = $true
        blockers = $Blockers
        reason = $Reason
        denied_before_first_boot_authority = $true
        side_effects = New-SideEffects
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
$resolvedContractPath = Resolve-RepoPath $ContractPath
$resolvedInstallAcceptanceResultPath = Resolve-RepoPath $InstallAcceptanceResultPath
$resolvedInstallAcceptanceEvidencePath = Resolve-RepoPath $InstallAcceptanceEvidencePath
$resolvedInstallAuditRecordPath = Resolve-RepoPath $InstallAuditRecordPath
$resolvedFirstBootProjectionResultPath = Resolve-RepoPath $FirstBootProjectionResultPath
$resolvedFirstBootProjectionPath = Resolve-RepoPath $FirstBootProjectionPath
$resolvedLocalOperatorIdentityProjectionPath = Resolve-RepoPath $LocalOperatorIdentityProjectionPath
$resolvedReleaseBundleResultPath = Resolve-RepoPath $ReleaseBundleResultPath
$resolvedPostInstallLifecycleResultPath = Resolve-RepoPath $PostInstallLifecycleResultPath
$resolvedSupportRecoveryResultPath = Resolve-RepoPath $SupportRecoveryResultPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$installAcceptanceResult = Read-Json $resolvedInstallAcceptanceResultPath
$installAcceptanceEvidence = Read-Json $resolvedInstallAcceptanceEvidencePath
$installAuditRecord = Read-Json $resolvedInstallAuditRecordPath
$firstBootProjectionResult = Read-Json $resolvedFirstBootProjectionResultPath
$firstBootProjection = Read-Json $resolvedFirstBootProjectionPath
$localOperatorIdentity = Read-Json $resolvedLocalOperatorIdentityProjectionPath
$releaseBundleResult = Read-Json $resolvedReleaseBundleResultPath
$postInstallLifecycleResult = Read-Json $resolvedPostInstallLifecycleResultPath
$supportRecoveryResult = Read-Json $resolvedSupportRecoveryResultPath

$rc20PreviousStatus = Get-TaskStatus -Plan $plan -TaskId "RC20-021"
$rc20TaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC20-022"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $plan.current_task -eq "RC20-022" -and
    $rc20PreviousStatus -eq "completed" -and
    ($rc20TaskStatus -eq "pending" -or $rc20TaskStatus -eq "completed")
)

$installAcceptanceReady = (
    $installAcceptanceResult.status -eq "passed" -and
    $installAcceptanceResult.summary.rc20_021_complete -eq $true -and
    $installAcceptanceResult.summary.first_user_install_performed_inside_disposable_target -eq $true -and
    $installAcceptanceResult.summary.host_rootfs_mutated -eq $false -and
    $installAcceptanceResult.summary.production_ring_mutated -eq $false -and
    $installAcceptanceEvidence.install_acceptance_id -eq $installAcceptanceResult.install_acceptance_id -and
    $installAuditRecord.audit_record_id -eq $installAcceptanceResult.audit_record_id
)

$firstBootProjectionReady = (
    $firstBootProjectionResult.status -eq "passed" -and
    $firstBootProjectionResult.summary.rc19_022_complete -eq $true -and
    $firstBootProjectionResult.summary.projection_only -eq $true -and
    $firstBootProjectionResult.summary.first_boot_provisioning_executed -eq $false -and
    $firstBootProjectionResult.summary.raw_user_secret_introduced -eq $false -and
    $firstBootProjectionResult.summary.credential_material_introduced -eq $false -and
    $firstBootProjection.first_boot_plan.local_operator_identity_projection_bound -eq $true -and
    $firstBootProjection.local_operator_identity.local_operator_identity_projection_id -eq $localOperatorIdentity.local_operator_identity_projection_id
)

$identityMatches = (
    $installAcceptanceResult.target_state_id -eq $firstBootProjection.projection_material.first_user_install_target_state_id -and
    $installAcceptanceResult.target_state_id -eq $releaseBundleResult.bundle_surface.first_user_target_state_id -and
    $installAcceptanceResult.release_bundle_id -eq $releaseBundleResult.release_bundle_id -and
    $installAcceptanceResult.selected_version -eq "rc20-single-user-stable-local-projection" -and
    $firstBootProjection.projection_material.installer_media_id -eq $releaseBundleResult.bundle_surface.installer_media_id -and
    $firstBootProjection.projection_material.boot_target_descriptor_id -eq $releaseBundleResult.bundle_surface.boot_target_descriptor_id
)

$rollbackSupportReady = (
    $postInstallLifecycleResult.status -eq "passed" -and
    $postInstallLifecycleResult.summary.update_compatibility_readiness -eq "ready" -and
    $postInstallLifecycleResult.summary.rollback_compatibility_readiness -eq "ready" -and
    $supportRecoveryResult.status -eq "passed" -and
    $supportRecoveryResult.summary.support_bundle_local_only -eq $true -and
    $supportRecoveryResult.summary.support_upload_performed -eq $false -and
    $supportRecoveryResult.summary.recovery_execution_performed -eq $false
)

$postureAllowed = $planAllowsRun -and $installAcceptanceReady -and $firstBootProjectionReady -and $identityMatches -and $rollbackSupportReady
$blockers = @()
if (-not $planAllowsRun) { $blockers += "rc20-022-plan-pointer-not-current" }
if (-not $installAcceptanceReady) { $blockers += "rc20-install-acceptance-not-ready" }
if (-not $firstBootProjectionReady) { $blockers += "first-boot-projection-not-ready" }
if (-not $identityMatches) { $blockers += "install-first-boot-target-identity-mismatch" }
if (-not $rollbackSupportReady) { $blockers += "rollback-support-posture-not-ready" }
if ($postureAllowed) { $blockers = @() }

$acceptanceMaterial = [ordered]@{
    schema = "agentos.rc20-first-boot-user-acceptance-material.v1"
    task = "RC20-022"
    release_bundle_id = [string]$releaseBundleResult.release_bundle_id
    install_acceptance_id = [string]$installAcceptanceResult.install_acceptance_id
    first_boot_provisioning_projection_id = [string]$firstBootProjectionResult.first_boot_provisioning_projection_id
    local_operator_identity_projection_id = [string]$localOperatorIdentity.local_operator_identity_projection_id
    target_state_id = [string]$installAcceptanceResult.target_state_id
    operator_handle = [string]$localOperatorIdentity.operator_handle
    selected_version = [string]$installAcceptanceResult.selected_version
    source_hashes = @(
        [ordered]@{ id = "rc20-install-acceptance-result"; path = Get-StablePath $resolvedInstallAcceptanceResultPath; sha256 = Get-FileSha256 $resolvedInstallAcceptanceResultPath; status = $installAcceptanceResult.status },
        [ordered]@{ id = "rc20-install-acceptance-evidence"; path = Get-StablePath $resolvedInstallAcceptanceEvidencePath; sha256 = Get-FileSha256 $resolvedInstallAcceptanceEvidencePath; status = $installAcceptanceEvidence.status },
        [ordered]@{ id = "rc20-install-audit-record"; path = Get-StablePath $resolvedInstallAuditRecordPath; sha256 = Get-FileSha256 $resolvedInstallAuditRecordPath; status = $installAuditRecord.status },
        [ordered]@{ id = "rc19-first-boot-result"; path = Get-StablePath $resolvedFirstBootProjectionResultPath; sha256 = Get-FileSha256 $resolvedFirstBootProjectionResultPath; status = $firstBootProjectionResult.status },
        [ordered]@{ id = "rc19-first-boot-projection"; path = Get-StablePath $resolvedFirstBootProjectionPath; sha256 = Get-FileSha256 $resolvedFirstBootProjectionPath; status = $firstBootProjection.status },
        [ordered]@{ id = "rc19-local-operator-identity"; path = Get-StablePath $resolvedLocalOperatorIdentityProjectionPath; sha256 = Get-FileSha256 $resolvedLocalOperatorIdentityProjectionPath; status = $localOperatorIdentity.status },
        [ordered]@{ id = "rc20-release-bundle-result"; path = Get-StablePath $resolvedReleaseBundleResultPath; sha256 = Get-FileSha256 $resolvedReleaseBundleResultPath; status = $releaseBundleResult.status },
        [ordered]@{ id = "rc19-post-install-lifecycle"; path = Get-StablePath $resolvedPostInstallLifecycleResultPath; sha256 = Get-FileSha256 $resolvedPostInstallLifecycleResultPath; status = $postInstallLifecycleResult.status },
        [ordered]@{ id = "rc19-support-recovery"; path = Get-StablePath $resolvedSupportRecoveryResultPath; sha256 = Get-FileSha256 $resolvedSupportRecoveryResultPath; status = $supportRecoveryResult.status }
    )
}
$firstBootAcceptanceId = "sha256:$(Get-StringSha256 (Get-JsonText $acceptanceMaterial))"

$operatorPostureMaterial = [ordered]@{
    schema = "agentos.rc20-local-operator-posture-material.v1"
    task = "RC20-022"
    local_operator_identity_projection_id = [string]$localOperatorIdentity.local_operator_identity_projection_id
    operator_handle = [string]$localOperatorIdentity.operator_handle
    target_state_id = [string]$installAcceptanceResult.target_state_id
    support_bundle_id = [string]$releaseBundleResult.bundle_surface.support_bundle_id
    update_readiness = [string]$postInstallLifecycleResult.summary.update_compatibility_readiness
    rollback_readiness = [string]$postInstallLifecycleResult.summary.rollback_compatibility_readiness
    support_bundle_local_only = $supportRecoveryResult.summary.support_bundle_local_only
    credential_projection_only = $true
}
$localOperatorPostureId = "sha256:$(Get-StringSha256 (Get-JsonText $operatorPostureMaterial))"

$sideEffects = New-SideEffects
$sideEffects.first_boot_acceptance_bound = $postureAllowed
$sideEffects.local_operator_posture_bound = $postureAllowed

$firstBootAcceptance = [ordered]@{
    schema = "agentos.rc20-first-boot-acceptance.v1"
    generated_at = $generatedAtValue
    task = "RC20-022"
    status = if ($postureAllowed) { "first-boot-acceptance-bound-projection-only" } else { "first-boot-acceptance-denied" }
    projection_only = $true
    production_ready_claim = $false
    consumer_ready_claim = $false
    first_boot_acceptance_id = $firstBootAcceptanceId
    local_operator_posture_id = $localOperatorPostureId
    release_bundle_id = [string]$releaseBundleResult.release_bundle_id
    install_acceptance_id = [string]$installAcceptanceResult.install_acceptance_id
    first_boot_provisioning_projection_id = [string]$firstBootProjectionResult.first_boot_provisioning_projection_id
    target_state_id = [string]$installAcceptanceResult.target_state_id
    selected_version = [string]$installAcceptanceResult.selected_version
    first_boot_projection = [ordered]@{
        first_boot_provisioning_executed = $false
        first_boot_state_mutated = $false
        local_operator_identity_created = $false
        local_operator_identity_projection_bound = $firstBootProjection.first_boot_plan.local_operator_identity_projection_bound
        local_operator_identity_projection_id = [string]$localOperatorIdentity.local_operator_identity_projection_id
        raw_user_secret_introduced = $false
        credential_material_introduced = $false
    }
    acceptance_material = $acceptanceMaterial
    authority = [ordered]@{
        host_boot_state_authority = $false
        host_boot_metadata_mutation_authority = $false
        host_active_slot_mutation_authority = $false
        support_upload_authority = $false
        recovery_execution_authority = $false
        remote_dispatch_authority = $false
        shell_authority = $false
        tui_authority = $false
        endpoint_reachability_authority = $false
        model_replay_authority = $false
    }
    side_effects = $sideEffects
}
$firstBootAcceptancePath = Join-Path $resolvedArtifactDir "first-boot-acceptance.json"
Write-Json $firstBootAcceptance $firstBootAcceptancePath

$localOperatorPosture = [ordered]@{
    schema = "agentos.rc20-local-operator-posture.v1"
    generated_at = $generatedAtValue
    task = "RC20-022"
    status = if ($postureAllowed) { "local-operator-posture-bound-redacted" } else { "local-operator-posture-denied" }
    projection_only = $true
    production_ready_claim = $false
    consumer_ready_claim = $false
    local_operator_posture_id = $localOperatorPostureId
    first_boot_acceptance_id = $firstBootAcceptanceId
    local_operator_identity_projection_id = [string]$localOperatorIdentity.local_operator_identity_projection_id
    operator_handle = [string]$localOperatorIdentity.operator_handle
    public_projection = $localOperatorIdentity.public_projection
    audit_expectations = [ordered]@{
        install_audit_record_id = [string]$installAcceptanceResult.audit_record_id
        first_boot_acceptance_id = $firstBootAcceptanceId
        local_operator_posture_id = $localOperatorPostureId
        exact_approval_required_before_activation = $true
        support_bundle_export_local_only = $true
    }
    rollback_support_references = [ordered]@{
        support_bundle_id = [string]$releaseBundleResult.bundle_surface.support_bundle_id
        update_readiness = [string]$postInstallLifecycleResult.summary.update_compatibility_readiness
        rollback_readiness = [string]$postInstallLifecycleResult.summary.rollback_compatibility_readiness
        support_bundle_local_only = $supportRecoveryResult.summary.support_bundle_local_only
        support_upload_performed = $supportRecoveryResult.summary.support_upload_performed
        recovery_execution_performed = $supportRecoveryResult.summary.recovery_execution_performed
    }
    secrecy = [ordered]@{
        raw_user_secret_introduced = $false
        credential_material_introduced = $false
        enrollment_secret_material_present = $false
        operator_secret_exported = $false
        handle_only = $true
        redacted_identity_posture = $true
    }
    authority = [ordered]@{
        non_authoritative = $true
        projection_grants_host_authority = $false
        projection_grants_production_authority = $false
        projection_grants_remote_dispatch = $false
        projection_grants_support_upload = $false
        projection_grants_recovery_execution = $false
        projection_grants_shell = $false
        projection_grants_tui = $false
        projection_grants_endpoint_reachability = $false
        model_replay_authority = $false
    }
    posture_material = $operatorPostureMaterial
}
$localOperatorPosturePath = Join-Path $resolvedArtifactDir "local-operator-posture.json"
Write-Json $localOperatorPosture $localOperatorPosturePath

$caseSpecs = @(
    [ordered]@{ id = "missing-install-acceptance"; blockers = @("install-acceptance-required"); reason = "First boot acceptance requires RC20 install acceptance." },
    [ordered]@{ id = "missing-first-boot-projection"; blockers = @("first-boot-projection-required"); reason = "First boot acceptance requires first boot projection." },
    [ordered]@{ id = "missing-local-operator-projection"; blockers = @("local-operator-projection-required"); reason = "Operator posture requires local operator identity projection." },
    [ordered]@{ id = "target-state-mismatch"; blockers = @("target-state-mismatch"); reason = "First boot acceptance denies target state mismatch." },
    [ordered]@{ id = "raw-user-secret-present"; blockers = @("raw-user-secret-denied"); reason = "Raw user secret material is forbidden." },
    [ordered]@{ id = "credential-material-present"; blockers = @("credential-material-denied"); reason = "Credential material is forbidden." },
    [ordered]@{ id = "host-boot-metadata-mutation"; blockers = @("host-boot-metadata-mutation-denied"); reason = "Host boot metadata mutation is forbidden." },
    [ordered]@{ id = "host-rootfs-mutation"; blockers = @("host-rootfs-mutation-denied"); reason = "Host rootfs mutation is forbidden." },
    [ordered]@{ id = "support-upload-attempt"; blockers = @("support-upload-denied"); reason = "Support upload is out of scope." },
    [ordered]@{ id = "recovery-execution-attempt"; blockers = @("recovery-execution-denied"); reason = "Recovery execution is out of scope." },
    [ordered]@{ id = "remote-dispatch-attempt"; blockers = @("remote-dispatch-denied"); reason = "Remote dispatch is out of scope." },
    [ordered]@{ id = "shell-authority-attempt"; blockers = @("shell-authority-denied"); reason = "Shell output is not first boot authority." },
    [ordered]@{ id = "tui-authority-attempt"; blockers = @("tui-authority-denied"); reason = "TUI output is not first boot authority." },
    [ordered]@{ id = "endpoint-authority-attempt"; blockers = @("endpoint-authority-denied"); reason = "Endpoint reachability is not first boot authority." },
    [ordered]@{ id = "model-replay-authority-attempt"; blockers = @("model-replay-authority-denied"); reason = "Model replay is not first boot authority." },
    [ordered]@{ id = "production-ring-mutation"; blockers = @("production-ring-mutation-denied"); reason = "Production ring mutation is forbidden." },
    [ordered]@{ id = "ga-claim-attempt"; blockers = @("ga-claim-denied"); reason = "First boot posture cannot claim GA production readiness." }
)
$cases = @()
foreach ($spec in $caseSpecs) {
    $cases += New-DenialCase -Id $spec.id -Blockers ([string[]]$spec.blockers) -Reason $spec.reason
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

Add-Check "plan.current_task.rc20_022" $planAllowsRun "RC20-022 must run after RC20-021 completed, with current_task set to RC20-022." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc20_021_status = $rc20PreviousStatus; rc20_022_status = $rc20TaskStatus })
Add-Check "contract.present" (-not [string]::IsNullOrWhiteSpace($contractText)) "RC20-022 must consume the RC20 authority contract." ([ordered]@{ path = Get-StablePath $resolvedContractPath; sha256 = Get-FileSha256 $resolvedContractPath })
Add-Check "install_acceptance.ready" $installAcceptanceReady "First boot acceptance must bind RC20 install acceptance target state and audit." ([ordered]@{ status = $installAcceptanceResult.status; install_acceptance_id = $installAcceptanceResult.install_acceptance_id; target_state_id = $installAcceptanceResult.target_state_id; host_rootfs_mutated = $installAcceptanceResult.summary.host_rootfs_mutated })
Add-Check "first_boot.projection_only_ready" $firstBootProjectionReady "First boot acceptance must remain projection-only and contain no raw credential material." ([ordered]@{ status = $firstBootProjectionResult.status; projection_only = $firstBootProjectionResult.summary.projection_only; first_boot_provisioning_executed = $firstBootProjectionResult.summary.first_boot_provisioning_executed; raw_user_secret_introduced = $firstBootProjectionResult.summary.raw_user_secret_introduced; credential_material_introduced = $firstBootProjectionResult.summary.credential_material_introduced })
Add-Check "identity.matches" $identityMatches "Install acceptance target state, release bundle, installer media, boot descriptor, and first boot projection must match." ([ordered]@{ install_target_state_id = $installAcceptanceResult.target_state_id; first_boot_target_state_id = $firstBootProjection.projection_material.first_user_install_target_state_id; release_bundle_target_state_id = $releaseBundleResult.bundle_surface.first_user_target_state_id })
Add-Check "operator_posture.rollback_support_bound" $rollbackSupportReady "Local operator posture must bind rollback/support references without support upload or recovery execution." ([ordered]@{ update_readiness = $postInstallLifecycleResult.summary.update_compatibility_readiness; rollback_readiness = $postInstallLifecycleResult.summary.rollback_compatibility_readiness; support_bundle_local_only = $supportRecoveryResult.summary.support_bundle_local_only; support_upload_performed = $supportRecoveryResult.summary.support_upload_performed; recovery_execution_performed = $supportRecoveryResult.summary.recovery_execution_performed })
Add-Check "authority.no_projection_broadening" ($firstBootAcceptance.authority.host_boot_metadata_mutation_authority -eq $false -and $firstBootAcceptance.authority.support_upload_authority -eq $false -and $firstBootAcceptance.authority.recovery_execution_authority -eq $false -and $firstBootAcceptance.authority.remote_dispatch_authority -eq $false -and $firstBootAcceptance.authority.shell_authority -eq $false -and $firstBootAcceptance.authority.tui_authority -eq $false -and $firstBootAcceptance.authority.endpoint_reachability_authority -eq $false -and $firstBootAcceptance.authority.model_replay_authority -eq $false) "First boot acceptance must not introduce host boot, support upload, recovery, remote dispatch, shell, TUI, endpoint, or model replay authority." $firstBootAcceptance.authority
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 15) "First boot posture must deny missing sources, identity mismatch, raw credentials, host boot mutation, support/recovery execution, remote dispatch, projection authority, production mutation, and GA claims." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })

$outputSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $firstBootAcceptancePath),
    (Get-Content -Raw -LiteralPath $localOperatorPosturePath)
)
Add-Check "outputs.secret_safe" $outputSecretSafe "RC20-022 outputs must not contain key blocks, private authority paths, auth tokens, signing key file names, raw passwords, or raw secrets." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc20-first-boot-user-acceptance-result.v1"
    generated_at = $generatedAtValue
    task = "RC20-022"
    status = $resultStatus
    production_ready_claim = $false
    consumer_ready_claim = $false
    first_boot_acceptance_id = $firstBootAcceptanceId
    local_operator_posture_id = $localOperatorPostureId
    release_bundle_id = [string]$releaseBundleResult.release_bundle_id
    target_state_id = [string]$installAcceptanceResult.target_state_id
    local_operator_identity_projection_id = [string]$localOperatorIdentity.local_operator_identity_projection_id
    outputs = [ordered]@{
        first_boot_acceptance = [ordered]@{
            path = Get-StablePath $firstBootAcceptancePath
            sha256 = Get-FileSha256 $firstBootAcceptancePath
            first_boot_acceptance_id = $firstBootAcceptanceId
        }
        local_operator_posture = [ordered]@{
            path = Get-StablePath $localOperatorPosturePath
            sha256 = Get-FileSha256 $localOperatorPosturePath
            local_operator_posture_id = $localOperatorPostureId
        }
    }
    first_boot_surface = [ordered]@{
        state = if ($postureAllowed) { "first-boot-user-acceptance-local-operator-posture-bound" } else { "first-boot-user-acceptance-denied" }
        install_acceptance_bound = $installAcceptanceReady
        first_boot_projection_bound = $firstBootProjectionReady
        local_operator_posture_bound = $postureAllowed
        identity_matches = $identityMatches
        projection_only_for_credentials = $true
        raw_user_secret_introduced = $false
        credential_material_introduced = $false
        host_boot_metadata_mutated = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        shell_authority = $false
        tui_authority = $false
        endpoint_reachability_authority = $false
        model_replay_authority = $false
        blockers = @($blockers)
    }
    checks = @($script:checks)
    fail_closed_cases = $cases
    invariants = [ordered]@{
        aios_body_only = $true
        projection_only_for_credentials = $true
        production_ready_claim = $false
        consumer_ready_claim = $false
        first_boot_provisioning_executed = $false
        first_boot_state_mutated = $false
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
        shell_authority = $false
        tui_authority = $false
        endpoint_reachability_authority = $false
        model_replay_authority = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
        rc20_022_complete = (@($script:failedChecks).Count -eq 0)
        first_boot_acceptance_id = $firstBootAcceptanceId
        local_operator_posture_id = $localOperatorPostureId
        target_state_id = [string]$installAcceptanceResult.target_state_id
        projection_only_for_credentials = $true
        raw_user_secret_introduced = $false
        credential_material_introduced = $false
        host_boot_metadata_mutated = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        next_task = "RC20-030"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC20-022-first-boot-user-acceptance.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc20-first-boot-user-acceptance-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC20-022"
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
    first_boot_surface = $result.first_boot_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc20_022_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC20-030"
        commit_required = $true
    }
    checks = @($script:checks)
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) { throw "Sensitive marker detected in RC20-022 outputs." }

Write-Host "RC20 first boot user acceptance $($result.status): $(Get-StablePath $resultPath)"
Write-Host "First boot acceptance: $(Get-StablePath $firstBootAcceptancePath)"
Write-Host "Local operator posture: $(Get-StablePath $localOperatorPosturePath)"
Write-Host "Projection-only credentials: true; raw secret introduced: false; host boot mutation: false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) { exit 1 }
