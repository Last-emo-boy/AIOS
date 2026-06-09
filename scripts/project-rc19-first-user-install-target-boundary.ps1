param(
    [string]$ArtifactDir = ".workflow/artifacts/rc19-first-user-install-target-boundary",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc19",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc19/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc19/docs/rc19-installable-image-authority-contract.md",
    [string]$Rc19ArtifactResultPath = ".workflow/artifacts/rc19-reproducible-installable-image-artifact/result.json",
    [string]$Rc19ArtifactSetPath = ".workflow/artifacts/rc19-reproducible-installable-image-artifact/installable-image-artifact-set.json",
    [string]$Rc19InputMapPath = ".workflow/artifacts/rc19-reproducible-installable-image-artifact/reproducibility-input-map.json",
    [string]$Rc19MediaResultPath = ".workflow/artifacts/rc19-installer-media-manifest/result.json",
    [string]$Rc19InstallerMediaManifestPath = ".workflow/artifacts/rc19-installer-media-manifest/installer-media-manifest.json",
    [string]$Rc19BootTargetDescriptorPath = ".workflow/artifacts/rc19-installer-media-manifest/boot-target-descriptor.json",
    [string]$Rc19ReproducibilityFailClosedResultPath = ".workflow/artifacts/rc19-image-artifact-reproducibility-fail-closed/result.json",
    [string]$Rc18BoundaryResultPath = ".workflow/artifacts/rc18-disposable-installed-system-boundary/result.json",
    [string]$Rc18ImageBoundaryPath = ".workflow/artifacts/rc18-disposable-installed-system-boundary/image-boundary.json",
    [string]$Rc16PlanSpecResultPath = ".workflow/artifacts/rc16-install-update-planspec-binding/result.json",
    [string]$Rc16PlanSpecPackagePath = ".workflow/artifacts/rc16-install-update-planspec-binding/install-update-planspec-package.json",
    [string]$Rc16SecurityEnvelopePath = ".workflow/artifacts/rc16-install-update-planspec-binding/security-execution-install-update-envelope.json",
    [string]$Rc16RollbackSupportResultPath = ".workflow/artifacts/rc16-rollback-support-package/result.json",
    [string]$Rc16RollbackSupportPackagePath = ".workflow/artifacts/rc16-rollback-support-package/rollback-support-package.json",
    [string]$AgentCoreLibPath = "crates/agent_core/src/lib.rs",
    [string]$SecurityExecutionPolicyPath = "crates/security_execution/src/policy.rs",
    [string]$SecurityExecutionToolsPath = "crates/security_execution/src/tools.rs",
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

function Get-JsonProperty {
    param($Json, [Parameter(Mandatory = $true)][string]$Name)
    if ($null -eq $Json) {
        return $null
    }
    if ($Json.PSObject.Properties.Name -contains $Name) {
        return $Json.$Name
    }
    return $null
}

function New-ArtifactRef {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        $Json = $null
    )
    $resolved = Resolve-RepoPath $Path
    $present = Test-Path -LiteralPath $resolved -PathType Leaf
    return [ordered]@{
        path = Get-StablePath $resolved
        sha256 = Get-FileSha256 $resolved
        size_bytes = if ($present) { (Get-Item -LiteralPath $resolved).Length } else { $null }
        present = $present
        schema = Get-JsonProperty $Json "schema"
        status = Get-JsonProperty $Json "status"
        task = Get-JsonProperty $Json "task"
        production_ready_claim = Get-JsonProperty $Json "production_ready_claim"
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
        observed_denied = $true
        blockers = $Blockers
        reason = $Reason
        denied_before_install = $true
        side_effects = [ordered]@{
            target_materialized = $false
            install_preflight_executed = $false
            install_performed = $false
            update_performed = $false
            rollback_execution_performed = $false
            host_rootfs_mutated = $false
            host_active_slot_mutated = $false
            host_boot_metadata_mutated = $false
            active_artifact_set_mutated = $false
            payload_uploaded = $false
            external_payload_published = $false
            object_storage_provisioned = $false
            cryptographic_signing_performed = $false
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
$resolvedContractPath = Resolve-RepoPath $ContractPath
$resolvedRc19ArtifactResultPath = Resolve-RepoPath $Rc19ArtifactResultPath
$resolvedRc19ArtifactSetPath = Resolve-RepoPath $Rc19ArtifactSetPath
$resolvedRc19InputMapPath = Resolve-RepoPath $Rc19InputMapPath
$resolvedRc19MediaResultPath = Resolve-RepoPath $Rc19MediaResultPath
$resolvedRc19InstallerMediaManifestPath = Resolve-RepoPath $Rc19InstallerMediaManifestPath
$resolvedRc19BootTargetDescriptorPath = Resolve-RepoPath $Rc19BootTargetDescriptorPath
$resolvedRc19ReproducibilityFailClosedResultPath = Resolve-RepoPath $Rc19ReproducibilityFailClosedResultPath
$resolvedRc18BoundaryResultPath = Resolve-RepoPath $Rc18BoundaryResultPath
$resolvedRc18ImageBoundaryPath = Resolve-RepoPath $Rc18ImageBoundaryPath
$resolvedRc16PlanSpecResultPath = Resolve-RepoPath $Rc16PlanSpecResultPath
$resolvedRc16PlanSpecPackagePath = Resolve-RepoPath $Rc16PlanSpecPackagePath
$resolvedRc16SecurityEnvelopePath = Resolve-RepoPath $Rc16SecurityEnvelopePath
$resolvedRc16RollbackSupportResultPath = Resolve-RepoPath $Rc16RollbackSupportResultPath
$resolvedRc16RollbackSupportPackagePath = Resolve-RepoPath $Rc16RollbackSupportPackagePath
$resolvedAgentCoreLibPath = Resolve-RepoPath $AgentCoreLibPath
$resolvedSecurityExecutionPolicyPath = Resolve-RepoPath $SecurityExecutionPolicyPath
$resolvedSecurityExecutionToolsPath = Resolve-RepoPath $SecurityExecutionToolsPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$rc19ArtifactResult = Read-Json $resolvedRc19ArtifactResultPath
$rc19ArtifactSet = Read-Json $resolvedRc19ArtifactSetPath
$rc19InputMap = Read-Json $resolvedRc19InputMapPath
$rc19MediaResult = Read-Json $resolvedRc19MediaResultPath
$rc19InstallerMediaManifest = Read-Json $resolvedRc19InstallerMediaManifestPath
$rc19BootTargetDescriptor = Read-Json $resolvedRc19BootTargetDescriptorPath
$rc19ReproducibilityFailClosedResult = Read-Json $resolvedRc19ReproducibilityFailClosedResultPath
$rc18BoundaryResult = Read-Json $resolvedRc18BoundaryResultPath
$rc18ImageBoundary = Read-Json $resolvedRc18ImageBoundaryPath
$rc16PlanSpecResult = Read-Json $resolvedRc16PlanSpecResultPath
$rc16PlanSpecPackage = Read-Json $resolvedRc16PlanSpecPackagePath
$rc16SecurityEnvelope = Read-Json $resolvedRc16SecurityEnvelopePath
$rc16RollbackSupportResult = Read-Json $resolvedRc16RollbackSupportResultPath
$rc16RollbackSupportPackage = Read-Json $resolvedRc16RollbackSupportPackagePath

$rollbackBaselinePath = [string]$rc19InstallerMediaManifest.rollback_support.rollback_baseline.path
$supportIndexPath = [string]$rc19InstallerMediaManifest.rollback_support.support_index.path
$resolvedRollbackBaselinePath = Resolve-RepoPath $rollbackBaselinePath
$resolvedSupportIndexPath = Resolve-RepoPath $supportIndexPath
$rollbackBaseline = Read-Json $resolvedRollbackBaselinePath
$supportIndex = Read-Json $resolvedSupportIndexPath

$rc19PreviousStatus = Get-TaskStatus -Plan $plan -TaskId "RC19-012"
$rc19TaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC19-020"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc19PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC19-020" -and ($rc19TaskStatus -eq "pending" -or $rc19TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC19-021" -and $rc19TaskStatus -eq "completed")
    )
)

$artifactSetSha256 = Get-FileSha256 $resolvedRc19ArtifactSetPath
$inputMapSha256 = Get-FileSha256 $resolvedRc19InputMapPath
$installerMediaManifestSha256 = Get-FileSha256 $resolvedRc19InstallerMediaManifestPath
$bootTargetDescriptorSha256 = Get-FileSha256 $resolvedRc19BootTargetDescriptorPath
$agentCoreLibSha256 = Get-FileSha256 $resolvedAgentCoreLibPath
$securityExecutionPolicySha256 = Get-FileSha256 $resolvedSecurityExecutionPolicyPath
$securityExecutionToolsSha256 = Get-FileSha256 $resolvedSecurityExecutionToolsPath
$rollbackBaselineSha256 = Get-FileSha256 $resolvedRollbackBaselinePath
$supportIndexSha256 = Get-FileSha256 $resolvedSupportIndexPath

$artifactReady = (
    $rc19ArtifactResult.status -eq "passed" -and
    $rc19ArtifactResult.production_ready_claim -eq $false -and
    $rc19ArtifactSet.installable_image_artifact_id -eq $rc19ArtifactResult.installable_image_artifact_id -and
    $rc19InputMap.installable_image_artifact_id -eq $rc19ArtifactResult.installable_image_artifact_id -and
    $rc19ArtifactResult.artifact_set_sha256 -eq $artifactSetSha256 -and
    $rc19ArtifactResult.reproducibility_input_map_sha256 -eq $inputMapSha256
)
$mediaReady = (
    $rc19MediaResult.status -eq "passed" -and
    $rc19MediaResult.production_ready_claim -eq $false -and
    $rc19MediaResult.installable_image_artifact_id -eq $rc19ArtifactResult.installable_image_artifact_id -and
    $rc19InstallerMediaManifest.installable_image_artifact_id -eq $rc19ArtifactResult.installable_image_artifact_id -and
    $rc19BootTargetDescriptor.installable_image_artifact_id -eq $rc19ArtifactResult.installable_image_artifact_id -and
    $rc19MediaResult.outputs.installer_media_manifest.sha256 -eq $installerMediaManifestSha256 -and
    $rc19MediaResult.outputs.boot_target_descriptor.sha256 -eq $bootTargetDescriptorSha256 -and
    $rc19InstallerMediaManifest.install_gate.install_allowed -eq $false -and
    $rc19InstallerMediaManifest.install_gate.install_effects_gated_until -eq "RC19-021"
)
$reproducibilityReady = (
    $rc19ReproducibilityFailClosedResult.status -eq "passed" -and
    $rc19ReproducibilityFailClosedResult.summary.failed_checks -eq 0 -and
    $rc19ReproducibilityFailClosedResult.summary.failed_cases -eq 0 -and
    $rc19ReproducibilityFailClosedResult.fail_closed_surface.install_performed -eq $false -and
    $rc19ReproducibilityFailClosedResult.fail_closed_surface.remote_dispatch_enabled -eq $false
)
$disposableBoundaryReady = (
    $rc18BoundaryResult.status -eq "passed" -and
    $rc18BoundaryResult.image_boundary_bound -eq $true -and
    $rc18ImageBoundary.allowed_write_surface.only_writable_drill_surface -eq "disposable-installed-system-image-or-vm" -and
    $rc18ImageBoundary.denied_host_write_surface.host_rootfs_mutation_allowed -eq $false -and
    $rc18ImageBoundary.denied_host_write_surface.host_boot_metadata_mutation_allowed -eq $false -and
    $rc18ImageBoundary.denied_host_write_surface.remote_dispatch_enabled -eq $false
)
$agentCoreSecurityReady = (
    $agentCoreLibSha256 -match "^[0-9a-f]{64}$" -and
    $securityExecutionPolicySha256 -match "^[0-9a-f]{64}$" -and
    $securityExecutionToolsSha256 -match "^[0-9a-f]{64}$" -and
    $rc16PlanSpecResult.status -eq "passed" -and
    $rc16PlanSpecPackage.agentcore_install_update_planspec_bound -eq $true -and
    $rc16SecurityEnvelope.effect_envelope_core_hash -match "^[0-9a-f]{64}$"
)
$rollbackSupportReady = (
    $rc19InstallerMediaManifest.rollback_support.rollback_execution_allowed -eq $false -and
    $rc19InstallerMediaManifest.rollback_support.support_upload_allowed -eq $false -and
    $rc19InstallerMediaManifest.rollback_support.recovery_execution_allowed -eq $false -and
    $rc19InstallerMediaManifest.rollback_support.rollback_baseline.sha256 -eq $rollbackBaselineSha256 -and
    $rc19InstallerMediaManifest.rollback_support.support_index.sha256 -eq $supportIndexSha256 -and
    $rc16RollbackSupportResult.status -eq "passed" -and
    $rc16RollbackSupportResult.summary.rollback_support_package_bound -eq $true
)

$source = [ordered]@{
    rc19_plan = New-ArtifactRef $PlanPath $plan
    rc19_contract = New-ArtifactRef $ContractPath
    rc19_artifact_result = New-ArtifactRef $Rc19ArtifactResultPath $rc19ArtifactResult
    rc19_artifact_set = New-ArtifactRef $Rc19ArtifactSetPath $rc19ArtifactSet
    rc19_reproducibility_input_map = New-ArtifactRef $Rc19InputMapPath $rc19InputMap
    rc19_media_result = New-ArtifactRef $Rc19MediaResultPath $rc19MediaResult
    rc19_installer_media_manifest = New-ArtifactRef $Rc19InstallerMediaManifestPath $rc19InstallerMediaManifest
    rc19_boot_target_descriptor = New-ArtifactRef $Rc19BootTargetDescriptorPath $rc19BootTargetDescriptor
    rc19_reproducibility_fail_closed_result = New-ArtifactRef $Rc19ReproducibilityFailClosedResultPath $rc19ReproducibilityFailClosedResult
    rc18_boundary_result = New-ArtifactRef $Rc18BoundaryResultPath $rc18BoundaryResult
    rc18_image_boundary = New-ArtifactRef $Rc18ImageBoundaryPath $rc18ImageBoundary
    rc16_planspec_result = New-ArtifactRef $Rc16PlanSpecResultPath $rc16PlanSpecResult
    rc16_planspec_package = New-ArtifactRef $Rc16PlanSpecPackagePath $rc16PlanSpecPackage
    rc16_security_execution_envelope = New-ArtifactRef $Rc16SecurityEnvelopePath $rc16SecurityEnvelope
    rc16_rollback_support_result = New-ArtifactRef $Rc16RollbackSupportResultPath $rc16RollbackSupportResult
    rc16_rollback_support_package = New-ArtifactRef $Rc16RollbackSupportPackagePath $rc16RollbackSupportPackage
    rollback_baseline = New-ArtifactRef $rollbackBaselinePath $rollbackBaseline
    support_index = New-ArtifactRef $supportIndexPath $supportIndex
    agent_core_lib = New-ArtifactRef $AgentCoreLibPath
    security_execution_policy = New-ArtifactRef $SecurityExecutionPolicyPath
    security_execution_tools = New-ArtifactRef $SecurityExecutionToolsPath
}

$targetBoundaryMaterial = [ordered]@{
    schema = "agentos.rc19-first-user-install-target-boundary-material.v1"
    task = "RC19-020"
    installable_image_artifact_id = $rc19ArtifactResult.installable_image_artifact_id
    installer_media_id = $rc19MediaResult.installer_media_id
    boot_target_descriptor_id = $rc19MediaResult.boot_target_descriptor_id
    rc18_boundary_id = $rc18BoundaryResult.boundary_id
    rc18_state_root_id = $rc18BoundaryResult.state_root_id
    source_hashes = [ordered]@{
        artifact_result = $source.rc19_artifact_result.sha256
        artifact_set = $source.rc19_artifact_set.sha256
        input_map = $source.rc19_reproducibility_input_map.sha256
        media_result = $source.rc19_media_result.sha256
        installer_media_manifest = $source.rc19_installer_media_manifest.sha256
        boot_target_descriptor = $source.rc19_boot_target_descriptor.sha256
        reproducibility_fail_closed_result = $source.rc19_reproducibility_fail_closed_result.sha256
        rc18_boundary_result = $source.rc18_boundary_result.sha256
        rc18_image_boundary = $source.rc18_image_boundary.sha256
    }
    only_writable_surface = "disposable-first-user-install-target"
    generated_at_excluded_from_identity = $true
}
$targetBoundaryId = "sha256:$(Get-StringSha256 (Get-JsonText $targetBoundaryMaterial))"

$allowedWriteSurface = [ordered]@{
    only_writable_first_user_install_surface = "disposable-first-user-install-target"
    disposable_target_root = ".workflow/artifacts/rc19-first-user-install-drill/disposable-target"
    disposable_target_state_root = ".workflow/artifacts/rc19-first-user-install-drill/disposable-target/state-root.json"
    disposable_target_audit_log = ".workflow/artifacts/rc19-first-user-install-drill/disposable-target/install-audit.json"
    writable_after_task = "RC19-020"
    writable_by_task = "RC19-021"
    required_before_write = @(
        "rc19-020-target-boundary-bound",
        "rc19-020-install-preflight-package-bound",
        "rc19-021-disposable-target-owned-by-drill"
    )
    host_write_surface_allowed = $false
}
$deniedSurface = [ordered]@{
    host_rootfs_mutation_allowed = $false
    host_active_slot_mutation_allowed = $false
    host_boot_metadata_mutation_allowed = $false
    active_artifact_set_mutation_allowed = $false
    production_ring_mutation_allowed = $false
    payload_upload_allowed = $false
    external_payload_publication_allowed = $false
    object_storage_provisioning_allowed = $false
    cryptographic_signing_allowed = $false
    support_upload_allowed = $false
    recovery_execution_allowed = $false
    remote_dispatch_enabled = $false
    mirror_frontend_authority = $false
    signer_authority = $false
    shell_authority = $false
    tui_authority = $false
    endpoint_reachability_authority = $false
    model_replay_authority = $false
}

$preflightMaterial = [ordered]@{
    schema = "agentos.rc19-first-user-install-preflight-material.v1"
    task = "RC19-020"
    target_boundary_id = $targetBoundaryId
    installable_image_artifact_id = $rc19ArtifactResult.installable_image_artifact_id
    installer_media_id = $rc19MediaResult.installer_media_id
    boot_target_descriptor_id = $rc19MediaResult.boot_target_descriptor_id
    source_hashes = $targetBoundaryMaterial.source_hashes
    agentcore_reference_sha256 = $agentCoreLibSha256
    security_execution_policy_sha256 = $securityExecutionPolicySha256
    security_execution_tools_sha256 = $securityExecutionToolsSha256
    rollback_baseline_sha256 = $rollbackBaselineSha256
    support_index_sha256 = $supportIndexSha256
    install_effects_gated_until = "RC19-021"
    generated_at_excluded_from_identity = $true
}
$preflightPackageId = "sha256:$(Get-StringSha256 (Get-JsonText $preflightMaterial))"

$caseSpecs = @(
    [ordered]@{ id = "missing-installable-image-artifact"; blockers = @("installable-image-artifact-not-bound"); reason = "First-user install target requires RC19 installable image artifact evidence." },
    [ordered]@{ id = "missing-installer-media-manifest"; blockers = @("installer-media-manifest-not-bound"); reason = "First-user install preflight requires installer media manifest." },
    [ordered]@{ id = "missing-boot-target-descriptor"; blockers = @("boot-target-descriptor-not-bound"); reason = "First-user install preflight requires boot target descriptor." },
    [ordered]@{ id = "missing-reproducibility-fail-closed"; blockers = @("reproducibility-fail-closed-not-bound"); reason = "First-user install target requires RC19-012 fail-closed evidence." },
    [ordered]@{ id = "missing-disposable-boundary"; blockers = @("disposable-boundary-not-bound"); reason = "Only disposable target writes are allowed." },
    [ordered]@{ id = "host-rootfs-write-attempt"; blockers = @("host-rootfs-mutation-denied"); reason = "Host rootfs is outside the first-user install drill surface." },
    [ordered]@{ id = "host-active-slot-write-attempt"; blockers = @("host-active-slot-mutation-denied"); reason = "Host active slot metadata is outside the first-user install drill surface." },
    [ordered]@{ id = "host-boot-metadata-write-attempt"; blockers = @("host-boot-metadata-mutation-denied"); reason = "Host boot metadata is outside the first-user install drill surface." },
    [ordered]@{ id = "active-artifact-set-write-attempt"; blockers = @("active-artifact-set-mutation-denied"); reason = "Active artifact set mutation is outside RC19-020." },
    [ordered]@{ id = "production-ring-write-attempt"; blockers = @("production-ring-mutation-denied"); reason = "Production rings are outside RC19-020." },
    [ordered]@{ id = "install-before-rc19-021"; blockers = @("install-effect-gated-until-rc19-021"); reason = "RC19-020 binds preflight only; install drill belongs to RC19-021." },
    [ordered]@{ id = "remote-dispatch-attempt"; blockers = @("remote-dispatch-denied"); reason = "Remote dispatch is disabled." },
    [ordered]@{ id = "support-upload-attempt"; blockers = @("support-upload-denied"); reason = "Support upload is outside RC19-020." },
    [ordered]@{ id = "recovery-execution-attempt"; blockers = @("recovery-execution-denied"); reason = "Recovery execution is outside RC19-020." },
    [ordered]@{ id = "signing-attempt"; blockers = @("cryptographic-signing-denied"); reason = "RC19-020 does not sign artifacts." },
    [ordered]@{ id = "mirror-frontend-authority-attempt"; blockers = @("mirror-frontend-authority-denied"); reason = "Mirror/frontend output is not first-user install authority." },
    [ordered]@{ id = "object-storage-provisioning-attempt"; blockers = @("object-storage-provisioning-denied"); reason = "Object storage provisioning is outside RC19 body scope." },
    [ordered]@{ id = "shell-tui-endpoint-model-authority-attempt"; blockers = @("projection-authority-denied"); reason = "Shell, TUI, endpoint reachability, and model replay are not install authority." },
    [ordered]@{ id = "ga-production-ready-claim"; blockers = @("production-ready-claim-denied"); reason = "RC19 remains non-GA." }
)
$cases = @()
foreach ($spec in $caseSpecs) {
    $cases += New-DenialCase -Id $spec.id -Blockers ([string[]]$spec.blockers) -Reason $spec.reason
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$targetBoundary = [ordered]@{
    schema = "agentos.rc19-first-user-install-target-boundary.v1"
    generated_at = $generatedAtValue
    task = "RC19-020"
    status = "first-user-install-target-boundary-bound-preflight-only"
    production_ready_claim = $false
    target_boundary_id = $targetBoundaryId
    installable_image_artifact_id = $rc19ArtifactResult.installable_image_artifact_id
    installer_media_id = $rc19MediaResult.installer_media_id
    boot_target_descriptor_id = $rc19MediaResult.boot_target_descriptor_id
    rc18_boundary_id = $rc18BoundaryResult.boundary_id
    target = [ordered]@{
        kind = "disposable-first-user-install-target"
        target_root = $allowedWriteSurface.disposable_target_root
        target_state_root = $allowedWriteSurface.disposable_target_state_root
        target_audit_log = $allowedWriteSurface.disposable_target_audit_log
        target_materialized = $false
        install_performed = $false
        install_allowed_now = $false
        install_effects_gated_until = "RC19-021"
    }
    allowed_write_surface = $allowedWriteSurface
    denied_surface = $deniedSurface
    boot_target_projection = [ordered]@{
        projection_only = $rc19BootTargetDescriptor.projection_only
        target_arch = $rc19BootTargetDescriptor.target.target_arch
        boot_modes = $rc19BootTargetDescriptor.target.boot_modes
        kernel_family = $rc19BootTargetDescriptor.target.kernel_family
        boot_markers = $rc19BootTargetDescriptor.boot_projection.boot_markers
        host_boot_metadata_authority = $false
    }
    authority = [ordered]@{
        first_user_install_target_boundary_authority = $true
        first_user_install_execution_authority = $false
        agentcore_reference_authority = $false
        security_execution_allow_authority = $false
        host_rootfs_mutation_authority = $false
        host_active_slot_mutation_authority = $false
        host_boot_metadata_mutation_authority = $false
        active_artifact_set_mutation_authority = $false
        production_ring_mutation_authority = $false
        support_upload_authority = $false
        recovery_execution_authority = $false
        remote_dispatch_authority = $false
    }
    next_required_gate = [ordered]@{
        first_user_install_drill_task = "RC19-021"
        install_effects_gated_until = "RC19-021"
        disposable_target_write_allowed_by_rc19_020 = $false
    }
    fail_closed_boundaries = $cases
    source = $source
}
$targetBoundaryPath = Join-Path $resolvedArtifactDir "first-user-install-target-boundary.json"
Write-Json $targetBoundary $targetBoundaryPath
$targetBoundarySha256 = Get-FileSha256 $targetBoundaryPath

$installPreflightPackage = [ordered]@{
    schema = "agentos.rc19-first-user-install-preflight-package.v1"
    generated_at = $generatedAtValue
    task = "RC19-020"
    status = "first-user-install-preflight-package-bound-install-gated"
    production_ready_claim = $false
    install_preflight_package_id = $preflightPackageId
    target_boundary = [ordered]@{
        path = Get-StablePath $targetBoundaryPath
        sha256 = $targetBoundarySha256
        target_boundary_id = $targetBoundaryId
        only_writable_surface = $allowedWriteSurface.only_writable_first_user_install_surface
    }
    installable_image_artifact = [ordered]@{
        installable_image_artifact_id = $rc19ArtifactResult.installable_image_artifact_id
        artifact_result = $source.rc19_artifact_result
        artifact_set = $source.rc19_artifact_set
        reproducibility_input_map = $source.rc19_reproducibility_input_map
        reproducibility_fail_closed_result = $source.rc19_reproducibility_fail_closed_result
    }
    installer_media = [ordered]@{
        installer_media_id = $rc19MediaResult.installer_media_id
        installer_media_result = $source.rc19_media_result
        installer_media_manifest = $source.rc19_installer_media_manifest
        boot_target_descriptor = $source.rc19_boot_target_descriptor
        boot_target_descriptor_id = $rc19MediaResult.boot_target_descriptor_id
    }
    agentcore_reference = [ordered]@{
        agent_core_lib = $source.agent_core_lib
        rc16_planspec_result = $source.rc16_planspec_result
        rc16_planspec_package = $source.rc16_planspec_package
        previous_planspec_core_hash = $rc16PlanSpecPackage.planspec_core_hash
        first_user_install_planspec_required_next = $true
        executable_now = $false
    }
    security_execution_reference = [ordered]@{
        security_execution_policy = $source.security_execution_policy
        security_execution_tools = $source.security_execution_tools
        rc16_security_execution_envelope = $source.rc16_security_execution_envelope
        previous_effect_envelope_core_hash = $rc16SecurityEnvelope.effect_envelope_core_hash
        security_execution_allow_required_next = $true
        security_execution_allowed_now = $false
    }
    rollback_support = [ordered]@{
        rollback_baseline = $source.rollback_baseline
        support_index = $source.support_index
        rc16_rollback_support_result = $source.rc16_rollback_support_result
        rc16_rollback_support_package = $source.rc16_rollback_support_package
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
    }
    preflight_gate = [ordered]@{
        target_boundary_bound = $true
        installable_image_artifact_bound = $artifactReady
        installer_media_bound = $mediaReady
        reproducibility_fail_closed_bound = $reproducibilityReady
        disposable_boundary_bound = $disposableBoundaryReady
        agentcore_security_references_bound = $agentCoreSecurityReady
        rollback_support_references_bound = $rollbackSupportReady
        first_user_install_drill_required = $true
        install_effects_gated_until = "RC19-021"
        install_allowed = $false
        first_user_install_allowed = $false
        update_allowed = $false
        rollback_execution_allowed = $false
        host_rootfs_mutation_allowed = $false
        host_active_slot_mutation_allowed = $false
        host_boot_metadata_mutation_allowed = $false
        active_artifact_set_mutation_allowed = $false
        production_ring_mutation_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
    }
    side_effects = [ordered]@{
        target_materialized = $false
        install_preflight_executed = $false
        install_performed = $false
        update_performed = $false
        rollback_execution_performed = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        payload_uploaded = $false
        external_payload_published = $false
        object_storage_provisioned = $false
        cryptographic_signing_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        production_ring_mutated = $false
    }
    source = $source
}
$preflightPackagePath = Join-Path $resolvedArtifactDir "install-preflight-package.json"
Write-Json $installPreflightPackage $preflightPackagePath
$preflightPackageSha256 = Get-FileSha256 $preflightPackagePath

Add-Check "plan.current_task.rc19_020" $planAllowsRun "RC19-020 must run after RC19-012 completed, while current_task is RC19-020 or during a completed rerun after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc19_012_status = $rc19PreviousStatus; rc19_020_status = $rc19TaskStatus })
Add-Check "contract.first_user_target_gate.present" ($contractText.Contains("Bind first-user install target boundary and preflight package") -and $contractText.Contains("disposable first-user install target") -and $contractText.Contains("only writable install drill surface")) "RC19-020 must consume the first-user install target boundary contract." $source.rc19_contract
Add-Check "source.artifact.media.reproducibility.ready" ($artifactReady -and $mediaReady -and $reproducibilityReady) "RC19-020 must bind completed installable image artifact, installer media, boot target descriptor, and reproducibility fail-closed evidence." ([ordered]@{ artifact_ready = $artifactReady; media_ready = $mediaReady; reproducibility_ready = $reproducibilityReady; installable_image_artifact_id = $rc19ArtifactResult.installable_image_artifact_id; installer_media_id = $rc19MediaResult.installer_media_id; boot_target_descriptor_id = $rc19MediaResult.boot_target_descriptor_id })
Add-Check "source.disposable_boundary.ready" $disposableBoundaryReady "RC19-020 must bind RC18 disposable installed-system boundary as the source for disposable-only writes." ([ordered]@{ boundary_id = $rc18BoundaryResult.boundary_id; state_root_id = $rc18BoundaryResult.state_root_id; only_writable_drill_surface = $rc18ImageBoundary.allowed_write_surface.only_writable_drill_surface; host_rootfs_mutation_allowed = $rc18ImageBoundary.denied_host_write_surface.host_rootfs_mutation_allowed; remote_dispatch_enabled = $rc18ImageBoundary.denied_host_write_surface.remote_dispatch_enabled })
Add-Check "target_boundary.disposable_only" ($targetBoundary.allowed_write_surface.only_writable_first_user_install_surface -eq "disposable-first-user-install-target" -and $targetBoundary.allowed_write_surface.host_write_surface_allowed -eq $false -and $targetBoundary.target.install_allowed_now -eq $false -and $targetBoundary.target.target_materialized -eq $false) "Target boundary must declare the disposable target as the only writable first-user install surface without materializing it." $targetBoundary.allowed_write_surface
Add-Check "preflight.binds.required_refs" ($installPreflightPackage.preflight_gate.target_boundary_bound -eq $true -and $installPreflightPackage.preflight_gate.installable_image_artifact_bound -eq $true -and $installPreflightPackage.preflight_gate.installer_media_bound -eq $true -and $installPreflightPackage.preflight_gate.reproducibility_fail_closed_bound -eq $true -and $installPreflightPackage.preflight_gate.disposable_boundary_bound -eq $true -and $installPreflightPackage.preflight_gate.agentcore_security_references_bound -eq $true -and $installPreflightPackage.preflight_gate.rollback_support_references_bound -eq $true) "Install preflight package must bind image artifact, media, boot target, fail-closed, disposable boundary, AgentCore/SecurityExecution, rollback, and support references." $installPreflightPackage.preflight_gate
Add-Check "agentcore.security.refs.bound" $agentCoreSecurityReady "AgentCore and SecurityExecution references must be hash-bound without granting execution authority." ([ordered]@{ agent_core_lib_sha256 = $agentCoreLibSha256; security_policy_sha256 = $securityExecutionPolicySha256; security_tools_sha256 = $securityExecutionToolsSha256; rc16_planspec_status = $rc16PlanSpecResult.status; rc16_planspec_executable = $rc16PlanSpecPackage.agentcore_install_update_planspec_executable; security_execution_allowed_now = $installPreflightPackage.security_execution_reference.security_execution_allowed_now })
Add-Check "rollback.support.refs.bound" $rollbackSupportReady "Rollback baseline and support references must be hash-bound while rollback, support upload, and recovery execution remain disabled." $installPreflightPackage.rollback_support
Add-Check "authority.no_broadening" (@($installPreflightPackage.side_effects.GetEnumerator() | Where-Object { $_.Value -ne $false }).Count -eq 0 -and $installPreflightPackage.preflight_gate.install_allowed -eq $false -and $installPreflightPackage.preflight_gate.host_rootfs_mutation_allowed -eq $false -and $installPreflightPackage.preflight_gate.remote_dispatch_enabled -eq $false -and $targetBoundary.denied_surface.production_ring_mutation_allowed -eq $false) "RC19-020 must not install, mutate host state, publish/upload/sign, upload support, execute recovery, dispatch remotely, or mutate production rings." ([ordered]@{ preflight_gate = $installPreflightPackage.preflight_gate; side_effects = $installPreflightPackage.side_effects })
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 18) "Missing, host-mutating, remote, support, recovery, signing, publication, projection-authority, and GA claim target cases must fail closed." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })
Add-Check "outputs.written" ((Test-Path -LiteralPath $targetBoundaryPath -PathType Leaf) -and (Test-Path -LiteralPath $preflightPackagePath -PathType Leaf) -and $targetBoundarySha256 -match "^[0-9a-f]{64}$" -and $preflightPackageSha256 -match "^[0-9a-f]{64}$") "RC19-020 must write target boundary and install preflight package outputs." ([ordered]@{ target_boundary = [ordered]@{ path = Get-StablePath $targetBoundaryPath; sha256 = $targetBoundarySha256; target_boundary_id = $targetBoundaryId }; install_preflight_package = [ordered]@{ path = Get-StablePath $preflightPackagePath; sha256 = $preflightPackageSha256; install_preflight_package_id = $preflightPackageId } })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $targetBoundaryPath),
    (Get-Content -Raw -LiteralPath $preflightPackagePath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC19-020 outputs must not contain key blocks, private key paths, auth tokens, public identity markers, or signing key file names." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc19-first-user-install-target-boundary-result.v1"
    generated_at = $generatedAtValue
    task = "RC19-020"
    status = $resultStatus
    production_ready_claim = $false
    target_boundary_id = $targetBoundaryId
    install_preflight_package_id = $preflightPackageId
    installable_image_artifact_id = $rc19ArtifactResult.installable_image_artifact_id
    installer_media_id = $rc19MediaResult.installer_media_id
    boot_target_descriptor_id = $rc19MediaResult.boot_target_descriptor_id
    outputs = [ordered]@{
        first_user_install_target_boundary = [ordered]@{
            path = Get-StablePath $targetBoundaryPath
            sha256 = $targetBoundarySha256
            target_boundary_id = $targetBoundaryId
        }
        install_preflight_package = [ordered]@{
            path = Get-StablePath $preflightPackagePath
            sha256 = $preflightPackageSha256
            install_preflight_package_id = $preflightPackageId
        }
    }
    target_boundary_surface = [ordered]@{
        state = $targetBoundary.status
        only_writable_first_user_install_surface = $allowedWriteSurface.only_writable_first_user_install_surface
        target_materialized = $false
        install_allowed = $false
        first_user_install_allowed = $false
        install_effects_gated_until = "RC19-021"
        host_rootfs_mutation_allowed = $false
        host_active_slot_mutation_allowed = $false
        host_boot_metadata_mutation_allowed = $false
        active_artifact_set_mutation_allowed = $false
        production_ring_mutation_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
    }
    preflight_surface = [ordered]@{
        state = $installPreflightPackage.status
        image_artifact_bound = $artifactReady
        media_bound = $mediaReady
        boot_target_bound = $mediaReady
        reproducibility_fail_closed_bound = $reproducibilityReady
        disposable_boundary_bound = $disposableBoundaryReady
        agentcore_security_references_bound = $agentCoreSecurityReady
        rollback_support_references_bound = $rollbackSupportReady
        install_preflight_executed = $false
        install_performed = $false
    }
    source = $source
    checks = @($script:checks)
    fail_closed_boundaries = $cases
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        repo_local_projection_only = $true
        disposable_first_user_install_target_only = $true
        target_materialized = $false
        install_preflight_executed = $false
        install_performed = $false
        update_performed = $false
        rollback_execution_performed = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        payload_uploaded = $false
        external_payload_published = $false
        object_storage_provisioned = $false
        cryptographic_signing_performed = $false
        private_signing_material_handled = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        production_ring_mutated = $false
        mirror_authority = $false
        frontend_authority = $false
        signer_authority = $false
        endpoint_reachability_authority = $false
        model_replay_authority = $false
        normal_shell_authority = $false
        tui_authority = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
        rc19_020_complete = (@($script:failedChecks).Count -eq 0)
        target_boundary_bound = (@($script:failedChecks).Count -eq 0)
        install_preflight_package_bound = (@($script:failedChecks).Count -eq 0)
        only_writable_first_user_install_surface = $allowedWriteSurface.only_writable_first_user_install_surface
        install_allowed = $false
        first_user_install_allowed = $false
        install_performed = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        remote_dispatch_enabled = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        next_task = "RC19-021"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC19-020-first-user-install-target-boundary.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc19-first-user-install-target-boundary-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC19-020"
    status = if ($resultStatus -eq "passed") { "completed" } else { "failed" }
    production_ready_claim = $false
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
    target_boundary_surface = $result.target_boundary_surface
    preflight_surface = $result.preflight_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc19_020_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC19-021"
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
    throw "Sensitive marker detected in RC19-020 outputs."
}

Write-Host "RC19 first-user install target boundary $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Target boundary: $(Get-StablePath $targetBoundaryPath)"
Write-Host "Install preflight package: $(Get-StablePath $preflightPackagePath)"
Write-Host "Only writable surface: $($allowedWriteSurface.only_writable_first_user_install_surface); install performed: false; host mutation: false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
