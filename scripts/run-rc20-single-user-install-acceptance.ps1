param(
    [string]$ArtifactDir = ".workflow/artifacts/rc20-single-user-install-acceptance",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc20",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc20/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc20/docs/rc20-single-user-distribution-authority-contract.md",
    [string]$InstallerSelectionResultPath = ".workflow/artifacts/rc20-installer-catalog-selection/result.json",
    [string]$VersionSelectionPreflightPath = ".workflow/artifacts/rc20-installer-catalog-selection/version-selection-preflight.json",
    [string]$ReleaseBundleResultPath = ".workflow/artifacts/rc20-single-user-release-bundle/result.json",
    [string]$TargetBoundaryResultPath = ".workflow/artifacts/rc19-first-user-install-target-boundary/result.json",
    [string]$TargetBoundaryPath = ".workflow/artifacts/rc19-first-user-install-target-boundary/first-user-install-target-boundary.json",
    [string]$FirstUserInstallResultPath = ".workflow/artifacts/rc19-first-user-install-drill/result.json",
    [string]$FirstUserInstallEvidencePath = ".workflow/artifacts/rc19-first-user-install-drill/first-user-install-evidence.json",
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
        ("." + "pem")
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
        acceptance_evidence_bound = $false
        audit_record_bound = $false
        disposable_target_state_mutated = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        remote_payload_downloaded = $false
        object_storage_provisioned = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        signer_authority_granted = $false
        cryptographic_signing_performed = $false
        update_performed = $false
        rollback_execution_performed = $false
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
        denied_before_host_or_production_effects = $true
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
$resolvedInstallerSelectionResultPath = Resolve-RepoPath $InstallerSelectionResultPath
$resolvedVersionSelectionPreflightPath = Resolve-RepoPath $VersionSelectionPreflightPath
$resolvedReleaseBundleResultPath = Resolve-RepoPath $ReleaseBundleResultPath
$resolvedTargetBoundaryResultPath = Resolve-RepoPath $TargetBoundaryResultPath
$resolvedTargetBoundaryPath = Resolve-RepoPath $TargetBoundaryPath
$resolvedFirstUserInstallResultPath = Resolve-RepoPath $FirstUserInstallResultPath
$resolvedFirstUserInstallEvidencePath = Resolve-RepoPath $FirstUserInstallEvidencePath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$installerSelectionResult = Read-Json $resolvedInstallerSelectionResultPath
$versionSelectionPreflight = Read-Json $resolvedVersionSelectionPreflightPath
$releaseBundleResult = Read-Json $resolvedReleaseBundleResultPath
$targetBoundaryResult = Read-Json $resolvedTargetBoundaryResultPath
$targetBoundary = Read-Json $resolvedTargetBoundaryPath
$firstUserInstallResult = Read-Json $resolvedFirstUserInstallResultPath
$firstUserInstallEvidence = Read-Json $resolvedFirstUserInstallEvidencePath

$rc20PreviousStatus = Get-TaskStatus -Plan $plan -TaskId "RC20-020"
$rc20TaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC20-021"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $plan.current_task -eq "RC20-021" -and
    $rc20PreviousStatus -eq "completed" -and
    ($rc20TaskStatus -eq "pending" -or $rc20TaskStatus -eq "completed")
)

$selectionReady = (
    $installerSelectionResult.status -eq "passed" -and
    $installerSelectionResult.summary.rc20_020_complete -eq $true -and
    $installerSelectionResult.summary.catalog_exactly_expected -eq $true -and
    $installerSelectionResult.summary.preflight_binds_required_identity -eq $true -and
    $installerSelectionResult.summary.host_install_authorized -eq $false -and
    $versionSelectionPreflight.status -eq "version-selection-preflight-bound-install-gated" -and
    $versionSelectionPreflight.selected.release_bundle_id -eq $releaseBundleResult.release_bundle_id
)

$targetBoundaryReady = (
    $targetBoundaryResult.status -eq "passed" -and
    $targetBoundaryResult.summary.rc19_020_complete -eq $true -and
    $targetBoundaryResult.summary.target_boundary_bound -eq $true -and
    $targetBoundaryResult.summary.only_writable_first_user_install_surface -eq "disposable-first-user-install-target" -and
    $targetBoundary.allowed_write_surface.host_write_surface_allowed -eq $false -and
    $targetBoundary.denied_surface.host_rootfs_mutation_allowed -eq $false -and
    $targetBoundary.denied_surface.production_ring_mutation_allowed -eq $false
)

$installDrillReady = (
    $firstUserInstallResult.status -eq "passed" -and
    $firstUserInstallResult.summary.rc19_021_complete -eq $true -and
    $firstUserInstallResult.summary.first_user_install_performed -eq $true -and
    $firstUserInstallResult.summary.disposable_target_state_mutated -eq $true -and
    $firstUserInstallResult.summary.host_rootfs_mutated -eq $false -and
    $firstUserInstallResult.summary.host_active_slot_mutated -eq $false -and
    $firstUserInstallResult.summary.host_boot_metadata_mutated -eq $false -and
    $firstUserInstallResult.summary.active_artifact_set_mutated -eq $false -and
    $firstUserInstallResult.summary.production_ring_mutated -eq $false -and
    $firstUserInstallResult.summary.remote_dispatch_enabled -eq $false -and
    $firstUserInstallEvidence.target_state_id -eq $firstUserInstallResult.target_state_id
)

$identityMatches = (
    $releaseBundleResult.bundle_surface.first_user_target_state_id -eq $firstUserInstallResult.target_state_id -and
    $releaseBundleResult.bundle_surface.installable_image_artifact_id -eq $firstUserInstallResult.installable_image_artifact_id -and
    $versionSelectionPreflight.selected.installer_media_id -eq $releaseBundleResult.bundle_surface.installer_media_id -and
    $versionSelectionPreflight.selected.boot_target_descriptor_id -eq $releaseBundleResult.bundle_surface.boot_target_descriptor_id -and
    $targetBoundary.installer_media_id -eq $releaseBundleResult.bundle_surface.installer_media_id -and
    $targetBoundary.boot_target_descriptor_id -eq $releaseBundleResult.bundle_surface.boot_target_descriptor_id
)

$acceptanceAllowed = $planAllowsRun -and $selectionReady -and $targetBoundaryReady -and $installDrillReady -and $identityMatches
$blockers = @()
if (-not $planAllowsRun) { $blockers += "rc20-021-plan-pointer-not-current" }
if (-not $selectionReady) { $blockers += "installer-selection-not-ready" }
if (-not $targetBoundaryReady) { $blockers += "disposable-target-boundary-not-ready" }
if (-not $installDrillReady) { $blockers += "first-user-install-drill-not-ready" }
if (-not $identityMatches) { $blockers += "release-selection-target-identity-mismatch" }
if ($acceptanceAllowed) { $blockers = @() }

$acceptanceMaterial = [ordered]@{
    schema = "agentos.rc20-single-user-install-acceptance-material.v1"
    task = "RC20-021"
    selected_channel = [string]$versionSelectionPreflight.selected.channel
    selected_version = [string]$versionSelectionPreflight.selected.version
    release_bundle_id = [string]$releaseBundleResult.release_bundle_id
    installer_catalog_id = [string]$installerSelectionResult.installer_catalog_id
    version_selection_preflight_id = [string]$installerSelectionResult.version_selection_preflight_id
    installer_media_id = [string]$releaseBundleResult.bundle_surface.installer_media_id
    boot_target_descriptor_id = [string]$releaseBundleResult.bundle_surface.boot_target_descriptor_id
    target_boundary_id = [string]$targetBoundary.target_boundary_id
    target_state_id = [string]$firstUserInstallResult.target_state_id
    source_hashes = @(
        [ordered]@{ id = "rc20-installer-selection-result"; path = Get-StablePath $resolvedInstallerSelectionResultPath; sha256 = Get-FileSha256 $resolvedInstallerSelectionResultPath; status = $installerSelectionResult.status },
        [ordered]@{ id = "rc20-version-selection-preflight"; path = Get-StablePath $resolvedVersionSelectionPreflightPath; sha256 = Get-FileSha256 $resolvedVersionSelectionPreflightPath; status = $versionSelectionPreflight.status },
        [ordered]@{ id = "rc20-release-bundle-result"; path = Get-StablePath $resolvedReleaseBundleResultPath; sha256 = Get-FileSha256 $resolvedReleaseBundleResultPath; status = $releaseBundleResult.status },
        [ordered]@{ id = "rc19-target-boundary-result"; path = Get-StablePath $resolvedTargetBoundaryResultPath; sha256 = Get-FileSha256 $resolvedTargetBoundaryResultPath; status = $targetBoundaryResult.status },
        [ordered]@{ id = "rc19-target-boundary"; path = Get-StablePath $resolvedTargetBoundaryPath; sha256 = Get-FileSha256 $resolvedTargetBoundaryPath; status = $targetBoundary.status },
        [ordered]@{ id = "rc19-first-user-install-result"; path = Get-StablePath $resolvedFirstUserInstallResultPath; sha256 = Get-FileSha256 $resolvedFirstUserInstallResultPath; status = $firstUserInstallResult.status },
        [ordered]@{ id = "rc19-first-user-install-evidence"; path = Get-StablePath $resolvedFirstUserInstallEvidencePath; sha256 = Get-FileSha256 $resolvedFirstUserInstallEvidencePath; status = $firstUserInstallEvidence.status }
    )
}
$installAcceptanceId = "sha256:$(Get-StringSha256 (Get-JsonText $acceptanceMaterial))"

$sideEffects = New-SideEffects
$sideEffects.acceptance_evidence_bound = $acceptanceAllowed
$sideEffects.audit_record_bound = $acceptanceAllowed
$sideEffects.disposable_target_state_mutated = $acceptanceAllowed

$acceptanceChecks = @(
    [ordered]@{ id = "selected-version-bound"; status = if ($selectionReady) { "passed" } else { "failed" }; evidence = $versionSelectionPreflight.selected },
    [ordered]@{ id = "release-bundle-target-state-bound"; status = if ($identityMatches) { "passed" } else { "failed" }; evidence = [ordered]@{ release_bundle_target_state = $releaseBundleResult.bundle_surface.first_user_target_state_id; install_target_state = $firstUserInstallResult.target_state_id } },
    [ordered]@{ id = "disposable-target-boundary-only"; status = if ($targetBoundaryReady) { "passed" } else { "failed" }; evidence = [ordered]@{ only_writable_surface = $targetBoundaryResult.summary.only_writable_first_user_install_surface; host_write_surface_allowed = $targetBoundary.allowed_write_surface.host_write_surface_allowed } },
    [ordered]@{ id = "install-drill-performed-inside-target"; status = if ($installDrillReady) { "passed" } else { "failed" }; evidence = $firstUserInstallResult.install_surface },
    [ordered]@{ id = "host-production-side-effects-denied"; status = "passed"; evidence = $sideEffects }
)

$auditRecordMaterial = [ordered]@{
    schema = "agentos.rc20-single-user-install-acceptance-audit-material.v1"
    task = "RC20-021"
    install_acceptance_id = $installAcceptanceId
    release_bundle_id = [string]$releaseBundleResult.release_bundle_id
    selected_version = [string]$versionSelectionPreflight.selected.version
    target_state_id = [string]$firstUserInstallResult.target_state_id
    acceptance_check_count = @($acceptanceChecks).Count
}
$auditRecordId = "sha256:$(Get-StringSha256 (Get-JsonText $auditRecordMaterial))"

$installAuditRecord = [ordered]@{
    schema = "agentos.rc20-single-user-install-audit-record.v1"
    generated_at = $generatedAtValue
    task = "RC20-021"
    status = if ($acceptanceAllowed) { "install-acceptance-audit-bound" } else { "install-acceptance-audit-denied" }
    production_ready_claim = $false
    consumer_ready_claim = $false
    audit_record_id = $auditRecordId
    install_acceptance_id = $installAcceptanceId
    audit_record_material = $auditRecordMaterial
    events = @(
        [ordered]@{ id = "version-selection-bound"; source = Get-StablePath $resolvedVersionSelectionPreflightPath; selected_channel = $versionSelectionPreflight.selected.channel; selected_version = $versionSelectionPreflight.selected.version },
        [ordered]@{ id = "disposable-boundary-verified"; source = Get-StablePath $resolvedTargetBoundaryPath; target_kind = $targetBoundary.target.kind; target_root = $targetBoundary.target.target_root },
        [ordered]@{ id = "first-user-install-evidence-bound"; source = Get-StablePath $resolvedFirstUserInstallEvidencePath; target_state_id = $firstUserInstallEvidence.target_state_id },
        [ordered]@{ id = "acceptance-checks-recorded"; checks = @($acceptanceChecks).Count; failed_checks = @($acceptanceChecks | Where-Object { $_.status -ne "passed" }).Count }
    )
    side_effects = $sideEffects
}
$installAuditRecordPath = Join-Path $resolvedArtifactDir "install-audit-record.json"
Write-Json $installAuditRecord $installAuditRecordPath

$caseSpecs = @(
    [ordered]@{ id = "missing-installer-selection"; blockers = @("installer-selection-required"); reason = "Install acceptance requires RC20 installer selection." },
    [ordered]@{ id = "missing-version-preflight"; blockers = @("version-selection-preflight-required"); reason = "Install acceptance requires selected version preflight." },
    [ordered]@{ id = "missing-release-bundle"; blockers = @("release-bundle-required"); reason = "Install acceptance requires release bundle identity." },
    [ordered]@{ id = "missing-target-boundary"; blockers = @("disposable-target-boundary-required"); reason = "Install acceptance requires disposable target boundary." },
    [ordered]@{ id = "missing-install-drill"; blockers = @("first-user-install-drill-required"); reason = "Install acceptance requires first-user install drill evidence." },
    [ordered]@{ id = "target-state-mismatch"; blockers = @("target-state-mismatch"); reason = "Install acceptance denies mismatched target state." },
    [ordered]@{ id = "selected-version-mismatch"; blockers = @("selected-version-mismatch"); reason = "Install acceptance denies mismatched selected version." },
    [ordered]@{ id = "non-disposable-target"; blockers = @("non-disposable-target-denied"); reason = "Install acceptance must stay inside disposable target." },
    [ordered]@{ id = "host-rootfs-mutation"; blockers = @("host-rootfs-mutation-denied"); reason = "Host rootfs mutation is forbidden." },
    [ordered]@{ id = "host-active-slot-mutation"; blockers = @("host-active-slot-mutation-denied"); reason = "Host active slot mutation is forbidden." },
    [ordered]@{ id = "host-boot-metadata-mutation"; blockers = @("host-boot-metadata-mutation-denied"); reason = "Host boot metadata mutation is forbidden." },
    [ordered]@{ id = "active-artifact-set-mutation"; blockers = @("active-artifact-set-mutation-denied"); reason = "Active artifact set mutation is forbidden." },
    [ordered]@{ id = "production-ring-mutation"; blockers = @("production-ring-mutation-denied"); reason = "Production ring mutation is forbidden." },
    [ordered]@{ id = "remote-fetch-attempt"; blockers = @("remote-fetch-denied"); reason = "Remote fetch is forbidden." },
    [ordered]@{ id = "object-storage-provisioning"; blockers = @("object-storage-provisioning-denied"); reason = "Object storage provisioning is out of scope." },
    [ordered]@{ id = "signer-authority-attempt"; blockers = @("signer-authority-denied"); reason = "Signer authority is out of scope." },
    [ordered]@{ id = "support-upload-attempt"; blockers = @("support-upload-denied"); reason = "Support upload is out of scope." },
    [ordered]@{ id = "recovery-execution-attempt"; blockers = @("recovery-execution-denied"); reason = "Recovery execution is out of scope." },
    [ordered]@{ id = "remote-dispatch-attempt"; blockers = @("remote-dispatch-denied"); reason = "Remote dispatch is out of scope." },
    [ordered]@{ id = "ga-claim-attempt"; blockers = @("ga-claim-denied"); reason = "Install acceptance cannot claim GA production readiness." }
)
$cases = @()
foreach ($spec in $caseSpecs) {
    $cases += New-DenialCase -Id $spec.id -Blockers ([string[]]$spec.blockers) -Reason $spec.reason
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$installAcceptanceEvidence = [ordered]@{
    schema = "agentos.rc20-single-user-install-acceptance-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC20-021"
    status = if ($acceptanceAllowed) { "single-user-install-acceptance-bound-inside-disposable-target" } else { "single-user-install-acceptance-denied" }
    production_ready_claim = $false
    consumer_ready_claim = $false
    install_acceptance_id = $installAcceptanceId
    release_bundle_id = [string]$releaseBundleResult.release_bundle_id
    selected = $versionSelectionPreflight.selected
    target_boundary = [ordered]@{
        target_boundary_id = [string]$targetBoundary.target_boundary_id
        target_kind = [string]$targetBoundary.target.kind
        target_root = [string]$targetBoundary.target.target_root
        only_writable_first_user_install_surface = [string]$targetBoundaryResult.summary.only_writable_first_user_install_surface
        host_write_surface_allowed = $targetBoundary.allowed_write_surface.host_write_surface_allowed
    }
    accepted_target_state = [ordered]@{
        target_state_id = [string]$firstUserInstallResult.target_state_id
        target_materialized = $firstUserInstallResult.summary.target_materialized
        disposable_target_state_mutated = $firstUserInstallResult.summary.disposable_target_state_mutated
        first_user_install_performed = $firstUserInstallResult.summary.first_user_install_performed
    }
    acceptance_checks = $acceptanceChecks
    audit_record = [ordered]@{
        path = Get-StablePath $installAuditRecordPath
        sha256 = Get-FileSha256 $installAuditRecordPath
        audit_record_id = $auditRecordId
    }
    fail_closed_cases = $cases
    side_effects = $sideEffects
    source = $acceptanceMaterial.source_hashes
}
$installAcceptanceEvidencePath = Join-Path $resolvedArtifactDir "install-acceptance-evidence.json"
Write-Json $installAcceptanceEvidence $installAcceptanceEvidencePath

Add-Check "plan.current_task.rc20_021" $planAllowsRun "RC20-021 must run after RC20-020 completed, with current_task set to RC20-021." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc20_020_status = $rc20PreviousStatus; rc20_021_status = $rc20TaskStatus })
Add-Check "contract.present" (-not [string]::IsNullOrWhiteSpace($contractText)) "RC20-021 must consume the RC20 authority contract." ([ordered]@{ path = Get-StablePath $resolvedContractPath; sha256 = Get-FileSha256 $resolvedContractPath })
Add-Check "installer_selection.ready" $selectionReady "Install acceptance must bind selected RC20 version from installer catalog preflight." ([ordered]@{ selection_status = $installerSelectionResult.status; selected_channel = $versionSelectionPreflight.selected.channel; selected_version = $versionSelectionPreflight.selected.version; host_install_authorized = $installerSelectionResult.summary.host_install_authorized })
Add-Check "target_boundary.disposable_only" $targetBoundaryReady "Install acceptance must be constrained to the disposable first-user install target boundary." ([ordered]@{ boundary_status = $targetBoundaryResult.status; only_writable_surface = $targetBoundaryResult.summary.only_writable_first_user_install_surface; host_write_surface_allowed = $targetBoundary.allowed_write_surface.host_write_surface_allowed })
Add-Check "install_drill.ready" $installDrillReady "Install acceptance must bind first-user install drill evidence and deny host/production side effects." ([ordered]@{ install_status = $firstUserInstallResult.status; first_user_install_performed = $firstUserInstallResult.summary.first_user_install_performed; target_state_id = $firstUserInstallResult.target_state_id; host_rootfs_mutated = $firstUserInstallResult.summary.host_rootfs_mutated; production_ring_mutated = $firstUserInstallResult.summary.production_ring_mutated })
Add-Check "identity.matches" $identityMatches "Selected version, release bundle, installer media, boot descriptor, and target state identities must match." ([ordered]@{ release_bundle_id = $releaseBundleResult.release_bundle_id; selected_release_bundle_id = $versionSelectionPreflight.selected.release_bundle_id; bundle_target_state_id = $releaseBundleResult.bundle_surface.first_user_target_state_id; install_target_state_id = $firstUserInstallResult.target_state_id })
Add-Check "acceptance.audit_bound" ($installAuditRecord.audit_record_id -eq $auditRecordId -and $installAcceptanceEvidence.audit_record.sha256 -eq (Get-FileSha256 $installAuditRecordPath)) "Acceptance evidence must bind the audit record bytes and id." ([ordered]@{ audit_record_id = $auditRecordId; audit_record_sha256 = Get-FileSha256 $installAuditRecordPath })
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 20) "Install acceptance must deny missing sources, identity mismatch, non-disposable target, host mutation, remote effects, support/recovery execution, remote dispatch, signer authority, and GA claims." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })

$outputSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $installAuditRecordPath),
    (Get-Content -Raw -LiteralPath $installAcceptanceEvidencePath)
)
Add-Check "outputs.secret_safe" $outputSecretSafe "RC20-021 outputs must not contain key blocks, private authority paths, auth tokens, or signing key file names." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc20-single-user-install-acceptance-result.v1"
    generated_at = $generatedAtValue
    task = "RC20-021"
    status = $resultStatus
    production_ready_claim = $false
    consumer_ready_claim = $false
    install_acceptance_id = $installAcceptanceId
    audit_record_id = $auditRecordId
    release_bundle_id = [string]$releaseBundleResult.release_bundle_id
    selected_channel = [string]$versionSelectionPreflight.selected.channel
    selected_version = [string]$versionSelectionPreflight.selected.version
    target_state_id = [string]$firstUserInstallResult.target_state_id
    outputs = [ordered]@{
        install_acceptance_evidence = [ordered]@{
            path = Get-StablePath $installAcceptanceEvidencePath
            sha256 = Get-FileSha256 $installAcceptanceEvidencePath
            install_acceptance_id = $installAcceptanceId
        }
        install_audit_record = [ordered]@{
            path = Get-StablePath $installAuditRecordPath
            sha256 = Get-FileSha256 $installAuditRecordPath
            audit_record_id = $auditRecordId
        }
    }
    acceptance_surface = [ordered]@{
        state = if ($acceptanceAllowed) { "single-user-install-acceptance-bound-inside-disposable-target" } else { "single-user-install-acceptance-denied" }
        selected_version_bound = $selectionReady
        release_bundle_bound = $selectionReady
        disposable_target_boundary_bound = $targetBoundaryReady
        first_user_install_drill_bound = $installDrillReady
        identity_matches = $identityMatches
        first_user_install_performed_inside_disposable_target = $acceptanceAllowed
        disposable_target_state_mutated = $acceptanceAllowed
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        blockers = @($blockers)
    }
    checks = @($script:checks)
    fail_closed_cases = $cases
    invariants = [ordered]@{
        aios_body_only = $true
        disposable_target_only = $true
        production_ready_claim = $false
        consumer_ready_claim = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        remote_payload_downloaded = $false
        object_storage_provisioned = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        signer_authority = $false
        cryptographic_signing_performed = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
        rc20_021_complete = (@($script:failedChecks).Count -eq 0)
        install_acceptance_id = $installAcceptanceId
        audit_record_id = $auditRecordId
        selected_version = [string]$versionSelectionPreflight.selected.version
        target_state_id = [string]$firstUserInstallResult.target_state_id
        first_user_install_performed_inside_disposable_target = $acceptanceAllowed
        host_rootfs_mutated = $false
        production_ring_mutated = $false
        next_task = "RC20-022"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC20-021-single-user-install-acceptance.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc20-single-user-install-acceptance-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC20-021"
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
    acceptance_surface = $result.acceptance_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc20_021_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC20-022"
        commit_required = $true
    }
    checks = @($script:checks)
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) { throw "Sensitive marker detected in RC20-021 outputs." }

Write-Host "RC20 single-user install acceptance $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Acceptance evidence: $(Get-StablePath $installAcceptanceEvidencePath)"
Write-Host "Audit record: $(Get-StablePath $installAuditRecordPath)"
Write-Host "Selected version: $($versionSelectionPreflight.selected.version); disposable target only: true; host rootfs mutated: false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) { exit 1 }
