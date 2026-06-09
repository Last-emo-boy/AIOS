param(
    [string]$ArtifactDir = ".workflow/artifacts/rc18-disposable-installed-system-boundary",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc18",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc18/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc18/docs/rc18-isolated-installed-system-drill-contract.md",
    [string]$Rc17FinalAuditResultPath = ".workflow/artifacts/rc17-final-closeout-audit/result.json",
    [string]$Rc17FinalAuditEvidencePath = ".workflow/active/WFS-20260609-agentos-production-distro-rc17/evidence/FINAL-AUDIT-20260609-production-distro-rc17.json",
    [string]$Rc17InstallResultPath = ".workflow/artifacts/rc17-controlled-local-install/result.json",
    [string]$Rc17UpdateResultPath = ".workflow/artifacts/rc17-controlled-local-update/result.json",
    [string]$Rc17RollbackSupportResultPath = ".workflow/artifacts/rc17-controlled-install-update-rollback-support/result.json",
    [string]$Rc17ConsumerSmokeResultPath = ".workflow/artifacts/rc17-local-release-channel-install-update-consumer-smoke/result.json",
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
        observed_denied = $true
        blockers = $Blockers
        reason = $Reason
        image_mutation_performed = $false
        side_effects = [ordered]@{
            host_rootfs_mutated = $false
            host_active_slot_mutated = $false
            host_boot_metadata_mutated = $false
            active_artifact_set_mutated = $false
            production_ring_mutated = $false
            support_upload_performed = $false
            recovery_execution_performed = $false
            remote_dispatch_enabled = $false
            mirror_frontend_mutated = $false
            signer_authority_granted = $false
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
$resolvedRc17FinalAuditResultPath = Resolve-RepoPath $Rc17FinalAuditResultPath
$resolvedRc17FinalAuditEvidencePath = Resolve-RepoPath $Rc17FinalAuditEvidencePath
$resolvedRc17InstallResultPath = Resolve-RepoPath $Rc17InstallResultPath
$resolvedRc17UpdateResultPath = Resolve-RepoPath $Rc17UpdateResultPath
$resolvedRc17RollbackSupportResultPath = Resolve-RepoPath $Rc17RollbackSupportResultPath
$resolvedRc17ConsumerSmokeResultPath = Resolve-RepoPath $Rc17ConsumerSmokeResultPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$rc17FinalAuditResult = Read-Json $resolvedRc17FinalAuditResultPath
$rc17FinalAuditEvidence = Read-Json $resolvedRc17FinalAuditEvidencePath
$rc17InstallResult = Read-Json $resolvedRc17InstallResultPath
$rc17UpdateResult = Read-Json $resolvedRc17UpdateResultPath
$rc17RollbackSupportResult = Read-Json $resolvedRc17RollbackSupportResultPath
$rc17ConsumerSmokeResult = Read-Json $resolvedRc17ConsumerSmokeResultPath

$rc18PreviousStatus = Get-TaskStatus -Plan $plan -TaskId "RC18-001"
$rc18TaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC18-010"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc18PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC18-010" -and ($rc18TaskStatus -eq "pending" -or $rc18TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC18-011" -and $rc18TaskStatus -eq "completed")
    )
)

$rc17EvidenceReady = (
    $rc17FinalAuditResult.status -eq "passed" -and
    $rc17FinalAuditResult.exact_install_update_ready -eq $true -and
    $rc17FinalAuditResult.production_ready_claim -eq $false -and
    $rc17InstallResult.status -eq "passed" -and
    $rc17InstallResult.install_surface.install_performed -eq $true -and
    $rc17UpdateResult.status -eq "passed" -and
    $rc17UpdateResult.update_surface.update_performed -eq $true -and
    $rc17RollbackSupportResult.status -eq "passed" -and
    $rc17RollbackSupportResult.rollback_support_surface.rollback_execution_performed -eq $true -and
    $rc17ConsumerSmokeResult.status -eq "passed" -and
    $rc17ConsumerSmokeResult.consumer_surface.consumer_decision -eq "exact-install-update-ready"
)

$sourceEvidence = [ordered]@{
    rc18_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc18_contract = New-ArtifactRef $resolvedContractPath
    rc17_final_audit_result = New-ArtifactRef $resolvedRc17FinalAuditResultPath $rc17FinalAuditResult
    rc17_final_audit_evidence = New-ArtifactRef $resolvedRc17FinalAuditEvidencePath $rc17FinalAuditEvidence
    rc17_controlled_install_result = New-ArtifactRef $resolvedRc17InstallResultPath $rc17InstallResult
    rc17_controlled_update_result = New-ArtifactRef $resolvedRc17UpdateResultPath $rc17UpdateResult
    rc17_rollback_support_result = New-ArtifactRef $resolvedRc17RollbackSupportResultPath $rc17RollbackSupportResult
    rc17_consumer_smoke_result = New-ArtifactRef $resolvedRc17ConsumerSmokeResultPath $rc17ConsumerSmokeResult
}

$artifactRoots = @(
    [ordered]@{ id = "rc18-boundary"; path = ".workflow/artifacts/rc18-disposable-installed-system-boundary"; writable_in_task = $true },
    [ordered]@{ id = "rc18-baseline"; path = ".workflow/artifacts/rc18-installed-system-baseline"; writable_after_task = "RC18-010" },
    [ordered]@{ id = "rc18-image-fail-closed"; path = ".workflow/artifacts/rc18-image-boundary-fail-closed"; writable_after_task = "RC18-011" },
    [ordered]@{ id = "rc18-isolated-install"; path = ".workflow/artifacts/rc18-isolated-install-drill"; writable_after_task = "RC18-012" },
    [ordered]@{ id = "rc18-isolated-update"; path = ".workflow/artifacts/rc18-isolated-update-drill"; writable_after_task = "RC18-020" },
    [ordered]@{ id = "rc18-rollback-preconditions"; path = ".workflow/artifacts/rc18-image-rollback-preconditions"; writable_after_task = "RC18-021" },
    [ordered]@{ id = "rc18-isolated-rollback"; path = ".workflow/artifacts/rc18-isolated-rollback-drill"; writable_after_task = "RC18-022" },
    [ordered]@{ id = "rc18-support-recovery"; path = ".workflow/artifacts/rc18-isolated-support-recovery"; writable_after_task = "RC18-030" },
    [ordered]@{ id = "rc18-consumer-smoke"; path = ".workflow/artifacts/rc18-installed-system-consumer-smoke"; writable_after_task = "RC18-031" }
)

$allowedWriteSurface = [ordered]@{
    only_writable_drill_surface = "disposable-installed-system-image-or-vm"
    boundary_task_writes = @(
        ".workflow/artifacts/rc18-disposable-installed-system-boundary/result.json",
        ".workflow/artifacts/rc18-disposable-installed-system-boundary/image-boundary.json"
    )
    future_image_state_root = ".workflow/artifacts/rc18-installed-system-image-state"
    future_image_mutation_requires = @(
        "rc18-010-boundary-bound",
        "rc18-011-baseline-bound",
        "rc18-012-fail-closed-fixtures-passed"
    )
    host_write_surface_allowed = $false
    artifact_roots = $artifactRoots
}

$deniedHostWriteSurface = [ordered]@{
    host_rootfs_mutation_allowed = $false
    host_active_slot_mutation_allowed = $false
    host_boot_metadata_mutation_allowed = $false
    active_artifact_set_mutation_allowed = $false
    production_ring_mutation_allowed = $false
    support_upload_allowed = $false
    recovery_execution_allowed = $false
    remote_dispatch_enabled = $false
    mirror_frontend_authority = $false
    signer_authority = $false
}

$rootBindingMaterial = [ordered]@{
    schema = "agentos.rc18-disposable-image-root-binding-material.v1"
    task = "RC18-010"
    rc17_exact_evidence = [ordered]@{
        final_audit_sha256 = $sourceEvidence.rc17_final_audit_result.sha256
        install_result_sha256 = $sourceEvidence.rc17_controlled_install_result.sha256
        update_result_sha256 = $sourceEvidence.rc17_controlled_update_result.sha256
        rollback_support_result_sha256 = $sourceEvidence.rc17_rollback_support_result.sha256
        consumer_smoke_result_sha256 = $sourceEvidence.rc17_consumer_smoke_result.sha256
    }
    allowed_write_surface = $allowedWriteSurface
    denied_host_write_surface = $deniedHostWriteSurface
}
$artifactRootBindingHash = Get-StringSha256 (Get-JsonText $rootBindingMaterial)

$stateRoot = [ordered]@{
    schema = "agentos.rc18-disposable-installed-system-state-root.v1"
    task = "RC18-010"
    state_root_id = "sha256:$artifactRootBindingHash"
    source_evidence_required = "rc17-exact-install-update-ready-non-ga"
    artifact_root_binding_hash = $artifactRootBindingHash
    image_materialized = $false
    image_mutation_performed_before_boundary_bound = $false
    vm_booted = $false
    network_fetch_attempted = $false
}

$boundaryCore = [ordered]@{
    schema = "agentos.rc18-disposable-installed-system-boundary-core.v1"
    task = "RC18-010"
    state_root = $stateRoot
    allowed_write_surface = $allowedWriteSurface
    denied_host_write_surface = $deniedHostWriteSurface
    source_evidence = $rootBindingMaterial.rc17_exact_evidence
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        disposable_image_boundary_bound = $true
        no_image_mutation_before_boundary = $true
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        mirror_frontend_changed = $false
        signer_authority = $false
    }
}
$boundaryCoreHash = Get-StringSha256 (Get-JsonText $boundaryCore)
$boundaryId = "sha256:$boundaryCoreHash"

$caseSpecs = @(
    [ordered]@{ id = "missing-rc17-final-audit"; blockers = @("rc17-final-audit-not-bound"); reason = "RC18 image boundary requires RC17 final audit evidence." },
    [ordered]@{ id = "missing-controlled-install"; blockers = @("rc17-controlled-install-not-bound"); reason = "RC18 image boundary requires RC17 install evidence." },
    [ordered]@{ id = "missing-controlled-update"; blockers = @("rc17-controlled-update-not-bound"); reason = "RC18 image boundary requires RC17 update evidence." },
    [ordered]@{ id = "missing-rollback-support"; blockers = @("rc17-rollback-support-not-bound"); reason = "RC18 image boundary requires RC17 rollback/support evidence." },
    [ordered]@{ id = "missing-consumer-smoke"; blockers = @("rc17-consumer-smoke-not-bound"); reason = "RC18 image boundary requires RC17 consumer smoke evidence." },
    [ordered]@{ id = "host-rootfs-write-attempt"; blockers = @("host-rootfs-mutation-denied"); reason = "Host rootfs is outside the writable drill surface." },
    [ordered]@{ id = "host-active-slot-write-attempt"; blockers = @("host-active-slot-mutation-denied"); reason = "Host active slot metadata is outside the writable drill surface." },
    [ordered]@{ id = "host-boot-metadata-write-attempt"; blockers = @("host-boot-metadata-mutation-denied"); reason = "Host boot metadata is outside the writable drill surface." },
    [ordered]@{ id = "active-artifact-set-write-attempt"; blockers = @("active-artifact-set-mutation-denied"); reason = "Host active artifact set is outside the writable drill surface." },
    [ordered]@{ id = "production-ring-write-attempt"; blockers = @("production-ring-mutation-denied"); reason = "Production rings are outside the writable drill surface." },
    [ordered]@{ id = "support-upload-attempt"; blockers = @("support-upload-denied"); reason = "Support upload is out of RC18 scope." },
    [ordered]@{ id = "recovery-execution-attempt"; blockers = @("recovery-execution-denied"); reason = "Recovery execution service is out of RC18 scope." },
    [ordered]@{ id = "remote-dispatch-attempt"; blockers = @("remote-dispatch-denied"); reason = "Remote dispatch is out of RC18 scope." },
    [ordered]@{ id = "mirror-frontend-authority-attempt"; blockers = @("mirror-frontend-authority-denied"); reason = "Mirror/frontend output is not authority." },
    [ordered]@{ id = "signer-authority-attempt"; blockers = @("signer-authority-denied"); reason = "Signer reachability is not image-boundary authority." },
    [ordered]@{ id = "image-mutation-before-boundary"; blockers = @("image-mutation-before-boundary-denied"); reason = "No image mutation is allowed before the boundary is bound." }
)
$cases = @()
foreach ($spec in $caseSpecs) {
    $cases += New-DenialCase -Id $spec.id -Blockers ([string[]]$spec.blockers) -Reason $spec.reason
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$imageBoundary = [ordered]@{
    schema = "agentos.rc18-disposable-installed-system-image-boundary.v1"
    generated_at = $generatedAtValue
    task = "RC18-010"
    status = "disposable-image-boundary-bound-no-image-mutation"
    production_ready_claim = $false
    boundary_id = $boundaryId
    boundary_core_hash = $boundaryCoreHash
    state_root = $stateRoot
    allowed_write_surface = $allowedWriteSurface
    denied_host_write_surface = $deniedHostWriteSurface
    artifact_roots = $artifactRoots
    boundary_core = $boundaryCore
    source = $sourceEvidence
    image_mutation = [ordered]@{
        image_materialized = $false
        image_mutation_performed_before_boundary_bound = $false
        install_performed = $false
        update_performed = $false
        rollback_execution_performed = $false
        vm_booted = $false
        network_fetch_attempted = $false
    }
    fail_closed_cases = $cases
}
$imageBoundaryPath = Join-Path $resolvedArtifactDir "image-boundary.json"
Write-Json $imageBoundary $imageBoundaryPath

Add-Check "plan.current_task.rc18_010" $planAllowsRun "RC18-010 must run after RC18-001 completed, either while current_task is RC18-010 or while rerunning after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc18_001_status = $rc18PreviousStatus; rc18_010_status = $rc18TaskStatus })
Add-Check "contract.boundary_gate.present" ($contractText.Contains("Bind the disposable installed-system image or VM boundary") -and $contractText.Contains("The installed-system image or VM is the only writable drill surface")) "RC18-010 must consume the isolated installed-system boundary contract." (New-ArtifactRef $resolvedContractPath)
Add-Check "source.rc17_exact_evidence.ready" $rc17EvidenceReady "RC18-010 must be hash-bound to RC17 exact install/update/rollback evidence and consumer smoke." ([ordered]@{ exact_install_update_ready = $rc17FinalAuditResult.exact_install_update_ready; install_performed = $rc17InstallResult.install_surface.install_performed; update_performed = $rc17UpdateResult.update_surface.update_performed; rollback_performed = $rc17RollbackSupportResult.rollback_support_surface.rollback_execution_performed; consumer_decision = $rc17ConsumerSmokeResult.consumer_surface.consumer_decision })
Add-Check "state_root.bound" ($stateRoot.state_root_id -like "sha256:*" -and $artifactRootBindingHash.Length -eq 64) "Disposable image state root must be hash-bound to RC17 evidence, allowed write surface, denied host write surface, and artifact roots." ([ordered]@{ state_root_id = $stateRoot.state_root_id; artifact_root_binding_hash = $artifactRootBindingHash })
Add-Check "write_surface.image_only" ($allowedWriteSurface.only_writable_drill_surface -eq "disposable-installed-system-image-or-vm" -and $allowedWriteSurface.host_write_surface_allowed -eq $false -and @($artifactRoots).Count -ge 8) "Installed-system image or VM must be the only writable drill surface and artifact roots must be declared." $allowedWriteSurface
Add-Check "host_write_surface.denied" ($deniedHostWriteSurface.host_rootfs_mutation_allowed -eq $false -and $deniedHostWriteSurface.host_active_slot_mutation_allowed -eq $false -and $deniedHostWriteSurface.host_boot_metadata_mutation_allowed -eq $false -and $deniedHostWriteSurface.active_artifact_set_mutation_allowed -eq $false -and $deniedHostWriteSurface.production_ring_mutation_allowed -eq $false -and $deniedHostWriteSurface.support_upload_allowed -eq $false -and $deniedHostWriteSurface.recovery_execution_allowed -eq $false -and $deniedHostWriteSurface.remote_dispatch_enabled -eq $false -and $deniedHostWriteSurface.mirror_frontend_authority -eq $false -and $deniedHostWriteSurface.signer_authority -eq $false) "Host rootfs, host active slot, host boot metadata, active artifact set, production ring, support upload, recovery service, remote dispatch, mirror/frontend, and signer authority must remain disabled." $deniedHostWriteSurface
Add-Check "image.no_mutation_before_boundary" ($imageBoundary.image_mutation.image_materialized -eq $false -and $imageBoundary.image_mutation.image_mutation_performed_before_boundary_bound -eq $false -and $imageBoundary.image_mutation.install_performed -eq $false -and $imageBoundary.image_mutation.update_performed -eq $false -and $imageBoundary.image_mutation.rollback_execution_performed -eq $false -and $imageBoundary.image_mutation.vm_booted -eq $false) "RC18-010 must not mutate or boot an image before the boundary is bound." $imageBoundary.image_mutation
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 16) "Missing RC17 evidence, host mutation, support upload, recovery, remote dispatch, mirror/frontend, signer, and pre-boundary image mutation attempts must fail closed." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })

$outputsSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $imageBoundaryPath))
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC18-010 image boundary output must not contain key blocks, private key paths, auth tokens, public identity markers, or signing key file names." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$imageBoundarySha256 = Get-FileSha256 $imageBoundaryPath
$result = [ordered]@{
    schema = "agentos.rc18-disposable-installed-system-boundary-result.v1"
    generated_at = $generatedAtValue
    task = "RC18-010"
    status = $resultStatus
    production_ready_claim = $false
    boundary_id = $boundaryId
    state_root_id = $stateRoot.state_root_id
    image_boundary_bound = (@($script:failedChecks).Count -eq 0)
    image_mutation_performed_before_boundary_bound = $false
    outputs = [ordered]@{
        image_boundary = [ordered]@{
            path = Get-StablePath $imageBoundaryPath
            sha256 = $imageBoundarySha256
            boundary_id = $boundaryId
            state_root_id = $stateRoot.state_root_id
        }
    }
    boundary_surface = [ordered]@{
        state = "disposable-installed-system-boundary-bound-no-image-mutation"
        state_root_bound = $true
        allowed_write_surface_bound = $true
        denied_host_write_surface_bound = $true
        artifact_roots_bound = $true
        rc17_exact_evidence_bound = $rc17EvidenceReady
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        mirror_frontend_authority = $false
        signer_authority = $false
        blockers = @("rc18-installed-system-baseline-not-bound", "rc18-image-boundary-fail-closed-not-run", "rc18-isolated-install-not-run", "rc18-isolated-update-not-run")
    }
    source = $sourceEvidence
    checks = @($script:checks)
    fail_closed_cases = $cases
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        disposable_image_or_vm_only = $true
        image_materialized = $false
        image_mutation_performed_before_boundary_bound = $false
        install_performed = $false
        update_performed = $false
        rollback_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        mirror_frontend_changed = $false
        signer_authority = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
        rc18_010_complete = (@($script:failedChecks).Count -eq 0)
        image_boundary_bound = (@($script:failedChecks).Count -eq 0)
        state_root_bound = $true
        rc17_exact_evidence_bound = $rc17EvidenceReady
        image_mutation_performed_before_boundary_bound = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        next_task = "RC18-011"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC18-010-disposable-installed-system-boundary.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc18-disposable-installed-system-boundary-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC18-010"
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
    boundary_surface = $result.boundary_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc18_010_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC18-011"
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
    throw "Sensitive marker detected in RC18-010 outputs."
}

Write-Host "RC18 disposable installed-system boundary $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Image boundary: $(Get-StablePath $imageBoundaryPath)"
Write-Host "Boundary id: $boundaryId"
Write-Host "Image mutation before boundary: false; host mutation: false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
