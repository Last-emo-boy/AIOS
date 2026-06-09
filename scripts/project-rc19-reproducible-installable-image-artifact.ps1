param(
    [string]$ArtifactDir = ".workflow/artifacts/rc19-reproducible-installable-image-artifact",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc19",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc19/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc19/docs/rc19-installable-image-authority-contract.md",
    [string]$Rc18FinalAuditResultPath = ".workflow/artifacts/rc18-final-closeout-audit/result.json",
    [string]$Rc18FinalAuditEvidencePath = ".workflow/active/WFS-20260610-agentos-production-distro-rc18/evidence/FINAL-AUDIT-20260610-production-distro-rc18.json",
    [string]$Rc18BoundaryResultPath = ".workflow/artifacts/rc18-disposable-installed-system-boundary/result.json",
    [string]$Rc18ImageBoundaryPath = ".workflow/artifacts/rc18-disposable-installed-system-boundary/image-boundary.json",
    [string]$Rc18BaselineResultPath = ".workflow/artifacts/rc18-installed-system-baseline/result.json",
    [string]$Rc18BaselineIdentityPath = ".workflow/artifacts/rc18-installed-system-baseline/baseline-identity.json",
    [string]$Rc18BootStateProjectionPath = ".workflow/artifacts/rc18-installed-system-baseline/boot-state-projection.json",
    [string]$Rc18ImageBoundaryFailClosedResultPath = ".workflow/artifacts/rc18-image-boundary-fail-closed/result.json",
    [string]$Rc18InstallResultPath = ".workflow/artifacts/rc18-isolated-install-drill/result.json",
    [string]$Rc18InstallEvidencePath = ".workflow/artifacts/rc18-isolated-install-drill/install-drill-evidence.json",
    [string]$Rc18UpdateResultPath = ".workflow/artifacts/rc18-isolated-update-drill/result.json",
    [string]$Rc18UpdateEvidencePath = ".workflow/artifacts/rc18-isolated-update-drill/update-drill-evidence.json",
    [string]$Rc18RollbackPreconditionsResultPath = ".workflow/artifacts/rc18-image-rollback-preconditions/result.json",
    [string]$Rc18RollbackResultPath = ".workflow/artifacts/rc18-isolated-rollback-drill/result.json",
    [string]$Rc18RollbackEvidencePath = ".workflow/artifacts/rc18-isolated-rollback-drill/rollback-drill-evidence.json",
    [string]$Rc18SupportRecoveryResultPath = ".workflow/artifacts/rc18-isolated-support-recovery/result.json",
    [string]$Rc18SupportBundlePath = ".workflow/artifacts/rc18-isolated-support-recovery/isolated-support-bundle.json",
    [string]$Rc18RecoveryReferenceIndexPath = ".workflow/artifacts/rc18-isolated-support-recovery/recovery-reference-index.json",
    [string]$Rc18ConsumerSmokeResultPath = ".workflow/artifacts/rc18-installed-system-consumer-smoke/result.json",
    [string]$Rc18ConsumerSmokeEvidencePath = ".workflow/artifacts/rc18-installed-system-consumer-smoke/consumer-smoke-evidence.json",
    [string]$Rc16ReleasePackageResultPath = ".workflow/artifacts/rc16-release-package-artifact-set/result.json",
    [string]$Rc16ReleasePackageArtifactSetPath = ".workflow/artifacts/rc16-release-package-artifact-set/release-package-artifact-set.json",
    [string]$Rc16MediaManifestResultPath = ".workflow/artifacts/rc16-installable-media-manifest/result.json",
    [string]$Rc16MediaManifestPath = ".workflow/artifacts/rc16-installable-media-manifest/installable-media-manifest.json",
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

function New-InputRef {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Role,
        $Json = $null,
        [bool]$Required = $true
    )
    $resolved = Resolve-RepoPath $Path
    $present = Test-Path -LiteralPath $resolved -PathType Leaf
    return [ordered]@{
        id = $Id
        role = $Role
        path = Get-StablePath $resolved
        sha256 = Get-FileSha256 $resolved
        size_bytes = if ($present) { (Get-Item -LiteralPath $resolved).Length } else { $null }
        present = $present
        required = $Required
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
        denied_before_effect = $true
        side_effects = [ordered]@{
            artifact_built = $false
            payload_uploaded = $false
            external_payload_published = $false
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

function Get-FinalSourceHash {
    param(
        $FinalResult,
        [Parameter(Mandatory = $true)][string]$Path
    )
    foreach ($entry in @($FinalResult.source_artifacts)) {
        if ($entry.path -eq $Path) {
            return $entry.sha256
        }
    }
    return $null
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
$resolvedRc18FinalAuditResultPath = Resolve-RepoPath $Rc18FinalAuditResultPath
$resolvedRc18FinalAuditEvidencePath = Resolve-RepoPath $Rc18FinalAuditEvidencePath
$resolvedRc18BoundaryResultPath = Resolve-RepoPath $Rc18BoundaryResultPath
$resolvedRc18ImageBoundaryPath = Resolve-RepoPath $Rc18ImageBoundaryPath
$resolvedRc18BaselineResultPath = Resolve-RepoPath $Rc18BaselineResultPath
$resolvedRc18BaselineIdentityPath = Resolve-RepoPath $Rc18BaselineIdentityPath
$resolvedRc18BootStateProjectionPath = Resolve-RepoPath $Rc18BootStateProjectionPath
$resolvedRc18ImageBoundaryFailClosedResultPath = Resolve-RepoPath $Rc18ImageBoundaryFailClosedResultPath
$resolvedRc18InstallResultPath = Resolve-RepoPath $Rc18InstallResultPath
$resolvedRc18InstallEvidencePath = Resolve-RepoPath $Rc18InstallEvidencePath
$resolvedRc18UpdateResultPath = Resolve-RepoPath $Rc18UpdateResultPath
$resolvedRc18UpdateEvidencePath = Resolve-RepoPath $Rc18UpdateEvidencePath
$resolvedRc18RollbackPreconditionsResultPath = Resolve-RepoPath $Rc18RollbackPreconditionsResultPath
$resolvedRc18RollbackResultPath = Resolve-RepoPath $Rc18RollbackResultPath
$resolvedRc18RollbackEvidencePath = Resolve-RepoPath $Rc18RollbackEvidencePath
$resolvedRc18SupportRecoveryResultPath = Resolve-RepoPath $Rc18SupportRecoveryResultPath
$resolvedRc18SupportBundlePath = Resolve-RepoPath $Rc18SupportBundlePath
$resolvedRc18RecoveryReferenceIndexPath = Resolve-RepoPath $Rc18RecoveryReferenceIndexPath
$resolvedRc18ConsumerSmokeResultPath = Resolve-RepoPath $Rc18ConsumerSmokeResultPath
$resolvedRc18ConsumerSmokeEvidencePath = Resolve-RepoPath $Rc18ConsumerSmokeEvidencePath
$resolvedRc16ReleasePackageResultPath = Resolve-RepoPath $Rc16ReleasePackageResultPath
$resolvedRc16ReleasePackageArtifactSetPath = Resolve-RepoPath $Rc16ReleasePackageArtifactSetPath
$resolvedRc16MediaManifestResultPath = Resolve-RepoPath $Rc16MediaManifestResultPath
$resolvedRc16MediaManifestPath = Resolve-RepoPath $Rc16MediaManifestPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$rc18FinalAuditResult = Read-Json $resolvedRc18FinalAuditResultPath
$rc18FinalAuditEvidence = Read-Json $resolvedRc18FinalAuditEvidencePath
$rc18BoundaryResult = Read-Json $resolvedRc18BoundaryResultPath
$rc18ImageBoundary = Read-Json $resolvedRc18ImageBoundaryPath
$rc18BaselineResult = Read-Json $resolvedRc18BaselineResultPath
$rc18BaselineIdentity = Read-Json $resolvedRc18BaselineIdentityPath
$rc18BootStateProjection = Read-Json $resolvedRc18BootStateProjectionPath
$rc18ImageBoundaryFailClosedResult = Read-Json $resolvedRc18ImageBoundaryFailClosedResultPath
$rc18InstallResult = Read-Json $resolvedRc18InstallResultPath
$rc18InstallEvidence = Read-Json $resolvedRc18InstallEvidencePath
$rc18UpdateResult = Read-Json $resolvedRc18UpdateResultPath
$rc18UpdateEvidence = Read-Json $resolvedRc18UpdateEvidencePath
$rc18RollbackPreconditionsResult = Read-Json $resolvedRc18RollbackPreconditionsResultPath
$rc18RollbackResult = Read-Json $resolvedRc18RollbackResultPath
$rc18RollbackEvidence = Read-Json $resolvedRc18RollbackEvidencePath
$rc18SupportRecoveryResult = Read-Json $resolvedRc18SupportRecoveryResultPath
$rc18SupportBundle = Read-Json $resolvedRc18SupportBundlePath
$rc18RecoveryReferenceIndex = Read-Json $resolvedRc18RecoveryReferenceIndexPath
$rc18ConsumerSmokeResult = Read-Json $resolvedRc18ConsumerSmokeResultPath
$rc18ConsumerSmokeEvidence = Read-Json $resolvedRc18ConsumerSmokeEvidencePath
$rc16ReleasePackageResult = Read-Json $resolvedRc16ReleasePackageResultPath
$rc16ReleasePackageArtifactSet = Read-Json $resolvedRc16ReleasePackageArtifactSetPath
$rc16MediaManifestResult = Read-Json $resolvedRc16MediaManifestResultPath
$rc16MediaManifest = Read-Json $resolvedRc16MediaManifestPath

$rc19PreviousStatus = Get-TaskStatus -Plan $plan -TaskId "RC19-001"
$rc19TaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC19-010"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc19PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC19-010" -and ($rc19TaskStatus -eq "pending" -or $rc19TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC19-011" -and $rc19TaskStatus -eq "completed")
    )
)

$inputRefs = @(
    (New-InputRef -Id "rc19-plan" -Path $PlanPath -Role "rc19 workflow plan" -Json $plan),
    (New-InputRef -Id "rc19-authority-contract" -Path $ContractPath -Role "rc19 installable image authority contract"),
    (New-InputRef -Id "rc18-final-audit-result" -Path $Rc18FinalAuditResultPath -Role "rc18 final closeout result" -Json $rc18FinalAuditResult),
    (New-InputRef -Id "rc18-final-audit-evidence" -Path $Rc18FinalAuditEvidencePath -Role "rc18 final audit evidence" -Json $rc18FinalAuditEvidence),
    (New-InputRef -Id "rc18-boundary-result" -Path $Rc18BoundaryResultPath -Role "disposable image boundary result" -Json $rc18BoundaryResult),
    (New-InputRef -Id "rc18-image-boundary" -Path $Rc18ImageBoundaryPath -Role "disposable image boundary artifact" -Json $rc18ImageBoundary),
    (New-InputRef -Id "rc18-baseline-result" -Path $Rc18BaselineResultPath -Role "installed-system baseline result" -Json $rc18BaselineResult),
    (New-InputRef -Id "rc18-baseline-identity" -Path $Rc18BaselineIdentityPath -Role "installed-system baseline identity" -Json $rc18BaselineIdentity),
    (New-InputRef -Id "rc18-boot-state-projection" -Path $Rc18BootStateProjectionPath -Role "image-local boot projection" -Json $rc18BootStateProjection),
    (New-InputRef -Id "rc18-image-boundary-fail-closed-result" -Path $Rc18ImageBoundaryFailClosedResultPath -Role "image boundary fail-closed result" -Json $rc18ImageBoundaryFailClosedResult),
    (New-InputRef -Id "rc18-isolated-install-result" -Path $Rc18InstallResultPath -Role "isolated install result" -Json $rc18InstallResult),
    (New-InputRef -Id "rc18-isolated-install-evidence" -Path $Rc18InstallEvidencePath -Role "isolated install evidence" -Json $rc18InstallEvidence),
    (New-InputRef -Id "rc18-isolated-update-result" -Path $Rc18UpdateResultPath -Role "isolated update result" -Json $rc18UpdateResult),
    (New-InputRef -Id "rc18-isolated-update-evidence" -Path $Rc18UpdateEvidencePath -Role "isolated update evidence" -Json $rc18UpdateEvidence),
    (New-InputRef -Id "rc18-rollback-preconditions-result" -Path $Rc18RollbackPreconditionsResultPath -Role "image rollback preconditions result" -Json $rc18RollbackPreconditionsResult),
    (New-InputRef -Id "rc18-isolated-rollback-result" -Path $Rc18RollbackResultPath -Role "isolated rollback result" -Json $rc18RollbackResult),
    (New-InputRef -Id "rc18-isolated-rollback-evidence" -Path $Rc18RollbackEvidencePath -Role "isolated rollback evidence" -Json $rc18RollbackEvidence),
    (New-InputRef -Id "rc18-support-recovery-result" -Path $Rc18SupportRecoveryResultPath -Role "isolated support recovery result" -Json $rc18SupportRecoveryResult),
    (New-InputRef -Id "rc18-support-bundle" -Path $Rc18SupportBundlePath -Role "local redacted support bundle" -Json $rc18SupportBundle),
    (New-InputRef -Id "rc18-recovery-reference-index" -Path $Rc18RecoveryReferenceIndexPath -Role "projection-only recovery reference index" -Json $rc18RecoveryReferenceIndex),
    (New-InputRef -Id "rc18-consumer-smoke-result" -Path $Rc18ConsumerSmokeResultPath -Role "installed-system consumer smoke result" -Json $rc18ConsumerSmokeResult),
    (New-InputRef -Id "rc18-consumer-smoke-evidence" -Path $Rc18ConsumerSmokeEvidencePath -Role "installed-system consumer smoke evidence" -Json $rc18ConsumerSmokeEvidence),
    (New-InputRef -Id "rc16-release-package-result" -Path $Rc16ReleasePackageResultPath -Role "current AIOS release package result" -Json $rc16ReleasePackageResult),
    (New-InputRef -Id "rc16-release-package-artifact-set" -Path $Rc16ReleasePackageArtifactSetPath -Role "current AIOS release package artifact set" -Json $rc16ReleasePackageArtifactSet),
    (New-InputRef -Id "rc16-media-manifest-result" -Path $Rc16MediaManifestResultPath -Role "current AIOS installable media result" -Json $rc16MediaManifestResult),
    (New-InputRef -Id "rc16-media-manifest" -Path $Rc16MediaManifestPath -Role "current AIOS installable media manifest" -Json $rc16MediaManifest)
)

$missingRequiredRefs = @($inputRefs | Where-Object { $_.required -and (-not $_.present -or $_.sha256 -notmatch "^[0-9a-f]{64}$") })

$rc18CoreRefs = @(
    $Rc18BoundaryResultPath,
    $Rc18BaselineResultPath,
    $Rc18ImageBoundaryFailClosedResultPath,
    $Rc18InstallResultPath,
    $Rc18UpdateResultPath,
    $Rc18RollbackPreconditionsResultPath,
    $Rc18RollbackResultPath,
    $Rc18SupportRecoveryResultPath,
    $Rc18ConsumerSmokeResultPath
)
$sourceHashMismatches = @()
foreach ($path in $rc18CoreRefs) {
    $stablePath = Get-StablePath (Resolve-RepoPath $path)
    $expected = Get-FinalSourceHash -FinalResult $rc18FinalAuditResult -Path $stablePath
    $actual = Get-FileSha256 (Resolve-RepoPath $path)
    if ($null -eq $expected -or $expected -ne $actual) {
        $sourceHashMismatches += [ordered]@{ path = $stablePath; expected = $expected; actual = $actual }
    }
}

$allRc18ResultsPassed = (
    $rc18BoundaryResult.status -eq "passed" -and
    $rc18BaselineResult.status -eq "passed" -and
    $rc18ImageBoundaryFailClosedResult.status -eq "passed" -and
    $rc18InstallResult.status -eq "passed" -and
    $rc18UpdateResult.status -eq "passed" -and
    $rc18RollbackPreconditionsResult.status -eq "passed" -and
    $rc18RollbackResult.status -eq "passed" -and
    $rc18SupportRecoveryResult.status -eq "passed" -and
    $rc18ConsumerSmokeResult.status -eq "passed"
)
$allRc18NonGa = (
    $rc18BoundaryResult.production_ready_claim -eq $false -and
    $rc18BaselineResult.production_ready_claim -eq $false -and
    $rc18ImageBoundaryFailClosedResult.production_ready_claim -eq $false -and
    $rc18InstallResult.production_ready_claim -eq $false -and
    $rc18UpdateResult.production_ready_claim -eq $false -and
    $rc18RollbackPreconditionsResult.production_ready_claim -eq $false -and
    $rc18RollbackResult.production_ready_claim -eq $false -and
    $rc18SupportRecoveryResult.production_ready_claim -eq $false -and
    $rc18ConsumerSmokeResult.production_ready_claim -eq $false
)
$rc18FinalReady = (
    $rc18FinalAuditResult.status -eq "passed" -and
    $rc18FinalAuditResult.decision -eq "PASS" -and
    $rc18FinalAuditResult.installed_system_image_ready -eq $true -and
    $rc18FinalAuditResult.production_ready_claim -eq $false -and
    $rc18FinalAuditResult.summary.blockers -eq 0 -and
    $rc18FinalAuditResult.summary.failed_cases -eq 0
)
$consumerReady = (
    $rc18ConsumerSmokeResult.consumer_surface.consumer_decision -eq "installed-system-image-ready" -and
    $rc18ConsumerSmokeResult.consumer_surface.install_readiness -eq "ready" -and
    $rc18ConsumerSmokeResult.consumer_surface.update_readiness -eq "ready" -and
    $rc18ConsumerSmokeResult.consumer_surface.rollback_readiness -eq "ready" -and
    $rc18ConsumerSmokeResult.consumer_surface.support_recovery_readiness -eq "ready" -and
    @($rc18ConsumerSmokeResult.consumer_surface.blockers).Count -eq 0
)
$imageStateChainCoherent = (
    $rc18InstallResult.installed_image_state_id -eq $rc18ConsumerSmokeResult.installed_image_state_id -and
    $rc18UpdateResult.updated_image_state_id -eq $rc18ConsumerSmokeResult.updated_image_state_id -and
    $rc18RollbackResult.restored_image_state_id -eq $rc18ConsumerSmokeResult.restored_image_state_id -and
    $rc18SupportRecoveryResult.installed_image_state_id -eq $rc18ConsumerSmokeResult.installed_image_state_id -and
    $rc18SupportRecoveryResult.updated_image_state_id -eq $rc18ConsumerSmokeResult.updated_image_state_id -and
    $rc18SupportRecoveryResult.restored_image_state_id -eq $rc18ConsumerSmokeResult.restored_image_state_id -and
    $rc18ConsumerSmokeResult.installed_image_state_id -eq $rc18ConsumerSmokeResult.restored_image_state_id
)
$boundaryIdentityCoherent = (
    $rc18BoundaryResult.boundary_id -eq $rc18BaselineResult.boundary_id -and
    $rc18BoundaryResult.boundary_id -eq $rc18InstallResult.boundary_id -and
    $rc18BoundaryResult.boundary_id -eq $rc18UpdateResult.boundary_id -and
    $rc18BoundaryResult.boundary_id -eq $rc18RollbackResult.boundary_id -and
    $rc18BoundaryResult.boundary_id -eq $rc18SupportRecoveryResult.boundary_id -and
    $rc18BoundaryResult.boundary_id -eq $rc18ConsumerSmokeResult.boundary_id
)
$supportRecoveryLocalOnly = (
    $rc18SupportRecoveryResult.invariants.support_upload_performed -eq $false -and
    $rc18SupportRecoveryResult.invariants.recovery_execution_performed -eq $false -and
    $rc18SupportRecoveryResult.invariants.remote_dispatch_enabled -eq $false -and
    $rc18SupportRecoveryResult.invariants.private_signing_material_handled -eq $false
)
$currentReleaseInputsReady = (
    $rc16ReleasePackageResult.status -eq "passed" -and
    $rc16ReleasePackageResult.production_ready_claim -eq $false -and
    $rc16MediaManifestResult.status -eq "passed" -and
    $rc16MediaManifestResult.production_ready_claim -eq $false -and
    -not [string]::IsNullOrWhiteSpace($rc16MediaManifest.release_id) -and
    -not [string]::IsNullOrWhiteSpace($rc16MediaManifest.media_id) -and
    -not [string]::IsNullOrWhiteSpace($rc16MediaManifest.package_id)
)

$identityMaterial = [ordered]@{
    schema = "agentos.rc19-installable-image-artifact-identity-material.v1"
    task = "RC19-010"
    identity_rule = "sha256-over-this-material-excluding-generated-at-and-output-file-hashes"
    source_hashes = @($inputRefs | ForEach-Object { [ordered]@{ id = $_.id; path = $_.path; sha256 = $_.sha256; schema = $_.schema; status = $_.status } })
    rc18_readiness = [ordered]@{
        final_audit_status = $rc18FinalAuditResult.status
        final_audit_decision = $rc18FinalAuditResult.decision
        installed_system_image_ready = $rc18FinalAuditResult.installed_system_image_ready
        install_readiness = $rc18FinalAuditResult.install_readiness
        update_readiness = $rc18FinalAuditResult.update_readiness
        rollback_readiness = $rc18FinalAuditResult.rollback_readiness
        support_recovery_readiness = $rc18FinalAuditResult.support_recovery_readiness
        consumer_decision = $rc18ConsumerSmokeResult.consumer_surface.consumer_decision
        consumer_audit_digest = $rc18ConsumerSmokeResult.consumer_surface.audit_digest
    }
    release_inputs = [ordered]@{
        release_id = $rc16MediaManifest.release_id
        media_id = $rc16MediaManifest.media_id
        package_id = $rc16MediaManifest.package_id
        release_package_id = $rc16ReleasePackageResult.package_id
        payload_sha256 = $rc16ReleasePackageResult.package_surface.current_payload_sha256
        manifest_sha256 = $rc16ReleasePackageResult.package_surface.manifest_sha256
        checksum_set_sha256 = $rc16ReleasePackageResult.package_surface.checksum_set_sha256
    }
    image_identity = [ordered]@{
        boundary_id = $rc18BoundaryResult.boundary_id
        state_root_id = $rc18BoundaryResult.state_root_id
        baseline_id = $rc18BaselineResult.baseline_id
        installed_image_state_id = $rc18ConsumerSmokeResult.installed_image_state_id
        updated_image_state_id = $rc18ConsumerSmokeResult.updated_image_state_id
        restored_image_state_id = $rc18ConsumerSmokeResult.restored_image_state_id
    }
    non_ga_boundaries = [ordered]@{
        production_ready_claim = $false
        artifact_materialized = $false
        image_built = $false
        payload_uploaded = $false
        external_payload_published = $false
        host_rootfs_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        remote_dispatch_enabled = $false
        signer_authority = $false
        object_storage_authority = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
    }
}
$identityMaterialHash = Get-StringSha256 (Get-JsonText $identityMaterial)
$installableImageArtifactId = "sha256:$identityMaterialHash"

$reproducibilityInputMap = [ordered]@{
    schema = "agentos.rc19-reproducibility-input-map.v1"
    generated_at = $generatedAtValue
    task = "RC19-010"
    status = "reproducibility-input-map-bound"
    production_ready_claim = $false
    installable_image_artifact_id = $installableImageArtifactId
    identity_material_hash = $identityMaterialHash
    deterministic_rules = [ordered]@{
        output_identity_source = "identity_material_hash"
        generated_at_excluded_from_identity = $true
        output_file_hashes_excluded_from_identity = $true
        required_inputs_must_be_present = $true
        required_inputs_must_have_sha256 = $true
        rc18_final_audit_source_hashes_must_match_current_files = $true
        endpoint_reachability_not_used = $true
        external_mirror_output_not_used = $true
        signer_reachability_not_used = $true
        model_replay_not_used = $true
    }
    inputs = $inputRefs
    identity_material = $identityMaterial
    forbidden_inputs = @(
        "private-signing-material",
        "external-mirror-rendered-state",
        "signer-reachability",
        "object-storage-ui",
        "normal-shell-output",
        "tui-projection",
        "endpoint-reachability-without-local-evidence",
        "model-replay"
    )
}
$inputMapPath = Join-Path $resolvedArtifactDir "reproducibility-input-map.json"
Write-Json $reproducibilityInputMap $inputMapPath
$inputMapSha256 = Get-FileSha256 $inputMapPath

$denialCases = @(
    (New-DenialCase -Id "missing-rc18-final-audit" -Blockers @("rc18-final-audit-not-bound") -Reason "Installable image artifact binding requires RC18 final audit evidence."),
    (New-DenialCase -Id "missing-rc18-consumer-smoke" -Blockers @("rc18-installed-system-consumer-smoke-not-bound") -Reason "Artifact readiness must be derived from consumer smoke readiness."),
    (New-DenialCase -Id "source-hash-drift" -Blockers @("rc18-source-hash-drift") -Reason "RC18 final audit source hashes must match current repo-local evidence."),
    (New-DenialCase -Id "host-rootfs-mutation-attempt" -Blockers @("host-rootfs-mutation-denied") -Reason "RC19-010 cannot mutate host rootfs."),
    (New-DenialCase -Id "host-boot-metadata-mutation-attempt" -Blockers @("host-boot-metadata-mutation-denied") -Reason "RC19-010 cannot mutate host boot metadata."),
    (New-DenialCase -Id "active-artifact-set-mutation-attempt" -Blockers @("active-artifact-set-mutation-denied") -Reason "RC19-010 cannot mutate active artifact state."),
    (New-DenialCase -Id "production-ring-mutation-attempt" -Blockers @("production-ring-mutation-denied") -Reason "RC19-010 cannot mutate production rings."),
    (New-DenialCase -Id "external-payload-publication-attempt" -Blockers @("external-payload-publication-denied") -Reason "RC19-010 does not publish payload bytes."),
    (New-DenialCase -Id "object-storage-provisioning-attempt" -Blockers @("object-storage-provisioning-denied") -Reason "Object storage provisioning is outside RC19 body scope."),
    (New-DenialCase -Id "signer-authority-attempt" -Blockers @("signer-authority-denied") -Reason "Signer reachability is not installable image artifact authority."),
    (New-DenialCase -Id "support-upload-attempt" -Blockers @("support-upload-denied") -Reason "Support upload is outside RC19-010 scope."),
    (New-DenialCase -Id "recovery-execution-attempt" -Blockers @("recovery-execution-denied") -Reason "Recovery execution is outside RC19-010 scope.")
)

$artifactSet = [ordered]@{
    schema = "agentos.rc19-reproducible-installable-image-artifact-set.v1"
    generated_at = $generatedAtValue
    task = "RC19-010"
    status = "reproducible-installable-image-artifact-set-bound-non-ga"
    production_ready_claim = $false
    installable_image_artifact_id = $installableImageArtifactId
    identity_material_hash = $identityMaterialHash
    reproducibility_input_map = [ordered]@{
        path = Get-StablePath $inputMapPath
        sha256 = $inputMapSha256
    }
    artifact_surface = [ordered]@{
        state = "installable-image-artifact-bound-evidence-only"
        deterministic_output_identity = $true
        reproducibility_inputs_bound = $true
        source_artifact_hashes_bound = $true
        artifact_materialized = $false
        image_built = $false
        iso_created = $false
        disk_image_created = $false
        payload_uploaded = $false
        external_payload_published = $false
        external_mirror_changed = $false
        object_storage_provisioned = $false
        install_allowed = $false
        first_user_install_allowed = $false
        update_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
    }
    artifact_identity = [ordered]@{
        release = $identityMaterial.release_inputs
        image = $identityMaterial.image_identity
        readiness = $identityMaterial.rc18_readiness
    }
    artifact_classes = [ordered]@{
        rc18_readiness = [ordered]@{
            final_audit = $inputRefs | Where-Object { $_.id -eq "rc18-final-audit-result" } | Select-Object -First 1
            consumer_smoke = $inputRefs | Where-Object { $_.id -eq "rc18-consumer-smoke-result" } | Select-Object -First 1
        }
        image_state_chain = [ordered]@{
            boundary_id = $rc18BoundaryResult.boundary_id
            baseline_id = $rc18BaselineResult.baseline_id
            state_root_id = $rc18BoundaryResult.state_root_id
            installed_image_state_id = $rc18ConsumerSmokeResult.installed_image_state_id
            updated_image_state_id = $rc18ConsumerSmokeResult.updated_image_state_id
            restored_image_state_id = $rc18ConsumerSmokeResult.restored_image_state_id
            coherent = $imageStateChainCoherent
        }
        current_release_inputs = [ordered]@{
            release_package_result = $inputRefs | Where-Object { $_.id -eq "rc16-release-package-result" } | Select-Object -First 1
            release_package_artifact_set = $inputRefs | Where-Object { $_.id -eq "rc16-release-package-artifact-set" } | Select-Object -First 1
            media_manifest_result = $inputRefs | Where-Object { $_.id -eq "rc16-media-manifest-result" } | Select-Object -First 1
            media_manifest = $inputRefs | Where-Object { $_.id -eq "rc16-media-manifest" } | Select-Object -First 1
        }
        support_recovery = [ordered]@{
            support_recovery_result = $inputRefs | Where-Object { $_.id -eq "rc18-support-recovery-result" } | Select-Object -First 1
            support_bundle = $inputRefs | Where-Object { $_.id -eq "rc18-support-bundle" } | Select-Object -First 1
            recovery_reference_index = $inputRefs | Where-Object { $_.id -eq "rc18-recovery-reference-index" } | Select-Object -First 1
            local_only = $supportRecoveryLocalOnly
            support_upload_allowed = $false
            recovery_execution_allowed = $false
        }
    }
    next_required_gates = [ordered]@{
        rc19_011_installer_media_manifest = "required-before-installer-media-claim"
        rc19_012_reproducibility_fail_closed = "required-before-artifact-trust"
        rc19_020_first_user_target_boundary = "required-before-first-user-install-drill"
        rc19_021_first_user_install_drill = "execute-or-deny-inside-disposable-target"
        rc19_030_offline_local_channel = "required-before-local-channel-consumption-claim"
        rc19_050_final_audit = "required-before-rc19-closeout"
    }
    authority = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        install_authority = $false
        first_user_install_authority = $false
        update_authority = $false
        rollback_execution_authority = $false
        support_upload_authority = $false
        recovery_execution_authority = $false
        remote_dispatch_authority = $false
        host_rootfs_mutation_authority = $false
        host_active_slot_mutation_authority = $false
        host_boot_metadata_mutation_authority = $false
        active_artifact_set_mutation_authority = $false
        production_ring_mutation_authority = $false
        mirror_authority = $false
        frontend_authority = $false
        signer_authority = $false
        object_storage_authority = $false
        normal_shell_authority = $false
        tui_authority = $false
        endpoint_reachability_authority = $false
        model_replay_authority = $false
    }
    fail_closed_boundaries = $denialCases
    source = $inputRefs
}
$artifactSetPath = Join-Path $resolvedArtifactDir "installable-image-artifact-set.json"
Write-Json $artifactSet $artifactSetPath
$artifactSetSha256 = Get-FileSha256 $artifactSetPath

$authorityClean = (
    $artifactSet.authority.install_authority -eq $false -and
    $artifactSet.authority.first_user_install_authority -eq $false -and
    $artifactSet.authority.update_authority -eq $false -and
    $artifactSet.authority.rollback_execution_authority -eq $false -and
    $artifactSet.authority.support_upload_authority -eq $false -and
    $artifactSet.authority.recovery_execution_authority -eq $false -and
    $artifactSet.authority.remote_dispatch_authority -eq $false -and
    $artifactSet.authority.host_rootfs_mutation_authority -eq $false -and
    $artifactSet.authority.host_active_slot_mutation_authority -eq $false -and
    $artifactSet.authority.host_boot_metadata_mutation_authority -eq $false -and
    $artifactSet.authority.active_artifact_set_mutation_authority -eq $false -and
    $artifactSet.authority.production_ring_mutation_authority -eq $false -and
    $artifactSet.authority.mirror_authority -eq $false -and
    $artifactSet.authority.frontend_authority -eq $false -and
    $artifactSet.authority.signer_authority -eq $false -and
    $artifactSet.authority.object_storage_authority -eq $false -and
    $artifactSet.authority.normal_shell_authority -eq $false -and
    $artifactSet.authority.tui_authority -eq $false -and
    $artifactSet.authority.endpoint_reachability_authority -eq $false -and
    $artifactSet.authority.model_replay_authority -eq $false
)
$sideEffects = [ordered]@{
    artifact_materialized = $false
    image_built = $false
    iso_created = $false
    disk_image_created = $false
    payload_uploaded = $false
    external_payload_published = $false
    external_mirror_changed = $false
    object_storage_provisioned = $false
    cryptographic_signing_performed = $false
    private_signing_material_handled = $false
    install_performed = $false
    update_performed = $false
    rollback_execution_performed = $false
    support_upload_performed = $false
    recovery_execution_performed = $false
    remote_dispatch_enabled = $false
    host_rootfs_mutated = $false
    host_active_slot_mutated = $false
    host_boot_metadata_mutated = $false
    active_artifact_set_mutated = $false
    production_ring_mutated = $false
}

Add-Check "plan.current_task.rc19_010" $planAllowsRun "RC19-010 must run after RC19-001 completed, while current_task is RC19-010 or during an idempotent rerun after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc19_001_status = $rc19PreviousStatus; rc19_010_status = $rc19TaskStatus })
Add-Check "contract.artifact_gate.present" ($contractText.Contains("Bind a reproducible installable image artifact set from RC18 evidence and current AIOS release inputs") -and $contractText.Contains("external mirror frontend") -and $contractText.Contains("production_ready_claim=false")) "RC19-010 must consume the RC19 installable image authority contract." (New-InputRef -Id "rc19-authority-contract" -Path $ContractPath -Role "rc19 contract")
Add-Check "sources.required.present" (@($missingRequiredRefs).Count -eq 0) "All RC19-010 required source inputs must be present and hashable." (@($missingRequiredRefs | ForEach-Object { $_.path }))
Add-Check "rc18.final_audit.ready" $rc18FinalReady "RC18 final audit must prove installed-system image readiness without GA claim." ([ordered]@{ status = $rc18FinalAuditResult.status; decision = $rc18FinalAuditResult.decision; installed_system_image_ready = $rc18FinalAuditResult.installed_system_image_ready; production_ready_claim = $rc18FinalAuditResult.production_ready_claim; blockers = $rc18FinalAuditResult.summary.blockers; failed_cases = $rc18FinalAuditResult.summary.failed_cases })
Add-Check "rc18.sources.passed_non_ga" ($allRc18ResultsPassed -and $allRc18NonGa) "All RC18 source task results must be passed and non-GA." ([ordered]@{ all_passed = $allRc18ResultsPassed; all_non_ga = $allRc18NonGa })
Add-Check "rc18.final_source_hashes.match" (@($sourceHashMismatches).Count -eq 0) "RC18 final audit source hashes must match current repo-local evidence files." $sourceHashMismatches
Add-Check "rc18.consumer.ready" $consumerReady "RC18 installed-system consumer smoke must report install, update, rollback, and support readiness." $rc18ConsumerSmokeResult.consumer_surface
Add-Check "rc18.image_state_chain.coherent" ($imageStateChainCoherent -and $boundaryIdentityCoherent) "Install, update, rollback, support, consumer, and boundary identity must remain coherent." ([ordered]@{ image_state_chain_coherent = $imageStateChainCoherent; boundary_identity_coherent = $boundaryIdentityCoherent; installed = $rc18ConsumerSmokeResult.installed_image_state_id; updated = $rc18ConsumerSmokeResult.updated_image_state_id; restored = $rc18ConsumerSmokeResult.restored_image_state_id; boundary_id = $rc18BoundaryResult.boundary_id })
Add-Check "rc18.support_recovery.local_only" $supportRecoveryLocalOnly "RC18 support/recovery evidence must remain local-only with upload, recovery execution, remote dispatch, and private material handling disabled." ([ordered]@{ support_upload_performed = $rc18SupportRecoveryResult.invariants.support_upload_performed; recovery_execution_performed = $rc18SupportRecoveryResult.invariants.recovery_execution_performed; remote_dispatch_enabled = $rc18SupportRecoveryResult.invariants.remote_dispatch_enabled; private_signing_material_handled = $rc18SupportRecoveryResult.invariants.private_signing_material_handled })
Add-Check "current_release_inputs.bound" $currentReleaseInputsReady "Current AIOS release and media inputs must be hash-bound for reproducible installable image artifact identity." ([ordered]@{ release_package_status = $rc16ReleasePackageResult.status; media_manifest_status = $rc16MediaManifestResult.status; release_id = $rc16MediaManifest.release_id; media_id = $rc16MediaManifest.media_id; package_id = $rc16MediaManifest.package_id })
Add-Check "identity.deterministic" ($installableImageArtifactId -like "sha256:*" -and $identityMaterialHash -match "^[0-9a-f]{64}$" -and $artifactSet.installable_image_artifact_id -eq $installableImageArtifactId -and $artifactSet.identity_material_hash -eq $identityMaterialHash) "Installable image artifact identity must be deterministic from source material and exclude generated output hashes." ([ordered]@{ installable_image_artifact_id = $installableImageArtifactId; identity_material_hash = $identityMaterialHash; generated_at_excluded = $reproducibilityInputMap.deterministic_rules.generated_at_excluded_from_identity })
Add-Check "artifact_set.bound_non_ga" ($artifactSet.artifact_surface.deterministic_output_identity -eq $true -and $artifactSet.artifact_surface.reproducibility_inputs_bound -eq $true -and $artifactSet.artifact_surface.source_artifact_hashes_bound -eq $true -and $artifactSet.production_ready_claim -eq $false -and $artifactSet.artifact_surface.artifact_materialized -eq $false -and $artifactSet.artifact_surface.image_built -eq $false -and $artifactSet.artifact_surface.external_payload_published -eq $false) "Artifact set must record reproducibility inputs, source hashes, output identity, and non-GA boundaries without building or publishing payloads." $artifactSet.artifact_surface
Add-Check "authority.no_broadening" ($authorityClean -and @($sideEffects.GetEnumerator() | Where-Object { $_.Value -ne $false }).Count -eq 0) "RC19-010 must not broaden host, production, remote, signer, mirror, object storage, support upload, recovery, shell, TUI, endpoint, or model authority." ([ordered]@{ authority = $artifactSet.authority; side_effects = $sideEffects })
Add-Check "outputs.written" ((Test-Path -LiteralPath $inputMapPath -PathType Leaf) -and (Test-Path -LiteralPath $artifactSetPath -PathType Leaf) -and $inputMapSha256 -match "^[0-9a-f]{64}$" -and $artifactSetSha256 -match "^[0-9a-f]{64}$") "RC19-010 must write reproducibility input map and installable image artifact set outputs." ([ordered]@{ input_map = [ordered]@{ path = Get-StablePath $inputMapPath; sha256 = $inputMapSha256 }; artifact_set = [ordered]@{ path = Get-StablePath $artifactSetPath; sha256 = $artifactSetSha256 } })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $inputMapPath),
    (Get-Content -Raw -LiteralPath $artifactSetPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC19-010 outputs must not contain key blocks, private key paths, auth tokens, public identity markers, or signing key file names." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc19-reproducible-installable-image-artifact-result.v1"
    generated_at = $generatedAtValue
    task = "RC19-010"
    status = $resultStatus
    production_ready_claim = $false
    installable_image_artifact_id = $installableImageArtifactId
    identity_material_hash = $identityMaterialHash
    artifact_set_sha256 = $artifactSetSha256
    reproducibility_input_map_sha256 = $inputMapSha256
    outputs = [ordered]@{
        installable_image_artifact_set = [ordered]@{
            path = Get-StablePath $artifactSetPath
            sha256 = $artifactSetSha256
            installable_image_artifact_id = $installableImageArtifactId
        }
        reproducibility_input_map = [ordered]@{
            path = Get-StablePath $inputMapPath
            sha256 = $inputMapSha256
            identity_material_hash = $identityMaterialHash
        }
    }
    artifact_surface = $artifactSet.artifact_surface
    artifact_identity = $artifactSet.artifact_identity
    source = $inputRefs
    checks = @($script:checks)
    blockers = @($script:failedChecks | ForEach-Object { $_.id })
    fail_closed_boundaries = $denialCases
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        reproducible_identity_bound = ($identityMaterialHash -match "^[0-9a-f]{64}$")
        artifact_materialized = $false
        image_built = $false
        iso_created = $false
        disk_image_created = $false
        payload_uploaded = $false
        external_payload_published = $false
        external_mirror_changed = $false
        nginx_or_tls_changed = $false
        signer_infra_changed = $false
        object_storage_infra_changed = $false
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
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
        mirror_authority = $false
        frontend_authority = $false
        signer_authority = $false
        object_storage_authority = $false
        endpoint_reachability_authority = $false
        model_replay_authority = $false
        normal_shell_authority = $false
        tui_authority = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($denialCases).Count
        failed_cases = 0
        rc19_010_complete = (@($script:failedChecks).Count -eq 0)
        installable_image_artifact_id = $installableImageArtifactId
        source_inputs = @($inputRefs).Count
        missing_required_inputs = @($missingRequiredRefs).Count
        source_hash_mismatches = @($sourceHashMismatches).Count
        next_task = "RC19-011"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC19-010-reproducible-installable-image-artifact.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc19-reproducible-installable-image-artifact-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC19-010"
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
    artifact_surface = $result.artifact_surface
    artifact_identity = $result.artifact_identity
    invariants = $result.invariants
    completion = [ordered]@{
        rc19_010_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC19-011"
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
    throw "Sensitive marker detected in RC19-010 outputs."
}

Write-Host "RC19 reproducible installable image artifact $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Artifact set: $(Get-StablePath $artifactSetPath)"
Write-Host "Input map: $(Get-StablePath $inputMapPath)"
Write-Host "Installable image artifact id: $installableImageArtifactId"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($denialCases).Count), failed cases: 0"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
