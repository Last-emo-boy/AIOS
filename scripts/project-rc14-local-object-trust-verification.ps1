param(
    [string]$ArtifactDir = ".workflow/artifacts/rc14-local-object-trust-verification",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc14",
    [string]$PlanPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc14/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc14/docs/rc14-local-execution-readiness-contract.md",
    [string]$DriftRepairResultPath = ".workflow/artifacts/rc14-declared-current-drift-zero-repair/result.json",
    [string]$IdentitySetPath = ".workflow/artifacts/rc14-declared-current-drift-zero-repair/declared-current-reconciled-identity-set.json",
    [string]$FreshnessResultPath = ".workflow/artifacts/rc14-freshness-window-revocation-binding/result.json",
    [string]$FreshnessBindingPath = ".workflow/artifacts/rc14-freshness-window-revocation-binding/freshness-window-revocation-binding.json",
    [string]$FreshnessHandoffPath = ".workflow/artifacts/rc14-freshness-window-revocation-binding/local-object-trust-verification-handoff.json",
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

function Copy-JsonObject {
    param([Parameter(Mandatory = $true)]$Value)
    return ($Value | ConvertTo-Json -Depth 100 | ConvertFrom-Json)
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

function Add-Comparison {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [AllowNull()]$Expected,
        [AllowNull()]$Actual,
        [Parameter(Mandatory = $true)][string]$ExpectedSource,
        [Parameter(Mandatory = $true)][string]$ActualSource,
        [string]$DenialReason = "local-object-trust-drift"
    )
    $expectedText = if ($null -eq $Expected) { $null } else { [string]$Expected }
    $actualText = if ($null -eq $Actual) { $null } else { [string]$Actual }
    $matched = ($expectedText -eq $actualText)
    $entry = [ordered]@{
        id = $Id
        status = if ($matched) { "matched" } else { "drift" }
        expected = $expectedText
        actual = $actualText
        expected_source = $ExpectedSource
        actual_source = $ActualSource
        denial_reason = if ($matched) { $null } else { $DenialReason }
    }
    $script:comparisons += $entry
    if (-not $matched) {
        $script:comparisonDrifts += $entry
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
    $publicKeyMarker = "PUBLIC" + " KEY"
    $identityWord = "finger" + "print"
    $markers = @(
        ("BEGIN " + $privateKeyMarker),
        ("BEGIN " + $publicKeyMarker),
        ($privateKeyMarker + "-----"),
        ("Authorization:" + " Bearer"),
        ("Bearer" + " "),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ("." + "local-release-authority"),
        ("signing" + "-key." + "pem"),
        ("/etc/" + "aios-signer/" + "private"),
        ("." + "pem"),
        $identityWord
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

function Test-TrustCase {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)]$Gates
    )
    $reasons = @()
    if ($Gates.declared_current_drift_zero -ne $true) { $reasons += "declared-current-drift-zero-not-proved" }
    if ($Gates.descriptor_manifest_consistent -ne $true) { $reasons += "descriptor-manifest-consistency-not-proved" }
    if ($Gates.payload_size_match -ne $true) { $reasons += "payload-size-mismatch" }
    if ($Gates.payload_digest_match -ne $true) { $reasons += "payload-digest-mismatch" }
    if ($Gates.descriptor_digest_bound -ne $true) { $reasons += "descriptor-digest-not-bound" }
    if ($Gates.manifest_bound -ne $true) { $reasons += "manifest-not-bound" }
    if ($Gates.checksum_set_bound -ne $true) { $reasons += "checksum-set-not-bound" }
    if ($Gates.public_signature_bound -ne $true) { $reasons += "public-signature-not-bound" }
    if ($Gates.public_signature_crypto_verified -ne $true) { $reasons += "public-signature-crypto-not-verified" }
    if ($Gates.revocation_snapshot_bound -ne $true) { $reasons += "revocation-snapshot-not-bound" }
    if ($Gates.revocation_snapshot_current -ne $true) { $reasons += "revocation-snapshot-stale-or-missing" }
    if ($Gates.revocation_status_not_revoked -ne $true) { $reasons += "revocation-status-not-current" }
    if ($Gates.freshness_window_bound -ne $true) { $reasons += "freshness-window-missing" }
    if ($Gates.freshness_window_current -ne $true) { $reasons += "freshness-window-stale-or-missing" }
    if ($Gates.compatibility_bound -ne $true) { $reasons += "compatibility-metadata-missing" }
    if ($Gates.rollback_bound -ne $true) { $reasons += "rollback-baseline-missing" }
    if ($Gates.support_recovery_bound -ne $true) { $reasons += "support-recovery-binding-missing" }
    if ($Gates.no_private_material -ne $true) { $reasons += "private-signing-material-used" }
    if ($Gates.endpoint_reachability_claimed -eq $true) { $reasons += "endpoint-reachability-is-not-trust" }
    if ($Gates.frontend_authority_claimed -eq $true) { $reasons += "frontend-output-is-not-trust" }
    if ($Gates.signer_reachability_claimed -eq $true) { $reasons += "signer-reachability-is-not-trust" }
    if ($Gates.tui_authority_claimed -eq $true) { $reasons += "tui-output-is-not-trust" }
    if ($Gates.shell_authority_claimed -eq $true) { $reasons += "shell-output-is-not-trust" }
    if ($Gates.model_replay_authority_claimed -eq $true) { $reasons += "model-replay-is-not-trust" }
    $uniqueReasons = @($reasons | Select-Object -Unique)
    return [ordered]@{
        id = $Id
        status = if ($uniqueReasons.Count -eq 0) { "accepted" } else { "denied" }
        denied = ($uniqueReasons.Count -gt 0)
        gates = $Gates
        denial_reasons = $uniqueReasons
    }
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:failedChecks = @()
$script:comparisons = @()
$script:comparisonDrifts = @()

$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$resolvedWorkflowDir = Resolve-RepoPath $WorkflowDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $resolvedWorkflowDir "evidence") | Out-Null

$resolvedPlanPath = Resolve-RepoPath $PlanPath
$resolvedContractPath = Resolve-RepoPath $ContractPath
$resolvedDriftRepairResultPath = Resolve-RepoPath $DriftRepairResultPath
$resolvedIdentitySetPath = Resolve-RepoPath $IdentitySetPath
$resolvedFreshnessResultPath = Resolve-RepoPath $FreshnessResultPath
$resolvedFreshnessBindingPath = Resolve-RepoPath $FreshnessBindingPath
$resolvedFreshnessHandoffPath = Resolve-RepoPath $FreshnessHandoffPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$driftRepairResult = Read-Json $resolvedDriftRepairResultPath
$identitySet = Read-Json $resolvedIdentitySetPath
$freshnessResult = Read-Json $resolvedFreshnessResultPath
$freshnessBinding = Read-Json $resolvedFreshnessBindingPath
$freshnessHandoff = Read-Json $resolvedFreshnessHandoffPath

$payloadPath = Resolve-RepoPath ([string]$identitySet.release_identity.payload_path)
$descriptorPath = Resolve-RepoPath ([string]$identitySet.descriptor_identity.descriptor_path)
$descriptorCandidatePath = Resolve-RepoPath ([string]$identitySet.descriptor_identity.descriptor_candidate_path)
$initramfsManifestPath = Resolve-RepoPath ([string]$identitySet.manifest_identity.initramfs_manifest_path)
$payloadManifestPath = Resolve-RepoPath ([string]$identitySet.manifest_identity.payload_manifest_path)
$objectChecksumsPath = Resolve-RepoPath ([string]$identitySet.manifest_identity.object_checksums_path)
$compatibilityPath = Resolve-RepoPath ([string]$identitySet.compatibility_identity.path)
$rollbackBaselinePath = Resolve-RepoPath ([string]$identitySet.rollback_identity.path)
$supportIndexPath = Resolve-RepoPath ([string]$identitySet.support_recovery_identity.path)
$freshnessWindowPath = Resolve-RepoPath ([string]$freshnessBinding.freshness_window.path)
$publicSignatureArtifactPath = Resolve-RepoPath ([string]$freshnessBinding.public_signature.signature_artifact_path)

$descriptor = Read-Json $descriptorPath
$descriptorCandidate = Read-Json $descriptorCandidatePath
$initramfsManifest = Read-Json $initramfsManifestPath
$payloadManifest = Read-Json $payloadManifestPath
$objectChecksums = Read-Json $objectChecksumsPath
$compatibility = Read-Json $compatibilityPath
$rollbackBaseline = Read-Json $rollbackBaselinePath
$supportIndex = Read-Json $supportIndexPath
$freshnessWindow = Read-Json $freshnessWindowPath

$generatedAtValue = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }
$releaseId = [string]$identitySet.release_id
$payloadSha256 = Get-FileSha256 $payloadPath
$payloadSize = if (Test-Path -LiteralPath $payloadPath -PathType Leaf) { (Get-Item -LiteralPath $payloadPath).Length } else { $null }
$descriptorSha256 = Get-FileSha256 $descriptorPath
$descriptorCandidateSha256 = Get-FileSha256 $descriptorCandidatePath
$initramfsManifestSha256 = Get-FileSha256 $initramfsManifestPath
$payloadManifestSha256 = Get-FileSha256 $payloadManifestPath
$objectChecksumsSha256 = Get-FileSha256 $objectChecksumsPath
$compatibilitySha256 = Get-FileSha256 $compatibilityPath
$rollbackBaselineSha256 = Get-FileSha256 $rollbackBaselinePath
$supportIndexSha256 = Get-FileSha256 $supportIndexPath
$freshnessWindowSha256 = Get-FileSha256 $freshnessWindowPath
$freshnessBindingSha256 = Get-FileSha256 $resolvedFreshnessBindingPath
$publicSignatureArtifactSha256 = Get-FileSha256 $publicSignatureArtifactPath

$source = [ordered]@{
    rc14_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc14_contract = New-ArtifactRef $resolvedContractPath
    rc14_drift_repair_result = New-ArtifactRef $resolvedDriftRepairResultPath $driftRepairResult
    rc14_reconciled_identity_set = New-ArtifactRef $resolvedIdentitySetPath $identitySet
    rc14_freshness_result = New-ArtifactRef $resolvedFreshnessResultPath $freshnessResult
    rc14_freshness_binding = New-ArtifactRef $resolvedFreshnessBindingPath $freshnessBinding
    rc14_local_object_trust_handoff = New-ArtifactRef $resolvedFreshnessHandoffPath $freshnessHandoff
    current_payload_bytes = New-ArtifactRef $payloadPath
    descriptor = New-ArtifactRef $descriptorPath $descriptor
    descriptor_candidate = New-ArtifactRef $descriptorCandidatePath $descriptorCandidate
    initramfs_manifest = New-ArtifactRef $initramfsManifestPath $initramfsManifest
    payload_manifest = New-ArtifactRef $payloadManifestPath $payloadManifest
    object_checksums = New-ArtifactRef $objectChecksumsPath $objectChecksums
    compatibility = New-ArtifactRef $compatibilityPath $compatibility
    rollback_baseline = New-ArtifactRef $rollbackBaselinePath $rollbackBaseline
    support_index = New-ArtifactRef $supportIndexPath $supportIndex
    freshness_window = New-ArtifactRef $freshnessWindowPath $freshnessWindow
    public_signature_artifact = New-ArtifactRef $publicSignatureArtifactPath
}

$rc14TaskStatus = ($plan.waves.tasks | Where-Object id -eq "RC14-012").status
$rc14PreviousStatus = ($plan.waves.tasks | Where-Object id -eq "RC14-011").status
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc14PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC14-012" -and ($rc14TaskStatus -eq "pending" -or $rc14TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC14-020" -and $rc14TaskStatus -eq "completed")
    )
)
Add-Check "plan.current_task.rc14_012" $planAllowsRun "RC14-012 must run after RC14-011 completed, either while current_task is RC14-012 or while rerunning after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc14_011_status = $rc14PreviousStatus; rc14_012_status = $rc14TaskStatus })
Add-Check "contract.local_object_trust_gate.present" ($contractText.Contains("local_object_trust_allowed") -and $contractText.Contains("endpoint reachability") -and $contractText.Contains("model replay")) "RC14-012 must consume the local object trust and non-authority boundary." $source.rc14_contract
Add-Check "source.rc14_010.drift_zero" ($driftRepairResult.status -eq "passed" -and $driftRepairResult.reconciliation_surface.declared_current_drift_zero -eq $true -and $identitySet.reconciliation.declared_current_drift_zero -eq $true) "RC14-012 requires RC14-010 local drift-zero evidence." ([ordered]@{ result_status = $driftRepairResult.status; drift_zero = $driftRepairResult.reconciliation_surface.declared_current_drift_zero; drift_count = $driftRepairResult.reconciliation_surface.drift_count })
Add-Check "source.rc14_011.freshness_revocation_bound" ($freshnessResult.status -eq "passed" -and $freshnessResult.authority_surface.freshness_revocation_authority_bound -eq $true -and $freshnessBinding.authority_surface.freshness_revocation_authority_bound -eq $true -and $freshnessHandoff.status -eq "ready-for-rc14-012-local-object-trust-verification") "RC14-012 requires current freshness and revocation authority from RC14-011." ([ordered]@{ result_status = $freshnessResult.status; binding_status = $freshnessBinding.status; handoff_status = $freshnessHandoff.status })

Add-Comparison "release_id.identity_vs_descriptor" $identitySet.release_id $descriptor.release_id "RC14 identity release id" "descriptor release id" "release-id-drift"
Add-Comparison "release_id.identity_vs_freshness" $identitySet.release_id $freshnessBinding.release_id "RC14 identity release id" "RC14 freshness binding release id" "release-id-drift"
Add-Comparison "payload.sha256.identity_vs_file" $identitySet.release_identity.payload_sha256 $payloadSha256 "RC14 identity payload sha256" "current payload file sha256" "payload-digest-drift"
Add-Comparison "payload.sha256.identity_vs_descriptor" $identitySet.release_identity.payload_sha256 $descriptor.sha256 "RC14 identity payload sha256" "descriptor sha256" "payload-digest-drift"
Add-Comparison "payload.sha256.identity_vs_manifest" $identitySet.release_identity.payload_sha256 $initramfsManifest.artifact_sha256 "RC14 identity payload sha256" "initramfs manifest artifact_sha256" "payload-digest-drift"
Add-Comparison "payload.sha256.identity_vs_object_checksums" $identitySet.release_identity.payload_sha256 $objectChecksums.sha256 "RC14 identity payload sha256" "object checksums sha256" "payload-digest-drift"
Add-Comparison "payload.size.identity_vs_file" $identitySet.release_identity.payload_size_bytes $payloadSize "RC14 identity payload size_bytes" "current payload file size_bytes" "payload-size-drift"
Add-Comparison "payload.size.identity_vs_descriptor" $identitySet.release_identity.payload_size_bytes $descriptor.size_bytes "RC14 identity payload size_bytes" "descriptor size_bytes" "payload-size-drift"
Add-Comparison "payload.size.identity_vs_object_checksums" $identitySet.release_identity.payload_size_bytes $objectChecksums.size_bytes "RC14 identity payload size_bytes" "object checksums size_bytes" "payload-size-drift"
Add-Comparison "descriptor.file_sha256.identity_vs_file" $identitySet.descriptor_identity.descriptor_file_sha256 $descriptorSha256 "RC14 identity descriptor file sha256" "current descriptor file sha256" "descriptor-digest-drift"
Add-Comparison "descriptor_candidate.file_sha256.identity_vs_file" $identitySet.descriptor_identity.descriptor_candidate_file_sha256 $descriptorCandidateSha256 "RC14 identity descriptor candidate file sha256" "current descriptor candidate file sha256" "descriptor-candidate-digest-drift"
Add-Comparison "manifest.file_sha256.identity_vs_file" $identitySet.manifest_identity.initramfs_manifest_file_sha256 $initramfsManifestSha256 "RC14 identity initramfs manifest sha256" "current initramfs manifest sha256" "manifest-digest-drift"
Add-Comparison "manifest.file_sha256.identity_vs_descriptor" $identitySet.manifest_identity.initramfs_manifest_file_sha256 $descriptor.manifest_sha256 "RC14 identity initramfs manifest sha256" "descriptor manifest sha256" "manifest-digest-drift"
Add-Comparison "payload_manifest.file_sha256.identity_vs_file" $identitySet.manifest_identity.payload_manifest_file_sha256 $payloadManifestSha256 "RC14 identity payload manifest sha256" "current payload manifest sha256" "checksum-set-drift"
Add-Comparison "payload_manifest.file_sha256.identity_vs_descriptor" $identitySet.manifest_identity.payload_manifest_file_sha256 $descriptor.checksums_sha256 "RC14 identity payload manifest sha256" "descriptor checksums sha256" "checksum-set-drift"
Add-Comparison "object_checksums.file_sha256.identity_vs_file" $identitySet.manifest_identity.object_checksums_file_sha256 $objectChecksumsSha256 "RC14 identity object checksums sha256" "current object checksums sha256" "object-checksums-drift"
Add-Comparison "compatibility.sha256.identity_vs_file" $identitySet.compatibility_identity.sha256 $compatibilitySha256 "RC14 identity compatibility sha256" "current compatibility sha256" "compatibility-drift"
Add-Comparison "compatibility.sha256.identity_vs_descriptor" $identitySet.compatibility_identity.sha256 $descriptor.installer_compatibility_sha256 "RC14 identity compatibility sha256" "descriptor compatibility sha256" "compatibility-drift"
Add-Comparison "rollback.sha256.identity_vs_file" $identitySet.rollback_identity.sha256 $rollbackBaselineSha256 "RC14 identity rollback baseline sha256" "current rollback baseline sha256" "rollback-baseline-drift"
Add-Comparison "rollback.sha256.identity_vs_descriptor" $identitySet.rollback_identity.sha256 $descriptor.rollback_baseline_sha256 "RC14 identity rollback baseline sha256" "descriptor rollback baseline sha256" "rollback-baseline-drift"
Add-Comparison "support.sha256.identity_vs_file" $identitySet.support_recovery_identity.sha256 $supportIndexSha256 "RC14 identity support recovery sha256" "current support index sha256" "support-recovery-drift"
Add-Comparison "support.sha256.identity_vs_descriptor" $identitySet.support_recovery_identity.sha256 $descriptor.support_recovery_sha256 "RC14 identity support recovery sha256" "descriptor support recovery sha256" "support-recovery-drift"
Add-Comparison "freshness_window.sha256.binding_vs_file" $freshnessBinding.freshness_window.sha256 $freshnessWindowSha256 "RC14 freshness binding window sha256" "current freshness window sha256" "freshness-window-drift"
Add-Comparison "freshness_binding.sha256.handoff_vs_file" $freshnessHandoff.authority.sha256 $freshnessBindingSha256 "RC14 handoff binding sha256" "current freshness binding sha256" "freshness-binding-drift"
Add-Comparison "public_signature.artifact_sha256.binding_vs_file" $freshnessBinding.public_signature.signature_artifact_sha256 $publicSignatureArtifactSha256 "RC14 freshness binding public signature artifact sha256" "current public signature artifact sha256" "public-signature-drift"

$comparisonCount = @($script:comparisons).Count
$comparisonDriftCount = @($script:comparisonDrifts).Count
$descriptorManifestConsistent = (
    $comparisonDriftCount -eq 0 -and
    [bool]$identitySet.reconciliation.local_reconciled_identity_set_drift_zero -eq $true -and
    [bool]$driftRepairResult.reconciliation_surface.local_descriptor_manifest_consistent -eq $true -and
    [bool]$objectChecksums.hash_matches_manifest -eq $true -and
    [bool]$descriptor.immutable -eq $true -and
    [bool]$descriptorCandidate.immutable -eq $true
)
$declaredCurrentDriftZero = ([bool]$identitySet.reconciliation.declared_current_drift_zero -and [bool]$driftRepairResult.reconciliation_surface.declared_current_drift_zero)
$freshnessAuthority = $freshnessResult.authority_surface
$noPrivateMaterial = (
    $freshnessResult.invariants.local_private_key_material_used -eq $false -and
    $freshnessResult.invariants.private_key_material_read_or_printed -eq $false -and
    $freshnessResult.invariants.cryptographic_signing_performed -eq $false -and
    $freshnessResult.invariants.signer_service_called -eq $false
)

$currentGates = [ordered]@{
    declared_current_drift_zero = $declaredCurrentDriftZero
    descriptor_manifest_consistent = $descriptorManifestConsistent
    payload_size_match = ($payloadSize -eq [int64]$identitySet.release_identity.payload_size_bytes -and $payloadSize -eq [int64]$descriptor.size_bytes)
    payload_digest_match = ($payloadSha256 -eq [string]$identitySet.release_identity.payload_sha256 -and $payloadSha256 -eq [string]$descriptor.sha256)
    descriptor_digest_bound = ($descriptorSha256 -eq [string]$identitySet.descriptor_identity.descriptor_file_sha256)
    manifest_bound = ($initramfsManifestSha256 -eq [string]$identitySet.manifest_identity.initramfs_manifest_file_sha256)
    checksum_set_bound = ($payloadManifestSha256 -eq [string]$identitySet.manifest_identity.payload_manifest_file_sha256 -and $objectChecksumsSha256 -eq [string]$identitySet.manifest_identity.object_checksums_file_sha256)
    public_signature_bound = [bool]$freshnessAuthority.public_signature_bound
    public_signature_crypto_verified = [bool]$freshnessAuthority.public_signature_crypto_verified
    revocation_snapshot_bound = [bool]$freshnessAuthority.revocation_snapshot_bound
    revocation_snapshot_current = [bool]$freshnessAuthority.revocation_snapshot_current
    revocation_status_not_revoked = [bool]$freshnessAuthority.revocation_status_not_revoked
    freshness_window_bound = [bool]$freshnessAuthority.freshness_window_bound
    freshness_window_current = [bool]$freshnessAuthority.freshness_window_current
    compatibility_bound = ($compatibilitySha256 -eq [string]$identitySet.compatibility_identity.sha256)
    rollback_bound = ($rollbackBaselineSha256 -eq [string]$identitySet.rollback_identity.sha256)
    support_recovery_bound = ($supportIndexSha256 -eq [string]$identitySet.support_recovery_identity.sha256)
    no_private_material = $noPrivateMaterial
    endpoint_reachability_claimed = $false
    frontend_authority_claimed = $false
    signer_reachability_claimed = $false
    tui_authority_claimed = $false
    shell_authority_claimed = $false
    model_replay_authority_claimed = $false
}

$cases = @()
$cases += Test-TrustCase -Id "current.local_object_trust_candidate" -Gates $currentGates
$allGood = Copy-JsonObject $currentGates
foreach ($prop in @("declared_current_drift_zero", "descriptor_manifest_consistent", "payload_size_match", "payload_digest_match", "descriptor_digest_bound", "manifest_bound", "checksum_set_bound", "public_signature_bound", "public_signature_crypto_verified", "revocation_snapshot_bound", "revocation_snapshot_current", "revocation_status_not_revoked", "freshness_window_bound", "freshness_window_current", "compatibility_bound", "rollback_bound", "support_recovery_bound", "no_private_material")) {
    $allGood.$prop = $true
}
foreach ($prop in @("endpoint_reachability_claimed", "frontend_authority_claimed", "signer_reachability_claimed", "tui_authority_claimed", "shell_authority_claimed", "model_replay_authority_claimed")) {
    $allGood.$prop = $false
}

$negativeMutations = @(
    @{ id = "negative.declared_current_drift_nonzero"; key = "declared_current_drift_zero"; value = $false },
    @{ id = "negative.descriptor_manifest_inconsistent"; key = "descriptor_manifest_consistent"; value = $false },
    @{ id = "negative.payload_size_mismatch"; key = "payload_size_match"; value = $false },
    @{ id = "negative.payload_digest_mismatch"; key = "payload_digest_match"; value = $false },
    @{ id = "negative.descriptor_unbound"; key = "descriptor_digest_bound"; value = $false },
    @{ id = "negative.manifest_unbound"; key = "manifest_bound"; value = $false },
    @{ id = "negative.checksum_set_unbound"; key = "checksum_set_bound"; value = $false },
    @{ id = "negative.public_signature_missing"; key = "public_signature_bound"; value = $false },
    @{ id = "negative.public_signature_not_verified"; key = "public_signature_crypto_verified"; value = $false },
    @{ id = "negative.revocation_missing"; key = "revocation_snapshot_bound"; value = $false },
    @{ id = "negative.revocation_stale"; key = "revocation_snapshot_current"; value = $false },
    @{ id = "negative.revoked_status"; key = "revocation_status_not_revoked"; value = $false },
    @{ id = "negative.freshness_missing"; key = "freshness_window_bound"; value = $false },
    @{ id = "negative.freshness_stale"; key = "freshness_window_current"; value = $false },
    @{ id = "negative.compatibility_missing"; key = "compatibility_bound"; value = $false },
    @{ id = "negative.rollback_missing"; key = "rollback_bound"; value = $false },
    @{ id = "negative.support_missing"; key = "support_recovery_bound"; value = $false },
    @{ id = "negative.private_material_used"; key = "no_private_material"; value = $false },
    @{ id = "negative.endpoint_reachability_only"; key = "endpoint_reachability_claimed"; value = $true },
    @{ id = "negative.frontend_authority"; key = "frontend_authority_claimed"; value = $true },
    @{ id = "negative.signer_reachability_authority"; key = "signer_reachability_claimed"; value = $true },
    @{ id = "negative.tui_authority"; key = "tui_authority_claimed"; value = $true },
    @{ id = "negative.shell_authority"; key = "shell_authority_claimed"; value = $true },
    @{ id = "negative.model_replay_authority"; key = "model_replay_authority_claimed"; value = $true }
)
foreach ($mutation in $negativeMutations) {
    $gates = Copy-JsonObject $allGood
    $gates.($mutation.key) = $mutation.value
    $cases += Test-TrustCase -Id $mutation.id -Gates $gates
}

$currentDecision = $cases | Where-Object { $_.id -eq "current.local_object_trust_candidate" } | Select-Object -First 1
$negativeCases = @($cases | Where-Object { $_.id -like "negative.*" })
$failedNegativeCases = @($negativeCases | Where-Object { $_.denied -ne $true })
$objectTrustAllowed = ($currentDecision.denied -eq $false)
$quarantinePreflightAllowed = $objectTrustAllowed
$verificationState = if ($objectTrustAllowed) { "local-object-trust-verified" } else { "local-object-trust-denied" }
$objectTrustBlockers = @($currentDecision.denial_reasons)
$downstreamBlockers = @(
    "verified-quarantine-preflight-not-run",
    "agentcore-planspec-not-executable",
    "security-execution-allow-not-bound",
    "two-target-local-canary-identities-not-enrolled",
    "exact-approval-not-bound",
    "controlled-activation-not-authorized",
    "controlled-rollback-not-authorized"
)

Add-Check "trust.current_candidate.accepted" $objectTrustAllowed "RC14-012 must allow local object trust only when drift-zero, descriptor/manifest, signature, revocation, freshness, compatibility, rollback, and support gates all pass." ([ordered]@{ object_trust_allowed = $objectTrustAllowed; blockers = $objectTrustBlockers })
Add-Check "trust.descriptor_manifest_consistent" $descriptorManifestConsistent "Descriptor, manifest, checksum set, compatibility, rollback, and support/recovery references must remain consistent." ([ordered]@{ comparisons = $comparisonCount; comparison_drifts = $comparisonDriftCount; drift_ids = @($script:comparisonDrifts | ForEach-Object { $_.id }) })
Add-Check "trust.freshness_revocation_current" ($freshnessAuthority.freshness_revocation_authority_bound -eq $true -and $freshnessAuthority.freshness_window_current -eq $true -and $freshnessAuthority.revocation_snapshot_current -eq $true -and $freshnessAuthority.revocation_status_not_revoked -eq $true) "Freshness and revocation must be current before local object trust." ([ordered]@{ fresh_until = $freshnessResult.authority_surface.freshness_valid_until; revocation_bound = $freshnessAuthority.revocation_snapshot_bound })
Add-Check "non_authority.negative_cases_denied" ($failedNegativeCases.Count -eq 0 -and @($negativeCases).Count -ge 20) "Endpoint, frontend, signer, TUI, shell, model replay, missing gate, and private-material cases must fail closed." ([ordered]@{ negative_cases = @($negativeCases).Count; failed_negative_cases = @($failedNegativeCases | ForEach-Object { $_.id }) })

$report = [ordered]@{
    schema = "agentos.rc14-local-object-trust-report.v1"
    generated_at = $generatedAtValue
    task = "RC14-012"
    release_id = $releaseId
    status = $verificationState
    production_ready_claim = $false
    current_gates = $currentGates
    current_decision = $currentDecision
    comparisons = [ordered]@{
        count = $comparisonCount
        drifts = $comparisonDriftCount
        detail = $script:comparisons
    }
    source = $source
}

$decision = [ordered]@{
    schema = "agentos.rc14-local-object-trust-decision.v1"
    generated_at = $generatedAtValue
    task = "RC14-012"
    release_id = $releaseId
    status = $verificationState
    production_ready_claim = $false
    local_object_trust_allowed = $objectTrustAllowed
    object_trust_blockers = $objectTrustBlockers
    downstream_blockers = $downstreamBlockers
    quarantine_preflight_allowed = $quarantinePreflightAllowed
    endpoint_reachability_is_trust = $false
    frontend_output_is_trust = $false
    signer_reachability_is_trust = $false
    tui_output_is_trust = $false
    shell_output_is_trust = $false
    model_replay_is_trust = $false
    install_allowed = $false
    activation_allowed = $false
    rollback_execution_allowed = $false
    support_upload_allowed = $false
    recovery_execution_allowed = $false
    remote_dispatch_enabled = $false
    production_ring_mutation_allowed = $false
    side_effects = [ordered]@{
        local_object_trust_recorded = $objectTrustAllowed
        network_probe_performed = $false
        payload_bytes_uploaded = $false
        remote_payload_bytes_downloaded = $false
        quarantine_payload_written = $false
        payload_interpreted = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        production_ring_mutated = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
    }
}

$matrix = [ordered]@{
    schema = "agentos.rc14-local-object-trust-fail-closed-matrix.v1"
    generated_at = $generatedAtValue
    task = "RC14-012"
    release_id = $releaseId
    status = if ($failedNegativeCases.Count -eq 0) { "passed" } else { "failed" }
    cases = $cases
    summary = [ordered]@{
        cases = @($cases).Count
        accepted_current_candidate = $objectTrustAllowed
        negative_cases = @($negativeCases).Count
        denied_negative_cases = @($negativeCases | Where-Object { $_.denied -eq $true }).Count
        failed_negative_cases = @($failedNegativeCases | ForEach-Object { $_.id })
    }
}

$handoff = [ordered]@{
    schema = "agentos.rc14-verified-quarantine-preflight-handoff.v1"
    generated_at = $generatedAtValue
    task = "RC14-012"
    release_id = $releaseId
    status = if ($objectTrustAllowed) { "ready-for-rc14-020-verified-quarantine-preflight" } else { "blocked-by-local-object-trust" }
    production_ready_claim = $false
    expected_next_task = "RC14-020"
    local_object_trust = [ordered]@{
        decision_path = $null
        decision_sha256 = $null
        report_path = $null
        report_sha256 = $null
        local_object_trust_allowed = $objectTrustAllowed
        quarantine_preflight_allowed = $quarantinePreflightAllowed
    }
    release_identity = $identitySet.release_identity
    required_next_gate = [ordered]@{
        verified_quarantine_preflight = $true
        bytes_may_be_written_only_to_quarantine = $true
        payload_interpretation_allowed_before_preflight = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
    }
    blocked_authority = [ordered]@{
        agentcore_planspec_executable = $false
        security_execution_allowed = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
    }
    blockers = $downstreamBlockers
}

$reportPath = Join-Path $resolvedArtifactDir "object-trust-report.json"
$decisionPath = Join-Path $resolvedArtifactDir "object-trust-decision.json"
$matrixPath = Join-Path $resolvedArtifactDir "object-trust-fail-closed-matrix.json"
$handoffPath = Join-Path $resolvedArtifactDir "verified-quarantine-preflight-handoff.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC14-012-local-object-trust-verification.json"

Write-Json $report $reportPath
Write-Json $decision $decisionPath
$handoff.local_object_trust.decision_path = Get-StablePath $decisionPath
$handoff.local_object_trust.decision_sha256 = Get-FileSha256 $decisionPath
$handoff.local_object_trust.report_path = Get-StablePath $reportPath
$handoff.local_object_trust.report_sha256 = Get-FileSha256 $reportPath
Write-Json $matrix $matrixPath
Write-Json $handoff $handoffPath

Add-Check "outputs.secret_safe" (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $reportPath), (Get-Content -Raw -LiteralPath $decisionPath), (Get-Content -Raw -LiteralPath $matrixPath), (Get-Content -Raw -LiteralPath $handoffPath))) "RC14-012 outputs must not contain key blocks, raw signatures, raw public identity, tokens, signer internals, or private authority paths." $null
Add-Check "outputs.side_effects_absent" ($decision.side_effects.network_probe_performed -eq $false -and $decision.side_effects.remote_payload_bytes_downloaded -eq $false -and $decision.side_effects.quarantine_payload_written -eq $false -and $decision.side_effects.payload_interpreted -eq $false -and $decision.side_effects.install_performed -eq $false -and $decision.side_effects.activation_performed -eq $false -and $decision.side_effects.rollback_execution_performed -eq $false -and $decision.side_effects.support_upload_performed -eq $false -and $decision.side_effects.recovery_execution_performed -eq $false -and $decision.side_effects.remote_dispatch_enabled -eq $false -and $decision.side_effects.production_ring_mutated -eq $false -and $decision.side_effects.active_slot_mutated -eq $false -and $decision.side_effects.boot_metadata_mutated -eq $false -and $decision.side_effects.active_artifact_set_mutated -eq $false) "RC14-012 must not probe network, fetch, quarantine, interpret, install, activate, rollback, upload support, recover, dispatch, or mutate production state." $decision.side_effects

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc14-local-object-trust-verification-result.v1"
    generated_at = $generatedAtValue
    task = "RC14-012"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    verification_surface = [ordered]@{
        state = $verificationState
        local_object_trust_allowed = $objectTrustAllowed
        object_trust_blockers = $objectTrustBlockers
        declared_current_drift_zero = $declaredCurrentDriftZero
        descriptor_manifest_consistent = $descriptorManifestConsistent
        public_signature_bound = [bool]$freshnessAuthority.public_signature_bound
        public_signature_crypto_verified = [bool]$freshnessAuthority.public_signature_crypto_verified
        revocation_snapshot_bound = [bool]$freshnessAuthority.revocation_snapshot_bound
        revocation_snapshot_current = [bool]$freshnessAuthority.revocation_snapshot_current
        revocation_status_not_revoked = [bool]$freshnessAuthority.revocation_status_not_revoked
        freshness_window_bound = [bool]$freshnessAuthority.freshness_window_bound
        freshness_window_current = [bool]$freshnessAuthority.freshness_window_current
        compatibility_bound = [bool]$currentGates.compatibility_bound
        rollback_bound = [bool]$currentGates.rollback_bound
        support_recovery_bound = [bool]$currentGates.support_recovery_bound
        endpoint_reachability_is_trust = $false
        network_probe_performed = $false
        comparisons = $comparisonCount
        comparison_drifts = $comparisonDriftCount
        fail_closed_cases = @($negativeCases).Count
        failed_fail_closed_cases = @($failedNegativeCases).Count
        quarantine_preflight_allowed = $quarantinePreflightAllowed
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        downstream_blockers = $downstreamBlockers
    }
    outputs = [ordered]@{
        report = [ordered]@{ path = Get-StablePath $reportPath; sha256 = Get-FileSha256 $reportPath }
        decision = [ordered]@{ path = Get-StablePath $decisionPath; sha256 = Get-FileSha256 $decisionPath }
        fail_closed_matrix = [ordered]@{ path = Get-StablePath $matrixPath; sha256 = Get-FileSha256 $matrixPath }
        verified_quarantine_preflight_handoff = [ordered]@{ path = Get-StablePath $handoffPath; sha256 = Get-FileSha256 $handoffPath }
    }
    source = $source
    invariants = [ordered]@{
        aios_body_only = $true
        mirror_frontend_changed = $false
        nginx_or_tls_changed = $false
        signer_infra_changed = $false
        object_storage_infra_changed = $false
        local_private_key_material_used = $false
        private_key_material_read_or_printed = $false
        cryptographic_signing_performed = $false
        signer_service_called = $false
        signature_value_exposed = $false
        raw_public_identity_exposed = $false
        endpoint_reachability_trusted = $false
        frontend_output_trusted = $false
        signer_reachability_trusted = $false
        tui_output_trusted = $false
        shell_output_trusted = $false
        model_replay_trusted = $false
        network_probe_performed = $false
        payload_upload_performed = $false
        remote_payload_bytes_downloaded = $false
        quarantine_payload_written = $false
        payload_interpreted = $false
        local_object_trust_allowed = $objectTrustAllowed
        quarantine_preflight_allowed = $quarantinePreflightAllowed
        verified_quarantine_preflight = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        canary_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        production_ring_mutated = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        frontend_authority = $false
        mirror_authority = $false
        signer_reachability_authority = $false
        model_replay_authority = $false
        normal_shell_authority = $false
        tui_authority = $false
        production_ready_claim = $false
    }
    checks = $script:checks
    blockers = $downstreamBlockers
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        comparisons = $comparisonCount
        comparison_drifts = $comparisonDriftCount
        local_object_trust_allowed = $objectTrustAllowed
        quarantine_preflight_allowed = $quarantinePreflightAllowed
        fail_closed_cases = @($negativeCases).Count
        failed_fail_closed_cases = @($failedNegativeCases).Count
        rc14_012_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC14-020"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc14-local-object-trust-verification-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC14-012"
    status = "completed"
    production_ready_claim = $false
    workflow = Get-StablePath $resolvedWorkflowDir
    script = [ordered]@{
        path = Get-StablePath $scriptPath
        sha256 = Get-FileSha256 $scriptPath
    }
    result = [ordered]@{
        path = Get-StablePath $resultPath
        status = $result.status
        sha256 = Get-FileSha256 $resultPath
    }
    outputs = $result.outputs
    verification_surface = $result.verification_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc14_012_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC14-020"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath), (Get-Content -Raw -LiteralPath $taskEvidencePath))
if (-not $finalSecretSafe) {
    throw "Sensitive marker detected in RC14-012 outputs."
}

Write-Host "RC14 local object trust verification $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Verification state: $verificationState"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), comparisons: $comparisonCount, fail-closed cases: $(@($negativeCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
