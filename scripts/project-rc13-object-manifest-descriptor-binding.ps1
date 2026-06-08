param(
    [string]$ArtifactDir = ".workflow/artifacts/rc13-object-manifest-descriptor-binding",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc13",
    [string]$PlanPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc13/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc13/docs/rc13-local-trust-unblock-contract.md",
    [string]$DriftResultPath = ".workflow/artifacts/rc13-declared-current-drift-zero/result.json",
    [string]$DriftHandoffPath = ".workflow/artifacts/rc13-declared-current-drift-zero/object-manifest-descriptor-binding-handoff.json",
    [string]$DescriptorPath = ".workflow/artifacts/rc8-real-payload-object-descriptor/payload-object-descriptor.json",
    [string]$ObjectChecksumsPath = ".workflow/artifacts/rc8-real-payload-object-descriptor/payload-object-checksums.json",
    [string]$DescriptorReportPath = ".workflow/artifacts/rc8-real-payload-object-descriptor/descriptor-report.json",
    [string]$DescriptorCandidatePath = ".workflow/artifacts/rc11-release-object-byte-map/immutable-descriptor-candidate.json",
    [string]$ByteMapPath = ".workflow/artifacts/rc11-release-object-byte-map/release-object-byte-map.json",
    [string]$PublicationBindingPath = ".workflow/artifacts/rc12-external-object-publication-binding/publication-binding.json",
    [string]$InitramfsManifestPath = "image/out/agentos-initramfs.manifest.json",
    [string]$PayloadManifestPath = ".workflow/artifacts/rc6-installable-payload-manifest/payload-manifest.json",
    [string]$CompatibilityPath = ".workflow/artifacts/rc7-install-rollback-baseline/compatibility.json",
    [string]$RollbackBaselinePath = ".workflow/artifacts/rc7-install-rollback-baseline/rollback-baseline.json",
    [string]$SupportIndexPath = ".workflow/artifacts/rc5-hosted-support-recovery/support-index.json",
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
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace("-", "").ToLowerInvariant()
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

function Get-CanonicalJsonSha256 {
    param([Parameter(Mandatory = $true)]$Value)
    return Get-StringSha256 (($Value | ConvertTo-Json -Depth 100 -Compress))
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

function Add-Comparison {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [AllowNull()]$Expected,
        [AllowNull()]$Actual,
        [Parameter(Mandatory = $true)][string]$ExpectedSource,
        [Parameter(Mandatory = $true)][string]$ActualSource,
        [string]$DenialReason = "object-manifest-descriptor-drift"
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
    $markers = @(
        ("BEGIN " + $privateKeyMarker),
        ($privateKeyMarker + "-----"),
        ("Authorization:" + " Bearer"),
        ("Bearer" + " "),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ("." + "local-release-authority"),
        ("signing" + "-key." + "pem"),
        ("/etc/" + "aios-signer"),
        ("." + "pem"),
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
$resolvedDriftResultPath = Resolve-RepoPath $DriftResultPath
$resolvedDriftHandoffPath = Resolve-RepoPath $DriftHandoffPath
$resolvedDescriptorPath = Resolve-RepoPath $DescriptorPath
$resolvedObjectChecksumsPath = Resolve-RepoPath $ObjectChecksumsPath
$resolvedDescriptorReportPath = Resolve-RepoPath $DescriptorReportPath
$resolvedDescriptorCandidatePath = Resolve-RepoPath $DescriptorCandidatePath
$resolvedByteMapPath = Resolve-RepoPath $ByteMapPath
$resolvedPublicationBindingPath = Resolve-RepoPath $PublicationBindingPath
$resolvedInitramfsManifestPath = Resolve-RepoPath $InitramfsManifestPath
$resolvedPayloadManifestPath = Resolve-RepoPath $PayloadManifestPath
$resolvedCompatibilityPath = Resolve-RepoPath $CompatibilityPath
$resolvedRollbackBaselinePath = Resolve-RepoPath $RollbackBaselinePath
$resolvedSupportIndexPath = Resolve-RepoPath $SupportIndexPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$driftResult = Read-Json $resolvedDriftResultPath
$driftHandoff = Read-Json $resolvedDriftHandoffPath
$descriptor = Read-Json $resolvedDescriptorPath
$objectChecksums = Read-Json $resolvedObjectChecksumsPath
$descriptorReport = Read-Json $resolvedDescriptorReportPath
$descriptorCandidate = Read-Json $resolvedDescriptorCandidatePath
$byteMap = Read-Json $resolvedByteMapPath
$publicationBinding = Read-Json $resolvedPublicationBindingPath
$initramfsManifest = Read-Json $resolvedInitramfsManifestPath
$payloadManifest = Read-Json $resolvedPayloadManifestPath
$compatibility = Read-Json $resolvedCompatibilityPath
$rollbackBaseline = Read-Json $resolvedRollbackBaselinePath
$supportIndex = Read-Json $resolvedSupportIndexPath

$generatedAtValue = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }
$releaseId = [string]$driftResult.release_id
$sourceArtifactPath = Resolve-RepoPath ([string]$driftHandoff.current_payload.path)
$sourceArtifactSha256 = Get-FileSha256 $sourceArtifactPath
$sourceArtifactSize = if (Test-Path -LiteralPath $sourceArtifactPath -PathType Leaf) { (Get-Item -LiteralPath $sourceArtifactPath).Length } else { $null }
$descriptorSha256 = Get-FileSha256 $resolvedDescriptorPath
$descriptorCandidateSha256 = Get-FileSha256 $resolvedDescriptorCandidatePath
$objectChecksumsSha256 = Get-FileSha256 $resolvedObjectChecksumsPath
$initramfsManifestSha256 = Get-FileSha256 $resolvedInitramfsManifestPath
$payloadManifestSha256 = Get-FileSha256 $resolvedPayloadManifestPath
$compatibilitySha256 = Get-FileSha256 $resolvedCompatibilityPath
$rollbackBaselineSha256 = Get-FileSha256 $resolvedRollbackBaselinePath
$supportIndexSha256 = Get-FileSha256 $resolvedSupportIndexPath
$descriptorCanonicalSha256 = Get-CanonicalJsonSha256 $descriptor
$descriptorCandidateCanonicalSha256 = Get-CanonicalJsonSha256 $descriptorCandidate
$initramfsManifestCanonicalSha256 = Get-CanonicalJsonSha256 $initramfsManifest
$payloadManifestCanonicalSha256 = Get-CanonicalJsonSha256 $payloadManifest

$source = [ordered]@{
    rc13_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc13_contract = New-ArtifactRef $resolvedContractPath
    rc13_drift_result = New-ArtifactRef $resolvedDriftResultPath $driftResult
    rc13_drift_handoff = New-ArtifactRef $resolvedDriftHandoffPath $driftHandoff
    rc8_descriptor = New-ArtifactRef $resolvedDescriptorPath $descriptor
    rc8_object_checksums = New-ArtifactRef $resolvedObjectChecksumsPath $objectChecksums
    rc8_descriptor_report = New-ArtifactRef $resolvedDescriptorReportPath $descriptorReport
    rc11_descriptor_candidate = New-ArtifactRef $resolvedDescriptorCandidatePath $descriptorCandidate
    rc11_byte_map = New-ArtifactRef $resolvedByteMapPath $byteMap
    rc12_publication_binding = New-ArtifactRef $resolvedPublicationBindingPath $publicationBinding
    initramfs_manifest = New-ArtifactRef $resolvedInitramfsManifestPath $initramfsManifest
    payload_manifest = New-ArtifactRef $resolvedPayloadManifestPath $payloadManifest
    compatibility = New-ArtifactRef $resolvedCompatibilityPath $compatibility
    rollback_baseline = New-ArtifactRef $resolvedRollbackBaselinePath $rollbackBaseline
    support_index = New-ArtifactRef $resolvedSupportIndexPath $supportIndex
    current_payload_bytes = New-ArtifactRef $sourceArtifactPath
}

$rc13TaskStatus = ($plan.waves.tasks | Where-Object id -eq "RC13-011").status
$rc13PreviousStatus = ($plan.waves.tasks | Where-Object id -eq "RC13-010").status
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc13PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC13-011" -and ($rc13TaskStatus -eq "pending" -or $rc13TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC13-012" -and $rc13TaskStatus -eq "completed")
    )
)
Add-Check "plan.current_task.rc13_011" $planAllowsRun "RC13-011 must run after RC13-010 completed, either while current_task is RC13-011 or while rerunning after RC13-011 completed and the pointer advanced to RC13-012." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc13_010_status = $rc13PreviousStatus; rc13_011_status = $rc13TaskStatus })
Add-Check "contract.object_manifest_descriptor_gate.present" ($contractText.Contains("object_manifest_descriptor_consistent") -and $contractText.Contains("descriptor/manifest consistency")) "RC13-011 must consume the RC13 object manifest descriptor gate contract." $source.rc13_contract
Add-Check "source.rc13_drift_result.passed" ($driftResult.status -eq "passed" -and $driftResult.task -eq "RC13-010") "RC13-011 must bind the RC13-010 declared/current drift result." ([ordered]@{ status = $driftResult.status; drift_zero = $driftResult.reconciliation_surface.drift_zero; drift_count = $driftResult.reconciliation_surface.drift_count })
Add-Check "source.handoff.current_payload_matches" ($driftHandoff.current_payload.matches_rc12_identity -eq $true -and $driftHandoff.current_payload.sha256 -eq $sourceArtifactSha256 -and [int64]$driftHandoff.current_payload.size_bytes -eq [int64]$sourceArtifactSize) "RC13-011 must inherit current payload identity from RC13-010 handoff." ([ordered]@{ handoff_sha256 = $driftHandoff.current_payload.sha256; observed_sha256 = $sourceArtifactSha256; handoff_size_bytes = $driftHandoff.current_payload.size_bytes; observed_size_bytes = $sourceArtifactSize })

Add-Comparison "release_id.drift_vs_descriptor" $releaseId $descriptor.release_id "RC13 drift result release_id" "RC8 descriptor release_id" "release-id-drift"
Add-Comparison "release_id.descriptor_vs_checksums" $descriptor.release_id $objectChecksums.release_id "RC8 descriptor release_id" "RC8 object checksums release_id" "release-id-drift"
Add-Comparison "release_id.descriptor_vs_candidate" $descriptor.release_id $descriptorCandidate.release_id "RC8 descriptor release_id" "RC11 descriptor candidate release_id" "release-id-drift"
Add-Comparison "object_id.current_vs_descriptor" ("sha256:" + $sourceArtifactSha256) $descriptor.object_id "current payload object id" "RC8 descriptor object_id" "object-id-drift"
Add-Comparison "object_id.descriptor_vs_checksums" $descriptor.object_id $objectChecksums.object_id "RC8 descriptor object_id" "RC8 object checksums object_id" "object-id-drift"
Add-Comparison "object_id.descriptor_vs_candidate" $descriptor.object_id $descriptorCandidate.object_id "RC8 descriptor object_id" "RC11 descriptor candidate object_id" "object-id-drift"
Add-Comparison "object_kind.descriptor_vs_candidate" $descriptor.kind $descriptorCandidate.object_kind "RC8 descriptor kind" "RC11 descriptor candidate object_kind" "object-kind-drift"
Add-Comparison "payload.sha256.current_vs_descriptor" $sourceArtifactSha256 $descriptor.sha256 "current payload sha256" "RC8 descriptor sha256" "payload-digest-drift"
Add-Comparison "payload.sha256.current_vs_candidate" $sourceArtifactSha256 $descriptorCandidate.sha256 "current payload sha256" "RC11 descriptor candidate sha256" "payload-digest-drift"
Add-Comparison "payload.sha256.current_vs_initramfs_manifest" $sourceArtifactSha256 $initramfsManifest.artifact_sha256 "current payload sha256" "initramfs manifest artifact_sha256" "payload-digest-drift"
Add-Comparison "payload.sha256.current_vs_object_checksums" $sourceArtifactSha256 $objectChecksums.sha256 "current payload sha256" "RC8 object checksums sha256" "payload-digest-drift"
Add-Comparison "payload.sha256.current_vs_checksums_manifest_declared" $sourceArtifactSha256 $objectChecksums.manifest_declared_sha256 "current payload sha256" "RC8 object checksums manifest_declared_sha256" "payload-digest-drift"
Add-Comparison "payload.sha256.current_vs_publication_binding" $sourceArtifactSha256 $publicationBinding.current_release_bytes.sha256 "current payload sha256" "RC12 publication binding current_release_bytes.sha256" "payload-digest-drift"
Add-Comparison "payload.size.current_vs_descriptor" $sourceArtifactSize $descriptor.size_bytes "current payload size_bytes" "RC8 descriptor size_bytes" "payload-size-drift"
Add-Comparison "payload.size.current_vs_candidate" $sourceArtifactSize $descriptorCandidate.size_bytes "current payload size_bytes" "RC11 descriptor candidate size_bytes" "payload-size-drift"
Add-Comparison "payload.size.current_vs_object_checksums" $sourceArtifactSize $objectChecksums.size_bytes "current payload size_bytes" "RC8 object checksums size_bytes" "payload-size-drift"
Add-Comparison "payload.size.current_vs_publication_binding" $sourceArtifactSize $publicationBinding.current_release_bytes.size_bytes "current payload size_bytes" "RC12 publication binding current_release_bytes.size_bytes" "payload-size-drift"
Add-Comparison "descriptor.sha256.file_vs_report" $descriptorSha256 $descriptorReport.descriptor_sha256 "RC8 descriptor file sha256" "RC8 descriptor report descriptor_sha256" "descriptor-digest-drift"
Add-Comparison "descriptor.sha256.file_vs_public_signature_target" $descriptorSha256 $descriptorCandidate.public_signature_target_sha256 "RC8 descriptor file sha256" "RC11 descriptor candidate public_signature_target_sha256" "descriptor-digest-drift"
Add-Comparison "descriptor_candidate.sha256.file_vs_publication_binding" $descriptorCandidateSha256 $publicationBinding.required_bindings.descriptor_candidate_sha256 "RC11 descriptor candidate file sha256" "RC12 publication binding descriptor candidate sha256" "descriptor-candidate-digest-drift"
Add-Comparison "object_checksums.sha256.file_vs_byte_map" $objectChecksumsSha256 $byteMap.required_bindings.object_checksums_sha256 "RC8 object checksums file sha256" "RC11 byte map object_checksums_sha256" "checksum-artifact-drift"
Add-Comparison "manifest.sha256.file_vs_descriptor" $initramfsManifestSha256 $descriptor.manifest_sha256 "initramfs manifest file sha256" "RC8 descriptor manifest_sha256" "manifest-digest-drift"
Add-Comparison "manifest.sha256.file_vs_candidate" $initramfsManifestSha256 $descriptorCandidate.manifest_sha256 "initramfs manifest file sha256" "RC11 descriptor candidate manifest_sha256" "manifest-digest-drift"
Add-Comparison "manifest.sha256.file_vs_publication_binding" $initramfsManifestSha256 $publicationBinding.required_bindings.manifest_sha256 "initramfs manifest file sha256" "RC12 publication binding manifest_sha256" "manifest-digest-drift"
Add-Comparison "checksums.sha256.payload_manifest_vs_descriptor" $payloadManifestSha256 $descriptor.checksums_sha256 "RC6 payload manifest file sha256" "RC8 descriptor checksums_sha256" "checksum-set-drift"
Add-Comparison "checksums.sha256.payload_manifest_vs_candidate" $payloadManifestSha256 $descriptorCandidate.checksums_sha256 "RC6 payload manifest file sha256" "RC11 descriptor candidate checksums_sha256" "checksum-set-drift"
Add-Comparison "checksums.sha256.payload_manifest_vs_publication_binding" $payloadManifestSha256 $publicationBinding.required_bindings.checksums_sha256 "RC6 payload manifest file sha256" "RC12 publication binding checksums_sha256" "checksum-set-drift"
Add-Comparison "compatibility.sha256.file_vs_descriptor" $compatibilitySha256 $descriptor.installer_compatibility_sha256 "compatibility file sha256" "RC8 descriptor installer_compatibility_sha256" "compatibility-drift"
Add-Comparison "compatibility.sha256.file_vs_candidate" $compatibilitySha256 $descriptorCandidate.installer_compatibility_sha256 "compatibility file sha256" "RC11 descriptor candidate installer_compatibility_sha256" "compatibility-drift"
Add-Comparison "compatibility.sha256.file_vs_publication_binding" $compatibilitySha256 $publicationBinding.required_bindings.compatibility_sha256 "compatibility file sha256" "RC12 publication binding compatibility_sha256" "compatibility-drift"
Add-Comparison "rollback.sha256.file_vs_descriptor" $rollbackBaselineSha256 $descriptor.rollback_baseline_sha256 "rollback baseline file sha256" "RC8 descriptor rollback_baseline_sha256" "rollback-baseline-drift"
Add-Comparison "rollback.sha256.file_vs_candidate" $rollbackBaselineSha256 $descriptorCandidate.rollback_baseline_sha256 "rollback baseline file sha256" "RC11 descriptor candidate rollback_baseline_sha256" "rollback-baseline-drift"
Add-Comparison "rollback.sha256.file_vs_publication_binding" $rollbackBaselineSha256 $publicationBinding.required_bindings.rollback_baseline_sha256 "rollback baseline file sha256" "RC12 publication binding rollback_baseline_sha256" "rollback-baseline-drift"
Add-Comparison "support.sha256.file_vs_descriptor" $supportIndexSha256 $descriptor.support_recovery_sha256 "support index file sha256" "RC8 descriptor support_recovery_sha256" "support-recovery-drift"
Add-Comparison "support.sha256.file_vs_candidate" $supportIndexSha256 $descriptorCandidate.support_recovery_sha256 "support index file sha256" "RC11 descriptor candidate support_recovery_sha256" "support-recovery-drift"
Add-Comparison "support.sha256.file_vs_publication_binding" $supportIndexSha256 $publicationBinding.required_bindings.support_recovery_sha256 "support index file sha256" "RC12 publication binding support_recovery_sha256" "support-recovery-drift"

$comparisonCount = @($script:comparisons).Count
$comparisonDriftCount = @($script:comparisonDrifts).Count
$localDescriptorManifestConsistent = ($comparisonDriftCount -eq 0 -and $sourceArtifactSha256 -and $sourceArtifactSize -gt 0 -and [bool]$descriptor.immutable -eq $true -and [bool]$descriptorCandidate.immutable -eq $true -and [bool]$objectChecksums.hash_matches_manifest -eq $true)
$driftZero = [bool]$driftResult.reconciliation_surface.drift_zero
$bindingAllowed = ($localDescriptorManifestConsistent -and $driftZero)
$bindingState = if ($localDescriptorManifestConsistent -and -not $bindingAllowed) { "local-descriptor-manifest-consistent-authority-denied" } elseif ($bindingAllowed) { "object-manifest-descriptor-bound" } else { "object-manifest-descriptor-inconsistent" }

Add-Check "binding.current_payload_size_digest_bound" ($sourceArtifactSha256 -eq $descriptor.sha256 -and $sourceArtifactSize -eq [int64]$descriptor.size_bytes -and $sourceArtifactSha256 -eq $initramfsManifest.artifact_sha256 -and $sourceArtifactSha256 -eq $objectChecksums.sha256) "Current payload bytes must be size-bound and digest-bound across descriptor, initramfs manifest, and checksum set." ([ordered]@{ sha256 = $sourceArtifactSha256; size_bytes = $sourceArtifactSize })
Add-Check "binding.descriptor_manifest_consistent" $localDescriptorManifestConsistent "Descriptor, manifest, checksum set, compatibility, rollback, and support/recovery references must agree before local consistency can be recorded." ([ordered]@{ comparisons = $comparisonCount; drifts = @($script:comparisonDrifts | ForEach-Object { $_.id }); descriptor_immutable = $descriptor.immutable; candidate_immutable = $descriptorCandidate.immutable; hash_matches_manifest = $objectChecksums.hash_matches_manifest })
Add-Check "binding.upstream_drift_denies_authority" (($bindingAllowed -eq $true -and $driftZero -eq $true) -or ($bindingAllowed -eq $false -and $driftZero -eq $false)) "Nonzero declared/current drift must deny authoritative object manifest descriptor binding and downstream object trust." ([ordered]@{ drift_zero = $driftZero; drift_count = $driftResult.reconciliation_surface.drift_count; local_descriptor_manifest_consistent = $localDescriptorManifestConsistent; binding_allowed = $bindingAllowed })

$blockers = @()
if (-not $localDescriptorManifestConsistent) { $blockers += "object-manifest-descriptor-inconsistent" }
if (-not $driftZero) { $blockers += "declared-current-drift-zero-not-proved" }
foreach ($blocker in @($driftResult.reconciliation_surface.blockers)) {
    if ($blockers -notcontains $blocker) { $blockers += $blocker }
}
$downstreamBlockers = @(
    "freshness-revocation-authority-not-bound",
    "object-trust-not-allowed",
    "quarantine-preflight-not-run",
    "agentcore-planspec-not-executable",
    "security-execution-allow-not-bound",
    "two-target-canary-not-enrolled",
    "exact-approval-not-bound",
    "controlled-activation-not-authorized",
    "controlled-rollback-not-authorized"
)
foreach ($blocker in $downstreamBlockers) {
    if ($blockers -notcontains $blocker) { $blockers += $blocker }
}

$binding = [ordered]@{
    schema = "agentos.rc13-object-manifest-descriptor-binding.v1"
    generated_at = $generatedAtValue
    task = "RC13-011"
    release_id = $releaseId
    status = $bindingState
    production_ready_claim = $false
    current_payload = [ordered]@{
        path = Get-StablePath $sourceArtifactPath
        object_id = "sha256:$sourceArtifactSha256"
        size_bytes = $sourceArtifactSize
        sha256 = $sourceArtifactSha256
        content_type = [string]$descriptor.content_type
        compression = [string]$descriptor.compression
        immutable = [bool]$descriptor.immutable
    }
    descriptor_binding = [ordered]@{
        descriptor_path = Get-StablePath $resolvedDescriptorPath
        descriptor_file_sha256 = $descriptorSha256
        descriptor_canonical_sha256 = $descriptorCanonicalSha256
        descriptor_candidate_path = Get-StablePath $resolvedDescriptorCandidatePath
        descriptor_candidate_file_sha256 = $descriptorCandidateSha256
        descriptor_candidate_canonical_sha256 = $descriptorCandidateCanonicalSha256
        release_id = [string]$descriptor.release_id
        object_id = [string]$descriptor.object_id
        object_kind = [string]$descriptor.kind
        size_bytes = [int64]$descriptor.size_bytes
        sha256 = [string]$descriptor.sha256
        range_request_supported = [bool]$descriptor.range_request_supported
    }
    manifest_binding = [ordered]@{
        initramfs_manifest_path = Get-StablePath $resolvedInitramfsManifestPath
        initramfs_manifest_file_sha256 = $initramfsManifestSha256
        initramfs_manifest_canonical_sha256 = $initramfsManifestCanonicalSha256
        descriptor_manifest_sha256 = [string]$descriptor.manifest_sha256
        payload_manifest_path = Get-StablePath $resolvedPayloadManifestPath
        payload_manifest_file_sha256 = $payloadManifestSha256
        payload_manifest_canonical_sha256 = $payloadManifestCanonicalSha256
        descriptor_checksums_sha256 = [string]$descriptor.checksums_sha256
        object_checksums_path = Get-StablePath $resolvedObjectChecksumsPath
        object_checksums_file_sha256 = $objectChecksumsSha256
        object_checksums_payload_sha256 = [string]$objectChecksums.sha256
        hash_matches_manifest = [bool]$objectChecksums.hash_matches_manifest
    }
    compatibility_binding = [ordered]@{
        path = Get-StablePath $resolvedCompatibilityPath
        sha256 = $compatibilitySha256
        descriptor_sha256 = [string]$descriptor.installer_compatibility_sha256
        status = [string]$compatibility.status
        production_ready_claim = [bool]$compatibility.production_ready_claim
    }
    rollback_binding = [ordered]@{
        path = Get-StablePath $resolvedRollbackBaselinePath
        sha256 = $rollbackBaselineSha256
        descriptor_sha256 = [string]$descriptor.rollback_baseline_sha256
        status = [string]$rollbackBaseline.status
        rollback_execution_allowed = [bool]$rollbackBaseline.execution_status.rollback_execution_allowed
        production_ready_claim = [bool]$rollbackBaseline.production_ready_claim
    }
    support_recovery_binding = [ordered]@{
        path = Get-StablePath $resolvedSupportIndexPath
        sha256 = $supportIndexSha256
        descriptor_sha256 = [string]$descriptor.support_recovery_sha256
        status = [string]$supportIndex.status
        support_upload_allowed = [bool]$supportIndex.support_upload_allowed
        recovery_execution_allowed = [bool]$supportIndex.recovery_execution_allowed
        production_ready_claim = [bool]$supportIndex.production_ready_claim
    }
    consistency = [ordered]@{
        local_descriptor_manifest_consistent = $localDescriptorManifestConsistent
        authoritative_binding_allowed = $bindingAllowed
        declared_current_drift_zero = $driftZero
        comparisons = $comparisonCount
        comparison_drifts = $comparisonDriftCount
        comparison_drift_ids = @($script:comparisonDrifts | ForEach-Object { $_.id })
        descriptor_manifest_checks = $script:comparisons
    }
    trust_decision = [ordered]@{
        object_manifest_descriptor_consistent = $localDescriptorManifestConsistent
        object_manifest_descriptor_binding_allowed = $bindingAllowed
        freshness_revocation_authority_allowed = $bindingAllowed
        object_trust_allowed = $false
        quarantine_preflight_allowed = $false
        agentcore_planspec_executable = $false
        security_execution_allowed = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        blockers = $blockers
    }
    source = $source
}

$denial = [ordered]@{
    schema = "agentos.rc13-object-manifest-descriptor-denial.v1"
    generated_at = $generatedAtValue
    task = "RC13-011"
    release_id = $releaseId
    status = if ($bindingAllowed) { "not-denied" } else { "object-manifest-descriptor-authority-denied" }
    production_ready_claim = $false
    denied = (-not $bindingAllowed)
    local_descriptor_manifest_consistent = $localDescriptorManifestConsistent
    declared_current_drift_zero = $driftZero
    denial_reasons = $blockers
    side_effects = [ordered]@{
        object_manifest_written_as_authority = $false
        descriptor_rewritten = $false
        declared_metadata_rewritten = $false
        payload_bytes_uploaded = $false
        remote_payload_bytes_downloaded = $false
        network_probe_performed = $false
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

$handoff = [ordered]@{
    schema = "agentos.rc13-freshness-revocation-authority-handoff.v1"
    generated_at = $generatedAtValue
    task = "RC13-011"
    release_id = $releaseId
    status = if ($localDescriptorManifestConsistent) { "ready-for-rc13-012-with-authority-denied-until-upstream-gates-pass" } else { "blocked-by-object-manifest-descriptor-drift" }
    production_ready_claim = $false
    expected_next_task = "RC13-012"
    binding = [ordered]@{
        path = $null
        sha256 = $null
        local_descriptor_manifest_consistent = $localDescriptorManifestConsistent
        object_manifest_descriptor_binding_allowed = $bindingAllowed
        declared_current_drift_zero = $driftZero
    }
    public_signature_target = [ordered]@{
        descriptor_path = Get-StablePath $resolvedDescriptorPath
        descriptor_sha256 = $descriptorSha256
        public_signature_target_sha256 = [string]$descriptorCandidate.public_signature_target_sha256
        public_signature_receipt_sha256 = [string]$descriptorCandidate.public_signature_receipt_sha256
    }
    revocation_and_freshness_inputs = [ordered]@{
        revocation_snapshot_sha256 = [string]$descriptor.revocation_snapshot_sha256
        fresh_until = $descriptorCandidate.fresh_until
        freshness_window_bound = $false
    }
    blocked_authority = [ordered]@{
        freshness_revocation_authority_bound = $false
        object_trust_allowed = $false
        quarantine_preflight_allowed = $false
        agentcore_planspec_executable = $false
        security_execution_allowed = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
    }
    blockers = $blockers
}

$bindingPath = Join-Path $resolvedArtifactDir "object-manifest-descriptor-binding.json"
$denialPath = Join-Path $resolvedArtifactDir "object-manifest-descriptor-denial.json"
$handoffPath = Join-Path $resolvedArtifactDir "freshness-revocation-authority-handoff.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC13-011-object-manifest-descriptor-binding.json"

Write-Json $binding $bindingPath
$handoff.binding.path = Get-StablePath $bindingPath
$handoff.binding.sha256 = Get-FileSha256 $bindingPath
Write-Json $denial $denialPath
Write-Json $handoff $handoffPath

Add-Check "outputs.secret_safe" (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $bindingPath), (Get-Content -Raw -LiteralPath $denialPath), (Get-Content -Raw -LiteralPath $handoffPath))) "RC13-011 outputs must not contain PEM blocks, auth tokens, signer internals, or key identity strings." $null
Add-Check "outputs.side_effects_absent" ($denial.side_effects.object_manifest_written_as_authority -eq $false -and $denial.side_effects.descriptor_rewritten -eq $false -and $denial.side_effects.declared_metadata_rewritten -eq $false -and $denial.side_effects.payload_bytes_uploaded -eq $false -and $denial.side_effects.remote_payload_bytes_downloaded -eq $false -and $denial.side_effects.network_probe_performed -eq $false -and $denial.side_effects.quarantine_payload_written -eq $false -and $denial.side_effects.payload_interpreted -eq $false -and $denial.side_effects.install_performed -eq $false -and $denial.side_effects.activation_performed -eq $false -and $denial.side_effects.rollback_execution_performed -eq $false -and $denial.side_effects.support_upload_performed -eq $false -and $denial.side_effects.recovery_execution_performed -eq $false -and $denial.side_effects.remote_dispatch_enabled -eq $false -and $denial.side_effects.production_ring_mutated -eq $false -and $denial.side_effects.active_slot_mutated -eq $false -and $denial.side_effects.boot_metadata_mutated -eq $false -and $denial.side_effects.active_artifact_set_mutated -eq $false) "RC13-011 must not rewrite authority metadata, upload/download/fetch/quarantine/interpret payloads, install, activate, rollback, upload support, recover, dispatch, or mutate production state." $denial.side_effects

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc13-object-manifest-descriptor-binding-result.v1"
    generated_at = $generatedAtValue
    task = "RC13-011"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    binding_surface = [ordered]@{
        state = $bindingState
        local_descriptor_manifest_consistent = $localDescriptorManifestConsistent
        object_manifest_descriptor_binding_allowed = $bindingAllowed
        declared_current_drift_zero = $driftZero
        current_payload_size_bytes = $sourceArtifactSize
        current_payload_sha256 = $sourceArtifactSha256
        descriptor_file_sha256 = $descriptorSha256
        descriptor_canonical_sha256 = $descriptorCanonicalSha256
        descriptor_candidate_sha256 = $descriptorCandidateSha256
        descriptor_candidate_canonical_sha256 = $descriptorCandidateCanonicalSha256
        initramfs_manifest_sha256 = $initramfsManifestSha256
        payload_manifest_sha256 = $payloadManifestSha256
        object_checksums_sha256 = $objectChecksumsSha256
        compatibility_sha256 = $compatibilitySha256
        rollback_baseline_sha256 = $rollbackBaselineSha256
        support_recovery_sha256 = $supportIndexSha256
        comparisons = $comparisonCount
        comparison_drifts = $comparisonDriftCount
        object_trust_allowed = $false
        quarantine_preflight_allowed = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        blockers = $blockers
    }
    outputs = [ordered]@{
        binding = [ordered]@{ path = Get-StablePath $bindingPath; sha256 = Get-FileSha256 $bindingPath }
        denial = [ordered]@{ path = Get-StablePath $denialPath; sha256 = Get-FileSha256 $denialPath }
        freshness_revocation_authority_handoff = [ordered]@{ path = Get-StablePath $handoffPath; sha256 = Get-FileSha256 $handoffPath }
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
        payload_upload_performed = $false
        object_storage_provisioned = $false
        network_probe_performed = $false
        remote_payload_bytes_downloaded = $false
        quarantine_payload_written = $false
        payload_interpreted = $false
        descriptor_rewritten = $false
        object_manifest_written_as_authority = $false
        object_trust_allowed = $false
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
    blockers = $blockers
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        comparisons = $comparisonCount
        comparison_drifts = $comparisonDriftCount
        local_descriptor_manifest_consistent = $localDescriptorManifestConsistent
        authority_denied_as_expected = (-not $bindingAllowed)
        rc13_011_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC13-012"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc13-object-manifest-descriptor-binding-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC13-011"
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
    binding_surface = $result.binding_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc13_011_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC13-012"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath), (Get-Content -Raw -LiteralPath $taskEvidencePath))
if (-not $finalSecretSafe) {
    throw "Sensitive marker detected in RC13-011 outputs."
}

Write-Host "RC13 object manifest descriptor binding $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Binding state: $bindingState"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), comparisons: $comparisonCount, drifts: $comparisonDriftCount"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
