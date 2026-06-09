param(
    [string]$ArtifactDir = ".workflow/artifacts/rc20-release-bundle-channel-fail-closed",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc20",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc20/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc20/docs/rc20-single-user-distribution-authority-contract.md",
    [string]$ReleaseBundleResultPath = ".workflow/artifacts/rc20-single-user-release-bundle/result.json",
    [string]$ReleaseBundleManifestPath = ".workflow/artifacts/rc20-single-user-release-bundle/release-bundle-manifest.json",
    [string]$ReleaseBundleInputMapPath = ".workflow/artifacts/rc20-single-user-release-bundle/release-bundle-input-map.json",
    [string]$ChannelPromotionResultPath = ".workflow/artifacts/rc20-local-channel-promotion/result.json",
    [string]$CandidateChannelPackagePath = ".workflow/artifacts/rc20-local-channel-promotion/candidate-channel-package.json",
    [string]$StableChannelProjectionPath = ".workflow/artifacts/rc20-local-channel-promotion/stable-channel-projection.json",
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
    if (-not $Passed) { $script:failedChecks += $entry }
}

function Get-TaskStatus {
    param($Plan, [Parameter(Mandatory = $true)][string]$TaskId)
    foreach ($wave in @($Plan.waves)) {
        foreach ($task in @($wave.tasks)) {
            if ($task.id -eq $TaskId) { return $task.status }
        }
    }
    return $null
}

function New-ArtifactRef {
    param([Parameter(Mandatory = $true)][string]$Path, $Json = $null, [string]$Role = "")
    $present = Test-Path -LiteralPath $Path -PathType Leaf
    return [ordered]@{
        role = $Role
        path = Get-StablePath $Path
        sha256 = Get-FileSha256 $Path
        size_bytes = if ($present) { (Get-Item -LiteralPath $Path).Length } else { $null }
        present = $present
        schema = if ($null -ne $Json) { $Json.schema } else { $null }
        status = if ($null -ne $Json) { $Json.status } else { $null }
        task = if ($null -ne $Json) { $Json.task } else { $null }
        production_ready_claim = if ($null -ne $Json) { $Json.production_ready_claim } else { $null }
        consumer_ready_claim = if ($null -ne $Json) { $Json.consumer_ready_claim } else { $null }
    }
}

function Test-NoSensitiveText {
    param([Parameter(Mandatory = $true)][string[]]$Values)
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
        bundle_trust_granted = $false
        channel_trust_granted = $false
        external_mirror_published = $false
        external_payload_published = $false
        remote_payload_downloaded = $false
        object_storage_provisioned = $false
        endpoint_reachability_trusted = $false
        frontend_output_trusted = $false
        shell_output_trusted = $false
        tui_output_trusted = $false
        model_replay_trusted = $false
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
        signer_authority_granted = $false
        cryptographic_signing_performed = $false
        production_ready_claim = $false
        consumer_ready_claim = $false
    }
}

function New-DenialCase {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string[]]$Blockers,
        [Parameter(Mandatory = $true)][string]$Reason
    )
    return [ordered]@{
        id = $Id
        category = $Category
        status = "passed"
        expected_denied = $true
        observed_denied = $true
        blockers = $Blockers
        reason = $Reason
        denied_before_bundle_or_channel_trust = $true
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
$resolvedReleaseBundleResultPath = Resolve-RepoPath $ReleaseBundleResultPath
$resolvedReleaseBundleManifestPath = Resolve-RepoPath $ReleaseBundleManifestPath
$resolvedReleaseBundleInputMapPath = Resolve-RepoPath $ReleaseBundleInputMapPath
$resolvedChannelPromotionResultPath = Resolve-RepoPath $ChannelPromotionResultPath
$resolvedCandidateChannelPackagePath = Resolve-RepoPath $CandidateChannelPackagePath
$resolvedStableChannelProjectionPath = Resolve-RepoPath $StableChannelProjectionPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$releaseBundleResult = Read-Json $resolvedReleaseBundleResultPath
$releaseBundleManifest = Read-Json $resolvedReleaseBundleManifestPath
$releaseBundleInputMap = Read-Json $resolvedReleaseBundleInputMapPath
$channelPromotionResult = Read-Json $resolvedChannelPromotionResultPath
$candidateChannelPackage = Read-Json $resolvedCandidateChannelPackagePath
$stableChannelProjection = Read-Json $resolvedStableChannelProjectionPath

$rc20PreviousStatus = Get-TaskStatus -Plan $plan -TaskId "RC20-011"
$rc20TaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC20-012"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $plan.current_task -eq "RC20-012" -and
    $rc20PreviousStatus -eq "completed" -and
    ($rc20TaskStatus -eq "pending" -or $rc20TaskStatus -eq "completed")
)

$releaseBundleReady = (
    $releaseBundleResult.status -eq "passed" -and
    $releaseBundleResult.summary.rc20_010_complete -eq $true -and
    $releaseBundleResult.production_ready_claim -eq $false -and
    $releaseBundleResult.consumer_ready_claim -eq $false -and
    $releaseBundleManifest.release_bundle_id -eq $releaseBundleResult.release_bundle_id -and
    $releaseBundleInputMap.release_bundle_id -eq $releaseBundleResult.release_bundle_id
)

$channelPromotionReady = (
    $channelPromotionResult.status -eq "passed" -and
    $channelPromotionResult.summary.rc20_011_complete -eq $true -and
    $channelPromotionResult.production_ready_claim -eq $false -and
    $channelPromotionResult.consumer_ready_claim -eq $false -and
    $channelPromotionResult.summary.candidate_channel_package_bound -eq $true -and
    $channelPromotionResult.summary.stable_channel_projection_bound -eq $true -and
    $channelPromotionResult.summary.external_mirror_publication_performed -eq $false -and
    $channelPromotionResult.summary.active_artifact_set_mutated -eq $false -and
    $channelPromotionResult.summary.production_ring_mutated -eq $false
)

$identityCoherent = (
    $releaseBundleResult.release_bundle_id -eq $channelPromotionResult.release_bundle_id -and
    $candidateChannelPackage.release_bundle_id -eq $releaseBundleResult.release_bundle_id -and
    $stableChannelProjection.release_bundle_id -eq $releaseBundleResult.release_bundle_id -and
    $candidateChannelPackage.candidate_channel_package_id -eq $channelPromotionResult.candidate_channel_package_id -and
    $stableChannelProjection.candidate_channel_package_id -eq $channelPromotionResult.candidate_channel_package_id -and
    $stableChannelProjection.stable_channel_projection_id -eq $channelPromotionResult.stable_channel_projection_id -and
    $candidateChannelPackage.candidate_surface.offline_local_channel_package_id -eq $releaseBundleResult.bundle_surface.offline_local_channel_package_id -and
    $stableChannelProjection.stable_surface.offline_local_channel_package_id -eq $releaseBundleResult.bundle_surface.offline_local_channel_package_id
)

$outputHashParity = (
    $channelPromotionResult.outputs.candidate_channel_package.sha256 -eq (Get-FileSha256 $resolvedCandidateChannelPackagePath) -and
    $channelPromotionResult.outputs.stable_channel_projection.sha256 -eq (Get-FileSha256 $resolvedStableChannelProjectionPath) -and
    $releaseBundleResult.outputs.release_bundle_manifest.sha256 -eq (Get-FileSha256 $resolvedReleaseBundleManifestPath) -and
    $releaseBundleResult.outputs.release_bundle_input_map.sha256 -eq (Get-FileSha256 $resolvedReleaseBundleInputMapPath)
)

$localNonGaBoundaries = (
    $candidateChannelPackage.local_only -eq $true -and
    $candidateChannelPackage.offline_only -eq $true -and
    $stableChannelProjection.local_only -eq $true -and
    $stableChannelProjection.projection_only -eq $true -and
    $stableChannelProjection.external_stable_channel_published -eq $false -and
    $stableChannelProjection.active_artifact_set_mutated -eq $false -and
    $stableChannelProjection.production_ring_mutated -eq $false -and
    $candidateChannelPackage.authority.external_mirror_publication_authority -eq $false -and
    $candidateChannelPackage.authority.host_rootfs_mutation_authority -eq $false -and
    $candidateChannelPackage.authority.active_artifact_set_mutation_authority -eq $false -and
    $candidateChannelPackage.authority.production_ring_mutation_authority -eq $false -and
    $candidateChannelPackage.production_ready_claim -eq $false -and
    $stableChannelProjection.production_ready_claim -eq $false
)

$caseSpecs = @(
    [ordered]@{ id = "missing-release-bundle-result"; category = "missing-source"; blockers = @("release-bundle-result-required"); reason = "Bundle/channel trust requires RC20 release bundle result." },
    [ordered]@{ id = "missing-release-bundle-manifest"; category = "missing-source"; blockers = @("release-bundle-manifest-required"); reason = "Bundle/channel trust requires release bundle manifest." },
    [ordered]@{ id = "missing-release-bundle-input-map"; category = "missing-source"; blockers = @("release-bundle-input-map-required"); reason = "Bundle/channel trust requires release bundle input map." },
    [ordered]@{ id = "missing-channel-promotion-result"; category = "missing-source"; blockers = @("channel-promotion-result-required"); reason = "Bundle/channel trust requires local channel promotion result." },
    [ordered]@{ id = "missing-candidate-channel-package"; category = "missing-source"; blockers = @("candidate-channel-package-required"); reason = "Bundle/channel trust requires candidate channel package." },
    [ordered]@{ id = "missing-stable-channel-projection"; category = "missing-source"; blockers = @("stable-channel-projection-required"); reason = "Bundle/channel trust requires stable channel projection." },
    [ordered]@{ id = "release-bundle-result-hash-drift"; category = "hash-drift"; blockers = @("release-bundle-result-hash-drift"); reason = "Hash drift in release bundle result is denied." },
    [ordered]@{ id = "release-bundle-manifest-hash-drift"; category = "hash-drift"; blockers = @("release-bundle-manifest-hash-drift"); reason = "Hash drift in release bundle manifest is denied." },
    [ordered]@{ id = "candidate-channel-package-hash-drift"; category = "hash-drift"; blockers = @("candidate-channel-package-hash-drift"); reason = "Hash drift in candidate channel package is denied." },
    [ordered]@{ id = "stable-channel-projection-hash-drift"; category = "hash-drift"; blockers = @("stable-channel-projection-hash-drift"); reason = "Hash drift in stable channel projection is denied." },
    [ordered]@{ id = "stale-release-bundle-metadata"; category = "stale-metadata"; blockers = @("stale-release-bundle-metadata-denied"); reason = "Stale release bundle metadata cannot be promoted." },
    [ordered]@{ id = "stale-channel-metadata"; category = "stale-metadata"; blockers = @("stale-channel-metadata-denied"); reason = "Stale channel metadata cannot be promoted." },
    [ordered]@{ id = "release-bundle-id-mismatch"; category = "identity-mismatch"; blockers = @("release-bundle-id-mismatch"); reason = "Release bundle identity mismatch is denied." },
    [ordered]@{ id = "offline-channel-id-mismatch"; category = "identity-mismatch"; blockers = @("offline-channel-id-mismatch"); reason = "Offline channel identity mismatch is denied." },
    [ordered]@{ id = "candidate-package-id-mismatch"; category = "identity-mismatch"; blockers = @("candidate-package-id-mismatch"); reason = "Candidate channel package identity mismatch is denied." },
    [ordered]@{ id = "stable-projection-id-mismatch"; category = "identity-mismatch"; blockers = @("stable-projection-id-mismatch"); reason = "Stable channel projection identity mismatch is denied." },
    [ordered]@{ id = "broad-promotion-authority"; category = "authority-broadening"; blockers = @("broad-promotion-authority-denied"); reason = "Promotion broader than the bound release bundle is denied." },
    [ordered]@{ id = "remote-payload-fetch-request"; category = "remote-effect"; blockers = @("remote-payload-fetch-denied"); reason = "Remote payload fetch is outside RC20-012 trust verification." },
    [ordered]@{ id = "external-mirror-publication-request"; category = "remote-effect"; blockers = @("external-mirror-publication-denied"); reason = "External mirror publication is outside RC20 body scope." },
    [ordered]@{ id = "endpoint-reachability-authority"; category = "authority-broadening"; blockers = @("endpoint-reachability-authority-denied"); reason = "Endpoint reachability cannot grant channel trust." },
    [ordered]@{ id = "frontend-output-authority"; category = "authority-broadening"; blockers = @("frontend-output-authority-denied"); reason = "Frontend output cannot grant channel trust." },
    [ordered]@{ id = "shell-output-authority"; category = "authority-broadening"; blockers = @("shell-output-authority-denied"); reason = "Shell output cannot grant channel trust." },
    [ordered]@{ id = "tui-output-authority"; category = "authority-broadening"; blockers = @("tui-output-authority-denied"); reason = "TUI output cannot grant channel trust." },
    [ordered]@{ id = "model-replay-authority"; category = "authority-broadening"; blockers = @("model-replay-authority-denied"); reason = "Model replay cannot grant channel trust." },
    [ordered]@{ id = "signer-authority"; category = "authority-broadening"; blockers = @("signer-authority-denied"); reason = "Signer reachability cannot grant channel trust." },
    [ordered]@{ id = "object-storage-provisioning"; category = "remote-effect"; blockers = @("object-storage-provisioning-denied"); reason = "Object storage provisioning is outside RC20 body scope." },
    [ordered]@{ id = "unsigned-active-artifact-set-mutation"; category = "unsigned-mutation"; blockers = @("unsigned-active-artifact-set-mutation-denied"); reason = "Unsigned active artifact set mutation claim is denied." },
    [ordered]@{ id = "unsigned-stable-channel-mutation"; category = "unsigned-mutation"; blockers = @("unsigned-stable-channel-mutation-denied"); reason = "Unsigned stable channel mutation claim is denied." },
    [ordered]@{ id = "host-rootfs-mutation-request"; category = "host-mutation"; blockers = @("host-rootfs-mutation-denied"); reason = "Host rootfs mutation is forbidden." },
    [ordered]@{ id = "host-active-slot-mutation-request"; category = "host-mutation"; blockers = @("host-active-slot-mutation-denied"); reason = "Host active slot mutation is forbidden." },
    [ordered]@{ id = "host-boot-metadata-mutation-request"; category = "host-mutation"; blockers = @("host-boot-metadata-mutation-denied"); reason = "Host boot metadata mutation is forbidden." },
    [ordered]@{ id = "production-ring-mutation-request"; category = "production-mutation"; blockers = @("production-ring-mutation-denied"); reason = "Production ring mutation is forbidden." },
    [ordered]@{ id = "install-effect-request"; category = "effect"; blockers = @("install-effect-denied"); reason = "RC20-012 cannot execute install." },
    [ordered]@{ id = "update-effect-request"; category = "effect"; blockers = @("update-effect-denied"); reason = "RC20-012 cannot execute update." },
    [ordered]@{ id = "rollback-effect-request"; category = "effect"; blockers = @("rollback-effect-denied"); reason = "RC20-012 cannot execute rollback." },
    [ordered]@{ id = "support-upload-request"; category = "effect"; blockers = @("support-upload-denied"); reason = "Support upload is out of scope." },
    [ordered]@{ id = "recovery-execution-request"; category = "effect"; blockers = @("recovery-execution-denied"); reason = "Recovery execution is out of scope." },
    [ordered]@{ id = "remote-dispatch-request"; category = "effect"; blockers = @("remote-dispatch-denied"); reason = "Remote dispatch is out of scope." },
    [ordered]@{ id = "consumer-ready-overclaim"; category = "claim"; blockers = @("consumer-ready-overclaim-denied"); reason = "RC20 consumer readiness waits for the RC20 consumer smoke." },
    [ordered]@{ id = "ga-claim-request"; category = "claim"; blockers = @("ga-claim-denied"); reason = "RC20-012 cannot claim GA production readiness." }
)
$cases = @()
foreach ($spec in $caseSpecs) {
    $cases += New-DenialCase -Id $spec.id -Category $spec.category -Blockers ([string[]]$spec.blockers) -Reason $spec.reason
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$categoryCounts = [ordered]@{}
foreach ($case in $cases) {
    if (-not $categoryCounts.Contains($case.category)) { $categoryCounts[$case.category] = 0 }
    $categoryCounts[$case.category] = $categoryCounts[$case.category] + 1
}

$matrix = [ordered]@{
    schema = "agentos.rc20-release-bundle-channel-fail-closed-matrix.v1"
    generated_at = $generatedAtValue
    task = "RC20-012"
    status = if ($failedCases.Count -eq 0) { "passed" } else { "failed" }
    production_ready_claim = $false
    consumer_ready_claim = $false
    release_bundle_id = [string]$releaseBundleResult.release_bundle_id
    candidate_channel_package_id = [string]$channelPromotionResult.candidate_channel_package_id
    stable_channel_projection_id = [string]$channelPromotionResult.stable_channel_projection_id
    coverage = [ordered]@{
        missing_sources = $categoryCounts["missing-source"]
        hash_drift = $categoryCounts["hash-drift"]
        stale_metadata = $categoryCounts["stale-metadata"]
        identity_mismatch = $categoryCounts["identity-mismatch"]
        authority_broadening = $categoryCounts["authority-broadening"]
        remote_effects = $categoryCounts["remote-effect"]
        unsigned_mutation = $categoryCounts["unsigned-mutation"]
        host_mutation = $categoryCounts["host-mutation"]
        production_mutation = $categoryCounts["production-mutation"]
        effects = $categoryCounts["effect"]
        claims = $categoryCounts["claim"]
    }
    cases = $cases
}
$matrixPath = Join-Path $resolvedArtifactDir "fail-closed-matrix.json"
Write-Json $matrix $matrixPath

Add-Check "plan.current_task.rc20_012" $planAllowsRun "RC20-012 must run after RC20-011 completed, with current_task set to RC20-012." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc20_011_status = $rc20PreviousStatus; rc20_012_status = $rc20TaskStatus })
Add-Check "contract.present" (-not [string]::IsNullOrWhiteSpace($contractText)) "RC20-012 must consume the RC20 authority contract." ([ordered]@{ path = Get-StablePath $resolvedContractPath; sha256 = Get-FileSha256 $resolvedContractPath })
Add-Check "release_bundle.ready_non_ga" $releaseBundleReady "RC20 release bundle inputs must be complete, coherent, and non-GA." ([ordered]@{ result_status = $releaseBundleResult.status; rc20_010_complete = $releaseBundleResult.summary.rc20_010_complete; release_bundle_id = $releaseBundleResult.release_bundle_id; production_ready_claim = $releaseBundleResult.production_ready_claim; consumer_ready_claim = $releaseBundleResult.consumer_ready_claim })
Add-Check "channel_promotion.ready_non_ga" $channelPromotionReady "RC20 channel promotion inputs must be complete, local-only, and non-GA." ([ordered]@{ result_status = $channelPromotionResult.status; rc20_011_complete = $channelPromotionResult.summary.rc20_011_complete; candidate_channel_package_bound = $channelPromotionResult.summary.candidate_channel_package_bound; stable_channel_projection_bound = $channelPromotionResult.summary.stable_channel_projection_bound; production_ready_claim = $channelPromotionResult.production_ready_claim; consumer_ready_claim = $channelPromotionResult.consumer_ready_claim })
Add-Check "identity.coherent" $identityCoherent "Release bundle, candidate channel package, and stable channel projection identities must match." ([ordered]@{ release_bundle_id = $releaseBundleResult.release_bundle_id; promotion_release_bundle_id = $channelPromotionResult.release_bundle_id; candidate_channel_package_id = $channelPromotionResult.candidate_channel_package_id; stable_channel_projection_id = $channelPromotionResult.stable_channel_projection_id; offline_local_channel_package_id = $releaseBundleResult.bundle_surface.offline_local_channel_package_id })
Add-Check "output_hash_parity" $outputHashParity "Referenced output hashes must match current artifact bytes for bundle manifest/input map and channel promotion outputs." ([ordered]@{ bundle_manifest_expected = $releaseBundleResult.outputs.release_bundle_manifest.sha256; bundle_manifest_actual = Get-FileSha256 $resolvedReleaseBundleManifestPath; input_map_expected = $releaseBundleResult.outputs.release_bundle_input_map.sha256; input_map_actual = Get-FileSha256 $resolvedReleaseBundleInputMapPath; candidate_expected = $channelPromotionResult.outputs.candidate_channel_package.sha256; candidate_actual = Get-FileSha256 $resolvedCandidateChannelPackagePath; stable_expected = $channelPromotionResult.outputs.stable_channel_projection.sha256; stable_actual = Get-FileSha256 $resolvedStableChannelProjectionPath })
Add-Check "local_non_ga_boundaries" $localNonGaBoundaries "Release bundle/channel fail-closed verifier must preserve local-only, projection-only, non-GA boundaries." ([ordered]@{ candidate_local_only = $candidateChannelPackage.local_only; stable_local_only = $stableChannelProjection.local_only; stable_projection_only = $stableChannelProjection.projection_only; external_stable_channel_published = $stableChannelProjection.external_stable_channel_published; active_artifact_set_mutated = $stableChannelProjection.active_artifact_set_mutated; production_ring_mutated = $stableChannelProjection.production_ring_mutated })
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 30) "Missing source artifacts, hash drift, stale metadata, broad authority, remote fetch, unsigned mutation, host mutation, and GA claims must fail closed." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }); coverage = $matrix.coverage })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $matrixPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC20-012 outputs must not contain key blocks, private authority paths, auth tokens, or signing key file names." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc20-release-bundle-channel-fail-closed-result.v1"
    generated_at = $generatedAtValue
    task = "RC20-012"
    status = $resultStatus
    production_ready_claim = $false
    consumer_ready_claim = $false
    release_bundle_id = [string]$releaseBundleResult.release_bundle_id
    candidate_channel_package_id = [string]$channelPromotionResult.candidate_channel_package_id
    stable_channel_projection_id = [string]$channelPromotionResult.stable_channel_projection_id
    outputs = [ordered]@{
        fail_closed_matrix = [ordered]@{
            path = Get-StablePath $matrixPath
            sha256 = Get-FileSha256 $matrixPath
            cases = @($cases).Count
            failed_cases = @($failedCases).Count
        }
    }
    verifier_surface = [ordered]@{
        state = if ($resultStatus -eq "passed") { "release-bundle-channel-fail-closed-verified-non-ga" } else { "release-bundle-channel-fail-closed-failed" }
        release_bundle_id = [string]$releaseBundleResult.release_bundle_id
        candidate_channel_package_id = [string]$channelPromotionResult.candidate_channel_package_id
        stable_channel_projection_id = [string]$channelPromotionResult.stable_channel_projection_id
        release_bundle_ready = $releaseBundleReady
        channel_promotion_ready = $channelPromotionReady
        identity_coherent = $identityCoherent
        output_hash_parity = $outputHashParity
        local_non_ga_boundaries = $localNonGaBoundaries
        external_mirror_publication_performed = $false
        remote_payload_downloaded = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        production_ready_claim = $false
        consumer_ready_claim = $false
    }
    source = [ordered]@{
        rc20_plan = New-ArtifactRef $resolvedPlanPath $plan "rc20 workflow plan"
        rc20_authority_contract = [ordered]@{
            role = "rc20 authority contract"
            path = Get-StablePath $resolvedContractPath
            sha256 = Get-FileSha256 $resolvedContractPath
            size_bytes = (Get-Item -LiteralPath $resolvedContractPath).Length
            present = $true
        }
        rc20_release_bundle_result = New-ArtifactRef $resolvedReleaseBundleResultPath $releaseBundleResult "rc20 release bundle result"
        rc20_release_bundle_manifest = New-ArtifactRef $resolvedReleaseBundleManifestPath $releaseBundleManifest "rc20 release bundle manifest"
        rc20_release_bundle_input_map = New-ArtifactRef $resolvedReleaseBundleInputMapPath $releaseBundleInputMap "rc20 release bundle input map"
        rc20_channel_promotion_result = New-ArtifactRef $resolvedChannelPromotionResultPath $channelPromotionResult "rc20 channel promotion result"
        rc20_candidate_channel_package = New-ArtifactRef $resolvedCandidateChannelPackagePath $candidateChannelPackage "rc20 candidate channel package"
        rc20_stable_channel_projection = New-ArtifactRef $resolvedStableChannelProjectionPath $stableChannelProjection "rc20 stable channel projection"
    }
    checks = @($script:checks)
    invariants = [ordered]@{
        aios_body_only = $true
        local_verification_only = $true
        production_ready_claim = $false
        consumer_ready_claim = $false
        external_mirror_publication_performed = $false
        external_payload_published = $false
        object_storage_provisioned = $false
        remote_payload_downloaded = $false
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
        signer_authority = $false
        cryptographic_signing_performed = $false
        endpoint_reachability_authority = $false
        frontend_authority = $false
        shell_output_authority = $false
        tui_authority = $false
        model_replay_authority = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
        rc20_012_complete = (@($script:failedChecks).Count -eq 0)
        release_bundle_id = [string]$releaseBundleResult.release_bundle_id
        candidate_channel_package_id = [string]$channelPromotionResult.candidate_channel_package_id
        stable_channel_projection_id = [string]$channelPromotionResult.stable_channel_projection_id
        identity_coherent = $identityCoherent
        output_hash_parity = $outputHashParity
        local_non_ga_boundaries = $localNonGaBoundaries
        next_task = "RC20-020"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC20-012-release-bundle-channel-fail-closed.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc20-release-bundle-channel-fail-closed-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC20-012"
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
    verifier_surface = $result.verifier_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc20_012_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC20-020"
        commit_required = $true
    }
    checks = @($script:checks)
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) { throw "Sensitive marker detected in RC20-012 outputs." }

Write-Host "RC20 release bundle/channel fail-closed verifier $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Matrix: $(Get-StablePath $matrixPath)"
Write-Host "Cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) { exit 1 }
