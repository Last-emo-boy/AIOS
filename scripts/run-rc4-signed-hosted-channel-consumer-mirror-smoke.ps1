param(
    [string]$ArtifactDir = ".workflow/artifacts/rc4-signed-hosted-channel-consumer-mirror-smoke",
    [string]$Rc4PlanPath = ".workflow/active/WFS-20260608-agentos-production-distro-rc4/plan.json",
    [string]$HostedTransportResultPath = ".workflow/artifacts/rc4-hosted-release-transport/result.json",
    [string]$HostedTransportManifestPath = ".workflow/artifacts/rc4-hosted-release-transport/hosted-transport-manifest.json",
    [string]$LocalMirrorFixturePath = ".workflow/artifacts/rc4-hosted-release-transport/local-mirror-fixture.json",
    [string]$MirrorPublicationResultPath = ".workflow/artifacts/rc4-remote-registry-mirror-publication/result.json",
    [string]$MirrorLockfilePath = ".workflow/artifacts/rc4-remote-registry-mirror-publication/mirror-lockfile.json",
    [string]$MirrorPublicationPath = ".workflow/artifacts/rc4-remote-registry-mirror-publication/mirror-publication.json",
    [string]$FleetRolloutPreconditionsPath = ".workflow/artifacts/rc4-fleet-ring-rollout-preconditions/result.json",
    [string]$HostedTransportFailClosedPath = ".workflow/artifacts/rc4-hosted-transport-fail-closed-fixtures/result.json",
    [string]$Rc3ConsumerSmokePath = ".workflow/artifacts/rc3-signed-channel-consumer/result.json",
    [string]$PublicationManifestPath = ".workflow/artifacts/rc3-release-channel-publication/publication-manifest.json",
    [string]$ChannelIndexPath = ".workflow/artifacts/rc3-release-channel-publication/channel-index.json",
    [string]$ProductionVerificationPath = ".workflow/artifacts/rc3-production-signature-verification/result.json",
    [string]$RevocationLogPath = "packaging/agentos/rootfs/etc/agentos/production-signing/key-revocation-log.json",
    [string]$OutputPath = "",
    [switch]$FailOnBlocked
)

$ErrorActionPreference = "Stop"

function Write-Json {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $parent = Split-Path -Parent $Path
    if ($parent) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    $Value | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $Path -Encoding UTF8
}

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

function Read-JsonFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Add-Check {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][bool]$Passed,
        [Parameter(Mandatory = $true)][string]$Message,
        [string]$Severity = "blocking",
        $Evidence = $null
    )
    $entry = [ordered]@{
        id = $Id
        status = if ($Passed) { "passed" } else { "failed" }
        severity = $Severity
        message = $Message
        evidence = $Evidence
    }
    $script:checks += $entry
    if (-not $Passed -and $Severity -eq "blocking") {
        $script:blockers += $entry
    }
}

function Get-JsonBlockerCount {
    param($Json)
    if ($null -eq $Json -or $Json.PSObject.Properties.Name -notcontains "blockers") {
        return 0
    }
    $value = $Json.PSObject.Properties["blockers"].Value
    if ($null -eq $value) {
        return 0
    }
    return @($value).Count
}

function Test-NoSensitiveContent {
    param([Parameter(Mandatory = $true)][string[]]$Paths)
    $patterns = @(
        "-----BEGIN [A-Z ]*PRIVATE KEY-----",
        "\bAIOS_SIGNER_API_TOKEN\b\s*[:=]",
        "\bAuthorization\b\s*:\s*Bearer\s+\S+",
        "\bBearer\s+[A-Za-z0-9._~+/-]+",
        "\baccess[_-]?token\b\s*[:=]\s*[""']?[^""'\s,}]+",
        "\brefresh[_-]?token\b\s*[:=]\s*[""']?[^""'\s,}]+",
        "\bprivate[_-]?key[_-]?pem\b\s*[:=]",
        "\.local-release-authority/private"
    )
    foreach ($path in $Paths) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            return $false
        }
        $text = Get-Content -LiteralPath $path -Raw
        foreach ($pattern in $patterns) {
            if ($text -match $pattern) {
                return $false
            }
        }
    }
    return $true
}

function Test-NoHostPathContent {
    param([Parameter(Mandatory = $true)][string[]]$Paths)
    foreach ($path in $Paths) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            return $false
        }
        $text = Get-Content -LiteralPath $path -Raw
        if ($text -match "[A-Za-z]:\\") {
            return $false
        }
    }
    return $true
}

function New-Projection {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        $Json = $null
    )
    return [ordered]@{
        path = Get-StablePath $Path
        sha256 = Get-FileSha256 $Path
        present = Test-Path -LiteralPath $Path -PathType Leaf
        schema = if ($null -ne $Json) { $Json.schema } else { $null }
        status = if ($null -ne $Json) { $Json.status } else { $null }
    }
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:blockers = @()

$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$expectedArtifactDir = Resolve-RepoPath ".workflow/artifacts/rc4-signed-hosted-channel-consumer-mirror-smoke"
if (-not $resolvedArtifactDir.Equals($expectedArtifactDir, [StringComparison]::OrdinalIgnoreCase)) {
    throw "ArtifactDir must be .workflow/artifacts/rc4-signed-hosted-channel-consumer-mirror-smoke"
}
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null

if (-not $OutputPath) {
    $OutputPath = Join-Path $ArtifactDir "result.json"
}

$resolvedPlanPath = Resolve-RepoPath $Rc4PlanPath
$resolvedHostedResultPath = Resolve-RepoPath $HostedTransportResultPath
$resolvedHostedManifestPath = Resolve-RepoPath $HostedTransportManifestPath
$resolvedLocalMirrorFixturePath = Resolve-RepoPath $LocalMirrorFixturePath
$resolvedMirrorResultPath = Resolve-RepoPath $MirrorPublicationResultPath
$resolvedMirrorLockfilePath = Resolve-RepoPath $MirrorLockfilePath
$resolvedMirrorPublicationPath = Resolve-RepoPath $MirrorPublicationPath
$resolvedFleetPreconditionsPath = Resolve-RepoPath $FleetRolloutPreconditionsPath
$resolvedFailClosedPath = Resolve-RepoPath $HostedTransportFailClosedPath
$resolvedRc3ConsumerPath = Resolve-RepoPath $Rc3ConsumerSmokePath
$resolvedPublicationManifestPath = Resolve-RepoPath $PublicationManifestPath
$resolvedChannelIndexPath = Resolve-RepoPath $ChannelIndexPath
$resolvedProductionVerificationPath = Resolve-RepoPath $ProductionVerificationPath
$resolvedRevocationLogPath = Resolve-RepoPath $RevocationLogPath
$resolvedOutputPath = Resolve-RepoPath $OutputPath

$plan = Read-JsonFile $resolvedPlanPath
$hostedResult = Read-JsonFile $resolvedHostedResultPath
$hostedManifest = Read-JsonFile $resolvedHostedManifestPath
$localMirrorFixture = Read-JsonFile $resolvedLocalMirrorFixturePath
$mirrorResult = Read-JsonFile $resolvedMirrorResultPath
$mirrorLockfile = Read-JsonFile $resolvedMirrorLockfilePath
$mirrorPublication = Read-JsonFile $resolvedMirrorPublicationPath
$fleetPreconditions = Read-JsonFile $resolvedFleetPreconditionsPath
$failClosed = Read-JsonFile $resolvedFailClosedPath
$rc3Consumer = Read-JsonFile $resolvedRc3ConsumerPath
$publicationManifest = Read-JsonFile $resolvedPublicationManifestPath
$channelIndex = Read-JsonFile $resolvedChannelIndexPath
$productionVerification = Read-JsonFile $resolvedProductionVerificationPath
$revocationLog = Read-JsonFile $resolvedRevocationLogPath

$rc4TaskStatuses = @{}
if ($null -ne $plan) {
    foreach ($wave in @($plan.waves)) {
        foreach ($task in @($wave.tasks)) {
            if ($null -ne $task.id) {
                $rc4TaskStatuses[$task.id] = $task.status
            }
        }
    }
}

$hostedManifestHash = Get-FileSha256 $resolvedHostedManifestPath
$localMirrorFixtureHash = Get-FileSha256 $resolvedLocalMirrorFixturePath
$mirrorLockfileHash = Get-FileSha256 $resolvedMirrorLockfilePath
$mirrorPublicationHash = Get-FileSha256 $resolvedMirrorPublicationPath
$fleetPreconditionsHash = Get-FileSha256 $resolvedFleetPreconditionsPath
$failClosedHash = Get-FileSha256 $resolvedFailClosedPath
$rc3ConsumerHash = Get-FileSha256 $resolvedRc3ConsumerPath
$publicationManifestHash = Get-FileSha256 $resolvedPublicationManifestPath
$channelIndexHash = Get-FileSha256 $resolvedChannelIndexPath
$productionVerificationHash = Get-FileSha256 $resolvedProductionVerificationPath
$revocationLogHash = Get-FileSha256 $resolvedRevocationLogPath

$planReady = $null -ne $plan -and (
    $plan.current_task -eq "RC4-020" -or
    ($rc4TaskStatuses["RC4-020"] -eq "completed" -and $plan.current_task -in @("RC4-021", "RC4-022", "RC4-023", "RC4-030"))
)
$hostedReady = $null -ne $hostedResult -and $hostedResult.status -eq "passed" -and $hostedResult.rc4_010_complete -eq $true -and
    (Get-JsonBlockerCount $hostedResult) -eq 0 -and
    $null -ne $hostedManifest -and $hostedManifest.status -eq "published-locally" -and
    $hostedManifest.production_ready_claim -eq $false -and
    $hostedManifest.transport.network_transfer_performed -eq $false -and
    $hostedManifest.transport.local_fixture_only -eq $true -and
    $hostedManifest.bindings.production_verification_sha256 -eq $productionVerificationHash -and
    $hostedManifest.bindings.publication_manifest_sha256 -eq $publicationManifestHash -and
    $hostedManifest.bindings.channel_index_sha256 -eq $channelIndexHash -and
    $hostedManifest.bindings.consumer_smoke_sha256 -eq $rc3ConsumerHash -and
    $hostedManifest.bindings.revocation_log_sha256 -eq $revocationLogHash
$localMirrorFixtureReady = $null -ne $localMirrorFixture -and
    $localMirrorFixture.status -eq "fixture-ready" -and
    $localMirrorFixture.production_ready_claim -eq $false -and
    $localMirrorFixture.hosted_transport_manifest_sha256 -eq $hostedManifestHash -and
    $localMirrorFixture.mirror.local_fixture_only -eq $true -and
    $localMirrorFixture.mirror.network_transfer_performed -eq $false
$mirrorReady = $null -ne $mirrorResult -and $mirrorResult.status -eq "passed" -and $mirrorResult.rc4_011_complete -eq $true -and
    (Get-JsonBlockerCount $mirrorResult) -eq 0 -and
    $null -ne $mirrorLockfile -and $mirrorLockfile.status -eq "locked-locally" -and
    $mirrorLockfile.hosted_transport_manifest.sha256 -eq $hostedManifestHash -and
    $mirrorLockfile.local_mirror_fixture.sha256 -eq $localMirrorFixtureHash -and
    $null -ne $mirrorPublication -and $mirrorPublication.status -eq "published-locally" -and
    $mirrorPublication.production_ready_claim -eq $false -and
    $mirrorPublication.mirror.network_transfer_performed -eq $false -and
    $mirrorPublication.mirror.active_registry_mutated -eq $false -and
    $mirrorPublication.bindings.hosted_transport_manifest_sha256 -eq $hostedManifestHash -and
    $mirrorPublication.bindings.local_mirror_fixture_sha256 -eq $localMirrorFixtureHash -and
    $mirrorPublication.bindings.mirror_lockfile_sha256 -eq $mirrorLockfileHash
$rc4PreconditionsReady = $null -ne $fleetPreconditions -and $fleetPreconditions.status -eq "ready-for-fleet-ring-rollout-plan" -and
    $fleetPreconditions.rc4_012_complete -eq $true -and
    (Get-JsonBlockerCount $fleetPreconditions) -eq 0 -and
    $fleetPreconditions.rollout_plan_created -eq $false -and
    $fleetPreconditions.exact_operator_approval_granted -eq $false -and
    $fleetPreconditions.activation_performed -eq $false -and
    $fleetPreconditions.production_ring_mutated -eq $false
$failClosedReady = $null -ne $failClosed -and $failClosed.status -eq "passed" -and
    $failClosed.rc4_013_complete -eq $true -and
    @($failClosed.cases).Count -eq 13 -and
    $failClosed.summary.passed_cases -eq 13 -and
    (Get-JsonBlockerCount $failClosed) -eq 0 -and
    $failClosed.activation_performed -eq $false -and
    $failClosed.remote_dispatch_enabled -eq $false
$rc3ConsumerReady = $null -ne $rc3Consumer -and $rc3Consumer.status -eq "passed" -and
    $rc3Consumer.rc3_021_complete -eq $true -and
    $rc3Consumer.verified.publication_manifest -eq $true -and
    $rc3Consumer.verified.channel_index -eq $true -and
    $rc3Consumer.verified.production_signatures -eq $true -and
    $rc3Consumer.verified.revocation_state -eq $true -and
    $rc3Consumer.mutation.activation_performed -eq $false -and
    $rc3Consumer.mutation.active_slot_mutated -eq $false -and
    $rc3Consumer.mutation.production_ring_mutated -eq $false -and
    $rc3Consumer.mutation.remote_dispatch_enabled -eq $false
$publicationReady = $null -ne $publicationManifest -and
    $publicationManifest.status -eq "published-locally" -and
    $publicationManifest.production_ready_claim -eq $false -and
    $publicationManifest.channel.immutable -eq $true -and
    $publicationManifest.channel.append_only -eq $true
$channelReady = $null -ne $channelIndex -and
    $channelIndex.status -eq "updated" -and
    $channelIndex.production_ready_claim -eq $false -and
    $channelIndex.channel.append_only -eq $true
$productionVerificationReady = $null -ne $productionVerification -and
    $productionVerification.status -eq "passed" -and
    (Get-JsonBlockerCount $productionVerification) -eq 0
$revocationReady = $null -ne $revocationLog -and $hostedManifest.bindings.revocation_log_sha256 -eq $revocationLogHash

Add-Check "rc4.plan.current_task" $planReady "RC4 plan must point at RC4-020 before the first smoke run, or remain on a later RC4 task after RC4-020 is completed." "blocking" $(if ($null -ne $plan) { [ordered]@{ current_task = $plan.current_task; RC4_020 = $rc4TaskStatuses["RC4-020"]; RC4_021 = $rc4TaskStatuses["RC4-021"] } } else { $null })
Add-Check "hosted_transport.hash_bound" $hostedReady "Hosted transport manifest must be passed, local-only, and hash-bound to RC3 publication, channel, production verification, consumer smoke, and revocation log." "blocking" $(if ($null -ne $hostedManifest) { $hostedManifest.bindings } else { $null })
Add-Check "local_mirror.fixture_bound" $localMirrorFixtureReady "Local mirror fixture must bind the current hosted transport manifest hash and remain local-only." "blocking" $(if ($null -ne $localMirrorFixture) { [ordered]@{ hosted_transport_manifest_sha256 = $localMirrorFixture.hosted_transport_manifest_sha256; mirror = $localMirrorFixture.mirror } } else { $null })
Add-Check "mirror_publication.hash_bound" $mirrorReady "Mirror lockfile and publication must bind hosted manifest, local fixture, and lockfile hashes without active registry mutation." "blocking" $(if ($null -ne $mirrorPublication) { $mirrorPublication.bindings } else { $null })
Add-Check "rc4.preconditions.ready" $rc4PreconditionsReady "RC4 fleet-ring rollout preconditions must be ready but still not create a rollout plan or approval." "blocking" $(if ($null -ne $fleetPreconditions) { $fleetPreconditions.summary } else { $null })
Add-Check "rc4.fail_closed.ready" $failClosedReady "RC4 hosted transport fail-closed fixtures must pass 13 negative cases with zero blockers." "blocking" $(if ($null -ne $failClosed) { $failClosed.summary } else { $null })
Add-Check "rc3.consumer_smoke.passed" $rc3ConsumerReady "RC3 signed channel consumer smoke must pass and remain mutation-free." "blocking" $(if ($null -ne $rc3Consumer) { [ordered]@{ verified = $rc3Consumer.verified; mutation = $rc3Consumer.mutation; sha256 = $rc3ConsumerHash } } else { $null })
Add-Check "rc3.publication_and_channel.ready" ($publicationReady -and $channelReady) "RC3 publication manifest and channel index must remain immutable, append-only, and non-GA." "blocking" ([ordered]@{ publication_manifest_sha256 = $publicationManifestHash; channel_index_sha256 = $channelIndexHash })
Add-Check "production_signatures.bound" $productionVerificationReady "Production signature verification artifact consumed by hosted smoke must remain passed with zero blockers." "blocking" $(if ($null -ne $productionVerification) { [ordered]@{ status = $productionVerification.status; blockers = Get-JsonBlockerCount $productionVerification; sha256 = $productionVerificationHash } } else { $null })
Add-Check "revocation_snapshot.bound" $revocationReady "Hosted smoke must bind packaged revocation/advisory snapshot hash." "blocking" ([ordered]@{ hosted_revocation_sha256 = if ($null -ne $hostedManifest) { $hostedManifest.bindings.revocation_log_sha256 } else { $null }; actual_revocation_sha256 = $revocationLogHash })
Add-Check "hosted_consumer_smoke.no_authority_broadened" $true "Hosted consumer smoke verifies local evidence only and must not sign, upload, activate, rollback, mutate registry, mutate slots, dispatch remotely, or use TUI authority." "blocking" ([ordered]@{
    local_private_key_material_used = $false
    cryptographic_signing_performed = $false
    cryptographic_verification_performed = $false
    network_transfer_performed = $false
    remote_upload_performed = $false
    activation_performed = $false
    rollback_execution_performed = $false
    active_registry_mutated = $false
    active_slot_mutated = $false
    active_artifact_set_mutated = $false
    production_ring_mutated = $false
    remote_dispatch_enabled = $false
    tui_authority = $false
})

$passed = @($script:blockers).Count -eq 0
$result = [ordered]@{
    schema = "agentos.rc4-signed-hosted-channel-consumer-mirror-smoke.v1"
    generated_at = "2026-06-08T10:00:00+08:00"
    checked_at = (Get-Date).ToString("o")
    task = "RC4-020"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    rc4_020_complete = $passed
    hosted_channel_consumer_ready = $passed
    mirror_smoke_ready = $passed
    rollout_plan_created = $false
    rollout_plan_executed = $false
    exact_operator_approval_granted = $false
    local_private_key_material_used = $false
    cryptographic_signing_performed = $false
    cryptographic_verification_performed = $false
    network_transfer_performed = $false
    remote_upload_performed = $false
    activation_performed = $false
    rollback_execution_performed = $false
    active_registry_mutated = $false
    active_slot_mutated = $false
    active_artifact_set_mutated = $false
    boot_metadata_mutated = $false
    production_ring_mutated = $false
    remote_dispatch_enabled = $false
    tui_authority = $false
    verified = [ordered]@{
        hosted_transport_manifest = $hostedReady
        local_mirror_fixture = $localMirrorFixtureReady
        mirror_publication = $mirrorReady
        rc4_preconditions = $rc4PreconditionsReady
        rc4_fail_closed = $failClosedReady
        rc3_signed_consumer = $rc3ConsumerReady
        publication_manifest = $publicationReady
        channel_index = $channelReady
        production_signatures = $productionVerificationReady
        revocation_snapshot = $revocationReady
    }
    bindings = [ordered]@{
        hosted_transport_manifest_sha256 = $hostedManifestHash
        local_mirror_fixture_sha256 = $localMirrorFixtureHash
        mirror_lockfile_sha256 = $mirrorLockfileHash
        mirror_publication_sha256 = $mirrorPublicationHash
        fleet_rollout_preconditions_sha256 = $fleetPreconditionsHash
        hosted_transport_fail_closed_sha256 = $failClosedHash
        rc3_consumer_smoke_sha256 = $rc3ConsumerHash
        publication_manifest_sha256 = $publicationManifestHash
        channel_index_sha256 = $channelIndexHash
        production_verification_sha256 = $productionVerificationHash
        revocation_log_sha256 = $revocationLogHash
    }
    source_artifacts = [ordered]@{
        rc4_plan = New-Projection -Path $resolvedPlanPath -Json $plan
        hosted_transport_result = New-Projection -Path $resolvedHostedResultPath -Json $hostedResult
        hosted_transport_manifest = New-Projection -Path $resolvedHostedManifestPath -Json $hostedManifest
        local_mirror_fixture = New-Projection -Path $resolvedLocalMirrorFixturePath -Json $localMirrorFixture
        mirror_publication_result = New-Projection -Path $resolvedMirrorResultPath -Json $mirrorResult
        mirror_lockfile = New-Projection -Path $resolvedMirrorLockfilePath -Json $mirrorLockfile
        mirror_publication = New-Projection -Path $resolvedMirrorPublicationPath -Json $mirrorPublication
        fleet_rollout_preconditions = New-Projection -Path $resolvedFleetPreconditionsPath -Json $fleetPreconditions
        hosted_transport_fail_closed = New-Projection -Path $resolvedFailClosedPath -Json $failClosed
        rc3_consumer_smoke = New-Projection -Path $resolvedRc3ConsumerPath -Json $rc3Consumer
        publication_manifest = New-Projection -Path $resolvedPublicationManifestPath -Json $publicationManifest
        channel_index = New-Projection -Path $resolvedChannelIndexPath -Json $channelIndex
        production_verification = New-Projection -Path $resolvedProductionVerificationPath -Json $productionVerification
        revocation_log = New-Projection -Path $resolvedRevocationLogPath -Json $revocationLog
    }
    checks = $script:checks
    blockers = $script:blockers
    summary = [ordered]@{
        checks = @($script:checks).Count
        blockers = @($script:blockers).Count
        rc4_020_complete = $passed
        hosted_channel_consumer_ready = $passed
        mirror_smoke_ready = $passed
        production_ready_claim = $false
        network_transfer_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        active_registry_mutated = $false
        active_slot_mutated = $false
        production_ring_mutated = $false
        remote_dispatch_enabled = $false
        tui_authority = $false
    }
}

Write-Json -Value $result -Path $resolvedOutputPath

$resultSecretSafe = Test-NoSensitiveContent -Paths @($resolvedOutputPath)
$resultHostPathFree = Test-NoHostPathContent -Paths @($resolvedOutputPath)
if (-not $resultSecretSafe -or -not $resultHostPathFree) {
    $extra = [ordered]@{
        id = "hosted_consumer_smoke.result_secret_safe"
        status = "failed"
        severity = "blocking"
        message = "RC4 signed hosted-channel consumer and mirror smoke result must be secret-safe and host-path-free."
        evidence = [ordered]@{ secret_safe = $resultSecretSafe; host_path_free = $resultHostPathFree; path = Get-StablePath $resolvedOutputPath }
    }
    $script:checks += $extra
    $script:blockers += $extra
    $result.checks = $script:checks
    $result.blockers = $script:blockers
    $result.status = "blocked"
    $result.rc4_020_complete = $false
    $result.hosted_channel_consumer_ready = $false
    $result.mirror_smoke_ready = $false
    $result.summary.checks = @($script:checks).Count
    $result.summary.blockers = @($script:blockers).Count
    $result.summary.rc4_020_complete = $false
    $result.summary.hosted_channel_consumer_ready = $false
    $result.summary.mirror_smoke_ready = $false
    Write-Json -Value $result -Path $resolvedOutputPath
}

Write-Host "RC4 signed hosted-channel consumer and mirror smoke $($result.status): $OutputPath"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
