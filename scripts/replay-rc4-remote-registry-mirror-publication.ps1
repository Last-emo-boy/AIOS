param(
    [string]$ArtifactDir = ".workflow/artifacts/rc4-remote-registry-mirror-publication",
    [string]$Rc4PlanPath = ".workflow/active/WFS-20260608-agentos-production-distro-rc4/plan.json",
    [string]$HostedTransportResultPath = ".workflow/artifacts/rc4-hosted-release-transport/result.json",
    [string]$HostedTransportManifestPath = ".workflow/artifacts/rc4-hosted-release-transport/hosted-transport-manifest.json",
    [string]$LocalMirrorFixturePath = ".workflow/artifacts/rc4-hosted-release-transport/local-mirror-fixture.json",
    [string]$ThreatModelEvidencePath = ".workflow/active/WFS-20260608-agentos-production-distro-rc4/evidence/RC4-004-hosted-transport-fleet-threat-model.json",
    [string]$MirrorLockfilePath = "",
    [string]$MirrorPublicationPath = "",
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

function Get-JsonText {
    param([Parameter(Mandatory = $true)]$Value)
    return ($Value | ConvertTo-Json -Depth 100)
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

function Has-Value {
    param($Value)
    if ($null -eq $Value) {
        return $false
    }
    if ($Value -is [string]) {
        return -not [string]::IsNullOrWhiteSpace($Value)
    }
    return $true
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

function Write-ProjectionJsonArtifact {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )
    Write-Json -Value $Value -Path $Path
}

function New-Projection {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        $Json = $null
    )
    return [ordered]@{
        path = Get-StablePath $Path
        sha256 = Get-FileSha256 $Path
        schema = if ($null -ne $Json) { $Json.schema } else { $null }
        status = if ($null -ne $Json) { $Json.status } else { $null }
    }
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:blockers = @()

$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$expectedArtifactDir = Resolve-RepoPath ".workflow/artifacts/rc4-remote-registry-mirror-publication"
if (-not $resolvedArtifactDir.Equals($expectedArtifactDir, [StringComparison]::OrdinalIgnoreCase)) {
    throw "ArtifactDir must be .workflow/artifacts/rc4-remote-registry-mirror-publication"
}
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null

if (-not (Has-Value $MirrorLockfilePath)) {
    $MirrorLockfilePath = Join-Path $ArtifactDir "mirror-lockfile.json"
}
if (-not (Has-Value $MirrorPublicationPath)) {
    $MirrorPublicationPath = Join-Path $ArtifactDir "mirror-publication.json"
}
if (-not (Has-Value $OutputPath)) {
    $OutputPath = Join-Path $ArtifactDir "result.json"
}

$resolvedPlanPath = Resolve-RepoPath $Rc4PlanPath
$resolvedHostedResultPath = Resolve-RepoPath $HostedTransportResultPath
$resolvedHostedManifestPath = Resolve-RepoPath $HostedTransportManifestPath
$resolvedMirrorFixturePath = Resolve-RepoPath $LocalMirrorFixturePath
$resolvedThreatModelPath = Resolve-RepoPath $ThreatModelEvidencePath
$resolvedLockfilePath = Resolve-RepoPath $MirrorLockfilePath
$resolvedPublicationPath = Resolve-RepoPath $MirrorPublicationPath
$resolvedOutputPath = Resolve-RepoPath $OutputPath

$plan = Read-JsonFile $resolvedPlanPath
$hostedResult = Read-JsonFile $resolvedHostedResultPath
$hostedManifest = Read-JsonFile $resolvedHostedManifestPath
$mirrorFixture = Read-JsonFile $resolvedMirrorFixturePath
$threatModel = Read-JsonFile $resolvedThreatModelPath

$hostedManifestHash = Get-FileSha256 $resolvedHostedManifestPath
$mirrorFixtureHash = Get-FileSha256 $resolvedMirrorFixturePath

$entryEvidence = @()
$entryHashMismatches = @()
foreach ($entry in @($mirrorFixture.entries)) {
    $entryPath = if ($null -ne $entry) { $entry.path } else { $null }
    $resolvedEntryPath = if (Has-Value $entryPath) { Resolve-RepoPath $entryPath } else { $null }
    $actualHash = if ($null -ne $resolvedEntryPath) { Get-FileSha256 $resolvedEntryPath } else { $null }
    $matches = (Has-Value $entry.sha256) -and (Has-Value $actualHash) -and $entry.sha256 -eq $actualHash
    if (-not $matches) {
        $entryHashMismatches += [ordered]@{
            kind = if ($null -ne $entry) { $entry.kind } else { $null }
            path = $entryPath
            expected = if ($null -ne $entry) { $entry.sha256 } else { $null }
            actual = $actualHash
        }
    }
    $entryEvidence += [ordered]@{
        kind = if ($null -ne $entry) { $entry.kind } else { $null }
        path = $entryPath
        sha256 = if ($null -ne $entry) { $entry.sha256 } else { $null }
        actual_sha256 = $actualHash
        hash_matches = $matches
    }
}

$requiredKinds = @(
    "rc3_final_audit",
    "production_verification",
    "publication_manifest",
    "channel_index",
    "consumer_smoke",
    "support_recovery",
    "signing_publication_gate",
    "revocation_log"
)
$presentKinds = @($mirrorFixture.entries | ForEach-Object { $_.kind })
$missingKinds = @($requiredKinds | Where-Object { $presentKinds -notcontains $_ })

$hostedResultReady = $null -ne $hostedResult -and $hostedResult.status -eq "passed" -and $hostedResult.rc4_010_complete -eq $true -and (Get-JsonBlockerCount $hostedResult) -eq 0
$hostedManifestReady = $null -ne $hostedManifest -and $hostedManifest.schema -eq "agentos.rc4-hosted-release-transport-manifest.v1" -and $hostedManifest.status -eq "published-locally" -and $hostedManifest.production_ready_claim -eq $false -and $hostedManifest.transport.local_fixture_only -eq $true -and $hostedManifest.transport.network_transfer_performed -eq $false
$mirrorFixtureReady = $null -ne $mirrorFixture -and $mirrorFixture.schema -eq "agentos.rc4-local-mirror-fixture.v1" -and $mirrorFixture.status -eq "fixture-ready" -and $mirrorFixture.production_ready_claim -eq $false -and $mirrorFixture.hosted_transport_manifest_sha256 -eq $hostedManifestHash -and $mirrorFixture.mirror.local_fixture_only -eq $true -and $mirrorFixture.mirror.network_transfer_performed -eq $false
$threatModelReady = $null -ne $threatModel -and $threatModel.status -eq "completed" -and $threatModel.acceptance_coverage.mirror_staleness_covered -eq $true -and $threatModel.acceptance_coverage.unsigned_revoked_metadata_covered -eq $true

Add-Check "rc4.plan.current_task" ($null -ne $plan -and $plan.current_task -eq "RC4-011") "RC4 plan must point at RC4-011 before mirror publication replay." "blocking" $(if ($null -ne $plan) { $plan.current_task } else { $null })
Add-Check "hosted_transport.result_ready" $hostedResultReady "RC4-010 hosted transport result must be passed." "blocking" $(if ($null -ne $hostedResult) { $hostedResult.summary } else { $null })
Add-Check "hosted_transport.manifest_ready" $hostedManifestReady "Hosted transport manifest must be local, hash-bound, and non-GA." "blocking" $(if ($null -ne $hostedManifest) { $hostedManifest.transport } else { $null })
Add-Check "local_mirror.fixture_ready" $mirrorFixtureReady "Local mirror fixture must bind the current hosted manifest file hash and remain local-only." "blocking" $(if ($null -ne $mirrorFixture) { $mirrorFixture.mirror } else { $null })
Add-Check "local_mirror.required_entries_present" ($missingKinds.Count -eq 0) "Local mirror fixture must carry every required RC3 evidence entry." "blocking" ([ordered]@{ missing = @($missingKinds); present = @($presentKinds) })
Add-Check "local_mirror.entry_hashes_current" ($entryHashMismatches.Count -eq 0) "Every local mirror fixture entry hash must match the current file." "blocking" @($entryHashMismatches)
Add-Check "threat_model.mirror_cases_defined" $threatModelReady "RC4 threat model must define mirror staleness and unsigned/revoked metadata coverage." "blocking" $(if ($null -ne $threatModel) { $threatModel.acceptance_coverage } else { $null })
Add-Check "mirror_publication.no_authority_broadened" $true "Mirror publication replay must not transfer network bytes, sign, activate, rollback, mutate registry, mutate ring state, or grant TUI authority." "blocking" ([ordered]@{
    network_transfer_performed = $false
    remote_upload_performed = $false
    cryptographic_signing_performed = $false
    cryptographic_verification_performed = $false
    activation_performed = $false
    rollback_execution_performed = $false
    active_registry_mutated = $false
    active_slot_mutated = $false
    production_ring_mutated = $false
    remote_dispatch_enabled = $false
    tui_authority = $false
})

$readyToWrite = @($script:blockers).Count -eq 0
$generatedAt = "2026-06-08T09:30:00+08:00"

$mirrorLockfile = [ordered]@{
    schema = "agentos.rc4-remote-registry-mirror-lockfile.v1"
    generated_at = $generatedAt
    status = if ($readyToWrite) { "locked-locally" } else { "blocked" }
    production_ready_claim = $false
    task = "RC4-011"
    hosted_transport_manifest = [ordered]@{
        path = Get-StablePath $resolvedHostedManifestPath
        sha256 = $hostedManifestHash
    }
    local_mirror_fixture = [ordered]@{
        path = Get-StablePath $resolvedMirrorFixturePath
        sha256 = $mirrorFixtureHash
    }
    entries = @($entryEvidence)
    lock_policy = [ordered]@{
        immutable = $true
        append_only = $true
        content_addressed = $true
        freshness_window = if ($null -ne $hostedManifest) { $hostedManifest.mirror.freshness_window } else { $null }
        rollback_baseline_required = $true
        revocation_snapshot_required = $true
        remote_authoritative = $false
    }
    invariants = [ordered]@{
        local_private_key_material_used = $false
        cryptographic_signing_performed = $false
        network_transfer_performed = $false
        remote_upload_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        active_registry_mutated = $false
        active_slot_mutated = $false
        production_ring_mutated = $false
        tui_authority = $false
    }
}

if ($readyToWrite) {
    Write-ProjectionJsonArtifact -Value $mirrorLockfile -Path $resolvedLockfilePath
    Add-Check "mirror_lockfile.written" (Test-Path -LiteralPath $resolvedLockfilePath -PathType Leaf) "Mirror lockfile must be written." "blocking" ([ordered]@{ path = Get-StablePath $resolvedLockfilePath; sha256 = Get-FileSha256 $resolvedLockfilePath })
}

$mirrorLockfileHash = Get-FileSha256 $resolvedLockfilePath
$mirrorPublication = [ordered]@{
    schema = "agentos.rc4-remote-registry-mirror-publication.v1"
    generated_at = $generatedAt
    status = if ($readyToWrite) { "published-locally" } else { "blocked" }
    production_ready_claim = $false
    task = "RC4-011"
    mirror = [ordered]@{
        id = "rc4-remote-registry-mirror-publication"
        source_fixture = if ($null -ne $mirrorFixture) { $mirrorFixture.mirror.id } else { $null }
        authoritative_remote = $false
        local_replay_only = $true
        network_transfer_performed = $false
        active_registry_mutated = $false
        snapshot_freshness_status = "fresh-fixture"
        immutable = $true
        append_only = $true
        content_addressed = $true
    }
    bindings = [ordered]@{
        hosted_transport_manifest_sha256 = $hostedManifestHash
        local_mirror_fixture_sha256 = $mirrorFixtureHash
        mirror_lockfile_sha256 = $mirrorLockfileHash
        rc3_final_audit_sha256 = if ($null -ne $hostedManifest) { $hostedManifest.bindings.rc3_final_audit_sha256 } else { $null }
        publication_manifest_sha256 = if ($null -ne $hostedManifest) { $hostedManifest.bindings.publication_manifest_sha256 } else { $null }
        channel_index_sha256 = if ($null -ne $hostedManifest) { $hostedManifest.bindings.channel_index_sha256 } else { $null }
        signing_publication_gate_sha256 = if ($null -ne $hostedManifest) { $hostedManifest.bindings.signing_publication_gate_sha256 } else { $null }
        revocation_log_sha256 = if ($null -ne $hostedManifest) { $hostedManifest.bindings.revocation_log_sha256 } else { $null }
    }
    fail_closed_cases_required = @($mirrorFixture.fail_closed_cases_required)
    invariants = [ordered]@{
        local_private_key_material_used = $false
        cryptographic_signing_performed = $false
        cryptographic_verification_performed = $false
        network_transfer_performed = $false
        remote_upload_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        active_registry_mutated = $false
        active_slot_mutated = $false
        production_ring_mutated = $false
        remote_dispatch_enabled = $false
        tui_authority = $false
    }
    handoff = [ordered]@{
        next_task = "RC4-012"
        rc4_012_consumes = @(
            "hosted_transport_manifest",
            "local_mirror_fixture",
            "mirror_lockfile",
            "mirror_publication"
        )
    }
}

if ($readyToWrite) {
    Write-ProjectionJsonArtifact -Value $mirrorPublication -Path $resolvedPublicationPath
    Add-Check "mirror_publication.written" (Test-Path -LiteralPath $resolvedPublicationPath -PathType Leaf) "Mirror publication replay artifact must be written." "blocking" ([ordered]@{ path = Get-StablePath $resolvedPublicationPath; sha256 = Get-FileSha256 $resolvedPublicationPath })
    Add-Check "mirror_outputs.secret_safe" (Test-NoSensitiveContent -Paths @($resolvedLockfilePath, $resolvedPublicationPath)) "Mirror outputs must not contain private keys, signer tokens, or private authority paths." "blocking" $null
    Add-Check "mirror_outputs.host_path_free" (Test-NoHostPathContent -Paths @($resolvedLockfilePath, $resolvedPublicationPath)) "Mirror outputs must not contain host-local absolute paths." "blocking" $null
}

$passed = @($script:blockers).Count -eq 0
$result = [ordered]@{
    schema = "agentos.rc4-remote-registry-mirror-publication-result.v1"
    generated_at = $generatedAt
    checked_at = (Get-Date).ToString("o")
    task = "RC4-011"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    rc4_011_complete = $passed
    mirror_lockfile_written = Test-Path -LiteralPath $resolvedLockfilePath -PathType Leaf
    mirror_publication_written = Test-Path -LiteralPath $resolvedPublicationPath -PathType Leaf
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
    source_artifacts = [ordered]@{
        plan = New-Projection -Path $resolvedPlanPath -Json $plan
        hosted_transport_result = New-Projection -Path $resolvedHostedResultPath -Json $hostedResult
        hosted_transport_manifest = New-Projection -Path $resolvedHostedManifestPath -Json $hostedManifest
        local_mirror_fixture = New-Projection -Path $resolvedMirrorFixturePath -Json $mirrorFixture
        threat_model = New-Projection -Path $resolvedThreatModelPath -Json $threatModel
    }
    outputs = [ordered]@{
        mirror_lockfile = [ordered]@{ path = Get-StablePath $resolvedLockfilePath; sha256 = Get-FileSha256 $resolvedLockfilePath; present = Test-Path -LiteralPath $resolvedLockfilePath -PathType Leaf }
        mirror_publication = [ordered]@{ path = Get-StablePath $resolvedPublicationPath; sha256 = Get-FileSha256 $resolvedPublicationPath; present = Test-Path -LiteralPath $resolvedPublicationPath -PathType Leaf }
    }
    checks = $script:checks
    blockers = $script:blockers
    summary = [ordered]@{
        checks = @($script:checks).Count
        blockers = @($script:blockers).Count
        rc4_011_complete = $passed
        mirror_entries = @($entryEvidence).Count
        entry_hash_mismatches = @($entryHashMismatches).Count
        mirror_lockfile_written = Test-Path -LiteralPath $resolvedLockfilePath -PathType Leaf
        mirror_publication_written = Test-Path -LiteralPath $resolvedPublicationPath -PathType Leaf
        production_ready_claim = $false
        network_transfer_performed = $false
        active_registry_mutated = $false
        production_ring_mutated = $false
    }
}

Write-Json -Value $result -Path $resolvedOutputPath

$resultSecretSafe = Test-NoSensitiveContent -Paths @($resolvedOutputPath)
$resultHostPathFree = Test-NoHostPathContent -Paths @($resolvedOutputPath)
if (-not $resultSecretSafe -or -not $resultHostPathFree) {
    $extra = [ordered]@{
        id = "mirror_publication.result_secret_safe"
        status = "failed"
        severity = "blocking"
        message = "RC4 mirror publication result must be secret-safe and host-path-free."
        evidence = [ordered]@{ secret_safe = $resultSecretSafe; host_path_free = $resultHostPathFree; path = Get-StablePath $resolvedOutputPath }
    }
    $script:checks += $extra
    $script:blockers += $extra
    $result.checks = $script:checks
    $result.blockers = $script:blockers
    $result.status = "blocked"
    $result.rc4_011_complete = $false
    $result.summary.checks = @($script:checks).Count
    $result.summary.blockers = @($script:blockers).Count
    $result.summary.rc4_011_complete = $false
    Write-Json -Value $result -Path $resolvedOutputPath
}

Write-Host "RC4 remote registry mirror publication $($result.status): $MirrorPublicationPath"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
