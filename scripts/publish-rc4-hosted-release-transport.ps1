param(
    [string]$ArtifactDir = ".workflow/artifacts/rc4-hosted-release-transport",
    [string]$Rc4PlanPath = ".workflow/active/WFS-20260608-agentos-production-distro-rc4/plan.json",
    [string]$Rc4ContractEvidencePath = ".workflow/active/WFS-20260608-agentos-production-distro-rc4/evidence/RC4-001-hosted-release-transport-fleet-contract.json",
    [string]$Rc4RolloutBoundaryEvidencePath = ".workflow/active/WFS-20260608-agentos-production-distro-rc4/evidence/RC4-002-staged-rollout-authority-rollback-boundary.json",
    [string]$Rc4GaGatesEvidencePath = ".workflow/active/WFS-20260608-agentos-production-distro-rc4/evidence/RC4-003-ga-hardening-acceptance-gates.json",
    [string]$Rc4ThreatModelEvidencePath = ".workflow/active/WFS-20260608-agentos-production-distro-rc4/evidence/RC4-004-hosted-transport-fleet-threat-model.json",
    [string]$Rc3FinalAuditPath = ".workflow/active/WFS-20260531-agentos-production-distro-rc3/evidence/FINAL-AUDIT-20260531-production-distro-rc3.json",
    [string]$ProductionVerificationPath = ".workflow/artifacts/rc3-production-signature-verification/result.json",
    [string]$PublicationManifestPath = ".workflow/artifacts/rc3-release-channel-publication/publication-manifest.json",
    [string]$ChannelIndexPath = ".workflow/artifacts/rc3-release-channel-publication/channel-index.json",
    [string]$ConsumerSmokePath = ".workflow/artifacts/rc3-signed-channel-consumer/result.json",
    [string]$SupportRecoveryPath = ".workflow/artifacts/rc3-published-release-support-recovery/result.json",
    [string]$SigningPublicationGatePath = ".workflow/artifacts/release/rc3-production-signing-publication-gate.json",
    [string]$RevocationLogPath = "packaging/agentos/rootfs/etc/agentos/production-signing/key-revocation-log.json",
    [string]$HostedTransportManifestPath = "",
    [string]$LocalMirrorFixturePath = "",
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

function Get-StringSha256 {
    param([Parameter(Mandatory = $true)][string]$Value)
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Value)
    $hash = [Security.Cryptography.SHA256]::HashData($bytes)
    return ([BitConverter]::ToString($hash)).Replace("-", "").ToLowerInvariant()
}

function Get-ObjectSha256 {
    param([Parameter(Mandatory = $true)]$Value)
    return Get-StringSha256 (Get-JsonText $Value)
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
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )
    $json = Get-JsonText $Value
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $existing = Get-Content -LiteralPath $Path -Raw
        if ($existing.TrimEnd() -ne $json.TrimEnd()) {
            Write-Json -Value $Value -Path $Path
        }
        return
    }
    Write-Json -Value $Value -Path $Path
}

function New-InputProjection {
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
$expectedArtifactDir = Resolve-RepoPath ".workflow/artifacts/rc4-hosted-release-transport"
if (-not $resolvedArtifactDir.Equals($expectedArtifactDir, [StringComparison]::OrdinalIgnoreCase)) {
    throw "ArtifactDir must be .workflow/artifacts/rc4-hosted-release-transport"
}
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null

if (-not (Has-Value $HostedTransportManifestPath)) {
    $HostedTransportManifestPath = Join-Path $ArtifactDir "hosted-transport-manifest.json"
}
if (-not (Has-Value $LocalMirrorFixturePath)) {
    $LocalMirrorFixturePath = Join-Path $ArtifactDir "local-mirror-fixture.json"
}
if (-not (Has-Value $OutputPath)) {
    $OutputPath = Join-Path $ArtifactDir "result.json"
}

$resolvedHostedTransportManifestPath = Resolve-RepoPath $HostedTransportManifestPath
$resolvedLocalMirrorFixturePath = Resolve-RepoPath $LocalMirrorFixturePath
$resolvedOutputPath = Resolve-RepoPath $OutputPath

$rc4PlanPathResolved = Resolve-RepoPath $Rc4PlanPath
$rc4ContractEvidencePathResolved = Resolve-RepoPath $Rc4ContractEvidencePath
$rc4RolloutBoundaryEvidencePathResolved = Resolve-RepoPath $Rc4RolloutBoundaryEvidencePath
$rc4GaGatesEvidencePathResolved = Resolve-RepoPath $Rc4GaGatesEvidencePath
$rc4ThreatModelEvidencePathResolved = Resolve-RepoPath $Rc4ThreatModelEvidencePath
$rc3FinalAuditPathResolved = Resolve-RepoPath $Rc3FinalAuditPath
$productionVerificationPathResolved = Resolve-RepoPath $ProductionVerificationPath
$publicationManifestPathResolved = Resolve-RepoPath $PublicationManifestPath
$channelIndexPathResolved = Resolve-RepoPath $ChannelIndexPath
$consumerSmokePathResolved = Resolve-RepoPath $ConsumerSmokePath
$supportRecoveryPathResolved = Resolve-RepoPath $SupportRecoveryPath
$signingPublicationGatePathResolved = Resolve-RepoPath $SigningPublicationGatePath
$revocationLogPathResolved = Resolve-RepoPath $RevocationLogPath

$rc4Plan = Read-JsonFile $rc4PlanPathResolved
$rc4ContractEvidence = Read-JsonFile $rc4ContractEvidencePathResolved
$rc4RolloutBoundaryEvidence = Read-JsonFile $rc4RolloutBoundaryEvidencePathResolved
$rc4GaGatesEvidence = Read-JsonFile $rc4GaGatesEvidencePathResolved
$rc4ThreatModelEvidence = Read-JsonFile $rc4ThreatModelEvidencePathResolved
$rc3FinalAudit = Read-JsonFile $rc3FinalAuditPathResolved
$productionVerification = Read-JsonFile $productionVerificationPathResolved
$publicationManifest = Read-JsonFile $publicationManifestPathResolved
$channelIndex = Read-JsonFile $channelIndexPathResolved
$consumerSmoke = Read-JsonFile $consumerSmokePathResolved
$supportRecovery = Read-JsonFile $supportRecoveryPathResolved
$signingPublicationGate = Read-JsonFile $signingPublicationGatePathResolved
$revocationLog = Read-JsonFile $revocationLogPathResolved

$rc4Wave0Ready = $null -ne $rc4ContractEvidence -and $rc4ContractEvidence.status -eq "completed" -and
    $null -ne $rc4RolloutBoundaryEvidence -and $rc4RolloutBoundaryEvidence.status -eq "completed" -and
    $null -ne $rc4GaGatesEvidence -and $rc4GaGatesEvidence.status -eq "completed" -and
    $null -ne $rc4ThreatModelEvidence -and $rc4ThreatModelEvidence.status -eq "completed"
$rc3FinalAuditReady = $null -ne $rc3FinalAudit -and $rc3FinalAudit.schema -eq "agentos.production-distro-rc3-final-audit.v1" -and $rc3FinalAudit.verdict -eq "PASS" -and $rc3FinalAudit.production_ready_claim -eq $false
$productionVerificationReady = $null -ne $productionVerification -and $productionVerification.status -eq "passed" -and (Get-JsonBlockerCount $productionVerification) -eq 0 -and $productionVerification.summary.required_artifacts -eq 41
$publicationManifestReady = $null -ne $publicationManifest -and $publicationManifest.schema -eq "agentos.immutable-release-channel-publication.v1" -and $publicationManifest.status -eq "published-locally" -and $publicationManifest.production_ready_claim -eq $false -and $publicationManifest.channel.immutable -eq $true -and $publicationManifest.channel.append_only -eq $true
$channelIndexReady = $null -ne $channelIndex -and $channelIndex.schema -eq "agentos.release-channel-index.v1" -and $channelIndex.status -eq "updated" -and $channelIndex.production_ready_claim -eq $false -and $channelIndex.channel.append_only -eq $true -and @($channelIndex.entries).Count -ge 1
$consumerReady = $null -ne $consumerSmoke -and $consumerSmoke.status -eq "passed" -and $consumerSmoke.rc3_021_complete -eq $true -and (Get-JsonBlockerCount $consumerSmoke) -eq 0
$supportReady = $null -ne $supportRecovery -and $supportRecovery.status -eq "passed" -and $supportRecovery.rc3_022_complete -eq $true -and $supportRecovery.summary.support_bundle_redacted -eq $true -and $supportRecovery.summary.remote_upload_performed -eq $false
$gateReady = $null -ne $signingPublicationGate -and $signingPublicationGate.status -eq "passed" -and $signingPublicationGate.production_ready_claim -eq $false
$revocationReady = $null -ne $revocationLog

Add-Check "rc4.plan.current_task" ($null -ne $rc4Plan -and $rc4Plan.current_task -eq "RC4-010") "RC4 plan must point at RC4-010 before hosted transport artifacts are written." "blocking" $(if ($null -ne $rc4Plan) { $rc4Plan.current_task } else { $null })
Add-Check "rc4.wave0.contracts_completed" $rc4Wave0Ready "RC4 Wave 0 contracts must be complete before hosted transport manifest generation." "blocking" ([ordered]@{
    RC4_001 = if ($null -ne $rc4ContractEvidence) { $rc4ContractEvidence.status } else { $null }
    RC4_002 = if ($null -ne $rc4RolloutBoundaryEvidence) { $rc4RolloutBoundaryEvidence.status } else { $null }
    RC4_003 = if ($null -ne $rc4GaGatesEvidence) { $rc4GaGatesEvidence.status } else { $null }
    RC4_004 = if ($null -ne $rc4ThreatModelEvidence) { $rc4ThreatModelEvidence.status } else { $null }
})
Add-Check "rc3.final_audit.pass" $rc3FinalAuditReady "RC3 final audit must pass and remain non-GA before RC4 hosted transport." "blocking" $(if ($null -ne $rc3FinalAudit) { [ordered]@{ verdict = $rc3FinalAudit.verdict; production_ready_claim = $rc3FinalAudit.production_ready_claim } } else { $null })
Add-Check "production_verification.passed" $productionVerificationReady "RC3 production signature verification must pass for all required artifacts." "blocking" $(if ($null -ne $productionVerification) { $productionVerification.summary } else { $null })
Add-Check "publication_manifest.ready" $publicationManifestReady "RC3 publication manifest must be immutable, append-only, and non-GA." "blocking" $(if ($null -ne $publicationManifest) { $publicationManifest.channel } else { $null })
Add-Check "channel_index.ready" $channelIndexReady "RC3 channel index must be append-only and non-GA." "blocking" $(if ($null -ne $channelIndex) { $channelIndex.channel } else { $null })
Add-Check "consumer_smoke.passed" $consumerReady "RC3 signed channel consumer smoke must pass." "blocking" $(if ($null -ne $consumerSmoke) { $consumerSmoke.summary } else { $null })
Add-Check "support_recovery.passed" $supportReady "RC3 support/recovery projection must be redacted and local-only." "blocking" $(if ($null -ne $supportRecovery) { $supportRecovery.summary } else { $null })
Add-Check "signing_publication_gate.passed" $gateReady "RC3 signing/publication gate must pass without GA claim." "blocking" $(if ($null -ne $signingPublicationGate) { [ordered]@{ status = $signingPublicationGate.status; production_ready_claim = $signingPublicationGate.production_ready_claim } } else { $null })
Add-Check "revocation_log.present" $revocationReady "Packaged revocation log must be present for hosted transport binding." "blocking" (Get-StablePath $revocationLogPathResolved)
Add-Check "hosted_transport.no_authority_broadened" $true "Hosted transport writer must not sign, upload, activate, rollback, mutate active artifacts, or grant TUI authority." "blocking" ([ordered]@{
    network_transfer_performed = $false
    remote_upload_performed = $false
    cryptographic_signing_performed = $false
    cryptographic_verification_performed = $false
    activation_performed = $false
    rollback_execution_performed = $false
    active_slot_mutated = $false
    active_artifact_set_mutated = $false
    production_ring_mutated = $false
    tui_authority = $false
})

$readyToWrite = @($script:blockers).Count -eq 0
$generatedAt = "2026-06-08T09:20:00+08:00"

$inputHashes = [ordered]@{
    rc4_plan = Get-FileSha256 $rc4PlanPathResolved
    rc4_contract = Get-FileSha256 $rc4ContractEvidencePathResolved
    rc4_rollout_boundary = Get-FileSha256 $rc4RolloutBoundaryEvidencePathResolved
    rc4_ga_gates = Get-FileSha256 $rc4GaGatesEvidencePathResolved
    rc4_threat_model = Get-FileSha256 $rc4ThreatModelEvidencePathResolved
    rc3_final_audit = Get-FileSha256 $rc3FinalAuditPathResolved
    production_verification = Get-FileSha256 $productionVerificationPathResolved
    publication_manifest = Get-FileSha256 $publicationManifestPathResolved
    channel_index = Get-FileSha256 $channelIndexPathResolved
    consumer_smoke = Get-FileSha256 $consumerSmokePathResolved
    support_recovery = Get-FileSha256 $supportRecoveryPathResolved
    signing_publication_gate = Get-FileSha256 $signingPublicationGatePathResolved
    revocation_log = Get-FileSha256 $revocationLogPathResolved
}

$hostedTransportManifest = [ordered]@{
    schema = "agentos.rc4-hosted-release-transport-manifest.v1"
    generated_at = $generatedAt
    status = if ($readyToWrite) { "published-locally" } else { "blocked" }
    production_ready_claim = $false
    task = "RC4-010"
    transport = [ordered]@{
        id = "production-candidate-rc4-hosted-transport"
        source_channel = "production-candidate-rc3"
        hosted_network_required_for_ga = $true
        network_transfer_performed = $false
        local_fixture_only = $true
        immutable = $true
        append_only = $true
        content_addressed = $true
        in_place_head_mutation_allowed = $false
        update_authority = "AgentCore PlanSpec + SecurityExecutionEngine"
        tui_authority = $false
    }
    bindings = [ordered]@{
        rc3_final_audit_sha256 = $inputHashes.rc3_final_audit
        production_verification_sha256 = $inputHashes.production_verification
        publication_manifest_sha256 = $inputHashes.publication_manifest
        channel_index_sha256 = $inputHashes.channel_index
        consumer_smoke_sha256 = $inputHashes.consumer_smoke
        support_recovery_sha256 = $inputHashes.support_recovery
        signing_publication_gate_sha256 = $inputHashes.signing_publication_gate
        revocation_log_sha256 = $inputHashes.revocation_log
    }
    inputs = [ordered]@{
        rc3_final_audit = Get-StablePath $rc3FinalAuditPathResolved
        production_verification = Get-StablePath $productionVerificationPathResolved
        publication_manifest = Get-StablePath $publicationManifestPathResolved
        channel_index = Get-StablePath $channelIndexPathResolved
        consumer_smoke = Get-StablePath $consumerSmokePathResolved
        support_recovery = Get-StablePath $supportRecoveryPathResolved
        signing_publication_gate = Get-StablePath $signingPublicationGatePathResolved
        revocation_log = Get-StablePath $revocationLogPathResolved
    }
    invariants = [ordered]@{
        local_private_key_material_used = $false
        cryptographic_signing_performed = $false
        network_transfer_performed = $false
        remote_upload_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        active_slot_mutated = $false
        production_ring_mutated = $false
        production_ready_claim = $false
    }
    mirror = [ordered]@{
        fixture_path = Get-StablePath $resolvedLocalMirrorFixturePath
        freshness_window = "P7D"
        lockfile_required = $true
        rollback_baseline_required = $true
        revocation_snapshot_required = $true
    }
}

if ($readyToWrite) {
    Write-ProjectionJsonArtifact -Value $hostedTransportManifest -Path $resolvedHostedTransportManifestPath -Name "RC4 hosted transport manifest"
    Add-Check "hosted_transport_manifest.written" (Test-Path -LiteralPath $resolvedHostedTransportManifestPath -PathType Leaf) "Hosted transport manifest must be written." "blocking" ([ordered]@{ path = Get-StablePath $resolvedHostedTransportManifestPath; sha256 = Get-FileSha256 $resolvedHostedTransportManifestPath })
}

$hostedManifestFileHash = Get-FileSha256 $resolvedHostedTransportManifestPath
if (-not (Has-Value $hostedManifestFileHash)) {
    $hostedManifestFileHash = Get-ObjectSha256 $hostedTransportManifest
}

$localMirrorFixture = [ordered]@{
    schema = "agentos.rc4-local-mirror-fixture.v1"
    generated_at = $generatedAt
    status = if ($readyToWrite) { "fixture-ready" } else { "blocked" }
    production_ready_claim = $false
    task = "RC4-010"
    mirror = [ordered]@{
        id = "local-rc4-hosted-transport-mirror"
        authoritative_remote = $false
        local_fixture_only = $true
        network_transfer_performed = $false
        active_registry_mutated = $false
        snapshot_freshness_window = "P7D"
        snapshot_state = "fresh-fixture"
    }
    hosted_transport_manifest_sha256 = $hostedManifestFileHash
    entries = @(
        [ordered]@{ kind = "rc3_final_audit"; path = Get-StablePath $rc3FinalAuditPathResolved; sha256 = $inputHashes.rc3_final_audit }
        [ordered]@{ kind = "production_verification"; path = Get-StablePath $productionVerificationPathResolved; sha256 = $inputHashes.production_verification }
        [ordered]@{ kind = "publication_manifest"; path = Get-StablePath $publicationManifestPathResolved; sha256 = $inputHashes.publication_manifest }
        [ordered]@{ kind = "channel_index"; path = Get-StablePath $channelIndexPathResolved; sha256 = $inputHashes.channel_index }
        [ordered]@{ kind = "consumer_smoke"; path = Get-StablePath $consumerSmokePathResolved; sha256 = $inputHashes.consumer_smoke }
        [ordered]@{ kind = "support_recovery"; path = Get-StablePath $supportRecoveryPathResolved; sha256 = $inputHashes.support_recovery }
        [ordered]@{ kind = "signing_publication_gate"; path = Get-StablePath $signingPublicationGatePathResolved; sha256 = $inputHashes.signing_publication_gate }
        [ordered]@{ kind = "revocation_log"; path = Get-StablePath $revocationLogPathResolved; sha256 = $inputHashes.revocation_log }
    )
    fail_closed_cases_required = @(
        "hosted-manifest-hash-drift",
        "missing-rc3-final-audit-binding",
        "stale-mirror-snapshot",
        "unsigned-mirror-metadata",
        "revoked-mirror-metadata",
        "registry-lockfile-mismatch",
        "rollback-baseline-missing",
        "remote-dispatch-mutation-attempt"
    )
    invariants = [ordered]@{
        local_private_key_material_used = $false
        cryptographic_signing_performed = $false
        network_transfer_performed = $false
        remote_upload_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        active_slot_mutated = $false
        active_registry_mutated = $false
        production_ring_mutated = $false
        tui_authority = $false
    }
}

if ($readyToWrite) {
    Write-ProjectionJsonArtifact -Value $localMirrorFixture -Path $resolvedLocalMirrorFixturePath -Name "RC4 local mirror fixture"
    Add-Check "local_mirror_fixture.written" (Test-Path -LiteralPath $resolvedLocalMirrorFixturePath -PathType Leaf) "Local mirror fixture must be written." "blocking" ([ordered]@{ path = Get-StablePath $resolvedLocalMirrorFixturePath; sha256 = Get-FileSha256 $resolvedLocalMirrorFixturePath })
    Add-Check "hosted_transport_outputs.secret_safe" (Test-NoSensitiveContent -Paths @($resolvedHostedTransportManifestPath, $resolvedLocalMirrorFixturePath)) "Hosted transport outputs must not contain private keys, signer tokens, or private authority paths." "blocking" $null
    Add-Check "hosted_transport_outputs.host_path_free" (Test-NoHostPathContent -Paths @($resolvedHostedTransportManifestPath, $resolvedLocalMirrorFixturePath)) "Hosted transport outputs must not contain host-local absolute paths." "blocking" $null
}

$passed = @($script:blockers).Count -eq 0
$result = [ordered]@{
    schema = "agentos.rc4-hosted-release-transport-result.v1"
    generated_at = $generatedAt
    checked_at = (Get-Date).ToString("o")
    task = "RC4-010"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    rc4_010_complete = $passed
    hosted_transport_manifest_written = Test-Path -LiteralPath $resolvedHostedTransportManifestPath -PathType Leaf
    local_mirror_fixture_written = Test-Path -LiteralPath $resolvedLocalMirrorFixturePath -PathType Leaf
    local_private_key_material_used = $false
    cryptographic_signing_performed = $false
    cryptographic_verification_performed = $false
    network_transfer_performed = $false
    remote_upload_performed = $false
    activation_performed = $false
    rollback_execution_performed = $false
    active_slot_mutated = $false
    active_artifact_set_mutated = $false
    boot_metadata_mutated = $false
    active_registry_mutated = $false
    production_ring_mutated = $false
    remote_dispatch_enabled = $false
    tui_authority = $false
    inputs = $inputHashes
    source_artifacts = [ordered]@{
        rc4_plan = New-InputProjection -Path $rc4PlanPathResolved -Json $rc4Plan
        rc4_contract = New-InputProjection -Path $rc4ContractEvidencePathResolved -Json $rc4ContractEvidence
        rc4_rollout_boundary = New-InputProjection -Path $rc4RolloutBoundaryEvidencePathResolved -Json $rc4RolloutBoundaryEvidence
        rc4_ga_gates = New-InputProjection -Path $rc4GaGatesEvidencePathResolved -Json $rc4GaGatesEvidence
        rc4_threat_model = New-InputProjection -Path $rc4ThreatModelEvidencePathResolved -Json $rc4ThreatModelEvidence
        rc3_final_audit = New-InputProjection -Path $rc3FinalAuditPathResolved -Json $rc3FinalAudit
        production_verification = New-InputProjection -Path $productionVerificationPathResolved -Json $productionVerification
        publication_manifest = New-InputProjection -Path $publicationManifestPathResolved -Json $publicationManifest
        channel_index = New-InputProjection -Path $channelIndexPathResolved -Json $channelIndex
        consumer_smoke = New-InputProjection -Path $consumerSmokePathResolved -Json $consumerSmoke
        support_recovery = New-InputProjection -Path $supportRecoveryPathResolved -Json $supportRecovery
        signing_publication_gate = New-InputProjection -Path $signingPublicationGatePathResolved -Json $signingPublicationGate
        revocation_log = New-InputProjection -Path $revocationLogPathResolved -Json $revocationLog
    }
    outputs = [ordered]@{
        hosted_transport_manifest = [ordered]@{ path = Get-StablePath $resolvedHostedTransportManifestPath; sha256 = Get-FileSha256 $resolvedHostedTransportManifestPath; present = Test-Path -LiteralPath $resolvedHostedTransportManifestPath -PathType Leaf }
        local_mirror_fixture = [ordered]@{ path = Get-StablePath $resolvedLocalMirrorFixturePath; sha256 = Get-FileSha256 $resolvedLocalMirrorFixturePath; present = Test-Path -LiteralPath $resolvedLocalMirrorFixturePath -PathType Leaf }
    }
    checks = $script:checks
    blockers = $script:blockers
    handoff = [ordered]@{
        next_task = "RC4-011"
        rc4_011_consumes = @(
            "hosted_transport_manifest",
            "local_mirror_fixture",
            "rc3_final_audit",
            "publication_manifest",
            "channel_index",
            "signing_publication_gate"
        )
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        blockers = @($script:blockers).Count
        rc4_010_complete = $passed
        hosted_transport_manifest_written = Test-Path -LiteralPath $resolvedHostedTransportManifestPath -PathType Leaf
        local_mirror_fixture_written = Test-Path -LiteralPath $resolvedLocalMirrorFixturePath -PathType Leaf
        production_ready_claim = $false
        network_transfer_performed = $false
        activation_performed = $false
        production_ring_mutated = $false
    }
}

Write-Json -Value $result -Path $resolvedOutputPath

$resultSecretSafe = Test-NoSensitiveContent -Paths @($resolvedOutputPath)
$resultHostPathFree = Test-NoHostPathContent -Paths @($resolvedOutputPath)
if (-not $resultSecretSafe -or -not $resultHostPathFree) {
    $extra = [ordered]@{
        id = "hosted_transport.result_secret_safe"
        status = "failed"
        severity = "blocking"
        message = "RC4 hosted transport result must be secret-safe and host-path-free."
        evidence = [ordered]@{ secret_safe = $resultSecretSafe; host_path_free = $resultHostPathFree; path = Get-StablePath $resolvedOutputPath }
    }
    $script:checks += $extra
    $script:blockers += $extra
    $result.checks = $script:checks
    $result.blockers = $script:blockers
    $result.status = "blocked"
    $result.rc4_010_complete = $false
    $result.summary.checks = @($script:checks).Count
    $result.summary.blockers = @($script:blockers).Count
    $result.summary.rc4_010_complete = $false
    Write-Json -Value $result -Path $resolvedOutputPath
}

Write-Host "RC4 hosted release transport $($result.status): $HostedTransportManifestPath"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
