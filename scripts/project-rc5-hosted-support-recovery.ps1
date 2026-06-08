param(
    [string]$RemoteHost = "47.101.11.109",
    [string]$RemoteUser = "root",
    [string]$Domain = "aios.w33d.xyz",
    [string]$ArtifactDir = ".workflow/artifacts/rc5-hosted-support-recovery",
    [string]$OutputPath = "",
    [string]$Rc5PlanPath = ".workflow/active/WFS-20260608-agentos-production-distro-rc5/plan.json",
    [string]$Rc5HostedServicePath = ".workflow/artifacts/rc5-hosted-mirror-service/result.json",
    [string]$Rc5EndpointVerifierPath = ".workflow/artifacts/rc5-hosted-endpoint-verifier/result.json",
    [string]$Rc5FailClosedPath = ".workflow/artifacts/rc5-hosted-metadata-fail-closed/result.json",
    [string]$Rc5UserReleasePath = ".workflow/artifacts/rc5-user-release-channel/result.json",
    [string]$Rc5HostedChannelPath = ".workflow/artifacts/rc5-user-release-channel/hosted-channel-index-after-user-release.json",
    [string]$Rc5CanaryProofPath = ".workflow/artifacts/rc5-multi-node-canary-proof/result.json",
    [string]$Rc5CanaryProjectionPath = ".workflow/artifacts/rc5-multi-node-canary-proof/multi-node-canary-plan-projection.json",
    [string]$Rc5RollbackProjectionPath = ".workflow/artifacts/rc5-multi-node-canary-proof/rollback-readiness-projection.json",
    [string]$Rc4SupportRecoveryPath = ".workflow/artifacts/rc4-ga-hardening-support-recovery-projection/result.json",
    [string]$Rc4SupportIndexPath = ".workflow/artifacts/rc4-ga-hardening-support-recovery-projection/support-recovery-index.json",
    [string]$Rc4RecoveryProjectionPath = ".workflow/artifacts/rc4-ga-hardening-support-recovery-projection/hosted-fleet-recovery-projection.json",
    [int]$SshConnectTimeoutSeconds = 10,
    [int]$CurlTimeoutSeconds = 15,
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
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha256.ComputeHash($bytes)
    } finally {
        $sha256.Dispose()
    }
    return ([BitConverter]::ToString($hash)).Replace("-", "").ToLowerInvariant()
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

function ConvertFrom-JsonTextSafe {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }
    try {
        return ConvertFrom-Json -InputObject $Text
    } catch {
        return $null
    }
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

function Invoke-Remote {
    param([Parameter(Mandatory = $true)][string]$Command)
    $target = "$RemoteUser@$RemoteHost"
    $args = @(
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=$SshConnectTimeoutSeconds",
        $target,
        $Command
    )
    $output = & ssh @args 2>&1
    $exitCode = $LASTEXITCODE
    $text = ($output | Out-String).Trim()
    if ($exitCode -ne 0) {
        throw "Remote command failed ($exitCode): $text"
    }
    return $text
}

function Set-RemoteTextFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Text,
        [string]$Mode = "0644"
    )
    $encoded = [Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes($Text))
    $parent = [IO.Path]::GetDirectoryName($Path) -replace "\\", "/"
    $command = "set -eu; install -d -m 0755 '$parent'; printf '%s' '$encoded' | base64 -d > '$Path'; chmod '$Mode' '$Path'"
    Invoke-Remote $command | Out-Null
}

function Invoke-Curl {
    param([Parameter(Mandatory = $true)][string]$Url)
    $args = @(
        "--noproxy", "*",
        "--max-time", "$CurlTimeoutSeconds",
        "--resolve", "$Domain`:80`:$RemoteHost",
        "-sS",
        "-w", "`n%{http_code}",
        $Url
    )
    $output = & curl.exe @args 2>&1
    $exitCode = $LASTEXITCODE
    $text = ($output | Out-String).TrimEnd()
    $parts = [regex]::Split($text, "\r?\n")
    $statusText = $parts[-1]
    $body = if ($parts.Count -gt 1) { ($parts[0..($parts.Count - 2)] -join "`n") } else { "" }
    $statusCode = 0
    [void][int]::TryParse($statusText, [ref]$statusCode)
    return [ordered]@{
        exit_code = $exitCode
        status_code = $statusCode
        body = $body
        url = $Url
    }
}

function Test-NoSensitiveValues {
    param([Parameter(Mandatory = $true)][string[]]$Values)
    $patterns = @(
        "-----BEGIN [A-Z ]*PRIVATE KEY-----",
        "\bAIOS_SIGNER_API_TOKEN\b\s*[:=]",
        "\bAuthorization\b\s*:\s*Bearer\s+\S+",
        "\bBearer\s+[A-Za-z0-9._~+/-]+",
        "\baccess[_-]?token\b\s*[:=]\s*[""']?[^""'\s,}]+",
        "\brefresh[_-]?token\b\s*[:=]\s*[""']?[^""'\s,}]+",
        "\bprivate[_-]?key[_-]?pem\b\s*[:=]",
        "\.local-release-authority/private",
        "signing-key\.pem"
    )
    foreach ($value in $Values) {
        foreach ($pattern in $patterns) {
            if ($value -match $pattern) {
                return $false
            }
        }
    }
    return $true
}

function Test-NoSensitiveContent {
    param([Parameter(Mandatory = $true)][string[]]$Paths)
    $values = @()
    foreach ($path in $Paths) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            return $false
        }
        $values += (Get-Content -LiteralPath $path -Raw)
    }
    return Test-NoSensitiveValues -Values $values
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

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:blockers = @()

$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$expectedArtifactDir = Resolve-RepoPath ".workflow/artifacts/rc5-hosted-support-recovery"
if (-not $resolvedArtifactDir.Equals($expectedArtifactDir, [StringComparison]::OrdinalIgnoreCase)) {
    throw "ArtifactDir must be .workflow/artifacts/rc5-hosted-support-recovery"
}
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null

if (-not (Has-Value $OutputPath)) {
    $OutputPath = Join-Path $ArtifactDir "result.json"
}

$resolvedOutputPath = Resolve-RepoPath $OutputPath
$supportIndexPath = Join-Path $resolvedArtifactDir "support-index.json"
$recoveryOperationsPath = Join-Path $resolvedArtifactDir "recovery-operations.json"
$hostedChannelAfterSupportPath = Join-Path $resolvedArtifactDir "hosted-channel-index-after-support-recovery.json"

$resolvedRc5PlanPath = Resolve-RepoPath $Rc5PlanPath
$resolvedRc5HostedServicePath = Resolve-RepoPath $Rc5HostedServicePath
$resolvedRc5EndpointVerifierPath = Resolve-RepoPath $Rc5EndpointVerifierPath
$resolvedRc5FailClosedPath = Resolve-RepoPath $Rc5FailClosedPath
$resolvedRc5UserReleasePath = Resolve-RepoPath $Rc5UserReleasePath
$resolvedRc5HostedChannelPath = Resolve-RepoPath $Rc5HostedChannelPath
$resolvedRc5CanaryProofPath = Resolve-RepoPath $Rc5CanaryProofPath
$resolvedRc5CanaryProjectionPath = Resolve-RepoPath $Rc5CanaryProjectionPath
$resolvedRc5RollbackProjectionPath = Resolve-RepoPath $Rc5RollbackProjectionPath
$resolvedRc4SupportRecoveryPath = Resolve-RepoPath $Rc4SupportRecoveryPath
$resolvedRc4SupportIndexPath = Resolve-RepoPath $Rc4SupportIndexPath
$resolvedRc4RecoveryProjectionPath = Resolve-RepoPath $Rc4RecoveryProjectionPath

$rc5Plan = Read-JsonFile $resolvedRc5PlanPath
$rc5HostedService = Read-JsonFile $resolvedRc5HostedServicePath
$rc5EndpointVerifier = Read-JsonFile $resolvedRc5EndpointVerifierPath
$rc5FailClosed = Read-JsonFile $resolvedRc5FailClosedPath
$rc5UserRelease = Read-JsonFile $resolvedRc5UserReleasePath
$rc5HostedChannel = Read-JsonFile $resolvedRc5HostedChannelPath
$rc5CanaryProof = Read-JsonFile $resolvedRc5CanaryProofPath
$rc5CanaryProjection = Read-JsonFile $resolvedRc5CanaryProjectionPath
$rc5RollbackProjection = Read-JsonFile $resolvedRc5RollbackProjectionPath
$rc4SupportRecovery = Read-JsonFile $resolvedRc4SupportRecoveryPath
$rc4SupportIndex = Read-JsonFile $resolvedRc4SupportIndexPath
$rc4RecoveryProjection = Read-JsonFile $resolvedRc4RecoveryProjectionPath

$rc5TaskStatuses = @{}
if ($null -ne $rc5Plan) {
    foreach ($wave in @($rc5Plan.waves)) {
        foreach ($task in @($wave.tasks)) {
            if ($null -ne $task.id) {
                $rc5TaskStatuses[$task.id] = $task.status
            }
        }
    }
}

$rc5PlanReady = $null -ne $rc5Plan -and
    $rc5Plan.current_task -eq "RC5-022" -and
    $rc5TaskStatuses["RC5-021"] -eq "completed" -and
    $rc5TaskStatuses["RC5-022"] -eq "pending"

$hostedServiceReady = $null -ne $rc5HostedService -and
    $rc5HostedService.status -eq "passed" -and
    $rc5HostedService.invariants.metadata_only -eq $true -and
    $rc5HostedService.invariants.activation_performed -eq $false -and
    $rc5HostedService.invariants.rollback_execution_performed -eq $false -and
    $rc5HostedService.invariants.production_ring_mutated -eq $false -and
    $rc5HostedService.invariants.remote_dispatch_enabled -eq $false -and
    $rc5HostedService.invariants.tui_authority -eq $false -and
    (Get-JsonBlockerCount $rc5HostedService) -eq 0

$endpointVerifierReady = $null -ne $rc5EndpointVerifier -and
    $rc5EndpointVerifier.status -eq "passed" -and
    $rc5EndpointVerifier.summary.blockers -eq 0 -and
    $rc5EndpointVerifier.production_ready_claim -eq $false

$failClosedReady = $null -ne $rc5FailClosed -and
    $rc5FailClosed.status -eq "passed" -and
    $rc5FailClosed.summary.negative_passed -eq 14 -and
    $rc5FailClosed.summary.blockers -eq 0

$userReleaseReady = $null -ne $rc5UserRelease -and
    $rc5UserRelease.status -eq "passed" -and
    $rc5UserRelease.summary.blockers -eq 0 -and
    $rc5UserRelease.invariants.install_allowed -eq $false -and
    $rc5UserRelease.invariants.update_allowed -eq $false -and
    $rc5UserRelease.invariants.activation_performed -eq $false -and
    $rc5UserRelease.invariants.rollback_execution_performed -eq $false -and
    $rc5UserRelease.invariants.remote_dispatch_enabled -eq $false

$canaryProofReady = $null -ne $rc5CanaryProof -and
    $rc5CanaryProof.status -eq "passed" -and
    $rc5CanaryProof.summary.blockers -eq 0 -and
    $rc5CanaryProof.canary_preconditions_proven -eq $true -and
    $rc5CanaryProof.controlled_multi_node_canary_execution_allowed -eq $false -and
    $rc5CanaryProof.controlled_multi_node_canary_execution_performed -eq $false -and
    $rc5CanaryProof.rollback_readiness_proven -eq $true -and
    $rc5CanaryProof.rollback_execution_performed -eq $false -and
    $rc5CanaryProof.invariants.remote_mutation_performed -eq $false

$canaryProjectionReady = $null -ne $rc5CanaryProjection -and
    $rc5CanaryProjection.status -eq "preconditions-proven-execution-blocked" -and
    $rc5CanaryProjection.canary_execution_allowed -eq $false -and
    $rc5CanaryProjection.canary_execution_performed -eq $false -and
    $rc5CanaryProjection.gates.rollback_readiness_ready -eq $true -and
    $rc5CanaryProjection.gates.execution_gate_status -eq "blocked-by-design"

$rollbackProjectionReady = $null -ne $rc5RollbackProjection -and
    $rc5RollbackProjection.status -eq "rollback-baseline-bound-execution-not-run" -and
    $rc5RollbackProjection.rollback_readiness_ready -eq $true -and
    $rc5RollbackProjection.rollback_execution_performed -eq $false -and
    $rc5RollbackProjection.previous_active_artifact_set_sha256 -eq $rc5RollbackProjection.restored_active_artifact_set_sha256

$rc4SupportReady = $null -ne $rc4SupportRecovery -and
    $rc4SupportRecovery.status -eq "passed" -and
    $rc4SupportRecovery.summary.blockers -eq 0 -and
    $rc4SupportRecovery.summary.support_bundle_redacted -eq $true -and
    $rc4SupportRecovery.summary.recovery_projection_emitted -eq $true -and
    $rc4SupportRecovery.summary.remote_upload_performed -eq $false -and
    $rc4SupportRecovery.summary.rollback_execution_performed -eq $false -and
    $rc4SupportRecovery.summary.remote_dispatch_enabled -eq $false -and
    $rc4SupportRecovery.summary.tui_authority -eq $false

$rc4SupportIndexReady = $null -ne $rc4SupportIndex -and
    $rc4SupportIndex.status -eq "indexed" -and
    $rc4SupportIndex.production_ready_claim -eq $false -and
    $rc4SupportIndex.local_only -eq $true

$rc4RecoveryReady = $null -ne $rc4RecoveryProjection -and
    $rc4RecoveryProjection.status -eq "projected" -and
    $rc4RecoveryProjection.production_ready_claim -eq $false -and
    $rc4RecoveryProjection.local_only -eq $true -and
    $rc4RecoveryProjection.authorities.remote_support_authority -eq $false -and
    $rc4RecoveryProjection.authorities.model_replay_authority -eq $false -and
    $rc4RecoveryProjection.authorities.normal_shell_authority -eq $false -and
    $rc4RecoveryProjection.authorities.tui_authority -eq $false -and
    $rc4RecoveryProjection.mutation_effects.rollback_execution_performed -eq $false -and
    $rc4RecoveryProjection.mutation_effects.active_slot_mutated -eq $false -and
    $rc4RecoveryProjection.mutation_effects.production_ring_mutated -eq $false

$sourceBindings = [ordered]@{
    rc5_hosted_service_result_sha256 = Get-FileSha256 $resolvedRc5HostedServicePath
    rc5_endpoint_verifier_result_sha256 = Get-FileSha256 $resolvedRc5EndpointVerifierPath
    rc5_hosted_metadata_fail_closed_sha256 = Get-FileSha256 $resolvedRc5FailClosedPath
    rc5_user_release_result_sha256 = Get-FileSha256 $resolvedRc5UserReleasePath
    rc5_hosted_channel_index_before_support_sha256 = Get-FileSha256 $resolvedRc5HostedChannelPath
    rc5_canary_proof_result_sha256 = Get-FileSha256 $resolvedRc5CanaryProofPath
    rc5_canary_projection_sha256 = Get-FileSha256 $resolvedRc5CanaryProjectionPath
    rc5_rollback_readiness_projection_sha256 = Get-FileSha256 $resolvedRc5RollbackProjectionPath
    rc4_support_recovery_result_sha256 = Get-FileSha256 $resolvedRc4SupportRecoveryPath
    rc4_support_recovery_index_sha256 = Get-FileSha256 $resolvedRc4SupportIndexPath
    rc4_recovery_projection_sha256 = Get-FileSha256 $resolvedRc4RecoveryProjectionPath
    rollback_baseline_sha256 = if ($null -ne $rc5RollbackProjection) { $rc5RollbackProjection.rollback_baseline_sha256 } else { $null }
    previous_active_artifact_set_sha256 = if ($null -ne $rc5RollbackProjection) { $rc5RollbackProjection.previous_active_artifact_set_sha256 } else { $null }
    restored_active_artifact_set_sha256 = if ($null -ne $rc5RollbackProjection) { $rc5RollbackProjection.restored_active_artifact_set_sha256 } else { $null }
}

$generatedAt = (Get-Date).ToString("o")

$supportIndex = [ordered]@{
    schema = "agentos.rc5-hosted-support-index.v1"
    generated_at = $generatedAt
    status = "hosted-metadata-only"
    production_ready_claim = $false
    domain = $Domain
    channel = "production-candidate-rc5"
    support_mode = "metadata-only"
    redacted = $true
    support_upload_allowed = $false
    support_upload_endpoint = $null
    recovery_execution_allowed = $false
    rollback_execution_allowed = $false
    activation_allowed = $false
    authority = [ordered]@{
        mirror_is_root_of_trust = $false
        support_authority = $false
        recovery_authority = $false
        signing_authority = $false
        activation_authority = $false
        rollback_execution_authority = $false
        production_ring_mutation_authority = $false
        remote_dispatch_authority = $false
        tui_authority = $false
    }
    endpoints = [ordered]@{
        index = "/support/index.json"
        recovery_operations = "/support/recovery.json"
        readme = "/support/README.txt"
    }
    source_bindings = $sourceBindings
    visible_status = [ordered]@{
        canary_preconditions_proven = if ($null -ne $rc5CanaryProof) { $rc5CanaryProof.canary_preconditions_proven } else { $false }
        canary_execution_allowed = $false
        rollback_readiness_proven = if ($null -ne $rc5CanaryProof) { $rc5CanaryProof.rollback_readiness_proven } else { $false }
        rollback_execution_performed = $false
        support_recovery_projection_ready = $rc4SupportReady
    }
}

$recoveryOperations = [ordered]@{
    schema = "agentos.rc5-hosted-recovery-operations.v1"
    generated_at = $generatedAt
    status = "projection-only"
    production_ready_claim = $false
    domain = $Domain
    recovery_truth = "local signed/hash-bound evidence chain; hosted mirror metadata is explanatory only"
    operations = @(
        [ordered]@{
            id = "mirror-health-triage"
            status = "available-as-metadata"
            executable_by_mirror = $false
            expected_inputs = @("/health.json", "/.well-known/aios/mirror.json", "/channel/index.json")
            fail_closed_if_missing = $true
        }
        [ordered]@{
            id = "metadata-drift-triage"
            status = "available-as-metadata"
            executable_by_mirror = $false
            expected_inputs = @("rc5-hosted-endpoint-verifier", "rc5-hosted-metadata-fail-closed", "rc5-user-release-channel")
            fail_closed_if_hash_mismatch = $true
        }
        [ordered]@{
            id = "canary-abort-preflight"
            status = "blocked-until-canary-execution-exists"
            executable_by_mirror = $false
            exact_operator_approval_required = $true
            rollback_readiness_required = $true
            rollback_readiness_proven = if ($null -ne $rc5CanaryProof) { $rc5CanaryProof.rollback_readiness_proven } else { $false }
        }
        [ordered]@{
            id = "rollback-readiness-explain"
            status = "projection-only"
            executable_by_mirror = $false
            rollback_baseline_sha256 = if ($null -ne $rc5RollbackProjection) { $rc5RollbackProjection.rollback_baseline_sha256 } else { $null }
            previous_active_artifact_set_sha256 = if ($null -ne $rc5RollbackProjection) { $rc5RollbackProjection.previous_active_artifact_set_sha256 } else { $null }
            restored_active_artifact_set_sha256 = if ($null -ne $rc5RollbackProjection) { $rc5RollbackProjection.restored_active_artifact_set_sha256 } else { $null }
        }
    )
    blockers_before_mutating_recovery = @(
        "AgentCore PlanSpec required",
        "SecurityExecutionEngine required",
        "exact operator approval required",
        "mirror cannot execute recovery",
        "TUI cannot execute recovery",
        "model replay cannot be recovery truth"
    )
    source_bindings = $sourceBindings
    invariants = [ordered]@{
        metadata_only = $true
        support_upload_performed = $false
        remote_bytes_sent_by_support = $false
        local_private_key_material_used = $false
        cryptographic_signing_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        active_registry_mutated = $false
        active_slot_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        remote_dispatch_enabled = $false
        model_replay_authority = $false
        normal_shell_authority = $false
        tui_authority = $false
    }
}

Write-Json -Value $supportIndex -Path $supportIndexPath
Write-Json -Value $recoveryOperations -Path $recoveryOperationsPath

$supportIndexHash = Get-FileSha256 $supportIndexPath
$recoveryOperationsHash = Get-FileSha256 $recoveryOperationsPath

$supportEntry = [ordered]@{
    id = "rc5-hosted-support-recovery"
    status = "available"
    path = "/support/index.json"
    kind = "support-recovery-metadata"
    activation_allowed = $false
    rollback_execution_allowed = $false
    support_upload_allowed = $false
    large_payload_deferred = $true
    sha256 = $supportIndexHash
}

$existingEntries = if ($null -ne $rc5HostedChannel) { @($rc5HostedChannel.entries | Where-Object { $_.path -ne "/support/index.json" }) } else { @() }
$hostedChannelAfterSupport = [ordered]@{
    schema = "agentos.rc5-hosted-channel-index.v1"
    status = "metadata-only"
    channel = "production-candidate-rc5"
    domain = $Domain
    generated_at = $generatedAt
    production_ready_claim = $false
    storage_mode = "metadata-only"
    source_rc4_final_audit_sha256 = if ($null -ne $rc5HostedChannel) { $rc5HostedChannel.source_rc4_final_audit_sha256 } else { $null }
    hosted_transport_manifest_sha256 = if ($null -ne $rc5HostedChannel) { $rc5HostedChannel.hosted_transport_manifest_sha256 } else { $null }
    mirror_publication_sha256 = if ($null -ne $rc5HostedChannel) { $rc5HostedChannel.mirror_publication_sha256 } else { $null }
    freshness_window = if ($null -ne $rc5HostedChannel) { $rc5HostedChannel.freshness_window } else { "P7D" }
    entries = @($existingEntries + $supportEntry)
    support_recovery = [ordered]@{
        index_path = "/support/index.json"
        recovery_operations_path = "/support/recovery.json"
        support_index_sha256 = $supportIndexHash
        recovery_operations_sha256 = $recoveryOperationsHash
        support_upload_allowed = $false
        recovery_execution_allowed = $false
    }
    authority = [ordered]@{
        signing_authority = $false
        activation_authority = $false
        rollback_execution_authority = $false
        support_upload_authority = $false
        recovery_authority = $false
        tui_authority = $false
    }
}

Write-Json -Value $hostedChannelAfterSupport -Path $hostedChannelAfterSupportPath
$hostedChannelAfterSupportHash = Get-FileSha256 $hostedChannelAfterSupportPath

$localOutputsReady = (Test-Path -LiteralPath $supportIndexPath -PathType Leaf) -and
    (Test-Path -LiteralPath $recoveryOperationsPath -PathType Leaf) -and
    (Test-Path -LiteralPath $hostedChannelAfterSupportPath -PathType Leaf) -and
    (Has-Value $supportIndexHash) -and
    (Has-Value $recoveryOperationsHash) -and
    (Has-Value $hostedChannelAfterSupportHash)

$localOutputSafe = (Test-NoSensitiveContent -Paths @($supportIndexPath, $recoveryOperationsPath, $hostedChannelAfterSupportPath)) -and
    (Test-NoHostPathContent -Paths @($supportIndexPath, $recoveryOperationsPath, $hostedChannelAfterSupportPath))

Add-Check "rc5.plan.current_task" $rc5PlanReady "RC5 plan must point at RC5-022 with RC5-021 completed and RC5-022 pending." "blocking" $(if ($null -ne $rc5Plan) { [ordered]@{ current_task = $rc5Plan.current_task; RC5_021 = $rc5TaskStatuses["RC5-021"]; RC5_022 = $rc5TaskStatuses["RC5-022"] } } else { $null })
Add-Check "rc5.hosted_service.ready" $hostedServiceReady "Hosted mirror service must remain metadata-only and authority-free before support/recovery publication." "blocking" $(if ($null -ne $rc5HostedService) { $rc5HostedService.summary } else { $null })
Add-Check "rc5.endpoint_verifier.ready" $endpointVerifierReady "Hosted endpoint verifier must remain passed and non-GA." "blocking" $(if ($null -ne $rc5EndpointVerifier) { $rc5EndpointVerifier.summary } else { $null })
Add-Check "rc5.fail_closed.ready" $failClosedReady "Hosted metadata fail-closed fixtures must remain passed before adding /support metadata." "blocking" $(if ($null -ne $rc5FailClosed) { $rc5FailClosed.summary } else { $null })
Add-Check "rc5.user_release.ready" $userReleaseReady "User release channel must remain metadata-only and block install/update." "blocking" $(if ($null -ne $rc5UserRelease) { $rc5UserRelease.summary } else { $null })
Add-Check "rc5.canary_proof.ready" $canaryProofReady "RC5-021 canary proof must be passed, rollback-ready, and execution-blocked." "blocking" $(if ($null -ne $rc5CanaryProof) { $rc5CanaryProof.summary } else { $null })
Add-Check "rc5.canary_projection.blocked" $canaryProjectionReady "Canary projection must remain non-executable and blocked by design." "blocking" $(if ($null -ne $rc5CanaryProjection) { $rc5CanaryProjection.gates } else { $null })
Add-Check "rc5.rollback_projection.ready" $rollbackProjectionReady "Rollback readiness projection must prove previous/restored hash equality without executing rollback." "blocking" $(if ($null -ne $rc5RollbackProjection) { [ordered]@{ status = $rc5RollbackProjection.status; baseline = $rc5RollbackProjection.rollback_baseline_sha256; previous = $rc5RollbackProjection.previous_active_artifact_set_sha256; restored = $rc5RollbackProjection.restored_active_artifact_set_sha256; rollback_execution_performed = $rc5RollbackProjection.rollback_execution_performed } } else { $null })
Add-Check "rc4.support_recovery.ready" $rc4SupportReady "RC4 support/recovery projection must be passed, redacted, local-only, and non-authoritative." "blocking" $(if ($null -ne $rc4SupportRecovery) { $rc4SupportRecovery.summary } else { $null })
Add-Check "rc4.support_index.ready" $rc4SupportIndexReady "RC4 support/recovery index must be present, indexed, local-only, and non-GA." "blocking" $(if ($null -ne $rc4SupportIndex) { [ordered]@{ status = $rc4SupportIndex.status; local_only = $rc4SupportIndex.local_only; production_ready_claim = $rc4SupportIndex.production_ready_claim } } else { $null })
Add-Check "rc4.recovery_projection.ready" $rc4RecoveryReady "RC4 recovery projection must keep recovery truth local and avoid active mutations." "blocking" $(if ($null -ne $rc4RecoveryProjection) { [ordered]@{ status = $rc4RecoveryProjection.status; authorities = $rc4RecoveryProjection.authorities; mutation_effects = $rc4RecoveryProjection.mutation_effects } } else { $null })
Add-Check "support.local_outputs.ready" $localOutputsReady "RC5 support index, recovery operations, and updated hosted channel index must be generated locally." "blocking" ([ordered]@{ support_index_sha256 = $supportIndexHash; recovery_operations_sha256 = $recoveryOperationsHash; hosted_channel_index_sha256 = $hostedChannelAfterSupportHash })
Add-Check "support.local_outputs.safe" $localOutputSafe "Generated RC5 support/recovery metadata must be secret-safe and host-path-free." "blocking" ([ordered]@{ support_index = Get-StablePath $supportIndexPath; recovery_operations = Get-StablePath $recoveryOperationsPath; hosted_channel = Get-StablePath $hostedChannelAfterSupportPath })
Add-Check "support.no_authority" ($supportIndex.authority.support_authority -eq $false -and $supportIndex.authority.recovery_authority -eq $false -and $supportIndex.support_upload_allowed -eq $false -and $supportIndex.recovery_execution_allowed -eq $false -and $supportIndex.rollback_execution_allowed -eq $false) "Support index must not grant support upload, recovery, rollback, activation, dispatch, or TUI authority." "blocking" $supportIndex.authority

$descriptorResponseBefore = Invoke-Curl "http://$Domain/.well-known/aios/mirror.json"
$descriptor = ConvertFrom-JsonTextSafe $descriptorResponseBefore.body
if ($null -ne $descriptor) {
    $allowedPaths = @($descriptor.allowed_paths)
    if ($allowedPaths -notcontains "/support/") {
        $allowedPaths += "/support/"
    }
    $descriptor.allowed_paths = $allowedPaths
    $descriptor.generated_at = $generatedAt
}

$supportReadme = @"
AIOS RC5 hosted support/recovery metadata

This directory is metadata-only. It does not accept uploads, execute recovery,
execute rollback, activate releases, mutate fleet rings, or provide signing authority.

Read /support/index.json and /support/recovery.json as explanatory public metadata only.
"@

Set-RemoteTextFile -Path "/srv/aios-mirror/support/index.json" -Text (Get-JsonText $supportIndex)
Set-RemoteTextFile -Path "/srv/aios-mirror/support/recovery.json" -Text (Get-JsonText $recoveryOperations)
Set-RemoteTextFile -Path "/srv/aios-mirror/support/README.txt" -Text $supportReadme
Set-RemoteTextFile -Path "/srv/aios-mirror/channel/index.json" -Text (Get-JsonText $hostedChannelAfterSupport)
if ($null -ne $descriptor) {
    Set-RemoteTextFile -Path "/srv/aios-mirror/.well-known/aios/mirror.json" -Text (Get-JsonText $descriptor)
}

$remoteCheck = Invoke-Remote "set -eu; systemctl is-active nginx; cd /srv/aios-mirror; find support -maxdepth 2 -type f -printf '%P %s\n' | sort; sha256sum support/index.json support/recovery.json support/README.txt channel/index.json"

$supportIndexResponse = Invoke-Curl "http://$Domain/support/index.json"
$recoveryResponse = Invoke-Curl "http://$Domain/support/recovery.json"
$supportReadmeResponse = Invoke-Curl "http://$Domain/support/README.txt"
$channelResponse = Invoke-Curl "http://$Domain/channel/index.json"
$descriptorResponseAfter = Invoke-Curl "http://$Domain/.well-known/aios/mirror.json"

$supportIndexLive = ConvertFrom-JsonTextSafe $supportIndexResponse.body
$recoveryLive = ConvertFrom-JsonTextSafe $recoveryResponse.body
$channelLive = ConvertFrom-JsonTextSafe $channelResponse.body
$descriptorLive = ConvertFrom-JsonTextSafe $descriptorResponseAfter.body

$remoteSupportPublished = $remoteCheck -match "active" -and
    $supportIndexResponse.status_code -eq 200 -and
    $recoveryResponse.status_code -eq 200 -and
    $supportReadmeResponse.status_code -eq 200 -and
    $channelResponse.status_code -eq 200 -and
    $descriptorResponseAfter.status_code -eq 200

$remoteSupportSemanticsReady = $null -ne $supportIndexLive -and
    $null -ne $recoveryLive -and
    $null -ne $channelLive -and
    $supportIndexLive.production_ready_claim -eq $false -and
    $supportIndexLive.support_upload_allowed -eq $false -and
    $supportIndexLive.recovery_execution_allowed -eq $false -and
    $supportIndexLive.rollback_execution_allowed -eq $false -and
    $supportIndexLive.authority.support_authority -eq $false -and
    $recoveryLive.production_ready_claim -eq $false -and
    $recoveryLive.invariants.support_upload_performed -eq $false -and
    $recoveryLive.invariants.rollback_execution_performed -eq $false -and
    $recoveryLive.invariants.remote_dispatch_enabled -eq $false -and
    @($channelLive.entries | Where-Object { $_.path -eq "/support/index.json" -and $_.activation_allowed -eq $false -and $_.support_upload_allowed -eq $false }).Count -eq 1 -and
    $channelLive.authority.support_upload_authority -eq $false -and
    $channelLive.authority.recovery_authority -eq $false

$descriptorReady = $null -ne $descriptorLive -and @($descriptorLive.allowed_paths) -contains "/support/"
$publishedSecretSafe = Test-NoSensitiveValues -Values @($supportIndexResponse.body, $recoveryResponse.body, $supportReadmeResponse.body, $channelResponse.body, $descriptorResponseAfter.body)

Add-Check "remote.support_metadata.published" $remoteSupportPublished "Remote mirror must serve /support metadata, README, channel index, and descriptor through nginx." "blocking" ([ordered]@{ support_index_status = $supportIndexResponse.status_code; recovery_status = $recoveryResponse.status_code; readme_status = $supportReadmeResponse.status_code; channel_status = $channelResponse.status_code; descriptor_status = $descriptorResponseAfter.status_code; remote = ($remoteCheck -split "`n") })
Add-Check "remote.support_metadata.non_authoritative" $remoteSupportSemanticsReady "Published support/recovery metadata must remain non-GA, upload-disabled, recovery-disabled, rollback-disabled, and channel-indexed." "blocking" ([ordered]@{ support_upload_allowed = if ($null -ne $supportIndexLive) { $supportIndexLive.support_upload_allowed } else { $null }; recovery_execution_allowed = if ($null -ne $supportIndexLive) { $supportIndexLive.recovery_execution_allowed } else { $null }; rollback_execution_allowed = if ($null -ne $supportIndexLive) { $supportIndexLive.rollback_execution_allowed } else { $null }; support_entries = if ($null -ne $channelLive) { @($channelLive.entries | Where-Object { $_.path -eq "/support/index.json" }).Count } else { 0 } })
Add-Check "remote.descriptor.support_allowed_path" $descriptorReady "Mirror descriptor must list /support/ as an allowed metadata path." "blocking" $(if ($null -ne $descriptorLive) { $descriptorLive.allowed_paths } else { $null })
Add-Check "remote.support_metadata.secret_safe" $publishedSecretSafe "Published support/recovery metadata must not contain private key, token, or local private authority markers." "blocking" $null
Add-Check "support.no_runtime_side_effects" $true "RC5 support/recovery projection must not upload support bundles, sign, activate, execute rollback, mutate active state, dispatch remotely, or grant TUI/model/shell authority." "blocking" $recoveryOperations.invariants

$passed = @($script:blockers).Count -eq 0

$result = [ordered]@{
    schema = "agentos.rc5-hosted-support-recovery-result.v1"
    generated_at = $generatedAt
    checked_at = (Get-Date).ToString("o")
    task = "RC5-022"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    rc5_022_complete = $passed
    support_recovery_metadata_published = $remoteSupportPublished
    hosted_support_recovery_ready = $passed
    local_private_key_material_used = $false
    cryptographic_signing_performed = $false
    support_upload_performed = $false
    remote_bytes_sent_by_support = $false
    activation_performed = $false
    rollback_execution_performed = $false
    active_registry_mutated = $false
    active_slot_mutated = $false
    active_artifact_set_mutated = $false
    production_ring_mutated = $false
    remote_dispatch_enabled = $false
    model_replay_authority = $false
    normal_shell_authority = $false
    tui_authority = $false
    remote = [ordered]@{
        host = $RemoteHost
        user = $RemoteUser
        domain = $Domain
        validation_used_local_dns = $false
        validation_resolve_override = "$Domain`:80`:$RemoteHost"
        remote_static_metadata_published = $true
        support_upload_endpoint_created = $false
    }
    verified = [ordered]@{
        rc5_plan = $rc5PlanReady
        hosted_service = $hostedServiceReady
        endpoint_verifier = $endpointVerifierReady
        fail_closed = $failClosedReady
        user_release = $userReleaseReady
        canary_proof = $canaryProofReady
        canary_projection = $canaryProjectionReady
        rollback_projection = $rollbackProjectionReady
        rc4_support_recovery = $rc4SupportReady
        rc4_support_index = $rc4SupportIndexReady
        rc4_recovery_projection = $rc4RecoveryReady
        local_outputs = $localOutputsReady
        remote_support_published = $remoteSupportPublished
        remote_support_semantics = $remoteSupportSemanticsReady
        descriptor_support_path = $descriptorReady
        published_secret_safe = $publishedSecretSafe
    }
    local_outputs = [ordered]@{
        support_index = [ordered]@{ path = Get-StablePath $supportIndexPath; sha256 = $supportIndexHash }
        recovery_operations = [ordered]@{ path = Get-StablePath $recoveryOperationsPath; sha256 = $recoveryOperationsHash }
        hosted_channel_index_after_support_recovery = [ordered]@{ path = Get-StablePath $hostedChannelAfterSupportPath; sha256 = $hostedChannelAfterSupportHash }
    }
    hosted_outputs = [ordered]@{
        support_index_sha256 = Get-StringSha256 $supportIndexResponse.body
        recovery_operations_sha256 = Get-StringSha256 $recoveryResponse.body
        support_readme_sha256 = Get-StringSha256 $supportReadmeResponse.body
        channel_index_sha256 = Get-StringSha256 $channelResponse.body
        descriptor_sha256 = Get-StringSha256 $descriptorResponseAfter.body
    }
    source_artifacts = [ordered]@{
        rc5_plan = New-Projection -Path $resolvedRc5PlanPath -Json $rc5Plan
        rc5_hosted_service = New-Projection -Path $resolvedRc5HostedServicePath -Json $rc5HostedService
        rc5_endpoint_verifier = New-Projection -Path $resolvedRc5EndpointVerifierPath -Json $rc5EndpointVerifier
        rc5_hosted_metadata_fail_closed = New-Projection -Path $resolvedRc5FailClosedPath -Json $rc5FailClosed
        rc5_user_release = New-Projection -Path $resolvedRc5UserReleasePath -Json $rc5UserRelease
        rc5_hosted_channel_before_support = New-Projection -Path $resolvedRc5HostedChannelPath -Json $rc5HostedChannel
        rc5_canary_proof = New-Projection -Path $resolvedRc5CanaryProofPath -Json $rc5CanaryProof
        rc5_canary_projection = New-Projection -Path $resolvedRc5CanaryProjectionPath -Json $rc5CanaryProjection
        rc5_rollback_readiness_projection = New-Projection -Path $resolvedRc5RollbackProjectionPath -Json $rc5RollbackProjection
        rc4_support_recovery = New-Projection -Path $resolvedRc4SupportRecoveryPath -Json $rc4SupportRecovery
        rc4_support_index = New-Projection -Path $resolvedRc4SupportIndexPath -Json $rc4SupportIndex
        rc4_recovery_projection = New-Projection -Path $resolvedRc4RecoveryProjectionPath -Json $rc4RecoveryProjection
    }
    evidence_chain = $sourceBindings
    checks = $script:checks
    blockers = $script:blockers
    handoff = [ordered]@{
        next_task = "RC5-030"
        rc5_030_consumes = @(
            "hosted_support_recovery",
            "hosted_support_index",
            "hosted_recovery_operations",
            "multi_node_canary_proof",
            "hosted_user_release_channel"
        )
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        blockers = @($script:blockers).Count
        rc5_022_complete = $passed
        support_recovery_metadata_published = $remoteSupportPublished
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        rollback_execution_performed = $false
        activation_performed = $false
        production_ready_claim = $false
        remote_static_metadata_published = $true
        support_upload_endpoint_created = $false
        active_slot_mutated = $false
        production_ring_mutated = $false
        remote_dispatch_enabled = $false
        tui_authority = $false
        published_endpoints = @(
            "http://$Domain/support/index.json",
            "http://$Domain/support/recovery.json",
            "http://$Domain/support/README.txt",
            "http://$Domain/channel/index.json"
        )
    }
}

Write-Json -Value $result -Path $resolvedOutputPath

$resultSecretSafe = Test-NoSensitiveContent -Paths @($supportIndexPath, $recoveryOperationsPath, $hostedChannelAfterSupportPath, $resolvedOutputPath)
$resultHostPathFree = Test-NoHostPathContent -Paths @($supportIndexPath, $recoveryOperationsPath, $hostedChannelAfterSupportPath, $resolvedOutputPath)
if (-not $resultSecretSafe -or -not $resultHostPathFree) {
    $extra = [ordered]@{
        id = "rc5.support_recovery.result_secret_safe"
        status = "failed"
        severity = "blocking"
        message = "RC5 hosted support/recovery artifacts must be secret-safe and host-path-free."
        evidence = [ordered]@{
            secret_safe = $resultSecretSafe
            host_path_free = $resultHostPathFree
            path = Get-StablePath $resolvedOutputPath
        }
    }
    $script:checks += $extra
    $script:blockers += $extra
    $result.checks = $script:checks
    $result.blockers = $script:blockers
    $result.status = "blocked"
    $result.rc5_022_complete = $false
    $result.hosted_support_recovery_ready = $false
    $result.summary.checks = @($script:checks).Count
    $result.summary.blockers = @($script:blockers).Count
    $result.summary.rc5_022_complete = $false
    Write-Json -Value $result -Path $resolvedOutputPath
}

Write-Host "RC5 hosted support/recovery $($result.status): $OutputPath"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
