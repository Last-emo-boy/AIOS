param(
    [string]$RemoteHost = "47.101.11.109",
    [string]$Domain = "aios.w33d.xyz",
    [string]$ArtifactDir = ".workflow/artifacts/rc6-rollback-execution-preconditions",
    [string]$OutputPath = "",
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
        $hash = $sha.ComputeHash($bytes)
        return ([BitConverter]::ToString($hash)).Replace("-", "").ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
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

function Invoke-Curl {
    param([Parameter(Mandatory = $true)][string]$Path)
    $url = "http://$Domain$Path"
    $args = @(
        "--noproxy", "*",
        "--max-time", "$CurlTimeoutSeconds",
        "--resolve", "$Domain`:80`:$RemoteHost",
        "-sS",
        "-w", "`n%{http_code}",
        $url
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
        path = $Path
        url = $url
        exit_code = $exitCode
        status_code = $statusCode
        body_sha256 = Get-StringSha256 $body
        json = ConvertFrom-JsonTextSafe $body
    }
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
        $script:blockers += $entry
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

function Test-NoSensitiveText {
    param([Parameter(Mandatory = $true)][string[]]$Values)
    $markers = @(
        ("BEGIN " + "PRIVATE KEY"),
        ("PRIVATE KEY" + "-----"),
        ("Authorization:" + " Bearer"),
        ("Bearer" + " "),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ".local-release-authority",
        ("signing" + "-key.pem")
    )
    foreach ($value in $Values) {
        foreach ($marker in $markers) {
            if ($value.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                return $false
            }
        }
    }
    return $true
}

function Test-NoSensitiveFiles {
    param([Parameter(Mandatory = $true)][string[]]$Paths)
    foreach ($path in $Paths) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            return $false
        }
        $text = Get-Content -Raw -LiteralPath $path
        if (-not (Test-NoSensitiveText -Values @($text))) {
            return $false
        }
    }
    return $true
}

function New-ArtifactRef {
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

function New-MatrixRow {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$State,
        [Parameter(Mandatory = $true)][string]$Requirement,
        [Parameter(Mandatory = $true)][string]$EvidencePath,
        $Evidence = $null
    )
    return [ordered]@{
        id = $Id
        state = $State
        requirement = $Requirement
        evidence_path = $EvidencePath
        evidence = $Evidence
    }
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:blockers = @()

$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
if (-not $OutputPath) {
    $OutputPath = Join-Path $ArtifactDir "result.json"
}
$resolvedOutputPath = Resolve-RepoPath $OutputPath
$matrixPath = Join-Path $resolvedArtifactDir "rollback-drill-precondition-matrix.json"
$blockersPath = Join-Path $resolvedArtifactDir "rollback-execution-blockers.json"

$paths = [ordered]@{
    rc6_canary_result = ".workflow/artifacts/rc6-canary-execution-packet/result.json"
    rc6_canary_packet = ".workflow/artifacts/rc6-canary-execution-packet/canary-execution-packet.json"
    rc6_rollback_preconditions = ".workflow/artifacts/rc6-canary-execution-packet/rollback-execution-preconditions.json"
    rc5_rollback_readiness = ".workflow/artifacts/rc5-multi-node-canary-proof/rollback-readiness-projection.json"
    rc4_rollback_drill = ".workflow/artifacts/rc4-staged-fleet-ring-rollout-smoke-rollback-drill/rollback-drill-projection.json"
    rc5_hosted_support_recovery = ".workflow/artifacts/rc5-hosted-support-recovery/result.json"
    rc5_recovery_operations = ".workflow/artifacts/rc5-hosted-support-recovery/recovery-operations.json"
    rc6_hosted_payload_metadata = ".workflow/artifacts/rc6-hosted-payload-metadata/result.json"
    rc6_bootstrap_preflight = ".workflow/artifacts/rc6-bootstrap-installer-preflight/result.json"
    rc6_bootstrap_preflight_report = ".workflow/artifacts/rc6-bootstrap-installer-preflight/preflight-report.json"
    rc6_installer_fail_closed = ".workflow/artifacts/rc6-installer-fail-closed/result.json"
    rc6_mirror_frontend_refresh = ".workflow/artifacts/rc6-mirror-frontend-refresh/result.json"
}

$resolved = [ordered]@{}
$json = [ordered]@{}
foreach ($key in $paths.Keys) {
    $resolved[$key] = Resolve-RepoPath $paths[$key]
    $json[$key] = Read-JsonFile $resolved[$key]
}

$live = [ordered]@{
    channel = Invoke-Curl "/channel/index.json"
    payload_index = Invoke-Curl "/payloads/index.json"
    install_bootstrap = Invoke-Curl "/install/bootstrap.json"
    support_index = Invoke-Curl "/support/index.json"
    support_recovery = Invoke-Curl "/support/recovery.json"
}

$payloadEntry = if ($null -ne $live.payload_index.json -and $null -ne $live.payload_index.json.entries) { @($live.payload_index.json.entries)[0] } else { $null }
$supportRecoveryOperation = if ($null -ne $json.rc5_recovery_operations -and $null -ne $json.rc5_recovery_operations.operations) {
    @($json.rc5_recovery_operations.operations | Where-Object { $_.id -eq "rollback-readiness-explain" } | Select-Object -First 1)[0]
} else {
    $null
}
$preflightBlockerIds = if ($null -ne $json.rc6_bootstrap_preflight_report -and $null -ne $json.rc6_bootstrap_preflight_report.blockers) {
    @($json.rc6_bootstrap_preflight_report.blockers | ForEach-Object { $_.id })
} else {
    @()
}

$generatedAt = (Get-Date).ToString("o")
$sourceBindings = [ordered]@{}
foreach ($key in $paths.Keys) {
    $sourceBindings["$($key)_sha256"] = Get-FileSha256 $resolved[$key]
}
$sourceBindings.live_channel_sha256 = $live.channel.body_sha256
$sourceBindings.live_payload_index_sha256 = $live.payload_index.body_sha256
$sourceBindings.live_install_bootstrap_sha256 = $live.install_bootstrap.body_sha256
$sourceBindings.live_support_index_sha256 = $live.support_index.body_sha256
$sourceBindings.live_support_recovery_sha256 = $live.support_recovery.body_sha256

$sourcesPresent = @($paths.Keys | Where-Object { -not (Test-Path -LiteralPath $resolved[$_] -PathType Leaf) }).Count -eq 0

$baselineConsistent = $null -ne $json.rc6_rollback_preconditions -and
    $null -ne $json.rc5_rollback_readiness -and
    $null -ne $json.rc4_rollback_drill -and
    $json.rc6_rollback_preconditions.rollback_baseline_sha256 -eq $json.rc5_rollback_readiness.rollback_baseline_sha256 -and
    $json.rc5_rollback_readiness.rollback_baseline_sha256 -eq $json.rc4_rollback_drill.rollback_baseline_sha256 -and
    $json.rc6_rollback_preconditions.previous_active_artifact_set_sha256 -eq $json.rc6_rollback_preconditions.restored_active_artifact_set_sha256 -and
    $json.rc5_rollback_readiness.previous_active_artifact_set_sha256 -eq $json.rc5_rollback_readiness.restored_active_artifact_set_sha256 -and
    $json.rc4_rollback_drill.previous_active_artifact_set_sha256 -eq $json.rc4_rollback_drill.restored_active_artifact_set_sha256

$rc6CanaryPacketBlocked = $null -ne $json.rc6_canary_result -and
    $null -ne $json.rc6_canary_packet -and
    $null -ne $json.rc6_rollback_preconditions -and
    $json.rc6_canary_result.status -eq "passed" -and
    $json.rc6_canary_result.canary_execution_allowed -eq $false -and
    $json.rc6_canary_result.canary_execution_performed -eq $false -and
    $json.rc6_canary_result.rollback_execution_allowed -eq $false -and
    $json.rc6_canary_result.rollback_execution_performed -eq $false -and
    $json.rc6_canary_packet.projection_only -eq $true -and
    $json.rc6_canary_packet.executable -eq $false -and
    $json.rc6_canary_packet.exact_operator_approval_required -eq $true -and
    $json.rc6_canary_packet.exact_operator_approval_granted -eq $false -and
    $json.rc6_rollback_preconditions.rollback_readiness_ready -eq $true -and
    $json.rc6_rollback_preconditions.rollback_execution_allowed -eq $false -and
    $json.rc6_rollback_preconditions.rollback_execution_performed -eq $false

$rc5Rc4RollbackReady = $null -ne $json.rc5_rollback_readiness -and
    $null -ne $json.rc4_rollback_drill -and
    $json.rc5_rollback_readiness.rollback_readiness_ready -eq $true -and
    $json.rc5_rollback_readiness.rollback_execution_performed -eq $false -and
    $json.rc4_rollback_drill.rollback_verified -eq $true -and
    $json.rc4_rollback_drill.rollback_execution_performed -eq $false -and
    $baselineConsistent

$supportRecoveryReady = $null -ne $json.rc5_hosted_support_recovery -and
    $null -ne $json.rc5_recovery_operations -and
    $json.rc5_hosted_support_recovery.status -eq "passed" -and
    $json.rc5_hosted_support_recovery.summary.support_upload_allowed -eq $false -and
    $json.rc5_hosted_support_recovery.summary.rollback_execution_performed -eq $false -and
    $json.rc5_hosted_support_recovery.summary.activation_performed -eq $false -and
    $json.rc5_hosted_support_recovery.summary.remote_dispatch_enabled -eq $false -and
    $json.rc5_recovery_operations.status -eq "projection-only" -and
    $json.rc5_recovery_operations.invariants.support_upload_performed -eq $false -and
    $json.rc5_recovery_operations.invariants.rollback_execution_performed -eq $false -and
    $json.rc5_recovery_operations.invariants.tui_authority -eq $false -and
    $null -ne $supportRecoveryOperation -and
    $supportRecoveryOperation.rollback_baseline_sha256 -eq $json.rc6_rollback_preconditions.rollback_baseline_sha256

$rc6PayloadBlocked = $null -ne $json.rc6_hosted_payload_metadata -and
    $json.rc6_hosted_payload_metadata.status -eq "passed" -and
    $json.rc6_hosted_payload_metadata.payload_surface.release_id -eq "production-distro-rc6-current-artifacts" -and
    $json.rc6_hosted_payload_metadata.payload_surface.status -eq "verification-blocked" -and
    $json.rc6_hosted_payload_metadata.payload_surface.signature_available -eq $false -and
    $json.rc6_hosted_payload_metadata.payload_surface.install_allowed -eq $false -and
    $json.rc6_hosted_payload_metadata.invariants.rollback_execution_performed -eq $false

$preflightExpectedBlocked = $null -ne $json.rc6_bootstrap_preflight -and
    $null -ne $json.rc6_bootstrap_preflight_report -and
    $json.rc6_bootstrap_preflight.status -eq "passed" -and
    $json.rc6_bootstrap_preflight.preflight.state -eq "verification-blocked" -and
    $json.rc6_bootstrap_preflight_report.state -eq "verification-blocked" -and
    @("verify-signature-or-signed-metadata-reference", "verify-revocation-snapshot", "verify-installer-compatibility-contract", "verify-rollback-baseline-hash" | Where-Object { $preflightBlockerIds -notcontains $_ }).Count -eq 0 -and
    $json.rc6_bootstrap_preflight.invariants.rollback_execution_performed -eq $false -and
    $json.rc6_bootstrap_preflight.invariants.remote_dispatch_enabled -eq $false

$installerFailClosedReady = $null -ne $json.rc6_installer_fail_closed -and
    $json.rc6_installer_fail_closed.status -eq "passed" -and
    $json.rc6_installer_fail_closed.summary.failed_cases -eq 0 -and
    $json.rc6_installer_fail_closed.invariants.install_performed -eq $false -and
    $json.rc6_installer_fail_closed.invariants.activation_performed -eq $false -and
    $json.rc6_installer_fail_closed.invariants.rollback_execution_performed -eq $false -and
    $json.rc6_installer_fail_closed.invariants.production_ring_mutated -eq $false

$frontendReady = $null -ne $json.rc6_mirror_frontend_refresh -and
    $json.rc6_mirror_frontend_refresh.status -eq "passed" -and
    $json.rc6_mirror_frontend_refresh.summary.blockers -eq 0 -and
    $json.rc6_mirror_frontend_refresh.invariants.metadata_preserved -eq $true -and
    $json.rc6_mirror_frontend_refresh.invariants.rollback_execution_performed -eq $false

$liveMetadataReady = $live.channel.status_code -eq 200 -and
    $live.payload_index.status_code -eq 200 -and
    $live.install_bootstrap.status_code -eq 200 -and
    $live.support_index.status_code -eq 200 -and
    $live.support_recovery.status_code -eq 200 -and
    $null -ne $live.channel.json -and
    $null -ne $live.payload_index.json -and
    $null -ne $live.install_bootstrap.json -and
    $null -ne $live.support_index.json -and
    $null -ne $live.support_recovery.json -and
    $live.channel.json.production_ready_claim -eq $false -and
    $live.channel.json.payload_channel.default_release_id -eq "production-distro-rc6-current-artifacts" -and
    $live.channel.json.payload_channel.signature_available -eq $false -and
    $live.channel.json.payload_channel.install_allowed -eq $false -and
    $payloadEntry.release_id -eq "production-distro-rc6-current-artifacts" -and
    $payloadEntry.status -eq "verification-blocked" -and
    $payloadEntry.install_allowed -eq $false -and
    $live.install_bootstrap.json.current_state -eq "verification-blocked" -and
    $live.install_bootstrap.json.install_allowed -eq $false -and
    ($null -eq $live.install_bootstrap.json.rollback_execution_allowed -or $live.install_bootstrap.json.rollback_execution_allowed -eq $false) -and
    $live.support_index.json.support_upload_allowed -eq $false -and
    $live.support_recovery.json.production_ready_claim -eq $false

$matrixRows = @(
    New-MatrixRow "rollback.baseline.consistent" "satisfied" "RC4, RC5, and RC6 rollback projections must agree on rollback baseline and previous/restored artifact hashes." $paths.rc6_rollback_preconditions ([ordered]@{
        rollback_baseline_sha256 = if ($null -ne $json.rc6_rollback_preconditions) { $json.rc6_rollback_preconditions.rollback_baseline_sha256 } else { $null }
        previous_active_artifact_set_sha256 = if ($null -ne $json.rc6_rollback_preconditions) { $json.rc6_rollback_preconditions.previous_active_artifact_set_sha256 } else { $null }
        restored_active_artifact_set_sha256 = if ($null -ne $json.rc6_rollback_preconditions) { $json.rc6_rollback_preconditions.restored_active_artifact_set_sha256 } else { $null }
    })
    New-MatrixRow "rollback.execution.authority" "blocked-by-design" "Rollback execution must wait for an exact-approved AgentCore PlanSpec executed by SecurityExecutionEngine." $paths.rc6_canary_packet ([ordered]@{
        canary_execution_allowed = if ($null -ne $json.rc6_canary_packet) { $json.rc6_canary_packet.canary_execution_allowed } else { $null }
        rollback_execution_allowed = if ($null -ne $json.rc6_canary_packet) { $json.rc6_canary_packet.rollback_execution_allowed } else { $null }
        exact_operator_approval_granted = if ($null -ne $json.rc6_canary_packet) { $json.rc6_canary_packet.exact_operator_approval_granted } else { $null }
    })
    New-MatrixRow "support.recovery.readiness" "satisfied" "Support/recovery metadata must be present, redacted, and non-authoritative before rollback execution can ever be considered." $paths.rc5_recovery_operations ([ordered]@{
        operation_id = if ($null -ne $supportRecoveryOperation) { $supportRecoveryOperation.id } else { $null }
        executable_by_mirror = if ($null -ne $supportRecoveryOperation) { $supportRecoveryOperation.executable_by_mirror } else { $null }
        rollback_baseline_sha256 = if ($null -ne $supportRecoveryOperation) { $supportRecoveryOperation.rollback_baseline_sha256 } else { $null }
    })
    New-MatrixRow "payload.signature.revocation" "blocked-by-design" "Payload signature and revocation snapshot remain mandatory before install, activation, canary, or rollback drill execution." $paths.rc6_bootstrap_preflight_report ([ordered]@{
        signature_blocked = $preflightBlockerIds -contains "verify-signature-or-signed-metadata-reference"
        revocation_blocked = $preflightBlockerIds -contains "verify-revocation-snapshot"
    })
    New-MatrixRow "installer.compatibility.rollback-baseline" "blocked-by-design" "Installer compatibility and rollback baseline must be published to install metadata before execution." $paths.rc6_bootstrap_preflight_report ([ordered]@{
        compatibility_blocked = $preflightBlockerIds -contains "verify-installer-compatibility-contract"
        rollback_baseline_blocked = $preflightBlockerIds -contains "verify-rollback-baseline-hash"
    })
    New-MatrixRow "installer.fail_closed" "satisfied" "Installer fail-closed fixtures must block unsigned, stale, revoked, oversized, hash-mismatched, and authority-broadening metadata." $paths.rc6_installer_fail_closed ([ordered]@{
        cases = if ($null -ne $json.rc6_installer_fail_closed) { $json.rc6_installer_fail_closed.summary.cases } else { $null }
        failed_cases = if ($null -ne $json.rc6_installer_fail_closed) { $json.rc6_installer_fail_closed.summary.failed_cases } else { $null }
    })
    New-MatrixRow "live.mirror.current_metadata" "satisfied" "Live mirror metadata must remain reachable, current-artifacts, non-GA, unsigned, install-blocked, and rollback-blocked." "/payloads/index.json" ([ordered]@{
        release_id = if ($null -ne $payloadEntry) { $payloadEntry.release_id } else { $null }
        payload_status = if ($null -ne $payloadEntry) { $payloadEntry.status } else { $null }
        install_state = if ($null -ne $live.install_bootstrap.json) { $live.install_bootstrap.json.current_state } else { $null }
        rollback_execution_allowed = if ($null -ne $live.install_bootstrap.json) { $live.install_bootstrap.json.rollback_execution_allowed } else { $null }
    })
    New-MatrixRow "runtime.side_effects" "satisfied" "This RC6-031 projection must not sign, install, activate, rollback, mutate slots/rings, upload support, dispatch remotely, or grant TUI/model/shell authority." $ArtifactDir ([ordered]@{
        projection_only = $true
        rollback_execution_performed = $false
        active_slot_mutated = $false
        production_ring_mutated = $false
    })
)

$remainingBlockersBeforeExecution = @(
    "payload-signature-not-published",
    "revocation-snapshot-not-published",
    "installer-compatibility-contract-pending",
    "rollback-baseline-not-published-to-install-metadata",
    "SecurityExecutionEngine-rollback-PlanSpec-not-approved",
    "canary-activation-evidence-not-present",
    "two-or-more-enrolled-canary-target-nodes",
    "remote-fleet-execution-not-enabled",
    "exact-operator-approval-not-granted",
    "tls-required-before-ga-claim"
)

$matrix = [ordered]@{
    schema = "agentos.rc6-rollback-drill-precondition-matrix.v1"
    generated_at = $generatedAt
    status = "preconditions-projected-execution-blocked"
    production_ready_claim = $false
    projection_only = $true
    release_id = "production-distro-rc6-current-artifacts"
    rollback_readiness_ready = $rc5Rc4RollbackReady
    rollback_execution_allowed = $false
    rollback_execution_performed = $false
    rows = $matrixRows
    source_bindings = $sourceBindings
    live_endpoint_bindings = [ordered]@{
        channel = [ordered]@{ path = "/channel/index.json"; sha256 = $live.channel.body_sha256 }
        payload_index = [ordered]@{ path = "/payloads/index.json"; sha256 = $live.payload_index.body_sha256 }
        install_bootstrap = [ordered]@{ path = "/install/bootstrap.json"; sha256 = $live.install_bootstrap.body_sha256 }
        support_index = [ordered]@{ path = "/support/index.json"; sha256 = $live.support_index.body_sha256 }
        support_recovery = [ordered]@{ path = "/support/recovery.json"; sha256 = $live.support_recovery.body_sha256 }
    }
    invariants = [ordered]@{
        local_private_key_material_used = $false
        cryptographic_signing_performed = $false
        remote_mutation_performed = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        persistent_state_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        remote_dispatch_enabled = $false
        model_replay_authority = $false
        normal_shell_authority = $false
        tui_authority = $false
    }
}

$blockerArtifact = [ordered]@{
    schema = "agentos.rc6-rollback-execution-blockers.v1"
    generated_at = $generatedAt
    status = "execution-blocked-by-required-gates"
    production_ready_claim = $false
    projection_only = $true
    rollback_execution_allowed = $false
    rollback_execution_performed = $false
    blockers_before_execution = $remainingBlockersBeforeExecution
    expected_blocked_preflight_steps = $preflightBlockerIds
    explanation = "RC6-031 proves the rollback drill precondition chain, not rollback execution. Execution remains blocked until signed payload, revocation, installer compatibility, rollback baseline, exact approval, multi-node canary, remote fleet execution, and TLS gates are satisfied."
    invariants = $matrix.invariants
}

Write-Json -Value $matrix -Path $matrixPath
Write-Json -Value $blockerArtifact -Path $blockersPath

$matrixHash = Get-FileSha256 $matrixPath
$blockersHash = Get-FileSha256 $blockersPath

Add-Check "source.artifacts.present" $sourcesPresent "RC6 rollback execution preconditions must bind all required RC4/RC5/RC6 source artifacts." $sourceBindings
Add-Check "rollback.baseline.consistency" $baselineConsistent "Rollback baseline and previous/restored artifact hashes must be consistent across RC4, RC5, and RC6 projections." ([ordered]@{
    rc6_baseline = if ($null -ne $json.rc6_rollback_preconditions) { $json.rc6_rollback_preconditions.rollback_baseline_sha256 } else { $null }
    rc5_baseline = if ($null -ne $json.rc5_rollback_readiness) { $json.rc5_rollback_readiness.rollback_baseline_sha256 } else { $null }
    rc4_baseline = if ($null -ne $json.rc4_rollback_drill) { $json.rc4_rollback_drill.rollback_baseline_sha256 } else { $null }
})
Add-Check "canary.packet.rollback_blocked" $rc6CanaryPacketBlocked "RC6 canary packet and rollback preconditions must remain projection-only, exact-approval gated, and execution-blocked." ([ordered]@{
    canary_result_status = if ($null -ne $json.rc6_canary_result) { $json.rc6_canary_result.status } else { $null }
    exact_operator_approval_granted = if ($null -ne $json.rc6_canary_packet) { $json.rc6_canary_packet.exact_operator_approval_granted } else { $null }
    rollback_execution_allowed = if ($null -ne $json.rc6_rollback_preconditions) { $json.rc6_rollback_preconditions.rollback_execution_allowed } else { $null }
})
Add-Check "rc4.rc5.rollback.readiness" $rc5Rc4RollbackReady "RC4 rollback drill projection and RC5 rollback readiness must prove rollback baseline readiness without executing rollback." ([ordered]@{
    rc5_status = if ($null -ne $json.rc5_rollback_readiness) { $json.rc5_rollback_readiness.status } else { $null }
    rc4_status = if ($null -ne $json.rc4_rollback_drill) { $json.rc4_rollback_drill.status } else { $null }
})
Add-Check "support.recovery.ready" $supportRecoveryReady "Hosted support/recovery metadata must be present, rollback-explanatory, upload-disabled, and non-authoritative." ([ordered]@{
    support_status = if ($null -ne $json.rc5_hosted_support_recovery) { $json.rc5_hosted_support_recovery.status } else { $null }
    operation_id = if ($null -ne $supportRecoveryOperation) { $supportRecoveryOperation.id } else { $null }
    executable_by_mirror = if ($null -ne $supportRecoveryOperation) { $supportRecoveryOperation.executable_by_mirror } else { $null }
})
Add-Check "payload.metadata.execution_blocked" $rc6PayloadBlocked "RC6 payload metadata must remain current-artifacts, verification-blocked, unsigned, install-blocked, and rollback-not-executed." ([ordered]@{
    release_id = if ($null -ne $json.rc6_hosted_payload_metadata) { $json.rc6_hosted_payload_metadata.payload_surface.release_id } else { $null }
    status = if ($null -ne $json.rc6_hosted_payload_metadata) { $json.rc6_hosted_payload_metadata.payload_surface.status } else { $null }
    signature_available = if ($null -ne $json.rc6_hosted_payload_metadata) { $json.rc6_hosted_payload_metadata.payload_surface.signature_available } else { $null }
})
Add-Check "preflight.expected_blockers" $preflightExpectedBlocked "Bootstrap preflight must remain verification-blocked specifically on signature, revocation, installer compatibility, and rollback baseline gates." ([ordered]@{
    state = if ($null -ne $json.rc6_bootstrap_preflight_report) { $json.rc6_bootstrap_preflight_report.state } else { $null }
    blockers = $preflightBlockerIds
})
Add-Check "installer.fail_closed.ready" $installerFailClosedReady "Installer fail-closed fixtures must pass and keep install, activation, rollback, and production ring mutations false." $(if ($null -ne $json.rc6_installer_fail_closed) { $json.rc6_installer_fail_closed.summary } else { $null })
Add-Check "frontend.metadata_preserved" $frontendReady "RC6 mirror frontend refresh must preserve metadata and avoid rollback execution authority." $(if ($null -ne $json.rc6_mirror_frontend_refresh) { $json.rc6_mirror_frontend_refresh.summary } else { $null })
Add-Check "live.metadata.rollback_blocked" $liveMetadataReady "Live mirror endpoints must be reachable through resolve-pinned HTTP and remain non-GA, unsigned, install-blocked, support-upload-disabled, and rollback-blocked." ([ordered]@{
    channel = $live.channel.status_code
    payload_index = $live.payload_index.status_code
    install_bootstrap = $live.install_bootstrap.status_code
    support_index = $live.support_index.status_code
    support_recovery = $live.support_recovery.status_code
    release_id = if ($null -ne $payloadEntry) { $payloadEntry.release_id } else { $null }
    install_state = if ($null -ne $live.install_bootstrap.json) { $live.install_bootstrap.json.current_state } else { $null }
})
Add-Check "outputs.generated" ((Test-Path -LiteralPath $matrixPath -PathType Leaf) -and (Test-Path -LiteralPath $blockersPath -PathType Leaf)) "Rollback precondition matrix and execution blocker artifacts must be generated." ([ordered]@{
    matrix = Get-StablePath $matrixPath
    blockers = Get-StablePath $blockersPath
})
Add-Check "projection.no_side_effects" $true "Projection must not sign, install, activate, execute rollback, mutate boot/slot/state/rings, upload support, dispatch remotely, or grant TUI/model/shell authority." $matrix.invariants

$passed = @($script:blockers).Count -eq 0

$result = [ordered]@{
    schema = "agentos.rc6-rollback-execution-preconditions-result.v1"
    generated_at = $generatedAt
    checked_at = (Get-Date).ToString("o")
    task = "RC6-031"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    rollback_precondition_matrix_projected = $passed
    rollback_readiness_ready = $rc5Rc4RollbackReady
    rollback_execution_allowed = $false
    rollback_execution_performed = $false
    canary_execution_allowed = $false
    canary_execution_performed = $false
    artifacts = [ordered]@{
        rollback_drill_precondition_matrix = [ordered]@{
            path = Get-StablePath $matrixPath
            sha256 = $matrixHash
            schema = $matrix.schema
            status = $matrix.status
        }
        rollback_execution_blockers = [ordered]@{
            path = Get-StablePath $blockersPath
            sha256 = $blockersHash
            schema = $blockerArtifact.schema
            status = $blockerArtifact.status
        }
    }
    source_artifacts = [ordered]@{}
    source_bindings = $sourceBindings
    live_endpoint_bindings = $matrix.live_endpoint_bindings
    payload_surface = [ordered]@{
        release_id = if ($null -ne $payloadEntry) { $payloadEntry.release_id } else { $null }
        status = if ($null -ne $payloadEntry) { $payloadEntry.status } else { $null }
        signature_available = if ($null -ne $payloadEntry) { $payloadEntry.signature_available } else { $null }
        install_allowed = if ($null -ne $live.install_bootstrap.json) { $live.install_bootstrap.json.install_allowed } else { $null }
        install_state = if ($null -ne $live.install_bootstrap.json) { $live.install_bootstrap.json.current_state } else { $null }
        rollback_execution_allowed = if ($null -ne $live.install_bootstrap.json) { $live.install_bootstrap.json.rollback_execution_allowed } else { $null }
    }
    rollback_surface = [ordered]@{
        rollback_baseline_sha256 = if ($null -ne $json.rc6_rollback_preconditions) { $json.rc6_rollback_preconditions.rollback_baseline_sha256 } else { $null }
        previous_active_artifact_set_sha256 = if ($null -ne $json.rc6_rollback_preconditions) { $json.rc6_rollback_preconditions.previous_active_artifact_set_sha256 } else { $null }
        restored_active_artifact_set_sha256 = if ($null -ne $json.rc6_rollback_preconditions) { $json.rc6_rollback_preconditions.restored_active_artifact_set_sha256 } else { $null }
        baseline_consistent = $baselineConsistent
        support_recovery_ready = $supportRecoveryReady
    }
    remaining_blockers_before_execution = $remainingBlockersBeforeExecution
    checks = $script:checks
    blockers = $script:blockers
    invariants = $matrix.invariants
    summary = [ordered]@{
        checks = @($script:checks).Count
        blockers = @($script:blockers).Count
        rc6_031_complete = $passed
        rollback_precondition_matrix_projected = $passed
        rollback_readiness_ready = $rc5Rc4RollbackReady
        rollback_execution_allowed = $false
        rollback_execution_performed = $false
        canary_execution_allowed = $false
        canary_execution_performed = $false
        release_id = if ($null -ne $payloadEntry) { $payloadEntry.release_id } else { $null }
        payload_status = if ($null -ne $payloadEntry) { $payloadEntry.status } else { $null }
        exact_operator_approval_required = $true
        exact_operator_approval_granted = $false
        production_ready_claim = $false
        next_task = "RC6-040"
    }
}

foreach ($key in $paths.Keys) {
    $result.source_artifacts[$key] = New-ArtifactRef -Path $resolved[$key] -Json $json[$key]
}

Write-Json -Value $result -Path $resolvedOutputPath

$secretSafe = Test-NoSensitiveFiles -Paths @($matrixPath, $blockersPath, $resolvedOutputPath)
if (-not $secretSafe) {
    $extra = [ordered]@{
        id = "outputs.secret_safe"
        status = "failed"
        severity = "blocking"
        message = "Generated rollback precondition artifacts must not contain private key or token markers."
        evidence = $null
    }
    $script:checks += $extra
    $script:blockers += $extra
    $result.status = "blocked"
    $result.rollback_precondition_matrix_projected = $false
    $result.checks = $script:checks
    $result.blockers = $script:blockers
    $result.summary.checks = @($script:checks).Count
    $result.summary.blockers = @($script:blockers).Count
    $result.summary.rc6_031_complete = $false
    $result.summary.rollback_precondition_matrix_projected = $false
    Write-Json -Value $result -Path $resolvedOutputPath
}

Write-Host "RC6 rollback execution preconditions $($result.status): $(Get-StablePath $resolvedOutputPath)"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
