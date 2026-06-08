param(
    [string]$RemoteHost = "47.101.11.109",
    [string]$Domain = "aios.w33d.xyz",
    [string]$ArtifactDir = ".workflow/artifacts/rc6-canary-execution-packet",
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
    $hash = [Security.Cryptography.SHA256]::HashData($bytes)
    return ([BitConverter]::ToString($hash)).Replace("-", "").ToLowerInvariant()
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
        body = $body
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
            if ($value.Contains($marker, [StringComparison]::OrdinalIgnoreCase)) {
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

function Get-Ring {
    param($FleetAuthority, [string]$Name)
    if ($null -eq $FleetAuthority -or $null -eq $FleetAuthority.rings) {
        return $null
    }
    return @($FleetAuthority.rings | Where-Object { $_.name -eq $Name } | Select-Object -First 1)[0]
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
$packetPath = Join-Path $resolvedArtifactDir "canary-execution-packet.json"
$rollbackPreconditionsPath = Join-Path $resolvedArtifactDir "rollback-execution-preconditions.json"

$paths = [ordered]@{
    rc5_canary_result = ".workflow/artifacts/rc5-multi-node-canary-proof/result.json"
    rc5_canary_projection = ".workflow/artifacts/rc5-multi-node-canary-proof/multi-node-canary-plan-projection.json"
    rc5_rollback_readiness = ".workflow/artifacts/rc5-multi-node-canary-proof/rollback-readiness-projection.json"
    rc6_hosted_payload_metadata = ".workflow/artifacts/rc6-hosted-payload-metadata/result.json"
    rc6_bootstrap_preflight = ".workflow/artifacts/rc6-bootstrap-installer-preflight/result.json"
    rc6_installer_fail_closed = ".workflow/artifacts/rc6-installer-fail-closed/result.json"
    rc6_mirror_frontend_refresh = ".workflow/artifacts/rc6-mirror-frontend-refresh/result.json"
    fleet_rollout_authority = ".workflow/artifacts/release/fleet-rollout-authority.json"
}

$resolved = [ordered]@{}
$json = [ordered]@{}
foreach ($key in $paths.Keys) {
    $resolved[$key] = Resolve-RepoPath $paths[$key]
    $json[$key] = Read-JsonFile $resolved[$key]
}

$live = [ordered]@{
    root = Invoke-Curl "/"
    channel = Invoke-Curl "/channel/index.json"
    payload_index = Invoke-Curl "/payloads/index.json"
    install_bootstrap = Invoke-Curl "/install/bootstrap.json"
    payload_manifest = Invoke-Curl "/payloads/aios/production-distro-rc6-current-artifacts/manifest.json"
    payload_checksums = Invoke-Curl "/payloads/aios/production-distro-rc6-current-artifacts/checksums.json"
    payload_signatures = Invoke-Curl "/payloads/aios/production-distro-rc6-current-artifacts/signatures.json"
}

$canaryRing = Get-Ring $json.fleet_rollout_authority "canary"
$minimumCanaryNodes = 2
$observedCanaryNodes = if ($null -ne $canaryRing -and $null -ne $canaryRing.node_count) { [int]$canaryRing.node_count } else { 0 }
$payloadEntry = if ($null -ne $live.payload_index.json -and $null -ne $live.payload_index.json.entries) { @($live.payload_index.json.entries)[0] } else { $null }

$generatedAt = (Get-Date).ToString("o")
$sourceBindings = [ordered]@{
    rc5_canary_result_sha256 = Get-FileSha256 $resolved.rc5_canary_result
    rc5_canary_projection_sha256 = Get-FileSha256 $resolved.rc5_canary_projection
    rc5_rollback_readiness_sha256 = Get-FileSha256 $resolved.rc5_rollback_readiness
    rc6_hosted_payload_metadata_sha256 = Get-FileSha256 $resolved.rc6_hosted_payload_metadata
    rc6_bootstrap_preflight_sha256 = Get-FileSha256 $resolved.rc6_bootstrap_preflight
    rc6_installer_fail_closed_sha256 = Get-FileSha256 $resolved.rc6_installer_fail_closed
    rc6_mirror_frontend_refresh_sha256 = Get-FileSha256 $resolved.rc6_mirror_frontend_refresh
    fleet_rollout_authority_sha256 = Get-FileSha256 $resolved.fleet_rollout_authority
    live_channel_sha256 = $live.channel.body_sha256
    live_payload_index_sha256 = $live.payload_index.body_sha256
    live_install_bootstrap_sha256 = $live.install_bootstrap.body_sha256
    live_payload_manifest_sha256 = $live.payload_manifest.body_sha256
    live_payload_checksums_sha256 = $live.payload_checksums.body_sha256
    live_payload_signatures_sha256 = $live.payload_signatures.body_sha256
}

$sourcesPresent = @($paths.Keys | Where-Object { -not (Test-Path -LiteralPath $resolved[$_] -PathType Leaf) }).Count -eq 0
$rc5CanaryReady = $null -ne $json.rc5_canary_result -and
    $json.rc5_canary_result.status -eq "passed" -and
    $json.rc5_canary_result.canary_preconditions_proven -eq $true -and
    $json.rc5_canary_result.controlled_multi_node_canary_execution_allowed -eq $false -and
    $json.rc5_canary_result.controlled_multi_node_canary_execution_performed -eq $false -and
    $json.rc5_canary_result.rollback_readiness_proven -eq $true -and
    $json.rc5_canary_result.rollback_execution_performed -eq $false -and
    $json.rc5_canary_result.exact_operator_approval_required -eq $true -and
    $json.rc5_canary_result.exact_operator_approval_granted -eq $false -and
    $json.rc5_canary_result.summary.blockers -eq 0

$rc5PacketBaseReady = $null -ne $json.rc5_canary_projection -and
    $json.rc5_canary_projection.projection_only -eq $true -and
    $json.rc5_canary_projection.executable -eq $false -and
    $json.rc5_canary_projection.canary_execution_allowed -eq $false -and
    $json.rc5_canary_projection.canary_execution_performed -eq $false -and
    $json.rc5_canary_projection.gates.rollback_readiness_ready -eq $true -and
    $json.rc5_canary_projection.gates.exact_operator_approval_required -eq $true -and
    $json.rc5_canary_projection.gates.exact_operator_approval_granted -eq $false -and
    $json.rc5_canary_projection.gates.multi_node_target_set_enrolled -eq $false

$rollbackReady = $null -ne $json.rc5_rollback_readiness -and
    $json.rc5_rollback_readiness.rollback_readiness_ready -eq $true -and
    $json.rc5_rollback_readiness.rollback_execution_performed -eq $false -and
    $json.rc5_rollback_readiness.previous_active_artifact_set_sha256 -eq $json.rc5_rollback_readiness.restored_active_artifact_set_sha256

$rc6PayloadReady = $null -ne $json.rc6_hosted_payload_metadata -and
    $json.rc6_hosted_payload_metadata.status -eq "passed" -and
    $json.rc6_hosted_payload_metadata.payload_surface.release_id -eq "production-distro-rc6-current-artifacts" -and
    $json.rc6_hosted_payload_metadata.payload_surface.status -eq "verification-blocked" -and
    $json.rc6_hosted_payload_metadata.payload_surface.signature_available -eq $false -and
    $json.rc6_hosted_payload_metadata.payload_surface.install_allowed -eq $false -and
    $json.rc6_hosted_payload_metadata.invariants.hosted_metadata_only -eq $true -and
    $json.rc6_hosted_payload_metadata.invariants.cryptographic_signing_performed -eq $false

$rc6PreflightReady = $null -ne $json.rc6_bootstrap_preflight -and
    $json.rc6_bootstrap_preflight.status -eq "passed" -and
    $json.rc6_bootstrap_preflight.preflight.release_id -eq "production-distro-rc6-current-artifacts" -and
    $json.rc6_bootstrap_preflight.preflight.state -eq "verification-blocked" -and
    $json.rc6_bootstrap_preflight.summary.preflight_blockers -eq 4 -and
    $json.rc6_bootstrap_preflight.invariants.install_performed -eq $false -and
    $json.rc6_bootstrap_preflight.invariants.activation_performed -eq $false -and
    $json.rc6_bootstrap_preflight.invariants.rollback_execution_performed -eq $false

$rc6FailClosedReady = $null -ne $json.rc6_installer_fail_closed -and
    $json.rc6_installer_fail_closed.status -eq "passed" -and
    $json.rc6_installer_fail_closed.summary.cases -eq 12 -and
    $json.rc6_installer_fail_closed.summary.failed_cases -eq 0 -and
    $json.rc6_installer_fail_closed.invariants.install_performed -eq $false -and
    $json.rc6_installer_fail_closed.invariants.activation_performed -eq $false -and
    $json.rc6_installer_fail_closed.invariants.rollback_execution_performed -eq $false -and
    $json.rc6_installer_fail_closed.invariants.production_ring_mutated -eq $false

$rc6FrontendReady = $null -ne $json.rc6_mirror_frontend_refresh -and
    $json.rc6_mirror_frontend_refresh.status -eq "passed" -and
    $json.rc6_mirror_frontend_refresh.summary.blockers -eq 0 -and
    $json.rc6_mirror_frontend_refresh.invariants.metadata_preserved -eq $true -and
    $json.rc6_mirror_frontend_refresh.invariants.no_external_dependencies -eq $true

$fleetAuthorityReady = $null -ne $json.fleet_rollout_authority -and
    $json.fleet_rollout_authority.status -eq "passed" -and
    $json.fleet_rollout_authority.authority.execution_authority -eq "AgentCore fleet_rollout PlanSpec + SecurityExecutionEngine" -and
    $json.fleet_rollout_authority.authority.tui_authority -eq $false -and
    $json.fleet_rollout_authority.authority.remote_command_dispatch_in_tui -eq $false -and
    $observedCanaryNodes -lt $minimumCanaryNodes -and
    $canaryRing.blocker -eq "remote-fleet-execution-not-enabled"

$liveMetadataReady = $live.root.status_code -eq 200 -and
    $live.channel.status_code -eq 200 -and
    $live.payload_index.status_code -eq 200 -and
    $live.install_bootstrap.status_code -eq 200 -and
    $live.payload_manifest.status_code -eq 200 -and
    $live.payload_checksums.status_code -eq 200 -and
    $live.payload_signatures.status_code -eq 200 -and
    $null -ne $live.channel.json -and
    $null -ne $live.payload_index.json -and
    $null -ne $live.install_bootstrap.json -and
    $live.channel.json.production_ready_claim -eq $false -and
    $live.channel.json.payload_channel.default_release_id -eq "production-distro-rc6-current-artifacts" -and
    $live.channel.json.payload_channel.signature_available -eq $false -and
    $live.channel.json.payload_channel.install_allowed -eq $false -and
    $payloadEntry.release_id -eq "production-distro-rc6-current-artifacts" -and
    $payloadEntry.status -eq "verification-blocked" -and
    $live.install_bootstrap.json.current_state -eq "verification-blocked" -and
    $live.install_bootstrap.json.install_allowed -eq $false

$executionMustRemainBlocked = $rc5CanaryReady -and
    $rc5PacketBaseReady -and
    $rollbackReady -and
    $rc6PayloadReady -and
    $rc6PreflightReady -and
    $rc6FailClosedReady -and
    $fleetAuthorityReady -and
    $observedCanaryNodes -lt $minimumCanaryNodes

$packet = [ordered]@{
    schema = "agentos.rc6-canary-execution-packet.v1"
    generated_at = $generatedAt
    status = "packet-projected-execution-blocked"
    production_ready_claim = $false
    projection_only = $true
    executable = $false
    ring = "canary"
    domain = $Domain
    release_id = "production-distro-rc6-current-artifacts"
    payload_state = "verification-blocked"
    canary_execution_allowed = $false
    canary_execution_performed = $false
    activation_allowed = $false
    activation_performed = $false
    rollback_execution_allowed = $false
    rollback_execution_performed = $false
    exact_operator_approval_required = $true
    exact_operator_approval_granted = $false
    exact_operator_approval_packet_hash = $null
    execution_authority = "AgentCore fleet_rollout PlanSpec + SecurityExecutionEngine"
    target_set = [ordered]@{
        required_minimum_nodes = $minimumCanaryNodes
        observed_canary_node_count = $observedCanaryNodes
        multi_node_target_set_enrolled = $false
        remote_fleet_execution_enabled = $false
        blocker = "remote-fleet-execution-not-enabled"
    }
    approval_binding_requirements = @(
        "payload-index-sha256",
        "payload-manifest-sha256",
        "payload-checksums-sha256",
        "payload-signatures-sha256",
        "revocation-snapshot-sha256",
        "installer-compatibility-contract-sha256",
        "rollback-baseline-sha256",
        "canary-target-set-sha256",
        "fleet-policy-version",
        "exact-operator-approval-hash",
        "tls-evidence-before-ga-claim"
    )
    gates = [ordered]@{
        rc5_canary_preconditions_proven = $rc5CanaryReady
        rc5_rollback_readiness_ready = $rollbackReady
        rc6_hosted_payload_metadata_ready = $rc6PayloadReady
        rc6_bootstrap_preflight_verification_blocked = $rc6PreflightReady
        rc6_installer_fail_closed_ready = $rc6FailClosedReady
        rc6_mirror_frontend_ready = $rc6FrontendReady
        live_metadata_current_artifacts = $liveMetadataReady
        fleet_authority_ready = $fleetAuthorityReady
        signed_payload_required = $true
        signature_available = $false
        revocation_snapshot_available = $false
        installer_compatibility_contract_available = $false
        rollback_baseline_published_to_install_metadata = $false
        multi_node_target_set_enrolled = $false
        exact_operator_approval_granted = $false
        remote_fleet_execution_enabled = $false
        execution_gate_status = "blocked-by-design"
    }
    remaining_blockers_before_execution = @(
        "payload-signature-not-published",
        "revocation-snapshot-not-published",
        "installer-compatibility-contract-pending",
        "rollback-baseline-not-published-to-install-metadata",
        "two-or-more-enrolled-canary-target-nodes",
        "remote-fleet-execution-not-enabled",
        "exact-operator-approval-not-granted",
        "tls-required-before-ga-claim"
    )
    source_bindings = $sourceBindings
    live_endpoint_bindings = [ordered]@{
        channel = [ordered]@{ path = "/channel/index.json"; sha256 = $live.channel.body_sha256 }
        payload_index = [ordered]@{ path = "/payloads/index.json"; sha256 = $live.payload_index.body_sha256 }
        install_bootstrap = [ordered]@{ path = "/install/bootstrap.json"; sha256 = $live.install_bootstrap.body_sha256 }
        payload_manifest = [ordered]@{ path = "/payloads/aios/production-distro-rc6-current-artifacts/manifest.json"; sha256 = $live.payload_manifest.body_sha256 }
        payload_checksums = [ordered]@{ path = "/payloads/aios/production-distro-rc6-current-artifacts/checksums.json"; sha256 = $live.payload_checksums.body_sha256 }
        payload_signatures = [ordered]@{ path = "/payloads/aios/production-distro-rc6-current-artifacts/signatures.json"; sha256 = $live.payload_signatures.body_sha256 }
    }
    invariants = [ordered]@{
        local_private_key_material_used = $false
        cryptographic_signing_performed = $false
        remote_mutation_performed = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        active_slot_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        remote_dispatch_enabled = $false
        model_replay_authority = $false
        normal_shell_authority = $false
        tui_authority = $false
    }
}

$rollbackPreconditions = [ordered]@{
    schema = "agentos.rc6-rollback-execution-preconditions.v1"
    generated_at = $generatedAt
    status = "rollback-preconditions-projected-execution-blocked"
    production_ready_claim = $false
    projection_only = $true
    rollback_readiness_ready = $rollbackReady
    rollback_execution_allowed = $false
    rollback_execution_performed = $false
    previous_active_artifact_set_sha256 = if ($null -ne $json.rc5_rollback_readiness) { $json.rc5_rollback_readiness.previous_active_artifact_set_sha256 } else { $null }
    restored_active_artifact_set_sha256 = if ($null -ne $json.rc5_rollback_readiness) { $json.rc5_rollback_readiness.restored_active_artifact_set_sha256 } else { $null }
    rollback_baseline_sha256 = if ($null -ne $json.rc5_rollback_readiness) { $json.rc5_rollback_readiness.rollback_baseline_sha256 } else { $null }
    required_before_canary_execution = @(
        "rollback-baseline-bound-to-exact-operator-approval",
        "SecurityExecutionEngine-rollback-PlanSpec-approved",
        "signed-payload-and-revocation-verification-passed",
        "support-recovery-redaction-evidence-present",
        "mirror-not-allowed-to-execute-rollback",
        "TUI-not-allowed-to-execute-rollback"
    )
    blocked_execution_reason = "RC6 canary packet binds rollback readiness, but rollback execution is still blocked until exact approval and SecurityExecutionEngine PlanSpec execution evidence exist."
    source_bindings = [ordered]@{
        rc5_rollback_readiness_sha256 = $sourceBindings.rc5_rollback_readiness_sha256
        rc6_bootstrap_preflight_sha256 = $sourceBindings.rc6_bootstrap_preflight_sha256
        rc6_installer_fail_closed_sha256 = $sourceBindings.rc6_installer_fail_closed_sha256
    }
    invariants = [ordered]@{
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        persistent_state_mutated = $false
        remote_dispatch_enabled = $false
        model_replay_authority = $false
        normal_shell_authority = $false
        tui_authority = $false
    }
}

Write-Json -Value $packet -Path $packetPath
Write-Json -Value $rollbackPreconditions -Path $rollbackPreconditionsPath

$packetHash = Get-FileSha256 $packetPath
$rollbackPreconditionsHash = Get-FileSha256 $rollbackPreconditionsPath

Add-Check "source.artifacts.present" $sourcesPresent "RC6 canary packet must bind all required RC5/RC6 source artifacts." $sourceBindings
Add-Check "rc5.canary.preconditions" $rc5CanaryReady "RC5 canary proof must be passed, rollback-ready, exact-approval-gated, and execution-blocked." $(if ($null -ne $json.rc5_canary_result) { $json.rc5_canary_result.summary } else { $null })
Add-Check "rc5.canary.packet_base" $rc5PacketBaseReady "RC5 canary plan projection must be non-executable and approval-gated." $(if ($null -ne $json.rc5_canary_projection) { $json.rc5_canary_projection.gates } else { $null })
Add-Check "rc5.rollback.readiness" $rollbackReady "Rollback readiness must be bound to equal previous/restored artifact hashes and execute no rollback." $(if ($null -ne $json.rc5_rollback_readiness) { [ordered]@{ previous = $json.rc5_rollback_readiness.previous_active_artifact_set_sha256; restored = $json.rc5_rollback_readiness.restored_active_artifact_set_sha256; baseline = $json.rc5_rollback_readiness.rollback_baseline_sha256; rollback_execution_performed = $json.rc5_rollback_readiness.rollback_execution_performed } } else { $null })
Add-Check "rc6.payload.metadata" $rc6PayloadReady "RC6 hosted payload metadata must point to current artifacts while remaining verification-blocked, unsigned, and install-blocked." $(if ($null -ne $json.rc6_hosted_payload_metadata) { $json.rc6_hosted_payload_metadata.payload_surface } else { $null })
Add-Check "rc6.bootstrap.preflight" $rc6PreflightReady "RC6 bootstrap installer preflight must be passed as verification-blocked with no side effects." $(if ($null -ne $json.rc6_bootstrap_preflight) { $json.rc6_bootstrap_preflight.preflight } else { $null })
Add-Check "rc6.installer.fail_closed" $rc6FailClosedReady "RC6 installer fail-closed fixtures must pass all negative cases without install/activation/rollback side effects." $(if ($null -ne $json.rc6_installer_fail_closed) { $json.rc6_installer_fail_closed.summary } else { $null })
Add-Check "rc6.frontend.refresh" $rc6FrontendReady "RC6 mirror frontend refresh must be passed, dependency-free, and metadata-preserving." $(if ($null -ne $json.rc6_mirror_frontend_refresh) { $json.rc6_mirror_frontend_refresh.summary } else { $null })
Add-Check "fleet.authority.canary_blocked" $fleetAuthorityReady "Fleet authority must remain AgentCore/SecurityExecution-owned; canary ring is not multi-node enrolled and remote execution is disabled." ([ordered]@{ observed_canary_nodes = $observedCanaryNodes; required_canary_nodes = $minimumCanaryNodes; canary_blocker = if ($null -ne $canaryRing) { $canaryRing.blocker } else { $null } })
Add-Check "live.metadata.current" $liveMetadataReady "Live mirror metadata must be reachable through resolve-pinned HTTP and remain current-artifacts, non-GA, unsigned, and install-blocked." ([ordered]@{ root = $live.root.status_code; channel = $live.channel.status_code; payload = $live.payload_index.status_code; install = $live.install_bootstrap.status_code; release_id = if ($null -ne $payloadEntry) { $payloadEntry.release_id } else { $null }; payload_status = if ($null -ne $payloadEntry) { $payloadEntry.status } else { $null }; install_state = if ($null -ne $live.install_bootstrap.json) { $live.install_bootstrap.json.current_state } else { $null } })
Add-Check "packet.execution_blocked" $executionMustRemainBlocked "Generated RC6 canary packet must remain non-executable until signature, revocation, compatibility, rollback, target-set, remote-execution, exact-approval, and TLS gates are satisfied." $packet.gates
Add-Check "packet.outputs.ready" ((Test-Path -LiteralPath $packetPath -PathType Leaf) -and (Test-Path -LiteralPath $rollbackPreconditionsPath -PathType Leaf)) "Canary packet and rollback preconditions artifacts must be generated." ([ordered]@{ packet = Get-StablePath $packetPath; rollback = Get-StablePath $rollbackPreconditionsPath })
Add-Check "packet.no_authority_broadened" $true "Projection must not sign, install, activate, rollback, mutate slots/rings, upload support, dispatch remotely, or grant TUI/model/shell authority." $packet.invariants

$passed = @($script:blockers).Count -eq 0

$result = [ordered]@{
    schema = "agentos.rc6-canary-execution-packet-result.v1"
    generated_at = $generatedAt
    checked_at = (Get-Date).ToString("o")
    task = "RC6-030"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    canary_execution_packet_projected = $passed
    canary_execution_allowed = $false
    canary_execution_performed = $false
    rollback_preconditions_projected = $rollbackReady
    rollback_execution_allowed = $false
    rollback_execution_performed = $false
    artifacts = [ordered]@{
        canary_execution_packet = [ordered]@{
            path = Get-StablePath $packetPath
            sha256 = $packetHash
            schema = $packet.schema
            status = $packet.status
        }
        rollback_execution_preconditions = [ordered]@{
            path = Get-StablePath $rollbackPreconditionsPath
            sha256 = $rollbackPreconditionsHash
            schema = $rollbackPreconditions.schema
            status = $rollbackPreconditions.status
        }
    }
    source_artifacts = [ordered]@{}
    live_endpoint_bindings = $packet.live_endpoint_bindings
    source_bindings = $sourceBindings
    payload_surface = [ordered]@{
        release_id = if ($null -ne $payloadEntry) { $payloadEntry.release_id } else { $null }
        status = if ($null -ne $payloadEntry) { $payloadEntry.status } else { $null }
        signature_available = if ($null -ne $payloadEntry) { $payloadEntry.signature_available } else { $null }
        install_allowed = if ($null -ne $live.install_bootstrap.json) { $live.install_bootstrap.json.install_allowed } else { $null }
        install_state = if ($null -ne $live.install_bootstrap.json) { $live.install_bootstrap.json.current_state } else { $null }
    }
    remaining_blockers_before_execution = $packet.remaining_blockers_before_execution
    checks = $script:checks
    blockers = $script:blockers
    invariants = $packet.invariants
    summary = [ordered]@{
        checks = @($script:checks).Count
        blockers = @($script:blockers).Count
        rc6_030_complete = $passed
        canary_execution_packet_projected = $passed
        canary_execution_allowed = $false
        canary_execution_performed = $false
        rollback_preconditions_projected = $rollbackReady
        rollback_execution_performed = $false
        release_id = if ($null -ne $payloadEntry) { $payloadEntry.release_id } else { $null }
        payload_status = if ($null -ne $payloadEntry) { $payloadEntry.status } else { $null }
        exact_operator_approval_required = $true
        exact_operator_approval_granted = $false
        observed_canary_node_count = $observedCanaryNodes
        required_canary_node_count = $minimumCanaryNodes
        remote_fleet_execution_enabled = $false
        production_ready_claim = $false
        next_task = "RC6-031"
    }
}

foreach ($key in $paths.Keys) {
    $result.source_artifacts[$key] = New-ArtifactRef -Path $resolved[$key] -Json $json[$key]
}

Write-Json -Value $result -Path $resolvedOutputPath

$secretSafe = Test-NoSensitiveFiles -Paths @($packetPath, $rollbackPreconditionsPath, $resolvedOutputPath)
if (-not $secretSafe) {
    $extra = [ordered]@{
        id = "packet.secret_safe"
        status = "failed"
        severity = "blocking"
        message = "Generated RC6 canary packet artifacts must not contain private key or token markers."
        evidence = $null
    }
    $script:checks += $extra
    $script:blockers += $extra
    $result.status = "blocked"
    $result.canary_execution_packet_projected = $false
    $result.checks = $script:checks
    $result.blockers = $script:blockers
    $result.summary.checks = @($script:checks).Count
    $result.summary.blockers = @($script:blockers).Count
    $result.summary.rc6_030_complete = $false
    $result.summary.canary_execution_packet_projected = $false
    Write-Json -Value $result -Path $resolvedOutputPath
}

Write-Host "RC6 canary execution packet $($result.status): $(Get-StablePath $resolvedOutputPath)"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
