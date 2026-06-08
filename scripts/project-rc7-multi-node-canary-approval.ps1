param(
    [string]$RemoteHost = "47.101.11.109",
    [string]$Domain = "aios.w33d.xyz",
    [string]$ArtifactDir = ".workflow/artifacts/rc7-multi-node-canary-approval",
    [string]$ResultPath = "",
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
    $json = $Value | ConvertTo-Json -Depth 100
    [IO.File]::WriteAllText([IO.Path]::GetFullPath($Path), $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
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
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace("-", "").ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Read-JsonFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    return Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
}

function ConvertFrom-JsonTextSafe {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }
    try {
        return ($Text | ConvertFrom-Json)
    } catch {
        return $null
    }
}

function Invoke-Curl {
    param([Parameter(Mandatory = $true)][string]$Path)
    $url = "https://$Domain$Path"
    $args = @(
        "--noproxy", "*",
        "--max-time", "$CurlTimeoutSeconds",
        "--resolve", "$Domain`:443`:$RemoteHost",
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
        ("BEGIN" + " " + "PRIVATE" + " " + "KEY"),
        ("PRIVATE" + " " + "KEY" + "-----"),
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

function Get-Ring {
    param($FleetAuthority, [string]$Name)
    if ($null -eq $FleetAuthority -or $null -eq $FleetAuthority.rings) {
        return $null
    }
    return @($FleetAuthority.rings | Where-Object { $_.name -eq $Name } | Select-Object -First 1)[0]
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

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:blockers = @()

$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
if (-not $ResultPath) {
    $ResultPath = Join-Path $ArtifactDir "result.json"
}
$resolvedResultPath = Resolve-RepoPath $ResultPath
$targetSetPath = Join-Path $resolvedArtifactDir "canary-target-set.json"
$approvalPacketPath = Join-Path $resolvedArtifactDir "exact-approval-packet.json"

$sourcePaths = [ordered]@{
    rc7_installer_signed_consumption = ".workflow/artifacts/rc7-installer-signed-consumption/result.json"
    rc7_signed_consumption_fail_closed = ".workflow/artifacts/rc7-signed-consumption-fail-closed/result.json"
    rc7_install_rollback_baseline = ".workflow/artifacts/rc7-install-rollback-baseline/result.json"
    rc7_mirror_frontend_signed_status = ".workflow/artifacts/rc7-mirror-frontend-signed-status/result.json"
    rc7_tls_nginx_hardening = ".workflow/artifacts/rc7-tls-nginx-hardening/result.json"
    rc7_large_payload_storage_policy = ".workflow/active/WFS-20260608-agentos-production-distro-rc7/evidence/RC7-022-large-payload-storage-policy.json"
    rc6_canary_packet = ".workflow/artifacts/rc6-canary-execution-packet/result.json"
    rc6_rollback_preconditions = ".workflow/artifacts/rc6-rollback-execution-preconditions/result.json"
    fleet_rollout_authority = ".workflow/artifacts/release/fleet-rollout-authority.json"
}

$sourceJson = [ordered]@{}
$sourceRefs = [ordered]@{}
foreach ($key in $sourcePaths.Keys) {
    $path = Resolve-RepoPath $sourcePaths[$key]
    $json = Read-JsonFile $path
    $sourceJson[$key] = $json
    $sourceRefs[$key] = New-ArtifactRef -Path $path -Json $json
}

$live = [ordered]@{
    root = Invoke-Curl "/"
    channel = Invoke-Curl "/channel/index.json"
    payload_index = Invoke-Curl "/payloads/index.json"
    install_bootstrap = Invoke-Curl "/install/bootstrap.json"
    compatibility = Invoke-Curl "/install/compatibility.json"
    rollback_baseline = Invoke-Curl "/install/rollback-baseline.json"
    signatures = Invoke-Curl "/payloads/aios/production-distro-rc6-current-artifacts/signatures.json"
    signed_metadata = Invoke-Curl "/payloads/aios/production-distro-rc6-current-artifacts/signed-metadata.json"
    revocations = Invoke-Curl "/payloads/aios/production-distro-rc6-current-artifacts/revocations.json"
}

$payloadEntry = if ($null -ne $live.payload_index.json -and $null -ne $live.payload_index.json.entries) { @($live.payload_index.json.entries)[0] } else { $null }
$canaryRing = Get-Ring $sourceJson.fleet_rollout_authority "canary"
$minimumCanaryNodes = 2
$observedCanaryNodes = if ($null -ne $canaryRing -and $null -ne $canaryRing.node_count) { [int]$canaryRing.node_count } else { 0 }
$generatedAt = (Get-Date).ToString("o")

$acceptedSourceStatuses = @("passed", "completed")
$sourcesReady = @($sourceRefs.Values | Where-Object { -not $_.present -or $acceptedSourceStatuses -notcontains $_.status }).Count -eq 0
$rc7ConsumptionReady = $sourceJson.rc7_installer_signed_consumption.status -eq "passed" -and
    $sourceJson.rc7_installer_signed_consumption.summary.blockers -eq 0 -and
    $sourceJson.rc7_installer_signed_consumption.summary.installer_blockers -gt 0 -and
    $sourceJson.rc7_installer_signed_consumption.summary.rc7_010_complete -eq $true -and
    $sourceJson.rc7_installer_signed_consumption.report.state -eq "verification-blocked" -and
    $sourceJson.rc7_installer_signed_consumption.consumption_summary.install_allowed -eq $false -and
    $sourceJson.rc7_installer_signed_consumption.consumption_summary.activation_allowed -eq $false -and
    $sourceJson.rc7_installer_signed_consumption.consumption_summary.rollback_execution_allowed -eq $false -and
    $sourceJson.rc7_installer_signed_consumption.invariants.install_performed -eq $false -and
    $sourceJson.rc7_installer_signed_consumption.invariants.activation_performed -eq $false -and
    $sourceJson.rc7_installer_signed_consumption.invariants.rollback_execution_performed -eq $false
$rc7FailClosedReady = $sourceJson.rc7_signed_consumption_fail_closed.status -eq "passed" -and
    $sourceJson.rc7_signed_consumption_fail_closed.summary.failed_cases -eq 0
$rollbackBaselineReady = $sourceJson.rc7_install_rollback_baseline.status -eq "passed" -and
    $sourceJson.rc7_install_rollback_baseline.payload_surface.compatibility_published -eq $true -and
    $sourceJson.rc7_install_rollback_baseline.payload_surface.rollback_baseline_published -eq $true
$tlsReady = $sourceJson.rc7_tls_nginx_hardening.status -eq "passed" -and
    $sourceJson.rc7_tls_nginx_hardening.invariants.tls_configured -eq $true -and
    $sourceJson.rc7_tls_nginx_hardening.endpoint_status.https_root -eq 200
$storagePolicyReady = $sourceJson.rc7_large_payload_storage_policy.status -eq "completed" -and
    $sourceJson.rc7_large_payload_storage_policy.policy.large_payloads_on_mirror_allowed -eq $false -and
    $sourceJson.rc7_large_payload_storage_policy.policy.external_object_storage_required -eq $true
$fleetAuthorityReady = $sourceJson.fleet_rollout_authority.status -eq "passed" -and
    $sourceJson.fleet_rollout_authority.authority.execution_authority -eq "AgentCore fleet_rollout PlanSpec + SecurityExecutionEngine" -and
    $sourceJson.fleet_rollout_authority.authority.tui_authority -eq $false
$liveMetadata = @(
    $live.channel,
    $live.payload_index,
    $live.install_bootstrap,
    $live.compatibility,
    $live.rollback_baseline,
    $live.signatures,
    $live.signed_metadata,
    $live.revocations
)
$liveReady = $live.root.exit_code -eq 0 -and
    $live.root.status_code -eq 200 -and
    @($liveMetadata | Where-Object { $_.exit_code -ne 0 -or $_.status_code -ne 200 -or $null -eq $_.json }).Count -eq 0 -and
    $live.channel.json.production_ready_claim -eq $false -and
    $payloadEntry.release_id -eq "production-distro-rc6-current-artifacts" -and
    $payloadEntry.status -eq "verification-blocked" -and
    $payloadEntry.install_allowed -eq $false -and
    $payloadEntry.activation_allowed -eq $false -and
    $payloadEntry.rollback_execution_allowed -eq $false -and
    $live.install_bootstrap.json.install_allowed -eq $false

$signedMetadataPublished = [bool]$payloadEntry.signed_metadata_sha256
$revocationPublished = [bool]$payloadEntry.revocation_snapshot_sha256
$compatibilityPublished = [bool]$payloadEntry.compatibility_sha256
$rollbackPublished = [bool]$payloadEntry.rollback_baseline_sha256
$cryptographicSignaturePresent = $live.signatures.json.cryptographic_signature_present -eq $true
$signatureAvailable = $live.signatures.json.signature_available -eq $true
$targetSetEnrolled = $observedCanaryNodes -ge $minimumCanaryNodes -and $sourceJson.fleet_rollout_authority.authority.remote_command_dispatch_in_tui -eq $false

$targetSet = [ordered]@{
    schema = "agentos.rc7-canary-target-set.v1"
    generated_at = $generatedAt
    status = "projected-target-set-enrollment-blocked"
    ring = "canary"
    required_minimum_nodes = $minimumCanaryNodes
    observed_canary_node_count = $observedCanaryNodes
    enrolled_target_count = 0
    target_set_enrolled = $false
    target_selection_policy = "two-or-more-enrolled-canary-nodes-required-before-activation"
    projected_targets = @(
        [ordered]@{
            slot = "canary-a"
            required = $true
            enrollment_status = "missing"
            node_id = $null
            target_profile_hash = $null
        },
        [ordered]@{
            slot = "canary-b"
            required = $true
            enrollment_status = "missing"
            node_id = $null
            target_profile_hash = $null
        }
    )
    authority = [ordered]@{
        plan_authority = "AgentCore"
        side_effect_authority = "SecurityExecutionEngine"
        mirror_authority = $false
        signer_authority = $false
        tui_authority = $false
        shell_authority = $false
        model_replay_authority = $false
    }
    blockers = @(
        "two-or-more-enrolled-canary-target-nodes-required",
        "remote-fleet-execution-not-enabled",
        "exact-operator-approval-not-granted"
    )
}

$approvalBinding = [ordered]@{
    release_id = if ($null -ne $payloadEntry) { $payloadEntry.release_id } else { $null }
    ring = "canary"
    target_set_policy = $targetSet.target_selection_policy
    payload_index_sha256 = $live.payload_index.body_sha256
    install_bootstrap_sha256 = $live.install_bootstrap.body_sha256
    signatures_sha256 = $live.signatures.body_sha256
    signed_metadata_sha256 = $live.signed_metadata.body_sha256
    revocations_sha256 = $live.revocations.body_sha256
    compatibility_sha256 = $live.compatibility.body_sha256
    rollback_baseline_sha256 = $live.rollback_baseline.body_sha256
    tls_evidence_sha256 = $sourceRefs.rc7_tls_nginx_hardening.sha256
    storage_policy_evidence_sha256 = $sourceRefs.rc7_large_payload_storage_policy.sha256
    fleet_rollout_authority_sha256 = $sourceRefs.fleet_rollout_authority.sha256
    agentcore_planspec_required = $true
    security_execution_engine_required = $true
    exact_operator_approval_required = $true
    approval_status = "required-not-granted"
}
$approvalBindingJson = $approvalBinding | ConvertTo-Json -Depth 100 -Compress
$approvalBindingSha256 = Get-StringSha256 $approvalBindingJson

$approvalPacket = [ordered]@{
    schema = "agentos.rc7-exact-canary-approval-packet.v1"
    generated_at = $generatedAt
    status = "approval-required-execution-blocked"
    production_ready_claim = $false
    projection_only = $true
    executable = $false
    approval_binding_sha256 = $approvalBindingSha256
    approval_binding = $approvalBinding
    required_actor = "release-operator"
    required_action = "approve-rc7-canary-activation"
    required_scope = "canary-ring-only"
    expiry_required = $true
    approval_granted = $false
    approval_token = $null
    canary_execution_allowed = $false
    canary_execution_performed = $false
    activation_allowed = $false
    activation_performed = $false
    rollback_execution_allowed = $false
    rollback_execution_performed = $false
    gates = [ordered]@{
        signed_metadata_published = $signedMetadataPublished
        revocation_snapshot_published = $revocationPublished
        compatibility_published = $compatibilityPublished
        rollback_baseline_published = $rollbackPublished
        tls_configured = $tlsReady
        storage_policy_defined = $storagePolicyReady
        cryptographic_signature_present = $cryptographicSignaturePresent
        signature_available = $signatureAvailable
        canary_target_set_enrolled = $targetSetEnrolled
        exact_operator_approval_granted = $false
        agentcore_planspec_bound = $false
        security_execution_approval_bound = $false
        execution_gate_status = "blocked-by-design"
    }
    remaining_blockers_before_execution = @(
        "real-cryptographic-payload-signature-not-present",
        "two-or-more-enrolled-canary-target-nodes-required",
        "remote-fleet-execution-not-enabled",
        "exact-operator-approval-not-granted",
        "AgentCore-PlanSpec-not-bound",
        "SecurityExecutionEngine-approval-not-bound"
    )
    invariants = [ordered]@{
        local_private_key_material_used = $false
        private_key_material_read_or_printed = $false
        cryptographic_signing_performed = $false
        payload_upload_performed = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        active_slot_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        remote_dispatch_enabled = $false
        tui_authority = $false
    }
}

Write-Json -Value $targetSet -Path $targetSetPath
Write-Json -Value $approvalPacket -Path $approvalPacketPath
$targetSetHash = Get-FileSha256 $targetSetPath
$approvalPacketHash = Get-FileSha256 $approvalPacketPath

Add-Check "source.artifacts.ready" $sourcesReady "RC7-030 must bind passed RC7 mirror, TLS, storage, signed-consumption, rollback, and fleet authority evidence." $sourceRefs
Add-Check "rc7.consumption.ready_blocked" $rc7ConsumptionReady "Installer signed consumption must be observable while still verification-blocked." $(if ($null -ne $sourceJson.rc7_installer_signed_consumption) { $sourceJson.rc7_installer_signed_consumption.summary } else { $null })
Add-Check "rc7.fail_closed.ready" $rc7FailClosedReady "Signed consumption fail-closed fixtures must pass all negative cases." $(if ($null -ne $sourceJson.rc7_signed_consumption_fail_closed) { $sourceJson.rc7_signed_consumption_fail_closed.summary } else { $null })
Add-Check "rc7.rollback_baseline.ready" $rollbackBaselineReady "Compatibility and rollback baseline must be published and hash-bound before canary approval packet projection." $(if ($null -ne $sourceJson.rc7_install_rollback_baseline) { $sourceJson.rc7_install_rollback_baseline.payload_surface } else { $null })
Add-Check "rc7.tls.ready" $tlsReady "TLS and nginx hardening evidence must pass before canary approval packet projection." $(if ($null -ne $sourceJson.rc7_tls_nginx_hardening) { $sourceJson.rc7_tls_nginx_hardening.summary } else { $null })
Add-Check "rc7.storage_policy.ready" $storagePolicyReady "Large payload storage policy must keep the mirror metadata-only and require external object storage." $(if ($null -ne $sourceJson.rc7_large_payload_storage_policy) { $sourceJson.rc7_large_payload_storage_policy.policy } else { $null })
Add-Check "fleet.authority.ready" $fleetAuthorityReady "Fleet rollout authority must remain AgentCore and SecurityExecutionEngine owned, with no TUI authority." $(if ($null -ne $sourceJson.fleet_rollout_authority) { $sourceJson.fleet_rollout_authority.authority } else { $null })
Add-Check "live.https.metadata.current" $liveReady "HTTPS live metadata must remain current-artifacts, non-GA, verification-blocked, and install/activation/rollback blocked." ([ordered]@{ root = $live.root.status_code; channel = $live.channel.status_code; payload_index = $live.payload_index.status_code; install = $live.install_bootstrap.status_code; release_id = if ($null -ne $payloadEntry) { $payloadEntry.release_id } else { $null }; status = if ($null -ne $payloadEntry) { $payloadEntry.status } else { $null } })
Add-Check "canary.target_set.projected_blocked" ((Test-Path -LiteralPath $targetSetPath -PathType Leaf) -and $targetSet.target_set_enrolled -eq $false -and $targetSet.required_minimum_nodes -eq 2) "Canary target set projection must require two nodes and refuse to fake enrollment." ([ordered]@{ path = Get-StablePath $targetSetPath; sha256 = $targetSetHash; observed = $observedCanaryNodes; required = $minimumCanaryNodes })
Add-Check "approval.packet.projected_blocked" ((Test-Path -LiteralPath $approvalPacketPath -PathType Leaf) -and $approvalPacket.approval_granted -eq $false -and $approvalPacket.executable -eq $false) "Exact approval packet must be generated, hash-bound, and non-executable until approval and execution gates pass." ([ordered]@{ path = Get-StablePath $approvalPacketPath; sha256 = $approvalPacketHash; approval_binding_sha256 = $approvalBindingSha256 })
Add-Check "execution.blocked_by_design" ($approvalPacket.canary_execution_allowed -eq $false -and $approvalPacket.activation_allowed -eq $false -and $approvalPacket.rollback_execution_allowed -eq $false) "RC7-030 must not authorize canary activation, install, or rollback execution." $approvalPacket.gates
Add-Check "authority.not_broadened" $true "RC7-030 must not sign, upload payloads, install, activate, rollback, mutate slots/rings, upload support, dispatch remotely, or grant TUI authority." $approvalPacket.invariants

$passed = @($script:blockers).Count -eq 0
$result = [ordered]@{
    schema = "agentos.rc7-multi-node-canary-approval-result.v1"
    generated_at = $generatedAt
    checked_at = (Get-Date).ToString("o")
    task = "RC7-030"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    canary_approval_packet_projected = $passed
    canary_execution_allowed = $false
    canary_execution_performed = $false
    activation_allowed = $false
    activation_performed = $false
    rollback_execution_allowed = $false
    rollback_execution_performed = $false
    artifacts = [ordered]@{
        canary_target_set = [ordered]@{
            path = Get-StablePath $targetSetPath
            sha256 = $targetSetHash
            schema = $targetSet.schema
            status = $targetSet.status
        }
        exact_approval_packet = [ordered]@{
            path = Get-StablePath $approvalPacketPath
            sha256 = $approvalPacketHash
            schema = $approvalPacket.schema
            status = $approvalPacket.status
            approval_binding_sha256 = $approvalBindingSha256
        }
    }
    source_artifacts = $sourceRefs
    live_endpoint_bindings = [ordered]@{
        channel = [ordered]@{ path = "/channel/index.json"; sha256 = $live.channel.body_sha256 }
        payload_index = [ordered]@{ path = "/payloads/index.json"; sha256 = $live.payload_index.body_sha256 }
        install_bootstrap = [ordered]@{ path = "/install/bootstrap.json"; sha256 = $live.install_bootstrap.body_sha256 }
        signatures = [ordered]@{ path = "/payloads/aios/production-distro-rc6-current-artifacts/signatures.json"; sha256 = $live.signatures.body_sha256 }
        signed_metadata = [ordered]@{ path = "/payloads/aios/production-distro-rc6-current-artifacts/signed-metadata.json"; sha256 = $live.signed_metadata.body_sha256 }
        revocations = [ordered]@{ path = "/payloads/aios/production-distro-rc6-current-artifacts/revocations.json"; sha256 = $live.revocations.body_sha256 }
        compatibility = [ordered]@{ path = "/install/compatibility.json"; sha256 = $live.compatibility.body_sha256 }
        rollback_baseline = [ordered]@{ path = "/install/rollback-baseline.json"; sha256 = $live.rollback_baseline.body_sha256 }
    }
    target_set = [ordered]@{
        required_minimum_nodes = $minimumCanaryNodes
        observed_canary_node_count = $observedCanaryNodes
        target_set_enrolled = $false
    }
    approval = [ordered]@{
        exact_operator_approval_required = $true
        exact_operator_approval_granted = $false
        approval_binding_sha256 = $approvalBindingSha256
    }
    payload_surface = [ordered]@{
        release_id = if ($null -ne $payloadEntry) { $payloadEntry.release_id } else { $null }
        status = if ($null -ne $payloadEntry) { $payloadEntry.status } else { $null }
        signed_metadata_published = $signedMetadataPublished
        revocation_snapshot_published = $revocationPublished
        compatibility_published = $compatibilityPublished
        rollback_baseline_published = $rollbackPublished
        cryptographic_signature_present = $cryptographicSignaturePresent
        signature_available = $signatureAvailable
        install_allowed = if ($null -ne $payloadEntry) { $payloadEntry.install_allowed } else { $null }
        activation_allowed = if ($null -ne $payloadEntry) { $payloadEntry.activation_allowed } else { $null }
        rollback_execution_allowed = if ($null -ne $payloadEntry) { $payloadEntry.rollback_execution_allowed } else { $null }
    }
    remaining_blockers_before_execution = $approvalPacket.remaining_blockers_before_execution
    checks = $script:checks
    blockers = $script:blockers
    invariants = $approvalPacket.invariants
    summary = [ordered]@{
        checks = @($script:checks).Count
        blockers = @($script:blockers).Count
        rc7_030_complete = $passed
        canary_approval_packet_projected = $passed
        canary_execution_allowed = $false
        canary_execution_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        exact_operator_approval_required = $true
        exact_operator_approval_granted = $false
        required_canary_node_count = $minimumCanaryNodes
        observed_canary_node_count = $observedCanaryNodes
        target_set_enrolled = $false
        remote_fleet_execution_enabled = $false
        production_ready_claim = $false
        next_task = "RC7-031"
    }
}

Write-Json -Value $result -Path $resolvedResultPath

$secretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $targetSetPath),
    (Get-Content -Raw -LiteralPath $approvalPacketPath),
    (Get-Content -Raw -LiteralPath $resolvedResultPath)
)
if (-not $secretSafe) {
    $extra = [ordered]@{
        id = "outputs.secret_safe"
        status = "failed"
        severity = "blocking"
        message = "RC7-030 artifacts must not contain private key or token markers."
        evidence = $null
    }
    $script:checks += $extra
    $script:blockers += $extra
    $result.status = "blocked"
    $result.checks = $script:checks
    $result.blockers = $script:blockers
    $result.summary.checks = @($script:checks).Count
    $result.summary.blockers = @($script:blockers).Count
    $result.summary.rc7_030_complete = $false
    Write-Json -Value $result -Path $resolvedResultPath
}

Write-Host "RC7 multi-node canary approval $($result.status): $(Get-StablePath $resolvedResultPath)"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
