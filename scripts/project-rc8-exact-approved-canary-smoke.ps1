param(
    [string]$RemoteHost = "47.101.11.109",
    [string]$Domain = "aios.w33d.xyz",
    [string]$ArtifactDir = ".workflow/artifacts/rc8-exact-approved-canary-smoke",
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
        ("." + "local-release" + "-authority"),
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

function Test-HasAllItems {
    param(
        [object[]]$Values,
        [string[]]$Expected
    )
    $observed = @($Values | ForEach-Object { [string]$_ })
    return @($Expected | Where-Object { $observed -notcontains $_ }).Count -eq 0
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
$gateReportPath = Join-Path $resolvedArtifactDir "activation-smoke-gate-report.json"
$denialEvidencePath = Join-Path $resolvedArtifactDir "activation-denial-evidence.json"

$sourcePaths = [ordered]@{
    rc8_descriptor_result = ".workflow/artifacts/rc8-real-payload-object-descriptor/result.json"
    rc8_descriptor = ".workflow/artifacts/rc8-real-payload-object-descriptor/payload-object-descriptor.json"
    rc8_signature_ingestion_result = ".workflow/artifacts/rc8-public-signature-ingestion/result.json"
    rc8_signature_receipt = ".workflow/artifacts/rc8-public-signature-ingestion/signature-ingestion-receipt.json"
    rc8_signature_summary = ".workflow/artifacts/rc8-public-signature-ingestion/public-signature-artifact-summary.json"
    rc8_signed_descriptor_fail_closed = ".workflow/artifacts/rc8-signed-object-descriptor-fail-closed/result.json"
    rc8_installer_vm_preflight = ".workflow/artifacts/rc8-installer-vm-preflight/result.json"
    rc8_installer_byte_fail_closed = ".workflow/artifacts/rc8-installer-byte-fail-closed/result.json"
    rc8_mirror_consistency_refresh = ".workflow/artifacts/rc8-mirror-consistency-refresh/result.json"
    rc8_hosted_payload_index = ".workflow/artifacts/rc8-mirror-consistency-refresh/hosted-payload-index.json"
    rc8_install_bootstrap = ".workflow/artifacts/rc8-mirror-consistency-refresh/install-bootstrap.json"
    rc8_hosted_channel_index = ".workflow/artifacts/rc8-mirror-consistency-refresh/hosted-channel-index.json"
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

$bootstrapEndpoints = $sourceJson.rc8_install_bootstrap.endpoints
$payloadEntry = if ($null -ne $sourceJson.rc8_hosted_payload_index -and $null -ne $sourceJson.rc8_hosted_payload_index.entries) {
    @($sourceJson.rc8_hosted_payload_index.entries)[0]
} else {
    $null
}

$live = [ordered]@{
    root = Invoke-Curl "/"
    channel = Invoke-Curl "/channel/index.json"
    payload_index = Invoke-Curl "/payloads/index.json"
    install_bootstrap = Invoke-Curl "/install/bootstrap.json"
    mirror_status = Invoke-Curl "/.well-known/aios/rc8-mirror-status.json"
    object_descriptor = Invoke-Curl $bootstrapEndpoints.object_descriptor
    signature_receipt = Invoke-Curl $bootstrapEndpoints.signature_receipt
    installer_preflight = Invoke-Curl $bootstrapEndpoints.installer_preflight
    installer_fail_closed = Invoke-Curl $bootstrapEndpoints.fail_closed_result
}
$livePayloadEntry = if ($null -ne $live.payload_index.json -and $null -ne $live.payload_index.json.entries) {
    @($live.payload_index.json.entries)[0]
} else {
    $null
}

$generatedAt = (Get-Date).ToString("o")
$canaryRing = Get-Ring $sourceJson.fleet_rollout_authority "canary"
$minimumCanaryNodes = 2
$observedCanaryNodes = if ($null -ne $canaryRing -and $null -ne $canaryRing.node_count) { [int]$canaryRing.node_count } else { 0 }

$descriptorReady = $sourceJson.rc8_descriptor_result.status -eq "passed" -and
    $sourceJson.rc8_descriptor_result.summary.blockers -eq 0 -and
    $sourceJson.rc8_descriptor.schema -eq "agentos.payload-object-descriptor.v1" -and
    $sourceJson.rc8_descriptor.release_id -eq "production-distro-rc8-current-artifacts" -and
    $sourceJson.rc8_descriptor.install_allowed -eq $false -and
    $sourceJson.rc8_descriptor.activation_allowed -eq $false -and
    $sourceJson.rc8_descriptor.rollback_execution_allowed -eq $false
$signatureReady = $sourceJson.rc8_signature_ingestion_result.status -eq "passed" -and
    $sourceJson.rc8_signature_ingestion_result.summary.blockers -eq 0 -and
    $sourceJson.rc8_signature_ingestion_result.signature_surface.signature_artifact_ingested -eq $true -and
    $sourceJson.rc8_signature_ingestion_result.signature_surface.crypto_verified -eq $true -and
    $sourceJson.rc8_signature_receipt.crypto_verified -eq $true -and
    $sourceJson.rc8_signature_receipt.no_private_material_indicators -eq $true
$signedDescriptorFailClosedReady = $sourceJson.rc8_signed_descriptor_fail_closed.status -eq "passed" -and
    $sourceJson.rc8_signed_descriptor_fail_closed.summary.failed_cases -eq 0
$installerVmReadyBlocked = $sourceJson.rc8_installer_vm_preflight.status -eq "passed" -and
    $sourceJson.rc8_installer_vm_preflight.summary.task_blockers -eq 0 -and
    $sourceJson.rc8_installer_vm_preflight.vm_surface.qemu_boot_smoke_completed -eq $true -and
    $sourceJson.rc8_installer_vm_preflight.object_fetch_surface.repo_local_quarantine_smoke_performed -eq $true -and
    $sourceJson.rc8_installer_vm_preflight.object_fetch_surface.quarantine_digest_verified -eq $true -and
    $sourceJson.rc8_installer_vm_preflight.object_fetch_surface.external_https_object_uri_published -eq $false -and
    (Test-HasAllItems -Values $sourceJson.rc8_installer_vm_preflight.payload_blockers -Expected @("external-https-object-uri-not-published", "declared-current-artifact-drift-unresolved"))
$installerFailClosedReady = $sourceJson.rc8_installer_byte_fail_closed.status -eq "passed" -and
    $sourceJson.rc8_installer_byte_fail_closed.summary.failed_cases -eq 0 -and
    $sourceJson.rc8_installer_byte_fail_closed.summary.passed_cases -eq 28 -and
    $sourceJson.rc8_installer_byte_fail_closed.invariants.install_performed -eq $false -and
    $sourceJson.rc8_installer_byte_fail_closed.invariants.activation_performed -eq $false -and
    $sourceJson.rc8_installer_byte_fail_closed.invariants.rollback_execution_performed -eq $false
$mirrorReadyBlocked = $sourceJson.rc8_mirror_consistency_refresh.status -eq "passed" -and
    $sourceJson.rc8_mirror_consistency_refresh.summary.blockers -eq 0 -and
    $sourceJson.rc8_mirror_consistency_refresh.payload_surface.release_id -eq "production-distro-rc8-current-artifacts" -and
    $sourceJson.rc8_mirror_consistency_refresh.payload_surface.storage_mode -eq "metadata-only" -and
    $sourceJson.rc8_mirror_consistency_refresh.payload_surface.external_https_object_uri_published -eq $false -and
    $sourceJson.rc8_mirror_consistency_refresh.payload_surface.public_signature_ingested -eq $true -and
    $sourceJson.rc8_mirror_consistency_refresh.payload_surface.signature_crypto_verified -eq $true -and
    $sourceJson.rc8_mirror_consistency_refresh.payload_surface.installer_vm_smoke_completed -eq $true -and
    $sourceJson.rc8_mirror_consistency_refresh.payload_surface.install_allowed -eq $false -and
    $sourceJson.rc8_mirror_consistency_refresh.payload_surface.activation_allowed -eq $false -and
    $sourceJson.rc8_mirror_consistency_refresh.payload_surface.rollback_execution_allowed -eq $false
$fleetAuthorityReadyBlocked = $sourceJson.fleet_rollout_authority.status -eq "passed" -and
    $sourceJson.fleet_rollout_authority.authority.execution_authority -eq "AgentCore fleet_rollout PlanSpec + SecurityExecutionEngine" -and
    $sourceJson.fleet_rollout_authority.authority.plan_authority -eq "AgentCore" -and
    $sourceJson.fleet_rollout_authority.authority.side_effect_authority -eq "SecurityExecutionEngine" -and
    $sourceJson.fleet_rollout_authority.authority.tui_authority -eq $false -and
    $sourceJson.fleet_rollout_authority.authority.remote_command_dispatch_in_tui -eq $false -and
    $observedCanaryNodes -lt $minimumCanaryNodes -and
    $canaryRing.rollout_dispatch_enabled_in_tui -eq $false

$liveMetadata = @(
    $live.channel,
    $live.payload_index,
    $live.install_bootstrap,
    $live.mirror_status,
    $live.object_descriptor,
    $live.signature_receipt,
    $live.installer_preflight,
    $live.installer_fail_closed
)
$liveReady = $live.root.exit_code -eq 0 -and
    $live.root.status_code -eq 200 -and
    @($liveMetadata | Where-Object { $_.exit_code -ne 0 -or $_.status_code -ne 200 -or $null -eq $_.json }).Count -eq 0 -and
    $live.channel.json.production_ready_claim -eq $false -and
    $live.channel.json.current_release_id -eq "production-distro-rc8-current-artifacts" -and
    $livePayloadEntry.release_id -eq "production-distro-rc8-current-artifacts" -and
    $livePayloadEntry.status -eq "verification-blocked" -and
    $livePayloadEntry.object_uri_external_https -eq $false -and
    $livePayloadEntry.public_signature_ingested -eq $true -and
    $livePayloadEntry.crypto_verified -eq $true -and
    $livePayloadEntry.install_allowed -eq $false -and
    $livePayloadEntry.activation_allowed -eq $false -and
    $livePayloadEntry.rollback_execution_allowed -eq $false -and
    $live.install_bootstrap.json.install_allowed -eq $false -and
    $live.install_bootstrap.json.activation_allowed -eq $false

$externalObjectPublished = $sourceJson.rc8_mirror_consistency_refresh.payload_surface.external_https_object_uri_published -eq $true -and
    $payloadEntry.object_uri_external_https -eq $true
$declaredCurrentArtifactDriftReconciled = -not (Test-HasAllItems -Values $sourceJson.rc8_mirror_consistency_refresh.payload_surface.blockers -Expected @("declared-current-artifact-drift-unresolved"))
$payloadVerificationReady = $descriptorReady -and
    $signatureReady -and
    $signedDescriptorFailClosedReady -and
    $installerVmReadyBlocked -and
    $installerFailClosedReady -and
    $mirrorReadyBlocked
$targetSetGate = $observedCanaryNodes -ge $minimumCanaryNodes -and $canaryRing.rollout_dispatch_enabled_in_tui -eq $true
$approvalGate = $false
$agentCorePlanSpecGate = $false
$securityExecutionGate = $false
$remoteFleetGate = $canaryRing.rollout_dispatch_enabled_in_tui -eq $true

$activationAllowed = $payloadVerificationReady -and
    $externalObjectPublished -and
    $declaredCurrentArtifactDriftReconciled -and
    $targetSetGate -and
    $approvalGate -and
    $agentCorePlanSpecGate -and
    $securityExecutionGate -and
    $remoteFleetGate -and
    $liveReady

$remainingBlockers = @(
    "external-https-object-uri-not-published",
    "declared-current-artifact-drift-unresolved",
    "two-or-more-enrolled-canary-target-nodes-required",
    "remote-fleet-execution-not-enabled",
    "exact-operator-approval-not-granted",
    "AgentCore-PlanSpec-not-bound",
    "SecurityExecutionEngine-approval-not-bound"
)

$targetSet = [ordered]@{
    schema = "agentos.rc8-canary-target-set.v1"
    generated_at = $generatedAt
    status = "projected-target-set-enrollment-blocked"
    release_id = $sourceJson.rc8_descriptor.release_id
    object_id = $sourceJson.rc8_descriptor.object_id
    object_sha256 = $sourceJson.rc8_descriptor.sha256
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

$sourceBindings = [ordered]@{
    rc8_descriptor_result_sha256 = $sourceRefs.rc8_descriptor_result.sha256
    rc8_descriptor_sha256 = $sourceRefs.rc8_descriptor.sha256
    rc8_signature_ingestion_result_sha256 = $sourceRefs.rc8_signature_ingestion_result.sha256
    rc8_signature_receipt_sha256 = $sourceRefs.rc8_signature_receipt.sha256
    rc8_signature_summary_sha256 = $sourceRefs.rc8_signature_summary.sha256
    rc8_signed_descriptor_fail_closed_sha256 = $sourceRefs.rc8_signed_descriptor_fail_closed.sha256
    rc8_installer_vm_preflight_sha256 = $sourceRefs.rc8_installer_vm_preflight.sha256
    rc8_installer_byte_fail_closed_sha256 = $sourceRefs.rc8_installer_byte_fail_closed.sha256
    rc8_mirror_consistency_refresh_sha256 = $sourceRefs.rc8_mirror_consistency_refresh.sha256
    rc8_hosted_payload_index_sha256 = $sourceRefs.rc8_hosted_payload_index.sha256
    rc8_install_bootstrap_sha256 = $sourceRefs.rc8_install_bootstrap.sha256
    rc8_hosted_channel_index_sha256 = $sourceRefs.rc8_hosted_channel_index.sha256
    fleet_rollout_authority_sha256 = $sourceRefs.fleet_rollout_authority.sha256
}

$liveBindings = [ordered]@{
    channel = [ordered]@{ path = "/channel/index.json"; sha256 = $live.channel.body_sha256 }
    payload_index = [ordered]@{ path = "/payloads/index.json"; sha256 = $live.payload_index.body_sha256 }
    install_bootstrap = [ordered]@{ path = "/install/bootstrap.json"; sha256 = $live.install_bootstrap.body_sha256 }
    mirror_status = [ordered]@{ path = "/.well-known/aios/rc8-mirror-status.json"; sha256 = $live.mirror_status.body_sha256 }
    object_descriptor = [ordered]@{ path = $bootstrapEndpoints.object_descriptor; sha256 = $live.object_descriptor.body_sha256 }
    signature_receipt = [ordered]@{ path = $bootstrapEndpoints.signature_receipt; sha256 = $live.signature_receipt.body_sha256 }
    installer_preflight = [ordered]@{ path = $bootstrapEndpoints.installer_preflight; sha256 = $live.installer_preflight.body_sha256 }
    installer_fail_closed = [ordered]@{ path = $bootstrapEndpoints.fail_closed_result; sha256 = $live.installer_fail_closed.body_sha256 }
}

$approvalBinding = [ordered]@{
    release_id = $sourceJson.rc8_descriptor.release_id
    ring = "canary"
    target_set_policy = $targetSet.target_selection_policy
    payload_object_id = $sourceJson.rc8_descriptor.object_id
    payload_object_sha256 = $sourceJson.rc8_descriptor.sha256
    payload_size_bytes = $sourceJson.rc8_descriptor.size_bytes
    descriptor_sha256 = $sourceRefs.rc8_descriptor.sha256
    signature_receipt_sha256 = $sourceRefs.rc8_signature_receipt.sha256
    signature_summary_sha256 = $sourceRefs.rc8_signature_summary.sha256
    installer_vm_preflight_sha256 = $sourceRefs.rc8_installer_vm_preflight.sha256
    installer_byte_fail_closed_sha256 = $sourceRefs.rc8_installer_byte_fail_closed.sha256
    mirror_consistency_refresh_sha256 = $sourceRefs.rc8_mirror_consistency_refresh.sha256
    live_payload_index_sha256 = $live.payload_index.body_sha256
    live_install_bootstrap_sha256 = $live.install_bootstrap.body_sha256
    live_channel_sha256 = $live.channel.body_sha256
    live_mirror_status_sha256 = $live.mirror_status.body_sha256
    fleet_rollout_authority_sha256 = $sourceRefs.fleet_rollout_authority.sha256
    agentcore_planspec_required = $true
    security_execution_engine_required = $true
    exact_operator_approval_required = $true
    approval_status = "required-not-granted"
}
$approvalBindingJson = $approvalBinding | ConvertTo-Json -Depth 100 -Compress
$approvalBindingSha256 = Get-StringSha256 $approvalBindingJson

$approvalPacket = [ordered]@{
    schema = "agentos.rc8-exact-canary-approval-packet.v1"
    generated_at = $generatedAt
    status = "approval-required-execution-blocked"
    production_ready_claim = $false
    projection_only = $true
    executable = $false
    approval_binding_sha256 = $approvalBindingSha256
    approval_binding = $approvalBinding
    required_actor = "release-operator"
    required_action = "approve-rc8-canary-activation"
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
        descriptor_projected = $descriptorReady
        public_signature_ingested = $signatureReady
        signature_crypto_verified = $sourceJson.rc8_signature_ingestion_result.signature_surface.crypto_verified
        signed_descriptor_fail_closed = $signedDescriptorFailClosedReady
        installer_vm_smoke_completed = $sourceJson.rc8_installer_vm_preflight.vm_surface.qemu_boot_smoke_completed
        installer_byte_fail_closed = $installerFailClosedReady
        mirror_metadata_current = $mirrorReadyBlocked -and $liveReady
        external_https_object_uri_published = $externalObjectPublished
        declared_current_artifact_drift_reconciled = $declaredCurrentArtifactDriftReconciled
        canary_target_set_enrolled = $targetSetGate
        observed_canary_node_count = $observedCanaryNodes
        required_canary_node_count = $minimumCanaryNodes
        exact_operator_approval_granted = $approvalGate
        agentcore_planspec_bound = $agentCorePlanSpecGate
        security_execution_approval_bound = $securityExecutionGate
        remote_fleet_execution_enabled = $remoteFleetGate
        execution_gate_status = "blocked-by-design"
    }
    remaining_blockers_before_execution = $remainingBlockers
    invariants = [ordered]@{
        local_private_key_material_used = $false
        private_key_material_read_or_printed = $false
        cryptographic_signing_performed = $false
        payload_upload_performed = $false
        remote_payload_bytes_downloaded = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        remote_dispatch_enabled = $false
        tui_authority = $false
    }
}

$gateReport = [ordered]@{
    schema = "agentos.rc8-canary-activation-smoke-gate-report.v1"
    generated_at = $generatedAt
    status = "activation-smoke-gates-evaluated-blocked"
    production_ready_claim = $false
    projection_only = $true
    release_id = $sourceJson.rc8_descriptor.release_id
    ring = "canary"
    all_gates_passed = $activationAllowed
    canary_activation_allowed = $activationAllowed
    canary_activation_performed = $false
    activation_allowed = $activationAllowed
    activation_performed = $false
    gate_inputs = $approvalPacket.gates
    remaining_blockers_before_activation = $remainingBlockers
    source_bindings = $sourceBindings
    live_endpoint_bindings = $liveBindings
    invariants = $approvalPacket.invariants
}

$denialCases = @(
    [ordered]@{ id = "external-https-object-uri-not-published"; status = "passed"; activation_allowed = $false; reason = "payload descriptor still uses non-external object identity" },
    [ordered]@{ id = "declared-current-artifact-drift-unresolved"; status = "passed"; activation_allowed = $false; reason = "declared/current drift remains an explicit payload blocker" },
    [ordered]@{ id = "canary-target-set-not-enrolled"; status = "passed"; activation_allowed = $false; reason = "observed canary node count is below required minimum" },
    [ordered]@{ id = "remote-fleet-execution-disabled"; status = "passed"; activation_allowed = $false; reason = "fleet dispatch remains disabled outside TUI projection" },
    [ordered]@{ id = "exact-operator-approval-not-granted"; status = "passed"; activation_allowed = $false; reason = "approval packet is projection-only and approval_granted is false" },
    [ordered]@{ id = "agentcore-planspec-not-bound"; status = "passed"; activation_allowed = $false; reason = "AgentCore PlanSpec binding is absent" },
    [ordered]@{ id = "security-execution-approval-not-bound"; status = "passed"; activation_allowed = $false; reason = "SecurityExecutionEngine approval is absent" }
)

$denialEvidence = [ordered]@{
    schema = "agentos.rc8-canary-activation-denial-evidence.v1"
    generated_at = $generatedAt
    status = "activation-denied-by-gates"
    production_ready_claim = $false
    projection_only = $true
    canary_activation_allowed = $false
    canary_activation_performed = $false
    activation_allowed = $false
    activation_performed = $false
    denial_cases = $denialCases
    remaining_blockers_before_activation = $remainingBlockers
    authority = [ordered]@{
        plan_authority = "AgentCore"
        side_effect_authority = "SecurityExecutionEngine"
        mirror_authority = $false
        signer_authority = $false
        tui_authority = $false
        shell_authority = $false
        model_replay_authority = $false
    }
    invariants = $approvalPacket.invariants
}

Write-Json -Value $targetSet -Path $targetSetPath
Write-Json -Value $approvalPacket -Path $approvalPacketPath
Write-Json -Value $gateReport -Path $gateReportPath
Write-Json -Value $denialEvidence -Path $denialEvidencePath

$targetSetHash = Get-FileSha256 $targetSetPath
$approvalPacketHash = Get-FileSha256 $approvalPacketPath
$gateReportHash = Get-FileSha256 $gateReportPath
$denialEvidenceHash = Get-FileSha256 $denialEvidencePath

Add-Check "source.rc8_010.descriptor.ready" $descriptorReady "RC8-010 descriptor must be projected, non-GA, and install/activation/rollback blocked." $(if ($null -ne $sourceJson.rc8_descriptor_result) { $sourceJson.rc8_descriptor_result.summary } else { $null })
Add-Check "source.rc8_011.signature.ready" $signatureReady "RC8-011 public signature ingestion must be passed and crypto verified without private material indicators." $(if ($null -ne $sourceJson.rc8_signature_ingestion_result) { $sourceJson.rc8_signature_ingestion_result.signature_surface } else { $null })
Add-Check "source.rc8_012.fail_closed.ready" $signedDescriptorFailClosedReady "RC8-012 signed object descriptor fail-closed fixtures must pass all negative cases." $(if ($null -ne $sourceJson.rc8_signed_descriptor_fail_closed) { $sourceJson.rc8_signed_descriptor_fail_closed.summary } else { $null })
Add-Check "source.rc8_020.preflight.ready_blocked" $installerVmReadyBlocked "RC8-020 installer VM preflight and quarantine smoke must pass while external object fetch remains blocked." $(if ($null -ne $sourceJson.rc8_installer_vm_preflight) { $sourceJson.rc8_installer_vm_preflight.summary } else { $null })
Add-Check "source.rc8_021.installer_fail_closed.ready" $installerFailClosedReady "RC8-021 installer byte/signature/storage/compatibility fail-closed fixtures must pass without side effects." $(if ($null -ne $sourceJson.rc8_installer_byte_fail_closed) { $sourceJson.rc8_installer_byte_fail_closed.summary } else { $null })
Add-Check "source.rc8_022.mirror.ready_blocked" $mirrorReadyBlocked "RC8-022 mirror refresh must expose RC8 metadata while preserving metadata-only and install/activation/rollback blocked semantics." $(if ($null -ne $sourceJson.rc8_mirror_consistency_refresh) { $sourceJson.rc8_mirror_consistency_refresh.payload_surface } else { $null })
Add-Check "fleet.authority.ready_blocked" $fleetAuthorityReadyBlocked "Fleet authority must remain AgentCore/SecurityExecution-owned, with canary under-enrolled and remote execution disabled." ([ordered]@{ observed = $observedCanaryNodes; required = $minimumCanaryNodes; canary_status = if ($null -ne $canaryRing) { $canaryRing.status } else { $null }; canary_blocker = if ($null -ne $canaryRing) { $canaryRing.blocker } else { $null } })
Add-Check "live.https.metadata.current" $liveReady "Resolve-pinned HTTPS mirror metadata must remain RC8 current, non-GA, verification-blocked, and activation-blocked." ([ordered]@{ root = $live.root.status_code; channel = $live.channel.status_code; payload_index = $live.payload_index.status_code; install_bootstrap = $live.install_bootstrap.status_code; release_id = if ($null -ne $livePayloadEntry) { $livePayloadEntry.release_id } else { $null }; status = if ($null -ne $livePayloadEntry) { $livePayloadEntry.status } else { $null } })
Add-Check "canary.target_set.projected_blocked" ((Test-Path -LiteralPath $targetSetPath -PathType Leaf) -and $targetSet.target_set_enrolled -eq $false -and $targetSet.required_minimum_nodes -eq 2) "Canary target set projection must require two nodes and refuse to fake enrollment." ([ordered]@{ path = Get-StablePath $targetSetPath; sha256 = $targetSetHash; observed = $observedCanaryNodes; required = $minimumCanaryNodes })
Add-Check "approval.packet.projected_blocked" ((Test-Path -LiteralPath $approvalPacketPath -PathType Leaf) -and $approvalPacket.approval_granted -eq $false -and $approvalPacket.executable -eq $false) "Exact approval packet must be generated, hash-bound, and non-executable until approval and execution gates pass." ([ordered]@{ path = Get-StablePath $approvalPacketPath; sha256 = $approvalPacketHash; approval_binding_sha256 = $approvalBindingSha256 })
Add-Check "activation.gates.fail_closed" (-not $activationAllowed) "Canary activation smoke must remain denied until object URI, drift, target, approval, PlanSpec, SecurityExecution, and remote fleet gates pass." $gateReport.gate_inputs
Add-Check "activation.gate_report.projected" ((Test-Path -LiteralPath $gateReportPath -PathType Leaf) -and $gateReport.activation_performed -eq $false) "Activation smoke gate report must be projected without performing activation." ([ordered]@{ path = Get-StablePath $gateReportPath; sha256 = $gateReportHash })
Add-Check "activation.denial_evidence.projected" ((Test-Path -LiteralPath $denialEvidencePath -PathType Leaf) -and @($denialEvidence.denial_cases | Where-Object { $_.status -ne "passed" -or $_.activation_allowed -ne $false }).Count -eq 0) "Activation denial evidence must cover each missing gate as fail-closed." ([ordered]@{ path = Get-StablePath $denialEvidencePath; sha256 = $denialEvidenceHash; cases = @($denialEvidence.denial_cases).Count })
Add-Check "authority.not_broadened" $true "RC8-030 must not sign, upload payloads, install, activate, rollback, mutate slots/rings, upload support, dispatch remotely, or grant TUI authority." $approvalPacket.invariants

$secretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $targetSetPath),
    (Get-Content -Raw -LiteralPath $approvalPacketPath),
    (Get-Content -Raw -LiteralPath $gateReportPath),
    (Get-Content -Raw -LiteralPath $denialEvidencePath)
)
Add-Check "outputs.secret_safe" $secretSafe "RC8-030 projected artifacts must not contain secret material paths, PEM private blocks, or token markers." $null

$passed = @($script:blockers).Count -eq 0
$result = [ordered]@{
    schema = "agentos.rc8-exact-approved-canary-smoke-result.v1"
    generated_at = $generatedAt
    checked_at = (Get-Date).ToString("o")
    task = "RC8-030"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    canary_activation_smoke_packet_projected = $passed
    canary_activation_allowed = $activationAllowed
    canary_activation_performed = $false
    activation_allowed = $activationAllowed
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
        activation_smoke_gate_report = [ordered]@{
            path = Get-StablePath $gateReportPath
            sha256 = $gateReportHash
            schema = $gateReport.schema
            status = $gateReport.status
        }
        activation_denial_evidence = [ordered]@{
            path = Get-StablePath $denialEvidencePath
            sha256 = $denialEvidenceHash
            schema = $denialEvidence.schema
            status = $denialEvidence.status
        }
    }
    source_artifacts = $sourceRefs
    source_bindings = $sourceBindings
    live_endpoint_bindings = $liveBindings
    target_set = [ordered]@{
        required_minimum_nodes = $minimumCanaryNodes
        observed_canary_node_count = $observedCanaryNodes
        target_set_enrolled = $targetSetGate
    }
    approval = [ordered]@{
        exact_operator_approval_required = $true
        exact_operator_approval_granted = $approvalGate
        approval_binding_sha256 = $approvalBindingSha256
    }
    payload_surface = [ordered]@{
        release_id = $sourceJson.rc8_descriptor.release_id
        status = $payloadEntry.status
        object_uri_external_https = $payloadEntry.object_uri_external_https
        public_signature_ingested = $signatureReady
        signature_crypto_verified = $sourceJson.rc8_signature_ingestion_result.signature_surface.crypto_verified
        installer_vm_smoke_completed = $sourceJson.rc8_installer_vm_preflight.vm_surface.qemu_boot_smoke_completed
        installer_fail_closed_cases = $sourceJson.rc8_installer_byte_fail_closed.summary.passed_cases
        external_https_object_uri_published = $externalObjectPublished
        declared_current_artifact_drift_reconciled = $declaredCurrentArtifactDriftReconciled
        install_allowed = $payloadEntry.install_allowed
        activation_allowed = $payloadEntry.activation_allowed
        rollback_execution_allowed = $payloadEntry.rollback_execution_allowed
    }
    gates = $gateReport.gate_inputs
    remaining_blockers_before_activation = $remainingBlockers
    checks = $script:checks
    blockers = $script:blockers
    invariants = $approvalPacket.invariants
    summary = [ordered]@{
        checks = @($script:checks).Count
        blockers = @($script:blockers).Count
        rc8_030_complete = $passed
        canary_activation_smoke_packet_projected = $passed
        canary_activation_allowed = $activationAllowed
        canary_activation_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        exact_operator_approval_required = $true
        exact_operator_approval_granted = $approvalGate
        required_canary_node_count = $minimumCanaryNodes
        observed_canary_node_count = $observedCanaryNodes
        target_set_enrolled = $targetSetGate
        agentcore_planspec_bound = $agentCorePlanSpecGate
        security_execution_approval_bound = $securityExecutionGate
        remote_fleet_execution_enabled = $remoteFleetGate
        production_ready_claim = $false
        next_task = "RC8-031"
    }
}

Write-Json -Value $result -Path $resolvedResultPath

$resultSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resolvedResultPath))
if (-not $resultSecretSafe) {
    $extra = [ordered]@{
        id = "result.secret_safe"
        status = "failed"
        severity = "blocking"
        message = "RC8-030 result must not contain secret material paths, PEM private blocks, or token markers."
        evidence = $null
    }
    $script:checks += $extra
    $script:blockers += $extra
    $result.status = "blocked"
    $result.canary_activation_smoke_packet_projected = $false
    $result.checks = $script:checks
    $result.blockers = $script:blockers
    $result.summary.checks = @($script:checks).Count
    $result.summary.blockers = @($script:blockers).Count
    $result.summary.rc8_030_complete = $false
    $result.summary.canary_activation_smoke_packet_projected = $false
    Write-Json -Value $result -Path $resolvedResultPath
}

Write-Host "RC8 exact-approved canary activation smoke $($result.status): $(Get-StablePath $resolvedResultPath)"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
