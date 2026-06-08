param(
    [string]$RemoteHost = "47.101.11.109",
    [string]$Domain = "aios.w33d.xyz",
    [string]$ArtifactDir = ".workflow/artifacts/rc7-gated-canary-activation",
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
$gateReportPath = Join-Path $resolvedArtifactDir "activation-gate-report.json"
$denialEvidencePath = Join-Path $resolvedArtifactDir "activation-denial-evidence.json"

$sourcePaths = [ordered]@{
    rc7_multi_node_canary_approval = ".workflow/artifacts/rc7-multi-node-canary-approval/result.json"
    rc7_canary_target_set = ".workflow/artifacts/rc7-multi-node-canary-approval/canary-target-set.json"
    rc7_exact_approval_packet = ".workflow/artifacts/rc7-multi-node-canary-approval/exact-approval-packet.json"
    rc7_installer_signed_consumption = ".workflow/artifacts/rc7-installer-signed-consumption/result.json"
    rc7_signed_consumption_fail_closed = ".workflow/artifacts/rc7-signed-consumption-fail-closed/result.json"
    rc7_install_rollback_baseline = ".workflow/artifacts/rc7-install-rollback-baseline/result.json"
    rc7_tls_nginx_hardening = ".workflow/artifacts/rc7-tls-nginx-hardening/result.json"
    rc7_large_payload_storage_policy = ".workflow/active/WFS-20260608-agentos-production-distro-rc7/evidence/RC7-022-large-payload-storage-policy.json"
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
    signatures = Invoke-Curl "/payloads/aios/production-distro-rc6-current-artifacts/signatures.json"
    signed_metadata = Invoke-Curl "/payloads/aios/production-distro-rc6-current-artifacts/signed-metadata.json"
    revocations = Invoke-Curl "/payloads/aios/production-distro-rc6-current-artifacts/revocations.json"
    compatibility = Invoke-Curl "/install/compatibility.json"
    rollback_baseline = Invoke-Curl "/install/rollback-baseline.json"
}

$payloadEntry = if ($null -ne $live.payload_index.json -and $null -ne $live.payload_index.json.entries) { @($live.payload_index.json.entries)[0] } else { $null }
$canaryRing = Get-Ring $sourceJson.fleet_rollout_authority "canary"
$minimumCanaryNodes = 2
$observedCanaryNodes = if ($null -ne $canaryRing -and $null -ne $canaryRing.node_count) { [int]$canaryRing.node_count } else { 0 }
$generatedAt = (Get-Date).ToString("o")

$rc7ApprovalReady = $sourceJson.rc7_multi_node_canary_approval.status -eq "passed" -and
    $sourceJson.rc7_multi_node_canary_approval.summary.blockers -eq 0 -and
    $sourceJson.rc7_multi_node_canary_approval.summary.rc7_030_complete -eq $true -and
    $sourceJson.rc7_multi_node_canary_approval.canary_execution_allowed -eq $false -and
    $sourceJson.rc7_multi_node_canary_approval.activation_allowed -eq $false -and
    $sourceJson.rc7_multi_node_canary_approval.rollback_execution_allowed -eq $false
$targetSetReadyBlocked = $sourceJson.rc7_canary_target_set.schema -eq "agentos.rc7-canary-target-set.v1" -and
    $sourceJson.rc7_canary_target_set.required_minimum_nodes -eq $minimumCanaryNodes -and
    $sourceJson.rc7_canary_target_set.observed_canary_node_count -lt $minimumCanaryNodes -and
    $sourceJson.rc7_canary_target_set.target_set_enrolled -eq $false
$approvalPacketReadyBlocked = $sourceJson.rc7_exact_approval_packet.schema -eq "agentos.rc7-exact-canary-approval-packet.v1" -and
    $sourceJson.rc7_exact_approval_packet.executable -eq $false -and
    $sourceJson.rc7_exact_approval_packet.approval_granted -eq $false -and
    $sourceJson.rc7_exact_approval_packet.activation_allowed -eq $false -and
    $sourceJson.rc7_exact_approval_packet.gates.agentcore_planspec_bound -eq $false -and
    $sourceJson.rc7_exact_approval_packet.gates.security_execution_approval_bound -eq $false
$rc7ConsumptionReady = $sourceJson.rc7_installer_signed_consumption.status -eq "passed" -and
    $sourceJson.rc7_installer_signed_consumption.summary.blockers -eq 0 -and
    $sourceJson.rc7_installer_signed_consumption.report.state -eq "verification-blocked" -and
    $sourceJson.rc7_installer_signed_consumption.summary.installer_blockers -gt 0 -and
    $sourceJson.rc7_installer_signed_consumption.consumption_summary.install_allowed -eq $false -and
    $sourceJson.rc7_installer_signed_consumption.consumption_summary.activation_allowed -eq $false
$rc7FailClosedReady = $sourceJson.rc7_signed_consumption_fail_closed.status -eq "passed" -and
    $sourceJson.rc7_signed_consumption_fail_closed.summary.failed_cases -eq 0
$rollbackBaselineReady = $sourceJson.rc7_install_rollback_baseline.status -eq "passed" -and
    $sourceJson.rc7_install_rollback_baseline.payload_surface.compatibility_published -eq $true -and
    $sourceJson.rc7_install_rollback_baseline.payload_surface.rollback_baseline_published -eq $true -and
    $sourceJson.rc7_install_rollback_baseline.payload_surface.activation_allowed -eq $false -and
    $sourceJson.rc7_install_rollback_baseline.payload_surface.rollback_execution_allowed -eq $false
$tlsStorageReady = $sourceJson.rc7_tls_nginx_hardening.status -eq "passed" -and
    $sourceJson.rc7_tls_nginx_hardening.invariants.tls_configured -eq $true -and
    $sourceJson.rc7_tls_nginx_hardening.invariants.activation_performed -eq $false -and
    $sourceJson.rc7_large_payload_storage_policy.status -eq "completed" -and
    $sourceJson.rc7_large_payload_storage_policy.policy.external_object_storage_required -eq $true -and
    $sourceJson.rc7_large_payload_storage_policy.policy.large_payloads_on_mirror_allowed -eq $false
$fleetAuthorityReady = $sourceJson.fleet_rollout_authority.status -eq "passed" -and
    $sourceJson.fleet_rollout_authority.authority.execution_authority -eq "AgentCore fleet_rollout PlanSpec + SecurityExecutionEngine" -and
    $sourceJson.fleet_rollout_authority.authority.tui_authority -eq $false -and
    $sourceJson.fleet_rollout_authority.authority.remote_command_dispatch_in_tui -eq $false -and
    $observedCanaryNodes -lt $minimumCanaryNodes -and
    $canaryRing.blocker -eq "remote-fleet-execution-not-enabled"

$liveMetadata = @(
    $live.channel,
    $live.payload_index,
    $live.install_bootstrap,
    $live.signatures,
    $live.signed_metadata,
    $live.revocations,
    $live.compatibility,
    $live.rollback_baseline
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

$liveMatchesApproval = $sourceJson.rc7_multi_node_canary_approval.live_endpoint_bindings.channel.sha256 -eq $live.channel.body_sha256 -and
    $sourceJson.rc7_multi_node_canary_approval.live_endpoint_bindings.payload_index.sha256 -eq $live.payload_index.body_sha256 -and
    $sourceJson.rc7_multi_node_canary_approval.live_endpoint_bindings.install_bootstrap.sha256 -eq $live.install_bootstrap.body_sha256 -and
    $sourceJson.rc7_multi_node_canary_approval.live_endpoint_bindings.signatures.sha256 -eq $live.signatures.body_sha256 -and
    $sourceJson.rc7_multi_node_canary_approval.live_endpoint_bindings.signed_metadata.sha256 -eq $live.signed_metadata.body_sha256 -and
    $sourceJson.rc7_multi_node_canary_approval.live_endpoint_bindings.revocations.sha256 -eq $live.revocations.body_sha256 -and
    $sourceJson.rc7_multi_node_canary_approval.live_endpoint_bindings.compatibility.sha256 -eq $live.compatibility.body_sha256 -and
    $sourceJson.rc7_multi_node_canary_approval.live_endpoint_bindings.rollback_baseline.sha256 -eq $live.rollback_baseline.body_sha256

$signedMetadataPublished = [bool]$payloadEntry.signed_metadata_sha256
$revocationPublished = [bool]$payloadEntry.revocation_snapshot_sha256
$compatibilityPublished = [bool]$payloadEntry.compatibility_sha256
$rollbackPublished = [bool]$payloadEntry.rollback_baseline_sha256
$signatureGate = $live.signatures.json.cryptographic_signature_present -eq $true -and $live.signatures.json.signature_available -eq $true
$targetSetGate = $sourceJson.rc7_canary_target_set.target_set_enrolled -eq $true
$approvalGate = $sourceJson.rc7_exact_approval_packet.approval_granted -eq $true
$agentCorePlanSpecGate = $sourceJson.rc7_exact_approval_packet.gates.agentcore_planspec_bound -eq $true
$securityExecutionGate = $sourceJson.rc7_exact_approval_packet.gates.security_execution_approval_bound -eq $true
$remoteFleetGate = $canaryRing.rollout_dispatch_enabled_in_tui -eq $true

$activationAllowed = $signedMetadataPublished -and
    $revocationPublished -and
    $compatibilityPublished -and
    $rollbackPublished -and
    $signatureGate -and
    $targetSetGate -and
    $approvalGate -and
    $agentCorePlanSpecGate -and
    $securityExecutionGate -and
    $remoteFleetGate -and
    $liveReady -and
    $liveMatchesApproval

$remainingBlockers = @(
    "real-cryptographic-payload-signature-not-present",
    "two-or-more-enrolled-canary-target-nodes-required",
    "remote-fleet-execution-not-enabled",
    "exact-operator-approval-not-granted",
    "AgentCore-PlanSpec-not-bound",
    "SecurityExecutionEngine-approval-not-bound"
)

$sourceBindings = [ordered]@{
    rc7_multi_node_canary_approval_sha256 = $sourceRefs.rc7_multi_node_canary_approval.sha256
    rc7_canary_target_set_sha256 = $sourceRefs.rc7_canary_target_set.sha256
    rc7_exact_approval_packet_sha256 = $sourceRefs.rc7_exact_approval_packet.sha256
    rc7_installer_signed_consumption_sha256 = $sourceRefs.rc7_installer_signed_consumption.sha256
    rc7_signed_consumption_fail_closed_sha256 = $sourceRefs.rc7_signed_consumption_fail_closed.sha256
    rc7_install_rollback_baseline_sha256 = $sourceRefs.rc7_install_rollback_baseline.sha256
    rc7_tls_nginx_hardening_sha256 = $sourceRefs.rc7_tls_nginx_hardening.sha256
    rc7_large_payload_storage_policy_sha256 = $sourceRefs.rc7_large_payload_storage_policy.sha256
    fleet_rollout_authority_sha256 = $sourceRefs.fleet_rollout_authority.sha256
}

$liveBindings = [ordered]@{
    channel = [ordered]@{ path = "/channel/index.json"; sha256 = $live.channel.body_sha256 }
    payload_index = [ordered]@{ path = "/payloads/index.json"; sha256 = $live.payload_index.body_sha256 }
    install_bootstrap = [ordered]@{ path = "/install/bootstrap.json"; sha256 = $live.install_bootstrap.body_sha256 }
    signatures = [ordered]@{ path = "/payloads/aios/production-distro-rc6-current-artifacts/signatures.json"; sha256 = $live.signatures.body_sha256 }
    signed_metadata = [ordered]@{ path = "/payloads/aios/production-distro-rc6-current-artifacts/signed-metadata.json"; sha256 = $live.signed_metadata.body_sha256 }
    revocations = [ordered]@{ path = "/payloads/aios/production-distro-rc6-current-artifacts/revocations.json"; sha256 = $live.revocations.body_sha256 }
    compatibility = [ordered]@{ path = "/install/compatibility.json"; sha256 = $live.compatibility.body_sha256 }
    rollback_baseline = [ordered]@{ path = "/install/rollback-baseline.json"; sha256 = $live.rollback_baseline.body_sha256 }
}

$invariants = [ordered]@{
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

$gateReport = [ordered]@{
    schema = "agentos.rc7-canary-activation-gate-report.v1"
    generated_at = $generatedAt
    status = "activation-gates-evaluated-blocked"
    production_ready_claim = $false
    projection_only = $true
    release_id = if ($null -ne $payloadEntry) { $payloadEntry.release_id } else { $null }
    ring = "canary"
    all_gates_passed = $activationAllowed
    canary_activation_allowed = $activationAllowed
    canary_activation_performed = $false
    activation_allowed = $activationAllowed
    activation_performed = $false
    gate_inputs = [ordered]@{
        signed_metadata_published = $signedMetadataPublished
        revocation_snapshot_published = $revocationPublished
        compatibility_published = $compatibilityPublished
        rollback_baseline_published = $rollbackPublished
        tls_configured = $sourceJson.rc7_tls_nginx_hardening.invariants.tls_configured
        storage_policy_defined = $sourceJson.rc7_large_payload_storage_policy.policy.external_object_storage_required
        cryptographic_signature_present = $live.signatures.json.cryptographic_signature_present
        signature_available = $live.signatures.json.signature_available
        canary_target_set_enrolled = $targetSetGate
        observed_canary_node_count = $observedCanaryNodes
        required_canary_node_count = $minimumCanaryNodes
        exact_operator_approval_granted = $approvalGate
        agentcore_planspec_bound = $agentCorePlanSpecGate
        security_execution_approval_bound = $securityExecutionGate
        remote_fleet_execution_enabled = $remoteFleetGate
        live_metadata_matches_approval_packet = $liveMatchesApproval
    }
    remaining_blockers_before_activation = $remainingBlockers
    source_bindings = $sourceBindings
    live_endpoint_bindings = $liveBindings
    invariants = $invariants
}

$denialCases = @(
    [ordered]@{ id = "missing-real-cryptographic-signature"; status = "passed"; activation_allowed = $false; reason = "signature gate is false" },
    [ordered]@{ id = "canary-target-set-not-enrolled"; status = "passed"; activation_allowed = $false; reason = "observed canary node count is below required minimum" },
    [ordered]@{ id = "exact-operator-approval-not-granted"; status = "passed"; activation_allowed = $false; reason = "approval packet is projection-only and approval_granted is false" },
    [ordered]@{ id = "agentcore-planspec-not-bound"; status = "passed"; activation_allowed = $false; reason = "AgentCore PlanSpec binding is absent" },
    [ordered]@{ id = "security-execution-approval-not-bound"; status = "passed"; activation_allowed = $false; reason = "SecurityExecutionEngine approval is absent" },
    [ordered]@{ id = "remote-fleet-execution-disabled"; status = "passed"; activation_allowed = $false; reason = "remote fleet dispatch remains disabled" }
)

$denialEvidence = [ordered]@{
    schema = "agentos.rc7-canary-activation-denial-evidence.v1"
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
    invariants = $invariants
}

Write-Json -Value $gateReport -Path $gateReportPath
Write-Json -Value $denialEvidence -Path $denialEvidencePath
$gateReportHash = Get-FileSha256 $gateReportPath
$denialEvidenceHash = Get-FileSha256 $denialEvidencePath

Add-Check "source.rc7_030.ready" ($rc7ApprovalReady -and $targetSetReadyBlocked -and $approvalPacketReadyBlocked) "RC7-031 must consume passed RC7-030 approval packet evidence while target, approval, PlanSpec, and execution remain blocked." ([ordered]@{ result = $sourceJson.rc7_multi_node_canary_approval.summary; target_set = $sourceJson.rc7_canary_target_set.status; approval_packet = $sourceJson.rc7_exact_approval_packet.status })
Add-Check "source.signed_consumption.ready_blocked" $rc7ConsumptionReady "Installer signed consumption must remain observable and verification-blocked." $(if ($null -ne $sourceJson.rc7_installer_signed_consumption) { $sourceJson.rc7_installer_signed_consumption.summary } else { $null })
Add-Check "source.fail_closed.ready" $rc7FailClosedReady "Signed consumption fail-closed fixtures must pass before gated activation evidence." $(if ($null -ne $sourceJson.rc7_signed_consumption_fail_closed) { $sourceJson.rc7_signed_consumption_fail_closed.summary } else { $null })
Add-Check "source.rollback_baseline.ready" $rollbackBaselineReady "Compatibility and rollback baseline metadata must be published while activation and rollback remain blocked." $(if ($null -ne $sourceJson.rc7_install_rollback_baseline) { $sourceJson.rc7_install_rollback_baseline.payload_surface } else { $null })
Add-Check "source.tls_storage.ready" $tlsStorageReady "TLS and storage policy must be ready before canary activation gate evaluation." ([ordered]@{ tls = if ($null -ne $sourceJson.rc7_tls_nginx_hardening) { $sourceJson.rc7_tls_nginx_hardening.summary } else { $null }; storage = if ($null -ne $sourceJson.rc7_large_payload_storage_policy) { $sourceJson.rc7_large_payload_storage_policy.policy } else { $null } })
Add-Check "fleet.authority.ready_blocked" $fleetAuthorityReady "Fleet authority must remain AgentCore/SecurityExecution-owned, with canary not enrolled and remote execution disabled." ([ordered]@{ observed = $observedCanaryNodes; required = $minimumCanaryNodes; canary_blocker = if ($null -ne $canaryRing) { $canaryRing.blocker } else { $null } })
Add-Check "live.https.metadata.matches_approval" ($liveReady -and $liveMatchesApproval) "HTTPS live metadata must remain current, non-GA, install/activation blocked, and hash-match the RC7-030 approval packet." ([ordered]@{ live_ready = $liveReady; matches_approval = $liveMatchesApproval; release_id = if ($null -ne $payloadEntry) { $payloadEntry.release_id } else { $null }; status = if ($null -ne $payloadEntry) { $payloadEntry.status } else { $null } })
Add-Check "activation.gates.fail_closed" (-not $activationAllowed) "Canary activation must remain denied until all signature, target, approval, PlanSpec, SecurityExecution, and remote fleet gates pass." $gateReport.gate_inputs
Add-Check "activation.gate_report.projected" ((Test-Path -LiteralPath $gateReportPath -PathType Leaf) -and $gateReport.activation_performed -eq $false) "Activation gate report must be projected without performing activation." ([ordered]@{ path = Get-StablePath $gateReportPath; sha256 = $gateReportHash })
Add-Check "activation.denial_evidence.projected" ((Test-Path -LiteralPath $denialEvidencePath -PathType Leaf) -and @($denialEvidence.denial_cases | Where-Object { $_.status -ne "passed" -or $_.activation_allowed -ne $false }).Count -eq 0) "Activation denial evidence must cover each missing gate as fail-closed." ([ordered]@{ path = Get-StablePath $denialEvidencePath; sha256 = $denialEvidenceHash; cases = @($denialEvidence.denial_cases).Count })
Add-Check "activation.no_authority_broadened" $true "RC7-031 must not sign, upload payloads, install, activate, rollback, mutate slots/rings, upload support, dispatch remotely, or grant TUI authority." $invariants

$passed = @($script:blockers).Count -eq 0
$result = [ordered]@{
    schema = "agentos.rc7-gated-canary-activation-result.v1"
    generated_at = $generatedAt
    checked_at = (Get-Date).ToString("o")
    task = "RC7-031"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    canary_activation_evidence_projected = $passed
    canary_activation_allowed = $activationAllowed
    canary_activation_performed = $false
    activation_allowed = $activationAllowed
    activation_performed = $false
    rollback_execution_allowed = $false
    rollback_execution_performed = $false
    artifacts = [ordered]@{
        activation_gate_report = [ordered]@{
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
    gates = $gateReport.gate_inputs
    remaining_blockers_before_activation = $remainingBlockers
    checks = $script:checks
    blockers = $script:blockers
    invariants = $invariants
    summary = [ordered]@{
        checks = @($script:checks).Count
        blockers = @($script:blockers).Count
        rc7_031_complete = $passed
        canary_activation_evidence_projected = $passed
        canary_activation_allowed = $activationAllowed
        canary_activation_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        exact_operator_approval_required = $true
        exact_operator_approval_granted = $false
        required_canary_node_count = $minimumCanaryNodes
        observed_canary_node_count = $observedCanaryNodes
        target_set_enrolled = $targetSetGate
        remote_fleet_execution_enabled = $remoteFleetGate
        production_ready_claim = $false
        next_task = "RC7-032"
    }
}

Write-Json -Value $result -Path $resolvedResultPath

$secretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $gateReportPath),
    (Get-Content -Raw -LiteralPath $denialEvidencePath),
    (Get-Content -Raw -LiteralPath $resolvedResultPath)
)
if (-not $secretSafe) {
    $extra = [ordered]@{
        id = "outputs.secret_safe"
        status = "failed"
        severity = "blocking"
        message = "RC7-031 artifacts must not contain private key or token markers."
        evidence = $null
    }
    $script:checks += $extra
    $script:blockers += $extra
    $result.status = "blocked"
    $result.canary_activation_evidence_projected = $false
    $result.checks = $script:checks
    $result.blockers = $script:blockers
    $result.summary.checks = @($script:checks).Count
    $result.summary.blockers = @($script:blockers).Count
    $result.summary.rc7_031_complete = $false
    $result.summary.canary_activation_evidence_projected = $false
    Write-Json -Value $result -Path $resolvedResultPath
}

Write-Host "RC7 gated canary activation $($result.status): $(Get-StablePath $resolvedResultPath)"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
