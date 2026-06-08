param(
    [string]$RemoteHost = "47.101.11.109",
    [string]$Domain = "aios.w33d.xyz",
    [string]$ArtifactDir = ".workflow/artifacts/rc8-controlled-rollback-drill",
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
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & curl.exe @args 2>&1
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
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
$planSpecRequirementPath = Join-Path $resolvedArtifactDir "rollback-planspec-requirement.json"
$gateReportPath = Join-Path $resolvedArtifactDir "rollback-drill-gate-report.json"
$denialEvidencePath = Join-Path $resolvedArtifactDir "rollback-drill-denial-evidence.json"

$sourcePaths = [ordered]@{
    rc8_canary_smoke = ".workflow/artifacts/rc8-exact-approved-canary-smoke/result.json"
    rc8_canary_target_set = ".workflow/artifacts/rc8-exact-approved-canary-smoke/canary-target-set.json"
    rc8_exact_approval_packet = ".workflow/artifacts/rc8-exact-approved-canary-smoke/exact-approval-packet.json"
    rc8_activation_gate_report = ".workflow/artifacts/rc8-exact-approved-canary-smoke/activation-smoke-gate-report.json"
    rc8_activation_denial_evidence = ".workflow/artifacts/rc8-exact-approved-canary-smoke/activation-denial-evidence.json"
    rc8_descriptor = ".workflow/artifacts/rc8-real-payload-object-descriptor/payload-object-descriptor.json"
    rc8_signature_ingestion_result = ".workflow/artifacts/rc8-public-signature-ingestion/result.json"
    rc8_signature_receipt = ".workflow/artifacts/rc8-public-signature-ingestion/signature-ingestion-receipt.json"
    rc8_installer_vm_preflight = ".workflow/artifacts/rc8-installer-vm-preflight/result.json"
    rc8_installer_byte_fail_closed = ".workflow/artifacts/rc8-installer-byte-fail-closed/result.json"
    rc8_mirror_consistency_refresh = ".workflow/artifacts/rc8-mirror-consistency-refresh/result.json"
    rc8_hosted_payload_index = ".workflow/artifacts/rc8-mirror-consistency-refresh/hosted-payload-index.json"
    rc8_install_bootstrap = ".workflow/artifacts/rc8-mirror-consistency-refresh/install-bootstrap.json"
    rc7_rollback_baseline_result = ".workflow/artifacts/rc7-install-rollback-baseline/result.json"
    rc7_rollback_baseline = ".workflow/artifacts/rc7-install-rollback-baseline/rollback-baseline.json"
    rc6_rollback_preconditions_result = ".workflow/artifacts/rc6-rollback-execution-preconditions/result.json"
    rc6_rollback_matrix = ".workflow/artifacts/rc6-rollback-execution-preconditions/rollback-drill-precondition-matrix.json"
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

$payloadEntry = if ($null -ne $sourceJson.rc8_hosted_payload_index -and $null -ne $sourceJson.rc8_hosted_payload_index.entries) {
    @($sourceJson.rc8_hosted_payload_index.entries)[0]
} else {
    $null
}
$bootstrapEndpoints = $sourceJson.rc8_install_bootstrap.endpoints
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
    compatibility = Invoke-Curl $bootstrapEndpoints.compatibility
    rollback_baseline = Invoke-Curl $bootstrapEndpoints.rollback_baseline
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

$rc8ActivationReadyBlocked = $sourceJson.rc8_canary_smoke.status -eq "passed" -and
    $sourceJson.rc8_canary_smoke.summary.blockers -eq 0 -and
    $sourceJson.rc8_canary_smoke.summary.rc8_030_complete -eq $true -and
    $sourceJson.rc8_canary_smoke.canary_activation_allowed -eq $false -and
    $sourceJson.rc8_canary_smoke.canary_activation_performed -eq $false -and
    $sourceJson.rc8_canary_smoke.rollback_execution_performed -eq $false -and
    $sourceJson.rc8_activation_gate_report.activation_performed -eq $false -and
    $sourceJson.rc8_activation_denial_evidence.activation_allowed -eq $false
$rc8ApprovalReadyBlocked = $sourceJson.rc8_exact_approval_packet.approval_granted -eq $false -and
    $sourceJson.rc8_exact_approval_packet.executable -eq $false -and
    $sourceJson.rc8_exact_approval_packet.gates.agentcore_planspec_bound -eq $false -and
    $sourceJson.rc8_exact_approval_packet.gates.security_execution_approval_bound -eq $false -and
    $sourceJson.rc8_canary_target_set.target_set_enrolled -eq $false
$rc8PayloadReadyBlocked = $sourceJson.rc8_signature_ingestion_result.status -eq "passed" -and
    $sourceJson.rc8_signature_ingestion_result.signature_surface.crypto_verified -eq $true -and
    $sourceJson.rc8_installer_vm_preflight.status -eq "passed" -and
    $sourceJson.rc8_installer_vm_preflight.vm_surface.qemu_boot_smoke_completed -eq $true -and
    $sourceJson.rc8_installer_byte_fail_closed.status -eq "passed" -and
    $sourceJson.rc8_installer_byte_fail_closed.summary.failed_cases -eq 0 -and
    $sourceJson.rc8_mirror_consistency_refresh.status -eq "passed" -and
    $sourceJson.rc8_mirror_consistency_refresh.payload_surface.storage_mode -eq "metadata-only" -and
    $sourceJson.rc8_mirror_consistency_refresh.payload_surface.install_allowed -eq $false -and
    $sourceJson.rc8_mirror_consistency_refresh.payload_surface.activation_allowed -eq $false -and
    $sourceJson.rc8_mirror_consistency_refresh.payload_surface.rollback_execution_allowed -eq $false
$rollbackBaselineReady = $sourceJson.rc7_rollback_baseline_result.status -eq "passed" -and
    $sourceJson.rc7_rollback_baseline_result.payload_surface.rollback_baseline_published -eq $true -and
    $sourceJson.rc7_rollback_baseline.execution_status.rollback_execution_allowed -eq $false -and
    $sourceJson.rc7_rollback_baseline.security_execution_requirement.agentcore_planspec_required -eq $true -and
    $sourceJson.rc7_rollback_baseline.security_execution_requirement.security_execution_engine_approval_required -eq $true -and
    $sourceJson.rc7_rollback_baseline.security_execution_requirement.approval_state -eq "not-approved" -and
    $sourceJson.rc7_rollback_baseline.previous_active_artifact_set_sha256 -eq $sourceJson.rc7_rollback_baseline.restored_active_artifact_set_sha256
$rc6RollbackReady = $sourceJson.rc6_rollback_preconditions_result.status -eq "passed" -and
    $sourceJson.rc6_rollback_preconditions_result.rollback_readiness_ready -eq $true -and
    $sourceJson.rc6_rollback_preconditions_result.rollback_execution_allowed -eq $false -and
    $sourceJson.rc6_rollback_preconditions_result.rollback_execution_performed -eq $false -and
    $sourceJson.rc6_rollback_matrix.rollback_readiness_ready -eq $true
$fleetAuthorityReadyBlocked = $sourceJson.fleet_rollout_authority.status -eq "passed" -and
    $sourceJson.fleet_rollout_authority.authority.execution_authority -eq "AgentCore fleet_rollout PlanSpec + SecurityExecutionEngine" -and
    $sourceJson.fleet_rollout_authority.authority.rollback_execution_in_tui -eq $false -and
    $sourceJson.fleet_rollout_authority.authority.tui_authority -eq $false -and
    $observedCanaryNodes -lt $minimumCanaryNodes -and
    $canaryRing.rollback_dispatch_enabled_in_tui -eq $false

$liveMetadata = @(
    $live.channel,
    $live.payload_index,
    $live.install_bootstrap,
    $live.mirror_status,
    $live.object_descriptor,
    $live.signature_receipt,
    $live.installer_preflight,
    $live.installer_fail_closed,
    $live.compatibility,
    $live.rollback_baseline
)
$liveReady = $live.root.exit_code -eq 0 -and
    $live.root.status_code -eq 200 -and
    @($liveMetadata | Where-Object { $_.exit_code -ne 0 -or $_.status_code -ne 200 -or $null -eq $_.json }).Count -eq 0 -and
    $live.channel.json.current_release_id -eq "production-distro-rc8-current-artifacts" -and
    $livePayloadEntry.release_id -eq "production-distro-rc8-current-artifacts" -and
    $livePayloadEntry.status -eq "verification-blocked" -and
    $livePayloadEntry.public_signature_ingested -eq $true -and
    $livePayloadEntry.crypto_verified -eq $true -and
    $livePayloadEntry.install_allowed -eq $false -and
    $livePayloadEntry.activation_allowed -eq $false -and
    $livePayloadEntry.rollback_execution_allowed -eq $false -and
    $live.install_bootstrap.json.rollback_execution_allowed -eq $false -and
    $live.rollback_baseline.json.execution_status.rollback_execution_allowed -eq $false

$externalObjectPublished = $payloadEntry.object_uri_external_https -eq $true
$declaredCurrentArtifactDriftReconciled = -not (Test-HasAllItems -Values $payloadEntry.payload_blockers -Expected @("declared-current-artifact-drift-unresolved"))
$activationPerformedGate = $sourceJson.rc8_canary_smoke.canary_activation_performed -eq $true
$targetSetGate = $sourceJson.rc8_canary_target_set.target_set_enrolled -eq $true
$exactApprovalGate = $sourceJson.rc8_exact_approval_packet.approval_granted -eq $true
$agentCoreRollbackPlanSpecGate = $false
$securityExecutionRollbackApprovalGate = $false
$remoteFleetGate = $canaryRing.rollback_dispatch_enabled_in_tui -eq $true

$rollbackExecutionAllowed = $rc8ActivationReadyBlocked -and
    $rc8ApprovalReadyBlocked -and
    $rc8PayloadReadyBlocked -and
    $rollbackBaselineReady -and
    $rc6RollbackReady -and
    $liveReady -and
    $externalObjectPublished -and
    $declaredCurrentArtifactDriftReconciled -and
    $activationPerformedGate -and
    $targetSetGate -and
    $exactApprovalGate -and
    $agentCoreRollbackPlanSpecGate -and
    $securityExecutionRollbackApprovalGate -and
    $remoteFleetGate

$remainingBlockers = @(
    "external-https-object-uri-not-published",
    "declared-current-artifact-drift-unresolved",
    "canary-activation-evidence-not-executed",
    "two-or-more-enrolled-canary-target-nodes-required",
    "remote-fleet-execution-not-enabled",
    "exact-operator-approval-not-granted",
    "AgentCore-rollback-PlanSpec-not-bound",
    "SecurityExecutionEngine-rollback-approval-not-bound"
)

$sourceBindings = [ordered]@{}
foreach ($key in $sourceRefs.Keys) {
    $sourceBindings["$($key)_sha256"] = $sourceRefs[$key].sha256
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
    compatibility = [ordered]@{ path = $bootstrapEndpoints.compatibility; sha256 = $live.compatibility.body_sha256 }
    rollback_baseline = [ordered]@{ path = $bootstrapEndpoints.rollback_baseline; sha256 = $live.rollback_baseline.body_sha256 }
}

$invariants = [ordered]@{
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
    persistent_state_mutated = $false
    active_artifact_set_mutated = $false
    production_ring_mutated = $false
    support_upload_performed = $false
    remote_dispatch_enabled = $false
    tui_authority = $false
}

$planSpecRequirement = [ordered]@{
    schema = "agentos.rc8-rollback-planspec-requirement.v1"
    generated_at = $generatedAt
    status = "rollback-planspec-required-execution-blocked"
    production_ready_claim = $false
    projection_only = $true
    release_id = $sourceJson.rc8_descriptor.release_id
    object_id = $sourceJson.rc8_descriptor.object_id
    object_sha256 = $sourceJson.rc8_descriptor.sha256
    rollback_baseline_sha256 = $sourceJson.rc7_rollback_baseline.rollback_baseline_sha256
    previous_active_artifact_set_sha256 = $sourceJson.rc7_rollback_baseline.previous_active_artifact_set_sha256
    restored_active_artifact_set_sha256 = $sourceJson.rc7_rollback_baseline.restored_active_artifact_set_sha256
    required_actor = "release-operator"
    required_action = "approve-rc8-rollback-drill"
    required_scope = "canary-ring-rollback-drill-only"
    agentcore_rollback_planspec_required = $true
    agentcore_rollback_planspec_bound = $false
    security_execution_engine_required = $true
    security_execution_rollback_approval_bound = $false
    exact_operator_approval_required = $true
    exact_operator_approval_granted = $false
    executable = $false
    rollback_execution_allowed = $false
    rollback_execution_performed = $false
    source_bindings = $sourceBindings
    remaining_blockers_before_rollback = $remainingBlockers
    invariants = $invariants
}

$gateInputs = [ordered]@{
    rc8_payload_verified = $rc8PayloadReadyBlocked
    public_signature_ingested = $sourceJson.rc8_signature_ingestion_result.signature_surface.signature_artifact_ingested
    signature_crypto_verified = $sourceJson.rc8_signature_ingestion_result.signature_surface.crypto_verified
    installer_vm_smoke_completed = $sourceJson.rc8_installer_vm_preflight.vm_surface.qemu_boot_smoke_completed
    installer_fail_closed = $sourceJson.rc8_installer_byte_fail_closed.summary.failed_cases -eq 0
    mirror_metadata_current = $liveReady
    external_https_object_uri_published = $externalObjectPublished
    declared_current_artifact_drift_reconciled = $declaredCurrentArtifactDriftReconciled
    rollback_baseline_published = $rollbackBaselineReady
    rollback_baseline_consistent = $sourceJson.rc7_rollback_baseline.previous_active_artifact_set_sha256 -eq $sourceJson.rc7_rollback_baseline.restored_active_artifact_set_sha256
    canary_activation_evidence_projected = $sourceJson.rc8_canary_smoke.canary_activation_smoke_packet_projected
    canary_activation_performed = $activationPerformedGate
    canary_target_set_enrolled = $targetSetGate
    observed_canary_node_count = $observedCanaryNodes
    required_canary_node_count = $minimumCanaryNodes
    exact_operator_approval_granted = $exactApprovalGate
    agentcore_rollback_planspec_bound = $agentCoreRollbackPlanSpecGate
    security_execution_rollback_approval_bound = $securityExecutionRollbackApprovalGate
    remote_fleet_execution_enabled = $remoteFleetGate
}

$gateReport = [ordered]@{
    schema = "agentos.rc8-controlled-rollback-drill-gate-report.v1"
    generated_at = $generatedAt
    status = "rollback-drill-gates-evaluated-blocked"
    production_ready_claim = $false
    projection_only = $true
    release_id = $sourceJson.rc8_descriptor.release_id
    rollback_readiness_ready = $rc6RollbackReady -and $rollbackBaselineReady
    rollback_execution_allowed = $rollbackExecutionAllowed
    rollback_execution_performed = $false
    gate_inputs = $gateInputs
    rollback_surface = [ordered]@{
        rollback_baseline_sha256 = $sourceJson.rc7_rollback_baseline.rollback_baseline_sha256
        previous_active_artifact_set_sha256 = $sourceJson.rc7_rollback_baseline.previous_active_artifact_set_sha256
        restored_active_artifact_set_sha256 = $sourceJson.rc7_rollback_baseline.restored_active_artifact_set_sha256
        baseline_consistent = $sourceJson.rc7_rollback_baseline.previous_active_artifact_set_sha256 -eq $sourceJson.rc7_rollback_baseline.restored_active_artifact_set_sha256
    }
    remaining_blockers_before_rollback = $remainingBlockers
    source_bindings = $sourceBindings
    live_endpoint_bindings = $liveBindings
    invariants = $invariants
}

$denialCases = @(
    [ordered]@{ id = "external-https-object-uri-not-published"; status = "passed"; rollback_execution_allowed = $false; reason = "payload descriptor still uses non-external object identity" },
    [ordered]@{ id = "declared-current-artifact-drift-unresolved"; status = "passed"; rollback_execution_allowed = $false; reason = "declared/current artifact drift remains unresolved" },
    [ordered]@{ id = "canary-activation-not-performed"; status = "passed"; rollback_execution_allowed = $false; reason = "canary activation evidence is projected but not executed" },
    [ordered]@{ id = "canary-target-set-not-enrolled"; status = "passed"; rollback_execution_allowed = $false; reason = "observed canary node count is below required minimum" },
    [ordered]@{ id = "exact-operator-approval-not-granted"; status = "passed"; rollback_execution_allowed = $false; reason = "approval packet is not granted" },
    [ordered]@{ id = "agentcore-rollback-planspec-not-bound"; status = "passed"; rollback_execution_allowed = $false; reason = "AgentCore rollback PlanSpec binding is absent" },
    [ordered]@{ id = "security-execution-rollback-approval-not-bound"; status = "passed"; rollback_execution_allowed = $false; reason = "SecurityExecutionEngine rollback approval is absent" },
    [ordered]@{ id = "remote-fleet-execution-disabled"; status = "passed"; rollback_execution_allowed = $false; reason = "remote fleet rollback dispatch remains disabled" }
)

$denialEvidence = [ordered]@{
    schema = "agentos.rc8-controlled-rollback-drill-denial-evidence.v1"
    generated_at = $generatedAt
    status = "rollback-drill-denied-by-gates"
    production_ready_claim = $false
    projection_only = $true
    rollback_execution_allowed = $false
    rollback_execution_performed = $false
    denial_cases = $denialCases
    remaining_blockers_before_rollback = $remainingBlockers
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

Write-Json -Value $planSpecRequirement -Path $planSpecRequirementPath
Write-Json -Value $gateReport -Path $gateReportPath
Write-Json -Value $denialEvidence -Path $denialEvidencePath
$planSpecRequirementHash = Get-FileSha256 $planSpecRequirementPath
$gateReportHash = Get-FileSha256 $gateReportPath
$denialEvidenceHash = Get-FileSha256 $denialEvidencePath

Add-Check "source.rc8_030.ready_blocked" ($rc8ActivationReadyBlocked -and $rc8ApprovalReadyBlocked) "RC8-031 must consume passed RC8-030 canary smoke while activation, approval, target, PlanSpec, and SecurityExecution remain blocked." ([ordered]@{ result = $sourceJson.rc8_canary_smoke.summary; approval_granted = $sourceJson.rc8_exact_approval_packet.approval_granted; target_set_enrolled = $sourceJson.rc8_canary_target_set.target_set_enrolled })
Add-Check "source.rc8.payload.ready_blocked" $rc8PayloadReadyBlocked "RC8 payload, public signature, installer preflight, fail-closed fixtures, and mirror evidence must remain passed while execution is blocked." $sourceJson.rc8_canary_smoke.payload_surface
Add-Check "source.rollback_baseline.ready" ($rollbackBaselineReady -and $rc6RollbackReady) "Rollback baseline and inherited rollback readiness must be available while rollback execution remains blocked." ([ordered]@{ rc7_baseline = $sourceJson.rc7_rollback_baseline.rollback_baseline_sha256; rc6_ready = $sourceJson.rc6_rollback_preconditions_result.rollback_readiness_ready })
Add-Check "fleet.authority.ready_blocked" $fleetAuthorityReadyBlocked "Fleet authority must remain AgentCore/SecurityExecution-owned, with canary under-enrolled and rollback dispatch disabled." ([ordered]@{ observed = $observedCanaryNodes; required = $minimumCanaryNodes; rollback_dispatch_enabled = if ($null -ne $canaryRing) { $canaryRing.rollback_dispatch_enabled_in_tui } else { $null } })
Add-Check "live.https.rollback_metadata.current" $liveReady "Resolve-pinned HTTPS metadata must expose RC8 payload evidence and rollback baseline while install, activation, and rollback remain blocked." ([ordered]@{ root = $live.root.status_code; payload_index = $live.payload_index.status_code; rollback_baseline = $live.rollback_baseline.status_code; release_id = if ($null -ne $livePayloadEntry) { $livePayloadEntry.release_id } else { $null }; status = if ($null -ne $livePayloadEntry) { $livePayloadEntry.status } else { $null } })
Add-Check "rollback.planspec_requirement.projected_blocked" ((Test-Path -LiteralPath $planSpecRequirementPath -PathType Leaf) -and $planSpecRequirement.executable -eq $false -and $planSpecRequirement.rollback_execution_allowed -eq $false) "Rollback PlanSpec requirement must be projected and non-executable until exact approval, PlanSpec, and SecurityExecution gates pass." ([ordered]@{ path = Get-StablePath $planSpecRequirementPath; sha256 = $planSpecRequirementHash })
Add-Check "rollback.gates.fail_closed" (-not $rollbackExecutionAllowed) "Rollback drill execution must remain denied until object URI, drift, activation, target, approval, AgentCore rollback PlanSpec, SecurityExecution, and remote fleet gates pass." $gateInputs
Add-Check "rollback.gate_report.projected" ((Test-Path -LiteralPath $gateReportPath -PathType Leaf) -and $gateReport.rollback_execution_performed -eq $false) "Rollback drill gate report must be projected without executing rollback." ([ordered]@{ path = Get-StablePath $gateReportPath; sha256 = $gateReportHash })
Add-Check "rollback.denial_evidence.projected" ((Test-Path -LiteralPath $denialEvidencePath -PathType Leaf) -and @($denialEvidence.denial_cases | Where-Object { $_.status -ne "passed" -or $_.rollback_execution_allowed -ne $false }).Count -eq 0) "Rollback denial evidence must cover each missing rollback execution gate as fail-closed." ([ordered]@{ path = Get-StablePath $denialEvidencePath; sha256 = $denialEvidenceHash; cases = @($denialEvidence.denial_cases).Count })
Add-Check "authority.not_broadened" $true "RC8-031 must not sign, upload payloads, install, activate, rollback, mutate boot/slot/state/rings, upload support, dispatch remotely, or grant TUI authority." $invariants

$secretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $planSpecRequirementPath),
    (Get-Content -Raw -LiteralPath $gateReportPath),
    (Get-Content -Raw -LiteralPath $denialEvidencePath)
)
Add-Check "outputs.secret_safe" $secretSafe "RC8-031 projected artifacts must not contain secret material paths, PEM private blocks, or token markers." $null

$passed = @($script:blockers).Count -eq 0
$result = [ordered]@{
    schema = "agentos.rc8-controlled-rollback-drill-result.v1"
    generated_at = $generatedAt
    checked_at = (Get-Date).ToString("o")
    task = "RC8-031"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    rollback_drill_evidence_projected = $passed
    rollback_readiness_ready = $rc6RollbackReady -and $rollbackBaselineReady
    rollback_execution_allowed = $rollbackExecutionAllowed
    rollback_execution_performed = $false
    canary_activation_allowed = $sourceJson.rc8_canary_smoke.canary_activation_allowed
    canary_activation_performed = $false
    activation_performed = $false
    artifacts = [ordered]@{
        rollback_planspec_requirement = [ordered]@{
            path = Get-StablePath $planSpecRequirementPath
            sha256 = $planSpecRequirementHash
            schema = $planSpecRequirement.schema
            status = $planSpecRequirement.status
        }
        rollback_drill_gate_report = [ordered]@{
            path = Get-StablePath $gateReportPath
            sha256 = $gateReportHash
            schema = $gateReport.schema
            status = $gateReport.status
        }
        rollback_drill_denial_evidence = [ordered]@{
            path = Get-StablePath $denialEvidencePath
            sha256 = $denialEvidenceHash
            schema = $denialEvidence.schema
            status = $denialEvidence.status
        }
    }
    source_artifacts = $sourceRefs
    source_bindings = $sourceBindings
    live_endpoint_bindings = $liveBindings
    rollback_surface = $gateReport.rollback_surface
    gates = $gateInputs
    remaining_blockers_before_rollback = $remainingBlockers
    checks = $script:checks
    blockers = $script:blockers
    invariants = $invariants
    summary = [ordered]@{
        checks = @($script:checks).Count
        blockers = @($script:blockers).Count
        rc8_031_complete = $passed
        rollback_drill_evidence_projected = $passed
        rollback_readiness_ready = $rc6RollbackReady -and $rollbackBaselineReady
        rollback_execution_allowed = $rollbackExecutionAllowed
        rollback_execution_performed = $false
        canary_activation_performed = $false
        exact_operator_approval_required = $true
        exact_operator_approval_granted = $false
        required_canary_node_count = $minimumCanaryNodes
        observed_canary_node_count = $observedCanaryNodes
        target_set_enrolled = $targetSetGate
        agentcore_rollback_planspec_bound = $agentCoreRollbackPlanSpecGate
        security_execution_rollback_approval_bound = $securityExecutionRollbackApprovalGate
        remote_fleet_execution_enabled = $remoteFleetGate
        production_ready_claim = $false
        next_task = "RC8-032"
    }
}

Write-Json -Value $result -Path $resolvedResultPath

$resultSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resolvedResultPath))
if (-not $resultSecretSafe) {
    $extra = [ordered]@{
        id = "result.secret_safe"
        status = "failed"
        severity = "blocking"
        message = "RC8-031 result must not contain secret material paths, PEM private blocks, or token markers."
        evidence = $null
    }
    $script:checks += $extra
    $script:blockers += $extra
    $result.status = "blocked"
    $result.rollback_drill_evidence_projected = $false
    $result.checks = $script:checks
    $result.blockers = $script:blockers
    $result.summary.checks = @($script:checks).Count
    $result.summary.blockers = @($script:blockers).Count
    $result.summary.rc8_031_complete = $false
    $result.summary.rollback_drill_evidence_projected = $false
    Write-Json -Value $result -Path $resolvedResultPath
}

Write-Host "RC8 controlled rollback drill $($result.status): $(Get-StablePath $resolvedResultPath)"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
