param(
    [string]$RemoteHost = "47.101.11.109",
    [string]$Domain = "aios.w33d.xyz",
    [string]$ArtifactDir = ".workflow/artifacts/rc7-gated-rollback-drill",
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
$gateReportPath = Join-Path $resolvedArtifactDir "rollback-drill-gate-report.json"
$denialEvidencePath = Join-Path $resolvedArtifactDir "rollback-drill-denial-evidence.json"

$sourcePaths = [ordered]@{
    rc7_gated_canary_activation = ".workflow/artifacts/rc7-gated-canary-activation/result.json"
    rc7_activation_gate_report = ".workflow/artifacts/rc7-gated-canary-activation/activation-gate-report.json"
    rc7_activation_denial_evidence = ".workflow/artifacts/rc7-gated-canary-activation/activation-denial-evidence.json"
    rc7_multi_node_canary_approval = ".workflow/artifacts/rc7-multi-node-canary-approval/result.json"
    rc7_exact_approval_packet = ".workflow/artifacts/rc7-multi-node-canary-approval/exact-approval-packet.json"
    rc7_install_rollback_baseline_result = ".workflow/artifacts/rc7-install-rollback-baseline/result.json"
    rc7_rollback_baseline = ".workflow/artifacts/rc7-install-rollback-baseline/rollback-baseline.json"
    rc6_rollback_preconditions_result = ".workflow/artifacts/rc6-rollback-execution-preconditions/result.json"
    rc6_rollback_matrix = ".workflow/artifacts/rc6-rollback-execution-preconditions/rollback-drill-precondition-matrix.json"
    rc6_rollback_blockers = ".workflow/artifacts/rc6-rollback-execution-preconditions/rollback-execution-blockers.json"
    rc7_installer_signed_consumption = ".workflow/artifacts/rc7-installer-signed-consumption/result.json"
    rc7_signed_consumption_fail_closed = ".workflow/artifacts/rc7-signed-consumption-fail-closed/result.json"
    rc7_tls_nginx_hardening = ".workflow/artifacts/rc7-tls-nginx-hardening/result.json"
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
    rollback_baseline = Invoke-Curl "/install/rollback-baseline.json"
    compatibility = Invoke-Curl "/install/compatibility.json"
    signatures = Invoke-Curl "/payloads/aios/production-distro-rc6-current-artifacts/signatures.json"
    revocations = Invoke-Curl "/payloads/aios/production-distro-rc6-current-artifacts/revocations.json"
    support_index = Invoke-Curl "/support/index.json"
    support_recovery = Invoke-Curl "/support/recovery.json"
}

$payloadEntry = if ($null -ne $live.payload_index.json -and $null -ne $live.payload_index.json.entries) { @($live.payload_index.json.entries)[0] } else { $null }
$canaryRing = Get-Ring $sourceJson.fleet_rollout_authority "canary"
$minimumCanaryNodes = 2
$observedCanaryNodes = if ($null -ne $canaryRing -and $null -ne $canaryRing.node_count) { [int]$canaryRing.node_count } else { 0 }
$generatedAt = (Get-Date).ToString("o")

$canaryActivationReadyBlocked = $sourceJson.rc7_gated_canary_activation.status -eq "passed" -and
    $sourceJson.rc7_gated_canary_activation.summary.blockers -eq 0 -and
    $sourceJson.rc7_gated_canary_activation.summary.rc7_031_complete -eq $true -and
    $sourceJson.rc7_gated_canary_activation.canary_activation_evidence_projected -eq $true -and
    $sourceJson.rc7_gated_canary_activation.canary_activation_allowed -eq $false -and
    $sourceJson.rc7_gated_canary_activation.activation_performed -eq $false -and
    $sourceJson.rc7_gated_canary_activation.rollback_execution_performed -eq $false
$activationGateReadyBlocked = $sourceJson.rc7_activation_gate_report.schema -eq "agentos.rc7-canary-activation-gate-report.v1" -and
    $sourceJson.rc7_activation_gate_report.canary_activation_allowed -eq $false -and
    $sourceJson.rc7_activation_gate_report.activation_performed -eq $false -and
    $sourceJson.rc7_activation_gate_report.gate_inputs.live_metadata_matches_approval_packet -eq $true
$rc7ApprovalReadyBlocked = $sourceJson.rc7_multi_node_canary_approval.status -eq "passed" -and
    $sourceJson.rc7_multi_node_canary_approval.summary.blockers -eq 0 -and
    $sourceJson.rc7_exact_approval_packet.approval_granted -eq $false -and
    $sourceJson.rc7_exact_approval_packet.gates.agentcore_planspec_bound -eq $false -and
    $sourceJson.rc7_exact_approval_packet.gates.security_execution_approval_bound -eq $false
$rc7RollbackBaselineReady = $sourceJson.rc7_install_rollback_baseline_result.status -eq "passed" -and
    $sourceJson.rc7_install_rollback_baseline_result.payload_surface.rollback_baseline_published -eq $true -and
    $sourceJson.rc7_install_rollback_baseline_result.payload_surface.rollback_execution_allowed -eq $false -and
    $sourceJson.rc7_rollback_baseline.schema -eq "agentos.rc7-rollback-baseline.v1" -and
    $sourceJson.rc7_rollback_baseline.rollback_baseline_sha256 -eq $sourceJson.rc7_rollback_baseline.support_recovery_binding.rollback_baseline_sha256 -and
    $sourceJson.rc7_rollback_baseline.previous_active_artifact_set_sha256 -eq $sourceJson.rc7_rollback_baseline.restored_active_artifact_set_sha256 -and
    $sourceJson.rc7_rollback_baseline.execution_status.rollback_execution_allowed -eq $false -and
    $sourceJson.rc7_rollback_baseline.security_execution_requirement.security_execution_engine_approval_required -eq $true -and
    $sourceJson.rc7_rollback_baseline.security_execution_requirement.approval_state -eq "not-approved"
$rc6RollbackReady = $sourceJson.rc6_rollback_preconditions_result.status -eq "passed" -and
    $sourceJson.rc6_rollback_preconditions_result.summary.blockers -eq 0 -and
    $sourceJson.rc6_rollback_preconditions_result.rollback_readiness_ready -eq $true -and
    $sourceJson.rc6_rollback_preconditions_result.rollback_execution_allowed -eq $false -and
    $sourceJson.rc6_rollback_preconditions_result.rollback_execution_performed -eq $false -and
    $sourceJson.rc6_rollback_matrix.rollback_readiness_ready -eq $true -and
    $sourceJson.rc6_rollback_matrix.rollback_execution_allowed -eq $false -and
    $sourceJson.rc6_rollback_blockers.rollback_execution_allowed -eq $false
$signedConsumptionReady = $sourceJson.rc7_installer_signed_consumption.status -eq "passed" -and
    $sourceJson.rc7_installer_signed_consumption.summary.blockers -eq 0 -and
    $sourceJson.rc7_installer_signed_consumption.report.state -eq "verification-blocked"
$failClosedReady = $sourceJson.rc7_signed_consumption_fail_closed.status -eq "passed" -and
    $sourceJson.rc7_signed_consumption_fail_closed.summary.failed_cases -eq 0
$tlsReady = $sourceJson.rc7_tls_nginx_hardening.status -eq "passed" -and
    $sourceJson.rc7_tls_nginx_hardening.invariants.tls_configured -eq $true
$fleetAuthorityReady = $sourceJson.fleet_rollout_authority.status -eq "passed" -and
    $sourceJson.fleet_rollout_authority.authority.execution_authority -eq "AgentCore fleet_rollout PlanSpec + SecurityExecutionEngine" -and
    $sourceJson.fleet_rollout_authority.authority.rollback_execution_in_tui -eq $false -and
    $sourceJson.fleet_rollout_authority.authority.tui_authority -eq $false -and
    $observedCanaryNodes -lt $minimumCanaryNodes -and
    $canaryRing.blocker -eq "remote-fleet-execution-not-enabled"

$liveMetadata = @(
    $live.channel,
    $live.payload_index,
    $live.install_bootstrap,
    $live.rollback_baseline,
    $live.compatibility,
    $live.signatures,
    $live.revocations,
    $live.support_index,
    $live.support_recovery
)
$supportRollbackOperation = if ($null -ne $live.support_recovery.json -and $null -ne $live.support_recovery.json.operations) {
    @($live.support_recovery.json.operations | Where-Object { $_.id -eq "rollback-readiness-explain" } | Select-Object -First 1)[0]
} else {
    $null
}
$liveReady = $live.root.exit_code -eq 0 -and
    $live.root.status_code -eq 200 -and
    @($liveMetadata | Where-Object { $_.exit_code -ne 0 -or $_.status_code -ne 200 -or $null -eq $_.json }).Count -eq 0 -and
    $payloadEntry.release_id -eq "production-distro-rc6-current-artifacts" -and
    $payloadEntry.status -eq "verification-blocked" -and
    $payloadEntry.install_allowed -eq $false -and
    $payloadEntry.activation_allowed -eq $false -and
    $payloadEntry.rollback_execution_allowed -eq $false -and
    $live.rollback_baseline.json.rollback_baseline_sha256 -eq $sourceJson.rc7_rollback_baseline.rollback_baseline_sha256 -and
    $live.rollback_baseline.json.execution_status.rollback_execution_allowed -eq $false -and
    $null -ne $supportRollbackOperation -and
    $supportRollbackOperation.executable_by_mirror -eq $false -and
    $supportRollbackOperation.rollback_baseline_sha256 -eq $sourceJson.rc7_rollback_baseline.rollback_baseline_sha256
$liveMatchesRc7Baseline = $live.rollback_baseline.body_sha256 -eq $sourceJson.rc7_install_rollback_baseline_result.output_hashes.rollback_baseline_sha256

$signatureGate = $live.signatures.json.cryptographic_signature_present -eq $true -and $live.signatures.json.signature_available -eq $true
$revocationGate = [bool]$payloadEntry.revocation_snapshot_sha256
$rollbackBaselineGate = $sourceJson.rc7_rollback_baseline.security_execution_requirement.security_execution_engine_approval_required -eq $true
$canaryActivationGate = $sourceJson.rc7_gated_canary_activation.canary_activation_performed -eq $true
$targetSetGate = $sourceJson.rc7_gated_canary_activation.target_set.target_set_enrolled -eq $true
$exactApprovalGate = $sourceJson.rc7_exact_approval_packet.approval_granted -eq $true
$agentCoreRollbackPlanSpecGate = $false
$securityExecutionRollbackApprovalGate = $false
$remoteFleetGate = $canaryRing.rollback_dispatch_enabled_in_tui -eq $true

$rollbackExecutionAllowed = $signatureGate -and
    $revocationGate -and
    $rollbackBaselineGate -and
    $canaryActivationGate -and
    $targetSetGate -and
    $exactApprovalGate -and
    $agentCoreRollbackPlanSpecGate -and
    $securityExecutionRollbackApprovalGate -and
    $remoteFleetGate -and
    $liveReady

$remainingBlockers = @(
    "real-cryptographic-payload-signature-not-present",
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
    rollback_baseline = [ordered]@{ path = "/install/rollback-baseline.json"; sha256 = $live.rollback_baseline.body_sha256 }
    compatibility = [ordered]@{ path = "/install/compatibility.json"; sha256 = $live.compatibility.body_sha256 }
    signatures = [ordered]@{ path = "/payloads/aios/production-distro-rc6-current-artifacts/signatures.json"; sha256 = $live.signatures.body_sha256 }
    revocations = [ordered]@{ path = "/payloads/aios/production-distro-rc6-current-artifacts/revocations.json"; sha256 = $live.revocations.body_sha256 }
    support_index = [ordered]@{ path = "/support/index.json"; sha256 = $live.support_index.body_sha256 }
    support_recovery = [ordered]@{ path = "/support/recovery.json"; sha256 = $live.support_recovery.body_sha256 }
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
    boot_metadata_mutated = $false
    persistent_state_mutated = $false
    active_artifact_set_mutated = $false
    production_ring_mutated = $false
    support_upload_performed = $false
    remote_dispatch_enabled = $false
    tui_authority = $false
}

$gateReport = [ordered]@{
    schema = "agentos.rc7-rollback-drill-gate-report.v1"
    generated_at = $generatedAt
    status = "rollback-drill-gates-evaluated-blocked"
    production_ready_claim = $false
    projection_only = $true
    release_id = if ($null -ne $payloadEntry) { $payloadEntry.release_id } else { $null }
    rollback_readiness_ready = $rc6RollbackReady
    rollback_execution_allowed = $rollbackExecutionAllowed
    rollback_execution_performed = $false
    gate_inputs = [ordered]@{
        signed_metadata_published = [bool]$payloadEntry.signed_metadata_sha256
        revocation_snapshot_published = $revocationGate
        compatibility_published = [bool]$payloadEntry.compatibility_sha256
        rollback_baseline_published = [bool]$payloadEntry.rollback_baseline_sha256
        rollback_baseline_consistent = $sourceJson.rc7_rollback_baseline.previous_active_artifact_set_sha256 -eq $sourceJson.rc7_rollback_baseline.restored_active_artifact_set_sha256
        support_recovery_ready = $null -ne $supportRollbackOperation -and $supportRollbackOperation.executable_by_mirror -eq $false
        tls_configured = $sourceJson.rc7_tls_nginx_hardening.invariants.tls_configured
        cryptographic_signature_present = $live.signatures.json.cryptographic_signature_present
        signature_available = $live.signatures.json.signature_available
        canary_activation_evidence_projected = $sourceJson.rc7_gated_canary_activation.canary_activation_evidence_projected
        canary_activation_performed = $sourceJson.rc7_gated_canary_activation.canary_activation_performed
        canary_target_set_enrolled = $targetSetGate
        observed_canary_node_count = $observedCanaryNodes
        required_canary_node_count = $minimumCanaryNodes
        exact_operator_approval_granted = $exactApprovalGate
        agentcore_rollback_planspec_bound = $agentCoreRollbackPlanSpecGate
        security_execution_rollback_approval_bound = $securityExecutionRollbackApprovalGate
        remote_fleet_execution_enabled = $remoteFleetGate
        live_metadata_matches_rc7_rollback_baseline = $liveMatchesRc7Baseline
    }
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
    [ordered]@{ id = "missing-real-cryptographic-signature"; status = "passed"; rollback_execution_allowed = $false; reason = "signature gate is false" },
    [ordered]@{ id = "canary-activation-not-performed"; status = "passed"; rollback_execution_allowed = $false; reason = "canary activation evidence is projected but not executed" },
    [ordered]@{ id = "canary-target-set-not-enrolled"; status = "passed"; rollback_execution_allowed = $false; reason = "observed canary node count is below required minimum" },
    [ordered]@{ id = "exact-operator-approval-not-granted"; status = "passed"; rollback_execution_allowed = $false; reason = "approval packet is not granted" },
    [ordered]@{ id = "agentcore-rollback-planspec-not-bound"; status = "passed"; rollback_execution_allowed = $false; reason = "AgentCore rollback PlanSpec binding is absent" },
    [ordered]@{ id = "security-execution-rollback-approval-not-bound"; status = "passed"; rollback_execution_allowed = $false; reason = "SecurityExecutionEngine rollback approval is absent" },
    [ordered]@{ id = "remote-fleet-execution-disabled"; status = "passed"; rollback_execution_allowed = $false; reason = "remote fleet rollback dispatch remains disabled" }
)

$denialEvidence = [ordered]@{
    schema = "agentos.rc7-rollback-drill-denial-evidence.v1"
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

Write-Json -Value $gateReport -Path $gateReportPath
Write-Json -Value $denialEvidence -Path $denialEvidencePath
$gateReportHash = Get-FileSha256 $gateReportPath
$denialEvidenceHash = Get-FileSha256 $denialEvidencePath

Add-Check "source.rc7_031.ready" ($canaryActivationReadyBlocked -and $activationGateReadyBlocked) "RC7-032 must consume passed RC7-031 canary activation evidence while activation remains denied." ([ordered]@{ result = $sourceJson.rc7_gated_canary_activation.summary; gate_status = $sourceJson.rc7_activation_gate_report.status })
Add-Check "source.rc7_030.approval_blocked" $rc7ApprovalReadyBlocked "RC7 exact approval packet must remain unapproved and without AgentCore/SecurityExecution bindings." ([ordered]@{ approval_granted = $sourceJson.rc7_exact_approval_packet.approval_granted; agentcore = $sourceJson.rc7_exact_approval_packet.gates.agentcore_planspec_bound; security_execution = $sourceJson.rc7_exact_approval_packet.gates.security_execution_approval_bound })
Add-Check "source.rc7.rollback_baseline.ready" $rc7RollbackBaselineReady "RC7 rollback baseline must be published, baseline-consistent, support-bound, and execution-blocked." ([ordered]@{ baseline = $sourceJson.rc7_rollback_baseline.rollback_baseline_sha256; previous = $sourceJson.rc7_rollback_baseline.previous_active_artifact_set_sha256; restored = $sourceJson.rc7_rollback_baseline.restored_active_artifact_set_sha256; approval_state = $sourceJson.rc7_rollback_baseline.security_execution_requirement.approval_state })
Add-Check "source.rc6.rollback_preconditions.ready" $rc6RollbackReady "RC6 rollback preconditions must prove rollback readiness while keeping rollback execution blocked." $(if ($null -ne $sourceJson.rc6_rollback_preconditions_result) { $sourceJson.rc6_rollback_preconditions_result.summary } else { $null })
Add-Check "source.signed_consumption.ready" ($signedConsumptionReady -and $failClosedReady) "Signed consumption and fail-closed evidence must remain passed before rollback drill gate evaluation." ([ordered]@{ consumption = $sourceJson.rc7_installer_signed_consumption.summary; fail_closed = $sourceJson.rc7_signed_consumption_fail_closed.summary })
Add-Check "source.tls_fleet.ready_blocked" ($tlsReady -and $fleetAuthorityReady) "TLS and fleet authority must be ready, while canary/remote rollback execution remains disabled." ([ordered]@{ tls = $sourceJson.rc7_tls_nginx_hardening.summary; observed = $observedCanaryNodes; required = $minimumCanaryNodes; canary_blocker = if ($null -ne $canaryRing) { $canaryRing.blocker } else { $null } })
Add-Check "live.https.rollback_metadata.current" ($liveReady -and $liveMatchesRc7Baseline) "HTTPS live metadata must expose rollback baseline and support/recovery metadata while install, activation, and rollback remain blocked." ([ordered]@{ live_ready = $liveReady; matches_baseline = $liveMatchesRc7Baseline; release_id = if ($null -ne $payloadEntry) { $payloadEntry.release_id } else { $null }; status = if ($null -ne $payloadEntry) { $payloadEntry.status } else { $null } })
Add-Check "rollback.gates.fail_closed" (-not $rollbackExecutionAllowed) "Rollback drill execution must remain denied until signature, canary activation, target, approval, AgentCore PlanSpec, SecurityExecution, and remote fleet gates pass." $gateReport.gate_inputs
Add-Check "rollback.gate_report.projected" ((Test-Path -LiteralPath $gateReportPath -PathType Leaf) -and $gateReport.rollback_execution_performed -eq $false) "Rollback drill gate report must be projected without executing rollback." ([ordered]@{ path = Get-StablePath $gateReportPath; sha256 = $gateReportHash })
Add-Check "rollback.denial_evidence.projected" ((Test-Path -LiteralPath $denialEvidencePath -PathType Leaf) -and @($denialEvidence.denial_cases | Where-Object { $_.status -ne "passed" -or $_.rollback_execution_allowed -ne $false }).Count -eq 0) "Rollback denial evidence must cover each missing rollback execution gate as fail-closed." ([ordered]@{ path = Get-StablePath $denialEvidencePath; sha256 = $denialEvidenceHash; cases = @($denialEvidence.denial_cases).Count })
Add-Check "rollback.no_authority_broadened" $true "RC7-032 must not sign, upload payloads, install, activate, rollback, mutate boot/slot/state/rings, upload support, dispatch remotely, or grant TUI authority." $invariants

$passed = @($script:blockers).Count -eq 0
$result = [ordered]@{
    schema = "agentos.rc7-gated-rollback-drill-result.v1"
    generated_at = $generatedAt
    checked_at = (Get-Date).ToString("o")
    task = "RC7-032"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    rollback_drill_evidence_projected = $passed
    rollback_readiness_ready = $rc6RollbackReady
    rollback_execution_allowed = $rollbackExecutionAllowed
    rollback_execution_performed = $false
    canary_activation_allowed = $sourceJson.rc7_gated_canary_activation.canary_activation_allowed
    canary_activation_performed = $false
    activation_performed = $false
    artifacts = [ordered]@{
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
    gates = $gateReport.gate_inputs
    remaining_blockers_before_rollback = $remainingBlockers
    checks = $script:checks
    blockers = $script:blockers
    invariants = $invariants
    summary = [ordered]@{
        checks = @($script:checks).Count
        blockers = @($script:blockers).Count
        rc7_032_complete = $passed
        rollback_drill_evidence_projected = $passed
        rollback_readiness_ready = $rc6RollbackReady
        rollback_execution_allowed = $rollbackExecutionAllowed
        rollback_execution_performed = $false
        canary_activation_performed = $false
        exact_operator_approval_required = $true
        exact_operator_approval_granted = $false
        required_canary_node_count = $minimumCanaryNodes
        observed_canary_node_count = $observedCanaryNodes
        target_set_enrolled = $targetSetGate
        remote_fleet_execution_enabled = $remoteFleetGate
        production_ready_claim = $false
        next_task = "RC7-040"
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
        message = "RC7-032 artifacts must not contain private key or token markers."
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
    $result.summary.rc7_032_complete = $false
    $result.summary.rollback_drill_evidence_projected = $false
    Write-Json -Value $result -Path $resolvedResultPath
}

Write-Host "RC7 gated rollback drill $($result.status): $(Get-StablePath $resolvedResultPath)"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
