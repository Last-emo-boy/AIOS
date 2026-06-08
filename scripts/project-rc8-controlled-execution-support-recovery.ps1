param(
    [string]$RemoteHost = "47.101.11.109",
    [string]$Domain = "aios.w33d.xyz",
    [string]$ArtifactDir = ".workflow/artifacts/rc8-controlled-execution-support-recovery",
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

function Get-OperationById {
    param($RecoveryJson, [string]$Id)
    if ($null -eq $RecoveryJson -or $null -eq $RecoveryJson.operations) {
        return $null
    }
    return @($RecoveryJson.operations | Where-Object { $_.id -eq $Id } | Select-Object -First 1)[0]
}

function Test-AllRecoveryOperationsNonExecutable {
    param($RecoveryJson)
    if ($null -eq $RecoveryJson -or $null -eq $RecoveryJson.operations) {
        return $false
    }
    return @($RecoveryJson.operations | Where-Object { $_.executable_by_mirror -ne $false }).Count -eq 0
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
$evidenceChainPath = Join-Path $resolvedArtifactDir "support-recovery-evidence-chain.json"
$supportBundlePath = Join-Path $resolvedArtifactDir "controlled-execution-support-bundle.json"
$recoveryIndexPath = Join-Path $resolvedArtifactDir "recovery-reference-index.json"

$sourcePaths = [ordered]@{
    rc8_activation_result = ".workflow/artifacts/rc8-exact-approved-canary-smoke/result.json"
    rc8_activation_gate_report = ".workflow/artifacts/rc8-exact-approved-canary-smoke/activation-smoke-gate-report.json"
    rc8_activation_denial_evidence = ".workflow/artifacts/rc8-exact-approved-canary-smoke/activation-denial-evidence.json"
    rc8_exact_approval_packet = ".workflow/artifacts/rc8-exact-approved-canary-smoke/exact-approval-packet.json"
    rc8_canary_target_set = ".workflow/artifacts/rc8-exact-approved-canary-smoke/canary-target-set.json"
    rc8_rollback_result = ".workflow/artifacts/rc8-controlled-rollback-drill/result.json"
    rc8_rollback_planspec_requirement = ".workflow/artifacts/rc8-controlled-rollback-drill/rollback-planspec-requirement.json"
    rc8_rollback_gate_report = ".workflow/artifacts/rc8-controlled-rollback-drill/rollback-drill-gate-report.json"
    rc8_rollback_denial_evidence = ".workflow/artifacts/rc8-controlled-rollback-drill/rollback-drill-denial-evidence.json"
    rc8_mirror_consistency_refresh = ".workflow/artifacts/rc8-mirror-consistency-refresh/result.json"
    rc8_hosted_payload_index = ".workflow/artifacts/rc8-mirror-consistency-refresh/hosted-payload-index.json"
    rc8_install_bootstrap = ".workflow/artifacts/rc8-mirror-consistency-refresh/install-bootstrap.json"
    rc8_hosted_channel_index = ".workflow/artifacts/rc8-mirror-consistency-refresh/hosted-channel-index.json"
    rc8_mirror_status = ".workflow/artifacts/rc8-mirror-consistency-refresh/mirror-status.json"
    rc7_rollback_baseline = ".workflow/artifacts/rc7-install-rollback-baseline/rollback-baseline.json"
    rc7_rollback_baseline_result = ".workflow/artifacts/rc7-install-rollback-baseline/result.json"
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
    support_index = Invoke-Curl "/support/index.json"
    support_recovery = Invoke-Curl "/support/recovery.json"
    support_readme = Invoke-Curl "/support/README.txt"
    compatibility = Invoke-Curl $bootstrapEndpoints.compatibility
    rollback_baseline = Invoke-Curl $bootstrapEndpoints.rollback_baseline
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
$rollbackExplainOperation = Get-OperationById -RecoveryJson $live.support_recovery.json -Id "rollback-readiness-explain"
$generatedAt = (Get-Date).ToString("o")

$activationDeniedReady = $sourceJson.rc8_activation_result.status -eq "passed" -and
    $sourceJson.rc8_activation_result.summary.blockers -eq 0 -and
    $sourceJson.rc8_activation_result.summary.rc8_030_complete -eq $true -and
    $sourceJson.rc8_activation_result.canary_activation_allowed -eq $false -and
    $sourceJson.rc8_activation_result.canary_activation_performed -eq $false -and
    $sourceJson.rc8_activation_gate_report.activation_performed -eq $false -and
    $sourceJson.rc8_activation_denial_evidence.activation_allowed -eq $false -and
    $sourceJson.rc8_exact_approval_packet.approval_granted -eq $false -and
    $sourceJson.rc8_canary_target_set.target_set_enrolled -eq $false

$rollbackDeniedReady = $sourceJson.rc8_rollback_result.status -eq "passed" -and
    $sourceJson.rc8_rollback_result.summary.blockers -eq 0 -and
    $sourceJson.rc8_rollback_result.summary.rc8_031_complete -eq $true -and
    $sourceJson.rc8_rollback_result.rollback_readiness_ready -eq $true -and
    $sourceJson.rc8_rollback_result.rollback_execution_allowed -eq $false -and
    $sourceJson.rc8_rollback_result.rollback_execution_performed -eq $false -and
    $sourceJson.rc8_rollback_planspec_requirement.executable -eq $false -and
    $sourceJson.rc8_rollback_planspec_requirement.agentcore_rollback_planspec_bound -eq $false -and
    $sourceJson.rc8_rollback_gate_report.rollback_execution_performed -eq $false -and
    $sourceJson.rc8_rollback_denial_evidence.rollback_execution_allowed -eq $false

$mirrorReady = $sourceJson.rc8_mirror_consistency_refresh.status -eq "passed" -and
    $sourceJson.rc8_mirror_consistency_refresh.summary.blockers -eq 0 -and
    $sourceJson.rc8_mirror_status.status -eq "verification-blocked" -and
    $sourceJson.rc8_mirror_status.payload_bytes_hosted_on_mirror -eq $false -and
    $sourceJson.rc8_hosted_channel_index.production_ready_claim -eq $false -and
    $sourceJson.rc8_hosted_channel_index.authority.support_upload_authority -eq $false -and
    $sourceJson.rc8_hosted_channel_index.authority.rollback_execution_authority -eq $false -and
    $sourceJson.rc8_install_bootstrap.install_allowed -eq $false -and
    $sourceJson.rc8_install_bootstrap.activation_allowed -eq $false -and
    $sourceJson.rc8_install_bootstrap.rollback_execution_allowed -eq $false

$liveMetadata = @(
    $live.channel,
    $live.payload_index,
    $live.install_bootstrap,
    $live.mirror_status,
    $live.support_index,
    $live.support_recovery,
    $live.support_readme,
    $live.compatibility,
    $live.rollback_baseline,
    $live.object_descriptor,
    $live.signature_receipt,
    $live.installer_preflight,
    $live.installer_fail_closed
)
$liveReady = $live.root.exit_code -eq 0 -and
    $live.root.status_code -eq 200 -and
    @($liveMetadata | Where-Object { $_.exit_code -ne 0 -or $_.status_code -ne 200 }).Count -eq 0 -and
    @($liveMetadata | Where-Object { $_.path -ne "/support/README.txt" -and $null -eq $_.json }).Count -eq 0 -and
    $live.channel.json.current_release_id -eq "production-distro-rc8-current-artifacts" -and
    $livePayloadEntry.release_id -eq "production-distro-rc8-current-artifacts" -and
    $livePayloadEntry.status -eq "verification-blocked" -and
    $livePayloadEntry.install_allowed -eq $false -and
    $livePayloadEntry.activation_allowed -eq $false -and
    $livePayloadEntry.rollback_execution_allowed -eq $false -and
    $live.install_bootstrap.json.install_allowed -eq $false -and
    $live.install_bootstrap.json.activation_allowed -eq $false -and
    $live.install_bootstrap.json.rollback_execution_allowed -eq $false

$supportReady = $live.support_index.json.production_ready_claim -eq $false -and
    $live.support_index.json.redacted -eq $true -and
    $live.support_index.json.support_upload_allowed -eq $false -and
    $live.support_index.json.recovery_execution_allowed -eq $false -and
    $live.support_index.json.rollback_execution_allowed -eq $false -and
    $live.support_index.json.activation_allowed -eq $false -and
    $live.support_index.json.authority.support_authority -eq $false -and
    $live.support_index.json.authority.recovery_authority -eq $false -and
    $live.support_index.json.authority.signing_authority -eq $false -and
    $live.support_index.json.authority.remote_dispatch_authority -eq $false -and
    $live.support_index.json.authority.tui_authority -eq $false

$recoveryReady = $live.support_recovery.json.production_ready_claim -eq $false -and
    $live.support_recovery.json.status -eq "projection-only" -and
    (Test-AllRecoveryOperationsNonExecutable -RecoveryJson $live.support_recovery.json) -and
    $live.support_recovery.json.invariants.support_upload_performed -eq $false -and
    $live.support_recovery.json.invariants.rollback_execution_performed -eq $false -and
    $live.support_recovery.json.invariants.active_slot_mutated -eq $false -and
    $live.support_recovery.json.invariants.active_artifact_set_mutated -eq $false -and
    $live.support_recovery.json.invariants.production_ring_mutated -eq $false -and
    $live.support_recovery.json.invariants.remote_dispatch_enabled -eq $false -and
    $live.support_recovery.json.invariants.tui_authority -eq $false

$rollbackBaselineReady = $sourceJson.rc7_rollback_baseline.execution_status.rollback_execution_allowed -eq $false -and
    $sourceJson.rc7_rollback_baseline.previous_active_artifact_set_sha256 -eq $sourceJson.rc7_rollback_baseline.restored_active_artifact_set_sha256 -and
    $live.rollback_baseline.json.rollback_baseline_sha256 -eq $sourceJson.rc7_rollback_baseline.rollback_baseline_sha256 -and
    $live.rollback_baseline.json.execution_status.rollback_execution_allowed -eq $false -and
    $null -ne $rollbackExplainOperation -and
    $rollbackExplainOperation.executable_by_mirror -eq $false -and
    $rollbackExplainOperation.rollback_baseline_sha256 -eq $sourceJson.rc7_rollback_baseline.rollback_baseline_sha256

$compatibilityReady = $live.compatibility.json.production_ready_claim -eq $false -and
    $live.compatibility.json.status -eq "compatibility-projected-verification-blocked" -and
    $live.compatibility.json.authority.mirror_is_root_of_trust -eq $false -and
    $live.compatibility.json.authority.installer_preflight_can_activate -eq $false -and
    $live.compatibility.json.authority.tui_authority -eq $false

$sourceBindings = [ordered]@{}
foreach ($key in $sourceRefs.Keys) {
    $sourceBindings["$($key)_sha256"] = $sourceRefs[$key].sha256
}

$liveBindings = [ordered]@{
    channel = [ordered]@{ path = "/channel/index.json"; sha256 = $live.channel.body_sha256 }
    payload_index = [ordered]@{ path = "/payloads/index.json"; sha256 = $live.payload_index.body_sha256 }
    install_bootstrap = [ordered]@{ path = "/install/bootstrap.json"; sha256 = $live.install_bootstrap.body_sha256 }
    mirror_status = [ordered]@{ path = "/.well-known/aios/rc8-mirror-status.json"; sha256 = $live.mirror_status.body_sha256 }
    support_index = [ordered]@{ path = "/support/index.json"; sha256 = $live.support_index.body_sha256 }
    support_recovery = [ordered]@{ path = "/support/recovery.json"; sha256 = $live.support_recovery.body_sha256 }
    support_readme = [ordered]@{ path = "/support/README.txt"; sha256 = $live.support_readme.body_sha256 }
    compatibility = [ordered]@{ path = $bootstrapEndpoints.compatibility; sha256 = $live.compatibility.body_sha256 }
    rollback_baseline = [ordered]@{ path = $bootstrapEndpoints.rollback_baseline; sha256 = $live.rollback_baseline.body_sha256 }
    object_descriptor = [ordered]@{ path = $bootstrapEndpoints.object_descriptor; sha256 = $live.object_descriptor.body_sha256 }
    signature_receipt = [ordered]@{ path = $bootstrapEndpoints.signature_receipt; sha256 = $live.signature_receipt.body_sha256 }
    installer_preflight = [ordered]@{ path = $bootstrapEndpoints.installer_preflight; sha256 = $live.installer_preflight.body_sha256 }
    installer_fail_closed = [ordered]@{ path = $bootstrapEndpoints.fail_closed_result; sha256 = $live.installer_fail_closed.body_sha256 }
}

$remainingBlockers = @(
    "external-https-object-uri-not-published",
    "declared-current-artifact-drift-unresolved",
    "canary-activation-evidence-not-executed",
    "two-or-more-enrolled-canary-target-nodes-required",
    "remote-fleet-execution-not-enabled",
    "exact-operator-approval-not-granted",
    "AgentCore-PlanSpec-not-bound",
    "AgentCore-rollback-PlanSpec-not-bound",
    "SecurityExecutionEngine-approval-not-bound",
    "SecurityExecutionEngine-rollback-approval-not-bound"
)

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
    recovery_execution_performed = $false
    remote_dispatch_enabled = $false
    model_replay_authority = $false
    normal_shell_authority = $false
    tui_authority = $false
    production_ready_claim = $false
}

$evidenceChain = [ordered]@{
    schema = "agentos.rc8-controlled-execution-support-recovery-chain.v1"
    generated_at = $generatedAt
    status = "support-recovery-bound-controlled-execution-blocked"
    production_ready_claim = $false
    projection_only = $true
    release_id = if ($null -ne $livePayloadEntry) { $livePayloadEntry.release_id } else { "production-distro-rc8-current-artifacts" }
    controlled_execution = [ordered]@{
        activation_allowed = $sourceJson.rc8_activation_result.canary_activation_allowed
        activation_performed = $false
        rollback_readiness_ready = $sourceJson.rc8_rollback_result.rollback_readiness_ready
        rollback_execution_allowed = $sourceJson.rc8_rollback_result.rollback_execution_allowed
        rollback_execution_performed = $false
        support_upload_allowed = $false
        support_upload_performed = $false
        recovery_execution_allowed = $false
        recovery_execution_performed = $false
    }
    support_surface = [ordered]@{
        live_schema = $live.support_index.json.schema
        status = $live.support_index.json.status
        redacted = $live.support_index.json.redacted
        support_upload_allowed = $live.support_index.json.support_upload_allowed
        recovery_execution_allowed = $live.support_index.json.recovery_execution_allowed
        rollback_execution_allowed = $live.support_index.json.rollback_execution_allowed
        inherited_support_channel = $live.support_index.json.channel
    }
    recovery_surface = [ordered]@{
        live_schema = $live.support_recovery.json.schema
        status = $live.support_recovery.json.status
        rollback_baseline_sha256 = $sourceJson.rc7_rollback_baseline.rollback_baseline_sha256
        previous_active_artifact_set_sha256 = $sourceJson.rc7_rollback_baseline.previous_active_artifact_set_sha256
        restored_active_artifact_set_sha256 = $sourceJson.rc7_rollback_baseline.restored_active_artifact_set_sha256
        baseline_consistent = $sourceJson.rc7_rollback_baseline.previous_active_artifact_set_sha256 -eq $sourceJson.rc7_rollback_baseline.restored_active_artifact_set_sha256
        rollback_readiness_operation_executable_by_mirror = if ($null -ne $rollbackExplainOperation) { $rollbackExplainOperation.executable_by_mirror } else { $null }
    }
    source_bindings = $sourceBindings
    live_endpoint_bindings = $liveBindings
    remaining_blockers_before_controlled_execution = $remainingBlockers
    invariants = $invariants
}

$supportBundle = [ordered]@{
    schema = "agentos.rc8-controlled-execution-support-bundle-projection.v1"
    generated_at = $generatedAt
    status = "redacted-local-support-projection"
    production_ready_claim = $false
    projection_only = $true
    local_only = $true
    redacted = $true
    upload_allowed = $false
    upload_performed = $false
    release_id = $evidenceChain.release_id
    sections = [ordered]@{
        activation_denial = [ordered]@{
            source = $sourceRefs.rc8_activation_denial_evidence.path
            sha256 = $sourceRefs.rc8_activation_denial_evidence.sha256
            activation_allowed = $sourceJson.rc8_activation_denial_evidence.activation_allowed
            activation_performed = $sourceJson.rc8_activation_denial_evidence.activation_performed
        }
        rollback_denial = [ordered]@{
            source = $sourceRefs.rc8_rollback_denial_evidence.path
            sha256 = $sourceRefs.rc8_rollback_denial_evidence.sha256
            rollback_execution_allowed = $sourceJson.rc8_rollback_denial_evidence.rollback_execution_allowed
            rollback_execution_performed = $sourceJson.rc8_rollback_denial_evidence.rollback_execution_performed
        }
        mirror_metadata = [ordered]@{
            channel_sha256 = $liveBindings.channel.sha256
            payload_index_sha256 = $liveBindings.payload_index.sha256
            install_bootstrap_sha256 = $liveBindings.install_bootstrap.sha256
            mirror_status_sha256 = $liveBindings.mirror_status.sha256
        }
        support_metadata = [ordered]@{
            support_index_sha256 = $liveBindings.support_index.sha256
            support_recovery_sha256 = $liveBindings.support_recovery.sha256
            support_upload_allowed = $false
            recovery_execution_allowed = $false
        }
    }
    operator_summary = [ordered]@{
        current_state = "controlled-execution-blocked"
        safe_next_task = "RC8-040 final audit or next milestone planning after RC8-032 evidence is committed"
        support_truth = "local hash-bound evidence plus live metadata hashes; no support upload endpoint is enabled"
        recovery_truth = "rollback baseline and denial evidence; no recovery or rollback execution is performed"
    }
    source_bindings = $sourceBindings
    live_endpoint_bindings = $liveBindings
    invariants = $invariants
}

$recoveryIndex = [ordered]@{
    schema = "agentos.rc8-controlled-execution-recovery-reference-index.v1"
    generated_at = $generatedAt
    status = "projection-only-recovery-execution-blocked"
    production_ready_claim = $false
    release_id = $evidenceChain.release_id
    entries = @(
        [ordered]@{ id = "activation-denial"; kind = "local-artifact"; path = $sourceRefs.rc8_activation_denial_evidence.path; sha256 = $sourceRefs.rc8_activation_denial_evidence.sha256; executable = $false },
        [ordered]@{ id = "rollback-denial"; kind = "local-artifact"; path = $sourceRefs.rc8_rollback_denial_evidence.path; sha256 = $sourceRefs.rc8_rollback_denial_evidence.sha256; executable = $false },
        [ordered]@{ id = "rollback-planspec-requirement"; kind = "local-artifact"; path = $sourceRefs.rc8_rollback_planspec_requirement.path; sha256 = $sourceRefs.rc8_rollback_planspec_requirement.sha256; executable = $false },
        [ordered]@{ id = "rollback-baseline"; kind = "live-metadata"; path = $liveBindings.rollback_baseline.path; sha256 = $liveBindings.rollback_baseline.sha256; executable = $false },
        [ordered]@{ id = "compatibility"; kind = "live-metadata"; path = $liveBindings.compatibility.path; sha256 = $liveBindings.compatibility.sha256; executable = $false },
        [ordered]@{ id = "support-index"; kind = "live-metadata"; path = $liveBindings.support_index.path; sha256 = $liveBindings.support_index.sha256; executable = $false },
        [ordered]@{ id = "support-recovery"; kind = "live-metadata"; path = $liveBindings.support_recovery.path; sha256 = $liveBindings.support_recovery.sha256; executable = $false }
    )
    recovery_authority = [ordered]@{
        plan_authority = "AgentCore"
        side_effect_authority = "SecurityExecutionEngine"
        mirror_authority = $false
        signer_authority = $false
        support_metadata_authority = $false
        tui_authority = $false
        shell_authority = $false
        model_replay_authority = $false
    }
    required_before_execution = @(
        "exact operator approval",
        "AgentCore PlanSpec",
        "SecurityExecutionEngine approval",
        "2+ enrolled canary nodes",
        "remote fleet execution gate",
        "external HTTPS object URI",
        "declared/current artifact drift reconciliation"
    )
    invariants = $invariants
}

Write-Json -Value $evidenceChain -Path $evidenceChainPath
Write-Json -Value $supportBundle -Path $supportBundlePath
Write-Json -Value $recoveryIndex -Path $recoveryIndexPath

$evidenceChainHash = Get-FileSha256 $evidenceChainPath
$supportBundleHash = Get-FileSha256 $supportBundlePath
$recoveryIndexHash = Get-FileSha256 $recoveryIndexPath

Add-Check "source.rc8_030.activation_denied_ready" $activationDeniedReady "RC8-032 must bind passed RC8-030 activation denial evidence without treating it as execution." ([ordered]@{ rc8_030 = $sourceJson.rc8_activation_result.summary; approval_granted = $sourceJson.rc8_exact_approval_packet.approval_granted; target_set_enrolled = $sourceJson.rc8_canary_target_set.target_set_enrolled })
Add-Check "source.rc8_031.rollback_denied_ready" $rollbackDeniedReady "RC8-032 must bind passed RC8-031 rollback denial evidence and rollback PlanSpec requirement without executing rollback." ([ordered]@{ rc8_031 = $sourceJson.rc8_rollback_result.summary; planspec_bound = $sourceJson.rc8_rollback_planspec_requirement.agentcore_rollback_planspec_bound })
Add-Check "source.rc8_mirror.metadata_blocked" $mirrorReady "RC8 mirror metadata must remain non-GA, metadata-only, and blocked for install, activation, rollback, and support upload authority." ([ordered]@{ mirror_status = $sourceJson.rc8_mirror_status.status; support_upload_authority = $sourceJson.rc8_hosted_channel_index.authority.support_upload_authority })
Add-Check "live.https.support_recovery.current" $liveReady "Resolve-pinned HTTPS metadata must expose RC8 channel/payload/install metadata plus support/recovery, compatibility, and rollback baseline endpoints." ([ordered]@{ root = $live.root.status_code; support_index = $live.support_index.status_code; support_recovery = $live.support_recovery.status_code; rollback_baseline = $live.rollback_baseline.status_code; release_id = if ($null -ne $livePayloadEntry) { $livePayloadEntry.release_id } else { $null } })
Add-Check "support.metadata.non_authoritative" $supportReady "Support metadata must be redacted, upload-disabled, recovery-disabled, rollback-disabled, and non-authoritative." ([ordered]@{ schema = $live.support_index.json.schema; redacted = $live.support_index.json.redacted; upload = $live.support_index.json.support_upload_allowed; recovery = $live.support_index.json.recovery_execution_allowed })
Add-Check "recovery.operations.non_executable" $recoveryReady "Recovery operations must remain projection-only, non-executable by mirror, and free of active mutations." ([ordered]@{ schema = $live.support_recovery.json.schema; operation_count = @($live.support_recovery.json.operations).Count })
Add-Check "rollback.baseline.bound_to_recovery" $rollbackBaselineReady "Rollback baseline must be live, baseline-consistent, support/recovery bound, and execution-blocked." ([ordered]@{ baseline = $sourceJson.rc7_rollback_baseline.rollback_baseline_sha256; operation = if ($null -ne $rollbackExplainOperation) { $rollbackExplainOperation.id } else { $null } })
Add-Check "compatibility.metadata.non_authoritative" $compatibilityReady "Compatibility metadata must remain verification-blocked and non-authoritative." ([ordered]@{ schema = $live.compatibility.json.schema; status = $live.compatibility.json.status })
Add-Check "support.outputs.projected" ((Test-Path -LiteralPath $evidenceChainPath -PathType Leaf) -and (Test-Path -LiteralPath $supportBundlePath -PathType Leaf) -and (Test-Path -LiteralPath $recoveryIndexPath -PathType Leaf)) "RC8-032 must emit support/recovery evidence chain, support bundle projection, and recovery reference index." ([ordered]@{ evidence_chain = $evidenceChainHash; support_bundle = $supportBundleHash; recovery_index = $recoveryIndexHash })
Add-Check "authority.not_broadened" $true "RC8-032 must not sign, upload payloads, install, activate, rollback, mutate boot/slot/state/rings, upload support, dispatch remotely, or grant TUI authority." $invariants

$secretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $evidenceChainPath),
    (Get-Content -Raw -LiteralPath $supportBundlePath),
    (Get-Content -Raw -LiteralPath $recoveryIndexPath)
)
Add-Check "outputs.secret_safe" $secretSafe "RC8-032 projected artifacts must not contain secret material paths, PEM private blocks, or token markers." $null

$passed = @($script:blockers).Count -eq 0
$result = [ordered]@{
    schema = "agentos.rc8-controlled-execution-support-recovery-result.v1"
    generated_at = $generatedAt
    checked_at = (Get-Date).ToString("o")
    task = "RC8-032"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    rc8_032_complete = $passed
    controlled_execution_support_recovery_bound = $passed
    support_recovery_evidence_projected = $passed
    activation_allowed = $sourceJson.rc8_activation_result.canary_activation_allowed
    activation_performed = $false
    rollback_readiness_ready = $sourceJson.rc8_rollback_result.rollback_readiness_ready
    rollback_execution_allowed = $sourceJson.rc8_rollback_result.rollback_execution_allowed
    rollback_execution_performed = $false
    support_upload_allowed = $false
    support_upload_performed = $false
    recovery_execution_allowed = $false
    recovery_execution_performed = $false
    artifacts = [ordered]@{
        support_recovery_evidence_chain = [ordered]@{
            path = Get-StablePath $evidenceChainPath
            sha256 = $evidenceChainHash
            schema = $evidenceChain.schema
            status = $evidenceChain.status
        }
        controlled_execution_support_bundle = [ordered]@{
            path = Get-StablePath $supportBundlePath
            sha256 = $supportBundleHash
            schema = $supportBundle.schema
            status = $supportBundle.status
        }
        recovery_reference_index = [ordered]@{
            path = Get-StablePath $recoveryIndexPath
            sha256 = $recoveryIndexHash
            schema = $recoveryIndex.schema
            status = $recoveryIndex.status
        }
    }
    source_artifacts = $sourceRefs
    source_bindings = $sourceBindings
    live_endpoint_bindings = $liveBindings
    support_surface = $evidenceChain.support_surface
    recovery_surface = $evidenceChain.recovery_surface
    remaining_blockers_before_controlled_execution = $remainingBlockers
    checks = $script:checks
    blockers = $script:blockers
    invariants = $invariants
    summary = [ordered]@{
        checks = @($script:checks).Count
        blockers = @($script:blockers).Count
        rc8_032_complete = $passed
        controlled_execution_support_recovery_bound = $passed
        support_upload_allowed = $false
        support_upload_performed = $false
        recovery_execution_allowed = $false
        recovery_execution_performed = $false
        activation_allowed = $sourceJson.rc8_activation_result.canary_activation_allowed
        activation_performed = $false
        rollback_readiness_ready = $sourceJson.rc8_rollback_result.rollback_readiness_ready
        rollback_execution_allowed = $sourceJson.rc8_rollback_result.rollback_execution_allowed
        rollback_execution_performed = $false
        production_ready_claim = $false
        next_task = "RC8-040"
    }
}

Write-Json -Value $result -Path $resolvedResultPath

$resultSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resolvedResultPath))
if (-not $resultSecretSafe) {
    $extra = [ordered]@{
        id = "result.secret_safe"
        status = "failed"
        severity = "blocking"
        message = "RC8-032 result must not contain secret material paths, PEM private blocks, or token markers."
        evidence = $null
    }
    $script:checks += $extra
    $script:blockers += $extra
    $result.status = "blocked"
    $result.rc8_032_complete = $false
    $result.controlled_execution_support_recovery_bound = $false
    $result.support_recovery_evidence_projected = $false
    $result.checks = $script:checks
    $result.blockers = $script:blockers
    $result.summary.checks = @($script:checks).Count
    $result.summary.blockers = @($script:blockers).Count
    $result.summary.rc8_032_complete = $false
    $result.summary.controlled_execution_support_recovery_bound = $false
    Write-Json -Value $result -Path $resolvedResultPath
}

Write-Host "RC8 controlled execution support/recovery $($result.status): $(Get-StablePath $resolvedResultPath)"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
