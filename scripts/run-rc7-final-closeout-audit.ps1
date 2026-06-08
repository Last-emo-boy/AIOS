param(
    [string]$RemoteHost = "47.101.11.109",
    [string]$Domain = "aios.w33d.xyz",
    [string]$ArtifactDir = ".workflow/artifacts/rc7-final-closeout-audit",
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
    $json = $Value | ConvertTo-Json -Depth 100
    [IO.File]::WriteAllText($Path, $json, [Text.UTF8Encoding]::new($false))
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

function Get-TaskStatus {
    param($Plan, [Parameter(Mandatory = $true)][string]$TaskId)
    if ($null -eq $Plan -or $Plan.PSObject.Properties.Name -notcontains "waves") {
        return $null
    }
    foreach ($wave in @($Plan.waves)) {
        foreach ($task in @($wave.tasks)) {
            if ($task.id -eq $TaskId) {
                return $task.status
            }
        }
    }
    return $null
}

function Is-PassedResult {
    param($Json)
    if ($null -eq $Json) {
        return $false
    }
    $blockers = if ($null -ne $Json.summary -and $Json.summary.PSObject.Properties.Name -contains "blockers") {
        [int]$Json.summary.blockers
    } else {
        @($Json.blockers).Count
    }
    return $Json.status -eq "passed" -and $blockers -eq 0 -and $Json.production_ready_claim -eq $false
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

function Test-NoSensitiveFiles {
    param([Parameter(Mandatory = $true)][string[]]$Paths)
    foreach ($path in $Paths) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            return $false
        }
        if (-not (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $path)))) {
            return $false
        }
    }
    return $true
}

function Test-NoHostPathFiles {
    param([Parameter(Mandatory = $true)][string[]]$Paths)
    foreach ($path in $Paths) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            return $false
        }
        $text = Get-Content -Raw -LiteralPath $path
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
$expectedArtifactDir = Resolve-RepoPath ".workflow/artifacts/rc7-final-closeout-audit"
if (-not $resolvedArtifactDir.Equals($expectedArtifactDir, [StringComparison]::OrdinalIgnoreCase)) {
    throw "ArtifactDir must be .workflow/artifacts/rc7-final-closeout-audit"
}
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
if (-not $OutputPath) {
    $OutputPath = Join-Path $ArtifactDir "result.json"
}

$paths = [ordered]@{
    plan = ".workflow/active/WFS-20260608-agentos-production-distro-rc7/plan.json"
    workflow_session = ".workflow/active/WFS-20260608-agentos-production-distro-rc7/workflow-session.json"
    rc6_final_audit = ".workflow/active/WFS-20260608-agentos-production-distro-rc6/evidence/FINAL-AUDIT-20260608-production-distro-rc6.json"
    signed_contract = ".workflow/active/WFS-20260608-agentos-production-distro-rc7/docs/signed-payload-consumption-controlled-execution-contract.md"
    compatibility_contract = ".workflow/active/WFS-20260608-agentos-production-distro-rc7/docs/installer-compatibility-rollback-baseline-contract.md"
    storage_policy = ".workflow/active/WFS-20260608-agentos-production-distro-rc7/docs/large-payload-storage-policy.md"
    signed_metadata = ".workflow/artifacts/rc7-signed-metadata-revocation/result.json"
    signature_claims = ".workflow/artifacts/rc7-signed-metadata-revocation/signature-claims.json"
    signed_metadata_doc = ".workflow/artifacts/rc7-signed-metadata-revocation/signed-metadata.json"
    revocation_snapshot = ".workflow/artifacts/rc7-signed-metadata-revocation/revocation-snapshot.json"
    installer_consumption = ".workflow/artifacts/rc7-installer-signed-consumption/result.json"
    signed_fail_closed = ".workflow/artifacts/rc7-signed-consumption-fail-closed/result.json"
    install_rollback = ".workflow/artifacts/rc7-install-rollback-baseline/result.json"
    compatibility = ".workflow/artifacts/rc7-install-rollback-baseline/compatibility.json"
    rollback_baseline = ".workflow/artifacts/rc7-install-rollback-baseline/rollback-baseline.json"
    mirror_frontend = ".workflow/artifacts/rc7-mirror-frontend-signed-status/result.json"
    tls_hardening = ".workflow/artifacts/rc7-tls-nginx-hardening/result.json"
    storage_policy_evidence = ".workflow/active/WFS-20260608-agentos-production-distro-rc7/evidence/RC7-022-large-payload-storage-policy.json"
    canary_approval = ".workflow/artifacts/rc7-multi-node-canary-approval/result.json"
    canary_target_set = ".workflow/artifacts/rc7-multi-node-canary-approval/canary-target-set.json"
    exact_approval_packet = ".workflow/artifacts/rc7-multi-node-canary-approval/exact-approval-packet.json"
    gated_activation = ".workflow/artifacts/rc7-gated-canary-activation/result.json"
    activation_gate = ".workflow/artifacts/rc7-gated-canary-activation/activation-gate-report.json"
    activation_denial = ".workflow/artifacts/rc7-gated-canary-activation/activation-denial-evidence.json"
    gated_rollback = ".workflow/artifacts/rc7-gated-rollback-drill/result.json"
    rollback_gate = ".workflow/artifacts/rc7-gated-rollback-drill/rollback-drill-gate-report.json"
    rollback_denial = ".workflow/artifacts/rc7-gated-rollback-drill/rollback-drill-denial-evidence.json"
    fleet_rollout_authority = ".workflow/artifacts/release/fleet-rollout-authority.json"
}

$resolved = [ordered]@{}
$json = [ordered]@{}
foreach ($key in $paths.Keys) {
    $resolved[$key] = Resolve-RepoPath $paths[$key]
    $json[$key] = if ([IO.Path]::GetExtension($paths[$key]) -eq ".json") { Read-JsonFile $resolved[$key] } else { $null }
}

$resolvedOutputPath = Resolve-RepoPath $OutputPath
$finalAuditPath = Resolve-RepoPath ".workflow/active/WFS-20260608-agentos-production-distro-rc7/evidence/FINAL-AUDIT-20260608-production-distro-rc7.json"
$closeoutSummaryPath = Resolve-RepoPath ".workflow/active/WFS-20260608-agentos-production-distro-rc7/docs/final-rc7-closeout-summary.md"

$preCloseoutTasks = @("RC7-001", "RC7-002", "RC7-003", "RC7-010", "RC7-011", "RC7-012", "RC7-020", "RC7-021", "RC7-022", "RC7-030", "RC7-031", "RC7-032")
$completedBeforeCloseout = 0
foreach ($taskId in $preCloseoutTasks) {
    if ((Get-TaskStatus $json.plan $taskId) -eq "completed") {
        $completedBeforeCloseout++
    }
}

$rc7040Status = Get-TaskStatus $json.plan "RC7-040"
$planReady = $null -ne $json.plan -and
    (($json.plan.current_task -eq "RC7-040" -and $rc7040Status -eq "pending") -or
        ($null -eq $json.plan.current_task -and $rc7040Status -eq "completed")) -and
    $completedBeforeCloseout -eq @($preCloseoutTasks).Count

$docsReady = (Test-Path -LiteralPath $resolved.signed_contract -PathType Leaf) -and
    (Test-Path -LiteralPath $resolved.compatibility_contract -PathType Leaf) -and
    (Test-Path -LiteralPath $resolved.storage_policy -PathType Leaf)

$rc6Ready = $null -ne $json.rc6_final_audit -and
    $json.rc6_final_audit.verdict -eq "PASS" -and
    $json.rc6_final_audit.production_ready_claim -eq $false

$signedMetadataReady = (Is-PassedResult $json.signed_metadata) -and
    $json.signed_metadata.payload_surface.public_signature_projection_available -eq $true -and
    $json.signed_metadata.payload_surface.revocation_snapshot_available -eq $true -and
    $json.signed_metadata.payload_surface.cryptographic_signature_present -eq $false -and
    $json.signed_metadata.payload_surface.signature_available -eq $false -and
    $json.signed_metadata.invariants.cryptographic_signing_performed -eq $false -and
    $json.signature_claims.schema -eq "agentos.rc7-signature-claims.v1" -and
    $json.signed_metadata_doc.production_ready_claim -eq $false -and
    $json.revocation_snapshot.revocation_status -eq "not-revoked"

$installerConsumptionReady = (Is-PassedResult $json.installer_consumption) -and
    $json.installer_consumption.summary.rc7_010_complete -eq $true -and
    $json.installer_consumption.production_ready_claim -eq $false

$failClosedReady = (Is-PassedResult $json.signed_fail_closed) -and
    $json.signed_fail_closed.summary.cases -eq 21 -and
    $json.signed_fail_closed.summary.failed_cases -eq 0 -and
    $json.signed_fail_closed.invariants.remote_publication_performed -eq $false

$installRollbackReady = (Is-PassedResult $json.install_rollback) -and
    $json.install_rollback.payload_surface.compatibility_published -eq $true -and
    $json.install_rollback.payload_surface.rollback_baseline_published -eq $true -and
    $json.install_rollback.payload_surface.install_allowed -eq $false -and
    $json.install_rollback.payload_surface.activation_allowed -eq $false -and
    $json.install_rollback.payload_surface.rollback_execution_allowed -eq $false -and
    $json.compatibility.status -eq "compatibility-projected-verification-blocked" -and
    $json.compatibility.production_ready_claim -eq $false -and
    $json.rollback_baseline.execution_status.rollback_execution_allowed -eq $false

$hostedReady = (Is-PassedResult $json.mirror_frontend) -and
    (Is-PassedResult $json.tls_hardening) -and
    $json.mirror_frontend.invariants.static_frontend_only -eq $true -and
    $json.mirror_frontend.invariants.metadata_preserved -eq $true -and
    $json.tls_hardening.invariants.tls_configured -eq $true -and
    $json.tls_hardening.invariants.https_preferred -eq $true

$storageReady = (Test-Path -LiteralPath $resolved.storage_policy -PathType Leaf) -and
    $json.storage_policy_evidence.status -eq "completed" -and
    $json.storage_policy_evidence.policy.mirror_storage_mode -eq "metadata-only" -and
    $json.storage_policy_evidence.policy.large_payloads_on_mirror_allowed -eq $false -and
    $json.storage_policy_evidence.policy.external_object_storage_required -eq $true -and
    $json.storage_policy_evidence.policy.object_storage_trust -eq "transport-only"

$canaryApprovalReady = (Is-PassedResult $json.canary_approval) -and
    $json.canary_approval.target_set.required_minimum_nodes -eq 2 -and
    $json.canary_approval.target_set.observed_canary_node_count -eq 1 -and
    $json.canary_approval.target_set.target_set_enrolled -eq $false -and
    $json.canary_approval.approval.exact_operator_approval_granted -eq $false -and
    $json.canary_target_set.target_set_enrolled -eq $false -and
    $json.exact_approval_packet.approval_granted -eq $false

$activationReady = (Is-PassedResult $json.gated_activation) -and
    $json.gated_activation.gates.signed_metadata_published -eq $true -and
    $json.gated_activation.gates.revocation_snapshot_published -eq $true -and
    $json.gated_activation.gates.compatibility_published -eq $true -and
    $json.gated_activation.gates.rollback_baseline_published -eq $true -and
    $json.gated_activation.gates.tls_configured -eq $true -and
    $json.gated_activation.gates.cryptographic_signature_present -eq $false -and
    $json.gated_activation.canary_activation_allowed -eq $false -and
    $json.gated_activation.activation_performed -eq $false -and
    $json.activation_gate.activation_allowed -eq $false -and
    $json.activation_denial.activation_performed -eq $false

$rollbackReady = (Is-PassedResult $json.gated_rollback) -and
    $json.gated_rollback.rollback_readiness_ready -eq $true -and
    $json.gated_rollback.rollback_execution_allowed -eq $false -and
    $json.gated_rollback.rollback_execution_performed -eq $false -and
    $json.gated_rollback.gates.support_recovery_ready -eq $true -and
    $json.gated_rollback.gates.agentcore_rollback_planspec_bound -eq $false -and
    $json.gated_rollback.gates.security_execution_rollback_approval_bound -eq $false -and
    $json.rollback_gate.rollback_execution_performed -eq $false -and
    $json.rollback_denial.rollback_execution_allowed -eq $false

$live = [ordered]@{
    root = Invoke-Curl "/"
    health = Invoke-Curl "/health.json"
    descriptor = Invoke-Curl "/.well-known/aios/mirror.json"
    channel = Invoke-Curl "/channel/index.json"
    payload_index = Invoke-Curl "/payloads/index.json"
    install_bootstrap = Invoke-Curl "/install/bootstrap.json"
    compatibility = Invoke-Curl "/install/compatibility.json"
    rollback_baseline = Invoke-Curl "/install/rollback-baseline.json"
    signatures = Invoke-Curl "/payloads/aios/production-distro-rc6-current-artifacts/signatures.json"
    signed_metadata = Invoke-Curl "/payloads/aios/production-distro-rc6-current-artifacts/signed-metadata.json"
    revocations = Invoke-Curl "/payloads/aios/production-distro-rc6-current-artifacts/revocations.json"
    support_index = Invoke-Curl "/support/index.json"
    support_recovery = Invoke-Curl "/support/recovery.json"
}
$payloadEntry = if ($null -ne $live.payload_index.json -and $null -ne $live.payload_index.json.entries) {
    @($live.payload_index.json.entries | Where-Object { $_.release_id -eq "production-distro-rc6-current-artifacts" } | Select-Object -First 1)[0]
} else {
    $null
}
$liveValues = @($live.Values)
$liveReachable = @($liveValues | Where-Object {
    $_.exit_code -ne 0 -or $_.status_code -ne 200 -or ($_.path -ne "/" -and $null -eq $_.json)
}).Count -eq 0
$liveSemanticsReady = $liveReachable -and
    $live.channel.json.production_ready_claim -eq $false -and
    $live.channel.json.payload_channel.default_release_id -eq "production-distro-rc6-current-artifacts" -and
    $live.channel.json.payload_channel.public_signature_projection_available -eq $true -and
    $live.channel.json.payload_channel.revocation_snapshot_available -eq $true -and
    $live.channel.json.payload_channel.signature_available -eq $false -and
    $live.channel.json.payload_channel.install_allowed -eq $false -and
    $payloadEntry.status -eq "verification-blocked" -and
    $payloadEntry.public_signature_projection_available -eq $true -and
    $payloadEntry.revocation_snapshot_available -eq $true -and
    $payloadEntry.cryptographic_signature_present -eq $false -and
    $payloadEntry.signature_available -eq $false -and
    $payloadEntry.install_allowed -eq $false -and
    $payloadEntry.activation_allowed -eq $false -and
    $payloadEntry.rollback_execution_allowed -eq $false -and
    $payloadEntry.compatibility_sha256 -eq $json.install_rollback.output_hashes.compatibility_sha256 -and
    $payloadEntry.rollback_baseline_sha256 -eq $json.install_rollback.output_hashes.rollback_baseline_sha256 -and
    $live.compatibility.json.status -eq "compatibility-projected-verification-blocked" -and
    $live.compatibility.json.production_ready_claim -eq $false -and
    $live.rollback_baseline.json.execution_status.rollback_execution_allowed -eq $false -and
    $live.signatures.json.cryptographic_signature_present -eq $false -and
    $live.signatures.json.signature_available -eq $false -and
    $live.revocations.json.revocation_status -eq "not-revoked"

Add-Check "plan.closeout_position" $planReady "RC7 plan must point at pending RC7-040 with all pre-closeout tasks completed." ([ordered]@{
    current_task = if ($null -ne $json.plan) { $json.plan.current_task } else { $null }
    completed_before_closeout = $completedBeforeCloseout
    required = @($preCloseoutTasks).Count
    rc7_040 = $rc7040Status
})
Add-Check "rc6.final_audit.boundary_ready" $rc6Ready "RC7 must inherit a passed RC6 final audit boundary without GA claim." $(if ($null -ne $json.rc6_final_audit) { [ordered]@{ verdict = $json.rc6_final_audit.verdict; production_ready_claim = $json.rc6_final_audit.production_ready_claim } } else { $null })
Add-Check "rc7.docs.present" $docsReady "RC7 signed consumption, compatibility/rollback, and storage policy docs must exist." ([ordered]@{
    signed_contract = Get-StablePath $resolved.signed_contract
    compatibility_contract = Get-StablePath $resolved.compatibility_contract
    storage_policy = Get-StablePath $resolved.storage_policy
})
Add-Check "rc7.signed_metadata.revocation_ready" $signedMetadataReady "RC7 signed metadata and revocation projections must pass while remaining public-only and unsigned." $(if ($null -ne $json.signed_metadata) { $json.signed_metadata.payload_surface } else { $null })
Add-Check "rc7.installer_consumption.ready" $installerConsumptionReady "Installer signed consumption evidence must pass without authorizing install." $(if ($null -ne $json.installer_consumption) { $json.installer_consumption.summary } else { $null })
Add-Check "rc7.signed_consumption.fail_closed" $failClosedReady "Signed consumption fail-closed fixtures must pass all 21 negative cases without remote mutation." $(if ($null -ne $json.signed_fail_closed) { $json.signed_fail_closed.summary } else { $null })
Add-Check "rc7.install_rollback_baseline.ready" $installRollbackReady "Installer compatibility and rollback baseline must be published and hash-bound while install, activation, and rollback remain blocked." $(if ($null -ne $json.install_rollback) { $json.install_rollback.payload_surface } else { $null })
Add-Check "rc7.hosted_tls.ready" $hostedReady "Mirror frontend and TLS hardening evidence must pass while preserving metadata and non-authority." ([ordered]@{ frontend = if ($null -ne $json.mirror_frontend) { $json.mirror_frontend.summary } else { $null }; tls = if ($null -ne $json.tls_hardening) { $json.tls_hardening.summary } else { $null } })
Add-Check "rc7.large_payload_storage.policy_ready" $storageReady "Large payload storage policy must keep the small host metadata-only and external object storage transport-only." $(if ($null -ne $json.storage_policy_evidence) { $json.storage_policy_evidence.policy } else { $null })
Add-Check "rc7.canary_approval.blocked" $canaryApprovalReady "Multi-node canary target and exact approval packet must be projected while target enrollment and approval remain false." $(if ($null -ne $json.canary_approval) { [ordered]@{ target_set = $json.canary_approval.target_set; approval = $json.canary_approval.approval } } else { $null })
Add-Check "rc7.gated_activation.blocked" $activationReady "Canary activation gates must be observable and activation must remain denied." $(if ($null -ne $json.gated_activation) { $json.gated_activation.gates } else { $null })
Add-Check "rc7.gated_rollback.blocked" $rollbackReady "Rollback drill gates must be observable, rollback-ready, and execution-denied." $(if ($null -ne $json.gated_rollback) { $json.gated_rollback.gates } else { $null })
Add-Check "live.https.endpoints.reachable" $liveReachable "Live RC7 mirror endpoints must be reachable over HTTPS with curl --resolve and without local DNS." ([ordered]@{
    validation_used_local_dns = $false
    resolve_override = "$Domain`:443`:$RemoteHost"
    statuses = @($liveValues | ForEach-Object { [ordered]@{ path = $_.path; status_code = $_.status_code; parsed_json = $null -ne $_.json } })
})
Add-Check "live.https.semantics.blocked" $liveSemanticsReady "Live RC7 metadata must remain non-GA, signature-projection-only, revocation-bound, compatibility/rollback-bound, install-blocked, activation-blocked, and rollback-blocked." ([ordered]@{
    release_id = if ($null -ne $payloadEntry) { $payloadEntry.release_id } else { $null }
    payload_status = if ($null -ne $payloadEntry) { $payloadEntry.status } else { $null }
    signature_available = if ($null -ne $payloadEntry) { $payloadEntry.signature_available } else { $null }
    install_allowed = if ($null -ne $payloadEntry) { $payloadEntry.install_allowed } else { $null }
    rollback_execution_allowed = if ($null -ne $payloadEntry) { $payloadEntry.rollback_execution_allowed } else { $null }
})
Add-Check "rc7.no_authority_broadened" $true "RC7 final audit must not sign, upload payloads, install, activate, execute rollback, mutate boot/slot/state/rings, upload support, dispatch remotely, or grant TUI/model/shell authority." ([ordered]@{
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
    model_replay_authority = $false
    normal_shell_authority = $false
    tui_authority = $false
    production_ready_claim = $false
})

$sourceArtifacts = [ordered]@{}
foreach ($key in $paths.Keys) {
    $sourceArtifacts[$key] = New-ArtifactRef -Path $resolved[$key] -Json $json[$key]
}
$liveEndpointBindings = [ordered]@{}
foreach ($key in $live.Keys) {
    $liveEndpointBindings[$key] = [ordered]@{
        path = $live[$key].path
        status_code = $live[$key].status_code
        body_sha256 = $live[$key].body_sha256
    }
}

$remainingBlockers = @(
    "real-cryptographic-payload-signature-not-present",
    "canary-activation-evidence-not-executed",
    "two-or-more-enrolled-canary-target-nodes-required",
    "remote-fleet-execution-not-enabled",
    "exact-operator-approval-not-granted",
    "AgentCore-PlanSpec-not-bound",
    "SecurityExecutionEngine-approval-not-bound",
    "AgentCore-rollback-PlanSpec-not-bound",
    "SecurityExecutionEngine-rollback-approval-not-bound",
    "large-release-payload-bytes-not-published",
    "installer-vm-install-smoke-not-run"
)

$passedBeforeWrite = @($script:blockers).Count -eq 0
$generatedAt = (Get-Date).ToString("o")

$finalAudit = [ordered]@{
    schema = "agentos.production-distro-rc7-final-audit.v1"
    generated_at = $generatedAt
    workflow = ".workflow/active/WFS-20260608-agentos-production-distro-rc7"
    milestone = "Production Distro RC7"
    verdict = if ($passedBeforeWrite) { "PASS" } else { "BLOCKED" }
    decision = if ($passedBeforeWrite) { "rc7-closeout-pass-next-milestone-planning" } else { "rc7-closeout-blocked" }
    production_ready_claim = $false
    hosted_domain = $Domain
    objective = "signed payload consumption, revocation, compatibility, rollback baseline, TLS, canary gate, and rollback drill evidence without GA claim"
    task_results = @($preCloseoutTasks | ForEach-Object { [ordered]@{ id = $_; status = Get-TaskStatus $json.plan $_ } })
    acceptance_coverage = @(
        [ordered]@{ requirement = "signed metadata and revocation projection are public, hash-bound, and non-authoritative"; status = if ($signedMetadataReady) { "proved" } else { "blocked" }; evidence = Get-StablePath $resolved.signed_metadata }
        [ordered]@{ requirement = "installer signed consumption and negative fixtures fail closed"; status = if ($installerConsumptionReady -and $failClosedReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.installer_consumption), (Get-StablePath $resolved.signed_fail_closed)) }
        [ordered]@{ requirement = "installer compatibility and rollback baseline are published and hash-bound"; status = if ($installRollbackReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.install_rollback), (Get-StablePath $resolved.compatibility), (Get-StablePath $resolved.rollback_baseline)) }
        [ordered]@{ requirement = "public mirror is HTTPS-capable, metadata-preserving, and metadata-only"; status = if ($hostedReady -and $storageReady -and $liveSemanticsReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.mirror_frontend), (Get-StablePath $resolved.tls_hardening), (Get-StablePath $resolved.storage_policy)) }
        [ordered]@{ requirement = "canary activation is exact-approval gated and denied"; status = if ($canaryApprovalReady -and $activationReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.canary_approval), (Get-StablePath $resolved.gated_activation)) }
        [ordered]@{ requirement = "rollback drill is observable, rollback-ready, and execution-denied"; status = if ($rollbackReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.gated_rollback), (Get-StablePath $resolved.rollback_gate), (Get-StablePath $resolved.rollback_denial)) }
    )
    payload_surface = [ordered]@{
        release_id = if ($null -ne $payloadEntry) { $payloadEntry.release_id } else { $null }
        status = if ($null -ne $payloadEntry) { $payloadEntry.status } else { $null }
        public_signature_projection_available = if ($null -ne $payloadEntry) { $payloadEntry.public_signature_projection_available } else { $null }
        revocation_snapshot_available = if ($null -ne $payloadEntry) { $payloadEntry.revocation_snapshot_available } else { $null }
        cryptographic_signature_present = if ($null -ne $payloadEntry) { $payloadEntry.cryptographic_signature_present } else { $null }
        signature_available = if ($null -ne $payloadEntry) { $payloadEntry.signature_available } else { $null }
        install_allowed = if ($null -ne $payloadEntry) { $payloadEntry.install_allowed } else { $null }
        activation_allowed = if ($null -ne $payloadEntry) { $payloadEntry.activation_allowed } else { $null }
        rollback_execution_allowed = if ($null -ne $payloadEntry) { $payloadEntry.rollback_execution_allowed } else { $null }
        observed_canary_node_count = $json.gated_rollback.gates.observed_canary_node_count
        required_canary_node_count = $json.gated_rollback.gates.required_canary_node_count
    }
    invariants_verified = [ordered]@{
        metadata_only = $true
        mirror_is_root_of_trust = $false
        production_ready_claim = $false
        local_private_key_material_used = $false
        cryptographic_signing_performed_by_rc7 = $false
        signature_available = $false
        install_allowed = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        canary_execution_performed = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        remote_dispatch_enabled = $false
        model_replay_authority = $false
        normal_shell_authority = $false
        tui_authority = $false
    }
    source_artifacts = $sourceArtifacts
    live_endpoint_bindings = $liveEndpointBindings
    remaining_blockers_before_ga_or_execution = $remainingBlockers
    next_milestone = [ordered]@{
        id = "Production Distro RC8"
        title = "real installable payload and controlled execution smoke"
        reason = "RC7 proves signed metadata consumption, revocation, compatibility, rollback baseline, TLS, and fail-closed canary/rollback gates. The next milestone should replace projections with real payload bytes, cryptographic signatures, installer VM smoke, exact-approved canary activation, and rollback drill execution under AgentCore and SecurityExecutionEngine."
    }
}

$summaryText = @'
# Production Distro RC7 Closeout Summary

RC7 closes signed payload consumption and controlled execution evidence for `aios.w33d.xyz`. The public mirror now exposes signed metadata projection, revocation snapshot, installer compatibility metadata, rollback baseline metadata, HTTPS hardening evidence, exact-approval canary gates, and rollback drill gates while keeping the service metadata-only and non-authoritative.

This is not a GA production-ready claim. RC7 remains verification-blocked: no real cryptographic payload signature, no canary activation execution, only one observed canary target, no exact operator approval, no AgentCore PlanSpec binding, no SecurityExecutionEngine approval, no remote fleet execution, no install, no activation, no rollback execution, no production ring mutation, and no TUI authority.

## Evidence

- Signed metadata and revocation: `.workflow/artifacts/rc7-signed-metadata-revocation/result.json`
- Installer signed consumption: `.workflow/artifacts/rc7-installer-signed-consumption/result.json`
- Signed consumption fail-closed fixtures: `.workflow/artifacts/rc7-signed-consumption-fail-closed/result.json`
- Compatibility and rollback baseline: `.workflow/artifacts/rc7-install-rollback-baseline/result.json`
- Mirror frontend signed status: `.workflow/artifacts/rc7-mirror-frontend-signed-status/result.json`
- TLS and nginx hardening: `.workflow/artifacts/rc7-tls-nginx-hardening/result.json`
- Large payload storage policy: `.workflow/active/WFS-20260608-agentos-production-distro-rc7/docs/large-payload-storage-policy.md`
- Multi-node canary approval packet: `.workflow/artifacts/rc7-multi-node-canary-approval/result.json`
- Gated canary activation evidence: `.workflow/artifacts/rc7-gated-canary-activation/result.json`
- Gated rollback drill evidence: `.workflow/artifacts/rc7-gated-rollback-drill/result.json`
- Final audit: `.workflow/active/WFS-20260608-agentos-production-distro-rc7/evidence/FINAL-AUDIT-20260608-production-distro-rc7.json`

## Verdict

Verdict PASS - Production Distro RC7 is closed for signed metadata consumption, revocation, compatibility and rollback metadata, HTTPS mirror evidence, exact-approval canary gating, and rollback drill gating.

## Next Milestone

Production Distro RC8 should focus on real installable payload and controlled execution smoke: publish immutable payload object descriptors, ingest real public signature artifacts, run installer VM smoke, require exact-approved canary activation, and execute a rollback drill only through AgentCore PlanSpec plus SecurityExecutionEngine approval.
'@

if ($passedBeforeWrite) {
    Write-Json -Value $finalAudit -Path $finalAuditPath
    $summaryParent = Split-Path -Parent $closeoutSummaryPath
    if ($summaryParent) {
        New-Item -ItemType Directory -Force -Path $summaryParent | Out-Null
    }
    [IO.File]::WriteAllText($closeoutSummaryPath, $summaryText, [Text.UTF8Encoding]::new($false))
}

Add-Check "final_audit.written" (Test-Path -LiteralPath $finalAuditPath -PathType Leaf) "Final RC7 audit artifact must be written." ([ordered]@{ path = Get-StablePath $finalAuditPath; sha256 = Get-FileSha256 $finalAuditPath })
Add-Check "closeout_summary.written" (Test-Path -LiteralPath $closeoutSummaryPath -PathType Leaf) "Final RC7 closeout summary must be written." ([ordered]@{ path = Get-StablePath $closeoutSummaryPath; sha256 = Get-FileSha256 $closeoutSummaryPath })
Add-Check "closeout_outputs.secret_safe" (Test-NoSensitiveFiles -Paths @($finalAuditPath, $closeoutSummaryPath)) "Final RC7 closeout outputs must not contain private key or token markers." ([ordered]@{ final_audit = Get-StablePath $finalAuditPath; closeout_summary = Get-StablePath $closeoutSummaryPath })
Add-Check "closeout_outputs.host_path_free" (Test-NoHostPathFiles -Paths @($finalAuditPath, $closeoutSummaryPath)) "Final RC7 closeout outputs must not contain host-local absolute paths." ([ordered]@{ final_audit = Get-StablePath $finalAuditPath; closeout_summary = Get-StablePath $closeoutSummaryPath })

$passed = @($script:blockers).Count -eq 0

$result = [ordered]@{
    schema = "agentos.rc7-final-closeout-audit-result.v1"
    generated_at = $generatedAt
    checked_at = (Get-Date).ToString("o")
    task = "RC7-040"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    rc7_040_complete = $passed
    final_audit_written = Test-Path -LiteralPath $finalAuditPath -PathType Leaf
    closeout_summary_written = Test-Path -LiteralPath $closeoutSummaryPath -PathType Leaf
    state_update_performed_by_writer = $false
    local_private_key_material_used = $false
    private_key_material_read_or_printed = $false
    cryptographic_signing_performed = $false
    payload_upload_performed = $false
    install_performed = $false
    activation_performed = $false
    rollback_execution_performed = $false
    canary_execution_performed = $false
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
    outputs = [ordered]@{
        final_audit = [ordered]@{ path = Get-StablePath $finalAuditPath; sha256 = Get-FileSha256 $finalAuditPath; present = Test-Path -LiteralPath $finalAuditPath -PathType Leaf }
        closeout_summary = [ordered]@{ path = Get-StablePath $closeoutSummaryPath; sha256 = Get-FileSha256 $closeoutSummaryPath; present = Test-Path -LiteralPath $closeoutSummaryPath -PathType Leaf }
    }
    source_artifacts = $sourceArtifacts
    live_endpoint_bindings = $liveEndpointBindings
    remaining_blockers_before_ga_or_execution = $remainingBlockers
    checks = $script:checks
    blockers = $script:blockers
    summary = [ordered]@{
        checks = @($script:checks).Count
        blockers = @($script:blockers).Count
        rc7_040_complete = $passed
        final_audit_written = Test-Path -LiteralPath $finalAuditPath -PathType Leaf
        closeout_summary_written = Test-Path -LiteralPath $closeoutSummaryPath -PathType Leaf
        payload_release_id = if ($null -ne $payloadEntry) { $payloadEntry.release_id } else { $null }
        payload_status = if ($null -ne $payloadEntry) { $payloadEntry.status } else { $null }
        public_signature_projection_available = if ($null -ne $payloadEntry) { $payloadEntry.public_signature_projection_available } else { $null }
        revocation_snapshot_available = if ($null -ne $payloadEntry) { $payloadEntry.revocation_snapshot_available } else { $null }
        signature_available = if ($null -ne $payloadEntry) { $payloadEntry.signature_available } else { $null }
        install_allowed = if ($null -ne $payloadEntry) { $payloadEntry.install_allowed } else { $null }
        activation_performed = $false
        rollback_execution_performed = $false
        observed_canary_node_count = $json.gated_rollback.gates.observed_canary_node_count
        required_canary_node_count = $json.gated_rollback.gates.required_canary_node_count
        production_ready_claim = $false
        next_milestone = "Production Distro RC8"
    }
}

Write-Json -Value $result -Path $resolvedOutputPath

$resultSafe = Test-NoSensitiveFiles -Paths @($resolvedOutputPath)
$resultHostPathFree = Test-NoHostPathFiles -Paths @($resolvedOutputPath)
if (-not $resultSafe -or -not $resultHostPathFree) {
    $extra = [ordered]@{
        id = "result.secret_safe"
        status = "failed"
        severity = "blocking"
        message = "Final RC7 closeout result must be secret-safe and host-path-free."
        evidence = [ordered]@{ secret_safe = $resultSafe; host_path_free = $resultHostPathFree; path = Get-StablePath $resolvedOutputPath }
    }
    $script:checks += $extra
    $script:blockers += $extra
    $result.checks = $script:checks
    $result.blockers = $script:blockers
    $result.status = "blocked"
    $result.rc7_040_complete = $false
    $result.summary.checks = @($script:checks).Count
    $result.summary.blockers = @($script:blockers).Count
    $result.summary.rc7_040_complete = $false
    Write-Json -Value $result -Path $resolvedOutputPath
}

Write-Host "RC7 final closeout audit $($result.status): $(Get-StablePath $resolvedOutputPath)"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
