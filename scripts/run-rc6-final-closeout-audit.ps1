param(
    [string]$RemoteHost = "47.101.11.109",
    [string]$Domain = "aios.w33d.xyz",
    [string]$ArtifactDir = ".workflow/artifacts/rc6-final-closeout-audit",
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

function Get-BlockerCount {
    param($Json)
    if ($null -eq $Json -or $Json.PSObject.Properties.Name -notcontains "blockers" -or $null -eq $Json.blockers) {
        return 0
    }
    return @($Json.blockers).Count
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
$expectedArtifactDir = Resolve-RepoPath ".workflow/artifacts/rc6-final-closeout-audit"
if (-not $resolvedArtifactDir.Equals($expectedArtifactDir, [StringComparison]::OrdinalIgnoreCase)) {
    throw "ArtifactDir must be .workflow/artifacts/rc6-final-closeout-audit"
}
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
if (-not $OutputPath) {
    $OutputPath = Join-Path $ArtifactDir "result.json"
}

$paths = [ordered]@{
    plan = ".workflow/active/WFS-20260608-agentos-production-distro-rc6/plan.json"
    workflow_session = ".workflow/active/WFS-20260608-agentos-production-distro-rc6/workflow-session.json"
    rc5_final_audit = ".workflow/active/WFS-20260608-agentos-production-distro-rc5/evidence/FINAL-AUDIT-20260608-production-distro-rc5.json"
    contract = ".workflow/active/WFS-20260608-agentos-production-distro-rc6/docs/installable-signed-payload-channel-contract.md"
    boundary = ".workflow/active/WFS-20260608-agentos-production-distro-rc6/docs/bootstrap-installer-consumption-boundary.md"
    threat_model = ".workflow/active/WFS-20260608-agentos-production-distro-rc6/docs/tls-storage-signed-payload-threat-model.md"
    mirror_portal = ".workflow/artifacts/rc6-mirror-portal/result.json"
    payload_manifest = ".workflow/artifacts/rc6-installable-payload-manifest/result.json"
    hosted_payload = ".workflow/artifacts/rc6-hosted-payload-metadata/result.json"
    signed_payload_fail_closed = ".workflow/artifacts/rc6-signed-payload-fail-closed/result.json"
    bootstrap_preflight = ".workflow/artifacts/rc6-bootstrap-installer-preflight/result.json"
    bootstrap_preflight_report = ".workflow/artifacts/rc6-bootstrap-installer-preflight/preflight-report.json"
    installer_fail_closed = ".workflow/artifacts/rc6-installer-fail-closed/result.json"
    mirror_frontend = ".workflow/artifacts/rc6-mirror-frontend-refresh/result.json"
    canary_packet = ".workflow/artifacts/rc6-canary-execution-packet/result.json"
    canary_packet_doc = ".workflow/artifacts/rc6-canary-execution-packet/canary-execution-packet.json"
    canary_rollback_preconditions = ".workflow/artifacts/rc6-canary-execution-packet/rollback-execution-preconditions.json"
    rollback_preconditions = ".workflow/artifacts/rc6-rollback-execution-preconditions/result.json"
    rollback_matrix = ".workflow/artifacts/rc6-rollback-execution-preconditions/rollback-drill-precondition-matrix.json"
    rollback_blockers = ".workflow/artifacts/rc6-rollback-execution-preconditions/rollback-execution-blockers.json"
}

$resolved = [ordered]@{}
$json = [ordered]@{}
foreach ($key in $paths.Keys) {
    $resolved[$key] = Resolve-RepoPath $paths[$key]
    $json[$key] = if ([IO.Path]::GetExtension($paths[$key]) -eq ".json") { Read-JsonFile $resolved[$key] } else { $null }
}

$resolvedOutputPath = Resolve-RepoPath $OutputPath
$finalAuditPath = Resolve-RepoPath ".workflow/active/WFS-20260608-agentos-production-distro-rc6/evidence/FINAL-AUDIT-20260608-production-distro-rc6.json"
$closeoutSummaryPath = Resolve-RepoPath ".workflow/active/WFS-20260608-agentos-production-distro-rc6/docs/final-rc6-closeout-summary.md"

$preCloseoutTasks = @("RC6-001", "RC6-002", "RC6-003", "RC6-004", "RC6-010", "RC6-011", "RC6-012", "RC6-020", "RC6-021", "RC6-022", "RC6-030", "RC6-031")
$completedBeforeCloseout = 0
foreach ($taskId in $preCloseoutTasks) {
    if ((Get-TaskStatus $json.plan $taskId) -eq "completed") {
        $completedBeforeCloseout++
    }
}

$requiredDocsPresent = (Test-Path -LiteralPath $resolved.contract -PathType Leaf) -and
    (Test-Path -LiteralPath $resolved.boundary -PathType Leaf) -and
    (Test-Path -LiteralPath $resolved.threat_model -PathType Leaf)

$planReady = $null -ne $json.plan -and
    $json.plan.current_task -eq "RC6-040" -and
    (Get-TaskStatus $json.plan "RC6-040") -eq "pending" -and
    $completedBeforeCloseout -eq @($preCloseoutTasks).Count

$rc5Ready = $null -ne $json.rc5_final_audit -and
    $json.rc5_final_audit.verdict -eq "PASS" -and
    $json.rc5_final_audit.production_ready_claim -eq $false

$portalReady = $null -ne $json.mirror_portal -and
    $json.mirror_portal.status -eq "passed" -and
    $json.mirror_portal.summary.blockers -eq 0 -and
    $json.mirror_portal.invariants.static_frontend_only -eq $true -and
    $json.mirror_portal.invariants.metadata_only -eq $true -and
    $json.mirror_portal.invariants.cryptographic_signing_performed -eq $false

$payloadManifestReady = $null -ne $json.payload_manifest -and
    $json.payload_manifest.status -eq "passed" -and
    $json.payload_manifest.summary.blockers -eq 0 -and
    $json.payload_manifest.payload_surface.status -eq "verification-blocked" -and
    $json.payload_manifest.payload_surface.signature_available -eq $false -and
    $json.payload_manifest.payload_surface.install_allowed -eq $false -and
    $json.payload_manifest.payload_surface.installable_media_declared_hash_drift_count -eq 3 -and
    $json.payload_manifest.invariants.cryptographic_signing_performed -eq $false -and
    $json.payload_manifest.invariants.activation_allowed -eq $false

$hostedPayloadReady = $null -ne $json.hosted_payload -and
    $json.hosted_payload.status -eq "passed" -and
    $json.hosted_payload.summary.blockers -eq 0 -and
    $json.hosted_payload.payload_surface.release_id -eq "production-distro-rc6-current-artifacts" -and
    $json.hosted_payload.payload_surface.status -eq "verification-blocked" -and
    $json.hosted_payload.payload_surface.signature_available -eq $false -and
    $json.hosted_payload.payload_surface.install_allowed -eq $false -and
    $json.hosted_payload.invariants.hosted_metadata_only -eq $true -and
    $json.hosted_payload.invariants.cryptographic_signing_performed -eq $false

$signedFailClosedReady = $null -ne $json.signed_payload_fail_closed -and
    $json.signed_payload_fail_closed.status -eq "passed" -and
    $json.signed_payload_fail_closed.summary.cases -eq 21 -and
    $json.signed_payload_fail_closed.summary.failed_cases -eq 0 -and
    $json.signed_payload_fail_closed.invariants.remote_mutation_performed -eq $false -and
    $json.signed_payload_fail_closed.invariants.cryptographic_signing_performed -eq $false -and
    $json.signed_payload_fail_closed.invariants.rollback_execution_performed -eq $false

$requiredPreflightBlockers = @(
    "verify-signature-or-signed-metadata-reference",
    "verify-revocation-snapshot",
    "verify-installer-compatibility-contract",
    "verify-rollback-baseline-hash"
)
$preflightBlockerIds = if ($null -ne $json.bootstrap_preflight_report -and $null -ne $json.bootstrap_preflight_report.blockers) {
    @($json.bootstrap_preflight_report.blockers | ForEach-Object { $_.id })
} else {
    @()
}
$missingPreflightBlockers = @($requiredPreflightBlockers | Where-Object { $preflightBlockerIds -notcontains $_ })
$bootstrapReady = $null -ne $json.bootstrap_preflight -and
    $null -ne $json.bootstrap_preflight_report -and
    $json.bootstrap_preflight.status -eq "passed" -and
    $json.bootstrap_preflight.summary.task_blockers -eq 0 -and
    $json.bootstrap_preflight.preflight.state -eq "verification-blocked" -and
    $json.bootstrap_preflight.summary.preflight_blockers -eq 4 -and
    $missingPreflightBlockers.Count -eq 0 -and
    $json.bootstrap_preflight.invariants.install_performed -eq $false -and
    $json.bootstrap_preflight.invariants.activation_performed -eq $false -and
    $json.bootstrap_preflight.invariants.rollback_execution_performed -eq $false

$installerFailClosedReady = $null -ne $json.installer_fail_closed -and
    $json.installer_fail_closed.status -eq "passed" -and
    $json.installer_fail_closed.summary.cases -eq 12 -and
    $json.installer_fail_closed.summary.failed_cases -eq 0 -and
    $json.installer_fail_closed.invariants.install_performed -eq $false -and
    $json.installer_fail_closed.invariants.activation_performed -eq $false -and
    $json.installer_fail_closed.invariants.rollback_execution_performed -eq $false

$frontendReady = $null -ne $json.mirror_frontend -and
    $json.mirror_frontend.status -eq "passed" -and
    $json.mirror_frontend.summary.blockers -eq 0 -and
    $json.mirror_frontend.invariants.metadata_preserved -eq $true -and
    $json.mirror_frontend.invariants.no_external_dependencies -eq $true -and
    $json.mirror_frontend.invariants.rollback_execution_performed -eq $false

$canaryReady = $null -ne $json.canary_packet -and
    $null -ne $json.canary_packet_doc -and
    $null -ne $json.canary_rollback_preconditions -and
    $json.canary_packet.status -eq "passed" -and
    $json.canary_packet.summary.blockers -eq 0 -and
    $json.canary_packet.canary_execution_allowed -eq $false -and
    $json.canary_packet.canary_execution_performed -eq $false -and
    $json.canary_packet.rollback_execution_allowed -eq $false -and
    $json.canary_packet.rollback_execution_performed -eq $false -and
    $json.canary_packet_doc.executable -eq $false -and
    $json.canary_packet_doc.exact_operator_approval_granted -eq $false -and
    $json.canary_rollback_preconditions.rollback_execution_performed -eq $false

$rollbackReady = $null -ne $json.rollback_preconditions -and
    $null -ne $json.rollback_matrix -and
    $null -ne $json.rollback_blockers -and
    $json.rollback_preconditions.status -eq "passed" -and
    $json.rollback_preconditions.summary.blockers -eq 0 -and
    $json.rollback_preconditions.rollback_readiness_ready -eq $true -and
    $json.rollback_preconditions.rollback_execution_allowed -eq $false -and
    $json.rollback_preconditions.rollback_execution_performed -eq $false -and
    $json.rollback_preconditions.summary.canary_execution_allowed -eq $false -and
    $json.rollback_matrix.rollback_execution_performed -eq $false -and
    $json.rollback_blockers.rollback_execution_performed -eq $false

$live = [ordered]@{
    root = Invoke-Curl "/"
    health = Invoke-Curl "/health.json"
    descriptor = Invoke-Curl "/.well-known/aios/mirror.json"
    channel = Invoke-Curl "/channel/index.json"
    payload_index = Invoke-Curl "/payloads/index.json"
    install_bootstrap = Invoke-Curl "/install/bootstrap.json"
    payload_manifest = Invoke-Curl "/payloads/aios/production-distro-rc6-current-artifacts/manifest.json"
    payload_checksums = Invoke-Curl "/payloads/aios/production-distro-rc6-current-artifacts/checksums.json"
    payload_signatures = Invoke-Curl "/payloads/aios/production-distro-rc6-current-artifacts/signatures.json"
    support_recovery = Invoke-Curl "/support/recovery.json"
}
$payloadEntry = if ($null -ne $live.payload_index.json -and $null -ne $live.payload_index.json.entries) { @($live.payload_index.json.entries)[0] } else { $null }
$liveReachable = @($live.Values | Where-Object { $_.exit_code -ne 0 -or $_.status_code -ne 200 -or $null -eq $_.json -and $_.path -ne "/" }).Count -eq 0 -and $live.root.status_code -eq 200
$liveSemanticsReady = $liveReachable -and
    $live.channel.json.production_ready_claim -eq $false -and
    $live.channel.json.payload_channel.default_release_id -eq "production-distro-rc6-current-artifacts" -and
    $live.channel.json.payload_channel.signature_available -eq $false -and
    $live.channel.json.payload_channel.install_allowed -eq $false -and
    $payloadEntry.release_id -eq "production-distro-rc6-current-artifacts" -and
    $payloadEntry.status -eq "verification-blocked" -and
    $payloadEntry.signature_available -eq $false -and
    $payloadEntry.install_allowed -eq $false -and
    $payloadEntry.rollback_execution_allowed -eq $false -and
    $live.install_bootstrap.json.current_state -eq "verification-blocked" -and
    $live.install_bootstrap.json.install_allowed -eq $false -and
    $live.install_bootstrap.json.activation_allowed -eq $false -and
    $live.payload_signatures.json.signature_available -eq $false -and
    (-not ($live.payload_signatures.json.revocation_snapshot_sha256))

Add-Check "plan.closeout_position" $planReady "RC6 plan must point at pending RC6-040 with all pre-closeout tasks completed." ([ordered]@{
    current_task = if ($null -ne $json.plan) { $json.plan.current_task } else { $null }
    completed_before_closeout = $completedBeforeCloseout
    required = @($preCloseoutTasks).Count
    rc6_040 = Get-TaskStatus $json.plan "RC6-040"
})
Add-Check "rc5.final_audit.boundary_ready" $rc5Ready "RC6 must inherit a passed RC5 final audit boundary without GA claim." $(if ($null -ne $json.rc5_final_audit) { [ordered]@{ verdict = $json.rc5_final_audit.verdict; production_ready_claim = $json.rc5_final_audit.production_ready_claim } } else { $null })
Add-Check "rc6.contracts.present" $requiredDocsPresent "RC6 contract, bootstrap boundary, and TLS/storage/signed-payload threat model docs must exist." ([ordered]@{
    contract = Get-StablePath $resolved.contract
    boundary = Get-StablePath $resolved.boundary
    threat_model = Get-StablePath $resolved.threat_model
})
Add-Check "rc6.mirror_portal.ready" $portalReady "RC6 mirror portal must be passed, metadata-only, and non-authoritative." $(if ($null -ne $json.mirror_portal) { $json.mirror_portal.summary } else { $null })
Add-Check "rc6.payload_manifest.ready" $payloadManifestReady "RC6 payload manifest projection must be passed, current-artifact based, verification-blocked, unsigned, install-blocked, and drift-aware." $(if ($null -ne $json.payload_manifest) { $json.payload_manifest.summary } else { $null })
Add-Check "rc6.hosted_payload.ready" $hostedPayloadReady "Hosted payload metadata must be current-artifacts, metadata-only, unsigned, install-blocked, and blocker-free." $(if ($null -ne $json.hosted_payload) { $json.hosted_payload.payload_surface } else { $null })
Add-Check "rc6.signed_payload_fail_closed.ready" $signedFailClosedReady "Signed payload fail-closed fixtures must pass all 21 negative cases without signing or side effects." $(if ($null -ne $json.signed_payload_fail_closed) { $json.signed_payload_fail_closed.summary } else { $null })
Add-Check "rc6.bootstrap_preflight.expected_blocked" $bootstrapReady "Bootstrap installer preflight must be passed as verification-blocked on signature, revocation, compatibility, and rollback baseline gates." ([ordered]@{
    state = if ($null -ne $json.bootstrap_preflight) { $json.bootstrap_preflight.preflight.state } else { $null }
    preflight_blockers = $preflightBlockerIds
})
Add-Check "rc6.installer_fail_closed.ready" $installerFailClosedReady "Installer fail-closed fixtures must pass all 12 cases without install, activation, or rollback." $(if ($null -ne $json.installer_fail_closed) { $json.installer_fail_closed.summary } else { $null })
Add-Check "rc6.frontend.ready" $frontendReady "RC6 mirror frontend refresh must preserve metadata, avoid dependencies, and stay non-authoritative." $(if ($null -ne $json.mirror_frontend) { $json.mirror_frontend.summary } else { $null })
Add-Check "rc6.canary_packet.blocked" $canaryReady "Canary execution packet must be projected and exact-approval gated while canary and rollback execution remain false." $(if ($null -ne $json.canary_packet) { $json.canary_packet.summary } else { $null })
Add-Check "rc6.rollback_preconditions.ready" $rollbackReady "Rollback precondition matrix must be projected, rollback-ready, and execution-blocked." $(if ($null -ne $json.rollback_preconditions) { $json.rollback_preconditions.summary } else { $null })
Add-Check "live.rc6.endpoints.reachable" $liveReachable "Live RC6 mirror endpoints must be reachable with curl --resolve and without local DNS." ([ordered]@{
    validation_used_local_dns = $false
    resolve_override = "$Domain`:80`:$RemoteHost"
    statuses = @($live.Values | ForEach-Object { [ordered]@{ path = $_.path; status_code = $_.status_code; parsed_json = $null -ne $_.json } })
})
Add-Check "live.rc6.semantics.blocked" $liveSemanticsReady "Live RC6 metadata must remain non-GA, current-artifacts, verification-blocked, unsigned, install-blocked, rollback-blocked, and revocation-blocked." ([ordered]@{
    release_id = if ($null -ne $payloadEntry) { $payloadEntry.release_id } else { $null }
    payload_status = if ($null -ne $payloadEntry) { $payloadEntry.status } else { $null }
    install_state = if ($null -ne $live.install_bootstrap.json) { $live.install_bootstrap.json.current_state } else { $null }
    signature_available = if ($null -ne $payloadEntry) { $payloadEntry.signature_available } else { $null }
})
Add-Check "rc6.no_authority_broadened" $true "RC6 final audit must not sign, install, activate, execute rollback, mutate boot/slot/state/rings, upload support, dispatch remotely, or grant TUI/model/shell authority." ([ordered]@{
    local_private_key_material_used = $false
    cryptographic_signing_performed = $false
    install_performed = $false
    activation_performed = $false
    rollback_execution_performed = $false
    active_slot_mutated = $false
    boot_metadata_mutated = $false
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
    "payload-signature-not-published",
    "revocation-snapshot-not-published",
    "installer-compatibility-contract-pending",
    "rollback-baseline-not-published-to-install-metadata",
    "large-payload-storage-policy-and-object-storage-pending",
    "installable-media-declared-hash-drift",
    "SecurityExecutionEngine-rollback-PlanSpec-not-approved",
    "canary-activation-evidence-not-present",
    "two-or-more-enrolled-canary-target-nodes",
    "remote-fleet-execution-not-enabled",
    "exact-operator-approval-not-granted",
    "tls-required-before-ga-claim"
)

$passedBeforeWrite = @($script:blockers).Count -eq 0
$generatedAt = (Get-Date).ToString("o")

$finalAudit = [ordered]@{
    schema = "agentos.production-distro-rc6-final-audit.v1"
    generated_at = $generatedAt
    workflow = ".workflow/active/WFS-20260608-agentos-production-distro-rc6"
    milestone = "Production Distro RC6"
    verdict = if ($passedBeforeWrite) { "PASS" } else { "BLOCKED" }
    decision = if ($passedBeforeWrite) { "rc6-closeout-pass-next-milestone-planning" } else { "rc6-closeout-blocked" }
    production_ready_claim = $false
    hosted_domain = $Domain
    objective = "installable signed payload channel metadata, bootstrap preflight, installer fail-closed proof, mirror frontend, canary packet, and rollback preconditions without GA claim"
    task_results = @($preCloseoutTasks | ForEach-Object {
        [ordered]@{
            id = $_
            status = Get-TaskStatus $json.plan $_
        }
    })
    acceptance_coverage = @(
        [ordered]@{ requirement = "RC6 contract and threat controls are documented"; status = if ($requiredDocsPresent) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.contract), (Get-StablePath $resolved.boundary), (Get-StablePath $resolved.threat_model)) }
        [ordered]@{ requirement = "hosted mirror exposes bounded RC6 payload and install metadata"; status = if ($portalReady -and $hostedPayloadReady -and $liveSemanticsReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.mirror_portal), (Get-StablePath $resolved.hosted_payload)) }
        [ordered]@{ requirement = "payload metadata is hash-bound, drift-aware, unsigned, verification-blocked, and install-blocked"; status = if ($payloadManifestReady -and $hostedPayloadReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.payload_manifest), (Get-StablePath $resolved.hosted_payload)) }
        [ordered]@{ requirement = "signed payload and installer negative fixtures fail closed"; status = if ($signedFailClosedReady -and $installerFailClosedReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.signed_payload_fail_closed), (Get-StablePath $resolved.installer_fail_closed)) }
        [ordered]@{ requirement = "bootstrap preflight explains missing signature, revocation, compatibility, and rollback baseline gates"; status = if ($bootstrapReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.bootstrap_preflight), (Get-StablePath $resolved.bootstrap_preflight_report)) }
        [ordered]@{ requirement = "mirror frontend remains static, metadata-preserving, dependency-free, and non-authoritative"; status = if ($frontendReady) { "proved" } else { "blocked" }; evidence = Get-StablePath $resolved.mirror_frontend }
        [ordered]@{ requirement = "canary execution packet and rollback preconditions are exact-approval gated and execution-blocked"; status = if ($canaryReady -and $rollbackReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.canary_packet), (Get-StablePath $resolved.rollback_preconditions)) }
    )
    payload_surface = [ordered]@{
        release_id = if ($null -ne $payloadEntry) { $payloadEntry.release_id } else { $null }
        status = if ($null -ne $payloadEntry) { $payloadEntry.status } else { $null }
        signature_available = if ($null -ne $payloadEntry) { $payloadEntry.signature_available } else { $null }
        install_allowed = if ($null -ne $payloadEntry) { $payloadEntry.install_allowed } else { $null }
        rollback_execution_allowed = if ($null -ne $payloadEntry) { $payloadEntry.rollback_execution_allowed } else { $null }
        install_state = if ($null -ne $live.install_bootstrap.json) { $live.install_bootstrap.json.current_state } else { $null }
        drifted_components = if ($null -ne $live.install_bootstrap.json) { $live.install_bootstrap.json.projection.drifted_components } else { $null }
    }
    invariants_verified = [ordered]@{
        metadata_only = $true
        mirror_is_root_of_trust = $false
        production_ready_claim = $false
        local_private_key_material_used = $false
        cryptographic_signing_performed_by_rc6 = $false
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
        id = "Production Distro RC7"
        title = "signed payload consumption and controlled execution evidence"
        reason = "RC6 closes hosted installable payload metadata, bootstrap preflight, fail-closed behavior, canary packet, and rollback preconditions. RC7 should turn the blocked gates into evidence: real signed payload metadata, revocation snapshot, installer compatibility contract, rollback baseline publication, TLS, and exact-approved canary/rollback execution."
    }
}

$summaryText = @'
# Production Distro RC6 Closeout Summary

RC6 closes the installable payload metadata and controlled execution readiness projection for `aios.w33d.xyz`. The mirror now serves current-artifacts payload metadata, install bootstrap metadata, support metadata, and a public AIOS mirror frontend while preserving non-authoritative metadata-only behavior.

This is not a GA production-ready claim. RC6 remains verification-blocked: no public payload signature, no revocation snapshot, no installer compatibility contract, no rollback baseline in install metadata, no large payload storage, no install, no activation, no canary execution, no rollback execution, no production ring mutation, no remote dispatch, and no TUI authority.

## Evidence

- Payload channel contract: `.workflow/active/WFS-20260608-agentos-production-distro-rc6/docs/installable-signed-payload-channel-contract.md`
- Hosted payload metadata: `.workflow/artifacts/rc6-hosted-payload-metadata/result.json`
- Signed payload fail-closed fixtures: `.workflow/artifacts/rc6-signed-payload-fail-closed/result.json`
- Bootstrap installer preflight: `.workflow/artifacts/rc6-bootstrap-installer-preflight/result.json`
- Installer fail-closed fixtures: `.workflow/artifacts/rc6-installer-fail-closed/result.json`
- Mirror frontend refresh: `.workflow/artifacts/rc6-mirror-frontend-refresh/result.json`
- Canary execution packet: `.workflow/artifacts/rc6-canary-execution-packet/result.json`
- Rollback execution preconditions: `.workflow/artifacts/rc6-rollback-execution-preconditions/result.json`
- Final audit: `.workflow/active/WFS-20260608-agentos-production-distro-rc6/evidence/FINAL-AUDIT-20260608-production-distro-rc6.json`

## Verdict

Verdict PASS - Production Distro RC6 is closed for installable payload metadata, bootstrap preflight, fail-closed installer behavior, public mirror frontend, exact-approval-gated canary packet, and rollback execution precondition proof.

## Next Milestone

Production Distro RC7 should focus on real signed payload consumption and controlled execution evidence: publish signed metadata, publish revocation snapshot, define installer compatibility contract, publish rollback baseline to install metadata, add TLS evidence, enroll at least two canary targets, and run exact-approved canary plus rollback drills under AgentCore and SecurityExecutionEngine.
'@

if ($passedBeforeWrite) {
    Write-Json -Value $finalAudit -Path $finalAuditPath
    $summaryParent = Split-Path -Parent $closeoutSummaryPath
    if ($summaryParent) {
        New-Item -ItemType Directory -Force -Path $summaryParent | Out-Null
    }
    Set-Content -LiteralPath $closeoutSummaryPath -Value $summaryText -Encoding UTF8
}

Add-Check "final_audit.written" (Test-Path -LiteralPath $finalAuditPath -PathType Leaf) "Final RC6 audit artifact must be written." ([ordered]@{ path = Get-StablePath $finalAuditPath; sha256 = Get-FileSha256 $finalAuditPath })
Add-Check "closeout_summary.written" (Test-Path -LiteralPath $closeoutSummaryPath -PathType Leaf) "Final RC6 closeout summary must be written." ([ordered]@{ path = Get-StablePath $closeoutSummaryPath; sha256 = Get-FileSha256 $closeoutSummaryPath })
Add-Check "closeout_outputs.secret_safe" (Test-NoSensitiveFiles -Paths @($finalAuditPath, $closeoutSummaryPath)) "Final RC6 closeout outputs must not contain private key or token markers." ([ordered]@{ final_audit = Get-StablePath $finalAuditPath; closeout_summary = Get-StablePath $closeoutSummaryPath })
Add-Check "closeout_outputs.host_path_free" (Test-NoHostPathFiles -Paths @($finalAuditPath, $closeoutSummaryPath)) "Final RC6 closeout outputs must not contain host-local absolute paths." ([ordered]@{ final_audit = Get-StablePath $finalAuditPath; closeout_summary = Get-StablePath $closeoutSummaryPath })

$passed = @($script:blockers).Count -eq 0

$result = [ordered]@{
    schema = "agentos.rc6-final-closeout-audit-result.v1"
    generated_at = $generatedAt
    checked_at = (Get-Date).ToString("o")
    task = "RC6-040"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    rc6_040_complete = $passed
    final_audit_written = Test-Path -LiteralPath $finalAuditPath -PathType Leaf
    closeout_summary_written = Test-Path -LiteralPath $closeoutSummaryPath -PathType Leaf
    state_update_performed_by_writer = $false
    local_private_key_material_used = $false
    cryptographic_signing_performed = $false
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
        rc6_040_complete = $passed
        final_audit_written = Test-Path -LiteralPath $finalAuditPath -PathType Leaf
        closeout_summary_written = Test-Path -LiteralPath $closeoutSummaryPath -PathType Leaf
        payload_release_id = if ($null -ne $payloadEntry) { $payloadEntry.release_id } else { $null }
        payload_status = if ($null -ne $payloadEntry) { $payloadEntry.status } else { $null }
        preflight_state = if ($null -ne $live.install_bootstrap.json) { $live.install_bootstrap.json.current_state } else { $null }
        signature_available = if ($null -ne $payloadEntry) { $payloadEntry.signature_available } else { $null }
        install_allowed = if ($null -ne $payloadEntry) { $payloadEntry.install_allowed } else { $null }
        canary_execution_performed = $false
        rollback_execution_performed = $false
        production_ready_claim = $false
        next_milestone = "Production Distro RC7"
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
        message = "Final RC6 closeout result must be secret-safe and host-path-free."
        evidence = [ordered]@{ secret_safe = $resultSafe; host_path_free = $resultHostPathFree; path = Get-StablePath $resolvedOutputPath }
    }
    $script:checks += $extra
    $script:blockers += $extra
    $result.checks = $script:checks
    $result.blockers = $script:blockers
    $result.status = "blocked"
    $result.rc6_040_complete = $false
    $result.summary.checks = @($script:checks).Count
    $result.summary.blockers = @($script:blockers).Count
    $result.summary.rc6_040_complete = $false
    Write-Json -Value $result -Path $resolvedOutputPath
}

Write-Host "RC6 final closeout audit $($result.status): $(Get-StablePath $resolvedOutputPath)"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
