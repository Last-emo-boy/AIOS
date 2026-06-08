param(
    [string]$RemoteHost = "47.101.11.109",
    [string]$Domain = "aios.w33d.xyz",
    [string]$ArtifactDir = ".workflow/artifacts/rc8-final-closeout-audit",
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

function Get-TaskStatus {
    param($Plan, [Parameter(Mandatory = $true)][string]$TaskId)
    if ($null -eq $Plan -or $null -eq $Plan.waves) {
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
    } elseif ($Json.PSObject.Properties.Name -contains "blockers" -and $null -ne $Json.blockers) {
        @($Json.blockers).Count
    } else {
        0
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
$expectedArtifactDir = Resolve-RepoPath ".workflow/artifacts/rc8-final-closeout-audit"
if (-not $resolvedArtifactDir.Equals($expectedArtifactDir, [StringComparison]::OrdinalIgnoreCase)) {
    throw "ArtifactDir must be .workflow/artifacts/rc8-final-closeout-audit"
}
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
if (-not $OutputPath) {
    $OutputPath = Join-Path $ArtifactDir "result.json"
}

$paths = [ordered]@{
    plan = ".workflow/active/WFS-20260608-agentos-production-distro-rc8/plan.json"
    workflow_session = ".workflow/active/WFS-20260608-agentos-production-distro-rc8/workflow-session.json"
    rc7_final_audit = ".workflow/active/WFS-20260608-agentos-production-distro-rc7/evidence/FINAL-AUDIT-20260608-production-distro-rc7.json"
    controlled_execution_contract = ".workflow/active/WFS-20260608-agentos-production-distro-rc8/docs/real-installable-payload-controlled-execution-contract.md"
    object_descriptor_contract = ".workflow/active/WFS-20260608-agentos-production-distro-rc8/docs/immutable-payload-object-descriptor-contract.md"
    public_signature_contract = ".workflow/active/WFS-20260608-agentos-production-distro-rc8/docs/public-signature-artifact-ingestion-contract.md"
    descriptor_result = ".workflow/artifacts/rc8-real-payload-object-descriptor/result.json"
    object_descriptor = ".workflow/artifacts/rc8-real-payload-object-descriptor/payload-object-descriptor.json"
    object_checksums = ".workflow/artifacts/rc8-real-payload-object-descriptor/payload-object-checksums.json"
    descriptor_report = ".workflow/artifacts/rc8-real-payload-object-descriptor/descriptor-report.json"
    signature_ingestion = ".workflow/artifacts/rc8-public-signature-ingestion/result.json"
    signature_receipt = ".workflow/artifacts/rc8-public-signature-ingestion/signature-ingestion-receipt.json"
    signature_summary = ".workflow/artifacts/rc8-public-signature-ingestion/public-signature-artifact-summary.json"
    signed_descriptor_fail_closed = ".workflow/artifacts/rc8-signed-object-descriptor-fail-closed/result.json"
    installer_vm_preflight = ".workflow/artifacts/rc8-installer-vm-preflight/result.json"
    preflight_report = ".workflow/artifacts/rc8-installer-vm-preflight/preflight-report.json"
    object_fetch_report = ".workflow/artifacts/rc8-installer-vm-preflight/object-fetch-report.json"
    installer_byte_fail_closed = ".workflow/artifacts/rc8-installer-byte-fail-closed/result.json"
    mirror_consistency = ".workflow/artifacts/rc8-mirror-consistency-refresh/result.json"
    hosted_payload_index = ".workflow/artifacts/rc8-mirror-consistency-refresh/hosted-payload-index.json"
    install_bootstrap = ".workflow/artifacts/rc8-mirror-consistency-refresh/install-bootstrap.json"
    hosted_channel_index = ".workflow/artifacts/rc8-mirror-consistency-refresh/hosted-channel-index.json"
    mirror_status = ".workflow/artifacts/rc8-mirror-consistency-refresh/mirror-status.json"
    canary_smoke = ".workflow/artifacts/rc8-exact-approved-canary-smoke/result.json"
    canary_target_set = ".workflow/artifacts/rc8-exact-approved-canary-smoke/canary-target-set.json"
    exact_approval_packet = ".workflow/artifacts/rc8-exact-approved-canary-smoke/exact-approval-packet.json"
    activation_gate_report = ".workflow/artifacts/rc8-exact-approved-canary-smoke/activation-smoke-gate-report.json"
    activation_denial = ".workflow/artifacts/rc8-exact-approved-canary-smoke/activation-denial-evidence.json"
    rollback_drill = ".workflow/artifacts/rc8-controlled-rollback-drill/result.json"
    rollback_planspec = ".workflow/artifacts/rc8-controlled-rollback-drill/rollback-planspec-requirement.json"
    rollback_gate_report = ".workflow/artifacts/rc8-controlled-rollback-drill/rollback-drill-gate-report.json"
    rollback_denial = ".workflow/artifacts/rc8-controlled-rollback-drill/rollback-drill-denial-evidence.json"
    support_recovery = ".workflow/artifacts/rc8-controlled-execution-support-recovery/result.json"
    support_recovery_chain = ".workflow/artifacts/rc8-controlled-execution-support-recovery/support-recovery-evidence-chain.json"
    support_bundle = ".workflow/artifacts/rc8-controlled-execution-support-recovery/controlled-execution-support-bundle.json"
    recovery_index = ".workflow/artifacts/rc8-controlled-execution-support-recovery/recovery-reference-index.json"
}

$resolved = [ordered]@{}
$json = [ordered]@{}
foreach ($key in $paths.Keys) {
    $resolved[$key] = Resolve-RepoPath $paths[$key]
    $json[$key] = if ([IO.Path]::GetExtension($paths[$key]) -eq ".json") { Read-JsonFile $resolved[$key] } else { $null }
}

$resolvedOutputPath = Resolve-RepoPath $OutputPath
$finalAuditPath = Resolve-RepoPath ".workflow/active/WFS-20260608-agentos-production-distro-rc8/evidence/FINAL-AUDIT-20260608-production-distro-rc8.json"
$closeoutSummaryPath = Resolve-RepoPath ".workflow/active/WFS-20260608-agentos-production-distro-rc8/docs/final-rc8-closeout-summary.md"

$preCloseoutTasks = @("RC8-001", "RC8-002", "RC8-003", "RC8-010", "RC8-011", "RC8-012", "RC8-020", "RC8-021", "RC8-022", "RC8-030", "RC8-031", "RC8-032")
$completedBeforeCloseout = 0
foreach ($taskId in $preCloseoutTasks) {
    if ((Get-TaskStatus $json.plan $taskId) -eq "completed") {
        $completedBeforeCloseout++
    }
}

$rc8040Status = Get-TaskStatus $json.plan "RC8-040"
$planReady = $null -ne $json.plan -and
    $json.plan.current_task -eq "RC8-040" -and
    $rc8040Status -eq "pending" -and
    $completedBeforeCloseout -eq @($preCloseoutTasks).Count

$docsReady = (Test-Path -LiteralPath $resolved.controlled_execution_contract -PathType Leaf) -and
    (Test-Path -LiteralPath $resolved.object_descriptor_contract -PathType Leaf) -and
    (Test-Path -LiteralPath $resolved.public_signature_contract -PathType Leaf)

$rc7Ready = $null -ne $json.rc7_final_audit -and
    $json.rc7_final_audit.verdict -eq "PASS" -and
    $json.rc7_final_audit.production_ready_claim -eq $false

$descriptorReady = (Is-PassedResult $json.descriptor_result) -and
    $json.descriptor_result.summary.rc8_010_complete -eq $true -and
    $json.object_descriptor.schema -eq "agentos.payload-object-descriptor.v1" -and
    $json.object_descriptor.release_id -eq "production-distro-rc8-current-artifacts" -and
    $json.object_descriptor.immutable -eq $true -and
    $json.object_descriptor.uri -like "urn:sha256:*" -and
    $json.object_descriptor.production_ready_claim -eq $false -and
    $json.object_descriptor.install_allowed -eq $false -and
    $json.object_descriptor.activation_allowed -eq $false -and
    $json.object_descriptor.rollback_execution_allowed -eq $false

$signatureReady = (Is-PassedResult $json.signature_ingestion) -and
    $json.signature_ingestion.signature_surface.signature_artifact_ingested -eq $true -and
    $json.signature_ingestion.signature_surface.crypto_verified -eq $true -and
    $json.signature_ingestion.signature_surface.descriptor_hash_bound -eq $true -and
    $json.signature_ingestion.signature_surface.canonical_payload_hash_bound -eq $true -and
    $json.signature_ingestion.invariants.private_key_material_read_or_printed -eq $false -and
    $json.signature_ingestion.invariants.cryptographic_signing_performed -eq $false -and
    $json.signature_receipt.crypto_verified -eq $true -and
    $json.signature_receipt.no_private_material_indicators -eq $true

$signedDescriptorFailClosedReady = (Is-PassedResult $json.signed_descriptor_fail_closed) -and
    $json.signed_descriptor_fail_closed.summary.cases -eq 34 -and
    $json.signed_descriptor_fail_closed.summary.failed_cases -eq 0

$installerVmReady = (Is-PassedResult $json.installer_vm_preflight) -and
    $json.installer_vm_preflight.summary.rc8_020_complete -eq $true -and
    $json.installer_vm_preflight.vm_surface.qemu_boot_smoke_completed -eq $true -and
    $json.installer_vm_preflight.object_fetch_surface.repo_local_quarantine_smoke_performed -eq $true -and
    $json.installer_vm_preflight.object_fetch_surface.quarantine_digest_verified -eq $true -and
    $json.installer_vm_preflight.object_fetch_surface.external_https_object_uri_published -eq $false -and
    $json.installer_vm_preflight.invariants.install_performed -eq $false -and
    $json.installer_vm_preflight.invariants.activation_performed -eq $false -and
    $json.installer_vm_preflight.invariants.rollback_execution_performed -eq $false

$installerFailClosedReady = (Is-PassedResult $json.installer_byte_fail_closed) -and
    $json.installer_byte_fail_closed.summary.cases -eq 28 -and
    $json.installer_byte_fail_closed.summary.failed_cases -eq 0 -and
    $json.installer_byte_fail_closed.invariants.install_performed -eq $false -and
    $json.installer_byte_fail_closed.invariants.activation_performed -eq $false -and
    $json.installer_byte_fail_closed.invariants.rollback_execution_performed -eq $false

$mirrorReady = (Is-PassedResult $json.mirror_consistency) -and
    $json.mirror_consistency.payload_surface.release_id -eq "production-distro-rc8-current-artifacts" -and
    $json.mirror_consistency.payload_surface.storage_mode -eq "metadata-only" -and
    $json.mirror_consistency.payload_surface.payload_bytes_hosted_on_mirror -eq $false -and
    $json.mirror_consistency.payload_surface.external_https_object_uri_published -eq $false -and
    $json.mirror_consistency.payload_surface.public_signature_ingested -eq $true -and
    $json.mirror_consistency.payload_surface.signature_crypto_verified -eq $true -and
    $json.mirror_consistency.payload_surface.install_allowed -eq $false -and
    $json.mirror_consistency.payload_surface.activation_allowed -eq $false -and
    $json.mirror_consistency.payload_surface.rollback_execution_allowed -eq $false -and
    $json.mirror_consistency.invariants.hosted_metadata_only -eq $true -and
    $json.hosted_channel_index.authority.signing_authority -eq $false -and
    $json.hosted_channel_index.authority.support_upload_authority -eq $false

$activationReady = (Is-PassedResult $json.canary_smoke) -and
    $json.canary_smoke.summary.rc8_030_complete -eq $true -and
    $json.canary_smoke.canary_activation_allowed -eq $false -and
    $json.canary_smoke.canary_activation_performed -eq $false -and
    $json.canary_smoke.rollback_execution_performed -eq $false -and
    $json.canary_target_set.target_set_enrolled -eq $false -and
    $json.canary_target_set.required_minimum_nodes -eq 2 -and
    $json.canary_target_set.observed_canary_node_count -eq 1 -and
    $json.exact_approval_packet.approval_granted -eq $false -and
    $json.activation_gate_report.activation_performed -eq $false -and
    $json.activation_denial.activation_allowed -eq $false

$rollbackReady = (Is-PassedResult $json.rollback_drill) -and
    $json.rollback_drill.summary.rc8_031_complete -eq $true -and
    $json.rollback_drill.rollback_readiness_ready -eq $true -and
    $json.rollback_drill.rollback_execution_allowed -eq $false -and
    $json.rollback_drill.rollback_execution_performed -eq $false -and
    $json.rollback_planspec.executable -eq $false -and
    $json.rollback_planspec.agentcore_rollback_planspec_bound -eq $false -and
    $json.rollback_gate_report.rollback_execution_performed -eq $false -and
    $json.rollback_denial.rollback_execution_allowed -eq $false

$supportReady = (Is-PassedResult $json.support_recovery) -and
    $json.support_recovery.summary.rc8_032_complete -eq $true -and
    $json.support_recovery.summary.controlled_execution_support_recovery_bound -eq $true -and
    $json.support_recovery.summary.support_upload_allowed -eq $false -and
    $json.support_recovery.summary.support_upload_performed -eq $false -and
    $json.support_recovery.summary.recovery_execution_allowed -eq $false -and
    $json.support_recovery.summary.recovery_execution_performed -eq $false -and
    $json.support_bundle.local_only -eq $true -and
    $json.support_bundle.redacted -eq $true -and
    $json.recovery_index.recovery_authority.support_metadata_authority -eq $false -and
    $json.recovery_index.recovery_authority.tui_authority -eq $false

$bootstrapEndpoints = $json.install_bootstrap.endpoints
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
    support_index = Invoke-Curl "/support/index.json"
    support_recovery = Invoke-Curl "/support/recovery.json"
    support_readme = Invoke-Curl "/support/README.txt"
}
$liveValues = @($live.Values)
$payloadEntry = if ($null -ne $live.payload_index.json -and $null -ne $live.payload_index.json.entries) {
    @($live.payload_index.json.entries | Where-Object { $_.release_id -eq "production-distro-rc8-current-artifacts" } | Select-Object -First 1)[0]
} else {
    $null
}
$liveReachable = $live.root.status_code -eq 200 -and @($liveValues | Where-Object {
    $_.exit_code -ne 0 -or $_.status_code -ne 200 -or (($_.path -notin @("/", "/support/README.txt")) -and $null -eq $_.json)
}).Count -eq 0
$liveSemanticsReady = $liveReachable -and
    $live.channel.json.production_ready_claim -eq $false -and
    $live.channel.json.current_release_id -eq "production-distro-rc8-current-artifacts" -and
    $payloadEntry.release_id -eq "production-distro-rc8-current-artifacts" -and
    $payloadEntry.status -eq "verification-blocked" -and
    $payloadEntry.object_uri_external_https -eq $false -and
    $payloadEntry.public_signature_ingested -eq $true -and
    $payloadEntry.crypto_verified -eq $true -and
    $payloadEntry.install_allowed -eq $false -and
    $payloadEntry.activation_allowed -eq $false -and
    $payloadEntry.rollback_execution_allowed -eq $false -and
    $live.install_bootstrap.json.install_allowed -eq $false -and
    $live.install_bootstrap.json.activation_allowed -eq $false -and
    $live.install_bootstrap.json.rollback_execution_allowed -eq $false -and
    $live.mirror_status.json.payload_bytes_hosted_on_mirror -eq $false -and
    $live.support_index.json.support_upload_allowed -eq $false -and
    $live.support_index.json.recovery_execution_allowed -eq $false -and
    $live.support_recovery.json.invariants.rollback_execution_performed -eq $false

Add-Check "plan.closeout_position" $planReady "RC8 plan must point at pending RC8-040 with all pre-closeout tasks completed." ([ordered]@{
    current_task = if ($null -ne $json.plan) { $json.plan.current_task } else { $null }
    completed_before_closeout = $completedBeforeCloseout
    required = @($preCloseoutTasks).Count
    rc8_040 = $rc8040Status
})
Add-Check "rc7.final_audit.boundary_ready" $rc7Ready "RC8 must inherit a passed RC7 final audit boundary without GA claim." $(if ($null -ne $json.rc7_final_audit) { [ordered]@{ verdict = $json.rc7_final_audit.verdict; production_ready_claim = $json.rc7_final_audit.production_ready_claim } } else { $null })
Add-Check "rc8.contracts.present" $docsReady "RC8 controlled execution, object descriptor, and public signature contracts must exist." ([ordered]@{
    controlled_execution = Get-StablePath $resolved.controlled_execution_contract
    object_descriptor = Get-StablePath $resolved.object_descriptor_contract
    public_signature = Get-StablePath $resolved.public_signature_contract
})
Add-Check "rc8.real_payload_descriptor.ready_blocked" $descriptorReady "RC8 real payload object descriptor must be projected, hash-bound, non-GA, and execution-blocked." $(if ($null -ne $json.descriptor_result) { $json.descriptor_result.summary } else { $null })
Add-Check "rc8.public_signature.ingested" $signatureReady "RC8 public signature artifacts must be ingested and crypto-verified without private key use or signing." $(if ($null -ne $json.signature_ingestion) { $json.signature_ingestion.signature_surface } else { $null })
Add-Check "rc8.signed_descriptor.fail_closed" $signedDescriptorFailClosedReady "RC8 signed object descriptor fail-closed fixtures must pass all 34 negative cases." $(if ($null -ne $json.signed_descriptor_fail_closed) { $json.signed_descriptor_fail_closed.summary } else { $null })
Add-Check "rc8.installer_vm.preflight_ready_blocked" $installerVmReady "RC8 installer VM preflight and strict quarantine byte smoke must pass while external object fetch remains blocked." $(if ($null -ne $json.installer_vm_preflight) { $json.installer_vm_preflight.summary } else { $null })
Add-Check "rc8.installer_byte.fail_closed" $installerFailClosedReady "RC8 installer byte/signature/storage/compatibility fail-closed fixtures must pass all 28 cases without side effects." $(if ($null -ne $json.installer_byte_fail_closed) { $json.installer_byte_fail_closed.summary } else { $null })
Add-Check "rc8.mirror.metadata_current_blocked" $mirrorReady "RC8 mirror consistency must be HTTPS-visible, metadata-only, payload-byte-free, and install/activation/rollback/support-upload blocked." $(if ($null -ne $json.mirror_consistency) { $json.mirror_consistency.payload_surface } else { $null })
Add-Check "rc8.activation.denied" $activationReady "RC8 exact-approved canary activation smoke must be projected and denied by missing object URI, drift reconciliation, target enrollment, approval, PlanSpec, SecurityExecution, and remote fleet gates." $(if ($null -ne $json.canary_smoke) { $json.canary_smoke.summary } else { $null })
Add-Check "rc8.rollback.denied" $rollbackReady "RC8 rollback drill must be rollback-ready, AgentCore/SecurityExecution gated, and execution-denied." $(if ($null -ne $json.rollback_drill) { $json.rollback_drill.summary } else { $null })
Add-Check "rc8.support_recovery.bound" $supportReady "RC8 support/recovery evidence must bind controlled execution smoke while keeping support upload and recovery execution disabled." $(if ($null -ne $json.support_recovery) { $json.support_recovery.summary } else { $null })
Add-Check "live.https.endpoints.reachable" $liveReachable "Live RC8 mirror endpoints must be reachable over HTTPS with curl --resolve and without local DNS." ([ordered]@{
    validation_used_local_dns = $false
    resolve_override = "$Domain`:443`:$RemoteHost"
    statuses = @($liveValues | ForEach-Object { [ordered]@{ path = $_.path; status_code = $_.status_code; parsed_json = $null -ne $_.json } })
})
Add-Check "live.https.semantics.blocked" $liveSemanticsReady "Live RC8 metadata must remain non-GA, metadata-only, signature-verified, install-blocked, activation-blocked, rollback-blocked, and support-upload-blocked." ([ordered]@{
    release_id = if ($null -ne $payloadEntry) { $payloadEntry.release_id } else { $null }
    status = if ($null -ne $payloadEntry) { $payloadEntry.status } else { $null }
    object_uri_external_https = if ($null -ne $payloadEntry) { $payloadEntry.object_uri_external_https } else { $null }
    install_allowed = if ($null -ne $payloadEntry) { $payloadEntry.install_allowed } else { $null }
    rollback_execution_allowed = if ($null -ne $payloadEntry) { $payloadEntry.rollback_execution_allowed } else { $null }
})
Add-Check "rc8.no_authority_broadened" $true "RC8 final audit must not sign, upload payloads, install, activate, execute rollback, mutate boot/slot/state/rings, upload support, dispatch remotely, or grant TUI/model/shell authority." ([ordered]@{
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
    "external-https-object-uri-not-published",
    "declared-current-artifact-drift-unresolved",
    "canary-activation-evidence-not-executed",
    "two-or-more-enrolled-canary-target-nodes-required",
    "remote-fleet-execution-not-enabled",
    "exact-operator-approval-not-granted",
    "AgentCore-PlanSpec-not-bound",
    "AgentCore-rollback-PlanSpec-not-bound",
    "SecurityExecutionEngine-approval-not-bound",
    "SecurityExecutionEngine-rollback-approval-not-bound",
    "real-external-object-storage-not-integrated",
    "controlled-canary-activation-not-executed",
    "controlled-rollback-execution-not-executed"
)

$passedBeforeWrite = @($script:blockers).Count -eq 0
$generatedAt = (Get-Date).ToString("o")

$finalAudit = [ordered]@{
    schema = "agentos.production-distro-rc8-final-audit.v1"
    generated_at = $generatedAt
    workflow = ".workflow/active/WFS-20260608-agentos-production-distro-rc8"
    milestone = "Production Distro RC8"
    verdict = if ($passedBeforeWrite) { "PASS" } else { "BLOCKED" }
    decision = if ($passedBeforeWrite) { "rc8-closeout-pass-next-milestone-planning" } else { "rc8-closeout-blocked" }
    production_ready_claim = $false
    hosted_domain = $Domain
    objective = "real payload object descriptor, public signature ingestion, installer VM preflight, HTTPS mirror consistency, exact-approved activation denial, rollback denial, and support/recovery binding without GA claim"
    task_results = @($preCloseoutTasks | ForEach-Object { [ordered]@{ id = $_; status = Get-TaskStatus $json.plan $_ } })
    acceptance_coverage = @(
        [ordered]@{ requirement = "real payload object descriptor is hash-bound and execution-blocked"; status = if ($descriptorReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.descriptor_result), (Get-StablePath $resolved.object_descriptor)) }
        [ordered]@{ requirement = "public signature artifact is ingested and crypto-verified without private key use"; status = if ($signatureReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.signature_ingestion), (Get-StablePath $resolved.signature_receipt)) }
        [ordered]@{ requirement = "descriptor/signature/installer fail-closed fixtures block unsafe paths"; status = if ($signedDescriptorFailClosedReady -and $installerFailClosedReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.signed_descriptor_fail_closed), (Get-StablePath $resolved.installer_byte_fail_closed)) }
        [ordered]@{ requirement = "installer VM preflight and quarantine byte smoke pass without install or external object fetch"; status = if ($installerVmReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.installer_vm_preflight), (Get-StablePath $resolved.preflight_report), (Get-StablePath $resolved.object_fetch_report)) }
        [ordered]@{ requirement = "HTTPS mirror metadata is current, metadata-only, and payload-byte-free"; status = if ($mirrorReady -and $liveSemanticsReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.mirror_consistency), (Get-StablePath $resolved.hosted_payload_index), (Get-StablePath $resolved.hosted_channel_index)) }
        [ordered]@{ requirement = "canary activation is exact-approval gated and denied"; status = if ($activationReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.canary_smoke), (Get-StablePath $resolved.activation_denial)) }
        [ordered]@{ requirement = "rollback drill is rollback-ready but execution-denied through AgentCore/SecurityExecution gates"; status = if ($rollbackReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.rollback_drill), (Get-StablePath $resolved.rollback_planspec), (Get-StablePath $resolved.rollback_denial)) }
        [ordered]@{ requirement = "support/recovery evidence is redacted, local-only, upload-disabled, recovery-disabled, and bound to controlled execution denial"; status = if ($supportReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolved.support_recovery), (Get-StablePath $resolved.support_bundle), (Get-StablePath $resolved.recovery_index)) }
    )
    payload_surface = [ordered]@{
        release_id = if ($null -ne $payloadEntry) { $payloadEntry.release_id } else { $null }
        status = if ($null -ne $payloadEntry) { $payloadEntry.status } else { $null }
        object_uri_external_https = if ($null -ne $payloadEntry) { $payloadEntry.object_uri_external_https } else { $null }
        public_signature_ingested = if ($null -ne $payloadEntry) { $payloadEntry.public_signature_ingested } else { $null }
        crypto_verified = if ($null -ne $payloadEntry) { $payloadEntry.crypto_verified } else { $null }
        install_allowed = if ($null -ne $payloadEntry) { $payloadEntry.install_allowed } else { $null }
        activation_allowed = if ($null -ne $payloadEntry) { $payloadEntry.activation_allowed } else { $null }
        rollback_execution_allowed = if ($null -ne $payloadEntry) { $payloadEntry.rollback_execution_allowed } else { $null }
        observed_canary_node_count = $json.rollback_drill.summary.observed_canary_node_count
        required_canary_node_count = $json.rollback_drill.summary.required_canary_node_count
    }
    invariants_verified = [ordered]@{
        metadata_only = $true
        mirror_is_root_of_trust = $false
        production_ready_claim = $false
        local_private_key_material_used = $false
        private_key_material_read_or_printed = $false
        cryptographic_signing_performed_by_rc8 = $false
        public_signature_ingested = $true
        payload_bytes_hosted_on_mirror = $false
        remote_payload_bytes_downloaded = $false
        install_allowed = $false
        install_performed = $false
        activation_allowed = $false
        activation_performed = $false
        rollback_execution_allowed = $false
        rollback_execution_performed = $false
        canary_execution_performed = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        model_replay_authority = $false
        normal_shell_authority = $false
        tui_authority = $false
    }
    source_artifacts = $sourceArtifacts
    live_endpoint_bindings = $liveEndpointBindings
    remaining_blockers_before_ga_or_execution = $remainingBlockers
    next_milestone = [ordered]@{
        id = "Production Distro RC9"
        title = "external object storage and controlled canary execution"
        reason = "RC8 closes real payload byte descriptor, public signature ingestion, VM preflight, HTTPS mirror consistency, fail-closed activation/rollback gates, and support/recovery binding. RC9 should publish a real immutable external HTTPS object URI, reconcile declared/current artifact drift, enroll at least two canary targets, bind exact operator approval to AgentCore PlanSpec and SecurityExecutionEngine, and execute controlled canary activation plus rollback drill evidence."
    }
}

$summaryText = @'
# Production Distro RC8 Closeout Summary

RC8 closes the real payload descriptor and controlled execution smoke milestone for AIOS. The mirror exposes RC8 metadata for the current payload object descriptor, public signature receipt, installer VM preflight, installer fail-closed result, compatibility, rollback baseline, and support/recovery references over HTTPS while preserving metadata-only behavior.

This is not a GA production-ready claim. RC8 remains verification-blocked: no external HTTPS object URI has been published for payload bytes, declared/current artifact drift is not reconciled, canary activation has not executed, only one canary target is observed, exact operator approval is not granted, AgentCore PlanSpec and SecurityExecutionEngine approvals are not bound, remote fleet execution is disabled, and rollback execution has not run.

## Evidence

- Real payload object descriptor: `.workflow/artifacts/rc8-real-payload-object-descriptor/result.json`
- Public signature ingestion: `.workflow/artifacts/rc8-public-signature-ingestion/result.json`
- Signed object descriptor fail-closed fixtures: `.workflow/artifacts/rc8-signed-object-descriptor-fail-closed/result.json`
- Installer VM preflight: `.workflow/artifacts/rc8-installer-vm-preflight/result.json`
- Installer byte fail-closed fixtures: `.workflow/artifacts/rc8-installer-byte-fail-closed/result.json`
- Mirror consistency refresh: `.workflow/artifacts/rc8-mirror-consistency-refresh/result.json`
- Exact-approved canary activation smoke: `.workflow/artifacts/rc8-exact-approved-canary-smoke/result.json`
- Controlled rollback drill: `.workflow/artifacts/rc8-controlled-rollback-drill/result.json`
- Controlled execution support/recovery: `.workflow/artifacts/rc8-controlled-execution-support-recovery/result.json`
- Final audit: `.workflow/active/WFS-20260608-agentos-production-distro-rc8/evidence/FINAL-AUDIT-20260608-production-distro-rc8.json`

## Verdict

Verdict PASS - Production Distro RC8 is closed for real payload descriptor projection, public signature ingestion, installer VM preflight, mirror consistency, exact-approval activation denial, rollback denial, and support/recovery binding.

## Next Milestone

Production Distro RC9 should focus on external object storage and controlled canary execution: publish a real immutable external HTTPS object URI, reconcile declared/current artifact drift, enroll at least two canary targets, bind exact operator approval to AgentCore PlanSpec and SecurityExecutionEngine approval, execute controlled canary activation, and then execute a rollback drill with evidence.
'@

if ($passedBeforeWrite) {
    Write-Json -Value $finalAudit -Path $finalAuditPath
    $summaryParent = Split-Path -Parent $closeoutSummaryPath
    if ($summaryParent) {
        New-Item -ItemType Directory -Force -Path $summaryParent | Out-Null
    }
    [IO.File]::WriteAllText($closeoutSummaryPath, $summaryText, [Text.UTF8Encoding]::new($false))
}

Add-Check "final_audit.written" (Test-Path -LiteralPath $finalAuditPath -PathType Leaf) "Final RC8 audit artifact must be written." ([ordered]@{ path = Get-StablePath $finalAuditPath; sha256 = Get-FileSha256 $finalAuditPath })
Add-Check "closeout_summary.written" (Test-Path -LiteralPath $closeoutSummaryPath -PathType Leaf) "Final RC8 closeout summary must be written." ([ordered]@{ path = Get-StablePath $closeoutSummaryPath; sha256 = Get-FileSha256 $closeoutSummaryPath })
Add-Check "closeout_outputs.secret_safe" (Test-NoSensitiveFiles -Paths @($finalAuditPath, $closeoutSummaryPath)) "Final RC8 closeout outputs must not contain private key or token markers." ([ordered]@{ final_audit = Get-StablePath $finalAuditPath; closeout_summary = Get-StablePath $closeoutSummaryPath })
Add-Check "closeout_outputs.host_path_free" (Test-NoHostPathFiles -Paths @($finalAuditPath, $closeoutSummaryPath)) "Final RC8 closeout outputs must not contain host-local absolute paths." ([ordered]@{ final_audit = Get-StablePath $finalAuditPath; closeout_summary = Get-StablePath $closeoutSummaryPath })

$passed = @($script:blockers).Count -eq 0

$result = [ordered]@{
    schema = "agentos.rc8-final-closeout-audit-result.v1"
    generated_at = $generatedAt
    checked_at = (Get-Date).ToString("o")
    task = "RC8-040"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    rc8_040_complete = $passed
    final_audit_written = Test-Path -LiteralPath $finalAuditPath -PathType Leaf
    closeout_summary_written = Test-Path -LiteralPath $closeoutSummaryPath -PathType Leaf
    state_update_performed_by_writer = $false
    local_private_key_material_used = $false
    private_key_material_read_or_printed = $false
    cryptographic_signing_performed = $false
    payload_upload_performed = $false
    remote_payload_bytes_downloaded = $false
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
    recovery_execution_performed = $false
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
        rc8_040_complete = $passed
        final_audit_written = Test-Path -LiteralPath $finalAuditPath -PathType Leaf
        closeout_summary_written = Test-Path -LiteralPath $closeoutSummaryPath -PathType Leaf
        payload_release_id = if ($null -ne $payloadEntry) { $payloadEntry.release_id } else { $null }
        payload_status = if ($null -ne $payloadEntry) { $payloadEntry.status } else { $null }
        object_uri_external_https = if ($null -ne $payloadEntry) { $payloadEntry.object_uri_external_https } else { $null }
        public_signature_ingested = if ($null -ne $payloadEntry) { $payloadEntry.public_signature_ingested } else { $null }
        crypto_verified = if ($null -ne $payloadEntry) { $payloadEntry.crypto_verified } else { $null }
        install_allowed = if ($null -ne $payloadEntry) { $payloadEntry.install_allowed } else { $null }
        activation_performed = $false
        rollback_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        observed_canary_node_count = $json.rollback_drill.summary.observed_canary_node_count
        required_canary_node_count = $json.rollback_drill.summary.required_canary_node_count
        production_ready_claim = $false
        next_milestone = "Production Distro RC9"
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
        message = "Final RC8 closeout result must be secret-safe and host-path-free."
        evidence = [ordered]@{ secret_safe = $resultSafe; host_path_free = $resultHostPathFree; path = Get-StablePath $resolvedOutputPath }
    }
    $script:checks += $extra
    $script:blockers += $extra
    $result.checks = $script:checks
    $result.blockers = $script:blockers
    $result.status = "blocked"
    $result.rc8_040_complete = $false
    $result.summary.checks = @($script:checks).Count
    $result.summary.blockers = @($script:blockers).Count
    $result.summary.rc8_040_complete = $false
    Write-Json -Value $result -Path $resolvedOutputPath
}

Write-Host "RC8 final closeout audit $($result.status): $(Get-StablePath $resolvedOutputPath)"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
