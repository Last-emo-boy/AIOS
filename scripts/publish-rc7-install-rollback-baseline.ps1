param(
    [string]$RemoteHost = "47.101.11.109",
    [string]$RemoteUser = "root",
    [string]$Domain = "aios.w33d.xyz",
    [string]$ArtifactDir = ".workflow/artifacts/rc7-install-rollback-baseline",
    [string]$ResultPath = "",
    [string]$Rc7ConsumptionResultPath = ".workflow/artifacts/rc7-installer-signed-consumption/result.json",
    [string]$Rc7FailClosedResultPath = ".workflow/artifacts/rc7-signed-consumption-fail-closed/result.json",
    [string]$Rc7SignedMetadataResultPath = ".workflow/artifacts/rc7-signed-metadata-revocation/result.json",
    [string]$PayloadIndexPath = ".workflow/artifacts/rc7-signed-metadata-revocation/hosted-payload-index-after-signed-metadata.json",
    [string]$InstallBootstrapPath = ".workflow/artifacts/rc7-signed-metadata-revocation/install-bootstrap-after-signed-metadata.json",
    [string]$ChannelIndexPath = ".workflow/artifacts/rc7-signed-metadata-revocation/hosted-channel-index-after-signed-metadata.json",
    [string]$Rc6RollbackResultPath = ".workflow/artifacts/rc6-rollback-execution-preconditions/result.json",
    [string]$Rc6RollbackMatrixPath = ".workflow/artifacts/rc6-rollback-execution-preconditions/rollback-drill-precondition-matrix.json",
    [string]$Rc7CompatibilityContractPath = ".workflow/active/WFS-20260608-agentos-production-distro-rc7/docs/installer-compatibility-rollback-baseline-contract.md",
    [int]$SshConnectTimeoutSeconds = 10,
    [switch]$FailOnBlocked
)

$ErrorActionPreference = "Stop"

function Write-JsonText {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $parent = Split-Path -Parent $Path
    if ($parent) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    Set-Content -LiteralPath $Path -Value $Text -Encoding UTF8
}

function Get-JsonText {
    param([Parameter(Mandatory = $true)]$Value)
    return ($Value | ConvertTo-Json -Depth 100 -Compress)
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

function Get-FileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Read-Json {
    param([Parameter(Mandatory = $true)][string]$Path)
    return Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
}

function Convert-JsonClone {
    param([Parameter(Mandatory = $true)]$Value)
    return ($Value | ConvertTo-Json -Depth 100 | ConvertFrom-Json)
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

function Has-Value {
    param($Value)
    if ($null -eq $Value) {
        return $false
    }
    if ($Value -is [string]) {
        return -not [string]::IsNullOrWhiteSpace($Value)
    }
    return $true
}

function Set-JsonProperty {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string]$Name,
        $Value
    )
    if ($Object.PSObject.Properties.Name -contains $Name) {
        $Object.$Name = $Value
    } else {
        $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -Force
    }
}

function Invoke-Remote {
    param([Parameter(Mandatory = $true)][string]$Command)
    $target = "$RemoteUser@$RemoteHost"
    $args = @(
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=$SshConnectTimeoutSeconds",
        $target,
        $Command
    )
    $output = & ssh @args 2>&1
    $exitCode = $LASTEXITCODE
    $text = ($output | Out-String).Trim()
    if ($exitCode -ne 0) {
        throw "Remote command failed ($exitCode): $text"
    }
    return $text
}

function Set-RemoteTextFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Text,
        [string]$Mode = "0644"
    )
    $encoded = [Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes($Text))
    $parent = [IO.Path]::GetDirectoryName($Path) -replace "\\", "/"
    $command = "set -eu; install -d -m 0755 '$parent'; printf '%s' '$encoded' | base64 -d > '$Path'; chmod '$Mode' '$Path'"
    Invoke-Remote $command | Out-Null
}

function Invoke-Curl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Method = "GET"
    )
    $url = "http://$Domain$Path"
    $args = @(
        "--noproxy", "*",
        "--max-time", "15",
        "--resolve", "$Domain`:80`:$RemoteHost",
        "-sS",
        "-X", $Method,
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
        method = $Method
        exit_code = $exitCode
        status_code = $statusCode
        body = $body
        body_sha256 = Get-StringSha256 $body
        json = if ($statusCode -eq 200) { ConvertFrom-JsonTextSafe $body } else { $null }
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

$resolvedRc7ConsumptionResultPath = Resolve-RepoPath $Rc7ConsumptionResultPath
$resolvedRc7FailClosedResultPath = Resolve-RepoPath $Rc7FailClosedResultPath
$resolvedRc7SignedMetadataResultPath = Resolve-RepoPath $Rc7SignedMetadataResultPath
$resolvedPayloadIndexPath = Resolve-RepoPath $PayloadIndexPath
$resolvedInstallBootstrapPath = Resolve-RepoPath $InstallBootstrapPath
$resolvedChannelIndexPath = Resolve-RepoPath $ChannelIndexPath
$resolvedRc6RollbackResultPath = Resolve-RepoPath $Rc6RollbackResultPath
$resolvedRc6RollbackMatrixPath = Resolve-RepoPath $Rc6RollbackMatrixPath
$resolvedRc7CompatibilityContractPath = Resolve-RepoPath $Rc7CompatibilityContractPath

$generatedAt = (Get-Date).ToString("o")
$validUntil = (Get-Date).AddDays(7).ToString("o")

$rc7ConsumptionResult = Read-Json $resolvedRc7ConsumptionResultPath
$rc7FailClosedResult = Read-Json $resolvedRc7FailClosedResultPath
$rc7SignedResult = Read-Json $resolvedRc7SignedMetadataResultPath
$payloadIndex = Read-Json $resolvedPayloadIndexPath
$installBootstrap = Read-Json $resolvedInstallBootstrapPath
$channelIndex = Read-Json $resolvedChannelIndexPath
$rc6RollbackResult = Read-Json $resolvedRc6RollbackResultPath
$rc6RollbackMatrix = Read-Json $resolvedRc6RollbackMatrixPath
$compatContractText = Get-Content -Raw -LiteralPath $resolvedRc7CompatibilityContractPath

$entry = @($payloadIndex.entries)[0]
$releaseId = $entry.release_id
$payloadBasePath = ($entry.manifest_path -replace "/manifest\.json$", "")
$rollbackRow = @($rc6RollbackMatrix.rows | Where-Object { $_.id -eq "rollback.baseline.consistent" } | Select-Object -First 1)[0]
$supportRow = @($rc6RollbackMatrix.rows | Where-Object { $_.id -eq "support.recovery.readiness" } | Select-Object -First 1)[0]

Add-Check "source.rc7_010.passed" ($rc7ConsumptionResult.status -eq "passed" -and $rc7ConsumptionResult.summary.blockers -eq 0) "RC7-010 consumption report must be passed before publishing rollback baseline metadata." $rc7ConsumptionResult.summary
Add-Check "source.rc7_011.passed" ($rc7FailClosedResult.status -eq "passed" -and $rc7FailClosedResult.summary.failed_cases -eq 0) "RC7-011 fail-closed fixtures must pass before publishing rollback baseline metadata." $rc7FailClosedResult.summary
Add-Check "source.rc6_rollback.ready" ($rc6RollbackResult.status -eq "passed" -and $rc6RollbackResult.rollback_readiness_ready -eq $true -and $rc6RollbackResult.rollback_execution_allowed -eq $false) "RC6 rollback preconditions must prove readiness while execution remains blocked." ([ordered]@{ status = $rc6RollbackResult.status; rollback_readiness_ready = $rc6RollbackResult.rollback_readiness_ready; rollback_execution_allowed = $rc6RollbackResult.rollback_execution_allowed })
Add-Check "source.rc7_003.contract" ($compatContractText.Contains("/install/compatibility.json") -and $compatContractText.Contains("/install/rollback-baseline.json")) "RC7-003 contract must authorize metadata-only compatibility and rollback baseline publication." (Get-StablePath $resolvedRc7CompatibilityContractPath)

$rollbackBaseline = [ordered]@{
    schema = "agentos.rc7-rollback-baseline.v1"
    generated_at = $generatedAt
    valid_until = $validUntil
    release_id = $releaseId
    status = "rollback-baseline-projected-execution-blocked"
    production_ready_claim = $false
    rollback_baseline_sha256 = $rollbackRow.evidence.rollback_baseline_sha256
    previous_active_artifact_set_sha256 = $rollbackRow.evidence.previous_active_artifact_set_sha256
    restored_active_artifact_set_sha256 = $rollbackRow.evidence.restored_active_artifact_set_sha256
    support_recovery_binding = [ordered]@{
        operation_id = $supportRow.evidence.operation_id
        rollback_baseline_sha256 = $supportRow.evidence.rollback_baseline_sha256
        executable_by_mirror = $false
        source_path = $supportRow.evidence_path
    }
    security_execution_requirement = [ordered]@{
        agentcore_planspec_required = $true
        security_execution_engine_approval_required = $true
        approval_state = "not-approved"
    }
    operator_approval_requirement = [ordered]@{
        exact_actor_required = $true
        target_release_id = $releaseId
        expiry_required = $true
        approval_state = "not-granted"
    }
    execution_status = [ordered]@{
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        rollback_execution_performed = $false
        active_slot_mutated = $false
        production_ring_mutated = $false
    }
    source_bindings = [ordered]@{
        rc6_rollback_result = [ordered]@{ path = Get-StablePath $resolvedRc6RollbackResultPath; sha256 = Get-FileSha256 $resolvedRc6RollbackResultPath }
        rc6_rollback_matrix = [ordered]@{ path = Get-StablePath $resolvedRc6RollbackMatrixPath; sha256 = Get-FileSha256 $resolvedRc6RollbackMatrixPath }
        rc7_consumption_result = [ordered]@{ path = Get-StablePath $resolvedRc7ConsumptionResultPath; sha256 = Get-FileSha256 $resolvedRc7ConsumptionResultPath }
        rc7_fail_closed_result = [ordered]@{ path = Get-StablePath $resolvedRc7FailClosedResultPath; sha256 = Get-FileSha256 $resolvedRc7FailClosedResultPath }
    }
}
$rollbackText = Get-JsonText $rollbackBaseline
$rollbackHash = Get-StringSha256 $rollbackText

$compatibility = [ordered]@{
    schema = "agentos.rc7-installer-compatibility.v1"
    generated_at = $generatedAt
    valid_until = $validUntil
    release_id = $releaseId
    status = "compatibility-projected-verification-blocked"
    production_ready_claim = $false
    target_arch = @("x86_64")
    image_format = @("agentos-current-artifacts-metadata-preview", "installable-media-projection")
    boot_path = [ordered]@{
        boot_modes = @("uefi", "bios")
        kernel_family = "linux-lts"
        initramfs_contract = "agentos-initramfs-stage-copy-only"
        console_readiness_marker_required = $true
    }
    minimum_runtime = [ordered]@{
        agentd_contract = "rc7"
        agent_core_contract = "production-distro-rc7"
        security_execution_engine_contract = "planspec-approval-required"
        installer_contract = "signed-consumption-v1"
    }
    required_metadata = [ordered]@{
        payload_manifest_sha256 = $entry.manifest_sha256
        payload_checksums_sha256 = $entry.checksums_sha256
        payload_signatures_sha256 = $entry.signatures_sha256
        signed_metadata_sha256 = $entry.signed_metadata_sha256
        revocation_snapshot_sha256 = $entry.revocation_snapshot_sha256
        rollback_baseline_document_sha256 = $rollbackHash
        rollback_baseline_sha256 = $rollbackBaseline.rollback_baseline_sha256
    }
    drift_policy = [ordered]@{
        installable_media_declared_hash_drift_count = $entry.installable_media_declared_hash_drift_count
        drift_blocks_install = $true
    }
    storage_policy = [ordered]@{
        storage_mode = $payloadIndex.storage_mode
        large_payload_deferred = $entry.large_payload_deferred
        large_payload_storage_policy_required = $true
    }
    authority = [ordered]@{
        mirror_is_root_of_trust = $false
        signer_can_install = $false
        installer_preflight_can_activate = $false
        frontend_authority = $false
        tui_authority = $false
        model_authority = $false
        shell_authority = $false
    }
}
$compatibilityText = Get-JsonText $compatibility
$compatibilityHash = Get-StringSha256 $compatibilityText

$payloadIndexOut = Convert-JsonClone $payloadIndex
$payloadEntry = @($payloadIndexOut.entries)[0]
Set-JsonProperty $payloadEntry "compatibility_path" "/install/compatibility.json"
Set-JsonProperty $payloadEntry "compatibility_sha256" $compatibilityHash
Set-JsonProperty $payloadEntry "rollback_baseline_path" "/install/rollback-baseline.json"
Set-JsonProperty $payloadEntry "rollback_baseline_sha256" $rollbackHash
Set-JsonProperty $payloadEntry "rollback_baseline_provenance_sha256" $rollbackBaseline.rollback_baseline_sha256
Set-JsonProperty $payloadEntry "reason" "Signed metadata, revocation, installer compatibility, and rollback baseline projections are published, but install remains blocked until byte-hash canonicalization, a real cryptographic signature, storage/drift, TLS, and exact approval gates pass."
$payloadIndexOut.status = "rollback-baseline-projected"
$payloadIndexText = Get-JsonText $payloadIndexOut
$payloadIndexHash = Get-StringSha256 $payloadIndexText

$installOut = Convert-JsonClone $installBootstrap
$installOut.status = "rollback-baseline-preflight-only"
$installOut.current_state = "verification-blocked"
Set-JsonProperty $installOut.endpoints "installer_compatibility" "/install/compatibility.json"
Set-JsonProperty $installOut.endpoints "rollback_baseline" "/install/rollback-baseline.json"
Set-JsonProperty $installOut.projection "payload_index_sha256" $payloadIndexHash
Set-JsonProperty $installOut.projection "installer_compatibility_sha256" $compatibilityHash
Set-JsonProperty $installOut.projection "rollback_baseline_sha256" $rollbackHash
Set-JsonProperty $installOut.projection "rollback_baseline_provenance_sha256" $rollbackBaseline.rollback_baseline_sha256
$installOut.blockers = @(
    "hosted-byte-hash-canonicalization-pending",
    "cryptographic-signature-not-present",
    "large-payload-storage-policy-and-object-storage-pending",
    "installable-media-declared-hash-drift",
    "tls-required-before-ga-claim",
    "exact-operator-approval-not-granted"
)
$installText = Get-JsonText $installOut
$installHash = Get-StringSha256 $installText

$channelOut = Convert-JsonClone $channelIndex
$channelOut.status = "rollback-baseline-projected"
$preservedEntries = @($channelOut.entries | Where-Object { $_.id -notin @("rc7-installer-compatibility", "rc7-rollback-baseline") })
$newEntries = @(
    [ordered]@{
        id = "rc7-installer-compatibility"
        status = "available"
        path = "/install/compatibility.json"
        kind = "installer-compatibility-metadata"
        sha256 = $compatibilityHash
        install_allowed = $false
    },
    [ordered]@{
        id = "rc7-rollback-baseline"
        status = "available"
        path = "/install/rollback-baseline.json"
        kind = "rollback-baseline-metadata"
        sha256 = $rollbackHash
        rollback_execution_allowed = $false
    }
)
$channelOut.entries = @($preservedEntries + $newEntries)
Set-JsonProperty $channelOut.payload_channel "payload_index_sha256" $payloadIndexHash
Set-JsonProperty $channelOut.payload_channel "install_bootstrap_sha256" $installHash
Set-JsonProperty $channelOut.payload_channel "installer_compatibility_sha256" $compatibilityHash
Set-JsonProperty $channelOut.payload_channel "rollback_baseline_sha256" $rollbackHash
Set-JsonProperty $channelOut.payload_channel "rollback_baseline_provenance_sha256" $rollbackBaseline.rollback_baseline_sha256
$channelText = Get-JsonText $channelOut
$channelHash = Get-StringSha256 $channelText

$compatibilityPathOut = Join-Path $resolvedArtifactDir "compatibility.json"
$rollbackPathOut = Join-Path $resolvedArtifactDir "rollback-baseline.json"
$payloadIndexPathOut = Join-Path $resolvedArtifactDir "payload-index-after-rollback-baseline.json"
$installPathOut = Join-Path $resolvedArtifactDir "install-bootstrap-after-rollback-baseline.json"
$channelPathOut = Join-Path $resolvedArtifactDir "hosted-channel-index-after-rollback-baseline.json"

Write-JsonText $compatibilityText $compatibilityPathOut
Write-JsonText $rollbackText $rollbackPathOut
Write-JsonText $payloadIndexText $payloadIndexPathOut
Write-JsonText $installText $installPathOut
Write-JsonText $channelText $channelPathOut

$localTexts = @($compatibilityText, $rollbackText, $payloadIndexText, $installText, $channelText)
Add-Check "projection.compatibility.rollback.hash_bound" ($installOut.projection.installer_compatibility_sha256 -eq $compatibilityHash -and $installOut.projection.rollback_baseline_sha256 -eq $rollbackHash -and $payloadEntry.compatibility_sha256 -eq $compatibilityHash -and $payloadEntry.rollback_baseline_sha256 -eq $rollbackHash) "Install and payload metadata must hash-bind compatibility and rollback baseline documents." ([ordered]@{ compatibility_sha256 = $compatibilityHash; rollback_baseline_sha256 = $rollbackHash })
Add-Check "projection.install.remains_blocked" ($installOut.install_allowed -eq $false -and $payloadEntry.install_allowed -eq $false -and $payloadEntry.rollback_execution_allowed -eq $false) "Publishing compatibility and rollback baseline metadata must not allow install, activation, or rollback execution." ([ordered]@{ install_allowed = $installOut.install_allowed; payload_install_allowed = $payloadEntry.install_allowed; rollback_execution_allowed = $payloadEntry.rollback_execution_allowed })
Add-Check "projection.secret_safe" (Test-NoSensitiveText -Values $localTexts) "RC7-012 local outputs must not contain private key paths, PEM private blocks, or tokens." $null

Set-RemoteTextFile -Path "/srv/aios-mirror/install/compatibility.json" -Text $compatibilityText
Set-RemoteTextFile -Path "/srv/aios-mirror/install/rollback-baseline.json" -Text $rollbackText
Set-RemoteTextFile -Path "/srv/aios-mirror/payloads/index.json" -Text $payloadIndexText
Set-RemoteTextFile -Path "/srv/aios-mirror/install/bootstrap.json" -Text $installText
Set-RemoteTextFile -Path "/srv/aios-mirror/channel/index.json" -Text $channelText

$remoteCheck = Invoke-Remote "set -eu; systemctl is-active nginx; cd /srv/aios-mirror; sha256sum install/compatibility.json install/rollback-baseline.json payloads/index.json install/bootstrap.json channel/index.json"

$compatibilityResponse = Invoke-Curl "/install/compatibility.json"
$rollbackResponse = Invoke-Curl "/install/rollback-baseline.json"
$payloadResponse = Invoke-Curl "/payloads/index.json"
$installResponse = Invoke-Curl "/install/bootstrap.json"
$channelResponse = Invoke-Curl "/channel/index.json"
$installDirResponse = Invoke-Curl "/install/"
$postResponse = Invoke-Curl "/install/rollback-baseline.json" -Method "POST"

$compatibilityLive = $compatibilityResponse.json
$rollbackLive = $rollbackResponse.json
$payloadLive = $payloadResponse.json
$installLive = $installResponse.json
$channelLive = $channelResponse.json
$payloadEntryLive = if ($null -ne $payloadLive -and $null -ne $payloadLive.entries) { @($payloadLive.entries)[0] } else { $null }

$remoteHttpReady = $compatibilityResponse.status_code -eq 200 -and $rollbackResponse.status_code -eq 200 -and $payloadResponse.status_code -eq 200 -and $installResponse.status_code -eq 200 -and $channelResponse.status_code -eq 200
$remoteHashReady = $compatibilityResponse.body_sha256 -eq $compatibilityHash -and
    $rollbackResponse.body_sha256 -eq $rollbackHash -and
    $payloadResponse.body_sha256 -eq $payloadIndexHash -and
    $installResponse.body_sha256 -eq $installHash -and
    $channelResponse.body_sha256 -eq $channelHash -and
    $installLive.projection.installer_compatibility_sha256 -eq $compatibilityHash -and
    $installLive.projection.rollback_baseline_sha256 -eq $rollbackHash -and
    $payloadEntryLive.compatibility_sha256 -eq $compatibilityHash -and
    $payloadEntryLive.rollback_baseline_sha256 -eq $rollbackHash -and
    $channelLive.payload_channel.installer_compatibility_sha256 -eq $compatibilityHash -and
    $channelLive.payload_channel.rollback_baseline_sha256 -eq $rollbackHash
$remoteSemanticsReady = $compatibilityLive.schema -eq "agentos.rc7-installer-compatibility.v1" -and
    $rollbackLive.schema -eq "agentos.rc7-rollback-baseline.v1" -and
    $compatibilityLive.release_id -eq $releaseId -and
    $rollbackLive.release_id -eq $releaseId -and
    $payloadEntryLive.status -eq "verification-blocked" -and
    $installLive.current_state -eq "verification-blocked" -and
    $installLive.install_allowed -eq $false -and
    $payloadEntryLive.install_allowed -eq $false -and
    $payloadEntryLive.activation_allowed -eq $false -and
    $payloadEntryLive.rollback_execution_allowed -eq $false -and
    $channelLive.payload_channel.install_allowed -eq $false
$remoteSecretSafe = Test-NoSensitiveText -Values @($compatibilityResponse.body, $rollbackResponse.body, $payloadResponse.body, $installResponse.body, $channelResponse.body)

Add-Check "remote.nginx.active" ($remoteCheck -match "active") "Nginx must remain active after RC7-012 metadata publication." ($remoteCheck -split "`n")
Add-Check "remote.http.ready" $remoteHttpReady "Compatibility, rollback baseline, payload index, install bootstrap, and channel metadata must be reachable." ([ordered]@{ compatibility = $compatibilityResponse.status_code; rollback = $rollbackResponse.status_code; payload = $payloadResponse.status_code; install = $installResponse.status_code; channel = $channelResponse.status_code })
Add-Check "remote.hash_bindings.match" $remoteHashReady "Live metadata byte hashes and embedded hash bindings must match RC7-012 outputs." ([ordered]@{ compatibility_sha256 = $compatibilityHash; rollback_baseline_sha256 = $rollbackHash; payload_index_sha256 = $payloadIndexHash; install_bootstrap_sha256 = $installHash; channel_index_sha256 = $channelHash })
Add-Check "remote.semantics.blocked" $remoteSemanticsReady "Live metadata must publish compatibility and rollback baseline while keeping install and rollback execution blocked." ([ordered]@{ release_id = $releaseId; install_state = if ($null -ne $installLive) { $installLive.current_state } else { $null }; install_allowed = if ($null -ne $installLive) { $installLive.install_allowed } else { $null } })
Add-Check "remote.secret_safe" $remoteSecretSafe "Remote RC7-012 metadata responses must not expose private key paths, PEM private blocks, or tokens." $null
Add-Check "remote.directory_listing.blocked" (@(403, 404) -contains $installDirResponse.status_code) "Install directory listing must remain blocked." $installDirResponse.status_code
Add-Check "remote.write_methods.blocked" (@(403, 405) -contains $postResponse.status_code) "POST to rollback baseline metadata must remain blocked." $postResponse.status_code

$passed = @($script:blockers).Count -eq 0
$result = [ordered]@{
    schema = "agentos.rc7-install-rollback-baseline-result.v1"
    generated_at = $generatedAt
    checked_at = (Get-Date).ToString("o")
    task = "RC7-012"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    remote = [ordered]@{
        host = $RemoteHost
        user = $RemoteUser
        domain = $Domain
        static_root = "/srv/aios-mirror"
        validation_used_local_dns = $false
        validation_resolve_override = "$Domain`:80`:$RemoteHost"
    }
    source = [ordered]@{
        rc7_consumption_result = New-ArtifactRef $resolvedRc7ConsumptionResultPath $rc7ConsumptionResult
        rc7_fail_closed_result = New-ArtifactRef $resolvedRc7FailClosedResultPath $rc7FailClosedResult
        rc7_signed_metadata_revocation = New-ArtifactRef $resolvedRc7SignedMetadataResultPath $rc7SignedResult
        rc6_rollback_result = New-ArtifactRef $resolvedRc6RollbackResultPath $rc6RollbackResult
        rc6_rollback_matrix = New-ArtifactRef $resolvedRc6RollbackMatrixPath $rc6RollbackMatrix
        rc7_compatibility_contract = [ordered]@{ path = Get-StablePath $resolvedRc7CompatibilityContractPath; sha256 = Get-FileSha256 $resolvedRc7CompatibilityContractPath }
    }
    local_outputs = [ordered]@{
        compatibility = Get-StablePath $compatibilityPathOut
        rollback_baseline = Get-StablePath $rollbackPathOut
        payload_index = Get-StablePath $payloadIndexPathOut
        install_bootstrap = Get-StablePath $installPathOut
        channel_index = Get-StablePath $channelPathOut
    }
    published_endpoints = @(
        "http://$Domain/install/compatibility.json",
        "http://$Domain/install/rollback-baseline.json",
        "http://$Domain/payloads/index.json",
        "http://$Domain/install/bootstrap.json",
        "http://$Domain/channel/index.json"
    )
    output_hashes = [ordered]@{
        compatibility_sha256 = $compatibilityHash
        rollback_baseline_sha256 = $rollbackHash
        payload_index_sha256 = $payloadIndexHash
        install_bootstrap_sha256 = $installHash
        channel_index_sha256 = $channelHash
    }
    payload_surface = [ordered]@{
        release_id = $releaseId
        status = "verification-blocked"
        compatibility_published = $true
        rollback_baseline_published = $true
        public_signature_projection_available = $true
        cryptographic_signature_present = $false
        signature_available = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
    }
    remaining_installer_blockers = @(
        "hosted-byte-hash-canonicalization-pending-for-prior-signed-metadata-artifacts",
        "cryptographic-signature-not-present",
        "large-payload-storage-policy-and-object-storage-pending",
        "installable-media-declared-hash-drift",
        "tls-required-before-ga-claim",
        "exact-operator-approval-not-granted"
    )
    invariants = [ordered]@{
        metadata_publication_only = $true
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
    checks = $script:checks
    blockers = $script:blockers
    summary = [ordered]@{
        checks = @($script:checks).Count
        blockers = @($script:blockers).Count
        rc7_012_complete = $passed
        next_task = "RC7-020"
    }
}

Write-JsonText (Get-JsonText $result) $resolvedResultPath
Write-Host "RC7 install rollback baseline publication $($result.status): $(Get-StablePath $resolvedResultPath)"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
