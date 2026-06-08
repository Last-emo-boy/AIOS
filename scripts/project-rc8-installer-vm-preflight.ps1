param(
    [string]$ArtifactDir = ".workflow/artifacts/rc8-installer-vm-preflight",
    [string]$ResultPath = "",
    [string]$DescriptorPath = ".workflow/artifacts/rc8-real-payload-object-descriptor/payload-object-descriptor.json",
    [string]$DescriptorResultPath = ".workflow/artifacts/rc8-real-payload-object-descriptor/result.json",
    [string]$SignatureIngestionResultPath = ".workflow/artifacts/rc8-public-signature-ingestion/result.json",
    [string]$SignedDescriptorFailClosedResultPath = ".workflow/artifacts/rc8-signed-object-descriptor-fail-closed/result.json",
    [string]$BootSmokeScriptPath = "scripts/boot-smoke-test.ps1",
    [string]$QemuPath = "E:\qemu\qemu-system-x86_64.exe",
    [string]$KernelPath = "image/cache/vmlinuz-virt",
    [int]$QemuTimeoutSeconds = 120,
    [switch]$SkipQemuSmoke,
    [switch]$FailOnBlocked
)

$ErrorActionPreference = "Stop"

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

function Assert-ChildPath {
    param(
        [Parameter(Mandatory = $true)][string]$Parent,
        [Parameter(Mandatory = $true)][string]$Child
    )
    $parentFull = [IO.Path]::GetFullPath($Parent).TrimEnd("\", "/") + [IO.Path]::DirectorySeparatorChar
    $childFull = [IO.Path]::GetFullPath($Child)
    if (-not $childFull.StartsWith($parentFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path escapes intended root: $childFull"
    }
}

function Get-StablePath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    if ($full.StartsWith($script:repoRoot, [StringComparison]::OrdinalIgnoreCase)) {
        return $full.Substring($script:repoRoot.Length).TrimStart("\", "/") -replace "\\", "/"
    }
    return $full
}

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
    [IO.File]::WriteAllText($Path, $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}

function Read-Json {
    param([Parameter(Mandatory = $true)][string]$Path)
    return Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
}

function Get-FileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
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

function Add-Check {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][bool]$Passed,
        [Parameter(Mandatory = $true)][string]$Message,
        $Evidence = $null,
        [string]$Severity = "blocking"
    )
    $entry = [ordered]@{
        id = $Id
        status = if ($Passed) { "passed" } else { "failed" }
        severity = $Severity
        message = $Message
        evidence = $Evidence
    }
    $script:checks += $entry
    if (-not $Passed -and $Severity -eq "blocking") {
        $script:taskBlockers += $entry
    }
}

function Add-PreflightStep {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][bool]$Passed,
        [Parameter(Mandatory = $true)][string]$Message,
        $Evidence = $null
    )
    $entry = [ordered]@{
        id = $Id
        status = if ($Passed) { "passed" } else { "blocked" }
        message = $Message
        evidence = $Evidence
    }
    $script:preflightSteps += $entry
    if (-not $Passed) {
        $script:preflightBlockers += $entry
    }
}

function Test-NoSensitiveText {
    param([Parameter(Mandatory = $true)][string[]]$Values)
    $markers = @(
        ("BEGIN " + "PRIVATE KEY"),
        ("BEGIN RSA " + "PRIVATE KEY"),
        ("BEGIN OPENSSH " + "PRIVATE KEY"),
        ("PRIVATE KEY" + "-----"),
        ("Authorization:" + " Bearer"),
        ("Bearer" + " "),
        "access_token",
        "refresh_token",
        ("." + "local-release-authority"),
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

function Test-ExternalHttpsObjectUri {
    param($Descriptor)
    return ((Has-Value $Descriptor.uri) -and ([string]$Descriptor.uri).StartsWith("https://", [StringComparison]::OrdinalIgnoreCase))
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

function Invoke-BootSmoke {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][string]$ArtifactDir
    )
    if ($SkipQemuSmoke) {
        return [ordered]@{
            skipped = $true
            exit_code = $null
            stdout = $null
            stderr = $null
        }
    }
    $stdoutPath = Join-Path $script:resolvedArtifactDir "qemu-smoke-command.stdout.txt"
    $stderrPath = Join-Path $script:resolvedArtifactDir "qemu-smoke-command.stderr.txt"
    & $ScriptPath `
        -SkipKernelDownload `
        -KernelPath $KernelPath `
        -QemuPath $QemuPath `
        -TimeoutSeconds $QemuTimeoutSeconds `
        -ArtifactDir $ArtifactDir `
        1> $stdoutPath 2> $stderrPath
    return [ordered]@{
        skipped = $false
        exit_code = if ($null -eq $LASTEXITCODE) { 0 } else { $LASTEXITCODE }
        stdout = Get-StablePath $stdoutPath
        stderr = Get-StablePath $stderrPath
    }
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:taskBlockers = @()
$script:preflightSteps = @()
$script:preflightBlockers = @()

$script:resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
New-Item -ItemType Directory -Force -Path $script:resolvedArtifactDir | Out-Null
if (-not $ResultPath) {
    $ResultPath = Join-Path $ArtifactDir "result.json"
}
$resolvedResultPath = Resolve-RepoPath $ResultPath
$resolvedDescriptorPath = Resolve-RepoPath $DescriptorPath
$resolvedDescriptorResultPath = Resolve-RepoPath $DescriptorResultPath
$resolvedSignatureIngestionResultPath = Resolve-RepoPath $SignatureIngestionResultPath
$resolvedSignedDescriptorFailClosedResultPath = Resolve-RepoPath $SignedDescriptorFailClosedResultPath
$resolvedBootSmokeScriptPath = Resolve-RepoPath $BootSmokeScriptPath

$descriptor = Read-Json $resolvedDescriptorPath
$descriptorResult = Read-Json $resolvedDescriptorResultPath
$signatureIngestionResult = Read-Json $resolvedSignatureIngestionResultPath
$signedDescriptorFailClosed = Read-Json $resolvedSignedDescriptorFailClosedResultPath

$qemuArtifactDir = Join-Path $ArtifactDir "qemu-smoke"
$bootInvocation = Invoke-BootSmoke -ScriptPath $resolvedBootSmokeScriptPath -ArtifactDir $qemuArtifactDir
$qemuResultPath = Resolve-RepoPath (Join-Path $qemuArtifactDir "boot-smoke-result.json")
$qemuDependencyPath = Resolve-RepoPath (Join-Path $qemuArtifactDir "dependency-check.json")
$qemuResult = if (Test-Path -LiteralPath $qemuResultPath -PathType Leaf) { Read-Json $qemuResultPath } else { $null }
$qemuDependency = if (Test-Path -LiteralPath $qemuDependencyPath -PathType Leaf) { Read-Json $qemuDependencyPath } else { $null }

$quarantineRoot = Join-Path $script:resolvedArtifactDir "quarantine"
New-Item -ItemType Directory -Force -Path $quarantineRoot | Out-Null
Assert-ChildPath -Parent $script:resolvedArtifactDir -Child $quarantineRoot
$quarantineObjectDir = Join-Path $quarantineRoot ("sha256-" + [string]$descriptor.sha256)
New-Item -ItemType Directory -Force -Path $quarantineObjectDir | Out-Null
Assert-ChildPath -Parent $quarantineRoot -Child $quarantineObjectDir
$quarantinePayloadPath = Join-Path $quarantineObjectDir "payload.cpio.gz"

$sourcePayloadPath = Resolve-RepoPath ([string]$descriptor.source_build_artifact)
$sourcePayloadSha256 = Get-FileSha256 $sourcePayloadPath
$sourcePayloadSize = if (Test-Path -LiteralPath $sourcePayloadPath -PathType Leaf) { (Get-Item -LiteralPath $sourcePayloadPath).Length } else { $null }
$externalHttpsObjectUriPublished = Test-ExternalHttpsObjectUri $descriptor
$repoLocalQuarantineCopyPerformed = $false
if (-not $externalHttpsObjectUriPublished -and $sourcePayloadSha256 -eq [string]$descriptor.sha256) {
    Copy-Item -LiteralPath $sourcePayloadPath -Destination $quarantinePayloadPath -Force
    $repoLocalQuarantineCopyPerformed = $true
}
$quarantinePayloadSha256 = Get-FileSha256 $quarantinePayloadPath
$quarantinePayloadSize = if (Test-Path -LiteralPath $quarantinePayloadPath -PathType Leaf) { (Get-Item -LiteralPath $quarantinePayloadPath).Length } else { $null }

Add-Check "source.rc8_010.result" ($descriptorResult.status -eq "passed" -and $descriptorResult.summary.blockers -eq 0) "RC8-010 descriptor projection must be passed before VM preflight." $descriptorResult.summary
Add-Check "source.rc8_011.result" ($signatureIngestionResult.status -eq "passed" -and $signatureIngestionResult.signature_surface.crypto_verified -eq $true) "RC8-011 public signature ingestion must be passed and crypto verified before VM preflight." $signatureIngestionResult.summary
Add-Check "source.rc8_012.result" ($signedDescriptorFailClosed.status -eq "passed" -and $signedDescriptorFailClosed.summary.failed_cases -eq 0) "RC8-012 fail-closed fixtures must pass before VM preflight." $signedDescriptorFailClosed.summary
Add-Check "vm.qemu_smoke_completed" ($SkipQemuSmoke -or ($bootInvocation.exit_code -eq 0 -and $qemuResult.status -eq "completed" -and $qemuResult.observed_all_markers -eq $true)) "QEMU boot smoke must complete before installer preflight can claim VM readiness." ([ordered]@{ skipped = [bool]$SkipQemuSmoke; exit_code = $bootInvocation.exit_code; status = if ($qemuResult) { $qemuResult.status } else { $null }; observed_all_markers = if ($qemuResult) { $qemuResult.observed_all_markers } else { $false } })
Add-Check "vm.payload_matches_descriptor" ($qemuResult -and $qemuResult.initramfs_sha256 -eq [string]$descriptor.sha256) "QEMU smoke initramfs hash must match the RC8 payload descriptor." ([ordered]@{ qemu_initramfs_sha256 = if ($qemuResult) { $qemuResult.initramfs_sha256 } else { $null }; descriptor_sha256 = $descriptor.sha256 })

Add-PreflightStep "verify-descriptor-source-and-signature" ($descriptor.schema -eq "agentos.payload-object-descriptor.v1" -and $signatureIngestionResult.signature_surface.crypto_verified -eq $true) "Descriptor schema and public signature ingestion are verified." ([ordered]@{ descriptor_schema = $descriptor.schema; crypto_verified = $signatureIngestionResult.signature_surface.crypto_verified })
Add-PreflightStep "run-installer-vm-boot-smoke" ($qemuResult -and $qemuResult.status -eq "completed" -and $qemuResult.observed_all_markers -eq $true) "Installer VM preflight can boot the current AIOS initramfs and observe runtime markers." ([ordered]@{ selected_machine = if ($qemuResult) { $qemuResult.selected_machine } else { $null }; required_markers = if ($qemuResult) { @($qemuResult.required_markers).Count } else { 0 } })
Add-PreflightStep "prepare-quarantine-root" ((Test-Path -LiteralPath $quarantineRoot -PathType Container) -and (Test-Path -LiteralPath $quarantineObjectDir -PathType Container)) "Quarantine root is a strict child of the RC8 preflight artifact directory." ([ordered]@{ quarantine_root = Get-StablePath $quarantineRoot; object_dir = Get-StablePath $quarantineObjectDir })
Add-PreflightStep "verify-source-payload-before-quarantine" ($sourcePayloadSha256 -eq [string]$descriptor.sha256 -and $sourcePayloadSize -eq [int64]$descriptor.size_bytes) "Repo-local source payload still matches descriptor before quarantine smoke." ([ordered]@{ source_sha256 = $sourcePayloadSha256; descriptor_sha256 = $descriptor.sha256; source_size = $sourcePayloadSize; descriptor_size = $descriptor.size_bytes })
Add-PreflightStep "repo-local-quarantine-byte-smoke" ($repoLocalQuarantineCopyPerformed -and $quarantinePayloadSha256 -eq [string]$descriptor.sha256 -and $quarantinePayloadSize -eq [int64]$descriptor.size_bytes) "Repo-local payload bytes can be copied into quarantine and verified by size and digest." ([ordered]@{ mode = "repo-local-source-quarantine-smoke"; quarantine_sha256 = $quarantinePayloadSha256; quarantine_size = $quarantinePayloadSize })
Add-PreflightStep "external-https-object-fetch" $externalHttpsObjectUriPublished "External HTTPS object URI must be published before real installer object fetch can run." ([ordered]@{ uri_class = if ($externalHttpsObjectUriPublished) { "https" } else { "not-external-https" }; remote_download_attempted = $false })
Add-PreflightStep "install-gate-remains-closed" ($descriptor.install_allowed -eq $false -and $descriptor.activation_allowed -eq $false -and $descriptor.rollback_execution_allowed -eq $false) "Installer preflight must not authorize install, activation, or rollback." ([ordered]@{ install_allowed = $descriptor.install_allowed; activation_allowed = $descriptor.activation_allowed; rollback_execution_allowed = $descriptor.rollback_execution_allowed })

$expectedPreflightBlockerIds = @("external-https-object-fetch")
$missingExpectedPreflightBlockers = @($expectedPreflightBlockerIds | Where-Object { $_ -notin @($script:preflightBlockers | ForEach-Object { $_.id }) })
Add-Check "preflight.expected_blockers" ($missingExpectedPreflightBlockers.Count -eq 0) "RC8-020 must record external object publication as the remaining object-fetch blocker." ([ordered]@{ expected = $expectedPreflightBlockerIds; missing = $missingExpectedPreflightBlockers })

$objectFetchReportPath = Join-Path $script:resolvedArtifactDir "object-fetch-report.json"
$objectFetchReport = [ordered]@{
    schema = "agentos.rc8-quarantined-object-fetch-report.v1"
    generated_at = (Get-Date).ToString("o")
    release_id = $descriptor.release_id
    descriptor_path = Get-StablePath $resolvedDescriptorPath
    descriptor_sha256 = Get-FileSha256 $resolvedDescriptorPath
    object_id = $descriptor.object_id
    descriptor_uri = $descriptor.uri
    external_https_object_uri_published = $externalHttpsObjectUriPublished
    remote_download_attempted = $false
    repo_local_quarantine_smoke_performed = $repoLocalQuarantineCopyPerformed
    quarantine_path_classification = "strict-child-of-rc8-preflight-artifact-dir"
    quarantine_payload_path = if (Test-Path -LiteralPath $quarantinePayloadPath -PathType Leaf) { Get-StablePath $quarantinePayloadPath } else { $null }
    expected_size_bytes = [int64]$descriptor.size_bytes
    actual_size_bytes = $quarantinePayloadSize
    expected_sha256 = $descriptor.sha256
    actual_sha256 = $quarantinePayloadSha256
    digest_verified = ($quarantinePayloadSha256 -eq [string]$descriptor.sha256)
    size_verified = ($quarantinePayloadSize -eq [int64]$descriptor.size_bytes)
    install_allowed = $false
    blockers = @($script:preflightBlockers | ForEach-Object { $_.id })
}
Write-Json -Value $objectFetchReport -Path $objectFetchReportPath

$preflightReportPath = Join-Path $script:resolvedArtifactDir "preflight-report.json"
$preflightState = if (@($script:preflightBlockers).Count -eq 0) { "install-preflight-ready" } else { "verification-blocked" }
$preflightReport = [ordered]@{
    schema = "agentos.rc8-installer-vm-preflight-report.v1"
    generated_at = (Get-Date).ToString("o")
    task = "RC8-020"
    release_id = $descriptor.release_id
    production_ready_claim = $false
    preflight_state = $preflightState
    installer_vm_smoke_run = ($qemuResult -and $qemuResult.status -eq "completed")
    object_fetch_smoke_mode = if ($repoLocalQuarantineCopyPerformed) { "repo-local-source-quarantine-smoke" } else { "not-run" }
    external_object_fetch_allowed = $externalHttpsObjectUriPublished
    exact_approval_required_before_install = $true
    steps = @($script:preflightSteps)
    blockers = @($script:preflightBlockers)
    qemu_smoke = [ordered]@{
        result_path = if ($qemuResult) { Get-StablePath $qemuResultPath } else { $null }
        result_sha256 = if ($qemuResult) { Get-FileSha256 $qemuResultPath } else { $null }
        dependency_path = if ($qemuDependency) { Get-StablePath $qemuDependencyPath } else { $null }
        dependency_sha256 = if ($qemuDependency) { Get-FileSha256 $qemuDependencyPath } else { $null }
        selected_machine = if ($qemuResult) { $qemuResult.selected_machine } else { $null }
        observed_all_markers = if ($qemuResult) { $qemuResult.observed_all_markers } else { $false }
        initramfs_sha256 = if ($qemuResult) { $qemuResult.initramfs_sha256 } else { $null }
    }
    object_fetch_report = [ordered]@{
        path = Get-StablePath $objectFetchReportPath
        sha256 = Get-FileSha256 $objectFetchReportPath
    }
    side_effects = [ordered]@{
        remote_publication_performed = $false
        payload_bytes_uploaded = $false
        remote_payload_bytes_downloaded = $false
        repo_local_quarantine_copy_performed = $repoLocalQuarantineCopyPerformed
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
Write-Json -Value $preflightReport -Path $preflightReportPath

$preflightText = Get-Content -Raw -LiteralPath $preflightReportPath
$objectFetchText = Get-Content -Raw -LiteralPath $objectFetchReportPath
Add-Check "preflight.report.generated" ((Test-Path -LiteralPath $preflightReportPath -PathType Leaf) -and (Test-Path -LiteralPath $objectFetchReportPath -PathType Leaf)) "Preflight and object-fetch reports must be generated." ([ordered]@{ preflight = Get-StablePath $preflightReportPath; object_fetch = Get-StablePath $objectFetchReportPath })
Add-Check "preflight.expected_state" ($preflightReport.preflight_state -eq "verification-blocked" -and @($preflightReport.blockers).Count -eq 1) "RC8-020 should remain verification-blocked only on external HTTPS object publication." ([ordered]@{ state = $preflightReport.preflight_state; blockers = @($preflightReport.blockers | ForEach-Object { $_.id }) })
Add-Check "preflight.no_forbidden_side_effects" ($preflightReport.side_effects.remote_publication_performed -eq $false -and $preflightReport.side_effects.payload_bytes_uploaded -eq $false -and $preflightReport.side_effects.remote_payload_bytes_downloaded -eq $false -and $preflightReport.side_effects.install_performed -eq $false -and $preflightReport.side_effects.activation_performed -eq $false -and $preflightReport.side_effects.rollback_execution_performed -eq $false -and $preflightReport.side_effects.remote_dispatch_enabled -eq $false -and $preflightReport.side_effects.tui_authority -eq $false) "RC8-020 must not publish, upload, remotely download, install, activate, rollback, dispatch, or grant TUI authority." $preflightReport.side_effects
Add-Check "preflight.secret_safe" (Test-NoSensitiveText -Values @($preflightText, $objectFetchText)) "RC8-020 reports must not contain private key or token markers." $null

$passed = @($script:taskBlockers).Count -eq 0
$result = [ordered]@{
    schema = "agentos.rc8-installer-vm-preflight-result.v1"
    generated_at = (Get-Date).ToString("o")
    task = "RC8-020"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    source = [ordered]@{
        descriptor_result = New-ArtifactRef $resolvedDescriptorResultPath $descriptorResult
        descriptor = New-ArtifactRef $resolvedDescriptorPath $descriptor
        signature_ingestion_result = New-ArtifactRef $resolvedSignatureIngestionResultPath $signatureIngestionResult
        signed_descriptor_fail_closed = New-ArtifactRef $resolvedSignedDescriptorFailClosedResultPath $signedDescriptorFailClosed
    }
    outputs = [ordered]@{
        preflight_report = [ordered]@{
            path = Get-StablePath $preflightReportPath
            sha256 = Get-FileSha256 $preflightReportPath
        }
        object_fetch_report = [ordered]@{
            path = Get-StablePath $objectFetchReportPath
            sha256 = Get-FileSha256 $objectFetchReportPath
        }
    }
    vm_surface = [ordered]@{
        qemu_boot_smoke_completed = ($qemuResult -and $qemuResult.status -eq "completed")
        selected_machine = if ($qemuResult) { $qemuResult.selected_machine } else { $null }
        observed_all_markers = if ($qemuResult) { $qemuResult.observed_all_markers } else { $false }
        qemu_result_sha256 = if ($qemuResult) { Get-FileSha256 $qemuResultPath } else { $null }
    }
    object_fetch_surface = [ordered]@{
        external_https_object_uri_published = $externalHttpsObjectUriPublished
        remote_download_attempted = $false
        repo_local_quarantine_smoke_performed = $repoLocalQuarantineCopyPerformed
        quarantine_digest_verified = ($quarantinePayloadSha256 -eq [string]$descriptor.sha256)
        quarantine_size_verified = ($quarantinePayloadSize -eq [int64]$descriptor.size_bytes)
    }
    payload_blockers = @(
        "external-https-object-uri-not-published",
        "declared-current-artifact-drift-unresolved"
    )
    invariants = [ordered]@{
        local_fixture_only = $true
        remote_publication_performed = $false
        payload_bytes_uploaded = $false
        remote_payload_bytes_downloaded = $false
        repo_local_quarantine_copy_performed = $repoLocalQuarantineCopyPerformed
        local_private_key_material_used = $false
        private_key_material_read_or_printed = $false
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
    }
    checks = $script:checks
    task_blockers = $script:taskBlockers
    preflight_steps = $script:preflightSteps
    preflight_blockers = $script:preflightBlockers
    summary = [ordered]@{
        checks = @($script:checks).Count
        task_blockers = @($script:taskBlockers).Count
        preflight_steps = @($script:preflightSteps).Count
        preflight_blockers = @($script:preflightBlockers).Count
        preflight_state = $preflightReport.preflight_state
        rc8_020_complete = $passed
        next_task = "RC8-021"
    }
}
Write-Json -Value $result -Path $resolvedResultPath

if ($FailOnBlocked -and @($script:taskBlockers).Count -gt 0) {
    exit 1
}

Write-Host "RC8 installer VM preflight $($result.status): $(Get-StablePath $resolvedResultPath)"
Write-Host "Preflight state: $($preflightReport.preflight_state); blockers: $(@($preflightReport.blockers).Count)"
