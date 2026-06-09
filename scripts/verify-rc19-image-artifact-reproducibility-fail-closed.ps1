param(
    [string]$ArtifactDir = ".workflow/artifacts/rc19-image-artifact-reproducibility-fail-closed",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc19",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc19/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc19/docs/rc19-installable-image-authority-contract.md",
    [string]$Rc19ArtifactResultPath = ".workflow/artifacts/rc19-reproducible-installable-image-artifact/result.json",
    [string]$Rc19ArtifactSetPath = ".workflow/artifacts/rc19-reproducible-installable-image-artifact/installable-image-artifact-set.json",
    [string]$Rc19InputMapPath = ".workflow/artifacts/rc19-reproducible-installable-image-artifact/reproducibility-input-map.json",
    [string]$Rc19MediaResultPath = ".workflow/artifacts/rc19-installer-media-manifest/result.json",
    [string]$Rc19InstallerMediaManifestPath = ".workflow/artifacts/rc19-installer-media-manifest/installer-media-manifest.json",
    [string]$Rc19BootTargetDescriptorPath = ".workflow/artifacts/rc19-installer-media-manifest/boot-target-descriptor.json",
    [string]$GeneratedAt = "",
    [switch]$FailOnFailedChecks
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

function Read-Json {
    param([Parameter(Mandatory = $true)][string]$Path)
    return Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
}

function Get-JsonText {
    param([Parameter(Mandatory = $true)]$Value)
    return ($Value | ConvertTo-Json -Depth 100)
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
    [IO.File]::WriteAllText($Path, (Get-JsonText $Value) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}

function Convert-JsonClone {
    param([Parameter(Mandatory = $true)]$Value)
    return ($Value | ConvertTo-Json -Depth 100 | ConvertFrom-Json)
}

function Add-Reason {
    param(
        [System.Collections.Generic.List[string]]$Reasons,
        [Parameter(Mandatory = $true)][string]$Reason
    )
    if (-not $Reasons.Contains($Reason)) {
        $Reasons.Add($Reason)
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
        $script:failedChecks += $entry
    }
}

function Get-TaskStatus {
    param($Plan, [Parameter(Mandatory = $true)][string]$TaskId)
    foreach ($wave in @($Plan.waves)) {
        foreach ($task in @($wave.tasks)) {
            if ($task.id -eq $TaskId) {
                return $task.status
            }
        }
    }
    return $null
}

function Get-JsonProperty {
    param($Json, [Parameter(Mandatory = $true)][string]$Name)
    if ($null -eq $Json) {
        return $null
    }
    if ($Json.PSObject.Properties.Name -contains $Name) {
        return $Json.$Name
    }
    return $null
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

function Test-StaleTimestamp {
    param($Value)
    if (-not (Has-Value $Value)) {
        return $true
    }
    try {
        return ([DateTimeOffset]::Parse([string]$Value)) -lt [DateTimeOffset]::Parse("2026-06-01T00:00:00+08:00")
    } catch {
        return $true
    }
}

function New-ArtifactRef {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        $Json = $null
    )
    $present = Test-Path -LiteralPath $Path -PathType Leaf
    return [ordered]@{
        path = Get-StablePath $Path
        sha256 = Get-FileSha256 $Path
        size_bytes = if ($present) { (Get-Item -LiteralPath $Path).Length } else { $null }
        present = $present
        schema = Get-JsonProperty $Json "schema"
        status = Get-JsonProperty $Json "status"
        task = Get-JsonProperty $Json "task"
        production_ready_claim = Get-JsonProperty $Json "production_ready_claim"
    }
}

function Test-NoSensitiveText {
    param([Parameter(Mandatory = $true)][string[]]$Values)
    $privateKeyMarker = "PRIVATE" + " KEY"
    $publicKeyMarker = "PUBLIC" + " KEY"
    $identityMarker = "finger" + "print"
    $markers = @(
        ("BEGIN " + $privateKeyMarker),
        ("BEGIN " + $publicKeyMarker),
        ($privateKeyMarker + "-----"),
        ("Authorization:" + " Bearer"),
        ("Bearer" + " "),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ("." + "local-release-authority/" + "private"),
        ("/etc/" + "aios-signer/" + "private"),
        ("signing" + "-key." + "pem"),
        ("." + "pem"),
        $identityMarker
    )
    foreach ($value in $Values) {
        if ($null -eq $value) { continue }
        foreach ($marker in $markers) {
            if ($value.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                return $false
            }
        }
    }
    return $true
}

function Test-AnyTrueField {
    param(
        $Object,
        [Parameter(Mandatory = $true)][string[]]$Names
    )
    if ($null -eq $Object) {
        return $false
    }
    foreach ($name in $Names) {
        if ($Object.PSObject.Properties.Name -contains $name -and $Object.$name -eq $true) {
            return $true
        }
    }
    return $false
}

function Test-SideEffectsClear {
    param([Parameter(Mandatory = $true)]$SideEffects)
    if ($SideEffects -is [System.Collections.IDictionary]) {
        foreach ($entry in $SideEffects.GetEnumerator()) {
            if ($entry.Value -ne $false) {
                return $false
            }
        }
        return $true
    }
    foreach ($entry in $SideEffects.PSObject.Properties) {
        if ($entry.Value -ne $false) {
            return $false
        }
    }
    return $true
}

function New-SideEffects {
    return [ordered]@{
        install_performed = $false
        update_performed = $false
        rollback_execution_performed = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        payload_uploaded = $false
        external_payload_published = $false
        object_storage_provisioned = $false
        cryptographic_signing_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        production_ring_mutated = $false
        mirror_frontend_mutated = $false
        signer_authority_granted = $false
        network_fetch_attempted = $false
    }
}

function Invoke-ReproducibilityEvaluation {
    param([Parameter(Mandatory = $true)]$Fixture)

    $reasons = [System.Collections.Generic.List[string]]::new()
    if ($Fixture.schema -ne "agentos.rc19-image-artifact-reproducibility-fixture.v1") {
        Add-Reason $reasons "bad-fixture-schema"
    }
    if ($Fixture.production_ready_claim -eq $true) {
        Add-Reason $reasons "production-ready-claim-denied"
    }

    if ($Fixture.source_presence.artifact_result_present -ne $true) {
        Add-Reason $reasons "missing-artifact-result"
    }
    if ($Fixture.source_presence.artifact_set_present -ne $true) {
        Add-Reason $reasons "missing-artifact-set"
    }
    if ($Fixture.source_presence.reproducibility_input_map_present -ne $true) {
        Add-Reason $reasons "missing-reproducibility-input-map"
    }
    if ($Fixture.source_presence.installer_media_manifest_present -ne $true) {
        Add-Reason $reasons "missing-installer-media-manifest"
    }
    if ($Fixture.source_presence.boot_target_descriptor_present -ne $true) {
        Add-Reason $reasons "missing-boot-target-descriptor"
    }

    if ($Fixture.artifact_result.status -ne "passed" -or $Fixture.artifact_result.production_ready_claim -eq $true) {
        Add-Reason $reasons "artifact-result-not-passed-non-ga"
    }
    if ($Fixture.media_result.status -ne "passed" -or $Fixture.media_result.production_ready_claim -eq $true) {
        Add-Reason $reasons "media-result-not-passed-non-ga"
    }
    foreach ($stamp in @(
        $Fixture.artifact_result.generated_at,
        $Fixture.artifact_set.generated_at,
        $Fixture.input_map.generated_at,
        $Fixture.media_result.generated_at,
        $Fixture.installer_media_manifest.generated_at,
        $Fixture.boot_target_descriptor.generated_at
    )) {
        if (Test-StaleTimestamp $stamp) {
            Add-Reason $reasons "stale-artifact-evidence"
            break
        }
    }
    if ($Fixture.replay_nonce_seen -eq $true -or $Fixture.artifact_identity_replayed -eq $true) {
        Add-Reason $reasons "replayed-artifact-identity"
    }

    $artifactId = [string]$Fixture.artifact_result.installable_image_artifact_id
    if (-not (Has-Value $artifactId) -or $artifactId -notlike "sha256:*") {
        Add-Reason $reasons "missing-installable-artifact-id"
    }
    $artifactIdPeers = @(
        $Fixture.artifact_set.installable_image_artifact_id,
        $Fixture.input_map.installable_image_artifact_id,
        $Fixture.media_result.installable_image_artifact_id,
        $Fixture.installer_media_manifest.installable_image_artifact_id,
        $Fixture.boot_target_descriptor.installable_image_artifact_id
    )
    foreach ($peer in $artifactIdPeers) {
        if ((Has-Value $artifactId) -and (Has-Value $peer) -and [string]$peer -ne $artifactId) {
            Add-Reason $reasons "installable-artifact-id-mismatch"
            break
        }
    }
    if ((Has-Value $Fixture.artifact_result.identity_material_hash) -and (Has-Value $Fixture.input_map.identity_material_hash) -and [string]$Fixture.artifact_result.identity_material_hash -ne [string]$Fixture.input_map.identity_material_hash) {
        Add-Reason $reasons "identity-material-hash-mismatch"
    }
    if ([string]$Fixture.artifact_result.artifact_set_sha256 -ne [string]$script:expectedArtifactSetSha256) {
        Add-Reason $reasons "artifact-set-sha-mismatch"
    }
    if ([string]$Fixture.artifact_result.reproducibility_input_map_sha256 -ne [string]$script:expectedInputMapSha256) {
        Add-Reason $reasons "input-map-sha-mismatch"
    }
    if ([string]$Fixture.artifact_set.reproducibility_input_map_sha256 -ne [string]$script:expectedInputMapSha256) {
        Add-Reason $reasons "artifact-set-input-map-sha-mismatch"
    }
    if ([string]$Fixture.media_result.installer_media_manifest_sha256 -ne [string]$script:expectedInstallerMediaManifestSha256) {
        Add-Reason $reasons "installer-media-manifest-sha-mismatch"
    }
    if ([string]$Fixture.media_result.boot_target_descriptor_sha256 -ne [string]$script:expectedBootTargetDescriptorSha256) {
        Add-Reason $reasons "boot-target-descriptor-sha-mismatch"
    }

    $installerMediaId = [string]$Fixture.media_result.installer_media_id
    if (-not (Has-Value $installerMediaId) -or $installerMediaId -notlike "sha256:*") {
        Add-Reason $reasons "missing-installer-media-id"
    }
    foreach ($peer in @($Fixture.installer_media_manifest.installer_media_id, $Fixture.boot_target_descriptor.installer_media_id)) {
        if ((Has-Value $installerMediaId) -and (Has-Value $peer) -and [string]$peer -ne $installerMediaId) {
            Add-Reason $reasons "installer-media-id-mismatch"
            break
        }
    }

    $bootTargetDescriptorId = [string]$Fixture.media_result.boot_target_descriptor_id
    if (-not (Has-Value $bootTargetDescriptorId) -or $bootTargetDescriptorId -notlike "sha256:*") {
        Add-Reason $reasons "missing-boot-target-descriptor-id"
    }
    foreach ($peer in @($Fixture.installer_media_manifest.boot_target_descriptor_id, $Fixture.boot_target_descriptor.boot_target_descriptor_id)) {
        if ((Has-Value $bootTargetDescriptorId) -and (Has-Value $peer) -and [string]$peer -ne $bootTargetDescriptorId) {
            Add-Reason $reasons "boot-target-descriptor-id-mismatch"
            break
        }
    }

    if (($Fixture.scope.PSObject.Properties.Name -contains "target_release_pattern" -and [string]$Fixture.scope.target_release_pattern -in @("*", "all", "all-releases")) -or
        ($Fixture.scope.PSObject.Properties.Name -contains "artifact_scope" -and [string]$Fixture.scope.artifact_scope -in @("*", "all", "all-releases"))) {
        Add-Reason $reasons "artifact-scope-too-broad"
    }
    if ($Fixture.input_map.deterministic_rules.required_inputs_must_be_present -ne $true -or
        $Fixture.input_map.deterministic_rules.required_inputs_must_have_sha256 -ne $true -or
        $Fixture.input_map.deterministic_rules.generated_at_excluded_from_identity -ne $true -or
        $Fixture.input_map.deterministic_rules.output_file_hashes_excluded_from_identity -ne $true) {
        Add-Reason $reasons "reproducibility-rule-missing"
    }

    $targetArch = @()
    if ($null -ne $Fixture.boot.target_arch) {
        $targetArch = @($Fixture.boot.target_arch)
    }
    if ($targetArch -notcontains "x86_64" -or $Fixture.boot.kernel_family -ne "linux-lts") {
        Add-Reason $reasons "unsupported-architecture"
    }
    $bootMarkers = @()
    if ($null -ne $Fixture.boot.boot_markers) {
        $bootMarkers = @($Fixture.boot.boot_markers)
    }
    if ($bootMarkers.Count -lt 5 -or $bootMarkers -notcontains "AGENTOS_TUI_CONSOLE_READY") {
        Add-Reason $reasons "boot-markers-missing"
    }
    if ($Fixture.boot_target_descriptor.projection_only -ne $true -or
        $Fixture.boot_target_descriptor.host_boot_state_authority -eq $true -or
        $Fixture.boot_target_descriptor.host_boot_metadata_mutation_authority -eq $true) {
        Add-Reason $reasons "boot-target-authority-broadening"
    }

    if ($Fixture.installer_media_manifest.install_effects_gated_until -ne "RC19-021" -or
        $Fixture.installer_media_manifest.install_allowed -eq $true -or
        $Fixture.installer_media_manifest.first_user_install_allowed -eq $true -or
        $Fixture.requests.install_now -eq $true) {
        Add-Reason $reasons "install-before-rc19-021-denied"
    }
    if ($Fixture.requests.host_rootfs_write -eq $true -or $Fixture.authority.host_rootfs_mutation_authority -eq $true) {
        Add-Reason $reasons "host-rootfs-mutation-denied"
    }
    if ($Fixture.requests.host_active_slot_write -eq $true -or $Fixture.authority.host_active_slot_mutation_authority -eq $true) {
        Add-Reason $reasons "host-active-slot-mutation-denied"
    }
    if ($Fixture.requests.host_boot_metadata_write -eq $true -or $Fixture.authority.host_boot_metadata_mutation_authority -eq $true) {
        Add-Reason $reasons "host-boot-metadata-mutation-denied"
    }
    if ($Fixture.requests.active_artifact_set_write -eq $true -or $Fixture.authority.active_artifact_set_mutation_authority -eq $true) {
        Add-Reason $reasons "active-artifact-set-mutation-denied"
    }
    if ($Fixture.requests.production_ring_write -eq $true -or $Fixture.authority.production_ring_mutation_authority -eq $true) {
        Add-Reason $reasons "production-ring-mutation-denied"
    }
    if ($Fixture.requests.payload_upload -eq $true) {
        Add-Reason $reasons "payload-upload-denied"
    }
    if ($Fixture.requests.external_payload_publication -eq $true) {
        Add-Reason $reasons "external-payload-publication-denied"
    }
    if ($Fixture.requests.object_storage_provisioning -eq $true -or $Fixture.authority.object_storage_authority -eq $true) {
        Add-Reason $reasons "object-storage-provisioning-denied"
    }
    if ($Fixture.requests.cryptographic_signing -eq $true) {
        Add-Reason $reasons "cryptographic-signing-denied"
    }
    if ($Fixture.requests.signer_authority -eq $true -or $Fixture.authority.signer_authority -eq $true) {
        Add-Reason $reasons "signer-authority-denied"
    }
    if ($Fixture.requests.mirror_frontend_authority -eq $true -or $Fixture.authority.mirror_authority -eq $true -or $Fixture.authority.frontend_authority -eq $true) {
        Add-Reason $reasons "mirror-frontend-authority-denied"
    }
    if ($Fixture.requests.support_upload -eq $true -or $Fixture.authority.support_upload_authority -eq $true) {
        Add-Reason $reasons "support-upload-denied"
    }
    if ($Fixture.requests.recovery_execution -eq $true -or $Fixture.authority.recovery_execution_authority -eq $true) {
        Add-Reason $reasons "recovery-execution-denied"
    }
    if ($Fixture.requests.remote_dispatch -eq $true -or $Fixture.authority.remote_dispatch_authority -eq $true) {
        Add-Reason $reasons "remote-dispatch-denied"
    }
    $projectionAuthorityRequested = Test-AnyTrueField $Fixture.authority @("normal_shell_authority", "tui_authority", "model_replay_authority", "endpoint_reachability_authority")
    if ($Fixture.requests.shell_tui_model_endpoint_authority -eq $true -or $projectionAuthorityRequested) {
        Add-Reason $reasons "projection-authority-broadening-denied"
    }

    return [ordered]@{
        observed_state = if ($reasons.Count -eq 0) { "artifact-reproducibility-valid-non-authoritative" } else { "artifact-reproducibility-denied-before-effect" }
        observed_reasons = @($reasons)
        denied_before_install = $true
        denied_before_host_mutation = $true
        denied_before_publication = $true
        denied_before_signing = $true
        denied_before_support_upload = $true
        denied_before_recovery_execution = $true
        denied_before_remote_dispatch = $true
        side_effects = New-SideEffects
    }
}

function Invoke-Case {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string[]]$ExpectedReasons,
        [scriptblock]$Mutate
    )
    $fixture = Convert-JsonClone $script:baselineFixture
    if ($null -ne $Mutate) {
        & $Mutate $fixture
    }
    $evaluation = Invoke-ReproducibilityEvaluation -Fixture $fixture
    $missing = @($ExpectedReasons | Where-Object { $_ -notin $evaluation.observed_reasons })
    $sideEffectsClear = Test-SideEffectsClear $evaluation.side_effects
    $passed = (
        $evaluation.observed_state -eq "artifact-reproducibility-denied-before-effect" -and
        $missing.Count -eq 0 -and
        $evaluation.denied_before_install -eq $true -and
        $evaluation.denied_before_host_mutation -eq $true -and
        $evaluation.denied_before_publication -eq $true -and
        $evaluation.denied_before_signing -eq $true -and
        $evaluation.denied_before_support_upload -eq $true -and
        $evaluation.denied_before_recovery_execution -eq $true -and
        $evaluation.denied_before_remote_dispatch -eq $true -and
        $sideEffectsClear
    )
    return [ordered]@{
        id = $Id
        status = if ($passed) { "passed" } else { "failed" }
        expected_reasons = $ExpectedReasons
        observed_reasons = @($evaluation.observed_reasons)
        missing_expected_reasons = $missing
        observed_state = $evaluation.observed_state
        denied_before_install = $evaluation.denied_before_install
        denied_before_host_mutation = $evaluation.denied_before_host_mutation
        denied_before_publication = $evaluation.denied_before_publication
        denied_before_signing = $evaluation.denied_before_signing
        denied_before_support_upload = $evaluation.denied_before_support_upload
        denied_before_recovery_execution = $evaluation.denied_before_recovery_execution
        denied_before_remote_dispatch = $evaluation.denied_before_remote_dispatch
        side_effects = $evaluation.side_effects
    }
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:failedChecks = @()

$generatedAtValue = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }
$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$resolvedWorkflowDir = Resolve-RepoPath $WorkflowDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $resolvedWorkflowDir "evidence") | Out-Null

$resolvedPlanPath = Resolve-RepoPath $PlanPath
$resolvedContractPath = Resolve-RepoPath $ContractPath
$resolvedRc19ArtifactResultPath = Resolve-RepoPath $Rc19ArtifactResultPath
$resolvedRc19ArtifactSetPath = Resolve-RepoPath $Rc19ArtifactSetPath
$resolvedRc19InputMapPath = Resolve-RepoPath $Rc19InputMapPath
$resolvedRc19MediaResultPath = Resolve-RepoPath $Rc19MediaResultPath
$resolvedRc19InstallerMediaManifestPath = Resolve-RepoPath $Rc19InstallerMediaManifestPath
$resolvedRc19BootTargetDescriptorPath = Resolve-RepoPath $Rc19BootTargetDescriptorPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$rc19ArtifactResult = Read-Json $resolvedRc19ArtifactResultPath
$rc19ArtifactSet = Read-Json $resolvedRc19ArtifactSetPath
$rc19InputMap = Read-Json $resolvedRc19InputMapPath
$rc19MediaResult = Read-Json $resolvedRc19MediaResultPath
$rc19InstallerMediaManifest = Read-Json $resolvedRc19InstallerMediaManifestPath
$rc19BootTargetDescriptor = Read-Json $resolvedRc19BootTargetDescriptorPath

$rc19PreviousArtifactStatus = Get-TaskStatus -Plan $plan -TaskId "RC19-010"
$rc19PreviousMediaStatus = Get-TaskStatus -Plan $plan -TaskId "RC19-011"
$rc19TaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC19-012"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc19PreviousArtifactStatus -eq "completed" -and
    $rc19PreviousMediaStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC19-012" -and ($rc19TaskStatus -eq "pending" -or $rc19TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC19-020" -and $rc19TaskStatus -eq "completed")
    )
)

$script:expectedArtifactSetSha256 = Get-FileSha256 $resolvedRc19ArtifactSetPath
$script:expectedInputMapSha256 = Get-FileSha256 $resolvedRc19InputMapPath
$script:expectedInstallerMediaManifestSha256 = Get-FileSha256 $resolvedRc19InstallerMediaManifestPath
$script:expectedBootTargetDescriptorSha256 = Get-FileSha256 $resolvedRc19BootTargetDescriptorPath

$source = [ordered]@{
    rc19_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc19_contract = New-ArtifactRef $resolvedContractPath
    rc19_artifact_result = New-ArtifactRef $resolvedRc19ArtifactResultPath $rc19ArtifactResult
    rc19_artifact_set = New-ArtifactRef $resolvedRc19ArtifactSetPath $rc19ArtifactSet
    rc19_reproducibility_input_map = New-ArtifactRef $resolvedRc19InputMapPath $rc19InputMap
    rc19_media_result = New-ArtifactRef $resolvedRc19MediaResultPath $rc19MediaResult
    rc19_installer_media_manifest = New-ArtifactRef $resolvedRc19InstallerMediaManifestPath $rc19InstallerMediaManifest
    rc19_boot_target_descriptor = New-ArtifactRef $resolvedRc19BootTargetDescriptorPath $rc19BootTargetDescriptor
}
$missingRequiredRefs = @($source.GetEnumerator() | Where-Object { $_.Value.present -ne $true -or $_.Value.sha256 -notmatch "^[0-9a-f]{64}$" } | ForEach-Object { $_.Value.path })

$artifactSourceReady = (
    $rc19ArtifactResult.status -eq "passed" -and
    $rc19ArtifactResult.production_ready_claim -eq $false -and
    $rc19ArtifactSet.production_ready_claim -eq $false -and
    $rc19InputMap.production_ready_claim -eq $false -and
    $rc19ArtifactSet.installable_image_artifact_id -eq $rc19ArtifactResult.installable_image_artifact_id -and
    $rc19InputMap.installable_image_artifact_id -eq $rc19ArtifactResult.installable_image_artifact_id -and
    $rc19ArtifactResult.artifact_set_sha256 -eq $script:expectedArtifactSetSha256 -and
    $rc19ArtifactResult.reproducibility_input_map_sha256 -eq $script:expectedInputMapSha256
)
$mediaSourceReady = (
    $rc19MediaResult.status -eq "passed" -and
    $rc19MediaResult.production_ready_claim -eq $false -and
    $rc19MediaResult.installable_image_artifact_id -eq $rc19ArtifactResult.installable_image_artifact_id -and
    $rc19InstallerMediaManifest.installable_image_artifact_id -eq $rc19ArtifactResult.installable_image_artifact_id -and
    $rc19BootTargetDescriptor.installable_image_artifact_id -eq $rc19ArtifactResult.installable_image_artifact_id -and
    $rc19MediaResult.outputs.installer_media_manifest.sha256 -eq $script:expectedInstallerMediaManifestSha256 -and
    $rc19MediaResult.outputs.boot_target_descriptor.sha256 -eq $script:expectedBootTargetDescriptorSha256
)
$projectionOnlyReady = (
    $rc19BootTargetDescriptor.projection_only -eq $true -and
    $rc19BootTargetDescriptor.authority.host_boot_state_authority -eq $false -and
    $rc19InstallerMediaManifest.authority.host_rootfs_mutation_authority -eq $false -and
    $rc19InstallerMediaManifest.install_gate.install_allowed -eq $false -and
    $rc19InstallerMediaManifest.install_gate.first_user_install_allowed -eq $false -and
    $rc19InstallerMediaManifest.install_gate.install_effects_gated_until -eq "RC19-021"
)

$script:baselineFixture = [ordered]@{
    schema = "agentos.rc19-image-artifact-reproducibility-fixture.v1"
    production_ready_claim = $false
    replay_nonce_seen = $false
    artifact_identity_replayed = $false
    source_presence = [ordered]@{
        artifact_result_present = $true
        artifact_set_present = $true
        reproducibility_input_map_present = $true
        installer_media_manifest_present = $true
        boot_target_descriptor_present = $true
    }
    scope = [ordered]@{
        artifact_scope = "single-installable-image-artifact"
        target_release_pattern = $rc19ArtifactSet.artifact_identity.release.release_id
    }
    artifact_result = [ordered]@{
        generated_at = $rc19ArtifactResult.generated_at
        status = $rc19ArtifactResult.status
        production_ready_claim = $rc19ArtifactResult.production_ready_claim
        installable_image_artifact_id = $rc19ArtifactResult.installable_image_artifact_id
        identity_material_hash = $rc19ArtifactResult.identity_material_hash
        artifact_set_sha256 = $rc19ArtifactResult.artifact_set_sha256
        reproducibility_input_map_sha256 = $rc19ArtifactResult.reproducibility_input_map_sha256
    }
    artifact_set = [ordered]@{
        generated_at = $rc19ArtifactSet.generated_at
        status = $rc19ArtifactSet.status
        production_ready_claim = $rc19ArtifactSet.production_ready_claim
        installable_image_artifact_id = $rc19ArtifactSet.installable_image_artifact_id
        identity_material_hash = $rc19ArtifactSet.identity_material_hash
        reproducibility_input_map_sha256 = $rc19ArtifactSet.reproducibility_input_map.sha256
        artifact_surface = $rc19ArtifactSet.artifact_surface
    }
    input_map = [ordered]@{
        generated_at = $rc19InputMap.generated_at
        status = $rc19InputMap.status
        production_ready_claim = $rc19InputMap.production_ready_claim
        installable_image_artifact_id = $rc19InputMap.installable_image_artifact_id
        identity_material_hash = $rc19InputMap.identity_material_hash
        deterministic_rules = $rc19InputMap.deterministic_rules
    }
    media_result = [ordered]@{
        generated_at = $rc19MediaResult.generated_at
        status = $rc19MediaResult.status
        production_ready_claim = $rc19MediaResult.production_ready_claim
        installable_image_artifact_id = $rc19MediaResult.installable_image_artifact_id
        installer_media_id = $rc19MediaResult.installer_media_id
        boot_target_descriptor_id = $rc19MediaResult.boot_target_descriptor_id
        installer_media_manifest_sha256 = $rc19MediaResult.outputs.installer_media_manifest.sha256
        boot_target_descriptor_sha256 = $rc19MediaResult.outputs.boot_target_descriptor.sha256
    }
    installer_media_manifest = [ordered]@{
        generated_at = $rc19InstallerMediaManifest.generated_at
        status = $rc19InstallerMediaManifest.status
        production_ready_claim = $rc19InstallerMediaManifest.production_ready_claim
        installable_image_artifact_id = $rc19InstallerMediaManifest.installable_image_artifact_id
        installer_media_id = $rc19InstallerMediaManifest.installer_media_id
        boot_target_descriptor_id = $rc19InstallerMediaManifest.boot_target_descriptor.boot_target_descriptor_id
        install_effects_gated_until = $rc19InstallerMediaManifest.install_gate.install_effects_gated_until
        install_allowed = $rc19InstallerMediaManifest.install_gate.install_allowed
        first_user_install_allowed = $rc19InstallerMediaManifest.install_gate.first_user_install_allowed
    }
    boot_target_descriptor = [ordered]@{
        generated_at = $rc19BootTargetDescriptor.generated_at
        status = $rc19BootTargetDescriptor.status
        production_ready_claim = $rc19BootTargetDescriptor.production_ready_claim
        boot_target_descriptor_id = $rc19BootTargetDescriptor.boot_target_descriptor_id
        installable_image_artifact_id = $rc19BootTargetDescriptor.installable_image_artifact_id
        installer_media_id = $rc19BootTargetDescriptor.installer_media_id
        projection_only = $rc19BootTargetDescriptor.projection_only
        host_boot_state_authority = $rc19BootTargetDescriptor.authority.host_boot_state_authority
        host_boot_metadata_mutation_authority = $rc19BootTargetDescriptor.authority.host_boot_metadata_mutation_authority
    }
    boot = [ordered]@{
        target_arch = @($rc19InstallerMediaManifest.boot.target_arch)
        kernel_family = $rc19InstallerMediaManifest.boot.kernel_family
        boot_markers = @($rc19InstallerMediaManifest.boot.boot_markers)
    }
    requests = [ordered]@{
        install_now = $false
        host_rootfs_write = $false
        host_active_slot_write = $false
        host_boot_metadata_write = $false
        active_artifact_set_write = $false
        production_ring_write = $false
        payload_upload = $false
        external_payload_publication = $false
        object_storage_provisioning = $false
        cryptographic_signing = $false
        signer_authority = $false
        mirror_frontend_authority = $false
        support_upload = $false
        recovery_execution = $false
        remote_dispatch = $false
        shell_tui_model_endpoint_authority = $false
    }
    authority = [ordered]@{
        install_authority = $false
        first_user_install_authority = $false
        update_authority = $false
        rollback_execution_authority = $false
        support_upload_authority = $false
        recovery_execution_authority = $false
        remote_dispatch_authority = $false
        host_rootfs_mutation_authority = $false
        host_active_slot_mutation_authority = $false
        host_boot_metadata_mutation_authority = $false
        active_artifact_set_mutation_authority = $false
        production_ring_mutation_authority = $false
        mirror_authority = $false
        frontend_authority = $false
        signer_authority = $false
        object_storage_authority = $false
        normal_shell_authority = $false
        tui_authority = $false
        endpoint_reachability_authority = $false
        model_replay_authority = $false
    }
}

$baselineEvaluation = Invoke-ReproducibilityEvaluation -Fixture $script:baselineFixture

$cases = @()
$cases += Invoke-Case "missing.artifact_result" @("missing-artifact-result") { param($f) $f.source_presence.artifact_result_present = $false }
$cases += Invoke-Case "missing.artifact_set" @("missing-artifact-set") { param($f) $f.source_presence.artifact_set_present = $false }
$cases += Invoke-Case "missing.reproducibility_input_map" @("missing-reproducibility-input-map") { param($f) $f.source_presence.reproducibility_input_map_present = $false }
$cases += Invoke-Case "missing.installer_media_manifest" @("missing-installer-media-manifest") { param($f) $f.source_presence.installer_media_manifest_present = $false }
$cases += Invoke-Case "missing.boot_target_descriptor" @("missing-boot-target-descriptor") { param($f) $f.source_presence.boot_target_descriptor_present = $false }
$cases += Invoke-Case "stale.artifact_result" @("stale-artifact-evidence") { param($f) $f.artifact_result.generated_at = "2020-01-01T00:00:00+00:00" }
$cases += Invoke-Case "stale.input_map" @("stale-artifact-evidence") { param($f) $f.input_map.generated_at = "2020-01-01T00:00:00+00:00" }
$cases += Invoke-Case "replayed.artifact_identity" @("replayed-artifact-identity") { param($f) $f.artifact_identity_replayed = $true }
$cases += Invoke-Case "mismatched.artifact_id.result_to_set" @("installable-artifact-id-mismatch") { param($f) $f.artifact_set.installable_image_artifact_id = "sha256:0000000000000000000000000000000000000000000000000000000000000000" }
$cases += Invoke-Case "mismatched.artifact_id.input_map" @("installable-artifact-id-mismatch") { param($f) $f.input_map.installable_image_artifact_id = "sha256:1111111111111111111111111111111111111111111111111111111111111111" }
$cases += Invoke-Case "mismatched.artifact_id.media" @("installable-artifact-id-mismatch") { param($f) $f.installer_media_manifest.installable_image_artifact_id = "sha256:2222222222222222222222222222222222222222222222222222222222222222" }
$cases += Invoke-Case "mismatched.identity_material_hash" @("identity-material-hash-mismatch") { param($f) $f.input_map.identity_material_hash = "3333333333333333333333333333333333333333333333333333333333333333" }
$cases += Invoke-Case "mismatched.artifact_set_sha" @("artifact-set-sha-mismatch") { param($f) $f.artifact_result.artifact_set_sha256 = "4444444444444444444444444444444444444444444444444444444444444444" }
$cases += Invoke-Case "mismatched.input_map_sha" @("input-map-sha-mismatch") { param($f) $f.artifact_result.reproducibility_input_map_sha256 = "5555555555555555555555555555555555555555555555555555555555555555" }
$cases += Invoke-Case "mismatched.artifact_set_input_map_sha" @("artifact-set-input-map-sha-mismatch") { param($f) $f.artifact_set.reproducibility_input_map_sha256 = "6666666666666666666666666666666666666666666666666666666666666666" }
$cases += Invoke-Case "mismatched.installer_media_id" @("installer-media-id-mismatch") { param($f) $f.boot_target_descriptor.installer_media_id = "sha256:7777777777777777777777777777777777777777777777777777777777777777" }
$cases += Invoke-Case "mismatched.boot_target_descriptor_id" @("boot-target-descriptor-id-mismatch") { param($f) $f.installer_media_manifest.boot_target_descriptor_id = "sha256:8888888888888888888888888888888888888888888888888888888888888888" }
$cases += Invoke-Case "mismatched.installer_media_manifest_sha" @("installer-media-manifest-sha-mismatch") { param($f) $f.media_result.installer_media_manifest_sha256 = "9999999999999999999999999999999999999999999999999999999999999999" }
$cases += Invoke-Case "mismatched.boot_target_descriptor_sha" @("boot-target-descriptor-sha-mismatch") { param($f) $f.media_result.boot_target_descriptor_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
$cases += Invoke-Case "broad.target_release_pattern" @("artifact-scope-too-broad") { param($f) $f.scope.target_release_pattern = "*" }
$cases += Invoke-Case "missing.reproducibility_rule" @("reproducibility-rule-missing") { param($f) $f.input_map.deterministic_rules.required_inputs_must_have_sha256 = $false }
$cases += Invoke-Case "missing.boot_markers" @("boot-markers-missing") { param($f) $f.boot.boot_markers = @() }
$cases += Invoke-Case "unsupported.architecture" @("unsupported-architecture") { param($f) $f.boot.target_arch = @("arm64") }
$cases += Invoke-Case "boot_target.projection_false" @("boot-target-authority-broadening") { param($f) $f.boot_target_descriptor.projection_only = $false }
$cases += Invoke-Case "install.allowed.before_rc19_021" @("install-before-rc19-021-denied") { param($f) $f.installer_media_manifest.install_allowed = $true }
$cases += Invoke-Case "host.rootfs_mutation" @("host-rootfs-mutation-denied") { param($f) $f.requests.host_rootfs_write = $true }
$cases += Invoke-Case "host.active_slot_mutation" @("host-active-slot-mutation-denied") { param($f) $f.requests.host_active_slot_write = $true }
$cases += Invoke-Case "host.boot_metadata_mutation" @("host-boot-metadata-mutation-denied") { param($f) $f.requests.host_boot_metadata_write = $true }
$cases += Invoke-Case "active_artifact_set.mutation" @("active-artifact-set-mutation-denied") { param($f) $f.requests.active_artifact_set_write = $true }
$cases += Invoke-Case "production_ring.mutation" @("production-ring-mutation-denied") { param($f) $f.requests.production_ring_write = $true }
$cases += Invoke-Case "payload.upload" @("payload-upload-denied") { param($f) $f.requests.payload_upload = $true }
$cases += Invoke-Case "external_payload.publication" @("external-payload-publication-denied") { param($f) $f.requests.external_payload_publication = $true }
$cases += Invoke-Case "object_storage.provisioning" @("object-storage-provisioning-denied") { param($f) $f.requests.object_storage_provisioning = $true }
$cases += Invoke-Case "cryptographic.signing" @("cryptographic-signing-denied") { param($f) $f.requests.cryptographic_signing = $true }
$cases += Invoke-Case "signer.authority" @("signer-authority-denied") { param($f) $f.authority.signer_authority = $true }
$cases += Invoke-Case "mirror_frontend.authority" @("mirror-frontend-authority-denied") { param($f) $f.requests.mirror_frontend_authority = $true }
$cases += Invoke-Case "support.upload" @("support-upload-denied") { param($f) $f.requests.support_upload = $true }
$cases += Invoke-Case "recovery.execution" @("recovery-execution-denied") { param($f) $f.requests.recovery_execution = $true }
$cases += Invoke-Case "remote.dispatch" @("remote-dispatch-denied") { param($f) $f.requests.remote_dispatch = $true }
$cases += Invoke-Case "projection.shell_tui_model_endpoint" @("projection-authority-broadening-denied") { param($f) $f.requests.shell_tui_model_endpoint_authority = $true }
$cases += Invoke-Case "ga.production_ready_claim" @("production-ready-claim-denied") { param($f) $f.production_ready_claim = $true }

$failedCases = @($cases | Where-Object { $_.status -ne "passed" })
$casesWithSideEffects = @($cases | Where-Object { -not (Test-SideEffectsClear $_.side_effects) })

Add-Check "plan.current_task.rc19_012" $planAllowsRun "RC19-012 must run after RC19-010 and RC19-011 completed, while current_task is RC19-012 or during a completed rerun after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc19_010_status = $rc19PreviousArtifactStatus; rc19_011_status = $rc19PreviousMediaStatus; rc19_012_status = $rc19TaskStatus })
Add-Check "contract.fail_closed_scope.present" ($contractText.Contains("Verify installable image artifact reproducibility fail-closed fixtures") -and $contractText.Contains("missing, stale, mismatched, broad") -and $contractText.Contains("support-upload") -and $contractText.Contains("remote dispatch")) "RC19-012 must consume the installable image authority contract fail-closed scope." $source.rc19_contract
Add-Check "sources.required.present" (@($missingRequiredRefs).Count -eq 0) "All RC19-012 required source artifacts must be present and hashable." $missingRequiredRefs
Add-Check "source.artifact.ready" $artifactSourceReady "RC19-012 must bind the completed RC19 installable image artifact result, artifact set, and input map with current output hashes." ([ordered]@{ result_status = $rc19ArtifactResult.status; artifact_id = $rc19ArtifactResult.installable_image_artifact_id; artifact_set_sha256 = $script:expectedArtifactSetSha256; input_map_sha256 = $script:expectedInputMapSha256 })
Add-Check "source.media.ready" $mediaSourceReady "RC19-012 must bind the completed installer media manifest and boot target descriptor with current output hashes." ([ordered]@{ media_status = $rc19MediaResult.status; installer_media_id = $rc19MediaResult.installer_media_id; boot_target_descriptor_id = $rc19MediaResult.boot_target_descriptor_id; media_manifest_sha256 = $script:expectedInstallerMediaManifestSha256; boot_target_descriptor_sha256 = $script:expectedBootTargetDescriptorSha256 })
Add-Check "baseline.fixture.valid_non_authoritative" ($baselineEvaluation.observed_state -eq "artifact-reproducibility-valid-non-authoritative") "The unmodified RC19 image artifact reproducibility fixture must be internally valid and non-authoritative." ([ordered]@{ observed_state = $baselineEvaluation.observed_state; reasons = $baselineEvaluation.observed_reasons })
Add-Check "baseline.install_effects.gated" $projectionOnlyReady "Baseline installer media and boot target descriptor must remain projection-only and gated until RC19-021." ([ordered]@{ boot_projection_only = $rc19BootTargetDescriptor.projection_only; install_allowed = $rc19InstallerMediaManifest.install_gate.install_allowed; first_user_install_allowed = $rc19InstallerMediaManifest.install_gate.first_user_install_allowed; install_effects_gated_until = $rc19InstallerMediaManifest.install_gate.install_effects_gated_until })
Add-Check "fixtures.coverage" (@($cases).Count -ge 35) "RC19-012 negative fixtures must cover missing, stale, mismatched, broad, replayed, remote, host-mutating, support upload, recovery execution, signing, publication, and authority-broadening cases." ([ordered]@{ cases = @($cases).Count; required_minimum = 35 })
Add-Check "fixtures.all_cases_passed" ($failedCases.Count -eq 0) "All RC19 image artifact reproducibility negative fixtures must deny before install, host mutation, publication, signing, support upload, recovery execution, or remote dispatch." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })
Add-Check "fixtures.no_side_effects" ($casesWithSideEffects.Count -eq 0) "Fixture execution must be local-only and create no install, host, publication, signing, support, recovery, remote dispatch, production, mirror/frontend, object storage, or network side effects." ([ordered]@{ side_effect_case_ids = @($casesWithSideEffects | ForEach-Object { $_.id }) })

$matrixPath = Join-Path $resolvedArtifactDir "reproducibility-fail-closed-matrix.json"
$matrix = [ordered]@{
    schema = "agentos.rc19-image-artifact-reproducibility-fail-closed-matrix.v1"
    generated_at = $generatedAtValue
    task = "RC19-012"
    status = if ($failedCases.Count -eq 0) { "passed" } else { "failed" }
    production_ready_claim = $false
    installable_image_artifact_id = $rc19ArtifactResult.installable_image_artifact_id
    installer_media_id = $rc19MediaResult.installer_media_id
    boot_target_descriptor_id = $rc19MediaResult.boot_target_descriptor_id
    baseline = [ordered]@{
        observed_state = $baselineEvaluation.observed_state
        observed_reasons = $baselineEvaluation.observed_reasons
        denied_before_install = $baselineEvaluation.denied_before_install
        denied_before_host_mutation = $baselineEvaluation.denied_before_host_mutation
        denied_before_publication = $baselineEvaluation.denied_before_publication
        denied_before_signing = $baselineEvaluation.denied_before_signing
        denied_before_support_upload = $baselineEvaluation.denied_before_support_upload
        denied_before_recovery_execution = $baselineEvaluation.denied_before_recovery_execution
        denied_before_remote_dispatch = $baselineEvaluation.denied_before_remote_dispatch
    }
    cases = $cases
    summary = [ordered]@{
        cases = @($cases).Count
        passed_cases = @($cases | Where-Object { $_.status -eq "passed" }).Count
        failed_cases = @($failedCases).Count
        failed_case_ids = @($failedCases | ForEach-Object { $_.id })
        side_effect_case_ids = @($casesWithSideEffects | ForEach-Object { $_.id })
    }
}
Write-Json $matrix $matrixPath

$outputsSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $matrixPath))
Add-Check "outputs.matrix.secret_safe" $outputsSecretSafe "RC19-012 fail-closed matrix must not contain key blocks, private key paths, auth tokens, public identity markers, or signing key file names." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc19-image-artifact-reproducibility-fail-closed-result.v1"
    generated_at = $generatedAtValue
    task = "RC19-012"
    status = $resultStatus
    production_ready_claim = $false
    installable_image_artifact_id = $rc19ArtifactResult.installable_image_artifact_id
    installer_media_id = $rc19MediaResult.installer_media_id
    boot_target_descriptor_id = $rc19MediaResult.boot_target_descriptor_id
    reproducibility_fail_closed_verified = (@($script:failedChecks).Count -eq 0)
    outputs = [ordered]@{
        reproducibility_fail_closed_matrix = [ordered]@{
            path = Get-StablePath $matrixPath
            sha256 = Get-FileSha256 $matrixPath
        }
    }
    fail_closed_surface = [ordered]@{
        state = "image-artifact-reproducibility-fail-closed-fixtures-passed-install-still-gated"
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
        denied_before_install = $true
        denied_before_host_mutation = $true
        denied_before_publication = $true
        denied_before_signing = $true
        denied_before_support_upload = $true
        denied_before_recovery_execution = $true
        denied_before_remote_dispatch = $true
        local_only_fixture_execution = $true
        install_performed = $false
        update_performed = $false
        rollback_execution_performed = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        payload_uploaded = $false
        external_payload_published = $false
        object_storage_provisioned = $false
        cryptographic_signing_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        production_ring_mutated = $false
    }
    source = $source
    checks = @($script:checks)
    blockers = @($script:failedChecks | ForEach-Object { $_.id })
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        repo_local_fixture_execution = $true
        projection_only = $true
        install_performed = $false
        update_performed = $false
        rollback_execution_performed = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        payload_uploaded = $false
        external_payload_published = $false
        external_mirror_changed = $false
        object_storage_provisioned = $false
        object_storage_authority = $false
        cryptographic_signing_performed = $false
        private_signing_material_handled = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        production_ring_mutated = $false
        mirror_authority = $false
        frontend_authority = $false
        signer_authority = $false
        endpoint_reachability_authority = $false
        model_replay_authority = $false
        normal_shell_authority = $false
        tui_authority = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        passed_cases = @($cases | Where-Object { $_.status -eq "passed" }).Count
        failed_cases = @($failedCases).Count
        rc19_012_complete = (@($script:failedChecks).Count -eq 0)
        reproducibility_fail_closed_verified = (@($script:failedChecks).Count -eq 0)
        next_task = "RC19-020"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC19-012-image-artifact-reproducibility-fail-closed.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc19-image-artifact-reproducibility-fail-closed-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC19-012"
    status = if ($resultStatus -eq "passed") { "completed" } else { "failed" }
    production_ready_claim = $false
    workflow = Get-StablePath $resolvedWorkflowDir
    script = [ordered]@{
        path = Get-StablePath $scriptPath
        sha256 = Get-FileSha256 $scriptPath
    }
    result = [ordered]@{
        path = Get-StablePath $resultPath
        status = $resultStatus
        sha256 = Get-FileSha256 $resultPath
    }
    outputs = $result.outputs
    fail_closed_surface = $result.fail_closed_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc19_012_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC19-020"
        commit_required = $true
    }
    checks = @($script:checks)
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) {
    throw "Sensitive marker detected in RC19-012 outputs."
}

Write-Host "RC19 image artifact reproducibility fail-closed $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Matrix: $(Get-StablePath $matrixPath)"
Write-Host "Cases: $(@($cases).Count), failed cases: $($failedCases.Count), failed checks: $(@($script:failedChecks).Count)"
Write-Host "Install performed: false; host mutation: false; publication: false; signing: false; support upload: false; recovery: false; remote dispatch: false"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
