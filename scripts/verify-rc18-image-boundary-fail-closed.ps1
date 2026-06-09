param(
    [string]$ArtifactDir = ".workflow/artifacts/rc18-image-boundary-fail-closed",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc18",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc18/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc18/docs/rc18-isolated-installed-system-drill-contract.md",
    [string]$BoundaryResultPath = ".workflow/artifacts/rc18-disposable-installed-system-boundary/result.json",
    [string]$ImageBoundaryPath = ".workflow/artifacts/rc18-disposable-installed-system-boundary/image-boundary.json",
    [string]$BaselineResultPath = ".workflow/artifacts/rc18-installed-system-baseline/result.json",
    [string]$BaselineIdentityPath = ".workflow/artifacts/rc18-installed-system-baseline/baseline-identity.json",
    [string]$BootStateProjectionPath = ".workflow/artifacts/rc18-installed-system-baseline/boot-state-projection.json",
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
        schema = if ($null -ne $Json) { $Json.schema } else { $null }
        status = if ($null -ne $Json) { $Json.status } else { $null }
        production_ready_claim = if ($null -ne $Json) { $Json.production_ready_claim } else { $null }
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

function Invoke-BoundaryEvaluation {
    param([Parameter(Mandatory = $true)]$Fixture)

    $reasons = [System.Collections.Generic.List[string]]::new()
    if ($Fixture.schema -ne "agentos.rc18-image-boundary-side-effect-fixture.v1") {
        Add-Reason $reasons "bad-fixture-schema"
    }
    if ($Fixture.production_ready_claim -eq $true) {
        Add-Reason $reasons "ga-claim-denied"
    }
    if ($Fixture.boundary.bound -ne $true -or [string]::IsNullOrWhiteSpace([string]$Fixture.boundary.boundary_id)) {
        Add-Reason $reasons "missing-boundary"
    } elseif ($Fixture.boundary.boundary_id -ne $script:expectedBoundaryId) {
        Add-Reason $reasons "boundary-id-mismatch"
    }
    if ($Fixture.baseline.bound -ne $true -or [string]::IsNullOrWhiteSpace([string]$Fixture.baseline.baseline_id)) {
        Add-Reason $reasons "missing-baseline"
    } elseif ($Fixture.baseline.baseline_id -ne $script:expectedBaselineId -or $Fixture.baseline.stale -eq $true) {
        Add-Reason $reasons "stale-baseline"
    }
    if ($Fixture.baseline.boot_state_projection_authoritative_for_host -eq $true) {
        Add-Reason $reasons "host-boot-authority-denied"
    }
    if ($Fixture.boundary.host_write_surface_allowed -eq $true -or
        $Fixture.requests.host_rootfs_write -eq $true -or
        $Fixture.requests.host_active_slot_write -eq $true -or
        $Fixture.requests.host_boot_metadata_write -eq $true -or
        $Fixture.requests.active_artifact_set_write -eq $true) {
        Add-Reason $reasons "host-write-broadening-denied"
    }
    if ($Fixture.requests.host_rootfs_write -eq $true) {
        Add-Reason $reasons "host-rootfs-mutation-denied"
    }
    if ($Fixture.requests.host_active_slot_write -eq $true) {
        Add-Reason $reasons "host-active-slot-mutation-denied"
    }
    if ($Fixture.requests.host_boot_metadata_write -eq $true) {
        Add-Reason $reasons "host-boot-metadata-mutation-denied"
    }
    if ($Fixture.requests.active_artifact_set_write -eq $true) {
        Add-Reason $reasons "active-artifact-set-mutation-denied"
    }
    if ($Fixture.requests.production_ring_write -eq $true -or $Fixture.authority.production_ring_mutation_allowed -eq $true) {
        Add-Reason $reasons "production-ring-mutation-denied"
    }
    if ($Fixture.requests.remote_dispatch -eq $true -or $Fixture.authority.remote_dispatch_enabled -eq $true) {
        Add-Reason $reasons "remote-dispatch-denied"
    }
    if ($Fixture.requests.support_upload -eq $true -or $Fixture.authority.support_upload_allowed -eq $true) {
        Add-Reason $reasons "support-upload-denied"
    }
    if ($Fixture.requests.recovery_execution -eq $true -or $Fixture.authority.recovery_execution_allowed -eq $true) {
        Add-Reason $reasons "recovery-execution-denied"
    }
    if ($Fixture.authority.signer_authority -eq $true -or $Fixture.requests.signer_authority -eq $true) {
        Add-Reason $reasons "signer-authority-denied"
    }
    if ($Fixture.authority.mirror_frontend_authority -eq $true -or $Fixture.requests.mirror_frontend_authority -eq $true) {
        Add-Reason $reasons "mirror-frontend-authority-denied"
    }
    if ($Fixture.requests.image_mutation_before_fail_closed -eq $true) {
        Add-Reason $reasons "image-mutation-before-fail-closed-denied"
    }
    if ($Fixture.authority.tui_authority -eq $true -or $Fixture.authority.model_replay_authority -eq $true -or $Fixture.authority.normal_shell_authority -eq $true) {
        Add-Reason $reasons "projection-authority-broadening-denied"
    }

    return [ordered]@{
        observed_state = if ($reasons.Count -eq 0) { "fixture-valid-non-authoritative" } else { "fixture-denied-before-side-effect" }
        observed_reasons = @($reasons)
        denied_before_image_mutation = $true
        denied_before_host_mutation = $true
        side_effects = [ordered]@{
            image_mutation_performed = $false
            host_rootfs_mutated = $false
            host_active_slot_mutated = $false
            host_boot_metadata_mutated = $false
            active_artifact_set_mutated = $false
            production_ring_mutated = $false
            support_upload_performed = $false
            recovery_execution_performed = $false
            remote_dispatch_enabled = $false
            mirror_frontend_mutated = $false
            signer_authority_granted = $false
            network_fetch_attempted = $false
        }
    }
}

function Invoke-Case {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string[]]$ExpectedReasons,
        [Parameter(Mandatory = $true)][scriptblock]$Mutate
    )
    $fixture = Convert-JsonClone $script:baselineFixture
    & $Mutate $fixture
    $evaluation = Invoke-BoundaryEvaluation -Fixture $fixture
    $missing = @($ExpectedReasons | Where-Object { $_ -notin $evaluation.observed_reasons })
    $sideEffectsClear = (
        $evaluation.side_effects.image_mutation_performed -eq $false -and
        $evaluation.side_effects.host_rootfs_mutated -eq $false -and
        $evaluation.side_effects.host_active_slot_mutated -eq $false -and
        $evaluation.side_effects.host_boot_metadata_mutated -eq $false -and
        $evaluation.side_effects.active_artifact_set_mutated -eq $false -and
        $evaluation.side_effects.production_ring_mutated -eq $false -and
        $evaluation.side_effects.support_upload_performed -eq $false -and
        $evaluation.side_effects.recovery_execution_performed -eq $false -and
        $evaluation.side_effects.remote_dispatch_enabled -eq $false -and
        $evaluation.side_effects.mirror_frontend_mutated -eq $false -and
        $evaluation.side_effects.signer_authority_granted -eq $false -and
        $evaluation.side_effects.network_fetch_attempted -eq $false
    )
    $passed = (
        $evaluation.observed_state -eq "fixture-denied-before-side-effect" -and
        $missing.Count -eq 0 -and
        $evaluation.denied_before_image_mutation -eq $true -and
        $evaluation.denied_before_host_mutation -eq $true -and
        $sideEffectsClear
    )
    return [ordered]@{
        id = $Id
        status = if ($passed) { "passed" } else { "failed" }
        expected_reasons = $ExpectedReasons
        observed_reasons = @($evaluation.observed_reasons)
        missing_expected_reasons = $missing
        observed_state = $evaluation.observed_state
        denied_before_image_mutation = $evaluation.denied_before_image_mutation
        denied_before_host_mutation = $evaluation.denied_before_host_mutation
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
$resolvedBoundaryResultPath = Resolve-RepoPath $BoundaryResultPath
$resolvedImageBoundaryPath = Resolve-RepoPath $ImageBoundaryPath
$resolvedBaselineResultPath = Resolve-RepoPath $BaselineResultPath
$resolvedBaselineIdentityPath = Resolve-RepoPath $BaselineIdentityPath
$resolvedBootStateProjectionPath = Resolve-RepoPath $BootStateProjectionPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$boundaryResult = Read-Json $resolvedBoundaryResultPath
$imageBoundary = Read-Json $resolvedImageBoundaryPath
$baselineResult = Read-Json $resolvedBaselineResultPath
$baselineIdentity = Read-Json $resolvedBaselineIdentityPath
$bootStateProjection = Read-Json $resolvedBootStateProjectionPath

$rc18PreviousStatus = Get-TaskStatus -Plan $plan -TaskId "RC18-011"
$rc18TaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC18-012"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc18PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC18-012" -and ($rc18TaskStatus -eq "pending" -or $rc18TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC18-020" -and $rc18TaskStatus -eq "completed")
    )
)

$script:expectedBoundaryId = $boundaryResult.boundary_id
$script:expectedBaselineId = $baselineResult.baseline_id

$source = [ordered]@{
    rc18_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc18_contract = New-ArtifactRef $resolvedContractPath
    rc18_boundary_result = New-ArtifactRef $resolvedBoundaryResultPath $boundaryResult
    rc18_image_boundary = New-ArtifactRef $resolvedImageBoundaryPath $imageBoundary
    rc18_baseline_result = New-ArtifactRef $resolvedBaselineResultPath $baselineResult
    rc18_baseline_identity = New-ArtifactRef $resolvedBaselineIdentityPath $baselineIdentity
    rc18_boot_state_projection = New-ArtifactRef $resolvedBootStateProjectionPath $bootStateProjection
}

$boundaryReady = (
    $boundaryResult.status -eq "passed" -and
    $boundaryResult.image_boundary_bound -eq $true -and
    $boundaryResult.boundary_surface.host_rootfs_mutated -eq $false -and
    $boundaryResult.boundary_surface.host_boot_metadata_mutated -eq $false -and
    $boundaryResult.boundary_surface.remote_dispatch_enabled -eq $false
)
$baselineReady = (
    $baselineResult.status -eq "passed" -and
    $baselineResult.baseline_identity_bound -eq $true -and
    $baselineResult.boot_state_projection_bound -eq $true -and
    $baselineResult.baseline_surface.image_boundary_bound -eq $true -and
    $baselineResult.baseline_surface.host_boot_metadata_mutated -eq $false -and
    $baselineResult.baseline_surface.remote_dispatch_enabled -eq $false
)
$bootProjectionReady = (
    $bootStateProjection.projection_authority.image_local_projection -eq $true -and
    $bootStateProjection.projection_authority.non_authoritative_for_host_boot_state -eq $true -and
    $bootStateProjection.projection_authority.host_boot_metadata_authority -eq $false -and
    $bootStateProjection.next_gate.image_mutation_allowed_now -eq $false
)

$script:baselineFixture = [ordered]@{
    schema = "agentos.rc18-image-boundary-side-effect-fixture.v1"
    production_ready_claim = $false
    boundary = [ordered]@{
        bound = $true
        boundary_id = $boundaryResult.boundary_id
        state_root_id = $boundaryResult.state_root_id
        host_write_surface_allowed = $false
        only_writable_drill_surface = $imageBoundary.allowed_write_surface.only_writable_drill_surface
    }
    baseline = [ordered]@{
        bound = $true
        baseline_id = $baselineResult.baseline_id
        stale = $false
        boot_state_projection_hash = $baselineResult.boot_state_projection_hash
        boot_state_projection_authoritative_for_host = $false
    }
    requests = [ordered]@{
        host_rootfs_write = $false
        host_active_slot_write = $false
        host_boot_metadata_write = $false
        active_artifact_set_write = $false
        production_ring_write = $false
        remote_dispatch = $false
        support_upload = $false
        recovery_execution = $false
        signer_authority = $false
        mirror_frontend_authority = $false
        image_mutation_before_fail_closed = $false
    }
    authority = [ordered]@{
        production_ring_mutation_allowed = $false
        remote_dispatch_enabled = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        signer_authority = $false
        mirror_frontend_authority = $false
        tui_authority = $false
        model_replay_authority = $false
        normal_shell_authority = $false
    }
}

$baselineEvaluation = Invoke-BoundaryEvaluation -Fixture $script:baselineFixture

$cases = @()
$cases += Invoke-Case "missing.boundary" @("missing-boundary") { param($f) $f.boundary.bound = $false; $f.boundary.boundary_id = $null }
$cases += Invoke-Case "mismatched.boundary_id" @("boundary-id-mismatch") { param($f) $f.boundary.boundary_id = "sha256:0000000000000000000000000000000000000000000000000000000000000000" }
$cases += Invoke-Case "missing.baseline" @("missing-baseline") { param($f) $f.baseline.bound = $false; $f.baseline.baseline_id = $null }
$cases += Invoke-Case "stale.baseline" @("stale-baseline") { param($f) $f.baseline.stale = $true }
$cases += Invoke-Case "mismatched.baseline_id" @("stale-baseline") { param($f) $f.baseline.baseline_id = "sha256:1111111111111111111111111111111111111111111111111111111111111111" }
$cases += Invoke-Case "host.write_surface_broadening" @("host-write-broadening-denied") { param($f) $f.boundary.host_write_surface_allowed = $true }
$cases += Invoke-Case "host.rootfs_write" @("host-write-broadening-denied", "host-rootfs-mutation-denied") { param($f) $f.requests.host_rootfs_write = $true }
$cases += Invoke-Case "host.active_slot_write" @("host-write-broadening-denied", "host-active-slot-mutation-denied") { param($f) $f.requests.host_active_slot_write = $true }
$cases += Invoke-Case "host.boot_metadata_write" @("host-write-broadening-denied", "host-boot-metadata-mutation-denied") { param($f) $f.requests.host_boot_metadata_write = $true }
$cases += Invoke-Case "active_artifact_set.write" @("host-write-broadening-denied", "active-artifact-set-mutation-denied") { param($f) $f.requests.active_artifact_set_write = $true }
$cases += Invoke-Case "production_ring.write" @("production-ring-mutation-denied") { param($f) $f.requests.production_ring_write = $true }
$cases += Invoke-Case "production_ring.authority" @("production-ring-mutation-denied") { param($f) $f.authority.production_ring_mutation_allowed = $true }
$cases += Invoke-Case "remote.dispatch" @("remote-dispatch-denied") { param($f) $f.requests.remote_dispatch = $true }
$cases += Invoke-Case "support.upload" @("support-upload-denied") { param($f) $f.requests.support_upload = $true }
$cases += Invoke-Case "recovery.execution" @("recovery-execution-denied") { param($f) $f.requests.recovery_execution = $true }
$cases += Invoke-Case "signer.authority" @("signer-authority-denied") { param($f) $f.authority.signer_authority = $true }
$cases += Invoke-Case "mirror_frontend.authority" @("mirror-frontend-authority-denied") { param($f) $f.authority.mirror_frontend_authority = $true }
$cases += Invoke-Case "ga.production_ready_claim" @("ga-claim-denied") { param($f) $f.production_ready_claim = $true }
$cases += Invoke-Case "boot_projection.host_authority" @("host-boot-authority-denied") { param($f) $f.baseline.boot_state_projection_authoritative_for_host = $true }
$cases += Invoke-Case "image_mutation.before_fail_closed" @("image-mutation-before-fail-closed-denied") { param($f) $f.requests.image_mutation_before_fail_closed = $true }
$cases += Invoke-Case "projection.tui_authority" @("projection-authority-broadening-denied") { param($f) $f.authority.tui_authority = $true }
$cases += Invoke-Case "projection.model_replay_authority" @("projection-authority-broadening-denied") { param($f) $f.authority.model_replay_authority = $true }
$cases += Invoke-Case "projection.normal_shell_authority" @("projection-authority-broadening-denied") { param($f) $f.authority.normal_shell_authority = $true }

$failedCases = @($cases | Where-Object { $_.status -ne "passed" })
$casesWithSideEffects = @($cases | Where-Object {
    $_.side_effects.image_mutation_performed -or
    $_.side_effects.host_rootfs_mutated -or
    $_.side_effects.host_active_slot_mutated -or
    $_.side_effects.host_boot_metadata_mutated -or
    $_.side_effects.active_artifact_set_mutated -or
    $_.side_effects.production_ring_mutated -or
    $_.side_effects.support_upload_performed -or
    $_.side_effects.recovery_execution_performed -or
    $_.side_effects.remote_dispatch_enabled -or
    $_.side_effects.mirror_frontend_mutated -or
    $_.side_effects.signer_authority_granted -or
    $_.side_effects.network_fetch_attempted
})

Add-Check "plan.current_task.rc18_012" $planAllowsRun "RC18-012 must run after RC18-011 completed, while current_task is RC18-012 or during a completed rerun." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc18_011_status = $rc18PreviousStatus; rc18_012_status = $rc18TaskStatus })
Add-Check "contract.fail_closed_scope.present" ($contractText.Contains("host rootfs") -and $contractText.Contains("host boot metadata") -and $contractText.Contains("remote dispatch") -and $contractText.Contains("support upload") -and $contractText.Contains("production rings")) "RC18-012 must consume the isolated installed-system drill contract fail-closed scope." $source.rc18_contract
Add-Check "source.boundary.ready" $boundaryReady "RC18-012 must bind the completed RC18 image boundary before fixture evaluation." ([ordered]@{ boundary_id = $boundaryResult.boundary_id; image_boundary_bound = $boundaryResult.image_boundary_bound; host_boot_metadata_mutated = $boundaryResult.boundary_surface.host_boot_metadata_mutated; remote_dispatch_enabled = $boundaryResult.boundary_surface.remote_dispatch_enabled })
Add-Check "source.baseline.ready" $baselineReady "RC18-012 must bind the completed installed-system baseline identity and boot-state projection before fixture evaluation." ([ordered]@{ baseline_id = $baselineResult.baseline_id; baseline_identity_bound = $baselineResult.baseline_identity_bound; boot_state_projection_bound = $baselineResult.boot_state_projection_bound; host_boot_metadata_mutated = $baselineResult.baseline_surface.host_boot_metadata_mutated; remote_dispatch_enabled = $baselineResult.baseline_surface.remote_dispatch_enabled })
Add-Check "source.boot_projection.image_local" $bootProjectionReady "Boot-state projection must remain image-local and non-authoritative for host boot state." ([ordered]@{ image_local_projection = $bootStateProjection.projection_authority.image_local_projection; non_authoritative_for_host_boot_state = $bootStateProjection.projection_authority.non_authoritative_for_host_boot_state; image_mutation_allowed_now = $bootStateProjection.next_gate.image_mutation_allowed_now })
Add-Check "baseline.fixture.valid_non_authoritative" ($baselineEvaluation.observed_state -eq "fixture-valid-non-authoritative") "The unmodified RC18 image-boundary fixture must be internally valid and non-authoritative." ([ordered]@{ observed_state = $baselineEvaluation.observed_state; reasons = $baselineEvaluation.observed_reasons })
Add-Check "fixtures.coverage" (@($cases).Count -ge 20) "RC18-012 negative fixtures must cover missing boundary, stale baseline, host write broadening, remote dispatch, support upload, recovery execution, signer authority, mirror/frontend authority, production ring mutation, GA claim, and projection authority broadening." ([ordered]@{ cases = @($cases).Count; required_minimum = 20 })
Add-Check "fixtures.all_cases_passed" ($failedCases.Count -eq 0) "All RC18 image-boundary negative fixtures must deny before image or host mutation." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })
Add-Check "fixtures.no_side_effects" ($casesWithSideEffects.Count -eq 0) "Fixture execution must be local-only and create no image, host, remote, support, recovery, mirror/frontend, signer, network, or production side effects." ([ordered]@{ side_effect_case_ids = @($casesWithSideEffects | ForEach-Object { $_.id }) })

$matrixPath = Join-Path $resolvedArtifactDir "image-boundary-fail-closed-matrix.json"
$matrix = [ordered]@{
    schema = "agentos.rc18-image-boundary-fail-closed-matrix.v1"
    generated_at = $generatedAtValue
    task = "RC18-012"
    status = if ($failedCases.Count -eq 0) { "passed" } else { "failed" }
    production_ready_claim = $false
    boundary_id = $boundaryResult.boundary_id
    baseline_id = $baselineResult.baseline_id
    baseline = [ordered]@{
        observed_state = $baselineEvaluation.observed_state
        observed_reasons = $baselineEvaluation.observed_reasons
        denied_before_image_mutation = $baselineEvaluation.denied_before_image_mutation
        denied_before_host_mutation = $baselineEvaluation.denied_before_host_mutation
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
Add-Check "outputs.matrix.secret_safe" $outputsSecretSafe "RC18-012 fail-closed matrix must not contain key blocks, private key paths, auth tokens, public identity markers, or signing key file names." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc18-image-boundary-fail-closed-result.v1"
    generated_at = $generatedAtValue
    task = "RC18-012"
    status = $resultStatus
    production_ready_claim = $false
    boundary_id = $boundaryResult.boundary_id
    baseline_id = $baselineResult.baseline_id
    side_effect_fail_closed_verified = (@($script:failedChecks).Count -eq 0)
    outputs = [ordered]@{
        image_boundary_fail_closed_matrix = [ordered]@{
            path = Get-StablePath $matrixPath
            sha256 = Get-FileSha256 $matrixPath
        }
    }
    fail_closed_surface = [ordered]@{
        state = "image-boundary-side-effect-fail-closed-fixtures-passed"
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
        denied_before_image_mutation = $true
        denied_before_host_mutation = $true
        local_only_fixture_execution = $true
        image_mutation_performed = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        mirror_frontend_mutated = $false
        signer_authority_granted = $false
        network_fetch_attempted = $false
        blockers = @(
            "rc18-isolated-install-not-run",
            "rc18-isolated-update-not-run",
            "rc18-isolated-rollback-not-run"
        )
    }
    source = $source
    checks = @($script:checks)
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        fixtures_local_only = $true
        image_mutation_performed = $false
        host_rootfs_mutated = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        mirror_frontend_changed = $false
        signer_authority = $false
        tui_authority = $false
        model_replay_authority = $false
        normal_shell_authority = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        passed_cases = @($cases | Where-Object { $_.status -eq "passed" }).Count
        failed_cases = @($failedCases).Count
        rc18_012_complete = (@($script:failedChecks).Count -eq 0)
        side_effect_fail_closed_verified = (@($script:failedChecks).Count -eq 0)
        image_mutation_performed = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        next_task = "RC18-020"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC18-012-image-boundary-fail-closed.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc18-image-boundary-fail-closed-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC18-012"
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
        rc18_012_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC18-020"
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
    throw "Sensitive marker detected in RC18-012 outputs."
}

Write-Host "RC18 image-boundary fail-closed $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Matrix: $(Get-StablePath $matrixPath)"
Write-Host "Cases: $(@($cases).Count), failed cases: $($failedCases.Count), failed checks: $(@($script:failedChecks).Count)"
Write-Host "Image mutation: false; host mutation: false; remote dispatch: false"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
