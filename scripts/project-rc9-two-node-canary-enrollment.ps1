param(
    [string]$ArtifactDir = ".workflow/artifacts/rc9-two-node-canary-enrollment",
    [string]$GeneratedAt = "",
    [string]$BindingContractPath = ".workflow/active/WFS-20260608-agentos-production-distro-rc9/docs/controlled-execution-binding-contract.md",
    [string]$PublicationResultPath = ".workflow/artifacts/rc9-external-object-publication/result.json",
    [string]$DriftResultPath = ".workflow/artifacts/rc9-artifact-drift-reconciliation/result.json",
    [string]$InstallerFetchResultPath = ".workflow/artifacts/rc9-external-object-installer-fetch/result.json",
    [string]$Rc8CanaryResultPath = ".workflow/artifacts/rc8-exact-approved-canary-smoke/result.json",
    [string]$Rc8CanaryTargetSetPath = ".workflow/artifacts/rc8-exact-approved-canary-smoke/canary-target-set.json",
    [string]$Rc8RollbackResultPath = ".workflow/artifacts/rc8-controlled-rollback-drill/result.json",
    [string]$DescriptorPath = ".workflow/artifacts/rc8-real-payload-object-descriptor/payload-object-descriptor.json",
    [string]$CompatibilityPath = ".workflow/artifacts/rc7-install-rollback-baseline/compatibility.json",
    [string]$RollbackBaselinePath = ".workflow/artifacts/rc7-install-rollback-baseline/rollback-baseline.json",
    [string]$SupportRecoveryPath = ".workflow/artifacts/rc5-hosted-support-recovery/support-index.json",
    [string]$FleetAuthorityPath = ".workflow/artifacts/release/fleet-rollout-authority.json",
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

function Add-Check {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][bool]$Passed,
        [Parameter(Mandatory = $true)][string]$Message,
        $Evidence = $null
    )
    $script:checks += [ordered]@{
        id = $Id
        status = if ($Passed) { "passed" } else { "failed" }
        severity = "blocking"
        message = $Message
        evidence = $Evidence
    }
}

function New-ArtifactRef {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        $Json = $null
    )
    return [ordered]@{
        path = Get-StablePath $Path
        sha256 = Get-FileSha256 $Path
        size_bytes = if (Test-Path -LiteralPath $Path -PathType Leaf) { (Get-Item -LiteralPath $Path).Length } else { $null }
        present = Test-Path -LiteralPath $Path -PathType Leaf
        schema = if ($null -ne $Json) { $Json.schema } else { $null }
        status = if ($null -ne $Json) { $Json.status } else { $null }
    }
}

function Test-NoSensitiveText {
    param([Parameter(Mandatory = $true)][string[]]$Values)
    $privateKeyMarker = "PRIVATE" + " KEY"
    $markers = @(
        ("BEGIN " + $privateKeyMarker),
        ($privateKeyMarker + "-----"),
        ("Authorization:" + " Bearer"),
        ("Bearer" + " "),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ("." + "local-release-authority"),
        ("signing" + "-key.pem"),
        ("/etc/" + "aios-signer")
    )
    foreach ($value in $Values) {
        if ($null -eq $value) {
            continue
        }
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

function Add-UniqueBlocker {
    param([Parameter(Mandatory = $true)][string]$Blocker)
    if ($script:blockers -notcontains $Blocker) {
        $script:blockers += $Blocker
    }
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:blockers = @()

$generatedAt = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }
$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null

$resolvedBindingContractPath = Resolve-RepoPath $BindingContractPath
$resolvedPublicationResultPath = Resolve-RepoPath $PublicationResultPath
$resolvedDriftResultPath = Resolve-RepoPath $DriftResultPath
$resolvedInstallerFetchResultPath = Resolve-RepoPath $InstallerFetchResultPath
$resolvedRc8CanaryResultPath = Resolve-RepoPath $Rc8CanaryResultPath
$resolvedRc8CanaryTargetSetPath = Resolve-RepoPath $Rc8CanaryTargetSetPath
$resolvedRc8RollbackResultPath = Resolve-RepoPath $Rc8RollbackResultPath
$resolvedDescriptorPath = Resolve-RepoPath $DescriptorPath
$resolvedCompatibilityPath = Resolve-RepoPath $CompatibilityPath
$resolvedRollbackBaselinePath = Resolve-RepoPath $RollbackBaselinePath
$resolvedSupportRecoveryPath = Resolve-RepoPath $SupportRecoveryPath
$resolvedFleetAuthorityPath = Resolve-RepoPath $FleetAuthorityPath

$publicationResult = Read-Json $resolvedPublicationResultPath
$driftResult = Read-Json $resolvedDriftResultPath
$installerFetchResult = Read-Json $resolvedInstallerFetchResultPath
$rc8CanaryResult = Read-Json $resolvedRc8CanaryResultPath
$rc8CanaryTargetSet = Read-Json $resolvedRc8CanaryTargetSetPath
$rc8RollbackResult = Read-Json $resolvedRc8RollbackResultPath
$descriptor = Read-Json $resolvedDescriptorPath
$compatibility = Read-Json $resolvedCompatibilityPath
$rollbackBaseline = Read-Json $resolvedRollbackBaselinePath
$supportRecovery = Read-Json $resolvedSupportRecoveryPath
$fleetAuthority = Read-Json $resolvedFleetAuthorityPath

$releaseId = [string]$descriptor.release_id
$descriptorSha256 = Get-FileSha256 $resolvedDescriptorPath
$compatibilitySha256 = Get-FileSha256 $resolvedCompatibilityPath
$rollbackBaselineSha256 = Get-FileSha256 $resolvedRollbackBaselinePath
$supportRecoverySha256 = Get-FileSha256 $resolvedSupportRecoveryPath
$canaryRing = Get-Ring $fleetAuthority "canary"

$requiredMinimumTargets = 2
$observedCandidateNodes = [int]$rc8CanaryTargetSet.observed_canary_node_count
if ($observedCandidateNodes -le 0 -and $null -ne $canaryRing -and $null -ne $canaryRing.node_count) {
    $observedCandidateNodes = [int]$canaryRing.node_count
}
$inheritedEnrolledTargets = [int]$rc8CanaryTargetSet.enrolled_target_count
$enrolledTargetCount = 0

$publicationReady = $publicationResult.status -eq "passed" -and $publicationResult.publication_surface.external_object_url_published -eq $true
$driftReady = $driftResult.status -eq "passed" -and $driftResult.reconciliation_surface.state -eq "reconciled-current-artifact"
$fetchReady = $installerFetchResult.status -eq "passed" -and $installerFetchResult.fetch_surface.fetch_allowed -eq $true
$rc8TargetProjectedDenied = $rc8CanaryResult.status -eq "passed" -and $rc8CanaryResult.target_set.target_set_enrolled -eq $false
$compatibilityBindingPresent = -not [string]::IsNullOrWhiteSpace($compatibilitySha256)
$rollbackBindingPresent = -not [string]::IsNullOrWhiteSpace($rollbackBaselineSha256)
$supportRecoveryBindingPresent = -not [string]::IsNullOrWhiteSpace($supportRecoverySha256)
$remoteFleetEnabled = $false
if ($null -ne $canaryRing -and $null -ne $canaryRing.rollout_dispatch_enabled_in_tui) {
    $remoteFleetEnabled = [bool]$canaryRing.rollout_dispatch_enabled_in_tui
}

if ($observedCandidateNodes -lt $requiredMinimumTargets -or $enrolledTargetCount -lt $requiredMinimumTargets) {
    Add-UniqueBlocker "two-or-more-enrolled-canary-target-nodes-required"
}
if ($enrolledTargetCount -lt $requiredMinimumTargets) {
    Add-UniqueBlocker "target-set-not-enrolled"
}
if (-not $remoteFleetEnabled) {
    Add-UniqueBlocker "remote-fleet-execution-not-enabled"
}
Add-UniqueBlocker "exact-operator-approval-pending"
if (-not $publicationReady) {
    Add-UniqueBlocker "external-https-object-uri-not-published"
}
if (-not $driftReady) {
    Add-UniqueBlocker "declared-current-artifact-drift-denied"
}
if (-not $fetchReady) {
    Add-UniqueBlocker "installer-quarantine-fetch-not-run"
}

$orderedTargets = @(
    [ordered]@{
        slot = "canary-a"
        required = $true
        enrollment_state = "missing"
        node_id = $null
        target_role = "canary"
        current_active_artifact_set_digest = $null
        expected_release_id = $releaseId
        expected_payload_object_digest = [string]$descriptor.sha256
        expected_descriptor_digest = $descriptorSha256
        compatibility_result_digest = $compatibilitySha256
        rollback_baseline_digest = $rollbackBaselineSha256
        support_recovery_reference_digest = $supportRecoverySha256
        audit_journal_sink = $null
        health_evidence_digest = $null
        node_uniqueness_proof = $null
        enrollment_freshness_window = $null
        policy_version = "rc9-controlled-execution-binding-v1"
        denial_reasons = @("target-enrollment-record-missing")
    },
    [ordered]@{
        slot = "canary-b"
        required = $true
        enrollment_state = "missing"
        node_id = $null
        target_role = "canary"
        current_active_artifact_set_digest = $null
        expected_release_id = $releaseId
        expected_payload_object_digest = [string]$descriptor.sha256
        expected_descriptor_digest = $descriptorSha256
        compatibility_result_digest = $compatibilitySha256
        rollback_baseline_digest = $rollbackBaselineSha256
        support_recovery_reference_digest = $supportRecoverySha256
        audit_journal_sink = $null
        health_evidence_digest = $null
        node_uniqueness_proof = $null
        enrollment_freshness_window = $null
        policy_version = "rc9-controlled-execution-binding-v1"
        denial_reasons = @("target-enrollment-record-missing")
    }
)
$targetListDigest = Get-StringSha256 (($orderedTargets | ConvertTo-Json -Depth 100 -Compress))

$targetSetEnrolled = $false
$targetSet = [ordered]@{
    schema = "agentos.rc9-canary-target-set.v1"
    generated_at = $generatedAt
    task = "RC9-020"
    status = "target-set-enrollment-denied"
    production_ready_claim = $false
    release_id = $releaseId
    object_id = [string]$descriptor.object_id
    object_sha256 = [string]$descriptor.sha256
    object_descriptor_sha256 = $descriptorSha256
    ring = "canary"
    required_minimum_target_count = $requiredMinimumTargets
    observed_candidate_node_count = $observedCandidateNodes
    inherited_rc8_enrolled_target_count = $inheritedEnrolledTargets
    enrolled_target_count = $enrolledTargetCount
    target_set_enrolled = $targetSetEnrolled
    target_selection_policy = "two-or-more-enrolled-compatible-canary-targets-required-before-controlled-execution"
    target_set_digest = $targetListDigest
    duplicate_node_check = [ordered]@{
        duplicate_node_ids_detected = $false
        evaluated_enrolled_node_count = $enrolledTargetCount
    }
    stale_node_check = [ordered]@{
        stale_enrollment_detected = $false
        evaluated_enrolled_node_count = $enrolledTargetCount
    }
    compatibility_summary = [ordered]@{
        binding_present = $compatibilityBindingPresent
        compatibility_digest = $compatibilitySha256
        compatibility_status = [string]$compatibility.status
        compatibility_release_id = [string]$compatibility.release_id
        authorizes_enrollment = $false
        denial_reason = "target-records-missing-and-rc9-drift-denied"
    }
    rollback_readiness_summary = [ordered]@{
        binding_present = $rollbackBindingPresent
        rollback_baseline_digest = $rollbackBaselineSha256
        rollback_baseline_status = [string]$rollbackBaseline.status
        rollback_execution_allowed = $false
        authorizes_enrollment = $false
        denial_reason = "target-records-missing-and-activation-not-authorized"
    }
    support_recovery_summary = [ordered]@{
        binding_present = $supportRecoveryBindingPresent
        support_recovery_digest = $supportRecoverySha256
        support_recovery_status = [string]$supportRecovery.status
        support_upload_allowed = $false
    }
    ordered_targets = $orderedTargets
    denial_reasons = $script:blockers
    authority = [ordered]@{
        plan_authority = "AgentCore"
        side_effect_authority = "SecurityExecutionEngine"
        mirror_authority = $false
        object_storage_authority = $false
        signer_authority = $false
        frontend_authority = $false
        tui_authority = $false
        shell_authority = $false
        model_replay_authority = $false
    }
}

$denial = [ordered]@{
    schema = "agentos.rc9-target-enrollment-denial.v1"
    generated_at = $generatedAt
    task = "RC9-020"
    status = "target-set-enrollment-denied"
    production_ready_claim = $false
    denied = $true
    release_id = $releaseId
    target_set_digest = $targetListDigest
    observed_candidate_node_count = $observedCandidateNodes
    required_minimum_target_count = $requiredMinimumTargets
    enrolled_target_count = $enrolledTargetCount
    denial_reasons = $script:blockers
    inherited_rc8_target_set = [ordered]@{
        path = Get-StablePath $resolvedRc8CanaryTargetSetPath
        sha256 = Get-FileSha256 $resolvedRc8CanaryTargetSetPath
        status = [string]$rc8CanaryTargetSet.status
        target_set_enrolled = [bool]$rc8CanaryTargetSet.target_set_enrolled
        observed_canary_node_count = [int]$rc8CanaryTargetSet.observed_canary_node_count
        enrolled_target_count = [int]$rc8CanaryTargetSet.enrolled_target_count
    }
    missing_bindings = @(
        "stable-node-id",
        "node-health-evidence-digest",
        "node-uniqueness-proof",
        "audit-journal-sink",
        "fresh-enrollment-window"
    )
    preserved_boundaries = [ordered]@{
        target_set_enrolled = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        production_ring_mutation_allowed = $false
        remote_dispatch_enabled = $false
    }
}

$handoff = [ordered]@{
    schema = "agentos.rc9-controlled-execution-handoff.v1"
    generated_at = $generatedAt
    task = "RC9-020"
    status = "blocked-by-target-set-denial"
    production_ready_claim = $false
    release_id = $releaseId
    target_set = [ordered]@{
        path = ".workflow/artifacts/rc9-two-node-canary-enrollment/canary-target-set.json"
        digest = $targetListDigest
        state = "target-set-enrollment-denied"
        enrolled = $false
        required_minimum_target_count = $requiredMinimumTargets
        observed_candidate_node_count = $observedCandidateNodes
        enrolled_target_count = $enrolledTargetCount
    }
    upstream_gates = [ordered]@{
        external_object_url_published = $publicationReady
        declared_current_artifact_drift_reconciled = $driftReady
        installer_quarantine_fetch_verified = $fetchReady
        rc8_canary_target_set_inherited = $rc8TargetProjectedDenied
        compatibility_binding_present = $compatibilityBindingPresent
        rollback_baseline_binding_present = $rollbackBindingPresent
        support_recovery_binding_present = $supportRecoveryBindingPresent
    }
    controlled_execution = [ordered]@{
        exact_approval_allowed = $false
        agentcore_planspec_allowed = $false
        security_execution_approval_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        remote_dispatch_enabled = $false
    }
    blockers = $script:blockers
    next_task = "RC9-021"
}

$targetSetPath = Join-Path $resolvedArtifactDir "canary-target-set.json"
$denialPath = Join-Path $resolvedArtifactDir "target-enrollment-denial.json"
$handoffPath = Join-Path $resolvedArtifactDir "controlled-execution-handoff.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"

Write-Json $targetSet $targetSetPath
Write-Json $denial $denialPath
Write-Json $handoff $handoffPath

Add-Check "source.rc9_010.publication" ($publicationResult.status -eq "passed" -and $publicationResult.summary.rc9_010_complete -eq $true) "RC9-010 publication evidence must pass before target enrollment evaluation." ([ordered]@{ status = $publicationResult.status; state = $publicationResult.publication_surface.state })
Add-Check "source.rc9_011.drift" ($driftResult.status -eq "passed" -and $driftResult.summary.rc9_011_complete -eq $true) "RC9-011 drift reconciliation evidence must pass before target enrollment evaluation." ([ordered]@{ status = $driftResult.status; state = $driftResult.reconciliation_surface.state; drift_count = $driftResult.reconciliation_surface.drift_count })
Add-Check "source.rc9_012.fetch" ($installerFetchResult.status -eq "passed" -and $installerFetchResult.summary.rc9_012_complete -eq $true) "RC9-012 installer fetch evidence must pass before target enrollment evaluation." ([ordered]@{ status = $installerFetchResult.status; state = $installerFetchResult.fetch_surface.state; fetch_allowed = $installerFetchResult.fetch_surface.fetch_allowed })
Add-Check "source.rc8.target_set_under_enrolled" $rc8TargetProjectedDenied "Inherited RC8 canary target set must remain projected and under-enrolled instead of being treated as real enrollment." ([ordered]@{ observed = $observedCandidateNodes; required = $requiredMinimumTargets; inherited_enrolled = $inheritedEnrolledTargets })
Add-Check "bindings.compatibility_and_rollback_present" ($compatibilityBindingPresent -and $rollbackBindingPresent -and $supportRecoveryBindingPresent) "Target enrollment denial must still bind compatibility, rollback baseline, and support/recovery references for downstream exact approval denial." ([ordered]@{ compatibility = $compatibilitySha256; rollback_baseline = $rollbackBaselineSha256; support_recovery = $supportRecoverySha256 })
Add-Check "target_set.denied_not_enrolled" ($targetSet.status -eq "target-set-enrollment-denied" -and $targetSet.target_set_enrolled -eq $false -and $targetSet.enrolled_target_count -eq 0) "RC9-020 must deny target enrollment when two enrolled canary targets are unavailable." ([ordered]@{ state = $targetSet.status; observed = $observedCandidateNodes; enrolled = $enrolledTargetCount; required = $requiredMinimumTargets; blockers = $script:blockers })
Add-Check "execution.side_effects_blocked" ($handoff.controlled_execution.activation_allowed -eq $false -and $handoff.controlled_execution.rollback_execution_allowed -eq $false -and $handoff.controlled_execution.remote_dispatch_enabled -eq $false) "Target enrollment must not authorize activation, rollback, support upload, production ring mutation, or remote dispatch." $handoff.controlled_execution

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $targetSetPath),
    (Get-Content -Raw -LiteralPath $denialPath),
    (Get-Content -Raw -LiteralPath $handoffPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC9-020 outputs must not contain secret paths, PEM blocks, auth tokens, or signer host internals." $null

$source = [ordered]@{
    binding_contract = New-ArtifactRef $resolvedBindingContractPath
    publication_result = New-ArtifactRef $resolvedPublicationResultPath $publicationResult
    drift_result = New-ArtifactRef $resolvedDriftResultPath $driftResult
    installer_fetch_result = New-ArtifactRef $resolvedInstallerFetchResultPath $installerFetchResult
    rc8_canary_result = New-ArtifactRef $resolvedRc8CanaryResultPath $rc8CanaryResult
    rc8_canary_target_set = New-ArtifactRef $resolvedRc8CanaryTargetSetPath $rc8CanaryTargetSet
    rc8_rollback_result = New-ArtifactRef $resolvedRc8RollbackResultPath $rc8RollbackResult
    descriptor = New-ArtifactRef $resolvedDescriptorPath $descriptor
    compatibility = New-ArtifactRef $resolvedCompatibilityPath $compatibility
    rollback_baseline = New-ArtifactRef $resolvedRollbackBaselinePath $rollbackBaseline
    support_recovery = New-ArtifactRef $resolvedSupportRecoveryPath $supportRecovery
    fleet_authority = New-ArtifactRef $resolvedFleetAuthorityPath $fleetAuthority
}

$failedChecks = @($script:checks | Where-Object { $_.status -ne "passed" })
$result = [ordered]@{
    schema = "agentos.rc9-two-node-canary-enrollment-result.v1"
    generated_at = $generatedAt
    task = "RC9-020"
    status = if ($failedChecks.Count -eq 0) { "passed" } else { "failed" }
    production_ready_claim = $false
    release_id = $releaseId
    enrollment_surface = [ordered]@{
        state = "target-set-enrollment-denied"
        required_minimum_target_count = $requiredMinimumTargets
        observed_candidate_node_count = $observedCandidateNodes
        inherited_rc8_enrolled_target_count = $inheritedEnrolledTargets
        enrolled_target_count = $enrolledTargetCount
        target_set_enrolled = $false
        compatibility_binding_present = $compatibilityBindingPresent
        rollback_baseline_binding_present = $rollbackBindingPresent
        support_recovery_binding_present = $supportRecoveryBindingPresent
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        remote_dispatch_enabled = $false
        blockers = $script:blockers
    }
    outputs = [ordered]@{
        canary_target_set = [ordered]@{
            path = Get-StablePath $targetSetPath
            sha256 = Get-FileSha256 $targetSetPath
        }
        target_enrollment_denial = [ordered]@{
            path = Get-StablePath $denialPath
            sha256 = Get-FileSha256 $denialPath
        }
        controlled_execution_handoff = [ordered]@{
            path = Get-StablePath $handoffPath
            sha256 = Get-FileSha256 $handoffPath
        }
    }
    source = $source
    checks = $script:checks
    blockers = $script:blockers
    invariants = [ordered]@{
        local_projection_only = $true
        target_enrollment_fabricated = $false
        external_payload_bytes_uploaded = $false
        network_fetch_attempted = $false
        quarantine_payload_written = $false
        payload_interpreted = $false
        cryptographic_signing_performed = $false
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
        mirror_authority = $false
        signer_authority = $false
        production_ready_claim = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = $failedChecks.Count
        rc9_020_complete = ($failedChecks.Count -eq 0)
        target_set_state = "target-set-enrollment-denied"
        target_set_enrolled = $false
        required_minimum_target_count = $requiredMinimumTargets
        observed_candidate_node_count = $observedCandidateNodes
        enrolled_target_count = $enrolledTargetCount
        activation_allowed = $false
        rollback_execution_allowed = $false
        remote_dispatch_enabled = $false
        next_task = "RC9-021"
    }
}

Write-Json $result $resultPath

if (-not (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath)))) {
    throw "Sensitive marker detected in RC9-020 result."
}

Write-Host "RC9 two-node canary enrollment $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Target set state: $($targetSet.status)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $($failedChecks.Count), blockers: $(@($script:blockers).Count)"

if ($FailOnFailedChecks -and $failedChecks.Count -gt 0) {
    exit 1
}
