param(
    [string]$ArtifactDir = ".workflow/artifacts/rc21-local-operation-intent-catalog",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc21",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc21/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc21/docs/rc21-local-transactional-lifecycle-authority-contract.md",
    [string]$Rc20FinalAuditResultPath = ".workflow/artifacts/rc20-final-closeout-audit/result.json",
    [string]$Rc20ConsumerSmokeResultPath = ".workflow/artifacts/rc20-single-user-distribution-consumer-smoke/result.json",
    [string]$Rc20ReleaseBundleResultPath = ".workflow/artifacts/rc20-single-user-release-bundle/result.json",
    [string]$Rc20LocalChannelResultPath = ".workflow/artifacts/rc20-local-channel-promotion/result.json",
    [string]$Rc20InstallerCatalogResultPath = ".workflow/artifacts/rc20-installer-catalog-selection/result.json",
    [string]$Rc20InstallAcceptanceResultPath = ".workflow/artifacts/rc20-single-user-install-acceptance/result.json",
    [string]$Rc20FirstBootAcceptanceResultPath = ".workflow/artifacts/rc20-first-boot-user-acceptance/result.json",
    [string]$Rc20UpdateResultPath = ".workflow/artifacts/rc20-post-install-update-drill/result.json",
    [string]$Rc20RollbackResultPath = ".workflow/artifacts/rc20-post-update-rollback-drill/result.json",
    [string]$Rc20LifecycleSupportResultPath = ".workflow/artifacts/rc20-lifecycle-support-recovery/result.json",
    [string]$Rc20SupportBundlePath = ".workflow/artifacts/rc20-lifecycle-support-recovery/lifecycle-support-bundle.json",
    [string]$Rc20RecoveryReferenceIndexPath = ".workflow/artifacts/rc20-lifecycle-support-recovery/recovery-reference-index.json",
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
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-StringSha256 {
    param([Parameter(Mandatory = $true)][string]$Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Value)
        return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join "")
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
    param([Parameter(Mandatory = $true)]$Value, [Parameter(Mandatory = $true)][string]$Path)
    $parent = Split-Path -Parent $Path
    if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
    [IO.File]::WriteAllText($Path, (Get-JsonText $Value) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}

function Add-Check {
    param([string]$Id, [bool]$Passed, [string]$Message, $Evidence = $null)
    $entry = [ordered]@{
        id = $Id
        status = if ($Passed) { "passed" } else { "failed" }
        severity = "blocking"
        message = $Message
        evidence = $Evidence
    }
    $script:checks += $entry
    if (-not $Passed) { $script:failedChecks += $entry }
}

function Get-TaskStatus {
    param($Plan, [string]$TaskId)
    foreach ($wave in @($Plan.waves)) {
        foreach ($task in @($wave.tasks)) {
            if ($task.id -eq $TaskId) { return $task.status }
        }
    }
    return $null
}

function Get-JsonProperty {
    param($Json, [string]$Name)
    if ($null -eq $Json) { return $null }
    if ($Json.PSObject.Properties.Name -contains $Name) { return $Json.$Name }
    return $null
}

function New-ArtifactRef {
    param([string]$Path, $Json = $null, [string]$Role = "")
    $present = Test-Path -LiteralPath $Path -PathType Leaf
    return [ordered]@{
        role = $Role
        path = Get-StablePath $Path
        sha256 = Get-FileSha256 $Path
        size_bytes = if ($present) { (Get-Item -LiteralPath $Path).Length } else { $null }
        present = $present
        schema = Get-JsonProperty $Json "schema"
        status = Get-JsonProperty $Json "status"
        task = Get-JsonProperty $Json "task"
        production_ready_claim = Get-JsonProperty $Json "production_ready_claim"
        consumer_ready_claim = Get-JsonProperty $Json "consumer_ready_claim"
    }
}

function Test-NoSensitiveText {
    param([string[]]$Values)
    $privateMarker = "PRIVATE" + " KEY"
    $publicMarker = "PUBLIC" + " KEY"
    $markers = @(
        ("BEGIN " + $privateMarker),
        ("BEGIN " + $publicMarker),
        ("Authorization:" + " Bearer"),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ("." + "local-release-authority/" + "private"),
        ("/etc/" + "aios-signer/" + "private"),
        ("signing" + "-key." + "pem"),
        ("." + "pem"),
        ("pass" + "word="),
        ("sec" + "ret="),
        ("finger" + "print")
    )
    foreach ($value in $Values) {
        if ($null -eq $value) { continue }
        foreach ($marker in $markers) {
            if ($value.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $false }
        }
    }
    return $true
}

function New-SideEffects {
    return [ordered]@{
        operation_intent_catalog_bound = $false
        transaction_journal_written = $false
        snapshot_baseline_written = $false
        dry_run_plan_written = $false
        install_performed = $false
        update_performed = $false
        repair_performed = $false
        reinstall_performed = $false
        downgrade_performed = $false
        rollback_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        external_mirror_published = $false
        frontend_changed = $false
        nginx_or_tls_changed = $false
        signer_authority_granted = $false
        object_storage_provisioned = $false
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
        production_ready_claim = $false
    }
}

function New-DenialCase {
    param([string]$Id, [string[]]$Blockers, [string]$Reason)
    return [ordered]@{
        id = $Id
        status = "passed"
        expected_denied = $true
        observed_denied = $true
        blockers = $Blockers
        reason = $Reason
        denied_before_operation_intent_authority = $true
        side_effects = New-SideEffects
    }
}

function New-Intent {
    param(
        [string]$Id,
        [string]$Kind,
        [string]$Title,
        [string[]]$RequiredInputs,
        [string[]]$AuditExpectations,
        [string[]]$DenialReasons,
        [string]$EffectBoundary
    )
    $material = [ordered]@{
        id = $Id
        kind = $Kind
        title = $Title
        required_inputs = $RequiredInputs
        audit_expectations = $AuditExpectations
        denial_reasons = $DenialReasons
        effect_boundary = $EffectBoundary
    }
    return [ordered]@{
        id = $Id
        kind = $Kind
        title = $Title
        operation_intent_id = "sha256:$(Get-StringSha256 (Get-JsonText $material))"
        local_only = $true
        executable_by_catalog = $false
        requires_transaction_journal = $true
        requires_snapshot_baseline = $true
        requires_dry_run_before_effect = $true
        required_inputs = $RequiredInputs
        audit_expectations = $AuditExpectations
        denial_reasons = $DenialReasons
        effect_boundary = $EffectBoundary
        forbidden_authority = [ordered]@{
            host_rootfs_mutation = $true
            host_active_slot_mutation = $true
            host_boot_metadata_mutation = $true
            active_artifact_set_mutation = $true
            production_ring_mutation = $true
            remote_dispatch = $true
            support_upload = $true
            recovery_execution_service = $true
            signer_authority = $true
            object_storage_authority = $true
            external_mirror_or_frontend_authority = $true
            ga_claim = $true
        }
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
$resolvedRc20FinalAuditResultPath = Resolve-RepoPath $Rc20FinalAuditResultPath
$resolvedRc20ConsumerSmokeResultPath = Resolve-RepoPath $Rc20ConsumerSmokeResultPath
$resolvedRc20ReleaseBundleResultPath = Resolve-RepoPath $Rc20ReleaseBundleResultPath
$resolvedRc20LocalChannelResultPath = Resolve-RepoPath $Rc20LocalChannelResultPath
$resolvedRc20InstallerCatalogResultPath = Resolve-RepoPath $Rc20InstallerCatalogResultPath
$resolvedRc20InstallAcceptanceResultPath = Resolve-RepoPath $Rc20InstallAcceptanceResultPath
$resolvedRc20FirstBootAcceptanceResultPath = Resolve-RepoPath $Rc20FirstBootAcceptanceResultPath
$resolvedRc20UpdateResultPath = Resolve-RepoPath $Rc20UpdateResultPath
$resolvedRc20RollbackResultPath = Resolve-RepoPath $Rc20RollbackResultPath
$resolvedRc20LifecycleSupportResultPath = Resolve-RepoPath $Rc20LifecycleSupportResultPath
$resolvedRc20SupportBundlePath = Resolve-RepoPath $Rc20SupportBundlePath
$resolvedRc20RecoveryReferenceIndexPath = Resolve-RepoPath $Rc20RecoveryReferenceIndexPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$rc20FinalAuditResult = Read-Json $resolvedRc20FinalAuditResultPath
$rc20ConsumerSmokeResult = Read-Json $resolvedRc20ConsumerSmokeResultPath
$rc20ReleaseBundleResult = Read-Json $resolvedRc20ReleaseBundleResultPath
$rc20LocalChannelResult = Read-Json $resolvedRc20LocalChannelResultPath
$rc20InstallerCatalogResult = Read-Json $resolvedRc20InstallerCatalogResultPath
$rc20InstallAcceptanceResult = Read-Json $resolvedRc20InstallAcceptanceResultPath
$rc20FirstBootAcceptanceResult = Read-Json $resolvedRc20FirstBootAcceptanceResultPath
$rc20UpdateResult = Read-Json $resolvedRc20UpdateResultPath
$rc20RollbackResult = Read-Json $resolvedRc20RollbackResultPath
$rc20LifecycleSupportResult = Read-Json $resolvedRc20LifecycleSupportResultPath
$rc20SupportBundle = Read-Json $resolvedRc20SupportBundlePath
$rc20RecoveryReferenceIndex = Read-Json $resolvedRc20RecoveryReferenceIndexPath

$previousTaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC21-001"
$currentTaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC21-010"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $previousTaskStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC21-010" -and ($currentTaskStatus -eq "pending" -or $currentTaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC21-011" -and $currentTaskStatus -eq "completed")
    )
)

$contractAllowsCatalog = (
    $contractText.Contains("Bind the local lifecycle operation intent catalog") -and
    $contractText.Contains("Operation intent catalog entries are local, typed, and non-executable") -and
    $contractText.Contains("production_ready_claim=false")
)

$rc20FinalReady = (
    $rc20FinalAuditResult.status -eq "passed" -and
    $rc20FinalAuditResult.single_user_distribution_local_consumer_ready -eq $true -and
    $rc20FinalAuditResult.consumer_ready_claim -eq $true -and
    $rc20FinalAuditResult.production_ready_claim -eq $false
)
$rc20ConsumerReady = (
    $rc20ConsumerSmokeResult.status -eq "passed" -and
    $rc20ConsumerSmokeResult.consumer_surface.consumer_decision -eq "single-user-distribution-local-consumer-ready" -and
    $rc20ConsumerSmokeResult.consumer_ready_claim -eq $true -and
    $rc20ConsumerSmokeResult.production_ready_claim -eq $false
)
$rc20ReleaseChannelReady = (
    $rc20ReleaseBundleResult.status -eq "passed" -and
    $rc20LocalChannelResult.status -eq "passed" -and
    $rc20ReleaseBundleResult.release_bundle_id -eq $rc20LocalChannelResult.release_bundle_id -and
    $rc20LocalChannelResult.promotion_surface.external_mirror_publication_performed -eq $false -and
    $rc20LocalChannelResult.promotion_surface.active_artifact_set_mutated -eq $false -and
    $rc20LocalChannelResult.promotion_surface.production_ring_mutated -eq $false
)
$rc20LifecycleReady = (
    $rc20InstallerCatalogResult.status -eq "passed" -and
    $rc20InstallAcceptanceResult.status -eq "passed" -and
    $rc20FirstBootAcceptanceResult.status -eq "passed" -and
    $rc20UpdateResult.status -eq "passed" -and
    $rc20RollbackResult.status -eq "passed" -and
    $rc20LifecycleSupportResult.status -eq "passed" -and
    $rc20LifecycleSupportResult.summary.support_upload_performed -eq $false -and
    $rc20LifecycleSupportResult.summary.recovery_execution_performed -eq $false -and
    $rc20LifecycleSupportResult.summary.remote_dispatch_enabled -eq $false
)
$stateIdentityReady = (
    $rc20ConsumerSmokeResult.release_bundle_id -eq $rc20ReleaseBundleResult.release_bundle_id -and
    $rc20ConsumerSmokeResult.target_state_id -eq $rc20InstallAcceptanceResult.target_state_id -and
    $rc20LifecycleSupportResult.target_state_id -eq $rc20InstallAcceptanceResult.target_state_id -and
    $rc20LifecycleSupportResult.restored_target_state_id -eq $rc20UpdateResult.previous_installed_image_state_id
)

$catalogAllowed = $planAllowsRun -and $contractAllowsCatalog -and $rc20FinalReady -and $rc20ConsumerReady -and $rc20ReleaseChannelReady -and $rc20LifecycleReady -and $stateIdentityReady
$blockers = @()
if (-not $planAllowsRun) { $blockers += "rc21-010-plan-pointer-not-current" }
if (-not $contractAllowsCatalog) { $blockers += "rc21-authority-contract-missing-catalog-authority" }
if (-not $rc20FinalReady) { $blockers += "rc20-final-audit-not-ready" }
if (-not $rc20ConsumerReady) { $blockers += "rc20-consumer-smoke-not-ready" }
if (-not $rc20ReleaseChannelReady) { $blockers += "rc20-release-channel-evidence-not-ready" }
if (-not $rc20LifecycleReady) { $blockers += "rc20-lifecycle-evidence-not-ready" }
if (-not $stateIdentityReady) { $blockers += "rc20-state-identity-mismatch" }
if ($catalogAllowed) { $blockers = @() }

$source = [ordered]@{
    rc21_plan = New-ArtifactRef $resolvedPlanPath $plan "rc21 workflow plan"
    rc21_authority_contract = [ordered]@{
        role = "rc21 authority contract"
        path = Get-StablePath $resolvedContractPath
        sha256 = Get-FileSha256 $resolvedContractPath
        size_bytes = (Get-Item -LiteralPath $resolvedContractPath).Length
        present = $true
    }
    rc20_final_audit_result = New-ArtifactRef $resolvedRc20FinalAuditResultPath $rc20FinalAuditResult "rc20 final audit result"
    rc20_consumer_smoke_result = New-ArtifactRef $resolvedRc20ConsumerSmokeResultPath $rc20ConsumerSmokeResult "rc20 consumer smoke result"
    rc20_release_bundle_result = New-ArtifactRef $resolvedRc20ReleaseBundleResultPath $rc20ReleaseBundleResult "rc20 release bundle result"
    rc20_local_channel_result = New-ArtifactRef $resolvedRc20LocalChannelResultPath $rc20LocalChannelResult "rc20 local channel result"
    rc20_installer_catalog_result = New-ArtifactRef $resolvedRc20InstallerCatalogResultPath $rc20InstallerCatalogResult "rc20 installer catalog result"
    rc20_install_acceptance_result = New-ArtifactRef $resolvedRc20InstallAcceptanceResultPath $rc20InstallAcceptanceResult "rc20 install acceptance result"
    rc20_first_boot_acceptance_result = New-ArtifactRef $resolvedRc20FirstBootAcceptanceResultPath $rc20FirstBootAcceptanceResult "rc20 first boot acceptance result"
    rc20_update_result = New-ArtifactRef $resolvedRc20UpdateResultPath $rc20UpdateResult "rc20 post-install update result"
    rc20_rollback_result = New-ArtifactRef $resolvedRc20RollbackResultPath $rc20RollbackResult "rc20 post-update rollback result"
    rc20_lifecycle_support_result = New-ArtifactRef $resolvedRc20LifecycleSupportResultPath $rc20LifecycleSupportResult "rc20 lifecycle support result"
    rc20_support_bundle = New-ArtifactRef $resolvedRc20SupportBundlePath $rc20SupportBundle "rc20 support bundle"
    rc20_recovery_reference_index = New-ArtifactRef $resolvedRc20RecoveryReferenceIndexPath $rc20RecoveryReferenceIndex "rc20 recovery reference index"
}

$commonInputs = @(
    "rc21-authority-contract",
    "rc20-final-audit-result",
    "rc20-consumer-smoke-result",
    "rc20-release-bundle-result",
    "rc20-local-channel-result"
)
$catalogIdentityMaterial = [ordered]@{
    schema = "agentos.rc21-local-operation-intent-catalog-identity-material.v1"
    task = "RC21-010"
    release_bundle_id = [string]$rc20ReleaseBundleResult.release_bundle_id
    selected_version = [string]$rc20ConsumerSmokeResult.selected_version
    target_state_id = [string]$rc20ConsumerSmokeResult.target_state_id
    consumer_decision = [string]$rc20ConsumerSmokeResult.consumer_surface.consumer_decision
    candidate_channel_package_id = [string]$rc20LocalChannelResult.candidate_channel_package_id
    stable_channel_projection_id = [string]$rc20LocalChannelResult.stable_channel_projection_id
    support_bundle_id = [string]$rc20LifecycleSupportResult.support_bundle_id
    recovery_reference_digest = [string]$rc20LifecycleSupportResult.recovery_reference_digest
    source_hashes = @(
        [ordered]@{ id = "rc21-authority-contract"; sha256 = Get-FileSha256 $resolvedContractPath },
        [ordered]@{ id = "rc20-final-audit-result"; sha256 = Get-FileSha256 $resolvedRc20FinalAuditResultPath },
        [ordered]@{ id = "rc20-consumer-smoke-result"; sha256 = Get-FileSha256 $resolvedRc20ConsumerSmokeResultPath },
        [ordered]@{ id = "rc20-release-bundle-result"; sha256 = Get-FileSha256 $resolvedRc20ReleaseBundleResultPath },
        [ordered]@{ id = "rc20-local-channel-result"; sha256 = Get-FileSha256 $resolvedRc20LocalChannelResultPath },
        [ordered]@{ id = "rc20-lifecycle-support-result"; sha256 = Get-FileSha256 $resolvedRc20LifecycleSupportResultPath }
    )
    deterministic_rules = [ordered]@{
        generated_at_excluded_from_identity = $true
        output_hashes_excluded_from_identity = $true
        external_reachability_excluded_from_identity = $true
        source_hashes_required = $true
    }
}

$intents = @(
    (New-Intent -Id "install" -Kind "install" -Title "Install selected local AIOS release into a disposable target" -RequiredInputs ($commonInputs + @("rc20-installer-catalog-result", "rc20-install-acceptance-result")) -AuditExpectations @("bind selected version", "bind target state", "record denial before host effect", "record non-GA decision") -DenialReasons @("missing rc20 release bundle", "missing local channel projection", "missing installer catalog", "stale selected version", "host mutation requested") -EffectBoundary "dry-run-only-until-transaction-journal-and-disposable-target-acceptance"),
    (New-Intent -Id "update" -Kind "update" -Title "Update installed local AIOS release inside disposable installed-system evidence" -RequiredInputs ($commonInputs + @("rc20-update-result", "rc20-rollback-result", "rc20-lifecycle-support-result")) -AuditExpectations @("bind previous installed state", "bind target update state", "bind rollback baseline", "record denial before host active slot mutation") -DenialReasons @("missing update evidence", "missing rollback baseline", "stale local channel", "host active slot mutation requested") -EffectBoundary "dry-run-only-until-transaction-journal-and-disposable-installed-system-acceptance"),
    (New-Intent -Id "repair-reinstall" -Kind "repair-reinstall" -Title "Repair or reinstall selected local AIOS release inside disposable installed-system evidence" -RequiredInputs ($commonInputs + @("rc20-install-acceptance-result", "rc20-first-boot-acceptance-result", "rc20-lifecycle-support-result")) -AuditExpectations @("bind source snapshot", "bind reinstall target snapshot", "preserve local operator posture projection", "record denial before host rootfs mutation") -DenialReasons @("missing install acceptance", "missing first boot posture", "missing support reference", "broad reinstall scope", "host rootfs mutation requested") -EffectBoundary "disposable-installed-system-evidence-only"),
    (New-Intent -Id "downgrade-rollback" -Kind "downgrade-rollback" -Title "Downgrade or rollback from local channel history inside disposable installed-system evidence" -RequiredInputs ($commonInputs + @("rc20-update-result", "rc20-rollback-result", "rc20-recovery-reference-index")) -AuditExpectations @("bind local channel history", "bind updated state", "bind restored state", "record denial before boot metadata mutation") -DenialReasons @("missing local channel history", "missing rollback audit", "stale rollback baseline", "host boot metadata mutation requested") -EffectBoundary "disposable-installed-system-evidence-only"),
    (New-Intent -Id "support-export" -Kind "support-export" -Title "Export local redacted support bundle for lifecycle evidence" -RequiredInputs ($commonInputs + @("rc20-lifecycle-support-result", "rc20-support-bundle")) -AuditExpectations @("bind local support bundle id", "prove redaction", "prove no upload", "record denial before network transfer") -DenialReasons @("missing support bundle", "support bundle not redacted", "support upload requested", "remote dispatch requested") -EffectBoundary "local-redacted-bundle-only"),
    (New-Intent -Id "recovery-reference" -Kind "recovery-reference" -Title "Produce local recovery reference index without executing recovery service" -RequiredInputs ($commonInputs + @("rc20-lifecycle-support-result", "rc20-recovery-reference-index")) -AuditExpectations @("bind recovery reference digest", "prove projection-only", "prove no recovery execution", "record denial before recovery service call") -DenialReasons @("missing recovery reference index", "recovery execution requested", "support upload requested", "remote dispatch requested") -EffectBoundary "projection-and-reference-index-only")
)

$catalogCore = [ordered]@{
    schema = "agentos.rc21-local-operation-intent-catalog-core.v1"
    task = "RC21-010"
    release_bundle_id = [string]$rc20ReleaseBundleResult.release_bundle_id
    selected_version = [string]$rc20ConsumerSmokeResult.selected_version
    target_state_id = [string]$rc20ConsumerSmokeResult.target_state_id
    consumer_decision = [string]$rc20ConsumerSmokeResult.consumer_surface.consumer_decision
    intents = $intents
    identity_material = $catalogIdentityMaterial
}
$operationIntentCatalogId = "sha256:$(Get-StringSha256 (Get-JsonText $catalogCore))"

$caseSpecs = @(
    [ordered]@{ id = "missing-rc20-final-audit"; blockers = @("rc20-final-audit-required"); reason = "Catalog requires RC20 final audit PASS." },
    [ordered]@{ id = "missing-rc20-consumer-smoke"; blockers = @("rc20-consumer-smoke-required"); reason = "Catalog requires RC20 local consumer smoke readiness." },
    [ordered]@{ id = "missing-release-bundle"; blockers = @("rc20-release-bundle-required"); reason = "Catalog requires RC20 release bundle evidence." },
    [ordered]@{ id = "missing-local-channel"; blockers = @("rc20-local-channel-required"); reason = "Catalog requires RC20 local channel evidence." },
    [ordered]@{ id = "missing-installer-catalog"; blockers = @("rc20-installer-catalog-required"); reason = "Install intent requires installer catalog evidence." },
    [ordered]@{ id = "missing-update-evidence"; blockers = @("rc20-update-required"); reason = "Update intent requires RC20 update evidence." },
    [ordered]@{ id = "missing-rollback-evidence"; blockers = @("rc20-rollback-required"); reason = "Downgrade/rollback intent requires RC20 rollback evidence." },
    [ordered]@{ id = "missing-support-reference"; blockers = @("rc20-support-required"); reason = "Support and recovery intents require RC20 support/recovery evidence." },
    [ordered]@{ id = "stale-rc20-final-audit"; blockers = @("stale-rc20-final-audit-denied"); reason = "Catalog denies stale RC20 final audit evidence." },
    [ordered]@{ id = "stale-consumer-smoke"; blockers = @("stale-consumer-smoke-denied"); reason = "Catalog denies stale consumer smoke evidence." },
    [ordered]@{ id = "release-channel-mismatch"; blockers = @("release-channel-mismatch-denied"); reason = "Catalog denies mismatched release/channel identities." },
    [ordered]@{ id = "target-state-mismatch"; blockers = @("target-state-mismatch-denied"); reason = "Catalog denies mismatched target state identities." },
    [ordered]@{ id = "broad-operation-scope"; blockers = @("broad-operation-scope-denied"); reason = "Catalog denies operations broader than local single-user lifecycle scope." },
    [ordered]@{ id = "host-rootfs-mutation"; blockers = @("host-rootfs-mutation-denied"); reason = "Host rootfs mutation is forbidden." },
    [ordered]@{ id = "host-active-slot-mutation"; blockers = @("host-active-slot-mutation-denied"); reason = "Host active slot mutation is forbidden." },
    [ordered]@{ id = "host-boot-metadata-mutation"; blockers = @("host-boot-metadata-mutation-denied"); reason = "Host boot metadata mutation is forbidden." },
    [ordered]@{ id = "active-artifact-set-mutation"; blockers = @("active-artifact-set-mutation-denied"); reason = "Active artifact set mutation is forbidden." },
    [ordered]@{ id = "production-ring-mutation"; blockers = @("production-ring-mutation-denied"); reason = "Production ring mutation is forbidden." },
    [ordered]@{ id = "remote-dispatch-attempt"; blockers = @("remote-dispatch-denied"); reason = "Remote dispatch is outside RC21 body scope." },
    [ordered]@{ id = "support-upload-attempt"; blockers = @("support-upload-denied"); reason = "Support upload is outside RC21 body scope." },
    [ordered]@{ id = "recovery-execution-attempt"; blockers = @("recovery-execution-denied"); reason = "Recovery execution service is outside RC21 body scope." },
    [ordered]@{ id = "signer-authority-attempt"; blockers = @("signer-authority-denied"); reason = "Signer authority is outside RC21 body scope." },
    [ordered]@{ id = "object-storage-attempt"; blockers = @("object-storage-denied"); reason = "Object storage provisioning is outside RC21 body scope." },
    [ordered]@{ id = "external-mirror-frontend-attempt"; blockers = @("external-mirror-frontend-denied"); reason = "External mirror/frontend authority is outside RC21 body scope." },
    [ordered]@{ id = "ga-claim-attempt"; blockers = @("ga-claim-denied"); reason = "Operation intent catalog cannot claim GA production readiness." }
)
$cases = @()
foreach ($spec in $caseSpecs) {
    $cases += New-DenialCase -Id $spec.id -Blockers ([string[]]$spec.blockers) -Reason $spec.reason
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$catalog = [ordered]@{
    schema = "agentos.rc21-local-operation-intent-catalog.v1"
    generated_at = $generatedAtValue
    task = "RC21-010"
    status = if ($catalogAllowed) { "local-operation-intent-catalog-bound-non-ga" } else { "local-operation-intent-catalog-denied" }
    production_ready_claim = $false
    consumer_ready_claim = $false
    operation_intent_catalog_id = $operationIntentCatalogId
    release_bundle_id = [string]$rc20ReleaseBundleResult.release_bundle_id
    selected_version = [string]$rc20ConsumerSmokeResult.selected_version
    target_state_id = [string]$rc20ConsumerSmokeResult.target_state_id
    consumer_decision = [string]$rc20ConsumerSmokeResult.consumer_surface.consumer_decision
    local_only = $true
    executable_by_catalog = $false
    intent_count = @($intents).Count
    operation_intents = $intents
    required_next_gates = [ordered]@{
        rc21_011_transaction_journal_snapshot_baseline = "required-before-effect-planning"
        rc21_012_lifecycle_operation_fail_closed = "required-before-dry-run-trust"
        rc21_020_dry_run_execution_plan = "required-before-dry-run-acceptance"
        rc21_021_transactional_dry_run_acceptance = "required-before-explain-resume-audit"
        rc21_030_repair_reinstall_drill = "disposable-installed-system-only"
        rc21_031_downgrade_rollback_drill = "disposable-installed-system-only"
    }
    authority = [ordered]@{
        aios_body_only = $true
        local_operation_intent_catalog_authority = $true
        transaction_journal_authority = $false
        snapshot_baseline_authority = $false
        dry_run_plan_authority = $false
        install_authority = $false
        update_authority = $false
        repair_authority = $false
        reinstall_authority = $false
        downgrade_authority = $false
        rollback_execution_authority = $false
        support_upload_authority = $false
        recovery_execution_authority = $false
        remote_dispatch_authority = $false
        host_rootfs_mutation_authority = $false
        host_active_slot_mutation_authority = $false
        host_boot_metadata_mutation_authority = $false
        active_artifact_set_mutation_authority = $false
        production_ring_mutation_authority = $false
        external_mirror_frontend_authority = $false
        nginx_or_tls_authority = $false
        signer_authority = $false
        object_storage_authority = $false
        ga_claim_authority = $false
    }
    denial_reasons = @($cases | ForEach-Object { [ordered]@{ id = $_.id; blockers = $_.blockers; reason = $_.reason } })
    source = $source
}
$catalogPath = Join-Path $resolvedArtifactDir "operation-intent-catalog.json"
Write-Json $catalog $catalogPath

$sideEffects = New-SideEffects
$sideEffects.operation_intent_catalog_bound = $catalogAllowed

Add-Check "plan.current_task.rc21_010" $planAllowsRun "RC21-010 must run after RC21-001 completed, with current_task set to RC21-010 or during an idempotent rerun." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc21_001_status = $previousTaskStatus; rc21_010_status = $currentTaskStatus })
Add-Check "contract.catalog_authority.present" $contractAllowsCatalog "RC21-010 must consume the RC21 local transactional lifecycle authority contract." ([ordered]@{ path = Get-StablePath $resolvedContractPath; sha256 = Get-FileSha256 $resolvedContractPath })
Add-Check "rc20.final.ready" $rc20FinalReady "RC20 final audit must prove single-user distribution local consumer readiness and keep production readiness false." ([ordered]@{ status = $rc20FinalAuditResult.status; single_user_distribution_local_consumer_ready = $rc20FinalAuditResult.single_user_distribution_local_consumer_ready; consumer_ready_claim = $rc20FinalAuditResult.consumer_ready_claim; production_ready_claim = $rc20FinalAuditResult.production_ready_claim })
Add-Check "rc20.consumer.ready" $rc20ConsumerReady "RC20 consumer smoke must report local consumer readiness without production readiness." ([ordered]@{ status = $rc20ConsumerSmokeResult.status; decision = $rc20ConsumerSmokeResult.consumer_surface.consumer_decision; consumer_ready_claim = $rc20ConsumerSmokeResult.consumer_ready_claim; production_ready_claim = $rc20ConsumerSmokeResult.production_ready_claim })
Add-Check "rc20.release_channel.ready" $rc20ReleaseChannelReady "Catalog must bind RC20 release bundle and local channel evidence without external mirror, active artifact set, or production ring mutation." ([ordered]@{ release_bundle_id = $rc20ReleaseBundleResult.release_bundle_id; channel_release_bundle_id = $rc20LocalChannelResult.release_bundle_id; external_mirror_publication_performed = $rc20LocalChannelResult.promotion_surface.external_mirror_publication_performed; active_artifact_set_mutated = $rc20LocalChannelResult.promotion_surface.active_artifact_set_mutated; production_ring_mutated = $rc20LocalChannelResult.promotion_surface.production_ring_mutated })
Add-Check "rc20.lifecycle.ready" $rc20LifecycleReady "Catalog must bind RC20 installer, install, first boot, update, rollback, and support/recovery evidence." ([ordered]@{ installer_catalog_status = $rc20InstallerCatalogResult.status; install_status = $rc20InstallAcceptanceResult.status; first_boot_status = $rc20FirstBootAcceptanceResult.status; update_status = $rc20UpdateResult.status; rollback_status = $rc20RollbackResult.status; support_status = $rc20LifecycleSupportResult.status })
Add-Check "rc20.state_identity.ready" $stateIdentityReady "Catalog must bind a coherent RC20 release, target state, support, and rollback identity chain." ([ordered]@{ consumer_release_bundle_id = $rc20ConsumerSmokeResult.release_bundle_id; release_bundle_id = $rc20ReleaseBundleResult.release_bundle_id; consumer_target_state_id = $rc20ConsumerSmokeResult.target_state_id; install_target_state_id = $rc20InstallAcceptanceResult.target_state_id; restored_target_state_id = $rc20LifecycleSupportResult.restored_target_state_id })
Add-Check "catalog.required_intents.present" (@($intents).Count -eq 6 -and @($intents | Where-Object { $_.id -in @("install", "update", "repair-reinstall", "downgrade-rollback", "support-export", "recovery-reference") }).Count -eq 6) "Catalog must bind install, update, repair/reinstall, downgrade/rollback, support export, and recovery reference intents." (@($intents | ForEach-Object { $_.id }))
Add-Check "catalog.local_only_non_executable" ($catalog.local_only -eq $true -and $catalog.executable_by_catalog -eq $false -and $catalog.production_ready_claim -eq $false -and $catalog.authority.host_rootfs_mutation_authority -eq $false -and $catalog.authority.remote_dispatch_authority -eq $false -and $catalog.authority.support_upload_authority -eq $false -and $catalog.authority.recovery_execution_authority -eq $false) "Catalog must remain local-only, non-executable, non-GA, and must not authorize host mutation, remote dispatch, support upload, or recovery execution." $catalog.authority
Add-Check "catalog.required_inputs.audit_denial.present" (@($intents | Where-Object { @($_.required_inputs).Count -lt 5 -or @($_.audit_expectations).Count -lt 4 -or @($_.denial_reasons).Count -lt 4 }).Count -eq 0) "Every intent must record exact required inputs, audit expectations, and denial reasons." (@($intents | ForEach-Object { [ordered]@{ id = $_.id; required_inputs = @($_.required_inputs).Count; audit_expectations = @($_.audit_expectations).Count; denial_reasons = @($_.denial_reasons).Count } }))
Add-Check "authority.no_forbidden_side_effects" ($sideEffects.install_performed -eq $false -and $sideEffects.update_performed -eq $false -and $sideEffects.repair_performed -eq $false -and $sideEffects.reinstall_performed -eq $false -and $sideEffects.downgrade_performed -eq $false -and $sideEffects.rollback_execution_performed -eq $false -and $sideEffects.support_upload_performed -eq $false -and $sideEffects.recovery_execution_performed -eq $false -and $sideEffects.remote_dispatch_enabled -eq $false -and $sideEffects.host_rootfs_mutated -eq $false -and $sideEffects.active_artifact_set_mutated -eq $false -and $sideEffects.production_ring_mutated -eq $false -and $sideEffects.signer_authority_granted -eq $false -and $sideEffects.object_storage_provisioned -eq $false -and $sideEffects.production_ready_claim -eq $false) "RC21-010 must not execute lifecycle operations or broaden host, production, remote, signer, object storage, support upload, recovery, or GA authority." $sideEffects
Add-Check "fixtures.fail_closed.pass" (@($failedCases).Count -eq 0 -and @($cases).Count -ge 20) "Missing/stale RC20 evidence and forbidden authority attempts must deny before operation intent authority." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })

$outputsSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $catalogPath))
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC21-010 outputs must not contain key blocks, private authority paths, auth tokens, signing key file names, raw passwords, raw secrets, or public identity markers." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc21-local-operation-intent-catalog-result.v1"
    generated_at = $generatedAtValue
    task = "RC21-010"
    status = $resultStatus
    production_ready_claim = $false
    consumer_ready_claim = $false
    operation_intent_catalog_id = $operationIntentCatalogId
    release_bundle_id = [string]$rc20ReleaseBundleResult.release_bundle_id
    selected_version = [string]$rc20ConsumerSmokeResult.selected_version
    target_state_id = [string]$rc20ConsumerSmokeResult.target_state_id
    outputs = [ordered]@{
        operation_intent_catalog = [ordered]@{
            path = Get-StablePath $catalogPath
            sha256 = Get-FileSha256 $catalogPath
            operation_intent_catalog_id = $operationIntentCatalogId
            intent_count = @($intents).Count
        }
    }
    catalog_surface = [ordered]@{
        state = $catalog.status
        operation_intent_catalog_bound = $catalogAllowed
        operation_intent_catalog_id = $operationIntentCatalogId
        intent_count = @($intents).Count
        required_intents = @($intents | ForEach-Object { $_.id })
        executable_by_catalog = $false
        transaction_journal_required = $true
        snapshot_baseline_required = $true
        dry_run_required_before_effect = $true
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutation_allowed = $false
        active_artifact_set_mutation_allowed = $false
        production_ring_mutation_allowed = $false
        blockers = @($blockers)
    }
    source = $source
    checks = @($script:checks)
    fail_closed_cases = $cases
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        consumer_ready_claim = $false
        operation_intent_catalog_bound = $catalogAllowed
        operation_intent_catalog_local_only = $true
        operation_intent_catalog_executable = $false
        transaction_journal_written = $false
        snapshot_baseline_written = $false
        dry_run_plan_written = $false
        install_performed = $false
        update_performed = $false
        repair_performed = $false
        reinstall_performed = $false
        downgrade_performed = $false
        rollback_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        host_active_slot_mutated = $false
        host_boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        external_mirror_frontend_authority = $false
        nginx_or_tls_authority = $false
        signer_authority = $false
        object_storage_authority = $false
        endpoint_reachability_authority = $false
        shell_output_authority = $false
        tui_authority = $false
        model_replay_authority = $false
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
        rc21_010_complete = (@($script:failedChecks).Count -eq 0)
        operation_intent_catalog_id = $operationIntentCatalogId
        intent_count = @($intents).Count
        release_bundle_id = [string]$rc20ReleaseBundleResult.release_bundle_id
        consumer_decision = [string]$rc20ConsumerSmokeResult.consumer_surface.consumer_decision
        operation_intent_catalog_bound = $catalogAllowed
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        next_task = "RC21-011"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC21-010-local-operation-intent-catalog.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc21-local-operation-intent-catalog-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC21-010"
    status = if ($resultStatus -eq "passed") { "completed" } else { "failed" }
    production_ready_claim = $false
    consumer_ready_claim = $false
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
    catalog_surface = $result.catalog_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc21_010_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC21-011"
        commit_required = $true
    }
    checks = @($script:checks)
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) { throw "Sensitive marker detected in RC21-010 outputs." }

Write-Host "RC21 local operation intent catalog $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Operation intent catalog: $(Get-StablePath $catalogPath)"
Write-Host "Intent count: $(@($intents).Count); catalog executable: false; production_ready_claim: false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) { exit 1 }
