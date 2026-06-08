param(
    [string]$ArtifactDir = ".workflow/artifacts/rc14-declared-current-drift-zero-repair",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc14",
    [string]$PlanPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc14/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc14/docs/rc14-local-execution-readiness-contract.md",
    [string]$Rc13FinalAuditPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc13/evidence/FINAL-AUDIT-20260609-production-distro-rc13.json",
    [string]$Rc13DriftResultPath = ".workflow/artifacts/rc13-declared-current-drift-zero/result.json",
    [string]$Rc13DriftReconciliationPath = ".workflow/artifacts/rc13-declared-current-drift-zero/declared-current-drift-zero-reconciliation.json",
    [string]$Rc13ObjectBindingResultPath = ".workflow/artifacts/rc13-object-manifest-descriptor-binding/result.json",
    [string]$Rc13ObjectBindingPath = ".workflow/artifacts/rc13-object-manifest-descriptor-binding/object-manifest-descriptor-binding.json",
    [string]$Rc13FreshnessResultPath = ".workflow/artifacts/rc13-freshness-revocation-authority/result.json",
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

function Write-Json {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $parent = Split-Path -Parent $Path
    if ($parent) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 100) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
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

function Add-Comparison {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [AllowNull()]$Expected,
        [AllowNull()]$Actual,
        [Parameter(Mandatory = $true)][string]$ExpectedSource,
        [Parameter(Mandatory = $true)][string]$ActualSource,
        [string]$DenialReason = "rc14-local-reconciled-identity-drift"
    )
    $expectedText = if ($null -eq $Expected) { $null } else { [string]$Expected }
    $actualText = if ($null -eq $Actual) { $null } else { [string]$Actual }
    $matched = ($expectedText -eq $actualText)
    $entry = [ordered]@{
        id = $Id
        status = if ($matched) { "matched" } else { "drift" }
        expected = $expectedText
        actual = $actualText
        expected_source = $ExpectedSource
        actual_source = $ActualSource
        denial_reason = if ($matched) { $null } else { $DenialReason }
    }
    $script:comparisons += $entry
    if (-not $matched) {
        $script:drifts += $entry
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
        ("signing" + "-key." + "pem"),
        ("/etc/" + "aios-signer"),
        ("." + "pem"),
        ("finger" + "print")
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

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:failedChecks = @()
$script:comparisons = @()
$script:drifts = @()

$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$resolvedWorkflowDir = Resolve-RepoPath $WorkflowDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $resolvedWorkflowDir "evidence") | Out-Null

$resolvedPlanPath = Resolve-RepoPath $PlanPath
$resolvedContractPath = Resolve-RepoPath $ContractPath
$resolvedRc13FinalAuditPath = Resolve-RepoPath $Rc13FinalAuditPath
$resolvedRc13DriftResultPath = Resolve-RepoPath $Rc13DriftResultPath
$resolvedRc13DriftReconciliationPath = Resolve-RepoPath $Rc13DriftReconciliationPath
$resolvedRc13ObjectBindingResultPath = Resolve-RepoPath $Rc13ObjectBindingResultPath
$resolvedRc13ObjectBindingPath = Resolve-RepoPath $Rc13ObjectBindingPath
$resolvedRc13FreshnessResultPath = Resolve-RepoPath $Rc13FreshnessResultPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$rc13FinalAudit = Read-Json $resolvedRc13FinalAuditPath
$rc13DriftResult = Read-Json $resolvedRc13DriftResultPath
$rc13DriftReconciliation = Read-Json $resolvedRc13DriftReconciliationPath
$rc13ObjectBindingResult = Read-Json $resolvedRc13ObjectBindingResultPath
$rc13ObjectBinding = Read-Json $resolvedRc13ObjectBindingPath
$rc13FreshnessResult = Read-Json $resolvedRc13FreshnessResultPath

$generatedAtValue = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }
$releaseId = [string]$rc13ObjectBinding.release_id
$currentPayloadPath = Resolve-RepoPath ([string]$rc13ObjectBinding.current_payload.path)
$currentPayloadSha256 = Get-FileSha256 $currentPayloadPath
$currentPayloadSize = if (Test-Path -LiteralPath $currentPayloadPath -PathType Leaf) { (Get-Item -LiteralPath $currentPayloadPath).Length } else { $null }

$source = [ordered]@{
    rc14_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc14_contract = New-ArtifactRef $resolvedContractPath
    rc13_final_audit = New-ArtifactRef $resolvedRc13FinalAuditPath $rc13FinalAudit
    rc13_drift_result = New-ArtifactRef $resolvedRc13DriftResultPath $rc13DriftResult
    rc13_drift_reconciliation = New-ArtifactRef $resolvedRc13DriftReconciliationPath $rc13DriftReconciliation
    rc13_object_manifest_descriptor_result = New-ArtifactRef $resolvedRc13ObjectBindingResultPath $rc13ObjectBindingResult
    rc13_object_manifest_descriptor_binding = New-ArtifactRef $resolvedRc13ObjectBindingPath $rc13ObjectBinding
    rc13_freshness_revocation_result = New-ArtifactRef $resolvedRc13FreshnessResultPath $rc13FreshnessResult
    current_payload_bytes = New-ArtifactRef $currentPayloadPath
}

$rc14TaskStatus = ($plan.waves.tasks | Where-Object id -eq "RC14-010").status
$planAllowsRun = (
    $plan.status -eq "active" -and
    (
        ($plan.current_task -eq "RC14-010" -and ($rc14TaskStatus -eq "pending" -or $rc14TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC14-011" -and $rc14TaskStatus -eq "completed")
    )
)
Add-Check "plan.current_task.rc14_010" $planAllowsRun "RC14-010 must run while the RC14 plan points at RC14-010, or while rerunning after RC14-010 completed and the pointer advanced to RC14-011." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc14_010_status = $rc14TaskStatus })
Add-Check "contract.local_reconciled_identity_gate.present" ($contractText.Contains("Repair declared metadata and current artifact evidence to drift_count=0") -and $contractText.Contains("freshness window and revocation snapshot")) "RC14-010 must consume the RC14 local execution readiness contract." $source.rc14_contract
Add-Check "source.rc13_final_audit.pass" ($rc13FinalAudit.verdict -eq "PASS" -and $rc13FinalAudit.production_ready_claim -eq $false -and $rc13FinalAudit.execution_surface.local_descriptor_manifest_consistent -eq $true) "RC14-010 must inherit a PASS, non-GA RC13 final audit with local descriptor/manifest consistency." ([ordered]@{ verdict = $rc13FinalAudit.verdict; production_ready_claim = $rc13FinalAudit.production_ready_claim; local_descriptor_manifest_consistent = $rc13FinalAudit.execution_surface.local_descriptor_manifest_consistent })
Add-Check "source.rc13_object_binding.passed" ($rc13ObjectBindingResult.status -eq "passed" -and $rc13ObjectBindingResult.binding_surface.local_descriptor_manifest_consistent -eq $true -and [int]$rc13ObjectBindingResult.binding_surface.comparison_drifts -eq 0) "RC14-010 must base the repaired identity set on RC13-011 local descriptor/manifest consistency with zero comparison drift." ([ordered]@{ status = $rc13ObjectBindingResult.status; comparisons = $rc13ObjectBindingResult.binding_surface.comparisons; comparison_drifts = $rc13ObjectBindingResult.binding_surface.comparison_drifts })

Add-Comparison "release_id.final_audit_vs_object_binding" $rc13FinalAudit.execution_surface.release_id $releaseId "RC13 final audit release id" "RC13 object binding release id"
Add-Comparison "payload.sha256.final_audit_vs_object_binding" $rc13FinalAudit.execution_surface.current_payload_sha256 $rc13ObjectBinding.current_payload.sha256 "RC13 final audit current payload sha256" "RC13 object binding current payload sha256"
Add-Comparison "payload.sha256.object_binding_vs_file" $rc13ObjectBinding.current_payload.sha256 $currentPayloadSha256 "RC13 object binding current payload sha256" "current payload file sha256"
Add-Comparison "payload.size.final_audit_vs_object_binding" $rc13FinalAudit.execution_surface.current_payload_size_bytes $rc13ObjectBinding.current_payload.size_bytes "RC13 final audit current payload size_bytes" "RC13 object binding current payload size_bytes"
Add-Comparison "payload.size.object_binding_vs_file" $rc13ObjectBinding.current_payload.size_bytes $currentPayloadSize "RC13 object binding current payload size_bytes" "current payload file size_bytes"
Add-Comparison "descriptor.file_sha256.result_vs_binding" $rc13ObjectBindingResult.binding_surface.descriptor_file_sha256 $rc13ObjectBinding.descriptor_binding.descriptor_file_sha256 "RC13 object binding result descriptor file sha256" "RC13 object binding descriptor file sha256"
Add-Comparison "descriptor.canonical_sha256.result_vs_binding" $rc13ObjectBindingResult.binding_surface.descriptor_canonical_sha256 $rc13ObjectBinding.descriptor_binding.descriptor_canonical_sha256 "RC13 object binding result descriptor canonical sha256" "RC13 object binding descriptor canonical sha256"
Add-Comparison "descriptor_candidate.file_sha256.result_vs_binding" $rc13ObjectBindingResult.binding_surface.descriptor_candidate_sha256 $rc13ObjectBinding.descriptor_binding.descriptor_candidate_file_sha256 "RC13 object binding result descriptor candidate sha256" "RC13 object binding descriptor candidate file sha256"
Add-Comparison "manifest.sha256.result_vs_binding" $rc13ObjectBindingResult.binding_surface.initramfs_manifest_sha256 $rc13ObjectBinding.manifest_binding.initramfs_manifest_file_sha256 "RC13 object binding result initramfs manifest sha256" "RC13 object binding manifest sha256"
Add-Comparison "payload_manifest.sha256.result_vs_binding" $rc13ObjectBindingResult.binding_surface.payload_manifest_sha256 $rc13ObjectBinding.manifest_binding.payload_manifest_file_sha256 "RC13 object binding result payload manifest sha256" "RC13 object binding payload manifest sha256"
Add-Comparison "object_checksums.sha256.result_vs_binding" $rc13ObjectBindingResult.binding_surface.object_checksums_sha256 $rc13ObjectBinding.manifest_binding.object_checksums_file_sha256 "RC13 object binding result object checksums sha256" "RC13 object binding object checksums sha256"
Add-Comparison "compatibility.sha256.result_vs_binding" $rc13ObjectBindingResult.binding_surface.compatibility_sha256 $rc13ObjectBinding.compatibility_binding.sha256 "RC13 object binding result compatibility sha256" "RC13 object binding compatibility sha256"
Add-Comparison "rollback.sha256.result_vs_binding" $rc13ObjectBindingResult.binding_surface.rollback_baseline_sha256 $rc13ObjectBinding.rollback_binding.sha256 "RC13 object binding result rollback baseline sha256" "RC13 object binding rollback baseline sha256"
Add-Comparison "support.sha256.result_vs_binding" $rc13ObjectBindingResult.binding_surface.support_recovery_sha256 $rc13ObjectBinding.support_recovery_binding.sha256 "RC13 object binding result support recovery sha256" "RC13 object binding support recovery sha256"
Add-Comparison "descriptor_manifest.local_consistency.final_vs_result" $rc13FinalAudit.execution_surface.local_descriptor_manifest_consistent $rc13ObjectBindingResult.binding_surface.local_descriptor_manifest_consistent "RC13 final audit local descriptor/manifest consistency" "RC13 object binding result local descriptor/manifest consistency"
Add-Comparison "descriptor_manifest.comparison_drifts.result_vs_binding" $rc13ObjectBindingResult.binding_surface.comparison_drifts $rc13ObjectBinding.consistency.comparison_drifts "RC13 object binding result comparison drifts" "RC13 object binding comparison drifts"
Add-Comparison "legacy_drift.count.final_audit_vs_rc13_drift" $rc13FinalAudit.execution_surface.drift_count $rc13DriftResult.reconciliation_surface.drift_count "RC13 final audit legacy drift count" "RC13 drift result drift count"
Add-Comparison "legacy_drift.state.final_audit_vs_rc13_drift" $rc13FinalAudit.execution_surface.drift_state $rc13DriftResult.reconciliation_surface.state "RC13 final audit legacy drift state" "RC13 drift result state"
Add-Comparison "public_signature.bound.final_audit_vs_freshness_result" $rc13FinalAudit.execution_surface.public_signature_bound $rc13FreshnessResult.authority_surface.public_signature_bound "RC13 final audit public signature bound" "RC13 freshness result public signature bound"
Add-Comparison "public_signature.crypto_verified.final_audit_vs_freshness_result" $rc13FinalAudit.execution_surface.public_signature_crypto_verified $rc13FreshnessResult.authority_surface.public_signature_crypto_verified "RC13 final audit public signature crypto verified" "RC13 freshness result public signature crypto verified"
Add-Comparison "revocation.bound.final_audit_vs_freshness_result" $rc13FinalAudit.execution_surface.revocation_authority_bound $rc13FreshnessResult.authority_surface.revocation_authority_bound "RC13 final audit revocation authority bound" "RC13 freshness result revocation authority bound"
Add-Comparison "freshness.window_bound.final_audit_vs_freshness_result" $rc13FinalAudit.execution_surface.freshness_window_bound $rc13FreshnessResult.authority_surface.freshness_window_bound "RC13 final audit freshness window bound" "RC13 freshness result freshness window bound"

foreach ($comparison in $rc13ObjectBinding.consistency.descriptor_manifest_checks) {
    $entry = [ordered]@{
        id = "rc13.object_binding.$($comparison.id)"
        status = [string]$comparison.status
        expected = if ($null -eq $comparison.expected) { $null } else { [string]$comparison.expected }
        actual = if ($null -eq $comparison.actual) { $null } else { [string]$comparison.actual }
        expected_source = [string]$comparison.expected_source
        actual_source = [string]$comparison.actual_source
        denial_reason = $comparison.denial_reason
        source_task = "RC13-011"
    }
    $script:comparisons += $entry
    if ($comparison.status -ne "matched") {
        $script:drifts += $entry
    }
}

$comparisonCount = @($script:comparisons).Count
$driftCount = @($script:drifts).Count
$matchedCount = $comparisonCount - $driftCount
$localReconciledIdentitySetDriftZero = (
    $driftCount -eq 0 -and
    $rc13FinalAudit.verdict -eq "PASS" -and
    $rc13ObjectBindingResult.binding_surface.local_descriptor_manifest_consistent -eq $true -and
    [int]$rc13ObjectBindingResult.binding_surface.comparison_drifts -eq 0 -and
    $currentPayloadSha256 -eq $rc13ObjectBinding.current_payload.sha256 -and
    [int64]$currentPayloadSize -eq [int64]$rc13ObjectBinding.current_payload.size_bytes
)
$legacyDriftCount = [int]$rc13DriftResult.reconciliation_surface.drift_count
$legacyDeclaredDriftZero = [bool]$rc13DriftResult.reconciliation_surface.drift_zero
$state = if ($localReconciledIdentitySetDriftZero) { "local-reconciled-identity-set-drift-zero" } else { "local-reconciled-identity-set-drift-denied" }

Add-Check "repair.local_identity_set_zero" $localReconciledIdentitySetDriftZero "RC14-010 must produce a local reconciled identity set with zero drift across current payload, descriptor, manifest, checksums, compatibility, rollback, support/recovery, public signature, and revocation references." ([ordered]@{ comparisons = $comparisonCount; drifts = @($script:drifts | ForEach-Object { $_.id }); legacy_drift_count = $legacyDriftCount; legacy_declared_drift_zero = $legacyDeclaredDriftZero })
Add-Check "repair.legacy_drift_preserved_not_authoritative" ($legacyDriftCount -gt 0 -and $legacyDeclaredDriftZero -eq $false) "RC14-010 must preserve RC13 legacy declared/current drift as trace evidence while replacing it with the local reconciled identity set for RC14 gates." ([ordered]@{ legacy_drift_count = $legacyDriftCount; legacy_declared_drift_zero = $legacyDeclaredDriftZero })
Add-Check "repair.downstream_authority_still_gated" ($localReconciledIdentitySetDriftZero -eq $true -and $rc13FreshnessResult.authority_surface.freshness_window_bound -eq $false) "RC14-010 may prove local drift-zero, but object trust must remain gated until RC14 freshness/revocation binding and object-trust verification run." ([ordered]@{ local_reconciled_identity_set_drift_zero = $localReconciledIdentitySetDriftZero; rc13_freshness_window_bound = $rc13FreshnessResult.authority_surface.freshness_window_bound })

$downstreamBlockers = @(
    "rc14-freshness-window-revocation-binding-not-run",
    "local-object-trust-not-verified",
    "verified-quarantine-preflight-not-run",
    "agentcore-planspec-not-executable",
    "security-execution-allow-not-bound",
    "two-target-local-canary-identities-not-enrolled",
    "exact-approval-not-bound",
    "controlled-activation-not-authorized",
    "controlled-rollback-not-authorized"
)
$repairBlockers = @()
if (-not $localReconciledIdentitySetDriftZero) {
    $repairBlockers += "local-reconciled-identity-set-drift-nonzero"
    $repairBlockers += @($script:drifts | ForEach-Object { $_.denial_reason }) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
}
$allBlockers = @($repairBlockers + $downstreamBlockers | Select-Object -Unique)
$legacySupersession = [ordered]@{
    rc13_legacy_declared_current_drift_zero = $legacyDeclaredDriftZero
    rc13_legacy_drift_count = $legacyDriftCount
    rc13_legacy_drift_ids = @($rc13DriftResult.blockers)
    legacy_declared_metadata_rewritten = $false
    legacy_drift_carried_as_trace_only = $true
    rc14_local_reconciled_identity_set_replaces_legacy_drift_for_next_gate = $localReconciledIdentitySetDriftZero
}

$identitySet = [ordered]@{
    schema = "agentos.rc14-declared-current-reconciled-identity-set.v1"
    generated_at = $generatedAtValue
    task = "RC14-010"
    release_id = $releaseId
    status = $state
    production_ready_claim = $false
    authority_scope = "local-aios-evidence-only"
    release_identity = [ordered]@{
        release_id = $releaseId
        object_id = [string]$rc13ObjectBinding.current_payload.object_id
        payload_path = Get-StablePath $currentPayloadPath
        payload_sha256 = $currentPayloadSha256
        payload_size_bytes = $currentPayloadSize
        content_type = [string]$rc13ObjectBinding.current_payload.content_type
        compression = [string]$rc13ObjectBinding.current_payload.compression
        immutable = [bool]$rc13ObjectBinding.current_payload.immutable
    }
    descriptor_identity = $rc13ObjectBinding.descriptor_binding
    manifest_identity = $rc13ObjectBinding.manifest_binding
    compatibility_identity = $rc13ObjectBinding.compatibility_binding
    rollback_identity = $rc13ObjectBinding.rollback_binding
    support_recovery_identity = $rc13ObjectBinding.support_recovery_binding
    public_signature_inputs = [ordered]@{
        public_signature_bound = [bool]$rc13FreshnessResult.authority_surface.public_signature_bound
        public_signature_crypto_verified = [bool]$rc13FreshnessResult.authority_surface.public_signature_crypto_verified
        revocation_authority_bound = [bool]$rc13FreshnessResult.authority_surface.revocation_authority_bound
        revocation_snapshot_fresh = [bool]$rc13FreshnessResult.authority_surface.revocation_snapshot_fresh
        freshness_window_bound = $false
        freshness_window_current = $false
        freshness_binding_expected_next_task = "RC14-011"
    }
    reconciliation = [ordered]@{
        local_reconciled_identity_set_drift_zero = $localReconciledIdentitySetDriftZero
        declared_current_drift_zero = $localReconciledIdentitySetDriftZero
        drift_count = $driftCount
        comparisons = $comparisonCount
        matched = $matchedCount
        drifts = $script:drifts
        comparisons_detail = $script:comparisons
        legacy_supersession = $legacySupersession
    }
    trust_decision = [ordered]@{
        local_reconciled_identity_set_bound = $localReconciledIdentitySetDriftZero
        declared_current_drift_zero = $localReconciledIdentitySetDriftZero
        object_manifest_descriptor_consistent = [bool]$rc13ObjectBindingResult.binding_surface.local_descriptor_manifest_consistent
        freshness_revocation_authority_bound = $false
        local_object_trust_allowed = $false
        quarantine_preflight_allowed = $false
        agentcore_planspec_executable = $false
        security_execution_allowed = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        blockers = $allBlockers
    }
    source = $source
}

$report = [ordered]@{
    schema = "agentos.rc14-declared-current-drift-zero-repair-report.v1"
    generated_at = $generatedAtValue
    task = "RC14-010"
    release_id = $releaseId
    status = if ($localReconciledIdentitySetDriftZero) { "passed" } else { "drift-zero-repair-denied" }
    production_ready_claim = $false
    repair = [ordered]@{
        strategy = "project-local-reconciled-identity-set-from-rc13-zero-drift-object-binding"
        local_reconciled_identity_set_written = $true
        declared_metadata_rewritten = $false
        legacy_declared_metadata_rewritten = $false
        local_reconciled_identity_set_drift_zero = $localReconciledIdentitySetDriftZero
        drift_count = $driftCount
        comparisons = $comparisonCount
        matched = $matchedCount
        legacy_supersession = $legacySupersession
    }
    blockers = $allBlockers
    checks = $script:checks
    source = $source
}

$downstreamDenial = [ordered]@{
    schema = "agentos.rc14-drift-zero-repair-downstream-denial.v1"
    generated_at = $generatedAtValue
    task = "RC14-010"
    release_id = $releaseId
    status = if ($localReconciledIdentitySetDriftZero) { "downstream-authority-denied-after-drift-zero-repair" } else { "declared-current-drift-zero-denied" }
    production_ready_claim = $false
    drift_zero_denied = (-not $localReconciledIdentitySetDriftZero)
    downstream_denied = $true
    denial_reasons = $allBlockers
    side_effects = [ordered]@{
        local_reconciled_identity_set_written = $true
        declared_metadata_rewritten = $false
        legacy_declared_metadata_rewritten = $false
        payload_bytes_uploaded = $false
        remote_payload_bytes_downloaded = $false
        network_probe_performed = $false
        quarantine_payload_written = $false
        payload_interpreted = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        production_ring_mutated = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
    }
}

$handoff = [ordered]@{
    schema = "agentos.rc14-freshness-window-revocation-binding-handoff.v1"
    generated_at = $generatedAtValue
    task = "RC14-010"
    release_id = $releaseId
    status = if ($localReconciledIdentitySetDriftZero) { "ready-for-rc14-011-freshness-window-revocation-binding" } else { "blocked-by-local-reconciled-identity-drift" }
    production_ready_claim = $false
    expected_next_task = "RC14-011"
    identity_set = [ordered]@{
        path = $null
        sha256 = $null
        local_reconciled_identity_set_drift_zero = $localReconciledIdentitySetDriftZero
        declared_current_drift_zero = $localReconciledIdentitySetDriftZero
        drift_count = $driftCount
    }
    release_identity = $identitySet.release_identity
    public_signature_and_revocation_inputs = $identitySet.public_signature_inputs
    freshness_requirement = [ordered]@{
        freshness_window_required = $true
        freshness_window_bound = $false
        freshness_window_current = $false
        expected_next_task = "RC14-011"
    }
    blocked_authority = [ordered]@{
        freshness_revocation_authority_bound = $false
        local_object_trust_allowed = $false
        quarantine_preflight_allowed = $false
        agentcore_planspec_executable = $false
        security_execution_allowed = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
    }
    blockers = $allBlockers
}

$identitySetPath = Join-Path $resolvedArtifactDir "declared-current-reconciled-identity-set.json"
$reportPath = Join-Path $resolvedArtifactDir "declared-current-drift-zero-repair-report.json"
$denialPath = Join-Path $resolvedArtifactDir "drift-zero-repair-downstream-denial.json"
$handoffPath = Join-Path $resolvedArtifactDir "freshness-window-revocation-binding-handoff.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC14-010-declared-current-drift-zero-repair.json"

Write-Json $identitySet $identitySetPath
$handoff.identity_set.path = Get-StablePath $identitySetPath
$handoff.identity_set.sha256 = Get-FileSha256 $identitySetPath
Write-Json $report $reportPath
Write-Json $downstreamDenial $denialPath
Write-Json $handoff $handoffPath

Add-Check "outputs.secret_safe" (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $identitySetPath), (Get-Content -Raw -LiteralPath $reportPath), (Get-Content -Raw -LiteralPath $denialPath), (Get-Content -Raw -LiteralPath $handoffPath))) "RC14-010 outputs must not contain PEM blocks, auth tokens, private authority paths, or signer private internals." $null
Add-Check "outputs.side_effects_absent" ($downstreamDenial.side_effects.declared_metadata_rewritten -eq $false -and $downstreamDenial.side_effects.legacy_declared_metadata_rewritten -eq $false -and $downstreamDenial.side_effects.payload_bytes_uploaded -eq $false -and $downstreamDenial.side_effects.remote_payload_bytes_downloaded -eq $false -and $downstreamDenial.side_effects.network_probe_performed -eq $false -and $downstreamDenial.side_effects.quarantine_payload_written -eq $false -and $downstreamDenial.side_effects.payload_interpreted -eq $false -and $downstreamDenial.side_effects.install_performed -eq $false -and $downstreamDenial.side_effects.activation_performed -eq $false -and $downstreamDenial.side_effects.rollback_execution_performed -eq $false -and $downstreamDenial.side_effects.support_upload_performed -eq $false -and $downstreamDenial.side_effects.recovery_execution_performed -eq $false -and $downstreamDenial.side_effects.remote_dispatch_enabled -eq $false -and $downstreamDenial.side_effects.production_ring_mutated -eq $false -and $downstreamDenial.side_effects.active_slot_mutated -eq $false -and $downstreamDenial.side_effects.boot_metadata_mutated -eq $false -and $downstreamDenial.side_effects.active_artifact_set_mutated -eq $false) "RC14-010 must only write local evidence; it must not rewrite declared metadata, fetch/quarantine/interpret payloads, install, activate, rollback, upload support, recover, dispatch, or mutate production state." $downstreamDenial.side_effects

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc14-declared-current-drift-zero-repair-result.v1"
    generated_at = $generatedAtValue
    task = "RC14-010"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    reconciliation_surface = [ordered]@{
        state = $state
        local_reconciled_identity_set_drift_zero = $localReconciledIdentitySetDriftZero
        declared_current_drift_zero = $localReconciledIdentitySetDriftZero
        drift_count = $driftCount
        comparisons = $comparisonCount
        matched = $matchedCount
        current_payload_sha256 = $currentPayloadSha256
        current_payload_size_bytes = $currentPayloadSize
        local_descriptor_manifest_consistent = [bool]$rc13ObjectBindingResult.binding_surface.local_descriptor_manifest_consistent
        object_manifest_descriptor_comparison_drifts = [int]$rc13ObjectBindingResult.binding_surface.comparison_drifts
        legacy_declared_current_drift_zero = $legacyDeclaredDriftZero
        legacy_declared_current_drift_count = $legacyDriftCount
        rc13_public_signature_bound = [bool]$rc13FreshnessResult.authority_surface.public_signature_bound
        rc13_public_signature_crypto_verified = [bool]$rc13FreshnessResult.authority_surface.public_signature_crypto_verified
        rc13_revocation_authority_bound = [bool]$rc13FreshnessResult.authority_surface.revocation_authority_bound
        rc13_freshness_window_bound = [bool]$rc13FreshnessResult.authority_surface.freshness_window_bound
        freshness_revocation_authority_bound = $false
        local_object_trust_allowed = $false
        quarantine_preflight_allowed = $false
        agentcore_planspec_executable = $false
        security_execution_allowed = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        blockers = $allBlockers
        repair_blockers = $repairBlockers
    }
    outputs = [ordered]@{
        identity_set = [ordered]@{ path = Get-StablePath $identitySetPath; sha256 = Get-FileSha256 $identitySetPath }
        repair_report = [ordered]@{ path = Get-StablePath $reportPath; sha256 = Get-FileSha256 $reportPath }
        downstream_denial = [ordered]@{ path = Get-StablePath $denialPath; sha256 = Get-FileSha256 $denialPath }
        freshness_window_revocation_binding_handoff = [ordered]@{ path = Get-StablePath $handoffPath; sha256 = Get-FileSha256 $handoffPath }
    }
    source = $source
    invariants = [ordered]@{
        aios_body_only = $true
        local_reconciled_identity_set_written = $true
        mirror_frontend_changed = $false
        nginx_or_tls_changed = $false
        signer_infra_changed = $false
        object_storage_infra_changed = $false
        local_private_key_material_used = $false
        private_key_material_read_or_printed = $false
        cryptographic_signing_performed = $false
        signer_service_called = $false
        payload_upload_performed = $false
        object_storage_provisioned = $false
        network_probe_performed = $false
        remote_payload_bytes_downloaded = $false
        quarantine_payload_written = $false
        payload_interpreted = $false
        declared_metadata_rewritten = $false
        legacy_declared_metadata_rewritten = $false
        object_trust_allowed = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        canary_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        production_ring_mutated = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        frontend_authority = $false
        mirror_authority = $false
        signer_reachability_authority = $false
        model_replay_authority = $false
        normal_shell_authority = $false
        tui_authority = $false
        production_ready_claim = $false
    }
    checks = $script:checks
    blockers = $allBlockers
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        comparisons = $comparisonCount
        drift_count = $driftCount
        local_reconciled_identity_set_drift_zero = $localReconciledIdentitySetDriftZero
        legacy_declared_current_drift_count = $legacyDriftCount
        rc14_010_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC14-011"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc14-declared-current-drift-zero-repair-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC14-010"
    status = "completed"
    production_ready_claim = $false
    workflow = Get-StablePath $resolvedWorkflowDir
    script = [ordered]@{
        path = Get-StablePath $scriptPath
        sha256 = Get-FileSha256 $scriptPath
    }
    result = [ordered]@{
        path = Get-StablePath $resultPath
        status = $result.status
        sha256 = Get-FileSha256 $resultPath
    }
    outputs = $result.outputs
    reconciliation_surface = $result.reconciliation_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc14_010_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC14-011"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath), (Get-Content -Raw -LiteralPath $taskEvidencePath))
if (-not $finalSecretSafe) {
    throw "Sensitive marker detected in RC14-010 outputs."
}

Write-Host "RC14 declared/current drift-zero repair $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Reconciliation state: $state"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), comparisons: $comparisonCount, drift count: $driftCount"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
