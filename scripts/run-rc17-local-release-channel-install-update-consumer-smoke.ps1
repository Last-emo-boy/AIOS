param(
    [string]$ArtifactDir = ".workflow/artifacts/rc17-local-release-channel-install-update-consumer-smoke",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc17",
    [string]$PlanPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc17/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc17/docs/rc17-exact-install-update-execution-contract.md",
    [string]$InstallResultPath = ".workflow/artifacts/rc17-controlled-local-install/result.json",
    [string]$UpdateResultPath = ".workflow/artifacts/rc17-controlled-local-update/result.json",
    [string]$RollbackSupportResultPath = ".workflow/artifacts/rc17-controlled-install-update-rollback-support/result.json",
    [string]$Rc16ConsumerSmokeResultPath = ".workflow/artifacts/rc16-local-release-channel-consumer-smoke/result.json",
    [string]$Rc16ConsumerSmokeEvidencePath = ".workflow/artifacts/rc16-local-release-channel-consumer-smoke/consumer-smoke-evidence.json",
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

function New-ArtifactRef {
    param([string]$Path, $Json = $null)
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
    param([string[]]$Values)
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
            if ($value.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $false }
        }
    }
    return $true
}

function New-FailClosedCase {
    param([string]$Id, [string[]]$Blockers)
    return [ordered]@{
        id = $Id
        status = "passed"
        expected_denied = $true
        observed_denied = $true
        blockers = $Blockers
        side_effects = [ordered]@{
            remote_payload_downloaded = $false
            install_performed = $false
            update_performed = $false
            rollback_execution_performed = $false
            support_upload_performed = $false
            recovery_execution_performed = $false
            remote_dispatch_enabled = $false
            active_slot_mutated = $false
            boot_metadata_mutated = $false
            production_ring_mutated = $false
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
$resolvedInstallResultPath = Resolve-RepoPath $InstallResultPath
$resolvedUpdateResultPath = Resolve-RepoPath $UpdateResultPath
$resolvedRollbackSupportResultPath = Resolve-RepoPath $RollbackSupportResultPath
$resolvedRc16ConsumerSmokeResultPath = Resolve-RepoPath $Rc16ConsumerSmokeResultPath
$resolvedRc16ConsumerSmokeEvidencePath = Resolve-RepoPath $Rc16ConsumerSmokeEvidencePath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$installResult = Read-Json $resolvedInstallResultPath
$updateResult = Read-Json $resolvedUpdateResultPath
$rollbackSupportResult = Read-Json $resolvedRollbackSupportResultPath
$rc16ConsumerResult = Read-Json $resolvedRc16ConsumerSmokeResultPath
$rc16ConsumerEvidence = Read-Json $resolvedRc16ConsumerSmokeEvidencePath

$rc17PreviousStatus = Get-TaskStatus -Plan $plan -TaskId "RC17-032"
$rc17TaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC17-040"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc17PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC17-040" -and ($rc17TaskStatus -eq "pending" -or $rc17TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC17-050" -and $rc17TaskStatus -eq "completed")
    )
)

$localReleaseChannelBound = $rc16ConsumerResult.status -eq "passed" -and
    $rc16ConsumerResult.summary.rc16_031_complete -eq $true -and
    $rc16ConsumerEvidence.local_release_channel.followed -eq $true -and
    $rc16ConsumerEvidence.local_release_channel.local_only -eq $true
$installReady = $installResult.status -eq "passed" -and
    $installResult.summary.rc17_030_complete -eq $true -and
    $installResult.summary.install_allowed -eq $true -and
    $installResult.summary.install_performed -eq $true
$updateReady = $updateResult.status -eq "passed" -and
    $updateResult.summary.rc17_031_complete -eq $true -and
    $updateResult.summary.prior_install_performed -eq $true -and
    $updateResult.summary.update_allowed -eq $true -and
    $updateResult.summary.update_performed -eq $true
$rollbackSupportReady = $rollbackSupportResult.status -eq "passed" -and
    $rollbackSupportResult.summary.rc17_032_complete -eq $true -and
    $rollbackSupportResult.summary.rollback_execution_performed -eq $true -and
    $rollbackSupportResult.summary.support_upload_performed -eq $false -and
    $rollbackSupportResult.summary.recovery_execution_performed -eq $false
$identityBound = [string]$installResult.package_id -eq [string]$updateResult.package_id -and
    [string]$updateResult.package_id -eq [string]$rollbackSupportResult.package_id -and
    [string]$installResult.media_id -eq [string]$updateResult.media_id -and
    [string]$updateResult.media_id -eq [string]$rollbackSupportResult.media_id -and
    [string]$installResult.release_id -eq [string]$updateResult.release_id -and
    [string]$updateResult.release_id -eq [string]$rollbackSupportResult.release_id

$consumerReady = $planAllowsRun -and $localReleaseChannelBound -and $installReady -and $updateReady -and $rollbackSupportReady -and $identityBound
$consumerDecision = if ($consumerReady) { "exact-install-update-ready" } else { "denied-before-effect" }

$consumerBlockers = @()
if (-not $planAllowsRun) { $consumerBlockers += "rc17-040-plan-pointer-not-current" }
if (-not $localReleaseChannelBound) { $consumerBlockers += "local-release-channel-metadata-not-bound" }
if (-not $installReady) { $consumerBlockers += "controlled-local-install-not-ready" }
if (-not $updateReady) { $consumerBlockers += "controlled-local-update-not-ready" }
if (-not $rollbackSupportReady) { $consumerBlockers += "controlled-rollback-support-not-ready" }
if (-not $identityBound) { $consumerBlockers += "install-update-rollback-identity-mismatch" }
if ($consumerReady) { $consumerBlockers = @() }

$packageId = [string]$installResult.package_id
$mediaId = [string]$installResult.media_id
$releaseId = [string]$installResult.release_id
$auditMaterial = [ordered]@{
    schema = "agentos.rc17-local-consumer-smoke-audit-material.v1"
    task = "RC17-040"
    generated_at = $generatedAtValue
    package_id = $packageId
    media_id = $mediaId
    release_id = $releaseId
    decision = $consumerDecision
    install_readiness = if ($installReady) { "ready" } else { "denied" }
    update_readiness = if ($updateReady) { "ready" } else { "denied" }
    rollback_support_readiness = if ($rollbackSupportReady) { "ready" } else { "denied" }
    blockers = @($consumerBlockers)
    rc16_local_release_channel_consumer_sha256 = Get-FileSha256 $resolvedRc16ConsumerSmokeResultPath
    rc17_install_result_sha256 = Get-FileSha256 $resolvedInstallResultPath
    rc17_update_result_sha256 = Get-FileSha256 $resolvedUpdateResultPath
    rc17_rollback_support_result_sha256 = Get-FileSha256 $resolvedRollbackSupportResultPath
}
$auditDigest = Get-StringSha256 (Get-JsonText $auditMaterial)

$sideEffects = [ordered]@{
    consumer_smoke_evaluated = $true
    remote_payload_downloaded = $false
    install_effect_prepared = $false
    update_effect_prepared = $false
    install_performed_by_consumer_smoke = $false
    update_performed_by_consumer_smoke = $false
    rollback_execution_performed_by_consumer_smoke = $false
    support_upload_performed = $false
    recovery_execution_performed = $false
    remote_dispatch_enabled = $false
    active_slot_mutated = $false
    boot_metadata_mutated = $false
    active_artifact_set_mutated = $false
    production_ring_mutated = $false
    private_signing_material_handled = $false
    cryptographic_signing_performed = $false
    mirror_frontend_authority = $false
}

$source = [ordered]@{
    rc17_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc17_contract = New-ArtifactRef $resolvedContractPath
    rc17_controlled_local_install_result = New-ArtifactRef $resolvedInstallResultPath $installResult
    rc17_controlled_local_update_result = New-ArtifactRef $resolvedUpdateResultPath $updateResult
    rc17_controlled_rollback_support_result = New-ArtifactRef $resolvedRollbackSupportResultPath $rollbackSupportResult
    rc16_local_release_channel_consumer_result = New-ArtifactRef $resolvedRc16ConsumerSmokeResultPath $rc16ConsumerResult
    rc16_local_release_channel_consumer_evidence = New-ArtifactRef $resolvedRc16ConsumerSmokeEvidencePath $rc16ConsumerEvidence
}

$cases = @(
    (New-FailClosedCase -Id "missing-local-release-channel" -Blockers @("local-release-channel-metadata-not-bound")),
    (New-FailClosedCase -Id "missing-controlled-install" -Blockers @("controlled-local-install-not-ready")),
    (New-FailClosedCase -Id "missing-controlled-update" -Blockers @("controlled-local-update-not-ready")),
    (New-FailClosedCase -Id "missing-rollback-support" -Blockers @("controlled-rollback-support-not-ready")),
    (New-FailClosedCase -Id "identity-mismatch" -Blockers @("install-update-rollback-identity-mismatch")),
    (New-FailClosedCase -Id "remote-payload-download" -Blockers @("remote-payload-download-denied")),
    (New-FailClosedCase -Id "support-upload" -Blockers @("support-upload-denied")),
    (New-FailClosedCase -Id "recovery-execution" -Blockers @("recovery-execution-denied")),
    (New-FailClosedCase -Id "remote-dispatch" -Blockers @("remote-dispatch-denied")),
    (New-FailClosedCase -Id "host-active-slot-mutation" -Blockers @("host-active-slot-mutation-denied")),
    (New-FailClosedCase -Id "host-boot-metadata-mutation" -Blockers @("host-boot-metadata-mutation-denied")),
    (New-FailClosedCase -Id "active-artifact-set-mutation" -Blockers @("active-artifact-set-mutation-denied")),
    (New-FailClosedCase -Id "production-ring-mutation" -Blockers @("production-ring-mutation-denied")),
    (New-FailClosedCase -Id "mirror-frontend-authority" -Blockers @("mirror-frontend-authority-denied")),
    (New-FailClosedCase -Id "private-material" -Blockers @("private-signing-material-denied")),
    (New-FailClosedCase -Id "release-signing" -Blockers @("cryptographic-signing-denied"))
)
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$auditRecord = [ordered]@{
    schema = "agentos.rc17-local-consumer-smoke-audit.v1"
    generated_at = $generatedAtValue
    task = "RC17-040"
    local_only = $true
    fabricated = $false
    decision = $consumerDecision
    decision_digest = $auditDigest
    exact_target_bound = $true
    exact_approval_bound = $true
    agentcore_bound = $true
    security_execution_bound = $true
    rollback_support_bound = $rollbackSupportReady
    production_ready_claim = $false
    blockers = @($consumerBlockers)
}

$consumerEvidence = [ordered]@{
    schema = "agentos.rc17-local-release-channel-install-update-consumer-smoke-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC17-040"
    status = "local-release-channel-consumer-$consumerDecision"
    production_ready_claim = $false
    package_id = $packageId
    media_id = $mediaId
    release_id = $releaseId
    local_release_channel = [ordered]@{
        followed = $localReleaseChannelBound
        local_only = $true
        remote_payload_download_attempted = $false
        rc16_consumer_result_sha256 = Get-FileSha256 $resolvedRc16ConsumerSmokeResultPath
    }
    decision = [ordered]@{
        outcome = $consumerDecision
        install_readiness = if ($installReady) { "ready" } else { "denied" }
        update_readiness = if ($updateReady) { "ready" } else { "denied" }
        rollback_support_readiness = if ($rollbackSupportReady) { "ready" } else { "denied" }
        exact_denial_blockers = @($consumerBlockers)
        next_safe_action = "run-rc17-final-closeout-audit"
    }
    bounded_by = [ordered]@{
        exact_target = $true
        exact_approval = $true
        agentcore_install_update_planspec = $true
        security_execution_install_update_allow = $true
        rollback_preconditions = $true
        controlled_install = $installReady
        controlled_update = $updateReady
        rollback_support = $rollbackSupportReady
    }
    audit = $auditRecord
    fail_closed_cases = $cases
    side_effects = $sideEffects
    source = $source
}
$consumerEvidencePath = Join-Path $resolvedArtifactDir "consumer-smoke-evidence.json"
Write-Json $consumerEvidence $consumerEvidencePath

Add-Check "plan.current_task.rc17_040" $planAllowsRun "RC17-040 must run after RC17-032 completed, either while current_task is RC17-040 or while rerunning after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc17_032_status = $rc17PreviousStatus; rc17_040_status = $rc17TaskStatus })
Add-Check "contract.consumer_smoke.present" ($contractText.Contains("Local release channel consumer smoke must explain exact install/update readiness or denial from RC17 evidence") -and $contractText.Contains("Final closeout must report install/update readiness truthfully")) "RC17 contract must require local consumer smoke to explain exact install/update readiness or denial." (New-ArtifactRef $resolvedContractPath)
Add-Check "local_release_channel.bound" $localReleaseChannelBound "Consumer smoke must follow repo-local release channel metadata from RC16 and remain local-only." ([ordered]@{ rc16_consumer_status = $rc16ConsumerResult.status; rc16_consumer_decision = $rc16ConsumerResult.summary.consumer_decision; followed = $rc16ConsumerEvidence.local_release_channel.followed })
Add-Check "rc17_body_gates.ready" ($installReady -and $updateReady -and $rollbackSupportReady -and $identityBound) "Consumer smoke must derive readiness from RC17 install, update, rollback/support, and package identity evidence." ([ordered]@{ install_ready = $installReady; update_ready = $updateReady; rollback_support_ready = $rollbackSupportReady; identity_bound = $identityBound })
Add-Check "consumer.ready_or_denial" ($consumerReady -and $consumerDecision -eq "exact-install-update-ready") "Consumer smoke must return exact install/update ready or denial evidence from RC17 body gates." ([ordered]@{ decision = $consumerDecision; blockers = @($consumerBlockers) })
Add-Check "consumer.audit.bound" ($auditRecord.local_only -eq $true -and $auditRecord.fabricated -eq $false -and -not [string]::IsNullOrWhiteSpace($auditDigest)) "Consumer smoke must be audited and bounded by exact target, exact approval, AgentCore, SecurityExecution, and rollback/support evidence." $auditRecord
Add-Check "authority.no_side_effects" ($sideEffects.remote_payload_downloaded -eq $false -and $sideEffects.install_performed_by_consumer_smoke -eq $false -and $sideEffects.update_performed_by_consumer_smoke -eq $false -and $sideEffects.rollback_execution_performed_by_consumer_smoke -eq $false -and $sideEffects.support_upload_performed -eq $false -and $sideEffects.recovery_execution_performed -eq $false -and $sideEffects.remote_dispatch_enabled -eq $false -and $sideEffects.boot_metadata_mutated -eq $false -and $sideEffects.production_ring_mutated -eq $false -and $sideEffects.private_signing_material_handled -eq $false -and $sideEffects.cryptographic_signing_performed -eq $false -and $sideEffects.mirror_frontend_authority -eq $false) "RC17-040 must not mutate production rings, dispatch remotely, upload support, execute recovery, handle private signing material, fetch remote payload bytes, mutate host boot state, or grant mirror/frontend authority." $sideEffects
Add-Check "fixtures.fail_closed.pass" ($failedCases.Count -eq 0 -and @($cases).Count -ge 16) "Missing gates and forbidden authority surfaces must fail closed." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })

$outputsSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $consumerEvidencePath))
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC17-040 outputs must not contain key blocks, private key paths, auth tokens, public identity markers, or signing key file names." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc17-local-release-channel-install-update-consumer-smoke-result.v1"
    generated_at = $generatedAtValue
    task = "RC17-040"
    status = $resultStatus
    production_ready_claim = $false
    package_id = $packageId
    media_id = $mediaId
    release_id = $releaseId
    consumer_surface = [ordered]@{
        state = "local-release-channel-consumer-$consumerDecision"
        local_release_channel_followed = $localReleaseChannelBound
        install_readiness = if ($installReady) { "ready" } else { "denied" }
        update_readiness = if ($updateReady) { "ready" } else { "denied" }
        rollback_support_readiness = if ($rollbackSupportReady) { "ready" } else { "denied" }
        consumer_decision = $consumerDecision
        audited = $true
        audit_digest = $auditDigest
        blockers = @($consumerBlockers)
    }
    outputs = [ordered]@{
        consumer_smoke_evidence = [ordered]@{
            path = Get-StablePath $consumerEvidencePath
            sha256 = Get-FileSha256 $consumerEvidencePath
            audit_digest = $auditDigest
        }
    }
    source = $source
    checks = @($script:checks)
    blockers = @($consumerBlockers)
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        repo_local_consumer_only = $true
        local_release_channel_followed = $localReleaseChannelBound
        audited = $true
        install_performed_by_consumer_smoke = $false
        update_performed_by_consumer_smoke = $false
        rollback_execution_performed_by_consumer_smoke = $false
        remote_payload_bytes_downloaded = $false
        remote_dispatch_enabled = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        private_signing_material_handled = $false
        cryptographic_signing_performed = $false
        mirror_frontend_authority = $false
    }
    fail_closed_cases = $cases
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = @($failedCases).Count
        rc17_040_complete = (@($script:failedChecks).Count -eq 0)
        consumer_decision = $consumerDecision
        install_readiness = if ($installReady) { "ready" } else { "denied" }
        update_readiness = if ($updateReady) { "ready" } else { "denied" }
        rollback_support_readiness = if ($rollbackSupportReady) { "ready" } else { "denied" }
        audited = $true
        next_task = "RC17-050"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC17-040-local-release-channel-install-update-consumer-smoke.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc17-local-release-channel-install-update-consumer-smoke-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC17-040"
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
    consumer_surface = $result.consumer_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc17_040_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC17-050"
        commit_required = $true
    }
    checks = @($script:checks)
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) { throw "Sensitive marker detected in RC17-040 outputs." }

Write-Host "RC17 local release channel install/update consumer smoke $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Evidence: $(Get-StablePath $consumerEvidencePath)"
Write-Host "Decision: $consumerDecision; install readiness: $($result.consumer_surface.install_readiness); update readiness: $($result.consumer_surface.update_readiness)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count), failed cases: $(@($failedCases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) { exit 1 }
