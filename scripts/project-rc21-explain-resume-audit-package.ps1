param(
    [string]$ArtifactDir = ".workflow/artifacts/rc21-explain-resume-audit-package",
    [string]$WorkflowDir = ".workflow/active/WFS-20260610-agentos-production-distro-rc21",
    [string]$PlanPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc21/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260610-agentos-production-distro-rc21/docs/rc21-local-transactional-lifecycle-authority-contract.md",
    [string]$DryRunPlanResultPath = ".workflow/artifacts/rc21-dry-run-execution-plan/result.json",
    [string]$DryRunPlanPath = ".workflow/artifacts/rc21-dry-run-execution-plan/dry-run-execution-plan.json",
    [string]$DryRunAcceptanceResultPath = ".workflow/artifacts/rc21-transactional-dry-run-acceptance/result.json",
    [string]$DryRunAcceptanceEvidencePath = ".workflow/artifacts/rc21-transactional-dry-run-acceptance/dry-run-acceptance-evidence.json",
    [string]$DryRunAuditRecordPath = ".workflow/artifacts/rc21-transactional-dry-run-acceptance/dry-run-audit-record.json",
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
    $markers = @(
        ("BEGIN " + "PRIVATE" + " KEY"),
        ("BEGIN " + "PUBLIC" + " KEY"),
        ("Authorization:" + " Bearer"),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ("." + "local-release-authority/" + "private"),
        ("/etc/" + "aios-signer/" + "private"),
        ("signing" + "-key." + "p" + "em"),
        ("." + "p" + "em"),
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

function New-DecisionExplanation {
    param([Parameter(Mandatory = $true)][string]$OperationId)
    $planOperation = @($script:dryRunPlan.operations | Where-Object { $_.operation -eq $OperationId })[0]
    $accepted = @($script:acceptanceEvidence.accepted_operations | Where-Object { $_.operation -eq $OperationId })[0]
    if ($null -ne $accepted) {
        return [ordered]@{
            operation = $OperationId
            decision = "dry-run-accepted-no-effect"
            user_visible_summary = "$OperationId is accepted for dry-run only from bound transaction, snapshot, and audit evidence."
            evidence_chain = @(
                "rc21-dry-run-execution-plan",
                "rc21-transactional-dry-run-acceptance",
                "rc21-dry-run-audit-record"
            )
            transaction_id = [string]$accepted.transaction_id
            resume_checkpoint_id = [string]$accepted.resume_checkpoint.checkpoint_id
            audit_sink_id = [string]$accepted.audit_sink.audit_sink_id
            audit_record_id = [string]$script:auditRecord.dry_run_audit_record_id
            denial_reason = "Lifecycle effect execution remains a later gate."
            effect_preparation_performed = $false
            lifecycle_effect_performed = $false
        }
    }
    return [ordered]@{
        operation = $OperationId
        decision = "deferred-after-dry-run-plan"
        user_visible_summary = "$OperationId remains planned but deferred until its drill gate."
        evidence_chain = @("rc21-dry-run-execution-plan")
        transaction_id = [string]$planOperation.transaction_id
        resume_checkpoint_id = [string]$planOperation.resume_checkpoint.checkpoint_id
        audit_sink_id = [string]$planOperation.audit_sink.audit_sink_id
        audit_record_id = [string]$script:auditRecord.dry_run_audit_record_id
        denial_reason = "RC21-021 only accepted install/update dry-run; repair/reinstall is later."
        effect_preparation_performed = $false
        lifecycle_effect_performed = $false
    }
}

function New-ResumeProjection {
    param([Parameter(Mandatory = $true)][string]$OperationId)
    $explanation = @($script:decisionExplanations | Where-Object { $_.operation -eq $OperationId })[0]
    return [ordered]@{
        operation = $OperationId
        checkpoint_id = [string]$explanation.resume_checkpoint_id
        transaction_id = [string]$explanation.transaction_id
        projection_only = $true
        resume_executable = $false
        host_effect_authority = $false
        endpoint_authority = $false
        shell_output_authority = $false
        tui_authority = $false
        model_replay_authority = $false
        next_gate_required = if ($OperationId -in @("install", "update")) { "RC21-030/RC21-031 drill gates before effects" } else { "RC21-030 repair/reinstall drill" }
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
$resolvedDryRunPlanResultPath = Resolve-RepoPath $DryRunPlanResultPath
$resolvedDryRunPlanPath = Resolve-RepoPath $DryRunPlanPath
$resolvedDryRunAcceptanceResultPath = Resolve-RepoPath $DryRunAcceptanceResultPath
$resolvedDryRunAcceptanceEvidencePath = Resolve-RepoPath $DryRunAcceptanceEvidencePath
$resolvedDryRunAuditRecordPath = Resolve-RepoPath $DryRunAuditRecordPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$dryRunPlanResult = Read-Json $resolvedDryRunPlanResultPath
$script:dryRunPlan = Read-Json $resolvedDryRunPlanPath
$dryRunAcceptanceResult = Read-Json $resolvedDryRunAcceptanceResultPath
$script:acceptanceEvidence = Read-Json $resolvedDryRunAcceptanceEvidencePath
$script:auditRecord = Read-Json $resolvedDryRunAuditRecordPath

$previousTaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC21-021"
$currentTaskStatus = Get-TaskStatus -Plan $plan -TaskId "RC21-022"
$planAllowsRun = (
    $plan.status -eq "active" -and
    $previousTaskStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC21-022" -and ($currentTaskStatus -eq "pending" -or $currentTaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC21-030" -and $currentTaskStatus -eq "completed")
    )
)

$contractAllowsExplainResumeAudit = (
    $contractText.Contains("Bind the user-visible explain, resume, and audit package") -and
    $contractText.Contains("Consumer smoke can report transactional local lifecycle readiness") -and
    $contractText.Contains("endpoint reachability") -and
    $contractText.Contains("TUI projection")
)

$dryRunReady = (
    $dryRunPlanResult.status -eq "passed" -and
    $dryRunPlanResult.summary.rc21_020_complete -eq $true -and
    $script:dryRunPlan.executable -eq $false -and
    @($script:dryRunPlan.operations).Count -eq 3
)
$acceptanceReady = (
    $dryRunAcceptanceResult.status -eq "passed" -and
    $dryRunAcceptanceResult.summary.rc21_021_complete -eq $true -and
    $script:acceptanceEvidence.status -eq "transactional-dry-run-accepted-no-effect" -and
    $script:acceptanceEvidence.no_effect_surface.effect_preparation_performed -eq $false -and
    @($script:acceptanceEvidence.accepted_operations).Count -eq 2
)
$auditReady = (
    $script:auditRecord.status -eq "dry-run-audit-record-local-only" -and
    $script:auditRecord.journal_sink_files_written -eq $false -and
    @($script:auditRecord.entries).Count -eq 2
)

$source = [ordered]@{
    rc21_plan = New-ArtifactRef $resolvedPlanPath $plan "rc21 workflow plan"
    rc21_authority_contract = [ordered]@{
        role = "rc21 authority contract"
        path = Get-StablePath $resolvedContractPath
        sha256 = Get-FileSha256 $resolvedContractPath
        size_bytes = (Get-Item -LiteralPath $resolvedContractPath).Length
        present = $true
    }
    rc21_dry_run_plan_result = New-ArtifactRef $resolvedDryRunPlanResultPath $dryRunPlanResult "rc21 dry-run plan result"
    rc21_dry_run_plan = New-ArtifactRef $resolvedDryRunPlanPath $script:dryRunPlan "rc21 dry-run plan"
    rc21_dry_run_acceptance_result = New-ArtifactRef $resolvedDryRunAcceptanceResultPath $dryRunAcceptanceResult "rc21 dry-run acceptance result"
    rc21_dry_run_acceptance_evidence = New-ArtifactRef $resolvedDryRunAcceptanceEvidencePath $script:acceptanceEvidence "rc21 dry-run acceptance evidence"
    rc21_dry_run_audit_record = New-ArtifactRef $resolvedDryRunAuditRecordPath $script:auditRecord "rc21 dry-run audit record"
}

$operations = @("install", "update", "repair-reinstall")
$script:decisionExplanations = @()
foreach ($operation in $operations) {
    $script:decisionExplanations += New-DecisionExplanation $operation
}
$resumeProjections = @()
foreach ($operation in $operations) {
    $resumeProjections += New-ResumeProjection $operation
}

$packageMaterial = [ordered]@{
    schema = "agentos.rc21-explain-resume-audit-material.v1"
    task = "RC21-022"
    dry_run_execution_plan_id = [string]$script:dryRunPlan.dry_run_execution_plan_id
    dry_run_acceptance_id = [string]$script:acceptanceEvidence.dry_run_acceptance_id
    dry_run_audit_record_id = [string]$script:auditRecord.dry_run_audit_record_id
    explanations = @($script:decisionExplanations | ForEach-Object {
        [ordered]@{
            operation = $_.operation
            decision = $_.decision
            transaction_id = $_.transaction_id
            checkpoint_id = $_.resume_checkpoint_id
        }
    })
}
$explainResumeAuditPackageId = "sha256:$(Get-StringSha256 (Get-JsonText $packageMaterial))"

$package = [ordered]@{
    schema = "agentos.rc21-explain-resume-audit-package.v1"
    generated_at = $generatedAtValue
    task = "RC21-022"
    status = "explain-resume-audit-package-bound-projection-only"
    production_ready_claim = $false
    consumer_ready_claim = $false
    explain_resume_audit_package_id = $explainResumeAuditPackageId
    dry_run_execution_plan_id = [string]$script:dryRunPlan.dry_run_execution_plan_id
    dry_run_acceptance_id = [string]$script:acceptanceEvidence.dry_run_acceptance_id
    dry_run_audit_record_id = [string]$script:auditRecord.dry_run_audit_record_id
    redacted = $true
    local_only = $true
    decision_explanations = $script:decisionExplanations
    resume_projections = $resumeProjections
    audit_chain = [ordered]@{
        local_only = $true
        redacted = $true
        audit_record_id = [string]$script:auditRecord.dry_run_audit_record_id
        journal_sink_files_written = $false
        entries = @($script:auditRecord.entries | ForEach-Object {
            [ordered]@{
                operation = $_.operation
                transaction_id = $_.transaction_id
                audit_sink_id = $_.audit_sink_id
                decision = $_.decision
                effect_preparation_performed = $false
                lifecycle_effect_performed = $false
            }
        })
    }
    authority = [ordered]@{
        package_authority = $true
        resume_execution_authority = $false
        endpoint_authority = $false
        shell_output_authority = $false
        tui_authority = $false
        model_replay_authority = $false
        support_upload_authority = $false
        recovery_execution_authority = $false
        remote_dispatch_authority = $false
        host_rootfs_mutation_authority = $false
        active_artifact_set_mutation_authority = $false
        production_ring_mutation_authority = $false
        signer_authority = $false
        object_storage_authority = $false
    }
    source = $source
}
$packagePath = Join-Path $resolvedArtifactDir "explain-resume-audit-package.json"
Write-Json $package $packagePath

$explanationsReady = (
    @($package.decision_explanations).Count -eq 3 -and
    @($package.decision_explanations | Where-Object {
        [string]::IsNullOrWhiteSpace([string]$_.user_visible_summary) -or
        [string]::IsNullOrWhiteSpace([string]$_.transaction_id) -or
        [string]::IsNullOrWhiteSpace([string]$_.resume_checkpoint_id) -or
        [string]::IsNullOrWhiteSpace([string]$_.audit_sink_id)
    }).Count -eq 0
)
$resumeProjectionSafe = (
    @($package.resume_projections).Count -eq 3 -and
    @($package.resume_projections | Where-Object {
        $_.projection_only -ne $true -or
        $_.resume_executable -ne $false -or
        $_.host_effect_authority -ne $false -or
        $_.endpoint_authority -ne $false -or
        $_.shell_output_authority -ne $false -or
        $_.tui_authority -ne $false -or
        $_.model_replay_authority -ne $false
    }).Count -eq 0
)
$auditChainReady = (
    $package.audit_chain.local_only -eq $true -and
    $package.audit_chain.redacted -eq $true -and
    $package.audit_chain.journal_sink_files_written -eq $false -and
    @($package.audit_chain.entries).Count -eq 2 -and
    @($package.audit_chain.entries | Where-Object { $_.effect_preparation_performed -ne $false -or $_.lifecycle_effect_performed -ne $false }).Count -eq 0
)
$authoritySafe = (
    $package.authority.resume_execution_authority -eq $false -and
    $package.authority.endpoint_authority -eq $false -and
    $package.authority.shell_output_authority -eq $false -and
    $package.authority.tui_authority -eq $false -and
    $package.authority.model_replay_authority -eq $false -and
    $package.authority.support_upload_authority -eq $false -and
    $package.authority.recovery_execution_authority -eq $false -and
    $package.authority.remote_dispatch_authority -eq $false -and
    $package.authority.host_rootfs_mutation_authority -eq $false -and
    $package.authority.production_ring_mutation_authority -eq $false -and
    $package.production_ready_claim -eq $false
)

Add-Check "plan.current_task.rc21_022" $planAllowsRun "RC21-022 must run after RC21-021 completed, with current_task set to RC21-022 or during an idempotent rerun." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc21_021_status = $previousTaskStatus; rc21_022_status = $currentTaskStatus })
Add-Check "contract.explain_resume_audit.present" $contractAllowsExplainResumeAudit "RC21-022 must consume the explain/resume/audit and non-authority contract language." ([ordered]@{ path = Get-StablePath $resolvedContractPath; sha256 = Get-FileSha256 $resolvedContractPath })
Add-Check "dry_run.ready" $dryRunReady "Explain/resume/audit package must bind completed dry-run execution plan evidence." ([ordered]@{ result_status = $dryRunPlanResult.status; operations = @($script:dryRunPlan.operations).Count; executable = $script:dryRunPlan.executable })
Add-Check "acceptance.ready" $acceptanceReady "Explain/resume/audit package must bind completed dry-run acceptance evidence." ([ordered]@{ result_status = $dryRunAcceptanceResult.status; accepted_operations = @($script:acceptanceEvidence.accepted_operations).Count; effect_preparation = $script:acceptanceEvidence.no_effect_surface.effect_preparation_performed })
Add-Check "audit.ready" $auditReady "Explain/resume/audit package must bind local dry-run audit records." ([ordered]@{ audit_status = $script:auditRecord.status; entries = @($script:auditRecord.entries).Count; journal_sink_files_written = $script:auditRecord.journal_sink_files_written })
Add-Check "explanations.user_visible" $explanationsReady "Package must explain each local lifecycle decision from bound evidence, transaction journal, dry-run plan, and audit record." (@($package.decision_explanations | ForEach-Object { [ordered]@{ operation = $_.operation; decision = $_.decision; transaction_id = $_.transaction_id; checkpoint_id = $_.resume_checkpoint_id } }))
Add-Check "resume.projection_only" $resumeProjectionSafe "Resume checkpoints must be projection-only and cannot execute host effects or claim endpoint, shell, TUI, or model authority." (@($package.resume_projections | ForEach-Object { [ordered]@{ operation = $_.operation; projection_only = $_.projection_only; resume_executable = $_.resume_executable; endpoint_authority = $_.endpoint_authority; tui_authority = $_.tui_authority } }))
Add-Check "audit.local_redacted" $auditChainReady "Audit chain must remain local-only, redacted, and non-executing." ([ordered]@{ audit_record_id = $package.audit_chain.audit_record_id; entries = @($package.audit_chain.entries).Count; journal_sink_files_written = $package.audit_chain.journal_sink_files_written })
Add-Check "authority.no_broadening" $authoritySafe "Package must not grant resume execution, endpoint, shell, TUI, model, support upload, recovery execution, remote dispatch, host, production, signer, object storage, or GA authority." $package.authority

$outputsSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $packagePath))
Add-Check "outputs.secret_safe" $outputsSecretSafe "Package must be redacted and contain no private material, tokens, raw secrets, support upload payloads, or recovery execution authority." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc21-explain-resume-audit-package-result.v1"
    generated_at = $generatedAtValue
    task = "RC21-022"
    status = $resultStatus
    production_ready_claim = $false
    consumer_ready_claim = $false
    explain_resume_audit_package_id = $explainResumeAuditPackageId
    dry_run_execution_plan_id = [string]$script:dryRunPlan.dry_run_execution_plan_id
    dry_run_acceptance_id = [string]$script:acceptanceEvidence.dry_run_acceptance_id
    dry_run_audit_record_id = [string]$script:auditRecord.dry_run_audit_record_id
    outputs = [ordered]@{
        explain_resume_audit_package = [ordered]@{
            path = Get-StablePath $packagePath
            sha256 = Get-FileSha256 $packagePath
            explain_resume_audit_package_id = $explainResumeAuditPackageId
            decision_count = @($package.decision_explanations).Count
            resume_projection_count = @($package.resume_projections).Count
        }
    }
    explain_resume_audit_surface = [ordered]@{
        state = "explain-resume-audit-package-bound-projection-only"
        package_bound = ($resultStatus -eq "passed")
        local_only = $true
        redacted = $true
        decision_count = @($package.decision_explanations).Count
        resume_projection_count = @($package.resume_projections).Count
        resume_executable = $false
        endpoint_authority = $false
        shell_output_authority = $false
        tui_authority = $false
        model_replay_authority = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        host_rootfs_mutation_allowed = $false
        production_ring_mutation_allowed = $false
    }
    source = $source
    checks = @($script:checks)
    invariants = [ordered]@{
        aios_body_only = $true
        production_ready_claim = $false
        consumer_ready_claim = $false
        explain_resume_audit_package_written = $true
        package_redacted = $true
        resume_executable = $false
        endpoint_authority = $false
        shell_output_authority = $false
        tui_authority = $false
        model_replay_authority = $false
        effect_preparation_performed = $false
        install_performed = $false
        update_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        signer_authority = $false
        object_storage_authority = $false
        private_signing_material_handled = $false
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        rc21_022_complete = (@($script:failedChecks).Count -eq 0)
        explain_resume_audit_package_id = $explainResumeAuditPackageId
        decision_count = @($package.decision_explanations).Count
        resume_projection_count = @($package.resume_projections).Count
        resume_executable = $false
        endpoint_authority = $false
        shell_output_authority = $false
        tui_authority = $false
        model_replay_authority = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        host_rootfs_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        next_task = "RC21-030"
    }
}
$resultPath = Join-Path $resolvedArtifactDir "result.json"
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC21-022-explain-resume-audit-package.json"
$taskEvidence = [ordered]@{
    schema = "agentos.rc21-explain-resume-audit-package-task-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC21-022"
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
    explain_resume_audit_surface = $result.explain_resume_audit_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc21_022_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC21-030"
        commit_required = $true
    }
    checks = @($script:checks)
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $resultPath),
    (Get-Content -Raw -LiteralPath $taskEvidencePath)
)
if (-not $finalSecretSafe) { throw "Sensitive marker detected in RC21-022 outputs." }

Write-Host "RC21 explain resume audit package $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Explain resume audit package: $(Get-StablePath $packagePath)"
Write-Host "Decisions: $(@($package.decision_explanations).Count); resume projections: $(@($package.resume_projections).Count); resume executable: false"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) { exit 1 }
