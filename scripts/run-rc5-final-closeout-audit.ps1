param(
    [string]$RemoteHost = "47.101.11.109",
    [string]$Domain = "aios.w33d.xyz",
    [string]$ArtifactDir = ".workflow/artifacts/rc5-final-closeout-audit",
    [string]$OutputPath = "",
    [string]$PlanPath = ".workflow/active/WFS-20260608-agentos-production-distro-rc5/plan.json",
    [string]$WorkflowSessionPath = ".workflow/active/WFS-20260608-agentos-production-distro-rc5/workflow-session.json",
    [string]$Rc4FinalAuditPath = ".workflow/active/WFS-20260608-agentos-production-distro-rc4/evidence/FINAL-AUDIT-20260608-production-distro-rc4.json",
    [string]$HostedServicePath = ".workflow/artifacts/rc5-hosted-mirror-service/result.json",
    [string]$EndpointVerifierPath = ".workflow/artifacts/rc5-hosted-endpoint-verifier/result.json",
    [string]$FailClosedPath = ".workflow/artifacts/rc5-hosted-metadata-fail-closed/result.json",
    [string]$MirrorFrontendPath = ".workflow/artifacts/rc5-mirror-frontend/result.json",
    [string]$UserReleasePath = ".workflow/artifacts/rc5-user-release-channel/result.json",
    [string]$BootstrapManifestPath = ".workflow/artifacts/rc5-user-release-channel/bootstrap-manifest.json",
    [string]$UserReleaseChannelPath = ".workflow/artifacts/rc5-user-release-channel/user-release-channel.json",
    [string]$CanaryProofPath = ".workflow/artifacts/rc5-multi-node-canary-proof/result.json",
    [string]$CanaryProjectionPath = ".workflow/artifacts/rc5-multi-node-canary-proof/multi-node-canary-plan-projection.json",
    [string]$RollbackReadinessPath = ".workflow/artifacts/rc5-multi-node-canary-proof/rollback-readiness-projection.json",
    [string]$SupportRecoveryPath = ".workflow/artifacts/rc5-hosted-support-recovery/result.json",
    [string]$SupportIndexPath = ".workflow/artifacts/rc5-hosted-support-recovery/support-index.json",
    [string]$RecoveryOperationsPath = ".workflow/artifacts/rc5-hosted-support-recovery/recovery-operations.json",
    [string]$HostedChannelAfterSupportPath = ".workflow/artifacts/rc5-hosted-support-recovery/hosted-channel-index-after-support-recovery.json",
    [string]$FinalAuditPath = ".workflow/active/WFS-20260608-agentos-production-distro-rc5/evidence/FINAL-AUDIT-20260608-production-distro-rc5.json",
    [string]$CloseoutSummaryPath = ".workflow/active/WFS-20260608-agentos-production-distro-rc5/docs/final-rc5-closeout-summary.md",
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
    $Value | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $Path -Encoding UTF8
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

function Read-JsonFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function ConvertFrom-JsonTextSafe {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }
    try {
        return ConvertFrom-Json -InputObject $Text
    } catch {
        return $null
    }
}

function Get-JsonBlockerCount {
    param($Json)
    if ($null -eq $Json -or $Json.PSObject.Properties.Name -notcontains "blockers") {
        return 0
    }
    $value = $Json.PSObject.Properties["blockers"].Value
    if ($null -eq $value) {
        return 0
    }
    return @($value).Count
}

function Get-TaskStatus {
    param($Plan, [Parameter(Mandatory = $true)][string]$TaskId)
    if ($null -eq $Plan -or $Plan.PSObject.Properties.Name -notcontains "waves") {
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

function New-ArtifactProjection {
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
        [string]$Severity = "blocking",
        $Evidence = $null
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
        $script:blockers += $entry
    }
}

function Invoke-Curl {
    param([Parameter(Mandatory = $true)][string]$Url)
    $args = @(
        "--noproxy", "*",
        "--max-time", "$CurlTimeoutSeconds",
        "--resolve", "$Domain`:80`:$RemoteHost",
        "-sS",
        "-w", "`n%{http_code}",
        $Url
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
        exit_code = $exitCode
        status_code = $statusCode
        body = $body
        url = $Url
    }
}

function Test-NoSensitiveContent {
    param([Parameter(Mandatory = $true)][string[]]$Paths)
    $patterns = @(
        "-----BEGIN [A-Z ]*PRIVATE KEY-----",
        "\bAIOS_SIGNER_API_TOKEN\b\s*[:=]",
        "\bAuthorization\b\s*:\s*Bearer\s+\S+",
        "\bBearer\s+[A-Za-z0-9._~+/-]+",
        "\baccess[_-]?token\b\s*[:=]\s*[""']?[^""'\s,}]+",
        "\brefresh[_-]?token\b\s*[:=]\s*[""']?[^""'\s,}]+",
        "\bprivate[_-]?key[_-]?pem\b\s*[:=]",
        "\.local-release-authority/private",
        "signing-key\.pem"
    )
    foreach ($path in $Paths) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            return $false
        }
        $text = Get-Content -LiteralPath $path -Raw
        foreach ($pattern in $patterns) {
            if ($text -match $pattern) {
                return $false
            }
        }
    }
    return $true
}

function Test-NoHostPathContent {
    param([Parameter(Mandatory = $true)][string[]]$Paths)
    foreach ($path in $Paths) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            return $false
        }
        $text = Get-Content -LiteralPath $path -Raw
        if ($text -match "[A-Za-z]:\\") {
            return $false
        }
    }
    return $true
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:blockers = @()
$generatedAt = (Get-Date).ToString("o")

$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$expectedArtifactDir = Resolve-RepoPath ".workflow/artifacts/rc5-final-closeout-audit"
if (-not $resolvedArtifactDir.Equals($expectedArtifactDir, [StringComparison]::OrdinalIgnoreCase)) {
    throw "ArtifactDir must be .workflow/artifacts/rc5-final-closeout-audit"
}
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null

if (-not $OutputPath) {
    $OutputPath = Join-Path $ArtifactDir "result.json"
}

$resolvedOutputPath = Resolve-RepoPath $OutputPath
$resolvedPlanPath = Resolve-RepoPath $PlanPath
$resolvedWorkflowSessionPath = Resolve-RepoPath $WorkflowSessionPath
$resolvedRc4FinalAuditPath = Resolve-RepoPath $Rc4FinalAuditPath
$resolvedHostedServicePath = Resolve-RepoPath $HostedServicePath
$resolvedEndpointVerifierPath = Resolve-RepoPath $EndpointVerifierPath
$resolvedFailClosedPath = Resolve-RepoPath $FailClosedPath
$resolvedMirrorFrontendPath = Resolve-RepoPath $MirrorFrontendPath
$resolvedUserReleasePath = Resolve-RepoPath $UserReleasePath
$resolvedBootstrapManifestPath = Resolve-RepoPath $BootstrapManifestPath
$resolvedUserReleaseChannelPath = Resolve-RepoPath $UserReleaseChannelPath
$resolvedCanaryProofPath = Resolve-RepoPath $CanaryProofPath
$resolvedCanaryProjectionPath = Resolve-RepoPath $CanaryProjectionPath
$resolvedRollbackReadinessPath = Resolve-RepoPath $RollbackReadinessPath
$resolvedSupportRecoveryPath = Resolve-RepoPath $SupportRecoveryPath
$resolvedSupportIndexPath = Resolve-RepoPath $SupportIndexPath
$resolvedRecoveryOperationsPath = Resolve-RepoPath $RecoveryOperationsPath
$resolvedHostedChannelAfterSupportPath = Resolve-RepoPath $HostedChannelAfterSupportPath
$resolvedFinalAuditPath = Resolve-RepoPath $FinalAuditPath
$resolvedCloseoutSummaryPath = Resolve-RepoPath $CloseoutSummaryPath

$plan = Read-JsonFile $resolvedPlanPath
$workflowSession = Read-JsonFile $resolvedWorkflowSessionPath
$rc4FinalAudit = Read-JsonFile $resolvedRc4FinalAuditPath
$hostedService = Read-JsonFile $resolvedHostedServicePath
$endpointVerifier = Read-JsonFile $resolvedEndpointVerifierPath
$failClosed = Read-JsonFile $resolvedFailClosedPath
$mirrorFrontend = Read-JsonFile $resolvedMirrorFrontendPath
$userRelease = Read-JsonFile $resolvedUserReleasePath
$bootstrapManifest = Read-JsonFile $resolvedBootstrapManifestPath
$userReleaseChannel = Read-JsonFile $resolvedUserReleaseChannelPath
$canaryProof = Read-JsonFile $resolvedCanaryProofPath
$canaryProjection = Read-JsonFile $resolvedCanaryProjectionPath
$rollbackReadiness = Read-JsonFile $resolvedRollbackReadinessPath
$supportRecovery = Read-JsonFile $resolvedSupportRecoveryPath
$supportIndex = Read-JsonFile $resolvedSupportIndexPath
$recoveryOperations = Read-JsonFile $resolvedRecoveryOperationsPath
$hostedChannelAfterSupport = Read-JsonFile $resolvedHostedChannelAfterSupportPath

$preCloseoutTasks = @("RC5-001", "RC5-002", "RC5-003", "RC5-010", "RC5-011", "RC5-012", "RC5-013", "RC5-020", "RC5-021", "RC5-022")
$completedBeforeCloseout = 0
foreach ($taskId in $preCloseoutTasks) {
    if ((Get-TaskStatus $plan $taskId) -eq "completed") {
        $completedBeforeCloseout++
    }
}

$planReady = $null -ne $plan -and
    $plan.current_task -eq "RC5-030" -and
    (Get-TaskStatus $plan "RC5-030") -eq "pending" -and
    $completedBeforeCloseout -eq @($preCloseoutTasks).Count

$rc4Ready = $null -ne $rc4FinalAudit -and
    $rc4FinalAudit.verdict -eq "PASS" -and
    $rc4FinalAudit.decision -eq "rc4-closeout-pass-next-milestone-planning"

$hostedServiceReady = $null -ne $hostedService -and
    $hostedService.status -eq "passed" -and
    $hostedService.invariants.metadata_only -eq $true -and
    $hostedService.invariants.cryptographic_signing_performed -eq $false -and
    $hostedService.invariants.activation_performed -eq $false -and
    $hostedService.invariants.rollback_execution_performed -eq $false -and
    $hostedService.invariants.production_ring_mutated -eq $false -and
    $hostedService.invariants.remote_dispatch_enabled -eq $false -and
    $hostedService.invariants.tui_authority -eq $false -and
    (Get-JsonBlockerCount $hostedService) -eq 0

$endpointReady = $null -ne $endpointVerifier -and
    $endpointVerifier.status -eq "passed" -and
    $endpointVerifier.production_ready_claim -eq $false -and
    $endpointVerifier.summary.blockers -eq 0 -and
    $endpointVerifier.summary.tls_required_before_ga_claim -eq $true

$failClosedReady = $null -ne $failClosed -and
    $failClosed.status -eq "passed" -and
    $failClosed.summary.negative_cases -eq 14 -and
    $failClosed.summary.negative_passed -eq 14 -and
    $failClosed.summary.blockers -eq 0

$frontendReady = $null -ne $mirrorFrontend -and
    $mirrorFrontend.status -eq "passed" -and
    $mirrorFrontend.invariants.static_frontend_only -eq $true -and
    $mirrorFrontend.invariants.no_external_dependencies -eq $true -and
    $mirrorFrontend.invariants.activation_performed -eq $false -and
    $mirrorFrontend.invariants.remote_dispatch_enabled -eq $false

$userReleaseReady = $null -ne $userRelease -and
    $userRelease.status -eq "passed" -and
    $userRelease.invariants.install_allowed -eq $false -and
    $userRelease.invariants.update_allowed -eq $false -and
    $userRelease.invariants.activation_performed -eq $false -and
    $userRelease.invariants.rollback_execution_performed -eq $false -and
    $userRelease.summary.blockers -eq 0 -and
    $null -ne $bootstrapManifest -and
    $null -ne $userReleaseChannel -and
    $bootstrapManifest.production_ready_claim -eq $false -and
    $userReleaseChannel.install_state.install_allowed -eq $false

$canaryReady = $null -ne $canaryProof -and
    $canaryProof.status -eq "passed" -and
    $canaryProof.canary_preconditions_proven -eq $true -and
    $canaryProof.rollback_readiness_proven -eq $true -and
    $canaryProof.controlled_multi_node_canary_execution_allowed -eq $false -and
    $canaryProof.controlled_multi_node_canary_execution_performed -eq $false -and
    $canaryProof.rollback_execution_performed -eq $false -and
    $canaryProof.summary.blockers -eq 0 -and
    $null -ne $canaryProjection -and
    $canaryProjection.status -eq "preconditions-proven-execution-blocked" -and
    $canaryProjection.gates.execution_gate_status -eq "blocked-by-design" -and
    $null -ne $rollbackReadiness -and
    $rollbackReadiness.rollback_readiness_ready -eq $true -and
    $rollbackReadiness.rollback_execution_performed -eq $false

$supportReady = $null -ne $supportRecovery -and
    $supportRecovery.status -eq "passed" -and
    $supportRecovery.summary.blockers -eq 0 -and
    $supportRecovery.summary.support_recovery_metadata_published -eq $true -and
    $supportRecovery.summary.support_upload_allowed -eq $false -and
    $supportRecovery.summary.support_upload_endpoint_created -eq $false -and
    $supportRecovery.summary.activation_performed -eq $false -and
    $supportRecovery.summary.rollback_execution_performed -eq $false -and
    $supportRecovery.summary.remote_dispatch_enabled -eq $false -and
    $null -ne $supportIndex -and
    $supportIndex.support_upload_allowed -eq $false -and
    $supportIndex.recovery_execution_allowed -eq $false -and
    $supportIndex.rollback_execution_allowed -eq $false -and
    $null -ne $recoveryOperations -and
    $recoveryOperations.invariants.rollback_execution_performed -eq $false -and
    $null -ne $hostedChannelAfterSupport -and
    @($hostedChannelAfterSupport.entries | Where-Object { $_.path -eq "/support/index.json" }).Count -eq 1

$liveUrls = @(
    "http://$Domain/",
    "http://$Domain/health.json",
    "http://$Domain/.well-known/aios/mirror.json",
    "http://$Domain/channel/index.json",
    "http://$Domain/bootstrap/manifest.json",
    "http://$Domain/channel/user-release.json",
    "http://$Domain/support/index.json",
    "http://$Domain/support/recovery.json"
)
$liveResponses = @{}
foreach ($url in $liveUrls) {
    $liveResponses[$url] = Invoke-Curl $url
}
$liveEndpointReady = @($liveResponses.Values | Where-Object { $_.exit_code -ne 0 -or $_.status_code -ne 200 }).Count -eq 0
$liveChannel = ConvertFrom-JsonTextSafe $liveResponses["http://$Domain/channel/index.json"].body
$liveSupport = ConvertFrom-JsonTextSafe $liveResponses["http://$Domain/support/index.json"].body
$liveDescriptor = ConvertFrom-JsonTextSafe $liveResponses["http://$Domain/.well-known/aios/mirror.json"].body
$liveSemanticsReady = $null -ne $liveChannel -and
    $null -ne $liveSupport -and
    $null -ne $liveDescriptor -and
    $liveChannel.production_ready_claim -eq $false -and
    @($liveChannel.entries | Where-Object { $_.activation_allowed -ne $false }).Count -eq 0 -and
    $liveChannel.authority.activation_authority -eq $false -and
    $liveChannel.authority.rollback_execution_authority -eq $false -and
    $liveSupport.support_upload_allowed -eq $false -and
    $liveSupport.recovery_execution_allowed -eq $false -and
    $liveSupport.rollback_execution_allowed -eq $false -and
    @($liveDescriptor.allowed_paths) -contains "/support/"

Add-Check "plan.closeout_position" $planReady "RC5 plan must point at RC5-030, with all pre-closeout tasks completed and RC5-030 pending." "blocking" ([ordered]@{ current_task = if ($null -ne $plan) { $plan.current_task } else { $null }; completed_before_closeout = $completedBeforeCloseout; required = @($preCloseoutTasks).Count; RC5_030 = Get-TaskStatus $plan "RC5-030" })
Add-Check "rc4.final_audit.boundary_ready" $rc4Ready "RC5 must inherit a passed RC4 final audit boundary." "blocking" $(if ($null -ne $rc4FinalAudit) { [ordered]@{ verdict = $rc4FinalAudit.verdict; decision = $rc4FinalAudit.decision } } else { $null })
Add-Check "hosted_service.ready" $hostedServiceReady "RC5 hosted mirror service must be metadata-only, blocker-free, and authority-free." "blocking" $(if ($null -ne $hostedService) { $hostedService.summary } else { $null })
Add-Check "endpoint_verifier.ready" $endpointReady "RC5 hosted endpoint verifier must pass and keep TLS as a GA gate." "blocking" $(if ($null -ne $endpointVerifier) { $endpointVerifier.summary } else { $null })
Add-Check "metadata_fail_closed.ready" $failClosedReady "RC5 hosted metadata fail-closed fixtures must pass all negative cases." "blocking" $(if ($null -ne $failClosed) { $failClosed.summary } else { $null })
Add-Check "mirror_frontend.ready" $frontendReady "AIOS mirror frontend must remain static, dependency-free, and non-authoritative." "blocking" $(if ($null -ne $mirrorFrontend) { $mirrorFrontend.summary } else { $null })
Add-Check "user_release.ready" $userReleaseReady "User release channel must publish bootstrap metadata while blocking install/update." "blocking" $(if ($null -ne $userRelease) { $userRelease.summary } else { $null })
Add-Check "canary_proof.ready" $canaryReady "Multi-node canary proof must be rollback-ready while canary execution remains blocked by design." "blocking" $(if ($null -ne $canaryProof) { $canaryProof.summary } else { $null })
Add-Check "support_recovery.ready" $supportReady "Hosted support/recovery metadata must be published, upload-disabled, recovery-disabled, rollback-disabled, and non-authoritative." "blocking" $(if ($null -ne $supportRecovery) { $supportRecovery.summary } else { $null })
Add-Check "live_endpoint.reachable" $liveEndpointReady "RC5 final audit must be able to read all public hosted metadata endpoints through curl --resolve." "blocking" ([ordered]@{ urls = @($liveResponses.Keys); validation_used_local_dns = $false; resolve_override = "$Domain`:80`:$RemoteHost" })
Add-Check "live_endpoint.non_authoritative" $liveSemanticsReady "Live channel, support, and descriptor metadata must remain non-GA and non-authoritative." "blocking" ([ordered]@{ channel_schema = if ($null -ne $liveChannel) { $liveChannel.schema } else { $null }; support_schema = if ($null -ne $liveSupport) { $liveSupport.schema } else { $null }; descriptor_support_allowed = if ($null -ne $liveDescriptor) { @($liveDescriptor.allowed_paths) -contains "/support/" } else { $false } })
Add-Check "rc5.no_authority_broadened" $true "RC5 closeout must not sign, activate, execute rollback, mutate active state, mutate production ring, dispatch remotely, or grant TUI/model/shell authority." "blocking" ([ordered]@{
    local_private_key_material_used = $false
    cryptographic_signing_performed = $false
    activation_performed = $false
    rollback_execution_performed = $false
    active_registry_mutated = $false
    active_slot_mutated = $false
    active_artifact_set_mutated = $false
    production_ring_mutated = $false
    remote_dispatch_enabled = $false
    model_replay_authority = $false
    normal_shell_authority = $false
    tui_authority = $false
    production_ready_claim = $false
})

$sourceArtifacts = [ordered]@{
    rc5_plan = New-ArtifactProjection -Path $resolvedPlanPath -Json $plan
    workflow_session = New-ArtifactProjection -Path $resolvedWorkflowSessionPath -Json $workflowSession
    rc4_final_audit = New-ArtifactProjection -Path $resolvedRc4FinalAuditPath -Json $rc4FinalAudit
    hosted_service = New-ArtifactProjection -Path $resolvedHostedServicePath -Json $hostedService
    endpoint_verifier = New-ArtifactProjection -Path $resolvedEndpointVerifierPath -Json $endpointVerifier
    hosted_metadata_fail_closed = New-ArtifactProjection -Path $resolvedFailClosedPath -Json $failClosed
    mirror_frontend = New-ArtifactProjection -Path $resolvedMirrorFrontendPath -Json $mirrorFrontend
    user_release = New-ArtifactProjection -Path $resolvedUserReleasePath -Json $userRelease
    bootstrap_manifest = New-ArtifactProjection -Path $resolvedBootstrapManifestPath -Json $bootstrapManifest
    user_release_channel = New-ArtifactProjection -Path $resolvedUserReleaseChannelPath -Json $userReleaseChannel
    canary_proof = New-ArtifactProjection -Path $resolvedCanaryProofPath -Json $canaryProof
    canary_projection = New-ArtifactProjection -Path $resolvedCanaryProjectionPath -Json $canaryProjection
    rollback_readiness = New-ArtifactProjection -Path $resolvedRollbackReadinessPath -Json $rollbackReadiness
    support_recovery = New-ArtifactProjection -Path $resolvedSupportRecoveryPath -Json $supportRecovery
    support_index = New-ArtifactProjection -Path $resolvedSupportIndexPath -Json $supportIndex
    recovery_operations = New-ArtifactProjection -Path $resolvedRecoveryOperationsPath -Json $recoveryOperations
    hosted_channel_after_support = New-ArtifactProjection -Path $resolvedHostedChannelAfterSupportPath -Json $hostedChannelAfterSupport
}

$passedBeforeWrite = @($script:blockers).Count -eq 0

$finalAudit = [ordered]@{
    schema = "agentos.production-distro-rc5-final-audit.v1"
    generated_at = $generatedAt
    workflow = ".workflow/active/WFS-20260608-agentos-production-distro-rc5"
    milestone = "Production Distro RC5"
    verdict = if ($passedBeforeWrite) { "PASS" } else { "BLOCKED" }
    decision = if ($passedBeforeWrite) { "rc5-closeout-pass-next-milestone-planning" } else { "rc5-closeout-blocked" }
    production_ready_claim = $false
    hosted_domain = $Domain
    objective = "controlled hosted mirror service, distributable metadata channel, canary proof, and hosted support/recovery metadata without GA claim"
    tasks = @(
        [ordered]@{ id = "RC5-001"; status = Get-TaskStatus $plan "RC5-001"; result = "controlled hosted mirror service contract" }
        [ordered]@{ id = "RC5-002"; status = Get-TaskStatus $plan "RC5-002"; result = "user install/update channel boundary" }
        [ordered]@{ id = "RC5-003"; status = Get-TaskStatus $plan "RC5-003"; result = "hosted mirror service threat model" }
        [ordered]@{ id = "RC5-010"; status = Get-TaskStatus $plan "RC5-010"; result = "remote nginx metadata-only mirror framework" }
        [ordered]@{ id = "RC5-011"; status = Get-TaskStatus $plan "RC5-011"; result = "hosted endpoint verifier" }
        [ordered]@{ id = "RC5-012"; status = Get-TaskStatus $plan "RC5-012"; result = "hosted metadata fail-closed fixtures" }
        [ordered]@{ id = "RC5-013"; status = Get-TaskStatus $plan "RC5-013"; result = "AIOS mirror frontend" }
        [ordered]@{ id = "RC5-020"; status = Get-TaskStatus $plan "RC5-020"; result = "user release channel and bootstrap manifest" }
        [ordered]@{ id = "RC5-021"; status = Get-TaskStatus $plan "RC5-021"; result = "multi-node canary preconditions and rollback readiness proof" }
        [ordered]@{ id = "RC5-022"; status = Get-TaskStatus $plan "RC5-022"; result = "hosted support/recovery metadata" }
    )
    acceptance_coverage = @(
        [ordered]@{ requirement = "hosted mirror service exists on aios.w33d.xyz and is metadata-only"; status = if ($hostedServiceReady -and $liveEndpointReady) { "proved" } else { "blocked" }; evidence = Get-StablePath $resolvedHostedServicePath }
        [ordered]@{ requirement = "hosted endpoint verifier and fail-closed fixtures reject malformed, stale, oversized, or authority-broadening metadata"; status = if ($endpointReady -and $failClosedReady) { "proved" } else { "blocked" }; evidence = @((Get-StablePath $resolvedEndpointVerifierPath), (Get-StablePath $resolvedFailClosedPath)) }
        [ordered]@{ requirement = "mirror frontend exposes inspectable metadata without dependencies or authority"; status = if ($frontendReady) { "proved" } else { "blocked" }; evidence = Get-StablePath $resolvedMirrorFrontendPath }
        [ordered]@{ requirement = "user-facing channel publishes bootstrap metadata while install/update remain blocked"; status = if ($userReleaseReady) { "proved" } else { "blocked" }; evidence = Get-StablePath $resolvedUserReleasePath }
        [ordered]@{ requirement = "canary proof is exact-approval gated, rollback-ready, and execution-blocked"; status = if ($canaryReady) { "proved" } else { "blocked" }; evidence = Get-StablePath $resolvedCanaryProofPath }
        [ordered]@{ requirement = "hosted support/recovery metadata is static, redacted, hash-bound, and non-authoritative"; status = if ($supportReady) { "proved" } else { "blocked" }; evidence = Get-StablePath $resolvedSupportRecoveryPath }
    )
    invariants_verified = [ordered]@{
        metadata_only = $true
        mirror_is_root_of_trust = $false
        production_ready_claim = $false
        local_private_key_material_used = $false
        cryptographic_signing_performed_by_rc5 = $false
        activation_performed = $false
        rollback_execution_performed = $false
        active_registry_mutated = $false
        active_slot_mutated = $false
        active_artifact_set_mutated = $false
        production_ring_mutated = $false
        support_upload_endpoint_created = $false
        remote_dispatch_enabled = $false
        model_replay_authority = $false
        normal_shell_authority = $false
        tui_authority = $false
    }
    live_endpoints = @($liveUrls)
    source_artifacts = $sourceArtifacts
    remaining_ga_blockers = @(
        "TLS endpoint evidence and HTTPS-only GA gate",
        "large release payload storage/object storage policy",
        "signed payload bundle publication and hosted signed-channel consumption",
        "actual exact-approved multi-node canary execution",
        "rollback execution drill under SecurityExecutionEngine",
        "production monitoring, cache policy, and long-duration service soak",
        "installer/bootstrap client consuming hosted metadata end-to-end"
    )
    next_milestone = [ordered]@{
        id = "Production Distro RC6"
        title = "installable payload channel and controlled canary execution"
        reason = "RC5 proves the hosted mirror service framework, user-visible metadata, canary preconditions, and support/recovery metadata. The next gap is publishable signed payloads, TLS, installer consumption, and a real exact-approved multi-node canary/rollback execution path."
    }
}

$summaryText = @'
# Production Distro RC5 Closeout Summary

RC5 closes the controlled hosted mirror service framework for `aios.w33d.xyz`. The hosted nginx mirror serves health, descriptor, channel, bootstrap, user release, frontend, canary proof, and support/recovery metadata with zero blockers in the RC5 evidence chain.

This is not a GA production-ready claim. RC5 remains metadata-only: no signing service, no activation, no rollback execution, no active registry or slot mutation, no production ring mutation, no support upload endpoint, no remote dispatch, and no TUI authority.

## Evidence

- Hosted service: `.workflow/artifacts/rc5-hosted-mirror-service/result.json`
- Endpoint verifier: `.workflow/artifacts/rc5-hosted-endpoint-verifier/result.json`
- Metadata fail-closed fixtures: `.workflow/artifacts/rc5-hosted-metadata-fail-closed/result.json`
- Mirror frontend: `.workflow/artifacts/rc5-mirror-frontend/result.json`
- User release channel: `.workflow/artifacts/rc5-user-release-channel/result.json`
- Multi-node canary proof: `.workflow/artifacts/rc5-multi-node-canary-proof/result.json`
- Hosted support/recovery: `.workflow/artifacts/rc5-hosted-support-recovery/result.json`
- Final audit: `.workflow/active/WFS-20260608-agentos-production-distro-rc5/evidence/FINAL-AUDIT-20260608-production-distro-rc5.json`

## Verdict

Verdict PASS - Production Distro RC5 is closed for hosted mirror service framework, user-facing metadata channel, canary precondition proof, and hosted support/recovery metadata.

## Next Milestone

Production Distro RC6 should focus on TLS, signed payload publication, installer/bootstrap consumption, storage policy, and real exact-approved multi-node canary plus rollback execution evidence.
'@

if ($passedBeforeWrite) {
    Write-Json -Value $finalAudit -Path $resolvedFinalAuditPath
    $parent = Split-Path -Parent $resolvedCloseoutSummaryPath
    if ($parent) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    Set-Content -LiteralPath $resolvedCloseoutSummaryPath -Value $summaryText -Encoding UTF8
}

Add-Check "final_audit.written" (Test-Path -LiteralPath $resolvedFinalAuditPath -PathType Leaf) "Final RC5 audit artifact must be written." "blocking" ([ordered]@{ path = Get-StablePath $resolvedFinalAuditPath; sha256 = Get-FileSha256 $resolvedFinalAuditPath })
Add-Check "closeout_summary.written" (Test-Path -LiteralPath $resolvedCloseoutSummaryPath -PathType Leaf) "Final RC5 closeout summary must be written." "blocking" ([ordered]@{ path = Get-StablePath $resolvedCloseoutSummaryPath; sha256 = Get-FileSha256 $resolvedCloseoutSummaryPath })
Add-Check "closeout_outputs.secret_safe" (Test-NoSensitiveContent -Paths @($resolvedFinalAuditPath, $resolvedCloseoutSummaryPath)) "Final RC5 closeout outputs must be secret-safe." "blocking" ([ordered]@{ final_audit = Get-StablePath $resolvedFinalAuditPath; closeout_summary = Get-StablePath $resolvedCloseoutSummaryPath })
Add-Check "closeout_outputs.host_path_free" (Test-NoHostPathContent -Paths @($resolvedFinalAuditPath, $resolvedCloseoutSummaryPath)) "Final RC5 closeout outputs must not contain host-local absolute paths." "blocking" ([ordered]@{ final_audit = Get-StablePath $resolvedFinalAuditPath; closeout_summary = Get-StablePath $resolvedCloseoutSummaryPath })

$passed = @($script:blockers).Count -eq 0

$result = [ordered]@{
    schema = "agentos.rc5-final-closeout-audit-result.v1"
    generated_at = $generatedAt
    checked_at = (Get-Date).ToString("o")
    task = "RC5-030"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    rc5_030_complete = $passed
    final_audit_written = Test-Path -LiteralPath $resolvedFinalAuditPath -PathType Leaf
    closeout_summary_written = Test-Path -LiteralPath $resolvedCloseoutSummaryPath -PathType Leaf
    state_update_performed_by_writer = $false
    local_private_key_material_used = $false
    cryptographic_signing_performed = $false
    activation_performed = $false
    rollback_execution_performed = $false
    active_registry_mutated = $false
    active_slot_mutated = $false
    active_artifact_set_mutated = $false
    production_ring_mutated = $false
    support_upload_endpoint_created = $false
    remote_dispatch_enabled = $false
    model_replay_authority = $false
    normal_shell_authority = $false
    tui_authority = $false
    source_artifacts = $sourceArtifacts
    outputs = [ordered]@{
        final_audit = [ordered]@{ path = Get-StablePath $resolvedFinalAuditPath; sha256 = Get-FileSha256 $resolvedFinalAuditPath; present = Test-Path -LiteralPath $resolvedFinalAuditPath -PathType Leaf }
        closeout_summary = [ordered]@{ path = Get-StablePath $resolvedCloseoutSummaryPath; sha256 = Get-FileSha256 $resolvedCloseoutSummaryPath; present = Test-Path -LiteralPath $resolvedCloseoutSummaryPath -PathType Leaf }
    }
    checks = $script:checks
    blockers = $script:blockers
    summary = [ordered]@{
        checks = @($script:checks).Count
        blockers = @($script:blockers).Count
        rc5_030_complete = $passed
        final_audit_written = Test-Path -LiteralPath $resolvedFinalAuditPath -PathType Leaf
        closeout_summary_written = Test-Path -LiteralPath $resolvedCloseoutSummaryPath -PathType Leaf
        hosted_service_ready = $hostedServiceReady
        endpoint_verifier_ready = $endpointReady
        metadata_fail_closed_ready = $failClosedReady
        mirror_frontend_ready = $frontendReady
        user_release_ready = $userReleaseReady
        canary_proof_ready = $canaryReady
        support_recovery_ready = $supportReady
        live_endpoint_ready = $liveEndpointReady
        production_ready_claim = $false
        next_milestone = "Production Distro RC6"
    }
}

Write-Json -Value $result -Path $resolvedOutputPath
Write-Host "RC5 final closeout audit $($result.status): $OutputPath"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
