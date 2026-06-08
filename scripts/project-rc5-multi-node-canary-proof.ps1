param(
    [string]$RemoteHost = "47.101.11.109",
    [string]$Domain = "aios.w33d.xyz",
    [string]$ArtifactDir = ".workflow/artifacts/rc5-multi-node-canary-proof",
    [string]$OutputPath = "",
    [string]$Rc5PlanPath = ".workflow/active/WFS-20260608-agentos-production-distro-rc5/plan.json",
    [string]$Rc5HostedServicePath = ".workflow/artifacts/rc5-hosted-mirror-service/result.json",
    [string]$Rc5EndpointVerifierPath = ".workflow/artifacts/rc5-hosted-endpoint-verifier/result.json",
    [string]$Rc5FailClosedPath = ".workflow/artifacts/rc5-hosted-metadata-fail-closed/result.json",
    [string]$Rc5FrontendPath = ".workflow/artifacts/rc5-mirror-frontend/result.json",
    [string]$Rc5UserReleasePath = ".workflow/artifacts/rc5-user-release-channel/result.json",
    [string]$Rc5BootstrapManifestPath = ".workflow/artifacts/rc5-user-release-channel/bootstrap-manifest.json",
    [string]$Rc5UserReleaseChannelPath = ".workflow/artifacts/rc5-user-release-channel/user-release-channel.json",
    [string]$Rc5HostedChannelPath = ".workflow/artifacts/rc5-user-release-channel/hosted-channel-index-after-user-release.json",
    [string]$Rc4FinalAuditPath = ".workflow/active/WFS-20260608-agentos-production-distro-rc4/evidence/FINAL-AUDIT-20260608-production-distro-rc4.json",
    [string]$Rc4StagedRolloutSmokePath = ".workflow/artifacts/rc4-staged-fleet-ring-rollout-smoke-rollback-drill/result.json",
    [string]$Rc4StagedRolloutProjectionPath = ".workflow/artifacts/rc4-staged-fleet-ring-rollout-smoke-rollback-drill/staged-rollout-plan-projection.json",
    [string]$Rc4RollbackProjectionPath = ".workflow/artifacts/rc4-staged-fleet-ring-rollout-smoke-rollback-drill/rollback-drill-projection.json",
    [string]$FleetRolloutAuthorityPath = ".workflow/artifacts/release/fleet-rollout-authority.json",
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

function Get-JsonText {
    param([Parameter(Mandatory = $true)]$Value)
    return ($Value | ConvertTo-Json -Depth 100)
}

function Get-StringSha256 {
    param([Parameter(Mandatory = $true)][string]$Value)
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Value)
    $hash = [Security.Cryptography.SHA256]::HashData($bytes)
    return ([BitConverter]::ToString($hash)).Replace("-", "").ToLowerInvariant()
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

function New-Projection {
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

$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$expectedArtifactDir = Resolve-RepoPath ".workflow/artifacts/rc5-multi-node-canary-proof"
if (-not $resolvedArtifactDir.Equals($expectedArtifactDir, [StringComparison]::OrdinalIgnoreCase)) {
    throw "ArtifactDir must be .workflow/artifacts/rc5-multi-node-canary-proof"
}
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null

if (-not (Has-Value $OutputPath)) {
    $OutputPath = Join-Path $ArtifactDir "result.json"
}

$resolvedOutputPath = Resolve-RepoPath $OutputPath
$canaryProjectionPath = Join-Path $resolvedArtifactDir "multi-node-canary-plan-projection.json"
$rollbackProjectionPath = Join-Path $resolvedArtifactDir "rollback-readiness-projection.json"

$resolvedRc5PlanPath = Resolve-RepoPath $Rc5PlanPath
$resolvedRc5HostedServicePath = Resolve-RepoPath $Rc5HostedServicePath
$resolvedRc5EndpointVerifierPath = Resolve-RepoPath $Rc5EndpointVerifierPath
$resolvedRc5FailClosedPath = Resolve-RepoPath $Rc5FailClosedPath
$resolvedRc5FrontendPath = Resolve-RepoPath $Rc5FrontendPath
$resolvedRc5UserReleasePath = Resolve-RepoPath $Rc5UserReleasePath
$resolvedRc5BootstrapManifestPath = Resolve-RepoPath $Rc5BootstrapManifestPath
$resolvedRc5UserReleaseChannelPath = Resolve-RepoPath $Rc5UserReleaseChannelPath
$resolvedRc5HostedChannelPath = Resolve-RepoPath $Rc5HostedChannelPath
$resolvedRc4FinalAuditPath = Resolve-RepoPath $Rc4FinalAuditPath
$resolvedRc4StagedRolloutSmokePath = Resolve-RepoPath $Rc4StagedRolloutSmokePath
$resolvedRc4StagedRolloutProjectionPath = Resolve-RepoPath $Rc4StagedRolloutProjectionPath
$resolvedRc4RollbackProjectionPath = Resolve-RepoPath $Rc4RollbackProjectionPath
$resolvedFleetRolloutAuthorityPath = Resolve-RepoPath $FleetRolloutAuthorityPath

$rc5Plan = Read-JsonFile $resolvedRc5PlanPath
$rc5HostedService = Read-JsonFile $resolvedRc5HostedServicePath
$rc5EndpointVerifier = Read-JsonFile $resolvedRc5EndpointVerifierPath
$rc5FailClosed = Read-JsonFile $resolvedRc5FailClosedPath
$rc5Frontend = Read-JsonFile $resolvedRc5FrontendPath
$rc5UserRelease = Read-JsonFile $resolvedRc5UserReleasePath
$bootstrapManifest = Read-JsonFile $resolvedRc5BootstrapManifestPath
$userReleaseChannel = Read-JsonFile $resolvedRc5UserReleaseChannelPath
$hostedChannel = Read-JsonFile $resolvedRc5HostedChannelPath
$rc4FinalAudit = Read-JsonFile $resolvedRc4FinalAuditPath
$rc4StagedSmoke = Read-JsonFile $resolvedRc4StagedRolloutSmokePath
$rc4StagedProjection = Read-JsonFile $resolvedRc4StagedRolloutProjectionPath
$rc4RollbackProjection = Read-JsonFile $resolvedRc4RollbackProjectionPath
$fleetAuthority = Read-JsonFile $resolvedFleetRolloutAuthorityPath

$rc5PlanTaskStatuses = @{}
if ($null -ne $rc5Plan) {
    foreach ($wave in @($rc5Plan.waves)) {
        foreach ($task in @($wave.tasks)) {
            if ($null -ne $task.id) {
                $rc5PlanTaskStatuses[$task.id] = $task.status
            }
        }
    }
}

$hostedChannelResponse = Invoke-Curl "http://$Domain/channel/index.json"
$bootstrapResponse = Invoke-Curl "http://$Domain/bootstrap/manifest.json"
$userChannelResponse = Invoke-Curl "http://$Domain/channel/user-release.json"
$frontendResponse = Invoke-Curl "http://$Domain/"

$hostedChannelLive = ConvertFrom-JsonTextSafe $hostedChannelResponse.body
$bootstrapLive = ConvertFrom-JsonTextSafe $bootstrapResponse.body
$userChannelLive = ConvertFrom-JsonTextSafe $userChannelResponse.body

$rc4FinalAuditHash = Get-FileSha256 $resolvedRc4FinalAuditPath
$rc5HostedServiceHash = Get-FileSha256 $resolvedRc5HostedServicePath
$rc5EndpointVerifierHash = Get-FileSha256 $resolvedRc5EndpointVerifierPath
$rc5FailClosedHash = Get-FileSha256 $resolvedRc5FailClosedPath
$rc5FrontendHash = Get-FileSha256 $resolvedRc5FrontendPath
$rc5UserReleaseHash = Get-FileSha256 $resolvedRc5UserReleasePath
$bootstrapManifestHash = Get-FileSha256 $resolvedRc5BootstrapManifestPath
$userReleaseChannelHash = Get-FileSha256 $resolvedRc5UserReleaseChannelPath
$hostedChannelHash = Get-FileSha256 $resolvedRc5HostedChannelPath
$rc4StagedSmokeHash = Get-FileSha256 $resolvedRc4StagedRolloutSmokePath
$rc4StagedProjectionHash = Get-FileSha256 $resolvedRc4StagedRolloutProjectionPath
$rc4RollbackProjectionHash = Get-FileSha256 $resolvedRc4RollbackProjectionPath
$fleetAuthorityHash = Get-FileSha256 $resolvedFleetRolloutAuthorityPath

$rc5PlanPositionReady = $null -ne $rc5Plan -and
    $rc5Plan.current_task -eq "RC5-021" -and
    $rc5PlanTaskStatuses["RC5-020"] -eq "completed" -and
    $rc5PlanTaskStatuses["RC5-021"] -eq "pending"

$hostedServiceReady = $null -ne $rc5HostedService -and
    $rc5HostedService.status -eq "passed" -and
    $rc5HostedService.production_ready_claim -eq $false -and
    $rc5HostedService.remote.domain -eq $Domain -and
    $rc5HostedService.remote.host -eq $RemoteHost -and
    $rc5HostedService.remote.validation_used_local_dns -eq $false -and
    $rc5HostedService.invariants.metadata_only -eq $true -and
    $rc5HostedService.invariants.large_artifact_storage_deferred -eq $true -and
    $rc5HostedService.invariants.local_private_key_material_used -eq $false -and
    $rc5HostedService.invariants.cryptographic_signing_performed -eq $false -and
    $rc5HostedService.invariants.activation_performed -eq $false -and
    $rc5HostedService.invariants.rollback_execution_performed -eq $false -and
    $rc5HostedService.invariants.active_slot_mutated -eq $false -and
    $rc5HostedService.invariants.production_ring_mutated -eq $false -and
    $rc5HostedService.invariants.remote_dispatch_enabled -eq $false -and
    $rc5HostedService.invariants.tui_authority -eq $false -and
    (Get-JsonBlockerCount $rc5HostedService) -eq 0

$endpointVerifierReady = $null -ne $rc5EndpointVerifier -and
    $rc5EndpointVerifier.status -eq "passed" -and
    $rc5EndpointVerifier.production_ready_claim -eq $false -and
    $rc5EndpointVerifier.summary.blockers -eq 0 -and
    $rc5EndpointVerifier.summary.tls_required_before_ga_claim -eq $true

$failClosedReady = $null -ne $rc5FailClosed -and
    $rc5FailClosed.status -eq "passed" -and
    $rc5FailClosed.summary.negative_cases -eq 14 -and
    $rc5FailClosed.summary.negative_passed -eq 14 -and
    $rc5FailClosed.summary.blockers -eq 0

$frontendReady = $null -ne $rc5Frontend -and
    $rc5Frontend.status -eq "passed" -and
    $rc5Frontend.production_ready_claim -eq $false -and
    $rc5Frontend.invariants.static_frontend_only -eq $true -and
    $rc5Frontend.invariants.no_external_dependencies -eq $true -and
    $rc5Frontend.invariants.activation_performed -eq $false -and
    $rc5Frontend.invariants.rollback_execution_performed -eq $false -and
    $rc5Frontend.invariants.production_ring_mutated -eq $false -and
    $rc5Frontend.invariants.remote_dispatch_enabled -eq $false -and
    $rc5Frontend.invariants.tui_authority -eq $false -and
    $rc5Frontend.summary.blockers -eq 0

$userReleaseReady = $null -ne $rc5UserRelease -and
    $rc5UserRelease.status -eq "passed" -and
    $rc5UserRelease.production_ready_claim -eq $false -and
    $rc5UserRelease.summary.blockers -eq 0 -and
    $rc5UserRelease.invariants.metadata_only -eq $true -and
    $rc5UserRelease.invariants.install_allowed -eq $false -and
    $rc5UserRelease.invariants.update_allowed -eq $false -and
    $rc5UserRelease.invariants.cryptographic_signing_performed -eq $false -and
    $rc5UserRelease.invariants.activation_performed -eq $false -and
    $rc5UserRelease.invariants.rollback_execution_performed -eq $false -and
    $rc5UserRelease.invariants.active_slot_mutated -eq $false -and
    $rc5UserRelease.invariants.production_ring_mutated -eq $false -and
    $rc5UserRelease.invariants.remote_dispatch_enabled -eq $false -and
    $rc5UserRelease.invariants.tui_authority -eq $false

$localChannelArtifactsReady = $null -ne $rc5UserRelease -and
    $rc5UserRelease.local_outputs.bootstrap_manifest.sha256 -eq $bootstrapManifestHash -and
    $rc5UserRelease.local_outputs.user_release_channel.sha256 -eq $userReleaseChannelHash -and
    $rc5UserRelease.local_outputs.hosted_channel_index_after_user_release.sha256 -eq $hostedChannelHash

$bootstrapTrustReady = $null -ne $bootstrapManifest -and
    $bootstrapManifest.production_ready_claim -eq $false -and
    $bootstrapManifest.status -eq "metadata-only-preview" -and
    @($bootstrapManifest.trust_requirements) -contains "rollback-baseline-before-activation" -and
    @($bootstrapManifest.trust_requirements) -contains "exact-operator-approval-before-canary" -and
    @($bootstrapManifest.blockers) -contains "multi-node-canary-execution-pending" -and
    $bootstrapManifest.authority.signing_authority -eq $false -and
    $bootstrapManifest.authority.activation_authority -eq $false -and
    $bootstrapManifest.authority.rollback_execution_authority -eq $false -and
    $bootstrapManifest.authority.production_ring_mutation_authority -eq $false -and
    $bootstrapManifest.authority.tui_authority -eq $false

$userChannelBlockedReady = $null -ne $userReleaseChannel -and
    $userReleaseChannel.production_ready_claim -eq $false -and
    $userReleaseChannel.install_state.bootstrap_metadata_available -eq $true -and
    $userReleaseChannel.install_state.release_payload_available -eq $false -and
    $userReleaseChannel.install_state.install_allowed -eq $false -and
    $userReleaseChannel.install_state.update_allowed -eq $false -and
    @($userReleaseChannel.user_visible_entries | Where-Object { $_.activation_allowed -ne $false }).Count -eq 0

$hostedChannelReady = $null -ne $hostedChannel -and
    $hostedChannel.production_ready_claim -eq $false -and
    $hostedChannel.storage_mode -eq "metadata-only" -and
    $hostedChannel.source_rc4_final_audit_sha256 -eq $rc4FinalAuditHash -and
    @($hostedChannel.entries | Where-Object { $_.activation_allowed -ne $false }).Count -eq 0 -and
    $hostedChannel.authority.signing_authority -eq $false -and
    $hostedChannel.authority.activation_authority -eq $false -and
    $hostedChannel.authority.rollback_execution_authority -eq $false -and
    $hostedChannel.authority.tui_authority -eq $false

$liveEndpointReady = $hostedChannelResponse.exit_code -eq 0 -and
    $bootstrapResponse.exit_code -eq 0 -and
    $userChannelResponse.exit_code -eq 0 -and
    $frontendResponse.exit_code -eq 0 -and
    $hostedChannelResponse.status_code -eq 200 -and
    $bootstrapResponse.status_code -eq 200 -and
    $userChannelResponse.status_code -eq 200 -and
    $frontendResponse.status_code -eq 200 -and
    $null -ne $hostedChannelLive -and
    $null -ne $bootstrapLive -and
    $null -ne $userChannelLive -and
    $hostedChannelLive.production_ready_claim -eq $false -and
    $bootstrapLive.production_ready_claim -eq $false -and
    $userChannelLive.production_ready_claim -eq $false -and
    $hostedChannelLive.authority.activation_authority -eq $false -and
    $bootstrapLive.authority.activation_authority -eq $false -and
    $userChannelLive.install_state.install_allowed -eq $false

$rc4StagedReady = $null -ne $rc4StagedSmoke -and
    $rc4StagedSmoke.status -eq "passed" -and
    $rc4StagedSmoke.rc4_021_complete -eq $true -and
    $rc4StagedSmoke.staged_fleet_ring_rollout_smoke_ready -eq $true -and
    $rc4StagedSmoke.rollback_drill_projection_ready -eq $true -and
    $rc4StagedSmoke.exact_operator_approval_required -eq $true -and
    $rc4StagedSmoke.exact_operator_approval_granted -eq $false -and
    $rc4StagedSmoke.rollout_plan_executable -eq $false -and
    $rc4StagedSmoke.activation_performed -eq $false -and
    $rc4StagedSmoke.rollback_execution_performed -eq $false -and
    $rc4StagedSmoke.production_ring_mutated -eq $false -and
    $rc4StagedSmoke.remote_dispatch_enabled -eq $false -and
    $rc4StagedSmoke.tui_authority -eq $false -and
    (Get-JsonBlockerCount $rc4StagedSmoke) -eq 0

$rc4RolloutProjectionReady = $null -ne $rc4StagedProjection -and
    $rc4StagedProjection.status -eq "approval-required-not-executable" -and
    $rc4StagedProjection.production_ready_claim -eq $false -and
    $rc4StagedProjection.projection_only -eq $true -and
    $rc4StagedProjection.executable -eq $false -and
    $rc4StagedProjection.exact_operator_approval_required -eq $true -and
    $rc4StagedProjection.exact_operator_approval_granted -eq $false -and
    $rc4StagedProjection.gates.approval_gate_status -eq "blocked-pending-exact-operator-approval" -and
    $rc4StagedProjection.gates.execution_gate_status -eq "blocked-by-design"

$rollbackReady = $null -ne $rc4RollbackProjection -and
    $rc4RollbackProjection.status -eq "projected-passed" -and
    $rc4RollbackProjection.production_ready_claim -eq $false -and
    $rc4RollbackProjection.projection_only -eq $true -and
    $rc4RollbackProjection.rollback_execution_performed -eq $false -and
    $rc4RollbackProjection.rollback_verified -eq $true -and
    $rc4RollbackProjection.rollback_previous_equals_restored -eq $true -and
    (Has-Value $rc4RollbackProjection.rollback_baseline_sha256) -and
    $rc4RollbackProjection.previous_active_artifact_set_sha256 -eq $rc4RollbackProjection.restored_active_artifact_set_sha256 -and
    $rc4RollbackProjection.invariants.active_slot_mutated -eq $false -and
    $rc4RollbackProjection.invariants.activation_attempted -eq $false -and
    $rc4RollbackProjection.invariants.remote_dispatch_enabled -eq $false -and
    $rc4RollbackProjection.invariants.tui_authority -eq $false

$rings = if ($null -ne $fleetAuthority) { @($fleetAuthority.rings) } else { @() }
$ringNames = @($rings | ForEach-Object { $_.name })
$canaryRing = @($rings | Where-Object { $_.name -eq "canary" } | Select-Object -First 1)
$stagingRing = @($rings | Where-Object { $_.name -eq "staging" } | Select-Object -First 1)
$productionRing = @($rings | Where-Object { $_.name -eq "production" } | Select-Object -First 1)
$remoteRingsBlocked = $null -ne $canaryRing -and $null -ne $stagingRing -and $null -ne $productionRing -and
    $canaryRing.blocker -eq "remote-fleet-execution-not-enabled" -and
    $stagingRing.blocker -eq "remote-fleet-execution-not-enabled" -and
    $productionRing.blocker -eq "remote-fleet-execution-not-enabled"
$fleetAuthorityReady = $null -ne $fleetAuthority -and
    $fleetAuthority.status -eq "passed" -and
    $fleetAuthority.production_ready_claim -eq $false -and
    $fleetAuthority.authority.execution_authority -eq "AgentCore fleet_rollout PlanSpec + SecurityExecutionEngine" -and
    $fleetAuthority.authority.tui_authority -eq $false -and
    $fleetAuthority.authority.rollout_execution_in_tui -eq $false -and
    $fleetAuthority.authority.rollback_execution_in_tui -eq $false -and
    $fleetAuthority.authority.remote_operator_bypass_allowed -eq $false -and
    $fleetAuthority.authority.normal_shell_rollout_allowed -eq $false -and
    $remoteRingsBlocked

$minimumCanaryNodeCount = 2
$observedCanaryNodeCount = if ($null -ne $canaryRing -and $null -ne $canaryRing.node_count) { [int]$canaryRing.node_count } else { 0 }
$multiNodeEnrollmentBlocked = $observedCanaryNodeCount -lt $minimumCanaryNodeCount
$canaryExecutionBlockedByDesign = $fleetAuthorityReady -and
    $rc4RolloutProjectionReady -and
    $remoteRingsBlocked -and
    $multiNodeEnrollmentBlocked -and
    $rc4StagedProjection.exact_operator_approval_granted -eq $false

$generatedAt = (Get-Date).ToString("o")

$sourceBindings = [ordered]@{
    rc4_final_audit_sha256 = $rc4FinalAuditHash
    rc5_hosted_service_result_sha256 = $rc5HostedServiceHash
    rc5_endpoint_verifier_result_sha256 = $rc5EndpointVerifierHash
    rc5_hosted_metadata_fail_closed_sha256 = $rc5FailClosedHash
    rc5_frontend_result_sha256 = $rc5FrontendHash
    rc5_user_release_result_sha256 = $rc5UserReleaseHash
    bootstrap_manifest_sha256 = $bootstrapManifestHash
    user_release_channel_sha256 = $userReleaseChannelHash
    hosted_channel_index_sha256 = $hostedChannelHash
    rc4_staged_rollout_smoke_sha256 = $rc4StagedSmokeHash
    rc4_staged_rollout_projection_sha256 = $rc4StagedProjectionHash
    rc4_rollback_projection_sha256 = $rc4RollbackProjectionHash
    fleet_rollout_authority_sha256 = $fleetAuthorityHash
    rollback_baseline_sha256 = if ($null -ne $rc4RollbackProjection) { $rc4RollbackProjection.rollback_baseline_sha256 } else { $null }
    previous_active_artifact_set_sha256 = if ($null -ne $rc4RollbackProjection) { $rc4RollbackProjection.previous_active_artifact_set_sha256 } else { $null }
    restored_active_artifact_set_sha256 = if ($null -ne $rc4RollbackProjection) { $rc4RollbackProjection.restored_active_artifact_set_sha256 } else { $null }
    exact_operator_approval_hash = $null
}

$canaryProjection = [ordered]@{
    schema = "agentos.rc5-controlled-multi-node-canary-plan-projection.v1"
    generated_at = $generatedAt
    status = "preconditions-proven-execution-blocked"
    production_ready_claim = $false
    projection_only = $true
    executable = $false
    ring = "canary"
    domain = $Domain
    canary_execution_allowed = $false
    canary_execution_performed = $false
    minimum_canary_node_count_required = $minimumCanaryNodeCount
    observed_canary_node_count = $observedCanaryNodeCount
    canary_target_set = [ordered]@{
        required_minimum_nodes = $minimumCanaryNodeCount
        observed_authority_ring_status = if ($null -ne $canaryRing) { $canaryRing.status } else { $null }
        observed_authority_ring_node_count = $observedCanaryNodeCount
        multi_node_target_set_enrolled = $false
        remote_fleet_execution_enabled = $false
        reason = "RC5 proves hosted metadata, authority, approval, and rollback preconditions; it does not enroll or execute a multi-node canary."
    }
    authority = [ordered]@{
        execution_authority = "AgentCore fleet_rollout PlanSpec + SecurityExecutionEngine"
        mirror_is_root_of_trust = $false
        signing_authority = $false
        activation_authority = $false
        rollback_execution_authority = $false
        production_ring_mutation_authority = $false
        remote_dispatch_authority = $false
        tui_authority = $false
    }
    gates = [ordered]@{
        hosted_mirror_service_ready = $hostedServiceReady
        hosted_endpoint_verifier_ready = $endpointVerifierReady
        hosted_metadata_fail_closed_ready = $failClosedReady
        mirror_frontend_ready = $frontendReady
        user_release_channel_ready = $userReleaseReady
        live_endpoint_metadata_ready = $liveEndpointReady
        rc4_staged_rollout_smoke_ready = $rc4StagedReady
        rc4_rollout_projection_ready = $rc4RolloutProjectionReady
        fleet_authority_ready = $fleetAuthorityReady
        remote_rings_blocked = $remoteRingsBlocked
        rollback_readiness_ready = $rollbackReady
        exact_operator_approval_required = $true
        exact_operator_approval_granted = $false
        multi_node_target_set_enrolled = $false
        execution_gate_status = "blocked-by-design"
    }
    required_before_execution = @(
        "two-or-more-enrolled-canary-target-nodes",
        "remote-fleet-execution-enabled-by-AgentCore-and-SecurityExecutionEngine",
        "exact-operator-approval-hash-bound-to-target-set-policy-rollback-and-revocation",
        "rollback-execution-plan-approved-but-not-mirror-owned",
        "signed-payload-and-revocation-verification",
        "TLS evidence before any GA user claim"
    )
    bindings = $sourceBindings
    invariants = [ordered]@{
        local_private_key_material_used = $false
        cryptographic_signing_performed = $false
        network_upload_performed = $false
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
    }
}

$rollbackProjection = [ordered]@{
    schema = "agentos.rc5-canary-rollback-readiness-projection.v1"
    generated_at = $generatedAt
    status = "rollback-baseline-bound-execution-not-run"
    production_ready_claim = $false
    projection_only = $true
    rollback_readiness_ready = $rollbackReady
    rollback_execution_allowed_by_mirror = $false
    rollback_execution_performed = $false
    rollback_verified = if ($null -ne $rc4RollbackProjection) { $rc4RollbackProjection.rollback_verified } else { $false }
    rollback_previous_equals_restored = if ($null -ne $rc4RollbackProjection) { $rc4RollbackProjection.rollback_previous_equals_restored } else { $false }
    previous_active_artifact_set_sha256 = if ($null -ne $rc4RollbackProjection) { $rc4RollbackProjection.previous_active_artifact_set_sha256 } else { $null }
    restored_active_artifact_set_sha256 = if ($null -ne $rc4RollbackProjection) { $rc4RollbackProjection.restored_active_artifact_set_sha256 } else { $null }
    rollback_baseline_sha256 = if ($null -ne $rc4RollbackProjection) { $rc4RollbackProjection.rollback_baseline_sha256 } else { $null }
    rc4_rollback_projection_sha256 = $rc4RollbackProjectionHash
    required_before_canary_execution = @(
        "rollback-baseline-bound-to-canary-approval",
        "SecurityExecutionEngine-rollback-plan-ready",
        "support-recovery-redaction-evidence-present",
        "mirror-not-allowed-to-execute-rollback"
    )
    blocked_execution_reason = "RC5 proves rollback readiness from RC4 baseline evidence; rollback execution remains a future SecurityExecutionEngine PlanSpec, not a mirror or TUI action."
    invariants = [ordered]@{
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        persistent_state_mutated = $false
        activation_attempted = $false
        rollback_execution_performed = $false
        remote_dispatch_enabled = $false
        model_replay_authority = $false
        normal_shell_authority = $false
        tui_authority = $false
    }
}

Write-Json -Value $canaryProjection -Path $canaryProjectionPath
Write-Json -Value $rollbackProjection -Path $rollbackProjectionPath

$canaryProjectionHash = Get-FileSha256 $canaryProjectionPath
$rollbackReadinessProjectionHash = Get-FileSha256 $rollbackProjectionPath

$projectionBindingReady = $canaryProjection.bindings.rc5_hosted_service_result_sha256 -eq $rc5HostedServiceHash -and
    $canaryProjection.bindings.rc5_endpoint_verifier_result_sha256 -eq $rc5EndpointVerifierHash -and
    $canaryProjection.bindings.rc5_hosted_metadata_fail_closed_sha256 -eq $rc5FailClosedHash -and
    $canaryProjection.bindings.rc5_user_release_result_sha256 -eq $rc5UserReleaseHash -and
    $canaryProjection.bindings.rc4_staged_rollout_smoke_sha256 -eq $rc4StagedSmokeHash -and
    $canaryProjection.bindings.rc4_staged_rollout_projection_sha256 -eq $rc4StagedProjectionHash -and
    $canaryProjection.bindings.rc4_rollback_projection_sha256 -eq $rc4RollbackProjectionHash -and
    $canaryProjection.bindings.fleet_rollout_authority_sha256 -eq $fleetAuthorityHash -and
    $canaryProjection.bindings.rollback_baseline_sha256 -eq $rollbackProjection.rollback_baseline_sha256

$rollbackProjectionBindingReady = $rollbackReady -and
    $rollbackProjection.rollback_readiness_ready -eq $true -and
    $rollbackProjection.rollback_execution_performed -eq $false -and
    $rollbackProjection.previous_active_artifact_set_sha256 -eq $rollbackProjection.restored_active_artifact_set_sha256 -and
    $rollbackProjection.rollback_baseline_sha256 -eq $canaryProjection.bindings.rollback_baseline_sha256

Add-Check "rc5.plan.current_task" $rc5PlanPositionReady "RC5 plan must be positioned at RC5-021 with RC5-020 completed and RC5-021 pending before this proof." "blocking" $(if ($null -ne $rc5Plan) { [ordered]@{ current_task = $rc5Plan.current_task; RC5_020 = $rc5PlanTaskStatuses["RC5-020"]; RC5_021 = $rc5PlanTaskStatuses["RC5-021"] } } else { $null })
Add-Check "rc5.hosted_service.ready" $hostedServiceReady "Hosted mirror service framework must be passed, metadata-only, DNS-override-verified, and authority-free." "blocking" $(if ($null -ne $rc5HostedService) { [ordered]@{ status = $rc5HostedService.status; remote = $rc5HostedService.remote; invariants = $rc5HostedService.invariants; summary = $rc5HostedService.summary } } else { $null })
Add-Check "rc5.endpoint_verifier.ready" $endpointVerifierReady "Hosted endpoint verifier must be passed, non-GA, blocker-free, and record TLS as a GA gate." "blocking" $(if ($null -ne $rc5EndpointVerifier) { $rc5EndpointVerifier.summary } else { $null })
Add-Check "rc5.metadata_fail_closed.ready" $failClosedReady "Hosted metadata fail-closed fixtures must reject all negative cases." "blocking" $(if ($null -ne $rc5FailClosed) { $rc5FailClosed.summary } else { $null })
Add-Check "rc5.frontend.ready" $frontendReady "Mirror frontend must remain static, dependency-free, non-authoritative, and served." "blocking" $(if ($null -ne $rc5Frontend) { [ordered]@{ status = $rc5Frontend.status; invariants = $rc5Frontend.invariants; summary = $rc5Frontend.summary } } else { $null })
Add-Check "rc5.user_release_channel.ready" $userReleaseReady "User release channel projection must be passed, metadata-only, and block install/update." "blocking" $(if ($null -ne $rc5UserRelease) { [ordered]@{ status = $rc5UserRelease.status; invariants = $rc5UserRelease.invariants; summary = $rc5UserRelease.summary } } else { $null })
Add-Check "rc5.local_channel_artifacts.hash_bound" $localChannelArtifactsReady "User release result must remain hash-bound to bootstrap, user channel, and hosted channel local outputs." "blocking" $(if ($null -ne $rc5UserRelease) { $rc5UserRelease.local_outputs } else { $null })
Add-Check "rc5.bootstrap.canary_and_rollback_gates" $bootstrapTrustReady "Bootstrap manifest must require rollback baseline and exact operator approval before canary, while carrying no authority." "blocking" $(if ($null -ne $bootstrapManifest) { [ordered]@{ trust_requirements = $bootstrapManifest.trust_requirements; blockers = $bootstrapManifest.blockers; authority = $bootstrapManifest.authority } } else { $null })
Add-Check "rc5.user_channel.install_blocked" $userChannelBlockedReady "User channel must keep release payload unavailable and install/update blocked." "blocking" $(if ($null -ne $userReleaseChannel) { $userReleaseChannel.install_state } else { $null })
Add-Check "rc5.hosted_channel.no_activation" $hostedChannelReady "Hosted channel must stay metadata-only, hash-bound to RC4 final audit, and advertise no activation/signing/rollback authority." "blocking" $(if ($null -ne $hostedChannel) { [ordered]@{ source_rc4_final_audit_sha256 = $hostedChannel.source_rc4_final_audit_sha256; storage_mode = $hostedChannel.storage_mode; authority = $hostedChannel.authority; entries = $hostedChannel.entries } } else { $null })
Add-Check "rc5.live_endpoint.metadata_readable" $liveEndpointReady "Live hosted endpoints must return HTTP 200 through curl --resolve and remain non-GA/non-authoritative." "blocking" ([ordered]@{ channel_status = $hostedChannelResponse.status_code; bootstrap_status = $bootstrapResponse.status_code; user_channel_status = $userChannelResponse.status_code; frontend_status = $frontendResponse.status_code; validation_used_local_dns = $false; resolve_override = "$Domain`:80`:$RemoteHost" })
Add-Check "rc4.staged_rollout_smoke.ready" $rc4StagedReady "RC4 staged rollout smoke must be passed, exact-approval-gated, non-executable, and mutation-free." "blocking" $(if ($null -ne $rc4StagedSmoke) { $rc4StagedSmoke.summary } else { $null })
Add-Check "rc4.rollout_projection.blocked_by_design" $rc4RolloutProjectionReady "RC4 rollout projection must remain approval-required, non-executable, and blocked by design." "blocking" $(if ($null -ne $rc4StagedProjection) { [ordered]@{ status = $rc4StagedProjection.status; executable = $rc4StagedProjection.executable; gates = $rc4StagedProjection.gates } } else { $null })
Add-Check "fleet_authority.canary_remote_blocked" $fleetAuthorityReady "Fleet authority must remain AgentCore/SecurityExecution-only, with remote canary/staging/production execution blocked." "blocking" ([ordered]@{ ring_order = $ringNames; canary_node_count = $observedCanaryNodeCount; canary_blocker = if ($null -ne $canaryRing) { $canaryRing.blocker } else { $null }; staging_blocker = if ($null -ne $stagingRing) { $stagingRing.blocker } else { $null }; production_blocker = if ($null -ne $productionRing) { $productionRing.blocker } else { $null }; authority = if ($null -ne $fleetAuthority) { $fleetAuthority.authority } else { $null } })
Add-Check "canary.multi_node_enrollment_blocked" $multiNodeEnrollmentBlocked "RC5 proof must require at least two enrolled canary target nodes before execution and must not fake enrollment." "blocking" ([ordered]@{ minimum_required = $minimumCanaryNodeCount; observed_canary_node_count = $observedCanaryNodeCount; multi_node_target_set_enrolled = $false })
Add-Check "canary.execution_blocked_by_design" $canaryExecutionBlockedByDesign "Controlled canary execution must remain blocked until exact approval, multi-node enrollment, and remote fleet execution are enabled through the correct authority path." "blocking" $canaryProjection.gates
Add-Check "canary.projection_hash_bound" $projectionBindingReady "Canary projection must bind RC5 hosted/user-channel evidence, RC4 rollout evidence, rollback readiness, and fleet authority." "blocking" $canaryProjection.bindings
Add-Check "rollback.readiness_projection" $rollbackProjectionBindingReady "Rollback readiness projection must reuse the RC4 rollback baseline, keep previous/restored hashes equal, and execute no rollback." "blocking" ([ordered]@{ rollback_projection_sha256 = $rollbackReadinessProjectionHash; rollback_ready = $rollbackProjection.rollback_readiness_ready; previous = $rollbackProjection.previous_active_artifact_set_sha256; restored = $rollbackProjection.restored_active_artifact_set_sha256; baseline = $rollbackProjection.rollback_baseline_sha256; rollback_execution_performed = $rollbackProjection.rollback_execution_performed })
Add-Check "canary.no_authority_broadened" $true "RC5 canary proof must not sign, upload, activate, execute rollback, mutate registry/slot/ring state, dispatch remotely, or grant TUI/model/shell authority." "blocking" $canaryProjection.invariants

$passed = @($script:blockers).Count -eq 0

$result = [ordered]@{
    schema = "agentos.rc5-multi-node-canary-proof-result.v1"
    generated_at = $generatedAt
    checked_at = (Get-Date).ToString("o")
    task = "RC5-021"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    rc5_021_complete = $passed
    canary_preconditions_proven = $passed
    controlled_multi_node_canary_execution_allowed = $false
    controlled_multi_node_canary_execution_performed = $false
    rollback_readiness_proven = $rollbackReady
    rollback_execution_performed = $false
    exact_operator_approval_required = $true
    exact_operator_approval_granted = $false
    exact_operator_approval_hash = $null
    minimum_canary_node_count_required = $minimumCanaryNodeCount
    observed_canary_node_count = $observedCanaryNodeCount
    remote = [ordered]@{
        host = $RemoteHost
        domain = $Domain
        validation_used_local_dns = $false
        validation_resolve_override = "$Domain`:80`:$RemoteHost"
        remote_mutation_performed = $false
    }
    verified = [ordered]@{
        hosted_mirror_service = $hostedServiceReady
        hosted_endpoint_verifier = $endpointVerifierReady
        hosted_metadata_fail_closed = $failClosedReady
        mirror_frontend = $frontendReady
        user_release_channel = $userReleaseReady
        local_channel_artifacts_hash_bound = $localChannelArtifactsReady
        live_endpoint_metadata = $liveEndpointReady
        rc4_staged_rollout_smoke = $rc4StagedReady
        rc4_rollout_projection = $rc4RolloutProjectionReady
        fleet_rollout_authority = $fleetAuthorityReady
        remote_rings_blocked = $remoteRingsBlocked
        multi_node_enrollment_blocked_until_real_nodes_exist = $multiNodeEnrollmentBlocked
        canary_execution_blocked_by_design = $canaryExecutionBlockedByDesign
        rollback_readiness = $rollbackReady
        rollback_readiness_projection = $rollbackProjectionBindingReady
    }
    bindings = $sourceBindings
    artifacts = [ordered]@{
        multi_node_canary_plan_projection = New-Projection -Path $canaryProjectionPath -Json $canaryProjection
        rollback_readiness_projection = New-Projection -Path $rollbackProjectionPath -Json $rollbackProjection
    }
    source_artifacts = [ordered]@{
        rc5_plan = New-Projection -Path $resolvedRc5PlanPath -Json $rc5Plan
        rc5_hosted_service = New-Projection -Path $resolvedRc5HostedServicePath -Json $rc5HostedService
        rc5_endpoint_verifier = New-Projection -Path $resolvedRc5EndpointVerifierPath -Json $rc5EndpointVerifier
        rc5_hosted_metadata_fail_closed = New-Projection -Path $resolvedRc5FailClosedPath -Json $rc5FailClosed
        rc5_frontend = New-Projection -Path $resolvedRc5FrontendPath -Json $rc5Frontend
        rc5_user_release = New-Projection -Path $resolvedRc5UserReleasePath -Json $rc5UserRelease
        bootstrap_manifest = New-Projection -Path $resolvedRc5BootstrapManifestPath -Json $bootstrapManifest
        user_release_channel = New-Projection -Path $resolvedRc5UserReleaseChannelPath -Json $userReleaseChannel
        hosted_channel_index = New-Projection -Path $resolvedRc5HostedChannelPath -Json $hostedChannel
        rc4_final_audit = New-Projection -Path $resolvedRc4FinalAuditPath -Json $rc4FinalAudit
        rc4_staged_rollout_smoke = New-Projection -Path $resolvedRc4StagedRolloutSmokePath -Json $rc4StagedSmoke
        rc4_staged_rollout_projection = New-Projection -Path $resolvedRc4StagedRolloutProjectionPath -Json $rc4StagedProjection
        rc4_rollback_projection = New-Projection -Path $resolvedRc4RollbackProjectionPath -Json $rc4RollbackProjection
        fleet_rollout_authority = New-Projection -Path $resolvedFleetRolloutAuthorityPath -Json $fleetAuthority
    }
    checks = $script:checks
    blockers = $script:blockers
    remaining_blockers_before_canary_execution = @(
        "two-or-more-enrolled-canary-target-nodes",
        "remote-fleet-execution-not-enabled",
        "exact-operator-approval-not-granted",
        "release-payload-storage-deferred",
        "payload-signature-bundle-deferred",
        "rollback-execution-plan-not-executed",
        "tls-required-before-ga-claim"
    )
    invariants = [ordered]@{
        metadata_only = $true
        local_private_key_material_used = $false
        cryptographic_signing_performed = $false
        network_upload_performed = $false
        remote_mutation_performed = $false
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
    }
    handoff = [ordered]@{
        next_task = "RC5-022"
        rc5_022_consumes = @(
            "multi_node_canary_plan_projection",
            "rollback_readiness_projection",
            "hosted_mirror_service",
            "user_release_channel",
            "hosted_metadata_fail_closed"
        )
    }
    summary = [ordered]@{
        checks = @($script:checks).Count
        blockers = @($script:blockers).Count
        rc5_021_complete = $passed
        canary_preconditions_proven = $passed
        rollback_readiness_proven = $rollbackReady
        canary_execution_allowed = $false
        canary_execution_performed = $false
        projected_ring = "canary"
        minimum_canary_node_count_required = $minimumCanaryNodeCount
        observed_canary_node_count = $observedCanaryNodeCount
        remote_rings_blocked = $remoteRingsBlocked
        exact_operator_approval_required = $true
        exact_operator_approval_granted = $false
        production_ready_claim = $false
        remote_mutation_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        active_slot_mutated = $false
        production_ring_mutated = $false
        remote_dispatch_enabled = $false
        tui_authority = $false
    }
}

Write-Json -Value $result -Path $resolvedOutputPath

$resultSecretSafe = Test-NoSensitiveContent -Paths @($canaryProjectionPath, $rollbackProjectionPath, $resolvedOutputPath)
$resultHostPathFree = Test-NoHostPathContent -Paths @($canaryProjectionPath, $rollbackProjectionPath, $resolvedOutputPath)
if (-not $resultSecretSafe -or -not $resultHostPathFree) {
    $extra = [ordered]@{
        id = "rc5.canary_proof.result_secret_safe"
        status = "failed"
        severity = "blocking"
        message = "RC5 canary proof artifacts must be secret-safe and host-path-free."
        evidence = [ordered]@{
            secret_safe = $resultSecretSafe
            host_path_free = $resultHostPathFree
            path = Get-StablePath $resolvedOutputPath
        }
    }
    $script:checks += $extra
    $script:blockers += $extra
    $result.checks = $script:checks
    $result.blockers = $script:blockers
    $result.status = "blocked"
    $result.rc5_021_complete = $false
    $result.canary_preconditions_proven = $false
    $result.summary.checks = @($script:checks).Count
    $result.summary.blockers = @($script:blockers).Count
    $result.summary.rc5_021_complete = $false
    $result.summary.canary_preconditions_proven = $false
    Write-Json -Value $result -Path $resolvedOutputPath
}

Write-Host "RC5 multi-node canary proof $($result.status): $OutputPath"

if ($FailOnBlocked -and @($script:blockers).Count -gt 0) {
    exit 1
}
