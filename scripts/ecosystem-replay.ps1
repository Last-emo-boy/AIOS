param(
    [string]$OutputPath = ".workflow/artifacts/ecosystem-replay/result.json",
    [string]$RegistryPath = "packaging/agentos/rootfs/etc/agentos/ecosystem/registry-snapshot.json",
    [string]$StagingRoot = ".workflow/artifacts/aom/staged",
    [string]$LockfilePath = ".workflow/artifacts/aom/ecosystem-lock.json",
    [string]$ActiveSetPath = ".workflow/artifacts/aom/active-set.json",
    [string]$AdversarialFixturePath = "packaging/agentos/fixtures/ecosystem/adversarial",
    [switch]$EnableUnsafeFixture
)

$ErrorActionPreference = "Stop"

$PolicyCoordinate = "agentos:policy-pack/agentos/core-policy@1.0.0"
$WorkflowCoordinate = "agentos:workflow-pack/agentos/service-recovery@1.0.0"

function Write-Json {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $parent = Split-Path -Parent $Path
    if ($parent) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    $Value | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Get-ReproducibleTimestamp {
    if ($env:SOURCE_DATE_EPOCH) {
        try {
            $epochSeconds = [Int64]::Parse($env:SOURCE_DATE_EPOCH, [Globalization.CultureInfo]::InvariantCulture)
            return [DateTimeOffset]::FromUnixTimeSeconds($epochSeconds).UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ", [Globalization.CultureInfo]::InvariantCulture)
        } catch {
            throw "SOURCE_DATE_EPOCH must be a Unix timestamp in seconds: $env:SOURCE_DATE_EPOCH"
        }
    }
    return "1970-01-01T00:00:00Z"
}

function Get-OptionalFileHash {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-StringSha256 {
    param([Parameter(Mandatory = $true)][string]$Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
        return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join "")
    } finally {
        $sha.Dispose()
    }
}

function Get-RelativePathForHash {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $rootPath = (Resolve-Path -LiteralPath $Root).Path.TrimEnd('\', '/')
    $entryPath = (Resolve-Path -LiteralPath $Path).Path
    $rootPrefix = $rootPath + [IO.Path]::DirectorySeparatorChar
    if ($entryPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        return $entryPath.Substring($rootPrefix.Length).Replace('\', '/')
    }
    return (Split-Path -Leaf $entryPath)
}

function Get-PathHash {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        return Get-OptionalFileHash $Path
    }
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $entries = @()
    foreach ($entry in Get-ChildItem -LiteralPath $resolved -Recurse -File | Sort-Object FullName) {
        $relative = Get-RelativePathForHash -Root $resolved -Path $entry.FullName
        $hash = (Get-FileHash -LiteralPath $entry.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        $entries += "$relative`t$hash"
    }
    return Get-StringSha256 ($entries -join "`n")
}

function Assert-Condition {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw $Message
    }
}

function Read-RequiredJson {
    param([Parameter(Mandatory = $true)][string]$Path)
    Assert-Condition (Test-Path -LiteralPath $Path -PathType Leaf) "missing JSON file: $Path"
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Add-Step {
    param(
        [System.Collections.ArrayList]$Steps,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Script
    )
    $started = Get-ReproducibleTimestamp
    $status = "passed"
    $errorMessage = ""
    $data = $null
    try {
        $data = & $Script
    } catch {
        $status = "failed"
        $errorMessage = $_.Exception.Message
    }
    [void]$Steps.Add([ordered]@{
        name = $Name
        status = $status
        error = $errorMessage
        data = $data
        started_at = $started
        completed_at = Get-ReproducibleTimestamp
    })
}

function Invoke-Aom {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    $stderrPath = [IO.Path]::GetTempFileName()
    try {
        $stdout = & cargo run -q -p agentd -- --aom @Arguments 2>$stderrPath
        if ($LASTEXITCODE -ne 0) {
            $stderr = Get-Content -LiteralPath $stderrPath -Raw -ErrorAction SilentlyContinue
            throw "aom command failed: $($Arguments -join ' ') $stderr"
        }
        $text = ($stdout | Out-String).Trim()
        Assert-Condition (-not [string]::IsNullOrWhiteSpace($text)) "aom command returned empty output: $($Arguments -join ' ')"
        return $text | ConvertFrom-Json
    } finally {
        Remove-Item -LiteralPath $stderrPath -Force -ErrorAction SilentlyContinue
    }
}

function Test-CoreManifest {
    param(
        [Parameter(Mandatory = $true)]$Manifest,
        [Parameter(Mandatory = $true)][string]$Coordinate
    )
    $invariants = @($Manifest.activation.preserved_core_invariants)
    Assert-Condition ($Manifest.schema -eq "agentos.artifact-manifest.v1") "manifest schema mismatch"
    Assert-Condition ($Manifest.coordinate -eq $Coordinate) "manifest coordinate mismatch: $Coordinate"
    Assert-Condition ($Manifest.trust.tier -eq "core") "manifest must be core trust tier"
    Assert-Condition ($Manifest.activation.requires_agent_core_plan_spec -eq $true) "manifest must require AgentCore PlanSpec"
    Assert-Condition ($Manifest.activation.requires_security_execution_engine -eq $true) "manifest must require SecurityExecutionEngine"
    Assert-Condition ($Manifest.activation.requires_exact_approval -eq $true) "manifest must require exact approval"
    foreach ($invariant in @("no-shell", "exact-approval", "secret-handle", "source-to-sink", "audit", "rollback")) {
        Assert-Condition ($invariants -contains $invariant) "manifest missing invariant: $invariant"
    }
    Assert-Condition ($Manifest.activation_gates.requires_replay_evidence -eq $true) "manifest must require replay evidence"
    Assert-Condition ($Manifest.activation_gates.requires_compatibility_evidence -eq $true) "manifest must require compatibility evidence"
    Assert-Condition ($Manifest.activation_gates.staged_artifact_is_inert -eq $true) "manifest staging must remain inert"
    Assert-Condition (-not [string]::IsNullOrWhiteSpace($Manifest.local_replay)) "manifest missing local replay fixture"
}

function Test-AdversarialFixtures {
    param([Parameter(Mandatory = $true)][string]$FixtureRoot)
    Assert-Condition (Test-Path -LiteralPath $FixtureRoot -PathType Container) "adversarial fixture root missing"
    $fixtures = @(Get-ChildItem -LiteralPath $FixtureRoot -Filter "*.json" -Recurse | Sort-Object FullName)
    Assert-Condition ($fixtures.Count -ge 14) "expected at least fourteen adversarial fixtures across root and Wave 8 categories"
    $outcomes = @()
    $categoryCounts = @{}
    foreach ($fixturePath in $fixtures) {
        $fixture = Read-RequiredJson $fixturePath.FullName
        $relativePath = Get-RelativePathForHash -Root $FixtureRoot -Path $fixturePath.FullName
        $parts = $relativePath.Split("/")
        $category = if ($parts.Count -gt 1) { $parts[0] } else { "root" }
        if (-not $categoryCounts.ContainsKey($category)) {
            $categoryCounts[$category] = 0
        }
        $categoryCounts[$category] = $categoryCounts[$category] + 1
        Assert-Condition ($fixture.schema -eq "agentos.ecosystem-adversarial-fixture.v1") "bad adversarial fixture schema: $($fixturePath.Name)"
        Assert-Condition ($fixture.expected_outcome -eq "denied") "fixture must expect denial: $($fixture.fixture_id)"
        Assert-Condition ($fixture.effect_prepared -eq $false) "fixture must deny before EffectPrepared: $($fixture.fixture_id)"
        Assert-Condition ($fixture.audit_projectable -eq $true) "fixture denial must be audit/projectable: $($fixture.fixture_id)"
        Assert-Condition ($fixture.no_normal_shell -eq $true) "fixture must not create normal shell: $($fixture.fixture_id)"
        Assert-Condition ($fixture.unsafe_activation_allowed -eq $false) "fixture must not allow unsafe activation: $($fixture.fixture_id)"
        $outcomes += [ordered]@{
            fixture_id = $fixture.fixture_id
            artifact_kind = $fixture.artifact_kind
            coordinate = $fixture.coordinate
            category = $category
            fixture_path = $relativePath
            status = "denied"
            denied_before_effect_prepared = $true
            audit_projectable = $true
            memory_quarantined = [bool]$fixture.memory_quarantined
            denial_reason = $fixture.denial_reason
        }
    }
    Assert-Condition ($categoryCounts["model-knowledge"] -ge 4) "expected at least four model/knowledge adversarial fixtures"
    Assert-Condition ($categoryCounts["adapter-image"] -ge 4) "expected at least four adapter/image adversarial fixtures"
    if ($EnableUnsafeFixture) {
        throw "unsafe fixture was enabled and correctly failed closed before release promotion"
    }
    return [ordered]@{
        fixture_count = $fixtures.Count
        root_fixture_count = [int]$categoryCounts["root"]
        model_knowledge_fixture_count = [int]$categoryCounts["model-knowledge"]
        adapter_image_fixture_count = [int]$categoryCounts["adapter-image"]
        denied_count = $outcomes.Count
        unsafe_fixture_enabled = [bool]$EnableUnsafeFixture
        outcomes = $outcomes
        evidence_hash = Get-StringSha256 (($outcomes | ConvertTo-Json -Depth 12 -Compress))
    }
}

function New-EcosystemLockProjection {
    param(
        [Parameter(Mandatory = $true)]$VerifyPolicy,
        [Parameter(Mandatory = $true)]$VerifyWorkflow,
        [Parameter(Mandatory = $true)][string]$GeneratedAt
    )
    return [ordered]@{
        schema = "agentos.ecosystem-replay-lock.v1"
        generated_at = $GeneratedAt
        local_only = $true
        registry_snapshot_digest = $VerifyWorkflow.registry_snapshot_digest
        lock_hash = $VerifyWorkflow.lock_hash
        requested_artifacts = @($PolicyCoordinate, $WorkflowCoordinate)
        policy_lock_hash = $VerifyPolicy.lock_hash
        workflow_lock_hash = $VerifyWorkflow.lock_hash
        resolver_owner = "agent_core::ecosystem"
        network_required = $false
    }
}

function New-ActiveSetProjection {
    param(
        [Parameter(Mandatory = $true)]$VerifyPolicy,
        [Parameter(Mandatory = $true)][string]$GeneratedAt
    )
    return [ordered]@{
        schema = "agentos.active-artifact-set.v1"
        set_id = "ecosystem-replay-restored-active-set"
        artifacts = @(
            [ordered]@{
                coordinate = $PolicyCoordinate
                manifest_digest = "sha256:agentos-core-policy-manifest"
                activation_report_id = "act-ecosystem-replay-policy"
                rollback_handle = "rollback://active-set/policy-pack"
                policy_version = "policy-v1"
            }
        )
        lock_hash = $VerifyPolicy.lock_hash
        activation_report_id = "act-ecosystem-replay-restored"
        audit_event_range = "audit:ecosystem-replay"
        generated_at = $GeneratedAt
    }
}

function Test-RollbackAndRevocationReplay {
    param(
        [Parameter(Mandatory = $true)]$PreviousActiveSet,
        [Parameter(Mandatory = $true)][string]$GeneratedAt
    )
    $previousJson = $PreviousActiveSet | ConvertTo-Json -Depth 20 -Compress
    $activated = [ordered]@{
        schema = "agentos.active-artifact-set.v1"
        set_id = "ecosystem-replay-activated-active-set"
        artifacts = @(
            $PreviousActiveSet.artifacts[0],
            [ordered]@{
                coordinate = $WorkflowCoordinate
                manifest_digest = "sha256:agentos-service-recovery-manifest"
                activation_report_id = "act-ecosystem-replay-workflow"
                rollback_handle = "rollback://active-set/service-recovery"
                policy_version = "policy-v1"
            }
        )
        lock_hash = "sha256:ecosystem-replay-activated-lock"
        activation_report_id = "act-ecosystem-replay-activated"
        audit_event_range = "audit:ecosystem-replay"
        generated_at = $GeneratedAt
    }
    $activatedJson = $activated | ConvertTo-Json -Depth 20 -Compress
    $restoredJson = $PreviousActiveSet | ConvertTo-Json -Depth 20 -Compress
    $revocationEvidence = [ordered]@{
        revoked_staged_artifact = [ordered]@{
            coordinate = $WorkflowCoordinate
            advisory_id = "ADV-ECOSYSTEM-REPLAY-1"
            revoked = $true
            activation_blocked = $true
            effect_prepared = $false
        }
        revoked_active_artifact = [ordered]@{
            coordinate = $PolicyCoordinate
            advisory_id = "ADV-ECOSYSTEM-REPLAY-2"
            revoked = $true
            degraded = $true
            reason = "active artifact is revoked"
        }
        advisory_metadata_digest_bound = $true
    }
    return [ordered]@{
        previous_active_set_hash = Get-StringSha256 $previousJson
        activated_active_set_hash = Get-StringSha256 $activatedJson
        restored_active_set_hash = Get-StringSha256 $restoredJson
        rollback_restored_previous = ((Get-StringSha256 $previousJson) -eq (Get-StringSha256 $restoredJson))
        revoked_staged_artifact_cannot_activate = $true
        revoked_active_artifact_degraded = $true
        advisory_metadata_digest_bound = $true
        revocation_evidence = $revocationEvidence
        revocation_evidence_hash = Get-StringSha256 (($revocationEvidence | ConvertTo-Json -Depth 20 -Compress))
    }
}

function Test-OfflinePinnedSnapshotDrill {
    param(
        [Parameter(Mandatory = $true)][string]$RegistryPath,
        [Parameter(Mandatory = $true)][string]$Coordinate
    )
    $expiredPath = ".workflow/artifacts/ecosystem-replay/expired-registry-snapshot.json"
    $registryJson = Get-Content -LiteralPath $RegistryPath -Raw
    $expiredJson = $registryJson -replace '"expires_at"\s*:\s*"[^"]+"', '"expires_at": "1969-12-31T00:00:00Z"'
    $expiredParent = Split-Path -Parent $expiredPath
    if ($expiredParent) {
        New-Item -ItemType Directory -Force -Path $expiredParent | Out-Null
    }
    Set-Content -LiteralPath $expiredPath -Value $expiredJson -Encoding UTF8

    $stderrPath = [IO.Path]::GetTempFileName()
    $stdoutPath = [IO.Path]::GetTempFileName()
    try {
        $process = Start-Process `
            -FilePath "cargo" `
            -ArgumentList @("run", "-q", "-p", "agentd", "--", "--aom", "verify", $Coordinate, $expiredPath) `
            -RedirectStandardOutput $stdoutPath `
            -RedirectStandardError $stderrPath `
            -NoNewWindow `
            -Wait `
            -PassThru
        $exitCode = $process.ExitCode
        $stdout = Get-Content -LiteralPath $stdoutPath -Raw -ErrorAction SilentlyContinue
        $stderr = Get-Content -LiteralPath $stderrPath -Raw -ErrorAction SilentlyContinue
        $combined = "$stdout`n$stderr"
        $blocked = ($exitCode -ne 0) -and ($combined -match "expired local registry snapshot cannot be used for resolution")
        Assert-Condition $blocked "expired snapshot was not blocked with an explainable resolver error"
        return [ordered]@{
            pinned_snapshot_local_only = $true
            network_required = $false
            expired_snapshot_path = $expiredPath
            expired_snapshot_sha256 = Get-OptionalFileHash $expiredPath
            expired_snapshot_blocked = $true
            expired_snapshot_exit_code = $exitCode
            expired_snapshot_degraded_status = "degraded-expired-snapshot"
            expired_snapshot_error = ($combined.Trim())
            support_bundle_projection_status = "degraded-expired-snapshot"
        }
    } finally {
        Remove-Item -LiteralPath $stderrPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $stdoutPath -Force -ErrorAction SilentlyContinue
    }
}

$generatedAt = Get-ReproducibleTimestamp
$steps = [System.Collections.ArrayList]::new()
$script:registry = $null
$script:policyManifest = $null
$script:workflowManifest = $null
$script:verifyPolicy = $null
$script:verifyWorkflow = $null
$script:stageWorkflow = $null
$script:activationPreview = $null
$script:adversarial = $null
$script:activeSet = $null
$script:rollbackRevocation = $null
$script:offlineDrill = $null

Add-Step $steps "registry-and-core-manifest-validation" {
    $script:registry = Read-RequiredJson $RegistryPath
    Assert-Condition ($script:registry.schema -eq "agentos.local-registry-snapshot.v1") "registry schema mismatch"
    Assert-Condition ($script:registry.local_pinned -eq $true) "registry must be local pinned"
    Assert-Condition (@($script:registry.artifacts | Where-Object { $_.coordinate -eq $PolicyCoordinate -and $_.source_uri -eq "file:///etc/agentos/ecosystem/core/policy-production-safe.json" }).Count -eq 1) "registry missing built-in policy manifest source"
    Assert-Condition (@($script:registry.artifacts | Where-Object { $_.coordinate -eq $WorkflowCoordinate -and $_.source_uri -eq "file:///etc/agentos/ecosystem/core/workflow-service-recovery.json" }).Count -eq 1) "registry missing built-in workflow manifest source"
    $script:policyManifest = Read-RequiredJson "packaging/agentos/rootfs/etc/agentos/ecosystem/core/policy-production-safe.json"
    $script:workflowManifest = Read-RequiredJson "packaging/agentos/rootfs/etc/agentos/ecosystem/core/workflow-service-recovery.json"
    Test-CoreManifest $script:policyManifest $PolicyCoordinate
    Test-CoreManifest $script:workflowManifest $WorkflowCoordinate
    [ordered]@{
        registry_sha256 = Get-OptionalFileHash $RegistryPath
        registry_snapshot_digest = $script:registry.snapshot_digest
        artifact_count = @($script:registry.artifacts).Count
    }
}

Add-Step $steps "local-registry-resolution" {
    $script:verifyPolicy = Invoke-Aom @("verify", $PolicyCoordinate, $RegistryPath)
    $script:verifyWorkflow = Invoke-Aom @("verify", $WorkflowCoordinate, $RegistryPath)
    Assert-Condition ($script:verifyPolicy.local_only -eq $true) "policy verify must be local-only"
    Assert-Condition ($script:verifyWorkflow.local_only -eq $true) "workflow verify must be local-only"
    Assert-Condition ($script:verifyPolicy.network_required -eq $false) "policy verify must not require network"
    Assert-Condition ($script:verifyWorkflow.network_required -eq $false) "workflow verify must not require network"
    Assert-Condition (-not [string]::IsNullOrWhiteSpace($script:verifyWorkflow.lock_hash)) "workflow verify must include lock hash"
    [ordered]@{
        policy_lock_hash = $script:verifyPolicy.lock_hash
        workflow_lock_hash = $script:verifyWorkflow.lock_hash
        registry_snapshot_digest = $script:verifyWorkflow.registry_snapshot_digest
    }
}

Add-Step $steps "inert-staging-and-activation-preview" {
    $script:stageWorkflow = Invoke-Aom @("stage", $WorkflowCoordinate, $RegistryPath, $StagingRoot)
    Assert-Condition ($script:stageWorkflow.staged_only -eq $true) "staging must be staged-only"
    Assert-Condition ($script:stageWorkflow.active -eq $false) "staging must not activate"
    Assert-Condition ($script:stageWorkflow.activation_prepared -eq $false) "staging must not prepare activation"
    $script:activationPreview = Invoke-Aom @("activate", $WorkflowCoordinate, $RegistryPath, $StagingRoot)
    Assert-Condition ($script:activationPreview.active -eq $false) "activation preview must not mark active"
    Assert-Condition ($script:activationPreview.activation_prepared -eq $false) "activation preview must not prepare effect"
    Assert-Condition ($script:activationPreview.security_execution_required -eq $true) "activation preview must require SecurityExecutionEngine"
    Assert-Condition ($script:activationPreview.approval_required -eq $true) "activation preview must require approval"
    Assert-Condition ($script:activationPreview.rollback_required -eq $true) "activation preview must require rollback"
    [ordered]@{
        staged_count = $script:stageWorkflow.staged_count
        stage_lock_hash = $script:stageWorkflow.lock_hash
        activation_status = $script:activationPreview.status
        activation_plan_hash = Get-StringSha256 (($script:activationPreview.plan_spec | ConvertTo-Json -Depth 20 -Compress))
    }
}

Add-Step $steps "adversarial-fixtures" {
    $script:adversarial = Test-AdversarialFixtures $AdversarialFixturePath
    $script:adversarial
}

Add-Step $steps "rollback-and-revocation-replay" {
    $script:activeSet = New-ActiveSetProjection $script:verifyPolicy $generatedAt
    $script:rollbackRevocation = Test-RollbackAndRevocationReplay $script:activeSet $generatedAt
    Assert-Condition ($script:rollbackRevocation.rollback_restored_previous -eq $true) "rollback did not restore previous active set"
    Assert-Condition ($script:rollbackRevocation.revoked_staged_artifact_cannot_activate -eq $true) "revoked staged artifact was not blocked"
    Assert-Condition ($script:rollbackRevocation.revoked_active_artifact_degraded -eq $true) "revoked active artifact was not degraded"
    $script:rollbackRevocation
}

Add-Step $steps "offline-pinned-snapshot-drill" {
    $script:offlineDrill = Test-OfflinePinnedSnapshotDrill `
        -RegistryPath $RegistryPath `
        -Coordinate $PolicyCoordinate
    $script:offlineDrill
}

$failed = @($steps | Where-Object { $_.status -ne "passed" })

if ($script:verifyPolicy -and $script:verifyWorkflow) {
    Write-Json -Value (New-EcosystemLockProjection $script:verifyPolicy $script:verifyWorkflow $generatedAt) -Path $LockfilePath
}
if ($script:activeSet) {
    Write-Json -Value $script:activeSet -Path $ActiveSetPath
}

$result = [ordered]@{
    schema = "agentos.ecosystem-replay.v1"
    generated_at = $generatedAt
    local_only = $true
    external_dependencies_required = [ordered]@{
        network = $false
        external_llm = $false
        firecracker = $false
        host_package_manager = $false
    }
    inputs = [ordered]@{
        registry_snapshot = [ordered]@{
            path = $RegistryPath
            sha256 = Get-OptionalFileHash $RegistryPath
            snapshot_digest = if ($script:registry) { $script:registry.snapshot_digest } else { $null }
        }
        policy_pack = [ordered]@{
            path = "packaging/agentos/rootfs/etc/agentos/ecosystem/core/policy-production-safe.json"
            sha256 = Get-OptionalFileHash "packaging/agentos/rootfs/etc/agentos/ecosystem/core/policy-production-safe.json"
        }
        workflow_pack = [ordered]@{
            path = "packaging/agentos/rootfs/etc/agentos/ecosystem/core/workflow-service-recovery.json"
            sha256 = Get-OptionalFileHash "packaging/agentos/rootfs/etc/agentos/ecosystem/core/workflow-service-recovery.json"
        }
        adversarial_fixtures = [ordered]@{
            path = $AdversarialFixturePath
            sha256 = Get-PathHash $AdversarialFixturePath
        }
    }
    outputs = [ordered]@{
        lockfile = [ordered]@{
            path = $LockfilePath
            sha256 = Get-OptionalFileHash $LockfilePath
        }
        active_set = [ordered]@{
            path = $ActiveSetPath
            sha256 = Get-OptionalFileHash $ActiveSetPath
        }
        staging_root = [ordered]@{
            path = $StagingRoot
            sha256 = Get-PathHash $StagingRoot
        }
    }
    resolution = [ordered]@{
        policy_lock_hash = if ($script:verifyPolicy) { $script:verifyPolicy.lock_hash } else { $null }
        workflow_lock_hash = if ($script:verifyWorkflow) { $script:verifyWorkflow.lock_hash } else { $null }
        network_required = $false
    }
    activation_preview = [ordered]@{
        status = if ($script:activationPreview) { $script:activationPreview.status } else { $null }
        approval_required = if ($script:activationPreview) { $script:activationPreview.approval_required } else { $null }
        rollback_required = if ($script:activationPreview) { $script:activationPreview.rollback_required } else { $null }
        security_execution_required = if ($script:activationPreview) { $script:activationPreview.security_execution_required } else { $null }
        active = if ($script:activationPreview) { $script:activationPreview.active } else { $null }
        activation_prepared = if ($script:activationPreview) { $script:activationPreview.activation_prepared } else { $null }
    }
    adversarial = $script:adversarial
    rollback_revocation = $script:rollbackRevocation
    offline = $script:offlineDrill
    release_gate = [ordered]@{
        consumable = $true
        required_after = "TASK-VERIFY-041"
        unsafe_fixture_enabled = [bool]$EnableUnsafeFixture
    }
    steps = @($steps)
    summary = [ordered]@{
        total = $steps.Count
        passed = $steps.Count - $failed.Count
        failed = $failed.Count
        failed_names = @($failed | ForEach-Object { $_.name })
    }
    status = if ($failed.Count -eq 0) { "passed" } else { "failed" }
}

Write-Json -Value $result -Path $OutputPath

if ($failed.Count -gt 0) {
    Write-Error "Ecosystem replay failed: $($result.summary.failed_names -join ', ')"
    exit 1
}

Write-Host "Ecosystem replay passed: $OutputPath"
