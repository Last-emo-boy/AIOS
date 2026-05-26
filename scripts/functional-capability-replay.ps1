param(
    [string]$OutputPath = ".workflow/artifacts/functional-replay/result.json",
    [string]$CapabilityMatrixPath = ".workflow/active/WFS-20260524-agentos-functional-iteration/docs/functional-capability-matrix.md",
    [switch]$SkipCargoTests
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
    $Value | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Get-OptionalSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Add-Result {
    param(
        [System.Collections.ArrayList]$Results,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][scriptblock]$Script
    )
    $started = (Get-Date).ToString("o")
    $status = "passed"
    $errorMessage = ""
    try {
        & $Script
        if ($LASTEXITCODE -ne 0) {
            $status = "failed"
            $errorMessage = "exit code $LASTEXITCODE"
        }
    } catch {
        $status = "failed"
        $errorMessage = $_.Exception.Message
    }
    [void]$Results.Add([ordered]@{
        name = $Name
        command = $Command
        status = $status
        error = $errorMessage
        started_at = $started
        completed_at = (Get-Date).ToString("o")
    })
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
    Assert-Condition (Test-Path -LiteralPath $Path -PathType Leaf) "missing JSON fixture: $Path"
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Assert-CoreActivationManifest {
    param(
        [Parameter(Mandatory = $true)]$Manifest,
        [Parameter(Mandatory = $true)][string]$Coordinate
    )
    $invariants = @($Manifest.activation.preserved_core_invariants)
    $capabilities = @($Manifest.activation.required_runtime_capabilities)
    Assert-Condition ($Manifest.schema -eq "agentos.artifact-manifest.v1") "unexpected manifest schema"
    Assert-Condition ($Manifest.coordinate -eq $Coordinate) "unexpected manifest coordinate"
    Assert-Condition ($Manifest.trust.tier -eq "core") "manifest must use core trust tier"
    Assert-Condition ($Manifest.activation.requires_agent_core_plan_spec -eq $true) "activation must require AgentCore PlanSpec"
    Assert-Condition ($Manifest.activation.requires_security_execution_engine -eq $true) "activation must require SecurityExecutionEngine"
    Assert-Condition ($Manifest.activation.requires_exact_approval -eq $true) "activation must require exact approval"
    foreach ($invariant in @("no-shell", "exact-approval", "secret-handle", "source-to-sink", "audit", "rollback")) {
        Assert-Condition ($invariants -contains $invariant) "missing core invariant: $invariant"
    }
    Assert-Condition ($capabilities -contains "audit-journal") "activation must require audit-journal"
    Assert-Condition ($capabilities -contains "rollback-store") "activation must require rollback-store"
    Assert-Condition ($Manifest.activation_gates.requires_replay_evidence -eq $true) "activation must require replay evidence"
    Assert-Condition ($Manifest.activation_gates.requires_compatibility_evidence -eq $true) "activation must require compatibility evidence"
    Assert-Condition ($Manifest.activation_gates.staged_artifact_is_inert -eq $true) "staged artifacts must remain inert"
    Assert-Condition (-not [string]::IsNullOrWhiteSpace($Manifest.local_replay)) "manifest must include local replay fixture"
}

function Test-BuiltInEcosystemPacks {
    $policyPath = "packaging/agentos/rootfs/etc/agentos/ecosystem/core/policy-production-safe.json"
    $workflowPath = "packaging/agentos/rootfs/etc/agentos/ecosystem/core/workflow-service-recovery.json"
    $registryPath = "packaging/agentos/rootfs/etc/agentos/ecosystem/registry-snapshot.json"
    $policy = Read-RequiredJson $policyPath
    $workflow = Read-RequiredJson $workflowPath
    $registry = Read-RequiredJson $registryPath

    Assert-CoreActivationManifest $policy "agentos:policy-pack/agentos/core-policy@1.0.0"
    Assert-Condition ($policy.pack_behavior.narrows_only -eq $true) "policy pack must only narrow policy"
    Assert-Condition ($policy.pack_behavior.normal_shell -eq "deny") "policy pack must keep no-shell policy"
    Assert-Condition ($policy.pack_behavior.broad_approval -eq "deny") "policy pack must deny broad approval"
    Assert-Condition ($policy.pack_behavior.denied_decisions_prepare_effect -eq $false) "denied decisions must not prepare effects"
    Assert-Condition ($policy.pack_behavior.can_deactivate -eq $true) "policy pack must support deactivation"
    Assert-Condition ($policy.pack_behavior.can_rollback -eq $true) "policy pack must support rollback"

    Assert-CoreActivationManifest $workflow "agentos:workflow-pack/agentos/service-recovery@1.0.0"
    Assert-Condition ($workflow.workflow.compile_target -eq "agent_core::service_recovery::AgentCoreServiceRecovery") "workflow must compile through AgentCore service recovery"
    Assert-Condition ($workflow.workflow.restart_action_tool -eq "svc.restart") "workflow restart must use semantic svc.restart"
    Assert-Condition ($workflow.workflow.restart_requires_exact_approval -eq $true) "restart must require exact approval"
    Assert-Condition ($workflow.workflow.denied_path_effect_prepared -eq $false) "denied restart must not prepare EffectPrepared"
    Assert-Condition ($workflow.workflow.direct_shell_authority -eq $false) "workflow must not provide shell authority"
    Assert-Condition ($workflow.workflow.local_replay_fixture -eq $true) "workflow replay fixture must be local-only"

    $policyRegistry = @($registry.artifacts | Where-Object { $_.coordinate -eq $policy.coordinate -and $_.source_uri -eq "file:///etc/agentos/ecosystem/core/policy-production-safe.json" })
    $workflowRegistry = @($registry.artifacts | Where-Object { $_.coordinate -eq $workflow.coordinate -and $_.source_uri -eq "file:///etc/agentos/ecosystem/core/workflow-service-recovery.json" })
    Assert-Condition ($policyRegistry.Count -eq 1) "registry must reference built-in policy manifest"
    Assert-Condition ($workflowRegistry.Count -eq 1) "registry must reference built-in service recovery manifest"
}

$results = [System.Collections.ArrayList]::new()

if (-not $SkipCargoTests) {
    Add-Result $results "runtime_contracts capability contracts" "cargo test -p runtime_contracts capability" {
        cargo test -p runtime_contracts capability
    }
}

Add-Result $results "service recovery approved/denied" "cargo test -p agentd service_recovery::" {
    cargo test -p agentd service_recovery::
}

Add-Result $results "package manager fixtures" "cargo test -p agent_core package_install" {
    cargo test -p agent_core package_install
}

Add-Result $results "untrusted content fixtures" "cargo test -p agent_core untrusted_content" {
    cargo test -p agent_core untrusted_content
}

Add-Result $results "firecracker fail-closed fixtures" "cargo test -p security_execution firecracker" {
    cargo test -p security_execution firecracker
}

Add-Result $results "operator support bundle manifest" "cargo test -p agentd support_bundle" {
    cargo test -p agentd support_bundle
}

Add-Result $results "operator projection" "cargo test -p agentd operator_projection" {
    cargo test -p agentd operator_projection
}

Add-Result $results "safety regression fixtures" "cargo test -p agentd safety::" {
    cargo test -p agentd safety::
}

Add-Result $results "built-in ecosystem packs" "local JSON replay gate for core policy and service recovery packs" {
    Test-BuiltInEcosystemPacks
}

$failed = @($results | Where-Object { $_.status -ne "passed" })
$matrixHash = Get-OptionalSha256 $CapabilityMatrixPath

$result = [ordered]@{
    schema = "agentos.functional-capability-replay.v1"
    generated_at = (Get-Date).ToString("o")
    local_only = $true
    external_dependencies_required = [ordered]@{
        network = $false
        external_llm = $false
        firecracker = $false
        host_package_manager = $false
    }
    capability_matrix = [ordered]@{
        path = $CapabilityMatrixPath
        sha256 = $matrixHash
    }
    capabilities = @($results)
    summary = [ordered]@{
        total = $results.Count
        passed = $results.Count - $failed.Count
        failed = $failed.Count
        failed_names = @($failed | ForEach-Object { $_.name })
    }
    status = if ($failed.Count -eq 0) { "passed" } else { "failed" }
}

Write-Json -Value $result -Path $OutputPath

if ($failed.Count -gt 0) {
    Write-Error "Functional capability replay failed: $($result.summary.failed_names -join ', ')"
    exit 1
}

Write-Host "Functional capability replay passed: $OutputPath"
