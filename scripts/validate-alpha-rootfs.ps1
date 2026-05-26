param(
    [string]$RootfsPath = "packaging/agentos/rootfs",
    [ValidateSet("PackageDefaults", "FullRootfs")]
    [string]$Stage = "PackageDefaults",
    [string]$OutputPath = ".workflow/artifacts/alpha-rootfs-validation/result.json"
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

function Get-RelativeRootPath {
    param([Parameter(Mandatory = $true)][string]$RootfsRelativePath)
    return $RootfsRelativePath.TrimStart("/").Replace("/", [IO.Path]::DirectorySeparatorChar)
}

function Get-ArtifactPath {
    param(
        [Parameter(Mandatory = $true)][string]$Rootfs,
        [Parameter(Mandatory = $true)][string]$RootfsRelativePath
    )
    return Join-Path $Rootfs (Get-RelativeRootPath $RootfsRelativePath)
}

function Get-OptionalSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Add-Check {
    param(
        [System.Collections.ArrayList]$Checks,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][bool]$Passed,
        [string]$Message = ""
    )
    [void]$Checks.Add([ordered]@{
        name = $Name
        status = if ($Passed) { "passed" } else { "failed" }
        message = $Message
    })
}

function Test-SecretFreeContent {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $true
    }
    $content = Get-Content -LiteralPath $Path -Raw
    $patterns = @(
        "password\s*=",
        "passwd\s*=",
        "api[_-]?key\s*=",
        "access_token\s*=",
        "refresh_token\s*=",
        "BEGIN RSA PRIVATE KEY",
        "BEGIN OPENSSH PRIVATE KEY"
    )
    foreach ($pattern in $patterns) {
        if ($content -match $pattern) {
            return $false
        }
    }
    return $true
}

function Test-PolicyPack {
    param([Parameter(Mandatory = $true)][string]$Path)
    $checks = [System.Collections.ArrayList]::new()
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Add-Check $checks "json-parse" $false "policy pack missing"
        return $checks
    }

    try {
        $policy = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
        Add-Check $checks "json-parse" $true
    } catch {
        Add-Check $checks "json-parse" $false $_.Exception.Message
        return $checks
    }

    Add-Check $checks "policy-version" ($policy.policy_version -eq "policy-v1") "expected policy-v1"
    Add-Check $checks "normal-shell-deny" ($policy.defaults.normal_shell -eq "deny") "normal shell must be denied"
    Add-Check $checks "broad-approval-deny" ($policy.defaults.broad_approval -eq "deny") "broad approvals must be denied"

    $binding = @($policy.approval_token.binding)
    foreach ($field in @("actor", "tool", "resource", "parameter_hash", "expires_at", "policy_version")) {
        Add-Check $checks "approval-binding-$field" ($binding -contains $field) "approval binding must include $field"
    }

    $shellDenied = $false
    foreach ($entry in @($policy.deny_tools)) {
        if ($entry.tool -eq "shell.exec" -and $entry.mode -eq "normal") {
            $shellDenied = $true
        }
    }
    Add-Check $checks "shell-explicit-deny" $shellDenied "shell.exec must be explicitly denied in normal mode"
    Add-Check $checks "denied-no-effect" ($policy.audit.denied_decisions_prepare_effect -eq $false) "denied decisions must not prepare effects"
    return $checks
}

function Test-SemanticTools {
    param([Parameter(Mandatory = $true)][string]$Path)
    $checks = [System.Collections.ArrayList]::new()
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Add-Check $checks "json-parse" $false "semantic tool manifest missing"
        return $checks
    }

    try {
        $manifest = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
        Add-Check $checks "json-parse" $true
    } catch {
        Add-Check $checks "json-parse" $false $_.Exception.Message
        return $checks
    }

    $toolNames = @($manifest.tools | ForEach-Object { $_.name })
    foreach ($tool in @("svc.logs", "svc.status", "http.check", "config.test", "fs.read", "fs.write.diff", "svc.restart", "audit.show", "rollback.trigger")) {
        Add-Check $checks "tool-$tool" ($toolNames -contains $tool) "required semantic tool missing"
    }
    Add-Check $checks "shell-absent" (-not ($toolNames -contains "shell.exec")) "shell.exec must not be a normal-mode semantic tool"
    Add-Check $checks "shell-denial-label" ($manifest.normal_mode_shell_exec -eq "absent-and-denied") "manifest must label shell as absent and denied"
    return $checks
}

function Test-OperatorCommands {
    param([Parameter(Mandatory = $true)][string]$Path)
    $checks = [System.Collections.ArrayList]::new()
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Add-Check $checks "json-parse" $false "operator command registry missing"
        return $checks
    }

    try {
        $registry = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
        Add-Check $checks "json-parse" $true
    } catch {
        Add-Check $checks "json-parse" $false $_.Exception.Message
        return $checks
    }

    Add-Check $checks "schema" ($registry.schema -eq "agentos.operator-commands.v1") "operator command schema must be stable"
    Add-Check $checks "shell-absent" (-not (@($registry.commands | ForEach-Object { $_.name }) -contains "shell.exec")) "operator registry must not expose shell.exec"
    foreach ($field in @("name", "owner", "risk", "semantic_mapping", "blocked_prerequisites")) {
        $missing = @($registry.commands | Where-Object { -not $_.PSObject.Properties[$field] })
        Add-Check $checks "command-field-$field" ($missing.Count -eq 0) "each operator command must declare $field"
    }
    foreach ($command in @("capability.list", "service.recover", "package.install.fixture", "content.inspect", "audit.export", "support.bundle.export", "tui.dashboard", "tui.intent.submit", "tui.run.advance", "tui.run.approve", "tui.run.deny", "tui.run.recover", "tui.audit.show", "tui.support.bundle", "tui.aom.lifecycle", "aom.search", "aom.show", "aom.verify", "aom.stage", "aom.explain", "aom.activate", "rollback.trigger")) {
        Add-Check $checks "command-$command" (@($registry.commands | Where-Object { $_.name -eq $command }).Count -eq 1) "required operator command missing"
    }
    Add-Check $checks "tui-no-shell" (@($registry.commands | Where-Object { $_.name -like "tui.*" -and $_.semantic_mapping -match "shell\.exec" }).Count -eq 0) "TUI registry entries must not map to shell.exec"
    return $checks
}

function Test-EcosystemRegistrySnapshot {
    param([Parameter(Mandatory = $true)][string]$Path)
    $checks = [System.Collections.ArrayList]::new()
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Add-Check $checks "json-parse" $false "ecosystem registry snapshot missing"
        return $checks
    }

    try {
        $snapshot = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
        Add-Check $checks "json-parse" $true
    } catch {
        Add-Check $checks "json-parse" $false $_.Exception.Message
        return $checks
    }

    Add-Check $checks "schema" ($snapshot.schema -eq "agentos.local-registry-snapshot.v1") "local registry snapshot schema must be stable"
    Add-Check $checks "local-pinned" ($snapshot.local_pinned -eq $true) "baseline registry must be local-pinned"
    Add-Check $checks "snapshot-digest" ($snapshot.snapshot_digest -match "^sha256:.+") "snapshot digest must be sha256-bound"
    Add-Check $checks "artifact-count" (@($snapshot.artifacts).Count -gt 0) "local registry must include at least one artifact"
    foreach ($field in @("coordinate", "manifest_digest", "artifact_digest", "declared_artifact_digest", "trust_tier", "source_uri", "revoked", "dependencies", "advisory_refs")) {
        $missing = @($snapshot.artifacts | Where-Object { -not $_.PSObject.Properties[$field] })
        Add-Check $checks "artifact-field-$field" ($missing.Count -eq 0) "each registry artifact must declare $field"
    }
    Add-Check $checks "no-revoked-default-artifacts" (@($snapshot.artifacts | Where-Object { $_.revoked -eq $true }).Count -eq 0) "baseline local registry must not stage revoked defaults"
    Add-Check $checks "core-policy-source" (@($snapshot.artifacts | Where-Object { $_.coordinate -eq "agentos:policy-pack/agentos/core-policy@1.0.0" -and $_.trust_tier -eq "core" -and $_.source_uri -eq "file:///etc/agentos/ecosystem/core/policy-production-safe.json" }).Count -eq 1) "core policy pack must point at built-in production-safe manifest"
    Add-Check $checks "service-recovery-source" (@($snapshot.artifacts | Where-Object { $_.coordinate -eq "agentos:workflow-pack/agentos/service-recovery@1.0.0" -and $_.trust_tier -eq "core" -and $_.source_uri -eq "file:///etc/agentos/ecosystem/core/workflow-service-recovery.json" }).Count -eq 1) "service recovery workflow must point at built-in core manifest"
    return $checks
}

function Test-CoreEcosystemManifest {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedCoordinate,
        [Parameter(Mandatory = $true)][string]$Kind
    )
    $checks = [System.Collections.ArrayList]::new()
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Add-Check $checks "json-parse" $false "core ecosystem manifest missing"
        return $checks
    }

    try {
        $manifest = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
        Add-Check $checks "json-parse" $true
    } catch {
        Add-Check $checks "json-parse" $false $_.Exception.Message
        return $checks
    }

    $invariants = @($manifest.activation.preserved_core_invariants)
    $capabilities = @($manifest.activation.required_runtime_capabilities)
    Add-Check $checks "schema" ($manifest.schema -eq "agentos.artifact-manifest.v1") "manifest schema must be stable"
    Add-Check $checks "coordinate" ($manifest.coordinate -eq $ExpectedCoordinate) "manifest coordinate must match registry coordinate"
    Add-Check $checks "core-trust-tier" ($manifest.trust.tier -eq "core") "built-in pack must be core trust tier"
    Add-Check $checks "production-promotable" ($manifest.trust.production_promotable -eq $true) "built-in pack must be production promotable"
    Add-Check $checks "agent-core-required" ($manifest.activation.requires_agent_core_plan_spec -eq $true) "activation must compile through AgentCore PlanSpec"
    Add-Check $checks "security-engine-required" ($manifest.activation.requires_security_execution_engine -eq $true) "activation must go through SecurityExecutionEngine"
    Add-Check $checks "exact-approval-required" ($manifest.activation.requires_exact_approval -eq $true) "exact approval must remain enforced"
    Add-Check $checks "policy-version" ($manifest.activation.required_policy_version -eq "policy-v1") "activation must bind policy-v1"
    foreach ($invariant in @("no-shell", "exact-approval", "secret-handle", "source-to-sink", "audit", "rollback")) {
        Add-Check $checks "invariant-$invariant" ($invariants -contains $invariant) "activation must preserve $invariant"
    }
    Add-Check $checks "audit-capability" ($capabilities -contains "audit-journal") "activation must require audit journal"
    Add-Check $checks "rollback-capability" ($capabilities -contains "rollback-store") "activation must require rollback store"
    Add-Check $checks "replay-required" ($manifest.activation_gates.requires_replay_evidence -eq $true) "activation must require replay evidence"
    Add-Check $checks "compatibility-required" ($manifest.activation_gates.requires_compatibility_evidence -eq $true) "activation must require compatibility evidence"
    Add-Check $checks "staged-inert" ($manifest.activation_gates.staged_artifact_is_inert -eq $true) "staged artifacts must be inert"
    Add-Check $checks "local-replay" (-not [string]::IsNullOrWhiteSpace($manifest.local_replay)) "manifest must include local replay fixture"
    Add-Check $checks "unknown-required-fields-empty" (@($manifest.unknown_required_fields).Count -eq 0) "unknown required fields must be empty"

    if ($Kind -eq "policy") {
        Add-Check $checks "narrows-only" ($manifest.pack_behavior.narrows_only -eq $true) "policy pack may only narrow policy"
        Add-Check $checks "normal-shell-deny" ($manifest.pack_behavior.normal_shell -eq "deny") "policy pack must keep normal shell denied"
        Add-Check $checks "broad-approval-deny" ($manifest.pack_behavior.broad_approval -eq "deny") "policy pack must keep broad approval denied"
        Add-Check $checks "denied-no-effect" ($manifest.pack_behavior.denied_decisions_prepare_effect -eq $false) "denied policy decisions must not prepare effects"
        Add-Check $checks "can-deactivate" ($manifest.pack_behavior.can_deactivate -eq $true) "policy pack must support deactivation"
        Add-Check $checks "can-rollback" ($manifest.pack_behavior.can_rollback -eq $true) "policy pack must support rollback"
    } elseif ($Kind -eq "workflow") {
        $dependencies = @($manifest.dependencies)
        Add-Check $checks "dependency-core-policy" (@($dependencies | Where-Object { $_.coordinate -eq "agentos:policy-pack/agentos/core-policy@1.0.0" -and $_.optional -eq $false -and $_.missing_behavior -eq "block-activation" -and $_.allows_host_mutation_when_missing -eq $false }).Count -eq 1) "workflow pack must require core policy without host mutation fallback"
        Add-Check $checks "compile-target" ($manifest.workflow.compile_target -eq "agent_core::service_recovery::AgentCoreServiceRecovery") "workflow must map to AgentCore service recovery"
        Add-Check $checks "restart-tool" ($manifest.workflow.restart_action_tool -eq "svc.restart") "workflow restart action must use semantic svc.restart"
        Add-Check $checks "restart-exact-approval" ($manifest.workflow.restart_requires_exact_approval -eq $true) "restart action must require exact approval"
        Add-Check $checks "denied-no-effect" ($manifest.workflow.denied_path_effect_prepared -eq $false) "denied restart path must not prepare effects"
        Add-Check $checks "direct-shell-denied" ($manifest.workflow.direct_shell_authority -eq $false) "workflow pack must not provide shell authority"
        Add-Check $checks "local-fixture" ($manifest.workflow.local_replay_fixture -eq $true) "workflow replay fixture must be local-only"
    }
    return $checks
}

function Test-ModelBrokerConfig {
    param([Parameter(Mandatory = $true)][string]$Path)
    $checks = [System.Collections.ArrayList]::new()
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Add-Check $checks "toml-present" $false "ModelBroker config missing"
        return $checks
    }

    $content = Get-Content -LiteralPath $Path -Raw
    Add-Check $checks "toml-present" $true
    Add-Check $checks "mode-stub" ($content -match '(?m)^\s*mode\s*=\s*"stub"\s*$') "default mode must be stub"
    Add-Check $checks "network-not-required" ($content -match '(?m)^\s*network_required\s*=\s*false\s*$') "acceptance must not require network"
    Add-Check $checks "default-provider-stub-local" ($content -match '(?m)^\s*default_provider\s*=\s*"stub-local"\s*$') "default provider must be stub-local"
    Add-Check $checks "stub-no-credentials" ($content -match '(?m)^\s*requires_credentials\s*=\s*false\s*$') "stub provider must not require credentials"
    Add-Check $checks "remote-disabled" ($content -match '(?ms)\[providers\.remote\].*?enabled\s*=\s*false') "remote provider must be disabled by default"
    Add-Check $checks "remote-not-acceptance" ($content -match '(?ms)\[providers\.remote\].*?required_for_acceptance\s*=\s*false') "remote provider must not be required for acceptance"
    return $checks
}

function Test-TuiConfig {
    param([Parameter(Mandatory = $true)][string]$Path)
    $checks = [System.Collections.ArrayList]::new()
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Add-Check $checks "toml-present" $false "TUI config missing"
        return $checks
    }

    $content = Get-Content -LiteralPath $Path -Raw
    Add-Check $checks "toml-present" $true
    Add-Check $checks "schema" ($content -match '(?m)^\s*schema\s*=\s*"agentos\.tui-console\.v1"\s*$') "TUI config schema must be stable"
    Add-Check $checks "default-durable" ($content -match '(?m)^\s*default_mode\s*=\s*"durable"\s*$') "default TUI mode must be durable"
    Add-Check $checks "projection-controller-only" ($content -match '(?m)^\s*projection_controller_only\s*=\s*true\s*$') "TUI must remain projection-controller only"
    Add-Check $checks "runtime-authority" ($content -match '(?m)^\s*runtime_authority\s*=\s*"AgentCore PlanSpec \+ SecurityExecutionEngine"\s*$') "runtime authority must remain AgentCore + SecurityExecutionEngine"
    foreach ($field in @("run_store", "audit_journal", "support_bundle")) {
        Add-Check $checks "path-$field" ($content -match "(?m)^\s*$field\s*=\s*`".+`"\s*$") "TUI config must declare $field"
    }
    Add-Check $checks "headless-available" ($content -match '(?m)^\s*headless_mode_available\s*=\s*true\s*$') "headless TUI mode must be available"
    Add-Check $checks "scripted-available" ($content -match '(?m)^\s*scripted_mode_available\s*=\s*true\s*$') "scripted TUI mode must be available"
    Add-Check $checks "interactive-available" ($content -match '(?m)^\s*interactive_mode_available\s*=\s*true\s*$') "interactive TUI mode must be available"
    Add-Check $checks "demo-not-default" ($content -match '(?m)^\s*demo_mode_default\s*=\s*false\s*$') "demo mode must not be the default"
    Add-Check $checks "normal-shell-denied" ($content -match '(?m)^\s*normal_shell_available\s*=\s*false\s*$') "normal shell must not be exposed through TUI"
    Add-Check $checks "model-direct-exec-denied" ($content -match '(?m)^\s*model_output_direct_execution_allowed\s*=\s*false\s*$') "model output must not execute directly"
    foreach ($field in @("external_llm_required", "network_required", "firecracker_required", "host_package_manager_required")) {
        Add-Check $checks "baseline-no-$field" ($content -match "(?m)^\s*$field\s*=\s*false\s*$") "baseline TUI must not require $field"
    }
    return $checks
}

function New-ArtifactResult {
    param(
        [Parameter(Mandatory = $true)][string]$Rootfs,
        [Parameter(Mandatory = $true)][hashtable]$Artifact
    )
    $path = Get-ArtifactPath $Rootfs $Artifact.path
    $exists = Test-Path -LiteralPath $path
    $checks = [System.Collections.ArrayList]::new()

    Add-Check $checks "exists" $exists "path must exist"
    Add-Check $checks "owner-intent" (-not [string]::IsNullOrWhiteSpace($Artifact.owner)) "artifact must declare expected owner"
    Add-Check $checks "mode-intent" (-not [string]::IsNullOrWhiteSpace($Artifact.mode)) "artifact must declare expected mode"
    if ($exists) {
        if ($Artifact.kind -eq "directory") {
            Add-Check $checks "directory" (Test-Path -LiteralPath $path -PathType Container) "path must be directory"
        } else {
            Add-Check $checks "file" (Test-Path -LiteralPath $path -PathType Leaf) "path must be file"
            Add-Check $checks "sha256" ((Get-OptionalSha256 $path) -ne $null) "file hash must be available"
        }
        Add-Check $checks "no-secret-values" (Test-SecretFreeContent $path) "raw secret-like values are forbidden"
    }

    if ($Artifact.id -eq "policy.pack") {
        foreach ($check in (Test-PolicyPack $path)) { [void]$checks.Add($check) }
    } elseif ($Artifact.id -eq "tools.semantic") {
        foreach ($check in (Test-SemanticTools $path)) { [void]$checks.Add($check) }
    } elseif ($Artifact.id -eq "operator.commands") {
        foreach ($check in (Test-OperatorCommands $path)) { [void]$checks.Add($check) }
    } elseif ($Artifact.id -eq "ecosystem.registry_snapshot") {
        foreach ($check in (Test-EcosystemRegistrySnapshot $path)) { [void]$checks.Add($check) }
    } elseif ($Artifact.id -eq "ecosystem.core_policy") {
        foreach ($check in (Test-CoreEcosystemManifest -Path $path -ExpectedCoordinate "agentos:policy-pack/agentos/core-policy@1.0.0" -Kind "policy")) { [void]$checks.Add($check) }
    } elseif ($Artifact.id -eq "ecosystem.workflow_service_recovery") {
        foreach ($check in (Test-CoreEcosystemManifest -Path $path -ExpectedCoordinate "agentos:workflow-pack/agentos/service-recovery@1.0.0" -Kind "workflow")) { [void]$checks.Add($check) }
    } elseif ($Artifact.id -eq "model_broker.config") {
        foreach ($check in (Test-ModelBrokerConfig $path)) { [void]$checks.Add($check) }
    } elseif ($Artifact.id -eq "tui.config") {
        foreach ($check in (Test-TuiConfig $path)) { [void]$checks.Add($check) }
    }

    $failed = @($checks | Where-Object { $_.status -eq "failed" })
    return [ordered]@{
        id = $Artifact.id
        kind = $Artifact.kind
        path = $Artifact.path
        host_path = $path
        exists = $exists
        expected_owner = $Artifact.owner
        expected_mode = $Artifact.mode
        sha256 = Get-OptionalSha256 $path
        checks = @($checks)
        status = if ($failed.Count -eq 0) { "passed" } else { "failed" }
    }
}

$resolvedRootfs = (Resolve-Path -LiteralPath $RootfsPath -ErrorAction Stop).Path

$required = @(
    @{ id = "policy.pack"; kind = "file"; path = "/etc/agentos/policy/policy-pack.json"; owner = "root:root"; mode = "0644" },
    @{ id = "tools.semantic"; kind = "file"; path = "/etc/agentos/tools/semantic-tools.json"; owner = "root:root"; mode = "0644" },
    @{ id = "operator.commands"; kind = "file"; path = "/etc/agentos/operator-commands.json"; owner = "root:root"; mode = "0644" },
    @{ id = "ecosystem.registry_snapshot"; kind = "file"; path = "/etc/agentos/ecosystem/registry-snapshot.json"; owner = "root:root"; mode = "0644" },
    @{ id = "ecosystem.core_policy"; kind = "file"; path = "/etc/agentos/ecosystem/core/policy-production-safe.json"; owner = "root:root"; mode = "0644" },
    @{ id = "ecosystem.workflow_service_recovery"; kind = "file"; path = "/etc/agentos/ecosystem/core/workflow-service-recovery.json"; owner = "root:root"; mode = "0644" },
    @{ id = "model_broker.config"; kind = "file"; path = "/etc/agentos/model-broker.toml"; owner = "root:root"; mode = "0644" },
    @{ id = "tui.config"; kind = "file"; path = "/etc/agentos/tui.toml"; owner = "root:root"; mode = "0644" },
    @{ id = "state.runs"; kind = "directory"; path = "/var/lib/agentos/runs/"; owner = "root:root"; mode = "0700" },
    @{ id = "state.audit"; kind = "directory"; path = "/var/log/agentos/audit/"; owner = "root:root"; mode = "0700" },
    @{ id = "state.rollback"; kind = "directory"; path = "/var/lib/agentos/rollback/"; owner = "root:root"; mode = "0700" },
    @{ id = "state.memory"; kind = "directory"; path = "/var/lib/agentos/memory/"; owner = "root:root"; mode = "0700" }
)

if ($Stage -eq "FullRootfs") {
    $required += @(
        @{ id = "agentd.boot"; kind = "file"; path = "/sbin/agentd"; owner = "root:root"; mode = "0755" },
        @{ id = "agentd.runtime"; kind = "file"; path = "/usr/lib/agentos/agentd"; owner = "root:root"; mode = "0755" },
        @{ id = "release.provenance"; kind = "file"; path = "/usr/lib/agentos/release/provenance.json"; owner = "root:root"; mode = "0644" },
        @{ id = "release.rootfs_manifest"; kind = "file"; path = "/usr/lib/agentos/release/rootfs-runtime-manifest.json"; owner = "root:root"; mode = "0644" }
    )
}

$artifacts = @()
foreach ($artifact in $required) {
    $artifacts += New-ArtifactResult -Rootfs $resolvedRootfs -Artifact $artifact
}

$failedArtifacts = @($artifacts | Where-Object { $_.status -eq "failed" })
$result = [ordered]@{
    schema = "agentos.alpha-rootfs-validation.v1"
    checked_at = (Get-Date).ToString("o")
    rootfs_path = $resolvedRootfs
    stage = $Stage
    runtime_authority = "root:root"
    artifacts = $artifacts
    summary = [ordered]@{
        total = $artifacts.Count
        passed = $artifacts.Count - $failedArtifacts.Count
        failed = $failedArtifacts.Count
        failed_ids = @($failedArtifacts | ForEach-Object { $_.id })
    }
    result = if ($failedArtifacts.Count -eq 0) { "passed" } else { "failed" }
}

Write-Json -Value $result -Path $OutputPath

if ($failedArtifacts.Count -gt 0) {
    Write-Error "Alpha rootfs validation failed: $($result.summary.failed_ids -join ', ')"
    exit 1
}

Write-Host "Alpha rootfs validation passed: $OutputPath"
