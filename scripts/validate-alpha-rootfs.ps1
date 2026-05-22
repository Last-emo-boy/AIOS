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
    } elseif ($Artifact.id -eq "model_broker.config") {
        foreach ($check in (Test-ModelBrokerConfig $path)) { [void]$checks.Add($check) }
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
    @{ id = "model_broker.config"; kind = "file"; path = "/etc/agentos/model-broker.toml"; owner = "root:root"; mode = "0644" },
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
