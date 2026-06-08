param(
    [string]$ArtifactDir = ".workflow/artifacts/rc4-hosted-transport-fail-closed-fixtures",
    [string]$PreconditionAuditScriptPath = "scripts/audit-rc4-fleet-ring-rollout-preconditions.ps1",
    [string]$Rc4PlanPath = ".workflow/active/WFS-20260608-agentos-production-distro-rc4/plan.json",
    [string]$Rc4RolloutBoundaryEvidencePath = ".workflow/active/WFS-20260608-agentos-production-distro-rc4/evidence/RC4-002-staged-rollout-authority-rollback-boundary.json",
    [string]$Rc4GaGatesEvidencePath = ".workflow/active/WFS-20260608-agentos-production-distro-rc4/evidence/RC4-003-ga-hardening-acceptance-gates.json",
    [string]$HostedTransportResultPath = ".workflow/artifacts/rc4-hosted-release-transport/result.json",
    [string]$HostedTransportManifestPath = ".workflow/artifacts/rc4-hosted-release-transport/hosted-transport-manifest.json",
    [string]$MirrorPublicationResultPath = ".workflow/artifacts/rc4-remote-registry-mirror-publication/result.json",
    [string]$MirrorLockfilePath = ".workflow/artifacts/rc4-remote-registry-mirror-publication/mirror-lockfile.json",
    [string]$MirrorPublicationPath = ".workflow/artifacts/rc4-remote-registry-mirror-publication/mirror-publication.json",
    [string]$FleetRolloutAuthorityPath = ".workflow/artifacts/release/fleet-rollout-authority.json",
    [string]$RollbackDrillPath = ".workflow/artifacts/rc2-block-rollback-drill/result.json",
    [string]$SupportRecoveryPath = ".workflow/artifacts/rc3-published-release-support-recovery/result.json",
    [string]$OutputPath = "",
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

function Read-OptionalJson {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Has-Value {
    param($Value)
    if ($null -eq $Value) { return $false }
    if ($Value -is [string]) { return -not [string]::IsNullOrWhiteSpace($Value) }
    return $true
}

function Resolve-RepoPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ([IO.Path]::IsPathRooted($Path)) {
        return [IO.Path]::GetFullPath($Path)
    }
    return [IO.Path]::GetFullPath((Join-Path $script:repoRoot $Path))
}

function Get-RelativeRepoPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    return [IO.Path]::GetRelativePath($script:repoRoot, (Resolve-RepoPath $Path)) -replace "\\", "/"
}

function Get-OptionalFileHash {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Copy-JsonValue {
    param([Parameter(Mandatory = $true)]$Value)
    return $Value | ConvertTo-Json -Depth 100 | ConvertFrom-Json
}

function Assert-StrictChildPath {
    param(
        [Parameter(Mandatory = $true)][string]$Parent,
        [Parameter(Mandatory = $true)][string]$Child
    )
    $parentFull = [IO.Path]::GetFullPath($Parent).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $childFull = [IO.Path]::GetFullPath($Child)
    return $childFull.StartsWith($parentFull + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)
}

function Assert-NotReparsePoint {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing to use reparse point fixture path: $Path"
    }
}

function Assert-ArtifactRoot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedRelativePath
    )
    $pathFull = Resolve-RepoPath $Path
    $expectedFull = Resolve-RepoPath $ExpectedRelativePath
    if (-not $pathFull.Equals($expectedFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to use unexpected RC4 fail-closed artifact root: $pathFull"
    }
}

function Reset-CaseDir {
    param([Parameter(Mandatory = $true)][string]$Id)
    $caseDir = Join-Path $ArtifactDir $Id
    $caseDirFull = Resolve-RepoPath $caseDir
    $artifactRootFull = Resolve-RepoPath $ArtifactDir
    if (-not (Assert-StrictChildPath -Parent $artifactRootFull -Child $caseDirFull)) {
        throw "Refusing to reset fixture directory outside artifact root: $caseDirFull"
    }
    if (Test-Path -LiteralPath $caseDirFull) {
        Assert-NotReparsePoint -Path $caseDirFull
        Remove-Item -LiteralPath $caseDirFull -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $caseDirFull | Out-Null
    Assert-NotReparsePoint -Path $caseDirFull
    return [ordered]@{
        path = $caseDir
        full_path = $caseDirFull
    }
}

function Write-CaseJson {
    param(
        [Parameter(Mandatory = $true)]$Case,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)]$Value
    )
    $path = Join-Path $Case.path $Name
    $pathFull = Resolve-RepoPath $path
    if (-not (Assert-StrictChildPath -Parent $Case.full_path -Child $pathFull)) {
        throw "Refusing to write fixture case JSON outside case root: $pathFull"
    }
    Assert-NotReparsePoint -Path $pathFull
    Write-Json -Value $Value -Path $pathFull
    return $path
}

function Get-OverrideValue {
    param(
        [Parameter(Mandatory = $true)]$Overrides,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Default
    )
    if ($Overrides.Contains($Name)) {
        return [string]$Overrides[$Name]
    }
    return $Default
}

function Invoke-FailClosedCase {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $true)][string[]]$ExpectedBlockerIds,
        [Parameter(Mandatory = $true)][scriptblock]$Setup
    )

    $case = Reset-CaseDir -Id $Id
    $overrides = [ordered]@{}
    & $Setup $case $overrides

    $caseAuditResult = Join-Path $case.path "audit-result.json"
    $exitCode = 0
    $errorMessage = $null
    try {
        $global:LASTEXITCODE = 0
        & $script:resolvedPreconditionAuditScriptPath `
            -ArtifactDir ".workflow/artifacts/rc4-fleet-ring-rollout-preconditions" `
            -Rc4PlanPath (Get-OverrideValue $overrides "Rc4PlanPath" $Rc4PlanPath) `
            -Rc4RolloutBoundaryEvidencePath (Get-OverrideValue $overrides "Rc4RolloutBoundaryEvidencePath" $Rc4RolloutBoundaryEvidencePath) `
            -Rc4GaGatesEvidencePath (Get-OverrideValue $overrides "Rc4GaGatesEvidencePath" $Rc4GaGatesEvidencePath) `
            -HostedTransportResultPath (Get-OverrideValue $overrides "HostedTransportResultPath" $HostedTransportResultPath) `
            -HostedTransportManifestPath (Get-OverrideValue $overrides "HostedTransportManifestPath" $HostedTransportManifestPath) `
            -MirrorPublicationResultPath (Get-OverrideValue $overrides "MirrorPublicationResultPath" $MirrorPublicationResultPath) `
            -MirrorLockfilePath (Get-OverrideValue $overrides "MirrorLockfilePath" $MirrorLockfilePath) `
            -MirrorPublicationPath (Get-OverrideValue $overrides "MirrorPublicationPath" $MirrorPublicationPath) `
            -FleetRolloutAuthorityPath (Get-OverrideValue $overrides "FleetRolloutAuthorityPath" $FleetRolloutAuthorityPath) `
            -RollbackDrillPath (Get-OverrideValue $overrides "RollbackDrillPath" $RollbackDrillPath) `
            -SupportRecoveryPath (Get-OverrideValue $overrides "SupportRecoveryPath" $SupportRecoveryPath) `
            -OutputPath $caseAuditResult | Out-Host
        $exitCode = $LASTEXITCODE
        if ($null -eq $exitCode) { $exitCode = 0 }
    } catch {
        $exitCode = 1
        $errorMessage = $_.Exception.Message
    }

    $audit = Read-OptionalJson (Resolve-RepoPath $caseAuditResult)
    $observedBlockerIds = if ($null -ne $audit) { @($audit.blockers | ForEach-Object { $_.id }) } else { @() }
    $missingExpected = @($ExpectedBlockerIds | Where-Object { $_ -notin $observedBlockerIds })
    $blocked = $null -ne $audit -and
        $audit.status -eq "blocked" -and
        $audit.rollout_preconditions_ready -eq $false -and
        $audit.production_ready_claim -eq $false -and
        $audit.rollout_plan_created -eq $false -and
        $audit.rollout_plan_executed -eq $false -and
        $audit.exact_operator_approval_granted -eq $false -and
        $audit.local_private_key_material_used -eq $false -and
        $audit.cryptographic_signing_performed -eq $false -and
        $audit.cryptographic_verification_performed -eq $false -and
        $audit.network_transfer_performed -eq $false -and
        $audit.remote_upload_performed -eq $false -and
        $audit.activation_performed -eq $false -and
        $audit.rollback_execution_performed -eq $false -and
        $audit.active_registry_mutated -eq $false -and
        $audit.active_slot_mutated -eq $false -and
        $audit.active_artifact_set_mutated -eq $false -and
        $audit.production_ring_mutated -eq $false -and
        $audit.remote_dispatch_enabled -eq $false -and
        $audit.model_replay_authority -eq $false -and
        $audit.normal_shell_authority -eq $false -and
        $audit.tui_authority -eq $false -and
        @($audit.blockers).Count -gt 0
    $passed = $blocked -and ($exitCode -eq 0) -and $missingExpected.Count -eq 0

    return [ordered]@{
        id = $Id
        description = $Description
        status = if ($passed) { "passed" } else { "failed" }
        expected_blocker_ids = @($ExpectedBlockerIds)
        observed_blocker_ids = @($observedBlockerIds)
        missing_expected_blocker_ids = @($missingExpected)
        audit_status = if ($null -ne $audit) { $audit.status } else { $null }
        audit_blockers = if ($null -ne $audit) { @($audit.blockers).Count } else { 0 }
        rollout_preconditions_ready = if ($null -ne $audit) { $audit.rollout_preconditions_ready } else { $null }
        production_ready_claim = if ($null -ne $audit) { $audit.production_ready_claim } else { $null }
        rollout_plan_created = if ($null -ne $audit) { $audit.rollout_plan_created } else { $null }
        rollout_plan_executed = if ($null -ne $audit) { $audit.rollout_plan_executed } else { $null }
        exact_operator_approval_granted = if ($null -ne $audit) { $audit.exact_operator_approval_granted } else { $null }
        activation_performed = if ($null -ne $audit) { $audit.activation_performed } else { $null }
        rollback_execution_performed = if ($null -ne $audit) { $audit.rollback_execution_performed } else { $null }
        active_registry_mutated = if ($null -ne $audit) { $audit.active_registry_mutated } else { $null }
        active_slot_mutated = if ($null -ne $audit) { $audit.active_slot_mutated } else { $null }
        production_ring_mutated = if ($null -ne $audit) { $audit.production_ring_mutated } else { $null }
        remote_dispatch_enabled = if ($null -ne $audit) { $audit.remote_dispatch_enabled } else { $null }
        tui_authority = if ($null -ne $audit) { $audit.tui_authority } else { $null }
        exit_code = $exitCode
        error = $errorMessage
        audit_result = Get-RelativeRepoPath $caseAuditResult
        audit_result_sha256 = Get-OptionalFileHash (Resolve-RepoPath $caseAuditResult)
        override_inputs = $overrides
    }
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$expectedArtifactDir = ".workflow/artifacts/rc4-hosted-transport-fail-closed-fixtures"
Assert-ArtifactRoot -Path $ArtifactDir -ExpectedRelativePath $expectedArtifactDir
$artifactDirFull = Resolve-RepoPath $ArtifactDir
New-Item -ItemType Directory -Force -Path $artifactDirFull | Out-Null
Assert-NotReparsePoint -Path $artifactDirFull

if (-not (Has-Value $OutputPath)) {
    $OutputPath = Join-Path $ArtifactDir "result.json"
}
$outputPathFull = Resolve-RepoPath $OutputPath
if (-not (Assert-StrictChildPath -Parent $artifactDirFull -Child $outputPathFull)) {
    throw "Refusing to write RC4 fail-closed result outside artifact root: $outputPathFull"
}

$canonicalPreconditionAuditScriptPath = "scripts/audit-rc4-fleet-ring-rollout-preconditions.ps1"
$script:resolvedPreconditionAuditScriptPath = Resolve-RepoPath $PreconditionAuditScriptPath
$canonicalPreconditionAuditScriptFullPath = Resolve-RepoPath $canonicalPreconditionAuditScriptPath
$preconditionAuditScriptAllowed = $script:resolvedPreconditionAuditScriptPath.Equals($canonicalPreconditionAuditScriptFullPath, [StringComparison]::OrdinalIgnoreCase)

$plan = Read-OptionalJson (Resolve-RepoPath $Rc4PlanPath)
$rolloutBoundary = Read-OptionalJson (Resolve-RepoPath $Rc4RolloutBoundaryEvidencePath)
$hostedManifest = Read-OptionalJson (Resolve-RepoPath $HostedTransportManifestPath)
$mirrorPublication = Read-OptionalJson (Resolve-RepoPath $MirrorPublicationPath)
$fleetAuthority = Read-OptionalJson (Resolve-RepoPath $FleetRolloutAuthorityPath)
$rollbackDrill = Read-OptionalJson (Resolve-RepoPath $RollbackDrillPath)
$supportRecovery = Read-OptionalJson (Resolve-RepoPath $SupportRecoveryPath)

$cases = @()
$harnessBlockers = @()

if (-not $preconditionAuditScriptAllowed -or -not (Test-Path -LiteralPath $script:resolvedPreconditionAuditScriptPath -PathType Leaf)) {
    $harnessBlockers += [ordered]@{
        id = "precondition_audit_script.canonical"
        status = "blocked"
        message = "RC4 hosted transport fail-closed fixtures may only invoke the canonical RC4 fleet-ring rollout precondition audit script."
        evidence = [ordered]@{
            supplied = $PreconditionAuditScriptPath
            expected = $canonicalPreconditionAuditScriptPath
            allowed = $preconditionAuditScriptAllowed
        }
    }
}

$requiredSources = [ordered]@{
    plan = $plan
    rollout_boundary = $rolloutBoundary
    hosted_manifest = $hostedManifest
    mirror_publication = $mirrorPublication
    fleet_authority = $fleetAuthority
    rollback_drill = $rollbackDrill
    support_recovery = $supportRecovery
}
foreach ($name in $requiredSources.Keys) {
    if ($null -eq $requiredSources[$name]) {
        $harnessBlockers += [ordered]@{
            id = "source.$name.present"
            status = "blocked"
            message = "Required source fixture is missing for RC4 hosted transport fail-closed validation."
            evidence = $name
        }
    }
}

if ($harnessBlockers.Count -eq 0) {
    $cases += Invoke-FailClosedCase `
        -Id "hosted-manifest-hash-drift" `
        -Description "Rejects mirror publication when the hosted transport manifest hash drifts." `
        -ExpectedBlockerIds @("mirror_publication.ready_no_mutation") `
        -Setup {
            param($case, $overrides)
            $copy = Copy-JsonValue $mirrorPublication
            $copy.bindings.hosted_transport_manifest_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
            $overrides["MirrorPublicationPath"] = Write-CaseJson -Case $case -Name "mirror-publication-hosted-hash-drift.json" -Value $copy
        }

    $cases += Invoke-FailClosedCase `
        -Id "missing-rc3-final-audit-binding" `
        -Description "Rejects hosted transport metadata missing the RC3 final audit binding." `
        -ExpectedBlockerIds @("hosted_mirror.release_bindings_consistent") `
        -Setup {
            param($case, $overrides)
            $copy = Copy-JsonValue $hostedManifest
            $copy.bindings.rc3_final_audit_sha256 = $null
            $overrides["HostedTransportManifestPath"] = Write-CaseJson -Case $case -Name "hosted-manifest-missing-rc3-final-audit.json" -Value $copy
        }

    $cases += Invoke-FailClosedCase `
        -Id "stale-mirror-snapshot" `
        -Description "Rejects stale or replayed mirror snapshot state." `
        -ExpectedBlockerIds @("mirror_publication.ready_no_mutation", "mirror_publication.fresh_fixture") `
        -Setup {
            param($case, $overrides)
            $copy = Copy-JsonValue $mirrorPublication
            $copy.mirror.snapshot_freshness_status = "stale-fixture"
            $overrides["MirrorPublicationPath"] = Write-CaseJson -Case $case -Name "mirror-publication-stale-snapshot.json" -Value $copy
        }

    $cases += Invoke-FailClosedCase `
        -Id "unsigned-mirror-metadata" `
        -Description "Rejects mirror publication that no longer declares unsigned metadata as a fail-closed case." `
        -ExpectedBlockerIds @("mirror_publication.fail_closed_cases_declared") `
        -Setup {
            param($case, $overrides)
            $copy = Copy-JsonValue $mirrorPublication
            $copy.fail_closed_cases_required = @($copy.fail_closed_cases_required | Where-Object { $_ -ne "unsigned-mirror-metadata" })
            $overrides["MirrorPublicationPath"] = Write-CaseJson -Case $case -Name "mirror-publication-no-unsigned-case.json" -Value $copy
        }

    $cases += Invoke-FailClosedCase `
        -Id "revoked-mirror-artifact" `
        -Description "Rejects mirror publication that no longer declares revoked mirror metadata as a fail-closed case." `
        -ExpectedBlockerIds @("mirror_publication.fail_closed_cases_declared") `
        -Setup {
            param($case, $overrides)
            $copy = Copy-JsonValue $mirrorPublication
            $copy.fail_closed_cases_required = @($copy.fail_closed_cases_required | Where-Object { $_ -ne "revoked-mirror-metadata" })
            $overrides["MirrorPublicationPath"] = Write-CaseJson -Case $case -Name "mirror-publication-no-revoked-case.json" -Value $copy
        }

    $cases += Invoke-FailClosedCase `
        -Id "registry-lockfile-mismatch" `
        -Description "Rejects mirror publication when the lockfile hash no longer matches." `
        -ExpectedBlockerIds @("mirror_publication.ready_no_mutation") `
        -Setup {
            param($case, $overrides)
            $copy = Copy-JsonValue $mirrorPublication
            $copy.bindings.mirror_lockfile_sha256 = "1111111111111111111111111111111111111111111111111111111111111111"
            $overrides["MirrorPublicationPath"] = Write-CaseJson -Case $case -Name "mirror-publication-lockfile-mismatch.json" -Value $copy
        }

    $cases += Invoke-FailClosedCase `
        -Id "fleet-target-set-drift" `
        -Description "Rejects changed local fleet target set cardinality before approval." `
        -ExpectedBlockerIds @("fleet_rings.staged_boundary_ready") `
        -Setup {
            param($case, $overrides)
            $copy = Copy-JsonValue $fleetAuthority
            foreach ($ring in $copy.rings) {
                if ($ring.name -eq "local") {
                    $ring.node_count = 2
                }
            }
            $overrides["FleetRolloutAuthorityPath"] = Write-CaseJson -Case $case -Name "fleet-authority-target-set-drift.json" -Value $copy
        }

    $cases += Invoke-FailClosedCase `
        -Id "ring-skip-attempt" `
        -Description "Rejects rollout ring order that skips canary before staging." `
        -ExpectedBlockerIds @("fleet_rings.staged_boundary_ready", "fleet_rings.staged_order") `
        -Setup {
            param($case, $overrides)
            $copy = Copy-JsonValue $fleetAuthority
            $local = @($copy.rings | Where-Object { $_.name -eq "local" } | Select-Object -First 1)
            $staging = @($copy.rings | Where-Object { $_.name -eq "staging" } | Select-Object -First 1)
            $canary = @($copy.rings | Where-Object { $_.name -eq "canary" } | Select-Object -First 1)
            $production = @($copy.rings | Where-Object { $_.name -eq "production" } | Select-Object -First 1)
            $copy.rings = @($local, $staging, $canary, $production)
            $overrides["FleetRolloutAuthorityPath"] = Write-CaseJson -Case $case -Name "fleet-authority-ring-skip.json" -Value $copy
        }

    $cases += Invoke-FailClosedCase `
        -Id "missing-rollback-baseline" `
        -Description "Rejects rollout preconditions without rollback baseline hash." `
        -ExpectedBlockerIds @("rollback_baseline.ready_no_mutation") `
        -Setup {
            param($case, $overrides)
            $copy = Copy-JsonValue $rollbackDrill
            $copy.evidence_chain.rollback_baseline_sha256 = $null
            $overrides["RollbackDrillPath"] = Write-CaseJson -Case $case -Name "rollback-drill-missing-baseline.json" -Value $copy
        }

    $cases += Invoke-FailClosedCase `
        -Id "tui-rollout-authority-attempt" `
        -Description "Rejects fleet authority or ring metadata that grants rollout authority to TUI." `
        -ExpectedBlockerIds @("fleet_authority.ready", "fleet_rings.staged_boundary_ready") `
        -Setup {
            param($case, $overrides)
            $copy = Copy-JsonValue $fleetAuthority
            $copy.authority.tui_authority = $true
            $copy.authority.rollout_execution_in_tui = $true
            foreach ($ring in $copy.rings) {
                if ($ring.name -eq "local") {
                    $ring.rollout_dispatch_enabled_in_tui = $true
                }
            }
            $overrides["FleetRolloutAuthorityPath"] = Write-CaseJson -Case $case -Name "fleet-authority-tui-rollout.json" -Value $copy
        }

    $cases += Invoke-FailClosedCase `
        -Id "model-replay-rollout-authority-attempt" `
        -Description "Rejects rollout boundary evidence that grants rollout authority to model replay." `
        -ExpectedBlockerIds @("rc4.rollout_boundary.ready") `
        -Setup {
            param($case, $overrides)
            $copy = Copy-JsonValue $rolloutBoundary
            $copy.acceptance_coverage.model_replay_authority = $true
            $overrides["Rc4RolloutBoundaryEvidencePath"] = Write-CaseJson -Case $case -Name "rollout-boundary-model-replay-authority.json" -Value $copy
        }

    $cases += Invoke-FailClosedCase `
        -Id "remote-dispatch-mutation-attempt" `
        -Description "Rejects mirror publication metadata that enables remote dispatch or active mutation." `
        -ExpectedBlockerIds @("mirror_publication.ready_no_mutation") `
        -Setup {
            param($case, $overrides)
            $copy = Copy-JsonValue $mirrorPublication
            $copy.invariants.remote_dispatch_enabled = $true
            $copy.invariants.active_registry_mutated = $true
            $copy.invariants.production_ring_mutated = $true
            $overrides["MirrorPublicationPath"] = Write-CaseJson -Case $case -Name "mirror-publication-remote-dispatch.json" -Value $copy
        }

    $cases += Invoke-FailClosedCase `
        -Id "unredacted-support-bundle" `
        -Description "Rejects support/recovery evidence that is no longer redacted and local-only." `
        -ExpectedBlockerIds @("support_recovery.redacted_local_only") `
        -Setup {
            param($case, $overrides)
            $copy = Copy-JsonValue $supportRecovery
            $copy.support_bundle_redacted = $false
            $copy.summary.support_bundle_redacted = $false
            $copy.remote_dispatch_enabled = $true
            $copy.tui_authority = $true
            $overrides["SupportRecoveryPath"] = Write-CaseJson -Case $case -Name "support-recovery-unredacted.json" -Value $copy
        }
}

$failedCases = @($cases | Where-Object { $_.status -ne "passed" })
foreach ($case in $failedCases) {
    $harnessBlockers += [ordered]@{
        id = "case.$($case.id)"
        status = "blocked"
        message = "Expected RC4 hosted transport fail-closed case did not block with every expected blocker and no authority broadening."
        evidence = [ordered]@{
            expected = $case.expected_blocker_ids
            observed = $case.observed_blocker_ids
            missing = $case.missing_expected_blocker_ids
            audit_result = $case.audit_result
            error = $case.error
        }
    }
}

$passed = $harnessBlockers.Count -eq 0
$result = [ordered]@{
    schema = "agentos.rc4-hosted-transport-fail-closed-fixtures.v1"
    generated_at = "2026-06-08T09:50:00+08:00"
    checked_at = (Get-Date).ToString("o")
    task = "RC4-013"
    status = if ($passed) { "passed" } else { "blocked" }
    production_ready_claim = $false
    rc4_013_complete = $passed
    hosted_transport_fail_closed_ready = $passed
    rollout_preconditions_ready = $false
    rollout_plan_created = $false
    rollout_plan_executed = $false
    exact_operator_approval_granted = $false
    local_private_key_material_used = $false
    cryptographic_signing_performed = $false
    cryptographic_verification_performed = $false
    network_transfer_performed = $false
    remote_upload_performed = $false
    activation_performed = $false
    rollback_execution_performed = $false
    active_registry_mutated = $false
    active_slot_mutated = $false
    active_artifact_set_mutated = $false
    boot_metadata_mutated = $false
    production_ring_mutated = $false
    remote_dispatch_enabled = $false
    model_replay_authority = $false
    normal_shell_authority = $false
    tui_authority = $false
    inputs = [ordered]@{
        precondition_audit_script = $PreconditionAuditScriptPath
        precondition_audit_script_sha256 = if ($preconditionAuditScriptAllowed) { Get-OptionalFileHash $script:resolvedPreconditionAuditScriptPath } else { $null }
        rc4_plan = $Rc4PlanPath
        rc4_plan_sha256 = Get-OptionalFileHash (Resolve-RepoPath $Rc4PlanPath)
        rollout_boundary = $Rc4RolloutBoundaryEvidencePath
        rollout_boundary_sha256 = Get-OptionalFileHash (Resolve-RepoPath $Rc4RolloutBoundaryEvidencePath)
        hosted_transport_manifest = $HostedTransportManifestPath
        hosted_transport_manifest_sha256 = Get-OptionalFileHash (Resolve-RepoPath $HostedTransportManifestPath)
        mirror_publication = $MirrorPublicationPath
        mirror_publication_sha256 = Get-OptionalFileHash (Resolve-RepoPath $MirrorPublicationPath)
        fleet_rollout_authority = $FleetRolloutAuthorityPath
        fleet_rollout_authority_sha256 = Get-OptionalFileHash (Resolve-RepoPath $FleetRolloutAuthorityPath)
        rollback_drill = $RollbackDrillPath
        rollback_drill_sha256 = Get-OptionalFileHash (Resolve-RepoPath $RollbackDrillPath)
        support_recovery = $SupportRecoveryPath
        support_recovery_sha256 = Get-OptionalFileHash (Resolve-RepoPath $SupportRecoveryPath)
    }
    cases = @($cases)
    blockers = @($harnessBlockers)
    summary = [ordered]@{
        cases = @($cases).Count
        passed_cases = @($cases | Where-Object { $_.status -eq "passed" }).Count
        failed_cases = $failedCases.Count
        child_audit_exit_zero_cases = @($cases | Where-Object { $_.exit_code -eq 0 }).Count
        blockers = $harnessBlockers.Count
        expected_fail_closed_cases = @(
            "hosted-manifest-hash-drift",
            "missing-rc3-final-audit-binding",
            "stale-mirror-snapshot",
            "unsigned-mirror-metadata",
            "revoked-mirror-artifact",
            "registry-lockfile-mismatch",
            "fleet-target-set-drift",
            "ring-skip-attempt",
            "missing-rollback-baseline",
            "tui-rollout-authority-attempt",
            "model-replay-rollout-authority-attempt",
            "remote-dispatch-mutation-attempt",
            "unredacted-support-bundle"
        )
        rc4_013_complete = $passed
        production_ready_claim = $false
        network_transfer_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        active_registry_mutated = $false
        active_slot_mutated = $false
        production_ring_mutated = $false
        remote_dispatch_enabled = $false
        tui_authority = $false
    }
}

Write-Json -Value $result -Path $outputPathFull
Write-Host "RC4 hosted transport fail-closed fixtures $($result.status): $OutputPath"

if ($FailOnBlocked -and -not $passed) {
    exit 1
}
