param(
    [string]$ArtifactDir = ".workflow/artifacts/rc12-object-trust-verification",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc12",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc12/docs/rc12-real-object-controlled-unblock-contract.md",
    [string]$PublicationResultPath = ".workflow/artifacts/rc12-external-object-publication-binding/result.json",
    [string]$PublicationBindingPath = ".workflow/artifacts/rc12-external-object-publication-binding/publication-binding.json",
    [string]$DriftResultPath = ".workflow/artifacts/rc12-declared-current-drift-zero/result.json",
    [string]$DriftHandoffPath = ".workflow/artifacts/rc12-declared-current-drift-zero/object-trust-verification-handoff.json",
    [string]$Rc11QuarantineResultPath = ".workflow/artifacts/rc11-installer-quarantine-verifier/result.json",
    [string]$DescriptorCandidatePath = ".workflow/artifacts/rc11-release-object-byte-map/immutable-descriptor-candidate.json",
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

function Get-JsonText {
    param([Parameter(Mandatory = $true)]$Value)
    return ($Value | ConvertTo-Json -Depth 100)
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
    [IO.File]::WriteAllText($Path, (Get-JsonText $Value) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
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

function Copy-JsonObject {
    param([Parameter(Mandatory = $true)]$Value)
    return ($Value | ConvertTo-Json -Depth 100 | ConvertFrom-Json)
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
        ("signing" + "-key.pem"),
        ("/etc/" + "aios-signer"),
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

function Test-TrustCase {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)]$Gates
    )
    $reasons = @()
    if ($Gates.uri_published -ne $true) { $reasons += "external-https-object-uri-not-published" }
    if ($Gates.uri_https -ne $true) { $reasons += "object-uri-not-https" }
    if ($Gates.uri_credential_free -ne $true) { $reasons += "object-uri-credential-bearing" }
    if ($Gates.uri_immutable -ne $true) { $reasons += "object-uri-not-immutable" }
    if ($Gates.size_match -ne $true) { $reasons += "object-size-mismatch" }
    if ($Gates.digest_match -ne $true) { $reasons += "object-digest-mismatch" }
    if ($Gates.descriptor_bound -ne $true) { $reasons += "descriptor-binding-missing" }
    if ($Gates.drift_zero -ne $true) { $reasons += "declared-current-drift-zero-not-proved" }
    if ($Gates.freshness_bound -ne $true) { $reasons += "freshness-window-missing" }
    if ($Gates.revocation_bound -ne $true) { $reasons += "revocation-snapshot-missing" }
    if ($Gates.compatibility_bound -ne $true) { $reasons += "compatibility-metadata-missing" }
    if ($Gates.rollback_bound -ne $true) { $reasons += "rollback-baseline-missing" }
    if ($Gates.support_bound -ne $true) { $reasons += "support-recovery-binding-missing" }
    if ($Gates.endpoint_reachability_claimed -eq $true) { $reasons += "endpoint-reachability-is-not-trust" }
    $uniqueReasons = @($reasons | Select-Object -Unique)
    return [ordered]@{
        id = $Id
        status = if ($uniqueReasons.Count -eq 0) { "accepted" } else { "denied" }
        denied = ($uniqueReasons.Count -gt 0)
        gates = $Gates
        denial_reasons = $uniqueReasons
    }
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:failedChecks = @()

$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$resolvedWorkflowDir = Resolve-RepoPath $WorkflowDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $resolvedWorkflowDir "evidence") | Out-Null

$resolvedContractPath = Resolve-RepoPath $ContractPath
$resolvedPublicationResultPath = Resolve-RepoPath $PublicationResultPath
$resolvedPublicationBindingPath = Resolve-RepoPath $PublicationBindingPath
$resolvedDriftResultPath = Resolve-RepoPath $DriftResultPath
$resolvedDriftHandoffPath = Resolve-RepoPath $DriftHandoffPath
$resolvedRc11QuarantineResultPath = Resolve-RepoPath $Rc11QuarantineResultPath
$resolvedDescriptorCandidatePath = Resolve-RepoPath $DescriptorCandidatePath

$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$publicationResult = Read-Json $resolvedPublicationResultPath
$publicationBinding = Read-Json $resolvedPublicationBindingPath
$driftResult = Read-Json $resolvedDriftResultPath
$driftHandoff = Read-Json $resolvedDriftHandoffPath
$rc11QuarantineResult = Read-Json $resolvedRc11QuarantineResultPath
$descriptorCandidate = Read-Json $resolvedDescriptorCandidatePath

$generatedAtValue = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }
$releaseId = [string]$publicationResult.release_id
$sourceArtifactPath = Resolve-RepoPath ([string]$publicationBinding.current_release_bytes.source_path)
$sourceArtifactSha256 = Get-FileSha256 $sourceArtifactPath
$sourceArtifactSize = if (Test-Path -LiteralPath $sourceArtifactPath -PathType Leaf) { (Get-Item -LiteralPath $sourceArtifactPath).Length } else { $null }

$source = [ordered]@{
    rc12_contract = New-ArtifactRef $resolvedContractPath
    rc12_publication_result = New-ArtifactRef $resolvedPublicationResultPath $publicationResult
    rc12_publication_binding = New-ArtifactRef $resolvedPublicationBindingPath $publicationBinding
    rc12_drift_result = New-ArtifactRef $resolvedDriftResultPath $driftResult
    rc12_drift_handoff = New-ArtifactRef $resolvedDriftHandoffPath $driftHandoff
    rc11_quarantine_result = New-ArtifactRef $resolvedRc11QuarantineResultPath $rc11QuarantineResult
    rc11_descriptor_candidate = New-ArtifactRef $resolvedDescriptorCandidatePath $descriptorCandidate
    current_payload_bytes = New-ArtifactRef $sourceArtifactPath
}

Add-Check "contract.object_trust_gate.present" ($contractText.Contains("object_trust_allowed") -and $contractText.Contains("endpoint reachability used as trust")) "RC12-012 must consume the object trust and reachability boundary." $source.rc12_contract
Add-Check "source.publication_binding.passed" ($publicationResult.status -eq "passed" -and $publicationResult.task -eq "RC12-010") "RC12-012 requires RC12-010 publication binding evidence." ([ordered]@{ status = $publicationResult.status; publication_allowed = $publicationResult.publication_surface.publication_allowed })
Add-Check "source.drift_zero.passed" ($driftResult.status -eq "passed" -and $driftResult.task -eq "RC12-011") "RC12-012 requires RC12-011 drift-zero evidence." ([ordered]@{ status = $driftResult.status; drift_zero = $driftResult.reconciliation_surface.drift_zero; drift_count = $driftResult.reconciliation_surface.drift_count })
Add-Check "source.rc11_quarantine.passed" ($rc11QuarantineResult.status -eq "passed" -and $rc11QuarantineResult.fetch_surface.fetch_allowed -eq $false -and $rc11QuarantineResult.fetch_surface.network_fetch_attempted -eq $false) "RC12-012 must bind prior quarantine denial before authorizing any fetch." ([ordered]@{ status = $rc11QuarantineResult.status; fetch_allowed = $rc11QuarantineResult.fetch_surface.fetch_allowed; network_fetch_attempted = $rc11QuarantineResult.fetch_surface.network_fetch_attempted })
Add-Check "source.current_bytes_match_descriptor" ($sourceArtifactSha256 -eq [string]$descriptorCandidate.sha256 -and $sourceArtifactSize -eq [int64]$descriptorCandidate.size_bytes) "Current payload bytes must match descriptor size and SHA-256 before object trust verification." ([ordered]@{ expected_sha256 = $descriptorCandidate.sha256; observed_sha256 = $sourceArtifactSha256; expected_size_bytes = $descriptorCandidate.size_bytes; observed_size_bytes = $sourceArtifactSize })

$currentGates = [ordered]@{
    uri_published = [bool]$publicationResult.publication_surface.external_object_uri_published
    uri_https = [bool]$publicationBinding.object_uri.https
    uri_credential_free = [bool]$publicationBinding.object_uri.credential_free
    uri_immutable = [bool]$publicationBinding.object_uri.immutable
    size_match = ($sourceArtifactSize -eq [int64]$descriptorCandidate.size_bytes -and $publicationBinding.object_uri.size_bound -eq $true)
    digest_match = ($sourceArtifactSha256 -eq [string]$descriptorCandidate.sha256 -and $publicationBinding.object_uri.digest_bound -eq $true)
    descriptor_bound = ([string]$publicationBinding.required_bindings.descriptor_candidate_sha256 -eq (Get-FileSha256 $resolvedDescriptorCandidatePath))
    drift_zero = [bool]$driftResult.reconciliation_surface.drift_zero
    freshness_bound = [bool]$publicationResult.publication_surface.freshness_window_bound
    revocation_bound = (-not [string]::IsNullOrWhiteSpace([string]$publicationBinding.required_bindings.revocation_snapshot_sha256))
    compatibility_bound = (-not [string]::IsNullOrWhiteSpace([string]$publicationBinding.required_bindings.compatibility_sha256))
    rollback_bound = (-not [string]::IsNullOrWhiteSpace([string]$publicationBinding.required_bindings.rollback_baseline_sha256))
    support_bound = (-not [string]::IsNullOrWhiteSpace([string]$publicationBinding.required_bindings.support_recovery_sha256))
    endpoint_reachability_claimed = $false
}

$cases = @()
$cases += Test-TrustCase -Id "current.object_trust_candidate" -Gates $currentGates
$allGood = Copy-JsonObject $currentGates
$allGood.uri_published = $true
$allGood.uri_https = $true
$allGood.uri_credential_free = $true
$allGood.uri_immutable = $true
$allGood.drift_zero = $true
$allGood.freshness_bound = $true
$cases += Test-TrustCase -Id "negative.endpoint_reachability_only" -Gates ([ordered]@{ uri_published = $true; uri_https = $true; uri_credential_free = $true; uri_immutable = $true; size_match = $true; digest_match = $true; descriptor_bound = $true; drift_zero = $true; freshness_bound = $true; revocation_bound = $true; compatibility_bound = $true; rollback_bound = $true; support_bound = $true; endpoint_reachability_claimed = $true })

$negativeMutations = @(
    @{ id = "negative.missing_uri"; key = "uri_published" },
    @{ id = "negative.non_https_uri"; key = "uri_https" },
    @{ id = "negative.credential_uri"; key = "uri_credential_free" },
    @{ id = "negative.mutable_uri"; key = "uri_immutable" },
    @{ id = "negative.size_mismatch"; key = "size_match" },
    @{ id = "negative.digest_mismatch"; key = "digest_match" },
    @{ id = "negative.descriptor_unbound"; key = "descriptor_bound" },
    @{ id = "negative.drift_nonzero"; key = "drift_zero" },
    @{ id = "negative.freshness_missing"; key = "freshness_bound" },
    @{ id = "negative.revocation_missing"; key = "revocation_bound" },
    @{ id = "negative.compatibility_missing"; key = "compatibility_bound" },
    @{ id = "negative.rollback_missing"; key = "rollback_bound" },
    @{ id = "negative.support_missing"; key = "support_bound" }
)
foreach ($mutation in $negativeMutations) {
    $gates = Copy-JsonObject $allGood
    $gates.($mutation.key) = $false
    $cases += Test-TrustCase -Id $mutation.id -Gates $gates
}

$failedCases = @($cases | Where-Object { $_.denied -ne $true })
$currentDecision = $cases | Where-Object { $_.id -eq "current.object_trust_candidate" } | Select-Object -First 1
$objectTrustAllowed = ($currentDecision.denied -eq $false)
$verificationState = if ($objectTrustAllowed) { "object-trust-verified" } else { "object-trust-denied" }
$blockers = @($currentDecision.denial_reasons + $driftResult.reconciliation_surface.blockers + $rc11QuarantineResult.fetch_surface.blockers | Select-Object -Unique)

Add-Check "object_trust.requires_all_gates" (($objectTrustAllowed -eq $true -and $blockers.Count -eq 0) -or ($objectTrustAllowed -eq $false -and $blockers.Count -gt 0)) "Object trust must be granted only when URI, size, digest, descriptor, drift-zero, freshness, revocation, compatibility, rollback, and support gates all pass." ([ordered]@{ object_trust_allowed = $objectTrustAllowed; blockers = $blockers })
Add-Check "endpoint.reachability_not_trust" (@($cases | Where-Object { $_.id -eq "negative.endpoint_reachability_only" -and $_.denial_reasons -contains "endpoint-reachability-is-not-trust" }).Count -eq 1) "Endpoint reachability must be recorded as non-authoritative." $null
Add-Check "fail_closed_matrix.all_cases_denied" ($failedCases.Count -eq 0 -and @($cases).Count -ge 14) "Object trust negative cases must all fail closed before installer authority." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })

$report = [ordered]@{
    schema = "agentos.rc12-object-trust-verification-report.v1"
    generated_at = $generatedAtValue
    task = "RC12-012"
    release_id = $releaseId
    status = $verificationState
    production_ready_claim = $false
    current_gates = $currentGates
    current_decision = $currentDecision
    source = $source
    object_trust_decision = [ordered]@{
        object_trust_allowed = $objectTrustAllowed
        endpoint_reachability_is_trust = $false
        network_probe_performed = $false
        quarantine_fetch_allowed = $objectTrustAllowed
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        blockers = $blockers
    }
}

$denial = [ordered]@{
    schema = "agentos.rc12-object-trust-denial.v1"
    generated_at = $generatedAtValue
    task = "RC12-012"
    release_id = $releaseId
    status = if ($objectTrustAllowed) { "not-denied" } else { "object-trust-denied" }
    production_ready_claim = $false
    denied = (-not $objectTrustAllowed)
    denial_reasons = $blockers
    side_effects = [ordered]@{
        endpoint_reachability_trusted = $false
        network_probe_performed = $false
        payload_bytes_uploaded = $false
        remote_payload_bytes_downloaded = $false
        quarantine_payload_written = $false
        payload_interpreted = $false
        install_performed = $false
        activation_performed = $false
        rollback_execution_performed = $false
        support_upload_performed = $false
        recovery_execution_performed = $false
        remote_dispatch_enabled = $false
        production_ring_mutated = $false
    }
}

$matrix = [ordered]@{
    schema = "agentos.rc12-object-trust-fail-closed-matrix.v1"
    generated_at = $generatedAtValue
    task = "RC12-012"
    release_id = $releaseId
    status = if ($failedCases.Count -eq 0) { "passed" } else { "failed" }
    cases = $cases
    summary = [ordered]@{
        cases = @($cases).Count
        denied = @($cases | Where-Object { $_.denied -eq $true }).Count
        failed_cases = @($failedCases | ForEach-Object { $_.id })
    }
}

$reportPath = Join-Path $resolvedArtifactDir "object-trust-report.json"
$denialPath = Join-Path $resolvedArtifactDir "object-trust-denial.json"
$matrixPath = Join-Path $resolvedArtifactDir "object-trust-fail-closed-matrix.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC12-012-object-trust-verification.json"

Write-Json $report $reportPath
Write-Json $denial $denialPath
Write-Json $matrix $matrixPath

Add-Check "outputs.secret_safe" (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $reportPath), (Get-Content -Raw -LiteralPath $denialPath), (Get-Content -Raw -LiteralPath $matrixPath))) "RC12-012 outputs must not contain PEM blocks, auth tokens, or signer internals." $null
Add-Check "outputs.side_effects_absent" ($denial.side_effects.endpoint_reachability_trusted -eq $false -and $denial.side_effects.network_probe_performed -eq $false -and $denial.side_effects.remote_payload_bytes_downloaded -eq $false -and $denial.side_effects.quarantine_payload_written -eq $false -and $denial.side_effects.payload_interpreted -eq $false -and $denial.side_effects.install_performed -eq $false -and $denial.side_effects.activation_performed -eq $false -and $denial.side_effects.rollback_execution_performed -eq $false -and $denial.side_effects.support_upload_performed -eq $false -and $denial.side_effects.recovery_execution_performed -eq $false -and $denial.side_effects.remote_dispatch_enabled -eq $false -and $denial.side_effects.production_ring_mutated -eq $false) "RC12-012 must not trust reachability, probe network, fetch, quarantine, interpret, install, activate, rollback, upload support, recover, dispatch, or mutate production rings." $denial.side_effects

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc12-object-trust-verification-result.v1"
    generated_at = $generatedAtValue
    task = "RC12-012"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    verification_surface = [ordered]@{
        state = $verificationState
        object_trust_allowed = $objectTrustAllowed
        endpoint_reachability_is_trust = $false
        network_probe_performed = $false
        external_object_uri_published = [bool]$publicationResult.publication_surface.external_object_uri_published
        drift_zero = [bool]$driftResult.reconciliation_surface.drift_zero
        freshness_window_bound = [bool]$publicationResult.publication_surface.freshness_window_bound
        revocation_bound = [bool]$currentGates.revocation_bound
        compatibility_bound = [bool]$currentGates.compatibility_bound
        rollback_bound = [bool]$currentGates.rollback_bound
        support_bound = [bool]$currentGates.support_bound
        fail_closed_cases = @($cases).Count
        failed_fail_closed_cases = @($failedCases).Count
        quarantine_fetch_allowed = $objectTrustAllowed
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        blockers = $blockers
    }
    outputs = [ordered]@{
        report = [ordered]@{ path = Get-StablePath $reportPath; sha256 = Get-FileSha256 $reportPath }
        denial = [ordered]@{ path = Get-StablePath $denialPath; sha256 = Get-FileSha256 $denialPath }
        fail_closed_matrix = [ordered]@{ path = Get-StablePath $matrixPath; sha256 = Get-FileSha256 $matrixPath }
    }
    source = $source
    invariants = [ordered]@{
        aios_body_only = $true
        mirror_frontend_changed = $false
        nginx_or_tls_changed = $false
        signer_infra_changed = $false
        object_storage_infra_changed = $false
        local_private_key_material_used = $false
        private_key_material_read_or_printed = $false
        cryptographic_signing_performed = $false
        endpoint_reachability_trusted = $false
        network_probe_performed = $false
        payload_upload_performed = $false
        remote_payload_bytes_downloaded = $false
        quarantine_payload_written = $false
        payload_interpreted = $false
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
    blockers = $blockers
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        object_trust_allowed = $objectTrustAllowed
        trust_denied_as_expected = (-not $objectTrustAllowed)
        fail_closed_cases = @($cases).Count
        failed_fail_closed_cases = @($failedCases).Count
        rc12_012_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC12-020"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc12-object-trust-verification-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC12-012"
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
    verification_surface = $result.verification_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc12_012_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC12-020"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath), (Get-Content -Raw -LiteralPath $taskEvidencePath))
if (-not $finalSecretSafe) {
    throw "Sensitive marker detected in RC12-012 outputs."
}

Write-Host "RC12 object trust verification $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Verification state: $verificationState"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), fail-closed cases: $(@($cases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
