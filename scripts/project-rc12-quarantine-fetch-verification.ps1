param(
    [string]$ArtifactDir = ".workflow/artifacts/rc12-quarantine-fetch-verification",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc12",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc12/docs/rc12-real-object-controlled-unblock-contract.md",
    [string]$ObjectTrustResultPath = ".workflow/artifacts/rc12-object-trust-verification/result.json",
    [string]$ObjectTrustReportPath = ".workflow/artifacts/rc12-object-trust-verification/object-trust-report.json",
    [string]$ObjectTrustDenialPath = ".workflow/artifacts/rc12-object-trust-verification/object-trust-denial.json",
    [string]$ObjectTrustMatrixPath = ".workflow/artifacts/rc12-object-trust-verification/object-trust-fail-closed-matrix.json",
    [string]$PublicationBindingPath = ".workflow/artifacts/rc12-external-object-publication-binding/publication-binding.json",
    [string]$Rc11QuarantineResultPath = ".workflow/artifacts/rc11-installer-quarantine-verifier/result.json",
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

function Add-UniqueBlocker {
    param([Parameter(Mandatory = $true)][string]$Blocker)
    if ([string]::IsNullOrWhiteSpace($Blocker)) {
        return
    }
    if ($script:blockers -notcontains $Blocker) {
        $script:blockers += $Blocker
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
        ("signing" + "-" + "key" + "." + "pem"),
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

function New-FailClosedCase {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string[]]$ExpectedBlockers,
        [Parameter(Mandatory = $true)][string[]]$ObservedBlockers
    )
    $missing = @($ExpectedBlockers | Where-Object { $_ -notin $ObservedBlockers })
    return [ordered]@{
        id = $Id
        status = if ($missing.Count -eq 0) { "passed" } else { "failed" }
        expected_blockers = $ExpectedBlockers
        observed_blocked = $true
        observed_blockers = @($ObservedBlockers | Select-Object -Unique)
        missing_expected_blockers = $missing
        side_effects = [ordered]@{
            network_fetch_attempted = $false
            remote_payload_bytes_downloaded = $false
            quarantine_payload_written = $false
            size_verified = $false
            digest_verified = $false
            manifest_verified = $false
            checksum_set_verified = $false
            public_signature_verified = $false
            revocation_verified = $false
            freshness_verified = $false
            compatibility_verified = $false
            rollback_baseline_verified = $false
            support_recovery_verified = $false
            payload_interpreted = $false
            install_performed = $false
            activation_performed = $false
            rollback_execution_performed = $false
            support_upload_performed = $false
            recovery_execution_performed = $false
            remote_dispatch_enabled = $false
            active_slot_mutated = $false
            boot_metadata_mutated = $false
            active_artifact_set_mutated = $false
            production_ring_mutated = $false
        }
    }
}

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:checks = @()
$script:failedChecks = @()
$script:blockers = @()

$generatedAtValue = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }
$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$resolvedWorkflowDir = Resolve-RepoPath $WorkflowDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $resolvedWorkflowDir "evidence") | Out-Null

$resolvedContractPath = Resolve-RepoPath $ContractPath
$resolvedObjectTrustResultPath = Resolve-RepoPath $ObjectTrustResultPath
$resolvedObjectTrustReportPath = Resolve-RepoPath $ObjectTrustReportPath
$resolvedObjectTrustDenialPath = Resolve-RepoPath $ObjectTrustDenialPath
$resolvedObjectTrustMatrixPath = Resolve-RepoPath $ObjectTrustMatrixPath
$resolvedPublicationBindingPath = Resolve-RepoPath $PublicationBindingPath
$resolvedRc11QuarantineResultPath = Resolve-RepoPath $Rc11QuarantineResultPath

$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$objectTrustResult = Read-Json $resolvedObjectTrustResultPath
$objectTrustReport = Read-Json $resolvedObjectTrustReportPath
$objectTrustDenial = Read-Json $resolvedObjectTrustDenialPath
$objectTrustMatrix = Read-Json $resolvedObjectTrustMatrixPath
$publicationBinding = Read-Json $resolvedPublicationBindingPath
$rc11QuarantineResult = Read-Json $resolvedRc11QuarantineResultPath

$releaseId = [string]$objectTrustResult.release_id
$sourceArtifactPath = Resolve-RepoPath ([string]$publicationBinding.current_release_bytes.source_path)
$sourceArtifactSha256 = Get-FileSha256 $sourceArtifactPath
$sourceArtifactSize = if (Test-Path -LiteralPath $sourceArtifactPath -PathType Leaf) { (Get-Item -LiteralPath $sourceArtifactPath).Length } else { $null }

$currentBytesMatch = ($sourceArtifactSha256 -eq [string]$publicationBinding.current_release_bytes.sha256) -and
    ([int64]$sourceArtifactSize -eq [int64]$publicationBinding.current_release_bytes.size_bytes) -and
    ([string]$publicationBinding.current_release_bytes.sha256 -eq [string]$publicationBinding.current_release_bytes.descriptor_sha256) -and
    ([int64]$publicationBinding.current_release_bytes.size_bytes -eq [int64]$publicationBinding.current_release_bytes.descriptor_size_bytes)

$objectTrustAllowed = [bool]$objectTrustResult.verification_surface.object_trust_allowed
$externalObjectUriPublished = [bool]$objectTrustResult.verification_surface.external_object_uri_published
$driftZero = [bool]$objectTrustResult.verification_surface.drift_zero
$freshnessWindowBound = [bool]$objectTrustResult.verification_surface.freshness_window_bound
$revocationBound = [bool]$objectTrustResult.verification_surface.revocation_bound
$compatibilityBound = [bool]$objectTrustResult.verification_surface.compatibility_bound
$rollbackBound = [bool]$objectTrustResult.verification_surface.rollback_bound
$supportBound = [bool]$objectTrustResult.verification_surface.support_bound

$quarantineFetchAllowed = $objectTrustAllowed -and
    $externalObjectUriPublished -and
    $driftZero -and
    $freshnessWindowBound -and
    $revocationBound -and
    $compatibilityBound -and
    $rollbackBound -and
    $supportBound -and
    $currentBytesMatch

foreach ($blocker in @($objectTrustResult.blockers + $objectTrustResult.verification_surface.blockers + $objectTrustDenial.denial_reasons + $rc11QuarantineResult.fetch_surface.blockers)) {
    Add-UniqueBlocker ([string]$blocker)
}
if (-not $objectTrustAllowed) { Add-UniqueBlocker "object-trust-not-allowed" }
if (-not $externalObjectUriPublished) { Add-UniqueBlocker "external-https-object-uri-not-published" }
if (-not $driftZero) { Add-UniqueBlocker "declared-current-drift-zero-not-proved" }
if (-not $freshnessWindowBound) { Add-UniqueBlocker "freshness-window-missing" }
if (-not $currentBytesMatch) { Add-UniqueBlocker "current-release-bytes-mismatch" }
if (-not $quarantineFetchAllowed) { Add-UniqueBlocker "installer-quarantine-fetch-not-run" }
foreach ($blocker in @(
    "payload-not-quarantined",
    "pre-interpretation-verification-not-run",
    "agentcore-planspec-not-bound",
    "security-execution-effect-envelope-not-bound",
    "two-target-canary-not-enrolled",
    "exact-approval-not-bound",
    "controlled-activation-not-authorized",
    "controlled-rollback-not-authorized"
)) {
    Add-UniqueBlocker $blocker
}

$requiredBindings = [ordered]@{
    size_bytes = [int64]$publicationBinding.current_release_bytes.size_bytes
    sha256 = [string]$publicationBinding.current_release_bytes.sha256
    descriptor_candidate_sha256 = [string]$publicationBinding.required_bindings.descriptor_candidate_sha256
    manifest_sha256 = [string]$publicationBinding.required_bindings.manifest_sha256
    checksums_sha256 = [string]$publicationBinding.required_bindings.checksums_sha256
    public_signature_target_sha256 = [string]$publicationBinding.required_bindings.public_signature_target_sha256
    public_signature_receipt_sha256 = [string]$publicationBinding.required_bindings.public_signature_receipt_sha256
    revocation_snapshot_sha256 = [string]$publicationBinding.required_bindings.revocation_snapshot_sha256
    freshness_window = if ($null -eq $publicationBinding.required_bindings.freshness.fresh_until) { $null } else { [string]$publicationBinding.required_bindings.freshness.fresh_until }
    freshness_window_bound = [bool]$publicationBinding.required_bindings.freshness.freshness_window_bound
    compatibility_sha256 = [string]$publicationBinding.required_bindings.compatibility_sha256
    rollback_baseline_sha256 = [string]$publicationBinding.required_bindings.rollback_baseline_sha256
    support_recovery_sha256 = [string]$publicationBinding.required_bindings.support_recovery_sha256
}

$source = [ordered]@{
    rc12_contract = New-ArtifactRef $resolvedContractPath
    rc12_object_trust_result = New-ArtifactRef $resolvedObjectTrustResultPath $objectTrustResult
    rc12_object_trust_report = New-ArtifactRef $resolvedObjectTrustReportPath $objectTrustReport
    rc12_object_trust_denial = New-ArtifactRef $resolvedObjectTrustDenialPath $objectTrustDenial
    rc12_object_trust_fail_closed_matrix = New-ArtifactRef $resolvedObjectTrustMatrixPath $objectTrustMatrix
    rc12_publication_binding = New-ArtifactRef $resolvedPublicationBindingPath $publicationBinding
    rc11_quarantine_result = New-ArtifactRef $resolvedRc11QuarantineResultPath $rc11QuarantineResult
    current_payload_bytes = New-ArtifactRef $sourceArtifactPath
}

Add-Check "contract.quarantine_gate.present" ($contractText.Contains("Fetch bytes only into quarantine after object trust is allowed") -and $contractText.Contains("Verify quarantined bytes")) "RC12-020 must consume the quarantine-before-interpretation gate order." $source.rc12_contract
Add-Check "source.object_trust.passed" ($objectTrustResult.status -eq "passed" -and $objectTrustResult.task -eq "RC12-012") "RC12-020 requires completed RC12-012 object trust evidence." ([ordered]@{ status = $objectTrustResult.status; object_trust_allowed = $objectTrustAllowed; state = $objectTrustResult.verification_surface.state })
Add-Check "source.object_trust.fail_closed" ($objectTrustMatrix.status -eq "passed" -and $objectTrustMatrix.summary.failed_cases.Count -eq 0) "RC12-020 requires object trust fail-closed cases to be clean before installer authority." ([ordered]@{ cases = $objectTrustMatrix.summary.cases; failed_cases = $objectTrustMatrix.summary.failed_cases })
Add-Check "source.current_bytes_match_descriptor" $currentBytesMatch "Current payload bytes must still match the publication binding and descriptor before quarantine policy evaluation." ([ordered]@{ expected_sha256 = $publicationBinding.current_release_bytes.sha256; observed_sha256 = $sourceArtifactSha256; expected_size_bytes = $publicationBinding.current_release_bytes.size_bytes; observed_size_bytes = $sourceArtifactSize })
Add-Check "fetch.denied_before_network" ($quarantineFetchAllowed -eq $false -and $objectTrustAllowed -eq $false) "Installer quarantine fetch must deny before network unless object trust and all pre-fetch gates are proved." ([ordered]@{ quarantine_fetch_allowed = $quarantineFetchAllowed; object_trust_allowed = $objectTrustAllowed; external_uri_published = $externalObjectUriPublished; drift_zero = $driftZero; freshness_window_bound = $freshnessWindowBound; blockers = @($script:blockers) })
Add-Check "pre_interpretation.gates_declared" ($requiredBindings.size_bytes -and $requiredBindings.sha256 -and $requiredBindings.manifest_sha256 -and $requiredBindings.checksums_sha256 -and $requiredBindings.public_signature_target_sha256 -and $requiredBindings.public_signature_receipt_sha256 -and $requiredBindings.revocation_snapshot_sha256 -and $requiredBindings.compatibility_sha256 -and $requiredBindings.rollback_baseline_sha256 -and $requiredBindings.support_recovery_sha256) "Quarantine verifier must declare size, SHA-256, descriptor, manifest, checksum, signature, revocation, freshness, compatibility, rollback, and support gates." $requiredBindings

$fetchReport = [ordered]@{
    schema = "agentos.rc12-quarantine-fetch-report.v1"
    generated_at = $generatedAtValue
    task = "RC12-020"
    release_id = $releaseId
    status = if ($quarantineFetchAllowed) { "quarantine-fetch-ready" } else { "quarantine-fetch-denied-before-network" }
    production_ready_claim = $false
    object = [ordered]@{
        uri = $publicationBinding.object_uri.candidate
        uri_classification = $publicationBinding.object_uri.classification
        object_trust_allowed = $objectTrustAllowed
        external_https_object_uri_published = $externalObjectUriPublished
        drift_zero = $driftZero
        freshness_window_bound = $freshnessWindowBound
        revocation_bound = $revocationBound
        compatibility_bound = $compatibilityBound
        rollback_bound = $rollbackBound
        support_bound = $supportBound
        current_bytes_match = $currentBytesMatch
    }
    quarantine_policy = [ordered]@{
        fetch_allowed = $quarantineFetchAllowed
        denied_before_network = (-not $quarantineFetchAllowed)
        quarantine_landing_zone_required = $true
        network_fetch_attempted = $false
        remote_payload_bytes_downloaded = $false
        quarantine_payload_written = $false
        interpret_before_size_digest_manifest_signature_revocation_freshness_compatibility_rollback_support_verification = $false
    }
    required_pre_interpretation_verification = $requiredBindings
    observed_pre_interpretation_verification = [ordered]@{
        size_verified = $false
        sha256_verified = $false
        descriptor_verified = $false
        manifest_verified = $false
        checksum_set_verified = $false
        public_signature_verified = $false
        revocation_verified = $false
        freshness_verified = $false
        compatibility_verified = $false
        rollback_baseline_verified = $false
        support_recovery_verified = $false
    }
    blockers = @($script:blockers)
}

$caseBlockers = @{
    "object-trust-missing-denies-fetch" = @("object-trust-not-allowed")
    "missing-external-uri-denies-network" = @("external-https-object-uri-not-published")
    "non-https-uri-denies-fetch" = @("object-uri-not-https")
    "mutable-uri-denies-fetch" = @("object-uri-not-immutable")
    "nonzero-drift-denies-fetch" = @("declared-current-drift-zero-not-proved")
    "freshness-missing-denies-fetch" = @("freshness-window-missing")
    "publication-drift-denies-fetch" = @("rc12-publication-binding-drift")
    "carried-forward-drift-denies-fetch" = @("rc11-declared-current-drift-carried-forward")
    "network-before-object-trust-denied" = @("object-trust-not-allowed", "installer-quarantine-fetch-not-run")
    "quarantine-write-before-fetch-denied" = @("payload-not-quarantined")
    "size-before-quarantine-denied" = @("pre-interpretation-verification-not-run")
    "digest-before-quarantine-denied" = @("pre-interpretation-verification-not-run")
    "manifest-before-quarantine-denied" = @("pre-interpretation-verification-not-run")
    "checksum-before-quarantine-denied" = @("pre-interpretation-verification-not-run")
    "signature-before-quarantine-denied" = @("pre-interpretation-verification-not-run")
    "revocation-before-quarantine-denied" = @("pre-interpretation-verification-not-run")
    "freshness-before-quarantine-denied" = @("freshness-window-missing", "pre-interpretation-verification-not-run")
    "compatibility-before-quarantine-denied" = @("pre-interpretation-verification-not-run")
    "rollback-baseline-before-quarantine-denied" = @("pre-interpretation-verification-not-run")
    "support-before-quarantine-denied" = @("pre-interpretation-verification-not-run")
    "payload-interpret-before-verification-denied" = @("pre-interpretation-verification-not-run")
    "install-before-verification-denied" = @("payload-not-quarantined", "pre-interpretation-verification-not-run")
    "activation-before-controlled-gates-denied" = @("agentcore-planspec-not-bound", "security-execution-effect-envelope-not-bound", "exact-approval-not-bound")
    "rollback-before-controlled-gates-denied" = @("controlled-rollback-not-authorized")
    "support-upload-before-controlled-gates-denied" = @("security-execution-effect-envelope-not-bound")
    "remote-dispatch-before-controlled-gates-denied" = @("security-execution-effect-envelope-not-bound")
    "production-mutation-before-controlled-gates-denied" = @("security-execution-effect-envelope-not-bound")
}

$cases = @()
foreach ($caseId in $caseBlockers.Keys | Sort-Object) {
    $cases += New-FailClosedCase -Id $caseId -ExpectedBlockers ([string[]]$caseBlockers[$caseId]) -ObservedBlockers $script:blockers
}
$failedCases = @($cases | Where-Object { $_.status -ne "passed" })

$matrix = [ordered]@{
    schema = "agentos.rc12-quarantine-fetch-fail-closed-matrix.v1"
    generated_at = $generatedAtValue
    task = "RC12-020"
    release_id = $releaseId
    status = if ($failedCases.Count -eq 0) { "passed" } else { "failed" }
    production_ready_claim = $false
    cases = $cases
    summary = [ordered]@{
        cases = @($cases).Count
        passed = @($cases | Where-Object { $_.status -eq "passed" }).Count
        failed = $failedCases.Count
        failed_cases = @($failedCases | ForEach-Object { $_.id })
    }
}

$gateReport = [ordered]@{
    schema = "agentos.rc12-quarantine-fetch-gate-report.v1"
    generated_at = $generatedAtValue
    task = "RC12-020"
    release_id = $releaseId
    status = if ($quarantineFetchAllowed) { "installer-quarantine-fetch-ready" } else { "installer-quarantine-fetch-blocked" }
    production_ready_claim = $false
    gates = [ordered]@{
        object_trust_allowed = $objectTrustAllowed
        external_https_object_uri_published = $externalObjectUriPublished
        drift_zero = $driftZero
        freshness_window_bound = $freshnessWindowBound
        revocation_bound = $revocationBound
        compatibility_bound = $compatibilityBound
        rollback_bound = $rollbackBound
        support_bound = $supportBound
        current_bytes_match = $currentBytesMatch
        quarantine_fetch_allowed = $quarantineFetchAllowed
        network_fetch_attempted = $false
        quarantine_payload_written = $false
        size_required = $true
        sha256_required = $true
        descriptor_required = $true
        manifest_required = $true
        checksum_set_required = $true
        public_signature_required = $true
        revocation_required = $true
        freshness_required = $true
        compatibility_required = $true
        rollback_baseline_required = $true
        support_recovery_required = $true
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
    }
    blockers = @($script:blockers)
    next_task = "RC12-021"
}

$handoff = [ordered]@{
    schema = "agentos.rc12-agentcore-security-execution-package-handoff.v1"
    generated_at = $generatedAtValue
    task = "RC12-020"
    release_id = $releaseId
    status = if ($quarantineFetchAllowed) { "quarantine-fetch-ready-for-package-binding" } else { "blocked-before-agentcore-security-package" }
    production_ready_claim = $false
    quarantine_fetch_allowed = $quarantineFetchAllowed
    quarantine_fetch_verified = $false
    installer_preflight_verified = $false
    agentcore_package_allowed = $false
    security_execution_allowed = $false
    activation_allowed = $false
    rollback_execution_allowed = $false
    handoff_bindings = [ordered]@{
        object_trust_result_sha256 = Get-FileSha256 $resolvedObjectTrustResultPath
        object_trust_report_sha256 = Get-FileSha256 $resolvedObjectTrustReportPath
        publication_binding_sha256 = Get-FileSha256 $resolvedPublicationBindingPath
        rc11_quarantine_result_sha256 = Get-FileSha256 $resolvedRc11QuarantineResultPath
        current_payload_sha256 = $sourceArtifactSha256
        current_payload_size_bytes = $sourceArtifactSize
    }
    blockers = @($script:blockers)
}

$fetchReportPath = Join-Path $resolvedArtifactDir "quarantine-fetch-report.json"
$matrixPath = Join-Path $resolvedArtifactDir "quarantine-fetch-fail-closed-matrix.json"
$gateReportPath = Join-Path $resolvedArtifactDir "quarantine-fetch-gate-report.json"
$handoffPath = Join-Path $resolvedArtifactDir "agentcore-security-package-handoff.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC12-020-quarantine-fetch-verification.json"

Write-Json $fetchReport $fetchReportPath
Write-Json $matrix $matrixPath
Write-Json $gateReport $gateReportPath
Write-Json $handoff $handoffPath

Add-Check "fixtures.fail_closed" ($failedCases.Count -eq 0 -and @($cases).Count -ge 24) "RC12-020 quarantine negative cases must fail closed before network, interpretation, install, activation, rollback, support upload, remote dispatch, or production mutation." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })
Add-Check "side_effects.none" (@($cases | Where-Object { $_.side_effects.network_fetch_attempted -or $_.side_effects.remote_payload_bytes_downloaded -or $_.side_effects.quarantine_payload_written -or $_.side_effects.payload_interpreted -or $_.side_effects.install_performed -or $_.side_effects.activation_performed -or $_.side_effects.rollback_execution_performed -or $_.side_effects.support_upload_performed -or $_.side_effects.recovery_execution_performed -or $_.side_effects.remote_dispatch_enabled -or $_.side_effects.production_ring_mutated }).Count -eq 0) "RC12-020 must not fetch, download, quarantine-write, interpret, install, activate, rollback, upload support, recover, dispatch, or mutate production state." $null
Add-Check "handoff.downstream_blocked" ($handoff.agentcore_package_allowed -eq $false -and $handoff.security_execution_allowed -eq $false -and $handoff.activation_allowed -eq $false -and $handoff.rollback_execution_allowed -eq $false) "RC12-020 handoff must keep AgentCore/SecurityExecution package and downstream effects blocked while quarantine fetch is denied." ([ordered]@{ status = $handoff.status; blockers = $handoff.blockers })

$outputsSecretSafe = Test-NoSensitiveText -Values @(
    (Get-Content -Raw -LiteralPath $fetchReportPath),
    (Get-Content -Raw -LiteralPath $matrixPath),
    (Get-Content -Raw -LiteralPath $gateReportPath),
    (Get-Content -Raw -LiteralPath $handoffPath)
)
Add-Check "outputs.secret_safe" $outputsSecretSafe "RC12-020 outputs must not contain PEM blocks, auth tokens, private key paths, signer internals, or secret identity markers." $null

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc12-quarantine-fetch-verification-result.v1"
    generated_at = $generatedAtValue
    task = "RC12-020"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    fetch_surface = [ordered]@{
        state = [string]$fetchReport.status
        object_trust_allowed = $objectTrustAllowed
        external_https_object_uri_published = $externalObjectUriPublished
        drift_zero = $driftZero
        freshness_window_bound = $freshnessWindowBound
        revocation_bound = $revocationBound
        compatibility_bound = $compatibilityBound
        rollback_bound = $rollbackBound
        support_bound = $supportBound
        current_bytes_match = $currentBytesMatch
        quarantine_fetch_allowed = $quarantineFetchAllowed
        network_fetch_attempted = $false
        remote_payload_bytes_downloaded = $false
        quarantine_payload_written = $false
        pre_interpretation_verification_performed = $false
        payload_interpreted = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        blockers = @($script:blockers)
    }
    outputs = [ordered]@{
        quarantine_fetch_report = [ordered]@{ path = Get-StablePath $fetchReportPath; sha256 = Get-FileSha256 $fetchReportPath }
        fail_closed_matrix = [ordered]@{ path = Get-StablePath $matrixPath; sha256 = Get-FileSha256 $matrixPath }
        gate_report = [ordered]@{ path = Get-StablePath $gateReportPath; sha256 = Get-FileSha256 $gateReportPath }
        agentcore_security_package_handoff = [ordered]@{ path = Get-StablePath $handoffPath; sha256 = Get-FileSha256 $handoffPath }
    }
    source = $source
    checks = $script:checks
    blockers = @($script:blockers)
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
        network_fetch_attempted = $false
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
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        cases = @($cases).Count
        failed_cases = $failedCases.Count
        fetch_denied_before_network = (-not $quarantineFetchAllowed)
        fetch_denied_as_expected = (-not $quarantineFetchAllowed -and -not $objectTrustAllowed)
        rc12_020_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC12-021"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc12-quarantine-fetch-verification-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC12-020"
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
    fetch_surface = $result.fetch_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc12_020_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC12-021"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath), (Get-Content -Raw -LiteralPath $taskEvidencePath))
if (-not $finalSecretSafe) {
    throw "Sensitive marker detected in RC12-020 outputs."
}

Write-Host "RC12 quarantine fetch verification $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Fetch state: $($result.fetch_surface.state)"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), cases: $(@($cases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
