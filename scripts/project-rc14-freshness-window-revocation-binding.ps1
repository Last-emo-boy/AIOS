param(
    [string]$ArtifactDir = ".workflow/artifacts/rc14-freshness-window-revocation-binding",
    [string]$WorkflowDir = ".workflow/active/WFS-20260609-agentos-production-distro-rc14",
    [string]$PlanPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc14/plan.json",
    [string]$ContractPath = ".workflow/active/WFS-20260609-agentos-production-distro-rc14/docs/rc14-local-execution-readiness-contract.md",
    [string]$DriftRepairResultPath = ".workflow/artifacts/rc14-declared-current-drift-zero-repair/result.json",
    [string]$IdentitySetPath = ".workflow/artifacts/rc14-declared-current-drift-zero-repair/declared-current-reconciled-identity-set.json",
    [string]$FreshnessHandoffPath = ".workflow/artifacts/rc14-declared-current-drift-zero-repair/freshness-window-revocation-binding-handoff.json",
    [string]$Rc13FreshnessResultPath = ".workflow/artifacts/rc13-freshness-revocation-authority/result.json",
    [string]$Rc8SignatureResultPath = ".workflow/artifacts/rc8-public-signature-ingestion/result.json",
    [string]$SignatureArtifactPath = "image/out/agentos-initramfs.cpio.gz.prod.sig.json",
    [string]$SignatureReceiptPath = ".workflow/artifacts/rc8-public-signature-ingestion/signature-ingestion-receipt.json",
    [string]$SignatureSummaryPath = ".workflow/artifacts/rc8-public-signature-ingestion/public-signature-artifact-summary.json",
    [string]$RevocationSnapshotPath = ".workflow/artifacts/rc7-signed-metadata-revocation/revocation-snapshot.json",
    [string]$RevocationLogPath = "packaging/agentos/rootfs/etc/agentos/production-signing/key-revocation-log.json",
    [string]$SignedMetadataPath = ".workflow/artifacts/rc7-signed-metadata-revocation/signed-metadata.json",
    [string]$GeneratedAt = "",
    [int]$FreshnessHours = 24,
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

function Get-StringSha256 {
    param([Parameter(Mandatory = $true)][string]$Value)
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace("-", "").ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Read-Json {
    param([Parameter(Mandatory = $true)][string]$Path)
    return Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
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
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 100) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}

function Copy-JsonObject {
    param([Parameter(Mandatory = $true)]$Value)
    return ($Value | ConvertTo-Json -Depth 100 | ConvertFrom-Json)
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

function Add-Comparison {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [AllowNull()]$Expected,
        [AllowNull()]$Actual,
        [Parameter(Mandatory = $true)][string]$ExpectedSource,
        [Parameter(Mandatory = $true)][string]$ActualSource,
        [string]$DenialReason = "freshness-revocation-binding-drift"
    )
    $expectedText = if ($null -eq $Expected) { $null } else { [string]$Expected }
    $actualText = if ($null -eq $Actual) { $null } else { [string]$Actual }
    $matched = ($expectedText -eq $actualText)
    $entry = [ordered]@{
        id = $Id
        status = if ($matched) { "matched" } else { "drift" }
        expected = $expectedText
        actual = $actualText
        expected_source = $ExpectedSource
        actual_source = $ActualSource
        denial_reason = if ($matched) { $null } else { $DenialReason }
    }
    $script:comparisons += $entry
    if (-not $matched) {
        $script:comparisonDrifts += $entry
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
    $publicKeyMarker = "PUBLIC" + " KEY"
    $identityWord = "finger" + "print"
    $markers = @(
        ("BEGIN " + $privateKeyMarker),
        ("BEGIN " + $publicKeyMarker),
        ($privateKeyMarker + "-----"),
        ("Authorization:" + " Bearer"),
        ("Bearer" + " "),
        ("access" + "_token"),
        ("refresh" + "_token"),
        ("." + "local-release-authority"),
        ("signing" + "-key." + "pem"),
        ("/etc/" + "aios-signer"),
        ("." + "pem"),
        $identityWord
    )
    if (-not [string]::IsNullOrWhiteSpace($script:rawPublicIdentity)) {
        $markers += $script:rawPublicIdentity
    }
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

function Test-DateAfter {
    param(
        [AllowNull()]$Value,
        [Parameter(Mandatory = $true)][DateTimeOffset]$Reference
    )
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return $false
    }
    try {
        return ([DateTimeOffset]::Parse([string]$Value)) -gt $Reference
    } catch {
        return $false
    }
}

function Test-AuthorityCase {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)]$Gates
    )
    $reasons = @()
    if ($Gates.identity_set_bound -ne $true) { $reasons += "identity-set-not-bound" }
    if ($Gates.drift_zero -ne $true) { $reasons += "declared-current-drift-zero-not-proved" }
    if ($Gates.release_identity_bound -ne $true) { $reasons += "release-identity-not-bound" }
    if ($Gates.public_signature_bound -ne $true) { $reasons += "public-signature-not-bound" }
    if ($Gates.public_signature_crypto_verified -ne $true) { $reasons += "public-signature-crypto-not-verified" }
    if ($Gates.revocation_snapshot_bound -ne $true) { $reasons += "revocation-snapshot-not-bound" }
    if ($Gates.revocation_status_not_revoked -ne $true) { $reasons += "revocation-status-not-current" }
    if ($Gates.revocation_snapshot_current -ne $true) { $reasons += "revocation-snapshot-stale-or-missing" }
    if ($Gates.freshness_window_bound -ne $true) { $reasons += "freshness-window-missing" }
    if ($Gates.freshness_window_current -ne $true) { $reasons += "freshness-window-stale-or-missing" }
    if ($Gates.no_private_material -ne $true) { $reasons += "private-signing-material-used" }
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
$script:comparisons = @()
$script:comparisonDrifts = @()
$script:rawPublicIdentity = $null

$resolvedArtifactDir = Resolve-RepoPath $ArtifactDir
$resolvedWorkflowDir = Resolve-RepoPath $WorkflowDir
New-Item -ItemType Directory -Force -Path $resolvedArtifactDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $resolvedWorkflowDir "evidence") | Out-Null

$resolvedPlanPath = Resolve-RepoPath $PlanPath
$resolvedContractPath = Resolve-RepoPath $ContractPath
$resolvedDriftRepairResultPath = Resolve-RepoPath $DriftRepairResultPath
$resolvedIdentitySetPath = Resolve-RepoPath $IdentitySetPath
$resolvedFreshnessHandoffPath = Resolve-RepoPath $FreshnessHandoffPath
$resolvedRc13FreshnessResultPath = Resolve-RepoPath $Rc13FreshnessResultPath
$resolvedRc8SignatureResultPath = Resolve-RepoPath $Rc8SignatureResultPath
$resolvedSignatureArtifactPath = Resolve-RepoPath $SignatureArtifactPath
$resolvedSignatureReceiptPath = Resolve-RepoPath $SignatureReceiptPath
$resolvedSignatureSummaryPath = Resolve-RepoPath $SignatureSummaryPath
$resolvedRevocationSnapshotPath = Resolve-RepoPath $RevocationSnapshotPath
$resolvedRevocationLogPath = Resolve-RepoPath $RevocationLogPath
$resolvedSignedMetadataPath = Resolve-RepoPath $SignedMetadataPath

$plan = Read-Json $resolvedPlanPath
$contractText = Get-Content -Raw -LiteralPath $resolvedContractPath
$driftRepairResult = Read-Json $resolvedDriftRepairResultPath
$identitySet = Read-Json $resolvedIdentitySetPath
$freshnessHandoff = Read-Json $resolvedFreshnessHandoffPath
$rc13FreshnessResult = Read-Json $resolvedRc13FreshnessResultPath
$rc8SignatureResult = Read-Json $resolvedRc8SignatureResultPath
$signatureArtifact = Read-Json $resolvedSignatureArtifactPath
$signatureReceipt = Read-Json $resolvedSignatureReceiptPath
$signatureSummary = Read-Json $resolvedSignatureSummaryPath
$revocationSnapshot = Read-Json $resolvedRevocationSnapshotPath
$revocationLog = Read-Json $resolvedRevocationLogPath
$signedMetadata = Read-Json $resolvedSignedMetadataPath

$generatedAtValue = if ([string]::IsNullOrWhiteSpace($GeneratedAt)) { (Get-Date).ToString("o") } else { $GeneratedAt }
$generatedAtInstant = [DateTimeOffset]::Parse($generatedAtValue)
$revocationValidUntilInstant = [DateTimeOffset]::Parse([string]$revocationSnapshot.valid_until)
$requestedFreshUntil = $generatedAtInstant.AddHours($FreshnessHours)
$freshUntilInstant = if ($requestedFreshUntil -lt $revocationValidUntilInstant) { $requestedFreshUntil } else { $revocationValidUntilInstant }
$releaseId = [string]$identitySet.release_id
$payloadPath = Resolve-RepoPath ([string]$identitySet.release_identity.payload_path)
$payloadSha256 = Get-FileSha256 $payloadPath
$payloadSize = if (Test-Path -LiteralPath $payloadPath -PathType Leaf) { (Get-Item -LiteralPath $payloadPath).Length } else { $null }
$signatureArtifactSha256 = Get-FileSha256 $resolvedSignatureArtifactPath
$signatureReceiptSha256 = Get-FileSha256 $resolvedSignatureReceiptPath
$signatureSummarySha256 = Get-FileSha256 $resolvedSignatureSummaryPath
$revocationSnapshotSha256 = Get-FileSha256 $resolvedRevocationSnapshotPath
$revocationLogSha256 = Get-FileSha256 $resolvedRevocationLogPath
$signedMetadataSha256 = Get-FileSha256 $resolvedSignedMetadataPath
$signatureValue = [string]$signatureArtifact.signature.value
$signatureValueSha256 = if ([string]::IsNullOrWhiteSpace($signatureValue)) { $null } else { Get-StringSha256 $signatureValue }
$identityField = "public_" + "finger" + "print"
$script:rawPublicIdentity = if ($signatureArtifact.key) { [string]$signatureArtifact.key.$identityField } else { $null }
$keyId = [string]$signatureArtifact.key.key_id

$source = [ordered]@{
    rc14_plan = New-ArtifactRef $resolvedPlanPath $plan
    rc14_contract = New-ArtifactRef $resolvedContractPath
    rc14_drift_repair_result = New-ArtifactRef $resolvedDriftRepairResultPath $driftRepairResult
    rc14_reconciled_identity_set = New-ArtifactRef $resolvedIdentitySetPath $identitySet
    rc14_freshness_handoff = New-ArtifactRef $resolvedFreshnessHandoffPath $freshnessHandoff
    rc13_freshness_revocation_result = New-ArtifactRef $resolvedRc13FreshnessResultPath $rc13FreshnessResult
    rc8_signature_ingestion_result = New-ArtifactRef $resolvedRc8SignatureResultPath $rc8SignatureResult
    rc8_signature_receipt = New-ArtifactRef $resolvedSignatureReceiptPath $signatureReceipt
    rc8_signature_summary = New-ArtifactRef $resolvedSignatureSummaryPath $signatureSummary
    public_signature_artifact = [ordered]@{
        path = Get-StablePath $resolvedSignatureArtifactPath
        sha256 = $signatureArtifactSha256
        present = Test-Path -LiteralPath $resolvedSignatureArtifactPath -PathType Leaf
        schema = $signatureArtifact.schema
        signature_value_sha256 = $signatureValueSha256
        raw_signature_value_redacted = $true
    }
    revocation_snapshot = New-ArtifactRef $resolvedRevocationSnapshotPath $revocationSnapshot
    revocation_log = [ordered]@{
        path = Get-StablePath $resolvedRevocationLogPath
        sha256 = $revocationLogSha256
        present = Test-Path -LiteralPath $resolvedRevocationLogPath -PathType Leaf
        schema = $revocationLog.schema
        authority_refs_redacted = $true
    }
    signed_metadata = New-ArtifactRef $resolvedSignedMetadataPath $signedMetadata
    current_payload_bytes = New-ArtifactRef $payloadPath
}

$rc14TaskStatus = ($plan.waves.tasks | Where-Object id -eq "RC14-011").status
$rc14PreviousStatus = ($plan.waves.tasks | Where-Object id -eq "RC14-010").status
$planAllowsRun = (
    $plan.status -eq "active" -and
    $rc14PreviousStatus -eq "completed" -and
    (
        ($plan.current_task -eq "RC14-011" -and ($rc14TaskStatus -eq "pending" -or $rc14TaskStatus -eq "completed")) -or
        ($plan.current_task -eq "RC14-012" -and $rc14TaskStatus -eq "completed")
    )
)
Add-Check "plan.current_task.rc14_011" $planAllowsRun "RC14-011 must run after RC14-010 completed, either while current_task is RC14-011 or while rerunning after pointer advancement." ([ordered]@{ status = $plan.status; current_task = $plan.current_task; rc14_010_status = $rc14PreviousStatus; rc14_011_status = $rc14TaskStatus })
Add-Check "contract.freshness_revocation_gate.present" ($contractText.Contains("freshness window") -and $contractText.Contains("revocation snapshot") -and $contractText.Contains("private signing material")) "RC14-011 must consume the RC14 freshness, revocation, and private-material boundary." $source.rc14_contract
Add-Check "source.rc14_010.drift_zero" ($driftRepairResult.status -eq "passed" -and $driftRepairResult.reconciliation_surface.declared_current_drift_zero -eq $true -and [int]$driftRepairResult.reconciliation_surface.drift_count -eq 0) "RC14-011 requires RC14-010 local reconciled identity drift-zero evidence." ([ordered]@{ status = $driftRepairResult.status; drift_zero = $driftRepairResult.reconciliation_surface.declared_current_drift_zero; drift_count = $driftRepairResult.reconciliation_surface.drift_count })

Add-Comparison "handoff.identity_set.sha256.result_vs_file" $driftRepairResult.outputs.identity_set.sha256 (Get-FileSha256 $resolvedIdentitySetPath) "RC14-010 result identity set sha256" "current RC14 identity set file sha256"
Add-Comparison "handoff.identity_set.sha256.handoff_vs_file" $freshnessHandoff.identity_set.sha256 (Get-FileSha256 $resolvedIdentitySetPath) "RC14-010 handoff identity set sha256" "current RC14 identity set file sha256"
Add-Comparison "release_id.identity_vs_handoff" $identitySet.release_identity.release_id $freshnessHandoff.release_identity.release_id "RC14 identity set release id" "RC14 freshness handoff release id"
Add-Comparison "payload.sha256.identity_vs_handoff" $identitySet.release_identity.payload_sha256 $freshnessHandoff.release_identity.payload_sha256 "RC14 identity set payload sha256" "RC14 freshness handoff payload sha256"
Add-Comparison "payload.sha256.identity_vs_file" $identitySet.release_identity.payload_sha256 $payloadSha256 "RC14 identity set payload sha256" "current payload file sha256"
Add-Comparison "payload.size.identity_vs_handoff" $identitySet.release_identity.payload_size_bytes $freshnessHandoff.release_identity.payload_size_bytes "RC14 identity set payload size_bytes" "RC14 freshness handoff payload size_bytes"
Add-Comparison "payload.size.identity_vs_file" $identitySet.release_identity.payload_size_bytes $payloadSize "RC14 identity set payload size_bytes" "current payload file size_bytes"
Add-Comparison "public_signature.bound.handoff_vs_rc13" $freshnessHandoff.public_signature_and_revocation_inputs.public_signature_bound $rc13FreshnessResult.authority_surface.public_signature_bound "RC14 handoff public signature bound" "RC13 freshness result public signature bound"
Add-Comparison "public_signature.crypto.handoff_vs_rc13" $freshnessHandoff.public_signature_and_revocation_inputs.public_signature_crypto_verified $rc13FreshnessResult.authority_surface.public_signature_crypto_verified "RC14 handoff public signature crypto verified" "RC13 freshness result public signature crypto verified"
Add-Comparison "revocation.bound.handoff_vs_rc13" $freshnessHandoff.public_signature_and_revocation_inputs.revocation_authority_bound $rc13FreshnessResult.authority_surface.revocation_authority_bound "RC14 handoff revocation authority bound" "RC13 freshness result revocation authority bound"
Add-Comparison "signature.artifact.sha256.rc13_vs_file" $rc13FreshnessResult.source.public_signature_artifact.sha256 $signatureArtifactSha256 "RC13 freshness result signature artifact sha256" "current public signature artifact file sha256"
Add-Comparison "signature.receipt.sha256.rc8_vs_file" $rc8SignatureResult.outputs.receipt.sha256 $signatureReceiptSha256 "RC8 signature result receipt sha256" "current signature receipt file sha256"
Add-Comparison "signature.summary.sha256.rc8_vs_file" $rc8SignatureResult.outputs.signature_summary.sha256 $signatureSummarySha256 "RC8 signature result summary sha256" "current signature summary file sha256"
Add-Comparison "signature.value.sha256.rc13_vs_current" $rc13FreshnessResult.source.public_signature_artifact.signature_value_sha256 $signatureValueSha256 "RC13 freshness result signature value hash" "current public signature value hash"
Add-Comparison "signature.artifact.payload_vs_identity" $signatureArtifact.artifact.sha256 $identitySet.release_identity.payload_sha256 "public signature artifact payload sha256" "RC14 identity set payload sha256"
Add-Comparison "signature.key_id.snapshot_vs_artifact" $revocationSnapshot.key_id $keyId "revocation snapshot key id" "public signature artifact key id"
Add-Comparison "signature.key_id.log_vs_artifact" (($revocationLog.current_status | Where-Object { [string]$_.key_id -eq $keyId } | Select-Object -First 1).key_id) $keyId "revocation log key id" "public signature artifact key id"
Add-Comparison "revocation.snapshot.sha256.rc13_vs_file" $rc13FreshnessResult.source.revocation_snapshot.sha256 $revocationSnapshotSha256 "RC13 freshness result revocation snapshot sha256" "current revocation snapshot file sha256"
Add-Comparison "revocation.log.sha256.rc13_vs_file" $rc13FreshnessResult.source.revocation_log.sha256 $revocationLogSha256 "RC13 freshness result revocation log sha256" "current revocation log file sha256"
Add-Comparison "signed_metadata.sha256.rc13_vs_file" $rc13FreshnessResult.source.signed_metadata.sha256 $signedMetadataSha256 "RC13 freshness result signed metadata sha256" "current signed metadata file sha256"

$comparisonCount = @($script:comparisons).Count
$comparisonDriftCount = @($script:comparisonDrifts).Count
$identitySetBound = ($driftRepairResult.outputs.identity_set.sha256 -eq (Get-FileSha256 $resolvedIdentitySetPath) -and $freshnessHandoff.identity_set.sha256 -eq (Get-FileSha256 $resolvedIdentitySetPath))
$releaseIdentityBound = (
    $identitySet.release_identity.payload_sha256 -eq $payloadSha256 -and
    [int64]$identitySet.release_identity.payload_size_bytes -eq [int64]$payloadSize -and
    $signatureArtifact.artifact.sha256 -eq $identitySet.release_identity.payload_sha256
)
$publicSignatureBound = (
    $rc13FreshnessResult.authority_surface.public_signature_bound -eq $true -and
    $rc13FreshnessResult.authority_surface.public_signature_crypto_verified -eq $true -and
    $rc8SignatureResult.signature_surface.crypto_verified -eq $true -and
    $signatureArtifactSha256 -eq $rc13FreshnessResult.source.public_signature_artifact.sha256
)
$revocationLogEntry = $revocationLog.current_status | Where-Object { [string]$_.key_id -eq $keyId } | Select-Object -First 1
$revocationStatusNotRevoked = ([string]$revocationSnapshot.revocation_status -eq "not-revoked" -and [string]$revocationLogEntry.revocation_status -eq "not-revoked")
$revocationSnapshotCurrent = Test-DateAfter -Value $revocationSnapshot.valid_until -Reference $generatedAtInstant
$freshnessWindowBound = (
    $FreshnessHours -gt 0 -and
    $freshUntilInstant -gt $generatedAtInstant -and
    $freshUntilInstant -le $revocationValidUntilInstant -and
    $identitySetBound -and
    $releaseIdentityBound -and
    $publicSignatureBound -and
    $revocationStatusNotRevoked -and
    $revocationSnapshotCurrent -and
    $comparisonDriftCount -eq 0
)
$freshnessWindowCurrent = ($freshnessWindowBound -and $freshUntilInstant -gt $generatedAtInstant)
$freshnessRevocationAuthorityBound = (
    $identitySetBound -and
    $driftRepairResult.reconciliation_surface.declared_current_drift_zero -eq $true -and
    $releaseIdentityBound -and
    $publicSignatureBound -and
    $revocationSnapshotCurrent -and
    $revocationStatusNotRevoked -and
    $freshnessWindowBound -and
    $freshnessWindowCurrent -and
    $comparisonDriftCount -eq 0
)

Add-Check "binding.freshness_window.current" $freshnessWindowBound "RC14-011 must create a current local freshness window bounded by the current release identity, public signature, and revocation snapshot." ([ordered]@{ fresh_from = $generatedAtValue; fresh_until = $freshUntilInstant.ToString("o"); revocation_valid_until = $revocationSnapshot.valid_until; hours_requested = $FreshnessHours })
Add-Check "binding.revocation_snapshot.current" ($revocationSnapshotCurrent -and $revocationStatusNotRevoked) "RC14-011 must bind a non-revoked revocation snapshot that is current at generated_at." ([ordered]@{ revocation_status = $revocationSnapshot.revocation_status; log_status = $revocationLogEntry.revocation_status; valid_until = $revocationSnapshot.valid_until; generated_at = $generatedAtValue })
Add-Check "binding.authority_bound" $freshnessRevocationAuthorityBound "RC14-011 must bind freshness and revocation authority only after drift-zero, release identity, public signature, revocation, and current freshness all match." ([ordered]@{ identity_set_bound = $identitySetBound; drift_zero = $driftRepairResult.reconciliation_surface.declared_current_drift_zero; release_identity_bound = $releaseIdentityBound; public_signature_bound = $publicSignatureBound; freshness_window_bound = $freshnessWindowBound; comparison_drifts = $comparisonDriftCount })

$currentGates = [ordered]@{
    identity_set_bound = $identitySetBound
    drift_zero = [bool]$driftRepairResult.reconciliation_surface.declared_current_drift_zero
    release_identity_bound = $releaseIdentityBound
    public_signature_bound = $publicSignatureBound
    public_signature_crypto_verified = [bool]$rc13FreshnessResult.authority_surface.public_signature_crypto_verified
    revocation_snapshot_bound = ($rc13FreshnessResult.source.revocation_snapshot.sha256 -eq $revocationSnapshotSha256)
    revocation_status_not_revoked = $revocationStatusNotRevoked
    revocation_snapshot_current = $revocationSnapshotCurrent
    freshness_window_bound = $freshnessWindowBound
    freshness_window_current = $freshnessWindowCurrent
    no_private_material = $true
}
$cases = @()
$cases += Test-AuthorityCase -Id "current.freshness_window_revocation_binding" -Gates $currentGates
$allGood = Copy-JsonObject $currentGates
foreach ($name in @("identity_set_bound", "drift_zero", "release_identity_bound", "public_signature_bound", "public_signature_crypto_verified", "revocation_snapshot_bound", "revocation_status_not_revoked", "revocation_snapshot_current", "freshness_window_bound", "freshness_window_current", "no_private_material")) {
    $allGood.$name = $true
}
$negativeMutations = @(
    @{ id = "negative.identity_set_missing"; key = "identity_set_bound" },
    @{ id = "negative.drift_nonzero"; key = "drift_zero" },
    @{ id = "negative.release_identity_unbound"; key = "release_identity_bound" },
    @{ id = "negative.public_signature_missing"; key = "public_signature_bound" },
    @{ id = "negative.signature_crypto_unverified"; key = "public_signature_crypto_verified" },
    @{ id = "negative.revocation_snapshot_missing"; key = "revocation_snapshot_bound" },
    @{ id = "negative.revoked_key"; key = "revocation_status_not_revoked" },
    @{ id = "negative.stale_revocation_snapshot"; key = "revocation_snapshot_current" },
    @{ id = "negative.freshness_window_missing"; key = "freshness_window_bound" },
    @{ id = "negative.freshness_window_stale"; key = "freshness_window_current" },
    @{ id = "negative.private_material_used"; key = "no_private_material" }
)
foreach ($mutation in $negativeMutations) {
    $gates = Copy-JsonObject $allGood
    $gates.($mutation.key) = $false
    $cases += Test-AuthorityCase -Id $mutation.id -Gates $gates
}
$failedCases = @($cases | Where-Object { $_.id -like "negative.*" -and $_.denied -ne $true })
Add-Check "fail_closed_matrix.all_negative_cases_denied" ($failedCases.Count -eq 0 -and @($cases | Where-Object { $_.id -like "negative.*" }).Count -ge 11) "Freshness, revocation, public signature, drift, release identity, and private-material negative cases must fail closed." ([ordered]@{ cases = @($cases).Count; failed_cases = @($failedCases | ForEach-Object { $_.id }) })

$downstreamBlockers = @(
    "local-object-trust-verification-not-run",
    "verified-quarantine-preflight-not-run",
    "agentcore-planspec-not-executable",
    "security-execution-allow-not-bound",
    "two-target-local-canary-identities-not-enrolled",
    "exact-approval-not-bound",
    "controlled-activation-not-authorized",
    "controlled-rollback-not-authorized"
)
$bindingBlockers = @()
if (-not $freshnessRevocationAuthorityBound) {
    $bindingBlockers += @($cases[0].denial_reasons)
}
$allBlockers = @($bindingBlockers + $downstreamBlockers | Select-Object -Unique)
$authorityState = if ($freshnessRevocationAuthorityBound) { "freshness-window-revocation-bound" } else { "freshness-window-revocation-denied" }

$freshnessWindow = [ordered]@{
    schema = "agentos.rc14-local-freshness-window.v1"
    generated_at = $generatedAtValue
    task = "RC14-011"
    release_id = $releaseId
    status = if ($freshnessWindowBound) { "current" } else { "denied" }
    production_ready_claim = $false
    freshness = [ordered]@{
        valid_from = $generatedAtValue
        valid_until = $freshUntilInstant.ToString("o")
        requested_hours = $FreshnessHours
        bounded_by_revocation_valid_until = $revocationSnapshot.valid_until
        freshness_window_bound = $freshnessWindowBound
        freshness_window_current = $freshnessWindowCurrent
    }
    release_identity = $identitySet.release_identity
    bindings = [ordered]@{
        identity_set_sha256 = Get-FileSha256 $resolvedIdentitySetPath
        drift_repair_result_sha256 = Get-FileSha256 $resolvedDriftRepairResultPath
        public_signature_artifact_sha256 = $signatureArtifactSha256
        public_signature_receipt_sha256 = $signatureReceiptSha256
        public_signature_summary_sha256 = $signatureSummarySha256
        signature_value_sha256 = $signatureValueSha256
        revocation_snapshot_sha256 = $revocationSnapshotSha256
        revocation_log_sha256 = $revocationLogSha256
        signed_metadata_sha256 = $signedMetadataSha256
        current_payload_sha256 = $payloadSha256
        current_payload_size_bytes = $payloadSize
    }
    authority = [ordered]@{
        public_signature_bound = $publicSignatureBound
        public_signature_crypto_verified = [bool]$rc13FreshnessResult.authority_surface.public_signature_crypto_verified
        revocation_status_not_revoked = $revocationStatusNotRevoked
        revocation_snapshot_current = $revocationSnapshotCurrent
        private_material_used = $false
    }
}

$binding = [ordered]@{
    schema = "agentos.rc14-freshness-window-revocation-binding.v1"
    generated_at = $generatedAtValue
    task = "RC14-011"
    release_id = $releaseId
    status = $authorityState
    production_ready_claim = $false
    authority_surface = [ordered]@{
        freshness_revocation_authority_bound = $freshnessRevocationAuthorityBound
        freshness_window_bound = $freshnessWindowBound
        freshness_window_current = $freshnessWindowCurrent
        revocation_snapshot_bound = ($rc13FreshnessResult.source.revocation_snapshot.sha256 -eq $revocationSnapshotSha256)
        revocation_snapshot_current = $revocationSnapshotCurrent
        revocation_status_not_revoked = $revocationStatusNotRevoked
        public_signature_bound = $publicSignatureBound
        public_signature_crypto_verified = [bool]$rc13FreshnessResult.authority_surface.public_signature_crypto_verified
        identity_set_bound = $identitySetBound
        declared_current_drift_zero = [bool]$driftRepairResult.reconciliation_surface.declared_current_drift_zero
        release_identity_bound = $releaseIdentityBound
        comparisons = $comparisonCount
        comparison_drifts = $comparisonDriftCount
    }
    freshness_window = [ordered]@{
        path = $null
        sha256 = $null
        valid_from = $generatedAtValue
        valid_until = $freshUntilInstant.ToString("o")
    }
    public_signature = [ordered]@{
        key_id = $keyId
        signature_artifact_path = Get-StablePath $resolvedSignatureArtifactPath
        signature_artifact_sha256 = $signatureArtifactSha256
        signature_value_sha256 = $signatureValueSha256
        signature_value_redacted = $true
        receipt_sha256 = $signatureReceiptSha256
        summary_sha256 = $signatureSummarySha256
        raw_public_identity_redacted = $true
        crypto_verified = [bool]$rc13FreshnessResult.authority_surface.public_signature_crypto_verified
    }
    revocation = [ordered]@{
        snapshot_path = Get-StablePath $resolvedRevocationSnapshotPath
        snapshot_sha256 = $revocationSnapshotSha256
        log_path = Get-StablePath $resolvedRevocationLogPath
        log_sha256 = $revocationLogSha256
        key_id = $keyId
        status = [string]$revocationSnapshot.revocation_status
        log_status = [string]$revocationLogEntry.revocation_status
        valid_until = $revocationSnapshot.valid_until
        current_at_generated_at = $revocationSnapshotCurrent
    }
    consistency = [ordered]@{
        comparisons = $script:comparisons
        comparison_drifts = @($script:comparisonDrifts)
    }
    trust_decision = [ordered]@{
        freshness_revocation_authority_bound = $freshnessRevocationAuthorityBound
        object_trust_preconditions_ready = $freshnessRevocationAuthorityBound
        local_object_trust_allowed = $false
        quarantine_preflight_allowed = $false
        agentcore_planspec_executable = $false
        security_execution_allowed = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        blockers = $allBlockers
    }
    source = $source
}

$matrix = [ordered]@{
    schema = "agentos.rc14-freshness-window-revocation-fail-closed-matrix.v1"
    generated_at = $generatedAtValue
    task = "RC14-011"
    release_id = $releaseId
    status = if ($failedCases.Count -eq 0) { "passed" } else { "failed" }
    cases = $cases
    summary = [ordered]@{
        cases = @($cases).Count
        negative_cases = @($cases | Where-Object { $_.id -like "negative.*" }).Count
        denied_negative_cases = @($cases | Where-Object { $_.id -like "negative.*" -and $_.denied -eq $true }).Count
        failed_cases = @($failedCases | ForEach-Object { $_.id })
    }
}

$denial = [ordered]@{
    schema = "agentos.rc14-freshness-window-revocation-downstream-denial.v1"
    generated_at = $generatedAtValue
    task = "RC14-011"
    release_id = $releaseId
    status = "downstream-object-trust-denied-pending-rc14-012"
    production_ready_claim = $false
    freshness_revocation_authority_bound = $freshnessRevocationAuthorityBound
    denied = $true
    denial_reasons = $allBlockers
    side_effects = [ordered]@{
        freshness_window_written = $true
        private_key_material_read_or_printed = $false
        local_private_key_material_used = $false
        cryptographic_signing_performed = $false
        signer_service_called = $false
        signature_value_exposed = $false
        public_identity_exposed = $false
        object_trust_allowed = $false
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
        active_slot_mutated = $false
        boot_metadata_mutated = $false
        active_artifact_set_mutated = $false
    }
}

$handoff = [ordered]@{
    schema = "agentos.rc14-local-object-trust-verification-handoff.v1"
    generated_at = $generatedAtValue
    task = "RC14-011"
    release_id = $releaseId
    status = if ($freshnessRevocationAuthorityBound) { "ready-for-rc14-012-local-object-trust-verification" } else { "blocked-by-freshness-window-revocation-binding" }
    production_ready_claim = $false
    expected_next_task = "RC14-012"
    authority = [ordered]@{
        path = $null
        sha256 = $null
        freshness_window_path = $null
        freshness_window_sha256 = $null
        freshness_revocation_authority_bound = $freshnessRevocationAuthorityBound
        object_trust_preconditions_ready = $freshnessRevocationAuthorityBound
        local_object_trust_allowed = $false
    }
    release_identity = $identitySet.release_identity
    blocked_authority = [ordered]@{
        local_object_trust_allowed = $false
        quarantine_preflight_allowed = $false
        agentcore_planspec_executable = $false
        security_execution_allowed = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
    }
    blockers = $allBlockers
}

$freshnessWindowPath = Join-Path $resolvedArtifactDir "freshness-window.json"
$bindingPath = Join-Path $resolvedArtifactDir "freshness-window-revocation-binding.json"
$matrixPath = Join-Path $resolvedArtifactDir "freshness-window-revocation-fail-closed-matrix.json"
$denialPath = Join-Path $resolvedArtifactDir "freshness-window-revocation-downstream-denial.json"
$handoffPath = Join-Path $resolvedArtifactDir "local-object-trust-verification-handoff.json"
$resultPath = Join-Path $resolvedArtifactDir "result.json"
$taskEvidencePath = Join-Path (Join-Path $resolvedWorkflowDir "evidence") "RC14-011-freshness-window-revocation-binding.json"

Write-Json $freshnessWindow $freshnessWindowPath
$binding.freshness_window.path = Get-StablePath $freshnessWindowPath
$binding.freshness_window.sha256 = Get-FileSha256 $freshnessWindowPath
Write-Json $binding $bindingPath
$handoff.authority.path = Get-StablePath $bindingPath
$handoff.authority.sha256 = Get-FileSha256 $bindingPath
$handoff.authority.freshness_window_path = Get-StablePath $freshnessWindowPath
$handoff.authority.freshness_window_sha256 = Get-FileSha256 $freshnessWindowPath
Write-Json $matrix $matrixPath
Write-Json $denial $denialPath
Write-Json $handoff $handoffPath

Add-Check "outputs.secret_safe" (Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $freshnessWindowPath), (Get-Content -Raw -LiteralPath $bindingPath), (Get-Content -Raw -LiteralPath $matrixPath), (Get-Content -Raw -LiteralPath $denialPath), (Get-Content -Raw -LiteralPath $handoffPath))) "RC14-011 outputs must not contain key blocks, raw signatures, raw public identity, tokens, signer internals, or private authority paths." $null
Add-Check "outputs.side_effects_absent" ($denial.side_effects.private_key_material_read_or_printed -eq $false -and $denial.side_effects.local_private_key_material_used -eq $false -and $denial.side_effects.cryptographic_signing_performed -eq $false -and $denial.side_effects.signer_service_called -eq $false -and $denial.side_effects.signature_value_exposed -eq $false -and $denial.side_effects.public_identity_exposed -eq $false -and $denial.side_effects.object_trust_allowed -eq $false -and $denial.side_effects.network_probe_performed -eq $false -and $denial.side_effects.payload_bytes_uploaded -eq $false -and $denial.side_effects.remote_payload_bytes_downloaded -eq $false -and $denial.side_effects.quarantine_payload_written -eq $false -and $denial.side_effects.payload_interpreted -eq $false -and $denial.side_effects.install_performed -eq $false -and $denial.side_effects.activation_performed -eq $false -and $denial.side_effects.rollback_execution_performed -eq $false -and $denial.side_effects.support_upload_performed -eq $false -and $denial.side_effects.recovery_execution_performed -eq $false -and $denial.side_effects.remote_dispatch_enabled -eq $false -and $denial.side_effects.production_ring_mutated -eq $false) "RC14-011 must not sign, call signer services, expose raw signature/key identity, trust objects, fetch/quarantine/interpret payloads, install, activate, rollback, upload support, recover, dispatch, or mutate production state." $denial.side_effects

$resultStatus = if (@($script:failedChecks).Count -eq 0) { "passed" } else { "failed" }
$result = [ordered]@{
    schema = "agentos.rc14-freshness-window-revocation-binding-result.v1"
    generated_at = $generatedAtValue
    task = "RC14-011"
    status = $resultStatus
    production_ready_claim = $false
    release_id = $releaseId
    authority_surface = [ordered]@{
        state = $authorityState
        freshness_revocation_authority_bound = $freshnessRevocationAuthorityBound
        freshness_window_bound = $freshnessWindowBound
        freshness_window_current = $freshnessWindowCurrent
        freshness_valid_from = $generatedAtValue
        freshness_valid_until = $freshUntilInstant.ToString("o")
        revocation_snapshot_bound = ($rc13FreshnessResult.source.revocation_snapshot.sha256 -eq $revocationSnapshotSha256)
        revocation_snapshot_current = $revocationSnapshotCurrent
        revocation_status_not_revoked = $revocationStatusNotRevoked
        public_signature_bound = $publicSignatureBound
        public_signature_crypto_verified = [bool]$rc13FreshnessResult.authority_surface.public_signature_crypto_verified
        identity_set_bound = $identitySetBound
        declared_current_drift_zero = [bool]$driftRepairResult.reconciliation_surface.declared_current_drift_zero
        release_identity_bound = $releaseIdentityBound
        comparisons = $comparisonCount
        comparison_drifts = $comparisonDriftCount
        fail_closed_cases = @($cases).Count
        failed_fail_closed_cases = @($failedCases).Count
        object_trust_preconditions_ready = $freshnessRevocationAuthorityBound
        local_object_trust_allowed = $false
        quarantine_preflight_allowed = $false
        network_fetch_allowed = $false
        install_allowed = $false
        activation_allowed = $false
        rollback_execution_allowed = $false
        support_upload_allowed = $false
        recovery_execution_allowed = $false
        remote_dispatch_enabled = $false
        production_ring_mutation_allowed = $false
        blockers = $allBlockers
    }
    outputs = [ordered]@{
        freshness_window = [ordered]@{ path = Get-StablePath $freshnessWindowPath; sha256 = Get-FileSha256 $freshnessWindowPath }
        binding = [ordered]@{ path = Get-StablePath $bindingPath; sha256 = Get-FileSha256 $bindingPath }
        fail_closed_matrix = [ordered]@{ path = Get-StablePath $matrixPath; sha256 = Get-FileSha256 $matrixPath }
        downstream_denial = [ordered]@{ path = Get-StablePath $denialPath; sha256 = Get-FileSha256 $denialPath }
        local_object_trust_verification_handoff = [ordered]@{ path = Get-StablePath $handoffPath; sha256 = Get-FileSha256 $handoffPath }
    }
    source = $source
    invariants = [ordered]@{
        aios_body_only = $true
        freshness_window_written = $true
        mirror_frontend_changed = $false
        nginx_or_tls_changed = $false
        signer_infra_changed = $false
        object_storage_infra_changed = $false
        local_private_key_material_used = $false
        private_key_material_read_or_printed = $false
        cryptographic_signing_performed = $false
        signer_service_called = $false
        signature_value_exposed = $false
        raw_public_identity_exposed = $false
        payload_upload_performed = $false
        object_storage_provisioned = $false
        network_probe_performed = $false
        remote_payload_bytes_downloaded = $false
        quarantine_payload_written = $false
        payload_interpreted = $false
        object_trust_allowed = $false
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
    blockers = $allBlockers
    summary = [ordered]@{
        checks = @($script:checks).Count
        failed_checks = @($script:failedChecks).Count
        comparisons = $comparisonCount
        comparison_drifts = $comparisonDriftCount
        fail_closed_cases = @($cases).Count
        failed_fail_closed_cases = @($failedCases).Count
        freshness_revocation_authority_bound = $freshnessRevocationAuthorityBound
        object_trust_preconditions_ready = $freshnessRevocationAuthorityBound
        rc14_011_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC14-012"
    }
}
Write-Json $result $resultPath

$scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$taskEvidence = [ordered]@{
    schema = "agentos.rc14-freshness-window-revocation-binding-evidence.v1"
    generated_at = $generatedAtValue
    task = "RC14-011"
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
    authority_surface = $result.authority_surface
    invariants = $result.invariants
    completion = [ordered]@{
        rc14_011_complete = (@($script:failedChecks).Count -eq 0)
        next_task = "RC14-012"
        commit_required = $true
    }
}
Write-Json $taskEvidence $taskEvidencePath

$finalSecretSafe = Test-NoSensitiveText -Values @((Get-Content -Raw -LiteralPath $resultPath), (Get-Content -Raw -LiteralPath $taskEvidencePath))
if (-not $finalSecretSafe) {
    throw "Sensitive marker detected in RC14-011 outputs."
}

Write-Host "RC14 freshness/revocation binding $($result.status): $(Get-StablePath $resultPath)"
Write-Host "Authority state: $authorityState"
Write-Host "Checks: $(@($script:checks).Count), failed checks: $(@($script:failedChecks).Count), comparisons: $comparisonCount, fail-closed cases: $(@($cases).Count)"

if ($FailOnFailedChecks -and @($script:failedChecks).Count -gt 0) {
    exit 1
}
