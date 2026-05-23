param(
    [string]$ArtifactDir = ".workflow/artifacts/production-signing-material-intake",
    [string]$QemuPath = "E:\qemu\qemu-system-x86_64.exe",
    [int]$QemuTimeoutSeconds = 45,
    [switch]$AllowSignatureOverwrite,
    [switch]$SkipQemuSmoke,
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
    $Value | ConvertTo-Json -Depth 32 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Read-OptionalJson {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Resolve-RepoPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ([IO.Path]::IsPathRooted($Path)) {
        return [IO.Path]::GetFullPath($Path)
    }
    return [IO.Path]::GetFullPath((Join-Path $script:repoRoot $Path))
}

function Add-Step {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [switch]$Blocking
    )
    $exitCode = 0
    $errorMessage = $null
    try {
        & $Action
        $exitCode = $LASTEXITCODE
        if ($null -eq $exitCode) {
            $exitCode = 0
        }
    } catch {
        $exitCode = 1
        $errorMessage = $_.Exception.Message
    }

    $artifact = Read-OptionalJson $OutputPath
    $artifactStatus = if ($null -ne $artifact -and $artifact.PSObject.Properties.Name -contains "status") {
        $artifact.status
    } else {
        $null
    }
    $blockerCount = if ($null -ne $artifact -and $artifact.PSObject.Properties.Name -contains "blockers") {
        @($artifact.blockers).Count
    } else {
        0
    }
    $passed = ($exitCode -eq 0 -and $blockerCount -eq 0 -and $artifactStatus -notin @("blocked"))
    $step = [ordered]@{
        id = $Id
        command = $Command
        output = $OutputPath
        status = if ($passed) { "passed" } elseif ($Blocking) { "blocked" } else { "failed" }
        artifact_status = $artifactStatus
        blockers = $blockerCount
        exit_code = $exitCode
        error = $errorMessage
    }
    $script:steps += $step
    if (-not $passed -and $Blocking) {
        $script:blockers += $step
    }
}

function Remove-InstalledProductionSignatures {
    param(
        [Parameter(Mandatory = $true)][string]$InstallationPath,
        [Parameter(Mandatory = $true)][string]$Reason
    )

    $installation = Read-OptionalJson $InstallationPath
    $actions = @()
    foreach ($entry in @($installation.installed_signatures)) {
        $path = $entry.path
        $action = [ordered]@{
            artifact = $entry.artifact
            path = $path
            status = "skipped"
            reason = $null
        }

        if ([string]::IsNullOrWhiteSpace($path)) {
            $action.reason = "missing-path"
            $actions += $action
            continue
        }
        if ($AllowSignatureOverwrite) {
            $action.reason = "allow-overwrite-enabled"
            $actions += $action
            continue
        }

        $resolved = Resolve-RepoPath $path
        $repoPrefix = $script:repoRoot.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
        $insideRepo = $resolved.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)
        $hasProductionSignatureSuffix = $resolved.EndsWith(".prod.sig.json", [StringComparison]::OrdinalIgnoreCase)
        if (-not $insideRepo) {
            $action.reason = "outside-repo"
            $actions += $action
            continue
        }
        if (-not $hasProductionSignatureSuffix) {
            $action.reason = "not-production-signature-path"
            $actions += $action
            continue
        }
        if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
            $action.reason = "already-absent"
            $actions += $action
            continue
        }

        Remove-Item -LiteralPath $resolved -Force
        $action.status = "removed"
        $action.reason = $Reason
        $actions += $action
    }
    return @($actions)
}

New-Item -ItemType Directory -Force -Path $ArtifactDir | Out-Null

$script:repoRoot = (Resolve-Path -LiteralPath ".").Path
$script:steps = @()
$script:blockers = @()
$script:cleanupActions = @()

$signingRequestPath = Join-Path $ArtifactDir "signing-request-decision-evidence.json"
$keyringVerificationPath = Join-Path $ArtifactDir "keyring-verification.json"
$bundleVerificationPath = Join-Path $ArtifactDir "signature-bundle-verification.json"
$bundleInstallationPath = Join-Path $ArtifactDir "signature-bundle-installation.json"
$productionSignatureVerificationPath = Join-Path $ArtifactDir "production-signature-verification.json"
$promotionPath = Join-Path $ArtifactDir "production-promotion-verification.json"
$qemuSmokeDir = Join-Path $ArtifactDir "qemu-distro-smoke"
$qemuSmokePath = Join-Path $qemuSmokeDir "result.json"
$resultPath = Join-Path $ArtifactDir "result.json"

Add-Step `
    -Id "signing_request" `
    -Command ".\scripts\create-production-signing-request.ps1 -RequireDecisionEvidence -OutputPath $signingRequestPath" `
    -OutputPath $signingRequestPath `
    -Blocking `
    -Action {
        & ".\scripts\create-production-signing-request.ps1" `
            -RequireDecisionEvidence `
            -OutputPath $signingRequestPath `
            -FailOnBlocked
    }

Add-Step `
    -Id "keyring_verification" `
    -Command ".\scripts\verify-production-keyring.ps1 -OutputPath $keyringVerificationPath" `
    -OutputPath $keyringVerificationPath `
    -Blocking `
    -Action {
        & ".\scripts\verify-production-keyring.ps1" `
            -OutputPath $keyringVerificationPath `
            -FailOnBlocked
    }

Add-Step `
    -Id "signature_bundle_verification" `
    -Command ".\scripts\verify-production-signature-bundle.ps1 -SigningRequestPath $signingRequestPath -OutputPath $bundleVerificationPath" `
    -OutputPath $bundleVerificationPath `
    -Blocking `
    -Action {
        & ".\scripts\verify-production-signature-bundle.ps1" `
            -SigningRequestPath $signingRequestPath `
            -OutputPath $bundleVerificationPath `
            -FailOnBlocked
    }

$installArgs = @{
    SigningRequestPath = $signingRequestPath
    SignatureBundlePath = ".workflow/artifacts/production-signing/signature-bundle.json"
    BundleVerificationPath = $bundleVerificationPath
    OutputPath = $bundleInstallationPath
    FailOnBlocked = $true
}
if ($AllowSignatureOverwrite) {
    $installArgs.AllowOverwrite = $true
}
Add-Step `
    -Id "signature_bundle_installation" `
    -Command ".\scripts\install-production-signature-bundle.ps1 -SigningRequestPath $signingRequestPath -BundleVerificationPath $bundleVerificationPath -OutputPath $bundleInstallationPath" `
    -OutputPath $bundleInstallationPath `
    -Blocking `
    -Action {
        & ".\scripts\install-production-signature-bundle.ps1" @installArgs
    }

Add-Step `
    -Id "production_signature_verification" `
    -Command ".\scripts\verify-production-signatures.ps1 -RequireDecisionEvidence -OutputPath $productionSignatureVerificationPath" `
    -OutputPath $productionSignatureVerificationPath `
    -Blocking `
    -Action {
        & ".\scripts\verify-production-signatures.ps1" `
            -RequireDecisionEvidence `
            -KeyringVerificationPath $keyringVerificationPath `
            -OutputPath $productionSignatureVerificationPath `
            -FailOnBlocked
    }

$productionSignatureStep = @($script:steps | Where-Object { $_.id -eq "production_signature_verification" } | Select-Object -Last 1)
if ($null -ne $productionSignatureStep -and $productionSignatureStep.status -ne "passed") {
    $script:cleanupActions = Remove-InstalledProductionSignatures `
        -InstallationPath $bundleInstallationPath `
        -Reason "production-signature-verification-$($productionSignatureStep.status)"
    $removedCount = @($script:cleanupActions | Where-Object { $_.status -eq "removed" }).Count
    $script:steps += [ordered]@{
        id = "signature_cleanup"
        command = "remove signatures installed by this replay after failed production signature verification"
        output = $bundleInstallationPath
        status = "passed"
        artifact_status = "cleanup-recorded"
        blockers = 0
        exit_code = 0
        error = $null
        removed_signatures = $removedCount
    }
}

Add-Step `
    -Id "production_promotion_verification" `
    -Command ".\scripts\verify-candidate-promotion.ps1 -RequireProductionSignatures -OutputPath $promotionPath" `
    -OutputPath $promotionPath `
    -Blocking `
    -Action {
        & ".\scripts\verify-candidate-promotion.ps1" `
            -RequireProductionSignatures `
            -OutputPath $promotionPath `
            -FailOnBlocked
    }

if (-not $SkipQemuSmoke) {
    Add-Step `
        -Id "qemu_distro_smoke" `
        -Command ".\scripts\candidate-qemu-distro-smoke.ps1 -QemuPath $QemuPath -ArtifactDir $qemuSmokeDir -TimeoutSeconds $QemuTimeoutSeconds" `
        -OutputPath $qemuSmokePath `
        -Blocking `
        -Action {
            & ".\scripts\candidate-qemu-distro-smoke.ps1" `
                -QemuPath $QemuPath `
                -ArtifactDir $qemuSmokeDir `
                -TimeoutSeconds $QemuTimeoutSeconds
        }
} else {
    $script:steps += [ordered]@{
        id = "qemu_distro_smoke"
        command = "skipped by -SkipQemuSmoke"
        output = $qemuSmokePath
        status = "skipped"
        artifact_status = $null
        blockers = 0
        exit_code = 0
        error = $null
    }
}

$result = [ordered]@{
    schema = "agentos.production-signing-material-intake.replay.v1"
    checked_at = (Get-Date).ToString("o")
    status = if ($script:blockers.Count -eq 0) { "passed" } else { "blocked" }
    production_ready_claim = $false
    artifact_dir = $ArtifactDir
    steps = @($script:steps)
    cleanup = [ordered]@{
        triggered = @($script:cleanupActions).Count -gt 0
        removed_signatures = @($script:cleanupActions | Where-Object { $_.status -eq "removed" }).Count
        actions = @($script:cleanupActions)
    }
    blockers = @($script:blockers)
    summary = [ordered]@{
        steps = @($script:steps).Count
        blockers = @($script:blockers).Count
    }
}

Write-Json -Value $result -Path $resultPath
Write-Host "Production signing material intake replay $($result.status): $resultPath"
if ($FailOnBlocked -and $script:blockers.Count -gt 0) {
    exit 1
}
