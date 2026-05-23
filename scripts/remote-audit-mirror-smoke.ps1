param(
    [string]$ArtifactDir = ".workflow/artifacts/remote-audit-mirror",
    [ValidateSet("warn", "pause", "fail-closed")]
    [string]$FailurePolicy = "warn",
    [switch]$SimulateMirrorFailure
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

function Redact-Summary {
    param([Parameter(Mandatory = $true)][string]$Value)
    $tokens = @()
    foreach ($token in ($Value -split "\s+")) {
        $lower = $token.ToLowerInvariant()
        $key = if ($lower -match "^([^=:_-]+)") { $Matches[1] } else { "" }
        if ($lower.StartsWith("secret://")) {
            $tokens += $token
        } elseif ($key -in @("secret", "password", "token", "apikey", "api_key", "access_token", "refresh_token")) {
            $tokens += "[REDACTED]"
        } else {
            $tokens += $token
        }
    }
    return ($tokens -join " ")
}

function Get-StableHash {
    param([Parameter(Mandatory = $true)][string]$Value)
    $stream = [IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes($Value))
    try {
        return (Get-FileHash -InputStream $stream -Algorithm SHA256).Hash.ToLowerInvariant()
    } finally {
        $stream.Dispose()
    }
}

function New-AuditEvent {
    param(
        [Parameter(Mandatory = $true)][string]$EventType,
        [Parameter(Mandatory = $true)][string]$RunId,
        [Parameter(Mandatory = $true)][string]$StepId,
        [Parameter(Mandatory = $true)][string]$Summary
    )
    return [ordered]@{
        schema = "agentos.audit-event.v1"
        event_type = $EventType
        run_id = $RunId
        step_id = $StepId
        actor = "operator"
        policy_version = "policy-v1"
        tool_version = "alpha-1"
        parameter_hash = Get-StableHash "$EventType/$RunId/$StepId"
        summary = (Redact-Summary $Summary)
    }
}

function Convert-ToMirrorRecord {
    param(
        [Parameter(Mandatory = $true)]$Event,
        [Parameter(Mandatory = $true)][int]$Sequence,
        [Parameter(Mandatory = $true)][string]$PreviousHash
    )
    $payload = [ordered]@{
        schema = "agentos.remote-audit-mirror-record.v1"
        sequence = $Sequence
        source = "local-audit-journal"
        event_type = $Event.event_type
        run_id = $Event.run_id
        step_id = $Event.step_id
        policy_version = $Event.policy_version
        tool_version = $Event.tool_version
        parameter_hash = $Event.parameter_hash
        summary = (Redact-Summary $Event.summary)
        previous_hash = $PreviousHash
    }
    $payloadJson = ($payload | ConvertTo-Json -Depth 8 -Compress)
    $payload.record_hash = Get-StableHash $payloadJson
    return $payload
}

New-Item -ItemType Directory -Force -Path $ArtifactDir | Out-Null
$localAuditPath = Join-Path $ArtifactDir "local-audit.jsonl"
$mirrorPath = Join-Path $ArtifactDir "remote-mirror.jsonl"
$resultPath = Join-Path $ArtifactDir "result.json"
Remove-Item -LiteralPath $localAuditPath, $mirrorPath, $resultPath -ErrorAction SilentlyContinue

$events = @(
    (New-AuditEvent -EventType "IntentReceived" -RunId "run-remote-audit" -StepId "intent" -Summary "operator requested mirror smoke"),
    (New-AuditEvent -EventType "PolicyEvaluated" -RunId "run-remote-audit" -StepId "restart-service" -Summary "decision=allow token=abc123 secret://operator-approval"),
    (New-AuditEvent -EventType "CommitSealed" -RunId "run-remote-audit" -StepId "restart-service" -Summary "commit sealed password=hunter2 public=ok")
)

foreach ($event in $events) {
    ($event | ConvertTo-Json -Depth 8 -Compress) | Add-Content -LiteralPath $localAuditPath -Encoding UTF8
}

$records = @()
$previous = "genesis"
$sequence = 0
foreach ($event in $events) {
    $record = Convert-ToMirrorRecord -Event $event -Sequence $sequence -PreviousHash $previous
    $records += $record
    $previous = $record.record_hash
    if (-not $SimulateMirrorFailure) {
        ($record | ConvertTo-Json -Depth 8 -Compress) | Add-Content -LiteralPath $mirrorPath -Encoding UTF8
    }
    $sequence += 1
}

$mirrorFailureAction = "none"
if ($SimulateMirrorFailure) {
    $mirrorFailureAction = switch ($FailurePolicy) {
        "warn" { "warn-and-continue-local-audit-authoritative" }
        "pause" { "pause-non-critical-workflows-until-mirror-recovers" }
        "fail-closed" { "fail-closed-before-non-local-side-effect" }
    }
}

$appendOnly = $true
$expectedPrevious = "genesis"
foreach ($record in $records) {
    if ($record.previous_hash -ne $expectedPrevious) {
        $appendOnly = $false
    }
    $expectedPrevious = $record.record_hash
}

$localSecretFree = Test-SecretFreeContent $localAuditPath
$mirrorSecretFree = if (Test-Path -LiteralPath $mirrorPath -PathType Leaf) {
    Test-SecretFreeContent $mirrorPath
} else {
    $true
}

$result = [ordered]@{
    schema = "agentos.remote-audit-mirror-smoke.v1"
    checked_at = (Get-Date).ToString("o")
    result = "passed"
    mode = "validated-local-stub"
    local_audit_source_of_truth = $true
    remote_mirror_authoritative_for_recovery = $false
    failure_policy = $FailurePolicy
    simulate_mirror_failure = [bool]$SimulateMirrorFailure
    mirror_failure_action = $mirrorFailureAction
    artifacts = [ordered]@{
        local_audit = $localAuditPath
        remote_mirror = $mirrorPath
        result = $resultPath
    }
    assertions = [ordered]@{
        append_only_hash_chain = $appendOnly
        local_audit_secret_free = $localSecretFree
        mirror_secret_free = $mirrorSecretFree
        secret_handles_preserved = ((Get-Content -LiteralPath $localAuditPath -Raw) -match "secret://operator-approval")
        raw_token_redacted = -not ((Get-Content -LiteralPath $localAuditPath -Raw) -match "token=abc123")
        raw_password_redacted = -not ((Get-Content -LiteralPath $localAuditPath -Raw) -match "password=hunter2")
    }
}

foreach ($assertion in $result.assertions.GetEnumerator()) {
    if ($assertion.Value -ne $true) {
        $result.result = "failed"
    }
}

Write-Json -Value $result -Path $resultPath

if ($result.result -ne "passed") {
    Write-Error "Remote audit mirror smoke failed: $resultPath"
    exit 1
}

Write-Host "Remote audit mirror smoke passed: $resultPath"
