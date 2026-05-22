# Recovery Semantics

Task: `TASK-AIOS-006`

## Purpose

Recovery is deterministic and model-independent. After restart, `agentd` scans the append-only audit journal for `EffectPrepared` events that do not have a matching `CommitSealed` or `RollbackObserved` event.

## Classifications

| Classification | Meaning |
|---|---|
| `safe-to-verify` | Read-only or status-like effect can resume verification. |
| `needs-rollback` | Write-like effect needs rollback or explicit operator handling. |
| `needs-human-review` | Ambiguous effect cannot continue without confirmation. |
| `abandoned` | Effect is known abandoned and should not continue. |

`needs-rollback` and `needs-human-review` require human confirmation before continuation.

## Recovery Events

The reconciler appends:

- `RecoveryStarted`
- `RecoveryCompleted`

These events prove recovery ran after restart and did not silently discard prepared effects.

## CLI Verification

```powershell
cargo test -p agentd
cargo run -p agentd -- --recovery-demo .workflow/artifacts/recovery/demo.jsonl
```

The demo injects one read-only prepared effect and one write-with-diff prepared effect, then renders both a JSON report and an operator prompt.
