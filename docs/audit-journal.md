# Audit Journal

Task: `TASK-AIOS-005`

## Purpose

The audit journal is append-only JSONL. It records intent, plan, approval, prepared effects, observed effects, commit sealing, rollback, and recovery events so `agentd` can reason about work that may have partially executed before a crash.

## Event Types

- `IntentReceived`
- `PlanFrozen`
- `PolicyEvaluated`
- `ApprovalBound`
- `EffectPrepared`
- `EffectObserved`
- `CommitSealed`
- `RollbackPending`
- `RollbackObserved`
- `RecoveryStarted`
- `RecoveryCompleted`

## Integrity Fields

Each event records:

- `run_id`
- `step_id`
- `actor`
- `timestamp`
- `policy_version`
- `tool_version`
- `parameter_hash`
- `parent_event`
- `summary`

Secret-like tokens in `summary` are redacted before writing.

## Recovery Query

`AuditJournal::unresolved_effects()` returns `EffectPrepared` events that do not have a matching `CommitSealed` or `RollbackObserved` event for the same `step_id`.

## Verification

```powershell
cargo test -p agentd
cargo run -p agentd -- --audit-demo .workflow/artifacts/audit/demo.jsonl
```

The demo writes `IntentReceived` and `EffectPrepared`, then reports one unresolved effect. The summary contains a secret-like token that is redacted before persistence.
