# Write Diff Rollback

Task: `TASK-AIOS-009`

## Purpose

`write-with-diff` file changes must be inspectable and reversible before they touch the target path. The MVP scope is file content replacement through `fs.write.diff`; package, service, and image rollbacks remain separate future flows.

## Flow

1. Route `fs.write.diff` and acquire an exact approval-bound capability lease.
2. Read the target and compare its current content hash with the requested `base_hash`.
3. Write `previous.txt` and `proposed.txt` into a shadow workspace.
4. Generate a diff preview with `target_path`, `base_hash`, `proposed_hash`, and `rollback_id`.
5. Wait for approval before commit.
6. At commit time, re-check `base_hash`, write `EffectPrepared`, mutate the target, verify final hash, then write `CommitSealed`.
7. If rollback is triggered, write `RollbackPending`, restore `previous.txt`, then write `RollbackObserved`.

## Safety Properties

- prepare does not mutate the target path
- stale base hash blocks both prepare and commit
- rollback handle contains enough metadata to restore supported file changes
- audit records include rollback id, target path, base hash, proposed hash, and parameter hash

## TUI Integration

The TUI renders a diff preview plus rollback handle before approval. Approval is still represented as terminal state; the UI does not bypass policy or audit.

## Verification

```powershell
cargo test -p agentd
cargo run -p agentd -- --write-diff-demo
Get-Content .workflow/artifacts/rollback/demo/audit.jsonl
```

The demo prepares a shadow diff, proves the target is unchanged before commit, commits after approval, and triggers rollback to restore the previous content.
