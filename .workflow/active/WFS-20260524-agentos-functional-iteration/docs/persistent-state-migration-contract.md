# Persistent State Migration Contract

Long-running AgentOS state must survive versioned upgrades without losing audit
truth or rollback handles.

State classes:

- compatible: current runtime can read state without mutation
- migratable: read-only preflight can produce a migration plan
- blocked: migration would lose rollback/audit evidence
- corrupted: recovery must classify and fail closed or reconcile

Rules:

- Migration preflight is read-only.
- Failed migration cannot delete run snapshots, audit events, rollback handles
  or memory quarantine metadata.
- Corrupted state enters recovery classification rather than model replay.
- Update readiness must include state compatibility before activation.

Verification:

- `cargo test -p agent_core recovery`
- `cargo test -p agent_core run_store`
- `cargo test --workspace`
