# Health, Diagnostics And Recovery Drills

AgentOS health must distinguish optional integration degradation from blocked
runtime authority.

Drills:

- sealed read-only diagnostic recovery
- unresolved read-only effect recovery
- unresolved write recovery to rollback-pending
- service recovery approved and denied
- support bundle projection over a redacted audit journal
- remote audit mirror degraded/failed-closed projection

Rules:

- Recovery never replays model output as authority.
- Diagnostics are redacted before projection.
- Operator projection explains recovery source and unresolved effects.

Verification:

- `cargo test -p agentd recovery`
- `cargo test -p agent_core recovery`
- `cargo test -p agentd operator_projection`
