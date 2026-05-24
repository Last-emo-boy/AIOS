# Diagnostics And Support Bundle Contract

Support bundles are operator-facing read-only projections. They carry
deterministic metadata and redacted audit excerpts, not raw secrets.

Manifest fields:

- bundle id
- source run ids
- audit event range
- audit hash chain
- redaction status
- raw-secret inclusion flag

Implementation anchors:

- `runtime_contracts::SupportBundleManifest`
- `crates/agentd/src/support_bundle.rs`
- `crates/agentd/src/operator_projection.rs`

Verification:

- `cargo test -p agentd support_bundle`
- `cargo test -p agentd operator_projection`
