# Audit Retention, Export And Redaction Gates

Audit export is a read-only operation over append-only journal evidence.

Export manifest requirements:

- audit event range
- hash chain or deterministic digest
- source run ids
- redaction status
- remote mirror failure policy if present

Secret-like values are redacted or export-blocked. Secret handles may remain
visible when they are handles rather than raw values.

Remote mirror failures are policy-aware:

- warn keeps local authority
- pause blocks non-local side effects
- fail-closed blocks non-local side effects

Verification:

- `cargo test -p security_execution audit`
- `cargo test -p agentd support_bundle`
