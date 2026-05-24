# Untrusted Content Adapter Contract

External content enters AgentOS as untrusted data. It cannot directly create
tool calls, approvals or side effects.

Required contract fields:

- content id
- source URI
- pinned SHA-256 digest
- max bytes
- trust boundary: `external-untrusted`

Workflow:

1. `content.fetch`
2. `content.sanitize`
3. `content.summarize`
4. `policy.source_to_sink.check`
5. `audit.project`

The adapter exposes `runtime_contracts::ContentFetchContract` and
`ContentAdapterReport`. Sanitized summaries are replanning context only.
Denied high-risk sinks are visible in audit projection and must not prepare
effects.

Implementation anchors:

- `crates/runtime_contracts/src/capability.rs`
- `crates/agent_core/src/lib.rs` module `untrusted_content`
- `crates/security_execution/src/lib.rs` module `source_to_sink`

Verification:

- `cargo test -p agent_core untrusted_content`
- `cargo test -p security_execution source_to_sink`
