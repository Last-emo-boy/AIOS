# Package Manager Adapter Contract

Package management is a typed AgentCore workflow backed by
`runtime_contracts::PackageIdentity` and `PackageAdapterReport`.

Required identity fields:

- package name
- version
- source URI
- source digest
- repository identity

Workflow phases:

1. `pkg.fetch.metadata`
2. `pkg.isolate.install`
3. `pkg.isolate.smoke`
4. `pkg.host.checkpoint`
5. `pkg.host.install`
6. `pkg.host.verify`
7. `rollback.trigger`

Host promotion remains `privileged-with-human-approval`. It requires isolated
validation, exact approval, source digest binding and rollback id. Failed
isolated installs produce denied reports without host mutation. Retained
artifacts must be `.json` or `.redacted`.

Implementation anchors:

- `crates/runtime_contracts/src/capability.rs`
- `crates/agent_core/src/lib.rs` module `package_install`
- `packaging/agentos/rootfs/etc/agentos/tools/semantic-tools.json`

Verification:

- `cargo test -p runtime_contracts capability`
- `cargo test -p agent_core package_install`
