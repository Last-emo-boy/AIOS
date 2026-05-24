# Firecracker Execution Adapter Contract

Firecracker is an optional SecurityExecution profile, not a normal-mode host
fallback.

Contract report:

- profile id
- dependency probe inputs
- missing dependencies
- whether an effect was prepared
- whether fallback was used
- artifact redaction status

Missing dependencies for KVM, Firecracker, jailer, kernel image or rootfs image
must fail closed before `EffectPrepared`. Planner hints cannot widen network,
filesystem or profile access. `CapabilityLease` is the only authority for
profile compilation.

Implementation anchors:

- `crates/runtime_contracts/src/capability.rs`
- `crates/security_execution/src/lib.rs` module `sandbox_profile`
- `crates/security_execution/src/lib.rs` module `engine`

Verification:

- `cargo test -p security_execution firecracker`
- `cargo test -p agentd security_execution::`
