# Final Functional Audit Summary

Decision: `functional-ready`

The functional iteration moved AgentOS beyond Distribution Alpha by adding
typed capability contracts, contract-backed AgentCore workflow reports,
operator command discovery, support bundle projection, local-only functional
replay and release provenance integration.

Completed scope:

- `runtime_contracts` now owns capability contract schemas for package adapter,
  untrusted content, Firecracker adapter reports and support bundle manifests.
- `agent_core` package and untrusted-content workflows export contract reports
  while preserving isolated validation, digest checks, redaction, exact approval
  and source-to-sink denial semantics.
- `security_execution` remains the only side-effect authority; Firecracker
  profile tests prove missing dependencies fail before `EffectPrepared`.
- `agentd` exposes read-only operator projection and deterministic support
  bundle status without owning adapter business logic.
- `packaging` includes `operator-commands.json`, and validation blocks
  registries that expose `shell.exec`.
- `scripts/functional-capability-replay.ps1` replays local-only functional
  fixtures and writes stable JSON evidence.
- `scripts/build-release.ps1` records capability matrix and replay hashes in
  provenance and blocks promotion if replay is skipped or failed.

Verification performed:

- `cargo test -p runtime_contracts`
- `cargo test -p agent_core package_install`
- `cargo test -p agent_core untrusted_content`
- `cargo test -p agentd operator_projection`
- `cargo test -p agentd support_bundle`
- `powershell -ExecutionPolicy Bypass -File scripts/validate-alpha-rootfs.ps1`
- `powershell -ExecutionPolicy Bypass -File scripts/functional-capability-replay.ps1`

Next Production Distro entry criteria:

- Full `cargo test --workspace` passes.
- Release gate passes with functional replay enabled.
- QEMU smoke remains separately visible and uses `E:\qemu\qemu-system-x86_64.exe`
  when required by the promotion stage.
- Production signing material stays outside git under ignored local paths.
