# AgentOS Functional Capability Matrix

This matrix freezes the post-Alpha functional surface. New functionality must
move through `runtime_contracts -> agent_core -> security_execution -> agentd
projection -> release gate`. `agentd` may project and operate workflows, but it
does not own adapter business logic.

| Capability | Primary Owner | Integration Layers | Semantic Tools | Risk | Local-Only Replay | Optional Dependency Behavior | Side Effect / Rollback Rule | Follow-Up Tasks |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Package manager adapter | `agent_core` | `runtime_contracts`, `agent_core`, `security_execution`, `agentd`, `scripts`, `packaging` | `pkg.fetch.metadata`, `pkg.isolate.install`, `pkg.isolate.smoke`, `pkg.host.checkpoint`, `pkg.host.install`, `pkg.host.verify`, `rollback.trigger` | privileged-with-human-approval | `cargo test -p agent_core package_install` | Host package manager is optional; missing integration fails before host mutation. | Host promotion requires isolated validation, exact approval, source digest, repository identity, and rollback id. | `TASK-FUNC-010`, `TASK-FUNC-020`, `TASK-FUNC-050` |
| Untrusted content adapter | `agent_core` | `runtime_contracts`, `agent_core`, `security_execution`, `agentd`, `scripts` | `content.fetch`, `content.sanitize`, `content.summarize`, `policy.source_to_sink.check`, `audit.project` | read-only until denied sink attempts | `cargo test -p agent_core untrusted_content` | Network fetch is optional; baseline uses static/file fixtures. | External content is untrusted; denied sinks are audit-visible without `EffectPrepared`. | `TASK-FUNC-011`, `TASK-FUNC-021`, `TASK-FUNC-050` |
| Firecracker execution profile | `security_execution` | `runtime_contracts`, `security_execution`, `agentd`, `scripts` | SecurityExecution Firecracker profile over semantic step leases | execute-with-confirmation | `cargo test -p security_execution firecracker` | Firecracker, jailer, KVM, kernel and rootfs are optional; missing dependencies fail closed before `EffectPrepared`. | `CapabilityLease` is the only profile authority; no host fallback. | `TASK-FUNC-012`, `TASK-FUNC-022`, `TASK-FUNC-050` |
| Diagnostics and support bundle | `agentd` | `runtime_contracts`, `security_execution`, `agentd`, `scripts` | `operator.project`, `audit.project` | read-only | `cargo test -p agentd support_bundle operator_projection` | No external service required. | Bundle manifests bind run ids, audit ranges and hash chain; raw secrets are excluded. | `TASK-FUNC-013`, `TASK-FUNC-023`, `TASK-FUNC-032`, `TASK-FUNC-041` |
| Operator command registry | `agentd` | `agentd`, `packaging`, `scripts` | `capability.list`, `service.recover`, `content.inspect`, `package.install.fixture`, `audit.export`, `rollback.trigger` | mixed, per command | `powershell -ExecutionPolicy Bypass -File scripts/validate-alpha-rootfs.ps1` | Optional integrations show blocked prerequisites. | Registry cannot expose `shell.exec`; high-risk commands reference exact approval prerequisites. | `TASK-FUNC-030`, `TASK-FUNC-031`, `TASK-FUNC-032` |
| Audit retention and export | `security_execution` | `runtime_contracts`, `security_execution`, `agentd`, `scripts` | `audit.project` | read-only | `cargo test -p security_execution audit` | Remote mirror is optional and policy-aware. | Export manifests bind event range and hash chain; secret-like data is redacted or blocked. | `TASK-FUNC-023`, `TASK-FUNC-042`, `TASK-FUNC-050` |
| Update and rollback readiness | `packaging` | `agent_core`, `security_execution`, `agentd`, `scripts`, `packaging` | rootfs update runtime, `rollback.trigger` | privileged-with-human-approval | `cargo test -p agent_core rootfs_update` | QEMU smoke is parameterized at `E:\qemu\qemu-system-x86_64.exe`; not needed for local replay baseline. | Updates stage inactive slot, retain rollback evidence, and block promotion when functional replay fails. | `TASK-FUNC-040`, `TASK-FUNC-043`, `TASK-FUNC-051`, `TASK-FUNC-052` |

## Non-Goals And Blocked Shortcuts

- No normal-mode arbitrary shell execution.
- No direct `agentd` adapter business logic.
- No host package mutation before isolated validation, exact approval and rollback binding.
- No external LLM, network, Firecracker or host package manager dependency for baseline replay.
- No support bundle export containing raw secret values.
