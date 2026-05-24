# Cross-Crate Capability Contract

AgentOS functional capabilities are layered by ownership, not by UI entry
point. `agentd` stays thin and operator-facing; adapter state and side effects
belong below it.

| Layer | Responsibility | Must Not Own |
| --- | --- | --- |
| `runtime_contracts` | Stable request, identity, report, manifest and replay schemas. | Runtime scheduling, host mutation, policy decisions. |
| `agent_core` | PlanRun orchestration, package/content workflow DAGs, state transitions, observations and projection inputs. | Direct host mutation, raw package manager commands, sandbox authority. |
| `security_execution` | Policy, exact approvals, leases, sandbox profiles, Firecracker profile, effect envelopes, audit, rollback and source-to-sink decisions. | UI command registry, product workflow sequencing. |
| `agentd` | PID 1 lifecycle, CLI/TUI/API, operator projection, support bundle projection and process integration. | Adapter business logic, policy bypasses, direct shell execution. |
| `scripts` | Local-only replay, release/provenance gates, smoke tests and artifact hashing. | Runtime authority or secret material. |
| `packaging` | Rootfs defaults, policy/tool/operator manifests and install-time file layout. | Runtime decisions or dynamic approvals. |

## Review Checklist

- New functional capability defines a `runtime_contracts` schema or explicitly
  links to an existing one.
- Agent workflow state is owned by `agent_core`.
- Every side-effecting path enters `security_execution` before `EffectPrepared`.
- Approval tokens remain bound to actor, tool, resource, parameter hash, expiry
  and policy version.
- `agentd` exposes only projection or command entry points.
- Local-only replay does not require external LLM, network, Firecracker or host
  package manager.
- Failure evidence states `denied`, `awaiting-approval`, `rollback-pending` or
  `failed-closed`.

## Initial File Ownership

- Package adapter: `crates/runtime_contracts/src/capability.rs`,
  `crates/agent_core/src/lib.rs`, `crates/security_execution/src/tools.rs`,
  `packaging/agentos/rootfs/etc/agentos/tools/semantic-tools.json`.
- Untrusted content: `crates/runtime_contracts/src/capability.rs`,
  `crates/agent_core/src/lib.rs`, `crates/security_execution/src/lib.rs`.
- Firecracker profile: `crates/runtime_contracts/src/capability.rs`,
  `crates/security_execution/src/lib.rs`, `crates/agentd/src/security_execution.rs`.
- Operator UX: `crates/agentd/src/operator_projection.rs`,
  `crates/agentd/src/tui.rs`,
  `packaging/agentos/rootfs/etc/agentos/operator-commands.json`.
- Support bundle: `crates/runtime_contracts/src/capability.rs`,
  `crates/agentd/src/support_bundle.rs`,
  `crates/agentd/src/operator_projection.rs`.
- Functional replay: `scripts/functional-capability-replay.ps1`,
  `scripts/build-release.ps1`.

Intentional exceptions: none.
