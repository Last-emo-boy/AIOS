# 003: Agent Core Runtime Boundary

Date: 2026-05-22
Status: Accepted
Task: `TASK-RTF-000`
Source: `research.md:127`

## Decision

AgentOS will implement a dedicated **Agent Core Runtime** inside `agentd`, but
Agent Core is not the model and is not an executor. Agent Core is deterministic
orchestration around model-assisted planning.

The **Security Execution Foundation** remains the only allowed path for
side-effecting work. Agent Core can request structured actions, but it cannot
prepare, execute, verify, seal, roll back, or recover effects by itself.

Initial implementation will keep AgentCore **in-process inside `agentd`**. A
future Unix socket or process boundary can be introduced after the API has
stabilized, but the first runtime must reuse the existing `agentd` module
boundaries and safety tests.

## Ownership

Agent Core owns:

- Intent intake and normalization.
- `PlanSpec` and `PlanRun` state.
- Planner orchestration through `ModelBroker`.
- Step scheduling and dependency ordering.
- Observation processing and trust labeling.
- Memory writes with source, TTL, redaction, and trust labels.
- TUI/API projection of run state and approval pauses.

Security Execution Foundation owns:

- Semantic tool routing.
- Policy evaluation and risk classification.
- Approval token validation.
- Capability lease issuance.
- Sandbox profile compilation.
- Effect preparation and observation.
- Verification and commit sealing.
- Rollback handles and recovery truth.
- Secret handle enforcement.

## Existing MVP Module Mapping

| Runtime responsibility | Existing module baseline | Boundary rule |
|---|---|---|
| Intent and lifecycle shell | `crates/agentd/src/lifecycle.rs` | May host AgentCore entry points, but lifecycle stubs must not remain the production runtime. |
| Semantic tool routing | `crates/agentd/src/tools.rs` | Every planned tool must route here before policy. |
| Policy and approval | `crates/agentd/src/policy.rs` | Planner risk hints are advisory; policy remains authoritative. |
| Sandbox constraints | `crates/agentd/src/sandbox.rs` | Profiles are compiled from leases, never from model output. |
| Audit truth | `crates/agentd/src/audit.rs` | Effect truth is recorded here before and after execution. |
| Rollback | `crates/agentd/src/rollback.rs` | Writes must use diff and rollback handles. |
| Recovery | `crates/agentd/src/recovery.rs` | Restart reconciliation uses audit/run state, not model replay. |
| Workflow proof | `crates/agentd/src/service_recovery.rs` | Must migrate to generic AgentCore execution. |
| Safety gate | `crates/agentd/src/safety.rs` | Must expand to full runtime abuse cases. |
| TUI projection | `crates/agentd/src/tui.rs` | Shows run state and approval, but does not grant broad authority. |

## Forbidden Paths

- Model output directly invoking a tool.
- Planner invoking raw shell or host commands.
- Agent Core preparing `EffectPrepared` without Security Execution Foundation.
- Agent Core sealing commits without verification.
- Tool observations directly creating follow-up high-risk actions.
- Memory storing raw secret values or untrusted instructions without labels.
- Sandbox profiles being weakened by planner or model hints.
- Distribution image work starting before generic AgentCore runtime acceptance.

## Distribution Alpha Gate

Distribution Alpha is blocked until Runtime Foundation proves:

1. A generic AgentCore run loop can execute service recovery.
2. All side effects pass through semantic tools, policy, capability leases,
   sandboxing, audit, verification, rollback, and recovery.
3. Runtime safety gates cover prompt injection, observation injection, memory
   poisoning, approval bypass, secret handling, and half-committed effects.

## Consequences

- `TASK-ACR-*` tasks implement orchestration only.
- `TASK-SEF-*` tasks own all side-effect safety semantics.
- Existing MVP modules must be reused and hardened, not duplicated.
- Any implementation that bypasses ToolRouter, PolicyEvaluator, AuditJournal,
  Rollback, or Recovery fails the runtime foundation gate.

## Change Control

Changing this boundary requires a new accepted decision and updates to
`TASK.md`, `plan.json`, affected `TASK-*.json` files, safety gates, and runtime
verification evidence before implementation continues.
