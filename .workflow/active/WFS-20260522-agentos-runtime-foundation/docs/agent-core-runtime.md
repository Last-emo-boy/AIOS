# Agent Core Runtime

Source: `research.md`
Workflow: `WFS-20260522-agentos-runtime-foundation`

## Purpose

Agent Core Runtime is the deterministic orchestration layer inside `agentd`.
It is not the model. It owns intent intake, plan creation, plan freezing,
step scheduling, observation handling, memory updates, approval pauses, and
run-state recovery.

The model is only reachable through `ModelBroker`. Model output can propose a
plan or summary, but it cannot execute tools and cannot weaken policy,
capability, sandbox, audit, rollback, or recovery rules.

## Boundary

Agent Core owns:

- `IntentCtx` intake and normalization.
- `PlanSpec` and `PlanRun` state.
- `Planner` orchestration through `ModelBroker`.
- `StepScheduler` dependency ordering.
- `ObservationProcessor` conversion from tool output to structured evidence.
- `Memory` writes with source, TTL, redaction, and trust labels.
- TUI/API projection of run state and approval pauses.

Agent Core does not own:

- Raw host command execution.
- Policy decisions.
- Capability lease issuance.
- Sandbox weakening.
- Audit seal semantics.
- Rollback or recovery truth.
- Secret resolution.

## Required State Machine

```text
Accepted
  -> Planning
  -> Planned
  -> AwaitingApproval
  -> Executing
  -> Observing
  -> Verifying
  -> Completed

Alternative exits:
  -> Denied
  -> Suspended
  -> RollbackPending
  -> Recovering
  -> FailedClosed
```

All transitions must be backed by persisted run state and audit events. A model
retry cannot erase previous observations or approvals.

## Run Loop Contract

```text
accept(intent) -> RunId
plan(run_id) -> FrozenPlan
next_step(run_id) -> SchedulableStep | AwaitingApproval | Completed
execute(step) -> EffectEnvelope
observe(effect) -> Observation
verify(observation) -> VerificationResult
advance(run_id) -> RunState
recover(run_id) -> ReconciledRunState
```

The run loop must call the Security Execution Foundation for every side effect:

```text
PlanStep
  -> SemanticToolCall
  -> PolicyDecision
  -> CapabilityLease
  -> Sandbox/Executor
  -> EffectPrepared
  -> EffectObserved
  -> VerificationResult
  -> CommitSealed | RollbackPending
```

## Acceptance Gate

The first proof is service recovery migration. The nginx recovery flow must run
through the generic Agent Core Runtime, not through a dedicated hard-coded
workflow path. The audit timeline must still show intent, frozen plan, policy
decision, approval, lease, prepared effect, observed effect, verification, and
sealed commit.

## Detailed TASK Map

The detailed Maestro implementation blueprint is maintained in
`docs/runtime-implementation-tasks.md`. Agent Core Runtime is decomposed into
the following executable chain:

| Task | Runtime responsibility | Must prove |
|---|---|---|
| `TASK-ACR-001` | Versioned runtime data model for `IntentCtx`, `PlanSpec`, `PlanStep`, `PlanRun`, and `Observation`. | Service recovery can be represented without executing tools; secrets cannot enter model surfaces. |
| `TASK-ACR-002` | Persistent `RunStore` for crash-safe `PlanRun` snapshots. | In-flight runs can be recovered without model replay; tampered snapshots fail closed. |
| `TASK-ACR-003` | `ModelBroker` trait and deterministic stub provider. | Tests require no external LLM; malformed model output is rejected before planning. |
| `TASK-ACR-004` | Planner and frozen `PlanSpec` validator. | Planning emits `IntentReceived` and `PlanFrozen` only; no side-effect event is created. |
| `TASK-ACR-005` | AgentCore run loop state machine. | Read-only steps can seal; high-risk steps pause before `EffectPrepared`. |
| `TASK-ACR-006` | Dependency-aware `StepScheduler`. | Dependencies require sealed success events; failed dependency blocks downstream work. |
| `TASK-ACR-007` | `ObservationProcessor` trust-boundary handling. | Observation text cannot directly create a tool call. |
| `TASK-ACR-008` | Minimal Agent memory layer. | Memory helps context but cannot authorize policy, approval, lease, or tool use. |
| `TASK-ACR-009` | Service recovery migration onto generic AgentCore. | The legacy workflow becomes a wrapper, not a second orchestration path. |
| `TASK-ACR-010` | AgentCore adversarial runtime tests. | Prompt injection, observation injection, memory poisoning, approval mutation, and malformed model output fail closed. |

The bottom Agent implementation is therefore not a single "agent loop" hidden
behind a prompt. It is a typed pipeline where the model proposes bounded
structure, AgentCore persists and schedules deterministic state, and the
Security Execution Foundation remains the only side-effect authority.
