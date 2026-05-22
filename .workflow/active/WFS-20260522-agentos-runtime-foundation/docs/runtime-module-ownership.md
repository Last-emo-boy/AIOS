# Runtime Module Ownership

Source: `research.md:143`
Task: `TASK-RTF-002`
Workflow: `WFS-20260522-agentos-runtime-foundation`

## Purpose

This document maps every planned AgentOS runtime responsibility to one owner,
one Rust module location, one integration point, and one testing surface. The
goal is to prevent parallel policy engines, parallel audit journals, or
workflow-specific execution stacks.

The first implementation remains in-process inside `agentd`. IPC boundaries can
be introduced later without changing ownership.

## Ownership Matrix

| Responsibility | Owner | Rust module location | Existing baseline | Integration point | May append audit events | Test owner |
|---|---|---|---|---|---|---|
| Agent orchestration | AgentCore | `crates/agentd/src/agent_core.rs` | `lifecycle.rs` stubs | `AgentCore::accept_intent`, `AgentCore::advance_run`, `AgentCore::recover_run` | No, requests writes through SEF or Planner hooks | `agent_core::run_loop` |
| Runtime data model | AgentCore | `crates/agentd/src/agent_core.rs` | `api.rs` skeleton types | `IntentCtx`, `PlanSpec`, `PlanStep`, `PlanRun`, `Observation` | No | `agent_core::model` |
| Run-state persistence | RunStore | `crates/agentd/src/agent_core.rs` initially | None | `RunStore` trait | No | `agent_core::run_store` |
| Planner | Planner | `crates/agentd/src/planner.rs` or `agent_core.rs` initially | `lifecycle.rs::plan` stub | `Planner::draft_plan`, `Planner::validate_plan`, `Planner::freeze_plan` | Yes, only `IntentReceived` and `PlanFrozen` via AuditJournal | `planner::` |
| Model access | ModelBroker | `crates/agentd/src/model_broker.rs` | `modules.rs` placeholder | `ModelBroker::plan`, `classify`, `summarize`, `sanitize` | No; returns metadata for audit | `model_broker::` |
| Step scheduling | StepScheduler | `crates/agentd/src/agent_core.rs` initially | None | `StepScheduler::next_ready_step` | No | `agent_core::scheduler` |
| Observation processing | ObservationProcessor | `crates/agentd/src/agent_core.rs` initially | Audit summaries and safety fixtures | `ObservationProcessor::normalize`, `sanitize`, `classify_trust` | May request observation audit through SEF | `agent_core::observation` |
| Memory | MemoryStore | `crates/agentd/src/memory.rs` or `agent_core.rs` initially | None | `MemoryStore::write_entry`, `read_context`, `quarantine` | No | `agent_core::memory` |
| Semantic routing | ToolRouter | `crates/agentd/src/tools.rs` | Existing implementation | `ToolRouter::route` | No | `tools::tests` |
| Policy evaluation | PolicyEvaluator | `crates/agentd/src/policy.rs` | Existing implementation | `PolicyEvaluator::evaluate`, `acquire_lease`, `record_decision` | Yes, `PolicyEvaluated` / decision records | `policy::tests` |
| Capability leasing | Capability manager | `crates/agentd/src/policy.rs` initially | Existing `CapabilityLease` | `PolicyEvaluator::acquire_lease` | Yes, through policy decision audit | `policy::tests` |
| Sandbox execution | SandboxExecutor | `crates/agentd/src/sandbox.rs` | Existing implementation | `SandboxCompiler::compile`, `SandboxExecutor::run` | Yes, sandbox denials/effects | `sandbox::tests` |
| Effect execution bridge | SecurityExecutionEngine | `crates/agentd/src/security_execution.rs` | Existing policy/sandbox/rollback pieces | `prepare`, `execute`, `observe`, `verify`, `seal`, `rollback` | Yes, all effect lifecycle events | `security_execution::engine` |
| Audit truth | AuditJournal | `crates/agentd/src/audit.rs` | Existing implementation | `AuditJournal::append`, `unresolved_effects`, `event_lines` | Yes, append-only owner | `audit::tests` |
| Rollback | Rollback manager | `crates/agentd/src/rollback.rs` | Existing implementation | `WriteDiffExecutor::prepare`, `commit`, `rollback` | Yes, rollback lifecycle events | `rollback::tests` |
| Recovery | RecoveryReconciler | `crates/agentd/src/recovery.rs` | Existing implementation | `RecoveryReconciler::reconcile` plus future run-state join | Yes, `RecoveryStarted` / `RecoveryCompleted` | `recovery::tests`, `agent_core::recovery` |
| Runtime projection | TUI/API | `crates/agentd/src/tui.rs`, `main.rs` | Existing demo projection | `--agent-run`, `--agent-approve`, `--agent-recover`, TUI run view | No, invokes runtime APIs | `tui::tests` |
| Safety gates | Safety suite | `crates/agentd/src/safety.rs` | Existing safety gate | `cargo test -p agentd safety::` | No | `safety::tests` |

## Integration Diagram

```text
TUI / CLI / API
  -> AgentCore
      -> Planner
          -> ModelBroker
          -> ToolRouter validation
          -> AuditJournal(IntentReceived, PlanFrozen)
      -> RunStore
      -> StepScheduler
      -> SecurityExecutionEngine
          -> ToolRouter
          -> PolicyEvaluator
          -> CapabilityLease
          -> SandboxCompiler / SandboxExecutor
          -> Rollback manager
          -> AuditJournal(PolicyEvaluated, EffectPrepared, EffectObserved,
                          CommitSealed, RollbackPending, Recovery*)
      -> ObservationProcessor
      -> MemoryStore
      -> RecoveryReconciler
```

## Public Interface Sketch

```rust
pub struct AgentCore<R, P, E, M> {
    run_store: R,
    planner: P,
    execution: E,
    memory: M,
}

impl<R, P, E, M> AgentCore<R, P, E, M> {
    pub fn accept_intent(&self, intent: IntentCtx) -> Result<RunId, AgentError>;
    pub fn plan_run(&self, run_id: &RunId) -> Result<FrozenPlan, AgentError>;
    pub fn advance_run(&self, run_id: &RunId) -> Result<RunState, AgentError>;
    pub fn approve_step(&self, run_id: &RunId, token: ApprovalToken) -> Result<RunState, AgentError>;
    pub fn deny_step(&self, run_id: &RunId, reason: String) -> Result<RunState, AgentError>;
    pub fn recover_run(&self, run_id: &RunId) -> Result<RunState, AgentError>;
}

pub trait SecurityExecutionEngine {
    fn prepare(&self, run: &PlanRun, step: &PlanStep) -> Result<EffectEnvelope, ExecutionError>;
    fn execute(&self, envelope: EffectEnvelope) -> Result<EffectEnvelope, ExecutionError>;
    fn verify(&self, envelope: &EffectEnvelope) -> Result<VerificationResult, ExecutionError>;
    fn seal(&self, envelope: EffectEnvelope) -> Result<EffectEnvelope, ExecutionError>;
    fn rollback(&self, envelope: EffectEnvelope) -> Result<EffectEnvelope, ExecutionError>;
}
```

## Audit Write Rules

- `AuditJournal` is the only append-only event writer.
- `Planner` may request `IntentReceived` and `PlanFrozen`.
- `PolicyEvaluator` may request `PolicyEvaluated` and `ApprovalBound`.
- `SecurityExecutionEngine` may request effect, sandbox, rollback, and recovery
  audit events through the existing audit layer.
- `AgentCore`, `StepScheduler`, `MemoryStore`, `ModelBroker`, TUI, CLI, and API
  do not directly invent effect audit records.

## CLI and TUI Entry Points

The first runtime CLI surface should add these command families:

| Command | Owner | Behavior |
|---|---|---|
| `--agent-run <intent>` | AgentCore | Accept intent, freeze plan, and advance until completion or approval pause. |
| `--agent-status <run-id>` | AgentCore / RunStore | Show current state, current step, pending approval, and evidence refs. |
| `--agent-approve <run-id> <step-id> <token>` | AgentCore / PolicyEvaluator | Bind exact approval and resume. |
| `--agent-deny <run-id> <step-id>` | AgentCore | Deny protected step without effect preparation. |
| `--agent-recover [run-id]` | AgentCore / RecoveryReconciler | Reconcile RunStore and audit evidence. |
| `--agent-audit <run-id>` | Audit projection | Project full run timeline. |

The TUI must call the same runtime APIs. It must not call service-specific
workflow code directly after `TASK-ACR-009`.

## Stub vs Implemented in This Workflow

| Area | First workflow target |
|---|---|
| AgentCore data model | Implemented |
| File-backed RunStore | Implemented |
| Stub ModelBroker provider | Implemented |
| Local model provider | Stubbed / deferred |
| Remote model provider | Stubbed / optional only |
| Planner validation and freeze | Implemented |
| StepScheduler sequential DAG | Implemented |
| ObservationProcessor trust labels | Implemented |
| MemoryStore minimal file-backed or in-memory implementation | Implemented |
| SecurityExecutionEngine bridge | Implemented |
| Firecracker runner | Deferred to Distribution/Alpha execution isolation tasks |
| Full Linux seccomp/Landlock enforcement | Existing profile contract hardened; deeper enforcement can remain platform-gated |

## Duplicate Stack Prohibition

No task may introduce a second:

- policy engine,
- audit journal,
- semantic tool router,
- rollback manager,
- recovery reconciler,
- shell execution path,
- service-specific orchestration loop that bypasses AgentCore.

Service recovery may keep compatibility wrappers, but orchestration must route
through AgentCore after `TASK-ACR-009`.
