# Runtime Control Loops

Task: `TASK-ARUN-010`

## Purpose

AgentOS should operate as an Agent Runtime controlled OS, not as a conventional distro with scattered scripts. This document defines the first production-oriented control-loop map for boot and steady-state operation.

The design is constrained by the current runtime:

- `agentd` is PID 1 / process integration / operator projection.
- Agent Core owns intent, PlanSpec, PlanRun, scheduler, observation, memory and recovery state.
- SecurityExecutionEngine owns policy, capability, sandbox, effect envelopes, verification, audit and rollback.
- Baseline operation must stay local-only and must not require external LLM, network, Firecracker or host package manager.

## Existing Runtime Signals

Current code already exposes the foundations needed for this loop model:

- `agent_core` has durable run states: `Accepted`, `Planning`, `Planned`, `AwaitingApproval`, `Executing`, `Observing`, `Verifying`, `Completed`, `Denied`, `Suspended`, `RollbackPending`, `Recovering` and `FailedClosed`.
- `agent_core` already separates planner, scheduler, observation, memory, recovery and run-store responsibilities.
- `agentd::operator_projection` is read-only and projects runtime health, telemetry, audit, update, adapter, support bundle and safety status.
- `scripts/boot-smoke-test.ps1` validates boot handoff plus packaged runtime markers and required runtime artifacts.

## Boot Control Loop

Goal: bring AgentOS from kernel handoff to a usable Agent Runtime control plane.

```text
Kernel/initramfs handoff
  -> agentd lifecycle start
  -> packaged runtime artifact validation
  -> policy/tool/model config load
  -> RunStore + AuditJournal + rollback recovery scan
  -> operator projection ready
  -> degraded-mode decision if optional dependencies are missing
```

### Boot Inputs

- kernel command line and initramfs handoff
- packaged `agentd`
- policy pack, semantic tool manifest, model broker config and operator command registry
- persistent state directories for runs, audit, rollback and memory
- release provenance and rootfs manifest markers

### Boot Outputs

- runtime health projection
- audit/recovery projection
- packaged runtime artifact status
- degraded-mode explanation when optional capabilities are unavailable
- boot evidence through QEMU markers

### Boot Persistence Rule

Boot may read durable state, but it must not create new side effects except lifecycle/recovery bookkeeping. Any compensating action must be represented as a recovery run and must still flow through SecurityExecutionEngine.

### Boot Local-Only Rule

Boot must not require:

- external LLM
- network registry
- Firecracker
- host package manager
- remote audit mirror

If these are unavailable, AgentOS should still boot and report degraded capability state.

## Steady-State Control Loop

Goal: keep AgentOS operating through bounded, observable and recoverable runtime loops.

```text
Observe -> Normalize -> Plan -> Schedule -> Execute -> Verify -> Seal -> Project
```

### Observe

Sources:

- operator command and TUI/API intent
- runtime health
- audit journal
- service/process state
- packaged runtime artifact state
- ecosystem staged/active artifact state
- external/untrusted content after sanitization only

Observation output must carry source and trust labels. External content and model output cannot directly create tool calls.

### Normalize

Operator input becomes `IntentCtx`. Non-operator observations become bounded observation records or sanitized replanning hints. The system must not confuse external text with operator authority.

### Plan

The planner produces a frozen `PlanSpec`. Planner risk hints remain advisory. They do not grant permission and cannot weaken sandbox, capability lease or policy evaluation.

### Schedule

The scheduler chooses ready steps based on dependencies, sealed predecessors, retry budgets and backpressure. It must not schedule protected side effects before approval and policy evaluation.

### Execute

All side effects go through SecurityExecutionEngine:

```text
PolicyAdapter -> CapabilityLease -> SandboxProfile -> EffectEnvelope
  -> observe -> verify -> CommitSealed / RollbackPending / FailedClosed
```

No steady-state loop may execute shell or adapter logic directly from `agentd`.

### Verify And Seal

Effects are not committed until verification passes. Failed write/activation/update effects must become `RollbackPending` or `FailedClosed`, not silently successful.

### Project

Operator projection must remain read-only. It should expose:

- runtime state
- latest run status
- unresolved effects
- audit seal status
- update readiness
- adapter availability
- support bundle readiness
- safety gate configuration
- degraded-mode explanation

## Control-Loop State Machine

```text
Booting
  -> RuntimeReady
  -> Observing
  -> Planning
  -> Planned
  -> Scheduling
  -> AwaitingApproval | Executing
  -> ObservingEffect
  -> Verifying
  -> Completed | RollbackPending | FailedClosed | Suspended
  -> Projecting
  -> Observing
```

Recovery can enter from `Booting`, `RuntimeReady`, `AwaitingApproval`, `Executing`, `Verifying` or `RollbackPending`.

## Durable State Before Side Effects

Before a side effect begins, AgentOS must already have:

- accepted intent or recovery reason
- frozen PlanSpec
- policy evaluation record
- exact approval record when required
- capability lease metadata
- effect envelope in `Prepared`
- rollback requirement or explicit no-rollback reason

This prevents the system from executing something it cannot later explain.

## Backpressure And Budgets

The steady-state loop must expose and enforce:

- max concurrent runs by risk class
- retry budget per step
- retry budget per run
- timeout per effect class
- degraded-mode pause for missing optional dependencies
- escalation when protected steps exceed budget

Read-only diagnostics may be more automatic, but they still need bounded resource use.

## Operator Projection Fields

Minimum projection additions for future implementation:

- `control_loop.boot_status`
- `control_loop.runtime_ready`
- `control_loop.degraded_mode`
- `control_loop.active_loop`
- `control_loop.pending_approvals`
- `control_loop.unresolved_effects`
- `control_loop.backpressure_status`
- `control_loop.last_recovery_action`

These fields can be added later without changing the current `agentd` responsibility boundary.

## Metrics

Suggested metrics:

- `agentos_runtime_boot_duration_ms`
- `agentos_runtime_loop_iterations_total`
- `agentos_runtime_degraded_mode_total`
- `agentos_runtime_pending_approvals`
- `agentos_runtime_unresolved_effects`
- `agentos_runtime_failed_closed_total`
- `agentos_runtime_rollback_pending_total`
- `agentos_runtime_scheduler_backpressure_total`
- `agentos_runtime_projection_latency_ms`

## Verification Mapping

| Requirement | Evidence |
| --- | --- |
| Boot loop does not require external dependencies | boot smoke and local/stub config validation |
| Steady-state loop cannot execute outside SecurityExecutionEngine | runtime architecture and existing safety tests |
| Projection can show loop health and degraded state | operator projection docs and future projection fields |
| QEMU smoke remains compatible | `scripts/boot-smoke-test.ps1 -QemuPath E:\qemu\qemu-system-x86_64.exe` |

## Implementation Follow-Up

This task is a contract/spec task. Later implementation should add the projection fields and runtime loop metrics after `TASK-ARUN-011` and `TASK-ARUN-012` define observation and scheduling details.
