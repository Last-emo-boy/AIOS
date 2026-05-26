# Runtime Scheduler And Autonomous Budget

Task: `TASK-ARUN-012`

## Purpose

AgentOS is operated through Agent Runtime, so autonomy must be explicitly bounded. The scheduler is not only a step picker; it is the runtime guard that prevents observation-triggered replanning, recovery loops, ecosystem activation and service repair from becoming unbounded OS mutation.

This contract defines scheduling, retry, quota, backpressure and operator escalation rules for Production Distro progression.

## Existing Runtime Basis

Current implementation already provides the core safety primitives:

- `agent_core::scheduler::StepScheduler` validates PlanSpec DAGs and rejects missing dependencies, cycles and unroutable tools.
- Scheduler readiness is based on durable `AuditJournal` `CommitSealed` evidence, not observation text alone.
- `EffectPrepared` attempts that are not resolved by `CommitSealed` or `RollbackObserved` count against the step retry budget.
- Retry exhaustion returns `SchedulerDecisionKind::RetryExhausted` with terminal state `FailedClosed`.
- Denied dependencies block dependent steps and return terminal state `FailedClosed`.
- Security execution sandbox profiles enforce resource ceilings such as `pids.max`, syscall denial and persistent write limits.

## Scheduling Model

The AgentOS steady-state loop remains:

```text
Observe -> Normalize -> Plan -> Schedule -> Execute -> Verify -> Seal -> Project
```

Scheduling authority is limited to frozen `PlanSpec`, durable `PlanRun` state and audit truth. Scheduler output may select a ready step or terminal state, but it must not grant approval, acquire capability leases or bypass SecurityExecutionEngine.

### Sequential-First Rule

Production baseline is sequential-first:

- one mutating step per run is scheduled at a time;
- dependent steps require sealed predecessors;
- `current_step_id` cannot bypass unsealed dependencies;
- read-only parallelism is an explicit future extension and must be separately budgeted.

### Dependency Truth Rule

A dependency is satisfied only when the audit journal contains a matching `CommitSealed` event for:

- `run_id`
- `step_id`
- normalized `parameter_hash`

Observation refs, model summaries, planner explanations and operator text cannot satisfy dependencies.

## Risk-Class Budget Policy

| Risk class | Autonomous scheduling | Retry budget default | Concurrency | Exhaustion result |
| --- | --- | --- | --- | --- |
| `read-only` | allowed after plan freeze | low, bounded | limited read-only pool | `Suspended` or `FailedClosed` with projection |
| `write-with-diff` | only after diff and rollback metadata exist | normally 1 | single mutating lane | `RollbackPending` or `FailedClosed` |
| `execute-with-confirmation` | requires exact approval before effect | normally 1 | single mutating lane | `FailedClosed` and operator escalation |
| `privileged-with-human-approval` | requires exact human approval and stronger sandbox/isolation | 0 or 1 by policy | exclusive lane | `FailedClosed` and support bundle hint |
| `never` | never scheduled | 0 | none | deny before `EffectPrepared` |

Planner risk hints are advisory only. Authoritative risk comes from tool routing and policy evaluation.

## Autonomous Action Budget

Each run should carry an action budget derived from policy, run source and risk class:

- `max_steps`: maximum scheduled steps before suspension;
- `max_unsealed_attempts`: maximum unresolved `EffectPrepared` records per step;
- `max_replans`: maximum observation-triggered replans per run;
- `max_runtime_ms`: wall-clock budget for the run;
- `max_read_only_parallelism`: read-only-only extension point, default `1`;
- `max_mutating_parallelism`: always `1` for baseline;
- `max_privileged_parallelism`: always `0` unless an exact human approval is active.

Budget state must be persisted or reconstructable from `RunStore` plus `AuditJournal`. A restart must not reset retry counters or replan counters.

## Backpressure Rules

Backpressure is the runtime state that says "do not schedule more work yet." It must be visible to operator projection and durable enough for recovery.

Backpressure sources:

- pending operator approval;
- unresolved effect envelope;
- retry exhaustion;
- rollback pending;
- denied dependency chain;
- degraded optional dependency;
- sandbox resource denial;
- too many queued runs;
- ecosystem activation lock held;
- release/replay gate running.

Backpressure actions:

- pause scheduling for the affected run;
- deny new high-risk work if a mutating lane is occupied;
- keep read-only diagnostics bounded;
- emit projection fields for blocked reason and next operator action;
- write audit/projection evidence before any retry.

## Observation-Triggered Replanning

Observation-derived replanning is allowed only when the observation fabric preserves trust labels from `TASK-ARUN-011`.

Rules:

- external or model-origin observations can create sanitized replanning hints only;
- replanning consumes `max_replans`;
- replanning cannot convert an untrusted observation into operator intent;
- replanning cannot increase risk authority or approval scope;
- replanning cannot reset retry budget;
- replanning must reference observation ids and hashes.

If the replan request would create a dangerous sink from untrusted content, source-to-sink policy must deny it before `EffectPrepared`.

## Quotas

Runtime quotas should be enforced in three layers.

### Run Queue Quotas

- total queued runs;
- queued runs per actor;
- queued high-risk runs;
- queued ecosystem activation runs;
- queued recovery runs.

### Step Execution Quotas

- per-step retry budget;
- per-step timeout;
- maximum unresolved prepared effects;
- maximum rollback attempts;
- maximum approval wait time.

### Sandbox Resource Quotas

- process count;
- CPU quota;
- memory;
- writable tmpfs;
- persistent write allowlist;
- syscall allow/deny set;
- network allowlist;
- Firecracker dependency availability when a microVM profile is required.

If sandbox limits are hit, the scheduler must treat it as runtime backpressure or failure evidence, not as permission to fall back to host execution.

## Operator Escalation

Budget exhaustion must produce an explainable state:

- `AwaitingApproval` when exact operator approval can safely unblock the step;
- `Suspended` when manual intervention or later retry window is appropriate;
- `RollbackPending` when an effect was prepared and must be reconciled;
- `FailedClosed` when authority is missing, retry is exhausted or dependency truth is broken.

Operator projection should expose:

- `scheduler.ready_steps`
- `scheduler.sealed_steps`
- `scheduler.blocked_by`
- `scheduler.retry_budget_remaining`
- `scheduler.backpressure_status`
- `scheduler.exhausted_budget`
- `scheduler.next_operator_action`

## Audit Requirements

Scheduling decisions that block, retry, exhaust or escalate must be audit-visible. Minimum evidence:

- scheduler decision kind;
- run id and selected step id;
- ready and sealed steps;
- blocked dependencies;
- retry attempts and retry budget;
- terminal state if any;
- backpressure reason;
- observation refs if replanning was involved.

No scheduler event grants authority. Authority remains in policy decisions, approvals, leases and SecurityExecutionEngine effect envelopes.

## Failure Modes To Block

- Infinite retries after repeated `EffectPrepared` without commit.
- Observation-only dependency satisfaction.
- Planner hint downgrades high-risk action to read-only.
- Replan resets budgets.
- Missing Firecracker or package-manager dependency falls back to host execution.
- Agentd introduces scheduler policy or adapter business logic.
- Ecosystem activation competes with service recovery in the mutating lane without a lock.

## Verification Mapping

| Requirement | Current evidence |
| --- | --- |
| High-risk actions cannot retry indefinitely | `agent_core::scheduler::tests::retry_budget_exhaustion_fails_closed` |
| Dependencies require sealed audit truth | `agent_core::scheduler::tests::linear_plan_waits_for_commit_sealed_not_observation_only` |
| Current step cannot bypass dependencies | `agent_core::scheduler::tests::current_step_cannot_bypass_unsealed_dependency` |
| Denied dependencies fail closed | `agent_core::scheduler::tests::denied_dependency_blocks_dependent_step` |
| Scheduler output is deterministic | `agent_core::scheduler::tests::branched_plan_selection_is_deterministic_and_explained` |
| Sandbox resource abuse is bounded | `agentd::safety::tests::resource_abuse_hits_configured_sandbox_limits` |

## Follow-Up Tasks

- `TASK-ARUN-020` should make budget and backpressure reconstruction durable across boot.
- `TASK-ARUN-021` should bind approval survival to budget exhaustion and operator escalation.
- `TASK-ECO-004` and `TASK-ECO-005` should route ecosystem activation through this scheduling model before SecurityExecutionEngine prepares effects.
- `TASK-PROD-053` should include long-running budget, backpressure and retry evidence in final Production Distro audit.
