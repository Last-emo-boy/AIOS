# Runtime Implementation Task Blueprint

Source: `research.md`
Workflow: `WFS-20260522-agentos-runtime-foundation`
Updated: `2026-05-23T06:24:00+08:00`

## Purpose

This document expands the Maestro task plan for the bottom Agent runtime and the
AgentOS Security Execution Foundation. It is the worker-facing blueprint for
turning the completed MVP safety substrate into a distribution-grade AgentOS
control plane.

Detailed per-task worker contracts are maintained in
`docs/agent-core-sef-detailed-tasks.md`. That companion document is the
authoritative expansion for each `TASK-ACR-*` and `TASK-SEF-*`
`read_first`, implementation step, failure-mode, verification-matrix, and
handoff requirement.

The design is intentionally split into two layers:

- Agent Core Runtime owns intent, planning, scheduling, observation, memory,
  run state, and user-facing projections.
- Security Execution Foundation owns policy, capability leases, sandbox
  compilation, effect transactions, audit truth, verification, rollback, and
  recovery.

Agent Core can decide what should happen next, but only the Security Execution
Foundation can decide whether an effect is allowed and how it is executed.

## Cross-Layer Execution Chain

```text
IntentCtx
  -> ModelBroker request
  -> Planner output
  -> PlanSpec validation
  -> PlanFrozen audit event
  -> PlanRun persisted by RunStore
  -> StepScheduler selects ready step
  -> SecurityExecutionEngine::prepare
  -> PolicyAdapter evaluates PlanStep
  -> CapabilityLease issued or denied
  -> SandboxProfile compiled from lease
  -> EffectPrepared audit event
  -> Executor invokes semantic tool
  -> EffectObserved audit event
  -> ObservationProcessor normalizes evidence
  -> VerificationResult
  -> CommitSealed | RollbackPending | FailedClosed
  -> Memory update with redaction and trust labels
  -> Runtime audit projection for CLI/TUI
```

Forbidden edges:

- `ModelBroker -> ToolRouter`
- `Planner -> Executor`
- `ObservationProcessor -> ToolRouter`
- `Memory -> PolicyDecision`
- `TUI approval -> broad session permission`
- `Sandbox hint from model -> SandboxProfile authority`

## Agent Core Runtime TASK Expansion

### `TASK-ACR-001` Runtime Data Model

Goal: define the stable vocabulary for every future Agent run.

Implementation slices:

- Define `IntentCtx` with actor, source, trust boundary, working scope, and
  requested outcome.
- Define `PlanSpec` with planner version, model evidence metadata, success
  criteria, rollback requirements, and risk hints.
- Define `PlanStep` with semantic tool call, dependencies, preconditions,
  expected observations, verification rule, approval requirement, and retry
  budget.
- Define `PlanRun` with frozen plan hash, state, step cursor, approval state,
  observation refs, memory refs, and recovery marker.
- Define `Observation` with source, trust label, normalized result, redaction
  status, and policy-relevant flags.
- Add deterministic JSON serialization for audit and run-state snapshots.

Convergence checks:

- Service recovery can be represented without executing a tool.
- Risk hints remain advisory and never become permissions.
- Secret-like values are rejected or redacted from every runtime model surface.
- Snapshot JSON remains stable across test runs.

### `TASK-ACR-002` Persistent PlanRun Store

Goal: make run state recoverable without model replay.

Implementation slices:

- Define `RunStore` trait with create, load, update-state, append observation,
  list recoverable, and seal operations.
- Implement file-backed store first, using deterministic JSON snapshots and
  atomic write discipline.
- Persist plan hash, run state, cursor, approval state, observation refs,
  memory refs, and recovery markers.
- Cross-check persisted run state with `AuditJournal` seal events.
- Detect tampered snapshots or plan-hash mismatch as fail-closed.

Convergence checks:

- Restart can list in-flight runs without asking the model to re-plan.
- Failed or partial writes do not produce a valid newer state.
- Completed runs are not re-executed.
- Snapshot tampering is detected by tests.

### `TASK-ACR-003` ModelBroker and Stub Provider

Goal: make all model access explicit, bounded, local-optional, and replaceable.

Implementation slices:

- Define `ModelBroker` trait for plan, classify, summarize, and sanitize calls.
- Add deterministic `StubModelProvider` for acceptance tests and offline mode.
- Store model metadata, provider ID, prompt template version, output length, and
  timeout/cancel result without storing secrets.
- Reject malformed or unbounded model output before it reaches Planner.
- Add provider failure behavior that downgrades to safe read-only or
  human-required states.

Convergence checks:

- Tests never require external LLM access.
- Provider output cannot directly name executor commands.
- Invalid JSON, oversized output, timeout, and cancellation all fail closed.
- Model call logs remain metadata-only.

### `TASK-ACR-004` Planner and Frozen PlanSpec

Goal: turn intent into a validated, side-effect-free, frozen plan.

Implementation slices:

- Create `Planner` that consumes `IntentCtx`, runtime context, and `ModelBroker`
  output.
- Validate every tool name against the semantic tool manifest.
- Validate dependencies, retry budget, rollback requirement, approval
  requirement, and success criteria.
- Compute and persist a plan freeze hash.
- Emit `IntentReceived` and `PlanFrozen`; emit no side-effect events.
- Reject generic `shell.exec`, unknown tools, missing rollback on writes, and
  secret-like plan content.

Convergence checks:

- Planner can produce the nginx recovery DAG.
- Planner cannot create an executable effect.
- Frozen plan hash changes on meaningful plan mutation.
- Invalid tool, invalid dependency, and secret-like plan tests fail closed.

### `TASK-ACR-005` AgentCore Run Loop

Goal: implement the deterministic state machine that advances a `PlanRun`.

Implementation slices:

- Implement `accept_intent`, `plan_run`, `advance_run`, `approve_step`,
  `deny_step`, `suspend_run`, and `recover_run`.
- Persist state transitions before external effects.
- Call the Security Execution Foundation for every effect.
- Pause high-risk steps before `EffectPrepared`.
- Return compact CLI/TUI projection for current state.
- Treat inconsistent planner, policy, executor, audit, or recovery state as
  `FailedClosed`.

Convergence checks:

- Read-only step can advance through prepare, observe, verify, and seal.
- Approval-required step reaches `AwaitingApproval` and prepares no effect.
- Denied or timed-out approval does not execute.
- Crash-safe state is visible through `RunStore`.

### `TASK-ACR-006` Dependency-Aware StepScheduler

Goal: choose ready steps deterministically from the frozen plan.

Implementation slices:

- Validate DAG shape before plan freeze.
- Select ready steps only when dependencies have sealed success events.
- Block dependents on denied, failed-closed, rollback-pending, or exhausted
  retry states.
- Provide deterministic scheduler explanations for audit projection.
- Keep retry budget state in `PlanRun`, not in model memory.

Convergence checks:

- Missing dependency, cycle, and self-dependency are rejected.
- Parallel-ready read-only steps are stable in order.
- Failed dependency blocks downstream writes.
- Retry exhaustion leads to suspended or failed-closed state, not a loop.

### `TASK-ACR-007` Observation Processor

Goal: turn tool output into structured evidence without letting observations
become commands.

Implementation slices:

- Normalize tool result into `Observation` records.
- Attach source labels: operator, local-system, sandbox, external, model, or
  sanitized.
- Redact secret-like values and preserve secret handles.
- Extract policy-relevant flags such as suspicious instruction, source mismatch,
  external command request, and exfiltration hint.
- Produce sanitized replanning hints only; never produce a direct tool call.

Convergence checks:

- Observation injection cannot schedule a new high-risk step.
- External content is labeled untrusted until sanitized.
- Secret-like output is redacted before memory or audit summaries.
- Policy flags are visible to SEF source-to-sink checks.

### `TASK-ACR-008` Minimal Agent Memory Layer

Goal: persist useful context without turning memory into authority.

Implementation slices:

- Define memory scopes: session, run, audit-derived, operator-pinned, and
  quarantined.
- Store source, trust label, TTL, redaction state, integrity hash, and run refs.
- Build bounded planner context from allowlisted memory entries.
- Quarantine suspicious, untrusted, or policy-like content.
- Reject secret values and broad capability claims.

Convergence checks:

- Memory can help explain a run but cannot authorize tools.
- Memory poisoning cannot inject policy overrides, approval claims, or leases.
- Expired memory is excluded from planner context.
- Secret handles survive redaction; secret values do not.

### `TASK-ACR-009` Service Recovery Migration

Goal: prove the generic runtime by moving nginx recovery off the dedicated
workflow path.

Implementation slices:

- Express recovery as `IntentCtx -> PlanSpec -> PlanRun`.
- Keep the old service workflow as a compatibility wrapper only.
- Run read-only diagnostics automatically.
- Pause restart/write steps until exact approval is bound.
- Preserve existing TUI/CLI behavior through the generic projection.

Convergence checks:

- Approved path seals restart effect after health check.
- Denied path prepares no restart effect.
- Audit timeline includes intent, plan, policy, approval, effect, observation,
  verification, and seal events.
- Legacy wrapper delegates to AgentCore and does not duplicate orchestration.

### `TASK-ACR-010` AgentCore Adversarial Runtime Tests

Goal: make abuse cases part of the release gate.

Implementation slices:

- Add prompt-injection planning tests.
- Add observation-injection tests.
- Add memory-poisoning tests.
- Add approval parameter mutation tests.
- Add malformed model output tests.
- Wire the suite into CI and release scripts.

Convergence checks:

- Abuse cases fail closed without `EffectPrepared`.
- The suite runs independently from external services.
- CI and release gate both require `agent_core::adversarial`.
- Test failures identify whether the break is planning, policy, memory,
  approval, or execution.

## Security Execution Foundation TASK Expansion

### `TASK-SEF-001` Generic EffectEnvelope

Goal: make each side effect a transaction with auditable state.

Implementation slices:

- Define `EffectEnvelope` with run ID, step ID, tool, normalized params,
  policy decision, lease, sandbox profile, prepared event, observed event,
  verification result, rollback handle, and commit ID.
- Define states: Draft, Prepared, Observed, Verified, Sealed,
  RollbackPending, RolledBack, and FailedClosed.
- Bind each transition to `AuditJournal` events.
- Prevent AgentCore from fabricating sealed effects.
- Redact serialized envelope content.

Convergence checks:

- `EffectPrepared` precedes any `EffectObserved`.
- `CommitSealed` requires successful verification.
- Failed writes cannot skip `RollbackPending`.
- Secret-like values never appear in serialized envelopes.

### `TASK-SEF-002` Policy and Capability Adapter

Goal: connect generic `PlanStep` requests to the existing policy evaluator.

Implementation slices:

- Normalize `PlanStep` into semantic tool request.
- Re-evaluate risk using policy, not planner hints.
- Return allow, deny, or pause-for-approval with reason and policy version.
- Bind approval tokens to actor, tool, resource, parameter hash, expiry, and
  policy version.
- Issue capability leases only after policy allows or approval is valid.

Convergence checks:

- Denied and paused paths emit policy audit only and prepare no effect.
- Mutated parameters invalidate approval.
- Planner risk hint cannot lower policy risk.
- Capability lease scope is no broader than the policy decision.

### `TASK-SEF-003` Lease-Derived Sandbox Profiles

Goal: make sandbox authority derive from leases, not planner suggestions.

Implementation slices:

- Compile namespace, cgroup, seccomp, filesystem, Landlock, and network
  constraints from `CapabilityLease`.
- Log ignored planner sandbox hints.
- Reject unsupported risk classes or missing lease fields.
- Provide stable profile summaries for audit projection.
- Keep high-risk Firecracker routing as a later distribution/Alpha executor
  profile, not an MVP dependency.

Convergence checks:

- Read-only leases produce read-only sandbox profiles.
- Persistent write requires explicit write lease.
- Network egress is deny-by-default unless lease allows it.
- Planner cannot weaken namespace, filesystem, or syscall constraints.

### `TASK-SEF-004` Untrusted Source-to-Sink Policy

Goal: prevent external or model-origin content from directly driving dangerous
sinks.

Implementation slices:

- Define source labels for operator, local-system, external, model, sanitized,
  memory, and audit-derived content.
- Define sink classes for read, write, execute, privileged, network, and
  secret access.
- Deny untrusted/model-origin direct access to execute, privileged, secret, and
  exfiltration-capable network sinks.
- Allow sanitized summaries to inform planning without becoming authority.
- Record blocked source-to-sink attempts in policy audit events.

Convergence checks:

- Webpage text cannot trigger `shell.exec`, package install, secret read, or
  outbound post.
- Sanitization changes trust label but not authority.
- Denied attempts have no `EffectPrepared`.
- Audit projection can explain source and sink classes.

### `TASK-SEF-005` Secret Handle Lease Rules

Goal: keep secrets as handles with short, narrow use windows.

Implementation slices:

- Define `SecretHandle` metadata without raw values.
- Define one-shot `SecretUseLease` with actor, tool, resource, expiry, and
  purpose.
- Preserve handles in redaction while removing raw secret values.
- Reject broad approvals such as "allow all secrets".
- Ensure model context, memory, audit summaries, and normal logs stay
  handle-only.

Convergence checks:

- Raw token/password/API key values are rejected from runtime surfaces.
- One-shot lease cannot be reused after consumption or expiry.
- Approval must bind exact secret handle and tool purpose.
- Audit can show handle use without leaking the value.

### `TASK-SEF-006` SecurityExecutionEngine Bridge

Goal: provide the only generic execution path for AgentCore effects.

Implementation slices:

- Define `SecurityExecutionEngine` trait with prepare, execute, observe,
  verify, seal, rollback, and explain operations.
- Implement default engine over ToolRouter, PolicyEvaluator, CapabilityLease,
  SandboxProfile, EffectEnvelope, AuditJournal, and rollback handles.
- Deny or pause without preparing effects.
- Keep write-with-diff checkpointing inside prepare.
- Return structured explanation for CLI/TUI projection.

Convergence checks:

- AgentCore cannot bypass the engine for side effects.
- Prepared write contains rollback handle before execution.
- Read-only effects can seal after verification.
- Engine errors map to rollback-pending or failed-closed states.

### `TASK-SEF-007` Agent Run Recovery Integration

Goal: reconcile `RunStore` and `AuditJournal` into a no-model-replay recovery
decision.

Implementation slices:

- Scan recoverable `PlanRun` snapshots.
- Scan audit for prepared, observed, sealed, rollback-pending, and unresolved
  effects.
- Classify runs as safe-to-verify, needs-rollback, needs-human-review,
  abandoned, completed, or failed-closed.
- Restore AgentCore state to Recovering, Suspended, RollbackPending,
  Completed, or FailedClosed.
- Emit recovery projection with sources and reasons.

Convergence checks:

- Recovery never asks the model to infer whether an effect happened.
- Prepared-but-unobserved writes require review or rollback.
- Observed-but-unsealed successful read-only steps can be verified and sealed.
- Inconsistent audit/run-store state fails closed.

### `TASK-SEF-008` Generic Agent Execution Safety Gate

Goal: make runtime abuse cases release-blocking.

Implementation slices:

- Extend safety manifest from MVP-only cases to generic Agent execution cases.
- Require `safety::` and `agent_core::adversarial` in CI and release scripts.
- Include model injection, observation injection, memory poisoning, approval
  mutation, source-to-sink abuse, secret misuse, and recovery abuse.
- Store scenario names, commands, and expected gate behavior in the manifest.

Convergence checks:

- Safety gate distinguishes model-planning failure from runtime bypass.
- Missing adversarial suite blocks release.
- Abuse scenario additions are visible to release evidence.
- Gate output is deterministic enough for CI.

### `TASK-SEF-009` Runtime Audit Projection and Explainability

Goal: give operators a complete terminal explanation of why every step ran,
paused, denied, rolled back, or sealed.

Implementation slices:

- Add `RuntimeAuditProjection` derived from `AuditJournal` and run timeline.
- Support latest-run and explicit run-id lookup.
- Group events by run and step while preserving global event order.
- Include plan hash, planner metadata, policy reason, approval binding, lease
  ID, sandbox profile summary, effect status, observation trust label,
  verification result, rollback/recovery status, and final summary.
- Redact secret-like content while preserving handles and source references.
- Expose projection through CLI and TUI without breaking raw audit output.

Convergence checks:

- Service recovery projection shows the full intent-to-seal chain.
- Denied and paused steps explain why no effect was prepared.
- Recovery projection names run-store and audit evidence sources.
- Snapshot tests prove stable ordering and redaction.

### `TASK-SEF-010` Final SEF Verification

Goal: prove the hardened substrate still holds when driven by generic
AgentCore.

Implementation slices:

- Run full `agentd` test suite.
- Run `safety::` and `agent_core::adversarial`.
- Run approved and denied service recovery paths.
- Run recovery tests for interrupted `PlanRun` states.
- Run release/provenance script where applicable.
- Record final evidence and update workflow handoff notes.

Convergence checks:

- No generic Agent path bypasses semantic tools, policy, capability, sandbox,
  audit, verification, rollback, or recovery.
- Denied high-risk actions have no `EffectPrepared`.
- Half-executed actions are recoverable, rollback-pending, or failed-closed.
- Generated artifacts remain ignored or deliberately tracked.
- Distribution Alpha remains blocked until this task passes.

## Pending Execution Pointer

Current next task: `TASK-RTF-004`.

Runtime Foundation Wave 4 is complete. `TASK-SEF-010` passed the Security
Execution Foundation final verification across full agentd regression, safety
gate, AgentCore adversarial tests, service recovery approved/denied smoke,
runtime audit projection, release/provenance generation, initramfs build, and
QEMU dependency check.

The next implementation should define Distribution Alpha entry criteria from
the completed runtime foundation. It must translate the runtime contract into
distribution gates for installed `agentd`, policy packs, semantic tool
manifests, run-state persistence, audit projection, rollback/recovery
artifacts, and ModelBroker configuration.

Minimum read-first set for `TASK-RTF-004`:

- `TASK.md`
- `.workflow/active/WFS-20260522-agentos-runtime-foundation/.task/TASK-RTF-004.json`
- `.workflow/active/WFS-20260522-agentos-runtime-foundation/evidence/TASK-SEF-010-final-verification.json`
- `.workflow/active/WFS-20260522-agentos-runtime-foundation/docs/agent-core-runtime.md`
- `.workflow/active/WFS-20260522-agentos-runtime-foundation/docs/security-execution-foundation.md`
- `.workflow/active/WFS-20260522-agentos-runtime-foundation/docs/runtime-safety-gates.md`

Minimum verification for `TASK-RTF-004`:

- JSON parse of updated workflow artifacts
- Cross-check that Distribution Alpha remains blocked until `TASK-RTF-005`
- Confirm no generated release or smoke artifacts are staged

## Distribution Bridge Requirement

Distribution work must not start from "a Linux image with an agent binary". It
must start from this runtime contract:

- `agentd` can accept intent and create a frozen `PlanRun`.
- Model access is only through `ModelBroker`.
- AgentCore uses the scheduler and cannot directly invoke tools.
- SecurityExecutionEngine is the only effect path.
- Policy, capability, sandbox, audit, verification, rollback, and recovery are
  mandatory for side effects.
- Runtime audit projection can explain the chain from intent to final state.
- Safety and adversarial gates are part of release verification.
