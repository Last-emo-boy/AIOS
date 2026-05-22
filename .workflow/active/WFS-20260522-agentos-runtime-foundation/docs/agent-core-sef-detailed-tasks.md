# Agent Core Runtime and SEF Detailed Task Specification

Source: `research.md`
Workflow: `WFS-20260522-agentos-runtime-foundation`
Purpose: worker-facing Maestro expansion for the bottom Agent runtime and the AgentOS Security Execution Foundation.

## Implementation Thesis

The bottom Agent is not an LLM prompt loop. It is a deterministic runtime inside
`agentd` with typed state, durable run snapshots, strict model boundaries, and a
single controlled effect path.

```text
IntentCtx
  -> ModelBroker
  -> Planner
  -> PlanSpec validation
  -> PlanRun persisted by RunStore
  -> StepScheduler
  -> SecurityExecutionEngine
  -> PolicyAdapter
  -> CapabilityLease
  -> SandboxProfile
  -> EffectEnvelope
  -> AuditJournal
  -> ObservationProcessor
  -> VerificationResult
  -> CommitSealed | RollbackPending | FailedClosed
  -> RuntimeAuditProjection
```

The Agent Core Runtime decides what should happen next. The Security Execution
Foundation decides whether an effect may happen and how it is constrained,
observed, verified, audited, rolled back, or recovered.

## Cross-Cutting Rules

- Model output never calls `ToolRouter`, executors, shell, policy, or sandbox
  APIs directly.
- Planner risk hints are advisory. `PolicyEvaluator` remains the risk authority.
- `SecurityExecutionEngine` is the only path to `EffectPrepared`.
- `RunStore` is scheduling state. `AuditJournal` remains effect truth.
- Recovery uses `RunStore + AuditJournal`, never model replay.
- Secret values are handle-only across model context, memory, audit, CLI, and
  TUI surfaces.
- External content, tool output, and model summaries are untrusted until labeled
  and sanitized.
- Distribution Alpha cannot start from a bootable MVP skeleton; it must inherit
  this runtime contract.

## Agent Core Runtime Task Expansion

### `TASK-ACR-001` Runtime Data Model

Owner: AgentCore model layer.
Primary files: `crates/agentd/src/agent_core.rs`, `crates/agentd/src/lib.rs`.

Input contract:

- `IntentCtx`: actor, source, trust boundary, working scope, requested outcome.
- Tool manifest and policy vocabulary from the existing MVP substrate.

Output contract:

- Versioned `PlanSpec`, `PlanStep`, `PlanRun`, `Observation`, and `RunState`.
- Stable JSON for audit, snapshot tests, and future distribution rootfs state.

Implementation steps:

1. Define runtime IDs and versioned structs with deterministic serialization.
2. Encode `PlanStep` dependencies, tool request, expected observation,
   verification rule, approval requirement, retry budget, and rollback need.
3. Encode `PlanRun` with frozen plan hash, cursor, approval state, observation
   refs, memory refs, and recovery marker.
4. Encode `Observation` with source label, trust label, summary, normalized
   result, redaction state, and policy flags.
5. Add constructors or validators that reject secret-like fields and direct
   executor commands.

Failure modes to test:

- Secret-like text in intent, plan, observation, or run snapshot.
- Plan step that names raw shell or unknown tool.
- Missing verification or rollback metadata on write-capable steps.
- Non-deterministic JSON output across test runs.

Verification:

- `cargo test -p agentd agent_core::model`
- Service recovery plan can be represented without preparing any effect.
- Stable JSON snapshot for a representative nginx recovery `PlanSpec`.

### `TASK-ACR-002` Persistent PlanRun Store

Owner: AgentCore persistence layer.
Primary files: `crates/agentd/src/agent_core.rs`.

Input contract:

- Validated `PlanRun` from `TASK-ACR-001`.
- Audit event refs from `AuditJournal`.

Output contract:

- Crash-safe, tamper-detectable run snapshots.
- Recoverable-run index for startup reconciliation.

Implementation steps:

1. Define `RunStore` trait: create, load, update state, append observation,
   attach approval, mark terminal, list recoverable.
2. Implement file-backed snapshots using temp-write plus rename semantics.
3. Persist plan hash, run state, cursor, approval, observations, memory refs,
   and recovery marker.
4. Store hashes for frozen plan and observation refs.
5. Treat audit seal information as read-only evidence, not as duplicated effect
   truth in the store.

Failure modes to test:

- Partial write leaves neither corrupt nor silently newer state.
- Snapshot tampering or plan-hash mismatch fails closed.
- Completed runs are not listed as recoverable.
- RunStore claims an effect is sealed without matching audit evidence.

Verification:

- `cargo test -p agentd agent_core::run_store`
- Simulated interrupted write.
- Cross-check persisted effect refs against `AuditJournal`.

### `TASK-ACR-003` ModelBroker and Stub Provider

Owner: model boundary.
Primary files: `crates/agentd/src/agent_core.rs`, `docs/model-broker.md`.

Input contract:

- Sanitized intent, bounded memory context, and explicit provider config.
- No raw secrets, only secret handles or redacted summaries.

Output contract:

- Structured plan, classify, summarize, and sanitize responses.
- Metadata-only model call records.
- Deterministic stub provider for local-only acceptance.

Implementation steps:

1. Define `ModelBroker` trait for plan, classify, summarize, and sanitize.
2. Define request/response envelopes with provider ID, model ID, template
   version, timeout, output bound, confidence, and digest.
3. Implement `StubModelProvider` with deterministic valid responses.
4. Add bounded-output, invalid-JSON, timeout, cancellation, and provider failure
   handling.
5. Reject malformed output before Planner receives it.

Failure modes to test:

- Oversized or malformed provider response.
- Provider timeout or cancellation.
- Model output containing shell commands or secret requests.
- Direct provider usage outside `ModelBroker`.

Verification:

- `cargo test -p agentd model_broker::`
- Source search for direct provider calls outside the broker.
- Confirm no provider failure creates `EffectPrepared`.

### `TASK-ACR-004` Planner and Frozen PlanSpec

Owner: planning layer.
Primary files: `crates/agentd/src/agent_core.rs`, `crates/agentd/src/tools.rs`.

Input contract:

- `IntentCtx`, bounded runtime context, and `ModelBroker` draft output.
- Semantic tool manifest and runtime safety gates.

Output contract:

- Frozen `PlanSpec` with stable hash.
- `IntentReceived` and `PlanFrozen` audit events only.

Implementation steps:

1. Create Planner trait with draft, validate, freeze, and explain methods.
2. Validate every tool name and normalized parameter shape through the semantic
   tool manifest.
3. Validate dependencies, retry budgets, approval requirements, rollback
   requirements, and success criteria.
4. Reject shell, unknown tools, secret-like content, and missing rollback on
   write-capable steps.
5. Freeze plan hash after validation and before any scheduling.

Failure modes to test:

- Planner tries to execute or prepare an effect.
- Planner labels high-risk work as read-only to downgrade policy.
- Plan has cycle, missing dependency, unknown tool, or missing verification.
- Frozen plan mutates without hash change.

Verification:

- `cargo test -p agentd planner::`
- Audit order: `IntentReceived -> PlanFrozen`, no `EffectPrepared`.
- Snapshot frozen service recovery plan.

### `TASK-ACR-005` AgentCore Run Loop

Owner: runtime state machine.
Primary files: `crates/agentd/src/agent_core.rs`, `crates/agentd/src/main.rs`,
`crates/agentd/src/tui.rs`.

Input contract:

- Frozen `PlanSpec`, `RunStore`, `StepScheduler`, and `SecurityExecutionEngine`.

Output contract:

- Durable `PlanRun` transitions through accepted, planning, planned,
  awaiting-approval, executing, observing, verifying, completed, suspended,
  rollback-pending, recovering, denied, or failed-closed.

Implementation steps:

1. Implement `accept_intent`, `plan_run`, `advance_run`, `approve_step`,
   `deny_step`, `suspend_run`, and `recover_run`.
2. Persist each state transition before invoking external effect code.
3. Call `SecurityExecutionEngine` for every side effect.
4. Pause approval-required steps before `EffectPrepared`.
5. Map planner, policy, executor, audit, rollback, and recovery inconsistencies
   to suspended, rollback-pending, or failed-closed states.
6. Return compact CLI/TUI projections without exposing raw secret values.

Failure modes to test:

- Approval timeout or denial prepares an effect.
- Executor called without `SecurityExecutionEngine`.
- Crash after state transition but before effect.
- Policy, audit, or envelope mismatch during advance.

Verification:

- `cargo test -p agentd agent_core::run_loop`
- Approved and denied diagnostic/restart demo.
- Audit timeline for state ordering.

### `TASK-ACR-006` Dependency-Aware StepScheduler

Owner: scheduler.
Primary files: `crates/agentd/src/agent_core.rs`.

Input contract:

- Frozen `PlanSpec` DAG and current `PlanRun` state.
- Audit-backed completed dependency evidence.

Output contract:

- Deterministic ready-step selection and scheduler explanation.

Implementation steps:

1. Validate missing dependency, self-dependency, and cycle cases before plan
   freeze.
2. Select only steps whose dependencies have sealed success events or explicit
   alternative-path satisfaction.
3. Block dependents after denied, failed-closed, rollback-pending, or exhausted
   dependency states.
4. Store retry budget in `PlanRun`, not model memory.
5. Generate stable scheduler explanation for audit projection.

Failure modes to test:

- Cyclic plan freezes.
- Denied dependency allows downstream write.
- Retry budget loops forever.
- Scheduler order changes nondeterministically.

Verification:

- `cargo test -p agentd agent_core::scheduler`
- Linear, branched, cyclic, denied-dependency, and retry-exhausted plans.

### `TASK-ACR-007` ObservationProcessor

Owner: observation and trust-boundary layer.
Primary files: `crates/agentd/src/agent_core.rs`,
`crates/agentd/src/security_execution.rs`.

Input contract:

- Tool result, external content, model summary, or operator note.

Output contract:

- Structured `Observation` with source label, trust label, redaction state, and
  policy flags.

Implementation steps:

1. Normalize tool output into observations with source labels.
2. Mark external/model-origin content untrusted until sanitized.
3. Redact secret-like values while preserving secret handles.
4. Extract flags: suggested command, credential request, exfiltration hint,
   privilege escalation, source mismatch, or policy override.
5. Emit sanitized replanning hints only; never emit direct tool calls.
6. Store observation refs in RunStore and audit summaries.

Failure modes to test:

- Observation text directly creates a high-risk step.
- External output loses its untrusted label.
- Secret value enters memory, audit, model context, CLI, or TUI.
- Sanitized hint is treated as authority.

Verification:

- `cargo test -p agentd agent_core::observation`
- Prompt/observation injection fixtures.
- Audit entries show source labels and flags.

### `TASK-ACR-008` Minimal Agent Memory Layer

Owner: runtime memory.
Primary files: `crates/agentd/src/agent_core.rs`.

Input contract:

- Sanitized observations, operator-pinned notes, audit-derived facts, and run
  summaries.

Output contract:

- Bounded planner context with scope, source, trust label, TTL, redaction state,
  and integrity metadata.

Implementation steps:

1. Define `MemoryStore` trait: write, read context, search recent, expire,
   quarantine.
2. Separate session, run, audit-derived, operator-pinned, and quarantined
   scopes.
3. Reject or redact raw secrets before write.
4. Quarantine suspicious untrusted instructions and policy-like claims.
5. Build bounded planner context from allowlisted entries.
6. Preserve source refs so the planner cannot treat memory as authority.

Failure modes to test:

- Memory grants policy, approval, or capability.
- Expired memory enters planner context.
- Secret-like value is stored as normal memory.
- Untrusted memory becomes trusted operator input.

Verification:

- `cargo test -p agentd agent_core::memory`
- Memory poisoning and secret-retention fixtures.
- Inspect planner context size and source labels.

### `TASK-ACR-009` Service Recovery Migration

Owner: generic runtime proof.
Primary files: `crates/agentd/src/agent_core.rs`,
`crates/agentd/src/service_recovery.rs`, `crates/agentd/src/main.rs`.

Input contract:

- Existing service recovery behavior and runtime contracts from ACR/SEF tasks.

Output contract:

- Service recovery expressed as `IntentCtx -> PlanSpec -> PlanRun`, with legacy
  wrapper delegating to AgentCore.

Implementation steps:

1. Encode nginx recovery as a Planner-produced DAG.
2. Run read-only diagnostics automatically through AgentCore.
3. Pause restart for exact approval.
4. Execute restart and health verification through `SecurityExecutionEngine`.
5. Keep old CLI behavior by wrapping the generic path.
6. Remove duplicate workflow ownership from the legacy path.

Failure modes to test:

- Legacy service workflow bypasses AgentCore for execution.
- Denied restart prepares protected effect.
- Final summary relies on model claims instead of observations.
- Audit misses intent, plan, policy, approval, lease, effect, observation, or
  seal events.

Verification:

- `cargo test -p agentd agent_core::service_recovery`
- `cargo test -p agentd service_recovery::`
- Approved and denied CLI demos.

### `TASK-ACR-010` AgentCore Adversarial Runtime Tests

Owner: runtime abuse gate.
Primary files: `crates/agentd/src/agent_core.rs`,
`crates/agentd/src/safety.rs`, `.github/workflows/safety.yml`,
`.github/workflows/release.yml`, `scripts/build-release.ps1`.

Input contract:

- Generic runtime path after service recovery migration.

Output contract:

- Release-blocking adversarial suite for model, observation, memory, approval,
  and malformed-output abuse.

Implementation steps:

1. Add planning prompt-injection fixtures.
2. Add observation-injection fixtures after read-only tool output.
3. Add memory-poisoning fixtures across runs.
4. Add approval parameter mutation fixtures.
5. Add malformed model output and model-generated shell command fixtures.
6. Wire the suite into CI and release scripts.

Failure modes to test:

- Abuse path creates `EffectPrepared` before denial.
- Approval mutation passes with changed parameter hash.
- Memory poisoning changes policy, lease, or approval behavior.
- Malformed model output reaches Planner as a valid plan.

Verification:

- `cargo test -p agentd agent_core::adversarial`
- `cargo test -p agentd safety::`
- CI/release script includes the runtime adversarial command.

## Security Execution Foundation Task Expansion

### `TASK-SEF-001` Generic EffectEnvelope

Owner: effect transaction contract.
Primary files: `crates/agentd/src/security_execution.rs`,
`crates/agentd/src/audit.rs`.

Input contract:

- AgentCore `PlanStep`, policy result, capability lease, sandbox profile, and
  tool result.

Output contract:

- Auditable `EffectEnvelope` state machine from draft to sealed, rollback, or
  failed-closed.

Implementation steps:

1. Define envelope fields: run ID, step ID, tool, normalized params, policy,
   lease, sandbox profile, prepared event, observed event, verification result,
   rollback handle, and commit ID.
2. Define states: Draft, Prepared, Observed, Verified, Sealed,
   RollbackPending, RolledBack, FailedClosed.
3. Bind transitions to `AuditJournal` event families.
4. Reject invalid ordering and AgentCore-fabricated sealed states.
5. Redact serialized envelope fields.

Failure modes to test:

- `EffectObserved` without `EffectPrepared`.
- `CommitSealed` without successful verification.
- Failed write skips `RollbackPending`.
- Secret-like data appears in envelope JSON.

Verification:

- `cargo test -p agentd security_execution::effect_envelope`
- Invalid transition tests.
- Audit unresolved-effect cross-check.

### `TASK-SEF-002` Policy and Capability Adapter

Owner: AgentCore-to-policy bridge.
Primary files: `crates/agentd/src/security_execution.rs`,
`crates/agentd/src/policy.rs`, `crates/agentd/src/tools.rs`.

Input contract:

- `PlanStep` and semantic tool manifest.

Output contract:

- Allow, deny, or pause-for-approval decision plus capability lease metadata
  when allowed.

Implementation steps:

1. Translate `PlanStep` to semantic tool request.
2. Route tool name and normalized parameters through `ToolRouter`.
3. Reclassify risk with `PolicyEvaluator`; ignore downgrade hints from Planner.
4. Bind approval tokens to actor, tool, resource, parameter hash, expiry, and
   policy version.
5. Return decision to AgentCore without preparing effects on denied or paused
   paths.
6. Emit policy diagnostics for audit projection.

Failure modes to test:

- Planner risk hint downgrades policy result.
- Unknown tool or `shell.exec` reaches executor.
- Approval token reused after parameter mutation.
- Pause-for-approval creates `EffectPrepared`.

Verification:

- `cargo test -p agentd security_execution::policy_adapter`
- Approval mutation fixture.
- Audit contains policy version and parameter hash.

### `TASK-SEF-003` Lease-Derived Sandbox Profiles

Owner: sandbox compilation.
Primary files: `crates/agentd/src/sandbox.rs`,
`crates/agentd/src/security_execution.rs`.

Input contract:

- `CapabilityLease`, policy risk class, and semantic tool requirements.

Output contract:

- Stable sandbox profile summary for execution and audit.

Implementation steps:

1. Compile namespace, cgroup, seccomp/no_new_privs, filesystem, Landlock
   placeholder, and network constraints from lease metadata.
2. Ignore or audit planner-provided sandbox hints.
3. Produce profile classes for read-only diagnostics, write-with-diff
   preparation, execute-with-confirmation, privileged, and never.
4. Reject unsupported profile requirements fail-closed.
5. Attach profile summary to `EffectEnvelope`.

Failure modes to test:

- Planner adds writable path or network egress.
- Read-only lease gets persistent write permission.
- Unsupported risk class defaults to permissive behavior.
- Profile metadata missing from envelope/audit.

Verification:

- `cargo test -p agentd sandbox::`
- `cargo test -p agentd security_execution::sandbox_profile`
- Resource-abuse safety fixtures.

### `TASK-SEF-004` Untrusted Source-to-Sink Policy

Owner: trust-boundary policy.
Primary files: `crates/agentd/src/security_execution.rs`,
`crates/agentd/src/safety.rs`.

Input contract:

- Source-labeled content from operator, local system, sandbox, external source,
  model, memory, audit, or sanitized summary.

Output contract:

- Source-to-sink allow/deny decision with audit reason.

Implementation steps:

1. Define source labels and sink classes: read, write, execute, privileged,
   network, secret.
2. Deny model/external/untrusted direct access to execute, privileged, secret,
   or exfiltration-capable network sinks.
3. Allow sanitized summaries to inform planning but not grant authority.
4. Preserve source labels through sanitization.
5. Audit denied attempts without `EffectPrepared`.

Failure modes to test:

- Webpage text triggers command execution.
- Model-origin content reads secrets or posts data.
- Sanitization erases trust boundary.
- Denied attempt prepares effect.

Verification:

- `cargo test -p agentd safety::prompt_injection`
- `cargo test -p agentd security_execution::source_to_sink`
- Audit denied record contains source and sink classes.

### `TASK-SEF-005` Secret Handle Lease Rules

Owner: secret runtime boundary.
Primary files: `crates/agentd/src/security_execution.rs`,
`crates/agentd/src/safety.rs`.

Input contract:

- Secret handles and explicit secret-use requests.

Output contract:

- Handle-only model, memory, audit, CLI, and TUI surfaces.
- One-shot secret-use leases for approved tools.

Implementation steps:

1. Define `SecretHandle` metadata without raw secret values.
2. Define one-shot `SecretUseLease` with actor, tool, resource, purpose, expiry,
   and consumption state.
3. Reject raw secret values in PlanSpec, Observation, Memory, audit summary, CLI,
   and TUI projection.
4. Preserve `secret://handle` references through redaction.
5. Reject broad approvals such as "all secrets" or "any credential".
6. Audit handle use without revealing the value.

Failure modes to test:

- Raw token/password/API key appears in serialized runtime surface.
- One-shot lease reused or used after expiry.
- Approval grants broad secret access.
- Secret handle loses identity during redaction.

Verification:

- `cargo test -p agentd safety::secret`
- `cargo test -p agentd security_execution::secret_runtime`
- Audit inspection for handle-only behavior.

### `TASK-SEF-006` SecurityExecutionEngine Bridge

Owner: generic execution choke point.
Primary files: `crates/agentd/src/security_execution.rs`,
`crates/agentd/src/rollback.rs`, `crates/agentd/src/audit.rs`.

Input contract:

- AgentCore `PlanStep` and optional approval context.

Output contract:

- Prepared, executed, observed, verified, sealed, rolled-back, or failed-closed
  effect lifecycle.

Implementation steps:

1. Define `SecurityExecutionEngine` trait: prepare, execute, observe, verify,
   seal, rollback, explain.
2. Implement default engine over `ToolRouter`, `PolicyEvaluator`,
   `CapabilityLease`, `SandboxProfile`, `EffectEnvelope`, `AuditJournal`, and
   rollback handles.
3. Ensure denied and paused paths return without `EffectPrepared`.
4. Prepare write-with-diff rollback handles before execution.
5. Run read-only tools under sandbox profile.
6. Return structured errors that AgentCore maps to suspended, rollback-pending,
   denied, or failed-closed states.

Failure modes to test:

- Execute called without prepared envelope.
- Write effect lacks rollback handle.
- Denied or paused path prepares effect.
- Engine error loses audit/recovery evidence.

Verification:

- `cargo test -p agentd security_execution::engine`
- Policy, sandbox, rollback, and audit targeted tests.
- Attempt direct execute-without-prepare rejection.

### `TASK-SEF-007` Agent Run Recovery Integration

Owner: recovery coordinator.
Primary files: `crates/agentd/src/agent_core.rs`,
`crates/agentd/src/recovery.rs`, `crates/agentd/src/audit.rs`.

Input contract:

- Recoverable `PlanRun` snapshots and unresolved audit effects.

Output contract:

- Recovery classification and restored AgentCore state without model replay.

Implementation steps:

1. Join RunStore recoverable runs with audit prepared, observed, sealed,
   rollback-pending, and unresolved effects.
2. Classify each run as safe-to-verify, needs-rollback, needs-human-review,
   abandoned, completed, or failed-closed.
3. Restore state to Recovering, Suspended, RollbackPending, Completed, or
   FailedClosed based on durable evidence.
4. Emit `RecoveryStarted` and `RecoveryCompleted` linked to run and step IDs.
5. Expose recovery projection for CLI/TUI.

Failure modes to test:

- Recovery asks model whether an effect happened.
- Prepared write without seal is marked completed.
- Observed but unsealed read-only effect cannot be safely reconciled.
- Inconsistent RunStore/audit state proceeds without fail-closed classification.

Verification:

- `cargo test -p agentd recovery::`
- `cargo test -p agentd agent_core::recovery`
- Crash simulations after prepare, observe, and verification failure.

### `TASK-SEF-008` Generic Agent Execution Safety Gate

Owner: release-blocking safety gate.
Primary files: `crates/agentd/src/safety.rs`, `.github/workflows/safety.yml`,
`.github/workflows/release.yml`, `scripts/build-release.ps1`.

Input contract:

- Generic AgentCore + SEF runtime path.

Output contract:

- CI and release gate requiring safety and adversarial subsets.

Implementation steps:

1. Extend the safety manifest from MVP substrate scenarios to generic Agent
   execution scenarios.
2. Require model output injection, observation injection, memory poisoning,
   approval mutation, source-to-sink abuse, secret misuse, and recovery abuse
   cases.
3. Assert denied paths have no `EffectPrepared`.
4. Assert half-committed paths enter recovery, rollback-pending, or failed-closed
   states.
5. Wire `safety::` and `agent_core::adversarial` into CI/release scripts.
6. Record scenario names and commands in evidence.

Failure modes to test:

- CI or release omits runtime adversarial suite.
- Safety gate only covers isolated substrate functions, not generic runtime.
- Denied path prepares effect.
- Half-executed effect has no recovery classification.

Verification:

- `cargo test -p agentd safety::`
- `cargo test -p agentd agent_core::adversarial`
- Inspect CI and release workflow command list.

### `TASK-SEF-009` Runtime Audit Projection

Owner: operator explainability.
Primary files: `crates/agentd/src/audit.rs`, `crates/agentd/src/main.rs`,
`crates/agentd/src/tui.rs`.

Input contract:

- Durable audit event timeline and optional run recovery evidence.

Output contract:

- Stable projection explaining why each step ran, paused, denied, rolled back,
  failed closed, or sealed.

Implementation steps:

1. Build `RuntimeAuditProjection` from audit timeline without changing raw
   event storage.
2. Support latest-run and explicit run-id lookup.
3. Preserve durable event order while grouping by run and step for readability.
4. Include plan hash, planner metadata, policy reason, approval binding, lease,
   sandbox summary, effect status, observation trust label, verification result,
   rollback/recovery status, and final summary.
5. Reuse redaction for every user-facing projection field.
6. Expose CLI and TUI render paths from the same projection model.

Failure modes to test:

- Missing run ID falls back to a different run.
- Prepared-but-unsealed effect appears completed.
- Denied or paused step omits the no-effect-prepared explanation.
- Projection leaks raw token/password/API key values.

Verification:

- `cargo test -p agentd audit::`
- `cargo test -p agentd tui::`
- `cargo test -p agentd agent_core::service_recovery`

### `TASK-SEF-010` Final SEF Verification

Owner: final runtime substrate gate before Distribution Alpha.
Primary files: full runtime, CI, release, and workflow evidence.

Input contract:

- Completed AgentCore migration, adversarial gates, safety gate, and runtime
  audit projection.

Output contract:

- Evidence that generic Agent execution preserves the SEF invariants and
  Distribution Alpha remains gated on the final Runtime Foundation audit.

Implementation steps:

1. Run full `agentd` regression.
2. Run `safety::`, `agent_core::adversarial`, `agent_core::service_recovery`,
   and `agent_core::` subsets independently.
3. Run approved and denied service recovery smoke through generic AgentCore.
4. Confirm denied high-risk action has no `EffectPrepared`.
5. Run release/provenance script and QEMU dependency check when applicable.
6. Inspect generated artifacts and git status so build byproducts are not
   staged as source.
7. Write final evidence and keep Distribution Alpha blocked until
   `TASK-RTF-005` completes.

Failure modes to test:

- Any safety/adversarial failure.
- Runtime path bypasses `SecurityExecutionEngine`.
- Denied high-risk action prepares an effect.
- Unresolved effect lacks recovery, rollback, or human-review state.
- Release script omits runtime safety gates.

Verification:

- `cargo test -p agentd`
- `cargo test -p agentd safety::`
- `cargo test -p agentd agent_core::adversarial`
- `cargo test -p agentd agent_core::service_recovery`
- `cargo test -p agentd agent_core::`
- `pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1`

## Maestro Execution Order

```text
TASK-RTF-000
  -> TASK-RTF-001 / TASK-RTF-002 / TASK-RTF-003
  -> TASK-ACR-001
  -> TASK-ACR-002 + TASK-ACR-003
  -> TASK-ACR-004
  -> TASK-SEF-001 / TASK-SEF-002 / TASK-SEF-003 / TASK-SEF-004 / TASK-SEF-005
  -> TASK-ACR-005 + TASK-SEF-006
  -> TASK-ACR-006 / TASK-ACR-007 / TASK-ACR-008 / TASK-SEF-007
  -> TASK-ACR-009
  -> TASK-ACR-010 + TASK-SEF-008 + TASK-SEF-009 + TASK-SEF-010
  -> TASK-RTF-004
  -> TASK-RTF-005
```

## Distribution Handoff Gate

Distribution Alpha may begin only after this chain proves:

- `agentd` has a generic AgentCore run loop, not a hand-written workflow set.
- `SecurityExecutionEngine` is the only side-effect path.
- Policy, capability, sandbox, audit, verification, rollback, and recovery are
  mandatory for every effect.
- Service recovery runs through the generic runtime.
- Safety and adversarial suites are release-blocking.
- Runtime audit projection can explain intent-to-seal evidence.
- Future rootfs includes runtime state, audit, rollback, policy pack, semantic
  tool manifest, and ModelBroker config as distribution artifacts.
