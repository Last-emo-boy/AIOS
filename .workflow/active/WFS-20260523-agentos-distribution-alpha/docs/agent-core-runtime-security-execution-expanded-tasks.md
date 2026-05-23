# Agent Core Runtime and Security Execution Expanded TASKS

Source: `research.md`
Workflow: `WFS-20260523-agentos-distribution-alpha`
Upstream workflow: `WFS-20260522-agentos-runtime-foundation`
Purpose: make the bottom Agent implementation and the AgentOS security execution substrate visible as Maestro-executable work, not only as a high-level architecture claim.

## Maestro Position

This document is a Distribution Alpha carry-forward view of the completed Runtime Foundation work.

The implementation source of truth remains:

- `.workflow/active/WFS-20260522-agentos-runtime-foundation/docs/runtime-implementation-tasks.md`
- `.workflow/active/WFS-20260522-agentos-runtime-foundation/docs/agent-core-sef-detailed-tasks.md`
- `.workflow/active/WFS-20260522-agentos-runtime-foundation/evidence/FINAL-AUDIT-20260522.json`

The Alpha source of truth is:

- `.workflow/active/WFS-20260523-agentos-distribution-alpha/plan.json`
- `.workflow/active/WFS-20260523-agentos-distribution-alpha/.task/TASK-DALPHA-009.json`
- `.workflow/active/WFS-20260523-agentos-distribution-alpha/.task/TASK-DALPHA-010.json`
- `.workflow/active/WFS-20260523-agentos-distribution-alpha/.task/TASK-DALPHA-011.json`
- `.workflow/active/WFS-20260523-agentos-distribution-alpha/.task/TASK-DALPHA-012.json`

Distribution Alpha does not reimplement the runtime from scratch. It packages and proves the already-built runtime in a releaseable OS image path, then extends it with the first high-risk executor/workflow profiles.

## Bottom Agent Implementation Thesis

The bottom Agent is not an LLM loop and not a privileged shell. It is a deterministic runtime inside `agentd`.

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

The Agent Core Runtime answers: what should happen next?

The Security Execution Foundation answers: may this effect happen, under which constraints, with which evidence, and how can it be rolled back or recovered?

Hard forbidden edges:

- `ModelBroker -> ToolRouter`
- `Planner -> Executor`
- `Planner -> shell`
- `ObservationProcessor -> ToolRouter`
- `Memory -> PolicyDecision`
- `Firecracker helper -> host side effect`
- `TUI approval -> broad session permission`

## ACR Task Set: Agent Core Runtime

### `TASK-ACR-001`: Runtime Data Model

Goal: define the stable vocabulary for every Agent run.

Runtime contract:

- `IntentCtx` captures actor, source, trust boundary, working scope, and requested outcome.
- `PlanSpec` captures planner metadata, success criteria, rollback requirements, dependency graph, risk hints, and frozen hash.
- `PlanStep` captures semantic tool request, dependencies, expected observation, verification rule, retry budget, and approval requirement.
- `PlanRun` captures run state, cursor, approval state, observation refs, memory refs, and recovery marker.
- `Observation` captures source label, trust label, normalized result, redaction state, and policy flags.

Worker implementation steps:

1. Define versioned structs with deterministic serialization.
2. Add validators for secret-like content, unknown tools, raw shell, missing rollback, and missing verification.
3. Ensure all user-facing and audit-facing projections use the same stable IDs.
4. Add snapshot tests for a representative service recovery plan.

Verification:

- `cargo test -p agentd agent_core::model`
- Representative nginx recovery plan serializes without preparing an effect.
- Secret-like input fails closed or is redacted before persistence.

Distribution evidence:

- Runtime artifact manifest must install the `agentd` binary that contains this model layer.
- Release provenance must prove `cargo test -p agentd agent_core::` ran.

### `TASK-ACR-002`: Persistent PlanRun Store

Goal: make run state durable and recoverable without model replay.

Runtime contract:

- `RunStore` is the source of scheduling state.
- `AuditJournal` remains the source of effect truth.
- A restart can list recoverable runs from persisted snapshots.

Worker implementation steps:

1. Define `RunStore` operations: create, load, update state, append observation, attach approval, mark terminal, and list recoverable.
2. Implement atomic file snapshots with temp-write and rename.
3. Persist frozen plan hash, cursor, approvals, observations, memory refs, and recovery marker.
4. Detect tampered snapshots and plan-hash mismatch.
5. Cross-check claimed sealed effects against `AuditJournal`.

Verification:

- `cargo test -p agentd agent_core::run_store`
- Partial write simulation leaves no valid corrupt newer state.
- Completed runs are not listed as recoverable.

Distribution evidence:

- Rootfs must include persistent `/var/lib/agentos/runs/`.
- State directory validator must verify owner/mode and restart survival assumptions.

### `TASK-ACR-003`: ModelBroker and Stub Provider

Goal: make model access explicit, bounded, replaceable, and local-only capable.

Runtime contract:

- All model calls go through `ModelBroker`.
- Acceptance cannot require external LLM credentials or network access.
- Model call records store metadata only, not raw secrets.

Worker implementation steps:

1. Define `ModelBroker` trait for plan, classify, summarize, and sanitize.
2. Define request/response envelopes with provider ID, model ID, timeout, template version, confidence, digest, and output bound.
3. Implement deterministic `StubModelProvider`.
4. Reject malformed JSON, oversized output, timeout, cancellation, and model-generated shell commands before Planner sees them.

Verification:

- `cargo test -p agentd agent_core::model_broker`
- Provider failure creates no `EffectPrepared`.
- Source search confirms no direct provider usage outside broker.

Distribution evidence:

- Rootfs must install `etc/agentos/model-broker.toml`.
- Alpha config defaults must be stub/local-only by default.

### `TASK-ACR-004`: Planner and Frozen PlanSpec

Goal: turn intent into a validated, side-effect-free, frozen plan.

Runtime contract:

- Planner may emit `IntentReceived` and `PlanFrozen`.
- Planner may not emit `EffectPrepared`.
- Planner risk hints are advisory and never grant permission.

Worker implementation steps:

1. Consume `IntentCtx`, bounded memory context, and `ModelBroker` output.
2. Validate tool names and normalized parameters through semantic tool manifest.
3. Validate dependencies, retry budgets, approval requirements, rollback requirements, and success criteria.
4. Reject `shell.exec`, unknown tools, secret-like content, missing rollback, and missing verification.
5. Freeze plan hash before scheduling.

Verification:

- `cargo test -p agentd agent_core::planner`
- Audit order is `IntentReceived -> PlanFrozen`, with no side-effect event.
- Mutation changes frozen plan hash.

Distribution evidence:

- Rootfs must install semantic tool manifest.
- Policy pack must keep normal-mode shell denied.

### `TASK-ACR-005`: AgentCore Run Loop

Goal: advance a `PlanRun` through deterministic states.

Runtime contract:

- State transitions persist before external effect invocation.
- Every side effect enters through `SecurityExecutionEngine`.
- High-risk or approval-required steps pause before `EffectPrepared`.

Worker implementation steps:

1. Implement `accept_intent`, `plan_run`, `advance_run`, `approve_step`, `deny_step`, `suspend_run`, and `recover_run`.
2. Persist each transition to `RunStore`.
3. Call `SecurityExecutionEngine` for any effect-bearing step.
4. Map policy, executor, audit, rollback, and recovery inconsistencies to suspended, rollback-pending, or failed-closed.
5. Return compact CLI/TUI projections with redaction.

Verification:

- `cargo test -p agentd agent_core::run_loop`
- Denied or timed-out approval prepares no effect.
- Read-only step can prepare, observe, verify, and seal.

Distribution evidence:

- Packaged service recovery smoke must exercise approved and denied run-loop paths.

### `TASK-ACR-006`: Dependency-Aware StepScheduler

Goal: select ready steps deterministically from a frozen plan DAG.

Runtime contract:

- Dependencies are satisfied by sealed evidence, not model claims.
- Denied, failed-closed, rollback-pending, or exhausted dependencies block downstream writes.
- Retry budget lives in `PlanRun`, not memory.

Worker implementation steps:

1. Validate missing dependency, self-dependency, and cycle before plan freeze.
2. Select ready steps only after dependencies have sealed success events or explicit alternative satisfaction.
3. Store retry budget and scheduler explanation in run state.
4. Keep selection order deterministic.

Verification:

- `cargo test -p agentd agent_core::scheduler`
- Cyclic plans fail closed.
- Denied dependency blocks downstream write.

Distribution evidence:

- Runtime audit projection must show scheduler reason for each executed or blocked step.

### `TASK-ACR-007`: ObservationProcessor

Goal: turn tool output into structured evidence without letting observations become commands.

Runtime contract:

- Tool output, external content, model summaries, and operator notes become labeled observations.
- External/model-origin content remains untrusted until sanitized.
- Sanitized hints can inform planning but cannot directly create tool calls.

Worker implementation steps:

1. Normalize tool output into `Observation` records.
2. Attach source labels: operator, local-system, sandbox, external, model, memory, audit-derived, or sanitized.
3. Redact secret-like values while preserving secret handles.
4. Extract policy flags: suggested command, credential request, exfiltration hint, privilege escalation, source mismatch, and policy override.
5. Store observation refs in `RunStore` and audit summaries.

Verification:

- `cargo test -p agentd agent_core::observation`
- Observation injection cannot schedule high-risk steps.
- Secret-like values do not enter memory, audit, CLI, TUI, or model context.

Distribution evidence:

- `TASK-DALPHA-011` must prove untrusted content remains source-labeled through packaged runtime workflow.

### `TASK-ACR-008`: Minimal Agent Memory Layer

Goal: persist useful context without turning memory into authority.

Runtime contract:

- Memory stores facts, not permissions.
- Memory cannot grant policy, approval, capability, sandbox, or secret access.
- Suspicious untrusted instructions are quarantined.

Worker implementation steps:

1. Define `MemoryStore` with write, read context, search recent, expire, and quarantine.
2. Separate session, run, audit-derived, operator-pinned, and quarantined scopes.
3. Store source refs, trust labels, TTL, redaction state, and integrity metadata.
4. Build bounded planner context from allowlisted entries.
5. Reject secret values and broad capability claims.

Verification:

- `cargo test -p agentd agent_core::memory`
- Memory poisoning cannot inject policy overrides, approval claims, or capability leases.
- Expired memory is excluded from planner context.

Distribution evidence:

- Rootfs must include persistent `/var/lib/agentos/memory/`.
- Validator must check permission and secret-safety expectations.

### `TASK-ACR-009`: Service Recovery Migration

Goal: prove generic AgentCore by moving service recovery off the dedicated workflow path.

Runtime contract:

- Service recovery is `IntentCtx -> PlanSpec -> PlanRun`.
- Legacy CLI behavior may remain as wrapper only.
- Restart requires exact approval and runs through `SecurityExecutionEngine`.

Worker implementation steps:

1. Encode nginx recovery as a planner-produced DAG.
2. Run read-only diagnostics automatically.
3. Pause restart for exact approval.
4. Execute restart and health verification through SEF.
5. Keep old CLI as compatibility wrapper without duplicate orchestration.

Verification:

- `cargo test -p agentd agent_core::service_recovery`
- Approved path seals restart after health check.
- Denied path prepares no restart effect.

Distribution evidence:

- `scripts/alpha-service-recovery-smoke.ps1` must validate packaged approved and denied paths.

### `TASK-ACR-010`: AgentCore Adversarial Runtime Tests

Goal: make runtime abuse cases release-blocking.

Runtime contract:

- Prompt injection, observation injection, memory poisoning, approval mutation, and malformed model output are release gate concerns.
- Denied abuse paths must have no `EffectPrepared`.

Worker implementation steps:

1. Add planning prompt-injection fixtures.
2. Add observation-injection fixtures.
3. Add memory-poisoning fixtures.
4. Add approval parameter mutation fixtures.
5. Add malformed model output and model-generated shell command fixtures.
6. Wire suite into CI and release scripts.

Verification:

- `cargo test -p agentd agent_core::adversarial`
- `cargo test -p agentd safety::`
- Release provenance lists both commands.

Distribution evidence:

- `scripts/build-release.ps1` must run and record `agent_core::adversarial`.

## SEF Task Set: AgentOS Security Execution Foundation

### `TASK-SEF-001`: Generic EffectEnvelope

Goal: make every side effect a transaction.

Security contract:

- Every effect transitions through Draft, Prepared, Observed, Verified, Sealed, RollbackPending, RolledBack, or FailedClosed.
- `EffectObserved` requires `EffectPrepared`.
- `CommitSealed` requires successful verification.
- Failed write-capable effects cannot skip rollback classification.

Worker implementation steps:

1. Define envelope fields: run ID, step ID, tool, normalized params, policy decision, lease, sandbox profile, audit event refs, verification result, rollback handle, and commit ID.
2. Bind transitions to `AuditJournal`.
3. Reject invalid ordering.
4. Redact serialized envelope fields.

Verification:

- `cargo test -p agentd security_execution::effect_envelope`
- Invalid transition tests.
- Audit unresolved-effect cross-check.

Distribution evidence:

- Packaged runtime smoke must show denied high-risk steps do not produce `EffectPrepared`.

### `TASK-SEF-002`: Policy and Capability Adapter

Goal: connect generic `PlanStep` to the policy and capability system.

Security contract:

- `PolicyEvaluator` is authority, not Planner.
- Approval tokens bind actor, tool, resource, parameter hash, expiry, and policy version.
- Denied and paused paths do not prepare effects.

Worker implementation steps:

1. Normalize `PlanStep` to semantic tool request.
2. Route tool names and parameters through `ToolRouter`.
3. Reclassify risk through policy and ignore downgrade hints.
4. Issue capability leases only after allow or valid approval.
5. Emit policy diagnostics for audit projection.

Verification:

- `cargo test -p agentd security_execution::policy_adapter`
- Approval mutation invalidates token.
- Unknown tool or `shell.exec` does not reach executor.

Distribution evidence:

- Packaged policy pack and semantic tool manifest must keep this adapter enforceable.

### `TASK-SEF-003`: Lease-Derived Sandbox Profiles

Goal: make sandbox authority derive from capability leases.

Security contract:

- Planner/model sandbox hints are ignored or audited.
- Read-only lease cannot gain persistent write or unbounded network egress.
- Unsupported risk classes fail closed.

Worker implementation steps:

1. Compile namespace, cgroup, seccomp/no_new_privs, filesystem, Landlock placeholder, and network allowlist from `CapabilityLease`.
2. Produce stable profile summaries for audit.
3. Define profile classes for read-only, write-with-diff, execute-with-confirmation, privileged, never, and Firecracker.
4. Reject missing or unsupported lease fields.

Verification:

- `cargo test -p agentd security_execution::sandbox_profile`
- `cargo test -p agentd sandbox::`
- Resource-abuse safety fixtures.

Distribution evidence:

- `TASK-DALPHA-009` extends this into a Firecracker executor profile behind SEF.

### `TASK-SEF-004`: Untrusted Source-to-Sink Policy

Goal: prevent external or model-origin content from directly driving dangerous sinks.

Security contract:

- Source labels: operator, local-system, sandbox, external, model, sanitized, memory, audit-derived.
- Sink classes: read, write, execute, privileged, network, secret.
- Untrusted/model-origin sources cannot directly access execute, privileged, secret, or exfiltration-capable network sinks.

Worker implementation steps:

1. Define source and sink vocabulary.
2. Preserve labels through sanitization.
3. Deny dangerous source-to-sink paths without `EffectPrepared`.
4. Audit denied attempts with source and sink reason.

Verification:

- `cargo test -p agentd security_execution::source_to_sink`
- `cargo test -p agentd safety::prompt_injection`
- Webpage text cannot trigger command execution, secret read, package install, or outbound post.

Distribution evidence:

- `TASK-DALPHA-011` must add packaged untrusted-content workflow proof.

### `TASK-SEF-005`: Secret Handle Lease Rules

Goal: keep secrets as handles with short, narrow use windows.

Security contract:

- Raw secrets are forbidden in model context, memory, audit summary, CLI, TUI, and provenance.
- Secret-use leases are one-shot, scoped, expiring, and purpose-bound.
- Broad approvals such as "all secrets" are denied.

Worker implementation steps:

1. Define `SecretHandle` metadata without raw values.
2. Define `SecretUseLease` with actor, tool, resource, purpose, expiry, and consumption state.
3. Preserve `secret://handle` through redaction.
4. Reject raw secret-like serialized runtime surfaces.
5. Audit handle use without value leakage.

Verification:

- `cargo test -p agentd security_execution::secret_runtime`
- `cargo test -p agentd safety::secret`
- One-shot lease cannot be reused.

Distribution evidence:

- Config and provenance docs must remain handle-only and local-only by default.

### `TASK-SEF-006`: SecurityExecutionEngine Bridge

Goal: provide the only generic side-effect path.

Security contract:

- AgentCore cannot call executors directly.
- Engine owns prepare, execute, observe, verify, seal, rollback, and explain.
- Denied and paused paths return before `EffectPrepared`.

Worker implementation steps:

1. Define `SecurityExecutionEngine` trait.
2. Implement default engine over `ToolRouter`, `PolicyEvaluator`, `CapabilityLease`, `SandboxProfile`, `EffectEnvelope`, `AuditJournal`, and rollback handles.
3. Prepare write-with-diff rollback handles before execution.
4. Run read-only tools under sandbox profile.
5. Return structured errors that AgentCore maps to suspended, rollback-pending, denied, or failed-closed.

Verification:

- `cargo test -p agentd security_execution::engine`
- Direct execute-without-prepare is rejected.
- Denied or paused path prepares no effect.

Distribution evidence:

- `TASK-DALPHA-009`, `TASK-DALPHA-010`, and `TASK-DALPHA-011` must all be behind this engine.

### `TASK-SEF-007`: Agent Run Recovery Integration

Goal: recover interrupted runs from durable evidence, not model replay.

Security contract:

- Recovery joins `RunStore` and `AuditJournal`.
- Prepared write without seal cannot be marked completed.
- Inconsistent state becomes needs-human-review, rollback-pending, or failed-closed.

Worker implementation steps:

1. Scan recoverable run snapshots.
2. Scan audit for prepared, observed, sealed, rollback-pending, and unresolved effects.
3. Classify safe-to-verify, needs-rollback, needs-human-review, abandoned, completed, or failed-closed.
4. Restore AgentCore state accordingly.
5. Emit recovery projection with evidence source.

Verification:

- `cargo test -p agentd agent_core::recovery`
- `cargo test -p agentd recovery::`
- Crash simulations after prepare, observe, and verification failure.

Distribution evidence:

- Persistent `/var/lib/agentos/runs/`, `/var/log/agentos/audit/`, and `/var/lib/agentos/rollback/` must survive packaged runtime validation.

### `TASK-SEF-008`: Generic Agent Execution Safety Gate

Goal: make runtime abuse scenarios release-blocking.

Security contract:

- Safety gate covers generic Agent execution, not only isolated helper functions.
- Missing adversarial gate blocks release.
- Half-executed effect must classify to recovery, rollback-pending, or failed-closed.

Worker implementation steps:

1. Extend safety manifest with model output injection, observation injection, memory poisoning, approval mutation, source-to-sink abuse, secret misuse, and recovery abuse.
2. Require `safety::` and `agent_core::adversarial` in CI and release scripts.
3. Assert denied paths have no `EffectPrepared`.
4. Record scenario names and commands in release evidence.

Verification:

- `cargo test -p agentd safety::`
- `cargo test -p agentd agent_core::adversarial`
- `scripts/build-release.ps1` records both.

Distribution evidence:

- Distribution Alpha provenance must list safety and adversarial gates.

### `TASK-SEF-009`: Runtime Audit Projection

Goal: explain why every step ran, paused, denied, rolled back, failed closed, or sealed.

Security contract:

- Projection derives from audit timeline and run evidence.
- Projection never mutates raw audit storage.
- Prepared-but-unsealed effects cannot appear completed.

Worker implementation steps:

1. Build `RuntimeAuditProjection` from audit timeline.
2. Support latest-run and explicit run-id lookup.
3. Preserve global ordering while grouping by run and step.
4. Include plan hash, policy reason, approval binding, lease, sandbox profile, effect status, observation trust label, verification result, rollback/recovery status, and final summary.
5. Reuse redaction for all user-facing fields.

Verification:

- `cargo test -p agentd audit::`
- `cargo test -p agentd tui::`
- Service recovery projection shows full intent-to-seal chain.

Distribution evidence:

- Packaged smokes must output approved and denied audit projections.

### `TASK-SEF-010`: Final SEF Verification

Goal: prove the hardened substrate still holds when driven by generic AgentCore.

Security contract:

- No generic Agent path bypasses semantic tools, policy, capability, sandbox, audit, verification, rollback, or recovery.
- Denied high-risk actions have no `EffectPrepared`.
- Distribution Alpha is blocked until this passes.

Worker implementation steps:

1. Run full `agentd` regression.
2. Run `safety::`, `agent_core::`, `agent_core::adversarial`, and `agent_core::service_recovery`.
3. Run approved and denied service recovery smoke.
4. Run release/provenance generation.
5. Inspect generated artifacts and git status for artifact hygiene.
6. Write final evidence.

Verification:

- `cargo test -p agentd`
- `cargo test -p agentd safety::`
- `cargo test -p agentd agent_core::`
- `cargo test -p agentd agent_core::adversarial`
- `cargo test -p agentd agent_core::service_recovery`
- `pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1`

Distribution evidence:

- Runtime Foundation final audit is the entry gate for Distribution Alpha.

## Distribution Alpha Continuation TASKS

The following Alpha tasks are the next execution layer over the completed ACR/SEF foundation.

### `TASK-DALPHA-009`: Firecracker Executor Profile Behind SEF

Purpose: represent Firecracker as a high-risk executor/sandbox profile, not a side-effect shortcut.

Inputs:

- `SecurityExecutionEngine`
- `CapabilityLease`
- `SandboxProfile`
- policy decision and approval binding
- Firecracker dependency probe result
- guest image/profile metadata

Implementation steps:

1. Define Firecracker profile fields: kernel image, rootfs image, jailer path, network mode, block devices, CPU/memory limits, rate limits, snapshot policy, and audit summary.
2. Derive all fields from `CapabilityLease` and policy-controlled config, not Planner text.
3. Add dependency checks for KVM, Firecracker binary, jailer, guest image, kernel image, and host support.
4. Fail closed if any dependency is missing; never fall back to host execution for the same high-risk step.
5. Attach profile summary to `EffectEnvelope` and `RuntimeAuditProjection`.
6. Document Firecracker snapshot trust limits and host trust assumptions.

Acceptance:

- Firecracker is reachable only through `SecurityExecutionEngine`.
- Planner output cannot weaken profile constraints.
- Missing dependencies fail closed.
- Audit records profile selection and policy reason without secrets.

Verification:

- `cargo test -p agentd security_execution::`
- `cargo test -p agentd sandbox::`
- Alpha evidence records dependency behavior on hosts without Firecracker.

### `TASK-DALPHA-010`: Package Install Isolation Workflow

Purpose: prove package installation is staged and verified before host promotion.

Inputs:

- package request intent
- package manager adapter
- Firecracker or isolated executor profile
- host promotion approval
- rollback/checkpoint strategy

Implementation steps:

1. Encode package install as a generic `PlanSpec` with isolate-test, smoke-test, host-checkpoint, approval, host-install, verify, and rollback branches.
2. Run untrusted package install first in isolated executor profile.
3. Record package metadata, source, digest, dependency summary, and test results.
4. Require exact approval before host promotion.
5. Prepare host rollback/checkpoint before host install.
6. Fail closed if package source, signature, test, approval, or rollback handle is missing.

Acceptance:

- Package install cannot land on host from model/external content alone.
- Failed isolated install does not modify host.
- Host promotion requires exact approval and rollback metadata.
- Audit projection explains each boundary crossing.

Verification:

- `cargo test -p agentd agent_core::`
- `cargo test -p agentd safety::`
- Packaged workflow smoke for approved and denied package promotion.

### `TASK-DALPHA-011`: Untrusted Content Runtime Workflow

Purpose: prove external content can inform summaries without directly driving high-risk sinks.

Inputs:

- untrusted URL/file/API content
- content fetch adapter
- sanitizer
- source-to-sink policy
- read-only summary output

Implementation steps:

1. Encode fetch, sanitize, summarize, policy-check, and audit projection as generic `PlanSpec`.
2. Label fetched content as external/untrusted.
3. Strip or flag active instructions, credential requests, exfiltration hints, and command suggestions.
4. Allow sanitized summary to reach Planner as context only.
5. Deny direct execute, privileged, secret, package install, or network exfiltration sinks from untrusted/model-origin content.
6. Record denied attempts without `EffectPrepared`.

Acceptance:

- Webpage/document text cannot directly trigger shell, package install, secret read, privileged action, or outbound post.
- Sanitized content keeps source reference and lower authority.
- Runtime audit projection shows source-to-sink denial reason.

Verification:

- `cargo test -p agentd security_execution::source_to_sink`
- `cargo test -p agentd safety::prompt_injection`
- Packaged workflow smoke for malicious content fixture.

### `TASK-DALPHA-012`: Distribution Alpha Final Audit

Purpose: decide whether the image path is promotable or explicitly blocked.

Inputs:

- rootfs runtime manifest
- packaged service recovery smoke
- QEMU runtime smoke
- release provenance
- Firecracker/profile evidence
- package install workflow evidence
- untrusted content workflow evidence

Implementation steps:

1. Parse all workflow JSON and task evidence.
2. Re-run inherited gates: full runtime, safety, AgentCore, adversarial, release, QEMU.
3. Verify Alpha rootfs artifacts and state directories.
4. Verify denied paths have no `EffectPrepared`.
5. Verify generated artifacts remain untracked.
6. Write promotion decision with blockers if any.

Acceptance:

- Every planned Alpha gate has direct evidence.
- Promotion cannot proceed with missing runtime, safety, release, QEMU, or isolation evidence.
- Final decision names exact commit, artifact hashes, and blocking risks.

Verification:

- `cargo test -p agentd`
- `cargo test -p agentd safety::`
- `cargo test -p agentd agent_core::`
- `cargo test -p agentd agent_core::adversarial`
- `pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1 -QemuPath E:\qemu\qemu-system-x86_64.exe -QemuTimeoutSeconds 30`

## Current Execution Pointer

Current next implementation task remains `TASK-DALPHA-009`.

Do not start it by adding a Firecracker helper that directly executes commands. Start by extending the SEF profile contract and dependency-check behavior, then wire it through the existing `SecurityExecutionEngine` path.
