# Security Execution Foundation

Source: `research.md`
Workflow: `WFS-20260522-agentos-runtime-foundation`

## Purpose

The Security Execution Foundation is the deterministic safety substrate below
Agent Core Runtime. It constrains every effect, records every decision, verifies
outcomes, and provides rollback/recovery semantics.

The completed MVP already includes the first version of this substrate:

- Semantic tool routing.
- Policy evaluator and capability leases.
- Approval token binding.
- Append-only audit journal.
- Read-only sandbox profile compiler.
- Write-with-diff rollback flow.
- Recovery reconciler.
- Safety regression gate.

This workflow hardens those pieces so they become reusable infrastructure for
all generic Agent plans.

## Non-Negotiable Invariants

- Normal mode has no arbitrary root shell.
- Model output cannot directly execute tools.
- Every side-effecting step must write `EffectPrepared` before execution.
- Every observed side effect must reach `CommitSealed` or `RollbackPending`.
- Approval tokens bind actor, tool, resource, parameter hash, expiry, and
  policy version.
- Read-only tools must run with constrained execution profiles.
- Secret values never enter model context, memory, normal logs, or summaries.
- External content is untrusted until sanitized and classified.

## Effect Envelope

Every executor must return an effect envelope:

```text
EffectEnvelope {
  run_id,
  step_id,
  tool,
  normalized_params,
  policy_decision,
  lease,
  sandbox_profile,
  prepared_event,
  observed_event,
  verification_result,
  rollback_handle?,
  commit_id?
}
```

Agent Core can inspect this envelope, but only the Security Execution
Foundation can produce, verify, seal, or roll it back.

## Runtime Integration

Agent Core sends only structured `PlanStep` and `SemanticToolCall` requests.
The Security Execution Foundation decides whether the request is denied,
allowed, paused for approval, sandboxed, or prepared for diff/rollback.

## Acceptance Gate

The final gate must prove that generic Agent execution still fails closed under:

- Prompt injection.
- Observation injection.
- Tool abuse.
- Approval parameter mutation.
- Secret exfiltration attempts.
- Resource abuse.
- Half-committed effects.
- Crash/restart during a run.

## Detailed TASK Map

The detailed Maestro implementation blueprint is maintained in
`docs/runtime-implementation-tasks.md`. Security Execution Foundation is
decomposed into the following executable chain:

| Task | Security responsibility | Must prove |
|---|---|---|
| `TASK-SEF-001` | Generic `EffectEnvelope` transaction contract. | `EffectPrepared` precedes observed effects; successful verification is required before `CommitSealed`. |
| `TASK-SEF-002` | Agent step policy and capability adapter. | Denied and paused decisions prepare no effect; planner risk hints cannot lower policy risk. |
| `TASK-SEF-003` | Lease-derived sandbox profile compiler. | Sandbox profile authority comes from `CapabilityLease`, not model or planner hints. |
| `TASK-SEF-004` | Untrusted content source-to-sink policy. | External/model-origin content cannot directly drive execute, privileged, secret, or exfiltration-capable sinks. |
| `TASK-SEF-005` | Secret handle lease runtime. | Secrets remain handle-only across model context, memory, audit summaries, and logs. |
| `TASK-SEF-006` | Generic `SecurityExecutionEngine` bridge. | AgentCore has one side-effect path: prepare, execute, observe, verify, seal, or rollback through SEF. |
| `TASK-SEF-007` | Agent run recovery integration. | Recovery reconciles `RunStore` and `AuditJournal` without model replay. |
| `TASK-SEF-008` | Generic Agent execution safety gate. | Runtime abuse tests are part of CI and release gates. |
| `TASK-SEF-009` | Runtime audit projection and explainability chain. | Operators can explain why each step ran, paused, denied, rolled back, or sealed. |
| `TASK-SEF-010` | Final SEF verification. | Distribution work stays blocked until generic runtime paths pass safety, adversarial, recovery, and release checks. |

The safety base is therefore not a collection of optional guards around an
agent. It is the execution substrate. If SEF cannot prepare, observe, verify,
and account for an effect, AgentCore must treat that effect as not executable.
