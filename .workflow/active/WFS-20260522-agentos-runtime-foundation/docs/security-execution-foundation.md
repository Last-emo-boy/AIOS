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
