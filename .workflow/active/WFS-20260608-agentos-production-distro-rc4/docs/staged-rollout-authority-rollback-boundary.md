# Staged Rollout Authority And Rollback Boundary

## Scope

RC4 staged rollout turns a signed hosted release into a fleet-ring plan. A rollout plan is not activation by itself. It is an inert, hash-bound proposal until AgentCore builds a PlanSpec, SecurityExecutionEngine validates policy and rollback evidence, and an exact operator approval binds the release, ring, target set, parameters, policy version, and expiry.

The boundary covers:

- Ring definitions and staged promotion order.
- Exact approval binding for rollout and rollback.
- Rollback baseline and revocation checks.
- Failure handling for stale, partial, or mismatched fleet evidence.

## Authority Model

The only rollout mutation authority is:

```text
AgentCore fleet_rollout PlanSpec + SecurityExecutionEngine
```

The following surfaces are non-authoritative:

- TUI panels and command palette.
- Model summaries and planner hints.
- Hosted transport metadata.
- Remote registry mirror metadata.
- Normal shell or ad hoc script dispatch.
- Remote control-plane push commands.

TUI may show rollout rings, blockers, expected blast radius, rollback baseline, and approval diff. It may request intent submission, but it must not directly mutate active slots, fleet ring state, production channel heads, or rollback state.

## Rollout Plan Binding

A valid rollout plan must bind:

- RC3 final audit hash.
- Hosted transport manifest hash.
- Publication manifest and channel index hashes.
- Production verification hash.
- Signing/publication gate hash.
- Fleet ring id and target set hash.
- Rollout policy version.
- Rollback baseline hash.
- Revocation/advisory snapshot hash.
- Exact operator approval hash.

Any drift after approval invalidates the plan and requires a new approval.

## Rollback Boundary

Rollback is a first-class PlanSpec, not a side effect hidden inside rollout.

Rollback evidence must include:

- Previous active artifact set hash.
- Previous channel head or ring assignment hash.
- Target ring state before rollout.
- Recovery command plan.
- Support bundle redaction proof.
- Operator approval or emergency policy reason.

Rollback may be projected in TUI, but execution remains SecurityExecutionEngine-owned.

## Fail-Closed Cases

RC4 rollout tasks must fail closed when:

- The rollout plan is missing hosted transport binding.
- Fleet target set hash changes after approval.
- Rollout policy version changes after approval.
- Rollback baseline is missing or mismatched.
- Revocation/advisory state is stale.
- A model or TUI attempts direct rollout authority.
- Remote control-plane dispatch attempts active mutation.
- Support bundle is unredacted.
- Ring promotion skips required canary or hold gates.

## Handoff

Implementation tasks may now write rollout precondition audits and local fixture plans, but they must not execute rollout mutation until the exact approval, rollback, revocation, and SecurityExecutionEngine checks are present.
