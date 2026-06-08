# RC15 Controlled Local Execution Readiness Contract

RC15 turns RC14 local trust readiness into controlled local execution readiness. The contract is local-first and AIOS-body-only: mirrors, signer reachability, frontend output, shell output, TUI projection, model replay, remote services, and object storage UI are never authority.

## Source Of Authority

RC15 inherits only these RC14 authorities:

1. Local declared/current drift-zero.
2. Current freshness window and revocation snapshot.
3. Verified local object trust.
4. Repo-local quarantine preflight before payload interpretation.
5. AgentCore PlanSpec candidate.
6. SecurityExecution effect envelope candidate.
7. Rollback baseline and support/recovery references.

All inherited evidence must be hash-bound into the RC15 task result that consumes it. Endpoint reachability, remote service health, and UI render state are not trust inputs.

## Gate Order

Controlled local execution is allowed only in this order:

1. Bind local audit sink.
2. Bind nonce, approval expiry, and policy version.
3. Enroll two distinct real local canary target identities.
4. Bind exact approval to actor authority, target set, release object, AgentCore PlanSpec, SecurityExecution envelope, audit sink, nonce, expiry, policy version, rollback baseline, and support/recovery references.
5. Mark AgentCore PlanSpec executable only after the exact approval and target identity set are bound.
6. Obtain SecurityExecution allow for the exact controlled local activation effect envelope.
7. Execute or deny controlled local activation with durable audit evidence.
8. Require a separate rollback approval, rollback PlanSpec, rollback SecurityExecution allow, audit journal, and support/recovery binding before rollback execution.
9. Close with final audit.

No later gate may be fabricated from a previous gate. Approval does not imply execution. AgentCore executable state does not imply SecurityExecution allow. SecurityExecution allow does not imply rollback authority.

## Required Fail-Closed Cases

Each RC15 execution task must deny at least these broadening attempts:

- Missing, stale, mismatched, broad, duplicate, or replayed target identity.
- Missing, stale, replayed, or mismatched nonce.
- Missing, expired, or broad approval.
- Missing or mismatched actor authority.
- Missing or mismatched audit sink.
- Missing or mismatched policy version.
- Release object, PlanSpec, SecurityExecution envelope, rollback baseline, or support/recovery mismatch.
- Shell bypass, policy weakening, model replay authority, TUI authority, remote dispatch authority, production mutation authority, or support upload authority.

## Activation Contract

Controlled local activation may execute only when all of these are true:

- RC14 local object trust is still bound.
- RC14 verified quarantine evidence is still bound.
- Two real local canary target identities are bound.
- Exact approval is granted and unexpired.
- Audit sink, nonce, expiry, and policy version are bound.
- AgentCore PlanSpec is executable.
- SecurityExecution allows the exact activation effect envelope.
- The task records either activation execution evidence or exact denial evidence.

If any condition is false, activation must be denied and no effect may be prepared or executed.

## Rollback Contract

Rollback execution is separate from activation. It requires:

- Controlled activation execution evidence, or an explicit safe denial path when activation did not execute.
- Separate exact rollback approval.
- Rollback target identities.
- AgentCore rollback PlanSpec.
- SecurityExecution rollback allow decision.
- Rollback audit journal.
- Post-rollback observations.
- Redacted local support/recovery binding.

Support upload, recovery execution, remote fleet execution, and production ring mutation remain disabled unless a later milestone creates explicit authority.

## Non-Goals

RC15 does not:

- Claim GA production readiness.
- Provision mirror frontend, Nginx, TLS, remote signer, object storage, or remote dispatch infrastructure.
- Read, move, print, hash, or handle private signing material.
- Upload payload bytes or support bundles.
- Mutate active slots, boot metadata, active artifact sets, or production rings.
- Treat endpoint reachability, frontend output, signer reachability, shell output, TUI output, or model replay as authority.
