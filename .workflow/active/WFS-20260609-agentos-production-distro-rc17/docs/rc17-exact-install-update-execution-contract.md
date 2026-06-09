# RC17 Exact Install/Update Execution Authority Contract

RC17 starts from RC16's non-GA distributable packaging readiness. RC16 proved the package surface, installable media manifest, descriptor fail-closed fixtures, installer/updater preflight, AgentCore and SecurityExecution install/update package binding, rollback/support package, TUI projection, and local consumer smoke. It still denied install/update because exact target, exact approval, executable AgentCore install/update PlanSpec, and SecurityExecution allow were not bound.

RC17 turns those missing gates into explicit AIOS-body evidence. It does not grant GA status, production ring authority, mirror authority, signer authority, remote dispatch authority, support upload authority, recovery execution authority, host active slot mutation, or host boot metadata mutation.

## Gate Order

1. RC16 final audit and release package evidence must be present and passed.
2. Exact repo-local install and update targets must be bound to target identities, package identity, installable media, and installer/updater preflight evidence.
3. Exact operator approval must bind actor, release object, target package, operation type, AgentCore package reference, SecurityExecution envelope reference, audit sink, nonce, expiry, policy version, rollback baseline, and support/recovery references.
4. AgentCore install/update PlanSpecs may become executable only after exact target, exact approval, audit, nonce, expiry, policy, rollback, and support references are bound.
5. SecurityExecution may allow only the exact repo-local install/update effect envelope produced from the executable PlanSpec and exact approval.
6. Rollback preconditions and post-effect observation requirements must be bound before any controlled local install/update effect is prepared.
7. Controlled local install must execute against the exact repo-local target or deny before effect with audit.
8. Controlled local update must execute against the exact repo-local target or deny before effect with audit.
9. Rollback/support evidence must bind the install/update outcome and remain local-only unless a later milestone explicitly authorizes support upload or recovery execution.
10. Local release channel consumer smoke must explain exact install/update readiness or denial from RC17 evidence.
11. Final closeout must report install/update readiness truthfully and keep production_ready_claim=false.

## Non-Authority Sources

The following are never authority for RC17 execution:

- mirror reachability
- frontend output
- signer reachability
- shell output
- TUI projection
- model replay
- object storage UI
- remote service reachability
- endpoint reachability without local evidence binding

## Effect Boundary

RC17 may only prepare or execute controlled local install/update effects when every gate above is bound. Any allowed effect is constrained to a repo-local exact target and must produce audit evidence. RC17 must not mutate host active slot metadata, host boot metadata, production rings, remote fleet state, support upload endpoints, recovery execution services, or private signing material.

## Fail-Closed Rule

Every gate must deny before effect on missing, broad, stale, mismatched, replayed, unsigned, expired, unapproved, remote, support-upload, recovery, host-boot, host-slot, or production-ring authority. Denial must be explicit, audited, and usable by the next task as evidence.
