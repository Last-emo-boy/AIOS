# Production Distro RC17 Planning Summary

RC17 starts from the RC16 final audit. RC16 closed with PASS as non-GA AIOS-body distributable packaging and release-operation readiness: release package surface, installable media manifest, package descriptor fail-closed fixtures, installer/updater preflight, AgentCore/SecurityExecution install/update binding, rollback/support package, TUI projection, and local consumer smoke were proved.

RC16 did not authorize install or update. The local consumer denied before effect because exact install/update target, exact approval, executable AgentCore install/update PlanSpec, and SecurityExecution install/update allow were not bound.

RC17 is scoped to AIOS body work. It must bind those exact install/update gates before any controlled local install/update effect can execute or deny with audit evidence.

## Execution Shape

1. Freeze the RC17 exact install/update execution authority contract.
2. Bind exact repo-local install and update target identities from RC16 package evidence.
3. Bind exact operator approval to target package, actor, audit sink, nonce, expiry, policy version, rollback baseline, and support/recovery references.
4. Make AgentCore install/update PlanSpecs executable from RC16 package/preflight evidence plus exact target and approval bindings.
5. Bind SecurityExecution install/update allow decisions to the exact effect envelope.
6. Bind rollback preconditions and post install/update observation package before effects.
7. Run controlled local install execute-or-deny evidence.
8. Run controlled local update execute-or-deny evidence.
9. Run controlled rollback/support evidence after install/update outcomes.
10. Run local release channel consumer smoke over exact install/update gates.
11. Close with RC17 final audit and keep production_ready_claim=false.

## Authority Boundary

RC17 remains non-GA and AIOS-body-only. Mirror output, frontend output, signer reachability, shell output, TUI projection, model replay, remote service reachability, and object storage UI remain non-authoritative.

RC17 must not handle private signing material, provision remote services, mutate production rings, mutate the host active slot, mutate host boot metadata, enable remote dispatch, upload support bundles, execute recovery services, or treat endpoint reachability as trust.
