# Production Distro RC13 Planning Summary

RC13 starts from the RC12 final audit. RC12 closed with PASS but remained non-GA and fail-closed because external object publication, declared/current drift-zero, object trust, quarantine fetch, AgentCore executable PlanSpec, SecurityExecution allow, two-target enrollment, exact approval, activation, rollback, support upload, recovery, remote dispatch, and production mutation all remained disabled.

RC13 is scoped to AIOS body work. It may consume externally published immutable HTTPS object metadata as an input, but it must not build mirror frontend, Nginx/TLS infrastructure, remote signer service work, object storage provisioning, signing ceremonies, remote dispatch infrastructure, or production ring mutation.

## Execution Shape

1. Freeze the RC13 local trust unblock and artifact repair contract.
2. Repair or precisely deny declared/current artifact drift-zero for current payload bytes.
3. Bind current payload bytes into an immutable object manifest and descriptor set.
4. Bind freshness, revocation, and public signature authority without private material.
5. Run verified quarantine preflight before payload interpretation.
6. Bind quarantine preflight to AgentCore executable PlanSpec readiness.
7. Bind SecurityExecution allow preconditions for controlled effects.
8. Enroll two local canary identities and bind exact approval with audit sink, nonce, and expiry.
9. Execute or deny controlled activation through AgentCore and SecurityExecution gates.
10. Execute or deny separate rollback PlanSpec and approval drill with support/recovery evidence.
11. Close with RC13 final audit and keep `production_ready_claim=false` unless every gate is proved.

## Authority Boundary

External object reachability is not trust. AIOS trust comes from local verification of descriptor, byte length, digest, manifest, checksum set, public signature, revocation, freshness, compatibility, rollback baseline, support/recovery binding, exact approval, AgentCore executable PlanSpec, SecurityExecutionEngine allow decision, and audit evidence.

Mirror, frontend, signer reachability, shell output, TUI output, model replay, object storage UI, and remote service reachability remain non-authoritative.
