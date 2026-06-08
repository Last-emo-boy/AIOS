# Production Distro RC12 Planning Summary

RC12 starts from the RC11 final audit. RC11 closed with PASS but remained non-GA and fail-closed because object trust, declared/current drift-zero, freshness, quarantine fetch, exact approval, AgentCore executable PlanSpec, SecurityExecution allow, controlled activation, rollback approval, rollback execution, audit journal, post-rollback observations, and remote fleet execution are still missing.

RC12 is scoped to AIOS body work. It may consume externally published immutable HTTPS object metadata as an input, but it must not build mirror frontend, Nginx/TLS infrastructure, remote signer service work, object storage provisioning, signing ceremonies, remote dispatch infrastructure, or production ring mutation.

## Execution Shape

1. Freeze the RC12 real object publication, drift-zero, and controlled execution contract.
2. Bind or deny immutable external object publication evidence for current payload bytes.
3. Reconcile declared/current artifact identity to zero or emit precise repair blockers.
4. Verify descriptor freshness, revocation, and object trust before installer authority.
5. Run installer quarantine fetch verification before payload interpretation.
6. Bind verified quarantine preflight to executable AgentCore and SecurityExecution package.
7. Enroll two canary targets and bind exact approval with audit sink, nonce, and expiry.
8. Execute or deny controlled canary activation through AgentCore and SecurityExecution.
9. Execute or deny separately approved rollback drill with support/recovery evidence.
10. Close with RC12 final audit and keep `production_ready_claim=false` unless every gate is proved.

## Authority Boundary

External object reachability is not trust. AIOS trust comes from local verification of descriptor, byte length, digest, manifest, checksum set, public signature, revocation, freshness, compatibility, rollback baseline, support/recovery binding, exact approval, AgentCore executable PlanSpec, SecurityExecutionEngine allow decision, and audit evidence.

Mirror, frontend, signer reachability, shell output, TUI output, model replay, object storage UI, and remote service reachability remain non-authoritative.