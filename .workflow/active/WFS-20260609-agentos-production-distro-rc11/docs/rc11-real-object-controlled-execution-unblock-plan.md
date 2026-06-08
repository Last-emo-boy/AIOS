# Production Distro RC11 Planning Summary

RC11 starts from the RC10 final audit. RC10 closed with PASS but remained non-GA and fail-closed because the real immutable external HTTPS object URI, drift-zero reconciliation, installer quarantine fetch verification, two enrolled canary targets, exact approval, AgentCore PlanSpec binding, SecurityExecutionEngine approval, controlled activation, rollback approval, rollback execution authorization, and remote fleet execution were still missing.

RC11 is scoped to AIOS body work. It does not include mirror frontend redesign, Nginx/TLS changes, remote signer service work, signing ceremonies, remote dispatch, or production ring mutation.

## Execution Shape

1. Freeze the RC11 trust handoff contract.
2. Build a current release byte map and immutable descriptor candidate.
3. Reconcile declared/current artifact drift to zero or emit precise blockers.
4. Verify any external HTTPS object descriptor against current bytes without granting install authority.
5. Add installer quarantine fetch verification and fail-closed cases.
6. Bind installer preflight evidence to AgentCore and SecurityExecutionEngine.
7. Build two-target canary enrollment and exact approval evidence.
8. Execute or deny controlled canary activation.
9. Execute or deny rollback with separate approval and support/recovery binding.
10. Close with RC11 final audit and keep `production_ready_claim=false` unless all gates are proved.

## Authority Boundary

External object reachability is not trust. AIOS trust comes from local verification of descriptor, byte length, digest, manifest, checksum set, public signature, revocation, freshness, compatibility, rollback baseline, support/recovery binding, exact approval, AgentCore PlanSpec, SecurityExecutionEngine effect envelope, and audit evidence.

Mirror, frontend, signer reachability, shell output, TUI output, and model replay remain non-authoritative.
