# Production Distro RC16 Planning Summary

RC16 starts from the RC15 final audit. RC15 closed with PASS and proved controlled local execution readiness: audit/nonce/policy binding, two real local target identities, exact approval, executable AgentCore PlanSpec, SecurityExecution allow, controlled local activation, separate rollback execution, and local support/recovery evidence.

RC16 is scoped to AIOS body work. It must turn that controlled execution readiness into a user-facing distributable release package path: repo-local release package artifact set, installable media manifest, descriptor fail-closed fixtures, installer/update preflight, AgentCore and SecurityExecution install/update PlanSpec binding, rollback/support package binding, operator explainability, local release channel consumer smoke, and final audit.

## Execution Shape

1. Freeze the RC16 distributable package and release-operation authority contract.
2. Project the repo-local release package artifact set from current AIOS build, manifest, checksum, signature, revocation, rollback, support, and RC15 execution evidence.
3. Assemble an installable media manifest that identifies current AIOS release bytes without installing, activating, uploading, or publishing them.
4. Verify distributable package descriptor fail-closed cases for stale, broad, mismatched, unsigned, revoked, missing, or authority-broadening metadata.
5. Bind installer and updater preflight evidence to the repo-local package without trusting mirror reachability or frontend output.
6. Bind AgentCore and SecurityExecution install/update PlanSpec packages while keeping side effects disabled unless gates are explicitly met.
7. Bind rollback baseline and support/recovery package evidence while support upload and recovery execution remain disabled.
8. Project installability/update readiness into the TUI/operator surface as explanation only, not authority.
9. Run local release channel consumer smoke that must execute or deny with audit evidence and no production mutation.
10. Close with RC16 final audit and keep production_ready_claim=false unless every scoped gate is proved.

## Authority Boundary

RC16 remains non-GA and AIOS-body-only. Mirror output, frontend output, signer reachability, shell output, TUI projection, model replay, remote service reachability, and object storage UI remain non-authoritative.

RC16 must not handle private signing material, provision remote services, mutate production rings, enable remote dispatch, upload support bundles, execute recovery services, or treat endpoint reachability as trust.
