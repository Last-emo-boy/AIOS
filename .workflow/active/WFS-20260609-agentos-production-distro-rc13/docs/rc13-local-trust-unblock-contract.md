# RC13 Local Trust Unblock Contract

## Scope

RC13-001 freezes the AIOS-body contract for converting RC12 fail-closed blockers into satisfiable local trust and controlled execution gates. External transport may provide immutable HTTPS metadata as an input, but authority remains local to AIOS artifact identity verification, freshness and revocation checks, quarantine preflight, AgentCore, SecurityExecutionEngine, audit, rollback, and support/recovery evidence.

This task does not configure mirror frontend, Nginx, TLS, remote signer infrastructure, object storage infrastructure, signing ceremonies, remote dispatch infrastructure, install, activation, rollback, support upload, active slot mutation, boot metadata mutation, active artifact set mutation, production ring mutation, or a GA production-ready claim.

## Gate Order

RC13 must evaluate gates in this order:

1. Freeze the current release artifact identity set: release id, payload object ids, descriptor candidates, manifest candidates, checksum set, public signature targets, revocation snapshot, freshness window, compatibility metadata, rollback baseline, and support/recovery references.
2. Reconcile declared metadata and current artifact evidence to `drift_count=0`; if any drift remains, object trust and downstream execution remain denied.
3. Bind current payload bytes into an immutable object manifest and descriptor set with size, SHA-256, canonical descriptor digest, manifest digest, checksum set digest, and compatibility references.
4. Bind public signature target, public keyring reference, revocation status, and freshness window without reading, copying, hashing, printing, or using private signing material.
5. Allow object trust only after drift-zero, descriptor/manifest consistency, public signature target, revocation, freshness, compatibility, rollback, and support/recovery gates are all proved.
6. Run quarantine preflight only after object trust is allowed; bytes may be written only to quarantine and must not be interpreted until verification succeeds.
7. Bind verified quarantine/preflight evidence into an AgentCore executable PlanSpec candidate with exact release, object, target, approval, rollback, support/recovery, and audit references.
8. Bind the same PlanSpec, object digest, target set, rollback baseline, support/recovery references, audit sink, nonce, expiry, and policy version into a SecurityExecutionEngine effect envelope.
9. Require at least two enrolled non-duplicate local canary target identities before activation authority; remote dispatch remains disabled.
10. Require exact operator approval bound to actor, release, object, target set, AgentCore PlanSpec, SecurityExecution envelope, audit sink, nonce, expiry, rollback baseline, and support/recovery evidence.
11. Execute controlled activation only if every prior gate is proved and the activation task records the exact effect or denial.
12. Execute rollback only after controlled activation evidence plus a separate exact rollback approval, rollback PlanSpec, SecurityExecution rollback allow decision, audit journal, rollback baseline, support/recovery evidence, and post-rollback observation plan are proved.

Any missing, stale, broad, mismatched, replayed, local-private-material, or authority-broadening input denies downstream authority.

## Authority Boundary

The following are authoritative only after local AIOS verification records them as evidence:

- release byte length and SHA-256;
- declared/current drift-zero reconciliation;
- descriptor canonical digest;
- manifest and checksum set digests;
- public signature target and receipt;
- public keyring reference;
- revocation snapshot and freshness window;
- compatibility metadata and rollback baseline;
- support/recovery binding;
- quarantine verification result;
- AgentCore executable PlanSpec hash;
- SecurityExecutionEngine allow decision and effect envelope;
- exact approval with audit sink, nonce, and expiry;
- canary target identity enrollment evidence;
- AuditJournal and RunStore evidence;
- post-activation and post-rollback observations.

The following are never authority by themselves:

- mirror reachability;
- signer reachability;
- frontend output;
- object storage UI;
- HTTP status alone;
- DNS resolution;
- shell output;
- TUI output;
- model replay;
- support endpoint reachability;
- human-readable runbook text without bound machine evidence.

## Controlled Unblock Rules

`declared_current_drift_zero` may become true only when every declared/current comparison is explicit, hash-bound, and matched.

`object_manifest_descriptor_consistent` may become true only when current payload bytes, descriptor, manifest, checksum set, compatibility metadata, rollback baseline, and support/recovery references all agree.

`freshness_revocation_authority_bound` may become true only when public signature target, public keyring reference, freshness window, and revocation snapshot are bound without private signing material.

`object_trust_allowed` may become true only when drift-zero, descriptor/manifest consistency, public signature target, revocation, freshness, compatibility, rollback, and support/recovery gates all pass.

`quarantine_preflight_allowed` may become true only after object trust is allowed. Bytes may be written only to quarantine and must not be interpreted until verification succeeds.

`agentcore_planspec_executable` may become true only when verified quarantine/preflight evidence is hash-bound into a PlanSpec with exact release, object, target, approval, rollback, support/recovery, and audit references.

`security_execution_allowed` may become true only when the effect envelope exactly matches the PlanSpec, approval package, target set, rollback baseline, support/recovery references, audit sink, nonce, expiry, and policy version.

`activation_allowed` may become true only when object trust, quarantine verification, two-target enrollment, exact approval, AgentCore executable PlanSpec, SecurityExecution allow decision, audit, rollback, and support/recovery gates are all true.

`rollback_execution_allowed` may become true only after controlled activation evidence exists and a separate rollback approval, rollback PlanSpec, SecurityExecution rollback allow decision, audit journal, post-rollback observation plan, rollback baseline, and support/recovery binding are all true.

## Fail-Closed Cases

RC13 must fail closed for:

- nonzero declared/current drift;
- missing, broad, stale, or mismatched declared artifact identity;
- object size mismatch;
- object SHA-256 mismatch;
- descriptor canonical digest mismatch;
- manifest or checksum mismatch;
- public signature target, receipt, or keyring mismatch;
- local private signing material used as production authority;
- missing, stale, revoked, or mismatched revocation evidence;
- missing or stale freshness window;
- missing or mismatched compatibility metadata;
- missing or mismatched rollback baseline;
- missing or mismatched support/recovery binding;
- endpoint reachability used as trust;
- quarantine fetch before object trust;
- bytes interpreted before quarantine verification;
- AgentCore PlanSpec missing, stale, broad, non-executable, or mismatched;
- SecurityExecutionEngine decision missing, denied, stale, broad, or mismatched;
- fewer than two enrolled canary targets;
- duplicate, stale, incompatible, or unbound canary target records;
- exact approval missing, stale, broad, replayed, missing audit sink, missing nonce, missing expiry, or mismatched to release/object/target/PlanSpec/effect envelope;
- controlled activation attempted before every activation gate is true;
- rollback attempted without controlled activation evidence;
- rollback attempted without separate rollback approval;
- rollback PlanSpec missing or mismatched;
- rollback audit journal or post-rollback observation plan missing;
- support upload authority broadening;
- remote dispatch authority broadening;
- production ring mutation authority broadening;
- mirror, signer, frontend, shell, TUI, model, object storage, or support endpoint authority broadening.

## Side-Effect Boundary

RC13 planning and verification tasks may write local evidence artifacts. They must not upload payload bytes, provision object storage, sign artifacts, install, activate, rollback, upload support bundles, recover systems, dispatch remote actions, mutate active slots, mutate boot metadata, mutate active artifact sets, or mutate production rings unless a later execution task proves every required gate and records the effect explicitly.

## Next Task Handoff

`RC13-010` must consume this contract and repair or precisely deny declared/current artifact drift-zero for the current payload bytes. It may compare and hash-bind local metadata and current artifacts, but it must not rewrite production metadata, provision object storage, upload payloads, sign, install, activate, rollback, dispatch remote actions, or mutate production state.
