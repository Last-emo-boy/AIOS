# RC12 Real Object Controlled Unblock Contract

## Scope

RC12-001 freezes the AIOS-body contract for moving from RC11 fail-closed evidence toward controlled unblock evidence. External object transport may provide candidate release bytes and metadata, but authority remains local to AIOS verification, AgentCore, SecurityExecutionEngine, audit, rollback, and support/recovery evidence.

This task does not configure mirror frontend, Nginx, TLS, remote signer infrastructure, object storage infrastructure, signing ceremonies, remote dispatch infrastructure, install, activation, rollback, support upload, active slot mutation, boot metadata mutation, active artifact set mutation, production ring mutation, or a GA production-ready claim.

## Gate Order

RC12 must evaluate gates in this order:

1. Classify the external object URI as immutable, HTTPS, credential-free, size-bound, digest-bound, and policy-bound.
2. Bind the URI to current release byte evidence, descriptor digest, manifest digest, checksum set digest, public signature target, revocation snapshot, freshness window, compatibility metadata, rollback baseline, and support/recovery references.
3. Reconcile declared metadata and current artifact evidence to `drift_count=0`.
4. Verify descriptor freshness, revocation status, compatibility, rollback baseline, and support/recovery binding before object trust.
5. Fetch bytes only into quarantine after object trust is allowed.
6. Verify quarantined bytes for size, SHA-256, manifest, checksum set, public signature, revocation, freshness, compatibility, rollback, and support/recovery before interpretation.
7. Bind verified quarantine/preflight evidence into an AgentCore executable PlanSpec candidate.
8. Bind the same PlanSpec, object digest, target set, rollback baseline, support/recovery references, audit sink, nonce, expiry, and policy version into a SecurityExecutionEngine effect envelope.
9. Require at least two enrolled non-duplicate canary targets before activation authority.
10. Require exact operator approval bound to actor, release, object, target set, AgentCore PlanSpec, SecurityExecution envelope, audit sink, nonce, expiry, rollback baseline, and support/recovery evidence.
11. Execute controlled canary activation only if every prior gate is proved.
12. Execute rollback only after controlled activation evidence plus a separate exact rollback approval, rollback PlanSpec, SecurityExecution rollback allow decision, audit journal, rollback baseline, support/recovery evidence, and post-rollback observation plan are proved.

Any missing, stale, broad, mismatched, replayed, or authority-broadening input denies downstream authority.

## Authority Boundary

The following are authoritative only after local AIOS verification records them as evidence:

- release byte length and SHA-256;
- descriptor canonical digest;
- manifest and checksum set digests;
- public signature target and receipt;
- revocation snapshot and freshness window;
- compatibility and rollback baseline;
- support/recovery binding;
- declared/current drift-zero reconciliation;
- quarantine verification result;
- AgentCore executable PlanSpec hash;
- SecurityExecutionEngine allow decision and effect envelope;
- exact approval with audit sink, nonce, and expiry;
- canary target enrollment evidence;
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

`object_trust_allowed` may become true only when URI classification, byte identity, descriptor digest, drift-zero, freshness, revocation, compatibility, rollback, and support/recovery gates all pass.

`quarantine_fetch_allowed` may become true only after object trust is allowed. Bytes may be written only to quarantine and must not be interpreted until verification succeeds.

`agentcore_planspec_executable` may become true only when verified quarantine/preflight evidence is hash-bound into a PlanSpec with exact release, object, target, rollback, support/recovery, and audit references.

`security_execution_allowed` may become true only when the effect envelope exactly matches the PlanSpec, approval package, target set, rollback baseline, support/recovery references, audit sink, nonce, expiry, and policy version.

`activation_allowed` may become true only when object trust, quarantine verification, two-target enrollment, exact approval, AgentCore executable PlanSpec, SecurityExecution allow decision, audit, rollback, and support/recovery gates are all true.

`rollback_execution_allowed` may become true only after controlled activation evidence exists and a separate rollback approval, rollback PlanSpec, SecurityExecution rollback allow decision, audit journal, post-rollback observation plan, rollback baseline, and support/recovery binding are all true.

## Fail-Closed Cases

RC12 must fail closed for:

- missing external HTTPS object URI;
- non-HTTPS, local, mutable, credential-bearing, unpinned, or authority-bearing URI;
- endpoint reachability used as trust;
- object size mismatch;
- object SHA-256 mismatch;
- descriptor canonical digest mismatch;
- manifest or checksum mismatch;
- public signature target or receipt mismatch;
- missing, stale, revoked, or mismatched revocation evidence;
- missing or stale freshness window;
- missing or mismatched compatibility metadata;
- missing or mismatched rollback baseline;
- missing or mismatched support/recovery binding;
- nonzero declared/current drift;
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

RC12 planning and verification tasks may write local evidence artifacts. They must not upload payload bytes, provision object storage, sign artifacts, install, activate, rollback, upload support bundles, recover systems, dispatch remote actions, mutate active slots, mutate boot metadata, mutate active artifact sets, or mutate production rings unless a later execution task proves every required gate and records the effect explicitly.

## Next Task Handoff

`RC12-010` must consume this contract and bind or deny immutable external object publication evidence for the current payload bytes. It may classify and hash-bind metadata, but it must not provision object storage, upload payloads, sign, install, activate, rollback, dispatch remote actions, or mutate production state.
