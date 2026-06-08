# RC14 Local Execution Readiness Contract

## Scope

RC14-001 freezes the AIOS-body contract for moving from RC13 fail-closed local trust evidence into satisfiable local execution readiness. RC14 may repair local declared/current identity evidence, bind freshness and revocation state, prove local object trust, run quarantine preflight, materialize executable AgentCore PlanSpec readiness, bind SecurityExecution allow envelopes, enroll local targets, bind exact approval, and then execute or deny controlled local activation and separately approved rollback.

This task does not configure mirror frontend, Nginx, TLS, remote signer infrastructure, object storage infrastructure, signing ceremonies, remote dispatch infrastructure, install, activation, rollback, support upload, active slot mutation, boot metadata mutation, active artifact set mutation, production ring mutation, or a GA production-ready claim.

## Gate Order

RC14 must evaluate gates in this order:

1. Freeze the current release artifact identity set from RC13 final audit: release id, payload object identity, descriptor, manifest, checksum set, public signature target, revocation snapshot, freshness requirement, compatibility metadata, rollback baseline, and support/recovery references.
2. Repair declared metadata and current artifact evidence to drift_count=0; if any drift remains, object trust and downstream execution remain denied.
3. Bind a current freshness window and revocation snapshot to the release identity without reading, copying, hashing, printing, or using private signing material.
4. Allow local object trust only after drift-zero, descriptor/manifest consistency, public signature target, revocation, freshness, compatibility, rollback, and support/recovery gates are all proved.
5. Run verified quarantine preflight only after local object trust is allowed; bytes may be written only to quarantine and must not be interpreted until verification succeeds.
6. Bind verified quarantine/preflight evidence into an AgentCore executable PlanSpec candidate with exact release, object, target, approval, rollback, support/recovery, and audit references.
7. Bind the same PlanSpec, object digest, target set, rollback baseline, support/recovery references, audit sink, nonce, expiry, and policy version into a SecurityExecutionEngine allow envelope.
8. Require at least two enrolled non-duplicate local canary target identities before activation authority; remote dispatch remains disabled.
9. Require exact operator approval bound to actor, release, object, target set, AgentCore PlanSpec, SecurityExecution envelope, audit sink, nonce, expiry, rollback baseline, and support/recovery evidence.
10. Execute controlled local activation only if every prior gate is proved and the activation task records the exact effect or denial.
11. Execute rollback only after controlled activation evidence plus a separate exact rollback approval, rollback PlanSpec, SecurityExecution rollback allow decision, audit journal, rollback baseline, support/recovery evidence, and post-rollback observation plan are proved.

Any missing, stale, broad, mismatched, replayed, private-material, or authority-broadening input denies downstream authority.

## Authority Boundary

The following are authoritative only after local AIOS verification records them as machine evidence:

- release byte length and SHA-256;
- declared/current drift-zero reconciliation;
- descriptor canonical digest;
- manifest and checksum set digests;
- public signature target and receipt;
- public key reference;
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

## Readiness Rules

declared_current_drift_zero may become true only when every declared/current comparison is explicit, hash-bound, and matched.

reshness_revocation_authority_bound may become true only when a current freshness window and revocation snapshot are hash-bound to the release identity and public signature target without private signing material.

local_object_trust_allowed may become true only when drift-zero, descriptor/manifest consistency, public signature target, revocation, freshness, compatibility, rollback, and support/recovery gates all pass.

erified_quarantine_preflight may become true only after local object trust is allowed. Bytes may be written only to quarantine and must not be interpreted until verification succeeds.

gentcore_planspec_executable may become true only when verified quarantine/preflight evidence is hash-bound into a PlanSpec with exact release, object, target, approval, rollback, support/recovery, and audit references.

security_execution_allowed may become true only when the effect envelope exactly matches the PlanSpec, approval package, target set, rollback baseline, support/recovery references, audit sink, nonce, expiry, and policy version.

ctivation_allowed may become true only when object trust, quarantine verification, two-target enrollment, exact approval, AgentCore executable PlanSpec, SecurityExecution allow decision, audit, rollback, and support/recovery gates are all true.

ollback_execution_allowed may become true only after controlled activation evidence exists and a separate rollback approval, rollback PlanSpec, SecurityExecution rollback allow decision, audit journal, post-rollback observation plan, rollback baseline, and support/recovery binding are all true.

## Fail-Closed Cases

RC14 must fail closed for:

- nonzero declared/current drift;
- missing, broad, stale, or mismatched declared artifact identity;
- object size mismatch;
- object SHA-256 mismatch;
- descriptor canonical digest mismatch;
- manifest or checksum mismatch;
- public signature target, receipt, or public key reference mismatch;
- local private signing material used as production authority;
- missing, stale, revoked, or mismatched revocation evidence;
- missing or stale freshness window;
- missing or mismatched compatibility metadata;
- missing or mismatched rollback baseline;
- missing or mismatched support/recovery binding;
- endpoint reachability used as trust;
- quarantine preflight before object trust;
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

RC14 planning and verification tasks may write local evidence artifacts. They must not upload payload bytes, provision object storage, sign artifacts, install, activate, rollback, upload support bundles, recover systems, dispatch remote actions, mutate active slots, mutate boot metadata, mutate active artifact sets, or mutate production rings unless a later execution task proves every required gate and records the effect explicitly.

## Next Task Handoff

RC14-010 must consume this contract and repair declared/current drift-zero into a local reconciled identity set. It may compare and hash-bind local metadata and current artifacts, but it must not provision object storage, upload payloads, sign, install, activate, rollback, dispatch remote actions, or mutate production state.