# Real External Object And Controlled Execution Enablement Contract

## Scope

RC10 starts after the RC9 final audit. RC9 proved that external object publication, declared/current drift reconciliation, installer fetch, target enrollment, exact approval, AgentCore binding, SecurityExecutionEngine binding, activation, rollback, and support/recovery all deny safely when their inputs are missing.

RC10 changes the target from denial-only evidence to controlled enablement. The milestone may publish a real immutable external HTTPS object descriptor, reconcile declared/current artifact drift to zero, verify installer quarantine fetch against the published object, enroll at least two canary targets, bind exact approval to AgentCore and SecurityExecutionEngine, and then produce controlled activation plus rollback evidence.

This contract does not itself upload payload bytes, sign payloads, install, activate, rollback, mutate boot metadata, mutate active slots, mutate production rings, upload support bundles, dispatch remote fleet actions, or grant authority to the mirror, signer, frontend, shell, model replay, or TUI.

## Authority Boundary

AIOS release authority remains local verification plus public signature and revocation evidence. The mirror is transport and metadata projection only. The signer endpoint is not a mirror and the mirror endpoint is not a signer.

RC10 must keep these boundaries:

- `aios.w33d.xyz` may expose metadata, descriptors, health, bootstrap, support/recovery references, and public release status.
- `sign.w33d.xyz` may be referenced only as an isolated signing service boundary when public signature artifacts already exist or are ingested through explicit receipts.
- External object storage may serve immutable payload bytes, but object reachability is not trust.
- Installer, AgentCore, SecurityExecutionEngine, AuditJournal, rollback baseline, and support/recovery evidence are the authority chain.
- TUI, frontend, shell output, object storage UI, model replay, and endpoint reachability are not authority.

Private signing material is outside RC10 task scope. RC10 tasks must not read, copy, print, hash, move, or reference private signing keys.

## External Object Publication Enablement

RC10 may publish a persistent external object descriptor only when the descriptor is:

- HTTPS;
- credential-free;
- stable and immutable;
- canonicalized;
- size-bound;
- SHA-256-bound;
- manifest-bound;
- checksum-set-bound;
- public-signature-bound;
- revocation-bound;
- installer-compatibility-bound;
- rollback-baseline-bound;
- support/recovery-bound;
- freshness-bound;
- policy-version-bound.

The descriptor must reject bearer tokens, cookies, local host paths, provider admin endpoints, mutable upload endpoints, presigned URLs with embedded credentials, authority-bearing query parameters, and any field that grants install, activation, rollback, support upload, production ring mutation, remote dispatch, shell, model, TUI, mirror, or frontend authority.

If a real external object URI is unavailable, mutable, credential-bearing, non-HTTPS, digest-mismatched, size-mismatched, stale, unsigned, revoked, incompatible, or not bound to rollback and support/recovery evidence, RC10 must produce denial evidence and keep install and activation blocked.

## Drift-Zero Requirement

RC9 observed declared/current drift. RC10 must treat drift-zero reconciliation as a hard precondition for trust.

The drift evidence must compare:

- release id;
- current payload digest;
- current payload byte length;
- object descriptor digest;
- external object digest;
- manifest digest;
- checksum set digest;
- public signature target digest;
- public signature receipt digest;
- revocation snapshot digest;
- installer compatibility digest;
- rollback baseline digest;
- support/recovery reference digest;
- mirror channel digest;
- install bootstrap digest.

Every comparison must be equal before external object trust, installer authorization, activation, or rollback can move forward. A single mismatch produces `drift-denied`.

## Installer Quarantine Fetch Requirement

Installer fetch is allowed only into quarantine. Quarantine fetch must verify bytes before interpretation.

The installer must:

1. Resolve the release channel metadata.
2. Resolve the external object descriptor.
3. Reject non-HTTPS, mutable, credential-bearing, local, stale, or authority-bearing object references.
4. Fetch bytes only into quarantine.
5. Verify byte length and SHA-256 before any parsing or extraction.
6. Verify manifest, checksum set, public signature, revocation snapshot, freshness, compatibility, rollback baseline, and support/recovery bindings.
7. Keep install blocked unless later install authorization is separately granted.

Quarantine fetch success is not install success. Install, activation, active slot mutation, boot metadata mutation, production ring mutation, support upload, recovery execution, and remote dispatch remain separately gated.

## Two-Node Canary Requirement

Controlled activation requires at least two enrolled canary target nodes. A target counts only when evidence binds:

- stable node id;
- enrollment state;
- expected release id;
- current active artifact set;
- desired artifact set;
- compatibility result;
- rollback baseline availability;
- support/recovery destination;
- audit journal destination;
- health evidence;
- duplicate-node check;
- expiry;
- policy version.

Projected, missing, duplicate, stale, incompatible, single-node, or unbound target sets must deny controlled activation.

## Exact Approval Requirement

Exact approval must bind:

- actor;
- scope;
- release id;
- external object digest;
- target node ids;
- target set digest;
- AgentCore PlanSpec id and hash;
- SecurityExecutionEngine policy id;
- effect envelope id;
- rollback baseline digest;
- support/recovery digest;
- audit sink;
- expiry;
- nonce;
- policy version.

Approval is invalid if it is stale, broad, missing any bound field, points to a different object digest, points to a different target set, skips AgentCore, skips SecurityExecutionEngine, grants rollback without a rollback-specific approval, or grants authority to mirror, frontend, TUI, shell, object storage, model replay, or signer reachability.

## AgentCore And SecurityExecution Enablement

Every side effect must be represented by both:

- an AgentCore PlanSpec; and
- a SecurityExecutionEngine effect envelope.

AgentCore must bind release id, object digest, target set digest, approval digest, rollback baseline digest, support/recovery digest, expected observations, recovery path, and audit sink.

SecurityExecutionEngine must bind effect type, target nodes, filesystem or boot metadata mutation scope, active artifact mutation scope, rollback path, policy decision, allowed effect set, expiry, audit sink, and denial reason when blocked.

Controlled activation may mutate canary target state only after all prior gates pass. Production ring mutation remains out of scope for RC10 unless a later final audit explicitly promotes it, which this contract does not do.

## Controlled Rollback Requirement

Rollback execution is a separate effect. It requires controlled activation evidence and a separate exact rollback approval.

Rollback evidence must bind:

- previous artifact set;
- activated artifact set;
- rollback baseline;
- target nodes;
- rollback approval digest;
- rollback AgentCore PlanSpec id and hash;
- rollback SecurityExecutionEngine effect envelope;
- support/recovery references;
- audit journal;
- post-rollback observations.

If activation never occurred, rollback may still produce readiness or denial evidence, but it must not execute a rollback side effect.

## Fail-Closed Rules

RC10 must deny trust, install, activation, or rollback for:

- missing external HTTPS object URI;
- non-HTTPS, mutable, credential-bearing, local, or authority-bearing object URI;
- object size mismatch;
- object digest mismatch;
- manifest or checksum set mismatch;
- signature target, object, canonical payload, or receipt mismatch;
- missing, stale, or revoked revocation snapshot;
- missing or mismatched installer compatibility metadata;
- missing or mismatched rollback baseline;
- unresolved declared/current artifact drift;
- missing installer quarantine fetch evidence;
- fewer than two enrolled canary targets;
- stale, broad, or missing exact operator approval;
- missing AgentCore PlanSpec;
- missing SecurityExecutionEngine approval;
- missing rollback-specific approval;
- missing support/recovery binding;
- any authority broadening by mirror, object storage, signer, frontend, TUI, shell, model replay, remote registry, or support endpoint.

## RC10 Task Direction

RC10 execution should proceed in this order:

1. Define drift-zero external object descriptor publication.
2. Define exact approval, canary activation, and rollback execution enablement.
3. Publish or reject an immutable external object descriptor for current AIOS payload bytes.
4. Reconcile declared/current artifact drift to zero.
5. Verify installer quarantine fetch against the published object descriptor.
6. Enroll or deny a two-node canary target set.
7. Bind exact operator approval to AgentCore PlanSpec and SecurityExecutionEngine effect envelope.
8. Execute or deny controlled canary activation.
9. Execute or deny rollback drill after controlled canary evidence.
10. Bind support/recovery evidence and close RC10 with final audit while keeping `production_ready_claim=false` unless every GA gate is proved.
