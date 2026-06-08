# External Object Storage And Controlled Canary Execution Contract

## Scope

RC9 starts after the RC8 final audit. RC8 proved a real payload object descriptor, public signature artifact ingestion, signed descriptor fail-closed fixtures, installer VM preflight, installer byte fail-closed fixtures, HTTPS mirror consistency, canary activation denial, rollback denial, and support/recovery binding. RC8 still did not claim GA because the payload has no external HTTPS object URI, declared/current artifact drift is unresolved, canary activation has not executed, only one canary target is observed, exact operator approval is not granted, AgentCore PlanSpec and SecurityExecutionEngine approvals are not bound, remote fleet execution is disabled, and rollback execution has not run.

This RC9 contract defines the next boundary: real payload bytes may move to immutable external object storage, but the mirror remains metadata-only and non-authoritative. Controlled activation and rollback may proceed only when exact approval, target enrollment, AgentCore, SecurityExecutionEngine, rollback, and recovery gates are all bound.

This contract does not itself upload payload bytes, publish external object URLs, sign payloads, install, activate, rollback, mutate boot metadata, mutate active slots, mutate production rings, upload support bundles, dispatch remote fleet actions, or grant authority to the mirror, signer, frontend, shell, model replay, or TUI.

## External Object Storage Boundary

The public mirror at `aios.w33d.xyz` remains a small metadata-only mirror. It must not store ISO, disk image, rootfs, update bundle, recovery image, package archive, VM image, or other large payload bytes under the mirror root.

External object storage may be used only as immutable byte transport. A persistent object reference is acceptable only when it is:

- HTTPS;
- credential-free;
- stable and immutable;
- size-bound;
- SHA-256-bound;
- manifest-bound;
- checksum-set-bound;
- public-signature-bound;
- revocation-bound;
- installer-compatibility-bound;
- rollback-baseline-bound;
- freshness-bound;
- policy-version-bound.

The descriptor must not contain bearer tokens, cookies, provider admin endpoints, mutable upload URLs, presigned URLs with embedded credentials, local host paths, secret handles, or any authority to install, activate, rollback, dispatch, upload support bundles, mutate rings, or sign.

Object storage reachability is not trust. The installer must download bytes to quarantine, verify size and digest before interpretation, verify public signature and revocation bindings, then keep install blocked until compatibility, rollback baseline, drift reconciliation, exact approval, AgentCore, and SecurityExecutionEngine gates pass.

## Declared/Current Drift Reconciliation

RC9 must reconcile declared release metadata with the current artifact set before any install or activation authorization.

The reconciliation evidence must bind:

- current build artifact path and digest;
- object descriptor digest;
- external object digest and byte length;
- release manifest digest;
- checksum set digest;
- public signature receipt digest;
- revocation snapshot digest;
- installer compatibility digest;
- rollback baseline digest;
- support/recovery reference digest;
- mirror channel digest;
- install bootstrap digest.

If the declared release id, artifact digest, manifest digest, checksum set digest, signature target, revocation binding, compatibility binding, rollback binding, or live mirror hash differs from the expected current artifact set, RC9 must produce a drift denial artifact and keep install, activation, and rollback blocked.

## Canary Enrollment Boundary

Fleet canary execution requires at least two enrolled target nodes. A node counts only when the enrollment evidence includes:

- stable node id;
- enrollment status;
- expected release id;
- current active artifact set;
- compatibility result;
- rollback baseline availability;
- support/recovery destination;
- audit journal destination;
- health evidence;
- duplicate-node check;
- expiry and policy version.

Projected, missing, duplicate, stale, incompatible, or single-node target sets must keep fleet canary execution blocked.

## Exact Approval Boundary

Exact operator approval must bind actor, scope, release id, payload object digest, target node ids, PlanSpec id and hash, SecurityExecutionEngine policy id, rollback baseline, support/recovery references, expiry, nonce, and policy version.

Approval is not valid if it is stale, broad, missing any bound field, points to a different payload digest, points to a different target set, skips AgentCore, skips SecurityExecutionEngine, or grants mirror/frontend/TUI/shell/model authority.

## AgentCore And SecurityExecution Boundary

Every side effect must be represented as an AgentCore PlanSpec and a SecurityExecutionEngine effect envelope.

AgentCore must bind:

- plan id;
- plan hash;
- release id;
- object digest;
- target set digest;
- approval digest;
- rollback baseline digest;
- support/recovery digest;
- expected observations;
- recovery path.

SecurityExecutionEngine must bind:

- policy decision;
- effect envelope id;
- allowed effect set;
- target nodes;
- filesystem or boot metadata mutation scope, if any;
- rollback path;
- audit sink;
- expiry;
- denial reason when blocked.

If either binding is absent or stale, the expected outcome is a denial artifact, not a side effect.

## Controlled Activation Boundary

RC9 can attempt controlled canary activation only after external object verification, drift reconciliation, target enrollment, exact approval, AgentCore PlanSpec, SecurityExecutionEngine approval, rollback baseline, and support/recovery bindings pass.

Activation must be deny-by-default. A successful controlled activation must produce audit evidence for target nodes, previous artifact set, intended artifact set, effect envelope, observations, and recovery path. A denied activation must produce exact blockers and must not mutate boot metadata, active slots, active artifact sets, persistent state, or production rings.

## Controlled Rollback Boundary

Rollback drill execution may proceed only after controlled canary activation evidence exists and rollback approval is separately bound through AgentCore and SecurityExecutionEngine.

Rollback evidence must bind previous artifact set, activated artifact set, rollback baseline, target nodes, exact rollback approval, PlanSpec id/hash, effect envelope, support/recovery references, audit journal, and post-rollback observations.

If any rollback gate is missing, RC9 must produce rollback denial evidence and preserve active slots, boot metadata, active artifact sets, persistent state, and production rings.

## Fail-Closed Rules

RC9 must remain `verification-blocked` or `execution-blocked` for:

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
- missing rollback approval for rollback execution;
- missing support/recovery binding;
- authority broadening by mirror, object storage, signer, frontend, TUI, shell, model replay, or remote registry.

## RC9 Task Direction

RC9 execution should proceed in this order:

1. Define external object descriptor publication and artifact drift reconciliation.
2. Define exact approval, target enrollment, AgentCore, and SecurityExecution binding.
3. Project or deny an immutable external object publication candidate for current payload bytes.
4. Reconcile declared/current artifact drift.
5. Run quarantine fetch and installer fail-closed evidence for the external object.
6. Enroll or deny a two-node canary target set.
7. Bind exact operator approval to AgentCore PlanSpec and SecurityExecutionEngine approval.
8. Execute or deny controlled canary activation.
9. Execute or deny rollback drill after controlled canary evidence.
10. Bind support/recovery evidence and close RC9 with final audit while keeping `production_ready_claim=false` unless every GA gate is proved.
