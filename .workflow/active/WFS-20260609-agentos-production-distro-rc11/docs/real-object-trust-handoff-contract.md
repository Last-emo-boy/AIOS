# RC11 Real Object Trust Handoff Contract

## Scope

RC11-001 freezes the handoff from external object transport into AIOS local verification and controlled execution. The external HTTPS object may be a distribution input, but it is never authority by itself.

This task is AIOS body work only. It does not configure mirror frontend, Nginx, TLS, remote signer infrastructure, signing ceremonies, remote dispatch, install, activation, rollback, support upload, active slot mutation, boot metadata mutation, active artifact set mutation, or production ring mutation.

## Trust Handoff Chain

RC11 must treat the handoff as a staged chain:

1. External transport exposes a candidate HTTPS object descriptor.
2. AIOS classifies the descriptor URI and rejects non-HTTPS, mutable, local, credential-bearing, stale, or authority-bearing references.
3. AIOS compares the descriptor against current release byte evidence.
4. AIOS reconciles declared metadata and current artifact evidence to drift count `0`.
5. Installer fetch is allowed only into quarantine.
6. Quarantine verification checks byte length and SHA-256 before parsing, mounting, extracting, or interpreting bytes.
7. Installer preflight verifies manifest, checksum set, public signature target, signature receipt, revocation snapshot, freshness, compatibility, rollback baseline, and support/recovery binding.
8. AgentCore receives only verified preflight evidence and may produce a PlanSpec candidate.
9. SecurityExecutionEngine receives only exact approval plus a matching PlanSpec and may approve or deny a bounded effect envelope.
10. Activation and rollback evidence must be audited and support/recovery-bound before any wider execution claim.

Any missing or mismatched link denies downstream trust and side effects.

## Descriptor Requirements

The descriptor must be canonical, hash-bound, size-bound, freshness-bound, and credential-free. It must bind:

- release id;
- release channel;
- object id;
- object URI classification;
- object size;
- object SHA-256;
- source artifact class;
- source artifact SHA-256;
- manifest SHA-256;
- checksum set SHA-256;
- public signature target SHA-256;
- public signature receipt SHA-256;
- revocation snapshot SHA-256;
- installer compatibility SHA-256;
- rollback baseline SHA-256;
- support/recovery SHA-256;
- policy version;
- freshness window.

The descriptor must set `production_ready_claim=false`, `install_allowed=false`, `activation_allowed=false`, and `rollback_execution_allowed=false` until later evidence proves every gate.

## AIOS Body Authority

Authority belongs to AIOS local verification and execution components:

- release artifact evidence;
- descriptor classifier;
- drift-zero reconciler;
- installer quarantine verifier;
- public signature verifier;
- revocation verifier;
- compatibility gate;
- rollback baseline gate;
- support/recovery binding;
- AgentCore PlanSpec;
- SecurityExecutionEngine effect envelope;
- AuditJournal and RunStore evidence.

The following are not authority:

- mirror reachability;
- signer reachability;
- frontend output;
- TUI output;
- shell output;
- model replay;
- object storage UI;
- support endpoint reachability;
- DNS resolution;
- HTTP status alone.

## Drift-Zero Gate

Drift-zero is a hard gate. RC11 must compare declared metadata and current artifact evidence for release id, source artifact class, byte length, object digest, manifest, checksum set, signature target, signature receipt, revocation, compatibility, rollback baseline, support/recovery, channel index, install bootstrap, and descriptor canonical digest.

`drift_count` must be `0` before object trust, installer authorization, activation, rollback, support upload, recovery execution, production ring mutation, or remote dispatch can proceed.

## Quarantine Fetch Gate

Installer fetch must use quarantine as the only landing zone. Bytes must be length-checked and SHA-256-checked before interpretation. Verification success is only preflight evidence; it is not install authorization.

The verifier must produce denial evidence for unsafe URI, missing descriptor, network denial, size mismatch, digest mismatch, manifest mismatch, checksum mismatch, signature mismatch, revoked or stale revocation, stale freshness, compatibility mismatch, rollback mismatch, support/recovery mismatch, and authority broadening.

## Controlled Execution Gate

Controlled activation requires all prior object and installer gates plus:

- at least two enrolled non-duplicate canary targets;
- exact operator approval;
- AgentCore PlanSpec hash bound to approval;
- SecurityExecutionEngine decision and effect envelope bound to the same approval;
- rollback baseline;
- support/recovery binding;
- audit sink;
- expiry and policy version.

Rollback requires separate exact rollback approval and a rollback PlanSpec. Activation evidence does not grant rollback authority.

## Fail-Closed Cases

RC11 must fail closed for:

- missing external HTTPS object URI;
- non-HTTPS, local, mutable, credential-bearing, or authority-bearing object URI;
- endpoint reachability used as trust;
- object size mismatch;
- object digest mismatch;
- descriptor canonical digest mismatch;
- nonzero declared/current artifact drift;
- missing quarantine fetch evidence;
- bytes interpreted before quarantine verification;
- manifest or checksum mismatch;
- missing, invalid, or mismatched public signature evidence;
- stale or revoked revocation snapshot;
- missing or mismatched compatibility metadata;
- missing or mismatched rollback baseline;
- missing or mismatched support/recovery binding;
- fewer than two enrolled canary targets;
- duplicate, stale, incompatible, or unbound target records;
- stale, broad, or missing exact approval;
- missing or mismatched AgentCore PlanSpec;
- missing or denied SecurityExecutionEngine decision;
- missing rollback-specific approval;
- support upload authority broadening;
- remote dispatch authority broadening;
- production ring mutation authority broadening;
- mirror, signer, frontend, TUI, shell, model, object storage, or support endpoint authority broadening.

## Next Task Handoff

`RC11-010` must consume this contract and build the current release object byte map plus immutable descriptor candidate. That task may project and verify local metadata, but it must not upload payload bytes, install, activate, rollback, dispatch remote actions, or mutate production state.
