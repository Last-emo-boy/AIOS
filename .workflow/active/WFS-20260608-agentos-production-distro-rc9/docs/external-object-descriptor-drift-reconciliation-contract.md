# External Object Descriptor Publication And Artifact Drift Reconciliation Contract

## Scope

RC9-002 defines the publication and reconciliation boundary for moving the RC8 real payload descriptor from a repo-local immutable reference to an external HTTPS object reference. This contract turns the RC9 external object storage direction into a concrete descriptor, mirror, installer, and drift evidence contract.

This contract does not upload payload bytes, publish a live external object URL, sign payloads, download remote payload bytes, install, activate, rollback, mutate boot metadata, mutate active slots, mutate active artifact sets, mutate production rings, upload support bundles, dispatch remote fleet actions, or grant authority to the mirror, object store, signer, frontend, shell, model replay, or TUI.

## Descriptor Publication Inputs

External object descriptor publication requires the following inputs before any mirror metadata can reference external payload bytes:

- current payload source artifact path;
- current payload source artifact SHA-256;
- current payload source artifact size;
- release id;
- object kind;
- immutable external HTTPS object URI candidate;
- object storage provider class;
- object immutability evidence;
- object size evidence;
- object SHA-256 evidence;
- range request policy evidence, if used;
- release provenance digest;
- release manifest digest;
- checksum set digest;
- public signature receipt digest;
- public signature summary digest;
- revocation snapshot digest;
- installer compatibility digest;
- rollback baseline digest;
- support/recovery reference digest;
- mirror payload index digest before publication;
- install bootstrap digest before publication;
- channel index digest before publication;
- policy version.

If any input is absent, stale, credential-bearing, mutable, host-local, or authority-bearing, publication must be denied and all install, activation, rollback, support upload, recovery execution, and remote dispatch flags must remain false.

## External Object Descriptor Schema

RC9 external object descriptor publication must extend the RC8 descriptor without weakening it. The persistent descriptor must include:

- `schema`: `agentos.payload-object-descriptor.v1`;
- `release_id`;
- `object_id`;
- `kind`;
- `uri`: immutable external HTTPS URI;
- `uri_policy`: `external-https-immutable`;
- `size_bytes`;
- `sha256`;
- optional `sha512`;
- `content_type`;
- `compression`;
- `range_request_supported`;
- `immutable`: true;
- `published_at`;
- optional `expires_at`;
- `storage_provider_class`;
- `source_build_artifact`;
- `source_build_artifact_sha256`;
- `source_build_artifact_size_bytes`;
- `release_provenance_sha256`;
- `manifest_sha256`;
- `checksums_sha256`;
- `signed_metadata_sha256`;
- `public_signature_receipt_sha256`;
- `public_signature_summary_sha256`;
- `revocation_snapshot_sha256`;
- `installer_compatibility_sha256`;
- `rollback_baseline_sha256`;
- `support_recovery_sha256`;
- `declared_current_reconciliation_sha256`;
- `policy_version`;
- `production_ready_claim`: false;
- `install_allowed`: false;
- `activation_allowed`: false;
- `rollback_execution_allowed`: false.

The descriptor must not contain bearer tokens, cookies, query-string credentials, authorization headers, provider admin endpoints, mutable upload URLs, presigned URLs with embedded credentials, local absolute paths, private signing material, secret handles, shell commands, support upload endpoints, remote dispatch endpoints, or any flag that grants install, activation, rollback, production ring, model, shell, frontend, signer, mirror, or TUI authority.

## Mirror Publication Boundary

The mirror may publish only small metadata:

- `/payloads/index.json`;
- `/payloads/aios/<release-id>/object-descriptor.json`;
- `/payloads/aios/<release-id>/signature-receipt.json`;
- `/payloads/aios/<release-id>/signature-summary.json`;
- `/payloads/aios/<release-id>/external-object-publication.json`;
- `/payloads/aios/<release-id>/artifact-drift-reconciliation.json`;
- `/install/bootstrap.json`;
- `/channel/index.json`;
- static frontend status.

The mirror must not host the payload byte stream. The mirror must not become a root of trust. A live mirror reference to external bytes is acceptable only when the descriptor and reconciliation evidence keep the release `verification-blocked` until installer quarantine fetch, signature, revocation, compatibility, rollback baseline, exact approval, AgentCore, and SecurityExecutionEngine gates pass.

## Declared/Current Artifact Reconciliation

RC9 must produce a declared/current reconciliation artifact before external object trust. The reconciliation artifact must compare declared release metadata against the current artifact set.

Required comparisons:

- release id equality;
- source artifact path classification;
- source artifact size equality;
- source artifact SHA-256 equality;
- descriptor object id equality;
- descriptor object size equality;
- descriptor object SHA-256 equality;
- manifest digest equality;
- checksum set digest equality;
- signed metadata digest equality;
- public signature receipt target equality;
- public signature summary target equality;
- revocation snapshot digest equality;
- installer compatibility digest equality;
- rollback baseline digest equality;
- support/recovery digest equality;
- mirror payload index binding equality;
- install bootstrap binding equality;
- channel index binding equality;
- freshness window validity;
- superseded metadata handling.

If the current artifact differs from the declared artifact, the reconciliation artifact must identify the exact field, expected value hash, actual value hash, source path, and denial reason. It must not repair drift by silently rewriting the declared release.

## Drift States

Allowed reconciliation states:

- `reconciled-current-artifact`: all required fields match and external object trust may proceed to installer quarantine fetch;
- `reconciled-superseded-artifact`: old hosted metadata is explicitly superseded and cannot authorize install or activation;
- `drift-denied`: at least one required field differs and install, activation, rollback, support upload, recovery, and remote dispatch remain blocked;
- `evidence-missing-denied`: required evidence is absent and all side effects remain blocked;
- `authority-broadening-denied`: any descriptor, mirror, object storage, signer, frontend, shell, model, or TUI authority broadening is detected.

No drift state may set `production_ready_claim=true`.

## Installer Handoff Boundary

The installer may consume an external object descriptor only after publication and reconciliation evidence exist. The handoff to `RC9-012` must include:

- descriptor path and SHA-256;
- reconciliation artifact path and SHA-256;
- expected object URI classification;
- expected byte size;
- expected byte SHA-256;
- expected manifest digest;
- expected checksum set digest;
- expected signature receipt digest;
- expected revocation digest;
- expected compatibility digest;
- expected rollback baseline digest;
- expected support/recovery digest;
- quarantine root policy;
- allowed network policy;
- denied side effect list.

The installer must keep the payload unusable until quarantine download, byte length, byte digest, public signature, revocation, compatibility, rollback baseline, and policy gates verify.

## Fail-Closed Rules

RC9 external object publication and drift reconciliation must fail closed for:

- missing source artifact evidence;
- source artifact size mismatch;
- source artifact digest mismatch;
- missing external HTTPS object URI;
- non-HTTPS object URI;
- mutable object URI;
- credential-bearing object URI;
- local absolute object path;
- object storage authority broadening;
- missing object immutability evidence;
- object size mismatch;
- object digest mismatch;
- descriptor hash mismatch;
- manifest digest mismatch;
- checksum set digest mismatch;
- signature receipt mismatch;
- signature summary mismatch;
- revocation snapshot mismatch;
- compatibility digest mismatch;
- rollback baseline digest mismatch;
- support/recovery digest mismatch;
- stale freshness window;
- missing superseded metadata marker;
- mirror payload index binding mismatch;
- install bootstrap binding mismatch;
- channel index binding mismatch;
- production-ready claim;
- install, activation, rollback, support upload, recovery, remote dispatch, model, shell, frontend, signer, mirror, or TUI authority broadening.

## Outputs For Future Tasks

`RC9-010` must produce an external object publication candidate or a publication denial artifact. `RC9-011` must produce declared/current reconciliation evidence or a drift denial artifact. `RC9-012` must use those artifacts to run external object quarantine fetch and installer fail-closed evidence.

Until those tasks pass, RC9 remains `verification-blocked`, `production_ready_claim=false`, `install_allowed=false`, `activation_allowed=false`, and `rollback_execution_allowed=false`.
