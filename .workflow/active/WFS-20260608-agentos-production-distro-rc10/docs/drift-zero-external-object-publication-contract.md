# Drift-Zero External Object Publication Contract

## Scope

RC10-002 defines the descriptor publication and reconciliation boundary for moving AIOS from RC9 `drift-denied` evidence to drift-zero external object trust.

RC10 may publish a real external object descriptor only after declared release metadata and current artifact evidence agree. Publication is still not install authorization. A successfully published descriptor may feed installer quarantine fetch and later controlled canary tasks, but it cannot by itself install, activate, rollback, mutate boot metadata, mutate active slots, mutate production rings, upload support bundles, dispatch remote fleet actions, or grant authority to the mirror, signer, object store, frontend, shell, model replay, or TUI.

This contract does not upload payload bytes, sign payloads, download payload bytes, install, activate, rollback, mutate system state, or perform remote dispatch.

## Publication Inputs

Drift-zero publication requires these inputs before mirror metadata can reference an external object descriptor:

- release id;
- release channel id;
- current payload source artifact path classification;
- current payload source artifact SHA-256;
- current payload source artifact byte length;
- current payload media kind;
- current release provenance digest;
- current release manifest digest;
- current checksum set digest;
- current public signature target digest;
- current public signature receipt digest;
- current revocation snapshot digest;
- current installer compatibility digest;
- current rollback baseline digest;
- current support/recovery digest;
- external object URI candidate;
- external object immutability evidence;
- external object byte length;
- external object SHA-256;
- external object content type;
- external object range policy;
- descriptor canonicalization policy;
- mirror payload index digest before publication;
- install bootstrap digest before publication;
- channel index digest before publication;
- policy version;
- freshness window.

Every input must be present, credential-free, non-local, immutable, non-authority-bearing, and bound to the same release id and payload digest.

## Descriptor Schema

The RC10 external object descriptor must use `agentos.payload-object-descriptor.v1` and include:

- `schema`;
- `release_id`;
- `release_channel`;
- `object_id`;
- `object_kind`;
- `uri`;
- `uri_policy`;
- `storage_provider_class`;
- `immutable`;
- `published_at`;
- `fresh_until`;
- `size_bytes`;
- `sha256`;
- optional `sha512`;
- `content_type`;
- `compression`;
- `range_request_supported`;
- `source_build_artifact_class`;
- `source_build_artifact_sha256`;
- `source_build_artifact_size_bytes`;
- `release_provenance_sha256`;
- `manifest_sha256`;
- `checksums_sha256`;
- `public_signature_target_sha256`;
- `public_signature_receipt_sha256`;
- `revocation_snapshot_sha256`;
- `installer_compatibility_sha256`;
- `rollback_baseline_sha256`;
- `support_recovery_sha256`;
- `declared_current_reconciliation_sha256`;
- `mirror_publication_sha256`;
- `install_bootstrap_sha256`;
- `channel_index_sha256`;
- `policy_version`;
- `production_ready_claim`;
- `install_allowed`;
- `activation_allowed`;
- `rollback_execution_allowed`.

The descriptor must set:

- `production_ready_claim`: false;
- `install_allowed`: false;
- `activation_allowed`: false;
- `rollback_execution_allowed`: false.

The descriptor must not contain bearer tokens, cookies, authorization headers, query-string credentials, presigned credentials, provider admin endpoints, mutable upload endpoints, local absolute paths, private signing material, secret handles, shell commands, support upload endpoints, remote dispatch endpoints, or any authority flag.

## Canonicalization

Descriptor digest calculation must be stable:

- UTF-8 JSON;
- deterministic property order;
- no comments;
- no trailing commas;
- normalized line endings;
- no local host paths;
- no volatile timestamps outside explicit publication and freshness fields;
- no environment-specific absolute paths;
- no credential-bearing query parameters.

Any descriptor digest mismatch between declared metadata, current metadata, mirror metadata, installer handoff, and support/recovery evidence must produce `drift-denied`.

## Drift-Zero Reconciliation Matrix

RC10 reconciliation must compare declared metadata against current artifact evidence.

Required comparisons:

- release id equality;
- release channel equality;
- source artifact class equality;
- source artifact byte length equality;
- source artifact SHA-256 equality;
- object id equality;
- object kind equality;
- external object URI policy equality;
- external object byte length equality;
- external object SHA-256 equality;
- release provenance digest equality;
- manifest digest equality;
- checksum set digest equality;
- public signature target digest equality;
- public signature receipt digest equality;
- revocation snapshot digest equality;
- installer compatibility digest equality;
- rollback baseline digest equality;
- support/recovery digest equality;
- descriptor canonical digest equality;
- mirror payload index binding equality;
- install bootstrap binding equality;
- channel index binding equality;
- freshness window validity;
- superseded metadata handling.

`drift_count` must equal `0` before publication can become `published-drift-zero`. A nonzero drift count must block descriptor publication, installer fetch, activation, rollback, support upload, recovery execution, production ring mutation, and remote dispatch.

## Allowed States

RC10 descriptor publication and reconciliation may produce only these states:

- `published-drift-zero`: descriptor is published and every required drift comparison matched;
- `publication-blocked-drift-nonzero`: descriptor publication is blocked because at least one comparison differs;
- `publication-blocked-evidence-missing`: descriptor publication is blocked because required evidence is absent;
- `publication-blocked-authority-broadening`: descriptor publication is blocked because metadata grants authority outside the allowed chain;
- `publication-blocked-unsafe-uri`: descriptor publication is blocked because URI policy fails;
- `superseded-metadata-no-authority`: old metadata is marked superseded and cannot authorize install or activation.

No allowed state may claim GA readiness or authorize install, activation, rollback, support upload, production ring mutation, remote dispatch, model replay authority, shell authority, frontend authority, mirror authority, signer authority, or TUI authority.

## Mirror And Installer Handoff

The mirror may publish only small metadata and must remain metadata-only. The handoff to installer quarantine fetch must include:

- descriptor path and SHA-256;
- reconciliation artifact path and SHA-256;
- publication report path and SHA-256;
- external object URI classification;
- expected object byte length;
- expected object SHA-256;
- expected manifest digest;
- expected checksum set digest;
- expected public signature target digest;
- expected public signature receipt digest;
- expected revocation digest;
- expected compatibility digest;
- expected rollback baseline digest;
- expected support/recovery digest;
- expected freshness window;
- quarantine root policy;
- allowed network policy;
- denied side effect list.

Installer handoff must keep `install_allowed=false`, `activation_allowed=false`, and `rollback_execution_allowed=false` until later tasks bind quarantine fetch, exact approval, AgentCore, SecurityExecutionEngine, canary target set, rollback, audit, and support/recovery evidence.

## Denial Evidence

For every denied state, the artifact must include:

- failed field id;
- expected value hash or classification;
- actual value hash or classification;
- source artifact path or descriptor path;
- denial reason;
- downstream gates blocked;
- side-effect flags proving no install, activation, rollback, support upload, recovery, production ring mutation, or remote dispatch happened.

The denial artifact must not repair drift by rewriting declared metadata. Repair belongs to a later explicit task that regenerates declared metadata from current artifacts and then re-runs reconciliation.

## Fail-Closed Rules

RC10 descriptor publication must fail closed for:

- missing release id;
- release id mismatch;
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
- descriptor canonical hash mismatch;
- manifest digest mismatch;
- checksum set digest mismatch;
- public signature target mismatch;
- public signature receipt mismatch;
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
- install authority broadening;
- activation authority broadening;
- rollback authority broadening;
- support upload authority broadening;
- recovery authority broadening;
- remote dispatch authority broadening;
- model, shell, frontend, signer, mirror, object storage, or TUI authority broadening.

## Outputs For Future Tasks

`RC10-010` must produce a publication report, descriptor candidate, and publication denial or `published-drift-zero` evidence. `RC10-011` must produce a drift-zero reconciliation report or nonzero drift denial. `RC10-012` must consume those outputs and verify installer quarantine fetch against the published descriptor.

Until those tasks pass, RC10 remains `verification-blocked`, `production_ready_claim=false`, `install_allowed=false`, `activation_allowed=false`, and `rollback_execution_allowed=false`.
