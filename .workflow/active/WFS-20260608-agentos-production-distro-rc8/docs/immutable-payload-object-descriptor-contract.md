# Immutable Payload Object Descriptor And Byte Boundary Contract

## Scope

RC8-002 defines the byte boundary for real installable AIOS payloads. It turns the RC7 large payload storage policy into a concrete descriptor contract that later tasks can use to project, verify, publish, and smoke-test real payload bytes without widening authority.

This contract does not upload payload bytes, publish a new object reference, sign anything, install, activate, rollback, mutate boot metadata, mutate active slots, mutate active artifact sets, mutate production rings, upload support bundles, dispatch remote fleet actions, or grant authority to the mirror, object store, signer, frontend, shell, model replay, or TUI.

## Object Descriptor Schema

Every real payload byte candidate must be represented by a small JSON descriptor before the byte stream can enter installer preflight. The descriptor is metadata, not trust by itself.

Required fields:

- `schema`: `agentos.payload-object-descriptor.v1`;
- `release_id`: stable release candidate id;
- `object_id`: content-addressed or release-scoped object id;
- `kind`: one of `iso`, `disk-image`, `rootfs`, `update-bundle`, or `recovery-image`;
- `uri`: HTTPS URI or provider-neutral immutable object reference resolved through a trusted HTTPS gateway;
- `size_bytes`: exact byte length expected by the installer;
- `sha256`: required byte digest;
- `sha512`: optional stronger byte digest;
- `content_type`: expected media type;
- `compression`: `none` or the expected compression method;
- `range_request_supported`: boolean;
- `immutable`: must be true;
- `published_at`: timestamp for freshness evaluation;
- `expires_at`: optional channel expiry timestamp;
- `storage_provider_class`: object storage class, not provider credentials;
- `source_build_artifact`: repo-relative build artifact or release evidence path that produced the descriptor;
- `source_build_artifact_sha256`: digest of the local source artifact when available;
- `release_provenance_sha256`;
- `manifest_sha256`;
- `checksums_sha256`;
- `signed_metadata_sha256`;
- `revocation_snapshot_sha256`;
- `installer_compatibility_sha256`;
- `rollback_baseline_sha256`;
- `support_recovery_sha256`;
- `policy_version`;
- `production_ready_claim`: must remain false until final audit changes it.

Optional fields must be additive and must not change the trust model. Unknown fields are ignored only if the schema version allows them and they are not authority-bearing.

## Forbidden Descriptor Content

The descriptor must not contain:

- private signing material;
- secret handles;
- bearer tokens;
- cookies;
- account ids that grant provider mutation authority;
- presigned upload URLs;
- long-lived presigned download URLs embedded as persistent metadata;
- mutable object URLs;
- `http://` URLs;
- local filesystem paths outside approved evidence or quarantine roots;
- shell commands;
- installer activation commands;
- rollback commands;
- support upload endpoints;
- remote dispatch endpoints;
- TUI authority flags;
- model authority flags.

Short-lived download credentials, if ever needed, must be produced by a future installer-local broker step after descriptor verification. They must not be persisted in mirror metadata.

## Byte Quarantine Boundary

Real payload bytes are untrusted until the installer proves the descriptor and the downloaded bytes match.

The installer or smoke harness must:

1. Fetch mirror metadata over HTTPS.
2. Verify schema and freshness.
3. Verify the object descriptor is credential-free, immutable, HTTPS-bound, size-bound, and policy-approved.
4. Download bytes only into a quarantine path.
5. Compare actual byte length with `size_bytes`.
6. Compare actual SHA-256 with `sha256`.
7. Compare optional stronger digest when present.
8. Keep the payload unusable until manifest, checksums, public signature artifact, revocation snapshot, compatibility, rollback baseline, and release provenance all verify.
9. Emit an object-fetch report that records expected length, actual length, expected digest, actual digest, descriptor hash, quarantine path classification, and blocker reason.

The installer or smoke harness must not extract, mount, install, activate, copy into an active slot, mutate boot metadata, or prepare rollback side effects before these checks pass and later approval gates authorize execution.

## Descriptor Publication Boundary

Publishing a descriptor may update small mirror metadata:

- `/payloads/index.json`;
- `/payloads/aios/<release-id>/manifest.json`;
- `/payloads/aios/<release-id>/checksums.json`;
- `/payloads/aios/<release-id>/signed-metadata.json`;
- `/payloads/aios/<release-id>/signatures.json`;
- `/install/bootstrap.json`;
- `/channel/index.json`;
- static frontend status.

Publishing a descriptor must not:

- upload large bytes to the mirror host;
- make object storage a root of trust;
- make the mirror a signer;
- set `install_allowed=true`;
- set `activation_allowed=true`;
- set `rollback_execution_allowed=true`;
- mutate active boot or release state;
- open upload endpoints;
- open remote dispatch endpoints.

## Drift And Reconciliation

The descriptor must bind the exact source artifact it describes. If the release has declared/current artifact drift, the descriptor must record it as a blocker and keep the payload `verification-blocked`.

RC8 later tasks may clear drift only by producing evidence that:

- the source build artifact exists;
- the object descriptor digest matches the source artifact bytes or an explicitly assembled release artifact;
- release provenance, manifest, checksum set, and descriptor hashes agree;
- stale hosted metadata is replaced or marked superseded;
- fail-closed fixtures prove old hashes, wrong sizes, and wrong object ids are rejected.

## Failure Modes

The descriptor gate must fail closed for:

- missing descriptor;
- malformed JSON;
- wrong schema;
- `production_ready_claim=true`;
- non-HTTPS URI;
- mutable URI;
- credential-bearing URI;
- missing size;
- size mismatch;
- missing digest;
- digest mismatch;
- missing source artifact binding;
- source artifact drift;
- stale `published_at` or expired metadata;
- missing manifest hash;
- missing checksums hash;
- missing signed metadata hash;
- missing public signature artifact reference;
- missing revocation snapshot hash;
- missing installer compatibility hash;
- missing rollback baseline hash;
- missing support/recovery binding;
- object storage authority broadening;
- mirror, frontend, signer, shell, model, or TUI authority broadening.

## Next Task

After this contract, RC8-003 must define how public signature artifacts are ingested and receipted without private signing material. RC8-010 may then project a concrete descriptor from current build artifacts, but it must remain blocked until public signature ingestion and installer VM smoke prove the full chain.
