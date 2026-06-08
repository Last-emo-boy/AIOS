# Large Payload Storage Policy And External Object Storage Boundary

## Scope

RC7-022 closes the storage gap left after signed metadata, revocation, compatibility, rollback baseline, mirror frontend, and TLS evidence. The public mirror at `aios.w33d.xyz` is now HTTPS-capable, but the host remains a small metadata mirror. It must not become the long-term byte store for ISO, disk image, rootfs, update bundle, or recovery image payloads.

This policy defines how AIOS may reference large payload bytes without widening mirror, signer, installer, TUI, model, shell, support, fleet, activation, rollback, or production ring authority.

## Storage Decision

`47.101.11.109` remains `metadata-only`.

Allowed on the mirror:

- public channel metadata;
- install bootstrap metadata;
- payload manifest, checksums, signatures, signed metadata, revocation snapshot, compatibility, and rollback baseline metadata;
- small support/recovery metadata;
- static frontend assets;
- redacted evidence summaries.

Not allowed on the mirror:

- large ISO, disk image, rootfs, update bundle, recovery image, package archive, or VM image bytes;
- upload endpoints;
- mutable object storage credentials;
- private signing material;
- activation, install, rollback, fleet dispatch, support upload, shell, model, or TUI authority.

Large payload bytes must live behind an external object storage boundary. Acceptable storage classes are S3-compatible object storage, provider object storage, or an equivalent immutable HTTPS object store. The provider choice is intentionally deferred; RC7 freezes the contract so the installer and metadata can be built without committing the small mirror host to bulk storage.

## Object Reference Contract

Payload metadata may reference external objects only through public, immutable, hash-bound object descriptors.

Each object descriptor must include:

- `release_id`;
- `object_id`;
- `kind`: `iso`, `disk-image`, `rootfs`, `update-bundle`, or `recovery-image`;
- `uri`: HTTPS URL or provider-neutral object reference resolved through a trusted HTTPS gateway;
- `size_bytes`;
- `sha256`;
- optional `sha512`;
- `content_type`;
- optional `compression`;
- optional `range_request_supported`;
- `immutable`: true;
- `published_at`;
- `storage_provider_class`;
- `mirror_metadata_sha256`;
- `manifest_sha256`;
- `checksums_sha256`;
- `signed_metadata_sha256`;
- `revocation_snapshot_sha256`;
- `compatibility_sha256`;
- `rollback_baseline_sha256`;
- `policy_version`.

The descriptor must not include credentials, presigned URLs with embedded secrets, bearer tokens, cookies, mutable upload URLs, or provider admin endpoints. Short-lived signed download URLs may be produced by a future broker only as an installer-local fetch step, never as persistent mirror metadata.

## Trust Model

Object storage is transport, not trust.

The installer, updater, or bootstrap client may download bytes from object storage only after it has fetched and locally verified:

- mirror metadata over HTTPS;
- schema and freshness;
- manifest hash;
- checksum set hash;
- signed metadata hash;
- cryptographic signature;
- revocation snapshot and key status;
- installer compatibility;
- rollback baseline;
- release provenance binding;
- exact operator approval when the operation moves beyond preflight.

Downloaded payload bytes are unusable until their local digest equals the hash-bound object descriptor. Object storage compromise, CDN drift, stale cache, range truncation, wrong content type, wrong content length, or byte hash mismatch must force `verification-blocked`.

## Publication Rules

Publishing an external object reference may update:

- `/payloads/index.json`;
- `/payloads/aios/<release-id>/manifest.json`;
- `/payloads/aios/<release-id>/checksums.json`;
- `/payloads/aios/<release-id>/signatures.json`;
- `/payloads/aios/<release-id>/signed-metadata.json`;
- `/install/bootstrap.json`;
- `/channel/index.json`;
- frontend display metadata.

Publishing an external object reference must not:

- upload large bytes to `47.101.11.109`;
- authorize install;
- authorize activation;
- authorize rollback execution;
- mutate active slots;
- mutate production rings;
- enable support upload;
- enable remote dispatch;
- turn the mirror into a signer;
- grant TUI, model, shell, or frontend authority.

## Size And Retention Policy

The mirror host keeps metadata small:

- individual JSON metadata files should stay below 512 KiB unless a later policy raises the ceiling;
- frontend assets should stay small enough for static mirror operation;
- large payload bytes have no place under `/srv/aios-mirror`;
- object storage retention is release-channel policy, not nginx policy;
- old payload objects must remain immutable until the channel explicitly revokes or expires them;
- metadata may remove object references only with revocation and rollback implications recorded.

## Installer Behavior

The installer must treat storage as a separate gate:

1. Fetch mirror metadata from `https://aios.w33d.xyz/` or a pinned equivalent.
2. Verify schema, freshness, hashes, signature, revocation, compatibility, and rollback baseline.
3. Confirm the object descriptor is immutable, HTTPS-bound, size-bounded, and credential-free.
4. Download object bytes into a quarantine path.
5. Verify byte length and digest before any extraction, mount, install, or activation step.
6. Produce a preflight report with object URI, expected hash, actual hash, size, storage class, and failure reason.
7. Require exact operator approval and SecurityExecutionEngine ownership before any side effect.

The installer must fail closed for missing storage policy, unapproved object class, non-HTTPS URL, credential-bearing URL, mutable URL, missing size, missing hash, byte mismatch, stale metadata, revoked key, missing rollback baseline, missing compatibility, or unresolved declared/current hash drift.

## Operational Boundary

Future object storage credentials, if any, must be handled as secret handles outside the repo and outside the mirror. The mirror may publish public metadata about object availability, but it must not receive upload credentials or perform provider-side mutation.

A future publisher may upload large payload bytes to object storage only through a dedicated release pipeline with:

- content-addressed object names;
- immutable object lock or equivalent policy;
- digest verification after upload;
- release evidence hash;
- public metadata update after upload verification;
- no private signing material on the mirror;
- no install, activation, rollback, support upload, or fleet authority.

## Current RC7 State

RC7-022 does not upload payload bytes and does not make the payload installable.

Current blockers after this policy:

- real cryptographic payload signature is still not present;
- prior signed metadata byte-hash canonicalization remains pending;
- object storage provider and upload evidence are not selected yet;
- installer object-fetch implementation and quarantine verification are not implemented yet;
- exact operator approval is not granted;
- canary target enrollment and controlled execution evidence remain pending.

The next RC7 work may move from mirror infrastructure back into the AIOS execution chain: exact canary approval packet, gated canary activation evidence, and rollback drill evidence under AgentCore PlanSpec and SecurityExecutionEngine.
