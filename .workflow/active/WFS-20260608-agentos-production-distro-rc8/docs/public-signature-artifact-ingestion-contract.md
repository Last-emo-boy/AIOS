# Public Signature Artifact Ingestion And Receipt Contract

## Scope

RC8-003 defines how AIOS may ingest public signature artifacts for a real payload object descriptor. It connects the RC8 real payload contract and immutable object descriptor contract to the later signature ingestion implementation, while keeping private signing material outside the repo, mirror, installer smoke, workflow evidence, and TUI.

This contract does not generate signatures, read signing secrets, install, activate, rollback, mutate boot metadata, mutate active slots, mutate production rings, upload support bundles, dispatch remote fleet actions, or grant signer, mirror, frontend, shell, model, or TUI authority.

## Signature Artifact Shape

Each public signature artifact must be a small JSON object with:

- `schema`: `agentos.public-signature-artifact.v1`;
- `release_id`;
- `object_id`;
- `signature_id`;
- `signature_kind`: `detached-signature` or `signed-metadata-envelope`;
- `algorithm`;
- `key_id`;
- `public_key_identity`;
- `signed_object_sha256`;
- `signed_object_descriptor_sha256`;
- `canonical_payload_sha256`;
- `signature_value`;
- `signature_encoding`;
- `signed_at`;
- `signer_endpoint_identity`;
- `signer_audit_id`;
- `revocation_snapshot_sha256`;
- `revocation_status_at_signing`;
- `freshness_not_before`;
- `freshness_not_after`;
- `receipt_policy_version`;
- `production_ready_claim`: must remain false unless a later final audit changes it.

The artifact is public verification input. Its presence does not authorize install or execution.

## Ingestion Boundary

The ingestion step may:

- read the payload object descriptor;
- read public signature artifacts from a controlled inbox or HTTPS endpoint;
- validate schema and canonical target binding;
- verify that `signed_object_descriptor_sha256` matches the descriptor bytes;
- verify that `signed_object_sha256` matches the byte digest declared by the descriptor;
- verify that revocation snapshot binding exists;
- verify freshness windows;
- record hash-only custody and receipt metadata;
- publish public signature metadata to mirror endpoints only after validation;
- emit exact blockers when verification is incomplete.

The ingestion step must not:

- read, print, hash, move, copy, or operate private signing material;
- accept broad signer commands;
- let the signer write mirror metadata directly;
- let the mirror sign anything;
- call install, activation, rollback, support upload, remote dispatch, shell, model, or TUI actions;
- treat signature availability as enough to install;
- mutate active release state.

## Receipt Boundary

Each ingestion must produce a receipt before later installer smoke can trust the signature artifact as candidate input.

The receipt must include:

- signature artifact path or endpoint identity;
- signature artifact SHA-256;
- descriptor SHA-256;
- signed object SHA-256;
- canonical payload SHA-256;
- revocation snapshot SHA-256;
- signer audit id;
- ingestion timestamp;
- verification status;
- rejection reasons, if blocked;
- no private-material indicators;
- publication eligibility;
- downstream installer gate state.

The receipt may include the public signature value if the artifact itself is public. It must not include private material, secret handles, tokens, cookies, provider credentials, operator approval tokens, or raw support bundle contents.

## Canonical Payload Binding

The signed object must be deterministic. RC8 signature ingestion must bind these values:

- payload object descriptor bytes;
- descriptor hash;
- release id;
- object id;
- object byte digest;
- manifest hash;
- checksum set hash;
- compatibility hash;
- rollback baseline hash;
- revocation snapshot hash;
- policy version.

If canonicalization changes, the previous signature artifact must be treated as stale until a new artifact and receipt prove the updated payload binding.

## Publication Rules

Validated public signature artifacts may update:

- `/payloads/aios/<release-id>/signatures.json`;
- `/payloads/aios/<release-id>/signed-metadata.json`;
- `/payloads/index.json`;
- `/install/bootstrap.json`;
- `/channel/index.json`;
- static frontend status.

Publication must keep:

- `install_allowed=false` until installer VM smoke and policy gates pass;
- `activation_allowed=false` until exact approval, target enrollment, AgentCore PlanSpec, and SecurityExecutionEngine approval pass;
- `rollback_execution_allowed=false` until rollback PlanSpec and SecurityExecutionEngine rollback approval pass;
- `production_ready_claim=false` until final audit proves GA gates.

## Fail-Closed Rules

Signature ingestion must fail closed for:

- missing signature artifact;
- malformed signature artifact;
- wrong schema;
- wrong release id;
- wrong object id;
- unknown algorithm;
- missing key id;
- missing public key identity;
- descriptor hash mismatch;
- signed object hash mismatch;
- canonical payload hash mismatch;
- missing signature value;
- invalid signature encoding;
- stale signing timestamp;
- missing signer audit id;
- missing revocation snapshot binding;
- revoked key status;
- stale revocation snapshot;
- freshness window mismatch;
- artifact replay from another release or object;
- signer authority broadening;
- mirror authority broadening;
- installer authority broadening;
- TUI, shell, model, support upload, remote dispatch, activation, rollback, active slot, or production ring authority broadening.

## Next Task

After this contract, RC8-010 may project a real installable payload object descriptor from current build artifacts. RC8-011 must then ingest public signature artifacts through this boundary. Until those tasks pass, the channel remains `verification-blocked`.
