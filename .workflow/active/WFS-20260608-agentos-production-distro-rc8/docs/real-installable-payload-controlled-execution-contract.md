# Real Installable Payload And Controlled Execution Smoke Contract

## Scope

RC8 starts after the RC7 final audit. RC7 proved signed metadata projection, revocation snapshot projection, installer compatibility metadata, rollback baseline metadata, HTTPS mirror hardening, canary activation denial, and rollback drill denial. The channel is still not GA because it has no real cryptographic payload signature, no real installable payload byte publication, no installer VM smoke, no executed canary activation, and no rollback drill execution through AgentCore and SecurityExecutionEngine.

This RC8 contract defines how AIOS moves from metadata-only projections to real installable payload bytes and controlled execution smoke. It does not by itself perform signing, upload large bytes to the mirror host, install, activate, rollback, mutate boot metadata, mutate active slots, mutate production rings, upload support bundles, dispatch remote fleet actions, or grant authority to the TUI, frontend, shell, model replay, mirror, or signer.

## Payload Byte Boundary

RC8 may introduce real installable payload byte evidence only through immutable object descriptors. The small mirror host remains metadata-only. Large ISO, disk image, rootfs, update bundle, recovery image, package archive, or VM image bytes must not be stored under the mirror root.

Each real payload byte candidate must have an object descriptor that records:

- `release_id`;
- `object_id`;
- `kind`;
- HTTPS object URI or provider-neutral immutable object reference;
- `size_bytes`;
- `sha256`;
- optional stronger digest;
- content type;
- compression, if any;
- range request support, if relied upon;
- immutable flag;
- published timestamp;
- storage provider class;
- manifest hash;
- checksum set hash;
- signed metadata hash;
- revocation snapshot hash;
- installer compatibility hash;
- rollback baseline hash;
- policy version.

The descriptor must not contain credentials, bearer tokens, cookies, mutable upload URLs, provider admin endpoints, secret handles, or short-lived signed URLs embedded into persistent mirror metadata.

## Public Signature Artifact Ingestion

RC8 may ingest public signature artifacts for the payload object descriptor and related metadata. The ingestion boundary is public artifacts only:

- algorithm;
- key id or public key identity;
- signed object hash;
- detached signature or signed metadata envelope;
- signing timestamp;
- signer audit id;
- signer endpoint identity;
- revocation snapshot binding;
- freshness window.

The repo, mirror, frontend, installer smoke, workflow evidence, and TUI must not read, print, copy, hash, move, or operate private signing material. A signer endpoint may return public signature artifacts, but it must not install, activate, rollback, mutate slots, mutate rings, upload support bundles, or dispatch fleet actions.

## Installer VM Smoke Boundary

RC8 installer VM smoke may:

- fetch mirror metadata over HTTPS with DNS or resolve-pinned validation;
- fetch the immutable object descriptor;
- download real payload bytes only into a quarantine path;
- verify schema, freshness, object URI policy, size, digest, manifest, checksum set, public signature artifact, revocation snapshot, installer compatibility, rollback baseline, and release provenance binding;
- report exact blockers and evidence paths;
- prove negative fail-closed cases with local fixtures.

RC8 installer VM smoke may not:

- install to an active rootfs from contract work alone;
- activate a release because bytes are reachable;
- mutate boot metadata, active slots, active artifact sets, persistent state, or production rings;
- use private signing material;
- bypass AgentCore PlanSpec or SecurityExecutionEngine for any side effect;
- treat mirror, object storage, signer, frontend, shell, model replay, or TUI output as authority.

## Controlled Execution Boundary

Canary activation and rollback drill work may proceed only after the payload bytes and public signature artifacts pass local verification and the execution packet is bound to:

- exact operator approval actor, scope, release id, payload digest, target nodes, expiry, and policy version;
- two or more enrolled canary target nodes for fleet canary claims;
- AgentCore PlanSpec id and hash;
- SecurityExecutionEngine policy decision and effect envelope;
- rollback baseline and support/recovery references;
- audit journal and recovery report output paths.

If any gate is missing, the expected result is a denial artifact, not a side effect.

## Fail-Closed Rules

RC8 must remain `verification-blocked` or `execution-blocked` for:

- missing object descriptor;
- mutable or credential-bearing object URI;
- object descriptor hash mismatch;
- missing object size or digest;
- quarantined byte length mismatch;
- quarantined byte digest mismatch;
- stale metadata or freshness expiry;
- missing public signature artifact;
- signature object hash mismatch;
- unknown, revoked, or unbound public key identity;
- missing or stale revocation snapshot;
- missing installer compatibility metadata;
- target compatibility mismatch;
- missing rollback baseline;
- rollback baseline hash mismatch;
- unresolved declared/current artifact drift;
- missing installer VM smoke;
- missing exact operator approval;
- insufficient canary target count;
- missing AgentCore PlanSpec;
- missing SecurityExecutionEngine approval;
- any authority broadening by mirror, signer, frontend, TUI, shell, model replay, or object storage.

## RC8 Task Direction

RC8 execution should proceed in this order:

1. Define immutable payload object descriptors and the real byte boundary.
2. Define public signature artifact ingestion and receipt rules.
3. Project the real installable payload object descriptor from current build artifacts.
4. Ingest public signature artifacts without private key use.
5. Verify signed object descriptor and installer negative fail-closed fixtures.
6. Run installer VM preflight and quarantined object-fetch smoke.
7. Refresh mirror metadata and frontend consistency for RC8, including the current health endpoint.
8. Produce exact-approved canary activation smoke only through AgentCore and SecurityExecutionEngine.
9. Execute or deny rollback drill through AgentCore rollback PlanSpec and SecurityExecutionEngine gates.
10. Close RC8 with final audit and keep `production_ready_claim=false` unless every GA gate is proved.
