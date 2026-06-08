# Installable Signed Payload Channel Contract

## Scope

RC6 starts after the RC5 final audit. RC5 proved that `aios.w33d.xyz` can serve metadata-only mirror, channel, bootstrap, canary proof, and support/recovery metadata without gaining signing, activation, rollback, production ring, remote dispatch, support upload, or TUI authority.

RC6 moves the AIOS distribution path toward an Ubuntu-like installable channel. The new work is not to make the mirror trusted by itself. The work is to publish inspectable, hash-bound payload metadata that an AIOS bootstrap or installer can verify before any install or activation is allowed.

## Channel Shape

The payload channel may expose small metadata under these paths:

- `/payloads/index.json`: channel-level index for installable payload metadata.
- `/payloads/aios/<release-id>/manifest.json`: content-addressed payload manifest.
- `/payloads/aios/<release-id>/checksums.json`: expected content hashes for payload files.
- `/payloads/aios/<release-id>/signatures.json`: public detached signature references or signed metadata references.
- `/install/bootstrap.json`: installer/bootstrap preflight metadata.
- `/releases/README.txt`: still allowed as a human-readable non-GA placeholder.

The RC6 mirror must not host large image payloads until a storage policy exists. On the current limited host, RC6 may publish metadata, manifests, hashes, public signature references, and placeholder descriptors only.

## Payload Trust Inputs

An installable payload candidate must bind:

- RC5 final audit hash.
- RC5 hosted support/recovery result hash.
- RC5 canary proof result hash.
- Current release provenance hash.
- Current installable media or image manifest hash, when present.
- Payload manifest hash.
- Payload content hashes.
- Public signature or signed metadata reference.
- Revocation snapshot hash.
- Rollback baseline hash.
- Installer compatibility contract.

Reachability of `aios.w33d.xyz` is not trust. Payload trust is local verification of schema, hashes, signatures, revocation, freshness, compatibility, and rollback metadata.

## Installer Boundary

The bootstrap or installer may:

- Fetch hosted payload metadata.
- Explain which payloads are placeholders, deferred, or candidates.
- Verify schema, hash bindings, signatures, revocation, freshness, compatibility, and rollback baseline.
- Produce a preflight report for the operator.

The bootstrap or installer may not:

- Install unsigned payloads.
- Treat metadata reachability as trust.
- Read private signing material.
- Substitute local or remote signatures.
- Activate a release from mirror metadata alone.
- Bypass AgentCore PlanSpec and SecurityExecutionEngine for side effects.
- Mutate active slots or production rings.

## Authority Boundary

The hosted mirror is transport only:

- Signing authority remains external to the mirror.
- Payload verification happens in the installer/bootstrap client.
- Activation remains AgentCore PlanSpec plus SecurityExecutionEngine.
- Rollback execution remains SecurityExecutionEngine-owned and requires rollback baseline evidence.
- Fleet canary execution remains exact-operator-approval gated.
- TUI remains projection-only.

## Fail-Closed Rules

The payload channel must fail closed for:

- Missing payload manifest.
- Malformed schema.
- `production_ready_claim=true` in RC6 metadata.
- Missing RC5 final audit binding.
- Missing release provenance binding.
- Missing signature or signed metadata reference.
- Hash mismatch.
- Revoked signing key or missing revocation snapshot.
- Stale metadata outside freshness window.
- Oversized payload reference before storage policy is upgraded.
- Missing rollback baseline.
- Missing installer compatibility contract.
- Any advertised signing, activation, rollback execution, production ring mutation, remote dispatch, support upload, or TUI authority.

## RC6 Completion Direction

RC6 is complete only when the repo contains evidence for:

- A signed payload metadata contract.
- A hosted payload metadata projection.
- Installer/bootstrap preflight consumption.
- Fail-closed payload metadata fixtures.
- Canary execution packet and rollback execution preconditions.
- Final audit that still records non-GA status unless TLS, signed payloads, installer consumption, canary execution, rollback execution, storage, and monitoring evidence all exist.
