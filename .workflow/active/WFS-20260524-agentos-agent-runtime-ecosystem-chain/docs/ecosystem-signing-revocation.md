# Ecosystem Signing And Revocation

## Purpose

Signing and revocation define whether an artifact may be promoted, staged or activated in Production Distro. They are evidence gates, not execution authority.

## Signed Objects

Production promotion requires signatures for:

- artifact manifest
- artifact archive or payload digest
- registry snapshot
- deterministic lockfile
- policy packs
- workflow packs
- model profile packs
- knowledge packs
- runtime adapter packs
- execution image packs
- revocation advisory metadata

Candidate hash-bound release signatures are useful for reproducibility, but production verification requires a production trust root and key custody evidence.

## Local-Dev Exception

`local-dev` artifacts may be unsigned only in explicit developer mode. They must be marked non-promotable, sandbox-only and excluded from Production Distro release provenance. Copying a local-dev artifact into a trusted path does not upgrade it.

## Revocation Behavior

Revocation metadata binds advisory id, coordinate, artifact digest, publisher and affected version range. A revoked staged artifact cannot activate. A revoked active artifact becomes degraded and must remain visible in operator projection and support bundles.

Future activation of a revoked artifact fails closed before EffectPrepared. Existing active artifacts are not silently removed; Agent Runtime should plan rollback or replacement through AgentCore and SecurityExecution.

## Key Rotation

Key rotation must be auditable:

- old key id
- new key id
- rotation epoch
- publisher identity
- snapshot digest containing the rotation
- verification outcome

If a publisher key is revoked, all artifacts signed only by that key are blocked from new activation until a non-revoked signature chain is available.

## Production Reaction

Production Distro blocks unsigned production activation, digest mismatch, stale revocation metadata and unknown required fields. Active revoked artifacts are projected as degraded with advisory references and rollback guidance.
