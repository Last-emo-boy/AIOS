# Ecosystem Channel Policy

## Purpose

AgentOS channels describe where ecosystem artifacts come from and which promotion gates they must pass. Channels do not grant runtime authority. Every activation still goes through AgentCore PlanSpec, SecurityExecutionEngine, audit, rollback and replay.

## Channel Metadata

Every registry snapshot entry must carry:

- `trust_tier`: `core`, `verified`, `organization`, `community` or `local-dev`
- `channel`: `stable`, `beta`, `edge` or `local`
- `publisher`
- `manifest_digest`
- `artifact_digest`
- `revoked`
- `advisory_refs`
- runtime compatibility range

Trust tier and channel are separate. A local snapshot can contain a core artifact, a community artifact or a local-dev artifact. Local path placement never upgrades trust.

## Defaults

`core` on `stable` is enabled by default for Production Distro release images. It must be pinned by release provenance and replay evidence.

`verified` is disabled until the signed publisher, signed registry snapshot, lockfile, replay evidence and revocation metadata are present.

`organization` is disabled until the organization policy overlay explicitly allows the artifact and the overlay narrows or extends behavior without weakening baseline invariants.

`community` is discoverable and stageable only after schema and digest verification. It is sandbox-only by default and cannot broaden host authority.

`local-dev` is allowed only for developer-mode fixtures and replay authoring. It is never production-promotable by default.

## Promotion Rules

Production promotion requires:

- signed manifest and artifact archive for `core`, `verified` and `organization`
- pinned snapshot and deterministic lockfile
- replay evidence
- compatibility evidence
- revocation metadata
- exact approval when authority broadens
- rollback handle and audit range

Blocked by default:

- unsigned production artifact
- `community` to production
- `local-dev` to production
- `edge` to production
- artifact with stale or missing revocation state
- artifact that disables no-shell, exact approval, secret-handle, source-to-sink, audit or rollback invariants

## Offline And Pinned Snapshots

Offline operation uses pinned local snapshots. Snapshot pinning preserves availability but does not change trust. If revocation metadata is stale, production activation fails closed unless an organization emergency policy explicitly degrades the active artifact and records the decision for support.

## Operator Visibility

Operator projection and support bundles must show trust tier, channel, active artifact state, revocation status and replay gate status without exposing raw secrets or private key paths.
