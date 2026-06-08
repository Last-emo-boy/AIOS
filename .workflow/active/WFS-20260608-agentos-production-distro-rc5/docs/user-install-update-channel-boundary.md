# User Install And Update Channel Boundary

## Scope

RC5 makes AIOS more distribution-shaped by allowing users and bootstrap tools to fetch public metadata from `aios.w33d.xyz`. This document defines what a user-facing install or update client may trust from that hosted mirror, and what it must verify locally before any install, update, activation, rollback, or canary action.

The mirror is a transport. It is not a root of trust.

## User-Facing Flow

A user-facing AIOS bootstrap or updater may:

- Resolve `aios.w33d.xyz`.
- Fetch `/health.json`.
- Fetch `/.well-known/aios/mirror.json`.
- Fetch `/channel/index.json`.
- Fetch small release metadata under `/releases/`.
- Download future release payloads only after RC5 upgrades storage policy and records new evidence.

Before trusting any fetched metadata, the client must verify:

- Metadata schema and version.
- `production_ready_claim=false` for RC5.
- RC4 final audit hash binding.
- Hosted transport manifest hash binding.
- Mirror publication hash binding.
- Public signature bundle or signed channel metadata, when present.
- Revocation metadata.
- Freshness window.
- Content-addressed artifact hashes.
- Rollback baseline metadata for any update path.

## Install Boundary

Initial RC5 install is a bootstrap projection, not a GA installer promise.

An RC5 bootstrap client may explain:

- Which release channel is available.
- Which metadata hashes are expected.
- Which payloads are placeholders or deferred.
- Which verification checks must pass before installation.
- Why activation is blocked until release payload, signature, rollback, and canary evidence exist.

An RC5 bootstrap client may not:

- Install unsigned payloads.
- Treat mirror reachability as trust.
- Substitute local or remote signatures.
- Read private signing material.
- Activate a release from mirror metadata alone.
- Bypass AgentCore PlanSpec and SecurityExecutionEngine for side effects.

## Update Boundary

An RC5 update client must treat `/channel/index.json` as candidate metadata only. The update path requires:

- Existing active artifact set hash.
- Candidate artifact set hash.
- Signature verification result.
- Revocation result.
- Rollback baseline hash.
- Exact operator approval for activation or canary.
- SecurityExecutionEngine execution evidence.

If any field is missing, stale, mismatched, unsigned, revoked, oversized, or authority-broadening, the update must fail closed.

## UX Requirements

User-facing text should make these states explicit:

- `metadata-only`: service framework exists, release payload storage is deferred.
- `candidate`: metadata can be inspected and verified, but not activated.
- `blocked`: a required trust, freshness, revocation, rollback, or canary check is missing.
- `non-ga`: RC5 does not claim general availability.

The user should never be asked to "trust the mirror" manually. The system should present concrete checks and blockers.

## Completion Criteria

RC5-002 is complete when this boundary exists, the evidence records `mirror_is_not_root_of_trust=true`, installer/update authority remains AgentCore plus SecurityExecutionEngine, and the next executable task is `RC5-003`.
