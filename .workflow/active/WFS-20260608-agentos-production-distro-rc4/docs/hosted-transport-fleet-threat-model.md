# Hosted Transport And Fleet Threat Model

## Assets

- RC3 final audit and signed publication evidence.
- Hosted release transport manifest.
- Remote registry mirror snapshot and lockfile.
- Fleet ring plan and target set.
- Rollback baseline.
- Revocation and advisory snapshot.
- Support bundle and recovery projection.

## Trust Boundaries

- Hosted transport is untrusted until hashes match RC3 signed evidence.
- Remote mirrors are untrusted until snapshot, lockfile, signature, freshness, and revocation checks pass.
- Fleet target state is untrusted until observed state matches the approved target set hash.
- TUI and model output are projection and explanation only.
- AgentCore and SecurityExecutionEngine remain the only mutation path.

## Threats

### Hosted Manifest Drift

An attacker changes hosted metadata after approval. RC4 must bind hosted manifest hash into rollout and promotion gates. Drift requires fail-closed and new approval.

### Mirror Replay Or Staleness

A stale or replayed mirror snapshot could present old advisories or revoked artifacts. RC4 must check freshness windows, revocation snapshots, and lockfile hashes.

### Unsigned Or Revoked Mirror Artifact

Unsigned or revoked artifact metadata must not be promotable. Mirror replay must explain the blocker without activating or staging unsafe content.

### Fleet Target Substitution

The target set could change after approval. Exact approval must bind ring id, target set hash, rollout parameters, and policy version.

### Ring Skip

A rollout could skip canary or hold gates. RC4 must model ring transitions and reject out-of-order promotion.

### Rollback Baseline Loss

Rollout without rollback baseline makes recovery ambiguous. RC4 must require previous active artifact set and recovery path before rollout may proceed.

### Remote Control-Plane Authority Creep

Remote services may attempt direct mutation. RC4 must keep remote dispatch non-authoritative unless routed through AgentCore PlanSpec and SecurityExecutionEngine.

### TUI Or Model Authority Creep

Operator UI or model output may attempt to authorize rollout. RC4 must keep both projection-only.

### Support Secret Leakage

Support bundles may include credentials, tokens, or raw secrets. RC4 support projections must redact and fail closed on secret-like content.

## Required Negative Fixtures

- Hosted manifest hash drift.
- Missing RC3 final audit binding.
- Stale mirror snapshot.
- Unsigned mirror metadata.
- Revoked mirror artifact.
- Registry lockfile mismatch.
- Fleet target set drift.
- Ring skip attempt.
- Missing rollback baseline.
- TUI rollout authority attempt.
- Model replay rollout authority attempt.
- Remote dispatch mutation attempt.
- Unredacted support bundle.
