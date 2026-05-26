# Remote Registry Mirror UX

## Status

This is a Console Beta design document. Remote registry mirrors are optional future UX and are not baseline authority.

The baseline source of ecosystem truth remains the pinned local registry snapshot, local lockfile, staged set, active set and local replay evidence. Network availability must not be required to operate AgentOS, inspect artifacts, recover runs or validate the current active set.

## Baseline Authority

Console Beta uses local evidence first:

- registry source: pinned local snapshot
- resolver baseline: local snapshot plus lockfile
- activation baseline: AgentCore PlanSpec plus SecurityExecutionEngine
- support baseline: local redacted support bundle
- audit baseline: local AuditJournal
- replay baseline: local ecosystem replay artifact

A mirror may provide update hints, freshness metadata or a candidate snapshot download path in future work. It may not silently override local pinned content, active artifacts, lockfile hashes or operator approvals.

## Mirror Status States

The TUI should use explicit mirror states:

- `not-configured`: no remote mirror is configured; local baseline remains healthy if the pinned snapshot is fresh.
- `available`: mirror endpoint, signature and trust metadata are visible and consistent with policy, but still not authoritative.
- `stale`: mirror metadata is older than policy allows or does not improve on the local snapshot.
- `failed`: mirror cannot be reached, response cannot be parsed or network is unavailable.
- `untrusted`: endpoint identity, signature, channel, trust tier or provenance binding does not match policy.
- `disabled`: local or organization policy forbids remote mirror use.

No state should be named `authoritative`. The UI should prefer `available-for-preview` or `candidate-refresh-available` when a mirror can be inspected.

## Snapshot Expiry UX

Expired local snapshot handling stays fail-closed unless an explicit future refresh policy allows a mirror-backed refresh PlanRun.

Operator projection should show:

- local snapshot id, digest and expiry
- snapshot freshness: `fresh`, `expiring-soon`, `expired` or `missing`
- local lockfile hash and active set hash
- mirror status and last successful mirror check, if any
- safe next action such as `aom.verify` or future `registry.refresh.preview`
- failure reason when verification is blocked

When a local snapshot is expired, the UX should say that activation and resolution are blocked by local policy. A reachable mirror can be shown as a candidate source only; it cannot make the expired local snapshot valid by implication.

## Mirror Failure UX

Network or mirror failure must not break local baseline operation when the pinned local snapshot is still fresh.

The UI should distinguish:

- `local-baseline-ready`: pinned snapshot and replay evidence pass; mirror failure is informational.
- `local-baseline-degraded`: local snapshot is missing or expired; mirror status is not enough to proceed.
- `mirror-failed-closed`: mirror result is unusable for refresh and no non-local side effects were prepared.
- `mirror-disabled`: configured policy prevents contacting the mirror.

Mirror failure must never trigger automatic fallback to a different remote endpoint.

## Trust And Signature Display

A mirror preview must render trust and signature facts before any refresh action exists:

- mirror id and configured endpoint fingerprint
- endpoint certificate or key pin status
- registry snapshot digest
- detached signature status
- signer key id and production key requirement
- channel and trust tier
- provenance hash
- SBOM hash when supplied
- revocation/advisory status
- policy version used for evaluation

The UI must show `signature_status=missing`, `signature_status=invalid`, `trust_status=untrusted` or `revocation_status=revoked` as blockers. It must not collapse these into a generic unavailable state.

## Future Refresh Flow

A future mirror-backed refresh must be a local PlanRun:

1. Preview mirror metadata without mutating local registry state.
2. Verify endpoint identity and pinned trust record.
3. Verify detached signature, provenance, SBOM and revocation data.
4. Compare candidate snapshot digest to local policy constraints.
5. Bind exact operator approval to mirror id, candidate digest, trust record hash, policy version and expiry.
6. Stage the candidate snapshot inertly.
7. Run ecosystem replay against the candidate snapshot.
8. Commit the new pinned local snapshot only through SecurityExecutionEngine.
9. Preserve rollback evidence for the previous snapshot and lockfile.

Until this flow exists and passes RC0 evidence, mirror status remains projection-only.

## Fail-Closed Rules

Fail closed if:

- local snapshot is expired and no approved refresh PlanRun exists
- mirror endpoint is unavailable or returns malformed content
- endpoint identity or pin mismatches
- detached signature is missing or invalid
- signer is not allowed for the channel
- revocation data blocks an artifact
- candidate snapshot digest does not match approval
- replay fails against the candidate snapshot
- rollback evidence for previous snapshot is missing
- policy attempts to make network a baseline dependency

Fail-closed means no active artifacts, staged artifacts, lockfiles or local snapshot files are mutated.

## TUI Boundary

The TUI may render mirror state, trust facts, expiry explanation and preview commands. It may not:

- fetch from the network directly
- replace the local snapshot
- weaken local expiry policy
- create hidden approvals
- make mirror data authoritative
- bypass AOM resolver rules
- bypass SecurityExecutionEngine for snapshot commit

The first executable implementation must live outside the TUI display layer and must preserve `aom install/stage is inert` and `aom activate is runtime-mediated`.

## Evidence Required Before Implementation

Before real mirror refresh is implemented, RC0 needs:

- mirror trust record schema
- detached signature verification fixtures
- expired local snapshot fail-closed replay
- mirror unavailable and malformed response smoke tests
- candidate snapshot replay gate
- rollback drill for previous local snapshot
- release provenance fields for mirror evaluation evidence
- TUI projection tests showing trust and signature blockers

## Non-Goals

- No silent registry refresh.
- No network requirement for baseline.
- No mirror authority over local active artifacts.
- No remote endpoint fallback without policy and approval.
- No production marketplace governance claim from Console Beta.
