# Support Bundle Upload Policy

## Status

This is a Console Beta design document. Support bundle upload is future work and is not enabled by the baseline.

The only baseline action is local support bundle export through the typed TUI command. Exported bundles remain local evidence projections with redaction applied before any file is written. No hosted support service, remote upload endpoint, background sync, automatic ticket attachment or remote support authority is part of Console Beta.

## Baseline Behavior

`support.bundle export` writes a local bundle only. The TUI may render support status, evidence paths and degraded-state guidance, but it does not upload, sync, retry network transfers or make a remote destination authoritative.

Baseline invariants:

- `local_only=true`
- `upload_enabled=false`
- `automatic_upload=false`
- `background_sync=false`
- `remote_support_authority=false`
- `local_audit_authoritative=true`
- `remote_authoritative_for_recovery=false`
- `redaction=secret-values-redacted`
- `includes_raw_secret=false`

If a support endpoint is absent, unavailable or untrusted, the system remains operable in local-only mode.

## Upload Preconditions

A future upload implementation must require all of the following before any bytes leave the node:

1. A locally exported bundle whose manifest is valid and whose hash is shown to the operator.
2. Redaction status `secret-values-redacted` with explicit checks for raw prompts, raw observations, raw secrets, private key paths, bearer tokens, passwords and environment dumps.
3. A trusted destination record pinned by organization policy or local operator configuration.
4. Destination trust evidence covering endpoint identity, expected public key or certificate pin, retention policy and support case scope.
5. Exact operator approval bound to bundle id, bundle hash, destination id, case id, actor, expiry and policy version.
6. A SecurityExecutionEngine-mediated upload PlanRun with audit events for approval, prepare, observed result and final seal.
7. A local retry budget and local cancellation path.

The future upload command should be modeled as `support.bundle.upload.preview` before any real upload verb exists. Preview must be deterministic and must not contact the network.

## Allowed Metadata

The following may be uploaded after the preconditions above pass:

- support bundle manifest
- redacted runtime projection
- redacted recovery projection
- redacted audit excerpts
- release provenance hash and gate summary
- ecosystem registry snapshot hash, active set hash and replay status
- local degraded-state explanation
- local node identity projection without credentials
- operator-selected case id or support ticket reference

The following must remain local:

- raw prompts, raw model outputs and raw observations
- raw secrets and secret values
- private key paths and private key material
- enrollment tokens, bearer tokens, passwords and cookies
- unredacted audit journal
- unredacted filesystem paths that contain secret-like values
- local policy override files unless separately reviewed
- rollback payloads and shadow diff contents unless explicitly redacted and separately approved

## Destination Trust States

The future UI should project destination state without uploading:

- `not-configured`: no upload destination is configured; baseline local export remains valid.
- `trusted`: destination identity, pin and retention policy match local policy.
- `untrusted`: destination identity, pin or retention policy does not match.
- `stale`: destination trust record exists but is expired.
- `disabled`: organization or local policy forbids upload.
- `failed`: a prior upload attempt failed; local bundle remains authoritative.

Only `trusted` may be eligible for future upload approval. All other states are fail-closed.

## Approval Binding

Future upload approval must be exact. Broad approvals such as "upload diagnostics" are not enough.

The approval token must bind:

- bundle id
- bundle content hash
- destination id
- destination trust record hash
- support case id
- actor
- policy version
- expiry
- redaction policy version

Changing any bound value invalidates the approval and returns to preview.

## Failure Policy

Upload failure cannot mutate local runtime state, active artifacts, rollback handles or audit authority.

Fail-closed cases:

- destination is missing, untrusted, stale or revoked
- redaction status is missing or not `secret-values-redacted`
- bundle hash changes after approval
- network is unavailable
- endpoint certificate or key pin mismatches
- upload response cannot be audited locally
- retry budget is exhausted
- operator cancels or approval expires

The local bundle remains available for manual inspection after failure.

## TUI Boundary

The TUI may show upload readiness, destination trust and preview text. It may not:

- upload directly
- own destination trust decisions
- bypass local redaction
- bypass exact approval
- make remote support authoritative for recovery
- mutate bundle contents after approval
- clear support blockers

Any future upload must enter AgentCore as a PlanRun and use SecurityExecutionEngine for the network side effect.

## Evidence Required Before Implementation

Before implementing upload execution, the project needs:

- redaction test fixtures for prompts, model output, observations, audit excerpts and path-like secrets
- destination trust schema and pin verification tests
- approval binding tests for bundle hash and destination hash mutation
- upload failure smoke test proving local state is unchanged
- support bundle replay artifact in release provenance
- operator registry entry marked `preview` until execution is implemented
- final RC0 audit confirming upload is optional and local-only baseline still passes without network

## Non-Goals

- No automatic upload.
- No remote support authority in Console Beta.
- No background diagnostics sync.
- No weaker redaction for uploaded bundles.
- No upload from TUI without AgentCore and SecurityExecutionEngine mediation.
