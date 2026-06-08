# Signed Payload Consumption And Controlled Execution Contract

## Scope

RC7 starts from the RC6 final audit. RC6 closed the metadata-only payload channel and installer preflight projection, but the channel is still `verification-blocked`: payload signatures are not published, revocation snapshot is not published, installer compatibility contract is missing, rollback baseline is not published to install metadata, large payload storage policy is deferred, canary execution has not run, rollback execution has not run, and TLS remains a GA gate.

This RC7 contract freezes how AIOS moves from hosted metadata to signed payload consumption and controlled execution evidence. It does not perform signing, installation, activation, canary execution, rollback execution, support upload, remote dispatch, active slot mutation, or production ring mutation.

## Endpoint Shape

RC7 may extend the existing `aios.w33d.xyz` metadata surface with public, cacheable metadata:

- `/payloads/index.json`: channel index, release id, metadata freshness, current verification state.
- `/payloads/aios/<release-id>/manifest.json`: payload manifest and hash-bound release provenance.
- `/payloads/aios/<release-id>/checksums.json`: expected content hashes for every referenced payload object.
- `/payloads/aios/<release-id>/signatures.json`: detached signature or signed metadata references only.
- `/payloads/aios/<release-id>/revocations.json`: revocation snapshot reference, key id status, freshness, and snapshot hash.
- `/install/bootstrap.json`: bootstrap state, install blockers, compatibility and rollback baseline references.
- `/install/compatibility.json`: installer compatibility contract for target architecture, image format, boot path, and minimum agentd/runtime versions.
- `/install/rollback-baseline.json`: rollback baseline hash, rollback preconditions, and recovery metadata references.
- `/execution/canary-packet.json`: exact-approval-gated canary packet projection.
- `/execution/rollback-packet.json`: rollback drill packet projection.

The mirror is transport only. It may host public metadata and public signature artifacts, but it is not a root of trust and must not hold or operate private signing material.

## External Signer Boundary

`sign.w33d.xyz` may become a separate signing endpoint, but RC7 contract work treats it as an external authority boundary:

- The repo, mirror, frontend, installer tests, and workflow evidence must not read, print, copy, hash, or move private key material.
- A signer endpoint may accept exact payload metadata hashes and return only public signature artifacts: algorithm, key id, signature, signed object hash, signing timestamp, signer audit id, and public fingerprint.
- The signer must not install, activate, rollback, mutate slots, mutate rings, upload support bundles, or dispatch fleet actions.
- The mirror must never become the signer; mirror reachability is not payload trust.
- Any signature without matching revocation snapshot, freshness, manifest hash, checksums, compatibility, and rollback baseline remains insufficient for install or execution.

## Consumption State Machine

AIOS clients and installer preflight must model the channel as explicit states:

- `metadata-observed`: metadata fetched and parsed, no trust granted.
- `hash-bound`: manifest, checksums, release provenance, and RC6 final audit binding verify.
- `signature-published`: public signature artifact is present and hash-bound.
- `revocation-current`: revocation snapshot verifies key status and freshness.
- `compatibility-matched`: installer compatibility contract matches target system and release artifacts.
- `rollback-baseline-bound`: rollback baseline and support/recovery references verify.
- `signed-consumption-ready`: local verification has all signed metadata inputs, but install still needs policy and approval gates.
- `controlled-execution-ready`: canary or rollback packet is exact-approved, AgentCore PlanSpec-bound, SecurityExecutionEngine-owned, and target-scoped.
- `verification-blocked`: any missing or mismatched required input forces fail-closed behavior.

RC7 starts in `verification-blocked` and may advance only through evidence-producing tasks.

## Installer Boundary

The bootstrap or installer may:

- Fetch hosted metadata and public signature artifacts.
- Verify schema, content hashes, manifest hash, release provenance, signature, revocation, freshness, installer compatibility, rollback baseline, and TLS evidence.
- Produce a preflight report with exact blockers and evidence paths.
- Prepare a signed-consumption candidate for explicit operator review.

The bootstrap or installer may not:

- Install unsigned, stale, revoked, hash-mismatched, incompatible, or rollback-baseline-missing payloads.
- Treat `signatures.json` reachability as enough to install.
- Read private signing material or call a signer with broad authority.
- Activate a release from mirror metadata alone.
- Mutate boot metadata, active slots, active artifact sets, or production rings.

## Controlled Execution Boundary

Canary activation or rollback drill evidence is allowed only after the signed-consumption gates are satisfied and the execution packet is bound to:

- Exact operator approval actor, scope, release id, payload digest, target nodes, expiry, and policy version.
- AgentCore PlanSpec id and hash.
- SecurityExecutionEngine policy decision and effect envelope.
- Two or more enrolled canary target nodes for fleet canary claims.
- Rollback baseline and support/recovery references.
- Audit journal and recovery report output paths.

Mirror files, frontend UI, signer responses, model replay, normal shell input, and TUI projection cannot directly execute canary or rollback actions.

## Fail-Closed Rules

The channel must remain `verification-blocked` for:

- Missing signature or signed metadata reference.
- Signature object hash mismatch.
- Unknown key id, revoked key id, missing revocation snapshot, stale revocation snapshot, or freshness expiry.
- Missing installer compatibility contract or target mismatch.
- Missing rollback baseline or rollback hash mismatch.
- Missing release provenance, manifest hash, checksum, RC6 final audit, or support/recovery binding.
- Declared/current hash drift that has not been reconciled.
- Large payload URL or upload before storage policy and object storage boundary exist.
- TLS downgrade or missing TLS evidence before GA claim.
- Missing exact operator approval, single canary target, disabled remote fleet execution, or missing SecurityExecutionEngine PlanSpec approval.
- Any advertised signing, install, activation, rollback execution, support upload, remote dispatch, production ring mutation, shell authority, model authority, or TUI authority outside the explicit boundaries above.

## RC7 Task Direction

RC7 execution should proceed in this order:

1. Publish signed metadata and revocation snapshot projection for the current payload candidate without exposing private key material.
2. Define installer compatibility and rollback baseline publication.
3. Prove installer signed consumption and negative fail-closed fixtures.
4. Refresh the mirror frontend so users can inspect signed payload and revocation status.
5. Record TLS, storage, and nginx hardening evidence.
6. Produce exact-approval-gated canary and rollback evidence only after the signed-consumption gates pass.
7. Close RC7 with a final audit that keeps `production_ready_claim=false` unless every GA gate is proved.
