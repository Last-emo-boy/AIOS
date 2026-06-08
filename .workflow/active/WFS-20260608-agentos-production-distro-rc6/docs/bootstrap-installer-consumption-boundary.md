# Bootstrap And Installer Consumption Boundary

## Scope

RC6 introduces installable payload metadata, but the AIOS bootstrap and installer are still verification clients, not trust shortcuts. The hosted mirror can help a user discover payload candidates. It cannot make a payload safe to install.

This boundary covers how a future AIOS bootstrap or installer consumes:

- `/install/bootstrap.json`
- `/payloads/index.json`
- `/payloads/aios/<release-id>/manifest.json`
- `/payloads/aios/<release-id>/checksums.json`
- `/payloads/aios/<release-id>/signatures.json`
- Existing RC5 channel, support, canary, and final audit metadata

## Installer States

The installer must project one of these states:

- `metadata-unavailable`: required hosted metadata could not be fetched or parsed.
- `metadata-candidate`: metadata is available but not fully verified.
- `verification-blocked`: one or more required trust checks failed or are missing.
- `install-preflight-ready`: all metadata checks pass, but install side effects are not yet authorized.
- `install-authorized`: exact operator approval, rollback baseline, and SecurityExecutionEngine execution plan are present.
- `installed`: install evidence is sealed and active state changes are recorded.

RC6 may reach only the first four states. It must not claim `install-authorized` or `installed` until signed payload, approval, execution, and rollback evidence exist.

## Required Verification Sequence

The installer must verify in this order:

1. Fetch health, mirror descriptor, channel index, and bootstrap metadata.
2. Verify schema versions and `production_ready_claim=false`.
3. Verify RC5 final audit hash binding.
4. Verify payload index hash binding to release provenance and RC5 evidence.
5. Verify payload manifest hash.
6. Verify payload content hashes.
7. Verify public signature or signed metadata reference.
8. Verify revocation snapshot and key status.
9. Verify freshness window.
10. Verify installer compatibility contract.
11. Verify rollback baseline hash.
12. Verify storage policy if a payload URL points at large artifacts.
13. Produce a preflight report.

Any failure before step 13 must fail closed.

## Allowed Installer Outputs

The installer may write local, non-authoritative outputs:

- A preflight report.
- A list of missing checks.
- A payload candidate explanation.
- A rollback readiness explanation.
- A support bundle pointer with redacted metadata references.

These outputs are evidence for a future approval flow. They are not install approval.

## Forbidden Side Effects

The bootstrap or installer may not:

- Install files into an active rootfs.
- Change boot metadata.
- Mutate active slots.
- Activate an A/B update.
- Execute rollback.
- Change production ring membership.
- Upload support bundles.
- Read private signing material.
- Dispatch remote commands.
- Treat TUI or model replay as authority.

## Approval Boundary

An install can only become authorized when all are true:

- Payload metadata verification passed.
- Payload signatures or signed metadata verify against public trust roots.
- Revocation snapshot is current and non-blocking.
- Rollback baseline is present.
- Installer compatibility contract is satisfied.
- Exact operator approval binds release id, payload manifest hash, target device, rollback baseline hash, revocation snapshot hash, policy version, actor, and expiry.
- AgentCore creates the PlanSpec.
- SecurityExecutionEngine owns all side effects.

## Fail-Closed Requirements

The installer must fail closed for:

- Missing bootstrap metadata.
- Missing payload index.
- Payload manifest mismatch.
- Missing checksum file.
- Missing signature reference.
- Revoked key.
- Stale revocation snapshot.
- Stale payload metadata.
- Missing rollback baseline.
- Missing compatibility contract.
- Payload URL that exceeds storage policy.
- Metadata that advertises signing, install, activation, rollback, production ring, remote dispatch, support upload, model replay, shell, or TUI authority.

## Completion Criteria

RC6-002 is complete when this boundary exists, task evidence records installer states, verification order, allowed outputs, forbidden effects, approval inputs, and fail-closed cases, and the next executable task is `RC6-003`.
