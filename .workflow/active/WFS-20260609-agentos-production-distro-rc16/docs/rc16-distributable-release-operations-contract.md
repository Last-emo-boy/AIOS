# RC16 Distributable Release Operations Contract

RC16 turns RC15 controlled local execution readiness into distributable user-facing release package readiness. The contract is AIOS-body-only: release package metadata, install/update preflight, AgentCore planning, SecurityExecution decisions, rollback/support evidence, and operator explainability must be derived from repo-local, hash-bound evidence.

Mirror output, frontend output, signer reachability, shell output, TUI projection, model replay, remote service reachability, and object storage UI are transport or display surfaces only. They are never release, install, update, activation, rollback, support, recovery, or production authority.

## Source Of Authority

RC16 starts only after RC15 final closeout has proved controlled local execution readiness. RC16 may consume these RC15 facts as prerequisites:

1. Audit sink, nonce, expiry, and policy version are bound.
2. Two real local canary target identities are bound.
3. Exact approval is bound and does not imply execution by itself.
4. AgentCore PlanSpec executable readiness is proved for the controlled local path.
5. SecurityExecution allow is bound before effects.
6. Controlled local activation executed with non-fabricated audit evidence.
7. Separate rollback execution and local support/recovery evidence are bound.

All downstream package, installer, update, rollback, support, and TUI explainability outputs must bind the source evidence they consume. No RC16 task may replace source evidence with endpoint reachability, rendered UI state, normal shell output, model replay, or remote service health.

## Gate Order

Distributable release operation readiness is allowed only in this order:

1. RC15 controlled local execution readiness is the prerequisite.
2. Freeze this RC16 release-operation authority contract.
3. Project the repo-local distributable release package artifact set.
4. Assemble the installable media manifest from current AIOS release bytes.
5. Verify distributable package descriptor fail-closed fixtures.
6. Bind installer and updater preflight package evidence.
7. Bind AgentCore install/update PlanSpec package.
8. Bind SecurityExecution install/update effect envelope and allow/deny evidence.
9. Bind rollback baseline and support/recovery package evidence.
10. Project TUI/operator installability and update readiness as explanation only.
11. Run local release channel consumer smoke that must execute or deny with audit evidence.
12. Close with RC16 final audit.

No later gate may be fabricated from a previous gate. Package descriptor validity does not imply install authority. Installer preflight does not imply AgentCore executable state. AgentCore executable state does not imply SecurityExecution allow. TUI readiness does not imply any effect authority.

## Required Fail-Closed Cases

Each RC16 execution task must deny at least these broadening attempts where relevant:

- Missing, stale, mismatched, unsigned, revoked, broad, duplicate, or replayed package descriptor metadata.
- Missing or mismatched release object digest, manifest digest, checksum set, signature summary, revocation snapshot, freshness window, compatibility contract, rollback baseline, support/recovery reference, or RC15 source evidence.
- Package metadata that claims install, update, activation, rollback, support upload, recovery execution, remote dispatch, production ring mutation, signing, or TUI authority.
- Installer/update preflight that trusts endpoint reachability, frontend output, shell output, signer reachability, model replay, or object storage UI as authority.
- AgentCore PlanSpec or SecurityExecution envelope that broadens from install/update readiness into activation, rollback, remote dispatch, support upload, recovery execution, production mutation, or signing.
- TUI/operator projection that attempts to mutate state, prepare effects, clear blockers, grant approval, or become a source of trust.

## Package Contract

The repo-local distributable package surface must identify the current AIOS release package without uploading, installing, activating, or publishing it. It must bind at least:

- Release id and package descriptor schema.
- Current release bytes and content hashes.
- Installable media manifest reference.
- Checksum set and detached public verification references.
- Revocation and freshness authority references.
- Installer/update compatibility and rollback baseline references.
- RC15 controlled local execution evidence references.
- Explicit `production_ready_claim=false` until final audit proves every scoped gate.

If any required reference is absent, stale, mismatched, broad, or authority-broadening, the package remains denied.

## Install And Update Contract

Installer and updater readiness must remain preflight-only until both AgentCore and SecurityExecution gates are bound. An install/update effect may be prepared only when:

- The repo-local release package artifact set is complete.
- The installable media manifest is hash-bound to current release bytes.
- Descriptor fail-closed fixtures pass.
- Installer/updater preflight evidence is bound.
- AgentCore install/update PlanSpec is executable for the exact package and target.
- SecurityExecution allows the exact install/update effect envelope.
- Rollback/support evidence is bound before any effect authority.

If any condition is false, the install/update path must deny with audit evidence and no effect preparation.

## Rollback And Support Contract

Rollback baseline and support/recovery package evidence must be distributable and explainable, but support upload and recovery execution remain disabled in RC16. Rollback/support package evidence must bind:

- The package identity and install/update PlanSpec identity.
- Rollback baseline and restore expectations.
- Local support bundle redaction policy.
- Recovery reference index.
- Audit trail requirements.
- Explicit denial of support upload, recovery execution, remote dispatch, and production ring mutation.

## Operator Explainability Contract

TUI and operator-facing outputs may explain package state, install/update readiness, blockers, rollback/support state, and final audit status. They cannot grant approval, prepare effects, mutate release channels, install, update, activate, rollback, upload support, execute recovery, dispatch remotely, sign artifacts, or clear blockers.

## Non-Goals

RC16 does not:

- Claim GA production readiness.
- Build or redesign mirror frontend, Nginx, TLS, remote signer, object storage, or remote dispatch infrastructure.
- Read, move, print, hash, or handle private signing material.
- Upload payload bytes or support bundles.
- Execute recovery services.
- Mutate active slots, boot metadata, active artifact sets, or production rings.
- Treat endpoint reachability, frontend output, signer reachability, shell output, TUI output, object storage UI, or model replay as authority.

The next executable task is RC16-010: project the repo-local distributable release package artifact set.
