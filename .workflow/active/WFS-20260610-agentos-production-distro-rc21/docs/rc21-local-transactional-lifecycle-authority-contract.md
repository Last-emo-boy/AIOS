# RC21 Local Transactional Lifecycle Authority Contract

RC21 starts from the RC20 final audit. RC20 proved non-GA AIOS-body single-user distribution local consumer readiness: canonical release bundle binding, local candidate/stable channel projection, fail-closed bundle/channel checks, installer catalog selection, single-user install acceptance, first boot posture, post-install update, post-update rollback, local support/recovery closure, and consumer smoke.

RC20 did not prove a transactional, resumable, user-visible local lifecycle surface. RC21 moves the evidence into an operation intent, journal, snapshot, dry-run, explain/resume/audit, repair/reinstall, downgrade/rollback, and support/recovery lifecycle while keeping the host, production rings, external mirror, frontend, Nginx/TLS, signer, object storage, remote dispatch, support upload, recovery execution services, shell output, TUI projections, endpoint reachability, and model replay out of authority.

## Source Of Authority

RC21 may consume RC20 final audit facts only when they remain locally hash-bound and non-GA:

1. Single-user release bundle identity is bound.
2. Local candidate/stable channel projection is bound.
3. Release bundle and channel fail-closed fixtures passed.
4. Installer catalog and version selection preflight are bound.
5. Single-user install acceptance ran inside a disposable target.
6. First boot user acceptance and local operator posture are bound.
7. Post-install update drill executed inside disposable installed-system evidence.
8. Post-update rollback drill executed inside disposable installed-system evidence and restored target state.
9. Lifecycle support/recovery evidence is local-only, redacted, and projection-only.
10. Local consumer smoke reports single-user distribution readiness without production readiness.

Endpoint reachability, rendered UI state, external mirror output, frontend output, signer reachability, object storage UI, normal shell output, TUI output, remote service health, support upload availability, recovery service availability, and model replay cannot replace any source evidence.

## Gate Order

RC21 local transactional lifecycle readiness is allowed only in this order:

1. RC20 final audit and single-user distribution local consumer readiness must be present and passed.
2. Freeze this RC21 local transactional lifecycle authority contract.
3. Bind the local lifecycle operation intent catalog for install, update, repair/reinstall, downgrade/rollback, support export, and recovery reference operations.
4. Bind the transaction journal and snapshot baseline package before any lifecycle operation can plan effects.
5. Verify lifecycle operation fail-closed fixtures for missing, stale, mismatched, broad, replayed, host-mutating, remote, signing-bypassing, support-upload, recovery-execution, frontend, mirror, shell, TUI, endpoint, model, and production-ring authority attempts.
6. Bind the install/update/reinstall dry-run execution plan from the operation intent catalog, transaction journal, snapshot baseline, RC20 release bundle, RC20 local channel, rollback baseline, and support/recovery references.
7. Run transactional install/update dry-run acceptance inside a disposable target, or deny before effect with audit.
8. Bind the user-visible explain, resume, and audit package from the dry-run acceptance, journal, snapshot baseline, and denial records.
9. Run repair/reinstall drill evidence inside the disposable installed-system boundary, or deny before effect with audit.
10. Run downgrade/rollback drill evidence from local channel history inside the disposable installed-system boundary, or deny before effect with audit.
11. Bind lifecycle support/recovery closure after repair/reinstall and downgrade/rollback drills as local, redacted, projection-only evidence.
12. Run transactional lifecycle local consumer smoke that explains readiness or denial from RC21 evidence without creating new authority.
13. Close with RC21 final audit and keep production_ready_claim=false.

No later gate may be fabricated from a previous gate. RC20 local consumer readiness does not imply transactional lifecycle authority. Operation intent catalog binding does not imply journal or snapshot authority. Journal and snapshot binding do not imply executable effects. Dry-run acceptance does not imply repair, reinstall, downgrade, rollback, support upload, recovery execution, host mutation, production ring mutation, external mirror, frontend, Nginx/TLS, signer, object storage, shell, TUI, endpoint, or model authority.

## Writable Surface

The disposable installed-system evidence boundary is the only writable lifecycle drill surface for RC21 repair, reinstall, downgrade, and rollback effects. Any lifecycle drill write must be scoped to the disposable boundary and must be traceable to the bound transaction journal, snapshot baseline, operation intent id, and artifact roots declared by RC21 tasks.

RC21 may write only repo-local workflow and artifact evidence for:

- RC21 authority contract and task evidence
- local operation intent catalog
- transaction journal and snapshot baseline package
- lifecycle fail-closed matrix
- dry-run execution plan and dry-run acceptance evidence
- explain/resume/audit package
- disposable repair/reinstall drill evidence
- disposable downgrade/rollback drill evidence
- local redacted support/recovery projection evidence
- transactional lifecycle consumer smoke and final audit evidence

RC21 must not write to or mutate:

- host rootfs
- host active slot metadata
- host boot metadata
- host active artifact set
- production rings
- remote fleet state
- external mirror roots or frontend output
- Nginx or TLS infrastructure
- signer infrastructure
- object storage infrastructure
- support upload endpoints
- recovery execution services
- private signing material

## Operation Authority Rules

RC21 grants only AIOS-body transactional lifecycle evidence authority:

- Operation intent catalog entries are local, typed, and non-executable until journal, snapshot, dry-run, and fail-closed gates are bound.
- Transaction journal entries must be append-only evidence and must bind operation intent, source snapshot, target snapshot, rollback reference, audit reference, and denial reason when denied.
- Snapshot baselines must be repo-local evidence or disposable installed-system evidence, not host boot state.
- Dry-run plans may explain ordered operations and predicted effects, but must not prepare or execute host effects.
- Repair, reinstall, downgrade, and rollback effects may run only inside disposable installed-system evidence until a later milestone explicitly authorizes host effects.
- Support output must be local-only and redacted.
- Recovery output must remain a reference index or projection, not service execution.
- Consumer smoke can report transactional local lifecycle readiness, not production readiness.

## Non-Authority Sources

The following are never authority for RC21 execution:

- external mirror reachability or rendered metadata
- frontend output
- Nginx or TLS service status
- signer reachability
- object storage UI
- endpoint reachability without local evidence binding
- normal shell output
- TUI projection
- model replay
- remote service health
- support upload availability
- recovery service availability
- local channel metadata without bound RC20/RC21 artifact identity

## Fail-Closed Rule

Every RC21 gate must deny before effect on missing, stale, mismatched, broad, replayed, unsigned, expired, unapproved, remote, host-mutating, support-upload, recovery-execution, signer, mirror, frontend, Nginx/TLS, object-storage, shell, TUI, endpoint, model, signing-bypass, or production-ring authority attempts.

Denial must be explicit, audited, local, and usable by the next task as evidence. A denial must not mutate host state, fabricate lifecycle state, upload support bundles, execute recovery services, dispatch remote fleet actions, sign artifacts, publish external payloads, or imply GA readiness.

## Non-Goals

RC21 does not:

- claim GA production readiness;
- build or redesign external mirror frontend, Nginx, TLS, remote signer, object storage, or remote dispatch infrastructure;
- read, copy, print, hash, move, or handle private signing material;
- upload payload bytes or support bundles;
- execute recovery services;
- mutate host rootfs, active slots, boot metadata, active artifact sets, or production rings;
- treat endpoint reachability, frontend output, signer reachability, shell output, TUI output, object storage UI, external mirror output, remote service health, or model replay as authority.

The next executable task is RC21-010: bind the local lifecycle operation intent catalog.
