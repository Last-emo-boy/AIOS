# RC19 Installable Image And First-User Install Authority Contract

RC19 starts from the RC18 final audit. RC18 proved non-GA AIOS-body isolated installed-system image readiness: disposable image boundary, baseline identity, image-boundary fail-closed fixtures, isolated install, isolated update, rollback preconditions, isolated rollback, local support/recovery evidence, and installed-system consumer smoke.

RC18 did not prove a user-facing installable image artifact or first-user installation path. RC19 moves the evidence into a reproducible installable image artifact surface while keeping the host, production rings, external mirror, signer, object storage, remote dispatch, support upload, recovery execution services, shell output, TUI projections, endpoint reachability, and model replay out of authority.

## Source Of Authority

RC19 may consume RC18 final audit facts only when they remain locally hash-bound and non-GA:

1. Disposable installed-system image boundary and state root are bound.
2. Installed-system baseline identity and boot-state projection are bound.
3. Image-boundary side-effect fail-closed fixtures passed.
4. Isolated installed-system install drill executed inside the disposable image boundary.
5. Isolated installed-system update drill executed inside the disposable image boundary.
6. Post-update observation and rollback preconditions are bound inside the image.
7. Isolated rollback drill executed inside the disposable image boundary and restored the installed image state.
8. Support/recovery evidence is local-only, redacted, and projection-only.
9. Installed-system consumer smoke reports install/update/rollback/support readiness without executing new effects.

Endpoint reachability, rendered UI state, external mirror output, signer reachability, object storage UI, normal shell output, TUI output, remote service health, and model replay cannot replace any source evidence.

## Gate Order

RC19 reproducible installable image and first-user install readiness is allowed only in this order:

1. RC18 final audit and isolated installed-system image readiness must be present and passed.
2. Freeze this RC19 installable image and first-user install authority contract.
3. Bind a reproducible installable image artifact set from RC18 evidence and current AIOS release inputs.
4. Bind installer media manifest and boot target descriptor.
5. Verify installable image artifact reproducibility fail-closed fixtures for missing, stale, broad, host-mutating, remote, signer, mirror, frontend, shell, TUI, endpoint, and model authority attempts.
6. Bind first-user install target boundary and preflight package.
7. Run first-user install drill evidence inside the disposable target boundary, or deny before effect with audit.
8. Bind first boot provisioning and local operator identity projection from first-user install evidence.
9. Bind offline/local channel consumption evidence without granting external mirror infrastructure authority.
10. Run post-install update and rollback compatibility smoke inside the disposable target boundary, or deny before effect with audit.
11. Bind first-user install support and recovery evidence as local, redacted evidence only.
12. Run installable image local consumer smoke that explains readiness or denial from RC19 evidence without creating new authority.
13. Close with RC19 final audit and keep production_ready_claim=false.

No later gate may be fabricated from a previous gate. RC18 installed-system image readiness does not imply installable image artifact authority. Installable image artifact binding does not imply first-user install execution. First-user install drill evidence does not imply host rootfs, host active slot, boot metadata, active artifact set, production ring, support upload, recovery execution, remote dispatch, external mirror, frontend, signer, shell, TUI, endpoint, or model authority.

## Writable Surface

The disposable first-user install target is the only writable install drill surface for RC19. Any drill write must be scoped to the disposable target boundary and must be traceable to the bound install target descriptor and artifact roots declared by RC19-020.

RC19 must not write to or mutate:

- host rootfs
- host active slot metadata
- host boot metadata
- host active artifact set
- production rings
- remote fleet state
- external mirror roots or frontend output
- signer infrastructure
- object storage infrastructure
- support upload endpoints
- recovery execution services
- private signing material

## Non-Authority Sources

The following are never authority for RC19 execution:

- external mirror reachability or mirror-rendered metadata
- frontend output
- signer reachability
- object storage UI
- endpoint reachability without local evidence binding
- normal shell output
- TUI projection
- model replay
- remote service health
- support upload availability
- recovery service availability
- local/offline channel metadata without bound artifact identity

## Fail-Closed Rule

Every RC19 gate must deny before effect on missing, stale, mismatched, broad, replayed, unsigned, expired, unapproved, remote, host-mutating, support-upload, recovery-service, signer, mirror, frontend, shell, TUI, endpoint, model, or production-ring authority attempts.

Denial must be explicit, audited, local, and usable by the next task as evidence. A denial must not mutate host state, fabricate install target state, upload support bundles, execute recovery services, dispatch remote fleet actions, sign artifacts, publish external payloads, or imply GA readiness.

## Non-Goals

RC19 does not:

- claim GA production readiness;
- build or redesign external mirror frontend, Nginx, TLS, remote signer, object storage, or remote dispatch infrastructure;
- read, copy, print, hash, move, or handle private signing material;
- upload payload bytes or support bundles;
- execute recovery services;
- mutate host rootfs, active slots, boot metadata, active artifact sets, or production rings;
- treat endpoint reachability, frontend output, signer reachability, shell output, TUI output, object storage UI, external mirror output, remote service health, or model replay as authority.

The next executable task is RC19-010: bind reproducible installable image artifact set.
