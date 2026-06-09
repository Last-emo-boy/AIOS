# RC18 Isolated Installed-System Drill Authority Contract

RC18 starts from the RC17 final audit. RC17 proved non-GA AIOS-body exact repo-local install/update execute-or-deny readiness: exact target, exact approval, executable AgentCore install/update PlanSpec, SecurityExecution install/update allow, rollback preconditions, controlled local install, controlled local update, controlled rollback/support, and local release channel consumer smoke.

RC17 did not prove those gates inside an installed-system image or VM. RC18 moves the evidence into a disposable installed-system boundary while keeping the host, production rings, mirror, signer, object storage, remote dispatch, support upload, recovery execution services, shell output, TUI projections, and model replay out of authority.

## Source Of Authority

RC18 may consume RC17 final audit facts only when they remain locally hash-bound and non-GA:

1. Exact repo-local install/update target binding is complete.
2. Exact install/update approval is bound.
3. AgentCore install/update PlanSpec is executable for the exact target.
4. SecurityExecution install/update allow is bound.
5. Rollback preconditions and post-effect observation requirements are bound.
6. Controlled local install, update, rollback, and support evidence are audited.
7. Local release channel consumer smoke reports exact install/update readiness without executing new effects.

Endpoint reachability, rendered UI state, mirror output, signer reachability, object storage UI, normal shell output, TUI output, remote service health, and model replay cannot replace any source evidence.

## Gate Order

RC18 isolated installed-system drill readiness is allowed only in this order:

1. RC17 final audit and exact install/update evidence must be present and passed.
2. Freeze this RC18 isolated installed-system drill authority contract.
3. Bind the disposable installed-system image or VM boundary, state root, allowed write surface, denied host write surface, and artifact roots.
4. Bind installed-system baseline identity and boot-state projection from current AIOS release evidence.
5. Verify image-boundary side-effect fail-closed fixtures for missing, stale, broad, host-mutating, remote, support-upload, recovery-service, signer, mirror, frontend, shell, TUI, and model authority attempts.
6. Run isolated installed-system install drill evidence inside the disposable image boundary, or deny before effect with audit.
7. Run isolated installed-system update drill evidence inside the same disposable image boundary, or deny before effect with audit.
8. Bind post-update observation and rollback preconditions inside the image before any rollback drill.
9. Run isolated installed-system rollback drill evidence inside the disposable image boundary, or deny before effect with audit.
10. Bind isolated image support and recovery evidence as local, redacted evidence only.
11. Run installed-system local release channel consumer smoke that explains readiness or denial from RC18 evidence without creating new authority.
12. Close with RC18 final audit and keep production_ready_claim=false.

No later gate may be fabricated from a previous gate. RC17 readiness does not imply image-boundary authority. Image-boundary binding does not imply install/update execution. Isolated install/update evidence does not imply host slot, boot metadata, production ring, support upload, recovery execution, remote dispatch, mirror, frontend, signer, shell, TUI, or model authority.

## Writable Surface

The installed-system image or VM is the only writable drill surface for RC18. Any drill write must be scoped to the disposable image boundary and must be traceable to the bound state root and artifact root declared by RC18-010.

RC18 must not write to or mutate:

- host rootfs
- host active slot metadata
- host boot metadata
- host active artifact set
- production rings
- remote fleet state
- mirror roots or frontend output
- signer infrastructure
- object storage infrastructure
- support upload endpoints
- recovery execution services
- private signing material

## Non-Authority Sources

The following are never authority for RC18 execution:

- mirror reachability or mirror-rendered metadata
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

## Fail-Closed Rule

Every RC18 gate must deny before effect on missing, stale, mismatched, broad, replayed, unsigned, expired, unapproved, remote, host-mutating, support-upload, recovery-service, signer, mirror, frontend, shell, TUI, model, or production-ring authority attempts.

Denial must be explicit, audited, local, and usable by the next task as evidence. A denial must not mutate host state, fabricate image state, upload support bundles, execute recovery services, dispatch remote fleet actions, sign artifacts, or imply GA readiness.

## Non-Goals

RC18 does not:

- claim GA production readiness;
- build or redesign mirror frontend, Nginx, TLS, remote signer, object storage, or remote dispatch infrastructure;
- read, copy, print, hash, move, or handle private signing material;
- upload payload bytes or support bundles;
- execute recovery services;
- mutate host rootfs, active slots, boot metadata, active artifact sets, or production rings;
- treat endpoint reachability, frontend output, signer reachability, shell output, TUI output, object storage UI, mirror output, remote service health, or model replay as authority.

The next executable task is RC18-010: bind disposable installed-system image boundary and state root.
