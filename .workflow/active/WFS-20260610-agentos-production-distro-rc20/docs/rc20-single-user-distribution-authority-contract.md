# RC20 Single-User Distribution Authority Contract

## Source Boundary

RC20 starts from RC19 final audit PASS: installable image local consumer readiness is true, consumer_ready_claim is true, and production_ready_claim remains false.

RC20 may consume RC19 public evidence and local artifacts only through hash-bound result files. RC20 does not authorize external infrastructure, remote reachability, signer reachability, frontend output, shell output, TUI output, endpoint status, or model replay as release authority.

## Gate Order

RC20 execution must follow this gate order:

1. RC19 local consumer readiness is accepted as the source baseline.
2. Canonical single-user release bundle manifest is bound.
3. Local candidate and stable channel promotion package is bound.
4. Release bundle and channel promotion fail-closed fixtures pass.
5. Installer catalog and version selection preflight is bound.
6. Single-user install acceptance runs inside a disposable target.
7. First boot user acceptance and local operator posture are bound.
8. Post-install local update execution drill runs inside the disposable installed-system boundary.
9. Post-update rollback execution drill runs inside the disposable installed-system boundary.
10. Local support/recovery closure is bound after install/update/rollback evidence.
11. Single-user distribution local consumer smoke passes.
12. RC20 final closeout audit decides the milestone and keeps GA claims disabled.

No later gate can claim readiness if an earlier gate is missing, stale, hash-mismatched, authority-broadened, host-mutating, remote-dependent, or support/recovery executing outside the disposable boundary.

## Writable Surfaces

RC20 allows writes only to repo-local workflow artifacts and disposable evidence surfaces:

- `.workflow/active/WFS-20260610-agentos-production-distro-rc20/`
- `.workflow/artifacts/rc20-*`
- disposable target state roots created by RC20 scripts
- local support/recovery projection artifacts produced by RC20 scripts

The host rootfs, host active slot, host boot metadata, active artifact set, production rings, remote mirrors, remote object storage, remote signer services, support upload endpoints, and recovery execution services are not writable surfaces for RC20.

## Authority Rules

RC20 grants only AIOS-body evidence authority:

- Release bundle identity is local and hash-bound.
- Local channel promotion is evidence-only and does not publish to an external mirror.
- Installer selection can select only local RC20 bundle entries.
- Install, update, and rollback drills can mutate only disposable target state.
- Support bundle output must be local-only and redacted.
- Recovery output must remain a reference index or projection, not service execution.
- Consumer smoke can report local single-user distribution readiness, not production readiness.

## Denied Authority

The following remain denied throughout RC20:

- external mirror frontend changes
- Nginx or TLS infrastructure changes
- remote signer service changes
- private signing material handling
- production signing ceremony
- large payload object storage provisioning
- remote fleet dispatch
- support upload
- recovery execution service
- host rootfs mutation
- host active slot mutation
- host boot metadata mutation
- active artifact set mutation
- production ring mutation
- GA production-ready claim
- shell output authority
- TUI output authority
- endpoint reachability authority
- model replay authority

## Completion Rule

RC20 can close only if the final audit proves every RC20 gate and confirms:

- production_ready_claim is false.
- Any consumer_ready_claim is local-only.
- No denied authority was broadened.
- All fail-closed fixtures have zero failed cases.
- All install/update/rollback effects happened only inside disposable target evidence.
