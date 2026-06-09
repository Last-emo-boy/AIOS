# Production Distro RC20 Planning Summary

RC20 starts from the RC19 final audit. RC19 closed with PASS as a non-GA AIOS-body installable image local consumer milestone: reproducible installable image artifact binding, installer media manifest binding, reproducibility fail-closed fixtures, first-user install target boundary, first-user install drill, first boot projection, offline/local channel consumption, post-install update and rollback compatibility smoke, first-user support/recovery evidence, and installable image local consumer smoke were proved.

RC19 did not yet turn that evidence into a complete single-user distribution candidate. It proved readiness for local consumption, but it did not bind a canonical release bundle, candidate-to-stable local channel promotion, installer catalog selection, acceptance install criteria, or actual post-install update and rollback execution drills inside the installed-system boundary.

RC20 is scoped to AIOS body work. It must turn RC19 local consumer readiness into a single-user distribution candidate while preserving the non-GA boundary and forbidding host and production mutation.

## Execution Shape

1. Freeze the RC20 single-user distribution authority contract.
2. Bind a canonical release bundle manifest from RC19 image, installer, channel, support, and recovery evidence.
3. Bind local candidate and stable channel promotion package without external mirror authority.
4. Prove release bundle and channel promotion fail-closed fixtures for missing, stale, broad, host-mutating, remote, and signing-bypassing paths.
5. Bind installer catalog and version selection preflight.
6. Run single-user install acceptance drill inside a disposable target.
7. Bind first boot user acceptance and local operator posture.
8. Run post-install local update execution drill inside a disposable installed-system boundary.
9. Run post-update rollback execution drill inside a disposable installed-system boundary.
10. Bind local support/recovery closure after install/update/rollback drills.
11. Run single-user distribution local consumer smoke.
12. Close with RC20 final audit and keep production_ready_claim=false.

## Authority Boundary

RC20 remains non-GA and AIOS-body-only. Mirror output, frontend output, signer reachability, shell output, TUI projection, model replay, remote service reachability, object storage UI, and endpoint reachability remain non-authoritative.

RC20 must not handle private signing material, provision remote services, mutate production rings, mutate the host rootfs, mutate the host active slot, mutate host boot metadata, mutate the active artifact set, enable remote dispatch, upload support bundles, execute recovery services, or treat a single-user distribution candidate as GA readiness.
