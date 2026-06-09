# Production Distro RC21 Planning Summary

RC21 starts from the RC20 final audit. RC20 closed with PASS as a non-GA AIOS-body single-user distribution local consumer milestone: canonical release bundle binding, local channel projection, installer catalog, single-user install acceptance, first boot posture, update execution, rollback execution, lifecycle support/recovery, and consumer smoke were proved.

RC20 does not yet model the local user lifecycle as a transactional, resumable operation surface. It proves readiness, but not a complete local operation intent catalog, dry-run explainability, transaction journal, snapshot baseline, repair/reinstall drill, downgrade/rollback drill from local channel history, or consumer smoke over that lifecycle surface.

RC21 is scoped to AIOS body work. It must turn RC20 local consumer readiness into a transactional local user lifecycle candidate while preserving the non-GA boundary and forbidding host and production mutation.

## Execution Shape

1. Freeze the RC21 local transactional lifecycle authority contract.
2. Bind a local operation intent catalog for install, update, repair/reinstall, downgrade/rollback, support export, and recovery reference.
3. Bind transaction journal and snapshot baseline package.
4. Prove lifecycle operation fail-closed fixtures for missing, stale, broad, host-mutating, remote, and signing-bypassing paths.
5. Bind install/update/reinstall dry-run execution plan.
6. Run transactional install/update dry-run acceptance inside a disposable target.
7. Bind user-visible explain/resume/audit package.
8. Run repair/reinstall drill inside a disposable installed-system boundary.
9. Run downgrade/rollback drill from local channel history inside a disposable boundary.
10. Bind lifecycle support/recovery closure after repair/downgrade drills.
11. Run transactional lifecycle local consumer smoke.
12. Close with RC21 final audit and keep production_ready_claim=false.

## Authority Boundary

RC21 remains non-GA and AIOS-body-only. Mirror output, frontend output, Nginx/TLS status, signer reachability, shell output, TUI projection, model replay, remote service reachability, object storage UI, and endpoint reachability remain non-authoritative.

RC21 must not handle private signing material, provision remote services, mutate production rings, mutate the host rootfs, mutate the host active slot, mutate host boot metadata, mutate the active artifact set, enable remote dispatch, upload support bundles, execute recovery services, or treat a local lifecycle candidate as GA readiness.
