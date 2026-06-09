# RC21 Local Transactional User Lifecycle Planning Context

Source: RC20 final closeout audit PASS. RC20 closed as a non-GA AIOS-body single-user distribution local consumer milestone: release bundle, local channel projection, installer catalog, install acceptance, first boot posture, update execution, rollback execution, lifecycle support/recovery, and local consumer smoke were proved.

RC21 objective: move local single-user distribution readiness into a transactional local user lifecycle candidate. The user-facing body should be able to explain install, update, repair/reinstall, downgrade/rollback, support, and recovery decisions from local evidence before any effect is prepared.

Exploration summary:
- Architecture: RC21 should add a local operation intent catalog, transaction journal, snapshot baseline, dry-run plan, explain/resume audit package, repair/reinstall drill, downgrade/rollback drill, lifecycle support/recovery closure, consumer smoke, and final audit.
- Implementation: follow RC20 task/result/evidence patterns with source artifact hashes, fail-closed matrices, local-only artifacts, invariant checks, task evidence files, and deterministic non-GA closeout.
- Integration: RC21 consumes RC20 result artifacts and writes only `.workflow/active/WFS-20260610-agentos-production-distro-rc21`, `.workflow/artifacts/rc21-*`, and RC21 scripts. It must not stage unrelated pre-existing WIP.
- Risk: RC21 must not mutate host rootfs, host active slot, host boot metadata, active artifact set, or production rings; it must not use mirror/frontend/Nginx/TLS/signer/object-storage/private-key/support-upload/recovery-execution/remote-dispatch authority.

Plan overview: 13 tasks in 5 waves, with RC21-001 as the next executable task.
