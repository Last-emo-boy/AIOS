# Production Distro RC18 Planning Summary

RC18 starts from the RC17 final audit. RC17 closed with PASS as non-GA AIOS-body exact install/update execute-or-deny readiness: exact target, exact approval, executable AgentCore install/update PlanSpec, SecurityExecution allow, rollback preconditions, controlled local install, controlled local update, controlled rollback/support, and local consumer smoke were proved.

RC17 did not prove an installed-system image or VM drill. Its install/update/rollback effects were repo-local evidence and the consumer smoke did not execute new effects.

RC18 is scoped to AIOS body work. It must move those gates into a disposable installed-system image boundary before any isolated install, update, or rollback drill can be considered meaningful.

## Execution Shape

1. Freeze the RC18 isolated installed-system drill authority contract.
2. Bind the disposable image boundary, state root, mount/write surface, and host-mutation denial model.
3. Bind installed-system baseline identity and boot-state projection from current AIOS release evidence.
4. Prove image-boundary fail-closed fixtures for missing, stale, broad, host-mutating, remote, and support-upload paths.
5. Run isolated installed-system install drill evidence.
6. Run isolated installed-system update drill evidence.
7. Bind post-update observation and rollback preconditions inside the image.
8. Run isolated installed-system rollback drill evidence.
9. Bind local support/recovery evidence after the image drill.
10. Run installed-system local release channel consumer smoke.
11. Close with RC18 final audit and keep production_ready_claim=false.

## Authority Boundary

RC18 remains non-GA and AIOS-body-only. Mirror output, frontend output, signer reachability, shell output, TUI projection, model replay, remote service reachability, object storage UI, and endpoint reachability remain non-authoritative.

RC18 must not handle private signing material, provision remote services, mutate production rings, mutate the host rootfs, mutate the host active slot, mutate host boot metadata, enable remote dispatch, upload support bundles, execute recovery services, or treat an isolated image drill as GA readiness.
