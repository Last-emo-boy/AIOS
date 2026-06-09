# Production Distro RC19 Planning Summary

RC19 starts from the RC18 final audit. RC18 closed with PASS as non-GA AIOS-body isolated installed-system image readiness: disposable image boundary, baseline identity, image-boundary fail-closed fixtures, isolated install, isolated update, rollback preconditions, isolated rollback, support/recovery evidence, and installed-system consumer smoke were proved.

RC18 did not yet produce an Ubuntu-like user-facing installable image artifact or first-user installation path. Its install/update/rollback execution remained an isolated drill surface rather than a distributable image artifact with installer media, first boot, local channel consumption, and post-install operation evidence.

RC19 is scoped to AIOS body work. It must turn the RC18 image-readiness evidence into a reproducible installable image artifact and first-user install path while preserving the non-GA boundary and forbidding host and production mutation.

## Execution Shape

1. Freeze the RC19 installable image and first-user install authority contract.
2. Bind a reproducible installable image artifact set from RC18 evidence and current release/package inputs.
3. Bind installer media manifest and boot target descriptor.
4. Prove installable image artifact reproducibility fail-closed fixtures for missing, stale, broad, host-mutating, remote, and signing-bypassing paths.
5. Bind first-user install target boundary and preflight package.
6. Run first-user install drill inside a disposable target.
7. Bind first boot provisioning and local operator identity projection.
8. Bind offline/local channel consumption evidence without external mirror infrastructure.
9. Run post-install update and rollback compatibility smoke.
10. Bind local support/recovery evidence after the first-user install drill.
11. Run installable image local consumer smoke.
12. Close with RC19 final audit and keep production_ready_claim=false.

## Authority Boundary

RC19 remains non-GA and AIOS-body-only. Mirror output, frontend output, signer reachability, shell output, TUI projection, model replay, remote service reachability, object storage UI, and endpoint reachability remain non-authoritative.

RC19 must not handle private signing material, provision remote services, mutate production rings, mutate the host rootfs, mutate the host active slot, mutate host boot metadata, mutate the active artifact set, enable remote dispatch, upload support bundles, execute recovery services, or treat an installable image drill as GA readiness.
