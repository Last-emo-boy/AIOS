# Update And Rollback Readiness Hooks

Production Distro promotion depends on functional capability evidence.

Readiness checks:

- runtime contract tests pass
- policy pack, semantic tools and operator command registry are packaged
- functional replay passes
- state migration contract is satisfied
- update metadata requires inactive-slot staging and rollback
- QEMU smoke remains separately visible when required

Rollback evidence path:

- rootfs update keeps active slot unchanged during staging
- pending slot health failure schedules rollback
- release provenance records functional matrix and replay hashes

Verification:

- `powershell -ExecutionPolicy Bypass -File scripts/functional-capability-replay.ps1`
- `powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1`
- `cargo test -p agent_core rootfs_update`
