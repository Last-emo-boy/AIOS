# Release Artifacts

Tasks: `TASK-AIOS-012`, `TASK-DALPHA-008`

## Purpose

Release artifacts must be reproducible enough to test, audit, and hand off
without relying on hidden local state. For Distribution Alpha, the release flow
records source revision, toolchain versions, dependency inventory, Alpha runtime
manifest inputs, image inputs, artifact hashes, service recovery smoke, QEMU
runtime smoke, and promotion blockers.

## Local Pipeline

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1
```

The script runs:

- `cargo test -p agentd`
- `cargo test -p agentd safety::`
- `cargo test -p agentd agent_core::`
- `cargo test -p agentd agent_core::adversarial`
- `cargo build -p agentd --release`
- `pwsh -NoProfile -ExecutionPolicy Bypass -File image/build-initramfs.ps1`
- `pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/alpha-service-recovery-smoke.ps1 -SkipCargoTests`
- `pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/boot-smoke-test.ps1 -QemuPath E:\qemu\qemu-system-x86_64.exe -TimeoutSeconds 30`

## Generated Metadata

The release script writes local generated metadata under ignored `.workflow/artifacts/release/`:

- `dependency-inventory.json`: workspace package inventory and `Cargo.lock` hash
- `provenance.json`: git revision, git status, toolchain versions, gate commands, artifact hashes, initramfs manifest, Alpha rootfs manifest, rootfs runtime manifest hash, service recovery smoke result, QEMU runtime smoke result, and promotion policy

The initramfs builder separately writes `image/out/agentos-initramfs.manifest.json`, which is referenced by provenance metadata.

## Retention

Commit scripts, docs, task evidence, and source. Do not commit generated binaries, initramfs archives, boot logs, cached kernels, or release metadata under `.workflow/artifacts/release/`.

## Promotion Rules

Promote a Distribution Alpha build only when:

- full unit tests pass
- safety gate passes
- AgentCore and adversarial runtime gates pass
- Alpha service recovery smoke passes
- dependency inventory and provenance metadata exist
- runtime-aware image assembly records Alpha rootfs and runtime manifest hashes
- full QEMU runtime smoke observes handoff, runtime marker, and rootfs runtime manifest hash marker
- provenance contains no secret values, only hashes, paths, versions, and policy labels
- `provenance.json` reports `promotion.status=promotable` and no blockers
- formal release promotion reruns `scripts/build-release.ps1` from a clean or tagged revision
