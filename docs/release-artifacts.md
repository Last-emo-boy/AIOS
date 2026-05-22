# Release Artifacts

Task: `TASK-AIOS-012`

## Purpose

MVP artifacts must be reproducible enough to test, audit, and hand off without relying on hidden local state. The release flow records source revision, toolchain versions, dependency inventory, image inputs, artifact hashes, and promotion gates.

## Local Pipeline

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1
```

The script runs:

- `cargo test -p agentd`
- `cargo test -p agentd safety::`
- `cargo build -p agentd --release`
- `pwsh -NoProfile -ExecutionPolicy Bypass -File image/build-initramfs.ps1`
- `pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/boot-smoke-test.ps1 -DependencyCheckOnly`

For a full boot check, run:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/boot-smoke-test.ps1 -QemuPath E:\qemu\qemu-system-x86_64.exe -TimeoutSeconds 30
```

## Generated Metadata

The release script writes local generated metadata under ignored `.workflow/artifacts/release/`:

- `dependency-inventory.json`: workspace package inventory and `Cargo.lock` hash
- `provenance.json`: git revision, git status, toolchain versions, commands, artifact hashes, initramfs manifest, and promotion policy

The initramfs builder separately writes `image/out/agentos-initramfs.manifest.json`, which is referenced by provenance metadata.

## Retention

Commit scripts, docs, task evidence, and source. Do not commit generated binaries, initramfs archives, boot logs, cached kernels, or release metadata under `.workflow/artifacts/release/`.

## Promotion Rules

Promote an MVP build only when:

- full unit tests pass
- safety gate passes
- dependency inventory and provenance metadata exist
- boot smoke dependency check passes, and full QEMU smoke is run before handoff
- provenance contains no secret values, only hashes, paths, versions, and policy labels
- formal release promotion reruns `scripts/build-release.ps1` from a clean or tagged revision
