# Runtime-Aware Image Assembly

Source task: `TASK-DALPHA-005`
Workflow: `WFS-20260523-agentos-distribution-alpha`

## Purpose

The Alpha image path must not build a handoff-only initramfs while ignoring the
runtime rootfs contract. The current assembly is still Developer VM first, but
it now performs a runtime-aware staging step before creating the initramfs
manifest.

## Build Path

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File image/build-alpha-rootfs.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File image/build-initramfs.ps1
```

`image/build-initramfs.ps1` runs `image/build-alpha-rootfs.ps1` by default unless
`-SkipAlphaRootfsAssembly` is set.

## Generated Outputs

All generated outputs remain under ignored `image/out/`:

- `image/out/agentos-alpha-rootfs/`
- `image/out/agentos-alpha-rootfs.validation.json`
- `image/out/agentos-alpha-rootfs.manifest.json`
- `image/out/agentos-alpha-rootfs/usr/lib/agentos/release/rootfs-runtime-manifest.json`
- `image/out/agentos-initramfs.manifest.json`
- `image/out/agentos-initramfs.cpio.gz`

## Runtime Evidence

The rootfs assembly manifest records:

- validation result path
- staged rootfs path
- rootfs runtime manifest path and hash
- `policy.pack`
- `tools.semantic`
- `model_broker.config`
- `state.runs`
- `state.audit`
- `state.rollback`
- `state.memory`

The initramfs manifest embeds the Alpha rootfs manifest reference and artifact
projection so release provenance can inherit it through existing release flow.

## Current Boundary

This task validates package defaults and persistent state paths. Full Alpha
promotion still requires later tasks to install and verify:

- `agentd.boot`
- `agentd.runtime`
- `release.provenance`
- full QEMU runtime smoke

Those remain blocking Alpha risks until `TASK-DALPHA-006`, `TASK-DALPHA-007`,
and `TASK-DALPHA-008`.
