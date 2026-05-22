# AgentOS MVP Boot Chain

Task: `TASK-AIOS-001`

## Target

The MVP boot path proves a deterministic Linux kernel can hand control to an `agentd` entrypoint in early userspace:

```text
QEMU -> Linux kernel -> initramfs -> rdinit=/sbin/agentd -> AGENTD_HANDOFF_OK
```

This task does not require Firecracker, remote LLM credentials, fleet orchestration, or a GUI.

## Artifacts

- `image/build-initramfs.ps1` builds `image/out/agentos-initramfs.cpio.gz`.
- `image/out/agentos-initramfs.manifest.json` records the build hash, boot args, MVP constraints, Alpha runtime artifact IDs, and boot markers.
- `scripts/boot-smoke-test.ps1` runs or diagnoses the QEMU smoke test.
- `.workflow/artifacts/boot/boot-smoke.log` stores boot output.
- `.workflow/artifacts/boot/boot-smoke-result.json` stores the structured result.

## Distribution Alpha Runtime Smoke

For Distribution Alpha, the smoke is no longer handoff-only. The initramfs
builder first stages and validates the Alpha rootfs contract, then embeds
runtime availability markers into the generated early `/sbin/agentd`:

```text
AGENTD_HANDOFF_OK
AGENTOS_RUNTIME_ARTIFACTS_OK
AGENTOS_RUNTIME_MANIFEST_SHA256=<rootfs-runtime-manifest-sha256>
```

The boot smoke test reads `image/out/agentos-initramfs.manifest.json`, confirms
the Alpha runtime artifact IDs are present and passed, then requires QEMU serial
output to contain all required markers. Use `-AllowHandoffOnly` only for legacy
MVP handoff diagnosis; Alpha promotion must not use it.

## QEMU

The default QEMU path is:

```text
E:\qemu\qemu-system-x86_64.exe
```

Override it with:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/boot-smoke-test.ps1 -QemuPath D:\tools\qemu\qemu-system-x86_64.exe
```

## Kernel

By default, the smoke test downloads and caches Alpine Linux latest-stable x86_64 `vmlinuz-virt`:

```text
https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/x86_64/netboot/vmlinuz-virt
```

The cached file is written to `image/cache/vmlinuz-virt`. It is an external dependency and should not be committed.

To use a local kernel:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/boot-smoke-test.ps1 -KernelPath E:\kernels\vmlinuz
```

## Verification

Build initramfs:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File image/build-initramfs.ps1
```

Check dependencies without booting:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/boot-smoke-test.ps1 -DependencyCheckOnly
```

Run the boot smoke test:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/boot-smoke-test.ps1
```

The test passes only when `AGENTD_HANDOFF_OK` appears in the QEMU serial output.
For Distribution Alpha, it also requires the runtime artifact marker and rootfs
runtime manifest hash marker.
