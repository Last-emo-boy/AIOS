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
- `image/out/agentos-initramfs.manifest.json` records the build hash, boot args, and MVP constraints.
- `scripts/boot-smoke-test.ps1` runs or diagnoses the QEMU smoke test.
- `.workflow/artifacts/boot/boot-smoke.log` stores boot output.
- `.workflow/artifacts/boot/boot-smoke-result.json` stores the structured result.

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
