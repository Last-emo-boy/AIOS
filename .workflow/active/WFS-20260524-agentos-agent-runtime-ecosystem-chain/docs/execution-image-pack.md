# Execution Image Pack

## Purpose

`execution-image-pack` defines sandbox rootfs, guest image, Firecracker image or update bundle artifacts. Image packs are ecosystem-managed inputs; they do not allow host execution fallback.

The intended runtime path is:

```text
image artifact
  -> digest and provenance verification
  -> compatibility report
  -> AgentCore activation PlanSpec
  -> SecurityExecutionEngine Firecracker profile
  -> audit, active set update and rollback
```

## Schema

Runtime contract:

```text
ExecutionImagePackV1
```

Schema version:

```text
agentos.execution-image-pack.v1
```

Required fields:

- `coordinate`: must use `execution-image-pack`.
- `kernel_digest`
- `rootfs_digest`
- `image_digest`
- `provenance_digest`
- `compatibility`
- `firecracker_dependency`
- `kvm_required`
- `host_fallback_allowed`
- `active_artifact_set_hash_required`
- `rollback_rule`

## Rules

Kernel, rootfs, image and provenance must be pinned by sha256-bound digests.

Firecracker dependency can be optional for baseline replay, but missing Firecracker or KVM must fail closed into read-only degradation before `EffectPrepared`.

No host execution fallback is allowed when virtualization is unavailable.

Update bundles must account for the active artifact set hash, because image compatibility depends on the active ecosystem artifacts.

Rollback rule must be explicit before activation.

## Failure Cases

Blocked by contract:

- unpinned image digest
- missing provenance digest
- missing KVM awareness
- host fallback after missing virtualization
- update bundle without active artifact set hash
- missing rollback rule

## Verification

Primary checks:

```powershell
cargo test -p runtime_contracts ecosystem
cargo test -p security_execution firecracker
powershell -ExecutionPolicy Bypass -File scripts\boot-smoke-test.ps1 -QemuPath E:\qemu\qemu-system-x86_64.exe -TimeoutSeconds 30
powershell -ExecutionPolicy Bypass -File scripts\ecosystem-replay.ps1
```
