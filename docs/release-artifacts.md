# Release Artifacts

Tasks: `TASK-AIOS-012`, `TASK-DALPHA-008`

## Purpose

Release artifacts must be reproducible enough to test, audit, and hand off
without relying on hidden local state. For Distribution Alpha, the release flow
records source revision, toolchain versions, dependency inventory, candidate
SBOM, update metadata, Alpha runtime manifest inputs, image inputs, artifact
hashes, service recovery smoke, QEMU runtime smoke, detached signature records,
and promotion blockers.

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
- `pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/alpha-service-recovery-smoke.ps1 -SkipCargoTests -SkipRootfsAssembly`
- `pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/boot-smoke-test.ps1 -QemuPath E:\qemu\qemu-system-x86_64.exe -TimeoutSeconds 30`

## Generated Metadata

The release script writes local generated metadata under ignored `.workflow/artifacts/release/`:

- `dependency-inventory.json`: workspace package inventory and `Cargo.lock` hash
- `sbom.json`: candidate SBOM derived from workspace package metadata and lockfile hash
- `update-metadata.json`: A/B rootfs update metadata binding the inactive-slot strategy, rollback requirement, SBOM hash, and release artifact hashes
- `provenance.json`: git revision, git status, toolchain versions, gate commands, artifact hashes, initramfs manifest, Alpha rootfs manifest, rootfs runtime manifest hash, service recovery smoke result, QEMU runtime smoke result, signing policy, and promotion policy
- `*.sig.json`: detached candidate signature records for dependency inventory, SBOM, update metadata, and provenance

The initramfs builder separately writes `image/out/agentos-initramfs.manifest.json`, which is referenced by provenance metadata.

## Signature And Key Policy

Candidate releases use deterministic, hash-bound detached signature records with
schema `agentos.release-detached-signature.v1` and algorithm
`sha256-hash-bound-candidate-signature-v1`. These records are not a production
private-key signature; they make the candidate promotion gate fail closed when a
metadata artifact is missing, altered, or not bound to the expected hash.

Production release hardening must replace the candidate hash-bound signer with
a real detached-signature backend before declaring Production ready. The
production signer must record algorithm, key id, key provenance, and rotation
policy in `provenance.json`, and promotion verification must fail closed when
any required detached signature is absent or invalid. Rotation is append-only:
new release keys get new key ids, old keys remain verifiable for retained
artifacts, and compromised or retired keys are disallowed for new promotion
decisions.

## Retention

Commit scripts, docs, task evidence, and source. Do not commit generated binaries, initramfs archives, boot logs, cached kernels, or release metadata under `.workflow/artifacts/release/`.

## Promotion Rules

Promote a Production Candidate build only when:

- full unit tests pass
- safety gate passes
- AgentCore and adversarial runtime gates pass
- Alpha service recovery smoke passes
- dependency inventory, SBOM, update metadata, and provenance metadata exist
- detached signatures exist and verify for dependency inventory, SBOM, update metadata, and provenance
- runtime-aware image assembly records Alpha rootfs and runtime manifest hashes
- full QEMU runtime smoke observes handoff, runtime marker, and rootfs runtime manifest hash marker
- provenance contains no secret values, only hashes, paths, versions, and policy labels
- release reproducibility verification reports `status=passed`
- `provenance.json` reports `promotion.status=promotable` and no blockers
- formal release promotion reruns `scripts/build-release.ps1` from a clean or tagged revision
