# Functional Release Gate

The functional gate proves post-Alpha capabilities with local-only fixtures
before a Production Distro promotion can claim functional readiness.

Primary command:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/functional-capability-replay.ps1
```

Release integration:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1
```

`scripts/build-release.ps1` runs functional replay unless
`-SkipFunctionalReplay` is explicitly passed. Skipping replay records
`functional-replay-skipped` as a promotion blocker.

## Baseline Fixtures

| Capability | Replay Check | External Dependency Required |
| --- | --- | --- |
| Service recovery approved and denied | `cargo test -p agentd service_recovery::` | No |
| Package install fixtures | `cargo test -p agent_core package_install` | No host package manager |
| Untrusted content fixtures | `cargo test -p agent_core untrusted_content` | No network |
| Firecracker fail-closed fixtures | `cargo test -p security_execution firecracker` | No Firecracker runtime |
| Support bundle and operator projection | `cargo test -p agentd support_bundle operator_projection` | No external service |
| Safety regression | `cargo test -p agentd safety::` | No external LLM |

## Provenance

The replay emits `.workflow/artifacts/functional-replay/result.json` with:

- capability matrix path and SHA-256
- per-capability command result
- local-only dependency declaration
- stable pass/fail summary

`scripts/build-release.ps1` records the functional replay artifact hash and
capability matrix hash in release provenance under `functional_iteration`.

## Failure Classification

- `remediation-required`: fixture or test failed while the gate ran normally.
- `rollout-blocked`: replay result is missing, skipped or release provenance
  lacks replay/matrix hashes.
- `optional-integration-degraded`: QEMU, Firecracker or host package manager is
  unavailable but local-only replay passed.

QEMU smoke remains separate and parameterized with default
`E:\qemu\qemu-system-x86_64.exe`.
