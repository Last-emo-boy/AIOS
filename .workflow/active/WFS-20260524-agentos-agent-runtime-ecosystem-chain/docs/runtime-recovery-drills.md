# Runtime Recovery Drills

Task: `TASK-ARUN-023`

## Purpose

AgentOS depends on `agentd` as PID 1 and Agent Runtime as the OS control plane. Recovery drills must prove that runtime restart, unfinished effects, pending approvals and activation-pending work remain explainable and recoverable without external LLM, network or hidden host scripts.

This document defines the local and QEMU drill set for Production Distro progression.

## Drill Taxonomy

| Drill | Simulated interruption | Expected recovered state | Evidence |
| --- | --- | --- | --- |
| `read-only-unsealed` | crash after read-only `EffectPrepared` or `EffectObserved` but before seal | `Recovering` with `safe-to-verify` | recovery projection plus `RecoveryStarted` / `RecoveryCompleted` |
| `write-with-diff-unsealed` | crash after write or host-promotion prepare before seal | `RollbackPending` with rollback id | audit unresolved effect and rollback marker |
| `approval-pending` | restart while protected step is `AwaitingApproval` | `AwaitingApproval` or `Suspended` if expired | RunStore approval status and no protected `EffectPrepared` |
| `approval-denied` | operator denies during recovery window | terminal `Denied` or `FailedClosed` | `ApprovalBound` denial and no protected effect |
| `activation-pending` | future `aom activate` interrupted after activation plan or effect prepare | `Suspended` or `RollbackPending` | activation report, active artifact state and audit |
| `degraded-dependency` | optional model/network/Firecracker/package dependency missing | degraded projection, no host fallback | degraded class and blocked effect |
| `pid1-boot-smoke` | boot AgentOS initramfs under QEMU | runtime markers observed | boot smoke result JSON and log |

## Local-Only Fixture Drills

Local drills must run without external model, remote registry, network or host package manager:

```text
cargo test -p agent_core recovery
cargo test -p agent_core run_loop
cargo test -p agentd support_bundle operator_projection
cargo test -p agentd safety::
```

The full workspace gate rolls these into:

```text
cargo test --workspace
```

## QEMU Drill

QEMU validates boot-time runtime packaging and PID 1 handoff:

```text
powershell -ExecutionPolicy Bypass -File scripts\boot-smoke-test.ps1 -QemuPath E:\qemu\qemu-system-x86_64.exe -TimeoutSeconds 30
```

Required markers:

- `AGENTD_HANDOFF_OK`
- runtime artifact marker from initramfs manifest
- runtime manifest marker from initramfs manifest

If 30 seconds is too tight on a host, rerun with 120 seconds and record both results. The 30 second failure remains a performance signal; the 120 second pass proves boot chain correctness.

## Expected Projection

Operator projection and support bundle evidence should show:

- audit seal status;
- unresolved effects;
- rollback pending count;
- latest run status;
- support bundle id;
- deterministic redaction status;
- recovery classification when available;
- degraded dependency reason when applicable.

Projection is read-only and must not mutate the journal.

## Acceptance Evidence

Each drill should answer:

- What state existed before interruption?
- What durable source reconstructed truth?
- What recovered state was selected?
- Was any model replay used?
- Was any protected effect prepared without approval?
- Is support evidence available without secrets?

## Safety Invariants

- No recovery drill depends on external LLM.
- No drill uses normal-mode arbitrary shell.
- No pending approval is auto-approved after restart.
- No half-committed write or activation is silently completed.
- No missing optional dependency falls back to unsafe host mutation.
- Support bundles remain deterministic and redacted.
- QEMU path is parameterized and currently uses `E:\qemu\qemu-system-x86_64.exe`.

## Follow-Up Tasks

- `TASK-ECO-022` should add activation report and active artifact state to recovery drill evidence.
- `TASK-VERIFY-043` should add activation rollback and revocation replay.
- `TASK-PROD-050` should include runtime and ecosystem recovery sections in support bundles.
- `TASK-PROD-053` should run the final long-running Production Distro recovery audit.
