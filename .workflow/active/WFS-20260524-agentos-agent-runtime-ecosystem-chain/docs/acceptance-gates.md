# Acceptance Gates

## Gate Philosophy

AgentOS Production Distro can only advance if runtime autonomy remains bounded, explainable and recoverable. The gate set therefore checks both sides:

- Agent Runtime can operate the OS without hidden side-effect paths.
- Ecosystem artifacts can extend OS behavior without bypassing Agent Runtime.

## Baseline Gates

Required for every wave that touches code:

```powershell
cargo test --workspace
powershell -ExecutionPolicy Bypass -File scripts\functional-capability-replay.ps1
powershell -ExecutionPolicy Bypass -File scripts\build-release.ps1
```

QEMU promotion gate, when boot/runtime proof is required:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\boot-smoke-test.ps1 -QemuPath E:\qemu\qemu-system-x86_64.exe -TimeoutSeconds 30
```

## Runtime Gates

Runtime changes must prove:

- PlanRun state transitions persist before side effects.
- recovery uses RunStore + AuditJournal, not model replay authority.
- model output cannot directly execute tools.
- observations cannot directly create high-risk tool calls.
- memory and knowledge cannot store raw secrets or privileged policy overrides.
- scheduler enforces dependency order, retry budget and backpressure.
- degraded mode remains read-only or explicitly approval-gated.

## Ecosystem Gates

Ecosystem changes must prove:

- artifact install/stage is inert.
- activation goes through AgentCore PlanSpec.
- activation side effects go through SecurityExecutionEngine.
- policy packs cannot weaken core invariants.
- manifests, registry snapshots and lockfiles are deterministic.
- optional dependencies fail before `EffectPrepared`.
- revoked or digest-mismatched artifacts fail closed.
- release provenance records registry snapshot, lockfile and replay hashes.

## Adversarial Fixtures

Minimum fixtures:

- workflow pack attempts `shell.exec`.
- policy pack tries to disable exact approval.
- capability pack tries to grant itself authority.
- knowledge pack injects privileged instructions into memory.
- model profile embeds secret-like content.
- adapter pack attempts direct host mutation.
- registry snapshot references mismatched digest.
- revoked artifact remains in local cache.

## Evidence Model

Each completed task should produce evidence JSON with:

- `task_id`
- `status`
- `artifacts`
- `commands`
- `hashes`
- `blocked_shortcuts`
- `optional_dependencies`
- `promotion_impact`

Final chain audit should include:

- runtime control loop readiness
- ecosystem object model readiness
- activation safety readiness
- replay and release gate readiness
- production operations readiness

## Blocking Conditions

Block promotion if:

- normal-mode arbitrary shell appears in operator registry or semantic tool manifest.
- activation can mutate runtime without SecurityExecutionEngine.
- policy pack can remove no-shell, exact approval, secret-handle, source-to-sink, audit or rollback invariants.
- release gate omits functional replay or ecosystem replay after they exist.
- support bundle includes raw secrets.
- active artifact set cannot be reconstructed after restart.
