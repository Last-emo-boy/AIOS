# TUI Release Gate

TUI-oriented AgentOS readiness is a release claim, not a documentation claim.

## Required Local Gates

The release path must prove:

- `cargo test --workspace`,
- `cargo test -p agentd tui`,
- `scripts/functional-capability-replay.ps1`,
- `scripts/ecosystem-replay.ps1`,
- `scripts/production-runbook-smoke.ps1`,
- `scripts/tui-replay.ps1`,
- `scripts/build-release.ps1`,
- `scripts/boot-smoke-test.ps1 -QemuPath E:\qemu\qemu-system-x86_64.exe -TimeoutSeconds 30`.

Baseline TUI replay must not require network, external LLM, Firecracker or host package manager.

## Replay Coverage

`scripts/tui-replay.ps1` must cover:

- dashboard render,
- intent submit,
- plan creation,
- read-only advance,
- approval-required pause,
- exact approve,
- deny,
- suspend,
- recover,
- audit projection,
- support bundle status/export,
- ecosystem search/show/verify/stage/explain projection,
- activation preview without activation by stage/install.

## Adversarial Coverage

The replay or test suite must reject:

- shell injection,
- pipe and redirect syntax,
- command chaining,
- unknown commands,
- approval parameter mutation,
- stale approval reuse,
- direct activation by install/stage,
- secret-like values in TUI command output.

Unsafe commands must fail before `EffectPrepared`.

## Provenance Fields

Release provenance must record:

- TUI replay result and hash,
- TUI command registry hash,
- packaged TUI config hash,
- adversarial TUI fixture status,
- QEMU TUI-ready marker status,
- promotion blockers.

If TUI replay is missing, stale or failed, promotion to TUI-oriented status is blocked.
