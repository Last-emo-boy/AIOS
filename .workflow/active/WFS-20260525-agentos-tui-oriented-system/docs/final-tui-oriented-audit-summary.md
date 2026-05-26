# Final TUI-Oriented Audit Summary

Workflow: `WFS-20260525-agentos-tui-oriented-system`

Decision: `tui-oriented-alpha`. This is not a GA production-ready claim. Production signatures, fleet rollout, remote registry governance and long-running operations remain future Production Distro waves.

## What Passed

- `cargo fmt --check`
- `cargo test --workspace`
- `cargo test -p agentd tui_ --no-fail-fast`
- `cargo test -p agentd tui --no-fail-fast`
- `scripts/functional-capability-replay.ps1`
- `scripts/ecosystem-replay.ps1`
- `scripts/production-runbook-smoke.ps1`
- `scripts/tui-replay.ps1`
- `scripts/validate-alpha-rootfs.ps1`
- `scripts/build-release.ps1 -QemuPath E:\qemu\qemu-system-x86_64.exe -QemuTimeoutSeconds 120`
- `scripts/boot-smoke-test.ps1 -SkipKernelDownload -KernelPath image\cache\vmlinuz-virt -QemuPath E:\qemu\qemu-system-x86_64.exe -TimeoutSeconds 120`

Release provenance reports `promotion.status=promotable` with no blockers. QEMU smoke observed `AGENTOS_TUI_CONSOLE_READY`.

## TUI State

- `--tui-interactive` and `--tui-scripted` now use the durable `TuiRuntimeController`.
- The controller drives real `AgentCore<FileRunStore, DeterministicPlanner<StubModelProvider>>` operations.
- Typed commands cover dashboard, intent submission, run advance, approve, deny, suspend, recover, audit, support bundle export and `aom` lifecycle projection.
- `approvals.show latest` renders exact approval binding context.
- `recovery.show latest` renders `source=run-store+audit-journal` and `no-model-replay=true`.
- Unsafe shell-like input fails closed before dispatch.

## Boundary Audit

- TUI remains projection-controller only.
- AgentCore owns PlanRun lifecycle.
- SecurityExecutionEngine owns all side effects.
- `agent_core::ecosystem` owns resolver and activation planning.
- `agentd` remains a thin operator surface and does not own planner, resolver, policy or side-effect logic.
- `aom install/stage` remains inert; activation is still mediated by AgentCore PlanSpec plus SecurityExecutionEngine.
- Baseline operation remains local-only and does not require network, external LLM, Firecracker or host package manager.

## Safety Evidence

TUI replay passed 20/20 checks:

- Durable dashboard projection rendered.
- Approval queue rendered with exact binding.
- Recovery view rendered from durable state.
- Support bundle exported.
- Ecosystem projection and activation preview rendered.
- Activation preview stayed gated with `activation_prepared=false`.
- Shell-like input and `shell.exec` were rejected.
- Secret-like operator input was not echoed raw.
- Denied restart prepared no side effect.

Production runbook smoke passed 12/12 cases and now includes a scripted TUI operator runbook.

## Remaining Risks

- The current TUI is still line-oriented typed command output, not a full-screen pane-based terminal application.
- Production signatures and key ceremony are still a separate release decision.
- Fleet telemetry, rollout rings, rollback drills and incident response operations need later waves.
- Remote registry governance and marketplace review policy are not GA-ready.

## Next Waves

- Build a full-screen TUI shell with panes, navigation, command palette and live event stream.
- Add operator session profiles, role-aware command scopes and sealed local profile state.
- Add fleet/update operations with rollout rings, rollback drills and support bundle upload policy.
- Add production signing ceremony, key rotation and release decision evidence.
- Add remote registry mirror, marketplace governance and organization policy overlays.
