# Next TASK Candidates

These are candidates for a future Maestro workflow, not yet active TASK files.

## Console Beta Foundation

- `TASK-TUI2-000`: Freeze Console Beta boundary and module ownership.
- `TASK-TUI2-001`: Split TUI runtime into shell, parser, view model and dispatch modules.
- `TASK-TUI2-002`: Add `ProjectionSnapshot` contract with source hashes.
- `TASK-TUI2-003`: Add full-screen pane layout model and narrow terminal fallback.
- `TASK-TUI2-004`: Add command palette with contextual preview.
- `TASK-TUI2-005`: Add full-screen layout snapshots and scripted parity gate.
- `TASK-TUI2-006`: Add live event feed from durable audit/runtime projections.

## Operations Workbench

- `TASK-TUI2-010`: Build Approval Center panel.
- `TASK-TUI2-011`: Add approval binding diff and stale/expired token UX.
- `TASK-TUI2-012`: Build Recovery Workbench panel.
- `TASK-TUI2-013`: Add rollback consequence preview.
- `TASK-TUI2-014`: Build Support Console panel.
- `TASK-TUI2-015`: Add degraded-state explainer and evidence path actions.

## Capability Catalog

- `TASK-TUI2-020`: Add capability index projection.
- `TASK-TUI2-021`: Add workflow catalog view.
- `TASK-TUI2-022`: Add launch-intent preview for operational capabilities.
- `TASK-TUI2-023`: Add AOM artifact detail and trust status panel.
- `TASK-TUI2-024`: Add catalog replay gate.

## Production Evidence Center

- `TASK-TUI2-030`: Add release provenance panel.
- `TASK-TUI2-031`: Add promotion blocker panel.
- `TASK-TUI2-032`: Add local update and rollback drill view.
- `TASK-TUI2-033`: Add QEMU/rootfs/replay gate status panel.
- `TASK-TUI2-034`: Add candidate signing status view.

## Fleet And Governance Preview

- `TASK-TUI2-040`: Draft local-first fleet operations model.
- `TASK-TUI2-041`: Add rollout ring projection prototype.
- `TASK-TUI2-042`: Add support bundle upload policy design.
- `TASK-TUI2-043`: Add remote registry mirror UX design.
- `TASK-TUI2-044`: Add organization policy overlay preview.

## Suggested Gates

- `cargo fmt --check`
- `cargo test --workspace`
- `cargo test -p agentd tui --no-fail-fast`
- `scripts/tui-replay.ps1`
- `scripts/production-runbook-smoke.ps1`
- `scripts/build-release.ps1`
- QEMU boot smoke with `AGENTOS_TUI_CONSOLE_READY`
