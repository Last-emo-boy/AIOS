# Synthesis Specification

## Core Recommendation

The next cadence should not start by adding many new Agent capabilities. The current system already has enough runtime depth to become useful, but the operator experience is still line-oriented. The strongest next move is:

1. Build a full-screen terminal operator shell.
2. Add live projection/event infrastructure that keeps scripted replay deterministic.
3. Turn approval, recovery and support into workbenches.
4. Add a capability catalog so existing runtime powers are discoverable.
5. Then move into update/fleet/signing/governance production work.

This order improves daily usability first while preserving AgentOS safety boundaries.

## Resolved Conflicts

- [RESOLVED] Product wants more visible capabilities, while architecture wants internal split first. Resolution: first wave performs TUI shell split and layout scaffolding, then immediately exposes capability catalog as projection.
- [RESOLVED] UX wants command shortcuts, while test strategy warns about bypass. Resolution: shortcuts may focus or prefill command palette, but high-risk commands still require preview and exact binding.
- [RESOLVED] UI wants live panels, while release gates require determinism. Resolution: live panels are fed by `ProjectionSnapshot` plus `EventCursor`; scripted replay remains deterministic.
- [RESOLVED] Production work wants fleet/update operations, while current system is single-node. Resolution: local update/release evidence center comes before fleet preview.

## Cadence

### Wave A: Console Beta Foundation

Purpose: make the TUI a real terminal shell without changing runtime authority.

Deliverables:

- split `crates/agentd/src/tui.rs` into shell, parser, view model and command dispatch modules
- full-screen pane layout model
- command palette with preview
- dashboard/run/approval/recovery panels using existing renderers
- wide and narrow layout snapshots
- scripted parity gate

Exit criteria:

- current `--tui-scripted` replay still passes
- full-screen mode can show dashboard, latest run, approvals, recovery and event feed
- unsafe input still fails before dispatch

### Wave B: Operations Workbench

Purpose: make approval, recovery and support operations first-class.

Deliverables:

- Approval Center with exact binding diff, expiry, stale token and deny path
- Recovery Workbench with source truth, rollback requirement and next safe action
- Support Console with health, degraded state, audit and bundle export
- event feed sourced from durable projections

Exit criteria:

- approval and recovery workflows are snapshot-tested
- denied/stale/expired approvals cannot be executed
- support bundle remains redacted and release-consumable

### Wave C: Capability Catalog

Purpose: make AgentOS feel functional beyond demos.

Deliverables:

- capability index projection
- workflow catalog over service recovery, package install, untrusted content, rootfs update and AOM previews
- launch intent preview for capabilities
- artifact detail view for policy/workflow/model/knowledge/adapter/image packs

Exit criteria:

- catalog cannot activate or execute directly
- all launches become typed intents or activation previews
- AOM resolver remains in `agent_core::ecosystem`

### Wave D: Production Evidence Center

Purpose: make release, update, rollback and promotion evidence operator-facing.

Deliverables:

- release provenance panel
- promotion blocker panel
- local update/rollback drill view
- QEMU/rootfs/replay status panel
- candidate signing status view

Exit criteria:

- release evidence center projects existing release artifacts without becoming release authority
- failed gate is visible and blocks promotion claim
- production signing remains explicit and not silently assumed

### Wave E: Fleet And Governance Preview

Purpose: prepare long-term Production Distro operations.

Deliverables:

- local-first fleet model design
- rollout ring concepts
- support bundle upload policy
- remote registry mirror UX
- organization policy overlay preview

Exit criteria:

- single-node local proof remains complete
- remote features are optional and fail closed
- governance UX explains trust, revocation and compatibility

## Recommended First Execution Slice

Start with these tasks:

1. `TASK-TUI2-000`: freeze Console Beta boundaries and module split.
2. `TASK-TUI2-001`: split TUI controller/parser/views without behavior change.
3. `TASK-TUI2-002`: introduce `ProjectionSnapshot` and source hashes.
4. `TASK-TUI2-003`: add full-screen layout model and narrow fallback.
5. `TASK-TUI2-004`: add command palette with preview-only dispatch.
6. `TASK-TUI2-005`: add layout snapshot tests and scripted parity replay.

This slice gives the next iteration a safe spine before adding more features.

## Promotion Language

After Wave A and B pass, the project can claim `Console Beta`. After Wave C and D pass, it can claim `Production Candidate UX`. Fleet and governance work should not be described as production-ready until signing, rollout and registry policy waves are complete.
