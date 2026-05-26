# Brainstorm Context: AgentOS TUI Production Next

Session: `.workflow/.csv-wave/20260525-brainstorm-agentos-tui-prod-next`

## Summary

The next cadence should strengthen AgentOS through experience-first work, then functional expansion, then production operations. The current line-oriented TUI is technically capable, but the next product leap is to become a long-running full-screen operator console.

## Recommended Rhythm

1. Console Beta Foundation: full-screen shell, layout, command palette, deterministic projections.
2. Operations Workbench: approval center, recovery workbench, support console.
3. Capability Catalog: discoverable workflows and AOM artifacts, all launched through safe previews.
4. Production Evidence Center: release, update, rollback, QEMU/rootfs/replay and signing status.
5. Fleet And Governance Preview: rollout rings, remote registry UX, organization overlays.

## Why This Order

Adding more capabilities before improving the console will make AgentOS more powerful but harder to operate. Improving the operator shell first makes existing capabilities visible, safer and easier to verify.

## Key Files

- `.brainstorming/guidance-specification.md`
- `.brainstorming/feature-index.json`
- `.brainstorming/synthesis-specification.md`
- `.brainstorming/next-task-candidates.md`
- `.brainstorming/system-architect/analysis.md`
- `.brainstorming/product-manager/analysis.md`
- `.brainstorming/ux-expert/analysis.md`
- `.brainstorming/ui-designer/analysis.md`
- `.brainstorming/test-strategist/analysis.md`

## Main Recommendation

Open the next Maestro workflow around `Console Beta Foundation`, with the first execution slice:

- `TASK-TUI2-000`: freeze Console Beta boundary and module ownership
- `TASK-TUI2-001`: split TUI runtime modules without behavior change
- `TASK-TUI2-002`: add `ProjectionSnapshot`
- `TASK-TUI2-003`: add full-screen pane layout
- `TASK-TUI2-004`: add command palette preview
- `TASK-TUI2-005`: add layout snapshots and scripted parity gate

This sets up the system for feature growth without growing `agentd` into a runtime owner.
