# Product Manager Analysis

## Product Thesis

The next stage should make AgentOS feel like an operating system, not a set of demos. The operator should be able to open the terminal console and understand:

- what the system is doing
- what needs approval
- what is degraded
- what can be recovered
- what capabilities are installed
- what evidence exists for support or release

## Prioritization

### Must Do First

1. Full-screen operator shell with panes and command palette.
2. Approval and recovery workbench.
3. Support console with health, degraded state and bundle export.
4. Capability catalog showing available workflows and ecosystem artifacts.

These directly improve daily usability and make existing runtime work visible.

### Should Do Next

1. Local update and rollback operations.
2. Operator session profiles.
3. AOM trust and governance UX.
4. Soak/replay dashboards.

These move toward Production Distro operations.

### Later

1. Fleet operations.
2. Remote registry governance.
3. Production signing ceremony automation.
4. Multi-operator role model.

These require stronger policy and release governance before productizing.

## Milestone Names

- `Console Beta`: full-screen TUI shell, command palette, panels, live projections.
- `Operations Beta`: approval/recovery workbench, support console, capability catalog.
- `Distro RC0`: update/rollback operations, release evidence center, signing decision workflow.
- `Fleet Preview`: local-first fleet model, rollout rings, support upload policy.

## User Value

- Faster situational awareness.
- Lower approval mistakes through exact binding visualization.
- Safer recovery after interrupted runs.
- More confidence that AgentOS is not executing hidden shell commands.
- Clear path from local Alpha to production candidate.

## Product Risks

- Adding too many capabilities before improving navigation will make the TUI feel cluttered.
- Calling it production-ready too early will create false expectations.
- A package/ecosystem manager without trust UX will feel unsafe.
- Full-screen visuals without deterministic scripted parity will break release gates.

## Recommendation

Sequence the next phase as:

1. Make the console usable all day.
2. Make high-risk decisions easier to inspect.
3. Make capabilities discoverable.
4. Make update/release operations auditable.
5. Only then move into fleet and remote ecosystem governance.
