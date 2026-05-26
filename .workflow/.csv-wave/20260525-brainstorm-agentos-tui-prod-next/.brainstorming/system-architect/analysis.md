# System Architect Analysis

## Architecture Direction

The next cadence SHOULD treat the TUI as a long-running projection controller with three internal layers:

- `ViewModel`: deterministic projections derived from RunStore, AuditJournal, active artifact state, support bundle sources and AOM registry state.
- `InteractionController`: typed command parsing, command palette selection, focus/navigation state and preview rendering.
- `DispatchAdapter`: typed command dispatch into existing AgentCore, support bundle and AOM APIs.

The TUI MUST NOT own planner, resolver, policy or side-effect execution. It should only compose view models and dispatch typed commands into existing owners.

## Data Model

- `OperatorSession`: local sealed UI state, including active workspace, selected run, selected artifact, view mode, filters and command history references.
- `PanelLayout`: stable pane definitions, focus id, scroll anchors and responsive terminal breakpoints.
- `ProjectionSnapshot`: immutable render input with source hashes for run store, audit journal, ecosystem state and support state.
- `CommandPreview`: parsed command, bound context, risk class, target resource and expected authority path.
- `EventCursor`: monotonic cursor over projection changes, not an authority source.

## State Model

The shell should move through:

`Booting -> Ready -> FocusedView -> CommandPreview -> Dispatching -> Refreshing -> Ready`

Failure states:

- `ParseRejected`: unsafe or unknown command.
- `DispatchRejected`: command valid but rejected by authority.
- `ProjectionDegraded`: source missing, stale or partially unreadable.
- `RecoveryAttention`: recoverable run, rollback pending or stale approval detected.

## Integration Points

- `crates/agentd/src/tui.rs`: split into shell/controller/view modules.
- `crates/agentd/src/operator_projection.rs`: source for dashboard and OS health.
- `crates/agentd/src/support_bundle.rs`: support console data.
- `crates/agentd/src/aom.rs`: ecosystem command projection.
- `crates/agent_core/src/lib.rs`: AgentCore run lifecycle and recovery.
- `crates/security_execution/*`: side-effect authority remains behind AgentCore and policy gates.

## Observability

Required metrics or counters:

- projection refresh duration
- render snapshot source hashes
- command parse rejections by reason
- dispatch rejections by authority
- approval queue age and expiry count
- recovery attention count
- support bundle export success/failure
- AOM activation preview status distribution
- terminal layout fallback count

## Migration Strategy

Wave 1 should split TUI internals without changing command behavior. After that, full-screen shell and panels can reuse existing line renderers as panel content. This reduces regression risk and keeps `--tui-scripted` stable.

## Architectural Risks

- If render cache becomes authority, recovery and audit truth can drift.
- If session profiles become permission authority, role UX can bypass policy.
- If AOM views call resolver logic directly from TUI, ownership regresses.
- If live refresh is nondeterministic, replay and release gates become unstable.

## Recommendation

Do `TUI shell architecture split` before adding full-screen UI. Then add `ProjectionSnapshot` and `OperatorSession` as explicit internal contracts. This makes future UI work cheaper and safer.
