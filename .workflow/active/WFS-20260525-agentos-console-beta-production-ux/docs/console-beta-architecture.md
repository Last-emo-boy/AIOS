# Console Beta Architecture

## Positioning

Console Beta turns the current line-oriented TUI into a long-running operator shell. It is an experience and operations layer over the existing AgentOS runtime, not a new runtime.

## Ownership

- `agentd` TUI: projection-controller, parser, layout, command palette, display state.
- `AgentCore`: intent acceptance, planning, PlanRun lifecycle, recovery.
- `SecurityExecutionEngine`: policy, capability leases, sandboxing, side effects, audit, rollback.
- `agent_core::ecosystem`: artifact resolution, staging, activation planning.
- `support_bundle`: support evidence projection and redaction.

## Target Internal Split

```text
TuiShell
  -> OperatorSession
  -> PanelLayout
  -> CommandPalette
  -> ProjectionSnapshot
  -> ViewRenderer
  -> TypedCommandDispatch

TypedCommandDispatch
  -> AgentCore APIs
  -> AOM projection APIs
  -> Support bundle APIs
```

`ProjectionSnapshot` is immutable render input with source hashes. It must never become source of truth.

## State Sources

- Run state: RunStore.
- Effect truth: AuditJournal and RuntimeAuditProjection.
- Ecosystem state: registry snapshot, staged set, active set, replay artifacts.
- Release evidence: release provenance, rootfs manifests, QEMU smoke result.
- Support evidence: support bundle manifest and redacted projections.

## Module Access Matrix

`TuiShell` may own focus, navigation, layout selection and status-line composition. It may read `ProjectionSnapshot` only.

`OperatorSession` may store selected panel, selected run id, selected artifact coordinate, local command history references and layout preferences. It is UI state only and must never become permission, role or policy authority.

`PanelLayout` may compute terminal regions for wide and narrow layouts. It must not read RunStore, AuditJournal, AOM state or support bundle files directly.

`CommandPalette` may parse typed commands, suggest contextual commands and render command previews. It must reject shell-like input before dispatch and must not turn fuzzy matches into hidden authority changes.

`ProjectionSnapshot` may aggregate immutable render input from RunStore, AuditJournal, RuntimeAuditProjection, support bundle projection, AOM projection and release evidence. It is never durable state or recovery truth.

`ViewRenderer` may render snapshots into line-oriented or full-screen panels. It must remain pure with respect to runtime state.

`TypedCommandDispatch` may call existing AgentCore, AOM projection and support bundle APIs using typed commands. It must not implement planner, resolver, policy, approval validation or side-effect execution logic.

## Dispatch Rules

All high-risk actions must pass through preview-before-dispatch. Approval, recovery, AOM activation preview, support bundle export and future update operations must display target, source, authority path and expected durable state changes before dispatch.

Dispatch may call:

- AgentCore APIs for intent, run lifecycle, approval, denial, suspend and recover.
- AOM projection APIs for search, show, verify, stage explanation and activation preview.
- Support bundle APIs for redacted local evidence export.

Dispatch may not call:

- direct shell execution
- host package manager commands
- raw filesystem mutation helpers
- AOM resolver internals
- SecurityExecutionEngine bypasses
- production signing key material

## Promotion Language

Console Beta means: a full-screen terminal operator shell exists, scripted replay remains deterministic, and the primary operator workflows are inspectable from the console.

Console Beta does not mean: GA production readiness, completed production signing ceremony, remote fleet rollout readiness, public marketplace governance or remote registry authority.

## Experience Principles

- Attention first: approvals, rollback, recovery and degraded states are visible before historical details.
- Preview before risk: high-risk commands must show bound context and authority path before dispatch.
- Deterministic by default: layout snapshots and scripted replay must remain stable.
- Local-first: no baseline dependency on network, external LLM, Firecracker or host package manager.
