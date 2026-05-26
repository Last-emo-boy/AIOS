# TUI State And Render Model

The first production TUI is deterministic and line-oriented. It is designed for replay and release gates before richer terminal widgets are introduced.

## Snapshot Contract

`TuiSnapshotV1` is a render snapshot derived from authoritative sources:

- dashboard: `OperatorProjection`,
- run detail: `RunProjection` plus audit timeline,
- approval queue: durable run state and audit evidence,
- recovery: `RunStore` plus `AuditJournal`,
- ecosystem: `agent_core::ecosystem` projection and active artifact state,
- support: support bundle projection,
- errors: typed parse/runtime errors.

Snapshots are serializable and render to stable text. They are not durable truth.

## Authority Rules

- `RunStore` owns run state.
- `AuditJournal` owns side-effect truth and audit timeline.
- active artifact state owns ecosystem runtime activation truth.
- release provenance owns update readiness evidence.
- TUI render cache never overrides durable state.

If snapshot state conflicts with durable state, durable state wins and the TUI must refresh from durable sources.

## Redaction

Raw secrets must not appear in snapshots, TUI text, JSON evidence, support bundle output or parse errors.

Secret handles may be displayed if they remain handle-only. Secret-like values are replaced by `[REDACTED]` or rejected before evidence is written.

## Determinism

The renderer must provide:

- stable section order,
- stable run/event ordering,
- explicit empty states,
- deterministic error text,
- no dependence on terminal width,
- no control sequence requirement for baseline replay.

## Golden Views

The initial golden snapshots must cover:

- dashboard,
- run detail,
- approval queue,
- recovery/degraded state,
- ecosystem projection,
- support bundle status,
- rejected unsafe command.

Snapshot tests should fail if raw secrets, hidden rollback state or hidden approval blockers appear.
