# TUI Oriented AgentOS Architecture

AgentOS should become TUI-oriented, not TUI-owned.

The TUI is the primary operator console for the OS. It receives operator intent, shows plans, lets the operator approve or deny gated actions, displays audit and recovery state, and explains ecosystem status. It does not plan, execute, resolve ecosystem artifacts, mutate host state, or replay model output as authority.

## Ownership

- `agent_core` owns durable `PlanRun`, planner, scheduler, observations, memory and recovery classification.
- `security_execution` owns policy, exact approval validation, capability leases, sandbox profiles, effect envelopes, audit, verification and rollback.
- `agent_core::ecosystem` owns local registry resolution and activation planning.
- `agentd` owns PID 1 integration, process lifecycle, CLI/TUI entry points and read-only projections.
- `tui` owns rendering and typed operator actions only.

## TUI Command Model

TUI commands are semantic operator actions:

- `intent.submit`
- `run.plan`
- `run.advance`
- `run.approve`
- `run.deny`
- `run.suspend`
- `run.recover`
- `audit.show`
- `support.bundle`
- `aom.search`
- `aom.show`
- `aom.verify`
- `aom.stage`
- `aom.explain`
- `aom.activate.preview`

The TUI command model explicitly rejects shell-like commands. A command string is not an execution surface; it is parsed into a typed operation and routed to the existing runtime owner.

## State Authority

The TUI may cache render snapshots for responsiveness, but authoritative state remains:

- `RunStore` for run state.
- `AuditJournal` for effect truth.
- active artifact set for ecosystem runtime state.
- release/update provenance for update readiness.

If render cache conflicts with durable state, durable state wins.

## Baseline Mode

The baseline TUI must work in local-only mode:

- no external LLM required,
- no network required,
- no Firecracker required,
- no host package manager required,
- no public registry required.

Missing optional capabilities must appear as degraded or blocked views, not as hidden failures.

## First Implementation Bias

The first production TUI should remain boring and testable: deterministic line-oriented rendering and command parsing, with golden text snapshots. A richer terminal UI library can be introduced later only after the durable controller and safety gates are stable.
