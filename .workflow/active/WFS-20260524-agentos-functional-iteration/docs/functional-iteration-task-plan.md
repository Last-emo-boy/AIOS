# AgentOS Functional Iteration Task Plan

## Objective

Make AgentOS functionally useful after Distribution Alpha while keeping the
runtime decomposed. Every new capability must travel through typed contracts,
AgentCore orchestration, SecurityExecution authority, audit projection, and
release evidence.

## Wave 0: Scope And Matrix

- `TASK-FUNC-000`: Freeze functional iteration scope and capability matrix.
- `TASK-FUNC-001`: Define cross-crate capability contract ownership.
- `TASK-FUNC-002`: Define functional release gate and fixture strategy.

Exit criteria:

- Capability matrix maps user-visible workflows to contracts, owner modules,
  semantic tools, policy decisions, audits, and gates.
- New capabilities cannot land directly in `agentd`.
- Release gate can run without external LLM, network, Firecracker, or package
  manager availability.

## Wave 1: Real Adapter Contracts

- `TASK-FUNC-010`: Expand package manager adapter contract and Debian fixture.
- `TASK-FUNC-011`: Expand untrusted content adapter contract and fetch fixture.
- `TASK-FUNC-012`: Expand Firecracker execution adapter contract and fail-closed fixture.
- `TASK-FUNC-013`: Add diagnostics and support bundle contract.

Exit criteria:

- Each adapter has typed inputs/outputs and failure modes.
- Each adapter has fixture-backed tests or smoke design.
- Optional host dependencies fail closed before side effects.

## Wave 2: Workflow Integration

- `TASK-FUNC-020`: Integrate package manager adapter into AgentCore workflow.
- `TASK-FUNC-021`: Integrate untrusted content adapter into AgentCore workflow.
- `TASK-FUNC-022`: Integrate Firecracker execution profile into SecurityExecutionEngine.
- `TASK-FUNC-023`: Integrate diagnostics/support bundle into audit projection.

Exit criteria:

- Workflows are exposed through `agent_core`, not direct `agentd` helpers.
- All side effects are prepared, observed, verified, and sealed or rolled back.
- Audit projection shows allowed, denied, paused, and failed-closed outcomes.

## Wave 3: Operator UX

- `TASK-FUNC-030`: Add operator command registry and capability matrix projection.
- `TASK-FUNC-031`: Add approval, denial, rollback, and audit command flows.
- `TASK-FUNC-032`: Add TUI views for capability workflows and support bundle export.

Exit criteria:

- Operator can see what AgentOS can do and why a workflow is blocked.
- Approval tokens remain exact and parameter-bound.
- TUI is a projection over runtime state, not a second runtime.

## Wave 4: Long-Running Control Plane

- `TASK-FUNC-040`: Define persistent state migration and compatibility checks.
- `TASK-FUNC-041`: Add health, diagnostics, and recovery drills.
- `TASK-FUNC-042`: Add audit retention, export, and redaction gates.
- `TASK-FUNC-043`: Add update/rollback readiness hooks for production distro.

Exit criteria:

- Runtime state can survive versioned migrations.
- Diagnostics do not leak secrets.
- Audit export and support bundle flows are redacted and reproducible.

## Wave 5: Functional Promotion

- `TASK-FUNC-050`: Build functional capability replay suite.
- `TASK-FUNC-051`: Wire functional replay into release/provenance gate.
- `TASK-FUNC-052`: Run final functional audit and decide next production-distro gate.

Exit criteria:

- `cargo test --workspace` and capability replay pass.
- Release provenance records capability matrix hash and replay evidence.
- Final audit reports `functional-ready`, `functional-remediation-required`, or
  `rollout-blocked`.
