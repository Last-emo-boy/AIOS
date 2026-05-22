# AgentOS Runtime Foundation Task Breakdown

Source: `research.md`
Workflow: `WFS-20260522-agentos-runtime-foundation`

## Why This Workflow Exists

The completed Linux MVP proved the safety substrate: semantic tools, policy,
capability leases, audit, rollback, recovery, sandboxing, service recovery, and
release provenance.

It did not yet implement a real bottom Agent runtime. This workflow fills that
gap before distribution work starts.

## Two Runtime Layers

### Agent Core Runtime

Agent Core Runtime owns intent and orchestration:

- Convert operator intent into a structured `PlanSpec`.
- Freeze plan before execution.
- Maintain `PlanRun` state.
- Schedule steps by dependency.
- Pause for approval.
- Process observations.
- Update bounded memory.
- Recover run state after restart.

It never directly executes tools. Every effect goes through the Security
Execution Foundation.

### Security Execution Foundation

Security Execution Foundation owns constrained effects:

- Route semantic tools.
- Evaluate policy.
- Issue capability leases.
- Compile sandbox profiles.
- Prepare effect envelopes.
- Write audit events.
- Verify outcomes.
- Seal commits or mark rollback pending.
- Reconcile unfinished effects after restart.

It never trusts model output as authority.

## Wave Summary

| Wave | Name | Purpose | Tasks |
|---|---|---|---|
| 0 | Runtime Boundary Freeze | Freeze ownership, state transitions, module integration, and inherited safety gates. | `TASK-RTF-000` to `TASK-RTF-003` |
| 1 | Agent Core Contracts | Define runtime data model, run store, ModelBroker, and Planner. | `TASK-ACR-001` to `TASK-ACR-004` |
| 2 | Security Execution Foundation Hardening | Define effect envelope, policy adapter, sandbox, untrusted content, and secret rules. | `TASK-SEF-001` to `TASK-SEF-005` |
| 3 | Generic Agent Run Loop | Implement AgentCore loop, scheduler, observation, memory, execution bridge, and recovery integration. | `TASK-ACR-005` to `TASK-ACR-008`, `TASK-SEF-006`, `TASK-SEF-007` |
| 4 | Workflow Migration and Safety Gates | Migrate service recovery and add runtime adversarial gates. | `TASK-ACR-009`, `TASK-ACR-010`, `TASK-SEF-008` to `TASK-SEF-010` |
| 5 | Distribution Readiness Bridge | Define distro entry criteria and complete final audit. | `TASK-RTF-004`, `TASK-RTF-005` |

## Critical Path

```text
TASK-RTF-000
  -> TASK-RTF-001 / TASK-RTF-002 / TASK-RTF-003
  -> TASK-ACR-001
  -> TASK-ACR-002 + TASK-ACR-003
  -> TASK-ACR-004
  -> TASK-SEF-001 / TASK-SEF-002 / TASK-SEF-003 / TASK-SEF-004 / TASK-SEF-005
  -> TASK-ACR-005 + TASK-SEF-006
  -> TASK-ACR-006 / TASK-ACR-007 / TASK-ACR-008 / TASK-SEF-007
  -> TASK-ACR-009
  -> TASK-ACR-010 + TASK-SEF-008 + TASK-SEF-009 + TASK-SEF-010
  -> TASK-RTF-004
  -> TASK-RTF-005
```

## Completion Definition

Runtime Foundation is complete only when:

- Service recovery runs through generic AgentCore, not a dedicated workflow.
- ModelBroker remains the only model boundary.
- RunStore can recover in-flight PlanRuns.
- Every side effect still goes through semantic tools, policy, capability,
  sandbox, audit, verification, rollback, and recovery.
- Runtime safety gates cover prompt injection, observation injection, memory
  poisoning, approval bypass, secret handling, and half-committed effects.
- Distribution Alpha entry criteria explicitly depend on this final audit.
