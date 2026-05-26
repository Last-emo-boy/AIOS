# Production Distro Task Chain

## Objective

This chain advances AgentOS from `functional-ready` toward a long-running Production Distro by combining:

1. Agent Runtime as the OS control plane.
2. `aom` as the local-first AgentOS ecosystem manager.
3. Production gates that prove runtime and ecosystem changes before promotion.

## Chain Overview

| Wave | Name | Focus | Output |
| --- | --- | --- | --- |
| 0 | Chain Freeze And Invariants | Unified operating model | accepted chain docs and task graph |
| 1 | Agent Runtime OS Control Loops | boot, steady-state, degraded, recovery, update loops | runtime control loop specs |
| 2 | Durable Agent Runtime State | recovery truth, approval survival, memory governance | state and recovery tasks |
| 3 | Ecosystem Object Model | artifact manifest, registry, lockfile, trust | contracts and fixture schema |
| 4 | Local-First aom Lifecycle | verify, stage, explain | inert staging path |
| 5 | Runtime-Mediated Activation | activation through AgentCore and SecurityExecution | safe artifact activation |
| 6 | Safety Replay And Production Gates | replay, adversarial fixtures, provenance | release promotion gates |
| 7 | Trust And Organization Controls | signing, revocation, org overlays | governed artifact channels |
| 8 | Model Knowledge Adapter And Image Packs | extended ecosystem kinds | model, knowledge, adapter and image governance |
| 9 | Production Distro Operations | support, update, offline, long-running operations | operational readiness |

## Task Groups

### Chain Tasks

- `TASK-CHAIN-000`: Freeze Agent-operated OS and ecosystem chain.
- `TASK-CHAIN-001`: Define AgentOS lifecycle control map.
- `TASK-CHAIN-002`: Define `aom` install/stage/activate invariant.
- `TASK-CHAIN-003`: Define chain acceptance gates and evidence model.

### Agent Runtime Tasks

- `TASK-ARUN-010`: Define boot and steady-state Agent Runtime control loops.
- `TASK-ARUN-011`: Define observation fabric and operator event intake.
- `TASK-ARUN-012`: Define scheduler, quotas, backpressure and autonomous action budget.
- `TASK-ARUN-013`: Define degraded mode and local/stub fallback behavior.
- `TASK-ARUN-020`: Define durable OS run state reconciliation.
- `TASK-ARUN-021`: Define approval, escalation and interrupt survival.
- `TASK-ARUN-022`: Define OS memory governance and knowledge quarantine.
- `TASK-ARUN-023`: Define runtime recovery drills for PID 1 operation.

### Ecosystem Tasks

- `TASK-ECO-000`: Freeze ecosystem scope and `install is not activation` invariant.
- `TASK-ECO-001`: Define `runtime_contracts::ecosystem` boundary.
- `TASK-ECO-020`: Define artifact coordinate and manifest schema.
- `TASK-ECO-021`: Define registry snapshot and lockfile schema.
- `TASK-ECO-022`: Define activation report and installed/active state schema.
- `TASK-ECO-023`: Define compatibility and migration validation.
- `TASK-ECO-030`: Define trust tier and channel policy.
- `TASK-ECO-002`: Add local registry fixture and artifact resolver.
- `TASK-ECO-003`: Implement staging store verification report.
- `TASK-ECO-010`: Define operator-facing artifact explanation format.
- `TASK-ECO-011`: Add `aom` CLI lifecycle surface.
- `TASK-ECO-024`: Add revocation/advisory metadata model.
- `TASK-ECO-025`: Add deterministic ecosystem hash projection.
- `TASK-ECO-004`: Implement activation planning through AgentCore PlanSpec.
- `TASK-ECO-005`: Route activation side effects through SecurityExecutionEngine.
- `TASK-ECO-006`: Add read-only ecosystem projection in `agentd`.
- `TASK-ECO-012`: Package built-in production-safe policy pack.
- `TASK-ECO-013`: Package built-in service recovery workflow pack.
- `TASK-ECO-014`: Add ecosystem status to TUI/operator projection.
- `TASK-ECO-015`: Define verified/community/local-dev channel policy.
- `TASK-ECO-031`: Define signing and revocation requirements.
- `TASK-ECO-032`: Define no-maintainer-script activation rule.
- `TASK-ECO-033`: Define community artifact sandbox-only policy.
- `TASK-ECO-034`: Add ecosystem state to support bundle manifest.
- `TASK-ECO-035`: Define organization allowlist and denylist overlay.
- `TASK-ECO-050`: Define model profile pack schema and local/stub/remote optionality.
- `TASK-ECO-051`: Define knowledge pack schema with trust labels and memory quarantine.
- `TASK-ECO-052`: Add model/knowledge adversarial replay fixtures.
- `TASK-ECO-060`: Define runtime adapter pack schema.
- `TASK-ECO-061`: Define execution image pack schema for Firecracker/sandbox/update bundles.
- `TASK-ECO-062`: Add adapter/image optional dependency fail-closed replay.

### Verification And Production Tasks

- `TASK-VERIFY-040`: Add ecosystem schema and resolver tests.
- `TASK-VERIFY-041`: Add ecosystem local replay script.
- `TASK-VERIFY-042`: Add adversarial ecosystem artifact fixtures.
- `TASK-VERIFY-043`: Add activation rollback and revocation replay.
- `TASK-VERIFY-044`: Integrate ecosystem hashes into release provenance.
- `TASK-PROD-050`: Add runtime and ecosystem support bundle sections.
- `TASK-PROD-051`: Add A/B update readiness with active artifact awareness.
- `TASK-PROD-052`: Add offline operation and pinned snapshot drills.
- `TASK-PROD-053`: Run final Production Distro chain audit.

## Recommended Implementation Order

Start with a narrow but coherent slice:

1. `TASK-CHAIN-000` through `TASK-CHAIN-003`
2. `TASK-ARUN-010` and `TASK-ARUN-011`
3. `TASK-ECO-000`, `TASK-ECO-001`, `TASK-ECO-020`, `TASK-ECO-021`
4. `TASK-ECO-002`, `TASK-ECO-003`, `TASK-ECO-010`
5. `TASK-VERIFY-040`, `TASK-VERIFY-041`

This builds the spine before adding activation. Activation work should wait until schema, registry fixture and staging reports are stable.

After the spine is stable, continue in this order:

6. `TASK-ECO-004`, `TASK-ECO-005`, `TASK-ECO-006`
7. `TASK-ECO-012`, `TASK-ECO-013`, `TASK-ECO-014`
8. `TASK-VERIFY-042`, `TASK-VERIFY-043`, `TASK-VERIFY-044`
9. `TASK-ECO-015`, `TASK-ECO-031`, `TASK-ECO-032`, `TASK-ECO-033`, `TASK-ECO-034`, `TASK-ECO-035`
10. `TASK-ECO-050`, `TASK-ECO-051`, `TASK-ECO-052`, `TASK-ECO-060`, `TASK-ECO-061`, `TASK-ECO-062`
11. `TASK-PROD-050`, `TASK-PROD-051`, `TASK-PROD-052`, `TASK-PROD-053`

## Definition Of Ready For Execution

A task is ready when:

- owner boundary is clear
- read-first files are listed
- side-effect authority is named
- test and replay evidence are defined
- optional dependency behavior is fail-closed
- support/provenance impact is understood

## Definition Of Done For Chain

The chain is complete when:

- Agent Runtime control loops are documented and implemented enough for Production Distro gating.
- `aom` can operate against a local registry and stage inert artifacts.
- artifact activation is mediated by AgentCore and SecurityExecutionEngine.
- ecosystem replay and adversarial fixtures gate release.
- production support bundle and update readiness include runtime and ecosystem state.
