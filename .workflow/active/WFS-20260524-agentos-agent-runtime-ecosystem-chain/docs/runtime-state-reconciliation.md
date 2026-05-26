# Runtime State Reconciliation

Task: `TASK-ARUN-020`

## Purpose

AgentOS is operated through Agent Runtime, so boot recovery must reconstruct OS truth from durable runtime records rather than asking a model what happened. This document defines how AgentOS reconciles `RunStore`, `AuditJournal`, rollback state and active ecosystem artifact state after restart.

Recovery is evidence reconstruction. It is not replanning authority.

## Existing Runtime Basis

Current implementation already provides durable recovery primitives:

- `agent_core::recovery::AgentRunRecoveryCoordinator` joins `RunStore::list_recoverable_runs` with `AuditJournal::run_timeline`.
- Recovery classifications include `safe-to-verify`, `needs-rollback`, `needs-human-review`, `abandoned`, `failed-closed` and `completed`.
- Recovery writes `RecoveryStarted` and `RecoveryCompleted` audit events.
- Recovery projections include `source=run-store+audit` and `no-model-replay`.
- `agentd::operator_projection` exposes audit seal status, unresolved effects, rollback pending count and support bundle readiness.
- `agentd::support_bundle` produces deterministic, redacted support bundle manifests linked to run ids and audit ranges.

## Boot-Time Reconciliation Order

AgentOS boot should reconcile state in this order:

```text
1. Validate packaged runtime artifacts and local config.
2. Open RunStore, AuditJournal, rollback store and active artifact state read-only.
3. Rebuild audit hash/projection and unresolved effect truth.
4. List recoverable runs from RunStore.
5. Join each recoverable run with its AuditJournal timeline.
6. Join active artifact state for runs that staged or activated ecosystem artifacts.
7. Classify recovery outcome.
8. Persist Recovering / Suspended / RollbackPending / Completed / FailedClosed as needed.
9. Emit RecoveryStarted and RecoveryCompleted audit events.
10. Project recovery status and support bundle hints to the operator.
```

No step in this sequence may call a model provider for authority. Optional model summaries may explain already reconstructed evidence later, but cannot change the classification.

## Truth Precedence

| Source | Authority | Used for | Cannot do |
| --- | --- | --- | --- |
| `AuditJournal` | highest effect truth | prepared, observed, sealed, rollback pending, rollback observed, approval and recovery events | invent missing commits |
| `RunStore` | durable run snapshot | run state, current step, approval state, observation/memory refs, recovery marker | override sealed audit truth |
| rollback store | rollback evidence | rollback handle, rollback id, rollback observed state | mark effect complete without audit |
| active artifact state | ecosystem activation truth | staged/active/blocked artifact set and activation run relation | activate artifacts by presence alone |
| operator projection | read-only explanation | expose recovery and unresolved effects | authorize recovery |
| model output | no authority | optional summary after evidence is reconstructed | decide what happened |

When sources disagree, the safer state wins:

- `EffectPrepared` without `CommitSealed` or `RollbackObserved` is unresolved.
- Write or activation effects without seal become `RollbackPending` or `FailedClosed`.
- Awaiting approval remains pending, suspended or expired; restart never auto-approves.
- Active artifact state must be reconciled with activation audit before being treated as active.
- Unknown or corrupted evidence fails closed.

## Recovery Classification

| Classification | Inputs | Restored state | Operator meaning |
| --- | --- | --- | --- |
| `safe-to-verify` | read-only prepared/observed effect without seal | `Recovering` | runtime can verify from durable evidence |
| `needs-rollback` | write, host promotion, update or activation effect unresolved | `RollbackPending` | rollback or human review is required |
| `needs-human-review` | pending approval, ambiguous effect, missing dependency | `Suspended` | operator must decide next action |
| `abandoned` | accepted run without durable planning/policy evidence | `Suspended` | no autonomous continuation |
| `failed-closed` | mid-effect run with no durable effect truth or corrupted evidence | `FailedClosed` | do not resume automatically |
| `completed` | sealed run with no active step | `Completed` | no recovery action required |

## Active Artifact State

Ecosystem artifacts are not fully implemented yet, but the reconciliation contract must reserve their role now because later `aom activate` flows can change OS behavior.

Active artifact state should include:

- registry snapshot id and lockfile hash;
- staged artifact digests;
- active artifact coordinates and digests;
- activation run id;
- activation report hash;
- rollback artifact set;
- revocation/advisory status;
- policy version used during activation.

Reconciliation rules:

- A staged artifact is inert and must not be treated as active.
- An active artifact requires matching activation audit and activation report.
- A blocked or revoked active artifact marks the runtime degraded and blocks dependent workflows.
- If activation audit is unresolved, recovery state is `RollbackPending` or `Suspended`.
- Artifact state cannot bypass `AgentCore PlanSpec + SecurityExecutionEngine`.

## No-Model-Replay Rule

Recovery must not ask a model to reconstruct missing truth. The runtime may only use:

- persisted `PlanRun`;
- frozen plan hash;
- audit events;
- rollback handles;
- observation refs and hashes;
- memory refs with trust labels;
- active artifact state;
- operator input after projection.

A model may summarize a recovery report for the operator only after the report is produced. That summary is not authority and cannot trigger tools.

## Operator Projection Impact

Operator projection should expose:

- `recovery.classification`
- `recovery.status`
- `recovery.source = run-store+audit+artifact-state`
- `recovery.no_model_replay = true`
- `recovery.unresolved_effects`
- `recovery.rollback_pending`
- `recovery.active_artifact_conflicts`
- `recovery.next_operator_action`
- `support_bundle.bundle_id`

Current projection already exposes unresolved effects, rollback pending count, seal status and support bundle readiness. Later tasks can add artifact-specific fields without moving policy into `agentd`.

## Support Bundle Impact

Support bundles must remain local, deterministic and redacted. For recovery incidents they should include:

- run ids;
- audit range;
- audit hash chain;
- recovery classification;
- unresolved effect counts;
- active artifact state hash when ecosystem activation exists;
- no raw secrets;
- no raw model prompts;
- no unredacted external content.

## Safety Invariants

- Recovery source is `RunStore + AuditJournal + rollback store + active artifact state`.
- Model replay is never authority.
- Half-committed effects are never silently completed.
- `RollbackPending` survives restart.
- Pending approvals survive as pending, suspended or expired; never as granted.
- Staged ecosystem artifacts remain inert.
- Active artifact state cannot override audit truth.
- Recovery projection is read-only.

## Verification Mapping

| Requirement | Current evidence |
| --- | --- |
| Run recovery joins RunStore and AuditJournal | `agent_core::recovery::AgentRunRecoveryCoordinator` |
| Half-committed write effects recover to rollback | `agent_core::recovery::tests::write_effect_without_seal_recovers_to_rollback_pending` |
| Read-only unresolved effects recover to reconciling state | `agent_core::recovery::tests::read_only_unresolved_effect_recovers_to_reconciling_state` |
| Recovery forbids model replay | recovery projections and prompts contain `no-model-replay` |
| Support bundle is deterministic and redacted | `agentd::support_bundle::tests::support_bundle_manifest_links_runs_and_redacts` |

## Follow-Up Tasks

- `TASK-ARUN-021` should define approval survival and exact-token validation after restart.
- `TASK-ARUN-023` should turn these classifications into PID 1 recovery drills.
- `TASK-ECO-022` should define active artifact state and activation report schema.
- `TASK-PROD-050` should add runtime and ecosystem recovery state to production support bundles.
