# Runtime State Contract

Source: `research.md:104`
Task: `TASK-RTF-001`
Workflow: `WFS-20260522-agentos-runtime-foundation`

## Purpose

This contract turns the research state diagram into a durable Agent runtime
state machine. AgentCore may advance a run only through these transitions, and
each transition must be backed by persisted run state plus append-only audit
events where an event exists.

Model output is never the source of recovery truth. Recovery reads `RunStore`
state and `AuditJournal` evidence.

## Runtime States

| State | Meaning | Durable source of truth | Recovery policy |
|---|---|---|---|
| `Accepted` | Operator intent has been accepted and assigned a `run_id`. | `RunStore` record plus `IntentReceived`. | Resume planning if no frozen plan exists. |
| `Planning` | Planner or ModelBroker is drafting a structured plan. | `RunStore` state. | Discard in-flight draft and restart planning from intent and bounded memory. |
| `Planned` | A validated `PlanSpec` is frozen with a plan hash. | `RunStore` frozen plan hash plus `PlanFrozen`. | Continue scheduling from frozen plan; do not ask model what happened. |
| `AwaitingApproval` | Current step is paused for exact approval. | `RunStore` approval request plus `PolicyEvaluated`. | Re-show approval prompt; do not prepare an effect. |
| `Executing` | A prepared step is being executed by Security Execution Foundation. | `EffectPrepared` plus `RunStore` step cursor. | Reconcile audit: verify if read-only, roll back or human-review if write/execute. |
| `Observing` | Tool output has been returned and is being normalized. | `EffectObserved` plus observation reference. | Re-process observation from stored raw/sanitized reference if available; otherwise human review. |
| `Verifying` | Runtime is checking success criteria from observations/effects. | `RunStore` verification marker plus effect references. | Re-run deterministic verification if safe; otherwise human review. |
| `Completed` | All required steps are sealed or intentionally skipped. | `RunStore` terminal state plus sealed effects. | Terminal; no further automatic action. |
| `Denied` | A step or run was denied before protected effect preparation. | `RunStore` terminal/step state plus `PolicyEvaluated` or approval denial record. | Terminal for denied path; dependents remain blocked unless alternative path exists. |
| `Suspended` | Human or system paused the run without completing it. | `RunStore` state and suspension reason. | Re-present run summary and next safe action. |
| `RollbackPending` | A prepared/observed side effect failed verification or exceeded boundary. | `RollbackPending` plus rollback handle reference. | Execute rollback or request human review; do not replan over the effect. |
| `Recovering` | `agentd` is reconciling RunStore with audit truth after restart. | `RecoveryStarted` plus recovery scan result. | Complete reconciliation and move to `Verifying`, `RollbackPending`, `Suspended`, `Completed`, or `FailedClosed`. |
| `FailedClosed` | Runtime cannot prove a safe next action. | `RunStore` terminal state plus failure reason. | Terminal until explicit operator intervention starts a new run or rescue flow. |

## Allowed Transitions

| From | To | Trigger | Required audit / persistence | TUI/API trigger |
|---|---|---|---|---|
| none | `Accepted` | `accept_intent` | Persist `RunStore` record, append `IntentReceived`. | TUI/API may trigger. |
| `Accepted` | `Planning` | planner starts | Persist state update. | Runtime only. |
| `Planning` | `Planned` | plan validated and frozen | Persist plan hash, append `PlanFrozen`. | Runtime only. |
| `Planning` | `Suspended` | model timeout or invalid output after retry budget | Persist reason. | Runtime only. |
| `Planning` | `FailedClosed` | planner violates forbidden path or cannot validate plan | Persist reason; no effect events. | Runtime only. |
| `Planned` | `AwaitingApproval` | policy says pause for exact approval | Persist approval request, append `PolicyEvaluated`; no `EffectPrepared`. | Runtime only. |
| `Planned` | `Executing` | read-only/allowed step prepared | Persist step cursor, append `PolicyEvaluated`, lease metadata, and `EffectPrepared`. | Runtime only. |
| `AwaitingApproval` | `Executing` | exact approval token accepted | Append `ApprovalBound`, persist approval, append `EffectPrepared`. | TUI/API may approve. |
| `AwaitingApproval` | `Denied` | approval denied | Persist denial, append decision event; no `EffectPrepared`. | TUI/API may deny. |
| `AwaitingApproval` | `Suspended` | approval timeout or operator suspend | Persist suspension reason; no `EffectPrepared`. | TUI/API may suspend. |
| `Executing` | `Observing` | executor returns output | Append `EffectObserved`, persist observation reference. | Runtime only. |
| `Executing` | `Recovering` | process restart or crash detected | Append `RecoveryStarted`. | Runtime boot path. |
| `Observing` | `Verifying` | observation normalized and trust-labeled | Persist observation summary and redaction status. | Runtime only. |
| `Verifying` | `Completed` | step/run success criteria pass | Append `CommitSealed` for sealed effects, persist completed state. | Runtime only. |
| `Verifying` | `RollbackPending` | verification fails for side-effecting step | Append `RollbackPending`, persist rollback handle reference. | Runtime only. |
| `Verifying` | `Suspended` | verification inconclusive | Persist reason and evidence refs. | Runtime only. |
| `RollbackPending` | `Recovering` | restart before rollback observed | Append `RecoveryStarted`. | Runtime boot path. |
| `RollbackPending` | `Suspended` | rollback requires human review | Persist review reason. | Runtime only. |
| `Recovering` | `Verifying` | unresolved read-only effect is safe to verify | Append `RecoveryCompleted`, persist next state. | Runtime only. |
| `Recovering` | `RollbackPending` | unresolved write/execute effect needs compensation | Append `RecoveryCompleted`, persist next state. | Runtime only. |
| `Recovering` | `Suspended` | classification requires human review | Append `RecoveryCompleted`, persist next state. | Runtime only. |
| `Recovering` | `Completed` | no unresolved effects remain | Append `RecoveryCompleted`, persist terminal state. | Runtime only. |
| any non-terminal | `Suspended` | explicit operator pause | Persist reason and current cursor. | TUI/API may suspend. |
| any non-terminal | `FailedClosed` | invariant violation or corrupted state | Persist reason; do not prepare new effects. | Runtime only. |

## Audit Event Mapping

| Runtime event | Existing audit event | Required fields |
|---|---|---|
| Intent accepted | `IntentReceived` | `run_id`, `step_id=run`, `actor`, redacted intent summary. |
| Plan frozen | `PlanFrozen` | `run_id`, `step_id=plan`, plan hash, planner version. |
| Policy evaluated | `PolicyEvaluated` | `run_id`, `step_id`, tool, resource, risk, policy version, parameter hash, reason. |
| Approval accepted | `ApprovalBound` | actor, tool, resource, exact parameter hash, expiry, policy version. |
| Effect prepared | `EffectPrepared` | lease id, tool, normalized params hash, rollback handle if applicable. |
| Effect observed | `EffectObserved` | observation ref, trust label, redaction status, summary. |
| Commit sealed | `CommitSealed` | verification result, commit id, sealed effect refs. |
| Rollback required | `RollbackPending` | rollback handle, failed verification reason. |
| Rollback observed | `RollbackObserved` | rollback result and verification summary. |
| Recovery started | `RecoveryStarted` | run id, scan source, unresolved effect count. |
| Recovery completed | `RecoveryCompleted` | classification and next state. |
| Sandbox denial | `SandboxDenied` | lease id, denied operation, profile name, reason. |

Future implementation may add run-specific event types such as `RunSuspended` or
`RunFailedClosed`, but the first runtime must be representable using existing
audit events plus `RunStore` state.

## Idempotency Rules

- Repeating `accept_intent` with the same external request id must return the
  same `run_id` or fail closed.
- Repeating `freeze_plan` for the same validated plan must produce the same
  plan hash.
- Repeating `prepare` for an already prepared step must not execute the step a
  second time; it must load the existing `EffectPrepared` evidence.
- Repeating `execute` after `EffectObserved` must not re-run the tool unless a
  task-specific retry policy explicitly creates a new step attempt id.
- Repeating `verify` may re-run deterministic checks but must not erase failed
  evidence.
- Repeating `rollback` must be safe if `RollbackObserved` already exists.

## Failure Handling

| Failure | Required behavior |
|---|---|
| Model timeout | Move `Planning` to `Suspended`; no effects prepared. |
| Invalid model output | Reject plan; retry within budget or move to `FailedClosed`. |
| Unknown tool | Reject plan or step before policy; no effects prepared. |
| Policy denial | Move step to `Denied`; no effects prepared. |
| Approval timeout | Move to `Suspended`; no effects prepared. |
| Approval parameter mismatch | Deny; no effects prepared. |
| Sandbox denial | Append `SandboxDenied`; move to `Suspended` or `FailedClosed` depending on risk. |
| Tool execution error after prepare | Append observed failure when possible; move to `Verifying`, `RollbackPending`, or `Suspended`. |
| Verification failure | Append or reference failure evidence; write `RollbackPending` when a side effect may exist. |
| Rollback failure | Move to `FailedClosed` or `Suspended` with human review; do not replan over the effect. |
| Corrupted RunStore or audit mismatch | Move to `FailedClosed` and require operator intervention. |

## Downstream Test Requirements

`TASK-ACR-005` and `TASK-SEF-007` must include tests for:

- All non-terminal state recovery policies.
- Approval denial and timeout producing no `EffectPrepared`.
- Crash after `EffectPrepared`.
- Crash after `EffectObserved`.
- Verification failure to `RollbackPending`.
- Invariant violation to `FailedClosed`.
