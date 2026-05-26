# Runtime Approval Survival

Task: `TASK-ARUN-021`

## Purpose

AgentOS runs through Agent Runtime, so approvals, denials, escalations and operator interrupts must survive restart without widening authority. A pending approval after reboot is still pending or expired; it is never implicitly granted.

Approval is an exact, time-bounded capability decision. It is not a reusable permission.

## Existing Runtime Basis

Current implementation already provides these primitives:

- `security_execution::policy::ApprovalToken` binds `actor`, `tool`, `resource`, `parameter_hash`, `expires_at` and `policy_version`.
- `PlanStepPolicyAdapter` routes a frozen `PlanStep` through `ToolRouter` and `PolicyEvaluator`, records `PolicyEvaluated`, and returns `Allowed`, `Denied` or `AwaitingApproval`.
- `AgentCore::advance_run` persists `AwaitingApproval` before any protected `EffectPrepared`.
- `AgentCore::approve_step`, `deny_step` and `suspend_run` attach approval state to `RunStore`.
- Broad approvals and parameter mutation attempts remain paused or denied by policy and safety tests.

## Durable Approval State

Each approval request should be reconstructable from durable state:

- `run_id`
- `step_id`
- `actor`
- `tool`
- `resource`
- normalized `parameter_hash`
- `risk`
- `policy_version`
- `approval_id`
- `approval_status`
- `reason`
- `created_at`
- `expires_at`
- source surface
- linked `PolicyEvaluated` event id or audit hash

The approval token itself must be exact:

```text
actor + tool + resource + parameter_hash + expires_at + policy_version
```

Wildcard actor, tool, resource or parameter hash is invalid for production approval. Any policy version mismatch requires a new approval.

## Restart Behavior

| Pre-restart state | Durable evidence | Restored state | Rule |
| --- | --- | --- | --- |
| `AwaitingApproval` | pending approval not expired | `AwaitingApproval` | keep waiting; do not execute |
| `AwaitingApproval` | pending approval expired | `Suspended` | require new operator action |
| `AwaitingApproval` | approval denied | `Denied` or `FailedClosed` | no protected effect |
| `Suspended` | timeout or interrupt marker | `Suspended` | preserve reason and next action |
| `Planned` with granted approval | exact token still valid and policy version matches | `Planned` | reevaluate policy before effect |
| `Planned` with stale approval | expired or policy mismatch | `AwaitingApproval` or `Suspended` | do not prepare effect |
| `Executing` or `Verifying` | effect prepared but unsealed | `Recovering` or `RollbackPending` | handled by `TASK-ARUN-020` recovery truth |

Restart must not recreate in-memory approval tokens from model output, planner hints or operator projection text. It may reconstruct approval eligibility only from `RunStore` and audit metadata.

## Interrupt And Escalation Transitions

Operator interrupts must become durable state before they affect scheduling:

- `cancel`: mark run `Suspended` unless an effect is prepared, then enter recovery classification.
- `deny`: attach denied approval state and write `ApprovalBound` denial; no protected effect may be prepared.
- `timeout`: attach expired approval state and suspend the run.
- `escalate`: preserve pending approval and mark next operator action; no extra authority is granted.
- `retry`: allowed only after scheduler budget checks and policy reevaluation.

Escalation is a visibility mechanism. It does not approve the action.

## Exact Validation After Restart

Before a protected step resumes after restart, Agent Runtime must:

1. Load `PlanRun` and frozen plan hash from `RunStore`.
2. Rebuild the routed policy request from the frozen `PlanStep`.
3. Recompute normalized `parameter_hash`.
4. Read approval/audit state.
5. Check actor, tool, resource, parameter hash, expiry and policy version.
6. Re-run policy evaluation.
7. Prepare an effect only if SecurityExecution returns an allowed decision and a matching lease.

If any value differs, the result is `AwaitingApproval`, `Suspended` or `FailedClosed`, not execution.

## Projection Requirements

Operator projection should expose pending approvals without secrets:

- `approval.run_id`
- `approval.step_id`
- `approval.status`
- `approval.risk`
- `approval.tool`
- `approval.resource_hash`
- `approval.parameter_hash`
- `approval.policy_version`
- `approval.expires_at`
- `approval.next_operator_action`
- `approval.escalation_reason`

Projection remains read-only. It can display and explain approval state; it cannot grant approval.

## Audit Requirements

Approval-related audit events must show:

- `PolicyEvaluated` for the protected step;
- `ApprovalBound` for grant or denial;
- exact `parameter_hash`;
- `policy_version`;
- summary redacted for secrets;
- no `EffectPrepared` on denied, paused, timed-out or expired approval paths.

## Failure Modes To Block

- Restart auto-approves a pending action.
- A broad approval token authorizes changed parameters.
- An expired approval resumes execution.
- Policy version changes but old approval remains valid.
- Approval projection text is treated as authority.
- Model output claims approval.
- Operator interrupt is lost on restart.

## Verification Mapping

| Requirement | Current evidence |
| --- | --- |
| Broad approvals are rejected | `agentd::safety::tests::broad_approval_token_cannot_authorize_changed_parameters` |
| Parameter mutation invalidates approval | `security_execution::policy_adapter::tests::approval_parameter_mutation_is_paused_not_allowed` |
| Protected step pauses without effect before approval | `agent_core::run_loop::tests::approval_required_step_pauses_without_preparing_effect` |
| Denied and timed-out approvals do not execute | `agent_core::run_loop::tests::denied_and_timed_out_approvals_do_not_prepare_protected_effect` |
| Pending approval survives recovery | `agent_core::run_loop::tests::recover_run_uses_persisted_state_projection` |
| Prompt injection cannot grant broad approval | `agentd::safety` prompt injection and approval tests |

## Follow-Up Tasks

- `TASK-ECO-004` and `TASK-ECO-005` must use the same exact-token model for artifact activation.
- `TASK-ARUN-023` should include pending approval and expired approval restart drills.
- `TASK-PROD-050` should include pending approval state in support bundles without exposing secrets.
