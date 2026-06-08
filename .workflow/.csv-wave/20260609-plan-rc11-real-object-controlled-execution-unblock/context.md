# RC11 Plan Context

Session: `.workflow/.csv-wave/20260609-plan-rc11-real-object-controlled-execution-unblock`

RC10 closed as a non-GA fail-closed milestone. The remaining blockers are real immutable external HTTPS object publication, declared/current drift-zero reconciliation, installer quarantine fetch verification, two enrolled canary targets, exact approval, AgentCore PlanSpec binding, SecurityExecutionEngine approval, controlled activation execution, separate rollback approval, rollback execution authorization, and remote fleet execution.

RC11 is scoped to the AIOS body. It may consume or verify external HTTPS object metadata as an input, but it must not build mirror frontend, Nginx infrastructure, remote signer infrastructure, remote dispatch, production ring mutation, or signing ceremonies.

## Findings

- Architecture: AIOS owns local verification, PlanSpec binding, SecurityExecutionEngine gating, audit, rollback, and support/recovery evidence. Mirror and signer endpoints remain transport or external authority boundaries, not local task authority.
- Implementation: Follow RC8-RC10 task patterns with `.workflow/active/.../plan.json`, `workflow-session.json`, `.task/TASK-*.json`, docs, evidence, and later task scripts.
- Integration: The next executable task is a contract task, followed by local release object verification, drift reconciliation, installer quarantine verifier, canary/approval execution packet, activation/rollback evidence, support/recovery, and final audit.
- Risk: RC11 must deny before side effects if any required gate is absent, broad, stale, mismatched, or authority-broadening.

## Plan Overview

The generated RC11 plan creates `RC11-000` as the completed planning task and advances the active task pointer to `RC11-001`. The execution plan has five waves: contract, object/drift, installer, controlled execution, rollback/support/closeout.
