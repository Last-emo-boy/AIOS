# RC12 Plan Context

Session: `.workflow/.csv-wave/20260609-plan-rc12-real-object-controlled-unblock`

RC11 closed as a non-GA fail-closed milestone. The remaining blockers are external HTTPS object URI publication, declared/current drift-zero, object trust, freshness, quarantine fetch, payload quarantine, pre-interpretation verification, two canary targets, exact approval with audit sink/nonce/expiry, AgentCore executable PlanSpec, SecurityExecution allow, controlled activation, separate rollback approval, rollback PlanSpec, rollback audit journal, post-rollback observations, and remote fleet execution.

RC12 is scoped to the AIOS body. It may bind and verify externally published immutable HTTPS object metadata as input, but it must not provision mirror frontend, Nginx/TLS, remote signer, object storage, remote dispatch infrastructure, signing ceremonies, or production ring mutation.

## Findings

- Architecture: AIOS owns local verification, quarantine, AgentCore executable PlanSpec, SecurityExecutionEngine allow decisions, audit, rollback, and support/recovery evidence. Transport surfaces remain non-authoritative.
- Implementation: Follow the RC10/RC11 task pattern with workflow plan/session files, `.task/TASK-*.json`, docs, evidence, and later per-task scripts under `scripts/` plus ignored `.workflow/artifacts/` results.
- Integration: RC12 must consume RC11 final audit, RC11 byte map, drift-zero denial, descriptor verification, installer quarantine verifier, AgentCore/SecurityExecution handoff, approval, activation, and rollback support evidence.
- Risk: RC12 can only move from denial to controlled execution when every trust and approval gate is proved. Otherwise each task must fail closed with precise blockers and no side effects.

## Plan Overview

The generated RC12 plan creates `RC12-000` as the completed planning task and advances the active task pointer to `RC12-001`. The execution plan has six waves: contract, object/drift/trust, quarantine/execution package, canary approval, activation/rollback, and closeout.