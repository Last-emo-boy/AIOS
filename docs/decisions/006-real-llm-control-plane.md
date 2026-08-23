# ADR-006: Real LLM Providers Remain an Untrusted Control-Plane Input

Status: Accepted
Date: 2026-08-19
Scope: `llm_planner`, `agent_runtime`, and the `agentd` HTTP daemon

## Context

ADR-000 through ADR-005 defined a deterministic orchestration boundary and a real Linux
execution foundation. The implementation now supports OpenAI-compatible and Anthropic
providers, but model output cannot become side-effect authority. The repository also
retains the older deterministic `AgentCore`/TUI stack as a differential oracle.

This ADR records the already implemented LLM integration and its binding limits. It does
not expand the MVP claim or supersede the ADR-004 KVM enforcement gate.

## Decision

### D1 — Providers produce intention only

`LlmProvider` may return a structured `RawPlan`. Provider output, retry behavior, model
identity, and network transport are not policy decisions. Missing credentials or provider
failure must fail closed or use an explicitly configured recorded/stub provider.

### D2 — The frozen tool router is authoritative

Every proposed step is rebuilt by the host and routed through the frozen `ToolRouter`.
The router validates the tool name and parameter schema and supplies the authoritative
`RiskClass`. Model-claimed risk, HTTP `PlanStep.risk`, and other planner hints are
diagnostic only and cannot lower authority requirements.

### D3 — Model provenance cannot directly authorize side effects

Model-derived content is marked `ModelOutput` and evaluated by the source-to-sink gate
before approval or execution. A model may propose read-only diagnostics. Write, restart,
package, activation, privileged, secret, or shell sinks require an operator-authored,
exactly bound follow-up plan. Arbitrary shell remains `Never` in normal mode.

An `approve=true` transport flag is not itself authority and must not convert model
provenance into operator provenance.

### D4 — Replan is bounded and audited

Replan attempts are bounded, support explicit abort/deadline signals, and write intent and
execution observations to the audit journal. Feedback may contain redacted observations,
but must not contain raw secrets or grant the model a capability lease.

### D5 — Execution success is explicit

Preparing or observing an effect does not mean the requested operation succeeded. The
daemon must carry an explicit success result. Only a prepared, observed, successful effect
may be verified, committed, or mapped to a completed runtime step.

Route rejection, missing implementations, I/O failure, and rollback failure must retain
their actual failure class; they must not be reported as Linux kernel confinement.

## Current implementation boundary

- `/run` integrates a provider, plan bridge, guarded runtime, audit, and a limited
  read-only `StdToolExecutor`.
- Direct `/execute` requires audit and only admits authoritative `ReadOnly` tools.
- `security_execution_linux::LinuxEnforcer` is not yet wired into the daemon.
- The HTTP API is unauthenticated and therefore restricted to loopback.
- The new runtime event log is not yet durable across process restart.
- The TUI continues to use the deterministic AgentCore path and is not a real-provider UI.

These limits are release blockers, not optional implementation details.

## Consequences

- LLM integration can advance independently without broadening side-effect authority.
- Read-only end-to-end tests are valid orchestration evidence, not enforcement evidence.
- Production side effects remain blocked until operator provenance, durable approval,
  Linux confinement, audit, verification, and rollback are joined in one path.
- ADR-004 `real_enforcement_claim` and `production_ready_claim` remain false.
