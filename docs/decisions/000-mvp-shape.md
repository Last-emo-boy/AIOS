# 000: MVP Product Shape

Date: 2026-05-22  
Status: Accepted  
Task: `TASK-AIOS-000A`  
Source: `research.md:33`

## Decision

The first AIOS MVP shape is **Developer VM first, Cloud VM compatible**.

The MVP optimizes for a single-operator developer VM that boots into `agentd` as the terminal-first control plane. The implementation must avoid assumptions that would block later Cloud VM use, but Cloud VM production operations, remote fleet management, and organization-level controls are deferred.

## Primary User

The primary operator is a developer or platform engineer working inside a controlled VM to inspect repositories, diagnose local services, repair environment problems, and review every side effect before it is committed.

## Primary Environment

- `x86_64` Linux VM.
- Single tenant and single operator.
- Debian/Ubuntu package-management target.
- Terminal-first interaction through `agentd` TUI.
- Local-only or stub planner mode must work; external LLM may be added only as optional planning enhancement.

## First Workflows

1. **Service recovery workflow**: diagnose a failing local service, run read-only checks, request confirmation for restart, verify health, and show an audit summary.
2. **Repository/environment self-bootstrap workflow**: inspect a repository, identify missing dependencies or setup problems, propose changes, and apply only through `write-with-diff`.
3. **Untrusted content summary workflow**: fetch or ingest untrusted content, sanitize it, summarize it, and prove it cannot silently trigger shell, login, download, or exfiltration actions.

These workflows deliberately cover the three MVP control surfaces: read-only diagnostics, constrained writes, and untrusted input handling.

## Deferred Shapes

Cloud VM is compatible but not the first optimization target. It enters after the local Developer VM path proves boot, audit, approval, rollback, and recovery semantics. Server, container, high-security seL4/Genode, and multi-tenant variants are deferred to later milestones.

## Rationale

Developer VM has the smallest coordination surface for proving the core thesis: `agentd` can act as a safe, auditable OS control plane without requiring immediate production fleet governance. It also keeps boot-chain, TUI, semantic tools, and rollback work testable on one machine.

Cloud VM remains architecturally compatible because the same Linux, cgroup, namespace, seccomp, audit, and recovery primitives are relevant there. The MVP must therefore avoid local-only shortcuts such as unmanaged shell access, implicit host mutation, or UI-only approvals.

## Consequences

- `TASK-AIOS-001` should build a local bootable VM image first.
- `TASK-AIOS-003` should optimize for terminal ergonomics over remote dashboard features.
- `TASK-AIOS-010` should use local service recovery as the first end-to-end Runbook.
- Fleet governance, remote audit mirrors, and HA are out of MVP.

## Alternatives Considered

| Alternative | Decision | Reason |
|---|---|---|
| Cloud VM first | Deferred | Higher approval, remote audit, rollout, and failure-domain complexity would slow the first executable slice. |
| Dual-track Developer VM + Cloud VM | Deferred | Useful later, but too easy to blur acceptance criteria during MVP. |
| Container first | Rejected for MVP | PID 1 and kernel boundary semantics are constrained by the host. |
| High-security seL4/Genode first | Rejected for MVP | Valuable product line, but driver, ecosystem, and team-cost risks are too high for the first delivery. |

## Change Control

Changing the primary MVP shape requires a new decision document that updates `TASK.md`, `plan.json`, Wave 1 task entry criteria, and all affected acceptance criteria before implementation proceeds.
