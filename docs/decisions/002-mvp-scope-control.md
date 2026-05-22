# 002: MVP Scope Control

Date: 2026-05-22  
Status: Accepted  
Task: `TASK-AIOS-000C`  
Source: `research.md:438`

## Decision

The MVP scope is locked around the Developer VM first executable slice. Deferred product lines and hardening work may shape interfaces, but they cannot become MVP exit criteria unless a new decision explicitly changes scope.

## MVP Non-Goals

| Non-goal | Status | Rationale | Re-entry path |
|---|---|---|---|
| Firecracker productionization | Deferred to Alpha | Firecracker is important for dangerous workloads, but requiring guest image lifecycle, networking, snapshots, and host orchestration would slow the first boot/control-plane proof. | Re-enter through Alpha runner task after semantic tools, audit, and capability leases exist. |
| seL4/Genode high-security product line | Separate product line | Strong capability model is valuable, but hardware, driver, toolchain, and formal/high-assurance costs exceed MVP scope. | Re-enter through a dedicated high-security roadmap with separate staffing and schedule. |
| Multi-tenant isolation and org governance | Deferred | MVP is single-operator; multi-tenant RBAC and policy delegation would change the threat model. | Re-enter after single-operator policy and audit semantics are stable. |
| HA, remote fleet management, and organization rollout | Deferred to Beta/Production | Requires remote audit, update orchestration, failure-domain handling, and runbooks beyond the first local VM proof. | Re-enter after boot image, recovery, and release artifact flow pass local gates. |
| Native GUI or web dashboard | Deferred | The native UI is terminal/TUI; GUI must not become the security boundary. | Re-enter only as a projection of audited `agentd` state. |
| Online self-update of running `agentd` | Rejected for MVP | PID 1 self-mutation creates recovery and rollback hazards. | Re-enter as A/B rootfs or dual-slot update design in Beta. |
| Arbitrary root shell as normal tool | Rejected | It violates the semantic capability boundary and collapses audit, policy, and rollback guarantees. | Only a separately marked rescue/research mode may expose it, outside MVP normal mode. |

## Scope Change Control

Adding a deferred item to MVP requires all of the following evidence:

1. A new decision document with status `Accepted`.
2. Updated `TASK.md`, `plan.json`, affected task JSON files, and verification gates.
3. A risk note explaining how the change preserves audit, approval, sandbox, and rollback guarantees.
4. A commit dedicated to the scope change before implementation work begins.

If the scope change affects security boundaries, the default answer is `defer` unless the change is required to satisfy an already accepted MVP exit criterion.

## Security Boundaries That Must Not Weaken

- No default arbitrary shell in normal mode.
- Side effects require semantic tools, policy evaluation, capability lease, audit event, and verification.
- High-risk actions require human approval bound to exact parameters.
- External content remains untrusted and cannot directly drive dangerous sinks.
- Secrets remain handle-only and must not enter model context, long-term memory, or normal logs.

## Alpha/Beta Parking Lot

Alpha candidates:
- Firecracker runner for package install, arbitrary code, and untrusted web rendering.
- Secret handle integration with kernel keyring or narrow helper.
- More complete policy engine and approval token UX.

Beta candidates:
- A/B rootfs update and migration strategy.
- Remote audit mirror and observability.
- Provenance, signing, SBOM, image scanning, and rollout hardening.

Separate product line:
- seL4/Genode high-security AgentOS.
- Static system graph and formal assurance work.

## Consequences

Wave 1 tasks should remain focused on local Developer VM boot, `agentd` lifecycle, and TUI control. They may define extension points for deferred items but must not require those items for acceptance.
