# 001: MVP Operating Assumptions

Date: 2026-05-22  
Status: Accepted  
Task: `TASK-AIOS-000B`  
Source: `research.md:21`

## Decision

The MVP operating assumptions are frozen for the Developer VM first path. These assumptions constrain Wave 1 implementation and prevent boot, model, UI, and package-management work from drifting.

## Assumption Table

| Research item | Status | MVP decision | Implementation consequence |
|---|---|---|---|
| Target hardware | Accepted | `x86_64` Linux VM first. Hardware virtualization should be available for future Firecracker work but is not required to complete the first boot/control-plane slice. | `TASK-AIOS-001` targets local VM boot first and must not require Firecracker to pass. |
| Network policy | Accepted | Host may have network access. Untrusted tasks default to no network or allowlisted egress through a controlled fetch/sanitize path. | Sandbox profiles must be able to deny or restrict network by capability. |
| External LLM | Accepted with constraint | External LLM is optional only. MVP must run in local-only or stub planner mode. | `Model Broker` interfaces may exist, but Wave 1 cannot require remote model credentials. |
| Tenant model | Accepted | MVP is single-tenant and single-operator. | No multi-tenant authz, org policy, or remote fleet RBAC in MVP. |
| GUI scope | Accepted | No native local GUI. TUI is the native surface; GUI can only be a later projection of terminal/control-plane state. | `TASK-AIOS-003` implements terminal-first UX and approval flow. |
| Package management | Accepted | Debian/Ubuntu package management is the first adapter target. | Package-related tests and docs should assume apt-compatible semantics unless changed by a later decision. |
| Reliability grade | Accepted | Target developer and operator recoverability first, not high-assurance certification. | Audit, rollback, and recovery semantics are mandatory; formal verification and certification are deferred. |

## Wave 1 Entry Constraints

- Boot work targets a local `x86_64` Linux VM image.
- `agentd` must boot without remote LLM access.
- The first interactive surface is terminal/TUI.
- Package-management assumptions should not leak into the core boot path.
- Any network-capable tool must be classifiable as trusted or untrusted before execution.

## Rejected or Deferred Implications

- ARM64 support is deferred until the MVP boot path is stable.
- Firecracker is not required for Wave 1 success.
- Multi-tenant identity, policy delegation, remote audit mirrors, and HA are deferred.
- Native GUI and web dashboard are deferred.
- High-assurance certification is not a Wave 0 or Wave 1 target.

## Change Control

Changing any accepted assumption requires updating this document, `plan.json`, affected task entry criteria, and the verification commands before implementation proceeds.
