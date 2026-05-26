# Guidance Specification: AgentOS Next Cadence

Session: `20260525-brainstorm-agentos-tui-prod-next`

Topic: functional and experience improvements after TUI-oriented Alpha.

## Positioning

AgentOS has reached `tui-oriented-alpha`: the TUI can drive durable AgentCore runs, approvals, denial, recovery, audit, support bundle export and ecosystem activation previews. The next cadence SHOULD move from line-oriented typed commands to a long-running operator environment that feels like the primary OS console.

This is still not a GA production-ready distribution claim. The next phase MUST improve operability, usability and production evidence without weakening the runtime boundaries already established.

## Baseline Constraints

- TUI MUST remain projection-controller only.
- AgentCore MUST own PlanRun lifecycle.
- SecurityExecutionEngine MUST remain the only side-effect authority.
- `agent_core::ecosystem` MUST own resolver and activation planning.
- `aom install/stage` MUST remain inert; activation MUST be runtime-mediated.
- Normal-mode arbitrary shell MUST remain denied.
- Baseline operation MUST remain local-only and MUST NOT require network, external LLM, Firecracker or host package manager.
- UX improvements MUST NOT create a bypass around typed command grammar, exact approval binding, audit or rollback.

## Core Terms

- `Operator Console`: the long-running terminal surface for monitoring, intent submission, approval, recovery and ecosystem operations.
- `Projection Store`: a deterministic materialized view derived from RunStore, AuditJournal, active artifact state and support bundle sources.
- `Command Palette`: typed action entry with discoverable commands, context binding and preview before dispatch.
- `Approval Center`: a dedicated workflow for exact approval binding, denial, expiry, risk explanation and rollback consequence display.
- `Run Workspace`: a focused view for one AgentCore run: plan, current step, audit, observations, approvals, recovery and artifacts.
- `Operational Capability`: a production workflow exposed through AgentOS, such as service recovery, package install isolation, update rollback or support bundle export.
- `AOM Ecosystem`: local-first artifact lifecycle for workflow/policy/model/knowledge/adapter/image packs.

## Non-Goals

- Do not build a GUI/web UI as the primary surface in this cadence.
- Do not add arbitrary shell escape as a convenience feature.
- Do not move resolver, planner, policy or side-effect logic into `agentd` or TUI.
- Do not make external network registry, external LLM, Firecracker or host package manager mandatory for baseline.
- Do not claim GA production readiness before signing ceremony, fleet rollout and operational policy waves.

## Feature Areas

### F-001 Full-Screen Operator Shell

Build a full-screen TUI shell with stable panes, navigation, command palette, status bar, run workspace, approval center and event feed. This SHOULD replace the line-oriented output as the normal human experience while preserving `--tui-scripted` for automation.

### F-002 Live Projection And Event Model

Add an internal projection refresh/event model so the TUI can update views without treating render cache as source of truth. It SHOULD derive state from durable runtime sources and support deterministic replay.

### F-003 Approval And Recovery Workbench

Upgrade approvals and recovery from views into first-class workflows: compare parameters, show policy reason, expiry, rollback handles, stale token state, recovery source and operator next actions.

### F-004 Operator Session And Profiles

Add local operator session state: selected workspace, command history, bookmarks, preferred views and role-aware command scopes. This MUST be sealed local state and MUST NOT become security authority.

### F-005 Capability Library And Workflow Catalog

Expose available operational capabilities and installed ecosystem artifacts as a navigable catalog. This SHOULD make AgentOS feel functional beyond recovery demos: services, packages, updates, content ingestion, model broker, memory and support operations.

### F-006 Production Update And Fleet Readiness

Turn A/B rootfs update, artifact activation, rollback drills and support bundle export into an operator-facing production operations path. Fleet control SHOULD be designed but can remain local/single-node first.

### F-007 Observability And Support Console

Add health, logs, audit, metrics, degraded-state explanation and support bundle workflow into one support console. The operator should understand what is wrong, what is blocked, and what evidence exists.

### F-008 Ecosystem Governance And Trust UX

Make AOM trust, signatures, revocation, policy overlays, compatibility and activation previews legible. The UX MUST explain why an artifact is installable, staged, blocked, revoked, incompatible or awaiting approval.

## Guidance For Role Analyses

Role analyses SHOULD propose an execution cadence, not a broad wishlist. Each recommendation SHOULD specify:

- What user/operator capability improves.
- Which existing boundary it must preserve.
- What state source is authoritative.
- What verification gate proves it.
- Whether it belongs before or after full-screen TUI shell.

Recommended bias:

1. Ship operator experience primitives first: shell, navigation, live projections.
2. Then expand workflows: approval/recovery workbench, support console, catalog.
3. Then harden production operations: update/fleet/signing/governance.
