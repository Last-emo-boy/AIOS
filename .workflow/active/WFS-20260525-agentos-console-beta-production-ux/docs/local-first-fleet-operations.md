# Local-First Fleet Operations Model

## Status

This document defines a Console Beta preview model. It is not a GA fleet manager, not a remote command plane, and not a production rollout authority.

Console Beta remains complete on a single node. Every fleet concept below must degrade to local-only proof without network, external LLM, Firecracker, host package manager, remote registry, remote audit mirror or hosted control plane.

## Concepts

`node_identity` is a local, non-secret identity projection for one AgentOS installation. It may include node id, build channel, runtime contract version, architecture, release provenance hash, active artifact set hash and audit seal status. It must not include private keys, raw enrollment tokens or remote credentials.

`node_state` is derived from local evidence only:

- runtime health from `agentd` lifecycle projection
- PlanRun state from AgentCore RunStore
- side-effect truth from SecurityExecutionEngine AuditJournal
- ecosystem state from local pinned registry snapshot, staged set and active set
- update state from local update metadata and rollback evidence
- release state from local provenance, gate artifacts and signing status

`fleet_target` is a future grouping label, not an execution target in Console Beta. It can refer to a proposed set of node identities, a rollout ring, a policy overlay audience or a support cohort, but it cannot carry command authority.

`rollout_ring` is a projection-only label such as `local`, `canary`, `staging` or `production`. Ring membership in Console Beta is fixture or local evidence. It cannot trigger remote update, activation, package install, policy overlay, support upload or reboot.

## Single-Node Proof

The baseline proof remains a single-node proof:

- `cargo test --workspace`
- TUI scripted replay
- production runbook smoke
- ecosystem replay
- release build
- QEMU boot smoke with AgentOS runtime and TUI markers
- candidate signing status showing production signing blockers when production signatures are absent

These gates prove that AgentOS can run and operate locally. They do not prove remote fleet rollout readiness.

## Authority Boundaries

Remote commands cannot bypass local AgentCore and SecurityExecutionEngine. Any future remote request must enter as a local intent, be planned by AgentCore, be evaluated by local policy, and prepare side effects only through SecurityExecutionEngine.

The TUI may project future fleet state, rollout rings, mirror status and policy overlays. The TUI may not own:

- planner logic
- resolver logic
- policy logic
- approval validation
- production signing
- remote command dispatch
- side-effect execution
- rollback execution

Fleet metadata is advisory until local evidence binds it. A remote controller may never be stronger than local policy.

## Preview States

Fleet preview panels should use explicit states:

- `local-only`: single-node proof is complete without remote dependencies
- `preview-only`: projected future fleet information, no dispatch authority
- `not-configured`: remote service is absent and baseline is still valid
- `degraded`: local evidence is missing or stale
- `blocked`: local gates, signatures, trust, rollback or policy checks fail
- `disabled`: feature intentionally unavailable in Console Beta

No preview state may be named `ready` unless it is scoped, for example `local-proof-ready`. Avoid `production-ready` for fleet preview.

## Rollout Expectations

A future rollout must be staged through local authority:

1. Resolve candidate artifact or update metadata from local pinned snapshot or a trusted mirror result.
2. Bind candidate to release provenance, SBOM, update metadata, dependency inventory and detached signatures.
3. Build a local PlanRun for the node.
4. Require exact approval for host mutation or activation.
5. Stage into inactive slot or inert ecosystem staging.
6. Verify health using local checks.
7. Commit only through SecurityExecutionEngine.
8. Persist rollback handle and audit seal before declaring node-level success.

Remote orchestration may sequence nodes, but each node must independently enforce local policy and rollback.

## Rollback Expectations

Rollback ownership is local first:

- Rootfs rollback returns to previous active slot or active artifact set.
- Ecosystem activation rollback uses activation report and active-set lock hash.
- Package host promotion rollback requires exact prior checkpoint and audit binding.
- Support upload failure cannot mutate local runtime state.
- Remote mirror failure cannot mutate local active artifacts.

Fleet-level rollback can request local rollback intents, but it cannot directly mutate nodes.

## Local Proof Before Remote Work

Before implementing real remote fleet functionality, the project must have:

- deterministic node identity projection
- rollout ring projection tests using fixtures
- support bundle upload policy with fail-closed destination trust
- remote registry mirror UX with pinned local snapshot as baseline authority
- organization policy overlay preview with non-removable local safety invariants
- production signing material flow that distinguishes candidate signatures from production signatures
- QEMU smoke evidence for candidate runtime
- final Console Beta audit decision and RC0 blocker list

## Non-Goals

- No hosted control plane in Console Beta.
- No remote shell or remote arbitrary command execution.
- No remote override of local policy.
- No silent registry refresh.
- No automatic support upload.
- No production rollout claim without production signatures, rollback drills and node-level audit evidence.
