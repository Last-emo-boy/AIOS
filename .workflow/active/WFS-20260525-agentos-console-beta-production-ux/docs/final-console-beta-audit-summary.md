# Final Console Beta Audit Summary

Workflow: `WFS-20260525-agentos-console-beta-production-ux`

Decision: `console-beta`. This is not a GA or Production Distro RC0 claim. `production_ready_claim=false` remains intentional.

## What Passed

- `cargo fmt --check`
- `cargo test --workspace`
- `cargo test -p agentd tui --no-fail-fast`
- `scripts/tui-replay.ps1`
- `scripts/production-runbook-smoke.ps1`
- `scripts/ecosystem-replay.ps1`
- `scripts/build-release.ps1 -QemuTimeoutSeconds 120`
- `scripts/boot-smoke-test.ps1 -QemuPath E:\qemu\qemu-system-x86_64.exe -TimeoutSeconds 120`

The final QEMU smoke observed `AGENTD_HANDOFF_OK`, `AGENTOS_RUNTIME_ARTIFACTS_OK`, `AGENTOS_TUI_CONSOLE_READY` and the runtime manifest hash marker. The boot smoke script now records machine candidates and selected machine, preserving `microvm` first with `pc` fallback.

## Console Beta State

- TUI has a full-screen-oriented pane layout model with deterministic wide and narrow snapshots.
- Command palette previews typed actions before dispatch.
- Event feed, gate status, release provenance, signing status and rollout ring panels are projection views.
- Approval Center shows exact binding, expiry, stale-token and denial paths.
- Recovery Workbench uses durable run store and audit journal state, without model replay.
- Support Console exports redacted bundles and explains degraded state.
- Capability Catalog and AOM artifact views are discoverable but cannot directly execute or activate.
- Fleet and governance surfaces are explicit preview-only designs.

## Boundary Audit

- TUI remains projection-controller only.
- AgentCore owns PlanRun lifecycle.
- SecurityExecutionEngine owns all side effects.
- TUI does not own planner, resolver, policy, signing, promotion, QEMU/rootfs validation, blocker clearing or remote rollout.
- Baseline remains local-only and does not require network, external LLM, Firecracker or host package manager.

## Release Position

Candidate release provenance reports `promotion.status=promotable` with no candidate blockers, but the product-level decision is still `production_ready_claim=false`.

That distinction matters: Console Beta has enough executable evidence for a strong operator experience, but Production Distro RC0 still needs real production signing, fleet authority, remote ecosystem operations and operational drills.

## RC0 Blockers

- Production signing ceremony, real keyring policy and key rotation are not implemented.
- Fleet rollout execution authority and rollback drills are preview-only.
- Support bundle upload implementation and destination trust verification are not implemented.
- Remote registry mirror refresh, trust distribution and quarantine implementation are not implemented.
- Organization policy overlay activation and conflict resolution are not implemented.
- Node-level rollout audit evidence and incident response drills are not proven across a real fleet.
- Public ecosystem governance, marketplace review and revocation operations require hardening.

## Next RC0 Chain

- `RC0-001`: production release signing ceremony and keyring trust store.
- `RC0-002`: immutable release channel metadata and rollback drill gate.
- `RC0-003`: fleet rollout authority split from TUI projection panels.
- `RC0-004`: support bundle upload implementation with destination trust and operator consent.
- `RC0-005`: remote registry mirror refresh with quarantine and replay evidence.
- `RC0-006`: organization policy overlay activation through AgentCore and SecurityExecutionEngine.
- `RC0-007`: node enrollment, local identity and fleet audit evidence model.
- `RC0-008`: long-running TUI session hardening, profile persistence and degraded offline UX.
- `RC0-009`: marketplace governance and artifact review workflow.
- `RC0-010`: production incident runbooks with recovery and rollback drills.
