# Distribution Alpha Entry Criteria

Source: `research.md`
Task: `TASK-RTF-004`
Workflow: `WFS-20260522-agentos-runtime-foundation`
Status: blocked until `TASK-RTF-005` completes the Runtime Foundation final audit

## Purpose

Distribution Alpha is not allowed to restart from the original MVP skeleton.
A bootable Linux image with an `agentd` binary is insufficient. The Alpha
distribution work must inherit the completed Agent Core Runtime and Security
Execution Foundation contracts so the image contains a real AgentOS control
plane, not only an early-userspace handoff demo.

The entry contract is:

```text
Runtime Foundation final audit
  -> installed agentd runtime
  -> installed policy and tool contracts
  -> persistent run, audit, and rollback state
  -> ModelBroker config
  -> inherited runtime safety and release gates
  -> Distribution Alpha VM image factory
```

## Entry Status

Distribution Alpha remains blocked after `TASK-RTF-004`. The bridge is now
defined, but the workflow is not closed until `TASK-RTF-005` produces the final
Runtime Foundation audit evidence.

Allowed after `TASK-RTF-004`:

- Create Distribution Alpha planning tasks that depend on this document.
- Define future rootfs install manifests and VM image factory tasks.
- Prepare Firecracker executor/isolation design tasks.

Not allowed until `TASK-RTF-005`:

- Promote a Distribution Alpha build.
- Treat the MVP initramfs skeleton as the Alpha base by itself.
- Remove or weaken runtime safety gates for image factory convenience.
- Replace Security Execution Foundation with Firecracker or a direct shell path.

## Required Runtime Foundation Prerequisites

Distribution Alpha tasks must depend on all of these Runtime Foundation proofs:

| Area | Required proof |
|---|---|
| AgentCore data model | `IntentCtx`, `PlanSpec`, `PlanStep`, `PlanRun`, `Observation`, and `RunState` are versioned, serializable, and secret-safe. |
| RunStore | In-flight `PlanRun` state can recover without model replay. |
| ModelBroker | Model access is explicit, bounded, metadata-only, and testable through stub/local provider mode. |
| Planner | Plans freeze before execution and cannot create effects. |
| AgentCore run loop | Generic run state can advance through planning, approval, execution, observation, verification, terminal, and recovery states. |
| StepScheduler | Dependencies, retry budget, and failure blocking are deterministic. |
| ObservationProcessor | Tool output and external content cannot directly become tool calls. |
| Memory | Memory is bounded, source-labeled, TTL-scoped, and cannot grant policy or capability authority. |
| Generic service recovery | nginx service recovery runs through AgentCore, not a dedicated workflow path. |
| Adversarial runtime tests | Planning injection, observation injection, memory poisoning, approval mutation, and malformed model output fail closed. |
| SecurityExecutionEngine | Every side effect goes through prepare, execute, observe, verify, seal, rollback, or failed-closed handling. |
| Audit projection | CLI/TUI can explain why a step ran, paused, denied, rolled back, failed closed, or sealed. |
| SEF final verification | `TASK-SEF-010` evidence proves the generic runtime path preserves semantic tools, policy, capability, sandbox, audit, rollback, and recovery. |
| Runtime final audit | `TASK-RTF-005` must pass before Alpha promotion begins. |

## Mandatory Rootfs Runtime Artifacts

The future Distribution Alpha rootfs must install and verify these runtime
artifacts. Paths are the initial contract and may only change through an
accepted decision that updates this document, the Alpha tasks, and release
gates.

| Artifact | Initial rootfs contract | Required validation |
|---|---|---|
| `agentd` | `/sbin/agentd` for boot handoff and `/usr/lib/agentos/agentd` or equivalent packaged binary path for managed runtime installs. | Version, hash, provenance, `AGENTD_HANDOFF_OK` or equivalent boot handoff, and AgentCore runtime commands available. |
| Policy pack | `/etc/agentos/policy/` | Policy version present; approval binding, denied shell, and high-risk pause rules load at runtime. |
| Semantic tool manifest | `/etc/agentos/tools/semantic-tools.json` | Manifest contains allowed semantic tools and explicitly excludes normal-mode `shell.exec`. |
| Run-state directory | `/var/lib/agentos/runs/` | Writable only by the runtime authority; survives restart; contains no raw secrets. |
| Audit directory | `/var/log/agentos/audit/` | Append-only runtime journal path exists; runtime audit projection can read latest and explicit run IDs. |
| Rollback directory | `/var/lib/agentos/rollback/` | Write-with-diff rollback handles persist and can be classified after restart. |
| ModelBroker config | `/etc/agentos/model-broker.toml` | Stub/local provider mode works without network or external LLM credentials; remote providers remain optional-only. |
| Runtime memory directory | `/var/lib/agentos/memory/` | Memory entries are bounded, source-labeled, TTL-aware, and secret-safe. |
| Release/provenance metadata | `/usr/lib/agentos/release/provenance.json` or release manifest equivalent | Records source revision, toolchain, dependency inventory, artifact hashes, runtime gate commands, and image inputs. |

## Distribution Alpha Gate Commands

Future Alpha tasks inherit these gates from the Runtime Foundation. A narrower
check cannot prove Alpha readiness unless the corresponding task explicitly
documents why the narrower scope is sufficient.

| Gate | Command or evidence |
|---|---|
| Full runtime regression | `cargo test -p agentd` |
| MVP safety substrate | `cargo test -p agentd safety::` |
| Generic AgentCore suite | `cargo test -p agentd agent_core::` |
| Runtime abuse suite | `cargo test -p agentd agent_core::adversarial` |
| Generic service recovery | `cargo test -p agentd agent_core::service_recovery` plus approved and denied CLI smoke where image changes touch runtime packaging. |
| Audit projection | Runtime audit projection shows approved and denied service recovery chains without leaking secrets. |
| Release/provenance | `pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1` |
| QEMU dependency gate | `scripts/build-release.ps1` dependency check, using `E:\qemu\qemu-system-x86_64.exe` when a full smoke is required. |
| Full QEMU boot smoke | Required when boot chain, initramfs, rootfs, runtime install path, or image factory changes affect boot handoff. |
| Artifact hygiene | Generated release, boot, target, and smoke artifacts remain ignored or intentionally tracked; no unrelated Rust WIP is staged. |

## VM Image Factory Prerequisite

The VM image factory must not be the next implementation layer unless it starts
from the generic AgentCore runtime contract. Image factory tasks must prove:

- `agentd` starts with AgentCore enabled, not only lifecycle skeleton mode.
- The rootfs includes policy pack, semantic tool manifest, and ModelBroker
  config before first boot smoke promotion.
- Persistent directories for runs, audit, rollback, and memory exist with
  runtime-safe permissions.
- Service recovery approved and denied paths can run from the packaged runtime
  or are explicitly deferred with a blocking Alpha risk.
- Release metadata records runtime gate commands and artifact hashes.

## Firecracker and Isolation Boundary

Firecracker is an Alpha executor/isolation workstream, not a replacement for
Security Execution Foundation.

Alpha may add Firecracker to isolate higher-risk executors, but Firecracker does
not remove the need for:

- Semantic tools.
- Policy evaluation.
- Exact approval tokens.
- Capability leases.
- Sandbox profile authority.
- EffectEnvelope state.
- Audit, verification, rollback, and recovery.

If Firecracker execution is added, it must be represented as a sandbox/executor
profile behind `SecurityExecutionEngine`, not as a parallel side-effect path.

## ModelBroker Rule

Distribution Alpha must remain runnable in stub/local-only model mode. External
LLM providers are optional and cannot be required by acceptance tests, boot
smoke, release promotion, or offline recovery.

Alpha ModelBroker config must prove:

- Stub or local provider works without network access.
- Provider metadata is logged without raw secrets.
- Invalid, oversized, timed-out, or canceled provider output fails closed.
- Model output cannot directly execute tools or weaken policy.

## Future Alpha Task Dependency Rule

Every future Distribution Alpha task that packages, boots, promotes, or tests a
VM image must depend on:

- `TASK-RTF-004` for this entry contract.
- `TASK-RTF-005` for final Runtime Foundation audit.
- `TASK-SEF-010` for final Security Execution Foundation verification.
- `TASK-ACR-009` for generic AgentCore service recovery proof.

The first Distribution Alpha plan must include explicit tasks for:

- Rootfs runtime artifact install manifest.
- Image factory with runtime-aware rootfs assembly.
- Runtime state directory and permission validation.
- Packaged service recovery smoke.
- QEMU boot and runtime smoke.
- Release/provenance promotion gate.

## Exit Criteria For This Bridge

`TASK-RTF-004` is complete when:

- Distribution Alpha is explicitly blocked until `TASK-RTF-005`.
- MVP skeleton alone is rejected as an Alpha base.
- Generic AgentCore service recovery is listed as a prerequisite.
- Runtime safety, adversarial, release, and QEMU gates are inherited.
- Rootfs runtime artifacts and persistent runtime directories are listed.
- Firecracker is positioned as an Alpha executor profile, not a SEF substitute.
