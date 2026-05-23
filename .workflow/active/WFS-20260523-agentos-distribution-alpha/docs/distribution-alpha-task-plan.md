# Distribution Alpha Task Plan

Source: `research.md`
Workflow: `WFS-20260523-agentos-distribution-alpha`
Previous workflow: `WFS-20260522-agentos-runtime-foundation`

## Purpose

Distribution Alpha turns the runtime foundation into a packageable AgentOS
distribution path. The work begins with install contracts, then rootfs/image
assembly, packaged runtime smoke, QEMU boot/runtime smoke, release provenance,
and finally the first Alpha isolation workstreams.

The guiding rule is:

```text
Runtime Foundation proof -> rootfs runtime contract -> image assembly -> QEMU runtime proof -> promotion gate
```

## Runtime and Security TASK Expansion

The bottom Agent implementation and the AgentOS security execution substrate are
expanded in:

```text
.workflow/active/WFS-20260523-agentos-distribution-alpha/docs/agent-core-runtime-security-execution-expanded-tasks.md
```

That document is the Alpha carry-forward view of the completed Runtime
Foundation tasks:

- `TASK-ACR-001` through `TASK-ACR-010`: runtime data model, RunStore,
  ModelBroker, Planner, run loop, scheduler, observations, memory, service
  recovery migration, and adversarial runtime tests.
- `TASK-SEF-001` through `TASK-SEF-010`: EffectEnvelope, policy/capability
  adapter, lease-derived sandbox profiles, source-to-sink policy, secret handle
  leases, SecurityExecutionEngine, recovery, safety gates, audit projection, and
  final SEF verification.
- `TASK-DALPHA-009` through `TASK-DALPHA-012`: Firecracker executor profile,
  package install isolation, untrusted content workflow, and Alpha promotion
  audit.

The key runtime rule is that AgentCore decides the next desired state, while
SecurityExecutionEngine remains the only side-effect path.

## Scope

Alpha must install and validate:

- `agentd` boot handoff path and managed runtime path.
- Policy pack.
- Semantic tool manifest without normal-mode `shell.exec`.
- Stub/local-only ModelBroker config.
- Persistent run-state, audit, rollback, and memory directories.
- Release/provenance metadata with artifact hashes and gate commands.

Alpha must prove:

- Approved and denied service recovery runs through packaged AgentCore.
- QEMU sees boot handoff and packaged runtime availability.
- Release provenance records source revision, toolchain, dependencies, image
  inputs, runtime gates, and artifact hashes.
- Firecracker and high-risk workflows remain behind SecurityExecutionEngine.

## Waves

### Wave 0: Alpha Scope and Packaging Contract

- `TASK-DALPHA-000`: freeze Distribution Alpha scope and task graph.
- `TASK-DALPHA-001`: define rootfs runtime artifact install manifest.
- `TASK-DALPHA-002`: define runtime state directory and permission validation.
- `TASK-DALPHA-004`: package policy pack, semantic tool manifest, and ModelBroker defaults.

### Wave 1: Runtime-Aware Image Assembly

- `TASK-DALPHA-003`: implement rootfs staging and manifest validation.
- `TASK-DALPHA-005`: assemble runtime-aware initramfs/rootfs image path.

### Wave 2: Packaged Runtime Proofs

- `TASK-DALPHA-006`: run packaged service recovery smoke.
- `TASK-DALPHA-007`: add QEMU boot and runtime smoke gate.
- `TASK-DALPHA-008`: add release/provenance promotion gate for Alpha.

### Wave 3: Alpha Isolation Workstreams

- `TASK-DALPHA-009`: add Firecracker executor profile behind SecurityExecutionEngine.
- `TASK-DALPHA-010`: add package install isolation workflow.
- `TASK-DALPHA-011`: add untrusted content runtime workflow.

### Wave 4: Alpha Promotion Audit

- `TASK-DALPHA-012`: final Distribution Alpha audit and promotion decision.

## Hard Gates

- `cargo test -p agentd`
- `cargo test -p agentd safety::`
- `cargo test -p agentd agent_core::`
- `cargo test -p agentd agent_core::adversarial`
- `pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1`
- `pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/boot-smoke-test.ps1 -QemuPath E:\qemu\qemu-system-x86_64.exe -TimeoutSeconds 30`

## Non-Negotiable Constraints

- No normal-mode arbitrary shell.
- No model-to-tool direct execution.
- No raw secret values in config, model context, memory, audit, or provenance.
- No untracked generated artifacts staged into commits.
- No Firecracker side path outside SecurityExecutionEngine.
