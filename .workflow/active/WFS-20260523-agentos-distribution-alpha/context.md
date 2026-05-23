# AgentOS Distribution Alpha Context

Source: `research.md`
Workflow: `.workflow/active/WFS-20260523-agentos-distribution-alpha`
Previous workflow: `.workflow/active/WFS-20260522-agentos-runtime-foundation`

## Current Decision

Distribution Alpha starts only after Runtime Foundation final audit. The Alpha
work must package the completed Agent Core Runtime and Security Execution
Foundation into a bootable VM image path. A minimal initramfs that only prints
`AGENTD_HANDOFF_OK` is useful evidence, but it is not the Alpha product.

## Required Carry-Forward

- AgentCore must remain the generic runtime path for service recovery and later workflows.
- SecurityExecutionEngine remains the only side-effect path.
- Policy pack, semantic tool manifest, ModelBroker config, runtime state, audit,
  rollback, memory, and release provenance are required rootfs artifacts.
- Stub/local-only ModelBroker mode remains mandatory for acceptance.
- Firecracker is an Alpha executor profile behind SecurityExecutionEngine, not
  a replacement for semantic tools, policy, capability, audit, rollback, or recovery.
- The worker-facing ACR/SEF task expansion for Alpha continuation is documented
  in `docs/agent-core-runtime-security-execution-expanded-tasks.md`.

## Current Progress

- `TASK-DALPHA-006` is complete: `scripts/alpha-service-recovery-smoke.ps1`
  validates staged Alpha runtime contracts, runs approved and denied generic
  AgentCore service recovery, projects both audit journals, and fails closed if
  denied restart prepares an effect.
- The smoke keeps generated journals, reports, projections, and result JSON
  under `.workflow/artifacts/alpha-service-recovery/`.
- `TASK-DALPHA-007` is complete: `image/build-initramfs.ps1` now embeds Alpha
  runtime markers into early `/sbin/agentd`, and `scripts/boot-smoke-test.ps1`
  requires QEMU serial output to include both `AGENTD_HANDOFF_OK` and
  `AGENTOS_RUNTIME_ARTIFACTS_OK` plus the rootfs runtime manifest hash marker.
- `TASK-DALPHA-008` is complete: `scripts/build-release.ps1` now emits
  `agentos.distribution-alpha.provenance.v1`, records Alpha runtime/image
  inputs, service recovery smoke, full QEMU runtime smoke, dependency inventory,
  artifact hashes, and promotion status with blockers.

## Next Task

Execute `TASK-DALPHA-009`: represent the Firecracker executor profile behind
SecurityExecutionEngine. It must not introduce a parallel side-effect path or
weaken policy, capability, EffectEnvelope, audit, rollback, or recovery.

Read before execution:

- `.workflow/active/WFS-20260523-agentos-distribution-alpha/docs/agent-core-runtime-security-execution-expanded-tasks.md`
- `.workflow/active/WFS-20260523-agentos-distribution-alpha/.task/TASK-DALPHA-009.json`
