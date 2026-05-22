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

## Next Task

Execute `TASK-DALPHA-001`: define the rootfs runtime artifact install manifest.
That manifest becomes the contract consumed by state directory validation,
packaging defaults, image assembly, QEMU runtime smoke, and release provenance.
