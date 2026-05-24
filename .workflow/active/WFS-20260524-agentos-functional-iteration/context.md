# AgentOS Functional Iteration Context

Source: `research.md`
Workflow: `.workflow/active/WFS-20260524-agentos-functional-iteration`
Previous workflow: `.workflow/active/WFS-20260523-agentos-distribution-alpha`

## Current State

`main` contains the Distribution Alpha and production-ready candidate merge. The
runtime is now split into `agent_core`, `security_execution`,
`runtime_contracts`, and `agentd`, and `cargo test --workspace` passes on the
merged main branch.

Alpha gives us a bootable/runtime-aware image path, service recovery,
package-install and untrusted-content workflow contracts, policy-pack defaults,
semantic tool manifest, release provenance, and QEMU runtime smoke. These are
still mostly contract/stub-first capabilities, which is correct for Alpha but
not enough for a useful long-lived AgentOS distribution.

## Functional Iteration Aim

The next iteration should make AgentOS more useful without relaxing the safety
model. The target is not "more autonomy"; the target is more real, operator
visible capabilities running through the existing AgentCore and
SecurityExecution chain.

The expected shape is:

```text
operator intent
  -> agentd CLI/TUI/API projection
  -> runtime_contracts typed request/response
  -> agent_core workflow orchestration
  -> security_execution prepare/execute/verify/seal/rollback
  -> audit/operator projection/release evidence
```

## Carry-Forward Constraints

- `agentd` must remain a composition, lifecycle, CLI/TUI, and operator
  projection layer.
- `agent_core` owns workflow orchestration, run state, scheduling, observation,
  memory, and capability workflow shape.
- `security_execution` owns side-effect authority, policy decisions,
  capability leases, sandbox profiles, effect envelopes, rollback, audit, and
  source-to-sink enforcement.
- `runtime_contracts` owns stable cross-crate request/response types.
- Packaging and scripts own distro artifacts, smoke tests, and release gates.
- External LLM, network, Firecracker, and host package manager availability are
  optional capability inputs, not baseline acceptance dependencies.

## Functional Capability Families

1. Real package management adapter behind `pkg.*`.
2. Real untrusted content fetch/sanitize adapter behind `content.*`.
3. Firecracker execution integration behind SecurityExecutionEngine.
4. Operator command surface and TUI/CLI workflows.
5. Update, rollback, support bundle, diagnostics, and audit export surfaces.
6. Functional release gate that replays all capabilities in local-only mode.

## Success Shape

This workflow is successful when each capability family has:

- a typed contract,
- a module owner,
- a semantic tool entry,
- policy and capability mapping,
- audit projection,
- failure/rollback behavior,
- a local-only or fixture-backed smoke,
- and a production-distro gate hook.
