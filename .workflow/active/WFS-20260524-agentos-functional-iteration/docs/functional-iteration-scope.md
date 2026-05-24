# AgentOS Functional Iteration Scope

## Decision

After Distribution Alpha, AgentOS should move from "runtime and image path
exists" to "useful operator capabilities exist". The work remains bounded by
the established thesis:

> Kernel handles reality; `agentd` handles intention.

Functionality is added by extending contracts and adapters behind the existing
runtime, not by giving `agentd` direct host authority.

## Included

- Package manager adapter family for metadata fetch, isolated install, smoke,
  host checkpoint, host promotion, host verification, and rollback evidence.
- Untrusted content adapter family for pinned fetch, size/content-type limits,
  sanitization, summary, source-to-sink policy, denied action projection, and
  local fixture replay.
- Firecracker executor integration for high-risk work, with dependency probing,
  fixture-backed fail-closed behavior, optional QEMU/Firecracker smoke, and no
  direct side-effect path.
- Operator UX and command surface for plan preview, approval/denial, audit
  projection, rollback, diagnostics, and support bundle export.
- Long-running AgentOS control-plane work: persistent state migration,
  health/diagnostics, audit retention/export, recovery drills, and upgrade
  readiness hooks.
- Functional release gates that can run in local-only mode and optionally use
  `E:\qemu\qemu-system-x86_64.exe`.

## Excluded

- Normal-mode arbitrary shell execution.
- Multi-tenant fleet orchestration.
- GUI as a primary native interface.
- External LLM as an acceptance dependency.
- Full seL4/Genode product line.
- Online self-modification of the running `agentd`.
- Production rollout automation before capability gates are stable.

## Promotion Rule

A capability cannot be considered ready until it has all of the following:

- typed request and response contract,
- semantic tool manifest entry,
- policy/risk mapping,
- capability lease and sandbox profile behavior,
- effect envelope lifecycle,
- audit projection and operator explanation,
- rollback or fail-closed semantics,
- local-only smoke,
- release gate evidence.
