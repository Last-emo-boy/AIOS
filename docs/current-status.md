# AIOS Current Status

Updated: 2026-08-23
Engineering track: `feat/real-execution-foundation`
Claim level: Developer VM / pre-alpha integration

This file is the current engineering status entry point. `.workflow/state.json` still
tracks the legacy RC21 projection closeout and is not authoritative for the real Linux
implementation added after ADR-004.

## Capability matrix

| Area | Status | Current evidence | Remaining gate |
|---|---|---|---|
| Contracts, tool schemas, policy | Implemented | `runtime_contracts`, `security_execution` tests | Replace remaining projection-only consumers |
| LLM providers and plan bridge | Implemented | OpenAI-compatible and Anthropic providers, mock E2E | Production credentials and operator-confirmed replan UX |
| HTTP `/run` orchestration | Integrated for read-only work | daemon E2E, audit, bounded replan | Authentication if non-local transport is introduced |
| Direct `/execute` | Read-only and fail-closed | authoritative schema risk, audit required | Exact approval protocol for any side effect |
| Standard executor | Partial | real `fs.read`, bounded TCP check, procfs service query, audit query | Implement remaining tools through confined backend |
| Linux enforcement backend | Implemented in isolation | namespace, seccomp, Landlock, cgroup and real-tool tests | Wire `LinuxEnforcer` into the production daemon |
| Runtime recovery | Partial | event replay and audit reconciliation | Durable event store and verified recovery execution |
| Rollback | Partial | tested rollback paths | Production backend and durable rollback binding |
| Appliance boot | BIOS prototype | GPT/ext4/GRUB QEMU disk boot | Long-running daemon, pinned kernel, UEFI, stable device discovery |
| KVM enforcement claim | Blocked | job intentionally disabled | Trusted KVM runner and adversarial escape harness |
| Secret materialization | Not implemented | ADR-005 contract only | sealed tmpfs store and inherited-FD helper path |
| Release supply chain | Not ready | local packaging and metadata projections | SBOM, provenance, signing, reproducibility and promotion |

## P0 closeout baseline

The current P0 closeout batch freezes truthful baseline behavior:

1. `Effect` distinguishes `observed` from `succeeded`; failed observations cannot become
   `Confined` or `Completed`.
2. Direct execution takes authoritative risk from `ToolRouter`, requires audit, and
   denies side effects until an exact approval flow exists.
3. Rollback is recorded as complete only after the rollback executor succeeds.
4. The local HTTP API enforces loopback, read/write timeouts, and bounded request lines,
   headers, and bodies.
5. GitHub Actions YAML and strict workspace clippy are part of the merge gate.

Repository-wide `cargo fmt --all -- --check` still reports historical formatting drift,
including files outside this batch. Keep that cleanup as an isolated formatting-only
change so it does not obscure the execution-safety diff.

## Claims that must remain false

- `production_ready_claim=false`
- `real_enforcement_claim=false`
- Production signing, remote audit authority, support upload, remote dispatch, and
  production ring mutation remain disabled.

ADR-004 permits `real_enforcement_claim=true` only after every cp1-cp9 checkpoint passes
on KVM CI. A passing host test or TCG boot test is not equivalent to that gate.

## Next closeout batch

1. Introduce one confined executor adapter and wire the daemon to
   `security_execution_linux::LinuxEnforcer` without fallback to `StdToolExecutor` for
   side effects.
2. Boot the same long-running daemon from the appliance instead of the disk smoke init.
3. Persist the new runtime event log and bind recovery/rollback to durable identifiers.
4. Enable the pinned-kernel KVM escape job, then add UEFI and stable PARTUUID/LABEL boot.
5. Unify appliance and systemd packaging into one release artifact pipeline.
