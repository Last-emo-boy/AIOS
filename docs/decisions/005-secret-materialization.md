# 005: Secret Materialization

Date: 2026-06-28
Status: Accepted
Task: `TASK-REAL-050`
Source: ADR-004 D6 (secret-materialization gate); `secret_runtime` handle/lease model review (2026-06-28); `security_execution_linux` confined-helper execve model
Supersedes: resolves and closes the ADR-004 D6 deferral; binds the cp8 "real tools that consume secrets" checkpoint

## Decision

ADR-004 implemented the secret *handle* layer — metadata, validation,
redaction, and one-shot lease rules (`secret_runtime`: `SecretHandle`,
`SecretUseLease`, `SecretRuntimePolicy`) — but deferred secret
*materialization* to this ADR (ADR-004 D6). This ADR decides, with binding
force, **how the real secret bytes behind a leased `secret://` handle reach a
namespace/seccomp/Landlock-isolated tool process at execution time**, and
nothing more.

The frozen handle model never carries bytes: a `SecretHandle` is a
single-token `secret://` reference plus `actor`/`allowed_tool`/`resource`/
`purpose`; a `SecretUseLease` is the one-shot, fully-bound authorization
(`actor` + `tool` + `resource` + `parameter_hash` + `policy_version` +
`expires_at`, `one_shot: true`, `consumed: false`) returned by
`SecretRuntimePolicy::require_secret_use_lease`. Materialization is the *only*
place in AgentOS where the plaintext exists, and it must exist there for as
short a window, on as narrow a path, as the kernel allows.

This ADR commits five binding decisions (D1–D5). The default posture
everywhere is: **the plaintext lives in RAM-backed root-only storage, crosses
the sandbox boundary through an inherited pipe read-end passed by file-
descriptor number, is read by the helper only after confinement is applied, and
is destroyed the instant the tool has consumed it.** No other crate gains
`unsafe`/FFI: all descriptor and syscall work stays in `platform_sys` per
ADR-004 D1.

## D1 — Backing store: root-only RAM-backed secret file, never the planner, never the disk

The real secret bytes live in a **root-only, RAM-backed file under a private
tmpfs mount owned by the supervisor**, not in the agent state and not in any
journaled partition.

- Location: `/run/agentos/secrets/<opaque-id>` on a **tmpfs** (`/run` is
  RAM-backed). The directory is mode `0700`, files mode `0600`, owned by outer
  root (the PID1/run-loop identity of ADR-004 D5). It is created in the
  **supervisor's mount namespace** and is **never** mounted into a sandboxed
  child's view.
- It is deliberately **not** on the writable GPT state partition
  (`/var/lib/agentos`, ADR-004 D5). Persisted, journaled, rollback-eligible
  storage is exactly what `fs.write.diff` operates on; secret plaintext must
  never enter that path, so the backing store is volatile by construction and is
  gone on reboot/power-loss.
- The `<opaque-id>` is **not** the `secret://` URI and is **not** derivable from
  audit; the URI (`SecretHandle::uri`) only ever names the handle, never the
  store path. The store is a sealed provider surface; `secret://` resolution to
  a store id happens only inside the supervisor under a validated
  `SecretUseLease`.
- Kernel keyring (`request_key`/`keyctl`) is the **rejected** alternative
  backing store (see Alternatives): it would force `keyctl` — a broad,
  bypass-prone multiplexer syscall — into the confined child's default-deny
  allowlist and entangle secret lifetime with `user_ns`/session keyring
  semantics, whereas a tmpfs file's lifetime is a single `unlink` the supervisor
  controls.

The plaintext is read from this store into the supervisor's own memory only at
the moment of injection (D2), and zeroized immediately after the write
completes. It never enters `agent_runtime` planner state, memory entries, or
model context — those surfaces already reject it (`RuntimeMemoryEntry::new`,
`SecretRuntimePolicy::inspect_boundary` on `SecretSurface::MemoryEntry`/
`ModelContext`/`PlannerOutput` return `ForbiddenRawSecret`).

## D2 — Injection path: pre-fork pipe, read-end inherited across `execve`, read after confinement

The secret crosses the sandbox boundary through a **pre-`fork` anonymous pipe
whose read-end is inherited by the execve'd confined helper and passed to it by
descriptor number in `argv`**. This is the decision; kernel keyring handoff is
rejected.

This is the only injection model that fits the existing execve-confined-helper
architecture without widening the kernel surface. Today the supervisor spawns
the helper through `platform_sys::spawn_and_wait` (fork + `execve`) with
`security_execution_linux::LinuxEnforcer::enforce_confined`, argv
`["confined", ns_csv, seccomp_csv, landlock_dir, vector, varg]`
(`crates/security_execution_linux/src/bin/sandbox_probe.rs::run_confined`). The
helper child, after `unshare`ing the namespaces and `fork`ing the new-pidns
PID 1, applies `set_no_new_privs`, then `apply_landlock_readonly`, then
`apply_seccomp_allowlist` **last**, then runs its vector. The secret read must
land **after** that final `apply_seccomp_allowlist` so the plaintext only exists
inside the fully-confined child.

Mechanism (the implementation contract cp8 must build, all FFI in
`platform_sys`):

1. **Parent (run-loop child of ADR-004 D5), pre-`fork`:** create an anonymous
   pipe. The read-end is **non-`CLOEXEC`** so it survives `execve`; the
   write-end is `CLOEXEC` so the helper never sees it. All other unrelated fds
   stay `CLOEXEC` (only this one read-end is intentionally inherited).
2. **Spawn:** call the confined helper with the read-end fd **number** appended
   to argv (e.g. a new `confined-secret` vector taking `<fd>`). The number is
   not secret; without the inherited descriptor it names nothing.
3. **Parent writes:** after the helper is spawned, the parent reads the
   plaintext from the D1 store into memory, writes it to the pipe write-end,
   `close`s the write-end (signalling EOF), and zeroizes its in-memory copy.
4. **Helper reads after confinement:** inside the new-pidns PID 1, after
   Landlock and the final seccomp allowlist are installed, the helper `read`s
   the inherited fd to EOF into a child-local buffer, then `close`s it. Because
   `read`/`close` are required by any static binary, they are already in the
   empirically-derived allowlist (ADR-004 D5); no new syscall is added to the
   default-deny filter, and **Landlock is filesystem-scoped and does not touch
   pipe reads**, so neither the seccomp nor the Landlock policy must be widened
   for secret transport.
5. The tool consumes the buffer; the helper zeroizes it before exec-completion
   or before handing it to the real tool's own consume-and-wipe path.

The plaintext therefore exists only: (a) momentarily in the supervisor between
store-read and pipe-write, and (b) inside the confined child between `read` and
zeroize. It never touches a filesystem visible to the sandbox, never an
argv/env slot, never an audit or log line.

Note on current surface: `platform_sys::spawn_and_wait(exe, args)` and the
`run_confined` vectors do **not** yet pass an fd; this ADR does not change frozen
or existing code. cp8 implements the new `platform_sys` spawn variant that
inherits the named read-end (the one new `unsafe`/FFI seam, kept in
`platform_sys` per ADR-004 D1) and the `confined-secret` helper vector. Until
that lands, secret-consuming tools stay gated (D5).

## D3 — One-shot lease consumption, bound and closed exactly once

Injection is authorized by exactly one `SecretUseLease`, consumed exactly once,
and the descriptor is closed whether or not the read succeeds.

- The supervisor obtains the lease only via
  `SecretRuntimePolicy::require_secret_use_lease(capability, handle, now)`, which
  enforces, against the frozen `CapabilityLease`: non-wildcard scope
  (`reject_wildcards`), `capability.actor == handle.actor`,
  `capability.tool == handle.allowed_tool`,
  `capability.resource == handle.uri`,
  `capability.risk == RiskClass::PrivilegedWithHumanApproval`,
  `capability.parameter_hash == handle.required_parameter_hash()` (which binds
  `actor` + `secret_handle` + `tool` + `resource` via `stable_parameter_hash`),
  and `capability.expires_at >= now`. The returned lease is
  `one_shot: true, consumed: false`.
- Materialization order is **bind, then consume, then inject**: the supervisor
  calls `lease.consume(now)` (frozen `SecretUseLease::consume`) — which fails
  closed on `consumed == true` (`LeaseDenied`) or `expires_at < now` and flips
  `consumed = true` — **before** it opens the D1 store and writes the pipe. A
  second injection attempt re-`consume`s, hits the already-consumed branch, and
  is denied; the store read never happens twice for one lease.
- The pipe is a per-exec object: the write-end is `close`d by the parent after
  one write, the read-end is `close`d by the helper after one read-to-EOF, and
  both ends are `close`d on **any** error path (spawn failure, short write,
  helper crash). A consumed lease plus a closed pipe is a terminal state; there
  is no descriptor left for a replay.
- Outcome is recorded only through
  `SecretRuntimePolicy::record_secret_use(journal, run_id, step_id, &lease,
  outcome)`, which logs `handle.uri`, `lease_id`, `one_shot`, `consumed`,
  `parameter_hash`, `policy_version`, and an `outcome` string that
  `ensure_no_secret` rejects if it looks secret-like — never the bytes.

## D4 — What must never happen (fail-closed invariants)

These are hard invariants; a build or test that can violate one is a defect, not
a degrade.

- **Never in `argv` or environment.** Only the read-end fd *number* is passed in
  argv; the plaintext is never an argument or env var of the helper or the tool.
- **Never on a planner-visible or persisted surface.** Never in `PlanSpec`,
  `Observation`, `MemoryEntry`, `ModelContext`, `PlannerOutput`,
  `CliProjection`, `TuiProjection`, never on the journaled state partition, never
  in a `fs.write.diff`/rollback artifact. The frozen
  `SecretRuntimePolicy::inspect_boundary` already returns `ForbiddenRawSecret`
  for raw values on the non-redacting surfaces and `Redacted` only for the three
  display/audit surfaces (`AuditSummary`, `CliProjection`, `TuiProjection`); this
  ADR adds no surface that carries plaintext.
- **Never in audit or logs.** Audit goes only through `record_secret_use`/
  `AuditJournal`; the only secret-adjacent token ever written is the `secret://`
  *handle URI*, never the value. Logs follow the same redaction discipline.
- **Never in the runtime memory store or model context.** `RuntimeMemoryEntry`
  construction rejects raw secret-like values; the planner only ever sees the
  handle reference, never the materialized bytes.
- **Never to disk inside the sandbox.** The backing store (D1) is RAM-backed and
  outside the child's mount namespace; the transport (D2) is a pipe, not a file;
  Landlock would deny a stray write anyway. The plaintext touches no
  filesystem the sandboxed tool can name.
- **Fail closed.** Absent/expired/wildcard/mismatched lease, an unavailable
  store, a non-inheritable descriptor, or a seccomp/Landlock setup error aborts
  injection with no plaintext emitted; the helper exits non-zero exactly as the
  existing `run_confined` setup-failure codes do.

## D5 — Gating the cp8 "real tools that consume secrets" checkpoint

This ADR is the hard precondition ADR-004 D6 named for checkpoint cp8
(Execution Sequencing step 8: real tools). A secret-consuming tool may ship at
cp8 only when **all** of the following are proven on KVM-CI (ADR-004 D5 runner):

1. The `platform_sys` fd-inheriting spawn variant and the `confined-secret`
   helper vector exist, with `// SAFETY:` notes and a real-syscall test, and all
   new FFI confined to `platform_sys` (ADR-004 D1); every other crate keeps
   `#![forbid(unsafe_code)]`.
2. A real-kernel test demonstrates end-to-end injection: a leased secret written
   to the pipe by the parent is read by the helper **only after**
   `apply_landlock_readonly` + `apply_seccomp_allowlist`, with `read`/`close`
   already in the allowlist and Landlock unwidened.
3. An adversarial test (extending the ADR-004 escape harness) proves the
   negatives of D4: the plaintext is absent from argv, env, `/proc/<pid>/cmdline`
   and `environ`, the audit journal, the memory store, and every sandbox-visible
   filesystem path; and a second `consume` of the same lease is denied.
4. The lease binding of D3 is exercised against the frozen oracle: a
   wildcard/mismatched/expired/wrong-risk capability yields `LeaseDenied`, a
   valid one yields a `one_shot` lease consumed exactly once. Per ADR-004 D2 the
   frozen decision is authoritative for this policy gate (real-stricter-passes).

Tools that need no secret continue to proceed without this path (ADR-004 D6,
cp6). `real_enforcement_claim` (ADR-004) does not flip on secrets alone, but a
secret-consuming tool that fails any of 1–4 blocks cp8 and therefore blocks the
claim.

## Consequences

- One new FFI seam (fd-inheriting spawn) is added to `platform_sys` and one new
  `confined-secret` vector to the `sandbox_probe` helper; no frozen crate
  (`agent_core`, `security_execution`, `agentd`) and no existing crate source is
  changed by this ADR.
- A RAM-backed `/run/agentos/secrets` tmpfs store and a sealed
  `secret://`→store-id resolver become supervisor responsibilities (ADR-004 D5
  run-loop identity).
- The frozen `secret_runtime` lease/handle/boundary model is the load-bearing
  authorization layer for materialization and remains read-only oracle; this ADR
  binds to it rather than extending it.
- cp8 acquires the four-part proof obligation of D5; the ADR-004 D6 gate is
  closed by this document.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Inherited read-end leaks to an unintended child via a later `fork`/`execve` | Only the single read-end is non-`CLOEXEC`; the helper `close`s it immediately after one read-to-EOF; all other fds stay `CLOEXEC`; the write-end is `CLOEXEC` so the helper never holds it. |
| Plaintext lingers in supervisor or child memory | Read store→write pipe→zeroize in the supervisor; `read`→consume→zeroize in the child; volatile RAM-backed store, no swap-eligible persistence; no copy into planner/memory/model surfaces. |
| Lease replay / double-injection | `lease.consume(now)` is called before any store read and is fail-closed on `consumed`/expiry; pipe ends `close`d on every path; a consumed lease + closed pipe is terminal. |
| seccomp/Landlock blocks the secret read | Transport is a pipe using `read`/`close`, already in the empirically-derived allowlist (ADR-004 D5); Landlock is filesystem-scoped and does not affect pipe reads — neither policy is widened. |
| Secret resurfaces in audit/logs/cmdline | Only `handle.uri` is ever logged (`record_secret_use`, `ensure_no_secret` on outcome); only the fd *number* is in argv; D5 adversarial test scans `cmdline`/`environ`/journal/memory/fs for the value. |
| Backing store persists across crash/rollback | tmpfs on `/run` (RAM), never the journaled `/var/lib/agentos` partition; gone on reboot/power-loss; `unlink` under supervisor control. |
| New FFI multiplies `unsafe` | One seam, confined to `platform_sys` with `// SAFETY:` + real-syscall KVM test; `#![forbid(unsafe_code)]` everywhere else (ADR-004 D1). |

## Alternatives Considered

| Alternative | Decision | Reason |
|---|---|---|
| Kernel keyring (`request_key`/`keyctl`) as transport and/or backing store | Rejected for D1/D2 | Forces the broad, bypass-prone `keyctl` multiplexer into the confined child's default-deny allowlist and entangles secret lifetime with `user_ns`/session-keyring semantics; the pipe needs only already-allowed `read`/`close` and a tmpfs file's lifetime is one supervisor-controlled `unlink`. |
| Pass the secret as an extra `argv` token or env var to the helper | Rejected for D2/D4 | Plaintext would be readable via `/proc/<pid>/cmdline`/`environ` and could reach audit; violates D4. |
| Bind-mount a secret file into the sandbox mount namespace | Rejected for D1/D2 | Puts plaintext on a sandbox-visible filesystem path and depends on Landlock/mount discipline to hide it; the pipe keeps the secret off every filesystem the tool can name. |
| Materialize the secret before applying seccomp/Landlock | Rejected for D2 | Plaintext would exist in a less-confined process state; reading after the final `apply_seccomp_allowlist` keeps the window inside the fully-confined child. |
| Store plaintext on the writable GPT state partition | Rejected for D1 | That partition is journaled and rollback/`fs.write.diff`-eligible; secrets must never enter persisted, recoverable storage. |

## Change Control

Changing this decision requires a new accepted ADR and updates to `TASK.md`,
`plan.json`, affected `TASK-*.json` files, safety gates, and runtime
verification evidence before implementation continues. Per ADR-002, any scope
change affecting security boundaries defaults to `defer` unless required to
satisfy an accepted MVP exit criterion. The frozen `secret_runtime` model is
read-only oracle (ADR-004 D2); changing the handle/lease semantics it defines is
out of scope for this ADR and requires its own change-control path.
