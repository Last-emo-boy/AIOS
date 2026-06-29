# 004: Real Execution Foundation

Date: 2026-06-28
Status: Accepted
Task: `TASK-REAL-000`
Source: `research.md`; distribution gap assessment (2026-06-28); ADR-004 adversarial review (2026-06-28)
Supersedes: ADR-003 module/test-reuse rules; revises ADR-000/001/002 MVP exit, interactive-surface, and hardware assumptions

## Decision

AgentOS turns from a **deterministic projection** of an agent OS into a **real,
bootable, enforcing** one. We will build the real execution foundation now.

The contracts-first phase produced an unusually complete specification layer —
contracts, state machines, validators, trust models — but almost no real OS
behavior. The evidence is concrete:

- The boot "proof" is tautological: a ~150-byte stub ELF (`image/build-initramfs.ps1`)
  hardcodes the exact marker strings (`AGENTD_HANDOFF_OK`, ...) that the smoke
  test (`scripts/boot-smoke-test.ps1`) greps for, then `exit(0)`.
- No disk image, bootloader, or pinned kernel config exists in the repo (the
  smoke test downloads a floating Alpine `vmlinuz-virt` from a CDN).
- No namespace/seccomp/cgroup/Landlock syscall is ever issued. A sandbox
  "denies" a syscall via `Vec::contains`, not the kernel.
- The only real host effect is `fs.write.diff` plus an audit-journal append.
- `stable_contract_hash` advertises `sha256:` but computes FNV-1a (64-bit).

Weighted across boot, init, sandbox, execution, and crypto, the system is
~10–15% real. This ADR commits the remaining work through six binding decisions
(D1–D6).

## D1 — System-call layer: `platform_sys` over `libc` (purity boundary lifted)

The workspace-wide "depends only on `sha2`" coding rule is **lifted** for the
real backend. AgentOS reaches the Linux kernel through one new crate,
**`platform_sys`**, built on the `libc` crate plus the focused safe-wrapper
crates `seccompiler` (seccomp-BPF authoring) and `landlock` (Landlock ABI).

Rationale: the thesis is "Kernel handles reality"; the real OS must own an
explicit, auditable kernel contract. We accept higher `unsafe` cost for control,
but we do NOT hand-assemble BPF or hand-roll Landlock ioctls — those are the two
most bypass-prone surfaces, so we use audited wrapper crates for them while
keeping every other syscall as direct `libc` FFI.

Guardrails (binding):

- `platform_sys` is the **only** crate that makes direct `libc` FFI or contains
  syscall `unsafe`, and the only crate permitted non-`sha2` external deps without
  a further ADR. All other crates keep `#![forbid(unsafe_code)]`. (Every crate
  still transitively links libc via `std`; the invariant is "no direct FFI /
  syscall `unsafe` elsewhere.")
- `platform_sys` exposes safe, fallible wrappers (`Result<_, Errno>`); every
  `unsafe` block carries a `// SAFETY:` note and a real-syscall test on KVM-CI.
- Syscall surface in scope: `mount`/`umount2`/`pivot_root`,
  `unshare`/`clone3`/`setns` (user, mount, pid, net, ipc, uts, cgroup
  namespaces), seccomp via `seccompiler` (arch-guard-first, x32 handled,
  `PR_SET_NO_NEW_PRIVS`), Landlock via `landlock` (fail-closed if absent),
  cgroup v2 (cgroupfs + `clone3(CLONE_INTO_CGROUP)`), `signalfd`/`sigaction`,
  `waitpid`/`wait4`, `reboot`, `execve`.
- `clone_args` is pinned to a documented struct size with a kernel-floor gate
  (D5); if `CLONE_INTO_CGROUP` is unavailable, fall back to
  `unshare`+cgroup-write+`fork`.
- Between `clone3` and `execve`, the child does only async-signal-safe work
  (no allocator/stdio/TLS touch) to protect the multithreaded supervisor.

## D2 — Existing deterministic code: freeze, rebuild, and use as oracle

The current ~50K-LOC deterministic crates are **frozen read-only** and not
extended; real implementations are written in new crates.

- The frozen **Rust code** (state machines, validators, invariants) is the
  trusted **differential oracle**: for a given input the real backend's *policy
  decision* must agree with the frozen prediction — with a defined divergence
  rule: **real-stricter-than-oracle passes; real-looser fails.** The oracle binds
  only stable boolean policy/trust decisions where the frozen model is
  authoritative (routing allow/deny, risk class, approval-binding, trust gates).
  It does **not** bind kernel-enforcement outcomes or the seccomp allowlist —
  there the real kernel result is authoritative and the frozen `Vec`-based
  sandbox is explicitly non-authoritative (it is replaced, not matched).
- The frozen **FNV-hash-bound RC0–21 JSON evidence corpus** is separate: it is
  legacy, untrusted, and regenerated under SHA-256 (D4). "Frozen code = trusted
  oracle" and "frozen evidence = rebuilt" are distinct.
- New crates host the real foundation:
  - `platform_sys` — libc/seccomp/landlock wrappers (D1).
  - `agent_runtime` — the real, un-simulated orchestration **run loop** that
    subsumes the responsibilities of the frozen `lifecycle::Agentd` and
    `run_loop::AgentCore` (both kept read-only as oracle). This is the named home
    the first draft omitted.
  - `agentd_init` — the real PID1/init and supervisor (D3.2, D5).
  - `security_execution_linux` — the real enforcement backend.
  - real tool adapters.
- `runtime_contracts` is the one crate carried forward (shared vocabulary), with
  one mandatory change: real SHA-256 replaces FNV, and `stable_contract_hash` is
  renamed to stop mislabelling.
- This **supersedes** ADR-003's "Existing MVP modules must be reused and
  hardened, not duplicated" AND its Decision-section clause "the first runtime
  must reuse the existing `agentd` module boundaries and safety tests." The
  ADR-003 ownership boundary and Forbidden Paths otherwise remain in force and
  bind the new crates.

## D3 — First milestone: a fully un-simulated Developer-VM MVP

The target is a **complete, un-simulated MVP**, not a minimal slice. MVP exit
requires ALL of the following, each proven on KVM-CI; each maps to a numbered
checkpoint in Execution Sequencing:

1. (→cp2,3) A real static-linked `x86_64-unknown-linux-musl` `agentd`; stub ELF
   deleted.
2. (→cp4) Real PID1: `agentd_init` mounts `/proc` `/sys` `/dev` (devtmpfs),
   installs signal handlers, reaps children, never exits, and **forks a
   supervised child that hosts the `agent_runtime` run loop** (process model
   fixed in D5). The frozen lifecycle/run_loop tracks are reimplemented in
   `agent_runtime`, not edited.
3. (→cp6,7) Real bootable disk image: GPT + ext4 + GRUB (BIOS+UEFI) + pinned
   kernel + initramfs that `pivot_root`s onto the rootfs (D5), booting under
   QEMU/KVM to real agentd. Boot proof de-tautologized: agentd re-derives the
   runtime-manifest SHA-256 at runtime and answers a scripted serial command.
4. (→cp5) Real sandbox enforcement: user/mount/pid/net namespaces + cgroup v2 +
   seccomp-bpf + Landlock + `no_new_privs` on really-spawned children, proven by
   a real-kernel adversarial escape harness.
5. (→cp8) Real tools: `fs.read` actually reads; `svc.status`/`config.test`
   query **agentd's own service supervisor and real process/port probes** (NOT
   systemd — see D5 image identity); `fs.write.diff` + rollback against real
   files on the writable state partition; real audit and post-crash recovery.
6. (→cp1) Real crypto root: FNV→SHA-256 everywhere; evidence corpus regenerated.
7. (→cp9) Enforcement-claiming tests rewritten from "the projection says denied"
   to "the kernel blocked it," running in VM-in-CI.

Out of MVP (Alpha/Beta): Firecracker microVM; a real local/remote LLM (stub
planner stays acceptance-compliant); a full-screen interactive TUI (the serial
REPL is the MVP approval surface — see Supersession); power-loss-safe A/B
installer; `apt`/`dpkg` host package adapters (deferred with Firecracker —
isolated install is the Alpha entry).

## D5 — Platform baseline and image identity (binding)

These resolve the realism gaps the review surfaced. Each is a decision, not an
option.

- **Image identity = minimal static-musl appliance.** `agentd` is the sole PID1;
  there is no systemd and no glibc/apt userland in MVP. Userland = `agentd` +
  busybox coreutils in the rootfs. This is the necessary consequence of
  "agentd as real PID1"; a Debian+systemd image where agentd is merely a service
  is rejected as not-an-agent-OS. (Reconciles ADR-001's apt target by deferring
  host package management to Alpha's isolated-install path.)
- **Kernel = vendored, pinned by exact version + SHA, built from a committed
  config.** The Alpine-CDN download path is killed exactly as the stub ELF is.
  Minimum kernel **6.6 LTS** (covers cgroup v2, `clone3`/`CLONE_INTO_CGROUP`,
  Landlock ABI≥3). Required `CONFIG_*`: `USER_NS`, `PID/NET/MOUNT/IPC/UTS_NS`,
  `SECCOMP`+`SECCOMP_FILTER`, `CGROUPS`+cgroup-v2 unified, `SECURITY_LANDLOCK`,
  `EXT4_FS`, `DEVTMPFS`, virtio (`BLK`/`NET`/`CONSOLE`). Boot cmdline must carry
  `lsm=landlock,yama,bpf`. Landlock absence is a hard enforcement-profile
  failure, not a silent degrade. (Landlock TCP-network rules need 6.7+; MVP
  egress is enforced by netns+proxy, not Landlock-net, so 6.6 suffices.)
- **Boot topology = minimal initramfs → `pivot_root` → GPT ext4 rootfs
  partition.** Mutable state is NOT in tmpfs. (cp7 实现注脚：从 initramfs 的 rootfs
  调 `pivot_root` 恒返回 EINVAL——rootfs 无父挂载、不可移动——故 boot 路径实现为
  **switch_root 序列**（`chdir`+`mount(MS_MOVE)`+`chroot`，均在 `platform_sys`）；
  `pivot_root` 封装保留给 cp5 沙箱子进程的真挂载 rootfs 切换。宿主内核 `EXT4_FS`/`VIRTIO_BLK`=m
  时 early_init 须 `finit_module` 按依赖序加载 `.ko.xz`（virtio_blk→crc16→crc32c→mbcache→jbd2→ext4）；
  vendored builtin-ext4 内核则模块列表为空、同一代码路径 no-op。本机 TCG 实测全链路通过，反假绿凭
  运行时派生量：root_dev major≠0 + root_fstype=ext4 + manifest SHA-256 运行时重算 + state_write=ok。)
- **Mutable/persistent state = a dedicated writable GPT partition** (ext4,
  journaled) mounted at `/var/lib/agentos`, with `fsync`/journal discipline that
  `fs.write.diff` + rollback + post-crash recovery depend on.
- **Process model = thin PID1 forks a supervised run-loop child.** `agentd_init`
  (PID1) owns mount/reap/signals/never-exit; the `agent_runtime` run loop lives
  in a supervised child; sandboxed tool processes are spawned from that child via
  `clone3`+`execve` with the async-signal-safe discipline of D1. This isolates
  the raw-clone child path from the multithreaded supervisor.
- **Network egress = fresh net namespace (loopback-only) + an in-VM userspace
  egress proxy that programs the allowlist.** Per-host/hostname allowlisting is
  done by the proxy (seccomp/Landlock cannot match hostnames; a bare net
  namespace has zero egress). MVP default is deny-all; `http.check` egress flows
  through the proxy only.
- **User namespace semantics = privilege *drop*, not gain.** Sandbox profiles are
  applied by the root PID1 inside the VM, which already holds the caps; `user_ns`
  is used to shed privilege for spawned children. Unprivileged-host operation is
  deferred.
- **Seccomp allowlist = empirically derived.** Generated by `strace`-ing the real
  static `agentd` and each diagnostic tool, then committed as authoritative (the
  current hand-written `sandbox.rs` allowlist cannot run any static binary — it
  is missing `rt_sigreturn`, `mprotect`, `getrandom`, `statx`, `getdents64`, ...).
  Where oracle and kernel disagree on syscalls, the kernel wins.
- **KVM-CI runner = a named class that exposes `/dev/kvm`**: bare-metal
  self-hosted or a GCP/large nested-virt instance (GitHub-hosted standard runners
  do not expose `/dev/kvm`). Non-enforcement tests may fall back to TCG software
  emulation; enforcement/escape tests require real `/dev/kvm`. Escape exploits run
  on a disposable, network-isolated runner (blast-radius containment).

## D6 — Secret materialization deferred to ADR-005 (gate)

Secret *handle* metadata, validation, redaction, and one-shot lease rules are
implemented (`secret_runtime`, `SecretHandle`, `SecretUseLease`). Secret
*materialization* — backing store, the syscall path that injects a leased secret
into a namespace/seccomp/Landlock-isolated child (pre-`fork` fd / kernel-keyring
handoff under `platform_sys`), and cross-boundary lease consumption — is
undecided. It is deferred to **ADR-005** and is a hard gate before the
"real tools that consume secrets" checkpoint (cp8). MVP tools that need no secret
proceed without it.

## Supersession and Revision

| Prior decision | Clause | Disposition |
|---|---|---|
| Coding rule (`research.md` / project convention, NOT ADR-001) | "workspace depends only on `sha2`" purity | Lifted for `platform_sys` and the Linux backend; `runtime_contracts` stays pure. (The original draft mis-cited this to ADR-001, which contains no dependency clause.) |
| ADR-001 | Target-hardware: "HW virtualization … not required to complete the first boot/control-plane slice" | Revised: KVM / nested-virt is now a hard MVP dependency for real boot/sandbox/test-validity. Firecracker stays deferred. |
| ADR-001 | Package management: Debian/Ubuntu apt target | Revised: MVP ships a static-musl appliance (busybox userland); host apt/dpkg deferred to Alpha isolated-install. |
| ADR-000 / ADR-001 | "Terminal/TUI is the MVP native/first interactive surface" | Revised: the serial **REPL** satisfies the MVP interactive + approval surface; the full-screen TUI is deferred. The approval-flow commitment is consciously re-scoped, not silently dropped. |
| ADR-002 | "Developer VM first **executable slice**" scope framing (exit criteria proper live in ADR-003 Alpha Gate + task JSON) | Revised: "executable" now means real kernel enforcement + real bootable image; projection-level completion no longer satisfies exit. |
| ADR-002 | Non-goals: seL4/Genode, multi-tenant, HA, native GUI, online self-update, normal-mode root shell; Firecracker→Alpha | Unchanged. |
| ADR-003 | "modules reused and hardened, not duplicated" + "reuse existing `agentd` module boundaries **and safety tests**" | Superseded by D2: rebuild in new crates; safety/enforcement tests rebuilt against the real kernel. |
| ADR-003 | Module Mapping table (`crates/agentd/src/*.rs`) | Superseded: those modules are the frozen oracle; real responsibilities move to the new crates. |
| ADR-003 | Forbidden Paths — **except** the distribution-image-blocking bullet | Unchanged and binding on the new crates. |
| ADR-003 | Forbidden Path "Distribution image work before generic AgentCore acceptance" + the 3-condition Alpha Gate | Revised: image work is on the MVP critical path, but the real `agent_runtime` run loop (D3.2) must land before image GA; the Alpha-Gate conditions become image-GA preconditions. |

## Claim semantics

- `production_ready_claim` stays **false** until Beta/GA: additionally requires
  the A/B installer, real signing/SBOM/provenance with an offline-verifiable
  trust root, remote audit, and an **external sandbox-escape security audit**.
- `real_enforcement_claim` flips **true** only when all seven D3 criteria pass on
  KVM-CI — equivalently, when Execution-Sequencing checkpoints 1–9 hold (the
  canonical gate; each D3 criterion maps to a checkpoint above). It must never be
  conflated with `production_ready_claim`.

## Execution sequencing (internal critical path)

Ordered so infrastructure precedes anything needing real syscalls/boot, and the
crypto root precedes the boot proof that depends on it:

0. Stand up the Linux build host + KVM-CI runner (D5) — prerequisite for every
   step below.
1. FNV→SHA-256 crypto-root swap in `runtime_contracts` (the boot proof in cp4
   re-derives a real SHA-256). RC0–21 evidence regeneration is tracked
   separately and may trail.
2. `platform_sys` skeleton + musl static-link de-risk: prove the carried-forward
   code links and runs statically.
3. `agent_runtime` real run loop (subsumes frozen `lifecycle::Agentd` +
   `run_loop::AgentCore`).
4. `agentd_init` real PID1 + real initramfs with the real musl binary (delete the
   stub); de-tautologize the boot proof. (Direct `-kernel`/`-initrd` boot here;
   the full GPT+GRUB disk boot is cp7.)
5. Real sandbox enforcement (`security_execution_linux`) + adversarial escape
   harness on a real kernel; empirical seccomp allowlist.
6. One real end-to-end effect inside the booted VM (real `fs.write.diff` + audit
   + verify-by-re-read) on the writable state partition — destroys the
   tautological smoke. (Secret-consuming tools gated on ADR-005, D6.)
7. Real bootable GPT+GRUB disk image with `pivot_root` to the ext4 rootfs.
8. Real tools (`fs.read`, `svc.status`/`config.test` via agentd supervisor,
   write-diff+rollback) + real post-crash recovery.
9. Rewrite enforcement-claiming tests against the real kernel; flip
   `real_enforcement_claim` only when 1–8 hold and the escape harness is green.

## Consequences

- New task namespace `TASK-REAL-*`; new crates `platform_sys`, `agent_runtime`,
  `agentd_init`, `security_execution_linux`, real tool adapters; follow-up
  ADR-005 (secret materialization).
- Frozen crates become a read-only differential oracle; their deterministic tests
  run as the oracle, not as a safety claim.
- CI moves to Linux + KVM; Windows/PowerShell evidence is legacy and rebuilt; the
  boot smoke and enforcement-claiming tests are tagged projection-only
  immediately.
- `research.md`, `TASK.md`, `plan.json`, and affected `TASK-*.json` are updated in
  the dedicated scope-change commit required by ADR-002.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| `libc` raw FFI multiplies `unsafe` | Confine all syscall `unsafe` to `platform_sys`; safe wrappers; `// SAFETY:` + real-syscall KVM tests; `#![forbid(unsafe_code)]` elsewhere; seccomp/Landlock via audited crates, not hand-rolled. |
| Full-MVP scope concentrates risk; a partial sandbox is worse than none | Ordered critical path; `real_enforcement_claim` gated on a real-kernel escape harness + (for GA) external audit; kernel/CONFIG/LSM baseline pinned (D5). |
| Real run loop had no home (review blocker) | `agent_runtime` named in D2 as the un-simulated loop subsuming both frozen tracks. |
| Freeze-and-rebuild drift / oracle vs reality | Oracle scoped to stable policy decisions with real-stricter-passes rule; kernel enforcement is authoritative, not oracle-bound; frozen code (trusted) vs FNV evidence (rebuilt) separated. |
| Non-determinism: real fs/timestamps/inode/pid/ordering (NOT LLM — stub planner is deterministic in MVP) | Normalize timestamps/inode/pid and use property assertions; temp-0/seeding applies only once a real planner enters Alpha. |
| KVM nested-virt CI flaky / security-sensitive | Named runner class exposing `/dev/kvm`; TCG fallback for non-enforcement tests; disposable network-isolated runner for escape exploits. |
| Image identity ambiguity (PID1 vs systemd/apt) | Resolved in D5: minimal musl appliance, agentd-as-sole-PID1; apt deferred to Alpha. |
| musl static link of a large `std` codebase | Dedicated de-risk at cp2 before PID1 depends on it. |

## Alternatives Considered

| Alternative | Decision | Reason |
|---|---|---|
| `rustix` for the whole syscall layer | Rejected for D1 | Chose `libc` for control; but adopted `seccompiler`/`landlock` for the two highest-risk surfaces rather than hand-rolling them. |
| Oracle-in-place (real backends behind the existing traits) | Rejected for D2 | Chose clean rebuild to avoid carrying simulation assumptions; frozen tree still serves as oracle. |
| Minimal real boot+execute slice first | Rejected for D3 | Committed to the full un-simulated MVP; the slice survives as checkpoint 6. |
| Debian + systemd rootfs, agentd as a service | Rejected for D5 | That is an agent daemon on Linux, not an agent OS; contradicts agentd-as-PID1. |
| systemd-boot (UEFI-only) | Rejected for D5 | GRUB gives BIOS+UEFI and avoids systemd-adjacent posture in an agentd-as-init appliance. |
| Keep Windows/PowerShell CI in parallel | Rejected for D4 | Real images/syscalls/escape tests require Linux+KVM; a parallel projection CI dilutes the real gate. |

## Change Control

Changing this decision requires a new accepted ADR and updates to `TASK.md`,
`plan.json`, affected `TASK-*.json` files, safety gates, and runtime
verification evidence before implementation continues. Per ADR-002, any scope
change affecting security boundaries defaults to `defer` unless required to
satisfy an accepted MVP exit criterion.
