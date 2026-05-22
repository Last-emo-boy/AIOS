# Linux Sandbox

Task: `TASK-AIOS-008`

## Purpose

`agentd` compiles a read-only capability lease into a Linux sandbox profile before a diagnostic tool can run. The profile is selected from lease metadata, not from the model prompt:

- `tool`
- `resource`
- `risk`
- `parameter_hash`
- `policy_version`

For the MVP, the low-risk sandbox profile is `read-only-diagnostic-v1`. `write-with-diff` is intentionally left for the rollback flow in `TASK-AIOS-009`.

## Read-Only Profile

The profile requires:

- user, mount, pid, network, and cgroup namespace isolation
- `no_new_privs=true`
- cgroup v2 limits: `cpu.max`, `memory.max`, `io.weight`, and `pids.max`
- seccomp default deny-by-errno behavior with an explicit diagnostic syscall allowlist
- read-only bind mounts for the requested resource and diagnostic system views
- writable tmpfs only under `/tmp/agentd-sandbox`
- Landlock read/write restrictions when the base kernel supports it

`http.check` is the only read-only profile that receives network access, and its network allowlist is derived from the approved resource.

## Guard Semantics

The executor guard denies persistent writes for read-only leases, denies process fanout above `pids.max`, and logs denied syscalls as `SandboxDenied` audit events. This lets Windows-hosted development verify the policy compiler deterministically while the same profile fields remain the Linux execution contract.

## Verification

```powershell
cargo test -p agentd
cargo run -p agentd -- --sandbox-demo
Get-Content .workflow/artifacts/sandbox/demo.jsonl
```

The demo acquires an `fs.read` read-only lease, compiles it into `read-only-diagnostic-v1`, allows a read diagnostic, denies a write to `/etc/passwd`, denies a fork-bomb simulation above `pids.max`, and denies the `mount` syscall with audit entries.
