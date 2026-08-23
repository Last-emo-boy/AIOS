# AIOS

AIOS is an experimental Linux-based agent operating environment. The Linux kernel owns
processes, isolation, resources, and side effects; `agentd` turns operator intent into
semantic tool calls that must pass policy, approval, audit, and recovery boundaries.

The project is in **Developer VM / pre-alpha integration**. It is not production ready,
and `real_enforcement_claim` remains false.

## Current implementation

The repository currently contains three tracks:

```text
legacy oracle:  TUI -> AgentCore -> deterministic projection
daemon path:    HTTP /run -> llm_planner -> agent_runtime -> StdToolExecutor
kernel path:    security_execution_linux -> platform_sys -> Linux kernel
```

The daemon path supports real LLM provider calls, frozen tool routing, bounded replan,
audit, and a small read-only executor. The kernel path implements namespace, seccomp,
Landlock, cgroup, real-tool, write-diff, and recovery experiments. These paths are not
yet joined in the production daemon.

The appliance can boot a BIOS GRUB/GPT/ext4 image under QEMU through `early_init` and
the PID 1 smoke runtime. It does not yet boot the long-running production daemon, ship a
pinned kernel, support UEFI, or pass an enabled KVM escape gate.

See [current status](docs/current-status.md) for the authoritative capability and gate
matrix. Historical RC workflow evidence under `.workflow/` is retained as a projection
oracle and must not be treated as real Linux enforcement evidence.

## Build and verify

The workspace is pinned to Rust 1.85.0.

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

The real disk boot test requires QEMU and a prebuilt appliance image:

```bash
export AIOS_DISK_IMAGE="$PWD/appliance/disk.img"
export AIOS_DISK_MANIFEST_SHA="<contents of appliance/disk.img.manifest.sha256>"
AIOS_QEMU_REQUIRED=1 cargo test -p agentd_init \
  --test real_qemu_disk_boot -- --ignored --nocapture
```

## Safety boundary

- `ToolRouter` schema risk is authoritative; planner and HTTP risk fields are advisory.
- Direct `/execute` is audit-required and read-only. Side effects require a separate,
  exact operator approval flow.
- The unauthenticated HTTP API is restricted to numeric loopback addresses and bounded
  request sizes.
- Observing a failed operation is not success. Only prepared, observed, and successful
  effects may complete a run.
- Arbitrary shell remains forbidden in normal mode.

## Key documents

- [Real execution foundation](docs/decisions/004-real-execution-foundation.md)
- [Secret materialization](docs/decisions/005-secret-materialization.md)
- [Real LLM control plane](docs/decisions/006-real-llm-control-plane.md)
- [Current status](docs/current-status.md)
- [Linux sandbox](docs/linux-sandbox.md)
- [Boot chain](docs/boot-chain.md)
