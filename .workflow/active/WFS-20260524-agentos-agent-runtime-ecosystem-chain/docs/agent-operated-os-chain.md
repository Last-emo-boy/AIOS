# Agent-Operated OS Chain

## Thesis

AgentOS 的核心不是“Linux 上跑一个 agent”。Linux 负责确定性现实边界，Agent Runtime 负责 OS 控制平面。也就是说，AgentOS 的日常运行、恢复、更新、生态激活和 operator projection 都应该由 Agent Runtime 驱动，而不是由一堆旁路脚本、人工 runbook 或 `agentd` 内部特判拼起来。

一句话：

```text
Kernel handles reality; Agent Runtime handles intention and operation.
```

## Layered Control Chain

```text
Bootloader / Kernel / initramfs
  -> agentd PID 1
  -> Agent Runtime control loops
  -> AgentCore PlanRun / Scheduler / Memory / Observation
  -> SecurityExecutionEngine
  -> semantic tools / adapters / sandbox / effect envelope
  -> audit / rollback / recovery
  -> operator projection / release provenance
```

`agentd` 是 PID 1，但不是大而全的 agent brain。它只负责启动、生命周期、进程集成、CLI/TUI/API、operator projection 和 runtime component wiring。真实的 OS 行为必须落在 Agent Runtime 和 SecurityExecutionEngine 中。

## OS Operation Modes

### Boot Mode

Goal: bring AgentOS from kernel handoff to a usable control plane.

Required chain:

```text
kernel handoff -> agentd lifecycle -> runtime artifact validation
  -> policy/model/tool config load -> run/audit/rollback recovery
  -> operator projection ready
```

Boot MUST NOT require external LLM, network, Firecracker or host package manager. If optional dependencies are missing, AgentOS should boot in degraded-but-explainable mode.

### Steady-State Mode

Goal: continuously observe OS state and operate through planned, bounded actions.

Core loops:

- observation loop: collect health, audit, service, runtime and ecosystem signals
- planning loop: turn operator intent or system condition into frozen PlanSpec
- scheduling loop: enforce dependency ordering, retry budget and backpressure
- execution loop: invoke SecurityExecutionEngine only
- projection loop: explain status, blocked actions, pending approvals and recovery needs

### Degraded Mode

Goal: keep OS explainable and recoverable when model/provider/adapter dependencies fail.

Rules:

- local/stub ModelBroker remains available
- read-only diagnostics stay available
- high-risk side effects remain paused or denied
- missing optional ecosystem dependencies block activation before `EffectPrepared`
- operator projection must explain the degraded reason

### Recovery Mode

Goal: reconcile durable runtime truth after crash, reboot or interrupted effect.

Required source of truth:

- RunStore for PlanRun and state transitions
- AuditJournal for durable effect truth
- rollback store for compensating action handles
- ecosystem active/staged state for artifact activation recovery

No recovery path may rely on model replay as the authority.

### Update Mode

Goal: stage and activate OS updates without breaking PID 1 or active artifacts.

Required chain:

```text
update metadata verify -> inactive slot stage -> runtime compatibility check
  -> active artifact compatibility check -> boot smoke -> promote or rollback
```

Updates MUST include active artifact set hash and runtime contract compatibility. A/B rootfs readiness must know which AgentOS artifacts were active when the update was staged.

## Agent Runtime Responsibilities

Agent Runtime owns:

- intent intake and normalization
- PlanSpec creation and freezing
- PlanRun state machine
- StepScheduler and retry/backpressure
- ObservationProcessor and trust labels
- Memory governance and quarantine
- ModelBroker routing in local/stub/optional remote modes
- recovery coordination from RunStore + AuditJournal
- ecosystem activation planning

SecurityExecution owns:

- policy authority
- capability leases
- sandbox profile compilation
- source-to-sink enforcement
- secret handle lease rules
- effect envelope state machine
- audit, verification, rollback and seal

agentd owns:

- PID 1 lifecycle
- process supervision boundary
- CLI/TUI/API command surfaces
- read-only operator projection
- support bundle projection
- wiring and configuration loading

## Non-Negotiable Invariants

- Model output cannot directly execute tools.
- Observation content cannot directly create tool calls.
- External content is untrusted by default.
- Memory cannot store raw secrets or privileged policy overrides.
- Planner risk hints are advisory; policy evaluation is authoritative.
- Artifact install/stage is inert; artifact activation is a controlled side effect.
- Every side effect must have an EffectEnvelope and audit trace.

## Production Distro Implication

Production Distro work should measure whether the OS can keep operating with the Agent Runtime as control plane:

- can it boot without network?
- can it explain current capabilities?
- can it recover unfinished effects?
- can it activate/deactivate safe ecosystem artifacts?
- can it reject unsafe artifacts?
- can it update and rollback with active artifact awareness?
- can it produce support evidence without raw secrets?
