# AgentOS Linux MVP Context

## 目标

把 `research.md` 中的 Agent-first OS 设想收敛为一个 Linux MVP：先证明 `agentd` 可以作为启动后的第一控制面，把 terminal、语义工具、capability、审计和恢复闭环跑通。

## 核心边界

- Kernel handles reality；`agentd` handles intention。
- Linux LTS 是主线基座；Firecracker 是危险动作隔离层，放在 Alpha 优先级。
- `agentd` 不是万能 shell，而是可审计的 capability compiler。
- 决策和执行分离：模型可生成 plan，副作用必须经过 policy、capability lease、audit 和 rollback。
- 所有外部内容默认不可信；MVP 先保留接口和测试，不把网页自动化作为核心交付。

## MVP 成功标准

- 可启动镜像进入 TUI 的目标路径明确，并有最小 smoke test。
- `read-only`、`write-with-diff`、`execute-with-confirmation` 三档 capability 有清晰 schema 和 runtime stub。
- 审计链采用 append-only event journal，具备崩溃后 reconcile 语义。
- 写入必须先在 shadow/overlay 工作区生成 diff，审批后才提交。
- 默认沙箱组合包括 namespace、cgroup、seccomp/no_new_privs，Landlock 作为文件访问加固层。

## Wave 0 冻结决策

- 产品形态：Developer VM first, Cloud VM compatible。
- 目标环境：`x86_64` Debian/Ubuntu-compatible Linux VM。
- 模型策略：external LLM optional-only；local-only 或 stub planner mode 必须工作。
- UI 策略：TUI 是 native MVP surface。
- 范围控制：Firecracker productionization、seL4/Genode、多租户、HA、native GUI、online self-update、normal-mode arbitrary root shell 均不属于 MVP。

## 推迟到 Alpha/Beta

- Firecracker runner 的完整生命周期和镜像治理。
- secrets handle 的生产级 keyring/agent 集成。
- A/B rootfs 升级、远程审计镜像、组织级策略治理。
- 多租户、HA、seL4/Genode 高安全产品线。
