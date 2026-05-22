# AIOS TASK

Source: `research.md`  
Workflow: `.workflow/active/WFS-20260522-agentos-runtime-foundation`
Previous workflow: `.workflow/active/WFS-20260522-agentos-linux-mvp`
Maestro session: `.workflow/.maestro/maestro-20260522-213125`

## 目标

构建 Linux-based AgentOS：先完成可启动 MVP，再补齐底层 Agent Core Runtime 和安全执行底座，最终推进到可发行的 AgentOS distribution。

一句话边界：

> Kernel handles reality；`agentd` handles intention。

## 当前判断

- 不重写内核；MVP 主线选择 Linux。
- 不把 LLM 放进 kernel；模型只能通过 `Model Broker` 参与计划、分类、摘要或解释。
- 不默认暴露任意 shell；所有副作用必须走 semantic tool、policy、capability、audit、rollback。
- Firecracker 作为危险动作隔离层进入 Alpha，不阻塞 MVP。
- seL4/Genode 是高安全版独立产品线，不拖慢 Linux 主线。

## 当前进度

- 当前 Maestro 计划已切到 Runtime Foundation：`.workflow/active/WFS-20260522-agentos-runtime-foundation`。
- Runtime Foundation 已完成详细 TASK 展开，状态为 `planned`：6 个 wave，26 个 task，覆盖 Agent Core Runtime、Security Execution Foundation 和 Distribution Alpha 入口门槛。
- `TASK-RTF-000` 已完成：Agent Core Runtime 和 Security Execution Foundation 边界已冻结为 accepted decision，AgentCore 初始实现选择 in-process inside `agentd`，Distribution Alpha 被阻塞到 generic AgentCore runtime 通过验收。
- `TASK-RTF-001` 已完成：runtime states、state transitions、audit event mapping、RunStore/AuditJournal source of truth、idempotency 和 recovery policy 已冻结为 contract。
- `TASK-RTF-002` 已完成：runtime module ownership、integration points、audit write rules、CLI/TUI entry points 和 duplicate-stack prohibition 已冻结。
- Wave 0 已完成：产品形态、运行假设、scope control 和 Wave 1 入口约束均已冻结。
- Wave 1 已完成：boot handoff、`agentd` lifecycle skeleton 和 terminal-first TUI surface 均已验证。
- Wave 2 已完成：semantic tool routing、append-only audit journal 和 recovery reconciler 均已验证。
- Wave 3 已完成：capability lease model、read-only sandbox executor 和 write-with-diff rollback flow 均已验证并归档。
- Wave 4 已完成：service recovery workflow、safety regression gate 和 release provenance flow 均已验证并归档。
- 最终全量完成审计已通过：所有 task JSON 为 `completed`，`.workflow` JSON 可解析，`cargo test -p agentd` 通过，release pipeline 通过，QEMU boot smoke 观察到 `AGENTD_HANDOFF_OK`。
- `TASK-AIOS-001` 已完成：最小 initramfs 通过 `E:\qemu\qemu-system-x86_64.exe` 启动，并观察到 `/sbin/agentd` 输出 `AGENTD_HANDOFF_OK`。
- `TASK-AIOS-002` 已完成：Rust `agentd` lifecycle skeleton 提供 local-only/stub 模式、健康状态、模块边界和 typed stub APIs。
- `TASK-AIOS-003` 已完成：terminal-first TUI surface 支持 intent、plan preview、approval/denial/timeout/suspended 和 audit projection。
- `TASK-AIOS-004` 已完成：semantic tool schema/router 支持 normalized params、`fs.write.diff` 风险分类，并拒绝 normal-mode `shell.exec`。
- `TASK-AIOS-005` 已完成：append-only JSONL audit journal 支持核心事件、未封口 effect 查询和 secret-like summary redaction。
- `TASK-AIOS-006` 已完成：recovery reconciler 可分类未完成 effect，写入 RecoveryStarted/Completed，并为写入类 effect 要求人工确认。
- `TASK-AIOS-007` 已完成：policy evaluator 支持 allow / deny / pause-for-approval，approval token 绑定 exact parameter hash，并记录 denied decision without execution。
- `TASK-AIOS-008` 已完成：read-only lease 可编译为 Linux sandbox profile，persistent write、fork fanout 和 denied syscall 均被 guard 拦截并记录。
- `TASK-AIOS-009` 已完成：`fs.write.diff` 先生成 shadow diff 和 rollback handle，commit 写入完整 audit 链，rollback 可恢复旧内容。
- `TASK-AIOS-010` 已完成：nginx service recovery fixture 可端到端运行，restart 需确认，denied 路径不准备 restart effect。
- `TASK-AIOS-011` 已完成：safety gate 覆盖 prompt injection、tool abuse、resource abuse、secret handle、rollback/recovery failure，并接入 CI。
- `TASK-AIOS-012` 已完成：release pipeline 可生成 agentd release build、initramfs、dependency inventory 和 provenance metadata。
- 下一执行任务：`TASK-RTF-003`，把 MVP safety invariants 继承为 runtime gates。

## Runtime Foundation 任务计划

目标：把已完成的 AgentOS MVP 安全底座，推进成真正的底层 Agent runtime。也就是让 `agentd` 不再只是 lifecycle skeleton、stub planner 和手写 workflow，而是具备通用的 Agent Core：接收 intent、生成冻结计划、调度步骤、处理观察、更新 memory、暂停审批、执行受控工具、恢复中断 run。

### 两层边界

- Agent Core Runtime：负责 intent、PlanSpec、PlanRun、ModelBroker、Planner、StepScheduler、ObservationProcessor、Memory 和 TUI/API run-state projection。
- Security Execution Foundation：负责 semantic tool、policy、capability lease、sandbox、EffectEnvelope、audit、verification、rollback 和 recovery。

关键约束：

- Model output 只能提出结构化计划或摘要，不能直接执行 tool。
- 所有 side effect 必须经过 Security Execution Foundation。
- Planner 的 risk hint 不是权限，PolicyEvaluator 才是权威。
- Observation 和 external content 默认不可信，不能直接触发高风险 sink。
- Memory 不允许保存 secret 明文或未经标记的不可信指令。
- Distribution Alpha 在 Runtime Foundation final audit 通过前不得启动。

### Runtime Foundation Wave 0：边界冻结

- `TASK-RTF-000`：冻结 Agent Core 和 Security Execution Foundation 边界（completed）
- `TASK-RTF-001`：定义 runtime state transitions 和 audit event mapping（completed）
- `TASK-RTF-002`：定义模块 ownership 与 runtime integration points（completed）
- `TASK-RTF-003`：把 MVP safety invariants 继承为 runtime gates（pending）

退出标准：

- AgentCore、ModelBroker、Memory、Planner、Scheduler、Policy、Capability、Audit、Rollback、Recovery 的职责明确。
- 没有 model-to-tool direct execution、planner-to-shell 或未记账写入路径。
- 已完成 MVP 的安全约束变成新 runtime 的入场门。

### Runtime Foundation Wave 1：Agent Core Contracts

- `TASK-ACR-001`：定义 Agent runtime data model（pending）
- `TASK-ACR-002`：实现 persistent PlanRun store（pending）
- `TASK-ACR-003`：实现 ModelBroker trait 和 stub provider（pending）
- `TASK-ACR-004`：实现 Planner，冻结结构化 PlanSpec（pending）

退出标准：

- `IntentCtx`、`PlanSpec`、`PlanStep`、`PlanRun`、`Observation`、`RunState` 可序列化、可恢复、可审计。
- `ModelBroker` 是唯一模型边界，并支持 local-only stub provider。
- Planner 只能冻结计划，不能执行 side effect。

### Runtime Foundation Wave 2：安全执行底座强化

- `TASK-SEF-001`：定义 generic EffectEnvelope contract（pending）
- `TASK-SEF-002`：创建 Agent step policy / capability adapter（pending）
- `TASK-SEF-003`：强化 lease-derived sandbox profile compilation（pending）
- `TASK-SEF-004`：定义 untrusted content source-to-sink policy（pending）
- `TASK-SEF-005`：实现 secret handle lease rules for Agent runtime（pending）

退出标准：

- 每个 side effect 都有 `EffectEnvelope`，从 prepare 到 seal / rollback 可追踪。
- AgentCore 只能通过 policy adapter 申请执行。
- Sandbox profile 从 capability lease 编译，不能由 planner 降级。
- untrusted content 和 secret handle 有明确 source-to-sink 约束。

### Runtime Foundation Wave 3：Generic Agent Run Loop

- `TASK-ACR-005`：实现 AgentCore run loop state machine（pending）
- `TASK-ACR-006`：实现 dependency-aware StepScheduler（pending）
- `TASK-ACR-007`：实现 ObservationProcessor 和 trust boundary handling（pending）
- `TASK-ACR-008`：实现最小 Agent memory layer（pending）
- `TASK-SEF-006`：实现 generic SecurityExecutionEngine bridge（pending）
- `TASK-SEF-007`：集成 recovery reconciler 与 Agent run state（pending）

退出标准：

- `PlanRun` 可经过 Accepted、Planning、Planned、AwaitingApproval、Executing、Observing、Verifying、Completed、Suspended、RollbackPending、Recovering。
- read-only step 可以自动执行并 seal，高风险 step 必须暂停审批。
- observation 不能直接变成 tool call。
- crash/restart 可以从 RunStore + AuditJournal 恢复状态。

### Runtime Foundation Wave 4：workflow 迁移与安全门

- `TASK-ACR-009`：把 service recovery 迁移到 generic AgentCore runtime（pending）
- `TASK-ACR-010`：加入 AgentCore adversarial runtime tests（pending）
- `TASK-SEF-008`：扩展 generic Agent execution safety gate（pending）
- `TASK-SEF-009`：构建 runtime audit projection 和 explainability chain（pending）
- `TASK-SEF-010`：运行 Security Execution Foundation final verification（pending）

退出标准：

- nginx service recovery 不再依赖专用手写 workflow，而是通过 generic AgentCore `PlanRun`。
- prompt injection、observation injection、memory poisoning、approval bypass、tool abuse、secret leak、half-committed effect 都进入 safety gate。
- TUI/CLI 可以解释每一步为什么运行、暂停、拒绝、回滚或 seal。

### Runtime Foundation Wave 5：发行版入口桥接

- `TASK-RTF-004`：定义 Distribution Alpha entry criteria from runtime foundation（pending）
- `TASK-RTF-005`：完成 Runtime Foundation final audit（pending）

退出标准：

- Distribution Alpha 明确依赖 AgentCore 和 Security Execution Foundation final audit。
- 后续发行版任务必须安装并验证 `agentd`、policy pack、tool manifest、run-state、audit、rollback、ModelBroker config。
- 所有 Runtime Foundation tests、safety gates、release/provenance checks 通过。

## 必须先冻结的决策

1. 首发产品形态：**已冻结为 Developer VM first, Cloud VM compatible**，见 `docs/decisions/000-mvp-shape.md`。
2. MVP 运行假设：**已冻结为 x86_64 Linux VM、Debian/Ubuntu、single-tenant/single-operator、TUI-first、external LLM optional-only**，见 `docs/decisions/001-mvp-operating-assumptions.md`。
3. 外部 LLM 策略：**已冻结为 optional-only；local-only 或 stub planner mode 必须可运行**。
4. Scope control：**已锁定 MVP non-goals 与回流规则**，见 `docs/decisions/002-mvp-scope-control.md`。
5. 首个真实 Runbook：已收窄为 service recovery，具体 fixture 留给 Wave 1/Wave 4 决策。

对应任务：`.workflow/active/WFS-20260522-agentos-linux-mvp/.task/TASK-AIOS-000.json`

## MVP 波次

### Wave 0：产品与架构冻结

- `TASK-AIOS-000`：冻结 MVP 产品形态与运行假设（父任务，completed）
- `TASK-AIOS-000A`：选择 MVP 产品形态与首批 workflow（completed，commit `6a7e6ab`）
- `TASK-AIOS-000B`：冻结 MVP 运行假设（completed，commit `951241d`）
- `TASK-AIOS-000C`：锁定 MVP non-goals 与 scope change control（completed，commit `a68e3bd`）
- `TASK-AIOS-000D`：把 Wave 0 决策传播到 Wave 1 入口条件（completed，commit `7281c8e`）

退出标准：

- 首发形态、目标用户、环境和前三个 workflow 明确。
- `research.md` 中未指定假设已经接受、拒绝或推迟。
- MVP non-goals 写入决策文档。

### Wave 1：可启动控制面

- `TASK-AIOS-001`：创建最小 Linux boot image，并验证 `agentd` handoff（completed）
- `TASK-AIOS-002`：实现 `agentd` lifecycle skeleton（completed）
- `TASK-AIOS-003`：构建 terminal-first TUI intent / approval surface（completed）

Wave 1 入口约束：

- 目标形态是 Developer VM first，Cloud VM compatible。
- 目标环境是 `x86_64` Debian/Ubuntu-compatible Linux VM。
- Wave 1 验收不能依赖 Firecracker、外部 LLM、fleet orchestration 或 GUI。
- `agentd` 与 TUI 必须支持 local-only 或 stub planner mode。
- normal mode 不允许任意 root shell。

退出标准：

- 最小镜像可以启动到 `agentd` / TUI 路径。
- `agentd` 有健康状态、模块边界和可测试 lifecycle。
- 操作员可以输入 intent，并看到确定性 plan preview。

### Wave 2：语义运行时与审计

- `TASK-AIOS-004`：定义 semantic tool call schema 和 router（completed）
- `TASK-AIOS-005`：实现 append-only audit event journal（completed）
- `TASK-AIOS-006`：实现 unfinished effects recovery reconciler（completed）

退出标准：

- normal mode 没有泛化 `shell.exec`。
- 每个 effect 都先写 `EffectPrepared`，再执行。
- 重启后能识别 prepared、observed、sealed、rollback-pending 状态。

### Wave 3：Capability、sandbox 与 rollback

- `TASK-AIOS-007`：实现 capability lease model 和 policy evaluator（completed）
- `TASK-AIOS-008`：为 read-only / low-risk tools 增加 Linux sandbox executor（completed）
- `TASK-AIOS-009`：实现 `write-with-diff` 和 rollback handle flow（completed）

退出标准：

- capability 分为 `read-only`、`write-with-diff`、`execute-with-confirmation`、`privileged-with-human-approval`、`never`。
- read-only 工具受 namespace、cgroup、seccomp/no_new_privs、可选 Landlock 约束。
- 写操作先生成 diff 和 rollback handle，审批后才提交。

### Wave 4：真实 workflow 与质量门

- `TASK-AIOS-010`：实现第一个 service recovery workflow（completed）
- `TASK-AIOS-011`：加入 adversarial / safety regression tests（completed）
- `TASK-AIOS-012`：建立 MVP build、provenance 和 release artifact flow（completed）

退出标准：

- 至少一个真实恢复 workflow 可端到端运行。
- prompt injection、越权、资源滥用、rollback failure 进入 CI gate。
- 构建产物带基本 provenance / dependency inventory。

## MVP 不做

- 不做完整 Firecracker 产品化，只保留接口设计和 Alpha 任务入口。
- 不做多租户、HA、组织级策略治理。
- 不做 seL4/Genode 高安全版。
- 不做默认 GUI；GUI 只能作为 terminal 状态投影。
- 不做在线自改 `agentd`，升级策略留到 Beta 的 A/B rootfs。
- 不做 normal mode 下的任意 root shell。

新增或恢复任何 deferred item 前，必须先写 accepted decision，更新 `TASK.md`、`plan.json`、受影响 task JSON 和验证门，并单独 commit。

## 安全底线

- 默认 deny arbitrary shell。
- 高风险动作必须 human-in-the-loop。
- 外部网页、邮件、文档、API 响应默认 untrusted。
- secrets 只允许 handle-only，不进入模型上下文、长期记忆或普通日志。
- 审批 token 必须绑定 actor、tool、resource、parameter hash、expiry、policy version。
- 没有 audit 和 rollback 语义的自动写入功能不能上线。

## 下一步

当前 Linux-based AgentOS MVP 任务计划已完成。后续新工作应从 Alpha backlog 或新的 workflow session 启动，并先写入 accepted decision、更新 `TASK.md` / `plan.json` / task JSON / 验证门后再执行。
