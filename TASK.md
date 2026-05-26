# AIOS TASK

Source: `research.md`  
Workflow: `.workflow/active/WFS-20260524-agentos-agent-runtime-ecosystem-chain`
Previous workflow: `.workflow/active/WFS-20260524-agentos-functional-iteration`
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

- 当前 Maestro 计划已完成 Agent Runtime + Ecosystem Chain：`.workflow/active/WFS-20260524-agentos-agent-runtime-ecosystem-chain`。
- 本轮 final audit 已完成：`.workflow/active/WFS-20260524-agentos-agent-runtime-ecosystem-chain/evidence/FINAL-AUDIT-20260524-agent-runtime-ecosystem-chain.json`。
- 当前 promotion decision：`promote-to-next-production-distro-stage`；这不是 GA production-ready claim，production signing、fleet rollout、public ecosystem governance 仍是后续 wave。
- 本轮验证通过：`cargo test --workspace`、`scripts/functional-capability-replay.ps1`、`scripts/ecosystem-replay.ps1`、`scripts/build-release.ps1`、`scripts/boot-smoke-test.ps1 -QemuPath E:\qemu\qemu-system-x86_64.exe -TimeoutSeconds 30`。
- `TASK-PROD-050` 已完成：support bundle 现在包含 Agent Runtime loop、recovery、ecosystem registry/lockfile/active set、replay、revocation 和 offline baseline 状态，且不泄漏 raw secrets；`agentd` 仍是只读 projection，不拥有 resolver logic。
- `TASK-PROD-051` 已完成：release update metadata / provenance 已加入 active artifact set hash、runtime contract compatibility、rollback previous active set evidence 和 promotion blockers；当前 `promotion.status=promotable` 且 blockers 为空。
- `TASK-PROD-052` 已完成：ecosystem replay 增加 offline pinned snapshot drill；expired local registry snapshot 会 fail closed，并投影为 `degraded-expired-snapshot`。
- `TASK-PROD-053` 已完成：final Production Distro chain audit 和 summary 已写入 `.workflow/active/WFS-20260524-agentos-agent-runtime-ecosystem-chain/docs/final-chain-audit-summary.md`。
- Distribution Alpha 已在前序 workflow 完成：`.workflow/active/WFS-20260523-agentos-distribution-alpha`。
- `TASK-DALPHA-000` 已完成：Distribution Alpha scope 和任务图已冻结，新的 workflow、plan、context、task plan、`TASK-DALPHA-001` 到 `TASK-DALPHA-012` 均已写入 `.workflow/active/WFS-20260523-agentos-distribution-alpha`。
- `TASK-DALPHA-001` 已完成：rootfs runtime artifact install manifest 已定义，覆盖 boot/runtime `agentd`、policy pack、semantic tool manifest、ModelBroker config、run/audit/rollback/memory persistent directories、release provenance 和 rootfs manifest metadata，并提供后续 validator 可消费的 artifact ID 与 validation labels。
- `TASK-DALPHA-002` 已完成：runtime state directory and permission validation 已定义，覆盖 `/var/lib/agentos/runs/`、`/var/log/agentos/audit/`、`/var/lib/agentos/rollback/` 和 `/var/lib/agentos/memory/` 的 `root:root` / `0700` 初始权限、runtime authority、secret-safety、restart-survival、audit projection、recovery truth 和 evidence schema。
- `TASK-DALPHA-004` 已完成：packageable policy pack、semantic tool manifest 和 ModelBroker defaults 已写入 `packaging/agentos/rootfs/etc/agentos/`，保留 exact approval binding，normal-mode `shell.exec` 只作为 deny policy 出现且不在 semantic tool manifest 中，ModelBroker 默认 stub/local-only 且不需要 network 或 external credentials。
- `TASK-DALPHA-003` 已完成：新增 `scripts/validate-alpha-rootfs.ps1`，可在 `PackageDefaults` 阶段验证 `policy.pack`、`tools.semantic`、`model_broker.config` 和四个 persistent state directories，输出稳定 JSON；缺失 `model_broker.config` 的 fixture 已验证 fail-closed。
- `TASK-DALPHA-005` 已完成：新增 `image/build-alpha-rootfs.ps1`，并让 `image/build-initramfs.ps1` 默认执行 Alpha rootfs validation / staging；生成的 initramfs manifest 已嵌入 Alpha rootfs manifest、runtime artifact hashes、rootfs runtime manifest hash 和 blocking Alpha risks，boot handoff 仍保持 `/sbin/agentd` / `AGENTD_HANDOFF_OK`。
- `TASK-DALPHA-006` 已完成：新增 `scripts/alpha-service-recovery-smoke.ps1`，从 staged Alpha rootfs runtime contracts 运行 approved / denied generic AgentCore service recovery；approved restart-service 投影为 sealed 且 `CommitSealed=true`，denied restart-service 记录 `PolicyEvaluated` 且 `EffectPrepared=0`，ModelBroker 保持 stub/local-only，无需外部 LLM。
- `TASK-DALPHA-007` 已完成：`image/build-initramfs.ps1` 会把 `AGENTOS_RUNTIME_ARTIFACTS_OK` 和 rootfs runtime manifest hash marker 嵌入 early `/sbin/agentd`，`scripts/boot-smoke-test.ps1` 已从 handoff-only gate 升级为 runtime-aware QEMU gate；完整 QEMU smoke 观察到 `AGENTD_HANDOFF_OK`、runtime marker 和 runtime manifest hash marker。
- `TASK-DALPHA-008` 已完成：`scripts/build-release.ps1` 已升级为 `agentos.distribution-alpha.provenance.v1` promotion gate，记录 source revision、toolchain、dependency inventory、runtime manifest hash、image inputs、artifact hashes、Alpha service recovery smoke、full QEMU runtime smoke 和 gate commands；本次 gate 结果为 `promotion.status=promotable`，blockers 为空。
- 已按 Maestro 方式补充 Agent Core Runtime 和 AgentOS 安全执行底座的 Alpha 延续展开：`.workflow/active/WFS-20260523-agentos-distribution-alpha/docs/agent-core-runtime-security-execution-expanded-tasks.md`。这份文档把 `TASK-ACR-001` 到 `TASK-ACR-010`、`TASK-SEF-001` 到 `TASK-SEF-010`、`TASK-DALPHA-009` 到 `TASK-DALPHA-012` 串成从底层 Agent runtime 到发行版安全执行面的执行链。
- `TASK-DALPHA-009` 已完成：Firecracker executor profile 已放到 SecurityExecutionEngine 后面，缺 KVM、Firecracker binary、jailer、kernel image 或 rootfs image 会在 `EffectPrepared` 前 fail closed；planner hints 只记录为 ignored，profile selection 和 policy reason 进入 audit/explain，没有新增直接 Firecracker 执行 helper。
- `TASK-DALPHA-010` 已完成：新增 `agent_core::package_install` Alpha workflow contract，第三方包安装必须先经过 metadata fetch、isolated install、isolated smoke test、host checkpoint，再凭绑定 package、version、source URI、source digest 和 rollback id 的 exact approval 才能 host promotion；external/model source、失败隔离验证、缺 rollback/checkpoint 或 raw artifacts 都会 fail closed 且 `host_modified=false`，`safety::` 已纳入 `runtime-package-install-host-promotion-bypass`。
- `TASK-DALPHA-011` 已完成：新增 `agent_core::untrusted_content` Alpha workflow contract，外部内容经过 fetch、sanitize、summarize、source-to-sink policy check 和 audit projection；sanitized summary 只能作为 replanning context，不能直接驱动 shell、secret、privileged、package install 或 exfiltration sink，denied action 会进入 RuntimeAuditProjection 且无 `EffectPrepared`，`safety::` 已纳入 `runtime-untrusted-content-direct-sink-bypass`。
- `TASK-DALPHA-012` 已完成：Distribution Alpha final audit 已在 clean detached worktree `56278f05d4ca078efe18a3be7aa42d8789a5490f` 上复跑通过，覆盖 `cargo test -p agentd` 178 passed、`safety::` 18 passed、`agent_core::` 77 passed、`agent_core::adversarial` 5 passed、`scripts/build-release.ps1` 和 `E:\qemu\qemu-system-x86_64.exe` full QEMU runtime smoke；promotion decision 为 `promotable`，blockers 为空。
- Runtime Foundation 已完成执行与 final audit：6 个 wave，26 个 task，覆盖 Agent Core Runtime、Security Execution Foundation 和 Distribution Alpha 入口门槛。
- `TASK-RTF-000` 已完成：Agent Core Runtime 和 Security Execution Foundation 边界已冻结为 accepted decision，AgentCore 初始实现选择 in-process inside `agentd`，Distribution Alpha 被阻塞到 generic AgentCore runtime 通过验收。
- `TASK-RTF-001` 已完成：runtime states、state transitions、audit event mapping、RunStore/AuditJournal source of truth、idempotency 和 recovery policy 已冻结为 contract。
- `TASK-RTF-002` 已完成：runtime module ownership、integration points、audit write rules、CLI/TUI entry points 和 duplicate-stack prohibition 已冻结。
- `TASK-RTF-003` 已完成：MVP safety invariants 已提升为 Runtime Foundation gate，`cargo test -p agentd` 49 passed，`cargo test -p agentd safety::` 8 passed。
- `TASK-ACR-001` 已完成：新增 `agent_core::model` 版本化 runtime 数据模型，覆盖 `IntentCtx`、`PlanSpec`、`PlanStep`、`PlanRun`、`Observation`、稳定 JSON、secret-like 拒绝和 advisory risk hints，`cargo test -p agentd` 56 passed。
- `TASK-ACR-002` 已完成：新增 `agent_core::run_store`，提供 `RunStore` trait、`FileRunStore` 快照持久化、recoverable run 查询、observation hash、tamper detection 和 AuditJournal seal 对照，`cargo test -p agentd` 63 passed。
- `TASK-ACR-003` 已完成：新增 `agent_core::model_broker`、`ModelBroker` trait 和 deterministic `StubModelProvider`，覆盖 plan/classify/summarize/sanitize、metadata-only call log、bounded output、timeout/cancel/failure fail-closed 和 invalid output rejection，`cargo test -p agentd` 70 passed。
- `TASK-ACR-004` 已完成：新增 `agent_core::planner`、deterministic planner、PlanSpec validator 和 freeze hash，规划阶段只写 IntentReceived / PlanFrozen，拒绝 shell.exec、unknown tool、缺 rollback 写入和 secret-like plan，`cargo test -p agentd` 78 passed。
- `TASK-SEF-001` 已完成：新增 `security_execution::effect_envelope`，定义 side effect transaction envelope、Draft/Prepared/Observed/Verified/Sealed/RollbackPending/RolledBack/FailedClosed 状态机、AuditJournal 事件绑定、成功 verification 后才能 CommitSealed、failed write-with-diff verification 必须进入 RollbackPending，以及 secret-like 序列化拒绝，`cargo test -p agentd` 84 passed。
- `TASK-SEF-002` 已完成：新增 `security_execution::policy_adapter`，把 generic `PlanStep` 接入 `ToolRouter`、`PolicyEvaluator`、approval token 和 `CapabilityLease`，policy 风险分类覆盖 planner risk hints，denied / paused 路径只写 PolicyEvaluated、不准备 effect，`cargo test -p agentd` 90 passed。
- `TASK-SEF-003` 已完成：强化 lease-derived sandbox profile，`SandboxProfile` 序列化现在投影 namespace、cgroup、seccomp、filesystem、Landlock 和 network allowlist；新增 `security_execution::sandbox_profile`，只接受 `CapabilityLease` 作为 profile authority，planner sandbox weakening hints 会被记录为 ignored，unsupported risk classes fail closed，`cargo test -p agentd` 96 passed。
- `TASK-SEF-004` 已完成：新增 `security_execution::source_to_sink`，定义 operator/local/external/model/sanitized source labels 和 read/write/execute/privileged/network/secret sink classes，阻断 untrusted 或 model-origin content 直接驱动高风险 sink，denied 路径只写 PolicyEvaluated 且不准备 effect，`safety::prompt_injection` 直接覆盖该 policy，`cargo test -p agentd` 104 passed。
- `TASK-SEF-005` 已完成：新增 `security_execution::secret_runtime`，定义 `SecretHandle` metadata、raw secret forbidden surfaces、handle-preserving redaction、one-shot `SecretUseLease`、broad approval 拒绝和 handle-only audit，`safety::secret` 直接覆盖该 policy，`cargo test -p agentd` 114 passed。
- `TASK-ACR-005` 已完成：新增 `agent_core::run_loop`，实现 `AgentCore` 的 `accept_intent`、`plan_run`、`advance_run`、`approve_step`、`deny_step`、`suspend_run`、`recover_run` 和 compact projection；状态转移先通过 `RunStore` 落盘，read-only step 通过 `EffectEnvelope` 自动 prepare/observe/verify/seal，高风险 step 暂停且不准备 effect，denied/timeout 不执行受保护动作，`cargo test -p agentd` 121 passed。
- `TASK-ACR-006` 已完成：新增 `agent_core::scheduler`，实现 dependency-aware `StepScheduler`、DAG 校验、CommitSealed-backed ready-step selection、denied dependency blocking、retry budget fail-closed 和 deterministic scheduler explanation；Planner freeze 前会拒绝 missing dependency / cycle，AgentCore run loop 已改用 scheduler decision，`cargo test -p agentd` 128 passed。
- `TASK-ACR-007` 已完成：新增 `agent_core::observation`，实现 `ObservationProcessor`、observation trust labels、secret-like redaction、untrusted content sanitization、policy flag extraction、direct action source-to-sink denial 和 run loop observation ref 接入；observation 文本只能生成 sanitized replanning hint，不能直接创建 tool call，`cargo test -p agentd` 132 passed。
- `TASK-ACR-008` 已完成：新增 `agent_core::memory`，实现 `MemoryStore` trait、`InMemoryMemoryStore`、session/run/audit-derived/quarantined scopes、entry metadata、TTL expiry、bounded Planner context、secret-like redaction 和 suspicious/untrusted quarantine；memory poisoning 不能把 policy override、capability lease 或 approval claim 注入 Planner context，`cargo test -p agentd` 137 passed。
- `TASK-SEF-006` 已完成：新增 `security_execution::engine`，实现 `SecurityExecutionEngine` trait 和 `DefaultSecurityExecutionEngine`，统一 prepare / execute / observe / verify / seal / rollback / explain API；prepare 贯通 ToolRouter、PolicyEvaluator、CapabilityLease、lease-derived sandbox profile、EffectEnvelope、AuditJournal 和 write-with-diff rollback handle，denied / paused 不准备 effect，`cargo test -p agentd` 142 passed。
- `TASK-SEF-007` 已完成：新增 `agent_core::recovery`，实现 `AgentRunRecoveryCoordinator`，把 RunStore recoverable runs 与 AuditJournal durable effect truth 联合分类为 safe-to-verify、needs-rollback、needs-human-review、abandoned、failed-closed 或 completed，并恢复到 Recovering、Suspended、RollbackPending、Completed 或 FailedClosed；恢复 projection 明确 source=run-store+audit 且 no-model-replay，`cargo test -p agentd` 150 passed。
- `TASK-ACR-009` 已完成：service recovery 已迁移到 generic AgentCore runtime，Planner 产出完整 nginx recovery DAG，旧 `ServiceRecoveryWorkflow` 仅作为兼容 wrapper 委托到 `agent_core::service_recovery`，approved/denied CLI demo 和 latest audit timeline 均通过，`cargo test -p agentd` 153 passed。
- `TASK-ACR-010` 已完成：新增 `agent_core::adversarial` runtime abuse suite，覆盖 planning prompt injection、observation injection、memory poisoning、approval parameter mutation 和 malformed model output；CI safety / release gate 已加入 `cargo test -p agentd agent_core::adversarial`，`cargo test -p agentd` 158 passed。
- `TASK-SEF-008` 已完成：`SafetyGateConfig` 已升级为 generic Agent execution gate，required scenarios 纳入 model output injection、observation injection、memory poisoning、approval mutation、source-to-sink abuse 和 runtime recovery abuse，并要求同时运行 `cargo test -p agentd safety::` 与 `cargo test -p agentd agent_core::adversarial`，`cargo test -p agentd` 158 passed。
- `TASK-SEF-009` 已完成：新增 `RuntimeAuditProjection`，CLI `--audit-project` 和 TUI render helper，覆盖 latest / run-id、stable ordering、redaction、denied / no-effect、recovery source；`cargo test -p agentd` 163 passed。
- `TASK-SEF-010` 已完成：Security Execution Foundation final verification 已通过，覆盖 `cargo test -p agentd` 163 passed、`safety::` 16 passed、`agent_core::adversarial` 5 passed、`agent_core::service_recovery` 3 passed、approved / denied service recovery CLI smoke、runtime audit projection、release/provenance gate、initramfs build 和 QEMU dependency check。
- Runtime Foundation Wave 1 已完成：Agent Core Contracts 的数据模型、RunStore、ModelBroker 和 Planner 均已验证。
- Runtime Foundation Wave 2 已完成：EffectEnvelope、policy adapter、lease-derived sandbox profile、source-to-sink policy 和 secret handle lease rules 均已验证。
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
- `TASK-RTF-004` 已完成：Distribution Alpha entry criteria 已定义，明确 Alpha 不能只从 MVP skeleton 启动，必须继承 generic AgentCore、Security Execution Foundation、rootfs runtime artifacts、persistent runtime directories、release/provenance 和 QEMU gates。
- `TASK-RTF-005` 已完成：Runtime Foundation final audit 已通过，覆盖 54 个 workflow JSON 解析、`cargo test -p agentd` 163 passed、`safety::` 16 passed、`agent_core::` 68 passed、release/provenance gate 和 `E:\qemu\qemu-system-x86_64.exe` 完整 QEMU boot smoke。
- Runtime Foundation workflow 已完成；Distribution Alpha planning 已启动并完成 `TASK-DALPHA-000`。

## Distribution Alpha 任务计划

目标：把已完成的 Agent Core Runtime 和 Security Execution Foundation 装进可发行的 AgentOS Alpha rootfs / VM image 路径。Alpha 不能只复用 MVP handoff skeleton，必须安装并验证 `agentd`、policy pack、semantic tool manifest、ModelBroker config、run/audit/rollback/memory persistent directories、release/provenance metadata 和 QEMU runtime smoke。

关键约束：

- Distribution Alpha 依赖 `TASK-RTF-005` Runtime Foundation final audit。
- Stub/local-only ModelBroker mode 必须可运行；外部 LLM 不能成为验收依赖。
- Firecracker 是 Alpha executor profile，必须位于 `SecurityExecutionEngine` 后面，不能成为并行 side-effect path。
- 所有 promotion gate 必须继承 runtime、safety、AgentCore、adversarial、release 和 QEMU 验证。
- 生成的 image、cache、release artifact 和 boot log 不能进入提交。
- Alpha 视角的底层 Agent 与安全执行 TASK 展开见 `.workflow/active/WFS-20260523-agentos-distribution-alpha/docs/agent-core-runtime-security-execution-expanded-tasks.md`。

### Distribution Alpha Wave 0：Alpha scope 与 packaging contract

- `TASK-DALPHA-000`：冻结 Distribution Alpha scope and task graph（completed）
- `TASK-DALPHA-001`：定义 rootfs runtime artifact install manifest（completed）
- `TASK-DALPHA-002`：定义 runtime state directory and permission validation（completed）
- `TASK-DALPHA-004`：package policy pack、semantic tool manifest 和 ModelBroker defaults（completed）

退出标准：

- Alpha scope 明确拒绝 MVP skeleton-only promotion。
- rootfs manifest 覆盖 `agentd`、policy、tools、ModelBroker、run-state、audit、rollback、memory 和 release metadata。
- state directory permission、secret-safety 和 restart-survival 验证可被后续脚本消费。

### Distribution Alpha Wave 1：runtime-aware image assembly

- `TASK-DALPHA-003`：实现 rootfs staging and manifest validation（completed）
- `TASK-DALPHA-005`：assemble runtime-aware initramfs and rootfs image path（completed）

退出标准：

- image/rootfs assembly 必须先通过 runtime manifest validation。
- assembly manifest 记录 runtime artifact hashes 和 image inputs。
- QEMU handoff 仍兼容 `/sbin/agentd` 或 accepted equivalent。

### Distribution Alpha Wave 2：packaged runtime proofs

- `TASK-DALPHA-006`：运行 packaged AgentCore service recovery smoke（completed）
- `TASK-DALPHA-007`：增加 QEMU boot and runtime smoke gate（completed）
- `TASK-DALPHA-008`：增加 Distribution Alpha release/provenance promotion gate（completed）

退出标准：

- packaged runtime 能跑 approved / denied service recovery。
- QEMU smoke 证明 boot handoff 和 packaged runtime availability。
- provenance 记录 runtime manifest、image inputs、artifact hashes 和 gate commands。

### Distribution Alpha Wave 3：Alpha isolation workstreams

- `TASK-DALPHA-009`：把 Firecracker executor profile 放到 SecurityExecutionEngine 后面（completed）
- `TASK-DALPHA-010`：增加 package install isolation workflow（completed）
- `TASK-DALPHA-011`：增加 untrusted content runtime workflow（completed）

退出标准：

- Firecracker 不绕过 semantic tools、policy、capability、EffectEnvelope、audit、rollback 或 recovery。
- package install 不能未经验证和精确审批直接落到 host。
- untrusted content 不能直接驱动 shell、secret、privileged 或 exfiltration sink。

### Distribution Alpha Wave 4：Alpha promotion audit

- `TASK-DALPHA-012`：完成 Distribution Alpha final audit and promotion decision（completed）

退出标准：

- 所有 Alpha evidence 可追溯。
- runtime、safety、AgentCore、adversarial、release 和 QEMU gates 均有直接证据。
- 明确记录 promotion decision 或 blocking risks。

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

详细 TASK 展开：

- Agent Core Runtime 和 Security Execution Foundation 的 worker-facing 实施蓝图已经写入 `.workflow/active/WFS-20260522-agentos-runtime-foundation/docs/runtime-implementation-tasks.md`，逐任务详细规格已经写入 `.workflow/active/WFS-20260522-agentos-runtime-foundation/docs/agent-core-sef-detailed-tasks.md`。
- Distribution Alpha 的延续执行视角已经写入 `.workflow/active/WFS-20260523-agentos-distribution-alpha/docs/agent-core-runtime-security-execution-expanded-tasks.md`，把已完成的 ACR/SEF foundation 映射到 Firecracker profile、package install isolation、untrusted content workflow 和 final promotion audit。
- Agent Core Runtime 的底层实现链路固定为 `IntentCtx -> ModelBroker -> Planner -> PlanSpec -> RunStore -> StepScheduler`，它只负责意图、计划、状态、调度、观察、memory 和 projection。
- AgentOS 安全执行底座固定为 `SecurityExecutionEngine -> PolicyAdapter -> CapabilityLease -> SandboxProfile -> EffectEnvelope -> AuditJournal -> VerificationResult -> CommitSealed/RollbackPending/FailedClosed`，它是唯一 side-effect path。
- `TASK-ACR-001` 到 `TASK-ACR-010`、`TASK-SEF-001` 到 `TASK-SEF-010` 均已补充 `read_first`、`implementation_steps`、`failure_modes`、`verification_matrix` 和 `handoff`，后续可直接按 Maestro 执行或审计。

### Runtime Foundation Wave 0：边界冻结

- `TASK-RTF-000`：冻结 Agent Core 和 Security Execution Foundation 边界（completed）
- `TASK-RTF-001`：定义 runtime state transitions 和 audit event mapping（completed）
- `TASK-RTF-002`：定义模块 ownership 与 runtime integration points（completed）
- `TASK-RTF-003`：把 MVP safety invariants 继承为 runtime gates（completed）

退出标准：

- AgentCore、ModelBroker、Memory、Planner、Scheduler、Policy、Capability、Audit、Rollback、Recovery 的职责明确。
- 没有 model-to-tool direct execution、planner-to-shell 或未记账写入路径。
- 已完成 MVP 的安全约束变成新 runtime 的入场门。

### Runtime Foundation Wave 1：Agent Core Contracts

- `TASK-ACR-001`：定义 Agent runtime data model（completed）
- `TASK-ACR-002`：实现 persistent PlanRun store（completed）
- `TASK-ACR-003`：实现 ModelBroker trait 和 stub provider（completed）
- `TASK-ACR-004`：实现 Planner，冻结结构化 PlanSpec（completed）

退出标准：

- `IntentCtx`、`PlanSpec`、`PlanStep`、`PlanRun`、`Observation`、`RunState` 可序列化、可恢复、可审计。
- `ModelBroker` 是唯一模型边界，并支持 local-only stub provider。
- Planner 只能冻结计划，不能执行 side effect。

### Runtime Foundation Wave 2：安全执行底座强化

- `TASK-SEF-001`：定义 generic EffectEnvelope contract（completed）
- `TASK-SEF-002`：创建 Agent step policy / capability adapter（completed）
- `TASK-SEF-003`：强化 lease-derived sandbox profile compilation（completed）
- `TASK-SEF-004`：定义 untrusted content source-to-sink policy（completed）
- `TASK-SEF-005`：实现 secret handle lease rules for Agent runtime（completed）

退出标准：

- 每个 side effect 都有 `EffectEnvelope`，从 prepare 到 seal / rollback 可追踪。
- AgentCore 只能通过 policy adapter 申请执行。
- Sandbox profile 从 capability lease 编译，不能由 planner 降级。
- untrusted content 和 secret handle 有明确 source-to-sink 约束。

### Runtime Foundation Wave 3：Generic Agent Run Loop

- `TASK-ACR-005`：实现 AgentCore run loop state machine（completed）
- `TASK-ACR-006`：实现 dependency-aware StepScheduler（completed）
- `TASK-ACR-007`：实现 ObservationProcessor 和 trust boundary handling（completed）
- `TASK-ACR-008`：实现最小 Agent memory layer（completed）
- `TASK-SEF-006`：实现 generic SecurityExecutionEngine bridge（completed）
- `TASK-SEF-007`：集成 recovery reconciler 与 Agent run state（completed）

退出标准：

- `PlanRun` 可经过 Accepted、Planning、Planned、AwaitingApproval、Executing、Observing、Verifying、Completed、Suspended、RollbackPending、Recovering。
- read-only step 可以自动执行并 seal，高风险 step 必须暂停审批。
- observation 不能直接变成 tool call。
- crash/restart 可以从 RunStore + AuditJournal 恢复状态。

### Runtime Foundation Wave 4：workflow 迁移与安全门

- `TASK-ACR-009`：把 service recovery 迁移到 generic AgentCore runtime（completed）
- `TASK-ACR-010`：加入 AgentCore adversarial runtime tests（completed）
- `TASK-SEF-008`：扩展 generic Agent execution safety gate（completed）
- `TASK-SEF-009`：构建 runtime audit projection 和 explainability chain（completed）
- `TASK-SEF-010`：运行 Security Execution Foundation final verification（completed）

退出标准：

- nginx service recovery 不再依赖专用手写 workflow，而是通过 generic AgentCore `PlanRun`。
- prompt injection、observation injection、memory poisoning、approval bypass、tool abuse、secret leak、half-committed effect 都进入 safety gate。
- TUI/CLI 可以解释每一步为什么运行、暂停、拒绝、回滚或 seal。

### Runtime Foundation Wave 5：发行版入口桥接

- `TASK-RTF-004`：定义 Distribution Alpha entry criteria from runtime foundation（completed）
- `TASK-RTF-005`：完成 Runtime Foundation final audit（completed）

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

## AgentOS Functional Iteration 任务计划

Source: `research.md`  
Workflow: `.workflow/active/WFS-20260524-agentos-functional-iteration`  
Previous workflow: `.workflow/active/WFS-20260523-agentos-distribution-alpha`

目标：把 Distribution Alpha 从“可启动、可审计、可 promotion 的 runtime image path”，推进到“对操作员真正有用的 AgentOS 功能层”。这轮不追求更多自治，而是补齐真实 adapter、operator workflow、长期运行控制面和 functional release gate。

核心边界：

- `runtime_contracts` 定义稳定 request / response / report 类型。
- `agent_core` 负责编排 workflow、PlanRun、scheduler、observation、memory 和 projection 输入。
- `security_execution` 负责唯一 side-effect authority：policy、lease、sandbox、effect envelope、audit、rollback、source-to-sink。
- `agentd` 只负责 PID 1 lifecycle、CLI/TUI/API、operator projection 和 process integration。
- packaging / scripts 负责 rootfs artifact、fixture、smoke、release/provenance gate。

### Functional Iteration Wave 0：scope 与 capability matrix

- `TASK-FUNC-000`：冻结 functional iteration scope and capability matrix（completed）
- `TASK-FUNC-001`：定义 cross-crate capability contract ownership（completed）
- `TASK-FUNC-002`：定义 functional release gate and fixture strategy（completed）

退出标准：

- 用户可见能力映射到 owner module、runtime contract、semantic tool、policy、audit、rollback/fail-closed 和 release gate。
- 新功能不能只落在 `agentd` 里。
- baseline replay 不依赖 external LLM、network、Firecracker 或 host package manager。

### Functional Iteration Wave 1：真实 adapter contracts

- `TASK-FUNC-010`：扩展 package manager adapter contract and Debian fixture（completed）
- `TASK-FUNC-011`：扩展 untrusted content adapter contract and fetch fixture（completed）
- `TASK-FUNC-012`：扩展 Firecracker execution adapter contract and fail-closed fixture（completed）
- `TASK-FUNC-013`：增加 diagnostics and support bundle contract（completed）

退出标准：

- package、content、Firecracker、diagnostics/support bundle 都有 typed contract 和 fixture strategy。
- 可选宿主依赖缺失必须在 `EffectPrepared` 前 fail closed。
- fixture schema 可被最终 functional replay 复用。

### Functional Iteration Wave 2：workflow integration

- `TASK-FUNC-020`：把 package manager adapter 接入 AgentCore workflow（completed）
- `TASK-FUNC-021`：把 untrusted content adapter 接入 AgentCore workflow（completed）
- `TASK-FUNC-022`：把 Firecracker execution profile 接入 SecurityExecutionEngine（completed）
- `TASK-FUNC-023`：把 diagnostics/support bundle 接入 audit projection（completed）

退出标准：

- AgentCore 只负责编排，不直接执行 host mutation。
- SecurityExecution 仍是唯一 side-effect path。
- audit/operator projection 能解释 allowed、denied、paused、rollback 和 failed-closed 结果。

### Functional Iteration Wave 3：operator UX

- `TASK-FUNC-030`：增加 operator command registry and capability matrix projection（completed）
- `TASK-FUNC-031`：增加 approval、denial、rollback 和 audit command flows（completed）
- `TASK-FUNC-032`：增加 TUI capability workflow 和 support bundle export views（completed）

退出标准：

- 操作员能看到 AgentOS 当前能做什么、缺什么依赖、为什么被阻止。
- approval token 继续绑定 actor、tool、resource、parameter hash、expiry、policy version。
- TUI 是 runtime state projection，不是第二套 runtime。

### Functional Iteration Wave 4：long-running control plane

- `TASK-FUNC-040`：定义 persistent state migration and compatibility checks（completed）
- `TASK-FUNC-041`：增加 health、diagnostics 和 recovery drills（completed）
- `TASK-FUNC-042`：增加 audit retention、export 和 redaction gates（completed）
- `TASK-FUNC-043`：增加 update/rollback readiness hooks for production distro（completed）

退出标准：

- runtime state 有 versioned migration 和 compatibility gate。
- diagnostics/support bundle 不泄漏 secrets。
- update/rollback readiness 能作为 Production Distro 的入口条件。

### Functional Iteration Wave 5：functional promotion

- `TASK-FUNC-050`：构建 functional capability replay suite（completed）
- `TASK-FUNC-051`：把 functional replay 接入 release/provenance gate（completed）
- `TASK-FUNC-052`：运行 final functional audit 并决定下一步 production-distro gate（completed）

退出标准：

- `cargo test --workspace`、functional replay、release gate 通过或 blocker 明确。
- provenance 记录 capability matrix hash、fixture inventory hash 和 replay evidence hash。
- final audit 输出 `functional-ready`、`functional-remediation-required` 或 `rollout-blocked`。

## 下一步

Functional Iteration 已完成：typed contracts、AgentCore workflow bridge、SecurityExecution Firecracker fail-closed gate、operator command registry、support bundle projection、functional replay 和 release provenance gate 已落地。下一步进入 Production Distro 加固入口：以 functional replay、release gate、QEMU smoke、production signing verification 作为进入条件。

## Production Ecosystem Brainstorm

Source: 用户提出 AgentOS 未来可能需要类似 APT 的生态管理器，但它管理的对象不只是传统 package。  
Maestro brainstorm session: `.workflow/.csv-wave/20260524-brainstorm-agentos-production-ecosystem`

结论：AgentOS 需要 APT-like 的体验，但不能复制 APT-like 的信任模型。建议工作名为 `aom`，即 AgentOS Ecosystem Manager。它管理 AgentOS-native artifacts：capability pack、semantic tool pack、policy pack、workflow/runbook pack、model profile pack、knowledge pack、runtime adapter pack、execution image pack、test/replay pack 和 trust metadata。

核心不变量：

```text
install/stage != activate
```

`install/stage` 只代表 artifact 已经本地可用；`activate` 才会改变 runtime 行为。所有 activation 必须继续经过 Agent Core Runtime、SecurityExecutionEngine、audit、rollback 和 release/replay gate。底层 Debian/Ubuntu package manager 仍作为可选 adapter，不成为 `aom` 的第一目标。

关键产物：

- Guidance spec: `.workflow/.csv-wave/20260524-brainstorm-agentos-production-ecosystem/.brainstorming/guidance-specification.md`
- Feature index: `.workflow/.csv-wave/20260524-brainstorm-agentos-production-ecosystem/.brainstorming/feature-index.json`
- Synthesis: `.workflow/.csv-wave/20260524-brainstorm-agentos-production-ecosystem/.brainstorming/synthesis-specification.md`
- Roadmap: `.workflow/.csv-wave/20260524-brainstorm-agentos-production-ecosystem/.brainstorming/production-ecosystem-task-roadmap.md`
- Context report: `.workflow/.csv-wave/20260524-brainstorm-agentos-production-ecosystem/context.md`

### Production Ecosystem Wave ECO-0：决策与对象模型

- `TASK-ECO-000`：冻结 ecosystem scope 和 `install is not activation` invariant（completed）
- `TASK-ECO-001`：定义 `runtime_contracts::ecosystem` module boundary（completed）
- `TASK-ECO-020`：定义 artifact coordinate 和 manifest schema（completed）
- `TASK-ECO-021`：定义 registry snapshot 和 lockfile schema（completed）
- `TASK-ECO-022`：定义 activation report 和 installed/active state schema（completed）
- `TASK-ECO-023`：定义 compatibility and migration validation（completed）
- `TASK-ECO-030`：定义 trust tier and channel policy（completed）

退出标准：

- Manifest、registry snapshot、lockfile 和 activation report 足够稳定，可被 fixture 和 replay 使用。
- 首批 artifact kinds 冻结为 `policy-pack`、`workflow-pack`、`test-replay-pack`。
- Policy invariant 明确：policy pack 不能削弱 core safety rules。

### Production Ecosystem Wave ECO-1：local registry 与 staging

- `TASK-ECO-002`：增加 local registry fixture 和 artifact resolver（completed）
- `TASK-ECO-003`：实现 staging store with digest/signature verification report（completed）
- `TASK-ECO-010`：定义 operator-facing artifact explanation format（completed）
- `TASK-ECO-011`：增加 `aom` CLI surface for local lifecycle（completed）
- `TASK-ECO-024`：增加 revocation/advisory metadata model（completed）
- `TASK-ECO-025`：增加 deterministic ecosystem hash projection for provenance（completed）

退出标准：

- `aom search/show/verify/stage/explain` 可以在 local fixture registry 上工作。
- Staged artifacts 是 inert state，不改变 runtime 行为。
- Digest mismatch、revoked artifact 和 incompatible schema fail closed。

当前完成度：

- `agentd --aom search/show/verify/stage/explain` 已可基于 rootfs local registry fixture 工作，`stage` 只写 inert staged artifact evidence，`activate` 仍明确 blocked 到 `TASK-ECO-004` / `TASK-ECO-005`。
- Operator projection 已增加只读 ecosystem 区块，显示 local registry、`aom.*` commands、activation gated、staged != active、无 shell、resolver owner 为 `agent_core::ecosystem`。
- Rootfs validator 已把 `aom.*` command registry 和 `ecosystem.registry_snapshot` 纳入 Alpha package defaults。
- Release provenance 已增加 deterministic ecosystem hash projection，记录 registry snapshot、lockfile、staged set、active set、replay，并声明 ecosystem replay gate 在 `TASK-VERIFY-041` 后成为硬门。

### Production Ecosystem Wave ECO-2：activation through runtime

- `TASK-ECO-004`：通过 AgentCore PlanSpec 实现 activation planning（planned）
- `TASK-ECO-005`：把 activation side effects 接入 SecurityExecutionEngine（planned）
- `TASK-ECO-006`：在 `agentd` 增加 read-only ecosystem projection（planned）
- `TASK-ECO-012`：打包 built-in production-safe policy pack（planned）
- `TASK-ECO-013`：打包 built-in service recovery workflow pack（planned）
- `TASK-ECO-014`：把 ecosystem status 加到 TUI/operator projection（planned）

退出标准：

- `aom activate` 生成 PlanSpec，并使用既有 approval / policy / effect / audit flow。
- Activation report 包含 audit range 和 rollback handle。
- `agentd` 只展示 active/staged/blocked artifacts，不拥有 resolver 逻辑。

### Production Ecosystem Wave ECO-3：safety、replay 与 release gate

- `TASK-ECO-040`：增加 ecosystem schema unit tests（planned）
- `TASK-ECO-041`：增加 local registry replay script（planned）
- `TASK-ECO-042`：增加 adversarial artifact pack fixtures（planned）
- `TASK-ECO-043`：增加 activation rollback drill（planned）
- `TASK-ECO-044`：增加 revocation and advisory replay（planned）
- `TASK-ECO-045`：把 ecosystem hashes 加入 release provenance（planned）
- `TASK-ECO-046`：增加 long-running active artifact recovery smoke（planned）

退出标准：

- Release gate 在 ecosystem replay skipped/failed 时阻塞。
- Provenance 记录 registry snapshot hash、lockfile hash 和 replay evidence hash。
- Adversarial fixtures 覆盖 shell bypass、policy weakening、memory poisoning、secret embedding 和 adapter bypass。

### Production Ecosystem Wave ECO-4：trust 与组织控制

- `TASK-ECO-015`：定义 verified/community/local-dev channel policy（planned）
- `TASK-ECO-031`：定义 signing and revocation requirements（planned）
- `TASK-ECO-032`：定义 no-maintainer-script activation rule（planned）
- `TASK-ECO-033`：定义 community artifact sandbox-only policy（planned）
- `TASK-ECO-034`：把 ecosystem state 加到 support bundle manifest（planned）
- `TASK-ECO-035`：定义 organization allowlist and denylist overlay（planned）

退出标准：

- Production Distro 可以 pin allowed channels 并拒绝 unsigned artifacts。
- Support bundle 能解释 active artifact set、trust tier、channel 和 hashes，且不包含 raw secrets。
- Community/local-dev artifacts 默认不能 production-promote。

### Production Ecosystem Wave ECO-5：model、knowledge、adapter 与 image packs

- `TASK-ECO-050`：定义 model profile pack schema and local/stub/remote optionality（planned）
- `TASK-ECO-051`：定义 knowledge pack schema with trust labels and memory quarantine（planned）
- `TASK-ECO-052`：增加 model/knowledge adversarial replay fixtures（planned）
- `TASK-ECO-060`：定义 runtime adapter pack schema（planned）
- `TASK-ECO-061`：定义 execution image pack schema for Firecracker/sandbox/update bundles（planned）
- `TASK-ECO-062`：增加 adapter/image optional dependency fail-closed replay（planned）

退出标准：

- Model 和 knowledge packs 不能泄漏 secrets 或污染 privileged memory。
- Adapter packs 不能绕过 SecurityExecutionEngine。
- Image packs 在 activation 前证明 provenance、compatibility 和 rollback rules。

## Agent Runtime + Ecosystem Chain

Source: 用户明确提出需要一条完整链路：扩充 AgentOS 生态，同时强化目前的 Agent Runtime，因为 AgentOS 是完全依靠 Agent 来运作的。  
Workflow: `.workflow/active/WFS-20260524-agentos-agent-runtime-ecosystem-chain`  
Brainstorm seed: `.workflow/.csv-wave/20260524-brainstorm-agentos-production-ecosystem`

目标：把 `functional-ready` 的 AgentOS 推进为 Production Distro 的完整运行链路。这个链路把两件事绑定在一起：

- Agent Runtime 是 OS control plane，负责 boot、steady-state、degraded、recovery、update 和 operator projection。
- `aom` 是 AgentOS-native ecosystem manager，负责管理 capability / tool / policy / workflow / model / knowledge / adapter / image / replay / trust metadata artifacts。

核心边界：

```text
Linux handles deterministic reality.
Agent Runtime handles intention and operation.
aom install/stage is inert.
aom activate is AgentCore PlanSpec + SecurityExecutionEngine side effect.
```

关键产物：

- Workflow session: `.workflow/active/WFS-20260524-agentos-agent-runtime-ecosystem-chain/workflow-session.json`
- Plan: `.workflow/active/WFS-20260524-agentos-agent-runtime-ecosystem-chain/plan.json`
- Task dir: `.workflow/active/WFS-20260524-agentos-agent-runtime-ecosystem-chain/.task`
- Agent-operated OS chain: `.workflow/active/WFS-20260524-agentos-agent-runtime-ecosystem-chain/docs/agent-operated-os-chain.md`
- Runtime ecosystem architecture: `.workflow/active/WFS-20260524-agentos-agent-runtime-ecosystem-chain/docs/runtime-ecosystem-architecture.md`
- Production distro task chain: `.workflow/active/WFS-20260524-agentos-agent-runtime-ecosystem-chain/docs/production-distro-task-chain.md`
- Acceptance gates: `.workflow/active/WFS-20260524-agentos-agent-runtime-ecosystem-chain/docs/acceptance-gates.md`

### Chain Wave 0：冻结完整链路与不变量

- `TASK-CHAIN-000`：冻结 Agent-operated OS and ecosystem chain（completed）
- `TASK-CHAIN-001`：定义 AgentOS lifecycle control map（completed）
- `TASK-CHAIN-002`：定义 `aom` install/stage/activate invariant（completed）
- `TASK-CHAIN-003`：定义 chain acceptance gates and evidence model（completed）

退出标准：

- AgentOS lifecycle 明确覆盖 boot、steady-state、degraded、recovery、update。
- `install/stage != activate` 成为生态不变量。
- Production Distro gate 同时覆盖 runtime 和 ecosystem。

### Chain Wave 1：Agent Runtime OS control loops

- `TASK-ARUN-010`：定义 boot and steady-state Agent Runtime control loops（completed）
- `TASK-ARUN-011`：定义 observation fabric and operator event intake（completed）
- `TASK-ARUN-012`：定义 scheduler、quotas、backpressure and autonomous action budget（completed）
- `TASK-ARUN-013`：定义 degraded mode and local/stub fallback behavior（completed）

退出标准：

- AgentOS 不靠旁路脚本维持主运行链路。
- Observation 不能直接触发高风险 action。
- Scheduler 能限制 retry、并发、预算和 backpressure。
- 缺 external LLM / network / Firecracker / host package manager 时可解释降级。

### Chain Wave 2：durable Agent Runtime state

- `TASK-ARUN-020`：定义 durable OS run state reconciliation（completed）
- `TASK-ARUN-021`：定义 approval、escalation and interrupt survival（completed）
- `TASK-ARUN-022`：定义 OS memory governance and knowledge quarantine（completed）
- `TASK-ARUN-023`：定义 runtime recovery drills for PID 1 operation（completed）

退出标准：

- Recovery 权威来自 RunStore + AuditJournal + active artifact state，不来自 model replay。
- Approval token 重启后仍绑定 actor、tool、resource、parameter hash、expiry、policy version。
- Memory / knowledge 不可污染 privileged action。
- PID 1 恢复 drill 可生成支持证据。

### Chain Wave 3-5：aom ecosystem spine and activation

- Wave 3：`TASK-ECO-000`、`TASK-ECO-001`、`TASK-ECO-020`、`TASK-ECO-021`、`TASK-ECO-022`、`TASK-ECO-023`、`TASK-ECO-030`
- Wave 4：`TASK-ECO-002`、`TASK-ECO-003`、`TASK-ECO-010`、`TASK-ECO-011`、`TASK-ECO-024`、`TASK-ECO-025`
- Wave 5：`TASK-ECO-004`、`TASK-ECO-005`、`TASK-ECO-006`、`TASK-ECO-012`、`TASK-ECO-013`、`TASK-ECO-014`

退出标准：

- `runtime_contracts::ecosystem` 定义 artifact、registry、lockfile、activation report。
- `aom search/show/verify/stage/explain` 可在 local fixture registry 工作。
- `aom activate` 生成 AgentCore PlanSpec，并由 SecurityExecutionEngine 执行。

### Chain Wave 6-9：verification、trust、full ecosystem、Production Distro operations

- Wave 6：`TASK-VERIFY-040` 到 `TASK-VERIFY-044`
- Wave 7：`TASK-ECO-015`、`TASK-ECO-031`、`TASK-ECO-032`、`TASK-ECO-033`、`TASK-ECO-034`、`TASK-ECO-035`
- Wave 8：`TASK-ECO-050`、`TASK-ECO-051`、`TASK-ECO-052`、`TASK-ECO-060`、`TASK-ECO-061`、`TASK-ECO-062`
- Wave 9：`TASK-PROD-050`、`TASK-PROD-051`、`TASK-PROD-052`、`TASK-PROD-053`

退出标准：

- Ecosystem replay 和 adversarial fixtures 进入 release gate。
- Trust tiers、signing、revocation、organization overlay 可解释、可审计。
- Model/knowledge/adapter/image packs 不能泄漏 secrets、污染 memory 或绕过 SecurityExecutionEngine。
- Support bundle、A/B update readiness、offline snapshot drill 和 final chain audit 完成。

## AgentOS TUI Oriented System

Source: 用户要求继续迭代 TASK，让 AgentOS 变成 TUI-oriented system。  
Workflow: `.workflow/active/WFS-20260525-agentos-tui-oriented-system`  
Previous workflow: `.workflow/active/WFS-20260524-agentos-agent-runtime-ecosystem-chain`

状态：completed。Final audit decision：`tui-oriented-alpha`。这不是 GA production-ready claim；production signatures、fleet rollout、remote registry governance 和长期运营运维仍是后续 Production Distro wave。

目标已完成：TUI 从 demo/projection surface 推进为 AgentOS 的主要 durable operator console。TUI 现在能驱动真实 AgentCore run、approval、denial、recovery、audit、support bundle 和 ecosystem activation preview，同时保持架构边界：TUI 是 projection-controller，不是第二套 runtime。

核心边界：

```text
TUI is the OS operator surface.
AgentCore owns PlanRun lifecycle.
SecurityExecutionEngine owns all side effects.
RunStore + AuditJournal + active artifact state are truth.
aom install/stage remains inert.
activation remains AgentCore PlanSpec + SecurityExecutionEngine.
```

关键产物：

- Workflow session: `.workflow/active/WFS-20260525-agentos-tui-oriented-system/workflow-session.json`
- Plan: `.workflow/active/WFS-20260525-agentos-tui-oriented-system/plan.json`
- Task dir: `.workflow/active/WFS-20260525-agentos-tui-oriented-system/.task`
- TUI architecture: `.workflow/active/WFS-20260525-agentos-tui-oriented-system/docs/tui-oriented-architecture.md`
- TUI task chain: `.workflow/active/WFS-20260525-agentos-tui-oriented-system/docs/tui-oriented-task-chain.md`
- Final audit: `.workflow/active/WFS-20260525-agentos-tui-oriented-system/evidence/FINAL-AUDIT-20260525-tui-oriented-agentos.json`
- Final summary: `.workflow/active/WFS-20260525-agentos-tui-oriented-system/docs/final-tui-oriented-audit-summary.md`

已通过验证：

- `cargo fmt --check`
- `cargo test --workspace`
- `cargo test -p agentd tui_ --no-fail-fast`
- `cargo test -p agentd tui --no-fail-fast`
- `scripts/functional-capability-replay.ps1`
- `scripts/ecosystem-replay.ps1`
- `scripts/production-runbook-smoke.ps1`
- `scripts/tui-replay.ps1`
- `scripts/validate-alpha-rootfs.ps1`
- `scripts/build-release.ps1 -QemuPath E:\qemu\qemu-system-x86_64.exe -QemuTimeoutSeconds 120`
- `scripts/boot-smoke-test.ps1 -SkipKernelDownload -KernelPath image\cache\vmlinuz-virt -QemuPath E:\qemu\qemu-system-x86_64.exe -TimeoutSeconds 120`

当前 TUI 能力：

- `--tui-interactive` 和 `--tui-scripted` 走 durable `TuiRuntimeController`。
- TUI controller 使用真实 `AgentCore<FileRunStore, DeterministicPlanner<StubModelProvider>>`。
- Typed command 支持 `dashboard.show`、`intent.submit`、`run.advance`、`run.approve`、`run.deny`、`run.suspend`、`run.recover`、`audit.show`、`support.bundle` 和 `aom.*`。
- `approvals.show latest` 渲染 exact approval binding：actor、tool、resource、parameter hash、policy version、expiry 和 deny hint。
- `recovery.show latest` 渲染 `source=run-store+audit-journal`、`no-model-replay=true`。
- `aom.activate.preview` 只做 activation preview，不因 install/stage 激活。
- Shell-like input、`shell.exec`、stage+activate chaining 和 secret-like input 均 fail closed / redacted。
- QEMU boot smoke 观察到 `AGENTOS_TUI_CONSOLE_READY`。

### TUI Wave 0：TUI OS Contract Freeze

- `TASK-TUI-000`：Freeze TUI-oriented AgentOS contract（completed）
- `TASK-TUI-001`：Define safe TUI command grammar（completed）
- `TASK-TUI-002`：Define TUI state and render model（completed）
- `TASK-TUI-003`：Define TUI replay and release gate strategy（completed）

### TUI Wave 1：Durable AgentCore TUI Bridge

- `TASK-TUI-010`：Add TuiRuntimeController over real AgentCore APIs（completed）
- `TASK-TUI-011`：Add durable TUI runtime path configuration（completed）
- `TASK-TUI-012`：Add approval、denial、suspend and recover handlers（completed）
- `TASK-TUI-013`：Add TUI controller lifecycle tests（completed）

### TUI Wave 2：Operator Console Views

- `TASK-TUI-020`：Build TUI dashboard from operator projection（completed）
- `TASK-TUI-021`：Build run detail and audit timeline view（completed）
- `TASK-TUI-022`：Build approval queue and blocked action view（completed）
- `TASK-TUI-023`：Build recovery、rollback and degraded state view（completed）
- `TASK-TUI-024`：Add TUI golden snapshot and redaction tests（completed）

### TUI Wave 3：Interactive Command Loop

- `TASK-TUI-030`：Replace demo interactive loop with safe typed command loop（completed）
- `TASK-TUI-031`：Add TUI command parser、help and explain errors（completed）
- `TASK-TUI-032`：Add deterministic TUI refresh and event model（completed）
- `TASK-TUI-033`：Add noninteractive scripted TUI mode for replay（completed）

### TUI Wave 4：Ecosystem And Production Operations In TUI

- `TASK-TUI-040`：Expose aom lifecycle projections in TUI（completed）
- `TASK-TUI-041`：Add activation preview view without stage activation（completed）
- `TASK-TUI-042`：Add support bundle export command and view（completed）
- `TASK-TUI-043`：Integrate TUI projection into production runbook smoke（completed）

### TUI Wave 5：Boot And Distro Packaging

- `TASK-TUI-050`：Add rootfs TUI console defaults（completed）
- `TASK-TUI-051`：Add TUI-ready boot marker and initramfs manifest fields（completed）
- `TASK-TUI-052`：Add QEMU TUI console smoke（completed）
- `TASK-TUI-053`：Preserve headless and automation compatibility（completed）

### TUI Wave 6：TUI Safety Replay And Final Audit

- `TASK-TUI-060`：Add local TUI replay script（completed）
- `TASK-TUI-061`：Add adversarial TUI command fixtures（completed）
- `TASK-TUI-062`：Gate release provenance on TUI replay（completed）
- `TASK-TUI-063`：Run final TUI-oriented AgentOS audit（completed）

后续 Production Distro 方向：

- Full-screen TUI shell：panes、navigation、command palette、live event stream。
- Operator session model：role-aware command scopes、sealed local profile state。
- Fleet/update operations：rollout rings、rollback drills、support bundle upload policy。
- Production signing：key ceremony、rotation、release decision evidence。
- Remote registry / marketplace governance：mirror、artifact review、organization policy overlays。

## AgentOS Console Beta And Production UX

Source: TUI-oriented Alpha final audit and post-Alpha Maestro brainstorm.  
Workflow: `.workflow/active/WFS-20260525-agentos-console-beta-production-ux`  
Previous workflow: `.workflow/active/WFS-20260525-agentos-tui-oriented-system`

状态：completed。结论是 `console-beta`，不是 GA / Production Distro RC0。目标已经从 line-oriented typed TUI 推进到 full-screen-oriented Console Beta，并完成 Production Distro UX 铺设：Operations Workbench、Capability Catalog、Production Evidence Center、Fleet and Governance Preview。

核心判断：不要先疯狂加更多 runtime 功能。当前 AgentOS 底层能力已经足够多，下一轮要先让 operator shell 长期可用、可观察、可验证。

关键产物：

- Workflow session: `.workflow/active/WFS-20260525-agentos-console-beta-production-ux/workflow-session.json`
- Plan: `.workflow/active/WFS-20260525-agentos-console-beta-production-ux/plan.json`
- Task dir: `.workflow/active/WFS-20260525-agentos-console-beta-production-ux/.task`
- Final audit: `.workflow/active/WFS-20260525-agentos-console-beta-production-ux/evidence/FINAL-AUDIT-20260525-console-beta-production-ux.json`
- Final summary: `.workflow/active/WFS-20260525-agentos-console-beta-production-ux/docs/final-console-beta-audit-summary.md`
- Console architecture: `.workflow/active/WFS-20260525-agentos-console-beta-production-ux/docs/console-beta-architecture.md`
- Task chain: `.workflow/active/WFS-20260525-agentos-console-beta-production-ux/docs/console-beta-task-chain.md`
- Brainstorm: `.workflow/.csv-wave/20260525-brainstorm-agentos-tui-prod-next/context.md`

边界：

```text
TUI remains projection-controller only.
AgentCore owns PlanRun lifecycle.
SecurityExecutionEngine owns all side effects.
agent_core::ecosystem owns resolver and activation planning.
OperatorSession is UI state only, not permission authority.
ProjectionSnapshot is immutable render input, not source of truth.
```

### Console Beta Wave 0：Contract And Refactor Spine

- `TASK-TUI2-000`：Freeze Console Beta boundary and module ownership（completed）
- `TASK-TUI2-001`：Split TUI runtime into shell, parser, view model and dispatch modules（completed）
- `TASK-TUI2-002`：Add `ProjectionSnapshot` contract with source hashes（completed）

退出标准：

- TUI module ownership and shell boundaries are documented。
- Existing scripted and interactive commands still work。
- `ProjectionSnapshot` is defined as render input, not authority。

### Console Beta Wave 1：Full-Screen Operator Shell

- `TASK-TUI2-003`：Add full-screen pane layout model and narrow terminal fallback（completed）
- `TASK-TUI2-004`：Add command palette with contextual preview（completed）
- `TASK-TUI2-005`：Add full-screen layout snapshots and scripted parity gate（completed）
- `TASK-TUI2-006`：Add live event feed from durable audit/runtime projections（completed）

退出标准：

- Wide and narrow terminal layouts are stable。
- Command palette previews actions before dispatch。
- Event feed derives from durable projections。
- Scripted parity gate still passes。

### Console Beta Wave 2：Operations Workbench

- `TASK-TUI2-010`：Build Approval Center panel（completed）
- `TASK-TUI2-011`：Add approval binding diff and stale/expired token UX（completed）
- `TASK-TUI2-012`：Build Recovery Workbench panel（completed）
- `TASK-TUI2-013`：Add rollback consequence preview（completed）
- `TASK-TUI2-014`：Build Support Console panel（completed）
- `TASK-TUI2-015`：Add degraded-state explainer and evidence path actions（completed）

退出标准：

- Approval Center shows exact binding diff、expiry and denial path。
- Recovery Workbench shows recovery source、rollback needs and safe next action。
- Support Console exports redacted evidence and explains degraded state。

### Console Beta Wave 3：Capability Catalog

- `TASK-TUI2-020`：Add capability index projection（completed）
- `TASK-TUI2-021`：Add workflow catalog view（completed）
- `TASK-TUI2-022`：Add launch-intent preview for operational capabilities（completed）
- `TASK-TUI2-023`：Add AOM artifact detail and trust status panel（completed）
- `TASK-TUI2-024`：Add catalog replay gate（completed）

退出标准：

- Operational workflows are discoverable。
- Launching a capability creates an intent or preview only。
- Catalog and AOM views cannot directly execute or activate。

### Console Beta Wave 4：Production Evidence Center

- `TASK-TUI2-030`：Add release provenance panel（completed）
- `TASK-TUI2-031`：Add promotion blocker panel（completed）
- `TASK-TUI2-032`：Add local update and rollback drill view（completed）
- `TASK-TUI2-033`：Add QEMU/rootfs/replay gate status panel（completed）
- `TASK-TUI2-034`：Add candidate signing status view（completed）

退出标准：

- Release provenance、blockers and signing status are visible。
- QEMU/rootfs/replay gate status is projectable。
- Local update and rollback drill evidence is explainable。

### Console Beta Wave 5：Fleet And Governance Preview

- `TASK-TUI2-040`：Draft local-first fleet operations model（completed）
- `TASK-TUI2-041`：Add rollout ring projection prototype（completed）
- `TASK-TUI2-042`：Add support bundle upload policy design（completed）
- `TASK-TUI2-043`：Add remote registry mirror UX design（completed）
- `TASK-TUI2-044`：Add organization policy overlay preview（completed）
- `TASK-TUI2-050`：Run final Console Beta and Production UX audit（completed）

退出标准：

- Fleet and governance previews are explicit non-GA previews。
- Remote features are optional and fail closed。
- Final audit decided `console-beta` promotion；`production_ready_claim=false` remains intentional。
