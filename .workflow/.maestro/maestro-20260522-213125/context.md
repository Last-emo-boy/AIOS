# Maestro Session Context

Session: `maestro-20260522-213125`

Intent: 使用 Maestro 管理 AIOS 进度，并把 `research.md` 解构成可执行 TASK。

Chain: `plan`

Scope: planning-only。当前没有代码仓库和现有实现，先生成任务分解、验收标准和后续执行入口。

Primary source:
- `research.md`

Key conclusion:
- MVP 不重写内核，选择 Linux LTS 基座。
- `agentd` 是 PID 1 / 用户态控制面，不是内核内 LLM。
- 首要验证路径是启动链、TUI、语义工具、capability runtime、审计、diff、rollback。
- Firecracker、高安全版、多租户和生产治理进入 Alpha/Beta 或独立产品线。

Produced artifacts:
- `TASK.md`
- `.workflow/active/WFS-20260522-agentos-linux-mvp/workflow-session.json`
- `.workflow/active/WFS-20260522-agentos-linux-mvp/context.md`
- `.workflow/active/WFS-20260522-agentos-linux-mvp/plan.json`
- `.workflow/active/WFS-20260522-agentos-linux-mvp/.task/TASK-AIOS-*.json`
