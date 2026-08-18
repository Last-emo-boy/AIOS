//! runner —— 把桥接出的 `Vec<PlannedStep>` 喂冻结 `AgentRuntime::run_plan_guarded`
//! 的 host 适配器（order9）。冻结裁决顺序：source_to_sink 门（model_output → 非 ReadOnly
//! Denied，exec 不触达）→ `PolicyEvaluator`（exact `ApprovalToken` consume-once）→ exec。
//!
//! `StubExecutor` 仿 `security_execution_linux/tests/service_recovery_real.rs` 的
//! `RecoveryExecutor`，但用 host stub 后端（记录被执行的 step，便于断言「exec 未被调用」）。
//!
//! cp-llm 阶段 D：`run_replan_loop` —— plan→bridge→run_plan_guarded→若未 Completed 且有
//! 可观察反馈，把 `EffectObserved`/`StepDenied` 作为上下文喂回 `LlmProvider` 再 plan，
//! 限制最大 replan 次数。**LLM 仍只产 intention**：每轮都经 `bridge_plan`（冻结 ToolRouter）
//! + `run_plan_guarded`（冻结 source_to_sink/policy/exec），裁决路径不变。

use std::cell::{Cell, RefCell};

use agent_runtime::{
    AgentRuntime, ApprovalSource, PlannedStep, RunEvent, RunState, StepExecutor, StepObservation,
    StepOutcome, StepProvenance, StepRisk,
};
use security_execution::audit::{redact_summary, AuditEvent, AuditEventType, AuditJournal};
use security_execution::policy::ApprovalToken;
use security_execution::source_to_sink::ContentSource;

/// 算子原生溯源：每步标记为 `ContentSource::operator_input`（可信算子来源）。用于「算子把
/// LLM 计划**重规划为自身意图**」的提权通道——与 `ModelProvenance` 字节相同的 step，仅溯源
/// 不同（model_output vs operator_input）即产生 Denied vs Completed 的反假绿 delta。
#[derive(Debug, Default, Clone, Copy)]
pub struct OperatorProvenance;

impl StepProvenance for OperatorProvenance {
    fn content_source(&self, step: &PlannedStep) -> Option<ContentSource> {
        ContentSource::operator_input(step.step_id.clone()).ok()
    }
}

/// 与该 step 的 `policy_request` 完全同形的冻结 `ApprovalToken`（actor/tool/resource/
/// parameter_hash/policy_version 一致，expires_at>=now=0）。
pub fn exact_token_for(actor: &str, step: &PlannedStep) -> ApprovalToken {
    let request = step.policy_request(actor);
    ApprovalToken {
        actor: request.actor,
        tool: request.tool,
        resource: request.resource,
        parameter_hash: request.parameter_hash,
        expires_at: 60,
        policy_version: request.policy_version,
    }
}

/// 运维审批源：对需确认的（非 ReadOnly）步返回 exact-matching token，consume-once（第二次
/// None）。`approve=false` 永不批。只读步返回 None（policy 对 ReadOnly 直接放行）。
pub struct OperatorApprovals {
    actor: String,
    approve: bool,
    used: Cell<bool>,
}

impl OperatorApprovals {
    pub fn new(actor: impl Into<String>, approve: bool) -> Self {
        Self {
            actor: actor.into(),
            approve,
            used: Cell::new(false),
        }
    }
}

impl ApprovalSource for OperatorApprovals {
    fn token_for(&self, step: &PlannedStep) -> Option<ApprovalToken> {
        if matches!(step.risk, StepRisk::ReadOnly) {
            return None;
        }
        if !self.approve || self.used.get() {
            return None;
        }
        self.used.set(true);
        Some(exact_token_for(&self.actor, step))
    }
}

/// host stub executor：记录每个被执行的 step_id（用于断言 exec 未被调用），返回 `Confined`
/// + 给定 detail。不触发 run loop 的 verify-rollback（step_id 非 "verify*"、detail 不含
/// "alive=false"）。
pub struct StubExecutor {
    executed: RefCell<Vec<String>>,
    detail: String,
}

impl StubExecutor {
    pub fn new(detail: impl Into<String>) -> Self {
        Self {
            executed: RefCell::new(Vec::new()),
            detail: detail.into(),
        }
    }

    /// 至今被 `execute` 触达过的 step_id（顺序）。s2s/policy 拦下的步不在此列。
    pub fn executed(&self) -> Vec<String> {
        self.executed.borrow().clone()
    }
}

impl StepExecutor for StubExecutor {
    fn execute(&self, step: &PlannedStep) -> std::io::Result<StepObservation> {
        self.executed.borrow_mut().push(step.step_id.clone());
        Ok(StepObservation {
            outcome: StepOutcome::Confined,
            detail: self.detail.clone(),
        })
    }
}

// ===== cp-llm 阶段 D：tool-result 反馈 / replan 循环 =====
// ===== cp-llm 阶段 E：agent 决策结构化追踪（TraceSpan） =====
// ===== cp-llm 阶段 F：上下文窗口管理（ContextWindow，防 replan 反馈无限增长） =====

/// 上下文窗口：管理 replan 反馈历史，构造给 LLM 的 context 字符串。
///
/// 问题：replan loop 多轮后，反馈串无限增长可能超出 LLM context window。且当前实现
/// 每轮覆盖只留最近一条反馈，丢失前序观察。
///
/// 方案：`ContextWindow` 保留原始 intent（始终保留）+ 滑动窗口的最近 `max_history` 条
/// 反馈。`render()` 拼成 `"{intent}\n[attempt N] {feedback}\n..."` 供 `LlmProvider::plan`
/// 调用。旧反馈滑出窗口（FIFO），保证上下文有界。
#[derive(Debug, Clone)]
pub struct ContextWindow {
    intent: String,
    history: Vec<String>,
    max_history: usize,
}

impl ContextWindow {
    /// 构造一个窗口。`max_history=0` ⇒ 不保留任何反馈（每轮 context = intent，等价单次）。
    pub fn new(intent: impl Into<String>, max_history: usize) -> Self {
        Self {
            intent: intent.into(),
            history: Vec::new(),
            max_history,
        }
    }

    /// 追加一条反馈。超过 `max_history` 时滑出最旧（FIFO）。
    pub fn push(&mut self, feedback: impl Into<String>) -> &mut Self {
        if self.max_history == 0 {
            return self; // 窗口关闭，不保留
        }
        self.history.push(feedback.into());
        while self.history.len() > self.max_history {
            self.history.remove(0);
        }
        self
    }

    /// 当前窗口保留的反馈条数。
    pub fn len(&self) -> usize {
        self.history.len()
    }

    /// 窗口是否为空（无反馈）。
    pub fn is_empty(&self) -> bool {
        self.history.is_empty()
    }

    /// 渲染给 LLM 的 context 字符串：intent + 反馈历史（按时间序，旧→新）。空窗口返回 intent。
    /// 不标 attempt 序号（窗口滑出后序号会不连续；LLM 只需观察内容，不需序号）。
    pub fn render(&self) -> String {
        if self.history.is_empty() {
            return self.intent.clone();
        }
        let mut parts: Vec<String> = vec![self.intent.clone()];
        for feedback in &self.history {
            parts.push(format!("previous feedback: {feedback}"));
        }
        parts.join("\n")
    }
}

/// 单次 replan attempt 的结构化追踪记录（advisory，供观测/审计；绝不参与裁决）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceSpan {
    /// 第几轮（1-based）。
    pub attempt: usize,
    /// 该轮 LLM 的 provider 标识（取 `LlmProvider::name`）。
    pub provider: String,
    /// 该轮 LLM 的模型（取 `RawPlan.model`）。
    pub model: String,
    /// bridge 后的步数（0 = bridge 失败或 plan 空）。
    pub step_count: usize,
    /// 该轮 `run_plan_guarded` 的终态（bridge/provider 失败时为 `FailedClosed`）。
    pub state: RunState,
    /// 该轮结束的原因。
    pub cause: TraceCause,
    /// 该轮耗时（毫秒，advisory 仅观测，绝不参与裁决）。abort 检查命中时为 0。
    pub elapsed_ms: u64,
}

/// 一轮 attempt 结束的原因。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceCause {
    /// 计划全步跑完。
    Completed,
    /// LLM provider 失败（fail-closed）。
    ProviderFailed { reason: String },
    /// bridge 拒绝（幻觉 tool / secret / 缺参）。
    BridgeRejected { reason: String },
    /// exec 阶段被冻结控制面拒绝/内核拒绝。
    ExecDenied { reason: String },
    /// run loop 收束于非 Completed 非 Denied 的中间态且配额耗尽。
    BudgetExhausted,
    /// 算子发出中止信号（阶段 G），run loop 在下一轮 plan 前 fail-closed。
    Aborted,
    /// 无可反馈观察，replan 无意义。
    NoFeedback,
}

/// `run_replan_loop` 的结果（advisory，供观测）。
#[derive(Debug, Clone)]
pub struct ReplanOutcome {
    /// 最终 run state（最后一轮 `run_plan_guarded` 的终态）。
    pub state: RunState,
    /// 总尝试次数（首次 plan = 1；每次 replan +1）。
    pub attempts: usize,
    /// 每轮（从第二轮起）喂给 LLM 的反馈上下文片段。
    pub feedback: Vec<String>,
    /// 每轮 attempt 的结构化追踪（阶段 E）。
    pub trace: Vec<TraceSpan>,
}

impl ReplanOutcome {
    /// 是否最终 Completed（全计划跑完）。
    pub fn completed(&self) -> bool {
        matches!(self.state, RunState::Completed)
    }

    /// 是否被算子中止（阶段 G）。
    pub fn aborted(&self) -> bool {
        self.trace
            .last()
            .is_some_and(|span| matches!(span.cause, TraceCause::Aborted))
    }

    /// 是否因 fail-closed 收束（provider/bridge/exec 拒绝）——非 Completed、非 Aborted。
    pub fn fail_closed(&self) -> bool {
        !self.completed() && !self.aborted()
    }

    /// 最终结局的人读摘要（单行，不含 secret——reason 经 extract_feedback 已净化）。
    /// 供 bin/CLI 直接打印，无需调用方自己拼字符串。
    pub fn summary(&self) -> String {
        if self.completed() {
            format!("completed in {} attempt(s)", self.attempts)
        } else if self.aborted() {
            format!("aborted after {} attempt(s)", self.attempts)
        } else if let Some(span) = self.trace.last() {
            format!(
                "failed after {} attempt(s): {}",
                self.attempts,
                trace_cause_str(&span.cause)
            )
        } else {
            format!("failed after {} attempt(s)", self.attempts)
        }
    }

    /// 所有轮次耗时之和（毫秒，advisory 仅观测）。abort 轮的 0 不影响总和。
    pub fn total_elapsed_ms(&self) -> u64 {
        self.trace.iter().map(|span| span.elapsed_ms).sum()
    }

    /// 把所有 trace span 渲染成多行可读串（每轮一行），供审计/调试输出。
    pub fn render_trace(&self) -> String {
        self.trace
            .iter()
            .map(|span| {
                format!(
                    "attempt {} provider={} model={} steps={} state={:?} cause={} elapsed_ms={}",
                    span.attempt,
                    span.provider,
                    span.model,
                    span.step_count,
                    span.state,
                    trace_cause_str(&span.cause),
                    span.elapsed_ms
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// 把 `TraceCause` 渲染成单行可读串（不含 secret：reason 经 extract_feedback 已净化）。
/// cp-llm 阶段 J：从 bin/llm_plan.rs 提升为模块级 pub 函数，供 `ReplanOutcome::summary`
/// / `render_trace` 及外部调用方复用。
pub fn trace_cause_str(cause: &TraceCause) -> String {
    match cause {
        TraceCause::Completed => "completed".to_string(),
        TraceCause::ProviderFailed { reason } => format!("provider_failed: {reason}"),
        TraceCause::BridgeRejected { reason } => format!("bridge_rejected: {reason}"),
        TraceCause::ExecDenied { reason } => format!("exec_denied: {reason}"),
        TraceCause::BudgetExhausted => "budget_exhausted".to_string(),
        TraceCause::Aborted => "aborted".to_string(),
        TraceCause::NoFeedback => "no_feedback".to_string(),
    }
}

/// 算子中止信号源（阶段 G）。
///
/// 生产 LLM agent 系统（LangGraph `interrupt`、OpenAI Assistants cancel）都提供运行
/// 中途叫停能力。本 trait 把「是否中止」的裁决权交给算子（通过共享 flag / channel /
/// 信号 fd 实现），`run_replan_loop` 每轮 plan 前检查——若 aborted 则 fail-closed，
/// 绝不让 LLM 继续产 intention。**不变量保持**：中止是算子裁决，不是 LLM 决策。
pub trait AbortSignal {
    fn is_aborted(&self) -> bool;
}

/// 默认实现：永不中止。向后兼容——`run_replan_loop` 的 `abort: &dyn AbortSignal`
/// 传 `&NoAbort` 时行为与阶段 F 完全一致。
pub struct NoAbort;
impl AbortSignal for NoAbort {
    fn is_aborted(&self) -> bool {
        false
    }
}

/// cp-llm 阶段 M：基于截止时间的 `AbortSignal` 实现。
///
/// 生产 LLM agent 系统都有运行级 deadline/timeout。`DeadlineAbort` 在构造时记录一个
/// 绝对截止时刻（`Instant`），`is_aborted()` 检查当前时间是否已过截止——超时即
/// fail-closed，绝不让 LLM 继续产 intention。**不变量保持**：deadline 是算子裁决，
/// 不是 LLM 决策。
///
/// 用法：`run_replan_loop_with_abort(..., &DeadlineAbort::after_secs(60))`。
/// 也可与其它 abort 信号组合（如 `union` 两个信号）。
pub struct DeadlineAbort {
    deadline: std::time::Instant,
}

impl DeadlineAbort {
    /// 从现在起 `secs` 秒后截止。
    pub fn after_secs(secs: u64) -> Self {
        Self {
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(secs),
        }
    }

    /// 从现在起 `dur` 后截止。
    pub fn after(dur: std::time::Duration) -> Self {
        Self {
            deadline: std::time::Instant::now() + dur,
        }
    }

    /// 截止时刻是否已过。
    pub fn is_expired(&self) -> bool {
        std::time::Instant::now() >= self.deadline
    }
}

impl AbortSignal for DeadlineAbort {
    fn is_aborted(&self) -> bool {
        self.is_expired()
    }
}

/// cp-llm 阶段 M：组合两个 abort 信号——任一触发即中止。
///
/// 便于把 `DeadlineAbort` 与算子手动 abort 信号组合（如 `union(deadline, manual_flag)`）。
pub struct UnionAbort<'a> {
    a: &'a dyn AbortSignal,
    b: &'a dyn AbortSignal,
}

impl<'a> UnionAbort<'a> {
    pub fn new(a: &'a dyn AbortSignal, b: &'a dyn AbortSignal) -> Self {
        Self { a, b }
    }
}

impl<'a> AbortSignal for UnionAbort<'a> {
    fn is_aborted(&self) -> bool {
        self.a.is_aborted() || self.b.is_aborted()
    }
}

/// plan→bridge→exec→（若未完成）把观察反馈给 LLM 再 plan，最多 `max_replans` 次重规划。
///
/// **不变量**：LLM 只产 intention。每轮：`LlmProvider::plan(context)` → `bridge_plan`
/// （冻结 ToolRouter 路由 + 权威风险 + secret 净化）→ `AgentRuntime::run_plan_guarded`
/// （冻结 source_to_sink → PolicyEvaluator → 审批 → exec）。反馈只把**观察细节**（如
/// `alive=false`、`restart approval denied`）作为上下文串拼进下一次 plan 调用——绝不
/// 把裁决权交给 LLM，绝不绕过冻结控制面。
///
/// 终止条件：`Completed`（成功）／达到 `max_replans` ／ provider/bridge fail-closed
/// ／算子中止信号（阶段 G）。
/// `max_replans=0` ⇒ 只跑首轮，不 replan（等价单次 plan+exec）。
///
/// `provenance`：每轮的 `PlannedStep` 溯源——LLM 衍生步用 `ModelProvenance`（model_output，
/// 非 ReadOnly 步被 s2s 门 Denied，符合设计意图：危险步须算子重规划而非 LLM 自主执行）。
///
/// 向后兼容入口：等价于 `run_replan_loop_with_abort(..., &NoAbort)`——不传中止信号。
pub fn run_replan_loop(
    provider: &dyn crate::LlmProvider,
    intent: &str,
    actor: &str,
    run_id: &str,
    provenance: &dyn StepProvenance,
    approvals: &dyn ApprovalSource,
    exec: &dyn StepExecutor,
    journal: &AuditJournal,
    max_replans: usize,
) -> ReplanOutcome {
    run_replan_loop_with_abort(
        provider, intent, actor, run_id, provenance, approvals, exec, journal,
        max_replans, &NoAbort,
    )
}

/// `run_replan_loop` 的完整版（阶段 G）：每轮 plan 前检查 `abort.is_aborted()`，
/// 若算子已中止则 fail-closed（trace 记 `TraceCause::Aborted`），绝不让 LLM 继续
/// 产 intention。其余行为与 `run_replan_loop` 一致。
pub fn run_replan_loop_with_abort(
    provider: &dyn crate::LlmProvider,
    intent: &str,
    actor: &str,
    run_id: &str,
    provenance: &dyn StepProvenance,
    approvals: &dyn ApprovalSource,
    exec: &dyn StepExecutor,
    journal: &AuditJournal,
    max_replans: usize,
    abort: &dyn AbortSignal,
) -> ReplanOutcome {
    // 阶段 F：ContextWindow 管理 replan 反馈上下文（滑动窗口，FIFO 滑出）。
    // max_history = max_replans：每轮最多产生一条反馈，窗口容量恰好覆盖全部 replan 轮次。
    let mut context_window = ContextWindow::new(intent, max_replans);
    let mut feedback: Vec<String> = Vec::new();
    let mut trace: Vec<TraceSpan> = Vec::new();
    let mut state = RunState::FailedClosed;
    let mut attempts = 0usize;
    let provider_name = provider.name().to_string();

    for attempt in 0..=max_replans {
        // 阶段 P：每轮起始锚点（advisory 耗时观测，绝不参与裁决）。
        let attempt_start = std::time::Instant::now();
        let elapsed_ms = || attempt_start.elapsed().as_millis() as u64;
        // 阶段 G：每轮 plan 前检查算子中止信号。若已中止 → fail-closed，绝不让 LLM
        // 继续产 intention。首轮也检查（算子可能在 plan 前就叫停）。
        if abort.is_aborted() {
            trace.push(TraceSpan {
                attempt: attempt + 1,
                provider: provider_name.clone(),
                model: String::new(),
                step_count: 0,
                state: RunState::FailedClosed,
                cause: TraceCause::Aborted,
                elapsed_ms: 0,
            });
            return ReplanOutcome {
                state: RunState::FailedClosed,
                attempts: attempt,
                feedback,
                trace,
            };
        }
        attempts = attempt + 1;
        // 阶段 K：每轮 plan 前记录 IntentReceived 审计事件，使 replan 进度可审计、
        // 崩溃后可从审计日志恢复（哪些 attempt 已执行、终态如何）。summary 经 redact_summary
        // 脱敏（intent 可能含不可信内容）。
        let _ = journal.append(&AuditEvent::new(
            AuditEventType::IntentReceived,
            run_id,
            "replan",
            actor,
            &format!("attempt {attempts} intent: {intent}"),
        ));
        // 1. LLM 产 intention（不可信 RawPlan）。
        let context = context_window.render();
        let raw = match provider.plan(&context) {
            Ok(raw) => raw,
            Err(error) => {
                let reason = error.to_string();
                feedback.push(format!("provider fail-closed: {reason}"));
                trace.push(TraceSpan {
                    attempt: attempts,
                    provider: provider_name.clone(),
                    model: String::new(),
                    step_count: 0,
                    state: RunState::FailedClosed,
                    cause: TraceCause::ProviderFailed { reason },
                    elapsed_ms: elapsed_ms(),
                });
                return ReplanOutcome {
                    state: RunState::FailedClosed,
                    attempts,
                    feedback,
                    trace,
                };
            }
        };
        let model = raw.model.clone();
        // 2. 桥接：冻结 ToolRouter 路由 + secret 净化。bridge 失败 → 反馈原因并 replan。
        let plan = match crate::bridge_plan(&raw) {
            Ok(plan) => plan,
            Err(error) => {
                let reason = error.to_string();
                trace.push(TraceSpan {
                    attempt: attempts,
                    provider: provider_name.clone(),
                    model: model.clone(),
                    step_count: 0,
                    state: RunState::FailedClosed,
                    cause: TraceCause::BridgeRejected { reason: reason.clone() },
                    elapsed_ms: elapsed_ms(),
                });
                if attempt >= max_replans {
                    return ReplanOutcome {
                        state: RunState::FailedClosed,
                        attempts,
                        feedback,
                        trace,
                    };
                }
                let note = format!("bridge rejected: {reason}");
                feedback.push(note.clone());
                context_window.push(note);
                continue;
            }
        };
        let step_count = plan.len();
        // 3. 冻结 run loop 裁决 + exec（每轮用新 runtime，事件序列独立）。
        let mut runtime = AgentRuntime::new();
        state = runtime.run_plan_guarded(actor, run_id, &plan, provenance, approvals, exec, journal);
        if matches!(state, RunState::Completed) {
            trace.push(TraceSpan {
                attempt: attempts,
                provider: provider_name.clone(),
                model: model.clone(),
                step_count,
                state,
                cause: TraceCause::Completed,
                elapsed_ms: elapsed_ms(),
            });
            return ReplanOutcome {
                state,
                attempts,
                feedback,
                trace,
            };
        }
        // 4. 未完成：提取观察作为反馈，replan（若还有配额）。
        if attempt >= max_replans {
            // 提取 exec 拒绝原因（若有）。
            let cause = extract_denied_reason(&runtime.events())
                .map(|reason| TraceCause::ExecDenied { reason })
                .unwrap_or(TraceCause::BudgetExhausted);
            trace.push(TraceSpan {
                attempt: attempts,
                provider: provider_name.clone(),
                model: model.clone(),
                step_count,
                state,
                cause,
                elapsed_ms: elapsed_ms(),
            });
            break;
        }
        let observation = extract_feedback(&runtime.events());
        match observation {
            Some(note) => {
                trace.push(TraceSpan {
                    attempt: attempts,
                    provider: provider_name.clone(),
                    model: model.clone(),
                    step_count,
                    state,
                    cause: TraceCause::ExecDenied { reason: note.clone() },
                    elapsed_ms: elapsed_ms(),
                });
                feedback.push(note.clone());
                context_window.push(note);
            }
            None => {
                trace.push(TraceSpan {
                    attempt: attempts,
                    provider: provider_name.clone(),
                    model: model.clone(),
                    step_count,
                    state,
                    cause: TraceCause::NoFeedback,
                    elapsed_ms: elapsed_ms(),
                });
                break; // 无可反馈观察，replan 无意义
            }
        }
    }

    ReplanOutcome {
        state,
        attempts,
        feedback,
        trace,
    }
}

/// 从 run loop 事件序列提取最近一次可反馈的观察：优先 `EffectObserved`，其次
/// `StepDenied`/`RollbackTriggered`。返回人读字符串（绝不含 secret——detail 经
/// `AuditEvent::new` 的 redact_summary 已净化，source_to_sink 门已挡 secret 回流）。
fn extract_feedback(events: &[RunEvent]) -> Option<String> {
    // 从后往前找最近一个有信息量的事件。
    for event in events.iter().rev() {
        match event {
            RunEvent::EffectObserved { step_id, tool, detail } => {
                return Some(format!("step {step_id} ({tool}) observed: {}", redact_summary(detail)))
            }
            RunEvent::StepDenied { step_id, reason } => {
                return Some(format!("step {step_id} denied: {reason}"))
            }
            RunEvent::SourceToSinkDenied { step_id, source_label, sink_class, reason } => {
                return Some(format!(
                    "step {step_id} source-to-sink denied ({source_label}→{sink_class}): {reason}"
                ))
            }
            RunEvent::RollbackTriggered { step_id, reason } => {
                return Some(format!("step {step_id} rollback: {reason}"))
            }
            _ => {}
        }
    }
    None
}

/// 从事件序列提取 exec 阶段的拒绝原因（供 TraceCause::ExecDenied）。优先 `StepDenied`
/// （含 source_to_sink 门拦的 `SourceToSinkDenied`），其次 `RollbackTriggered`。
fn extract_denied_reason(events: &[RunEvent]) -> Option<String> {
    for event in events.iter().rev() {
        match event {
            RunEvent::StepDenied { step_id, reason } => {
                return Some(format!("step {step_id} denied: {reason}"))
            }
            RunEvent::SourceToSinkDenied { step_id, reason, .. } => {
                return Some(format!("step {step_id} source-to-sink denied: {reason}"))
            }
            RunEvent::RollbackTriggered { step_id, reason } => {
                return Some(format!("step {step_id} rollback: {reason}"))
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod replan_tests {
    use super::*;
    use crate::{bridge::ModelProvenance, LlmProvider, RawPlan, RawStep};
    use std::cell::Cell;

    fn ok_plan() -> RawPlan {
        RawPlan {
            provider: "stub".to_string(),
            model: "m".to_string(),
            raw_json: "{\"steps\":[{\"tool\":\"svc.status\",\"params\":{\"service\":\"nginx\"}}]}".to_string(),
            http_status: 200,
            steps: vec![RawStep {
                tool: "svc.status".to_string(),
                params: vec![("service".to_string(), "nginx".to_string())],
                claimed_risk: None,
                text: String::new(),
                depends_on: vec![],
            }],
        }
    }

    /// 多剧本 stub：按调用序号返回不同 RawPlan（首轮失败→观察；第二轮成功）。
    struct ScriptedProvider {
        plans: Vec<RawPlan>,
        calls: Cell<usize>,
    }
    impl ScriptedProvider {
        fn new(plans: Vec<RawPlan>) -> Self {
            Self { plans, calls: Cell::new(0) }
        }
    }
    impl LlmProvider for ScriptedProvider {
        fn plan(&self, _intent: &str) -> std::io::Result<RawPlan> {
            let idx = self.calls.get();
            self.calls.set(idx + 1);
            self.plans.get(idx).cloned().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::Other, "script exhausted")
            })
        }
    }

    fn journal(tag: &str) -> AuditJournal {
        let path = std::env::temp_dir().join(format!(
            "llm-replan-{tag}-{}.jsonl", std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        AuditJournal::new(path)
    }

    /// 首轮即 Completed：不 replan，attempts=1。
    #[test]
    fn first_plan_completes_no_replan() {
        let provider = ScriptedProvider::new(vec![ok_plan()]);
        let exec = StubExecutor::new("alive=true pid=1");
        let journal = journal("first-ok");
        let outcome = run_replan_loop(
            &provider, "check nginx", "operator", "run-1",
            &ModelProvenance, &OperatorApprovals::new("operator", false),
            &exec, &journal, 3,
        );
        assert!(outcome.completed());
        assert_eq!(outcome.attempts, 1);
        assert!(outcome.feedback.is_empty());
        // 阶段 K：首轮 IntentReceived 审计行已写入。
        let lines = journal.event_lines().unwrap();
        assert!(
            lines.iter().any(|l| l.contains("IntentReceived") && l.contains("attempt 1")),
            "replan attempt must be audited, got {lines:?}"
        );
    }

    /// 首轮 bridge 拒（幻觉 tool）→ 反馈 → 第二轮成功：attempts=2，有反馈。
    #[test]
    fn bridge_rejection_triggers_replan_to_success() {
        // 首轮：幻觉 tool（bridge 拒）；第二轮：合法 svc.status。
        let bad = RawPlan {
            provider: "stub".to_string(),
            model: "m".to_string(),
            raw_json: "{\"steps\":[{\"tool\":\"frobnicate\",\"params\":{}}]}".to_string(),
            http_status: 200,
            steps: vec![RawStep {
                tool: "frobnicate".to_string(),
                params: vec![],
                claimed_risk: None,
                text: String::new(),
                depends_on: vec![],
            }],
        };
        let provider = ScriptedProvider::new(vec![bad, ok_plan()]);
        let exec = StubExecutor::new("alive=true");
        let journal = journal("bridge-replan");
        let outcome = run_replan_loop(
            &provider, "check nginx", "operator", "run-2",
            &ModelProvenance, &OperatorApprovals::new("operator", false),
            &exec, &journal, 3,
        );
        assert!(outcome.completed());
        assert_eq!(outcome.attempts, 2);
        assert_eq!(outcome.feedback.len(), 1);
        assert!(outcome.feedback[0].contains("bridge rejected"));
    }

    /// provider 失败 → fail-closed，不 replan。
    #[test]
    fn provider_failure_is_fail_closed_no_replan() {
        struct FailingProvider;
        impl LlmProvider for FailingProvider {
            fn plan(&self, _intent: &str) -> std::io::Result<RawPlan> {
                Err(std::io::Error::new(std::io::ErrorKind::Other, "transport: down"))
            }
        }
        let exec = StubExecutor::new("alive=true");
        let journal = journal("provider-fail");
        let outcome = run_replan_loop(
            &FailingProvider, "x", "operator", "run-3",
            &ModelProvenance, &OperatorApprovals::new("operator", false),
            &exec, &journal, 3,
        );
        assert!(!outcome.completed());
        assert_eq!(outcome.state, RunState::FailedClosed);
        assert_eq!(outcome.attempts, 1);
    }

    /// max_replans=0：只跑首轮，不 replan（即使首轮 bridge 拒也不重试）。
    #[test]
    fn max_replans_zero_no_replan() {
        let bad = RawPlan {
            provider: "stub".to_string(),
            model: "m".to_string(),
            raw_json: "{\"steps\":[{\"tool\":\"frobnicate\",\"params\":{}}]}".to_string(),
            http_status: 200,
            steps: vec![RawStep {
                tool: "frobnicate".to_string(),
                params: vec![],
                claimed_risk: None,
                text: String::new(),
                depends_on: vec![],
            }],
        };
        let provider = ScriptedProvider::new(vec![bad, ok_plan()]);
        let exec = StubExecutor::new("alive=true");
        let journal = journal("no-replan");
        let outcome = run_replan_loop(
            &provider, "x", "operator", "run-4",
            &ModelProvenance, &OperatorApprovals::new("operator", false),
            &exec, &journal, 0,
        );
        // 首轮 bridge 拒 + 不 replan → FailedClosed。
        assert!(!outcome.completed());
        assert_eq!(outcome.attempts, 1);
    }

    /// 效果观察反馈：首轮 exec 返回 KernelDenied → 反馈 → 第二轮成功。
    /// （用自定义 executor 模拟首轮被内核拒、第二轮 Confined。）
    #[test]
    fn kernel_denied_observation_feeds_back_to_replan() {
        use std::cell::RefCell as RC;
        struct FlippingExecutor {
            calls: RC<usize>,
        }
        impl StepExecutor for FlippingExecutor {
            fn execute(&self, _step: &PlannedStep) -> std::io::Result<StepObservation> {
                let n = *self.calls.borrow();
                *self.calls.borrow_mut() = n + 1;
                if n == 0 {
                    Ok(StepObservation {
                        outcome: StepOutcome::KernelDenied { reason: "SIGSYS".into() },
                        detail: "sandbox blocked syscall".into(),
                    })
                } else {
                    Ok(StepObservation {
                        outcome: StepOutcome::Confined,
                        detail: "alive=true".into(),
                    })
                }
            }
        }
        // 两轮都给合法 plan；首轮 exec KernelDenied → run_plan_guarded 收束 FailedClosed；
        // 反馈观察 → 第二轮 exec Confined → Completed。
        let provider = ScriptedProvider::new(vec![ok_plan(), ok_plan()]);
        let exec = FlippingExecutor { calls: RC::new(0) };
        let journal = journal("kernel-feedback");
        let outcome = run_replan_loop(
            &provider, "check nginx", "operator", "run-5",
            &ModelProvenance, &OperatorApprovals::new("operator", false),
            &exec, &journal, 3,
        );
        assert!(outcome.completed(), "should complete on replan after kernel denial");
        assert_eq!(outcome.attempts, 2);
        assert!(!outcome.feedback.is_empty());
    }

    // ===== cp-llm 阶段 E：agent 决策结构化追踪（TraceSpan） =====

    /// trace 每轮产出一个 span；首轮完成 → 1 个 Completed span。
    #[test]
    fn trace_single_span_on_first_completion() {
        let provider = ScriptedProvider::new(vec![ok_plan()]);
        let exec = StubExecutor::new("alive=true");
        let journal = journal("trace-1");
        let outcome = run_replan_loop(
            &provider, "x", "operator", "run-t1",
            &ModelProvenance, &OperatorApprovals::new("operator", false),
            &exec, &journal, 3,
        );
        assert_eq!(outcome.trace.len(), 1);
        let span = &outcome.trace[0];
        assert_eq!(span.attempt, 1);
        assert_eq!(span.state, RunState::Completed);
        assert!(matches!(span.cause, TraceCause::Completed));
        assert_eq!(span.step_count, 1);
        assert_eq!(span.model, "m");
    }

    /// 两轮（bridge 拒→成功）→ 2 个 span：首个 BridgeRejected，次个 Completed。
    #[test]
    fn trace_spans_for_bridge_replan() {
        let bad = RawPlan {
            provider: "stub".to_string(),
            model: "m".to_string(),
            raw_json: "{\"steps\":[{\"tool\":\"frobnicate\",\"params\":{}}]}".to_string(),
            http_status: 200,
            steps: vec![RawStep {
                tool: "frobnicate".to_string(),
                params: vec![],
                claimed_risk: None,
                text: String::new(),
                depends_on: vec![],
            }],
        };
        let provider = ScriptedProvider::new(vec![bad, ok_plan()]);
        let exec = StubExecutor::new("alive=true");
        let journal = journal("trace-2");
        let outcome = run_replan_loop(
            &provider, "x", "operator", "run-t2",
            &ModelProvenance, &OperatorApprovals::new("operator", false),
            &exec, &journal, 3,
        );
        assert_eq!(outcome.trace.len(), 2);
        assert!(matches!(&outcome.trace[0].cause, TraceCause::BridgeRejected { .. }));
        assert_eq!(outcome.trace[0].step_count, 0);
        assert!(matches!(outcome.trace[1].cause, TraceCause::Completed));
        assert_eq!(outcome.trace[1].attempt, 2);
    }

    /// provider 失败 → 1 个 ProviderFailed span。
    #[test]
    fn trace_provider_failure_span() {
        struct FailingProvider;
        impl LlmProvider for FailingProvider {
            fn name(&self) -> &str { "failing" }
            fn plan(&self, _intent: &str) -> std::io::Result<RawPlan> {
                Err(std::io::Error::new(std::io::ErrorKind::Other, "transport: down"))
            }
        }
        let exec = StubExecutor::new("alive=true");
        let journal = journal("trace-3");
        let outcome = run_replan_loop(
            &FailingProvider, "x", "operator", "run-t3",
            &ModelProvenance, &OperatorApprovals::new("operator", false),
            &exec, &journal, 3,
        );
        assert_eq!(outcome.trace.len(), 1);
        assert_eq!(outcome.trace[0].provider, "failing");
        assert!(matches!(&outcome.trace[0].cause, TraceCause::ProviderFailed { reason } if reason.contains("transport")));
    }

    // ===== cp-llm 阶段 F：ContextWindow 单元测试 =====

    #[test]
    fn context_window_empty_renders_intent_only() {
        let cw = ContextWindow::new("check nginx", 3);
        assert!(cw.is_empty());
        assert_eq!(cw.len(), 0);
        assert_eq!(cw.render(), "check nginx");
    }

    #[test]
    fn context_window_push_renders_history() {
        let mut cw = ContextWindow::new("check nginx", 3);
        cw.push("step s1 denied: source-to-sink");
        assert_eq!(cw.len(), 1);
        assert!(!cw.is_empty());
        assert_eq!(
            cw.render(),
            "check nginx\nprevious feedback: step s1 denied: source-to-sink"
        );
    }

    #[test]
    fn context_window_fifo_slide() {
        // max_history=2：push 3 条，最旧滑出，render 只含最近 2 条。
        let mut cw = ContextWindow::new("intent", 2);
        cw.push("fb-1");
        cw.push("fb-2");
        cw.push("fb-3");
        assert_eq!(cw.len(), 2); // 滑出后窗口大小受限
        let rendered = cw.render();
        assert!(rendered.contains("previous feedback: fb-2"));
        assert!(rendered.contains("previous feedback: fb-3"));
        assert!(!rendered.contains("fb-1")); // 最旧已滑出
        assert!(rendered.starts_with("intent\n"));
    }

    #[test]
    fn context_window_zero_history_drops_feedback() {
        // max_history=0：窗口关闭，push 被忽略，render 永远只返回 intent。
        let mut cw = ContextWindow::new("intent", 0);
        cw.push("fb-1");
        assert!(cw.is_empty());
        assert_eq!(cw.len(), 0);
        assert_eq!(cw.render(), "intent");
    }

    // ===== cp-llm 阶段 G：OperatorAbort 测试 =====

    /// 中止信号在首轮即触发 → 0 次 plan 调用、1 个 Aborted span、attempts=0。
    #[test]
    fn abort_before_first_plan_fail_closed() {
        struct AlwaysAborted;
        impl AbortSignal for AlwaysAborted {
            fn is_aborted(&self) -> bool { true }
        }
        struct CountingProvider { calls: Cell<usize> }
        impl LlmProvider for CountingProvider {
            fn name(&self) -> &str { "counting" }
            fn plan(&self, _intent: &str) -> std::io::Result<RawPlan> {
                self.calls.set(self.calls.get() + 1);
                Ok(ok_plan())
            }
        }
        let provider = CountingProvider { calls: Cell::new(0) };
        let exec = StubExecutor::new("alive=true");
        let journal = journal("abort-1");
        let outcome = run_replan_loop_with_abort(
            &provider, "x", "operator", "run-ab1",
            &ModelProvenance, &OperatorApprovals::new("operator", false),
            &exec, &journal, 3, &AlwaysAborted,
        );
        assert_eq!(provider.calls.get(), 0); // plan 从未被调用
        assert_eq!(outcome.attempts, 0);
        assert_eq!(outcome.state, RunState::FailedClosed);
        assert_eq!(outcome.trace.len(), 1);
        assert!(matches!(outcome.trace[0].cause, TraceCause::Aborted));
        assert!(exec.executed().is_empty()); // exec 也未被触达
    }

    /// 中止信号在第二轮触发：首轮 plan+exec 跑完未 Completed，replan 前被叫停。
    #[test]
    fn abort_after_first_attempt_stops_replan() {
        struct AbortAfterFirst { calls: Cell<usize> }
        impl AbortSignal for AbortAfterFirst {
            fn is_aborted(&self) -> bool {
                let n = self.calls.get();
                self.calls.set(n + 1);
                n >= 1 // 首次检查 false（attempt 0），第二次检查 true（attempt 1）
            }
        }
        // 用一个首轮不 Completed 的 plan（非 ReadOnly 步被 s2s 拦 → Denied）触发 replan。
        let bad = RawPlan {
            provider: "stub".to_string(),
            model: "m".to_string(),
            raw_json: r#"{"steps":[{"tool":"svc.restart","resource":"nginx","params":{"service":"nginx"}}]}"#.to_string(),
            http_status: 200,
            steps: vec![RawStep {
                tool: "svc.restart".to_string(),
                params: vec![("service".to_string(), "nginx".to_string())],
                claimed_risk: None,
                text: String::new(),
                depends_on: vec![],
            }],
        };
        // ScriptedProvider 给两轮 plan（第二轮因 abort 不会被调用）。
        let provider = ScriptedProvider::new(vec![bad, ok_plan()]);
        let abort = AbortAfterFirst { calls: Cell::new(0) };
        let exec = StubExecutor::new("alive=true");
        let journal = journal("abort-2");
        let outcome = run_replan_loop_with_abort(
            &provider, "x", "operator", "run-ab2",
            &ModelProvenance, &OperatorApprovals::new("operator", false),
            &exec, &journal, 3, &abort,
        );
        // 首轮跑了（attempt 1），replan 前被叫停（attempt 计数停在 1）。
        assert_eq!(outcome.attempts, 1);
        assert_eq!(outcome.state, RunState::FailedClosed);
        // 最后一个 trace span 是 Aborted。
        let last = outcome.trace.last().expect("at least one span");
        assert!(matches!(last.cause, TraceCause::Aborted));
    }

    /// NoAbort（默认）行为与 run_replan_loop 等价——向后兼容。
    #[test]
    fn no_abort_equivalent_to_default() {
        let provider = ScriptedProvider::new(vec![ok_plan()]);
        let exec = StubExecutor::new("alive=true");
        let journal = journal("abort-3");
        let outcome = run_replan_loop_with_abort(
            &provider, "x", "operator", "run-ab3",
            &ModelProvenance, &OperatorApprovals::new("operator", false),
            &exec, &journal, 3, &NoAbort,
        );
        assert!(outcome.completed()); // 正常完成，未被中止
    }

    // ===== cp-llm 阶段 M：DeadlineAbort / UnionAbort 测试 =====

    #[test]
    fn deadline_not_expired_when_future() {
        let dl = DeadlineAbort::after_secs(60);
        assert!(!dl.is_aborted());
        assert!(!dl.is_expired());
    }

    #[test]
    fn deadline_expired_when_past() {
        let dl = DeadlineAbort::after(std::time::Duration::from_millis(1));
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(dl.is_aborted());
        assert!(dl.is_expired());
    }

    #[test]
    fn deadline_aborts_replan_loop() {
        // 已过期的 deadline → 首轮即被中止（与 AlwaysAborted 等价）。
        let dl = DeadlineAbort::after(std::time::Duration::from_millis(0));
        std::thread::sleep(std::time::Duration::from_millis(2));
        let provider = ScriptedProvider::new(vec![ok_plan()]);
        let exec = StubExecutor::new("alive=true");
        let journal = journal("dl-1");
        let outcome = run_replan_loop_with_abort(
            &provider, "x", "operator", "run-dl1",
            &ModelProvenance, &OperatorApprovals::new("operator", false),
            &exec, &journal, 3, &dl,
        );
        assert!(outcome.aborted());
        assert_eq!(outcome.attempts, 0);
    }

    #[test]
    fn union_abort_triggers_on_either() {
        let never = NoAbort;
        // future deadline: not expired; union with NoAbort → not aborted.
        let dl = DeadlineAbort::after_secs(60);
        let union = UnionAbort::new(&never, &dl);
        assert!(!union.is_aborted());

        // expired deadline: union with NoAbort → aborted.
        let dl2 = DeadlineAbort::after(std::time::Duration::from_millis(0));
        std::thread::sleep(std::time::Duration::from_millis(2));
        let union2 = UnionAbort::new(&never, &dl2);
        assert!(union2.is_aborted());
    }

    // ===== cp-llm 阶段 J：ReplanOutcome 辅助方法测试 =====

    #[test]
    fn summary_completed() {
        let provider = ScriptedProvider::new(vec![ok_plan()]);
        let exec = StubExecutor::new("alive=true");
        let journal = journal("sum-1");
        let outcome = run_replan_loop(
            &provider, "x", "operator", "run-s1",
            &ModelProvenance, &OperatorApprovals::new("operator", false),
            &exec, &journal, 3,
        );
        assert!(outcome.completed());
        assert!(!outcome.aborted());
        assert!(!outcome.fail_closed());
        assert!(outcome.summary().contains("completed"));
        assert!(outcome.summary().contains("1 attempt"));
    }

    #[test]
    fn summary_aborted() {
        struct AlwaysAborted;
        impl AbortSignal for AlwaysAborted {
            fn is_aborted(&self) -> bool { true }
        }
        let provider = ScriptedProvider::new(vec![ok_plan()]);
        let exec = StubExecutor::new("alive=true");
        let journal = journal("sum-2");
        let outcome = run_replan_loop_with_abort(
            &provider, "x", "operator", "run-s2",
            &ModelProvenance, &OperatorApprovals::new("operator", false),
            &exec, &journal, 3, &AlwaysAborted,
        );
        assert!(!outcome.completed());
        assert!(outcome.aborted());
        assert!(!outcome.fail_closed());
        assert!(outcome.summary().contains("aborted"));
    }

    #[test]
    fn summary_fail_closed_on_provider_error() {
        struct FailingProvider;
        impl LlmProvider for FailingProvider {
            fn name(&self) -> &str { "failing" }
            fn plan(&self, _intent: &str) -> std::io::Result<RawPlan> {
                Err(std::io::Error::new(std::io::ErrorKind::Other, "transport: down"))
            }
        }
        let exec = StubExecutor::new("alive=true");
        let journal = journal("sum-3");
        let outcome = run_replan_loop(
            &FailingProvider, "x", "operator", "run-s3",
            &ModelProvenance, &OperatorApprovals::new("operator", false),
            &exec, &journal, 3,
        );
        assert!(!outcome.completed());
        assert!(!outcome.aborted());
        assert!(outcome.fail_closed());
        assert!(outcome.summary().contains("failed"));
        assert!(outcome.summary().contains("provider_failed"));
    }

    #[test]
    fn render_trace_is_multiline() {
        let provider = ScriptedProvider::new(vec![ok_plan()]);
        let exec = StubExecutor::new("alive=true");
        let journal = journal("sum-4");
        let outcome = run_replan_loop(
            &provider, "x", "operator", "run-s4",
            &ModelProvenance, &OperatorApprovals::new("operator", false),
            &exec, &journal, 3,
        );
        let trace = outcome.render_trace();
        assert!(trace.contains("attempt 1"));
        assert!(trace.contains("completed"));
        assert!(
            trace.contains("elapsed_ms="),
            "render_trace must include elapsed_ms: {trace}"
        );
    }

    #[test]
    fn total_elapsed_ms_sums_all_spans() {
        let provider = ScriptedProvider::new(vec![
            ok_plan(),
            ok_plan(),
            ok_plan(),
        ]);
        let exec = StubExecutor::new("denied"); // never completes → triggers replans
        let journal = journal("sum-el");
        let outcome = run_replan_loop(
            &provider, "x", "operator", "run-el",
            &ModelProvenance, &OperatorApprovals::new("operator", false),
            &exec, &journal, 2,
        );
        // 每个非零 span 贡献非负毫秒；总和 ≥ 0 且 == 各 span 之和。
        let total = outcome.total_elapsed_ms();
        let sum: u64 = outcome.trace.iter().map(|s| s.elapsed_ms).sum();
        assert_eq!(total, sum);
    }
}
