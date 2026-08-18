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
use security_execution::audit::AuditJournal;
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

/// `run_replan_loop` 的结果（advisory，供观测）。
#[derive(Debug, Clone)]
pub struct ReplanOutcome {
    /// 最终 run state（最后一轮 `run_plan_guarded` 的终态）。
    pub state: RunState,
    /// 总尝试次数（首次 plan = 1；每次 replan +1）。
    pub attempts: usize,
    /// 每轮（从第二轮起）喂给 LLM 的反馈上下文片段。
    pub feedback: Vec<String>,
}

impl ReplanOutcome {
    /// 是否最终 Completed（全计划跑完）。
    pub fn completed(&self) -> bool {
        matches!(self.state, RunState::Completed)
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
/// 终止条件：`Completed`（成功）／达到 `max_replans` ／ provider/bridge fail-closed。
/// `max_replans=0` ⇒ 只跑首轮，不 replan（等价单次 plan+exec）。
///
/// `provenance`：每轮的 `PlannedStep` 溯源——LLM 衍生步用 `ModelProvenance`（model_output，
/// 非 ReadOnly 步被 s2s 门 Denied，符合设计意图：危险步须算子重规划而非 LLM 自主执行）。
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
    let mut context = intent.to_string();
    let mut feedback: Vec<String> = Vec::new();
    let mut state = RunState::FailedClosed;
    let mut attempts = 0usize;

    for attempt in 0..=max_replans {
        attempts = attempt + 1;
        // 1. LLM 产 intention（不可信 RawPlan）。
        let raw = match provider.plan(&context) {
            Ok(raw) => raw,
            Err(error) => {
                feedback.push(format!("provider fail-closed: {error}"));
                return ReplanOutcome {
                    state: RunState::FailedClosed,
                    attempts,
                    feedback,
                };
            }
        };
        // 2. 桥接：冻结 ToolRouter 路由 + secret 净化。bridge 失败 → 反馈原因并 replan。
        let plan = match crate::bridge_plan(&raw) {
            Ok(plan) => plan,
            Err(error) => {
                if attempt >= max_replans {
                    return ReplanOutcome {
                        state: RunState::FailedClosed,
                        attempts,
                        feedback,
                    };
                }
                let note = format!("bridge rejected: {error}");
                feedback.push(note.clone());
                context = format!("{intent}\nprevious attempt {attempt} feedback: {note}");
                continue;
            }
        };
        // 3. 冻结 run loop 裁决 + exec（每轮用新 runtime，事件序列独立）。
        let mut runtime = AgentRuntime::new();
        state = runtime.run_plan_guarded(actor, run_id, &plan, provenance, approvals, exec, journal);
        if matches!(state, RunState::Completed) {
            return ReplanOutcome {
                state,
                attempts,
                feedback,
            };
        }
        // 4. 未完成：提取观察作为反馈，replan（若还有配额）。
        if attempt >= max_replans {
            break;
        }
        let observation = extract_feedback(&runtime.events());
        match observation {
            Some(note) => {
                feedback.push(note.clone());
                context = format!("{intent}\nprevious attempt {attempt} feedback: {note}");
            }
            None => break, // 无可反馈观察，replan 无意义
        }
    }

    ReplanOutcome {
        state,
        attempts,
        feedback,
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
                return Some(format!("step {step_id} ({tool}) observed: {detail}"))
            }
            RunEvent::StepDenied { step_id, reason } => {
                return Some(format!("step {step_id} denied: {reason}"))
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
}
