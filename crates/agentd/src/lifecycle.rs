use crate::api::{
    CapabilityLease, CommitId, Effect, PlanSpec, PlanStep, PolicyDecision,
    ReconciledState, RiskClass, RollbackResult, SemanticToolCall, VerificationResult, escape_json,
};
use crate::adapter::ToolExecutorBridge;
use crate::audit::AuditJournal;
use crate::executor::{StdToolExecutor, ToolExecutor};
use crate::modules::{ModuleKind, ModuleStatus};
use crate::tools::{RoutedToolCall, ToolRejection, ToolRouter};
use llm_planner::runner::{run_replan_loop, OperatorApprovals, ReplanOutcome};
use llm_planner::ModelProvenance;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleConfig {
    pub run_mode: &'static str,
    pub planner_mode: &'static str,
    pub arbitrary_shell_enabled: bool,
}

impl Default for LifecycleConfig {
    fn default() -> Self {
        Self {
            run_mode: "local-only",
            planner_mode: "stub",
            arbitrary_shell_enabled: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleState {
    Created,
    Running,
    Stopping,
    Stopped,
}

impl LifecycleState {
    fn as_str(&self) -> &'static str {
        match self {
            LifecycleState::Created => "created",
            LifecycleState::Running => "running",
            LifecycleState::Stopping => "stopping",
            LifecycleState::Stopped => "stopped",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthReport {
    pub state: LifecycleState,
    pub run_mode: &'static str,
    pub planner_mode: &'static str,
    pub arbitrary_shell_enabled: bool,
    pub module_count: usize,
    pub last_error: Option<String>,
}

impl HealthReport {
    pub fn to_json(&self) -> String {
        let last_error = self
            .last_error
            .as_ref()
            .map(|error| format!("\"{}\"", escape_json(error)))
            .unwrap_or_else(|| "null".to_string());
        format!(
            "{{\"state\":\"{}\",\"run_mode\":\"{}\",\"planner_mode\":\"{}\",\"arbitrary_shell_enabled\":{},\"module_count\":{},\"last_error\":{}}}",
            self.state.as_str(),
            self.run_mode,
            self.planner_mode,
            self.arbitrary_shell_enabled,
            self.module_count,
            last_error
        )
    }
}

pub struct Agentd {
    config: LifecycleConfig,
    state: LifecycleState,
    modules: Vec<ModuleStatus>,
    last_error: Option<String>,
    /// 可选的持久化审计日志。`None` 时（默认）编排链照旧 stub 路径，不落盘——
    /// 保证向后兼容。`Some` 时（`with_audit`）走可审计路径：每步记 `AuditEvent`，
    /// 写失败则该步 fail-closed（无审计则不执行，符合可审计 OS 哲学）。
    audit: Option<AuditJournal>,
    /// 工具执行后端。`None` 时 `execute_committed` 用 stub `invoke`（向后兼容）；
    /// `Some` 时走真实 `ToolExecutor::execute`（裁决通过后产生真实观测 Effect）。
    executor: Option<Box<dyn ToolExecutor>>,
    /// LLM 规划后端。`None` 时 `plan()` 返回固定 stub 计划（向后兼容）；
    /// `Some` 时调用 `provider.plan(intent)` + `bridge_plan` 生成可信计划
    /// （LLM 只产意图，桥接层验证工具/参数，裁决仍由后续 classify/evaluate 做）。
    planner: Option<Box<dyn llm_planner::LlmProvider>>,
}

impl std::fmt::Debug for Agentd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Agentd")
            .field("config", &self.config)
            .field("state", &self.state)
            .field("modules", &self.modules)
            .field("last_error", &self.last_error)
            .field("audit_enabled", &self.audit.is_some())
            .field("executor_enabled", &self.executor.is_some())
            .field("planner_enabled", &self.planner.is_some())
            .finish()
    }
}

impl Agentd {
    pub fn new(config: LifecycleConfig) -> Self {
        let modules = ModuleKind::ALL
            .iter()
            .copied()
            .map(ModuleStatus::stub_ready)
            .collect();
        Self {
            config,
            state: LifecycleState::Created,
            modules,
            last_error: None,
            audit: None,
            executor: None,
            planner: None,
        }
    }

    /// 注入持久化审计日志，启用可审计执行路径。返回 `self`（builder 风格）。
    /// 启用后 `execute_committed` / `execute_run` 会在每步写 `AuditEvent`，
    /// 并在 `/execute` 返回中暴露 `run_id` 与 `commit_id`。
    pub fn with_audit(mut self, audit: AuditJournal) -> Self {
        self.audit = Some(audit);
        self
    }

    /// 注入真实工具执行后端。启用后 `execute_committed` 走 `ToolExecutor::execute`
    /// 产生真实观测 Effect（仍经裁决前置 + verify 后置）。`audit` 已启用时，
    /// `StdToolExecutor` 会同时获得 journal 句柄供 `audit.show` 查询。
    pub fn with_executor(mut self, executor: Box<dyn ToolExecutor>) -> Self {
        self.executor = Some(executor);
        self
    }

    /// 一键启用可审计 + 真实执行：注入 audit journal 与 `StdToolExecutor`，
    /// executor 共享同一 journal（`audit.show`/`audit.project` 可查）。
    pub fn with_audit_and_executor(mut self, audit: AuditJournal) -> Self {
        let exec = StdToolExecutor::new().with_audit(audit.clone());
        self.audit = Some(audit);
        self.executor = Some(Box::new(exec));
        self
    }

    /// 审计日志是否已启用。
    pub fn audit_enabled(&self) -> bool {
        self.audit.is_some()
    }

    /// 审计日志句柄（已启用时）。
    pub fn audit(&self) -> Option<&AuditJournal> {
        self.audit.as_ref()
    }

    /// 是否已注入真实执行后端。
    pub fn executor_enabled(&self) -> bool {
        self.executor.is_some()
    }

    /// 注入 LLM 规划后端。启用后 `plan()` 调用 `provider.plan(intent)` + `bridge_plan`
    /// 生成可信计划。`planner_mode=stub`（缺省）时返回固定计划，向后兼容。
    pub fn with_planner(mut self, planner: Box<dyn llm_planner::LlmProvider>) -> Self {
        self.planner = Some(planner);
        self
    }

    /// 是否已注入真实 LLM 规划后端。
    pub fn planner_enabled(&self) -> bool {
        self.planner.is_some()
    }

    pub fn start(&mut self) {
        self.state = LifecycleState::Running;
    }

    pub fn stop(&mut self) {
        self.state = LifecycleState::Stopping;
        self.state = LifecycleState::Stopped;
    }

    pub fn record_error(&mut self, error: impl Into<String>) {
        self.last_error = Some(error.into());
    }

    pub fn module_statuses(&self) -> &[ModuleStatus] {
        &self.modules
    }

    pub fn health_report(&self) -> HealthReport {
        HealthReport {
            state: self.state.clone(),
            run_mode: self.config.run_mode,
            planner_mode: self.config.planner_mode,
            arbitrary_shell_enabled: self.config.arbitrary_shell_enabled,
            module_count: self.modules.len(),
            last_error: self.last_error.clone(),
        }
    }

    pub fn plan(&self, intent: impl Into<String>) -> PlanSpec {
        let intent = intent.into();

        // 真实规划路径：LLM provider 产 RawPlan（不可信）→ bridge_plan 验证 → PlanSpec。
        // provider 失败或桥接失败 → fail-closed 返回空计划（不谎报成功）。
        if let Some(planner) = self.planner.as_ref() {
            let steps = match planner.plan(&intent) {
                Ok(raw) => match llm_planner::bridge_plan(&raw) {
                    Ok(planned) => planned
                        .into_iter()
                        .map(|p| PlanStep {
                            id: p.step_id,
                            tool: p.tool,
                            risk: RiskClass::ReadOnly, // advisory；权威风险由 classify 裁决
                        })
                        .collect(),
                    Err(_err) => {
                        // 桥接失败（LLM 提议了非法工具/参数）→ fail-closed 空计划。
                        Vec::new()
                    }
                },
                Err(_err) => {
                    // provider 失败（网络/解析）→ fail-closed 空计划。
                    Vec::new()
                }
            };
            return PlanSpec {
                run_mode: self.config.run_mode,
                intent,
                steps,
            };
        }

        // stub 路径（planner 未注入，向后兼容）。
        PlanSpec {
            run_mode: self.config.run_mode,
            intent,
            steps: vec![PlanStep {
                id: "step-001".to_string(),
                tool: "svc.status".to_string(),
                risk: RiskClass::ReadOnly,
            }],
        }
    }

    pub fn classify(&self, step: &PlanStep) -> RiskClass {
        if step.tool == "shell.exec" {
            RiskClass::Never
        } else {
            step.risk
        }
    }

    pub fn evaluate(&self, step: &PlanStep) -> PolicyDecision {
        let risk = self.classify(step);
        PolicyDecision {
            allowed: risk != RiskClass::Never,
            risk,
            reason: if risk == RiskClass::Never {
                "normal mode denies arbitrary shell".to_string()
            } else {
                "stub policy allows deterministic local-only step".to_string()
            },
        }
    }

    pub fn acquire(&self, decision: &PolicyDecision) -> Result<CapabilityLease, String> {
        if !decision.allowed {
            return Err(decision.reason.clone());
        }
        Ok(CapabilityLease {
            lease_id: format!("lease-{}", decision.risk.as_str()),
            risk: decision.risk,
            expires_in_seconds: 60,
        })
    }

    pub fn invoke(&self, call: SemanticToolCall) -> Effect {
        Effect {
            prepared: true,
            observed: true,
            tool: call.name,
            summary: "stub effect only; no persistent side effects".to_string(),
        }
    }

    pub fn route_tool(&self, call: &SemanticToolCall) -> Result<RoutedToolCall, ToolRejection> {
        ToolRouter.route(call)
    }

    pub fn verify(&self, effect: &Effect) -> VerificationResult {
        VerificationResult {
            success: effect.prepared && effect.observed,
            reason: "stub verification over observed effect".to_string(),
        }
    }

    pub fn commit(&self, effect: &Effect) -> Result<CommitId, String> {
        let verification = self.verify(effect);
        if verification.success {
            Ok(CommitId("commit-stub-001".to_string()))
        } else {
            Err(verification.reason)
        }
    }

    pub fn rollback(&self, _commit_id: &CommitId) -> RollbackResult {
        RollbackResult {
            triggered: false,
            reason: "no persistent side effects in lifecycle skeleton".to_string(),
        }
    }

    pub fn recover(&self) -> ReconciledState {
        ReconciledState {
            unresolved_effects: 0,
        }
    }

    pub fn reap_children_once(&self) -> usize {
        0
    }

    /// 可审计的完整编排链：classify → evaluate → acquire → invoke → verify → commit，
    /// 可审计的完整编排链：classify → evaluate → acquire → invoke → verify → commit，
    /// 每步写 `AuditEvent`。audit 写失败 → 该步 fail-closed（无审计则不执行）。
    ///
    /// 返回 `ExecutionOutcome`：`Denied`（policy 拒绝）、`Committed`（成功提交，含 run_id/commit_id）、
    /// `FailedClosed`（acquire/invoke/commit 失败或 audit 写失败）。
    ///
    /// 冻结控制平面哲学：audit 只观测、不裁决。裁决仍由 `classify`/`evaluate`/`verify` 做出；
    /// audit 落盘失败时**拒绝继续执行**，保证"未审计即不发生"的可审计性。
    pub fn execute_committed(
        &self,
        run_id: &str,
        step: &PlanStep,
        call: SemanticToolCall,
    ) -> ExecutionOutcome {
        use crate::audit::{AuditEvent, AuditEventType};
        let Some(journal) = self.audit.as_ref() else {
            return ExecutionOutcome::audit_disabled();
        };

        // 1. Policy 评估（裁决）。裁决先于审计——裁决是权威，审计是观测。
        let decision = self.evaluate(step);
        if !decision.allowed {
            // 仍记审计（被拒步也是可审计事件），写失败则 fail-closed。
            if let Err(err) = journal.append(&AuditEvent::new(
                AuditEventType::PolicyEvaluated,
                run_id,
                &step.id,
                "operator",
                format!("decision=deny tool={} risk={} reason={}", step.tool, decision.risk.as_str(), decision.reason),
            )) {
                return ExecutionOutcome::audit_failure(&err);
            }
            return ExecutionOutcome::Denied {
                risk: decision.risk,
                reason: decision.reason,
            };
        }
        // 记允许决策。
        if let Err(err) = journal.append(&AuditEvent::new(
            AuditEventType::PolicyEvaluated,
            run_id,
            &step.id,
            "operator",
            format!("decision=allow tool={} risk={} reason={}", step.tool, decision.risk.as_str(), decision.reason),
        )) {
            return ExecutionOutcome::audit_failure(&err);
        }

        // 2. Acquire lease。
        let lease = match self.acquire(&decision) {
            Ok(lease) => lease,
            Err(reason) => {
                let _ = journal.append(&AuditEvent::new(
                    AuditEventType::PolicyEvaluated,
                    run_id,
                    &step.id,
                    "operator",
                    format!("acquire failed reason={reason}"),
                ));
                return ExecutionOutcome::FailedClosed { reason };
            }
        };
        if let Err(err) = journal.append(&AuditEvent::new(
            AuditEventType::ApprovalBound,
            run_id,
            &step.id,
            "operator",
            format!("lease_id={} risk={}", lease.lease_id, lease.risk.as_str()),
        )) {
            return ExecutionOutcome::audit_failure(&err);
        }

        // 3. Invoke（执行意图）。
        // 冻结原则：真实执行前先经 ToolRouter 裁决（route），裁决通过才执行。
        // executor 存在时走真实后端，否则退回 stub invoke（向后兼容）。
        let effect = if let Some(executor) = self.executor.as_ref() {
            match self.route_tool(&call) {
                Ok(routed) => executor.execute(&routed),
                Err(rejection) => {
                    let _ = journal.append(&AuditEvent::new(
                        AuditEventType::SandboxDenied,
                        run_id,
                        &step.id,
                        "operator",
                        format!("route rejected tool={} reason={}", rejection.tool, rejection.reason),
                    ));
                    return ExecutionOutcome::FailedClosed {
                        reason: format!("route rejected: {}", rejection.reason),
                    };
                }
            }
        } else {
            self.invoke(call)
        };
        if !effect.prepared {
            return ExecutionOutcome::FailedClosed {
                reason: "effect not prepared".to_string(),
            };
        }
        if let Err(err) = journal.append(&AuditEvent::new(
            AuditEventType::EffectPrepared,
            run_id,
            &step.id,
            "operator",
            format!("prepared tool={} summary={}", effect.tool, effect.summary),
        )) {
            return ExecutionOutcome::audit_failure(&err);
        }
        if let Err(err) = journal.append(&AuditEvent::new(
            AuditEventType::EffectObserved,
            run_id,
            &step.id,
            "operator",
            format!("observed tool={} summary={}", effect.tool, effect.summary),
        )) {
            return ExecutionOutcome::audit_failure(&err);
        }

        // 4. Verify + Commit（验证裁决 + 提交）。
        let verification = self.verify(&effect);
        let commit = match self.commit(&effect) {
            Ok(commit) => commit,
            Err(reason) => return ExecutionOutcome::FailedClosed { reason },
        };
        if !verification.success {
            return ExecutionOutcome::FailedClosed {
                reason: verification.reason,
            };
        }
        if let Err(err) = journal.append(&AuditEvent::new(
            AuditEventType::CommitSealed,
            run_id,
            &step.id,
            "operator",
            format!("commit_id={} tool={} sealed", commit.0, effect.tool),
        )) {
            return ExecutionOutcome::audit_failure(&err);
        }

        ExecutionOutcome::Committed {
            run_id: run_id.to_string(),
            lease_id: lease.lease_id,
            commit_id: commit.0,
            effect,
        }
    }

    /// 驱动完整 agent 执行闭环：LLM 产意图 → bridge 验证 → run_plan_guarded 裁决+执行
    /// → 反馈 → replan（受 `max_replans` 限制）。返回 `ReplanOutcome`（advisory 观测）。
    ///
    /// **冻结控制平面哲学**：LLM 只产 intention；裁决（policy / source-to-sink / 审批 /
    /// ToolRouter）全在 `run_plan_guarded` + 桥接器内。本方法只编排，不自造裁决。
    ///
    /// 前置条件：planner + audit + executor 均已注入。任一缺失 → fail-closed
    /// 返回 `None`（绝不谎报闭环跑通）。operator 入口据此区分"未配置"与"跑了但失败"。
    ///
    /// `approve`：非只读步是否自动批准。`false`（缺省建议）→ 只读步放行，执行类步被审批门拒
    /// （operator 可经审计看到 StepDenied，再决定是否带 approve=true 重跑）。
    pub fn run_intent(
        &self,
        intent: &str,
        actor: &str,
        run_id: &str,
        approve: bool,
        max_replans: usize,
    ) -> Option<ReplanOutcome> {
        // fail-closed：闭环三件套缺一不可。audit 是真相源（run_replan_loop 依赖 journal 持久化
        // exec 观测 + IntentReceived 锚点，崩溃可恢复）；executor 是真实后端；planner 产 intention。
        let planner = self.planner.as_ref()?;
        let journal = self.audit.as_ref()?;
        let executor = self.executor.as_ref()?;

        // 桥接器：把 agentd 的 ToolExecutor 适配为 agent_runtime::StepExecutor。
        let bridge = ToolExecutorBridge::new(executor.as_ref());

        // ModelProvenance：LLM 产的 step 标记为 model_output（经 source-to-sink 门约束）。
        // OperatorApprovals：approve=false 时非只读步被拒（consume-once token）。
        let outcome = run_replan_loop(
            planner.as_ref(),
            intent,
            actor,
            run_id,
            &ModelProvenance,
            &OperatorApprovals::new(actor, approve),
            &bridge,
            journal,
            max_replans,
        );
        Some(outcome)
    }
}

/// 可审计执行路径的最终结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionOutcome {
    /// Policy 拒绝（裁决为 Never）。
    Denied {
        risk: RiskClass,
        reason: String,
    },
    /// 成功提交：run_id、lease_id、commit_id、effect。
    Committed {
        run_id: String,
        lease_id: String,
        commit_id: String,
        effect: Effect,
    },
    /// fail-closed：acquire/invoke/verify/commit 失败。
    FailedClosed {
        reason: String,
    },
    /// audit 未启用——编排链未走可审计路径。
    AuditDisabled,
}

impl ExecutionOutcome {
    fn audit_disabled() -> Self {
        Self::AuditDisabled
    }

    fn audit_failure(err: &std::io::Error) -> Self {
        Self::FailedClosed {
            reason: format!("audit write failed: {err}"),
        }
    }

    /// 是否成功提交。
    pub fn is_committed(&self) -> bool {
        matches!(self, Self::Committed { .. })
    }

    /// 是否被拒绝（policy 裁决）。
    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Denied { .. })
    }

    /// 是否 fail-closed。
    pub fn is_failed_closed(&self) -> bool {
        matches!(self, Self::FailedClosed { .. })
    }

    /// 序列化为 JSON（/execute 端点用）。audit 未启用时返回 `audit_disabled` 标记。
    pub fn to_json(&self) -> String {
        match self {
            Self::Committed {
                run_id,
                lease_id,
                commit_id,
                effect,
            } => format!(
                r#"{{"allowed":true,"committed":true,"run_id":"{}","lease_id":"{}","commit_id":"{}","effect":{}}}"#,
                escape_json(run_id),
                escape_json(lease_id),
                escape_json(commit_id),
                effect.to_json(),
            ),
            Self::Denied { risk, reason } => format!(
                r#"{{"allowed":false,"committed":false,"risk":"{}","reason":"{}"}}"#,
                risk.as_str(),
                escape_json(reason),
            ),
            Self::FailedClosed { reason } => format!(
                r#"{{"allowed":false,"committed":false,"failed_closed":true,"reason":"{}"}}"#,
                escape_json(reason),
            ),
            Self::AuditDisabled => {
                r#"{"allowed":false,"committed":false,"audit_disabled":true}"#.to_string()
            }
        }
    }
}

#[cfg(test)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_in_local_only_stub_mode() {
        let mut agentd = Agentd::new(LifecycleConfig::default());
        agentd.start();
        let health = agentd.health_report();
        assert_eq!(health.state, LifecycleState::Running);
        assert_eq!(health.run_mode, "local-only");
        assert_eq!(health.planner_mode, "stub");
        assert!(!health.arbitrary_shell_enabled);
        assert_eq!(health.module_count, 8);
    }

    #[test]
    fn exposes_all_required_module_boundaries() {
        let agentd = Agentd::new(LifecycleConfig::default());
        let modules = agentd
            .module_statuses()
            .iter()
            .map(|status| status.kind.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            modules,
            vec![
                "planner",
                "policy",
                "capability",
                "tool_router",
                "audit",
                "rollback",
                "model_broker",
                "tui",
            ]
        );
    }

    #[test]
    fn denies_arbitrary_shell_in_normal_mode() {
        let agentd = Agentd::new(LifecycleConfig::default());
        let step = PlanStep {
            id: "danger".to_string(),
            tool: "shell.exec".to_string(),
            risk: RiskClass::ReadOnly,
        };
        let decision = agentd.evaluate(&step);
        assert!(!decision.allowed);
        assert_eq!(decision.risk, RiskClass::Never);
        assert!(agentd.acquire(&decision).is_err());
    }

    #[test]
    fn stub_api_flow_returns_typed_results() {
        let mut agentd = Agentd::new(LifecycleConfig::default());
        agentd.start();
        let plan = agentd.plan("check agentd");
        let step = plan.steps.first().expect("plan has a step");
        let decision = agentd.evaluate(step);
        let lease = agentd.acquire(&decision).expect("lease is issued");
        assert_eq!(lease.risk, RiskClass::ReadOnly);
        let effect = agentd.invoke(SemanticToolCall::new(
            "svc.status",
            vec![("service", "agentd")],
        ));
        assert!(agentd.verify(&effect).success);
        let commit = agentd
            .commit(&effect)
            .expect("commit seals verified effect");
        assert!(!agentd.rollback(&commit).triggered);
        assert_eq!(agentd.recover().unresolved_effects, 0);
    }

    #[test]
    fn records_controlled_error_in_health_report() {
        let mut agentd = Agentd::new(LifecycleConfig::default());
        agentd.start();
        agentd.record_error("simulated controlled agentd error");
        let health = agentd.health_report();
        assert_eq!(
            health.last_error.as_deref(),
            Some("simulated controlled agentd error")
        );
    }

    // ===== 阶段 AB：plan() 接入真实 LLM provider =====

    /// OpenAI 兼容 envelope（回放用，与 llm_planner 测试一致）。
    const OPENAI_PLAN_ENVELOPE: &str = r#"{
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "choices": [
            {"index": 0, "finish_reason": "stop",
             "message": {"role": "assistant",
                "content": "{\"steps\":[{\"tool\":\"svc.status\",\"resource\":\"nginx\",\"params\":{\"service\":\"nginx\"}},{\"tool\":\"fs.read\",\"resource\":\"config\",\"params\":{\"path\":\"/etc/nginx/nginx.conf\"}}]}"}}
        ]
    }"#;

    #[test]
    fn plan_without_provider_returns_stub_step() {
        // 无 planner 注入 → stub 路径（向后兼容）。
        let agentd = Agentd::new(LifecycleConfig::default());
        let plan = agentd.plan("check nginx");
        assert_eq!(plan.steps.len(), 1);
        assert_eq!(plan.steps[0].tool, "svc.status");
    }

    #[test]
    fn plan_with_recorded_provider_produces_real_steps() {
        let provider =
            llm_planner::RecordedProvider::openai("gpt-4o-mini", OPENAI_PLAN_ENVELOPE);
        let agentd = Agentd::new(LifecycleConfig::default()).with_planner(Box::new(provider));
        let plan = agentd.plan("inspect nginx config");
        // LLM 提议了 2 步，经 bridge_plan 验证为合法工具 → 转为 PlanSpec。
        assert_eq!(plan.steps.len(), 2, "steps: {:?}", plan.steps);
        assert_eq!(plan.steps[0].tool, "svc.status");
        assert_eq!(plan.steps[1].tool, "fs.read");
        assert!(agentd.planner_enabled());
    }

    #[test]
    fn plan_with_invalid_tool_provider_fail_closed_empty() {
        // LLM 提议非法工具 → bridge_plan 拒绝 → fail-closed 空计划。
        let bad_envelope = r#"{
            "id": "x", "object": "chat.completion",
            "choices": [{"index": 0, "finish_reason": "stop",
             "message": {"role": "assistant",
                "content": "{\"steps\":[{\"tool\":\"shell.exec\",\"params\":{}}]}"}}]
        }"#;
        let provider = llm_planner::RecordedProvider::openai("m", bad_envelope);
        let agentd = Agentd::new(LifecycleConfig::default()).with_planner(Box::new(provider));
        let plan = agentd.plan("do something bad");
        // shell.exec 经 bridge_plan 拒绝（或空）→ fail-closed。
        // 即使 bridge 通过，classify 仍裁决 Never；此处验证不谎报非法步。
        for step in &plan.steps {
            assert_ne!(step.tool, "shell.exec", "shell.exec 不应出现在计划中");
        }
    }

    #[test]
    fn plan_with_failing_provider_fail_closed_empty() {
        // provider 报错（网络/解析）→ fail-closed 空计划，不 panic。
        struct FailingProvider;
        impl llm_planner::LlmProvider for FailingProvider {
            fn plan(&self, _intent: &str) -> std::io::Result<llm_planner::RawPlan> {
                Err(std::io::Error::new(std::io::ErrorKind::Other, "network down"))
            }
        }
        let agentd =
            Agentd::new(LifecycleConfig::default()).with_planner(Box::new(FailingProvider));
        let plan = agentd.plan("anything");
        assert!(plan.steps.is_empty(), "fail-closed 应返回空计划");
    }

    #[test]
    fn debug_repr_does_not_leak_planner_internals() {
        // Agentd 手动 Debug 不展开 planner（trait object 无 Debug），只报 planner_enabled。
        let provider =
            llm_planner::RecordedProvider::openai("m", OPENAI_PLAN_ENVELOPE);
        let agentd =
            Agentd::new(LifecycleConfig::default()).with_planner(Box::new(provider));
        let debug = format!("{agentd:?}");
        assert!(debug.contains("planner_enabled: true"));
        assert!(!debug.contains("api_key"));
    }

    // ===== 阶段 H：run_intent 接入完整 agent 执行闭环 =====

    fn tmp_journal(tag: &str) -> AuditJournal {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "agentd-run-intent-{}-{}-{}.jsonl",
            tag,
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&path);
        AuditJournal::new(path)
    }

    /// 三件套齐全（planner + audit + executor）→ 闭环跑通，Completed。
    #[test]
    fn run_intent_completes_with_full_stack() {
        let journal = tmp_journal("complete");
        let provider =
            llm_planner::RecordedProvider::openai("gpt-4o-mini", OPENAI_PLAN_ENVELOPE);
        // OPENAI envelope 提议 svc.status（只读）+ fs.read（只读）——均 ReadOnly，
        // approve=false 也能放行，桥接到真实 executor 观测后 Completed。
        let agentd = Agentd::new(LifecycleConfig::default())
            .with_planner(Box::new(provider))
            .with_audit_and_executor(journal);

        let outcome = agentd
            .run_intent("inspect nginx config", "operator", "run-complete", false, 2)
            .expect("full stack should run");

        assert!(outcome.completed(), "summary: {}", outcome.summary());
        assert!(outcome.attempts >= 1);
        assert!(!outcome.trace.is_empty());
    }

    /// 缺 planner → fail-closed 返回 None（绝不谎报闭环跑通）。
    #[test]
    fn run_intent_fail_closed_without_planner() {
        let journal = tmp_journal("no-planner");
        // 有 audit + executor 但无 planner → None。
        let agentd = Agentd::new(LifecycleConfig::default())
            .with_audit_and_executor(journal);
        assert!(agentd.run_intent("x", "operator", "run-np", false, 1).is_none());
    }

    /// 缺 audit → fail-closed 返回 None（无真相源无法走可恢复闭环）。
    #[test]
    fn run_intent_fail_closed_without_audit() {
        let provider =
            llm_planner::RecordedProvider::openai("m", OPENAI_PLAN_ENVELOPE);
        // 有 planner 但无 audit/executor → None。
        let agentd = Agentd::new(LifecycleConfig::default()).with_planner(Box::new(provider));
        assert!(agentd.run_intent("x", "operator", "run-na", false, 1).is_none());
    }

    /// 审计持久化：run_intent 跑完后，journal 应含 IntentReceived 锚点（可恢复）。
    #[test]
    fn run_intent_persists_intent_anchor_to_audit() {
        let journal = tmp_journal("audit");
        let provider =
            llm_planner::RecordedProvider::openai("m", OPENAI_PLAN_ENVELOPE);
        let agentd = Agentd::new(LifecycleConfig::default())
            .with_planner(Box::new(provider))
            .with_audit_and_executor(journal.clone());

        let outcome = agentd
            .run_intent("inspect nginx", "operator", "run-audit", false, 1)
            .expect("run");
        assert!(outcome.completed());

        // journal 应含至少一条 IntentReceived 事件（run_replan_loop 每轮 plan 前写入）。
        let lines = journal.run_timeline("run-audit").expect("timeline");
        assert!(
            lines.iter().any(|l| l.contains("IntentReceived")),
            "应有 IntentReceived 锚点: {lines:?}"
        );
    }
}
