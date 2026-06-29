//! runner —— 把桥接出的 `Vec<PlannedStep>` 喂冻结 `AgentRuntime::run_plan_guarded`
//! 的 host 适配器（order9）。冻结裁决顺序：source_to_sink 门（model_output → 非 ReadOnly
//! Denied，exec 不触达）→ `PolicyEvaluator`（exact `ApprovalToken` consume-once）→ exec。
//!
//! `StubExecutor` 仿 `security_execution_linux/tests/service_recovery_real.rs` 的
//! `RecoveryExecutor`，但用 host stub 后端（记录被执行的 step，便于断言「exec 未被调用」）。

use std::cell::{Cell, RefCell};

use agent_runtime::{
    ApprovalSource, PlannedStep, StepExecutor, StepObservation, StepOutcome, StepProvenance,
    StepRisk,
};
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
