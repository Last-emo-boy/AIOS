//! agent_runtime —— 真实、未模拟的编排运行循环（ADR-004 D2 / cp3）。
//!
//! 取代冻结的 `agent_core::run_loop::AgentCore` 与 `agentd::lifecycle::Agentd`
//! （二者保留为只读差分 oracle）。驱动 accept_intent → 规划一步 → 经 `StepConfiner`
//! （真实强制后端，见 security_execution_linux::LinuxEnforcer）在真沙箱执行 →
//! 按内核结果封存/拒绝。状态**纯从 append-only 事件日志重建**（崩溃可恢复，
//! 不信任内存）。
#![forbid(unsafe_code)]

/// 运行循环状态（从日志重建，不直接持有）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunState {
    Idle,
    Planned,
    Executing,
    Completed,
    Denied,
    FailedClosed,
    /// 多步 run loop 在 verify 仍不健康时触发回滚并收束（ADR-004 service-recovery）。
    RolledBack,
}

/// 一步在真沙箱里执行的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepOutcome {
    /// 在内核约束下完成（动作被允许）。
    Confined,
    /// 内核阻止了该步骤（seccomp SIGSYS / Landlock EACCES / cgroup EAGAIN）。
    KernelDenied { reason: String },
}

/// 把一个计划步骤交给真实强制后端在沙箱里执行的抽象。
/// 实现见 `security_execution_linux::LinuxEnforcer`（agent_runtime 本身不依赖它，
/// 避免循环；真实实现经 dev/集成层注入）。
pub trait StepConfiner {
    fn confine(&self, step_id: &str) -> std::io::Result<StepOutcome>;
}

// ===== 多步 run loop + 真审批门（ADDITIVE）：复用冻结 `security_execution::policy` =====

use runtime_contracts::RiskClass;
use security_execution::policy::{
    stable_parameter_hash, ApprovalToken, PolicyDecisionKind, PolicyEvaluator, PolicyRequest,
};

/// 计划步骤的风险类（映射到冻结 `RiskClass`）。只暴露 run loop 实际驱动的两类：
/// 只读诊断（svc.status）与需确认的执行（svc.restart）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepRisk {
    ReadOnly,
    ExecuteWithConfirmation,
}

impl StepRisk {
    pub fn to_risk_class(self) -> RiskClass {
        match self {
            StepRisk::ReadOnly => RiskClass::ReadOnly,
            StepRisk::ExecuteWithConfirmation => RiskClass::ExecuteWithConfirmation,
        }
    }
}

/// 一个被规划的步骤。`policy_request` 与冻结 oracle 同形：`parameter_hash` 必须用
/// `stable_parameter_hash(&params)`，`policy_version="policy-v1"`，`now=0`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedStep {
    pub step_id: String,
    pub tool: String,
    pub resource: String,
    pub params: Vec<(String, String)>,
    pub risk: StepRisk,
}

impl PlannedStep {
    pub fn policy_request(&self, actor: &str) -> PolicyRequest {
        PolicyRequest {
            actor: actor.to_string(),
            tool: self.tool.clone(),
            resource: self.resource.clone(),
            risk: self.risk.to_risk_class(),
            parameter_hash: stable_parameter_hash(&self.params),
            policy_version: "policy-v1".to_string(),
            now: 0,
        }
    }
}

/// 一步在真后端执行后回传的观测：内核结局 + 人读细节（如 `alive=true pid=1234`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepObservation {
    pub outcome: StepOutcome,
    pub detail: String,
}

/// 把一个计划步骤交给真后端执行并回传真实观测的抽象（真实现见集成测试 RecoveryExecutor）。
pub trait StepExecutor {
    fn execute(&self, step: &PlannedStep) -> std::io::Result<StepObservation>;
}

/// 审批来源：对需确认的步骤返回 exact-matching 冻结 `ApprovalToken`（consume-once 由
/// 实现持内部状态保证：第二次返回 None）。只读步骤返回 None（policy 对 ReadOnly 直接放行）。
pub trait ApprovalSource {
    fn token_for(&self, step: &PlannedStep) -> Option<ApprovalToken>;
}

/// append-only 运行事件 —— 运行状态的唯一真相。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunEvent {
    IntentAccepted { actor: String },
    StepPlanned { step_id: String },
    StepConfined { step_id: String },
    StepDenied { step_id: String, reason: String },
    RunCompleted,
    RunFailedClosed,
    // ===== 多步 run loop + 真审批门（ADDITIVE，复用冻结 policy）的新增事件 =====
    /// 冻结 `PolicyEvaluator` 对一步的裁决（Allow/Deny/PauseForApproval + 风险类）。
    StepPolicyEvaluated {
        step_id: String,
        decision: security_execution::policy::PolicyDecisionKind,
        risk: runtime_contracts::RiskClass,
    },
    /// 该步的 exact-matching 审批 token 已绑定到精确参数哈希（审批与参数同形）。
    ApprovalBound {
        step_id: String,
        parameter_hash: String,
    },
    /// 一步在真后端执行后回传的真实副作用观测。
    EffectObserved {
        step_id: String,
        tool: String,
        detail: String,
    },
    /// verify 仍不健康，触发回滚。
    RollbackTriggered { step_id: String, reason: String },
    /// run 因回滚而收束。
    RunRolledBack,
}

#[derive(Debug, Default)]
pub struct AgentRuntime {
    log: Vec<RunEvent>,
}

impl AgentRuntime {
    pub fn new() -> Self {
        Self::default()
    }

    /// append-only 事件序列（持久化的真相）。
    pub fn events(&self) -> &[RunEvent] {
        &self.log
    }

    /// 接受意图 → 规划一步 → 经 confiner 在真沙箱执行 → 按内核结果封存/拒绝。
    pub fn run_step(&mut self, actor: &str, step_id: &str, confiner: &dyn StepConfiner) -> RunState {
        self.log.push(RunEvent::IntentAccepted {
            actor: actor.to_string(),
        });
        self.log.push(RunEvent::StepPlanned {
            step_id: step_id.to_string(),
        });
        match confiner.confine(step_id) {
            Ok(StepOutcome::Confined) => {
                self.log.push(RunEvent::StepConfined {
                    step_id: step_id.to_string(),
                });
                self.log.push(RunEvent::RunCompleted);
            }
            Ok(StepOutcome::KernelDenied { reason }) => {
                self.log.push(RunEvent::StepDenied {
                    step_id: step_id.to_string(),
                    reason,
                });
            }
            Err(_) => self.log.push(RunEvent::RunFailedClosed),
        }
        self.state()
    }

    /// 多步 run loop + 真审批门（复用冻结 `PolicyEvaluator` 作裁决 oracle）。
    ///
    /// 每步：StepPlanned → 构造 `policy_request` → 取审批 token → **冻结 evaluate** 裁决 →
    /// 记 StepPolicyEvaluated。
    /// - Allow：token 精确匹配则记 ApprovalBound；执行 → Confined 记 StepConfined +
    ///   EffectObserved（若是 verify 步的 svc.status 探到 alive=false，则执行一个回滚步、
    ///   记 RollbackTriggered + RunRolledBack 并收束）；KernelDenied/Err 记 RunFailedClosed 收束。
    /// - PauseForApproval：记 StepDenied("restart approval denied; no effect prepared") 收束
    ///   （restart **不执行**，对应冻结 denied 分支）。
    /// - Deny：记 StepDenied 收束。
    /// 全部步骤走完则 RunCompleted。状态纯从 append-only 日志重建。
    pub fn run_plan(
        &mut self,
        actor: &str,
        plan: &[PlannedStep],
        approvals: &dyn ApprovalSource,
        exec: &dyn StepExecutor,
    ) -> RunState {
        self.log.push(RunEvent::IntentAccepted {
            actor: actor.to_string(),
        });
        let evaluator = PolicyEvaluator;
        for step in plan {
            self.log.push(RunEvent::StepPlanned {
                step_id: step.step_id.clone(),
            });
            let request = step.policy_request(actor);
            let token = approvals.token_for(step);
            let decision = evaluator.evaluate(&request, token.as_ref());
            self.log.push(RunEvent::StepPolicyEvaluated {
                step_id: step.step_id.clone(),
                decision: decision.kind,
                risk: decision.risk,
            });
            match decision.kind {
                PolicyDecisionKind::Allow => {
                    if token.as_ref().is_some_and(|t| t.matches(&request)) {
                        self.log.push(RunEvent::ApprovalBound {
                            step_id: step.step_id.clone(),
                            parameter_hash: request.parameter_hash.clone(),
                        });
                    }
                    match exec.execute(step) {
                        Ok(StepObservation {
                            outcome: StepOutcome::Confined,
                            detail,
                        }) => {
                            self.log.push(RunEvent::StepConfined {
                                step_id: step.step_id.clone(),
                            });
                            self.log.push(RunEvent::EffectObserved {
                                step_id: step.step_id.clone(),
                                tool: step.tool.clone(),
                                detail: detail.clone(),
                            });
                            // verify 步的 svc.status 仍探到 alive=false => 触发回滚并收束。
                            if step.tool == "svc.status"
                                && step.step_id.starts_with("verify")
                                && detail.contains("alive=false")
                            {
                                let rollback_step = PlannedStep {
                                    step_id: format!("{}-rollback", step.step_id),
                                    tool: "svc.restart.rollback".to_string(),
                                    resource: step.resource.clone(),
                                    params: step.params.clone(),
                                    risk: StepRisk::ExecuteWithConfirmation,
                                };
                                let _ = exec.execute(&rollback_step);
                                self.log.push(RunEvent::RollbackTriggered {
                                    step_id: step.step_id.clone(),
                                    reason: format!("verify probe still unhealthy: {detail}"),
                                });
                                self.log.push(RunEvent::RunRolledBack);
                                return self.state();
                            }
                        }
                        Ok(StepObservation {
                            outcome: StepOutcome::KernelDenied { reason },
                            ..
                        }) => {
                            self.log.push(RunEvent::StepDenied {
                                step_id: step.step_id.clone(),
                                reason,
                            });
                            self.log.push(RunEvent::RunFailedClosed);
                            return self.state();
                        }
                        Err(_) => {
                            self.log.push(RunEvent::RunFailedClosed);
                            return self.state();
                        }
                    }
                }
                PolicyDecisionKind::PauseForApproval => {
                    // restart 不执行：对应冻结 denied 分支（no effect prepared）。
                    self.log.push(RunEvent::StepDenied {
                        step_id: step.step_id.clone(),
                        reason: "restart approval denied; no effect prepared".to_string(),
                    });
                    return self.state();
                }
                PolicyDecisionKind::Deny => {
                    self.log.push(RunEvent::StepDenied {
                        step_id: step.step_id.clone(),
                        reason: decision.reason.clone(),
                    });
                    return self.state();
                }
            }
        }
        self.log.push(RunEvent::RunCompleted);
        self.state()
    }

    pub fn state(&self) -> RunState {
        Self::rehydrate(&self.log)
    }

    /// 纯从 append-only 日志重建状态（durability：崩溃后只 replay 日志）。
    pub fn rehydrate(log: &[RunEvent]) -> RunState {
        let mut s = RunState::Idle;
        for ev in log {
            s = match ev {
                RunEvent::IntentAccepted { .. } => RunState::Planned,
                RunEvent::StepPlanned { .. } => RunState::Executing,
                RunEvent::StepConfined { .. } => RunState::Executing,
                RunEvent::RunCompleted => RunState::Completed,
                RunEvent::StepDenied { .. } => RunState::Denied,
                RunEvent::RunFailedClosed => RunState::FailedClosed,
                // 新增事件的 rehydrate arm（保持 exhaustive、无 catch-all）。
                RunEvent::StepPolicyEvaluated { .. } => RunState::Executing,
                RunEvent::ApprovalBound { .. } => RunState::Executing,
                RunEvent::EffectObserved { .. } => RunState::Executing,
                RunEvent::RollbackTriggered { .. } => RunState::Executing,
                RunEvent::RunRolledBack => RunState::RolledBack,
            };
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockConfiner(StepOutcome);
    impl StepConfiner for MockConfiner {
        fn confine(&self, _step_id: &str) -> std::io::Result<StepOutcome> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn completes_on_confined_step_and_rebuilds_from_log() {
        let mut rt = AgentRuntime::new();
        assert_eq!(
            rt.run_step("op", "s1", &MockConfiner(StepOutcome::Confined)),
            RunState::Completed
        );
        // durability：纯 replay 日志 == Completed
        assert_eq!(AgentRuntime::rehydrate(rt.events()), RunState::Completed);
    }

    #[test]
    fn denied_when_kernel_blocks_step() {
        let mut rt = AgentRuntime::new();
        let out = StepOutcome::KernelDenied {
            reason: "SIGSYS".into(),
        };
        assert_eq!(rt.run_step("op", "s1", &MockConfiner(out)), RunState::Denied);
    }
}
