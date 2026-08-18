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
// ADR-000 第三 MVP「不可信内容处理」：把冻结 source-to-sink 门接到多步 run loop（ADDITIVE）。
use security_execution::audit::{AuditEvent, AuditEventType, AuditJournal};
use security_execution::source_to_sink::{
    ContentSource, SinkDescriptor, SourceToSinkDecisionKind, SourceToSinkError, SourceToSinkPolicy,
    SourceToSinkRequest,
};

/// 计划步骤的风险类（与冻结 `RiskClass` 一一对应）。
///
/// **附加式扩展（ADR-006 LLM 接入）**：原先只暴露 run loop 实际驱动的两类
/// （`ReadOnly` 诊断 / `ExecuteWithConfirmation` 执行）；现补齐 `RiskClass` 的全部 5 类，
/// 使 LLM 桥接层能把冻结 `ToolRouter` 给出的**权威** RiskClass（如 `fs.write.diff`=
/// WriteWithDiff、`pkg.host.install`=PrivilegedWithHumanApproval）无损映射、绝不降级。
/// 现有 `ReadOnly`/`ExecuteWithConfirmation` 的行为字节一致（向后兼容）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepRisk {
    ReadOnly,
    WriteWithDiff,
    ExecuteWithConfirmation,
    PrivilegedWithHumanApproval,
    Never,
}

impl StepRisk {
    pub fn to_risk_class(self) -> RiskClass {
        match self {
            StepRisk::ReadOnly => RiskClass::ReadOnly,
            StepRisk::WriteWithDiff => RiskClass::WriteWithDiff,
            StepRisk::ExecuteWithConfirmation => RiskClass::ExecuteWithConfirmation,
            StepRisk::PrivilegedWithHumanApproval => RiskClass::PrivilegedWithHumanApproval,
            StepRisk::Never => RiskClass::Never,
        }
    }
}

/// 由冻结 `RiskClass` 构造 `StepRisk`（桥接层用：权威风险只来自 `ToolRouter`/`TOOL_SCHEMAS`，
/// 绝不信任 LLM 自报）。一一对应，无降级。
impl From<RiskClass> for StepRisk {
    fn from(risk: RiskClass) -> Self {
        match risk {
            RiskClass::ReadOnly => StepRisk::ReadOnly,
            RiskClass::WriteWithDiff => StepRisk::WriteWithDiff,
            RiskClass::ExecuteWithConfirmation => StepRisk::ExecuteWithConfirmation,
            RiskClass::PrivilegedWithHumanApproval => StepRisk::PrivilegedWithHumanApproval,
            RiskClass::Never => StepRisk::Never,
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

    /// 该步作为 source-to-sink「汇」的描述符（汇类由冻结 oracle 据 tool/risk/资源/参数推断）。
    /// 参数与冻结 `SinkDescriptor::for_tool` 同形：构造时若任一字段含 secret-like 串则返回
    /// `SecretValue` 错（fail-closed，调用方据此收束为 RunFailedClosed）。
    pub fn sink_descriptor(&self) -> Result<SinkDescriptor, SourceToSinkError> {
        SinkDescriptor::for_tool(
            self.tool.clone(),
            self.risk.to_risk_class(),
            self.resource.clone(),
            self.params.clone(),
        )
    }
}

/// 一步内容的**来源溯源**：返回驱动该步的不可信内容来源（外部/模型/净化摘要等），
/// 或 `None`（算子原生步骤，无外部内容驱动 => 跳过 source-to-sink 门）。
/// 平行于 `PlannedStep`（不给计划结构加必填字段，保持向后兼容）。
pub trait StepProvenance {
    fn content_source(&self, step: &PlannedStep) -> Option<ContentSource>;
}

/// 单步主体处理的控制流：继续下一步，或以给定状态收束当前 run（早退）。
/// 由 `run_plan` 与 `run_plan_guarded` 共用同一段每步逻辑（`run_plan` 行为一字不变）。
enum StepFlow {
    Continue,
    Halt(RunState),
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
    /// 冻结 source-to-sink 门拒绝了一步（不可信来源直接驱动越权汇）：在 policy/审批/exec
    /// **之前**裁决，故 exec 不触达（no effect prepared）。run 据此收束为 `Denied`。
    SourceToSinkDenied {
        step_id: String,
        source_label: String,
        sink_class: String,
        reason: String,
    },
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
        for step in plan {
            self.log.push(RunEvent::StepPlanned {
                step_id: step.step_id.clone(),
            });
            match self.run_plan_step(actor, step, approvals, exec, None, "") {
                StepFlow::Continue => {}
                StepFlow::Halt(state) => return state,
            }
        }
        self.log.push(RunEvent::RunCompleted);
        self.state()
    }

    /// 单步主体（policy → 审批 → exec），`run_plan` / `run_plan_guarded` 共用。**前置不变量**：
    /// 调用方已 push 该步 `StepPlanned`。返回 `Continue`（走下一步）或 `Halt`（早退收束）。
    /// 逻辑与原 `run_plan` 每步体逐字一致（行为不变）。
    ///
    /// `journal`（阶段 H）：`Some` 时，exec 阶段事件（`StepConfined`/`EffectObserved`/
    /// `StepDenied`）追加到 audit journal——持久化 exec 副作用观测，summary 经
    /// `redact_summary` 脱敏。`None` 时跳过（`run_plan` 行为不变）。
    fn run_plan_step(
        &mut self,
        actor: &str,
        step: &PlannedStep,
        approvals: &dyn ApprovalSource,
        exec: &dyn StepExecutor,
        journal: Option<&AuditJournal>,
        run_id: &str,
    ) -> StepFlow {
        let evaluator = PolicyEvaluator;
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
                        // 阶段 H：exec 副作用观测持久化到 audit journal（summary 经
                        // `redact_summary` 脱敏，防 exec 后端注入 secret 回流到审计/反馈）。
                        if let Some(journal) = journal {
                            let _ = journal.append(&AuditEvent::new(
                                AuditEventType::EffectObserved,
                                run_id,
                                &step.step_id,
                                actor,
                                &format!("{} observed: {detail}", step.tool),
                            ));
                        }
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
                            return StepFlow::Halt(self.state());
                        }
                        StepFlow::Continue
                    }
                    Ok(StepObservation {
                        outcome: StepOutcome::KernelDenied { reason },
                        ..
                    }) => {
                        self.log.push(RunEvent::StepDenied {
                            step_id: step.step_id.clone(),
                            reason: reason.clone(),
                        });
                        // 阶段 H：内核拒绝也持久化到审计日志。
                        if let Some(journal) = journal {
                            let _ = journal.append(&AuditEvent::new(
                                AuditEventType::SandboxDenied,
                                run_id,
                                &step.step_id,
                                actor,
                                &format!("kernel denied: {reason}"),
                            ));
                        }
                        self.log.push(RunEvent::RunFailedClosed);
                        StepFlow::Halt(self.state())
                    }
                    Err(_) => {
                        self.log.push(RunEvent::RunFailedClosed);
                        StepFlow::Halt(self.state())
                    }
                }
            }
            PolicyDecisionKind::PauseForApproval => {
                // restart 不执行：对应冻结 denied 分支（no effect prepared）。
                self.log.push(RunEvent::StepDenied {
                    step_id: step.step_id.clone(),
                    reason: "restart approval denied; no effect prepared".to_string(),
                });
                StepFlow::Halt(self.state())
            }
            PolicyDecisionKind::Deny => {
                self.log.push(RunEvent::StepDenied {
                    step_id: step.step_id.clone(),
                    reason: decision.reason.clone(),
                });
                StepFlow::Halt(self.state())
            }
        }
    }

    /// 多步 run loop + **source-to-sink 门**（ADR-000 第三 MVP「不可信内容处理」，ADDITIVE）。
    ///
    /// 每步：push `StepPlanned` → 若 `provenance.content_source(step)=Some(source)`，则在
    /// policy/审批/exec **之前**经冻结 `SourceToSinkPolicy::evaluate_and_audit` 裁决：
    /// - `Denied`：push `SourceToSinkDenied` 并收束（**exec 不触达**，no effect prepared）。
    /// - `Allowed`：落到既有每步主体（`run_plan_step`，与 `run_plan` 同形）。
    /// - 汇描述符 / 请求构造失败（secret-like 字段）=> push `RunFailedClosed` 收束。
    /// `None`（算子原生步）：直接走既有逻辑。全部走完则 `RunCompleted`。状态纯从日志重建。
    pub fn run_plan_guarded(
        &mut self,
        actor: &str,
        run_id: &str,
        plan: &[PlannedStep],
        provenance: &dyn StepProvenance,
        approvals: &dyn ApprovalSource,
        exec: &dyn StepExecutor,
        journal: &AuditJournal,
    ) -> RunState {
        self.log.push(RunEvent::IntentAccepted {
            actor: actor.to_string(),
        });
        let gate = SourceToSinkPolicy;
        for step in plan {
            self.log.push(RunEvent::StepPlanned {
                step_id: step.step_id.clone(),
            });
            // source-to-sink 门：仅当该步由不可信内容驱动时介入，且在 policy/exec 之前。
            if let Some(source) = provenance.content_source(step) {
                let sink = match step.sink_descriptor() {
                    Ok(sink) => sink,
                    Err(_) => {
                        self.log.push(RunEvent::RunFailedClosed);
                        return self.state();
                    }
                };
                let request = match SourceToSinkRequest::new(
                    run_id,
                    step.step_id.as_str(),
                    actor,
                    source,
                    sink,
                ) {
                    Ok(request) => request,
                    Err(_) => {
                        self.log.push(RunEvent::RunFailedClosed);
                        return self.state();
                    }
                };
                match gate.evaluate_and_audit(journal, &request) {
                    Ok(decision) if decision.kind == SourceToSinkDecisionKind::Denied => {
                        // exec 不触达：在 capability 绑定前断开不可信来源 → 越权汇的路径。
                        self.log.push(RunEvent::SourceToSinkDenied {
                            step_id: step.step_id.clone(),
                            source_label: decision.source_label.as_str().to_string(),
                            sink_class: decision.sink_class.as_str().to_string(),
                            reason: decision.reason.clone(),
                        });
                        return self.state();
                    }
                    Ok(_) => {} // Allowed：落到既有每步主体（policy/审批/exec 仍各司其职）。
                    Err(_) => {
                        self.log.push(RunEvent::RunFailedClosed);
                        return self.state();
                    }
                }
            }
            match self.run_plan_step(actor, step, approvals, exec, Some(journal), run_id) {
                StepFlow::Continue => {}
                StepFlow::Halt(state) => return state,
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
                RunEvent::SourceToSinkDenied { .. } => RunState::Denied,
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

    // ===== ADR-000 第三 MVP「不可信内容处理」：source-to-sink 门接入多步 run loop =====

    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// 记录被真正执行的步骤（断言「拒绝步 exec 不触达」）；每步回 Confined "ok"。
    struct RecordingExecutor {
        executed: RefCell<Vec<String>>,
    }
    impl RecordingExecutor {
        fn new() -> Self {
            Self {
                executed: RefCell::new(Vec::new()),
            }
        }
        fn executed(&self) -> Vec<String> {
            self.executed.borrow().clone()
        }
    }
    impl StepExecutor for RecordingExecutor {
        fn execute(&self, step: &PlannedStep) -> std::io::Result<StepObservation> {
            self.executed.borrow_mut().push(step.step_id.clone());
            Ok(StepObservation {
                outcome: StepOutcome::Confined,
                detail: "ok".to_string(),
            })
        }
    }

    /// 从不发审批 token（ReadOnly 步由 policy 直接放行；被门拒的步在门前已收束）。
    struct NoApprovals;
    impl ApprovalSource for NoApprovals {
        fn token_for(&self, _step: &PlannedStep) -> Option<ApprovalToken> {
            None
        }
    }

    /// 按 step_id 映射不可信来源；未登记 => None（算子原生，跳过门）。
    struct MapProvenance(HashMap<String, ContentSource>);
    impl StepProvenance for MapProvenance {
        fn content_source(&self, step: &PlannedStep) -> Option<ContentSource> {
            self.0.get(&step.step_id).cloned()
        }
    }

    /// 全 None：用于向后兼容差分（门对每步都跳过 => 与 run_plan 同形）。
    struct NoProvenance;
    impl StepProvenance for NoProvenance {
        fn content_source(&self, _step: &PlannedStep) -> Option<ContentSource> {
            None
        }
    }

    static JOURNAL_SEQ: AtomicU64 = AtomicU64::new(0);
    fn temp_journal(tag: &str) -> AuditJournal {
        let n = JOURNAL_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "aios_s2s_{}_{}_{}.log",
            tag,
            std::process::id(),
            n
        ));
        let _ = std::fs::remove_file(&path);
        AuditJournal::new(path)
    }

    fn read_step(id: &str) -> PlannedStep {
        PlannedStep {
            step_id: id.to_string(),
            tool: "fs.read".to_string(),
            resource: "report".to_string(),
            params: vec![],
            risk: StepRisk::ReadOnly,
        }
    }
    fn restart_step(id: &str) -> PlannedStep {
        PlannedStep {
            step_id: id.to_string(),
            tool: "svc.restart".to_string(),
            resource: "nginx".to_string(),
            params: vec![("service".to_string(), "nginx".to_string())],
            risk: StepRisk::ExecuteWithConfirmation,
        }
    }
    fn has_s2s_denied(events: &[RunEvent]) -> bool {
        events
            .iter()
            .any(|e| matches!(e, RunEvent::SourceToSinkDenied { .. }))
    }

    /// 拒绝流：external 内容直接驱动 svc.restart（ExecuteWithConfirmation 汇）=> 门在 exec 前
    /// 收束为 Denied；restart 未执行（no effect prepared）；审计落一行。
    #[test]
    fn untrusted_source_denied_before_exec_with_audit() {
        let mut map = HashMap::new();
        map.insert(
            "restart".to_string(),
            ContentSource::external_content("webpage-shell").unwrap(),
        );
        let provenance = MapProvenance(map);
        let plan = vec![read_step("fetch"), restart_step("restart")];
        let exec = RecordingExecutor::new();
        let journal = temp_journal("deny");
        let mut rt = AgentRuntime::new();

        let state = rt.run_plan_guarded(
            "operator",
            "run-injection",
            &plan,
            &provenance,
            &NoApprovals,
            &exec,
            &journal,
        );

        assert_eq!(state, RunState::Denied);
        assert!(has_s2s_denied(rt.events()), "gate must emit SourceToSinkDenied");
        // fetch（算子原生 ReadOnly）执行，restart 在门前被拦 => exec 不触达。
        assert_eq!(exec.executed(), vec!["fetch".to_string()]);
        let lines = journal.event_lines().unwrap();
        assert!(
            lines.iter().any(|l| {
                l.contains("source_label=external-untrusted-content")
                    && l.contains("sink_class=execute-with-confirmation")
            }),
            "deny must be audited with frozen source/sink labels, got {lines:?}"
        );
    }

    /// 允许流：fetch + sanitize + summarize 全是 ReadOnly 汇 => 门全 Allowed，跑到 Completed；
    /// 三步都执行；evaluate_and_audit 仅在 Denied 写审计 => 允许流不留审计行。
    #[test]
    fn read_only_sinks_pass_the_gate_to_completion() {
        let origin = ContentSource::external_content("webpage").unwrap();
        let mut map = HashMap::new();
        map.insert(
            "sanitize".to_string(),
            ContentSource::external_content("webpage").unwrap(),
        );
        map.insert(
            "summarize".to_string(),
            ContentSource::sanitized_summary(&origin, "summary").unwrap(),
        );
        let provenance = MapProvenance(map);
        let plan = vec![
            read_step("fetch"),
            read_step("sanitize"),
            read_step("summarize"),
        ];
        let exec = RecordingExecutor::new();
        let journal = temp_journal("allow");
        let mut rt = AgentRuntime::new();

        let state = rt.run_plan_guarded(
            "operator",
            "run-allow",
            &plan,
            &provenance,
            &NoApprovals,
            &exec,
            &journal,
        );

        assert_eq!(state, RunState::Completed);
        assert!(!has_s2s_denied(rt.events()));
        assert_eq!(
            exec.executed(),
            vec![
                "fetch".to_string(),
                "sanitize".to_string(),
                "summarize".to_string()
            ]
        );
        // 阶段 H：允许流的 exec 副作用观测现在持久化到审计日志（source-to-sink 门
        // 仍仅在 Denied 写审计行；exec 审计是新增的独立可观测性）。
        let lines = journal.event_lines().unwrap();
        assert!(
            lines.iter().any(|l| l.contains("EffectObserved")),
            "exec observations must be audited, got {lines:?}"
        );
        assert!(
            !lines.iter().any(|l| l.contains("SourceToSinkDenied")),
            "allowed flow must not write s2s deny rows, got {lines:?}"
        );
    }

    /// 净化不擦边界：SanitizedSummary 源（保留 original_trust=external）+ ExecuteWithConfirmation
    /// 汇 => 仍 Denied（reason 要求 replanning）；exec 不触达。
    #[test]
    fn sanitized_summary_cannot_drive_execute_sink() {
        let origin = ContentSource::external_content("webpage").unwrap();
        let sanitized = ContentSource::sanitized_summary(&origin, "summary").unwrap();
        let mut map = HashMap::new();
        map.insert("restart".to_string(), sanitized);
        let provenance = MapProvenance(map);
        let plan = vec![restart_step("restart")];
        let exec = RecordingExecutor::new();
        let journal = temp_journal("sanitized");
        let mut rt = AgentRuntime::new();

        let state = rt.run_plan_guarded(
            "operator",
            "run-sanitized",
            &plan,
            &provenance,
            &NoApprovals,
            &exec,
            &journal,
        );

        assert_eq!(state, RunState::Denied);
        let denied = rt
            .events()
            .iter()
            .find_map(|e| match e {
                RunEvent::SourceToSinkDenied {
                    source_label,
                    sink_class,
                    reason,
                    ..
                } => Some((source_label.clone(), sink_class.clone(), reason.clone())),
                _ => None,
            })
            .expect("SourceToSinkDenied present");
        assert_eq!(denied.0, "sanitized-summary");
        assert_eq!(denied.1, "execute-with-confirmation");
        assert!(
            denied.2.contains("replanning"),
            "sanitized summary still requires replanning before an execute sink: {}",
            denied.2
        );
        assert!(exec.executed().is_empty(), "exec must not be touched");
    }

    /// 差分：对 (source × sink) 小矩阵，比对 run_plan_guarded 的门 Denied 与冻结
    /// `SourceToSinkPolicy::evaluate` 直评一致（运行循环不自造裁决）。
    #[test]
    fn guarded_gate_matches_frozen_policy_across_matrix() {
        let origin = ContentSource::external_content("origin").unwrap();
        let combos: Vec<(&str, ContentSource, StepRisk)> = vec![
            (
                "op-read",
                ContentSource::operator_input("op").unwrap(),
                StepRisk::ReadOnly,
            ),
            (
                "op-exec",
                ContentSource::operator_input("op").unwrap(),
                StepRisk::ExecuteWithConfirmation,
            ),
            (
                "ext-read",
                ContentSource::external_content("ext").unwrap(),
                StepRisk::ReadOnly,
            ),
            (
                "ext-exec",
                ContentSource::external_content("ext").unwrap(),
                StepRisk::ExecuteWithConfirmation,
            ),
            (
                "model-exec",
                ContentSource::model_output("model").unwrap(),
                StepRisk::ExecuteWithConfirmation,
            ),
            (
                "san-exec",
                ContentSource::sanitized_summary(&origin, "san").unwrap(),
                StepRisk::ExecuteWithConfirmation,
            ),
        ];

        for (id, source, risk) in combos {
            let step = PlannedStep {
                step_id: id.to_string(),
                tool: if risk == StepRisk::ReadOnly {
                    "fs.read".to_string()
                } else {
                    "svc.restart".to_string()
                },
                resource: "nginx".to_string(),
                params: vec![("service".to_string(), "nginx".to_string())],
                risk,
            };

            // 冻结直评。
            let sink = step.sink_descriptor().unwrap();
            let request =
                SourceToSinkRequest::new("run-diff", step.step_id.as_str(), "operator", source.clone(), sink)
                    .unwrap();
            let frozen_denied =
                SourceToSinkPolicy.evaluate(&request).unwrap().kind == SourceToSinkDecisionKind::Denied;

            // run loop 门。
            let mut map = HashMap::new();
            map.insert(id.to_string(), source);
            let provenance = MapProvenance(map);
            let exec = RecordingExecutor::new();
            let journal = temp_journal("diff");
            let mut rt = AgentRuntime::new();
            rt.run_plan_guarded(
                "operator",
                "run-diff",
                std::slice::from_ref(&step),
                &provenance,
                &NoApprovals,
                &exec,
                &journal,
            );
            let loop_denied = has_s2s_denied(rt.events());

            assert_eq!(loop_denied, frozen_denied, "gate vs frozen mismatch for {id}");
        }
    }

    /// 向后兼容：provenance 全 None => run_plan_guarded 的事件序列与 run_plan **逐事件一致**。
    #[test]
    fn all_none_provenance_matches_run_plan_events() {
        let plan = vec![read_step("a"), read_step("b")];

        let exec1 = RecordingExecutor::new();
        let mut rt1 = AgentRuntime::new();
        rt1.run_plan("operator", &plan, &NoApprovals, &exec1);

        let exec2 = RecordingExecutor::new();
        let journal = temp_journal("compat");
        let mut rt2 = AgentRuntime::new();
        rt2.run_plan_guarded(
            "operator",
            "run-compat",
            &plan,
            &NoProvenance,
            &NoApprovals,
            &exec2,
            &journal,
        );

        assert_eq!(
            rt1.events(),
            rt2.events(),
            "guarded with no provenance must equal run_plan event-for-event"
        );
        // 阶段 H：run_plan_guarded 现在持久化 exec 副作用观测到审计日志（run_plan
        // 不写审计，行为不变）。事件序列仍逐事件一致（审计 append 不影响 self.log）。
        let lines = journal.event_lines().unwrap();
        assert!(
            lines.iter().any(|l| l.contains("EffectObserved")),
            "exec observations must be audited even without provenance, got {lines:?}"
        );
    }
}
