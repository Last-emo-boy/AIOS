//! 端到端：真服务监督 + svc.restart + 多步 run loop + 真审批门 → service-recovery
//! （ADR-000 旗舰工作流的真实版，ADR-004 D2）。
//!
//! - 真服务：`sandbox_probe service-sleep`（直接进程，心跳写 health 文件，不进沙箱）。
//! - 审批门：冻结 `security_execution::policy::PolicyEvaluator`/`ApprovalToken` 裁决，
//!   `agent_runtime::run_plan` 驱动；放行后 `RecoveryExecutor` 经 `ServiceSupervisor`
//!   执行真 restart（kill→在 spawn 前阻塞回收 old→spawn 新实例→await_health）。
//! - 差分 oracle：冻结 `AgentCoreServiceRecovery`（service="nginx"）单独对照决策形状。
//!
//! 每个 spawn 的服务 pid 测试结束都经 `shutdown()`（+ Drop 安全网）kill+wait 回收。
#![cfg(target_os = "linux")]

use std::cell::{Cell, RefCell};

use agent_runtime::{
    AgentRuntime, ApprovalSource, PlannedStep, RunEvent, RunState, StepExecutor, StepObservation,
    StepOutcome, StepRisk,
};
use security_execution::policy::ApprovalToken;
use security_execution_linux::{ServiceSpec, ServiceSupervisor};

fn helper() -> &'static str {
    env!("CARGO_BIN_EXE_sandbox_probe")
}

fn proc_exists(pid: i32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

/// 每个用例的唯一临时 health/pid 文件路径（测试在同进程内并行，路径必须互不冲突）。
fn spec(name: &str) -> ServiceSpec {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base = std::env::temp_dir().join(format!(
        "aios-svc-recovery-{name}-{}-{nanos}",
        std::process::id()
    ));
    let health = format!("{}.health", base.display());
    let pid = format!("{}.pid", base.display());
    let _ = std::fs::remove_file(&health);
    let _ = std::fs::remove_file(&pid);
    ServiceSpec {
        helper: helper().to_string(),
        health_file: health,
        pid_file: pid,
        // 取够长：测试用 fail()/restart() 主动杀，避免服务自然退出造成误判。
        secs: 30,
    }
}

fn status_step(step_id: &str, service: &str) -> PlannedStep {
    PlannedStep {
        step_id: step_id.to_string(),
        tool: "svc.status".to_string(),
        resource: service.to_string(),
        params: vec![("service".to_string(), service.to_string())],
        risk: StepRisk::ReadOnly,
    }
}

fn restart_step(service: &str) -> PlannedStep {
    PlannedStep {
        step_id: "restart-service".to_string(),
        tool: "svc.restart".to_string(),
        resource: service.to_string(),
        params: vec![("service".to_string(), service.to_string())],
        risk: StepRisk::ExecuteWithConfirmation,
    }
}

/// 与该 step 的 `policy_request` 完全同形的冻结 `ApprovalToken`（actor/tool/resource/
/// parameter_hash/policy_version 一致，expires_at>=now=0）。run_plan 的 policy gate 与
/// executor 的真 restart 都用它 —— 同一参数同一证明，自洽。
fn exact_token_for(actor: &str, step: &PlannedStep) -> ApprovalToken {
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

/// 运维审批源：对需确认的 restart 步返回 exact-matching token，consume-once（第二次 None）；
/// 只读步骤返回 None（policy 对 ReadOnly 直接放行，无需 token）。
struct OperatorApprovals {
    actor: String,
    approve_restart: bool,
    used: Cell<bool>,
}

impl ApprovalSource for OperatorApprovals {
    fn token_for(&self, step: &PlannedStep) -> Option<ApprovalToken> {
        if step.risk != StepRisk::ExecuteWithConfirmation {
            return None;
        }
        if !self.approve_restart || self.used.get() {
            return None;
        }
        self.used.set(true);
        Some(exact_token_for(&self.actor, step))
    }
}

/// 把 run loop 的一步接到真 `ServiceSupervisor`。policy gate 已在 run_plan 把关，放行后
/// 这里执行真副作用：svc.status=>真 status()；svc.restart[.rollback]=>重构 exact token
/// 后调用真 restart()（token 在 run_plan 已被消费，executor 侧重构一份执行许可）。
struct RecoveryExecutor<'a> {
    actor: String,
    supervisor: RefCell<&'a mut ServiceSupervisor>,
    /// 仅 rollback 用例：在 verify 步前真实地让服务再次挂掉，使 verify 探到 alive=false。
    crash_before_verify: bool,
}

impl StepExecutor for RecoveryExecutor<'_> {
    fn execute(&self, step: &PlannedStep) -> std::io::Result<StepObservation> {
        match step.tool.as_str() {
            "svc.status" => {
                if self.crash_before_verify && step.step_id.starts_with("verify") {
                    self.supervisor.borrow_mut().fail()?;
                }
                let status = self.supervisor.borrow().status()?;
                Ok(StepObservation {
                    outcome: StepOutcome::Confined,
                    detail: format!("alive={} pid={}", status.alive, status.pid),
                })
            }
            "svc.restart" => {
                let token = exact_token_for(&self.actor, step);
                let new_pid = self.supervisor.borrow_mut().restart(token)?;
                Ok(StepObservation {
                    outcome: StepOutcome::Confined,
                    detail: format!("restarted pid={new_pid}"),
                })
            }
            "svc.restart.rollback" => {
                let token = exact_token_for(&self.actor, step);
                let pid = self.supervisor.borrow_mut().restart(token)?;
                Ok(StepObservation {
                    outcome: StepOutcome::Confined,
                    detail: format!("rolled-back pid={pid}"),
                })
            }
            other => Ok(StepObservation {
                outcome: StepOutcome::Confined,
                detail: format!("noop tool={other}"),
            }),
        }
    }
}

fn approvals(actor: &str, approve_restart: bool) -> OperatorApprovals {
    OperatorApprovals {
        actor: actor.to_string(),
        approve_restart,
        used: Cell::new(false),
    }
}

/// 无审批 => restart 步 PauseForApproval => RunState::Denied，且服务未被 restart（pid 不变）。
#[test]
fn denied_path_pauses_restart_and_leaves_service_untouched() {
    let mut sup = ServiceSupervisor::new(spec("denied"));
    let started = sup.start().expect("start service");
    assert!(proc_exists(started), "service must be alive after start");

    let gate = approvals("operator", false);
    let plan = vec![restart_step("demo")];
    let mut rt = AgentRuntime::new();
    let state = {
        let exec = RecoveryExecutor {
            actor: "operator".to_string(),
            supervisor: RefCell::new(&mut sup),
            crash_before_verify: false,
        };
        rt.run_plan("operator", &plan, &gate, &exec)
    };

    assert_eq!(state, RunState::Denied, "no approval => PauseForApproval => Denied");
    let after = sup.status().expect("status");
    assert_eq!(after.pid, started, "restart must not execute; pid unchanged");
    assert!(after.alive, "service must remain alive (untouched)");
    // restart 步未执行 => 无 svc.restart 的 EffectObserved。
    assert!(!rt
        .events()
        .iter()
        .any(|e| matches!(e, RunEvent::EffectObserved { tool, .. } if tool == "svc.restart")));

    sup.shutdown().expect("cleanup");
}

/// exact 审批 => restart 真执行 => 新 pid != 旧 pid 且 /proc/new 存活、/proc/old 不存在
/// => RunState::Completed。
#[test]
fn approved_path_executes_real_restart_with_fresh_live_pid() {
    let mut sup = ServiceSupervisor::new(spec("approved"));
    let old = sup.start().expect("start service");
    assert!(proc_exists(old));

    let gate = approvals("operator", true);
    let plan = vec![restart_step("demo")];
    let mut rt = AgentRuntime::new();
    let state = {
        let exec = RecoveryExecutor {
            actor: "operator".to_string(),
            supervisor: RefCell::new(&mut sup),
            crash_before_verify: false,
        };
        rt.run_plan("operator", &plan, &gate, &exec)
    };

    assert_eq!(state, RunState::Completed);
    let new = sup.current_pid().expect("new pid");
    assert_ne!(new, old, "restart must produce a fresh pid");
    assert!(proc_exists(new), "new instance must be alive");
    assert!(!proc_exists(old), "old instance must be reaped (/proc/old gone)");
    assert!(
        rt.events()
            .iter()
            .any(|e| matches!(e, RunEvent::ApprovalBound { .. })),
        "exact token must bind to parameters"
    );
    assert!(
        rt.events()
            .iter()
            .any(|e| matches!(e, RunEvent::EffectObserved { tool, .. } if tool == "svc.restart")),
        "restart effect must be observed"
    );

    sup.shutdown().expect("cleanup");
}

/// 完整恢复：start 真服务 -> fail()（SIGKILL）-> 多步 plan：svc.status(诊断 alive=false)
/// -> svc.restart(审批门) -> svc.status(verify alive=true) -> Completed，审计日志可 rehydrate。
#[test]
fn full_recovery_diagnoses_restarts_and_verifies_healthy() {
    let mut sup = ServiceSupervisor::new(spec("full"));
    let crashed = sup.start().expect("start service");
    sup.fail().expect("simulate crash via SIGKILL");
    assert!(!proc_exists(crashed), "after fail() the crashed instance is reaped");

    let gate = approvals("operator", true);
    let plan = vec![
        status_step("diagnose-status", "demo"),
        restart_step("demo"),
        status_step("verify-status", "demo"),
    ];
    let mut rt = AgentRuntime::new();
    let state = {
        let exec = RecoveryExecutor {
            actor: "operator".to_string(),
            supervisor: RefCell::new(&mut sup),
            crash_before_verify: false,
        };
        rt.run_plan("operator", &plan, &gate, &exec)
    };

    assert_eq!(state, RunState::Completed);
    let recovered = sup.current_pid().expect("recovered pid");
    assert!(proc_exists(recovered), "service must be healthy after recovery");
    assert_ne!(recovered, crashed, "recovered instance is a fresh process");

    // 审计日志可纯 replay 重建到同一终态（durability）。
    assert_eq!(AgentRuntime::rehydrate(rt.events()), RunState::Completed);

    // 诊断步真实探到 alive=false（崩溃），verify 步真实探到 alive=true（恢复）。
    let observed = |step: &str| -> Option<String> {
        rt.events().iter().find_map(|e| match e {
            RunEvent::EffectObserved { step_id, detail, .. } if step_id == step => {
                Some(detail.clone())
            }
            _ => None,
        })
    };
    assert!(
        observed("diagnose-status")
            .expect("diagnose observed")
            .contains("alive=false"),
        "diagnose must observe the crashed service"
    );
    assert!(
        observed("verify-status")
            .expect("verify observed")
            .contains("alive=true"),
        "verify must observe the recovered service"
    );

    sup.shutdown().expect("cleanup");
}

/// rollback：verify 仍 alive=false => RollbackTriggered + RunRolledBack => RunState::RolledBack。
#[test]
fn rollback_path_triggers_when_verify_still_unhealthy() {
    let mut sup = ServiceSupervisor::new(spec("rollback"));
    sup.start().expect("start service");

    let gate = approvals("operator", true);
    let plan = vec![restart_step("demo"), status_step("verify-status", "demo")];
    let mut rt = AgentRuntime::new();
    let state = {
        let exec = RecoveryExecutor {
            actor: "operator".to_string(),
            supervisor: RefCell::new(&mut sup),
            crash_before_verify: true,
        };
        rt.run_plan("operator", &plan, &gate, &exec)
    };

    assert_eq!(state, RunState::RolledBack);
    assert!(rt
        .events()
        .iter()
        .any(|e| matches!(e, RunEvent::RollbackTriggered { .. })));
    assert!(rt.events().iter().any(|e| matches!(e, RunEvent::RunRolledBack)));
    assert_eq!(AgentRuntime::rehydrate(rt.events()), RunState::RolledBack);
    // 回滚后服务被恢复为一个新的就绪实例。
    assert!(proc_exists(sup.current_pid().expect("post-rollback pid")));

    sup.shutdown().expect("cleanup");
}

/// 差分 oracle：冻结 `AgentCoreServiceRecovery`（nginx，Approved/Denied）的决策形状
/// （restart_executed 仅 Approved 为真）与真实 run_plan 的 Allow/PauseForApproval 形状同形。
#[test]
fn differential_oracle_matches_real_run_plan_shapes() {
    use agent_core::service_recovery::{AgentCoreServiceRecovery, AgentRestartApproval};
    use security_execution::audit::AuditJournal;

    let root = std::env::temp_dir().join(format!("aios-svc-oracle-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("oracle root");

    // 冻结 oracle：service="nginx"，Approved 与 Denied 各跑一次（单独临时 journal）。
    let approved = AgentCoreServiceRecovery
        .run_with_root(
            &AuditJournal::new(root.join("approved.jsonl")),
            root.join("approved.runs"),
            "req-approved",
            "nginx",
            AgentRestartApproval::Approved,
        )
        .expect("oracle approved");
    let denied = AgentCoreServiceRecovery
        .run_with_root(
            &AuditJournal::new(root.join("denied.jsonl")),
            root.join("denied.runs"),
            "req-denied",
            "nginx",
            AgentRestartApproval::Denied,
        )
        .expect("oracle denied");

    assert!(approved.restart_executed, "oracle: Approved executes restart");
    assert!(!denied.restart_executed, "oracle: Denied prepares no restart");

    // 真实 run_plan（真服务 sleeper）：Approved=>Allow=>真 restart；Denied=>PauseForApproval=>不执行。
    let real_restart_executed = |approve: bool, name: &str| -> bool {
        let mut sup = ServiceSupervisor::new(spec(name));
        sup.start().expect("start service");
        let gate = approvals("operator", approve);
        let plan = vec![restart_step("demo")];
        let mut rt = AgentRuntime::new();
        {
            let exec = RecoveryExecutor {
                actor: "operator".to_string(),
                supervisor: RefCell::new(&mut sup),
                crash_before_verify: false,
            };
            rt.run_plan("operator", &plan, &gate, &exec);
        }
        let executed = rt
            .events()
            .iter()
            .any(|e| matches!(e, RunEvent::EffectObserved { tool, .. } if tool == "svc.restart"));
        sup.shutdown().expect("cleanup");
        executed
    };

    let real_approved = real_restart_executed(true, "oracle-real-approved");
    let real_denied = real_restart_executed(false, "oracle-real-denied");

    // 同形：真实路径与冻结决策形状逐一一致（restart 仅 Approved 真执行）。
    assert_eq!(real_approved, approved.restart_executed, "approved shape matches oracle");
    assert_eq!(real_denied, denied.restart_executed, "denied shape matches oracle");
    assert!(real_approved && !real_denied, "restart executed only when approved");

    let _ = std::fs::remove_dir_all(&root);
}
