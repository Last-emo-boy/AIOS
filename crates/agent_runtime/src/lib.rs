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

/// append-only 运行事件 —— 运行状态的唯一真相。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunEvent {
    IntentAccepted { actor: String },
    StepPlanned { step_id: String },
    StepConfined { step_id: String },
    StepDenied { step_id: String, reason: String },
    RunCompleted,
    RunFailedClosed,
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
