//! agent_runtime —— 真实、未模拟的编排运行循环（ADR-004 D2 / cp3）。
//!
//! 本 crate 取代冻结的 `agent_core::run_loop::AgentCore` 与
//! `agentd::lifecycle::Agentd`（二者保留为只读差分 oracle）。它承担：
//! 意图接收 → PlanSpec → 调度 → 经 SecurityExecution 强制执行 → 观察 → 封存，
//! 由 `agentd_init`（PID1）fork 出的受监督子进程托管。
#![forbid(unsafe_code)]

/// 运行循环生命周期状态（替代冻结的 lifecycle::Agentd 四态 + run_loop 状态机）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunState {
    Idle,
    Planning,
    AwaitingApproval,
    Executing,
    Observing,
    Verifying,
    Completed,
    Denied,
    RollbackPending,
    Recovering,
    FailedClosed,
}

/// 真实运行循环骨架。cp3 填充 accept_intent / plan / advance / approve / recover，
/// 全部经由 security_execution_linux 强制执行，状态从 append-only 审计日志重建。
#[derive(Debug, Default)]
pub struct AgentRuntime {
    // TODO(cp3): run store、audit journal、scheduler、policy adapter 接线。
}

impl AgentRuntime {
    pub fn new() -> Self {
        Self::default()
    }

    /// 当前状态。骨架阶段恒为 Idle。
    pub fn state(&self) -> RunState {
        RunState::Idle
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skeleton_starts_idle() {
        assert_eq!(AgentRuntime::new().state(), RunState::Idle);
    }
}
