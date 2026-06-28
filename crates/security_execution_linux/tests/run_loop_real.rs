//! cp3 端到端：agent_runtime 真 run loop 驱动一个**真沙箱**步骤（ADR-004 D2/cp3）。
//!
//! `SandboxConfiner` 把 run loop 的一步接到 `LinuxEnforcer::enforce_confined`，在
//! user+mount+pid+net namespace + seccomp 全栈下执行；内核结果决定 run loop 走向
//! Completed 还是 Denied，且状态纯从 append-only 日志重建（durability）。
#![cfg(target_os = "linux")]

use agent_runtime::{AgentRuntime, RunState, StepConfiner, StepOutcome};
use security_execution_linux::{resolve_syscall_name, EnforcementOutcome, LinuxEnforcer};

fn helper() -> &'static str {
    env!("CARGO_BIN_EXE_sandbox_probe")
}

/// 把一步交给完整受限执行器：在沙箱里触发 getpid，由内核决定放行/拒绝。
struct SandboxConfiner {
    allow_csv: String,
}

impl StepConfiner for SandboxConfiner {
    fn confine(&self, _step_id: &str) -> std::io::Result<StepOutcome> {
        match LinuxEnforcer::new().enforce_confined(
            helper(),
            "user,mount,pid,net",
            &self.allow_csv,
            "",
            "getpid",
            "",
        )? {
            EnforcementOutcome::Confined => Ok(StepOutcome::Confined),
            EnforcementOutcome::KernelDenied { reason } => Ok(StepOutcome::KernelDenied { reason }),
        }
    }
}

/// allowlist 含 getpid → 内核放行 → run loop Completed；状态从日志重建一致。
#[test]
fn run_loop_completes_with_real_sandboxed_step() {
    let getpid = resolve_syscall_name("getpid").expect("getpid resolves");
    let confiner = SandboxConfiner {
        allow_csv: getpid.to_string(),
    };
    let mut rt = AgentRuntime::new();
    assert_eq!(
        rt.run_step("operator", "step-1", &confiner),
        RunState::Completed
    );
    assert_eq!(
        AgentRuntime::rehydrate(rt.events()),
        RunState::Completed,
        "run state must rebuild purely from the append-only log"
    );
}

/// allowlist 不含 getpid → 内核 SIGSYS → run loop Denied（真内核决定 run 走向）。
#[test]
fn run_loop_denied_when_kernel_blocks_step() {
    let write_nr = resolve_syscall_name("write").expect("write resolves");
    let confiner = SandboxConfiner {
        allow_csv: write_nr.to_string(), // 非空但不含 getpid
    };
    let mut rt = AgentRuntime::new();
    assert_eq!(
        rt.run_step("operator", "step-1", &confiner),
        RunState::Denied
    );
}
