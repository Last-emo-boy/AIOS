//! StepExecutor 适配桥接 —— 把 agentd 的真实工具后端 `ToolExecutor` 接到
//! `agent_runtime::StepExecutor`，使 `run_replan_loop` 能驱动 agentd 的真实执行器。
//!
//! **冻结控制平面哲学**：桥接器只做**适配**（`PlannedStep` → `SemanticToolCall` →
//! `ToolRouter::route` 裁决 → `ToolExecutor::execute` → `Effect` → `StepObservation`），
//! 不做裁决。裁决仍由 `run_plan_guarded` 的 policy / source-to-sink / 审批门做。
//!
//! `Effect → StepObservation` 映射遵循 fail-safe：只有
//! `prepared && observed && succeeded` 才能成为 `Confined`。工具未实现、route 拒绝、
//! 执行失败或未观测都返回带原因的 `io::Error`，由 runtime 记录 `StepDenied` +
//! `RunFailedClosed`。这些情况没有经过 Linux sandbox，禁止伪装成 `KernelDenied`。
#![forbid(unsafe_code)]

use std::io;

use agent_runtime::{PlannedStep, StepExecutor, StepObservation, StepOutcome};
use runtime_contracts::SemanticToolCall;

use crate::executor::ToolExecutor;
use crate::tools::ToolRouter;

/// 把 agentd 的 `ToolExecutor`（真实后端）适配为 `agent_runtime::StepExecutor`。
///
/// `run_replan_loop` 需要 `&dyn StepExecutor`；本桥接器持有 agentd 的 `ToolExecutor`
/// 引用 + 冻结 `ToolRouter`，在每步把 `PlannedStep` 转成裁决后的 `RoutedToolCall`
/// 交真实后端执行。
pub struct ToolExecutorBridge<'a> {
    router: ToolRouter,
    executor: &'a dyn ToolExecutor,
}

impl<'a> ToolExecutorBridge<'a> {
    pub fn new(executor: &'a dyn ToolExecutor) -> Self {
        Self {
            router: ToolRouter,
            executor,
        }
    }
}

impl StepExecutor for ToolExecutorBridge<'_> {
    fn execute(&self, step: &PlannedStep) -> io::Result<StepObservation> {
        // PlannedStep → SemanticToolCall（参数从 (String,String) 借用为 (&str,&str)）。
        let params: Vec<(&str, &str)> = step
            .params
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let call = SemanticToolCall::new(&step.tool, params);

        // route 裁决（冻结 ToolRouter）：验证工具名/参数 schema/风险。
        let routed = self.router.route(&call).map_err(|rejection| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "tool route denied tool={}: {}",
                    rejection.tool, rejection.reason
                ),
            )
        })?;

        // 真实执行（裁决通过后）。
        let effect = self.executor.execute(&routed);
        effect_to_observation(&effect)
    }
}

/// `Effect → StepObservation`（fail-safe 映射）。
fn effect_to_observation(effect: &crate::api::Effect) -> io::Result<StepObservation> {
    if !effect.prepared {
        return Err(io::Error::other(format!(
            "effect not prepared tool={}",
            effect.tool
        )));
    }
    if !effect.observed {
        return Err(io::Error::other(format!(
            "effect not observed tool={}: {}",
            effect.tool, effect.summary
        )));
    }
    if !effect.succeeded {
        return Err(io::Error::other(format!(
            "tool execution failed tool={}: {}",
            effect.tool, effect.summary
        )));
    }
    Ok(StepObservation {
        outcome: StepOutcome::Confined,
        detail: effect.summary.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::Effect;
    use crate::executor::StdToolExecutor;
    use agent_runtime::{PlannedStep, StepRisk};
    use std::sync::atomic::{AtomicU32, Ordering};

    fn step(tool: &str, params: &[(&str, &str)]) -> PlannedStep {
        PlannedStep {
            step_id: "s1".to_string(),
            tool: tool.to_string(),
            resource: "r".to_string(),
            params: params.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            risk: StepRisk::ReadOnly,
        }
    }

    #[test]
    fn bridge_confined_when_real_read_observes() {
        let path = std::env::temp_dir().join(format!("bridge-{}.txt", std::process::id()));
        std::fs::write(&path, "hello").expect("write");
        let exec = StdToolExecutor::new();
        let bridge = ToolExecutorBridge::new(&exec);
        let s = step("fs.read", &[("path", path.to_str().unwrap())]);
        let obs = bridge.execute(&s).expect("execute");
        assert!(matches!(obs.outcome, StepOutcome::Confined), "{:?}", obs);
        assert!(obs.detail.contains("bytes=5"), "detail: {}", obs.detail);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn bridge_returns_permission_error_when_route_rejects_unknown_tool() {
        let exec = StdToolExecutor::new();
        let bridge = ToolExecutorBridge::new(&exec);
        let s = step("future.tool", &[]);
        let err = bridge.execute(&s).expect_err("unknown tool must fail");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("unknown semantic tool"));
    }

    #[test]
    fn bridge_fails_when_required_param_is_missing() {
        let exec = StdToolExecutor::new();
        let bridge = ToolExecutorBridge::new(&exec);
        let s = step("fs.read", &[]);
        let err = bridge.execute(&s).expect_err("missing param must fail");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn effect_to_observation_confined_when_prepared_and_observed() {
        let e = Effect {
            prepared: true,
            observed: true,
            succeeded: true,
            tool: "svc.status".to_string(),
            summary: "alive".to_string(),
        };
        let obs = effect_to_observation(&e).expect("successful observation");
        assert!(matches!(obs.outcome, StepOutcome::Confined));
    }

    #[test]
    fn effect_to_observation_fails_when_not_observed() {
        let e = Effect {
            prepared: true,
            observed: false,
            succeeded: false,
            tool: "x".to_string(),
            summary: "not-implemented".to_string(),
        };
        let err = effect_to_observation(&e).expect_err("unobserved effect must fail");
        assert!(err.to_string().contains("not observed"));
    }

    #[test]
    fn effect_to_observation_fails_when_operation_failed() {
        let e = Effect {
            prepared: true,
            observed: true,
            succeeded: false,
            tool: "fs.read".to_string(),
            summary: "read failed".to_string(),
        };
        let err = effect_to_observation(&e).expect_err("failed operation must fail");
        assert!(err.to_string().contains("tool execution failed"));
    }

    /// 计数执行器：记录被调用次数，返回固定 Effect。
    #[derive(Debug)]
    struct CountingExec {
        calls: AtomicU32,
    }
    impl ToolExecutor for CountingExec {
        fn execute(&self, call: &crate::tools::RoutedToolCall) -> Effect {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Effect {
                prepared: true,
                observed: true,
                succeeded: true,
                tool: call.tool.to_string(),
                summary: "counted".to_string(),
            }
        }
    }

    #[test]
    fn bridge_delegates_to_real_executor() {
        let exec = CountingExec {
            calls: AtomicU32::new(0),
        };
        let bridge = ToolExecutorBridge::new(&exec);
        let s = step("svc.status", &[("service", "nginx")]);
        let obs = bridge.execute(&s).expect("execute");
        assert!(matches!(obs.outcome, StepOutcome::Confined));
        assert_eq!(exec.calls.load(Ordering::Relaxed), 1, "executor 应被调用一次");
    }
}
