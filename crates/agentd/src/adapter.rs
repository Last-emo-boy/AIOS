//! StepExecutor 适配桥接 —— 把 agentd 的真实工具后端 `ToolExecutor` 接到
//! `agent_runtime::StepExecutor`，使 `run_replan_loop` 能驱动 agentd 的真实执行器。
//!
//! **冻结控制平面哲学**：桥接器只做**适配**（`PlannedStep` → `SemanticToolCall` →
//! `ToolRouter::route` 裁决 → `ToolExecutor::execute` → `Effect` → `StepObservation`），
//! 不做裁决。裁决仍由 `run_plan_guarded` 的 policy / source-to-sink / 审批门做。
//!
//! `Effect → StepObservation` 映射遵循 fail-safe：
//! - `prepared && observed`（真实观测到结果）→ `Confined`（含成功与观测到的失败，如读不到文件）。
//! - `prepared && !observed`（工具未实现 / 缺参 / route 拒绝）→ `KernelDenied`——
//!   把「未真实执行」当作内核拒绝，让 `run_plan_guarded` 收束为 `StepDenied`，
//!   绝不谎报成功。
//! - `!prepared`（不应发生，executor 总置 prepared=true）→ `KernelDenied`。
//!
//! route 拒绝也映射为 `KernelDenied`（route 即裁决门，拒绝 = 该步不可执行），
//! 而非 `Err`——`Err` 会让 `run_plan_guarded` 传播异常，违背 fail-closed 收束语义。
#![forbid(unsafe_code)]

use std::io;

use agent_runtime::{PlannedStep, StepExecutor, StepObservation, StepOutcome};
use runtime_contracts::SemanticToolCall;

use crate::executor::ToolExecutor;
use crate::tools::{ToolRejection, ToolRouter};

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
        // 拒绝 → KernelDenied（route 即裁决门，拒绝 = 不可执行），不传播 Err。
        let routed = match self.router.route(&call) {
            Ok(routed) => routed,
            Err(rejection) => {
                return Ok(denied_observation(step, route_rejection_reason(&rejection)));
            }
        };

        // 真实执行（裁决通过后）。
        let effect = self.executor.execute(&routed);
        Ok(effect_to_observation(&effect))
    }
}

/// `Effect → StepObservation`（fail-safe 映射）。
fn effect_to_observation(effect: &crate::api::Effect) -> StepObservation {
    if effect.prepared && effect.observed {
        StepObservation {
            outcome: StepOutcome::Confined,
            detail: effect.summary.clone(),
        }
    } else {
        StepObservation {
            outcome: StepOutcome::KernelDenied {
                reason: if effect.prepared {
                    // prepared 但未观测：工具未实现/缺参 → 视作内核拒绝。
                    format!("not observed: {}", effect.summary)
                } else {
                    "effect not prepared".to_string()
                },
            },
            detail: effect.summary.clone(),
        }
    }
}

/// 构造一个 `KernelDenied` 观测（route 拒绝 / 构造失败时）。
fn denied_observation(step: &PlannedStep, reason: String) -> StepObservation {
    StepObservation {
        outcome: StepOutcome::KernelDenied { reason },
        detail: format!("tool={} denied before exec", step.tool),
    }
}

fn route_rejection_reason(rejection: &ToolRejection) -> String {
    format!("route rejected tool={}: {}", rejection.tool, rejection.reason)
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
    fn bridge_kernel_denied_when_route_rejects_unknown_tool() {
        // 未知工具被 ToolRouter 拒绝 → KernelDenied（不传播 Err）。
        let exec = StdToolExecutor::new();
        let bridge = ToolExecutorBridge::new(&exec);
        let s = step("future.tool", &[]);
        let obs = bridge.execute(&s).expect("execute");
        assert!(
            matches!(obs.outcome, StepOutcome::KernelDenied { .. }),
            "{:?}",
            obs.outcome
        );
    }

    #[test]
    fn bridge_kernel_denied_when_not_observed() {
        // fs.read 缺 path 参数 → effect.observed=false → KernelDenied（fail-safe）。
        let exec = StdToolExecutor::new();
        let bridge = ToolExecutorBridge::new(&exec);
        let s = step("fs.read", &[]);
        let obs = bridge.execute(&s).expect("execute");
        assert!(matches!(obs.outcome, StepOutcome::KernelDenied { .. }));
    }

    #[test]
    fn effect_to_observation_confined_when_prepared_and_observed() {
        let e = Effect {
            prepared: true,
            observed: true,
            tool: "svc.status".to_string(),
            summary: "alive".to_string(),
        };
        let obs = effect_to_observation(&e);
        assert!(matches!(obs.outcome, StepOutcome::Confined));
    }

    #[test]
    fn effect_to_observation_denied_when_not_observed() {
        let e = Effect {
            prepared: true,
            observed: false,
            tool: "x".to_string(),
            summary: "not-implemented".to_string(),
        };
        let obs = effect_to_observation(&e);
        assert!(matches!(obs.outcome, StepOutcome::KernelDenied { .. }));
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
