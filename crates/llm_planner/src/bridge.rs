//! bridge —— `RawPlan` → `Vec<PlannedStep>` 经**冻结** `ToolRouter`（接入点核心）。
//!
//! 三道不可信内容防线，全部委托冻结 oracle，桥接层不自造裁决：
//! 1. **secret-reflux 门**（order8）：解析前对整个 `raw_json` 跑
//!    `SecretRuntimePolicy::inspect_boundary(PlannerOutput, ..)`——防 LLM 把 API key
//!    回灌进 plan（`ForbiddenRawSecret` → fail-closed）。
//! 2. **逐参 secret 净化**（order7a）：任一 param 经 `contains_secret_value`==true → 丢弃整
//!    plan（明文 secret 不得入计划；仅 `secret://` handle 通过）。
//! 3. **权威路由**（order7b/c/d）：`ToolRouter::route` 给权威 `RoutedToolCall`（shell.exec
//!    硬拒 / 未知 tool 拒 / 缺参拒）；`claimed_risk` 仅 advisory，风险**永远**取自 ToolRouter。

use agent_runtime::{PlannedStep, StepProvenance, StepRisk};
use runtime_contracts::{contains_secret_value, SemanticToolCall};
use security_execution::secret_runtime::{SecretRuntimePolicy, SecretSurface};
use security_execution::source_to_sink::ContentSource;
use security_execution::tools::ToolRouter;

use crate::RawPlan;

/// 桥接失败（全部 fail-closed）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeError {
    /// LLM 把明文 secret 回灌进 plan（reflux 门拦下）。
    SecretReflux { reason: String },
    /// 某步某 param 含明文 secret（净化门拦下）。
    SecretInParam { step_index: usize, param: String },
    /// 冻结 `ToolRouter` 拒绝该步（shell.exec/未知 tool/缺参/多余参 = 幻觉/越权）。
    ToolRejected {
        step_index: usize,
        tool: String,
        reason: String,
    },
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BridgeError::SecretReflux { reason } => {
                write!(formatter, "secret reflux blocked: {reason}")
            }
            BridgeError::SecretInParam { step_index, param } => write!(
                formatter,
                "plaintext secret in step-{step_index} param \"{param}\""
            ),
            BridgeError::ToolRejected {
                step_index,
                tool,
                reason,
            } => write!(
                formatter,
                "tool rejected at step-{step_index} ({tool}): {reason}"
            ),
        }
    }
}

impl std::error::Error for BridgeError {}

/// 把不可信 `RawPlan` 桥接成权威 `Vec<PlannedStep>`。`step_id="step-{i}"` 由**我们**赋
/// （不让 LLM 控制，防 parameter_hash 碰撞）；`params` 用 `ToolRouter` 规范化后的
/// （已排序 → 稳定 `stable_parameter_hash`）；`risk` 一律来自冻结 `RoutedToolCall.risk`。
pub fn bridge_plan(raw: &RawPlan) -> Result<Vec<PlannedStep>, BridgeError> {
    // (order8) secret-reflux 门：解析/路由前先看整个不可信 blob 是否夹带明文 secret。
    if let Err(error) = SecretRuntimePolicy::inspect_boundary(SecretSurface::PlannerOutput, &raw.raw_json)
    {
        return Err(BridgeError::SecretReflux {
            reason: error.to_string(),
        });
    }

    let router = ToolRouter;
    let mut plan = Vec::with_capacity(raw.steps.len());
    for (index, step) in raw.steps.iter().enumerate() {
        // (order7a) 逐参净化：明文 secret → fail-closed（secret:// handle 放行）。
        for (key, value) in &step.params {
            if contains_secret_value(value) {
                return Err(BridgeError::SecretInParam {
                    step_index: index,
                    param: key.clone(),
                });
            }
        }

        // (order7b) 权威路由：冻结 ToolRouter 给 RoutedToolCall（含权威 RiskClass）。
        let call = SemanticToolCall {
            name: step.tool.clone(),
            params: step.params.clone(),
        };
        let routed = router.route(&call).map_err(|rejection| BridgeError::ToolRejected {
            step_index: index,
            tool: rejection.tool,
            reason: rejection.reason,
        })?;

        // (order7c) claimed_risk 仅 advisory：此处刻意忽略，风险只来自 routed.risk。
        // (order7d) 构造 PlannedStep（step_id 我们赋；params 用规范化已排序结果）。
        plan.push(PlannedStep {
            step_id: format!("step-{index}"),
            tool: routed.tool.to_string(),
            resource: derive_resource(routed.tool, &routed.normalized_params),
            params: routed.normalized_params.clone(),
            risk: StepRisk::from(routed.risk),
        });
    }
    Ok(plan)
}

/// 权威 resource 从规范化参数派生（与冻结 `PolicyRequest::from_routed` 同形：path/service/url
/// 优先，否则退回 tool 名）。
fn derive_resource(tool: &str, params: &[(String, String)]) -> String {
    params
        .iter()
        .find(|(key, _)| key == "path" || key == "service" || key == "url")
        .map(|(_, value)| value.clone())
        .unwrap_or_else(|| tool.to_string())
}

/// LLM 衍生步的溯源：每步返回 `ContentSource::model_output("step-{i}")`（不可信 ModelOutput）。
/// 冻结 source_to_sink 门据此对 model_output → 非 ReadOnly sink 在 capability 绑定前 Denied。
#[derive(Debug, Default, Clone, Copy)]
pub struct ModelProvenance;

impl StepProvenance for ModelProvenance {
    fn content_source(&self, step: &PlannedStep) -> Option<ContentSource> {
        // step_id 不含 secret（我们赋的 "step-{i}"），故 model_output 构造不会失败。
        ContentSource::model_output(step.step_id.clone()).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RawPlan, RawStep};

    fn raw_plan(raw_json: &str, steps: Vec<RawStep>) -> RawPlan {
        RawPlan {
            provider: "stub".to_string(),
            model: "stub".to_string(),
            raw_json: raw_json.to_string(),
            http_status: 200,
            steps,
        }
    }

    fn step(tool: &str, params: &[(&str, &str)], claimed_risk: Option<&str>) -> RawStep {
        RawStep {
            tool: tool.to_string(),
            params: params
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
            claimed_risk: claimed_risk.map(|risk| risk.to_string()),
            text: String::new(),
        }
    }

    #[test]
    fn benign_read_only_step_routes() {
        let plan = bridge_plan(&raw_plan(
            "{\"steps\":[{\"tool\":\"svc.status\",\"params\":{\"service\":\"nginx\"}}]}",
            vec![step("svc.status", &[("service", "nginx")], None)],
        ))
        .expect("benign routes");
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].step_id, "step-0");
        assert_eq!(plan[0].tool, "svc.status");
        assert_eq!(plan[0].resource, "nginx");
        assert_eq!(plan[0].risk, StepRisk::ReadOnly);
    }

    #[test]
    fn shell_exec_is_rejected_by_frozen_router() {
        let error = bridge_plan(&raw_plan(
            "{\"steps\":[{\"tool\":\"shell.exec\",\"params\":{\"cmd\":\"id\"}}]}",
            vec![step("shell.exec", &[("cmd", "id")], None)],
        ))
        .expect_err("shell denied");
        assert!(matches!(error, BridgeError::ToolRejected { .. }));
    }

    #[test]
    fn claimed_risk_cannot_downgrade_authoritative_risk() {
        // LLM 谎报 svc.restart 是 read-only —— 桥接层必须以权威 ExecuteWithConfirmation 为准。
        let plan = bridge_plan(&raw_plan(
            "{\"steps\":[{\"tool\":\"svc.restart\",\"params\":{\"service\":\"nginx\"},\"risk\":\"read-only\"}]}",
            vec![step("svc.restart", &[("service", "nginx")], Some("read-only"))],
        ))
        .expect("svc.restart routes");
        assert_eq!(plan[0].risk, StepRisk::ExecuteWithConfirmation);
    }

    #[test]
    fn write_with_diff_maps_without_downgrade() {
        let plan = bridge_plan(&raw_plan(
            "{\"steps\":[{\"tool\":\"fs.write.diff\",\"params\":{\"path\":\"/etc/x\",\"content_hash\":\"abc\"}}]}",
            vec![step(
                "fs.write.diff",
                &[("path", "/etc/x"), ("content_hash", "abc")],
                None,
            )],
        ))
        .expect("fs.write.diff routes");
        assert_eq!(plan[0].risk, StepRisk::WriteWithDiff);
    }

    #[test]
    fn plaintext_secret_param_is_fail_closed() {
        let error = bridge_plan(&raw_plan(
            "{\"steps\":[{\"tool\":\"svc.status\",\"params\":{\"service\":\"password=hunter2\"}}]}",
            vec![step("svc.status", &[("service", "password=hunter2")], None)],
        ))
        .expect_err("secret fail-closed");
        // reflux 门先于逐参门触发（两者都 fail-closed）。
        assert!(matches!(
            error,
            BridgeError::SecretReflux { .. } | BridgeError::SecretInParam { .. }
        ));
    }

    #[test]
    fn secret_handle_param_passes() {
        let plan = bridge_plan(&raw_plan(
            "{\"steps\":[{\"tool\":\"svc.status\",\"params\":{\"service\":\"secret://vault/db\"}}]}",
            vec![step("svc.status", &[("service", "secret://vault/db")], None)],
        ))
        .expect("handle passes");
        assert_eq!(plan[0].params[0].1, "secret://vault/db");
    }
}
