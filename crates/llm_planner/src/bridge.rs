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
    /// cp-llm 阶段 N：LLM 提议的步骤依赖引用不存在的 step（索引越界或 tool 名不匹配）。
    DagMissingDep {
        step_index: usize,
        dep: String,
    },
    /// cp-llm 阶段 N：LLM 提议的步骤依赖含循环（无法生成拓扑序）。
    DagCycle {
        step_index: usize,
        cycle: String,
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
            BridgeError::DagMissingDep { step_index, dep } => write!(
                formatter,
                "dag missing dependency at step-{step_index}: \"{dep}\" not found"
            ),
            BridgeError::DagCycle { step_index, cycle } => write!(
                formatter,
                "dag cycle detected at step-{step_index}: {cycle}"
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

    // cp-llm 阶段 N：DAG 验证 + 权威拓扑排序。
    // 若任一步声明了 depends_on，验证引用存在性、无循环，生成权威拓扑序。
    // LLM 只提议依赖（intention）；拓扑排序由 host 裁决（reality）。
    // 无任何 depends_on → 原序（向后兼容）。
    if raw.steps.iter().any(|s| !s.depends_on.is_empty()) {
        plan = topo_sort(raw, plan)?;
    }

    Ok(plan)
}

/// cp-llm 阶段 N：验证 `depends_on` 引用并生成拓扑序。
///
/// `depends_on` 元素可以是 step 索引（"0", "1"）或 tool 名（"svc.status"）。
/// 先把每个 dep 解析成原始 step 索引，再 Kahn 拓扑排序。引用不存在或循环 → fail-closed。
fn topo_sort(raw: &RawPlan, plan: Vec<PlannedStep>) -> Result<Vec<PlannedStep>, BridgeError> {
    let n = raw.steps.len();
    // 解析依赖（与 dag_levels 共用 resolve_deps，保证一致性）。
    let deps = resolve_deps(raw)?;

    // Kahn 算法：计算入度，从入度 0 的节点开始。
    // in_degree[i] = deps[i].len()（i 依赖的 step 数）
    let mut in_degree: Vec<usize> = deps.iter().map(|d| d.len()).collect();

    let mut queue: std::collections::VecDeque<usize> = (0..n).filter(|&i| in_degree[i] == 0).collect();
    let mut order: Vec<usize> = Vec::with_capacity(n);
    // 保持原始序的稳定性：queue 初始按原始序入队。
    while let Some(i) = queue.pop_front() {
        order.push(i);
        // 对所有依赖 i 的 step j，in_degree[j] -= 1；若归零则入队。
        for j in 0..n {
            if deps[j].contains(&i) {
                in_degree[j] -= 1;
                if in_degree[j] == 0 {
                    queue.push_back(j);
                }
            }
        }
    }

    if order.len() != n {
        // 存在循环：找出未入序的节点。
        let remaining: Vec<String> = (0..n)
            .filter(|i| !order.contains(i))
            .map(|i| format!("step-{i}({})", raw.steps[i].tool))
            .collect();
        return Err(BridgeError::DagCycle {
            step_index: order.len(),
            cycle: remaining.join(" -> "),
        });
    }

    // 按拓扑序重排 plan（step_id 保持原索引语义：step-{i} 对应 raw.steps[i]）。
    let mut sorted = Vec::with_capacity(n);
    for &i in &order {
        sorted.push(plan[i].clone());
    }
    Ok(sorted)
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

/// cp-llm 阶段 Q：计算每步的拓扑层级（advisory，仅供上层决定哪些步可并行）。
///
/// 层级语义：根步（无依赖）= 层 0；其余步 = `max(依赖步层级) + 1`。同层步互不依赖，
/// 理论上可并行执行。**本函数不改变 plan 顺序，也不参与裁决**——执行序仍由
/// `topo_sort` 的权威拓扑序决定；层级只是 advisory 元数据，供未来并行调度器使用。
///
/// 依赖解析与 `topo_sort` 同形：dep 元素是 step 索引（"0"）或 tool 名。引用缺失/循环 →
/// `Err`（fail-closed，与 `topo_sort` 一致）。
pub fn dag_levels(raw: &RawPlan) -> Result<Vec<u32>, BridgeError> {
    let n = raw.steps.len();
    let deps = resolve_deps(raw)?;
    // Kahn 同时计算层级与循环检测：根步（无依赖）= 层 0；其余步 = max(依赖层级) + 1。
    let mut level = vec![0u32; n];
    let mut in_degree: Vec<usize> = deps.iter().map(|d| d.len()).collect();
    let mut queue: std::collections::VecDeque<usize> =
        (0..n).filter(|&i| in_degree[i] == 0).collect();
    let mut processed = 0usize;
    while let Some(i) = queue.pop_front() {
        processed += 1;
        for j in 0..n {
            if deps[j].contains(&i) {
                // j 依赖 i，j 的层级至少为 level[i] + 1。
                if level[i] + 1 > level[j] {
                    level[j] = level[i] + 1;
                }
                in_degree[j] -= 1;
                if in_degree[j] == 0 {
                    queue.push_back(j);
                }
            }
        }
    }
    if processed != n {
        // 循环：列出未入序的节点（与 topo_sort 的报错同形）。
        let remaining: Vec<String> = (0..n)
            .filter(|i| in_degree[*i] > 0)
            .map(|i| format!("step-{i}({})", raw.steps[i].tool))
            .collect();
        return Err(BridgeError::DagCycle {
            step_index: processed,
            cycle: remaining.join(" -> "),
        });
    }
    Ok(level)
}

/// 解析 `raw.steps` 的 depends_on 为索引集合（与 `topo_sort` 同形逻辑，抽出复用）。
fn resolve_deps(raw: &RawPlan) -> Result<Vec<Vec<usize>>, BridgeError> {
    let n = raw.steps.len();
    let mut deps: Vec<Vec<usize>> = Vec::with_capacity(n);
    for (i, step) in raw.steps.iter().enumerate() {
        let mut resolved = Vec::new();
        for dep in &step.depends_on {
            if let Ok(idx) = dep.parse::<usize>() {
                if idx < n {
                    resolved.push(idx);
                    continue;
                }
            }
            if let Some(idx) = raw.steps.iter().position(|s| s.tool == *dep) {
                resolved.push(idx);
                continue;
            }
            return Err(BridgeError::DagMissingDep {
                step_index: i,
                dep: dep.clone(),
            });
        }
        if resolved.contains(&i) {
            return Err(BridgeError::DagCycle {
                step_index: i,
                cycle: format!("step-{i} depends on itself"),
            });
        }
        deps.push(resolved);
    }
    Ok(deps)
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
                depends_on: vec![],
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

    // ===== cp-llm 阶段 N：PlanDAG 测试 =====

    /// 无 depends_on → 原序（向后兼容）。
    #[test]
    fn dag_empty_deps_preserves_order() {
        let plan = bridge_plan(&raw_plan(
            r#"{"steps":[{"tool":"svc.status","params":{"service":"a"}},{"tool":"svc.status","params":{"service":"b"}}]}"#,
            vec![
                step("svc.status", &[("service", "a")], None),
                step("svc.status", &[("service", "b")], None),
            ],
        ))
        .expect("no deps");
        assert_eq!(plan[0].resource, "a");
        assert_eq!(plan[1].resource, "b");
    }

    /// 有效依赖 → 拓扑排序（step 1 依赖 step 0 → order 不变）。
    #[test]
    fn dag_valid_dependency_preserves_order() {
        let s0 = step("svc.status", &[("service", "a")], None);
        let mut s1 = step("svc.status", &[("service", "b")], None);
        s1.depends_on = vec!["0".to_string()];
        let plan = bridge_plan(&RawPlan {
            provider: "stub".to_string(),
            model: "m".to_string(),
            raw_json: r#"{"steps":[{"tool":"svc.status","params":{"service":"a"}},{"tool":"svc.status","params":{"service":"b"},"depends_on":["0"]}]}"#.to_string(),
            http_status: 200,
            steps: vec![s0, s1],
        })
        .expect("valid dag");
        assert_eq!(plan[0].resource, "a");
        assert_eq!(plan[1].resource, "b");
    }

    /// 依赖反序 → 拓扑排序把依赖项排前。
    #[test]
    fn dag_reorders_when_dependency_is_later() {
        // step 0 依赖 step 1 → 拓扑序应为 [1, 0]。
        let mut s0 = step("svc.logs", &[("service", "a")], None);
        let s1 = step("svc.status", &[("service", "a")], None);
        s0.depends_on = vec!["svc.status".to_string()];
        let plan = bridge_plan(&RawPlan {
            provider: "stub".to_string(),
            model: "m".to_string(),
            raw_json: r#"{"steps":[{"tool":"svc.logs","params":{"service":"a"},"depends_on":["svc.status"]},{"tool":"svc.status","params":{"service":"a"}}]}"#.to_string(),
            http_status: 200,
            steps: vec![s0, s1],
        })
        .expect("reordered");
        assert_eq!(plan[0].tool, "svc.status");
        assert_eq!(plan[1].tool, "svc.logs");
    }

    /// 缺失依赖 → fail-closed。
    #[test]
    fn dag_missing_dependency_fail_closed() {
        let mut s0 = step("svc.status", &[("service", "a")], None);
        s0.depends_on = vec!["99".to_string()]; // 不存在的索引
        let result = bridge_plan(&RawPlan {
            provider: "stub".to_string(),
            model: "m".to_string(),
            raw_json: r#"{"steps":[{"tool":"svc.status","params":{"service":"a"},"depends_on":["99"]}]}"#.to_string(),
            http_status: 200,
            steps: vec![s0],
        });
        assert!(matches!(result, Err(BridgeError::DagMissingDep { dep, .. }) if dep == "99"));
    }

    /// 循环依赖 → fail-closed。
    #[test]
    fn dag_cycle_fail_closed() {
        let mut s0 = step("svc.status", &[("service", "a")], None);
        let mut s1 = step("svc.logs", &[("service", "a")], None);
        s0.depends_on = vec!["1".to_string()];
        s1.depends_on = vec!["0".to_string()];
        let result = bridge_plan(&RawPlan {
            provider: "stub".to_string(),
            model: "m".to_string(),
            raw_json: r#"{"steps":[{"tool":"svc.status","params":{"service":"a"},"depends_on":["1"]},{"tool":"svc.logs","params":{"service":"a"},"depends_on":["0"]}]}"#.to_string(),
            http_status: 200,
            steps: vec![s0, s1],
        });
        assert!(matches!(result, Err(BridgeError::DagCycle { .. })));
    }

    // ===== 阶段 Q：dag_levels =====

    #[test]
    fn dag_levels_all_root_when_no_deps() {
        let s0 = step("svc.status", &[("service", "a")], None);
        let s1 = step("svc.logs", &[("service", "a")], None);
        let raw = raw_plan(
            r#"{"steps":[{"tool":"svc.status","params":{"service":"a"}},{"tool":"svc.logs","params":{"service":"a"}}]}"#,
            vec![s0, s1],
        );
        let levels = dag_levels(&raw).expect("levels");
        assert_eq!(levels, vec![0, 0]);
    }

    #[test]
    fn dag_levels_chain_increments() {
        let mut s0 = step("svc.status", &[("service", "a")], None);
        let mut s1 = step("svc.logs", &[("service", "a")], None);
        let mut s2 = step("fs.read", &[("path", "/etc/hosts")], None);
        s0.depends_on = vec![];
        s1.depends_on = vec!["0".to_string()];
        s2.depends_on = vec!["1".to_string()];
        let raw = raw_plan("{}", vec![s0, s1, s2]);
        let levels = dag_levels(&raw).expect("levels");
        assert_eq!(levels, vec![0, 1, 2]);
    }

    #[test]
    fn dag_levels_parallel_siblings_same_level() {
        // s0, s1 = 根层 0；s2 依赖两者 → 层 1；s3 依赖 s2 → 层 2。
        let s0 = step("svc.status", &[("service", "a")], None);
        let s1 = step("svc.logs", &[("service", "a")], None);
        let mut s2 = step("fs.read", &[("path", "/x")], None);
        s2.depends_on = vec!["0".to_string(), "1".to_string()];
        let mut s3 = step("fs.write.diff", &[("path", "/y")], None);
        s3.depends_on = vec!["2".to_string()];
        let raw = raw_plan("{}", vec![s0, s1, s2, s3]);
        let levels = dag_levels(&raw).expect("levels");
        assert_eq!(levels, vec![0, 0, 1, 2]);
    }

    #[test]
    fn dag_levels_cycle_fail_closed() {
        let mut s0 = step("svc.status", &[("service", "a")], None);
        let mut s1 = step("svc.logs", &[("service", "a")], None);
        s0.depends_on = vec!["1".to_string()];
        s1.depends_on = vec!["0".to_string()];
        let raw = raw_plan("{}", vec![s0, s1]);
        assert!(matches!(dag_levels(&raw), Err(BridgeError::DagCycle { .. })));
    }

    #[test]
    fn dag_levels_missing_dep_fail_closed() {
        let mut s0 = step("svc.status", &[("service", "a")], None);
        s0.depends_on = vec!["99".to_string()]; // 不存在的索引
        let raw = raw_plan("{}", vec![s0]);
        assert!(matches!(dag_levels(&raw), Err(BridgeError::DagMissingDep { .. })));
    }
}
