//! llm_plan —— 阶段 A+B+C+D 端到端演示 host 入口（无 appliance/egress/secret 物化）。
//!
//! 流程：provider（有 key 则真 Claude/OpenAI，否则 RecordedProvider 罐装信封，无网无 key）
//! → `bridge_plan`（经冻结 ToolRouter，权威风险）→ `run_plan_guarded`（ModelProvenance =
//! 每步 model_output，经冻结 source_to_sink → PolicyEvaluator → exec）。LLM 自主驱动的
//! 非 ReadOnly 步会被 source_to_sink 门 Denied（符合设计意图：危险步须算子重规划）。
//!
//! 阶段 C：`ProviderChain` fallback 链（两 key 齐备→链；单 key→单 provider；无 key→录制）。
//!
//! 阶段 D：`run_replan_loop` —— 若首轮未 Completed，把 `EffectObserved`/`StepDenied` 作为
//! 上下文喂回 provider 再 plan，最多 `AIOS_MAX_REPLANS` 次（默认 3）。LLM 仍只产 intention。
//!
//! 也作 musl 静态构建产物，验证 webpki-roots TLS 栈纯 Rust 静态链。
#![forbid(unsafe_code)]

use llm_planner::bridge::ModelProvenance;
use llm_planner::runner::{run_replan_loop, OperatorApprovals, StubExecutor};
use llm_planner::{
    ClaudeProvider, LlmProvider, OpenAiCompatProvider, ProviderChain, RecordedProvider, RetryPolicy,
};
use security_execution::audit::AuditJournal;

const RECORDED_ANTHROPIC: &str = r#"{
    "id": "msg_demo",
    "type": "message",
    "role": "assistant",
    "model": "claude-opus-4-8",
    "stop_reason": "end_turn",
    "content": [
        {"type": "text",
         "text": "{\"steps\":[{\"tool\":\"svc.status\",\"resource\":\"nginx\",\"params\":{\"service\":\"nginx\"}}]}"}
    ]
}"#;

fn main() {
    let intent = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "check nginx service health".to_string());

    // provider 选择（阶段 C fallback 链）：
    // - 两 key 均有 → ProviderChain（Anthropic 首选 → OpenAI 兜底）；
    // - 单 key → 单 provider；
    // - 无 key → RecordedProvider（无网无 key，仍流经真控制面）。
    let provider: Box<dyn LlmProvider> = match (
        std::env::var("ANTHROPIC_API_KEY").ok().filter(|k| !k.is_empty()),
        std::env::var("OPENAI_API_KEY").ok().filter(|k| !k.is_empty()),
    ) {
        (Some(anthropic_key), Some(openai_key)) => Box::new(ProviderChain::new(
            vec![
                Box::new(ClaudeProvider::from_env(anthropic_key)),
                Box::new(OpenAiCompatProvider::from_env(openai_key)),
            ],
            retry_policy_from_env(),
        )),
        (Some(key), None) => Box::new(ClaudeProvider::from_env(key)),
        (None, Some(key)) => Box::new(OpenAiCompatProvider::from_env(key)),
        (None, None) => Box::new(RecordedProvider::anthropic("claude-opus-4-8", RECORDED_ANTHROPIC)),
    };

    let journal = AuditJournal::new(
        std::env::temp_dir().join(format!("llm-plan-{}.jsonl", std::process::id())),
    );
    let exec = StubExecutor::new("alive=true pid=1");
    let approvals = OperatorApprovals::new("operator", false);
    let max_replans = std::env::var("AIOS_MAX_REPLANS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(3);
    // ModelProvenance：每步 model_output（不可信）。LLM 自主驱动的非 ReadOnly 步将被 s2s 门拦。
    // 阶段 D：replan loop —— provider→bridge→run_plan_guarded，未完成时把观察喂回 provider
    // 再 plan（每轮仍经冻结 bridge + run_plan_guarded，LLM 只产 intention）。
    let outcome = run_replan_loop(
        provider.as_ref(),
        &intent,
        "operator",
        "run-demo",
        &ModelProvenance,
        &approvals,
        &exec,
        &journal,
        max_replans,
    );
    // 阶段 J：用 ReplanOutcome 辅助方法渲染结局摘要 + trace。
    println!(
        "RUN state={:?} {} executed={:?}",
        outcome.state,
        outcome.summary(),
        exec.executed()
    );
    // 阶段 E：结构化 trace 摘要（每轮 attempt 的 provider/state/cause）。
    println!("{}", outcome.render_trace());
}

/// 从环境变量构造 RetryPolicy（阶段 L）：
/// - `AIOS_BACKOFF_BASE_MS`（缺省 0 = 不 sleep，向后兼容）
/// - `AIOS_BACKOFF_CAP_MS`（缺省 30000 = 30s 封顶）
/// - `AIOS_MAX_RETRIES`（缺省 1）
fn retry_policy_from_env() -> RetryPolicy {
    let max_retries = std::env::var("AIOS_MAX_RETRIES")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(1);
    let base_ms = std::env::var("AIOS_BACKOFF_BASE_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    let cap_ms = std::env::var("AIOS_BACKOFF_CAP_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(30000);
    RetryPolicy {
        max_retries,
        backoff_base_ms: base_ms,
        backoff_cap_ms: cap_ms,
    }
}
