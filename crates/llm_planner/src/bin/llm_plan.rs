//! llm_plan —— 阶段 A+B+C 端到端演示 host 入口（无 appliance/egress/secret 物化，那是 D）。
//!
//! 流程：provider（有 key 则真 Claude/OpenAI，否则 RecordedProvider 罐装信封，无网无 key）
//! → `bridge_plan`（经冻结 ToolRouter，权威风险）→ `run_plan_guarded`（ModelProvenance =
//! 每步 model_output，经冻结 source_to_sink → PolicyEvaluator → exec）。LLM 自主驱动的
//! 非 ReadOnly 步会被 source_to_sink 门 Denied（符合设计意图：危险步须算子重规划）。
//!
//! 阶段 C：当同时配置 `ANTHROPIC_API_KEY` 与 `OPENAI_API_KEY` 时，构造 `ProviderChain`
//! fallback 链（首选 Anthropic，OpenAI 兜底）+ 默认重试策略；任一可用 key 单独配置时退
//! 回单 provider；均无 key 时用 `RecordedProvider`（仍流经真控制面）。
//!
//! 也作 musl 静态构建产物，验证 webpki-roots TLS 栈纯 Rust 静态链。
#![forbid(unsafe_code)]

use agent_runtime::AgentRuntime;
use llm_planner::bridge::ModelProvenance;
use llm_planner::runner::{OperatorApprovals, StubExecutor};
use llm_planner::{
    bridge_plan, ClaudeProvider, LlmProvider, OpenAiCompatProvider, ProviderChain, RecordedProvider,
    RetryPolicy,
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
            RetryPolicy::default(),
        )),
        (Some(key), None) => Box::new(ClaudeProvider::from_env(key)),
        (None, Some(key)) => Box::new(OpenAiCompatProvider::from_env(key)),
        (None, None) => Box::new(RecordedProvider::anthropic("claude-opus-4-8", RECORDED_ANTHROPIC)),
    };

    let raw = match provider.plan(&intent) {
        Ok(raw) => raw,
        Err(error) => {
            eprintln!("provider error (fail-closed): {error}");
            std::process::exit(2);
        }
    };
    println!(
        "RAW_PLAN provider={} model={} http_status={} steps={}",
        raw.provider,
        raw.model,
        raw.http_status,
        raw.steps.len()
    );

    let plan = match bridge_plan(&raw) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("bridge rejected untrusted plan (fail-closed): {error}");
            std::process::exit(3);
        }
    };
    for step in &plan {
        println!(
            "PLANNED step_id={} tool={} resource={} risk={}",
            step.step_id,
            step.tool,
            step.resource,
            step.risk.to_risk_class().as_str()
        );
    }

    let journal = AuditJournal::new(
        std::env::temp_dir().join(format!("llm-plan-{}.jsonl", std::process::id())),
    );
    let exec = StubExecutor::new("alive=true pid=1");
    let approvals = OperatorApprovals::new("operator", false);
    let mut runtime = AgentRuntime::new();
    // ModelProvenance：每步 model_output（不可信）。LLM 自主驱动的非 ReadOnly 步将被 s2s 门拦。
    let state = runtime.run_plan_guarded(
        "operator",
        "run-demo",
        &plan,
        &ModelProvenance,
        &approvals,
        &exec,
        &journal,
    );
    println!(
        "RUN state={:?} events={} executed={:?}",
        state,
        runtime.events().len(),
        exec.executed()
    );
}
