//! llm_plan —— 阶段 A+B 端到端演示 host 入口（无 appliance/egress/secret 物化，那是 C/D）。
//!
//! 流程：provider（有 key 则真 Claude/OpenAI，否则 RecordedProvider 罐装信封，无网无 key）
//! → `bridge_plan`（经冻结 ToolRouter，权威风险）→ `run_plan_guarded`（ModelProvenance =
//! 每步 model_output，经冻结 source_to_sink → PolicyEvaluator → exec）。LLM 自主驱动的
//! 非 ReadOnly 步会被 source_to_sink 门 Denied（符合设计意图：危险步须算子重规划）。
//!
//! 也作 musl 静态构建产物，验证 webpki-roots TLS 栈纯 Rust 静态链。
#![forbid(unsafe_code)]

use agent_runtime::AgentRuntime;
use llm_planner::bridge::ModelProvenance;
use llm_planner::runner::{OperatorApprovals, StubExecutor};
use llm_planner::{bridge_plan, ClaudeProvider, LlmProvider, OpenAiCompatProvider, RecordedProvider};
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

    // provider 选择：真 key 走真 API；否则录制（仍流经真控制面）。
    let provider: Box<dyn LlmProvider> = if let Ok(key) = std::env::var("ANTHROPIC_API_KEY") {
        Box::new(ClaudeProvider::anthropic(key))
    } else if let Ok(key) = std::env::var("OPENAI_API_KEY") {
        Box::new(OpenAiCompatProvider::openai(key))
    } else {
        Box::new(RecordedProvider::anthropic("claude-opus-4-8", RECORDED_ANTHROPIC))
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
