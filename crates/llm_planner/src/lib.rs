//! llm_planner —— 真 LLM 接入 阶段 A+B（ADR-006）。
//!
//! 核心命题：**「LLM 只产 PlannedStep（intention），不直接触达内核；内核机制裁决与执行
//! （reality）」**。本 crate 提供：
//! - 阶段 A：`LlmProvider` provider 抽象（`ClaudeProvider` Anthropic messages /
//!   `OpenAiCompatProvider` OpenAI-compatible chat-completions / `RecordedProvider`
//!   录制信封）→ 统一解析成 `RawPlan`（整体标记为不可信 ModelOutput）。
//! - 阶段 B：`bridge`（`RawPlan` → `Vec<PlannedStep>` 经**冻结** `ToolRouter`，权威风险
//!   绝不取自 LLM 自报）+ `ModelProvenance`（每步 `ContentSource::model_output`）+
//!   secret-reflux 门（`inspect_boundary(PlannerOutput)`）+ `runner`（接冻结
//!   `run_plan_guarded`：source_to_sink → PolicyEvaluator → exec）。
//!
//! 本 crate 不自造任何裁决逻辑——全部委托冻结 oracle 的 pub API。
#![forbid(unsafe_code)]

use std::io;

pub mod anthropic;
pub mod bridge;
pub mod openai;
pub mod runner;

pub use anthropic::ClaudeProvider;
pub use bridge::{bridge_plan, BridgeError, ModelProvenance};
pub use openai::OpenAiCompatProvider;

/// 强制 LLM 只输出单个纯 JSON 对象的系统提示。结构由冻结工具集决定，但**风险绝不信任
/// LLM 自报**（桥接层一律以 `ToolRouter` 的权威 RiskClass 为准）。
pub const SYSTEM_PROMPT: &str = concat!(
    "You are the AIOS planner. Translate the operator intent into tool steps. ",
    "Output ONLY a single JSON object, no prose and no markdown fence:\n",
    "{\"steps\":[{\"tool\":<string>,\"resource\":<string>,\"params\":{<string>:<string>}}]}\n",
    "Every step's \"params\" MUST be a flat object whose keys and values are all strings. ",
    "Use only known AIOS semantic tools (e.g. svc.status, svc.logs, fs.read, http.check, ",
    "svc.restart, fs.write.diff). Never use shell or arbitrary commands. ",
    "Never embed secrets, API keys, tokens or passwords in any field."
);

/// 一个 LLM 提议的原始步骤 —— **不可信内容（ModelOutput）**。`claimed_risk` 仅 advisory，
/// 桥接层绝不据此构造权威风险。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawStep {
    pub tool: String,
    pub params: Vec<(String, String)>,
    /// LLM 自报风险（如有），仅作 advisory 提示，**绝不**用于裁决。
    pub claimed_risk: Option<String>,
    /// LLM 提供的人读资源标签（advisory）；权威 resource 由桥接层据 normalized_params 派生。
    pub text: String,
}

/// 一个 LLM 提议的原始计划。**整体是不可信 ModelOutput**；`raw_json` 是不可信原始文本，
/// 在桥接前经冻结 `inspect_boundary(PlannerOutput)` 防 secret 回流。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawPlan {
    pub provider: String,
    pub model: String,
    /// LLM 实际产出的 plan 文本（不可信原始 blob）。
    pub raw_json: String,
    pub http_status: u16,
    pub steps: Vec<RawStep>,
}

/// provider 抽象：把算子意图变成不可信 `RawPlan`。provider 层只产意图，无任何控制面逻辑。
pub trait LlmProvider {
    fn plan(&self, intent: &str) -> io::Result<RawPlan>;
}

pub(crate) fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

pub(crate) fn parse_json(text: &str) -> io::Result<serde_json::Value> {
    serde_json::from_str(text).map_err(|err| invalid(format!("json parse: {err}")))
}

/// 容忍 LLM 把 JSON 裹进 ```json fence。
fn strip_json_fence(text: &str) -> &str {
    let trimmed = text.trim();
    let without_open = trimmed
        .strip_prefix("```json")
        .or_else(|| trimmed.strip_prefix("```"))
        .unwrap_or(trimmed);
    without_open.trim().trim_end_matches("```").trim()
}

/// 解析 `{"steps":[{tool,resource,params,risk?}]}`。空/缺 steps → fail-closed；params 必须
/// 为 string→string 对象；可选 `risk` → `claimed_risk`（advisory）；可选 `resource` →
/// `text`（advisory）。
pub(crate) fn parse_plan_steps(plan_text: &str) -> io::Result<Vec<RawStep>> {
    let value = parse_json(strip_json_fence(plan_text))?;
    let steps = value
        .get("steps")
        .and_then(|steps| steps.as_array())
        .ok_or_else(|| invalid("plan missing \"steps\" array"))?;
    if steps.is_empty() {
        return Err(invalid("plan has empty \"steps\""));
    }
    let mut out = Vec::with_capacity(steps.len());
    for step in steps {
        let tool = step
            .get("tool")
            .and_then(|tool| tool.as_str())
            .ok_or_else(|| invalid("step missing string \"tool\""))?;
        let mut params = Vec::new();
        if let Some(object) = step.get("params").and_then(|params| params.as_object()) {
            for (key, value) in object {
                let value = value
                    .as_str()
                    .ok_or_else(|| invalid(format!("param \"{key}\" is not a string")))?;
                params.push((key.clone(), value.to_string()));
            }
        }
        let claimed_risk = step
            .get("risk")
            .and_then(|risk| risk.as_str())
            .map(|risk| risk.to_string());
        let text = step
            .get("resource")
            .and_then(|resource| resource.as_str())
            .unwrap_or("")
            .to_string();
        out.push(RawStep {
            tool: tool.to_string(),
            params,
            claimed_risk,
            text,
        });
    }
    Ok(out)
}

/// Anthropic messages 信封 → plan 文本。`stop_reason in {refusal, max_tokens}` → fail-closed
/// （不解析半截 plan）；取 `content[]` 第一个 `type=="text"` 块。
pub(crate) fn anthropic_plan_text(envelope: &str) -> io::Result<String> {
    let value = parse_json(envelope)?;
    if let Some(stop) = value.get("stop_reason").and_then(|stop| stop.as_str()) {
        if stop == "refusal" || stop == "max_tokens" {
            return Err(invalid(format!("anthropic stop_reason={stop} (no half-plan)")));
        }
    }
    let content = value
        .get("content")
        .and_then(|content| content.as_array())
        .ok_or_else(|| invalid("anthropic envelope missing \"content\""))?;
    for block in content {
        if block.get("type").and_then(|kind| kind.as_str()) == Some("text") {
            if let Some(text) = block.get("text").and_then(|text| text.as_str()) {
                return Ok(text.to_string());
            }
        }
    }
    Err(invalid("anthropic envelope has no text block"))
}

/// OpenAI-compatible chat-completions 信封 → plan 文本。`finish_reason=="length"`（截断）→
/// fail-closed；取 `choices[0].message.content`。
pub(crate) fn openai_plan_text(envelope: &str) -> io::Result<String> {
    let value = parse_json(envelope)?;
    let choice = value
        .get("choices")
        .and_then(|choices| choices.as_array())
        .and_then(|choices| choices.first())
        .ok_or_else(|| invalid("openai envelope missing \"choices\""))?;
    if let Some(reason) = choice.get("finish_reason").and_then(|reason| reason.as_str()) {
        if reason == "length" {
            return Err(invalid("openai finish_reason=length (truncated)"));
        }
    }
    let content = choice
        .get("message")
        .and_then(|message| message.get("content"))
        .and_then(|content| content.as_str())
        .ok_or_else(|| invalid("openai envelope missing message.content"))?;
    Ok(content.to_string())
}

/// 共享的 HTTP POST（JSON）。非 2xx 经 `ureq::Error::Status` 读 body → `io::Error`
/// （fail-closed，绝不静默吞）；传输/TLS 失败经 `ureq::Error::Transport` → `io::Error`。
pub(crate) fn post_json(
    agent: &ureq::Agent,
    url: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> io::Result<(u16, String)> {
    let mut request = agent.post(url);
    for (name, value) in headers {
        request = request.set(name, value);
    }
    match request.send_string(body) {
        Ok(response) => {
            let status = response.status();
            let text = response
                .into_string()
                .map_err(|err| io::Error::new(io::ErrorKind::Other, format!("read body: {err}")))?;
            Ok((status, text))
        }
        Err(ureq::Error::Status(code, response)) => {
            let body = response.into_string().unwrap_or_default();
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("http {code}: {body}"),
            ))
        }
        Err(ureq::Error::Transport(transport)) => Err(io::Error::new(
            io::ErrorKind::Other,
            format!("transport: {transport}"),
        )),
    }
}

/// 录制 provider：无网无 key，从录制的 Anthropic/OpenAI 信封解析出 `RawPlan`，但**仍流经真
/// 控制面**（仅网络打桩，非 mock 自欺）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordedFormat {
    Anthropic,
    OpenAi,
}

#[derive(Debug, Clone)]
pub struct RecordedProvider {
    pub provider: String,
    pub model: String,
    pub http_status: u16,
    pub envelope: String,
    pub format: RecordedFormat,
}

impl RecordedProvider {
    pub fn anthropic(model: impl Into<String>, envelope: impl Into<String>) -> Self {
        Self {
            provider: "anthropic".to_string(),
            model: model.into(),
            http_status: 200,
            envelope: envelope.into(),
            format: RecordedFormat::Anthropic,
        }
    }

    pub fn openai(model: impl Into<String>, envelope: impl Into<String>) -> Self {
        Self {
            provider: "openai".to_string(),
            model: model.into(),
            http_status: 200,
            envelope: envelope.into(),
            format: RecordedFormat::OpenAi,
        }
    }
}

impl LlmProvider for RecordedProvider {
    fn plan(&self, _intent: &str) -> io::Result<RawPlan> {
        let plan_text = match self.format {
            RecordedFormat::Anthropic => anthropic_plan_text(&self.envelope)?,
            RecordedFormat::OpenAi => openai_plan_text(&self.envelope)?,
        };
        let steps = parse_plan_steps(&plan_text)?;
        Ok(RawPlan {
            provider: self.provider.clone(),
            model: self.model.clone(),
            raw_json: plan_text,
            http_status: self.http_status,
            steps,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ANTHROPIC_ENVELOPE: &str = r#"{
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "model": "claude-opus-4-8",
        "stop_reason": "end_turn",
        "content": [
            {"type": "text", "text": "{\"steps\":[{\"tool\":\"svc.status\",\"resource\":\"nginx\",\"params\":{\"service\":\"nginx\"}}]}"}
        ]
    }"#;

    const OPENAI_ENVELOPE: &str = r#"{
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "choices": [
            {"index": 0, "finish_reason": "stop",
             "message": {"role": "assistant",
                "content": "{\"steps\":[{\"tool\":\"svc.status\",\"resource\":\"nginx\",\"params\":{\"service\":\"nginx\"}}]}"}}
        ]
    }"#;

    #[test]
    fn recorded_anthropic_envelope_parses_to_raw_plan() {
        let provider = RecordedProvider::anthropic("claude-opus-4-8", ANTHROPIC_ENVELOPE);
        let plan = provider.plan("check nginx").expect("recorded plan");
        assert_eq!(plan.provider, "anthropic");
        assert_eq!(plan.http_status, 200);
        assert_eq!(plan.steps.len(), 1);
        assert_eq!(plan.steps[0].tool, "svc.status");
        assert_eq!(
            plan.steps[0].params,
            vec![("service".to_string(), "nginx".to_string())]
        );
    }

    #[test]
    fn recorded_openai_envelope_parses_to_raw_plan() {
        let provider = RecordedProvider::openai("gpt-4o-mini", OPENAI_ENVELOPE);
        let plan = provider.plan("check nginx").expect("recorded plan");
        assert_eq!(plan.provider, "openai");
        assert_eq!(plan.steps[0].tool, "svc.status");
    }

    #[test]
    fn fence_wrapped_plan_is_tolerated() {
        let steps = parse_plan_steps("```json\n{\"steps\":[{\"tool\":\"fs.read\",\"params\":{\"path\":\"/etc/hosts\"}}]}\n```")
            .expect("fenced plan parses");
        assert_eq!(steps[0].tool, "fs.read");
    }

    #[test]
    fn empty_steps_is_fail_closed() {
        assert!(parse_plan_steps("{\"steps\":[]}").is_err());
        assert!(parse_plan_steps("not json at all").is_err());
    }

    #[test]
    fn anthropic_truncation_is_fail_closed() {
        let truncated = r#"{"stop_reason":"max_tokens","content":[{"type":"text","text":"{\"steps\":["}]}"#;
        assert!(anthropic_plan_text(truncated).is_err());
    }

    #[test]
    fn openai_truncation_is_fail_closed() {
        let truncated = r#"{"choices":[{"finish_reason":"length","message":{"content":"{"}}]}"#;
        assert!(openai_plan_text(truncated).is_err());
    }

    #[test]
    fn claimed_risk_is_captured_but_advisory() {
        let steps = parse_plan_steps(
            "{\"steps\":[{\"tool\":\"svc.restart\",\"params\":{\"service\":\"nginx\"},\"risk\":\"read-only\"}]}",
        )
        .expect("parse");
        assert_eq!(steps[0].claimed_risk.as_deref(), Some("read-only"));
    }
}
