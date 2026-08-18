//! OpenAiCompatProvider —— OpenAI-compatible chat-completions backend
//! （POST {base_url}/chat/completions）。base_url 可配，覆盖 OpenAI / vLLM / ollama /
//! llama.cpp-server。

use std::io;
use std::time::Duration;

use crate::{build_system_prompt, openai_plan_text, parse_plan_steps, post_json, LlmProvider, RawPlan};

/// OpenAI-compatible `/chat/completions` provider。鉴权头 `Authorization: Bearer`；
/// `system` 是 messages 里一条；`response_format:{type:json_object}` 约束输出为合法 JSON。
pub struct OpenAiCompatProvider {
    pub base_url: String,
    pub api_key: String,
    pub model: String,
    pub max_tokens: u32,
    /// 系统提示词（阶段 I）：默认用 `build_system_prompt()` 从冻结 `TOOL_SCHEMAS`
    /// 动态生成，确保 prompt 与 ToolRouter 同步。算子可覆盖（`with_system_prompt`）。
    pub system_prompt: String,
    agent: ureq::Agent,
}

impl OpenAiCompatProvider {
    pub fn new(
        base_url: impl Into<String>,
        api_key: impl Into<String>,
        model: impl Into<String>,
        max_tokens: u32,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            api_key: api_key.into(),
            model: model.into(),
            max_tokens,
            system_prompt: build_system_prompt(),
            agent: ureq::AgentBuilder::new()
                .timeout_connect(Duration::from_secs(20))
                .timeout_read(Duration::from_secs(120))
                .build(),
        }
    }

    /// 覆盖默认系统提示词（阶段 I）。算子可注入自定义 prompt（仍经冻结 bridge 裁决）。
    pub fn with_system_prompt(mut self, prompt: impl Into<String>) -> Self {
        self.system_prompt = prompt.into();
        self
    }

    /// 默认指向 api.openai.com/v1。
    pub fn openai(api_key: impl Into<String>) -> Self {
        Self::new("https://api.openai.com/v1", api_key, "gpt-4o-mini", 1024)
    }

    /// 据环境变量构造（便于接 vLLM / ollama / 本地兼容网关）：
    /// - `OPENAI_BASE_URL`（缺省 `https://api.openai.com/v1`）
    /// - `OPENAI_MODEL`（缺省 `gpt-4o-mini`）
    pub fn from_env(api_key: impl Into<String>) -> Self {
        let base_url = std::env::var("OPENAI_BASE_URL")
            .unwrap_or_else(|_| "https://api.openai.com/v1".to_string());
        let model = std::env::var("OPENAI_MODEL")
            .unwrap_or_else(|_| "gpt-4o-mini".to_string());
        Self::new(base_url, api_key, model, 1024)
    }
}

impl LlmProvider for OpenAiCompatProvider {
    fn name(&self) -> &str {
        "openai"
    }

    fn plan(&self, intent: &str) -> io::Result<RawPlan> {
        let body = serde_json::json!({
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": intent},
            ],
            "response_format": {"type": "json_object"},
        })
        .to_string();
        let url = format!("{}/chat/completions", self.base_url);
        let authorization = format!("Bearer {}", self.api_key);
        let (status, envelope) = post_json(
            &self.agent,
            &url,
            &[
                ("authorization", authorization.as_str()),
                ("content-type", "application/json"),
            ],
            &body,
        )?;
        let plan_text = openai_plan_text(&envelope)?;
        let steps = parse_plan_steps(&plan_text)?;
        Ok(RawPlan {
            provider: "openai".to_string(),
            model: self.model.clone(),
            raw_json: plan_text,
            http_status: status,
            steps,
        })
    }
}
