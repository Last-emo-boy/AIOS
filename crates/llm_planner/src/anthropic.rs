//! ClaudeProvider —— Anthropic messages backend（POST {base_url}/v1/messages）。

use std::io;
use std::time::Duration;

use crate::{anthropic_plan_text, build_system_prompt, parse_plan_steps, post_json, LlmProvider, RawPlan};

/// Anthropic `/v1/messages` provider。鉴权头 `x-api-key` + `anthropic-version:2023-06-01`；
/// `system` 是 body 顶层字段。
pub struct ClaudeProvider {
    pub base_url: String,
    pub api_key: String,
    pub model: String,
    pub max_tokens: u32,
    /// 系统提示词（阶段 I）：默认用 `build_system_prompt()` 从冻结 `TOOL_SCHEMAS`
    /// 动态生成，确保 prompt 与 ToolRouter 同步。算子可覆盖（`with_system_prompt`）。
    pub system_prompt: String,
    agent: ureq::Agent,
}

impl ClaudeProvider {
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

    /// 默认指向 api.anthropic.com + claude-opus-4-8。
    pub fn anthropic(api_key: impl Into<String>) -> Self {
        Self::new(
            "https://api.anthropic.com",
            api_key,
            "claude-opus-4-8",
            1024,
        )
    }

    /// 据环境变量构造（便于接自托管网关 / 本地代理）：
    /// - `ANTHROPIC_BASE_URL`（缺省 `https://api.anthropic.com`）
    /// - `ANTHROPIC_MODEL`（缺省 `claude-opus-4-8`）
    pub fn from_env(api_key: impl Into<String>) -> Self {
        let base_url = std::env::var("ANTHROPIC_BASE_URL")
            .unwrap_or_else(|_| "https://api.anthropic.com".to_string());
        let model = std::env::var("ANTHROPIC_MODEL")
            .unwrap_or_else(|_| "claude-opus-4-8".to_string());
        Self::new(base_url, api_key, model, 1024)
    }
}

impl LlmProvider for ClaudeProvider {
    fn name(&self) -> &str {
        "anthropic"
    }

    fn plan(&self, intent: &str) -> io::Result<RawPlan> {
        let body = serde_json::json!({
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": self.system_prompt,
            "messages": [{"role": "user", "content": intent}],
        })
        .to_string();
        let url = format!("{}/v1/messages", self.base_url);
        let (status, envelope) = post_json(
            &self.agent,
            &url,
            &[
                ("x-api-key", self.api_key.as_str()),
                ("anthropic-version", "2023-06-01"),
                ("content-type", "application/json"),
            ],
            &body,
        )?;
        let plan_text = anthropic_plan_text(&envelope)?;
        let steps = parse_plan_steps(&plan_text)?;
        Ok(RawPlan {
            provider: "anthropic".to_string(),
            model: self.model.clone(),
            raw_json: plan_text,
            http_status: status,
            steps,
        })
    }
}
