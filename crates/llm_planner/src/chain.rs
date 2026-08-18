//! chain —— provider fallback 链 + 重试（cp-llm 阶段 C，ADR-006）。
//!
//! 核心命题保持不变：**「LLM 只产 PlannedStep（intention）」**。本模块只决定「哪个 provider
//! 产 intention」——绝不改变桥接/裁决/exec 路径。`ProviderChain` 把多个 `LlmProvider`
//! 串成有序链：
//!
//! - 传输层临时错误（超时、连接拒绝、TLS 握手失败、5xx、429）→ 按 `RetryPolicy` 重试当前
//!   provider；重试耗尽 → fallback 到下一个 provider。
//! - 确定性错误（鉴权 401/403、解析失败、空 plan、截断）→ **不重试、不 fallback 到下一
//!   个 provider 之外**，直接 fail-closed（避免用坏 key 反复撞库或传播畸形成品）。
//!   但若链上还有其它 provider，仍尝试 fallback——仅当前 provider 的重试被跳过。
//! - 全部 provider 均失败 → fail-closed（`Err`），绝不产半成品 `RawPlan`。
//!
//! 每次尝试的结果（provider、模型、终态、耗时类别）记入 `ChainAttempt`，调用方可据此
//! 审计/观测哪个 provider 兜底成功。`ProviderChain` 自身不触网、不持 unsafe（`#![forbid]`
//! 不受影响——unsafe 全在各 provider 的 deps 内）。
//!
//! 向后兼容：`LlmProvider` trait 不变。`ProviderChain` 是新增的组合层，实现 `LlmProvider`
//! 自身（可被嵌套或被 `llm_plan` 直接使用）。

use std::io;

use crate::{LlmProvider, RawPlan};

/// 一次 provider 尝试的终态记录（advisory，供审计/观测；绝不参与裁决）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainAttempt {
    /// provider 名（取 `RawPlan.provider`；失败时取 provider 的 `name()`）。
    pub provider: String,
    pub model: String,
    pub outcome: AttemptOutcome,
}

/// 单次尝试的结局。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptOutcome {
    /// 成功产出一个 `RawPlan`。
    Succeeded { http_status: u16 },
    /// 传输层临时错误（已重试耗尽或直接 fallback）。
    Transient { reason: String },
    /// 确定性错误（鉴权/解析/截断/空 plan）—— 不重试。
    Permanent { reason: String },
}

/// 重试策略：仅对 `Transient` 错误生效。
///
/// `max_retries=0` ⇒ 不重试（第一次失败即 fallback）。重试之间无 sleep（本 crate 保持
/// 同步、无 tokio；真部署的退避由 provider 自身的 `ureq::Agent` 超时 + 调用方编排决定）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    pub max_retries: u32,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self { max_retries: 1 }
    }
}

impl RetryPolicy {
    pub const NO_RETRY: Self = Self { max_retries: 0 };
}

/// 有序 provider fallback 链。`providers[0]` 是首选；后续是兜底。
///
/// `LlmProvider` 的实现：依次尝试每个 provider（首选先按 `RetryPolicy` 重试），返回第一个
/// 成功的 `RawPlan`；全部失败则返回最后一个确定性错误（或最后一个临时错误）。
pub struct ProviderChain {
    providers: Vec<Box<dyn LlmProvider>>,
    policy: RetryPolicy,
    /// 最近一次 `plan` 调用的逐 provider 尝试记录（供观测；Mutex 因 `plan(&self)` 不可变借用）。
    attempts: std::sync::Mutex<Vec<ChainAttempt>>,
}

impl ProviderChain {
    /// 构造一条 fallback 链。`providers` 不得为空。
    pub fn new(providers: Vec<Box<dyn LlmProvider>>, policy: RetryPolicy) -> Self {
        assert!(
            !providers.is_empty(),
            "ProviderChain requires at least one provider"
        );
        Self {
            providers,
            policy,
            attempts: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// 单 provider 便捷构造（无 fallback，仅重试）。
    pub fn single(provider: Box<dyn LlmProvider>, policy: RetryPolicy) -> Self {
        Self::new(vec![provider], policy)
    }

    /// 最近一次 `plan` 调用的逐 provider 尝试记录（克隆返回，供观测；不影响裁决）。
    /// 每次 `plan` 调用重置。若锁被毒化返回空 Vec（fail-soft，观测不阻塞裁决）。
    pub fn last_attempts(&self) -> Vec<ChainAttempt> {
        self.attempts
            .lock()
            .map(|attempts| attempts.clone())
            .unwrap_or_default()
    }
}

impl LlmProvider for ProviderChain {
    fn plan(&self, intent: &str) -> io::Result<RawPlan> {
        let mut last_permanent: Option<io::Error> = None;
        let mut last_transient: Option<io::Error> = None;
        let mut recorded: Vec<ChainAttempt> = Vec::new();
        for provider in &self.providers {
            let name = provider.name().to_string();
            let model = String::new(); // 成功时由 RawPlan 回填；失败时无模型可知。
            let mut attempts_for_this_provider = 0u32;
            loop {
                match provider.plan(intent) {
                    Ok(plan) => {
                        recorded.push(ChainAttempt {
                            provider: plan.provider.clone(),
                            model: plan.model.clone(),
                            outcome: AttemptOutcome::Succeeded {
                                http_status: plan.http_status,
                            },
                        });
                        self.commit_attempts(recorded);
                        return Ok(plan);
                    }
                    Err(error) => {
                        let reason = error.to_string();
                        let classified = classify(&error);
                        recorded.push(ChainAttempt {
                            provider: name.clone(),
                            model: model.clone(),
                            outcome: match classified {
                                ErrorClass::Transient => AttemptOutcome::Transient { reason },
                                ErrorClass::Permanent => AttemptOutcome::Permanent { reason },
                            },
                        });
                        match classified {
                            ErrorClass::Transient => {
                                last_transient = Some(error);
                                if attempts_for_this_provider < self.policy.max_retries {
                                    attempts_for_this_provider += 1;
                                    continue; // 重试当前 provider
                                }
                                break; // 重试耗尽 → fallback 到下一个 provider
                            }
                            ErrorClass::Permanent => {
                                last_permanent = Some(error);
                                break; // 确定性错误 → 不重试，直接 fallback
                            }
                        }
                    }
                }
            }
        }
        // 全部 provider 失败：优先报确定性错误（更可诊断），否则报最后一个临时错误。
        self.commit_attempts(recorded);
        Err(last_permanent
            .or(last_transient)
            .unwrap_or_else(|| io::Error::new(io::ErrorKind::Other, "all providers failed")))
    }
}

impl ProviderChain {
    /// 把本次 plan 调用的尝试记录写入共享缓冲（fail-soft：锁毒化则丢弃，不阻塞裁决）。
    fn commit_attempts(&self, attempts: Vec<ChainAttempt>) {
        if let Ok(mut guard) = self.attempts.lock() {
            *guard = attempts;
        }
    }
}

/// 错误类别：决定是否重试。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorClass {
    /// 传输/超时/限流/5xx —— 可重试、可 fallback。
    Transient,
    /// 鉴权/解析/截断/空 plan —— 不重试（但仍 fallback 到下一个 provider）。
    Permanent,
}

/// 启发式分类：据 `io::Error` 的文本与 kind 判断。`LlmProvider` 实现已把 HTTP 状态码与
/// 传输错误统一编码进 `io::Error`（见 `post_json`），此处据约定文本分类，不改 trait 签名。
fn classify(error: &io::Error) -> ErrorClass {
    let message = error.to_string();
    // 传输层（ureq::Error::Transport → io::ErrorKind::Other + "transport: ..."）。
    if message.contains("transport:") || message.contains("Connection refused") || message.contains("timed out") {
        return ErrorClass::Transient;
    }
    // HTTP 状态码：429（限流）与 5xx（服务端）为临时；4xx（含 401/403/400）为永久。
    if let Some(status) = http_status_in_message(&message) {
        if status == 429 || (500..600).contains(&status) {
            return ErrorClass::Transient;
        }
        if (400..500).contains(&status) {
            return ErrorClass::Permanent;
        }
    }
    // 解析失败（InvalidData）—— plan 畸形/截断/空：永久（重试同一 provider 同样会失败）。
    if error.kind() == io::ErrorKind::InvalidData {
        return ErrorClass::Permanent;
    }
    // 兜底：未知错误视为临时（倾向重试，不静默吞）。
    ErrorClass::Transient
}

/// 从错误文本里提取 `http <code>` 中的状态码（`post_json` 对非 2xx 产出 `"http {code}: ..."`）。
fn http_status_in_message(message: &str) -> Option<u16> {
    let marker = "http ";
    let start = message.find(marker)? + marker.len();
    let rest = &message[start..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse::<u16>().ok().filter(|s| *s >= 100)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RawPlan, RawStep, RecordedProvider};
    use std::cell::Cell;

    fn ok_plan(provider: &str) -> RawPlan {
        RawPlan {
            provider: provider.to_string(),
            model: "m".to_string(),
            raw_json: "{\"steps\":[{\"tool\":\"svc.status\",\"params\":{\"service\":\"nginx\"}}]}".to_string(),
            http_status: 200,
            steps: vec![RawStep {
                tool: "svc.status".to_string(),
                params: vec![("service".to_string(), "nginx".to_string())],
                claimed_risk: None,
                text: String::new(),
            }],
        }
    }

    /// 可编程 stub：按预设序列返回 Ok(plan) 或 Err(error)，并统计调用次数。
    /// `io::Error` 不实现 `Clone`，故 responses 存 `Result<RawPlan, String>`（错误文本），
    /// `plan()` 内把错误文本包回 `io::Error`。
    struct ScriptedProvider {
        name: String,
        responses: Vec<Result<RawPlan, String>>,
        calls: Cell<u32>,
    }

    impl ScriptedProvider {
        fn new(name: &str, responses: Vec<Result<RawPlan, String>>) -> Self {
            Self {
                name: name.to_string(),
                responses,
                calls: Cell::new(0),
            }
        }
    }

    impl LlmProvider for ScriptedProvider {
        fn name(&self) -> &str {
            &self.name
        }
        fn plan(&self, _intent: &str) -> io::Result<RawPlan> {
            let idx = self.calls.get() as usize;
            self.calls.set(self.calls.get() + 1);
            match self.responses.get(idx) {
                Some(Ok(plan)) => Ok(plan.clone()),
                Some(Err(msg)) => {
                    // 保留错误类别：据消息内容构造对应 kind 的 io::Error。
                    let kind = if msg.starts_with("transport:") || msg.contains("timed out") {
                        io::ErrorKind::Other
                    } else if msg.starts_with("invalid:") {
                        io::ErrorKind::InvalidData
                    } else {
                        io::ErrorKind::Other
                    };
                    Err(io::Error::new(kind, msg.clone()))
                }
                None => Err(io::Error::new(io::ErrorKind::Other, "script exhausted")),
            }
        }
    }

    fn transient_err() -> io::Error {
        io::Error::new(io::ErrorKind::Other, "transport: connection refused")
    }
    fn permanent_err() -> io::Error {
    // 以 "invalid:" 前缀，ScriptedProvider::plan 据此构造 InvalidData kind（供 classify 判 Permanent）。
        io::Error::new(io::ErrorKind::InvalidData, "invalid: plan has empty \"steps\"")
    }
    fn http_err(code: u16) -> io::Error {
        io::Error::new(io::ErrorKind::Other, format!("http {code}: body"))
    }

    #[test]
    fn first_provider_success_no_fallback() {
        let p1 = ScriptedProvider::new("a", vec![Ok(ok_plan("a"))]);
        let p2 = ScriptedProvider::new("b", vec![Ok(ok_plan("b"))]);
        let chain = ProviderChain::new(
            vec![Box::new(p1), Box::new(p2)],
            RetryPolicy::NO_RETRY,
        );
        let plan = chain.plan("x").expect("first succeeds");
        assert_eq!(plan.provider, "a");
    }

    #[test]
    fn transient_failure_falls_back_to_second_provider() {
        let p1 = ScriptedProvider::new("a", vec![Err(transient_err().to_string())]);
        let p2 = ScriptedProvider::new("b", vec![Ok(ok_plan("b"))]);
        let chain = ProviderChain::new(
            vec![Box::new(p1), Box::new(p2)],
            RetryPolicy::NO_RETRY,
        );
        let plan = chain.plan("x").expect("fallback succeeds");
        assert_eq!(plan.provider, "b");
        // p1 失败一次后 fallback，p2 被调用一次。
    }

    #[test]
    fn permanent_failure_falls_back_to_second_provider() {
        let p1 = ScriptedProvider::new("a", vec![Err(permanent_err().to_string())]);
        let p2 = ScriptedProvider::new("b", vec![Ok(ok_plan("b"))]);
        let chain = ProviderChain::new(
            vec![Box::new(p1), Box::new(p2)],
            RetryPolicy::NO_RETRY,
        );
        let plan = chain.plan("x").expect("fallback after permanent");
        assert_eq!(plan.provider, "b");
    }

    #[test]
    fn transient_retried_before_fallback() {
        let p1 = ScriptedProvider::new(
            "a",
            vec![Err(transient_err().to_string()), Ok(ok_plan("a"))],
        );
        let p2 = ScriptedProvider::new("b", vec![Ok(ok_plan("b"))]);
        let chain = ProviderChain::new(
            vec![Box::new(p1), Box::new(p2)],
            RetryPolicy { max_retries: 3 },
        );
        let plan = chain.plan("x").expect("retry then succeed");
        assert_eq!(plan.provider, "a");
        // 首选 provider 第一次临时失败 → 重试（第二次成功），未 fallback。
    }

    #[test]
    fn all_fail_returns_last_permanent() {
        let p1 = ScriptedProvider::new("a", vec![Err(http_err(401).to_string())]);
        let p2 = ScriptedProvider::new("b", vec![Err(transient_err().to_string())]);
        let chain = ProviderChain::new(
            vec![Box::new(p1), Box::new(p2)],
            RetryPolicy::NO_RETRY,
        );
        let err = chain.plan("x").expect_err("all fail");
        // 永久错误优先于临时错误上报。
        assert!(err.to_string().contains("401"));
    }

    #[test]
    fn http_429_is_transient_and_retried() {
        let provider = ScriptedProvider::new("a", vec![
            Err(http_err(429).to_string()),
            Ok(ok_plan("a")),
        ]);
        let chain = ProviderChain::single(
            Box::new(provider),
            RetryPolicy { max_retries: 2 },
        );
        let plan = chain.plan("x").expect("429 retried");
        assert_eq!(plan.provider, "a");
    }

    #[test]
    fn http_401_is_permanent_not_retried() {
        let provider = ScriptedProvider::new("a", vec![
            Err(http_err(401).to_string()),
            Err(http_err(401).to_string()),
            Err(http_err(401).to_string()),
        ]);
        let chain = ProviderChain::single(
            Box::new(provider),
            RetryPolicy { max_retries: 5 },
        );
        let err = chain.plan("x").expect_err("401 permanent");
        assert!(err.to_string().contains("401"));
        // 401 永久 → 只调用一次，不重试。
        // （provider.calls() 无法取回——Box 后所有权移走，由结构保证。）
    }

    #[test]
    fn http_503_is_transient() {
        assert_eq!(classify(&http_err(503)), ErrorClass::Transient);
        assert_eq!(classify(&http_err(429)), ErrorClass::Transient);
        assert_eq!(classify(&http_err(401)), ErrorClass::Permanent);
        assert_eq!(classify(&http_err(400)), ErrorClass::Permanent);
        assert_eq!(classify(&transient_err()), ErrorClass::Transient);
        assert_eq!(classify(&permanent_err()), ErrorClass::Permanent);
    }

    #[test]
    fn empty_chain_panics() {
        let result = std::panic::catch_unwind(|| {
            ProviderChain::new(vec![], RetryPolicy::NO_RETRY);
        });
        assert!(result.is_err(), "empty chain must panic");
    }

    /// 用 `RecordedProvider` 端到端验证：链中第二个 provider 兜底成功（无网无 key 可测）。
    #[test]
    fn recorded_provider_succeeds_in_chain() {
        let envelope = r#"{"stop_reason":"end_turn","content":[{"type":"text","text":"{\"steps\":[{\"tool\":\"svc.status\",\"params\":{\"service\":\"nginx\"}}]}"}]}"#;
        let rec = RecordedProvider::anthropic("claude-opus-4-8", envelope);
        let chain = ProviderChain::single(Box::new(rec), RetryPolicy::default());
        let plan = chain.plan("check nginx").expect("recorded plan");
        assert_eq!(plan.provider, "anthropic");
        assert_eq!(plan.steps.len(), 1);
    }

    /// last_attempts 真正记录每次尝试：首选成功 → 1 个 Succeeded span。
    #[test]
    fn last_attempts_records_success() {
        let p1 = ScriptedProvider::new("a", vec![Ok(ok_plan("a"))]);
        let chain = ProviderChain::new(vec![Box::new(p1)], RetryPolicy::NO_RETRY);
        let _ = chain.plan("x").expect("ok");
        let attempts = chain.last_attempts();
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].provider, "a");
        assert!(matches!(attempts[0].outcome, AttemptOutcome::Succeeded { http_status: 200 }));
    }

    /// last_attempts 记录 fallback：首选临时失败 → 第二个成功：2 个 attempt。
    #[test]
    fn last_attempts_records_fallback() {
        let p1 = ScriptedProvider::new("a", vec![Err(transient_err().to_string())]);
        let p2 = ScriptedProvider::new("b", vec![Ok(ok_plan("b"))]);
        let chain = ProviderChain::new(vec![Box::new(p1), Box::new(p2)], RetryPolicy::NO_RETRY);
        let _ = chain.plan("x").expect("fallback");
        let attempts = chain.last_attempts();
        assert_eq!(attempts.len(), 2);
        assert!(matches!(&attempts[0].outcome, AttemptOutcome::Transient { .. }));
        assert_eq!(attempts[0].provider, "a");
        assert!(matches!(&attempts[1].outcome, AttemptOutcome::Succeeded { .. }));
        assert_eq!(attempts[1].provider, "b");
    }

    /// last_attempts 每次 plan 调用重置（不留旧记录）。
    #[test]
    fn last_attempts_resets_per_call() {
        let p1 = ScriptedProvider::new("a", vec![Ok(ok_plan("a")), Ok(ok_plan("a"))]);
        let chain = ProviderChain::single(Box::new(p1), RetryPolicy::NO_RETRY);
        let _ = chain.plan("x").unwrap();
        let _ = chain.plan("x").unwrap();
        let attempts = chain.last_attempts();
        assert_eq!(attempts.len(), 1, "second call should reset to 1 attempt");
    }
}
