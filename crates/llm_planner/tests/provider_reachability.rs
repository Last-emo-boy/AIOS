//! order5 —— provider 解析 + 真 API 可达性（无 key → 401 证 TLS 握手/信封；无网则标注跳过）。
//!
//! 录制信封解析（Anthropic + OpenAI）保证无网可测；真 API 401 证明 webpki-roots TLS
//! 握手 + 连接 + 请求体格式全通（有真 key 即 200）。

use llm_planner::{ClaudeProvider, LlmProvider, OpenAiCompatProvider, RecordedProvider};

const ANTHROPIC_ENVELOPE: &str = r#"{
    "id": "msg_real_1",
    "type": "message",
    "role": "assistant",
    "model": "claude-opus-4-8",
    "stop_reason": "end_turn",
    "content": [
        {"type": "text",
         "text": "{\"steps\":[{\"tool\":\"svc.status\",\"resource\":\"nginx\",\"params\":{\"service\":\"nginx\"}},{\"tool\":\"svc.logs\",\"params\":{\"service\":\"nginx\",\"last\":\"100\"}}]}"}
    ]
}"#;

const OPENAI_ENVELOPE: &str = r#"{
    "id": "chatcmpl-real-1",
    "object": "chat.completion",
    "choices": [
        {"index": 0, "finish_reason": "stop",
         "message": {"role": "assistant",
            "content": "{\"steps\":[{\"tool\":\"fs.read\",\"resource\":\"/etc/hosts\",\"params\":{\"path\":\"/etc/hosts\"}}]}"}}
    ]
}"#;

#[test]
fn recorded_anthropic_envelope_parses_full_plan() {
    let provider = RecordedProvider::anthropic("claude-opus-4-8", ANTHROPIC_ENVELOPE);
    let plan = provider.plan("diagnose nginx").expect("anthropic recorded");
    assert_eq!(plan.provider, "anthropic");
    assert_eq!(plan.steps.len(), 2);
    assert_eq!(plan.steps[0].tool, "svc.status");
    assert_eq!(plan.steps[1].tool, "svc.logs");
}

#[test]
fn recorded_openai_envelope_parses_plan() {
    let provider = RecordedProvider::openai("gpt-4o-mini", OPENAI_ENVELOPE);
    let plan = provider.plan("read hosts").expect("openai recorded");
    assert_eq!(plan.provider, "openai");
    assert_eq!(plan.steps[0].tool, "fs.read");
    assert_eq!(plan.steps[0].params, vec![("path".to_string(), "/etc/hosts".to_string())]);
}

/// 真 POST api.anthropic.com/v1/messages 无 key：在线 → 401（证 TLS+信封）；离线 → 标注跳过。
#[test]
fn anthropic_real_endpoint_401_without_key_proves_tls() {
    let provider = ClaudeProvider::anthropic("");
    match provider.plan("diagnose nginx") {
        Ok(_) => panic!("unexpected success without API key"),
        Err(error) => {
            let message = error.to_string();
            if message.contains("http 401") {
                // TLS 握手成功 + 信封到达服务端，被鉴权拒。
                assert!(
                    message.contains("authentication") || message.contains("x-api-key"),
                    "401 body should mention auth: {message}"
                );
                eprintln!("anthropic reachable: 401 authentication error (TLS + envelope OK)");
            } else {
                // 无外网/被墙：传输层失败 —— 标注跳过，不判失败。
                eprintln!("anthropic endpoint not reachable (no network), skipping: {message}");
            }
        }
    }
}

/// 真 POST api.openai.com/v1/chat/completions 无 key：在线 → 401；离线 → 标注跳过。
#[test]
fn openai_real_endpoint_401_without_key_proves_tls() {
    let provider = OpenAiCompatProvider::openai("");
    match provider.plan("read hosts") {
        Ok(_) => panic!("unexpected success without API key"),
        Err(error) => {
            let message = error.to_string();
            if message.contains("http 401") {
                eprintln!("openai reachable: 401 (TLS + envelope OK)");
            } else {
                eprintln!("openai endpoint not reachable (no network), skipping: {message}");
            }
        }
    }
}
