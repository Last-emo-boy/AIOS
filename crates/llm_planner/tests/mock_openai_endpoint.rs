//! order11 —— OpenAiCompatProvider mock server 端到端验证。
//!
//! 发行版'配好 API key 真能跑通'的最后一公里：启动本地 TcpListener 假装 OpenAI
//! `/chat/completions`，验证 `OpenAiCompatProvider::plan()` 完整 HTTP+解析路径——
//! 请求方法/header/body 格式、envelope 解析、RawPlan 产出。无需真 API key / 外网。
//!
//! 这是 provider_reachability.rs 的补充：后者用 RecordedProvider 跳过网络层、用真
//! API 401 仅证 TLS。本测试用本地 mock 证**完整链路**（HTTP 请求构造 → 服务端响应
//! → envelope 解析 → RawPlan），是发行版真实可用的核心验证。

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use llm_planner::{LlmProvider, OpenAiCompatProvider};

/// 合法 OpenAI envelope：content 是 JSON 计划（svc.status + fs.read，均只读）。
const MOCK_ENVELOPE: &str = r#"{
    "id": "chatcmpl-mock-1",
    "object": "chat.completion",
    "choices": [
        {"index": 0, "finish_reason": "stop",
         "message": {"role": "assistant",
            "content": "{\"steps\":[{\"tool\":\"svc.status\",\"resource\":\"nginx\",\"params\":{\"service\":\"nginx\"}},{\"tool\":\"fs.read\",\"resource\":\"cfg\",\"params\":{\"path\":\"/etc/hostname\"}}]}"}}
    ]
}"#;

/// 启动 mock OpenAI server，返回 (base_url, 收到的请求记录句柄)。
/// server 在独立线程跑，每个连接回 MOCK_ENVELOPE + 记录请求行/header/body。
fn mock_openai_server() -> (String, std::sync::Arc<std::sync::Mutex<CapturedRequest>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let captured = std::sync::Arc::new(std::sync::Mutex::new(CapturedRequest::default()));
    let captured_clone = captured.clone();

    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let captured_clone = captured_clone.clone();
            thread::spawn(move || {
                let _ = handle_one(&mut stream, &captured_clone);
            });
        }
    });

    (format!("http://{addr}"), captured)
}

#[derive(Default, Debug, Clone)]
struct CapturedRequest {
    request_line: String,
    authorization: String,
    content_type: String,
    body: String,
}

fn handle_one(
    stream: &mut std::net::TcpStream,
    captured: &std::sync::Arc<std::sync::Mutex<CapturedRequest>>,
) -> std::io::Result<()> {
    let mut buf = [0u8; 8192];
    let n = stream.read(&mut buf)?;
    let raw = String::from_utf8_lossy(&buf[..n]).to_string();

    // 解析请求行 + headers + body（\r\n\r\n 分隔）。
    let mut parts = raw.split("\r\n\r\n");
    let head = parts.next().unwrap_or("");
    let body = parts.next().unwrap_or("");

    let mut head_lines = head.split("\r\n");
    let request_line = head_lines.next().unwrap_or("").to_string();
    let mut authorization = String::new();
    let mut content_type = String::new();
    for line in head_lines {
        if let Some(v) = line.strip_prefix("Authorization:").or_else(|| line.strip_prefix("authorization:")) {
            authorization = v.trim().to_string();
        } else if let Some(v) = line
            .strip_prefix("Content-Type:")
            .or_else(|| line.strip_prefix("content-type:"))
        {
            content_type = v.trim().to_string();
        }
    }

    if let Ok(mut c) = captured.lock() {
        *c = CapturedRequest {
            request_line,
            authorization,
            content_type,
            body: body.to_string(),
        };
    }

    // 回合法 envelope（HTTP/1.1 200）。
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        MOCK_ENVELOPE.len(),
        MOCK_ENVELOPE
    );
    stream.write_all(response.as_bytes())?;
    Ok(())
}

#[test]
fn openai_provider_full_http_path_parses_plan() {
    let (base_url, captured) = mock_openai_server();
    let provider = OpenAiCompatProvider::new(&base_url, "test-key-xyz", "gpt-4o-mini", 1024);

    let plan = provider.plan("inspect nginx config").expect("plan should parse");

    // RawPlan 字段正确。
    assert_eq!(plan.provider, "openai");
    assert_eq!(plan.model, "gpt-4o-mini");
    assert_eq!(plan.http_status, 200);
    assert_eq!(plan.steps.len(), 2, "steps: {:?}", plan.steps);
    assert_eq!(plan.steps[0].tool, "svc.status");
    assert_eq!(plan.steps[1].tool, "fs.read");
    assert_eq!(
        plan.steps[1].params,
        vec![("path".to_string(), "/etc/hostname".to_string())]
    );

    // 验证 provider 发出的 HTTP 请求格式。
    let req = captured.lock().expect("lock").clone();
    assert!(
        req.request_line.starts_with("POST ") && req.request_line.contains("/chat/completions"),
        "应 POST /chat/completions: {}",
        req.request_line
    );
    assert_eq!(
        req.authorization, "Bearer test-key-xyz",
        "Authorization Bearer 头应携带 api_key"
    );
    assert!(
        req.content_type.contains("application/json"),
        "Content-Type 应为 application/json: {}",
        req.content_type
    );
    // body 含 system + user 两条 messages（intent 注入 user）。
    assert!(req.body.contains("\"role\":\"system\""), "body: {}", req.body);
    assert!(req.body.contains("\"role\":\"user\""), "body: {}", req.body);
    assert!(
        req.body.contains("inspect nginx config"),
        "intent 应注入 user message: {}",
        req.body
    );
    assert!(
        req.body.contains("\"response_format\":{\"type\":\"json_object\"}"),
        "应约束 JSON 输出: {}",
        req.body
    );
}

#[test]
fn openai_provider_fail_closed_on_500() {
    // mock 返回 500 → provider fail-closed 返回 Err（不静默吞）。
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            thread::spawn(move || {
                let mut buf = [0u8; 8192];
                let _ = stream.read(&mut buf);
                let resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 11\r\nConnection: close\r\n\r\nserver down";
                let _ = stream.write_all(resp.as_bytes());
            });
        }
    });

    let base_url = format!("http://{addr}");
    let provider = OpenAiCompatProvider::new(&base_url, "k", "m", 1024);
    let result = provider.plan("anything");
    assert!(result.is_err(), "500 应 fail-closed");
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("http 500"), "应报告 500: {msg}");
}

#[test]
fn openai_provider_fail_closed_on_malformed_envelope() {
    // mock 返回 200 但 envelope 缺 choices → 解析失败 fail-closed。
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let bad_body = r#"{"unexpected":"shape"}"#;
    let bad = bad_body.to_string();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let bad = bad.clone();
            thread::spawn(move || {
                let mut buf = [0u8; 8192];
                let _ = stream.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    bad.len(),
                    bad
                );
                let _ = stream.write_all(resp.as_bytes());
            });
        }
    });

    let base_url = format!("http://{addr}");
    let provider = OpenAiCompatProvider::new(&base_url, "k", "m", 1024);
    let result = provider.plan("anything");
    assert!(result.is_err(), "缺 choices 应 fail-closed");
}
