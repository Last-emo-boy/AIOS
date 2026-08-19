//! agentd HTTP API server —— 发行版 operator 入口（纯 `std::net`，零外部依赖）。
//!
//! cp-llm 阶段 V：暴露最小 JSON-over-HTTP 接口，让 operator 可远程驱动 OS：
//! - `GET /health` → `HealthReport::to_json()`
//! - `POST /plan` body `{"intent":"..."}` → `PlanSpec::to_json()`
//!
//! **安全边界**：本 server 只序列化已有的冻结编排结果（`Lifecycle`），不自造裁决。
//! 它绑定 loopback（`127.0.0.1`）且不暴露 shell——所有工具调用仍经冻结 `ToolRouter`。
//! `#![forbid(unsafe_code)]` 适用（`std::net::TcpListener` 是安全抽象）。
#![forbid(unsafe_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;

use crate::lifecycle::Agentd;

/// 启动 HTTP server，阻塞调用（适合作为 agentd 主循环或独立线程）。
///
/// 绑定 `addr`（建议 loopback，如 `127.0.0.1:8421`）。每个连接单线程处理
/// （无并发——发行版最小可用，避免 trait Send+Sync 问题）。连接处理失败不
/// 终止 server（记录到 stderr，继续 accept 下一个）。
pub fn serve(lifecycle: &Agentd, addr: &str) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    eprintln!("agentd http api listening on {addr}");
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                if let Err(err) = handle_connection(&mut stream, lifecycle) {
                    eprintln!("agentd http: connection error: {err}");
                }
            }
            Err(err) => {
                eprintln!("agentd http: accept error: {err}");
            }
        }
    }
    Ok(())
}

fn handle_connection(
    stream: &mut std::net::TcpStream,
    lifecycle: &Agentd,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    // 读请求行 + headers，再按 Content-Length 读 body。
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("/");

    // 读取 headers 直到空行，提取 Content-Length。
    let mut content_length: usize = 0;
    loop {
        let mut header = String::new();
        let n = reader.read_line(&mut header)?;
        if n == 0 || header.trim().is_empty() {
            break;
        }
        if let Some(value) = header.strip_prefix("Content-Length:") {
            content_length = value.trim().parse().unwrap_or(0);
        }
    }

    // 读 body（POST）。
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }
    let body_str = String::from_utf8_lossy(&body);

    let (status, content) = route(lifecycle, method, path, &body_str);
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{content}",
        content.len()
    );
    stream.write_all(response.as_bytes())?;
    Ok(())
}

/// 路由请求到对应的 Lifecycle 方法。返回 (HTTP status, JSON body)。
fn route(lifecycle: &Agentd, method: &str, path: &str, body: &str) -> (&'static str, String) {
    match (method, path) {
        ("GET", "/health") => ("200 OK", lifecycle.health_report().to_json()),
        ("POST", "/plan") => {
            let intent = extract_intent(body);
            let plan = lifecycle.plan(intent);
            ("200 OK", plan.to_json())
        }
        ("POST", "/execute") => ("200 OK", execute_tool(lifecycle, body)),
        ("GET", "/") => ("200 OK", r#"{"service":"agentd","endpoints":["GET /health","POST /plan","POST /execute"]}"#.to_string()),
        _ => ("404 Not Found", r#"{"error":"not found"}"#.to_string()),
    }
}

/// 走完整冻结编排链：classify → evaluate → acquire → invoke → verify → commit。
/// 接收 `{"tool":"svc.status","params":{"service":"nginx"}}`。任一步被拒绝即 fail-closed。
/// 全程不自造裁决——每步委托冻结 `Agentd` 方法。
fn execute_tool(lifecycle: &Agentd, body: &str) -> String {
    let tool = extract_field(body, "tool").unwrap_or_default();
    if tool.is_empty() {
        return r#"{"error":"missing \"tool\" field"}"#.to_string();
    }
    // 构造 PlanStep（风险由 classify 裁决，不自造）。
    let step = crate::api::PlanStep {
        id: format!("exec-{}", tool),
        tool: tool.clone(),
        risk: crate::api::RiskClass::ReadOnly, // advisory 初始值；权威风险由 classify 裁决
    };
    let decision = lifecycle.evaluate(&step);
    if !decision.allowed {
        return format!(
            r#"{{"allowed":false,"risk":"{}","reason":"{}"}}"#,
            decision.risk.as_str(),
            crate::api::escape_json(&decision.reason)
        );
    }
    let lease = match lifecycle.acquire(&decision) {
        Ok(lease) => lease,
        Err(reason) => {
            return format!(
                r#"{{"allowed":true,"error":"acquire failed: {}"}}"#,
                crate::api::escape_json(&reason)
            );
        }
    };
    let call = runtime_contracts::SemanticToolCall::new(tool, Vec::<(&str, &str)>::new());
    let effect = lifecycle.invoke(call);
    let verification = lifecycle.verify(&effect);
    let commit = match lifecycle.commit(&effect) {
        Ok(commit) => format!(r#","commit_id":"{}""#, crate::api::escape_json(&commit.0)),
        Err(reason) => format!(
            r#","commit_error":"{}""#,
            crate::api::escape_json(&reason)
        ),
    };
    format!(
        r#"{{"allowed":true,"risk":"{}","lease_id":"{}","effect":{},"verified":{}{}}}"#,
        decision.risk.as_str(),
        crate::api::escape_json(&lease.lease_id),
        effect.to_json(),
        verification.success,
        commit
    )
}

/// 从 POST body `{"intent":"..."}` 提取 intent 字段。容错：无字段则空串。
fn extract_intent(body: &str) -> String {
    extract_field(body, "intent").unwrap_or_default()
}

/// 从 POST body 提取任意字符串字段 `"key":"value"` 的 value。容错返回 None。
/// 极简解析（不引入 JSON 依赖）——发行版最小可用。
fn extract_field(body: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{key}\"");
    let idx = body.find(&pattern)?;
    let after = &body[idx + pattern.len()..];
    let start = after.find('"')?;
    let rest = &after[start + 1..];
    let end = rest.find('"')?;
    Some(rest[..end].replace("\\n", "\n").replace("\\\"", "\"").replace("\\\\", "\\"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::{Agentd, LifecycleConfig};

    fn lifecycle() -> Agentd {
        Agentd::new(LifecycleConfig::default())
    }

    #[test]
    fn route_health_returns_report() {
        let lc = lifecycle();
        let (status, body) = route(&lc, "GET", "/health", "");
        assert_eq!(status, "200 OK");
        assert!(body.contains("\"state\""));
        assert!(body.contains("\"run_mode\""));
    }

    #[test]
    fn route_plan_returns_spec() {
        let lc = lifecycle();
        let (status, body) = route(&lc, "POST", "/plan", r#"{"intent":"check nginx"}"#);
        assert_eq!(status, "200 OK");
        assert!(body.contains("\"intent\""));
        assert!(body.contains("check nginx"));
    }

    #[test]
    fn route_root_lists_endpoints() {
        let lc = lifecycle();
        let (status, body) = route(&lc, "GET", "/", "");
        assert_eq!(status, "200 OK");
        assert!(body.contains("agentd"));
        assert!(body.contains("/health"));
        assert!(body.contains("/execute"));
    }

    #[test]
    fn route_execute_returns_effect() {
        let lc = lifecycle();
        let (status, body) = route(&lc, "POST", "/execute", r#"{"tool":"svc.status"}"#);
        assert_eq!(status, "200 OK");
        // svc.status 是 ReadOnly → allowed:true，返回 lease + effect + commit。
        assert!(body.contains("\"allowed\":true"), "body: {body}");
        assert!(body.contains("\"lease_id\""), "body: {body}");
        assert!(body.contains("\"effect\""), "body: {body}");
    }

    #[test]
    fn route_execute_shell_denied_fail_closed() {
        let lc = lifecycle();
        let (status, body) = route(&lc, "POST", "/execute", r#"{"tool":"shell.exec"}"#);
        assert_eq!(status, "200 OK");
        // shell.exec 被 classify 裁决为 Never → allowed:false（fail-closed）。
        assert!(body.contains("\"allowed\":false"), "body: {body}");
    }

    #[test]
    fn route_execute_missing_tool_returns_error() {
        let lc = lifecycle();
        let (status, body) = route(&lc, "POST", "/execute", r#"{}"#);
        assert_eq!(status, "200 OK");
        assert!(body.contains("\"error\""), "body: {body}");
    }

    #[test]
    fn extract_field_general() {
        assert_eq!(extract_field(r#"{"tool":"svc.status"}"#, "tool"), Some("svc.status".to_string()));
        assert_eq!(extract_field(r#"{"intent":"x"}"#, "intent"), Some("x".to_string()));
        assert_eq!(extract_field(r#"{"a":"1","b":"2"}"#, "b"), Some("2".to_string()));
        assert_eq!(extract_field(r#"{}"#, "missing"), None);
    }

    #[test]
    fn route_unknown_returns_404() {
        let lc = lifecycle();
        let (status, body) = route(&lc, "GET", "/nonexistent", "");
        assert_eq!(status, "404 Not Found");
        assert!(body.contains("not found"));
    }

    #[test]
    fn extract_intent_parses_simple() {
        assert_eq!(extract_intent(r#"{"intent":"check nginx"}"#), "check nginx");
        assert_eq!(extract_intent(r#"{"intent":""}"#), "");
        assert_eq!(extract_intent(r#"{}"#), "");
        assert_eq!(extract_intent(""), "");
    }

    #[test]
    fn extract_intent_unescapes() {
        assert_eq!(
            extract_intent(r#"{"intent":"line1\nline2"}"#),
            "line1\nline2"
        );
    }

    /// 端到端：启动 server 线程，用 TcpStream 客户端请求 /health。
    #[test]
    fn serve_health_end_to_end() {
        use std::net::TcpStream;
        use std::thread;

        let lc = lifecycle();
        let addr = format!("127.0.0.1:{}", 18400 + (std::process::id() % 1000));
        let server_addr = addr.clone();
        let handle = thread::spawn(move || {
            let _ = serve(&lc, &server_addr);
        });

        // 给 server 一点启动时间。
        thread::sleep(std::time::Duration::from_millis(100));

        let mut client = TcpStream::connect(&addr).expect("connect to server");
        client
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .expect("send");
        let mut response = String::new();
        client.read_to_string(&mut response).expect("read");
        assert!(response.starts_with("HTTP/1.1 200 OK"), "got: {response}");
        assert!(response.contains("\"state\""), "body: {response}");

        // 连接关闭后 server 的 incoming() 会继续——释放线程（连接 close 后 handle 阻塞在 accept）。
        drop(handle);
    }
}
