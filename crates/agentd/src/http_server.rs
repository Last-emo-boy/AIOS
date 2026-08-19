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
use std::sync::atomic::{AtomicU64, Ordering};

use crate::lifecycle::Agentd;

/// 单调递增的 run_id 计数器（进程级，避免引入随机/时间源依赖）。
static RUN_SEQ: AtomicU64 = AtomicU64::new(1);

fn next_run_id() -> String {
    format!("run-{}", RUN_SEQ.fetch_add(1, Ordering::Relaxed))
}

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

/// 路由请求到对应的 Agentd 方法。返回 (HTTP status, JSON body)。
fn route(lifecycle: &Agentd, method: &str, path: &str, body: &str) -> (&'static str, String) {
    match (method, path) {
        ("GET", "/health") => ("200 OK", lifecycle.health_report().to_json()),
        ("POST", "/plan") => {
            let intent = extract_intent(body);
            let plan = lifecycle.plan(intent);
            ("200 OK", plan.to_json())
        }
        ("POST", "/execute") => ("200 OK", execute_tool(lifecycle, body)),
        ("GET", "/audit") => ("200 OK", audit_timeline(lifecycle, body)),
        ("GET", "/audit/latest") => ("200 OK", audit_latest(lifecycle)),
        ("GET", "/") => ("200 OK", r#"{"service":"agentd","endpoints":["GET /health","POST /plan","POST /execute","GET /audit?run_id=...","GET /audit/latest"]}"#.to_string()),
        _ => ("404 Not Found", r#"{"error":"not found"}"#.to_string()),
    }
}

/// 走完整冻结编排链：classify → evaluate → acquire → invoke → verify → commit。
/// 接收 `{"tool":"svc.status","params":{"service":"nginx"}}`。任一步被拒绝即 fail-closed。
///
/// **审计路径**：当 Agentd 已 `with_audit` 时，走 `execute_committed` 可审计路径，
/// 每步写 `AuditEvent`，返回中暴露 `run_id`/`commit_id`，audit 写失败则 fail-closed。
/// 未启用 audit 时退回原 stub 路径（向后兼容）。
/// 全程不自造裁决——每步委托冻结 `Agentd` 方法。
fn execute_tool(lifecycle: &Agentd, body: &str) -> String {
    let tool = extract_field(body, "tool").unwrap_or_default();
    if tool.is_empty() {
        return r#"{"error":"missing \"tool\" field"}"#.to_string();
    }

    // 可审计路径：audit 已启用。
    if lifecycle.audit_enabled() {
        let run_id = next_run_id();
        let step = crate::api::PlanStep {
            id: format!("exec-{}", tool),
            tool: tool.clone(),
            risk: crate::api::RiskClass::ReadOnly, // advisory；权威风险由 classify 裁决
        };
        let params = extract_params(body);
        let call = runtime_contracts::SemanticToolCall::new(
            tool,
            params.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect(),
        );
        let outcome = lifecycle.execute_committed(&run_id, &step, call);
        return outcome.to_json();
    }

    // stub 路径（audit 未启用，向后兼容）。
    let step = crate::api::PlanStep {
        id: format!("exec-{}", tool),
        tool: tool.clone(),
        risk: crate::api::RiskClass::ReadOnly,
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

/// `GET /audit?run_id=...` —— 返回指定 run 的审计事件 timeline（JSON 数组）。
/// 无 `run_id` 时返回全部事件。audit 未启用时返回 `audit_disabled`。
fn audit_timeline(lifecycle: &Agentd, query: &str) -> String {
    let Some(journal) = lifecycle.audit() else {
        return r#"{"audit_disabled":true}"#.to_string();
    };
    let run_id = extract_field(query, "run_id");
    let lines = match journal.event_lines() {
        Ok(lines) => lines,
        Err(err) => {
            return format!(
                r#"{{"error":"{}"}}"#,
                crate::api::escape_json(&err.to_string())
            );
        }
    };
    let filtered: Vec<&String> = match &run_id {
        Some(run) => lines
            .iter()
            .filter(|l| l.contains(&format!("\"run_id\":\"{run}\"")))
            .collect(),
        None => lines.iter().collect(),
    };
    let joined = filtered
        .iter()
        .map(|l| l.as_str())
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{"count":{},"events":[{}]}}"#,
        filtered.len(),
        joined
    )
}

/// `GET /audit/latest` —— 返回最近 run 的 run_id（operator 重启后查"上次发生了什么"）。
/// audit 未启用时返回 `audit_disabled`。
fn audit_latest(lifecycle: &Agentd) -> String {
    let Some(journal) = lifecycle.audit() else {
        return r#"{"audit_disabled":true}"#.to_string();
    };
    match journal.latest_run() {
        Ok(Some(run_id)) => format!(
            r#"{{"latest_run_id":"{}"}}"#,
            crate::api::escape_json(&run_id)
        ),
        Ok(None) => r#"{"latest_run_id":null}"#.to_string(),
        Err(err) => format!(r#"{{"error":"{}"}}"#, crate::api::escape_json(&err.to_string())),
    }
}

/// 从 POST body 的 `{"params":{"k":"v",...}}` 提取字符串键值对。
/// 极简解析（无 JSON 依赖）：扫描 `"params"` 对象内的 `"key":"value"` 对。
fn extract_params(body: &str) -> Vec<(String, String)> {
    let Some(params_idx) = body.find("\"params\"") else {
        return Vec::new();
    };
    let after = &body[params_idx..];
    // 找到 params 对象的起始 `{`。
    let Some(brace_start) = after.find('{') else {
        return Vec::new();
    };
    let rest = &after[brace_start + 1..];
    // 找到匹配的 `}`（不处理嵌套——发行版最小可用）。
    let depth_end = rest
        .find('}')
        .unwrap_or(rest.len());
    let obj = &rest[..depth_end];
    // 在对象体内扫描 `"key":"value"` 对。
    let mut pairs = Vec::new();
    let mut cursor = 0usize;
    while let Some(key_quote) = obj[cursor..].find('"') {
        let abs = cursor + key_quote;
        let key_start = abs + 1;
        if let Some(key_end_rel) = obj[key_start..].find('"') {
            let key_end = key_start + key_end_rel;
            let key = &obj[key_start..key_end];
            // 跳过冒号与空白，找值引号。
            let after_key = &obj[key_end + 1..];
            if let Some(colon) = after_key.find(':') {
                let val_region = &after_key[colon + 1..];
                if let Some(val_quote) = val_region.find('"') {
                    let val_start = val_quote + 1;
                    if let Some(val_end) = val_region[val_start..].find('"') {
                        let value =
                            &val_region[val_start..val_start + val_end];
                        pairs.push((key.to_string(), value.to_string()));
                        cursor = key_end + 1 + colon + 1 + val_start + val_end + 1;
                        continue;
                    }
                }
            }
        }
        break;
    }
    pairs
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

    /// 带 audit journal + 真实执行后端的 lifecycle（每个测试独立临时文件）。
    fn lifecycle_with_audit() -> (Agentd, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "agentd-http-audit-{}-{}.jsonl",
            std::process::id(),
            RUN_SEQ.fetch_add(1000, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&path);
        let journal = crate::audit::AuditJournal::new(&path);
        let lc = Agentd::new(LifecycleConfig::default()).with_audit_and_executor(journal);
        (lc, path)
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

    // ===== 阶段 W：可审计 /execute 路径 =====

    #[test]
    fn execute_with_audit_returns_run_id_and_commit() {
        let (lc, _path) = lifecycle_with_audit();
        let (status, body) = route(&lc, "POST", "/execute", r#"{"tool":"svc.status","params":{"service":"nginx"}}"#);
        assert_eq!(status, "200 OK");
        // 可审计 + 真实执行路径返回 committed:true + run_id + commit_id。
        assert!(body.contains("\"committed\":true"), "body: {body}");
        assert!(body.contains("\"run_id\":\"run-"), "body: {body}");
        assert!(body.contains("\"commit_id\":\"commit-stub-001\""), "body: {body}");
    }

    #[test]
    fn execute_with_audit_persists_events_to_journal() {
        let (lc, path) = lifecycle_with_audit();
        let _ = route(&lc, "POST", "/execute", r#"{"tool":"svc.status","params":{"service":"nginx"}}"#);
        // 重开 journal（模拟重启），事件应已落盘。
        let journal = crate::audit::AuditJournal::new(&path);
        let lines = journal.event_lines().expect("read");
        // 完整链：PolicyEvaluated + ApprovalBound + EffectPrepared + EffectObserved + CommitSealed。
        assert!(lines.iter().any(|l| l.contains("PolicyEvaluated")), "no policy event");
        assert!(lines.iter().any(|l| l.contains("CommitSealed")), "no commit event");
        assert!(lines.iter().any(|l| l.contains("decision=allow")), "no allow decision");
        assert!(lines.iter().any(|l| l.contains("\"run_id\":\"run-")), "no run_id in events");
        // 真实执行：summary 应含 svc.status 的真实观测（systemd queryable）。
        assert!(lines.iter().any(|l| l.contains("queryable=true")), "no real exec observation");
    }

    #[test]
    fn execute_shell_with_audit_denied_and_recorded() {
        let (lc, path) = lifecycle_with_audit();
        let (_status, body) = route(&lc, "POST", "/execute", r#"{"tool":"shell.exec"}"#);
        // 被拒。
        assert!(body.contains("\"allowed\":false"), "body: {body}");
        assert!(body.contains("\"committed\":false"), "body: {body}");
        // 被拒步也记 audit（decision=deny）。
        let journal = crate::audit::AuditJournal::new(&path);
        let lines = journal.event_lines().expect("read");
        assert!(lines.iter().any(|l| l.contains("decision=deny")), "no deny event");
    }

    #[test]
    fn audit_timeline_endpoint_returns_events_by_run_id() {
        let (lc, _path) = lifecycle_with_audit();
        // 先执行一次，拿到 run_id。
        let (_s, body) = route(&lc, "POST", "/execute", r#"{"tool":"svc.status","params":{"service":"nginx"}}"#);
        let run_id = extract_field(&body, "run_id").expect("run_id in response");
        // 再查 timeline。
        let query = format!("{{\"run_id\":\"{}\"}}", run_id);
        let (status, timeline) = route(&lc, "GET", "/audit", &query);
        assert_eq!(status, "200 OK");
        assert!(timeline.contains("\"count\":5"), "expected 5 events, got: {timeline}");
        assert!(timeline.contains(&run_id), "timeline missing run_id");
    }

    #[test]
    fn audit_latest_endpoint_returns_latest_run() {
        let (lc, _path) = lifecycle_with_audit();
        let (status, empty) = route(&lc, "GET", "/audit/latest", "");
        assert_eq!(status, "200 OK");
        assert!(empty.contains("\"latest_run_id\":null"), "expected null, got: {empty}");
        let _ = route(&lc, "POST", "/execute", r#"{"tool":"svc.status","params":{"service":"nginx"}}"#);
        let (_s, latest) = route(&lc, "GET", "/audit/latest", "");
        assert!(latest.contains("\"latest_run_id\":\"run-"), "expected run id, got: {latest}");
    }

    #[test]
    fn audit_endpoints_disabled_without_journal() {
        let lc = lifecycle(); // 无 audit
        let (_s, timeline) = route(&lc, "GET", "/audit", "");
        assert!(timeline.contains("\"audit_disabled\":true"), "got: {timeline}");
        let (_s, latest) = route(&lc, "GET", "/audit/latest", "");
        assert!(latest.contains("\"audit_disabled\":true"), "got: {latest}");
    }

    #[test]
    fn execute_missing_required_param_fail_closed() {
        let (lc, _path) = lifecycle_with_audit();
        // svc.status 缺 service 参数 → ToolRouter route 拒绝 → fail-closed。
        let (_s, body) = route(&lc, "POST", "/execute", r#"{"tool":"svc.status"}"#);
        assert!(body.contains("\"failed_closed\":true"), "body: {body}");
        assert!(body.contains("missing required parameter"), "body: {body}");
    }

    #[test]
    fn execute_with_params_passes_through() {
        let (lc, _path) = lifecycle_with_audit();
        let (_s, body) = route(
            &lc,
            "POST",
            "/execute",
            r#"{"tool":"svc.status","params":{"service":"nginx"}}"#,
        );
        assert!(body.contains("\"committed\":true"), "body: {body}");
    }

    #[test]
    fn execute_fs_read_real_observation() {
        // 写临时文件，用 fs.read 真实读取。
        let file = std::env::temp_dir().join(format!("agentd-fsread-{}.txt", std::process::id()));
        std::fs::write(&file, "agentd release test").expect("write");
        let path_str = file.to_str().unwrap().to_string();
        let (lc, _j) = lifecycle_with_audit();
        let body = format!(r#"{{"tool":"fs.read","params":{{"path":"{}"}}}}"#, path_str);
        let (_s, resp) = route(&lc, "POST", "/execute", &body);
        assert!(resp.contains("\"committed\":true"), "body: {resp}");
        // 真实执行：effect summary 含 bytes + preview。
        assert!(resp.contains("bytes=19"), "body: {resp}");
        assert!(resp.contains("agentd release test"), "body: {resp}");
        let _ = std::fs::remove_file(&file);
    }

    #[test]
    fn extract_params_parses_simple_object() {
        assert_eq!(
            extract_params(r#"{"params":{"service":"nginx","port":"80"}}"#),
            vec![("service".to_string(), "nginx".to_string()), ("port".to_string(), "80".to_string())]
        );
        assert!(extract_params(r#"{"tool":"x"}"#).is_empty());
        assert!(extract_params(r#"{"params":{}}"#).is_empty());
    }

}
