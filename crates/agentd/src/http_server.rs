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
/// 终止 server（记录到 stderr，继续 accept 下一个）。`max_replans` 透传给
/// `POST /run` 的 agent 执行闭环。
pub fn serve(lifecycle: &Agentd, addr: &str, max_replans: usize) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    eprintln!("agentd http api listening on {addr}");
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                if let Err(err) = handle_connection(&mut stream, lifecycle, max_replans) {
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
    max_replans: usize,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    // 读请求行 + headers，再按 Content-Length 读 body。
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let raw_path = parts.next().unwrap_or("/");
    // 剥离 query string（? 之后）做路由匹配；query 串作为 GET 端点的参数来源。
    let (path, query) = match raw_path.split_once('?') {
        Some((p, q)) => (p, q),
        None => (raw_path, ""),
    };

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

    // GET 请求用 query string 作为参数来源；POST 用 body。空 query 时用空串。
    let params: &str = if content_length > 0 { &body_str } else { query };
    let (status, content) = route(lifecycle, method, path, params, max_replans);
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{content}",
        content.len()
    );
    stream.write_all(response.as_bytes())?;
    Ok(())
}

/// 路由请求到对应的 Agentd 方法。返回 (HTTP status, JSON body)。
fn route(
    lifecycle: &Agentd,
    method: &str,
    path: &str,
    body: &str,
    max_replans: usize,
) -> (&'static str, String) {
    match (method, path) {
        ("GET", "/health") => ("200 OK", lifecycle.health_report().to_json()),
        ("POST", "/plan") => {
            let intent = extract_intent(body);
            let plan = lifecycle.plan(intent);
            ("200 OK", plan.to_json())
        }
        ("POST", "/run") => ("200 OK", run_intent(lifecycle, body, max_replans)),
        ("POST", "/execute") => ("200 OK", execute_tool(lifecycle, body)),
        ("GET", "/audit") => ("200 OK", audit_timeline(lifecycle, body)),
        ("GET", "/audit/latest") => ("200 OK", audit_latest(lifecycle)),
        ("GET", "/recover") => ("200 OK", recover_run(lifecycle, body)),
        ("GET", "/config") => ("200 OK", config_diagnostics(lifecycle)),
        ("GET", "/") => ("200 OK", r#"{"service":"agentd","endpoints":["GET /health","POST /plan","POST /run","POST /execute","GET /audit?run_id=...","GET /audit/latest","GET /recover?run_id=...","GET /config"]}"#.to_string()),
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

/// `POST /run` —— 单次提交意图即驱动完整 agent 执行闭环：
/// LLM 产意图 → bridge 验证 → run_plan_guarded 裁决+执行 → 反馈 → replan。
///
/// 请求 body：`{"intent":"...","run_id":"run-xxx"(可选),"approve":true(可选)}`。
/// - `run_id` 缺省时自动生成（`run-N`）。
/// - `approve` 缺省 `false`：只读步放行，执行类步被审批门拒（operator 经审计看到后可带
///   `approve=true` 重跑）。
///
/// 响应：
/// - 闭环跑通：`{"ran":true,"run_id":"...","completed":<bool>,"aborted":<bool>,
///   "fail_closed":<bool>,"attempts":N,"summary":"...","trace":[...]}`
/// - 三件套未配齐（planner/audit/executor）：`{"ran":false,"reason":"..."}`
/// - intent 缺失：`{"error":"missing intent"}`
///
/// **冻结控制平面哲学**：本端点只编排（调 `run_intent`），不自造裁决。裁决全在
/// `run_plan_guarded` 的 policy / source-to-sink / 审批门 + 桥接器的 ToolRouter 内。
fn run_intent(lifecycle: &Agentd, body: &str, max_replans: usize) -> String {
    let intent = extract_intent(body);
    if intent.is_empty() {
        return r#"{"error":"missing intent"}"#.to_string();
    }
    let run_id = extract_field(body, "run_id").unwrap_or_else(next_run_id);
    let approve = extract_bool(body, "approve");

    match lifecycle.run_intent(&intent, "operator", &run_id, approve, max_replans) {
        Some(outcome) => outcome_to_json(&outcome, &run_id),
        None => {
            // fail-closed：三件套未配齐。报告具体缺什么，便于 operator 排障。
            let missing = [
                ("planner", !lifecycle.planner_enabled()),
                ("audit", !lifecycle.audit_enabled()),
                ("executor", !lifecycle.executor_enabled()),
            ]
            .iter()
            .filter(|(_, missing)| *missing)
            .map(|(name, _)| *name)
            .collect::<Vec<_>>()
            .join(", ");
            format!(
                r#"{{"ran":false,"reason":"not configured: {missing}"}}"#,
                missing = crate::api::escape_json(&missing)
            )
        }
    }
}

/// 把 `ReplanOutcome` 序列化为 JSON（advisory 观测，不含 secret——summary 经 runner
/// 内 `redact_summary` 脱敏，reason 经 `extract_feedback` 净化）。
fn outcome_to_json(outcome: &llm_planner::runner::ReplanOutcome, run_id: &str) -> String {
    let trace_json = outcome
        .trace
        .iter()
        .map(trace_span_to_json)
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{"ran":true,"run_id":"{}","completed":{},"aborted":{},"fail_closed":{},"attempts":{},"summary":"{}","trace":[{}]}}"#,
        crate::api::escape_json(run_id),
        outcome.completed(),
        outcome.aborted(),
        outcome.fail_closed(),
        outcome.attempts,
        crate::api::escape_json(&outcome.summary()),
        trace_json
    )
}

/// 单个 `TraceSpan` 序列化（advisory，仅观测字段）。
fn trace_span_to_json(span: &llm_planner::runner::TraceSpan) -> String {
    format!(
        r#"{{"attempt":{},"provider":"{}","model":"{}","step_count":{},"state":"{:?}","cause":"{}","elapsed_ms":{},"parallel_depth":{},"max_parallel_width":{}}}"#,
        span.attempt,
        crate::api::escape_json(&span.provider),
        crate::api::escape_json(&span.model),
        span.step_count,
        span.state,
        crate::api::escape_json(&llm_planner::runner::trace_cause_str(&span.cause)),
        span.elapsed_ms,
        span.parallel_depth,
        span.max_parallel_width
    )
}

/// 从 POST body 提取布尔字段 `"key":true|false`。缺省 `false`。
fn extract_bool(body: &str, key: &str) -> bool {
    let pattern = format!("\"{key}\":");
    let Some(idx) = body.find(&pattern) else {
        return false;
    };
    let rest = &body[idx + pattern.len()..];
    rest.trim_start().starts_with("true")
}

/// `GET /audit?run_id=...` —— 返回指定 run 的审计事件 timeline（JSON 数组）。
/// 无 `run_id` 时返回全部事件。audit 未启用时返回 `audit_disabled`。
fn audit_timeline(lifecycle: &Agentd, query: &str) -> String {
    let Some(journal) = lifecycle.audit() else {
        return r#"{"audit_disabled":true}"#.to_string();
    };
    let run_id = extract_query(query, "run_id");
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

/// `GET /recover?run_id=...` —— 扫描指定 run 的未完成效应（EffectPrepared 但未 CommitSealed/RollbackObserved）。
/// 发行版关键能力：operator 重启后查"上次有哪些未完成效应需要恢复"。
/// 走 `RecoveryReconciler`（记 RecoveryStarted/Completed 事件，分类每项）。
/// audit 未启用时返回 `audit_disabled`。
fn recover_run(lifecycle: &Agentd, query: &str) -> String {
    use crate::recovery::RecoveryReconciler;
    let Some(journal) = lifecycle.audit() else {
        return r#"{"audit_disabled":true}"#.to_string();
    };
    let Some(run_id) = extract_query(query, "run_id") else {
        return r#"{"error":"missing run_id"}"#.to_string();
    };
    match RecoveryReconciler.reconcile(journal, &run_id) {
        Ok(report) => report.to_json(),
        Err(err) => format!(
            r#"{{"error":"{}"}}"#,
            crate::api::escape_json(&err.to_string())
        ),
    }
}

/// `GET /config` —— 当前运行配置诊断（operator 查"audit/executor 是否启用、run_mode 是什么"）。
/// 复用 `health_report` 字段 + audit/executor 启用状态，不引入额外 Agentd 字段。
fn config_diagnostics(lifecycle: &Agentd) -> String {
    let health = lifecycle.health_report().to_json();
    // health_report 已含 state/run_mode/planner_mode/arbitrary_shell_enabled/module_count。
    // 追加 audit_enabled / executor_enabled（编排链能力开关）。
    format!(
        "{}, \"audit_enabled\":{}, \"executor_enabled\":{}}}",
        &health[..health.len() - 1], // 去掉末尾 }
        lifecycle.audit_enabled(),
        lifecycle.executor_enabled(),
    )
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

/// 从 URL query string（`key=value`，& 分隔）或 JSON body 提取字段值。
/// GET 端点（/audit、/recover）的 run_id 经此提取。容错返回 None。
fn extract_query(value: &str, key: &str) -> Option<String> {
    // 先尝试 URL query 格式 `key=value`。
    let needle = format!("{key}=");
    for part in value.split('&') {
        if let Some(rest) = part.strip_prefix(&needle) {
            let v = rest.split('&').next().unwrap_or("");
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    // 退回 JSON 字段提取（兼容测试用 JSON body 传参）。
    extract_field(value, key)
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
        let (status, body) = route(&lc, "GET", "/health", "", 3);
        assert_eq!(status, "200 OK");
        assert!(body.contains("\"state\""));
        assert!(body.contains("\"run_mode\""));
    }

    #[test]
    fn route_plan_returns_spec() {
        let lc = lifecycle();
        let (status, body) = route(&lc, "POST", "/plan", r#"{"intent":"check nginx"}"#, 3);
        assert_eq!(status, "200 OK");
        assert!(body.contains("\"intent\""));
        assert!(body.contains("check nginx"));
    }

    #[test]
    fn route_root_lists_endpoints() {
        let lc = lifecycle();
        let (status, body) = route(&lc, "GET", "/", "", 3);
        assert_eq!(status, "200 OK");
        assert!(body.contains("agentd"));
        assert!(body.contains("/health"));
        assert!(body.contains("/execute"));
    }

    #[test]
    fn route_execute_returns_effect() {
        let lc = lifecycle();
        let (status, body) = route(&lc, "POST", "/execute", r#"{"tool":"svc.status"}"#, 3);
        assert_eq!(status, "200 OK");
        // svc.status 是 ReadOnly → allowed:true，返回 lease + effect + commit。
        assert!(body.contains("\"allowed\":true"), "body: {body}");
        assert!(body.contains("\"lease_id\""), "body: {body}");
        assert!(body.contains("\"effect\""), "body: {body}");
    }

    #[test]
    fn route_execute_shell_denied_fail_closed() {
        let lc = lifecycle();
        let (status, body) = route(&lc, "POST", "/execute", r#"{"tool":"shell.exec"}"#, 3);
        assert_eq!(status, "200 OK");
        // shell.exec 被 classify 裁决为 Never → allowed:false（fail-closed）。
        assert!(body.contains("\"allowed\":false"), "body: {body}");
    }

    #[test]
    fn route_execute_missing_tool_returns_error() {
        let lc = lifecycle();
        let (status, body) = route(&lc, "POST", "/execute", r#"{}"#, 3);
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
        let (status, body) = route(&lc, "GET", "/nonexistent", "", 3);
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
            let _ = serve(&lc, &server_addr, 3);
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
        let (status, body) = route(&lc, "POST", "/execute", r#"{"tool":"svc.status","params":{"service":"nginx"}}"#, 3);
        assert_eq!(status, "200 OK");
        // 可审计 + 真实执行路径返回 committed:true + run_id + commit_id。
        assert!(body.contains("\"committed\":true"), "body: {body}");
        assert!(body.contains("\"run_id\":\"run-"), "body: {body}");
        assert!(body.contains("\"commit_id\":\"commit-stub-001\""), "body: {body}");
    }

    #[test]
    fn execute_with_audit_persists_events_to_journal() {
        let (lc, path) = lifecycle_with_audit();
        let _ = route(&lc, "POST", "/execute", r#"{"tool":"svc.status","params":{"service":"nginx"}}"#, 3);
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
        let (_status, body) = route(&lc, "POST", "/execute", r#"{"tool":"shell.exec"}"#, 3);
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
        let (_s, body) = route(&lc, "POST", "/execute", r#"{"tool":"svc.status","params":{"service":"nginx"}}"#, 3);
        let run_id = extract_field(&body, "run_id").expect("run_id in response");
        // 再查 timeline。
        let query = format!("{{\"run_id\":\"{}\"}}", run_id);
        let (status, timeline) = route(&lc, "GET", "/audit", &query, 3);
        assert_eq!(status, "200 OK");
        assert!(timeline.contains("\"count\":5"), "expected 5 events, got: {timeline}");
        assert!(timeline.contains(&run_id), "timeline missing run_id");
    }

    #[test]
    fn audit_latest_endpoint_returns_latest_run() {
        let (lc, _path) = lifecycle_with_audit();
        let (status, empty) = route(&lc, "GET", "/audit/latest", "", 3);
        assert_eq!(status, "200 OK");
        assert!(empty.contains("\"latest_run_id\":null"), "expected null, got: {empty}");
        let _ = route(&lc, "POST", "/execute", r#"{"tool":"svc.status","params":{"service":"nginx"}}"#, 3);
        let (_s, latest) = route(&lc, "GET", "/audit/latest", "", 3);
        assert!(latest.contains("\"latest_run_id\":\"run-"), "expected run id, got: {latest}");
    }

    #[test]
    fn audit_endpoints_disabled_without_journal() {
        let lc = lifecycle(); // 无 audit
        let (_s, timeline) = route(&lc, "GET", "/audit", "", 3);
        assert!(timeline.contains("\"audit_disabled\":true"), "got: {timeline}");
        let (_s, latest) = route(&lc, "GET", "/audit/latest", "", 3);
        assert!(latest.contains("\"audit_disabled\":true"), "got: {latest}");
    }

    #[test]
    fn execute_missing_required_param_fail_closed() {
        let (lc, _path) = lifecycle_with_audit();
        // svc.status 缺 service 参数 → ToolRouter route 拒绝 → fail-closed。
        let (_s, body) = route(&lc, "POST", "/execute", r#"{"tool":"svc.status"}"#, 3);
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
            3,
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
        let (_s, resp) = route(&lc, "POST", "/execute", &body, 3);
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


    // ===== 阶段 Y：/recover 端点 + query string 解析 =====

    #[test]
    fn extract_query_parses_url_query_string() {
        assert_eq!(extract_query("run_id=run-1", "run_id"), Some("run-1".to_string()));
        assert_eq!(extract_query("foo=bar&run_id=run-2", "run_id"), Some("run-2".to_string()));
        assert_eq!(extract_query("run_id=run-3&extra=x", "run_id"), Some("run-3".to_string()));
        // 空 value 不返回。
        assert_eq!(extract_query("run_id=", "run_id"), None);
        // 兼容 JSON body。
        assert_eq!(extract_query(r#"{"run_id":"run-4"}"#, "run_id"), Some("run-4".to_string()));
        assert_eq!(extract_query("missing", "run_id"), None);
    }

    #[test]
    fn recover_endpoint_returns_empty_for_completed_run() {
        let (lc, _path) = lifecycle_with_audit();
        // 执行一个完整 run（committed）。
        let (_s, body) = route(&lc, "POST", "/execute", r#"{"tool":"svc.status","params":{"service":"nginx"}}"#, 3);
        let run_id = extract_field(&body, "run_id").expect("run_id");
        // recover 该 run → 无未完成效应（已 CommitSealed）。
        let (status, resp) = route(&lc, "GET", "/recover", &format!("run_id={}", run_id), 3);
        assert_eq!(status, "200 OK");
        assert!(resp.contains(&format!("\"run_id\":\"{}\"", run_id)), "body: {resp}");
        assert!(resp.contains("\"items\":[]"), "expected no unresolved, got: {resp}");
    }

    #[test]
    fn recover_endpoint_requires_run_id() {
        let (lc, _path) = lifecycle_with_audit();
        let (_s, resp) = route(&lc, "GET", "/recover", "", 3);
        assert!(resp.contains("missing run_id"), "body: {resp}");
    }

    #[test]
    fn recover_endpoint_disabled_without_journal() {
        let lc = lifecycle(); // 无 audit
        let (_s, resp) = route(&lc, "GET", "/recover", "run_id=run-x", 3);
        assert!(resp.contains("\"audit_disabled\":true"), "body: {resp}");
    }

    #[test]
    fn recover_endpoint_detects_unresolved_prepared_effect() {
        let (lc, path) = lifecycle_with_audit();
        // 手动注入一个未完成的 EffectPrepared 事件（无 CommitSealed）。
        let journal = crate::audit::AuditJournal::new(&path);
        journal
            .append(&crate::audit::AuditEvent::new(
                crate::audit::AuditEventType::EffectPrepared,
                "run-stuck",
                "step-stuck",
                "operator",
                "prepared fs.write.diff",
            ))
            .expect("append");
        let (_s, resp) = route(&lc, "GET", "/recover", "run_id=run-stuck", 3);
        // 写操作未 sealed → 需要 rollback，需人工确认。
        assert!(resp.contains("\"run_id\":\"run-stuck\""), "body: {resp}");
        assert!(resp.contains("\"requires_human_confirmation\":true"), "body: {resp}");
    }

    #[test]
    fn audit_timeline_supports_url_query_string() {
        let (lc, _path) = lifecycle_with_audit();
        let (_s, body) = route(&lc, "POST", "/execute", r#"{"tool":"svc.status","params":{"service":"nginx"}}"#, 3);
        let run_id = extract_field(&body, "run_id").expect("run_id");
        // 用 URL query 格式（而非 JSON body）查 timeline。
        let (status, timeline) = route(&lc, "GET", "/audit", &format!("run_id={}", run_id), 3);
        assert_eq!(status, "200 OK");
        assert!(timeline.contains("\"count\":5"), "got: {timeline}");
    }

    #[test]
    fn config_endpoint_reports_audit_and_executor_enabled() {
        let (lc, _path) = lifecycle_with_audit();
        let (status, body) = route(&lc, "GET", "/config", "", 3);
        assert_eq!(status, "200 OK");
        assert!(body.contains("\"audit_enabled\":true"), "body: {body}");
        assert!(body.contains("\"executor_enabled\":true"), "body: {body}");
        assert!(body.contains("\"run_mode\":\"local-only\""), "body: {body}");
    }

    #[test]
    fn config_endpoint_reports_disabled_without_audit() {
        let lc = lifecycle();
        let (_s, body) = route(&lc, "GET", "/config", "", 3);
        assert!(body.contains("\"audit_enabled\":false"), "body: {body}");
        assert!(body.contains("\"executor_enabled\":false"), "body: {body}");
    }

    // ===== POST /run：完整 agent 执行闭环端点 =====

    /// OPENAI 兼容 envelope（提议 svc.status + fs.read，均只读，approve=false 可放行）。
    const RUN_ENVELOPE: &str = r#"{
        "id": "chatcmpl-1", "object": "chat.completion",
        "choices": [{"index": 0, "finish_reason": "stop",
         "message": {"role": "assistant",
            "content": "{\"steps\":[{\"tool\":\"svc.status\",\"resource\":\"nginx\",\"params\":{\"service\":\"nginx\"}},{\"tool\":\"fs.read\",\"resource\":\"cfg\",\"params\":{\"path\":\"/etc/hostname\"}}]}"}}
        ]
    }"#;

    /// 三件套齐全的 lifecycle（planner + audit + executor）。
    fn lifecycle_with_planner() -> Agentd {
        let path = std::env::temp_dir().join(format!(
            "agentd-http-run-{}-{}.jsonl",
            std::process::id(),
            RUN_SEQ.fetch_add(1000, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&path);
        let journal = crate::audit::AuditJournal::new(&path);
        let provider = llm_planner::RecordedProvider::openai("gpt-4o-mini", RUN_ENVELOPE);
        Agentd::new(LifecycleConfig::default())
            .with_planner(Box::new(provider))
            .with_audit_and_executor(journal)
    }

    #[test]
    fn route_run_completes_full_loop() {
        let lc = lifecycle_with_planner();
        let (status, body) = route(
            &lc,
            "POST",
            "/run",
            r#"{"intent":"inspect nginx"}"#,
            2,
        );
        assert_eq!(status, "200 OK");
        assert!(body.contains("\"ran\":true"), "body: {body}");
        assert!(body.contains("\"completed\":true"), "body: {body}");
        assert!(body.contains("\"attempts\":1"), "body: {body}");
        assert!(body.contains("\"run_id\":\"run-"), "body: {body}");
        assert!(body.contains("\"trace\":["), "body: {body}");
    }

    #[test]
    fn route_run_uses_provided_run_id() {
        let lc = lifecycle_with_planner();
        let (status, body) = route(
            &lc,
            "POST",
            "/run",
            r#"{"intent":"inspect nginx","run_id":"my-run-42"}"#,
            2,
        );
        assert_eq!(status, "200 OK");
        assert!(body.contains("\"run_id\":\"my-run-42\""), "body: {body}");
    }

    #[test]
    fn route_run_missing_intent_returns_error() {
        let lc = lifecycle_with_planner();
        let (status, body) = route(&lc, "POST", "/run", r#"{}"#, 2);
        assert_eq!(status, "200 OK");
        assert!(body.contains("\"error\""), "body: {body}");
        assert!(body.contains("missing intent"), "body: {body}");
    }

    #[test]
    fn route_run_fail_closed_when_not_configured() {
        // 仅 audit+executor，无 planner → ran:false，报告 missing planner。
        let (lc, _path) = lifecycle_with_audit();
        let (status, body) = route(&lc, "POST", "/run", r#"{"intent":"x"}"#, 2);
        assert_eq!(status, "200 OK");
        assert!(body.contains("\"ran\":false"), "body: {body}");
        assert!(body.contains("planner"), "body: {body}");
    }

    #[test]
    fn route_run_lists_in_root_endpoints() {
        let lc = lifecycle();
        let (_s, body) = route(&lc, "GET", "/", "", 3);
        assert!(body.contains("/run"), "root 应列出 /run: {body}");
    }


}
