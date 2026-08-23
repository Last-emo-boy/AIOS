//! 真实工具执行后端 —— 把 `Agentd::invoke` 从固定 stub Effect 升级为真实观测。
//!
//! cp-llm 阶段 X：发行版关键缺口——delegate 研究指出"彻底移除 stub-success"。
//! `ToolRouter::route()` 只做**裁决**（验证工具名/参数 schema/风险），不执行。
//! 本模块提供 `ToolExecutor` trait + `StdToolExecutor`：在裁决通过后执行只读工具，
//! 产生真实 observed summary（事实）与显式 success bit，但仍经冻结 `verify` 裁决。
//!
//! **冻结控制平面哲学**：执行后端只产生**事实**（observed summary），不做裁决。
//! 裁决链 classify → evaluate → acquire → [执行] → verify → commit 不变；
//! 执行后端的产物是 verify 的输入，不是裁决本身。`#![forbid(unsafe_code)]` 适用
//! （纯 `std` 系统调用是安全抽象）。
//!
//! 真实执行范围（仅 ReadOnly，零外部依赖）：
//! - `fs.read`：读文件内容（`std::fs::read_to_string`），返回前 N 字节 + 字节数。
//! - `http.check`：TCP 探活（`std::net::TcpStream::connect`），返回连通性 + 耗时。
//! - `svc.status`：查 `/proc` 或服务状态（最小实现：报告进程可查性）。
//! - `audit.show` / `audit.project`：查 audit journal（需注入 journal 句柄）。
//!
//! 其余工具返回 "not-implemented: observed=false"（fail-safe，不谎报成功）。
#![forbid(unsafe_code)]

use std::net::ToSocketAddrs;
use std::time::{Duration, Instant};

use crate::api::Effect;
use crate::audit::AuditJournal;
use crate::tools::RoutedToolCall;

/// 工具执行后端抽象。接收已裁决的 `RoutedToolCall`，返回真实 `Effect`。
///
/// 实现只产生 observed summary（事实），不裁决。裁决仍由 `verify` 做。
/// `Send + Sync` 让 `Agentd` 可跨线程（daemon 单线程，但测试与未来并发调度需要）。
pub trait ToolExecutor: std::fmt::Debug + Send + Sync {
    fn execute(&self, call: &RoutedToolCall) -> Effect;
}

/// 默认纯 std 执行后端。可选注入 audit journal 供 `audit.show` 等查询。
#[derive(Debug, Default)]
pub struct StdToolExecutor {
    /// `audit.show` / `audit.project` 查询的 journal（None 时这些工具返回 observed=false）。
    audit: Option<AuditJournal>,
}

impl StdToolExecutor {
    pub fn new() -> Self {
        Self { audit: None }
    }

    /// 注入 audit journal，启用 `audit.show` / `audit.project` 真实查询。
    pub fn with_audit(mut self, audit: AuditJournal) -> Self {
        self.audit = Some(audit);
        self
    }
}

impl ToolExecutor for StdToolExecutor {
    fn execute(&self, call: &RoutedToolCall) -> Effect {
        let tool = call.tool;
        let params: std::collections::HashMap<&str, &str> = call
            .normalized_params
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        match tool {
            "fs.read" => exec_fs_read(&params),
            "http.check" => exec_http_check(&params),
            "svc.status" => exec_svc_status(&params),
            "audit.show" | "audit.project" => exec_audit_query(tool, &params, self.audit.as_ref()),
            _ => Effect {
                prepared: true,
                observed: false,
                succeeded: false,
                tool: tool.to_string(),
                summary: format!("not-implemented: tool={tool} no real backend"),
            },
        }
    }
}

/// `fs.read`：读文件内容。返回前 256 字节预览 + 总字节数。
fn exec_fs_read(params: &std::collections::HashMap<&str, &str>) -> Effect {
    let Some(path) = params.get("path") else {
        return Effect {
            prepared: true,
            observed: false,
            succeeded: false,
            tool: "fs.read".to_string(),
            summary: "missing path".to_string(),
        };
    };
    match std::fs::read(path) {
        Ok(bytes) => {
            let total = bytes.len();
            let preview_len = total.min(256);
            let preview = String::from_utf8_lossy(&bytes[..preview_len]);
            Effect {
                prepared: true,
                observed: true,
                succeeded: true,
                tool: "fs.read".to_string(),
                summary: format!(
                    "read path={} bytes={} preview={:?}",
                    redact_path(path),
                    total,
                    preview.replace('\n', "\\n")
                ),
            }
        }
        Err(err) => Effect {
            prepared: true,
            observed: true,
            succeeded: false,
            tool: "fs.read".to_string(),
            summary: format!("read failed path={} error={}", redact_path(path), err),
        },
    }
}

/// `http.check`：TCP 探活。返回连通性 + 耗时（ms）。
fn exec_http_check(params: &std::collections::HashMap<&str, &str>) -> Effect {
    let Some(url) = params.get("url") else {
        return Effect {
            prepared: true,
            observed: false,
            succeeded: false,
            tool: "http.check".to_string(),
            summary: "missing url".to_string(),
        };
    };
    let host_port = strip_scheme(url);
    let start = Instant::now();
    let connect_result = host_port
        .to_socket_addrs()
        .and_then(|mut addrs| {
            addrs
                .next()
                .ok_or_else(|| std::io::Error::other("address resolved to no endpoints"))
        })
        .and_then(|addr| std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(3)));
    match connect_result {
        Ok(_) => {
            let elapsed = start.elapsed().as_millis();
            Effect {
                prepared: true,
                observed: true,
                succeeded: true,
                tool: "http.check".to_string(),
                summary: format!("alive url={} elapsed_ms={}", redact_url(url), elapsed),
            }
        }
        Err(err) => {
            let elapsed = start.elapsed().as_millis();
            Effect {
                prepared: true,
                observed: true,
                succeeded: false,
                tool: "http.check".to_string(),
                summary: format!(
                    "dead url={} elapsed_ms={} error={}",
                    redact_url(url),
                    elapsed,
                    err
                ),
            }
        }
    }
}

/// `svc.status`：通过 procfs 查询匹配的进程，而不是把 systemd 是否存在当作服务状态。
/// 查询本身成功时 `succeeded=true`；服务未运行由 `alive=false` 表示，不是查询失败。
fn exec_svc_status(params: &std::collections::HashMap<&str, &str>) -> Effect {
    let service = params.get("service").copied().unwrap_or("unknown");
    let entries = match std::fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(err) => {
            return Effect {
                prepared: true,
                observed: true,
                succeeded: false,
                tool: "svc.status".to_string(),
                summary: format!("status query failed service={service} source=procfs error={err}"),
            };
        }
    };
    let mut matches = 0usize;
    for entry in entries.flatten() {
        let pid = entry.file_name();
        if !pid.as_encoded_bytes().iter().all(u8::is_ascii_digit) {
            continue;
        }
        let process_dir = entry.path();
        let comm_matches = std::fs::read_to_string(process_dir.join("comm"))
            .is_ok_and(|comm| comm.trim() == service);
        let cmdline_matches = std::fs::read(process_dir.join("cmdline")).is_ok_and(|cmdline| {
            cmdline
                .split(|byte| *byte == 0)
                .filter_map(|arg| std::str::from_utf8(arg).ok())
                .any(|arg| {
                    std::path::Path::new(arg)
                        .file_name()
                        .and_then(|name| name.to_str())
                        == Some(service)
                })
        });
        if comm_matches || cmdline_matches {
            matches += 1;
        }
    }
    Effect {
        prepared: true,
        observed: true,
        succeeded: true,
        tool: "svc.status".to_string(),
        summary: format!(
            "service={} alive={} matches={} source=procfs",
            service,
            matches > 0,
            matches
        ),
    }
}

/// `audit.show` / `audit.project`：查 audit journal。
fn exec_audit_query(
    tool: &str,
    params: &std::collections::HashMap<&str, &str>,
    audit: Option<&AuditJournal>,
) -> Effect {
    let Some(journal) = audit else {
        return Effect {
            prepared: true,
            observed: false,
            succeeded: false,
            tool: tool.to_string(),
            summary: "no audit journal attached".to_string(),
        };
    };
    let key = if tool == "audit.show" { "run" } else { "run_id" };
    let Some(run_id) = params.get(key) else {
        return Effect {
            prepared: true,
            observed: false,
            succeeded: false,
            tool: tool.to_string(),
            summary: format!("missing {key}"),
        };
    };
    match journal.run_timeline(run_id) {
        Ok(lines) => Effect {
            prepared: true,
            observed: true,
            succeeded: true,
            tool: tool.to_string(),
            summary: format!("run={} events={}", run_id, lines.len()),
        },
        Err(err) => Effect {
            prepared: true,
            observed: true,
            succeeded: false,
            tool: tool.to_string(),
            summary: format!("query failed run={} error={}", run_id, err),
        },
    }
}

/// 去除 URL 的 scheme，返回 `host:port`。默认端口 80（http）/ 443（https）。
fn strip_scheme(url: &str) -> String {
    let bare = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let authority = bare.split('/').next().unwrap_or(bare);
    if authority.contains(':') {
        authority.to_string()
    } else if url.starts_with("https://") {
        format!("{authority}:443")
    } else {
        format!("{authority}:80")
    }
}

/// 脱敏路径中的用户目录（发行版最小可用，不泄露 home 结构）。
/// `/root/<user>/rest` → `/root/<redacted>/rest`，`/home/<user>/rest` → `/home/<redacted>/rest`。
fn redact_path(path: &str) -> String {
    for prefix in ["/root/", "/home/"] {
        if let Some(rest) = path.strip_prefix(prefix) {
            if let Some(slash) = rest.find('/') {
                let after = &rest[slash + 1..];
                return format!("{prefix}<redacted>/{after}");
            }
            return format!("{prefix}<redacted>");
        }
    }
    path.to_string()
}

/// 脱敏 URL 的用户信息（user:pass@host）。
fn redact_url(url: &str) -> String {
    if let Some(at) = url.find('@') {
        if let Some(scheme_end) = url.find("://") {
            let scheme = &url[..scheme_end + 3];
            return format!("{scheme}<redacted>{}", &url[at + 1..]);
        }
        return format!("<redacted>{}", &url[at + 1..]);
    }
    url.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditEvent, AuditEventType, AuditJournal};
    use crate::tools::ToolRouter;
    use runtime_contracts::SemanticToolCall;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// 测试用唯一 journal 文件名计数器（避免时间源依赖）。
    static TEST_SEQ: AtomicU64 = AtomicU64::new(1);

    fn journal() -> AuditJournal {
        let path = std::env::temp_dir().join(format!(
            "agentd-exec-{}-{}.jsonl",
            std::process::id(),
            TEST_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&path);
        AuditJournal::new(path)
    }

    fn route_and_exec(exec: &StdToolExecutor, name: &str, params: &[(&str, &str)]) -> Effect {
        let call = SemanticToolCall::new(name, params.to_vec());
        let routed = ToolRouter.route(&call).expect("route");
        exec.execute(&routed)
    }

    #[test]
    fn fs_read_observes_file_content() {
        let path = std::env::temp_dir().join(format!("agentd-exec-read-{}.txt", std::process::id()));
        std::fs::write(&path, "hello world").expect("write");
        let exec = StdToolExecutor::new();
        let effect = route_and_exec(&exec, "fs.read", &[("path", path.to_str().unwrap())]);
        assert!(effect.observed);
        assert!(effect.succeeded);
        assert!(effect.summary.contains("bytes=11"), "summary: {}", effect.summary);
        assert!(effect.summary.contains("hello world"), "summary: {}", effect.summary);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn fs_read_missing_file_observed_as_failure() {
        let exec = StdToolExecutor::new();
        let effect = route_and_exec(
            &exec,
            "fs.read",
            &[("path", "/nonexistent-aios-test-xyz/nope")],
        );
        // 观测到失败是事实，但不能等价为成功。
        assert!(effect.observed);
        assert!(!effect.succeeded);
        assert!(effect.summary.contains("read failed"), "summary: {}", effect.summary);
    }

    #[test]
    fn http_check_observes_connectivity() {
        let exec = StdToolExecutor::new();
        // 连本地不可能的端口 → dead（观测到连通性事实）。
        let effect = route_and_exec(
            &exec,
            "http.check",
            &[("url", "127.0.0.1:1")],
        );
        assert!(effect.observed);
        assert!(!effect.succeeded);
        assert!(effect.summary.contains("dead") || effect.summary.contains("alive"));
    }

    #[test]
    fn http_check_alive_to_real_listener() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let exec = StdToolExecutor::new();
        let effect = route_and_exec(
            &exec,
            "http.check",
            &[("url", &addr.to_string())],
        );
        assert!(effect.observed);
        assert!(effect.succeeded);
        assert!(effect.summary.contains("alive"), "summary: {}", effect.summary);
        drop(listener);
    }

    #[test]
    fn svc_status_queries_procfs() {
        let exec = StdToolExecutor::new();
        let effect = route_and_exec(&exec, "svc.status", &[("service", "nginx")]);
        assert!(effect.observed);
        assert!(effect.succeeded);
        assert!(effect.summary.contains("service=nginx"), "summary: {}", effect.summary);
        assert!(effect.summary.contains("source=procfs"));
    }

    #[test]
    fn audit_show_queries_journal() {
        let j = journal();
        j.append(&AuditEvent::new(
            AuditEventType::IntentReceived,
            "run-x",
            "step-1",
            "operator",
            "test intent",
        ))
        .expect("append");
        let exec = StdToolExecutor::new().with_audit(j);
        let effect = route_and_exec(&exec, "audit.show", &[("run", "run-x")]);
        assert!(effect.observed);
        assert!(effect.succeeded);
        assert!(effect.summary.contains("run=run-x"), "summary: {}", effect.summary);
        assert!(effect.summary.contains("events=1"), "summary: {}", effect.summary);
    }

    #[test]
    fn audit_show_without_journal_observed_false() {
        let exec = StdToolExecutor::new();
        let effect = route_and_exec(&exec, "audit.show", &[("run", "run-x")]);
        assert!(!effect.observed);
        assert!(!effect.succeeded);
        assert!(effect.summary.contains("no audit journal"));
    }

    #[test]
    fn unknown_tool_returns_not_implemented() {
        // route 会拒绝未知工具，所以直接构造 RoutedToolCall 测 execute。
        let exec = StdToolExecutor::new();
        let routed = RoutedToolCall {
            tool: "future.tool",
            version: "v1",
            risk: runtime_contracts::RiskClass::ReadOnly,
            normalized_params: vec![],
            decision: "allow",
        };
        let effect = exec.execute(&routed);
        assert!(effect.prepared);
        assert!(!effect.observed);
        assert!(!effect.succeeded);
        assert!(effect.summary.contains("not-implemented"), "summary: {}", effect.summary);
    }

    #[test]
    fn strip_scheme_defaults_port() {
        assert_eq!(strip_scheme("http://example.com"), "example.com:80");
        assert_eq!(strip_scheme("https://example.com"), "example.com:443");
        assert_eq!(strip_scheme("example.com:8080"), "example.com:8080");
        assert_eq!(strip_scheme("http://h:9"), "h:9");
        assert_eq!(strip_scheme("https://example.com/path?q=1"), "example.com:443");
    }

    #[test]
    fn redact_path_masks_home_dirs() {
        assert_eq!(redact_path("/root/secret/key"), "/root/<redacted>/key");
        assert_eq!(redact_path("/home/user/data"), "/home/<redacted>/data");
        assert_eq!(redact_path("/etc/nginx.conf"), "/etc/nginx.conf");
    }

    #[test]
    fn redact_url_masks_userinfo() {
        assert_eq!(
            redact_url("https://user:pass@host/path"),
            "https://<redacted>host/path"
        );
        assert_eq!(redact_url("http://h:80/p"), "http://h:80/p");
    }
}
