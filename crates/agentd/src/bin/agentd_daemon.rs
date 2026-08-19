//! agentd —— 发行版 daemon 二进制入口。
//!
//! 启动 `Agentd` lifecycle 并在 loopback 暴露 HTTP API server。operator 可通过
//! `POST /plan {"intent":"..."}` 远程提交意图，`GET /health` 查询状态，
//! `POST /execute` 执行工具，`GET /audit` 查审计 timeline。
//!
//! 配置（环境变量）：
//! - `AIOS_HTTP_ADDR`：HTTP 监听地址（缺省 `127.0.0.1:8421`）。
//! - `AIOS_AUDIT_PATH`：审计日志落盘路径（缺省 `/var/lib/aios/audit.jsonl`）。
//!   启用后每次 `/execute` 走可审计路径，每步写 `AuditEvent`，audit 写失败则 fail-closed。
//!
//! 所有工具调用仍经冻结 `ToolRouter`——本入口只编排，不自造裁决。
#![forbid(unsafe_code)]

use agentd::audit::AuditJournal;
use agentd::http_server;
use agentd::lifecycle::{Agentd, LifecycleConfig};
use std::path::PathBuf;

fn main() -> std::io::Result<()> {
    let config = LifecycleConfig::default();
    let audit_path = std::env::var("AIOS_AUDIT_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/aios/audit.jsonl"));
    let mut agentd = Agentd::new(config).with_audit(AuditJournal::new(&audit_path));
    agentd.start();

    let addr = std::env::var("AIOS_HTTP_ADDR").unwrap_or_else(|_| "127.0.0.1:8421".to_string());

    eprintln!(
        "agentd starting (run_mode={}, planner_mode={}, audit_path={})",
        agentd.health_report().run_mode,
        agentd.health_report().planner_mode,
        audit_path.display()
    );

    http_server::serve(&agentd, &addr)
}
