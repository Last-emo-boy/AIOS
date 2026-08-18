//! agentd —— 发行版 daemon 二进制入口。
//!
//! 启动 `Agentd` lifecycle 并在 loopback 暴露 HTTP API server。operator 可通过
//! `POST /plan {"intent":"..."}` 远程提交意图，`GET /health` 查询状态。
//!
//! 端口可通过 `AIOS_HTTP_ADDR` 环境变量配置（缺省 `127.0.0.1:8421`）。
//! 所有工具调用仍经冻结 `ToolRouter`——本入口只编排，不自造裁决。
#![forbid(unsafe_code)]

use agentd::http_server;
use agentd::lifecycle::{Agentd, LifecycleConfig};

fn main() -> std::io::Result<()> {
    let config = LifecycleConfig::default();
    let mut agentd = Agentd::new(config);
    agentd.start();

    let addr = std::env::var("AIOS_HTTP_ADDR").unwrap_or_else(|_| "127.0.0.1:8421".to_string());

    eprintln!("agentd starting (run_mode={}, planner_mode={})",
        agentd.health_report().run_mode,
        agentd.health_report().planner_mode);

    http_server::serve(&agentd, &addr)
}
