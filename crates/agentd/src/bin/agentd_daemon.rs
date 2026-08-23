//! agentd —— 发行版 daemon 二进制入口。
//!
//! 启动 `Agentd` lifecycle 并在 loopback 暴露 HTTP API server。operator 可通过
//! `POST /plan {"intent":"..."}` 远程提交意图，`GET /health` 查询状态，
//! `POST /execute` 执行工具，`GET /audit` 查审计 timeline，`GET /recover` 查恢复。
//!
//! 配置优先级：环境变量 > 配置文件 > 缺省。配置文件（`key=value`，`#` 注释）路径
//! 由 `AIOS_CONFIG` 指定（缺省 `/etc/agentos/agentd.conf`，不存在则用缺省 + 环境变量）。
//! 关键环境变量：`AIOS_HTTP_ADDR`、`AIOS_AUDIT_PATH`、`AIOS_RUN_MODE`、
//! `AIOS_PLANNER_MODE`、`AIOS_ARBITRARY_SHELL`、`AIOS_MAX_REPLANS`。
//!
//! 所有工具调用仍经冻结 `ToolRouter`——本入口只编排，不自造裁决。
#![forbid(unsafe_code)]

use agentd::audit::AuditJournal;
use agentd::config::ConfigLoader;
use agentd::http_server;
use agentd::lifecycle::{Agentd, LifecycleConfig};
use std::path::PathBuf;

fn main() -> std::io::Result<()> {
    // 配置加载：环境变量 > 配置文件 > 缺省。
    let config_path = std::env::var("AIOS_CONFIG")
        .unwrap_or_else(|_| "/etc/agentos/agentd.conf".to_string());
    let loaded = ConfigLoader::new().with_file(&config_path).load();
    let cfg = &loaded.config;

    // audit + 真实执行后端。
    let audit_path = PathBuf::from(&cfg.audit_path);
    let lifecycle_cfg: LifecycleConfig = cfg.to_lifecycle_config();
    let mut agentd = Agentd::new(lifecycle_cfg).with_audit_and_executor(AuditJournal::new(&audit_path));

    // planner_mode=real 时注入 LLM provider（OpenAI 兼容 API，从环境变量配置）。
    if cfg.planner_mode == "real" {
        if let Ok(api_key) = std::env::var("AIOS_LLM_API_KEY") {
            let provider = llm_planner::OpenAiCompatProvider::from_env(api_key);
            agentd = agentd.with_planner(Box::new(provider));
            eprintln!("agentd planner_mode=real (provider=openai)");
        } else {
            eprintln!("agentd planner_mode=real but AIOS_LLM_API_KEY unset; falling back to stub planner");
        }
    }

    agentd.start();

    eprintln!(
        "agentd starting (run_mode={}, planner_mode={}, http_addr={}, audit_path={}, config={})",
        cfg.run_mode,
        cfg.planner_mode,
        cfg.http_addr,
        cfg.audit_path,
        if agentd::config::config_exists(&config_path) {
            &config_path
        } else {
            "<defaults>"
        },
    );
    if loaded.has_warnings() {
        for warning in &loaded.warnings {
            eprintln!("agentd config warning: {warning}");
        }
    }

    http_server::serve(&agentd, &cfg.http_addr, cfg.max_replans as usize)
}
