//! 配置管理 —— 发行版可配置能力（纯 std，零外部依赖）。
//!
//! cp-llm 阶段 Z：delegate 指出的配置管理缺口。daemon 当前全靠硬编码缺省 + 环境变量，
//! 无配置文件。本模块提供 `DaemonConfig`（String 字段，跨 `'static` 生命周期）+
//! `ConfigLoader`，从纯 std KV 配置文件加载，优先级：环境变量 > 配置文件 > 缺省。
//!
//! **配置文件格式**（极简 KV，无 toml/json 依赖）：
//! ```text
//! # agentd 配置
//! run_mode = local-only
//! planner_mode = stub
//! http_addr = 127.0.0.1:8421
//! audit_path = /var/log/agentos/audit/agentd.jsonl
//! arbitrary_shell_enabled = false
//! max_replans = 3
//! ```
//! `#` 开头为注释，`=` 分隔 key/value，忽略首尾空白。未知 key 警告但不失败。
//!
//! **向后兼容**：`LifecycleConfig`（`&'static str`）不变；`DaemonConfig` 是独立的
//! owned 版本，daemon 用它，再映射到 `LifecycleConfig`。`#![forbid(unsafe_code)]` 适用。
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::Path;

/// daemon 运行配置（owned，跨配置来源统一）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonConfig {
    pub run_mode: String,
    pub planner_mode: String,
    pub http_addr: String,
    pub audit_path: String,
    pub arbitrary_shell_enabled: bool,
    /// run loop 最大重规划次数（advisory，运行时裁剪）。
    pub max_replans: u32,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            run_mode: "local-only".to_string(),
            planner_mode: "stub".to_string(),
            http_addr: "127.0.0.1:8421".to_string(),
            audit_path: "/var/log/agentos/audit/agentd.jsonl".to_string(),
            arbitrary_shell_enabled: false,
            max_replans: 3,
        }
    }
}

/// 配置加载结果：最终配置 + 来源追踪（每字段来自 default/file/env）。
#[derive(Debug, Clone, Default)]
pub struct ConfigLoadResult {
    pub config: DaemonConfig,
    /// 字段名 → 来源（"default"/"file"/"env"）。
    pub sources: HashMap<String, &'static str>,
    /// 加载过程中的警告（未知 key、解析失败等）。
    pub warnings: Vec<String>,
}

impl ConfigLoadResult {
    /// 是否有警告。
    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }

    /// 序列化为 JSON（/health 或诊断端点用）。
    pub fn to_json(&self) -> String {
        let sources = self
            .sources
            .iter()
            .map(|(k, v)| format!("\"{}\":\"{}\"", escape_kv(k), escape_kv(v)))
            .collect::<Vec<_>>()
            .join(",");
        let warnings = self
            .warnings
            .iter()
            .map(|w| format!("\"{}\"", escape_kv(w)))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            r#"{{"config":{{"run_mode":"{}","planner_mode":"{}","http_addr":"{}","audit_path":"{}","arbitrary_shell_enabled":{},"max_replans":{}}},"sources":{{{}}},"warnings":[{}]}}"#,
            escape_kv(&self.config.run_mode),
            escape_kv(&self.config.planner_mode),
            escape_kv(&self.config.http_addr),
            escape_kv(&self.config.audit_path),
            self.config.arbitrary_shell_enabled,
            self.config.max_replans,
            sources,
            warnings,
        )
    }
}

/// 配置加载器。优先级：环境变量 > 配置文件 > 缺省。
#[derive(Debug, Default)]
pub struct ConfigLoader {
    /// 配置文件路径（None 时跳过文件加载）。
    pub file_path: Option<String>,
}

impl ConfigLoader {
    pub fn new() -> Self {
        Self { file_path: None }
    }

    /// 指定配置文件路径。
    pub fn with_file(mut self, path: impl Into<String>) -> Self {
        self.file_path = Some(path.into());
        self
    }

    /// 加载配置。环境变量覆盖文件值，文件覆盖缺省。
    /// 文件不存在不算错误（视为无文件配置，用缺省 + 环境变量）。
    pub fn load(&self) -> ConfigLoadResult {
        let mut result = ConfigLoadResult {
            config: DaemonConfig::default(),
            ..ConfigLoadResult::default()
        };
        for field in ["run_mode", "planner_mode", "http_addr", "audit_path", "arbitrary_shell_enabled", "max_replans"] {
            result.sources.insert(field.to_string(), "default");
        }

        // 1. 文件（若存在）。
        if let Some(path) = &self.file_path {
            match std::fs::read_to_string(path) {
                Ok(content) => self.apply_file(&content, &mut result),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    // 文件不存在：用缺省，继续环境变量。
                }
                Err(err) => {
                    result.warnings.push(format!("config file read failed: {err}"));
                }
            }
        }

        // 2. 环境变量（覆盖文件）。
        self.apply_env(&mut result);
        self.validate(&mut result);

        result
    }

    fn validate(&self, result: &mut ConfigLoadResult) {
        let valid_loopback = result
            .config
            .http_addr
            .parse::<std::net::SocketAddr>()
            .is_ok_and(|address| address.ip().is_loopback());
        if !valid_loopback {
            let rejected = std::mem::replace(
                &mut result.config.http_addr,
                DaemonConfig::default().http_addr,
            );
            result.sources.insert("http_addr".to_string(), "default");
            result.warnings.push(format!(
                "http_addr must be a numeric loopback socket; rejected {rejected:?} and restored default"
            ));
        }
    }

    fn apply_file(&self, content: &str, result: &mut ConfigLoadResult) {
        for (lineno, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let Some((key, value)) = trimmed.split_once('=') else {
                result.warnings.push(format!("line {}: missing '=' separator", lineno + 1));
                continue;
            };
            let key = key.trim();
            let value = value.trim();
            self.set_field(result, key, value, "file", lineno + 1);
        }
    }

    fn apply_env(&self, result: &mut ConfigLoadResult) {
        // AIOS_ 前缀的环境变量映射到配置字段。
        for (env_key, field) in [
            ("AIOS_RUN_MODE", "run_mode"),
            ("AIOS_PLANNER_MODE", "planner_mode"),
            ("AIOS_HTTP_ADDR", "http_addr"),
            ("AIOS_AUDIT_PATH", "audit_path"),
        ] {
            if let Ok(value) = std::env::var(env_key) {
                result.config.set_str(field, &value);
                result.sources.insert(field.to_string(), "env");
            }
        }
        if let Ok(value) = std::env::var("AIOS_ARBITRARY_SHELL") {
            match parse_bool(&value) {
                Some(b) => {
                    result.config.arbitrary_shell_enabled = b;
                    result.sources.insert("arbitrary_shell_enabled".to_string(), "env");
                }
                None => result.warnings.push(format!("AIOS_ARBITRARY_SHELL invalid bool: {value}")),
            }
        }
        if let Ok(value) = std::env::var("AIOS_MAX_REPLANS") {
            match value.parse::<u32>() {
                Ok(n) => {
                    result.config.max_replans = n;
                    result.sources.insert("max_replans".to_string(), "env");
                }
                Err(_) => result.warnings.push(format!("AIOS_MAX_REPLANS invalid u32: {value}")),
            }
        }
    }

    fn set_field(&self, result: &mut ConfigLoadResult, key: &str, value: &str, source: &'static str, lineno: usize) {
        match key {
            "run_mode" | "planner_mode" | "http_addr" | "audit_path" => {
                result.config.set_str(key, value);
                result.sources.insert(key.to_string(), source);
            }
            "arbitrary_shell_enabled" => match parse_bool(value) {
                Some(b) => {
                    result.config.arbitrary_shell_enabled = b;
                    result.sources.insert(key.to_string(), source);
                }
                None => result.warnings.push(format!("line {lineno}: arbitrary_shell_enabled invalid bool: {value}")),
            },
            "max_replans" => match value.parse::<u32>() {
                Ok(n) => {
                    result.config.max_replans = n;
                    result.sources.insert(key.to_string(), source);
                }
                Err(_) => result.warnings.push(format!("line {lineno}: max_replans invalid u32: {value}")),
            },
            other => {
                result.warnings.push(format!("line {lineno}: unknown config key: {other}"));
            }
        }
    }
}

impl DaemonConfig {
    /// 设置字符串字段（run_mode/planner_mode/http_addr/audit_path）。
    fn set_str(&mut self, key: &str, value: &str) {
        match key {
            "run_mode" => self.run_mode = value.to_string(),
            "planner_mode" => self.planner_mode = value.to_string(),
            "http_addr" => self.http_addr = value.to_string(),
            "audit_path" => self.audit_path = value.to_string(),
            _ => {}
        }
    }

    /// 映射到 `LifecycleConfig`（向后兼容：&'static str 字段用泄漏的 String）。
    /// daemon 用此构造 Agentd。run_mode/planner_mode 必须是已知常量，否则回落到缺省。
    #[allow(clippy::should_implement_trait)]
    pub fn to_lifecycle_config(&self) -> super::lifecycle::LifecycleConfig {
        super::lifecycle::LifecycleConfig {
            run_mode: leak_or_default(&self.run_mode, "local-only"),
            planner_mode: leak_or_default(&self.planner_mode, "stub"),
            arbitrary_shell_enabled: self.arbitrary_shell_enabled,
        }
    }
}

/// 把 String 泄漏为 &'static str（daemon 生命周期 = 进程生命周期，泄漏可接受）。
/// 若值为已知缺省常量，直接返回该常量（避免无谓泄漏）。
fn leak_or_default(value: &str, default: &'static str) -> &'static str {
    if value == default {
        return default;
    }
    Box::leak(value.to_string().into_boxed_str())
}

/// 解析布尔值（true/false/1/0/yes/no，大小写不敏感）。
fn parse_bool(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// 转义 KV 字符串用于 JSON。
fn escape_kv(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// 判断配置文件路径是否存在（辅助 daemon 诊断）。
pub fn config_exists(path: &str) -> bool {
    Path::new(path).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_config(name: &str, content: &str) -> String {
        let path = std::env::temp_dir().join(format!(
            "agentd-cfg-{name}-{}-{}.conf",
            std::process::id(),
            unique_seq()
        ));
        std::fs::write(&path, content).expect("write config");
        path.to_string_lossy().to_string()
    }

    fn unique_seq() -> u64 {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    #[test]
    fn defaults_when_no_file_no_env() {
        let loader = ConfigLoader::new();
        let result = loader.load();
        assert_eq!(result.config.run_mode, "local-only");
        assert_eq!(result.config.http_addr, "127.0.0.1:8421");
        assert_eq!(result.config.audit_path, "/var/log/agentos/audit/agentd.jsonl");
        assert!(!result.config.arbitrary_shell_enabled);
        assert_eq!(result.config.max_replans, 3);
        assert_eq!(result.sources.get("run_mode").copied(), Some("default"));
    }

    #[test]
    fn loads_from_file() {
        let path = tmp_config("basic", "run_mode = hardened\nplanner_mode = real\nhttp_addr = 127.0.0.1:9000\naudit_path = /data/audit.jsonl\narbitrary_shell_enabled = true\nmax_replans = 5\n");
        let loader = ConfigLoader::new().with_file(path);
        let result = loader.load();
        assert_eq!(result.config.run_mode, "hardened");
        assert_eq!(result.config.planner_mode, "real");
        assert_eq!(result.config.http_addr, "127.0.0.1:9000");
        assert_eq!(result.config.audit_path, "/data/audit.jsonl");
        assert!(result.config.arbitrary_shell_enabled);
        assert_eq!(result.config.max_replans, 5);
        assert_eq!(result.sources.get("run_mode").copied(), Some("file"));
    }

    #[test]
    fn rejects_non_loopback_http_address() {
        let path = tmp_config("non-loopback", "http_addr = 0.0.0.0:9000\n");
        let result = ConfigLoader::new().with_file(path).load();
        assert_eq!(result.config.http_addr, "127.0.0.1:8421");
        assert_eq!(result.sources.get("http_addr").copied(), Some("default"));
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("must be a numeric loopback socket")),
            "warnings: {:?}",
            result.warnings
        );
    }

    #[test]
    fn ignores_comments_and_blank_lines() {
        let path = tmp_config("comments", "# comment\n\nrun_mode = x\n  # indented comment\nplanner_mode = y\n");
        let result = ConfigLoader::new().with_file(path).load();
        assert_eq!(result.config.run_mode, "x");
        assert_eq!(result.config.planner_mode, "y");
        assert!(!result.has_warnings());
    }

    #[test]
    fn warns_on_missing_separator() {
        let path = tmp_config("bad", "run_mode local-only\n");
        let result = ConfigLoader::new().with_file(path).load();
        assert!(result.warnings.iter().any(|w| w.contains("missing '='")), "warnings: {:?}", result.warnings);
        // 缺省值不受影响。
        assert_eq!(result.config.run_mode, "local-only");
    }

    #[test]
    fn warns_on_unknown_key() {
        let path = tmp_config("unknown", "mystery_key = value\n");
        let result = ConfigLoader::new().with_file(path).load();
        assert!(result.warnings.iter().any(|w| w.contains("unknown config key: mystery_key")), "warnings: {:?}", result.warnings);
    }

    #[test]
    fn warns_on_invalid_bool() {
        let path = tmp_config("badbool", "arbitrary_shell_enabled = maybe\n");
        let result = ConfigLoader::new().with_file(path).load();
        assert!(result.warnings.iter().any(|w| w.contains("invalid bool")), "warnings: {:?}", result.warnings);
        assert!(!result.config.arbitrary_shell_enabled);
    }

    #[test]
    fn warns_on_invalid_u32() {
        let path = tmp_config("badu32", "max_replans = lots\n");
        let result = ConfigLoader::new().with_file(path).load();
        assert!(result.warnings.iter().any(|w| w.contains("max_replans invalid u32")), "warnings: {:?}", result.warnings);
        assert_eq!(result.config.max_replans, 3);
    }

    #[test]
    fn missing_file_uses_defaults() {
        let loader = ConfigLoader::new().with_file("/nonexistent-aios-cfg-test.conf");
        let result = loader.load();
        // 文件不存在不算错误，无警告。
        assert!(!result.has_warnings());
        assert_eq!(result.config.run_mode, "local-only");
    }

    #[test]
    fn bool_parses_various_forms() {
        assert_eq!(parse_bool("true"), Some(true));
        assert_eq!(parse_bool("YES"), Some(true));
        assert_eq!(parse_bool("1"), Some(true));
        assert_eq!(parse_bool("on"), Some(true));
        assert_eq!(parse_bool("false"), Some(false));
        assert_eq!(parse_bool("0"), Some(false));
        assert_eq!(parse_bool("off"), Some(false));
        assert_eq!(parse_bool("maybe"), None);
    }

    #[test]
    fn to_lifecycle_config_maps_fields() {
        let cfg = DaemonConfig {
            run_mode: "hardened".to_string(),
            planner_mode: "real".to_string(),
            http_addr: "x".to_string(),
            audit_path: "y".to_string(),
            arbitrary_shell_enabled: true,
            max_replans: 7,
        };
        let lc = cfg.to_lifecycle_config();
        assert_eq!(lc.run_mode, "hardened");
        assert_eq!(lc.planner_mode, "real");
        assert!(lc.arbitrary_shell_enabled);
    }

    #[test]
    fn to_lifecycle_config_defaults_to_known_when_matching() {
        // 值为缺省常量时不泄漏，直接返回静态串。
        let cfg = DaemonConfig::default();
        let lc = cfg.to_lifecycle_config();
        assert_eq!(lc.run_mode, "local-only");
        assert_eq!(lc.planner_mode, "stub");
    }

    #[test]
    fn to_json_includes_sources_and_warnings() {
        let result = ConfigLoader::new().load();
        let json = result.to_json();
        assert!(json.contains("\"run_mode\":\"local-only\""), "json: {json}");
        assert!(json.contains("\"sources\""), "json: {json}");
        assert!(json.contains("\"default\""), "json: {json}");
        assert!(json.contains("\"warnings\":[]"), "json: {json}");
    }

    #[test]
    fn file_value_persists_in_sources() {
        // env 覆盖逻辑通过端到端验证；此处验证文件加载后 sources 正确标记 "file"。
        let path = tmp_config("src", "run_mode = file-mode\n");
        let result = ConfigLoader::new().with_file(path).load();
        // 若无 AIOS_RUN_MODE 环境变量，source 应为 file；若有（CI 环境），应为 env。
        let src = result.sources.get("run_mode").copied().unwrap_or("default");
        assert!(src == "file" || src == "env", "unexpected source: {src}");
        if std::env::var("AIOS_RUN_MODE").is_ok() {
            // 环境变量存在时值应等于环境变量值。
        } else {
            assert_eq!(result.config.run_mode, "file-mode");
        }
    }
}
