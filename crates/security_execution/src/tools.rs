use crate::escape_json;
use runtime_contracts::{RiskClass, SemanticToolCall};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamRequirement {
    Required,
    Optional,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamSpec {
    pub name: &'static str,
    pub requirement: ParamRequirement,
}

impl ParamSpec {
    pub const fn required(name: &'static str) -> Self {
        Self {
            name,
            requirement: ParamRequirement::Required,
        }
    }

    pub const fn optional(name: &'static str) -> Self {
        Self {
            name,
            requirement: ParamRequirement::Optional,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolSchema {
    pub name: &'static str,
    pub version: &'static str,
    pub risk: RiskClass,
    pub params: &'static [ParamSpec],
}

impl ToolSchema {
    pub fn required_params(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.params
            .iter()
            .filter(|param| matches!(param.requirement, ParamRequirement::Required))
            .map(|param| param.name)
    }

    pub fn allows_param(&self, name: &str) -> bool {
        self.params.iter().any(|param| param.name == name)
    }
}

const SVC_LOGS_PARAMS: &[ParamSpec] =
    &[ParamSpec::required("service"), ParamSpec::optional("last")];
const SVC_STATUS_PARAMS: &[ParamSpec] = &[ParamSpec::required("service")];
const HTTP_CHECK_PARAMS: &[ParamSpec] = &[ParamSpec::required("url")];
const CONFIG_TEST_PARAMS: &[ParamSpec] = &[ParamSpec::required("service")];
const FS_READ_PARAMS: &[ParamSpec] = &[ParamSpec::required("path")];
const FS_WRITE_DIFF_PARAMS: &[ParamSpec] = &[
    ParamSpec::required("path"),
    ParamSpec::required("content_hash"),
    ParamSpec::optional("base_hash"),
];
const SVC_RESTART_PARAMS: &[ParamSpec] = &[ParamSpec::required("service")];
const AUDIT_SHOW_PARAMS: &[ParamSpec] = &[ParamSpec::required("run")];
const ROLLBACK_TRIGGER_PARAMS: &[ParamSpec] = &[ParamSpec::required("rollback_id")];
const CONTENT_FETCH_PARAMS: &[ParamSpec] = &[
    ParamSpec::required("source_uri"),
    ParamSpec::required("content_digest"),
];
const CONTENT_SANITIZE_PARAMS: &[ParamSpec] = &[ParamSpec::required("content_id")];
const CONTENT_SUMMARIZE_PARAMS: &[ParamSpec] = &[ParamSpec::required("content_id")];
const SOURCE_TO_SINK_CHECK_PARAMS: &[ParamSpec] = &[ParamSpec::required("content_id")];
const AUDIT_PROJECT_PARAMS: &[ParamSpec] = &[ParamSpec::required("run_id")];
const PKG_FETCH_METADATA_PARAMS: &[ParamSpec] = &[
    ParamSpec::required("package"),
    ParamSpec::required("version"),
    ParamSpec::required("source_uri"),
    ParamSpec::required("source_digest"),
];
const PKG_ISOLATE_INSTALL_PARAMS: &[ParamSpec] = &[
    ParamSpec::required("package"),
    ParamSpec::required("version"),
    ParamSpec::required("source_digest"),
];
const PKG_ISOLATE_SMOKE_PARAMS: &[ParamSpec] =
    &[ParamSpec::required("package"), ParamSpec::required("version")];
const PKG_HOST_CHECKPOINT_PARAMS: &[ParamSpec] = &[
    ParamSpec::required("package"),
    ParamSpec::required("version"),
    ParamSpec::required("rollback_id"),
];
const PKG_HOST_INSTALL_PARAMS: &[ParamSpec] = &[
    ParamSpec::required("package"),
    ParamSpec::required("version"),
    ParamSpec::required("source_uri"),
    ParamSpec::required("source_digest"),
    ParamSpec::required("rollback_id"),
];
const PKG_HOST_VERIFY_PARAMS: &[ParamSpec] =
    &[ParamSpec::required("package"), ParamSpec::required("version")];

pub const TOOL_SCHEMAS: &[ToolSchema] = &[
    ToolSchema {
        name: "svc.logs",
        version: "v1",
        risk: RiskClass::ReadOnly,
        params: SVC_LOGS_PARAMS,
    },
    ToolSchema {
        name: "svc.status",
        version: "v1",
        risk: RiskClass::ReadOnly,
        params: SVC_STATUS_PARAMS,
    },
    ToolSchema {
        name: "http.check",
        version: "v1",
        risk: RiskClass::ReadOnly,
        params: HTTP_CHECK_PARAMS,
    },
    ToolSchema {
        name: "config.test",
        version: "v1",
        risk: RiskClass::ReadOnly,
        params: CONFIG_TEST_PARAMS,
    },
    ToolSchema {
        name: "fs.read",
        version: "v1",
        risk: RiskClass::ReadOnly,
        params: FS_READ_PARAMS,
    },
    ToolSchema {
        name: "fs.write.diff",
        version: "v1",
        risk: RiskClass::WriteWithDiff,
        params: FS_WRITE_DIFF_PARAMS,
    },
    ToolSchema {
        name: "svc.restart",
        version: "v1",
        risk: RiskClass::ExecuteWithConfirmation,
        params: SVC_RESTART_PARAMS,
    },
    ToolSchema {
        name: "audit.show",
        version: "v1",
        risk: RiskClass::ReadOnly,
        params: AUDIT_SHOW_PARAMS,
    },
    ToolSchema {
        name: "rollback.trigger",
        version: "v1",
        risk: RiskClass::ExecuteWithConfirmation,
        params: ROLLBACK_TRIGGER_PARAMS,
    },
    ToolSchema {
        name: "content.fetch",
        version: "v1",
        risk: RiskClass::ReadOnly,
        params: CONTENT_FETCH_PARAMS,
    },
    ToolSchema {
        name: "content.sanitize",
        version: "v1",
        risk: RiskClass::ReadOnly,
        params: CONTENT_SANITIZE_PARAMS,
    },
    ToolSchema {
        name: "content.summarize",
        version: "v1",
        risk: RiskClass::ReadOnly,
        params: CONTENT_SUMMARIZE_PARAMS,
    },
    ToolSchema {
        name: "policy.source_to_sink.check",
        version: "v1",
        risk: RiskClass::ReadOnly,
        params: SOURCE_TO_SINK_CHECK_PARAMS,
    },
    ToolSchema {
        name: "audit.project",
        version: "v1",
        risk: RiskClass::ReadOnly,
        params: AUDIT_PROJECT_PARAMS,
    },
    ToolSchema {
        name: "pkg.fetch.metadata",
        version: "v1",
        risk: RiskClass::ReadOnly,
        params: PKG_FETCH_METADATA_PARAMS,
    },
    ToolSchema {
        name: "pkg.isolate.install",
        version: "v1",
        risk: RiskClass::ExecuteWithConfirmation,
        params: PKG_ISOLATE_INSTALL_PARAMS,
    },
    ToolSchema {
        name: "pkg.isolate.smoke",
        version: "v1",
        risk: RiskClass::ReadOnly,
        params: PKG_ISOLATE_SMOKE_PARAMS,
    },
    ToolSchema {
        name: "pkg.host.checkpoint",
        version: "v1",
        risk: RiskClass::WriteWithDiff,
        params: PKG_HOST_CHECKPOINT_PARAMS,
    },
    ToolSchema {
        name: "pkg.host.install",
        version: "v1",
        risk: RiskClass::PrivilegedWithHumanApproval,
        params: PKG_HOST_INSTALL_PARAMS,
    },
    ToolSchema {
        name: "pkg.host.verify",
        version: "v1",
        risk: RiskClass::ReadOnly,
        params: PKG_HOST_VERIFY_PARAMS,
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutedToolCall {
    pub tool: &'static str,
    pub version: &'static str,
    pub risk: RiskClass,
    pub normalized_params: Vec<(String, String)>,
    pub decision: &'static str,
}

impl RoutedToolCall {
    pub fn to_json(&self) -> String {
        let params = self
            .normalized_params
            .iter()
            .map(|(key, value)| format!("\"{}\":\"{}\"", escape_json(key), escape_json(value)))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"tool\":\"{}\",\"version\":\"{}\",\"risk\":\"{}\",\"decision\":\"{}\",\"normalized_params\":{{{}}}}}",
            self.tool,
            self.version,
            self.risk.as_str(),
            self.decision,
            params
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolRejection {
    pub tool: String,
    pub reason: String,
}

impl ToolRejection {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"tool\":\"{}\",\"decision\":\"deny\",\"reason\":\"{}\"}}",
            escape_json(&self.tool),
            escape_json(&self.reason)
        )
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ToolRouter;

impl ToolRouter {
    pub fn route(&self, call: &SemanticToolCall) -> Result<RoutedToolCall, ToolRejection> {
        if call.name == "shell.exec" {
            return Err(ToolRejection {
                tool: call.name.clone(),
                reason: "normal mode denies arbitrary shell".to_string(),
            });
        }

        let schema = TOOL_SCHEMAS
            .iter()
            .find(|schema| schema.name == call.name)
            .ok_or_else(|| ToolRejection {
                tool: call.name.clone(),
                reason: "unknown semantic tool".to_string(),
            })?;

        let mut params = call.params.clone();
        params.sort_by(|left, right| left.0.cmp(&right.0));

        for required in schema.required_params() {
            if !params
                .iter()
                .any(|(name, value)| name == required && !value.is_empty())
            {
                return Err(ToolRejection {
                    tool: call.name.clone(),
                    reason: format!("missing required parameter: {required}"),
                });
            }
        }

        for (name, _) in &params {
            if !schema.allows_param(name) {
                return Err(ToolRejection {
                    tool: call.name.clone(),
                    reason: format!("unexpected parameter: {name}"),
                });
            }
        }

        Ok(RoutedToolCall {
            tool: schema.name,
            version: schema.version,
            risk: schema.risk,
            normalized_params: params,
            decision: "allow",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_required_tool_families() {
        let names = TOOL_SCHEMAS
            .iter()
            .map(|schema| schema.name)
            .collect::<Vec<_>>();
        for expected in [
            "svc.logs",
            "svc.status",
            "http.check",
            "config.test",
            "fs.read",
            "fs.write.diff",
            "svc.restart",
            "audit.show",
            "rollback.trigger",
            "content.fetch",
            "content.sanitize",
            "content.summarize",
            "policy.source_to_sink.check",
            "audit.project",
            "pkg.fetch.metadata",
            "pkg.isolate.install",
            "pkg.isolate.smoke",
            "pkg.host.checkpoint",
            "pkg.host.install",
            "pkg.host.verify",
        ] {
            assert!(names.contains(&expected), "missing {expected}");
        }
    }

    #[test]
    fn canonicalizes_accepted_call_params() {
        let router = ToolRouter;
        let routed = router
            .route(&SemanticToolCall::new(
                "svc.logs",
                vec![("last", "200"), ("service", "nginx")],
            ))
            .expect("svc.logs routes");
        assert_eq!(routed.risk, RiskClass::ReadOnly);
        assert_eq!(
            routed.normalized_params,
            vec![
                ("last".to_string(), "200".to_string()),
                ("service".to_string(), "nginx".to_string())
            ]
        );
    }

    #[test]
    fn represents_write_with_diff_tool() {
        let router = ToolRouter;
        let routed = router
            .route(&SemanticToolCall::new(
                "fs.write.diff",
                vec![("path", "/etc/nginx/nginx.conf"), ("content_hash", "abc")],
            ))
            .expect("fs.write.diff routes");
        assert_eq!(routed.risk, RiskClass::WriteWithDiff);
    }

    #[test]
    fn routes_untrusted_content_tool_chain() {
        let router = ToolRouter;
        let fetched = router
            .route(&SemanticToolCall::new(
                "content.fetch",
                vec![
                    ("source_uri", "https://docs.example/setup"),
                    ("content_digest", "sha256:abcdef"),
                ],
            ))
            .expect("content.fetch routes");
        assert_eq!(fetched.risk, RiskClass::ReadOnly);
        assert_eq!(fetched.version, "v1");

        for call in [
            SemanticToolCall::new("content.sanitize", vec![("content_id", "doc-1")]),
            SemanticToolCall::new("content.summarize", vec![("content_id", "doc-1")]),
            SemanticToolCall::new("policy.source_to_sink.check", vec![("content_id", "doc-1")]),
            SemanticToolCall::new("audit.project", vec![("run_id", "run-doc-1")]),
        ] {
            assert_eq!(
                router.route(&call).expect("content chain route").risk,
                RiskClass::ReadOnly
            );
        }
    }

    #[test]
    fn routes_package_manager_tool_chain_without_raw_apt_or_shell() {
        let router = ToolRouter;
        let fetch = router
            .route(&SemanticToolCall::new(
                "pkg.fetch.metadata",
                vec![
                    ("package", "nginx-agent-plugin"),
                    ("version", "1.2.3"),
                    ("source_uri", "https://packages.example/nginx-agent-plugin_1.2.3.deb"),
                    ("source_digest", "sha256:abcdef"),
                ],
            ))
            .expect("package metadata routes");
        assert_eq!(fetch.risk, RiskClass::ReadOnly);

        let isolate = router
            .route(&SemanticToolCall::new(
                "pkg.isolate.install",
                vec![
                    ("package", "nginx-agent-plugin"),
                    ("version", "1.2.3"),
                    ("source_digest", "sha256:abcdef"),
                ],
            ))
            .expect("isolated package install routes");
        assert_eq!(isolate.risk, RiskClass::ExecuteWithConfirmation);

        let checkpoint = router
            .route(&SemanticToolCall::new(
                "pkg.host.checkpoint",
                vec![
                    ("package", "nginx-agent-plugin"),
                    ("version", "1.2.3"),
                    ("rollback_id", "rollback-package-nginx-agent-plugin-1.2.3"),
                ],
            ))
            .expect("host checkpoint routes");
        assert_eq!(checkpoint.risk, RiskClass::WriteWithDiff);

        let host_install = router
            .route(&SemanticToolCall::new(
                "pkg.host.install",
                vec![
                    ("package", "nginx-agent-plugin"),
                    ("version", "1.2.3"),
                    ("source_uri", "https://packages.example/nginx-agent-plugin_1.2.3.deb"),
                    ("source_digest", "sha256:abcdef"),
                    ("rollback_id", "rollback-package-nginx-agent-plugin-1.2.3"),
                ],
            ))
            .expect("host package install routes");
        assert_eq!(host_install.risk, RiskClass::PrivilegedWithHumanApproval);
        assert!(router
            .route(&SemanticToolCall::new("apt.install", vec![("package", "nginx")]))
            .is_err());
        assert!(router
            .route(&SemanticToolCall::new("dpkg.install", vec![("package", "nginx")]))
            .is_err());
        assert!(router
            .route(&SemanticToolCall::new(
                "pkg.host.install",
                vec![
                    ("package", "nginx-agent-plugin"),
                    ("version", "1.2.3"),
                    ("source_uri", "https://packages.example/nginx-agent-plugin_1.2.3.deb"),
                    ("source_digest", "sha256:abcdef"),
                    ("rollback_id", "rollback-package-nginx-agent-plugin-1.2.3"),
                    ("cmd", "apt install nginx"),
                ],
            ))
            .is_err());
    }

    #[test]
    fn rejects_shell_exec_and_unknown_tools() {
        let router = ToolRouter;
        let shell = router
            .route(&SemanticToolCall::new("shell.exec", vec![("cmd", "id")]))
            .expect_err("shell denied");
        assert!(shell.reason.contains("denies arbitrary shell"));

        let unknown = router
            .route(&SemanticToolCall::new("unknown.tool", vec![]))
            .expect_err("unknown denied");
        assert_eq!(unknown.reason, "unknown semantic tool");
    }

    #[test]
    fn rejects_missing_or_unexpected_params() {
        let router = ToolRouter;
        let missing = router
            .route(&SemanticToolCall::new("svc.status", vec![]))
            .expect_err("missing service");
        assert!(missing.reason.contains("missing required parameter"));

        let unexpected = router
            .route(&SemanticToolCall::new(
                "svc.status",
                vec![("service", "nginx"), ("cmd", "id")],
            ))
            .expect_err("unexpected cmd");
        assert!(unexpected.reason.contains("unexpected parameter"));
    }
}
