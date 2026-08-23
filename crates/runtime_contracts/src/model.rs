#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskClass {
    ReadOnly,
    WriteWithDiff,
    ExecuteWithConfirmation,
    PrivilegedWithHumanApproval,
    Never,
}

impl RiskClass {
    pub fn as_str(self) -> &'static str {
        match self {
            RiskClass::ReadOnly => "read-only",
            RiskClass::WriteWithDiff => "write-with-diff",
            RiskClass::ExecuteWithConfirmation => "execute-with-confirmation",
            RiskClass::PrivilegedWithHumanApproval => "privileged-with-human-approval",
            RiskClass::Never => "never",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "read-only" => RiskClass::ReadOnly,
            "write-with-diff" => RiskClass::WriteWithDiff,
            "execute-with-confirmation" => RiskClass::ExecuteWithConfirmation,
            "privileged-with-human-approval" => RiskClass::PrivilegedWithHumanApproval,
            "never" => RiskClass::Never,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticToolCall {
    pub name: String,
    pub params: Vec<(String, String)>,
}

impl SemanticToolCall {
    pub fn new(name: impl Into<String>, params: Vec<(&str, &str)>) -> Self {
        Self {
            name: name.into(),
            params: params
                .into_iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
        }
    }

    pub fn to_json(&self) -> String {
        let mut params = self.params.clone();
        params.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
        let params = params
            .iter()
            .map(|(key, value)| format!("\"{}\":\"{}\"", escape_json(key), escape_json(value)))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"name\":\"{}\",\"params\":{{{}}}}}",
            escape_json(&self.name),
            params
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustBoundary {
    Operator,
    OperatorApproved,
    LocalSystem,
    SandboxedTool,
    ExternalUntrusted,
    ModelOutput,
    ModelSummary,
    SanitizedSummary,
}

impl TrustBoundary {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::OperatorApproved => "operator-approved",
            Self::LocalSystem => "local-system",
            Self::SandboxedTool => "sandboxed-tool",
            Self::ExternalUntrusted => "external-untrusted",
            Self::ModelOutput => "model-output",
            Self::ModelSummary => "model-summary",
            Self::SanitizedSummary => "sanitized-summary",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "operator" => Self::Operator,
            "operator-approved" => Self::OperatorApproved,
            "local-system" => Self::LocalSystem,
            "sandboxed-tool" => Self::SandboxedTool,
            "external-untrusted" => Self::ExternalUntrusted,
            "model-output" => Self::ModelOutput,
            "model-summary" => Self::ModelSummary,
            "sanitized-summary" => Self::SanitizedSummary,
            _ => return None,
        })
    }
}

pub fn contains_secret_value(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if lower.trim().starts_with("secret://") && !lower.trim().contains(char::is_whitespace) {
        return false;
    }
    let compact = lower.replace(['"', '\'', '`'], "");
    for key in ["password", "token", "apikey", "api_key", "secret"] {
        for separator in ["=", ":"] {
            let pattern = format!("{key}{separator}");
            let mut search = compact.as_str();
            while let Some(index) = search.find(&pattern) {
                let tail = &search[index..];
                if key == "secret" && tail.starts_with("secret://") {
                    search = &tail["secret://".len()..];
                    continue;
                }
                let after = tail[pattern.len()..].trim_start();
                if let Some(stripped) = after.strip_prefix("secret://") {
                    search = stripped;
                    continue;
                }
                if after.chars().next().is_some_and(|ch| {
                    ch.is_ascii_alphanumeric()
                        || matches!(ch, '_' | '-' | '.' | '/' | '\\' | '$' | '{' | '[')
                }) {
                    return true;
                }
                search = &tail[pattern.len()..];
            }
        }
    }
    false
}

fn escape_json(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_class_round_trips_stable_labels() {
        for risk in [
            RiskClass::ReadOnly,
            RiskClass::WriteWithDiff,
            RiskClass::ExecuteWithConfirmation,
            RiskClass::PrivilegedWithHumanApproval,
            RiskClass::Never,
        ] {
            assert_eq!(RiskClass::parse(risk.as_str()), Some(risk));
        }
        assert_eq!(RiskClass::parse("unknown"), None);
    }

    #[test]
    fn semantic_tool_call_json_is_stable() {
        let call = SemanticToolCall::new("svc.status", vec![("service", "agentd"), ("a", "b")]);
        assert_eq!(
            call.to_json(),
            "{\"name\":\"svc.status\",\"params\":{\"a\":\"b\",\"service\":\"agentd\"}}"
        );
    }

    #[test]
    fn secret_handles_are_not_raw_secret_values() {
        assert!(!contains_secret_value("secret://prod/db-token"));
        assert!(contains_secret_value("token=abc123"));
    }
}
