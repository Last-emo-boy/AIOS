use crate::runtime_contracts::contains_secret_value;

use super::launch_preview::validate_launch_preview_inputs;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TuiCommand {
    Noop,
    Help,
    Refresh,
    Exit,
    DashboardShow,
    PalettePreview {
        line: String,
    },
    IntentSubmit {
        intent: String,
        actor: String,
    },
    RunPlan {
        run_id: String,
    },
    RunAdvance {
        run_id: String,
    },
    RunApprove {
        run_id: String,
        step_id: String,
        actor: String,
    },
    RunDeny {
        run_id: String,
        step_id: String,
        actor: String,
        reason: String,
    },
    RunSuspend {
        run_id: String,
        reason: String,
    },
    RunRecover {
        run_id: String,
    },
    RunShow {
        run_id: String,
    },
    AuditShow {
        run_id: Option<String>,
    },
    EventFeedShow {
        limit: usize,
    },
    ApprovalsShow {
        run_id: Option<String>,
    },
    RecoveryShow {
        run_id: Option<String>,
    },
    SupportBundleStatus,
    SupportBundleExport,
    CapabilityIndexShow,
    WorkflowCatalogShow {
        workflow_id: Option<String>,
    },
    LaunchPreview {
        workflow_id: String,
        inputs: Vec<String>,
    },
    AomArtifactShow {
        coordinate: String,
    },
    ReleaseProvenanceShow,
    PromotionBlockersShow,
    UpdateRollbackShow,
    GateStatusShow,
    SigningStatusShow,
    RolloutRingsShow,
    Aom {
        args: Vec<String>,
    },
}

impl TuiCommand {
    pub fn parse(line: &str) -> Result<Self, TuiParseError> {
        let line = line.trim();
        if line.is_empty() {
            return Ok(Self::Noop);
        }
        reject_unsafe_input(line)?;
        if contains_secret_value(line) {
            return Err(TuiParseError::new(
                "secret-like value is not allowed in TUI command",
            ));
        }
        let mut tokens = line.split_whitespace();
        let command = tokens
            .next()
            .ok_or_else(|| TuiParseError::new("missing command"))?;
        let rest = line[command.len()..].trim();
        Ok(match command {
            "help" => Self::Help,
            "refresh" => Self::Refresh,
            "exit" | "quit" => Self::Exit,
            "dashboard.show" => Self::DashboardShow,
            "palette.preview" => {
                if rest.is_empty() {
                    return Err(TuiParseError::new(
                        "palette.preview requires typed command text",
                    ));
                }
                Self::PalettePreview {
                    line: rest.to_string(),
                }
            }
            "intent.submit" => {
                if rest.is_empty() {
                    return Err(TuiParseError::new("intent.submit requires intent text"));
                }
                Self::IntentSubmit {
                    intent: rest.to_string(),
                    actor: "operator".to_string(),
                }
            }
            "run.plan" => Self::RunPlan {
                run_id: required_token(tokens.next(), "run.plan requires run id")?,
            },
            "run.advance" => Self::RunAdvance {
                run_id: required_token(tokens.next(), "run.advance requires run id")?,
            },
            "run.approve" => {
                let run_id = required_token(tokens.next(), "run.approve requires run id")?;
                let step_id = required_token(tokens.next(), "run.approve requires step id")?;
                let actor = required_key(line, "actor")?;
                Self::RunApprove {
                    run_id,
                    step_id,
                    actor,
                }
            }
            "run.deny" => {
                let run_id = required_token(tokens.next(), "run.deny requires run id")?;
                let step_id = required_token(tokens.next(), "run.deny requires step id")?;
                let actor = required_key(line, "actor")?;
                let reason = required_key_tail(line, "reason")?;
                Self::RunDeny {
                    run_id,
                    step_id,
                    actor,
                    reason,
                }
            }
            "run.suspend" => {
                let run_id = required_token(tokens.next(), "run.suspend requires run id")?;
                let reason = required_key_tail(line, "reason")?;
                Self::RunSuspend { run_id, reason }
            }
            "run.recover" => Self::RunRecover {
                run_id: required_token(tokens.next(), "run.recover requires run id")?,
            },
            "run.show" => Self::RunShow {
                run_id: tokens.next().unwrap_or("latest").to_string(),
            },
            "audit.show" => Self::AuditShow {
                run_id: tokens.next().map(ToString::to_string),
            },
            "events.show" => Self::EventFeedShow {
                limit: optional_limit(tokens.next())?,
            },
            "approvals.show" => Self::ApprovalsShow {
                run_id: tokens.next().map(ToString::to_string),
            },
            "recovery.show" => Self::RecoveryShow {
                run_id: tokens.next().map(ToString::to_string),
            },
            "support.bundle" => match tokens.next() {
                Some("status") | None => Self::SupportBundleStatus,
                Some("export") => Self::SupportBundleExport,
                Some(other) => {
                    return Err(TuiParseError::new(format!(
                        "unknown support.bundle action: {other}"
                    )));
                }
            },
            "capabilities.show" | "capability.list" => Self::CapabilityIndexShow,
            "workflows.show" | "workflow.show" => Self::WorkflowCatalogShow {
                workflow_id: tokens.next().map(ToString::to_string),
            },
            "launch.preview" | "capability.launch.preview" => {
                let workflow_id =
                    required_token(tokens.next(), "launch.preview requires workflow id")?;
                let inputs = tokens.map(ToString::to_string).collect::<Vec<_>>();
                validate_launch_preview_inputs(&inputs)
                    .map_err(|error| TuiParseError::new(error.reason))?;
                Self::LaunchPreview {
                    workflow_id,
                    inputs,
                }
            }
            "aom.artifact.show" | "aom.artifact.detail" => Self::AomArtifactShow {
                coordinate: required_token(tokens.next(), "aom.artifact.show requires coordinate")?,
            },
            "release.provenance.show" | "provenance.show" => Self::ReleaseProvenanceShow,
            "promotion.blockers.show" | "release.blockers.show" => Self::PromotionBlockersShow,
            "update.rollback.show" | "release.update.show" => Self::UpdateRollbackShow,
            "gate.status.show" | "release.gates.show" => Self::GateStatusShow,
            "signing.status.show" | "release.signing.show" => Self::SigningStatusShow,
            "rollout.rings.show" | "fleet.rollout.show" => Self::RolloutRingsShow,
            "aom.search" => Self::Aom {
                args: aom_args("search", tokens),
            },
            "aom.show" => Self::Aom {
                args: aom_args("show", tokens),
            },
            "aom.verify" => Self::Aom {
                args: aom_args("verify", tokens),
            },
            "aom.stage" => Self::Aom {
                args: aom_args("stage", tokens),
            },
            "aom.explain" => Self::Aom {
                args: aom_args("explain", tokens),
            },
            "aom.activate.preview" => Self::Aom {
                args: aom_args("activate", tokens),
            },
            other => return Err(TuiParseError::new(format!("unknown TUI command: {other}"))),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TuiParseError {
    pub reason: String,
}

impl TuiParseError {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

fn reject_unsafe_input(line: &str) -> Result<(), TuiParseError> {
    let lower = line.to_ascii_lowercase();
    for forbidden in ["|", ">", "<", ";", "&&", "||", "$(", "`"] {
        if line.contains(forbidden) {
            return Err(TuiParseError::new(format!(
                "shell-like syntax is not accepted by TUI commands: {forbidden}"
            )));
        }
    }
    let first = lower.split_whitespace().next().unwrap_or_default();
    if matches!(first, "sh" | "bash" | "cmd" | "powershell" | "pwsh") {
        return Err(TuiParseError::new(
            "host shell command names are not accepted by TUI",
        ));
    }
    if lower.contains("shell.exec") {
        return Err(TuiParseError::new(
            "direct shell.exec authority is not accepted by TUI",
        ));
    }
    Ok(())
}

fn required_token(value: Option<&str>, message: &str) -> Result<String, TuiParseError> {
    value
        .map(ToString::to_string)
        .ok_or_else(|| TuiParseError::new(message))
}

fn required_key(line: &str, key: &str) -> Result<String, TuiParseError> {
    let prefix = format!("{key}=");
    line.split_whitespace()
        .find_map(|token| token.strip_prefix(&prefix))
        .map(ToString::to_string)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| TuiParseError::new(format!("missing {prefix}<value>")))
}

fn required_key_tail(line: &str, key: &str) -> Result<String, TuiParseError> {
    let prefix = format!("{key}=");
    let Some(index) = line.find(&prefix) else {
        return Err(TuiParseError::new(format!("missing {prefix}<value>")));
    };
    let value = line[index + prefix.len()..].trim();
    if value.is_empty() {
        return Err(TuiParseError::new(format!("missing {prefix}<value>")));
    }
    Ok(value.to_string())
}

fn optional_limit(value: Option<&str>) -> Result<usize, TuiParseError> {
    let Some(value) = value else {
        return Ok(super::event_feed::DEFAULT_EVENT_FEED_LIMIT);
    };
    let limit = value
        .parse::<usize>()
        .map_err(|_| TuiParseError::new("events.show limit must be a positive integer"))?;
    if limit == 0 {
        return Err(TuiParseError::new(
            "events.show limit must be a positive integer",
        ));
    }
    Ok(limit)
}

fn aom_args<'a>(command: &str, tokens: impl Iterator<Item = &'a str>) -> Vec<String> {
    std::iter::once(command.to_string())
        .chain(tokens.map(ToString::to_string))
        .collect()
}
