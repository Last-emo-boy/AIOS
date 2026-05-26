use super::parser::TuiCommand;
use super::snapshot::ProjectionSnapshot;
use crate::audit::redact_summary;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandPaletteContext {
    pub selected_run_id: Option<String>,
    pub selected_step_id: Option<String>,
    pub selected_actor: String,
    pub selected_artifact: Option<String>,
    pub focus: PaletteFocus,
}

impl CommandPaletteContext {
    pub fn from_snapshot(snapshot: &ProjectionSnapshot) -> Self {
        Self {
            selected_run_id: snapshot
                .latest_run_id
                .clone()
                .or_else(|| Some("latest".to_string())),
            selected_step_id: None,
            selected_actor: "operator".to_string(),
            selected_artifact: None,
            focus: if snapshot.approvals.status == "pending" {
                PaletteFocus::Approvals
            } else if snapshot.recovery.degraded {
                PaletteFocus::Recovery
            } else {
                PaletteFocus::Dashboard
            },
        }
    }

    pub fn with_run(mut self, run_id: impl Into<String>) -> Self {
        self.selected_run_id = Some(run_id.into());
        self
    }

    pub fn with_step(mut self, step_id: impl Into<String>) -> Self {
        self.selected_step_id = Some(step_id.into());
        self
    }

    pub fn with_artifact(mut self, coordinate: impl Into<String>) -> Self {
        self.selected_artifact = Some(coordinate.into());
        self
    }

    fn run_id(&self) -> &str {
        self.selected_run_id.as_deref().unwrap_or("latest")
    }

    fn step_id(&self) -> &str {
        self.selected_step_id.as_deref().unwrap_or("step-id")
    }

    fn artifact(&self) -> &str {
        self.selected_artifact.as_deref().unwrap_or("coordinate")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaletteFocus {
    Dashboard,
    Runs,
    Approvals,
    Recovery,
    Support,
    Ecosystem,
    Release,
}

impl PaletteFocus {
    pub fn as_str(self) -> &'static str {
        match self {
            PaletteFocus::Dashboard => "dashboard",
            PaletteFocus::Runs => "runs",
            PaletteFocus::Approvals => "approvals",
            PaletteFocus::Recovery => "recovery",
            PaletteFocus::Support => "support",
            PaletteFocus::Ecosystem => "ecosystem",
            PaletteFocus::Release => "release",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSuggestion {
    pub label: &'static str,
    pub command: String,
    pub risk: PaletteRisk,
    pub authority_path: &'static str,
    pub requires_preview: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaletteRisk {
    ReadOnly,
    Lifecycle,
    Approval,
    Recovery,
    Export,
    ActivationPreview,
}

impl PaletteRisk {
    pub fn as_str(self) -> &'static str {
        match self {
            PaletteRisk::ReadOnly => "read-only",
            PaletteRisk::Lifecycle => "lifecycle",
            PaletteRisk::Approval => "approval",
            PaletteRisk::Recovery => "recovery",
            PaletteRisk::Export => "export",
            PaletteRisk::ActivationPreview => "activation-preview",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandPreview {
    pub command: String,
    pub target: String,
    pub risk: PaletteRisk,
    pub authority_path: &'static str,
    pub expected_state_change: &'static str,
    pub requires_preview: bool,
    pub dispatch_allowed: bool,
}

impl CommandPreview {
    pub fn render(&self) -> String {
        format!(
            "Command Preview\ncommand=\"{}\"\ntarget=\"{}\"\nrisk={}\nauthority_path=\"{}\"\nexpected_state_change=\"{}\"\nrequires_preview={}\ndispatch_allowed={}\n",
            redact_summary(&self.command),
            redact_summary(&self.target),
            self.risk.as_str(),
            self.authority_path,
            redact_summary(self.expected_state_change),
            self.requires_preview,
            self.dispatch_allowed
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandPaletteError {
    pub reason: String,
}

impl CommandPaletteError {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

pub struct CommandPalette;

impl CommandPalette {
    pub fn suggestions(context: &CommandPaletteContext) -> Vec<CommandSuggestion> {
        let mut suggestions = vec![
            suggestion(
                "Show dashboard",
                "dashboard.show",
                PaletteRisk::ReadOnly,
                "agentd TUI projection controller",
                false,
            ),
            suggestion(
                "Refresh projections",
                "refresh",
                PaletteRisk::ReadOnly,
                "agentd TUI projection controller",
                false,
            ),
            suggestion(
                "Show run",
                format!("run.show {}", context.run_id()),
                PaletteRisk::ReadOnly,
                "AgentCore RunStore",
                false,
            ),
            suggestion(
                "Show event feed",
                "events.show 12",
                PaletteRisk::ReadOnly,
                "ProjectionSnapshot + SecurityExecutionEngine AuditJournal",
                false,
            ),
            suggestion(
                "Show capabilities",
                "capabilities.show",
                PaletteRisk::ReadOnly,
                "agentd TUI capability index projection",
                false,
            ),
            suggestion(
                "Show workflows",
                "workflows.show",
                PaletteRisk::ReadOnly,
                "agentd TUI workflow catalog projection",
                false,
            ),
            suggestion(
                "Show approvals",
                format!("approvals.show {}", context.run_id()),
                PaletteRisk::ReadOnly,
                "AgentCore RunStore + SecurityExecutionEngine AuditJournal",
                false,
            ),
            suggestion(
                "Show recovery",
                format!("recovery.show {}", context.run_id()),
                PaletteRisk::ReadOnly,
                "AgentCore RunStore + SecurityExecutionEngine AuditJournal",
                false,
            ),
        ];

        match context.focus {
            PaletteFocus::Approvals => {
                suggestions.push(suggestion(
                    "Approve current step",
                    format!(
                        "run.approve {} {} actor={}",
                        context.run_id(),
                        context.step_id(),
                        context.selected_actor
                    ),
                    PaletteRisk::Approval,
                    "AgentCore approval token + SecurityExecutionEngine audit binding",
                    true,
                ));
                suggestions.push(suggestion(
                    "Deny current step",
                    format!(
                        "run.deny {} {} actor={} reason=operator-review",
                        context.run_id(),
                        context.step_id(),
                        context.selected_actor
                    ),
                    PaletteRisk::Approval,
                    "AgentCore approval token + SecurityExecutionEngine audit binding",
                    true,
                ));
            }
            PaletteFocus::Recovery => {
                suggestions.push(suggestion(
                    "Recover run",
                    format!("run.recover {}", context.run_id()),
                    PaletteRisk::Recovery,
                    "AgentCore recovery + SecurityExecutionEngine audit journal",
                    true,
                ));
            }
            PaletteFocus::Support => {
                suggestions.push(suggestion(
                    "Export support bundle",
                    "support.bundle export",
                    PaletteRisk::Export,
                    "support_bundle redacted local evidence export",
                    true,
                ));
            }
            PaletteFocus::Ecosystem => {
                suggestions.push(suggestion(
                    "Preview activation",
                    format!("aom.activate.preview {}", context.artifact()),
                    PaletteRisk::ActivationPreview,
                    "agent_core::ecosystem activation plan preview",
                    true,
                ));
            }
            PaletteFocus::Dashboard | PaletteFocus::Runs | PaletteFocus::Release => {}
        }

        suggestions
    }

    pub fn preview(line: &str) -> Result<CommandPreview, CommandPaletteError> {
        let command = TuiCommand::parse(line).map_err(|error| CommandPaletteError {
            reason: error.reason,
        })?;
        Ok(preview_for_command(line.trim(), command))
    }
}

fn suggestion(
    label: &'static str,
    command: impl Into<String>,
    risk: PaletteRisk,
    authority_path: &'static str,
    requires_preview: bool,
) -> CommandSuggestion {
    CommandSuggestion {
        label,
        command: command.into(),
        risk,
        authority_path,
        requires_preview,
    }
}

fn preview_for_command(line: &str, command: TuiCommand) -> CommandPreview {
    match command {
        TuiCommand::Noop => preview(
            line,
            "-",
            PaletteRisk::ReadOnly,
            "agentd TUI parser",
            "none",
            false,
            true,
        ),
        TuiCommand::Help
        | TuiCommand::Refresh
        | TuiCommand::DashboardShow
        | TuiCommand::PalettePreview { .. } => preview(
            line,
            "projection snapshot",
            PaletteRisk::ReadOnly,
            "agentd TUI projection controller",
            "read-only projection refresh",
            false,
            true,
        ),
        TuiCommand::Exit => preview(
            line,
            "operator session",
            PaletteRisk::ReadOnly,
            "agentd TUI shell",
            "close local TUI session",
            false,
            true,
        ),
        TuiCommand::IntentSubmit { intent, .. } => preview(
            line,
            &format!("intent={intent}"),
            PaletteRisk::Lifecycle,
            "AgentCore intent acceptance + deterministic planner",
            "create or update durable PlanRun",
            true,
            true,
        ),
        TuiCommand::RunPlan { run_id } => preview(
            line,
            &format!("run={run_id}"),
            PaletteRisk::Lifecycle,
            "AgentCore PlanRun lifecycle",
            "plan run from durable intent",
            true,
            true,
        ),
        TuiCommand::RunAdvance { run_id } => preview(
            line,
            &format!("run={run_id}"),
            PaletteRisk::Lifecycle,
            "AgentCore PlanRun lifecycle + SecurityExecutionEngine gate",
            "advance run until next lifecycle boundary",
            true,
            true,
        ),
        TuiCommand::RunApprove {
            run_id,
            step_id,
            actor,
        } => preview(
            line,
            &format!("run={run_id} step={step_id} actor={actor}"),
            PaletteRisk::Approval,
            "AgentCore approval token + SecurityExecutionEngine audit binding",
            "grant exact approval token for bound step",
            true,
            true,
        ),
        TuiCommand::RunDeny {
            run_id,
            step_id,
            actor,
            ..
        } => preview(
            line,
            &format!("run={run_id} step={step_id} actor={actor}"),
            PaletteRisk::Approval,
            "AgentCore approval token + SecurityExecutionEngine audit binding",
            "deny bound step and keep side effects closed",
            true,
            true,
        ),
        TuiCommand::RunSuspend { run_id, .. } => preview(
            line,
            &format!("run={run_id}"),
            PaletteRisk::Lifecycle,
            "AgentCore PlanRun lifecycle",
            "suspend run with operator reason",
            true,
            true,
        ),
        TuiCommand::RunRecover { run_id } => preview(
            line,
            &format!("run={run_id}"),
            PaletteRisk::Recovery,
            "AgentCore recovery + SecurityExecutionEngine audit journal",
            "recover from durable run and audit state",
            true,
            true,
        ),
        TuiCommand::RunShow { run_id } => preview(
            line,
            &format!("run={run_id}"),
            PaletteRisk::ReadOnly,
            "AgentCore RunStore",
            "read-only run projection",
            false,
            true,
        ),
        TuiCommand::AuditShow { run_id } => preview(
            line,
            &format!("run={}", run_id.as_deref().unwrap_or("latest")),
            PaletteRisk::ReadOnly,
            "SecurityExecutionEngine AuditJournal",
            "read-only audit projection",
            false,
            true,
        ),
        TuiCommand::EventFeedShow { limit } => preview(
            line,
            &format!("limit={limit}"),
            PaletteRisk::ReadOnly,
            "ProjectionSnapshot + SecurityExecutionEngine AuditJournal",
            "read-only bounded event feed projection",
            false,
            true,
        ),
        TuiCommand::ApprovalsShow { run_id } => preview(
            line,
            &format!("run={}", run_id.as_deref().unwrap_or("latest")),
            PaletteRisk::ReadOnly,
            "AgentCore RunStore + SecurityExecutionEngine AuditJournal",
            "read-only approval queue projection",
            false,
            true,
        ),
        TuiCommand::RecoveryShow { run_id } => preview(
            line,
            &format!("run={}", run_id.as_deref().unwrap_or("latest")),
            PaletteRisk::ReadOnly,
            "AgentCore RunStore + SecurityExecutionEngine AuditJournal",
            "read-only recovery projection",
            false,
            true,
        ),
        TuiCommand::SupportBundleStatus => preview(
            line,
            "support bundle",
            PaletteRisk::ReadOnly,
            "support_bundle redacted projection",
            "read-only support bundle readiness",
            false,
            true,
        ),
        TuiCommand::SupportBundleExport => preview(
            line,
            "support bundle",
            PaletteRisk::Export,
            "support_bundle redacted local evidence export",
            "write redacted support bundle artifact",
            true,
            true,
        ),
        TuiCommand::CapabilityIndexShow => preview(
            line,
            "capability index",
            PaletteRisk::ReadOnly,
            "agentd TUI capability index projection",
            "read-only capability catalog projection",
            false,
            true,
        ),
        TuiCommand::WorkflowCatalogShow { workflow_id } => preview(
            line,
            &format!("workflow={}", workflow_id.as_deref().unwrap_or("all")),
            PaletteRisk::ReadOnly,
            "agentd TUI workflow catalog projection",
            "read-only workflow catalog projection",
            false,
            true,
        ),
        TuiCommand::LaunchPreview {
            workflow_id,
            inputs,
        } => preview(
            line,
            &format!("workflow={workflow_id} inputs={}", inputs.len()),
            PaletteRisk::Lifecycle,
            "AgentCore planner -> SecurityExecutionEngine -> approval -> rollback",
            "preview typed launch intent; explicit dispatch required; no PlanRun created",
            true,
            true,
        ),
        TuiCommand::AomArtifactShow { coordinate } => preview(
            line,
            &format!("artifact={coordinate}"),
            PaletteRisk::ReadOnly,
            "agent_core::ecosystem registry/staging/active-set projections",
            "read-only artifact trust and activation gate projection",
            false,
            true,
        ),
        TuiCommand::ReleaseProvenanceShow => preview(
            line,
            "release provenance",
            PaletteRisk::ReadOnly,
            "local release evidence artifacts",
            "read-only release provenance projection; no signing or promotion mutation",
            false,
            true,
        ),
        TuiCommand::PromotionBlockersShow => preview(
            line,
            "promotion blockers",
            PaletteRisk::ReadOnly,
            "local release provenance promotion.blockers",
            "read-only promotion blocker projection; no blocker override or promotion mutation",
            false,
            true,
        ),
        TuiCommand::UpdateRollbackShow => preview(
            line,
            "update rollback evidence",
            PaletteRisk::ReadOnly,
            "local release update metadata and rollback evidence",
            "read-only update and rollback projection; no slot mutation or rollback execution",
            false,
            true,
        ),
        TuiCommand::GateStatusShow => preview(
            line,
            "release gate evidence",
            PaletteRisk::ReadOnly,
            "local QEMU/rootfs/replay gate artifacts",
            "read-only gate evidence projection; no QEMU boot, rootfs validation, or replay execution",
            false,
            true,
        ),
        TuiCommand::SigningStatusShow => preview(
            line,
            "release signing evidence",
            PaletteRisk::ReadOnly,
            "local candidate signatures and production signature verification artifacts",
            "read-only signing evidence projection; no signing, key handling, or production promotion",
            false,
            true,
        ),
        TuiCommand::RolloutRingsShow => preview(
            line,
            "fleet rollout ring projection",
            PaletteRisk::ReadOnly,
            "local rollout preview artifacts and AgentCore/SecurityExecutionEngine authority boundaries",
            "read-only rollout ring projection; no remote rollout execution, fleet mutation, or rollback execution",
            false,
            true,
        ),
        TuiCommand::Aom { args } => preview_aom(line, &args),
    }
}

fn preview_aom(line: &str, args: &[String]) -> CommandPreview {
    let action = args.first().map(String::as_str).unwrap_or("-");
    let target = args.get(1).map(String::as_str).unwrap_or("<registry>");
    match action {
        "activate" => preview(
            line,
            &format!("artifact={target}"),
            PaletteRisk::ActivationPreview,
            "agent_core::ecosystem activation plan preview",
            "preview activation plan without mutating active set",
            true,
            true,
        ),
        "stage" => preview(
            line,
            &format!("artifact={target}"),
            PaletteRisk::Lifecycle,
            "agent_core::ecosystem resolver and staging planner",
            "stage inert artifact evidence only",
            true,
            true,
        ),
        "verify" | "show" | "search" | "explain" => preview(
            line,
            &format!("artifact_or_registry={target}"),
            PaletteRisk::ReadOnly,
            "agent_core::ecosystem projection APIs",
            "read-only ecosystem projection",
            false,
            true,
        ),
        _ => preview(
            line,
            "aom",
            PaletteRisk::ReadOnly,
            "agent_core::ecosystem projection APIs",
            "read-only ecosystem projection",
            false,
            true,
        ),
    }
}

fn preview(
    line: &str,
    target: &str,
    risk: PaletteRisk,
    authority_path: &'static str,
    expected_state_change: &'static str,
    requires_preview: bool,
    dispatch_allowed: bool,
) -> CommandPreview {
    CommandPreview {
        command: line.to_string(),
        target: target.to_string(),
        risk,
        authority_path,
        expected_state_change,
        requires_preview,
        dispatch_allowed,
    }
}
