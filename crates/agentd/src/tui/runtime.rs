use std::fs;
use std::path::{Path, PathBuf};

use crate::agent_core::{
    model::{IntentCtx, IntentSource, TrustBoundary},
    model_broker::StubModelProvider,
    planner::DeterministicPlanner,
    recovery::AgentRunRecoveryCoordinator,
    run_loop::{AgentCore, RunProjection},
    run_store::FileRunStore,
};
use crate::aom::run_aom;
use crate::audit::{AuditJournal, redact_summary};
use crate::lifecycle::Agentd;
use crate::operator_projection::OperatorProjection;
use crate::runtime_contracts::{contains_secret_value, stable_contract_hash};
use crate::support_bundle::SupportBundleProjection;

use super::aom_artifact_panel::AomArtifactPanel;
use super::approval_center::ApprovalCenterPanel;
use super::capability_index::CapabilityIndexProjection;
use super::event_feed::EventFeed;
use super::gate_status_panel::GateStatusPanel;
use super::launch_preview::LaunchIntentPreview;
use super::palette::CommandPalette;
use super::parser::TuiCommand;
use super::promotion_blocker_panel::PromotionBlockerPanel;
use super::recovery_workbench::RecoveryWorkbench;
use super::release_provenance_panel::ReleaseProvenancePanel;
use super::render::{
    binding_for_step, render_help, render_operator_projection, render_run_projection,
};
use super::rollout_ring_panel::RolloutRingPanel;
use super::signing_status_panel::SigningStatusPanel;
use super::snapshot::ProjectionSnapshot;
use super::support_console::SupportConsolePanel;
use super::update_rollback_panel::UpdateRollbackPanel;
use super::workflow_catalog::WorkflowCatalogProjection;

pub const DEFAULT_TUI_RUN_STORE: &str = ".workflow/artifacts/tui/runs";
pub const DEFAULT_TUI_AUDIT_JOURNAL: &str = ".workflow/artifacts/tui/audit.jsonl";
pub const DEFAULT_TUI_SUPPORT_BUNDLE: &str = ".workflow/artifacts/tui/support-bundle.json";

type DefaultTuiCore = AgentCore<FileRunStore, DeterministicPlanner<StubModelProvider>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TuiRuntimePaths {
    pub run_store_root: PathBuf,
    pub audit_journal_path: PathBuf,
    pub support_bundle_path: PathBuf,
}

impl Default for TuiRuntimePaths {
    fn default() -> Self {
        Self {
            run_store_root: PathBuf::from(DEFAULT_TUI_RUN_STORE),
            audit_journal_path: PathBuf::from(DEFAULT_TUI_AUDIT_JOURNAL),
            support_bundle_path: PathBuf::from(DEFAULT_TUI_SUPPORT_BUNDLE),
        }
    }
}

impl TuiRuntimePaths {
    pub fn new(run_store_root: impl Into<PathBuf>, audit_journal_path: impl Into<PathBuf>) -> Self {
        Self {
            run_store_root: run_store_root.into(),
            audit_journal_path: audit_journal_path.into(),
            support_bundle_path: PathBuf::from(DEFAULT_TUI_SUPPORT_BUNDLE),
        }
    }

    pub fn with_support_bundle_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.support_bundle_path = path.into();
        self
    }

    fn ensure(&self) -> Result<(), String> {
        fs::create_dir_all(&self.run_store_root)
            .map_err(|error| format!("create TUI run store failed: {error}"))?;
        ensure_parent_dir(&self.audit_journal_path)?;
        ensure_parent_dir(&self.support_bundle_path)?;
        Ok(())
    }
}

pub struct TuiRuntimeController {
    core: DefaultTuiCore,
    paths: TuiRuntimePaths,
}

impl TuiRuntimeController {
    pub fn new(paths: TuiRuntimePaths) -> Result<Self, String> {
        paths.ensure()?;
        let core = AgentCore::new(
            FileRunStore::new(paths.run_store_root.clone()),
            DeterministicPlanner::stub(),
            AuditJournal::new(paths.audit_journal_path.clone()),
        );
        Ok(Self { core, paths })
    }

    pub fn default_local() -> Result<Self, String> {
        Self::new(TuiRuntimePaths::default())
    }

    pub fn paths(&self) -> &TuiRuntimePaths {
        &self.paths
    }

    pub fn journal(&self) -> &AuditJournal {
        self.core.journal()
    }

    pub fn projection_snapshot(&self, agentd: &Agentd) -> ProjectionSnapshot {
        let latest_run = self.core.journal().latest_run();
        let run_projection = match &latest_run {
            Ok(Some(run_id)) => self
                .core
                .project_run(run_id)
                .map(Some)
                .map_err(|error| error.to_string()),
            Ok(None) => Ok(None),
            Err(error) => Err(error.to_string()),
        };
        let audit_projection = match latest_run {
            Ok(Some(run_id)) => self
                .core
                .journal()
                .project_runtime_run(&run_id)
                .map_err(|error| error.to_string()),
            Ok(None) => Ok(None),
            Err(error) => Err(error.to_string()),
        };
        ProjectionSnapshot::collect(
            agentd,
            self.core.journal(),
            &self.paths,
            run_projection,
            audit_projection,
        )
    }

    pub fn dispatch_line(&self, agentd: &Agentd, line: &str) -> TuiDispatch {
        match TuiCommand::parse(line) {
            Ok(command) => self.dispatch(agentd, command),
            Err(error) => {
                TuiDispatch::render(format!("TUI Error\nkind=parse\nreason={}\n", error.reason))
            }
        }
    }

    pub fn dispatch(&self, agentd: &Agentd, command: TuiCommand) -> TuiDispatch {
        match command {
            TuiCommand::Noop => TuiDispatch::render(String::new()),
            TuiCommand::Exit => TuiDispatch {
                text: "TUI Session\nstatus=exit\n".to_string(),
                should_exit: true,
            },
            TuiCommand::Help => TuiDispatch::render(render_help()),
            TuiCommand::PalettePreview { line } => {
                TuiDispatch::from_result(self.render_palette_preview(&line))
            }
            TuiCommand::Refresh | TuiCommand::DashboardShow => {
                TuiDispatch::from_result(self.render_dashboard(agentd))
            }
            TuiCommand::IntentSubmit { intent, actor } => {
                TuiDispatch::from_result(self.submit_intent(&intent, &actor))
            }
            TuiCommand::RunPlan { run_id } => TuiDispatch::from_result(
                self.resolve_run_id(&run_id)
                    .and_then(|run_id| {
                        self.core
                            .plan_run(&run_id)
                            .map_err(|error| error.to_string())
                    })
                    .map(render_run_projection),
            ),
            TuiCommand::RunAdvance { run_id } => TuiDispatch::from_result(
                self.resolve_run_id(&run_id)
                    .and_then(|run_id| {
                        self.core
                            .advance_run(&run_id)
                            .map_err(|error| error.to_string())
                    })
                    .map(render_run_projection),
            ),
            TuiCommand::RunApprove {
                run_id,
                step_id,
                actor,
            } => TuiDispatch::from_result(
                self.preflight_approval(&run_id, &step_id, &actor)
                    .and_then(|run_id| {
                        self.core
                            .approve_step(&run_id, &step_id, &actor)
                            .map_err(|error| error.to_string())
                    })
                    .map(render_run_projection),
            ),
            TuiCommand::RunDeny {
                run_id,
                step_id,
                actor,
                reason,
            } => TuiDispatch::from_projection(self.resolve_run_id(&run_id).and_then(|run_id| {
                self.core
                    .deny_step(&run_id, &step_id, &actor, &reason)
                    .map_err(|error| error.to_string())
            })),
            TuiCommand::RunSuspend { run_id, reason } => TuiDispatch::from_result(
                self.resolve_run_id(&run_id)
                    .and_then(|run_id| {
                        self.core
                            .suspend_run(&run_id, &reason)
                            .map_err(|error| error.to_string())
                    })
                    .map(render_run_projection),
            ),
            TuiCommand::RunRecover { run_id } => TuiDispatch::from_result(
                self.resolve_run_id(&run_id)
                    .and_then(|run_id| {
                        self.core
                            .recover_run(&run_id)
                            .map_err(|error| error.to_string())
                    })
                    .map(render_run_projection),
            ),
            TuiCommand::RunShow { run_id } => {
                TuiDispatch::from_result(self.resolve_run_id(&run_id).and_then(|run_id| {
                    self.core
                        .project_run(&run_id)
                        .map(render_run_projection)
                        .map_err(|error| error.to_string())
                }))
            }
            TuiCommand::AuditShow { run_id } => {
                TuiDispatch::from_result(self.render_audit(run_id.as_deref()))
            }
            TuiCommand::EventFeedShow { limit } => {
                TuiDispatch::from_result(self.render_event_feed(agentd, limit))
            }
            TuiCommand::ApprovalsShow { run_id } => {
                TuiDispatch::from_result(self.render_approvals(run_id.as_deref()))
            }
            TuiCommand::RecoveryShow { run_id } => {
                TuiDispatch::from_result(self.render_recovery(run_id.as_deref()))
            }
            TuiCommand::SupportBundleStatus => {
                TuiDispatch::from_result(self.render_support_bundle(agentd, false))
            }
            TuiCommand::SupportBundleExport => {
                TuiDispatch::from_result(self.render_support_bundle(agentd, true))
            }
            TuiCommand::CapabilityIndexShow => {
                TuiDispatch::from_result(self.render_capability_index(agentd))
            }
            TuiCommand::WorkflowCatalogShow { workflow_id } => TuiDispatch::from_result(
                self.render_workflow_catalog(agentd, workflow_id.as_deref()),
            ),
            TuiCommand::LaunchPreview {
                workflow_id,
                inputs,
            } => {
                TuiDispatch::from_result(self.render_launch_preview(agentd, &workflow_id, &inputs))
            }
            TuiCommand::AomArtifactShow { coordinate } => {
                TuiDispatch::from_result(self.render_aom_artifact(&coordinate))
            }
            TuiCommand::ReleaseProvenanceShow => {
                TuiDispatch::from_result(self.render_release_provenance())
            }
            TuiCommand::PromotionBlockersShow => {
                TuiDispatch::from_result(self.render_promotion_blockers())
            }
            TuiCommand::UpdateRollbackShow => {
                TuiDispatch::from_result(self.render_update_rollback())
            }
            TuiCommand::GateStatusShow => TuiDispatch::from_result(self.render_gate_status()),
            TuiCommand::SigningStatusShow => TuiDispatch::from_result(self.render_signing_status()),
            TuiCommand::RolloutRingsShow => TuiDispatch::from_result(self.render_rollout_rings()),
            TuiCommand::Aom { args } => TuiDispatch::from_result(
                run_aom(&args).map(|output| format!("TUI Ecosystem\n{output}\n")),
            ),
        }
    }

    fn submit_intent(&self, requested_outcome: &str, actor: &str) -> Result<String, String> {
        if contains_secret_value(requested_outcome) {
            return Err("secret-like value is not allowed in TUI intent".to_string());
        }
        let intent = IntentCtx::new(
            actor,
            TrustBoundary::Operator,
            IntentSource::Tui,
            "agentos:tui",
            requested_outcome,
        )
        .map_err(|error| error.to_string())?;
        let request_id = format!(
            "tui-{}",
            stable_contract_hash(&format!("{actor}:{requested_outcome}"))
        );
        let accepted = self
            .core
            .accept_intent(&request_id, intent)
            .map_err(|error| error.to_string())?;
        let planned = self
            .core
            .plan_run(&accepted.run_id)
            .map_err(|error| error.to_string())?;
        Ok(render_run_projection(planned))
    }

    fn render_palette_preview(&self, line: &str) -> Result<String, String> {
        CommandPalette::preview(line)
            .map(|preview| preview.render())
            .map_err(|error| error.reason)
    }

    fn render_dashboard(&self, agentd: &Agentd) -> Result<String, String> {
        let projection = OperatorProjection::collect(agentd, Some(self.core.journal()), None)
            .map_err(|error| error.to_string())?;
        let snapshot = self.projection_snapshot(agentd);
        Ok(format!(
            "TUI Dashboard\nmode=durable projection_controller=true run_store={} audit_journal={}\n{}\n{}\n",
            self.paths.run_store_root.display(),
            self.paths.audit_journal_path.display(),
            render_operator_projection(&projection).trim_end(),
            snapshot.to_cli_text()
        ))
    }

    fn render_audit(&self, run_id: Option<&str>) -> Result<String, String> {
        let run_id = self.resolve_run_id(run_id.unwrap_or("latest"))?;
        let timeline = self
            .core
            .journal()
            .run_timeline(&run_id)
            .map_err(|error| error.to_string())?;
        if timeline.is_empty() {
            return Err(format!("audit journal has no run: {run_id}"));
        }
        Ok(format!(
            "TUI Audit\nrun={run_id}\nevents={}\n{}\n",
            timeline.len(),
            timeline
                .iter()
                .map(|line| format!("  - {}", redact_summary(line)))
                .collect::<Vec<_>>()
                .join("\n")
        ))
    }

    fn render_event_feed(&self, agentd: &Agentd, limit: usize) -> Result<String, String> {
        let snapshot = self.projection_snapshot(agentd);
        EventFeed::collect(&snapshot, self.core.journal(), limit).map(|feed| {
            let mut rendered = feed.render();
            rendered.push('\n');
            rendered
        })
    }

    fn render_support_bundle(&self, agentd: &Agentd, export: bool) -> Result<String, String> {
        let run_id = self
            .core
            .journal()
            .latest_run()
            .map_err(|error| error.to_string())?
            .unwrap_or_else(|| "no-run".to_string());
        let projection = SupportBundleProjection::from_journal(
            self.core.journal(),
            format!("support-{run_id}"),
            vec![run_id.clone()],
        )
        .map_err(|error| error.to_string())?;
        let json = projection.to_json();
        if export {
            fs::write(&self.paths.support_bundle_path, &json)
                .map_err(|error| format!("support bundle export failed: {error}"))?;
        }
        let operator =
            OperatorProjection::collect(agentd, Some(self.core.journal()), Some(&run_id))
                .map_err(|error| error.to_string())?;
        let snapshot = self.projection_snapshot(agentd);
        let mut rendered = SupportConsolePanel::collect(
            export,
            &self.paths.support_bundle_path,
            projection,
            operator,
            snapshot,
        )
        .render();
        rendered.push('\n');
        Ok(rendered)
    }

    fn render_capability_index(&self, agentd: &Agentd) -> Result<String, String> {
        let operator = OperatorProjection::collect(agentd, Some(self.core.journal()), None)
            .map_err(|error| error.to_string())?;
        let snapshot = self.projection_snapshot(agentd);
        let mut rendered = CapabilityIndexProjection::collect(&operator, &snapshot).render();
        rendered.push('\n');
        Ok(rendered)
    }

    fn render_workflow_catalog(
        &self,
        agentd: &Agentd,
        workflow_id: Option<&str>,
    ) -> Result<String, String> {
        let operator = OperatorProjection::collect(agentd, Some(self.core.journal()), None)
            .map_err(|error| error.to_string())?;
        let snapshot = self.projection_snapshot(agentd);
        let capabilities = CapabilityIndexProjection::collect(&operator, &snapshot);
        let mut rendered = WorkflowCatalogProjection::collect(&capabilities).render(workflow_id);
        rendered.push('\n');
        Ok(rendered)
    }

    fn render_launch_preview(
        &self,
        agentd: &Agentd,
        workflow_id: &str,
        inputs: &[String],
    ) -> Result<String, String> {
        let operator = OperatorProjection::collect(agentd, Some(self.core.journal()), None)
            .map_err(|error| error.to_string())?;
        let snapshot = self.projection_snapshot(agentd);
        let capabilities = CapabilityIndexProjection::collect(&operator, &snapshot);
        let catalog = WorkflowCatalogProjection::collect(&capabilities);
        let mut rendered = LaunchIntentPreview::collect(&catalog, workflow_id, inputs)
            .map_err(|error| error.reason)?
            .render();
        rendered.push('\n');
        Ok(rendered)
    }

    fn render_aom_artifact(&self, coordinate: &str) -> Result<String, String> {
        let mut rendered = AomArtifactPanel::collect(coordinate)?.render();
        rendered.push('\n');
        Ok(rendered)
    }

    fn render_release_provenance(&self) -> Result<String, String> {
        let mut rendered = ReleaseProvenancePanel::collect().render();
        rendered.push('\n');
        Ok(rendered)
    }

    fn render_promotion_blockers(&self) -> Result<String, String> {
        let mut rendered = PromotionBlockerPanel::collect().render();
        rendered.push('\n');
        Ok(rendered)
    }

    fn render_update_rollback(&self) -> Result<String, String> {
        let mut rendered = UpdateRollbackPanel::collect().render();
        rendered.push('\n');
        Ok(rendered)
    }

    fn render_gate_status(&self) -> Result<String, String> {
        let mut rendered = GateStatusPanel::collect().render();
        rendered.push('\n');
        Ok(rendered)
    }

    fn render_signing_status(&self) -> Result<String, String> {
        let mut rendered = SigningStatusPanel::collect().render();
        rendered.push('\n');
        Ok(rendered)
    }

    fn render_rollout_rings(&self) -> Result<String, String> {
        let mut rendered = RolloutRingPanel::collect().render();
        rendered.push('\n');
        Ok(rendered)
    }

    fn render_approvals(&self, run_id: Option<&str>) -> Result<String, String> {
        let run_id = self.resolve_run_id(run_id.unwrap_or("latest"))?;
        let run = self
            .core
            .project_run(&run_id)
            .map_err(|error| error.to_string())?;
        let audit = self
            .core
            .journal()
            .project_runtime_run(&run_id)
            .map_err(|error| error.to_string())?;
        ApprovalCenterPanel::collect(&run, audit.as_ref()).map(|panel| {
            let mut rendered = panel.render();
            rendered.push('\n');
            rendered
        })
    }

    fn preflight_approval(
        &self,
        requested_run_id: &str,
        step_id: &str,
        actor: &str,
    ) -> Result<String, String> {
        let run_id = self.resolve_run_id(requested_run_id)?;
        let run = self
            .core
            .project_run(&run_id)
            .map_err(|error| error.to_string())?;
        if run.state.as_str() != "AwaitingApproval" || run.approval_status.as_str() != "Pending" {
            return Err(format!(
                "approval is not actionable run={} state={} approval={} reason=stale-or-expired",
                run.run_id,
                run.state.as_str(),
                run.approval_status.as_str()
            ));
        }
        if run.current_step_id.as_deref() != Some(step_id) {
            return Err(format!(
                "approval step mismatch run={} current_step={} requested_step={}",
                run.run_id,
                run.current_step_id.as_deref().unwrap_or("-"),
                step_id
            ));
        }
        let audit = self
            .core
            .journal()
            .project_runtime_run(&run_id)
            .map_err(|error| error.to_string())?;
        let binding = audit
            .as_ref()
            .and_then(|projection| binding_for_step(projection, step_id))
            .ok_or_else(|| {
                format!(
                    "approval missing exact binding context run={} step={}",
                    run.run_id, step_id
                )
            })?;
        if binding.actor != actor {
            return Err(format!(
                "approval actor mismatch run={} step={} binding_actor={} requested_actor={}",
                run.run_id, step_id, binding.actor, actor
            ));
        }
        Ok(run_id)
    }

    fn render_recovery(&self, run_id: Option<&str>) -> Result<String, String> {
        let run_id = match run_id {
            Some(value) if value != "latest" => self.resolve_run_id(value)?,
            _ => match self
                .core
                .journal()
                .latest_run()
                .map_err(|error| error.to_string())?
            {
                Some(value) => value,
                None => {
                    return Ok(format!("{}\n", RecoveryWorkbench::empty()));
                }
            },
        };
        let run = self
            .core
            .project_run(&run_id)
            .map_err(|error| error.to_string())?;
        let audit = self
            .core
            .journal()
            .project_runtime_run(&run_id)
            .map_err(|error| error.to_string())?;
        let report = AgentRunRecoveryCoordinator::new(self.core.store(), self.core.journal())
            .scan()
            .map_err(|error| error.to_string())?;
        let mut rendered = RecoveryWorkbench::collect(&run, report, audit.as_ref()).render();
        rendered.push('\n');
        Ok(rendered)
    }

    fn resolve_run_id(&self, requested: &str) -> Result<String, String> {
        if requested == "latest" {
            self.core
                .journal()
                .latest_run()
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "audit journal has no runs".to_string())
        } else {
            Ok(requested.to_string())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TuiDispatch {
    pub text: String,
    pub should_exit: bool,
}

impl TuiDispatch {
    fn render(text: String) -> Self {
        Self {
            text,
            should_exit: false,
        }
    }

    fn from_projection<E: ToString>(result: Result<RunProjection, E>) -> Self {
        Self::from_result(
            result
                .map(render_run_projection)
                .map_err(|error| error.to_string()),
        )
    }

    fn from_result(result: Result<String, String>) -> Self {
        match result {
            Ok(text) => Self::render(text),
            Err(error) => Self::render(format!(
                "TUI Error\nkind=runtime\nreason={}\n",
                redact_summary(&error)
            )),
        }
    }
}

pub fn run_scripted_lines(
    agentd: &Agentd,
    controller: &TuiRuntimeController,
    lines: &[String],
) -> String {
    let mut output = String::new();
    for line in lines {
        let dispatch = controller.dispatch_line(agentd, line);
        if !dispatch.text.is_empty() {
            output.push_str(&dispatch.text);
            if !dispatch.text.ends_with('\n') {
                output.push('\n');
            }
        }
        if dispatch.should_exit {
            break;
        }
    }
    output
}

fn ensure_parent_dir(path: &Path) -> Result<(), String> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    fs::create_dir_all(parent).map_err(|error| {
        format!(
            "create parent directory failed for {}: {error}",
            path.display()
        )
    })
}
