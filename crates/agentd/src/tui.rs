mod aom_artifact_panel;
mod approval_center;
mod capability_index;
mod degraded_state;
mod event_feed;
mod gate_status_panel;
mod launch_preview;
mod layout;
mod legacy;
mod palette;
mod parser;
mod promotion_blocker_panel;
mod recovery_workbench;
mod release_provenance_panel;
mod render;
mod rollback_preview;
mod rollout_ring_panel;
mod runtime;
mod signing_status_panel;
mod snapshot;
mod support_console;
mod update_rollback_panel;
mod workflow_catalog;

pub use aom_artifact_panel::{AOM_ARTIFACT_PANEL_SCHEMA_VERSION, AomArtifactPanel};
pub use approval_center::{ApprovalCenterItem, ApprovalCenterPanel};
pub use capability_index::{
    CAPABILITY_INDEX_SCHEMA_VERSION, CapabilityIndexItem, CapabilityIndexProjection,
};
pub use degraded_state::{
    DEGRADED_EXPLAINER_SCHEMA_VERSION, DegradedStateExplainer, DegradedStateItem,
};
pub use event_feed::{DEFAULT_EVENT_FEED_LIMIT, EventCursor, EventFeed, EventFeedItem};
pub use gate_status_panel::{GATE_STATUS_PANEL_SCHEMA_VERSION, GateStatusPanel};
pub use launch_preview::{LAUNCH_INTENT_PREVIEW_SCHEMA_VERSION, LaunchIntentPreview};
pub use layout::{
    FocusPanel, LayoutMode, Pane, PaneKind, PaneRect, PanelLayout, PanelSnapshot, TerminalSize,
    render_full_screen_snapshot, render_layout_snapshot,
};
pub use legacy::{
    ApprovalDecision, AuditEvent, TuiSession, build_demo_session, render_diff_preview,
};
pub use palette::{
    CommandPalette, CommandPaletteContext, CommandPaletteError, CommandPreview, CommandSuggestion,
    PaletteFocus, PaletteRisk,
};
pub use parser::{TuiCommand, TuiParseError};
pub use promotion_blocker_panel::{
    PROMOTION_BLOCKER_PANEL_SCHEMA_VERSION, PromotionBlockerItem, PromotionBlockerPanel,
};
pub use recovery_workbench::RecoveryWorkbench;
pub use release_provenance_panel::{
    RELEASE_PROVENANCE_PANEL_SCHEMA_VERSION, ReleaseProvenancePanel,
};
pub use render::{
    render_operator_projection, render_run_projection, render_runtime_audit_projection,
};
pub use rollback_preview::{RollbackConsequencePreview, RollbackPreviewItem};
pub use rollout_ring_panel::{ROLLOUT_RING_PANEL_SCHEMA_VERSION, RolloutRingPanel};
pub use runtime::{
    DEFAULT_TUI_AUDIT_JOURNAL, DEFAULT_TUI_RUN_STORE, DEFAULT_TUI_SUPPORT_BUNDLE, TuiDispatch,
    TuiRuntimeController, TuiRuntimePaths, run_scripted_lines,
};
pub use signing_status_panel::{SIGNING_STATUS_PANEL_SCHEMA_VERSION, SigningStatusPanel};
pub use snapshot::{
    PROJECTION_SNAPSHOT_SCHEMA_VERSION, ProjectionSnapshot, ProjectionSourceSnapshot,
};
pub use support_console::SupportConsolePanel;
pub use update_rollback_panel::{UPDATE_ROLLBACK_PANEL_SCHEMA_VERSION, UpdateRollbackPanel};
pub use workflow_catalog::{
    WORKFLOW_CATALOG_SCHEMA_VERSION, WorkflowCatalogItem, WorkflowCatalogProjection,
};
#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::lifecycle::{Agentd, LifecycleConfig};
    use crate::operator_projection::OperatorProjection;
    use crate::rollback::DiffPreview;
    use crate::runtime_contracts::stable_contract_hash;

    fn temp_tui_paths(name: &str) -> TuiRuntimePaths {
        let root = std::env::temp_dir().join(format!("agentd-tui-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("temp root");
        TuiRuntimePaths::new(root.join("runs"), root.join("audit.jsonl"))
            .with_support_bundle_path(root.join("support.json"))
    }

    fn started_agentd() -> Agentd {
        let mut agentd = Agentd::new(LifecycleConfig::default());
        agentd.start();
        agentd
    }

    fn run_id_from_output(output: &str) -> String {
        output
            .split_whitespace()
            .find_map(|token| token.strip_prefix("run="))
            .expect("run id in output")
            .to_string()
    }

    fn has_snapshot(root: &Path) -> bool {
        fn has_json_file(path: &Path) -> bool {
            let entries = std::fs::read_dir(path).expect("run store dir");
            entries.filter_map(Result::ok).any(|entry| {
                let path = entry.path();
                if path.is_dir() {
                    return has_json_file(&path);
                }
                path.extension()
                    .and_then(|extension| extension.to_str())
                    .is_some_and(|extension| extension == "json")
            })
        }

        has_json_file(root)
    }

    fn temp_aom_fixture_root(name: &str) -> std::path::PathBuf {
        let root =
            std::env::temp_dir().join(format!("agentd-tui-aom-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("aom temp root");
        root
    }

    fn write_aom_registry(
        root: &Path,
        coordinate: &str,
        revoked: bool,
        min_runtime: &str,
        max_runtime: &str,
        required_features: &[&str],
        optional_features: &[&str],
    ) -> std::path::PathBuf {
        let registry_path = root.join("registry-snapshot.json");
        let required = required_features
            .iter()
            .map(|feature| format!("\"{feature}\""))
            .collect::<Vec<_>>()
            .join(",");
        let optional = optional_features
            .iter()
            .map(|feature| format!("\"{feature}\""))
            .collect::<Vec<_>>()
            .join(",");
        let json = format!(
            "{{\"schema\":\"agentos.local-registry-snapshot.v1\",\"snapshot_id\":\"tui-aom-fixture\",\"generated_at\":\"2026-05-25T01:00:00Z\",\"expires_at\":\"2026-06-01T00:00:00Z\",\"local_pinned\":true,\"snapshot_digest\":\"sha256:tui-aom-snapshot\",\"artifacts\":[{{\"coordinate\":\"{coordinate}\",\"manifest_digest\":\"sha256:tui-aom-manifest\",\"artifact_digest\":\"sha256:tui-aom-artifact\",\"declared_artifact_digest\":\"sha256:tui-aom-artifact\",\"trust_tier\":\"core\",\"source_uri\":\"file:///etc/agentos/ecosystem/core/tui-aom.json\",\"revoked\":{revoked},\"min_runtime_contract_version\":\"{min_runtime}\",\"max_runtime_contract_version\":\"{max_runtime}\",\"architectures\":[\"x86_64\"],\"required_host_features\":[{required}],\"optional_host_features\":[{optional}],\"dependencies\":[\"agentos:policy-pack/agentos/core-policy@1.0.0\"],\"advisory_refs\":[]}}]}}"
        );
        std::fs::write(&registry_path, json).expect("write registry");
        registry_path
    }

    fn write_aom_staging(root: &Path, coordinate: &str) -> std::path::PathBuf {
        let staging_root = root.join("staged");
        let artifact_dir = staging_root.join("artifact");
        std::fs::create_dir_all(&artifact_dir).expect("staging dir");
        std::fs::write(
            artifact_dir.join("staging-report.json"),
            format!(
                "{{\"schema\":\"agentos.artifact-staging-report.v1\",\"staging_id\":\"stage-tui\",\"coordinate\":\"{coordinate}\",\"staged_path\":\"{}\",\"manifest_digest\":\"sha256:tui-aom-manifest\",\"staged_artifact_digest\":\"sha256:tui-aom-artifact\",\"verification_report_digest\":\"sha256:tui-aom-verification\",\"inert\":true,\"activation_prepared\":false}}",
                artifact_dir.join("artifact.json").display()
            ),
        )
        .expect("write staging report");
        std::fs::write(
            artifact_dir.join("verification-report.json"),
            format!(
                "{{\"schema\":\"agentos.artifact-verification-report.v1\",\"report_id\":\"verify-tui\",\"coordinate\":\"{coordinate}\",\"manifest_digest\":\"sha256:tui-aom-manifest\",\"artifact_digest\":\"sha256:tui-aom-artifact\",\"digest_match\":true,\"signature_verified\":true,\"sbom_verified\":true,\"revoked\":false,\"unknown_required_fields_rejected\":true,\"trust_tier\":\"core\",\"production_promotable\":true,\"accepted_for_production\":true,\"failure\":null}}"
            ),
        )
        .expect("write verification report");
        staging_root
    }

    fn write_aom_active_set(root: &Path, coordinate: Option<&str>) -> std::path::PathBuf {
        let active_set_path = root.join("active-set.json");
        let artifacts = coordinate
            .map(|coordinate| {
                format!(
                    "{{\"coordinate\":\"{coordinate}\",\"manifest_digest\":\"sha256:tui-aom-manifest\",\"activation_report_id\":\"act-tui\",\"rollback_handle\":\"rollback://tui-aom\",\"policy_version\":\"policy-v1\"}}"
                )
            })
            .unwrap_or_default();
        std::fs::write(
            &active_set_path,
            format!(
                "{{\"schema\":\"agentos.active-artifact-set.v1\",\"set_id\":\"tui-aom-active\",\"artifacts\":[{artifacts}],\"lock_hash\":\"sha256:tui-aom-lock\",\"activation_report_id\":\"act-tui\",\"audit_event_range\":\"audit:tui-aom\",\"generated_at\":\"1970-01-01T00:00:00Z\"}}"
            ),
        )
        .expect("write active set");
        active_set_path
    }

    fn temp_release_fixture_root(name: &str) -> std::path::PathBuf {
        let root =
            std::env::temp_dir().join(format!("agentd-tui-release-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("release temp root");
        root
    }

    fn write_release_fixture(root: &Path, dirty: bool, blockers: &[&str]) {
        write_release_fixture_with_gates(
            root,
            dirty,
            blockers,
            &[
                (
                    "cargo test -p agentd",
                    "cargo test -p agentd",
                    "passed",
                    ".workflow/artifacts/release/cargo-test-agentd.json",
                ),
                (
                    "TUI replay",
                    "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/tui-replay.ps1",
                    "passed",
                    ".workflow/artifacts/tui-replay/result.json",
                ),
            ],
        );
    }

    fn write_release_fixture_with_gates(
        root: &Path,
        dirty: bool,
        blockers: &[&str],
        gates: &[(&str, &str, &str, &str)],
    ) {
        std::fs::write(
            root.join("dependency-inventory.json"),
            r#"{"schema":"aios.dependency-inventory.v1","packages":[{"name":"agentd","version":"0.1.0"},{"name":"runtime_contracts","version":"0.1.0"}],"lockfile":{"path":"Cargo.lock","sha256":"sha256:lock"}}"#,
        )
        .expect("inventory");
        std::fs::write(
            root.join("sbom.json"),
            r#"{"schema":"agentos.candidate-sbom.v1","packages":[{"name":"agentd","version":"0.1.0"},{"name":"runtime_contracts","version":"0.1.0"}],"lockfile":{"path":"Cargo.lock","sha256":"sha256:lock"}}"#,
        )
        .expect("sbom");
        std::fs::write(
            root.join("update-metadata.json"),
            r#"{"schema":"agentos.candidate-update-metadata.v1","generated_at":"1970-01-01T00:00:00Z","production_ready_claim":false,"source":{"git_commit":"abc123","git_branch":"main"},"update_strategy":{"mode":"ab-rootfs","stage_target":"inactive-slot","active_slot_modified_in_place":false,"health_gate_required":true,"rollback_required":true},"artifacts":{"agentd_binary_sha256":"sha256:agentd","initramfs_sha256":"sha256:initramfs","initramfs_manifest_sha256":"sha256:initramfs-manifest","alpha_rootfs_manifest_sha256":"sha256:alpha-rootfs","rootfs_runtime_manifest_sha256":"sha256:runtime-manifest","active_artifact_set":{"path":"active-set.json","sha256":"sha256:active-set","required":true},"ecosystem_replay":{"path":"ecosystem-replay-result.json","sha256":"sha256:ecosystem","required":true},"sbom":{"path":"sbom.json","sha256":"sha256:sbom"}},"update_readiness":{"active_artifact_set_hash":"sha256:active-set","active_artifact_set_path":"active-set.json","active_artifact_set_present":true,"runtime_contract_compatibility_checked":true,"incompatible_active_artifacts":[],"rollback_preserves_previous_active_set":true,"previous_active_set_hash":"sha256:previous-active-set","restored_active_set_hash":"sha256:previous-active-set","ecosystem_replay_status":"passed","promotion_allowed":true},"signature_policy":{"status":"candidate-hash-bound"}}"#,
        )
        .expect("update metadata");
        std::fs::write(
            root.join("active-set.json"),
            r#"{"schema":"agentos.active-artifact-set.v1","set_id":"fixture-active"}"#,
        )
        .expect("active set");
        std::fs::write(
            root.join("ecosystem-replay-result.json"),
            r#"{"schema":"agentos.ecosystem-replay.v1","status":"passed"}"#,
        )
        .expect("ecosystem replay");

        for (name, file, hash) in [
            (
                "dependency_inventory",
                "dependency-inventory.json.sig.json",
                "sha256:inventory",
            ),
            ("sbom", "sbom.json.sig.json", "sha256:sbom"),
            (
                "update_metadata",
                "update-metadata.json.sig.json",
                "sha256:update",
            ),
            (
                "provenance",
                "provenance.json.sig.json",
                "sha256:provenance",
            ),
        ] {
            std::fs::write(
                root.join(file),
                format!(
                    "{{\"schema\":\"agentos.release-detached-signature.v1\",\"artifact\":{{\"name\":\"{name}\",\"sha256\":\"{hash}\"}},\"signature\":{{\"algorithm\":\"sha256-hash-bound-candidate-signature-v1\",\"value\":\"sig-{name}\"}},\"key\":{{\"key_id\":\"agentos-candidate-release-hash-bound-v1\",\"production_key_required\":false}}}}"
                ),
            )
            .expect("signature");
        }

        let blocker_json = blockers
            .iter()
            .map(|blocker| format!("\"{blocker}\""))
            .collect::<Vec<_>>()
            .join(",");
        let gate_json = gates
            .iter()
            .map(|(name, command, status, evidence_path)| {
                format!(
                    "{{\"name\":\"{}\",\"command\":\"{}\",\"status\":\"{}\",\"evidence_path\":\"{}\"}}",
                    crate::api::escape_json(name),
                    crate::api::escape_json(command),
                    crate::api::escape_json(status),
                    crate::api::escape_json(evidence_path)
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let dirty_status = if dirty {
            " M TASK.md\\n?? crates/agentd/src/tui/release_provenance_panel.rs"
        } else {
            ""
        };
        let promotion_status = if blockers.is_empty() {
            "promotable"
        } else {
            "blocked"
        };
        let artifacts = [
            ("agentd_binary", "agentd.exe", "sha256:agentd"),
            ("initramfs", "agentos-initramfs.cpio.gz", "sha256:initramfs"),
            (
                "alpha_rootfs_manifest",
                "agentos-alpha-rootfs.manifest.json",
                "sha256:alpha-rootfs",
            ),
            (
                "rootfs_runtime_manifest",
                "rootfs-runtime-manifest.json",
                "sha256:runtime-manifest",
            ),
            (
                "dependency_inventory",
                "dependency-inventory.json",
                "sha256:inventory",
            ),
            ("sbom", "sbom.json", "sha256:sbom"),
            ("update_metadata", "update-metadata.json", "sha256:update"),
            (
                "qemu_runtime_smoke",
                ".workflow/artifacts/boot/boot-smoke-result.json",
                "sha256:qemu",
            ),
            (
                "alpha_service_recovery_smoke",
                ".workflow/artifacts/alpha-service-recovery/result.json",
                "sha256:service",
            ),
            (
                "functional_capability_replay",
                ".workflow/artifacts/functional-replay/result.json",
                "sha256:functional",
            ),
            (
                "ecosystem_replay",
                ".workflow/artifacts/ecosystem-replay/result.json",
                "sha256:ecosystem",
            ),
            (
                "tui_replay",
                ".workflow/artifacts/tui-replay/result.json",
                "sha256:tui",
            ),
        ]
        .iter()
        .map(|(name, path, hash)| {
            format!("\"{name}\":{{\"path\":\"{path}\",\"sha256\":\"{hash}\",\"present\":true}}")
        })
        .collect::<Vec<_>>()
        .join(",");
        std::fs::write(
            root.join("provenance.json"),
            format!(
                "{{\"schema\":\"agentos.production-candidate.provenance.v1\",\"generated_at\":\"1970-01-01T00:00:00Z\",\"source\":{{\"git_commit\":\"abc123\",\"git_branch\":\"main\",\"git_status_porcelain\":\"{dirty_status}\"}},\"toolchain\":{{\"cargo\":\"cargo 1.0\",\"rustc\":\"rustc 1.0\",\"powershell\":\"7.5.0\"}},\"gates\":[{gate_json}],\"artifacts\":{{{artifacts}}},\"signing\":{{\"signature_schema\":\"agentos.release-detached-signature.v1\",\"algorithm\":\"sha256-hash-bound-candidate-signature-v1\",\"key_id\":\"agentos-candidate-release-hash-bound-v1\",\"required_detached_signatures\":[\"dependency_inventory\",\"sbom\",\"update_metadata\",\"provenance\"],\"production_key_required\":false,\"fail_closed\":true}},\"promotion\":{{\"status\":\"{promotion_status}\",\"blockers\":[{blocker_json}]}}}}"
            ),
        )
        .expect("provenance");
    }

    fn write_gate_status_fixture(root: &Path) {
        std::fs::write(
            root.join("boot-smoke-result.json"),
            r#"{"status":"completed","observed_all_markers":true,"observed_markers":{"AGENTD_HANDOFF_OK":true,"AGENTOS_RUNTIME_ARTIFACTS_OK":true,"AGENTOS_TUI_CONSOLE_READY":true},"runtime_manifest_marker":"AGENTOS_RUNTIME_MANIFEST_SHA256=sha256:runtime-manifest","runtime_artifact_ids":["policy.pack","tools.semantic","operator.commands","ecosystem.registry_snapshot","ecosystem.core_policy","ecosystem.workflow_service_recovery","model_broker.config","tui.config","state.runs","state.audit","state.rollback","state.memory"],"missing_runtime_artifact_ids":[],"failed_runtime_artifact_ids":[],"qemu_path":"E:\\qemu\\qemu-system-x86_64.exe","log_path":".workflow/artifacts/boot/boot-smoke.log","rootfs_runtime_manifest_sha256":"sha256:runtime-manifest"}"#,
        )
        .expect("boot smoke");
        std::fs::write(
            root.join("rootfs-runtime-manifest.json"),
            r#"{"schema":"agentos.rootfs-runtime-manifest.v1","runtime_artifact_ids":["policy.pack","tools.semantic","operator.commands","ecosystem.registry_snapshot","ecosystem.core_policy","ecosystem.workflow_service_recovery","model_broker.config","tui.config","state.runs","state.audit","state.rollback","state.memory"],"blocking_alpha_risks":[]}"#,
        )
        .expect("rootfs runtime manifest");
        std::fs::write(
            root.join("alpha-rootfs-validation.json"),
            r#"{"schema":"agentos.alpha-rootfs-validation.v1","result":"passed","summary":{"total":12,"passed":12,"failed":0}}"#,
        )
        .expect("rootfs validation");
        std::fs::write(
            root.join("functional-replay-result.json"),
            r#"{"schema":"agentos.functional-capability-replay.v1","status":"passed","summary":{"total":3,"passed":3,"failed":0}}"#,
        )
        .expect("functional replay");
        std::fs::write(
            root.join("ecosystem-replay-result.json"),
            r#"{"schema":"agentos.ecosystem-replay.v1","status":"passed","summary":{"total":6,"passed":6,"failed":0}}"#,
        )
        .expect("ecosystem replay");
        std::fs::write(
            root.join("tui-replay-result.json"),
            r#"{"schema":"agentos.tui-replay.v1","status":"passed","summary":{"total":26,"passed":26,"failed":0}}"#,
        )
        .expect("tui replay");
        std::fs::write(
            root.join("production-runbook-smoke-result.json"),
            r#"{"schema":"agentos.production-runbook-smoke.v1","result":"passed","summary":{"total":8,"passed":8,"failed":0}}"#,
        )
        .expect("production runbook smoke");
        std::fs::write(
            root.join("provenance.json"),
            r#"{"schema":"agentos.production-candidate.provenance.v1","generated_at":"1970-01-01T00:00:00Z","artifacts":{"rootfs_runtime_manifest":{"path":"rootfs-runtime-manifest.json","sha256":"sha256:runtime-manifest","present":true,"required":true},"qemu_runtime_smoke":{"path":"boot-smoke-result.json","sha256":"sha256:qemu","present":true,"required":true},"alpha_rootfs_validation":{"path":"alpha-rootfs-validation.json","sha256":"sha256:rootfs-validation","present":true,"required":true},"functional_capability_replay":{"path":"functional-replay-result.json","sha256":"sha256:functional","present":true,"required":true},"ecosystem_replay":{"path":"ecosystem-replay-result.json","sha256":"sha256:ecosystem","present":true,"required":true},"tui_replay":{"path":"tui-replay-result.json","sha256":"sha256:tui","present":true,"required":true},"production_runbook_smoke":{"path":"production-runbook-smoke-result.json","sha256":"sha256:runbook","present":true,"required":true}},"image_inputs":{"alpha_rootfs_manifest":{"rootfs_runtime_manifest":"rootfs-runtime-manifest.json","rootfs_runtime_manifest_sha256":"sha256:runtime-manifest"}},"alpha_runtime":{"runtime_artifact_ids":["policy.pack","tools.semantic","operator.commands","ecosystem.registry_snapshot","ecosystem.core_policy","ecosystem.workflow_service_recovery","model_broker.config","tui.config","state.runs","state.audit","state.rollback","state.memory"],"required_runtime_artifact_ids":["policy.pack","tools.semantic","operator.commands","ecosystem.registry_snapshot","ecosystem.core_policy","ecosystem.workflow_service_recovery","model_broker.config","tui.config","state.runs","state.audit","state.rollback","state.memory"],"missing_runtime_artifact_ids":[],"failed_runtime_artifact_ids":[],"rootfs_runtime_manifest_sha256":"sha256:runtime-manifest","tui_marker":"AGENTOS_TUI_CONSOLE_READY"}}"#,
        )
        .expect("gate provenance");
    }

    fn write_rollout_ring_artifacts(root: &Path, include_ecosystem_replay: bool) {
        std::fs::create_dir_all(root.join("release")).expect("release dir");
        std::fs::create_dir_all(root.join("tui-replay")).expect("tui replay dir");
        std::fs::create_dir_all(root.join("production-runbook-smoke"))
            .expect("production runbook dir");
        std::fs::create_dir_all(root.join("production-signature-verification"))
            .expect("production signature verification dir");
        if include_ecosystem_replay {
            std::fs::create_dir_all(root.join("ecosystem-replay")).expect("ecosystem replay dir");
        }

        std::fs::write(
            root.join("release").join("provenance.json"),
            r#"{"schema":"agentos.production-candidate.provenance.v1","promotion":{"status":"blocked","blockers":["production-signatures-not-verified"]}}"#,
        )
        .expect("release provenance");
        std::fs::write(
            root.join("tui-replay").join("result.json"),
            r#"{"schema":"agentos.tui-replay.v1","status":"passed"}"#,
        )
        .expect("tui replay result");
        std::fs::write(
            root.join("production-runbook-smoke").join("result.json"),
            r#"{"schema":"agentos.production-runbook-smoke.v1","result":"passed"}"#,
        )
        .expect("production runbook result");
        if include_ecosystem_replay {
            std::fs::write(
                root.join("ecosystem-replay").join("result.json"),
                r#"{"schema":"agentos.ecosystem-replay.v1","status":"passed"}"#,
            )
            .expect("ecosystem replay result");
        }
        std::fs::write(
            root.join("production-signature-verification")
                .join("result.json"),
            r#"{"schema":"agentos.production-signature-verification.v1","status":"blocked","production_ready_claim":false,"blockers":[{"id":"production-keyring-missing"},{"id":"production-signature-missing"}]}"#,
        )
        .expect("production signature verification result");
    }

    fn controller_at_approval(name: &str) -> (Agentd, TuiRuntimeController) {
        let agentd = started_agentd();
        let controller = TuiRuntimeController::new(temp_tui_paths(name)).expect("controller");
        controller.dispatch_line(&agentd, "intent.submit recover nginx service");
        for _ in 0..8 {
            let output = controller.dispatch_line(&agentd, "run.advance latest").text;
            if output.contains("state=AwaitingApproval") {
                return (agentd, controller);
            }
        }
        panic!("controller did not reach AwaitingApproval");
    }

    #[test]
    fn tui_layout_wide_uses_stable_non_overlapping_operator_panes() {
        let layout = PanelLayout::compute(TerminalSize::new(140, 36), FocusPanel::Runs);

        assert_eq!(layout.mode, LayoutMode::Wide);
        assert_eq!(layout.focus, FocusPanel::Runs);
        assert_eq!(layout.panes.len(), 5);
        layout.validate().expect("wide layout is valid");
        assert_eq!(
            layout.pane(PaneKind::StatusBar).expect("status").rect,
            PaneRect {
                x: 0,
                y: 0,
                width: 140,
                height: 1
            }
        );
        assert_eq!(
            layout.pane(PaneKind::NavigationRail).expect("nav").rect,
            PaneRect {
                x: 0,
                y: 1,
                width: 20,
                height: 32
            }
        );
        assert_eq!(
            layout.pane(PaneKind::RunWorkspace).expect("workspace").rect,
            PaneRect {
                x: 20,
                y: 1,
                width: 86,
                height: 32
            }
        );
        assert_eq!(
            layout.pane(PaneKind::EventFeed).expect("events").rect,
            PaneRect {
                x: 106,
                y: 1,
                width: 34,
                height: 32
            }
        );
        assert_eq!(
            layout.pane(PaneKind::CommandPalette).expect("palette").rect,
            PaneRect {
                x: 0,
                y: 33,
                width: 140,
                height: 3
            }
        );

        let text = layout.to_cli_text();
        assert!(text.contains("mode=wide"), "{text}");
        assert!(text.contains("pane=run-workspace"), "{text}");
        assert!(text.contains("pane=event-feed"), "{text}");
    }

    #[test]
    fn tui_layout_narrow_falls_back_to_tabbed_focus_panel() {
        let layout = PanelLayout::compute(TerminalSize::new(64, 18), FocusPanel::Approvals);

        assert_eq!(layout.mode, LayoutMode::Narrow);
        assert_eq!(layout.focus, FocusPanel::Approvals);
        assert_eq!(layout.panes.len(), 4);
        layout.validate().expect("narrow layout is valid");
        assert!(layout.pane(PaneKind::NavigationRail).is_none());
        assert!(layout.pane(PaneKind::EventFeed).is_none());
        assert_eq!(
            layout.pane(PaneKind::FocusPanel).expect("focus").rect,
            PaneRect {
                x: 0,
                y: 2,
                width: 64,
                height: 13
            }
        );
        assert_eq!(
            layout.pane(PaneKind::CommandPalette).expect("palette").rect,
            PaneRect {
                x: 0,
                y: 15,
                width: 64,
                height: 3
            }
        );

        let text = layout.to_cli_text();
        assert!(text.contains("mode=narrow"), "{text}");
        assert!(text.contains("pane=tab-strip"), "{text}");
        assert!(text.contains("pane=focus-panel"), "{text}");
    }

    #[test]
    fn tui_layout_snapshot_renderer_reads_projection_without_runtime_authority() {
        let agentd = started_agentd();
        let controller =
            TuiRuntimeController::new(temp_tui_paths("layout-snapshot")).expect("controller");
        controller.dispatch_line(&agentd, "intent.submit recover nginx service");
        for _ in 0..8 {
            let output = controller.dispatch_line(&agentd, "run.advance latest").text;
            if output.contains("state=AwaitingApproval") {
                break;
            }
        }

        let snapshot = controller.projection_snapshot(&agentd);
        let layout = PanelLayout::compute(TerminalSize::new(120, 30), FocusPanel::Approvals);
        let rendered = render_layout_snapshot(&layout, &snapshot);

        assert!(rendered.contains("TUI Layout mode=wide"), "{rendered}");
        assert!(rendered.contains("source_of_truth=false"), "{rendered}");
        assert!(rendered.contains("panel status latest_run="), "{rendered}");
        assert!(rendered.contains("approvals=pending"), "{rendered}");
        assert!(rendered.contains("recovery="), "{rendered}");
        assert!(!rendered.contains("EffectPrepared"), "{rendered}");
    }

    #[test]
    fn tui_layout_snapshot_full_screen_bundle_is_deterministic_and_redacted() {
        let (agentd, controller) = controller_at_approval("layout-snapshot-bundle");
        let snapshot = controller.projection_snapshot(&agentd);
        let approvals = controller
            .dispatch_line(&agentd, "approvals.show latest")
            .text;
        let recovery = controller
            .dispatch_line(&agentd, "recovery.show latest")
            .text;
        let preview = CommandPalette::preview("run.approve latest restart-service actor=operator")
            .expect("approval preview");
        let layout = PanelLayout::compute(TerminalSize::new(140, 36), FocusPanel::Approvals);
        let panels = [
            PanelSnapshot::new("approval-panel", &approvals),
            PanelSnapshot::new("recovery-panel", &recovery),
            PanelSnapshot::new(
                "history-fixture",
                "command=\"intent.submit recover nginx token=abc123 password=hunter2\"",
            ),
        ];
        let history = [
            "dashboard.show",
            "intent.submit recover nginx token=abc123",
            "run.deny latest restart-service actor=operator reason=password=hunter2",
        ];

        let first =
            render_full_screen_snapshot(&layout, &snapshot, Some(&preview), &history, &panels);
        let second =
            render_full_screen_snapshot(&layout, &snapshot, Some(&preview), &history, &panels);
        let hash = stable_contract_hash(&first);

        assert_eq!(first, second);
        assert_eq!(hash, stable_contract_hash(&second));
        assert!(
            first.contains("Full Screen TUI Snapshot mode=wide"),
            "{first}"
        );
        assert!(first.contains("pane=run-workspace"), "{first}");
        assert!(first.contains("palette Command Preview"), "{first}");
        assert!(
            first.contains("panel approval-panel TUI Approvals"),
            "{first}"
        );
        assert!(
            first.contains("panel recovery-panel TUI Recovery"),
            "{first}"
        );
        assert!(first.contains("snapshot_hash="), "{first}");
        assert!(!first.contains("token=abc123"), "{first}");
        assert!(!first.contains("password=hunter2"), "{first}");
        assert!(first.contains("[REDACTED]"), "{first}");
        eprintln!("tui_layout_snapshot_wide_hash={hash}");
    }

    #[test]
    fn tui_layout_snapshot_narrow_fallback_and_width_boundaries_are_stable() {
        let (agentd, controller) = controller_at_approval("layout-snapshot-narrow");
        let snapshot = controller.projection_snapshot(&agentd);
        let preview = CommandPalette::preview("recovery.show latest").expect("recovery preview");
        let narrow = PanelLayout::compute(TerminalSize::new(64, 18), FocusPanel::Recovery);
        let tiny = PanelLayout::compute(TerminalSize::new(2, 8), FocusPanel::Dashboard);
        let edge_narrow = PanelLayout::compute(TerminalSize::new(99, 24), FocusPanel::Approvals);
        let edge_wide = PanelLayout::compute(TerminalSize::new(100, 24), FocusPanel::Approvals);

        narrow.validate().expect("narrow layout valid");
        tiny.validate().expect("tiny width layout valid");
        edge_narrow.validate().expect("edge narrow valid");
        edge_wide.validate().expect("edge wide valid");
        assert_eq!(edge_narrow.mode, LayoutMode::Narrow);
        assert_eq!(edge_wide.mode, LayoutMode::Wide);
        for pane in &tiny.panes {
            assert!(
                pane.title.chars().count() <= pane.rect.width as usize,
                "{} title overflows {:?}",
                pane.kind.as_str(),
                pane
            );
        }

        let rendered = render_full_screen_snapshot(&narrow, &snapshot, Some(&preview), &[], &[]);
        let hash = stable_contract_hash(&rendered);
        assert!(
            rendered.contains("Full Screen TUI Snapshot mode=narrow"),
            "{rendered}"
        );
        assert!(rendered.contains("pane=tab-strip"), "{rendered}");
        assert!(rendered.contains("pane=focus-panel"), "{rendered}");
        assert!(!rendered.contains("pane=event-feed"), "{rendered}");
        assert_eq!(hash, stable_contract_hash(&rendered));
        eprintln!("tui_layout_snapshot_narrow_hash={hash}");
    }

    #[test]
    fn tui_layout_snapshot_uses_same_projection_sources_as_scripted_mode() {
        let (agentd, controller) = controller_at_approval("layout-snapshot-parity");
        let snapshot = controller.projection_snapshot(&agentd);
        let layout = PanelLayout::compute(TerminalSize::new(120, 30), FocusPanel::Approvals);
        let approvals = controller
            .dispatch_line(&agentd, "approvals.show latest")
            .text;
        let recovery = controller
            .dispatch_line(&agentd, "recovery.show latest")
            .text;
        let rendered = render_full_screen_snapshot(
            &layout,
            &snapshot,
            None,
            &[
                "dashboard.show",
                "approvals.show latest",
                "recovery.show latest",
            ],
            &[
                PanelSnapshot::new("approval-panel", &approvals),
                PanelSnapshot::new("recovery-panel", &recovery),
            ],
        );
        let scripted = run_scripted_lines(
            &agentd,
            &controller,
            &[
                "dashboard.show".to_string(),
                "approvals.show latest".to_string(),
                "recovery.show latest".to_string(),
            ],
        );

        let snapshot_hash_line = format!("snapshot_hash={}", snapshot.snapshot_hash);
        assert!(rendered.contains(&snapshot_hash_line), "{rendered}");
        assert!(scripted.contains(&snapshot_hash_line), "{scripted}");
        for source in [
            "runs status=AwaitingApproval",
            "audit status=present",
            "approvals status=pending",
            "recovery status=",
            "source_of_truth=false",
        ] {
            assert!(
                rendered.contains(source),
                "full-screen missing {source}: {rendered}"
            );
            assert!(
                scripted.contains(source),
                "scripted missing {source}: {scripted}"
            );
        }
        assert!(scripted.contains("TUI Dashboard"), "{scripted}");
        assert!(
            rendered.contains("projection Projection Snapshot"),
            "{rendered}"
        );
        eprintln!(
            "tui_layout_snapshot_parity_hash={}",
            stable_contract_hash(&rendered)
        );
    }

    #[test]
    fn renders_plan_preview_and_audit() {
        let mut agentd = Agentd::new(LifecycleConfig::default());
        agentd.start();
        let session =
            build_demo_session(&agentd, "recover local service", ApprovalDecision::Approved);
        let rendered = session.render();
        assert!(rendered.contains("AIOS agentd TUI"));
        assert!(rendered.contains("Intent: recover local service"));
        assert!(rendered.contains("Plan Preview"));
        assert!(rendered.contains("svc.status"));
        assert!(rendered.contains("Approval: approved"));
        assert!(rendered.contains("EffectObserved"));
    }

    #[test]
    fn supports_denial_timeout_and_suspended_states() {
        let mut agentd = Agentd::new(LifecycleConfig::default());
        agentd.start();
        for decision in [
            ApprovalDecision::Denied,
            ApprovalDecision::TimedOut,
            ApprovalDecision::Suspended,
        ] {
            let session = build_demo_session(&agentd, "recover local service", decision);
            assert!(session.render().contains(decision.as_str()));
            assert!(!session.render().contains("EffectObserved"));
        }
    }

    #[test]
    fn audit_json_records_policy_and_approval_projection() {
        let mut agentd = Agentd::new(LifecycleConfig::default());
        agentd.start();
        let session =
            build_demo_session(&agentd, "recover local service", ApprovalDecision::Denied);
        let audit = session.audit_json();
        assert!(audit.contains("IntentReceived"));
        assert!(audit.contains("PlanFrozen"));
        assert!(audit.contains("PolicyEvaluated"));
        assert!(audit.contains("ApprovalDecision"));
        assert!(audit.contains("denied"));
    }

    #[test]
    fn renders_write_diff_preview_with_rollback_handle() {
        let preview = DiffPreview {
            target_path: "target.conf".into(),
            base_hash: "base".to_string(),
            proposed_hash: "next".to_string(),
            rollback_id: "rb-1".to_string(),
            unified_diff: "--- before\n+++ after\n-old\n+new".to_string(),
        };
        let rendered = render_diff_preview(&preview, ApprovalDecision::Suspended);
        assert!(rendered.contains("Diff Preview"));
        assert!(rendered.contains("-old"));
        assert!(rendered.contains("+new"));
        assert!(rendered.contains("RollbackHandle: rb-1"));
        assert!(rendered.contains("Approval: suspended"));
    }

    #[test]
    fn renders_runtime_audit_projection() {
        let journal = crate::audit::AuditJournal::new(std::env::temp_dir().join(format!(
            "agentd-tui-projection-{}.jsonl",
            std::process::id()
        )));
        let _ = std::fs::remove_file(journal.path());
        journal
            .append(&crate::audit::AuditEvent::new(
                crate::audit::AuditEventType::PolicyEvaluated,
                "run-tui",
                "step-read",
                "operator",
                "decision=allow tool=svc.status resource=nginx risk=read-only reason=diagnostic",
            ))
            .expect("policy");
        journal
            .append(&crate::audit::AuditEvent::new(
                crate::audit::AuditEventType::EffectObserved,
                "run-tui",
                "step-read",
                "operator",
                "observation processed source=semantic-tool trust=sandboxed-tool summary=ok",
            ))
            .expect("observed");
        let projection = journal
            .project_runtime_run("run-tui")
            .expect("projection")
            .expect("run");
        let rendered = render_runtime_audit_projection(&projection);
        assert!(rendered.contains("Runtime Audit Projection"));
        assert!(rendered.contains("run=run-tui"));
        assert!(rendered.contains("step=step-read"));
        assert!(rendered.contains("trust=sandboxed-tool"));
    }

    #[test]
    fn renders_operator_projection_without_runtime_logic() {
        let mut agentd = Agentd::new(LifecycleConfig::default());
        agentd.start();
        let projection = OperatorProjection::collect(&agentd, None, None).expect("projection");
        let rendered = render_operator_projection(&projection);

        assert!(rendered.contains("Operator Projection"));
        assert!(rendered.contains("runtime state=running"));
        assert!(rendered.contains("audit journal=-"));
        assert!(rendered.contains("ecosystem registry="));
        assert!(rendered.contains("activation_status=gated"));
        assert!(
            rendered.contains("required_approvals=exact approval token for ecosystem.activate")
        );
        assert!(rendered.contains("blocked_until=local replay evidence"));
        assert!(rendered.contains("safety gate=agentd-safety-regression-v1"));
    }

    #[test]
    fn parses_typed_commands_and_rejects_shell_like_input() {
        assert_eq!(
            TuiCommand::parse("intent.submit recover nginx service").expect("intent"),
            TuiCommand::IntentSubmit {
                intent: "recover nginx service".to_string(),
                actor: "operator".to_string(),
            }
        );
        assert_eq!(
            TuiCommand::parse("run.approve run-x restart-service actor=operator").expect("approve"),
            TuiCommand::RunApprove {
                run_id: "run-x".to_string(),
                step_id: "restart-service".to_string(),
                actor: "operator".to_string(),
            }
        );

        for line in [
            "sh -c id",
            "dashboard.show | sh",
            "run.approve run-x restart-service actor=operator; id",
            "intent.submit recover nginx token=abc123",
        ] {
            assert!(
                TuiCommand::parse(line).is_err(),
                "{line} should fail closed"
            );
        }
    }

    #[test]
    fn tui_command_palette_suggestions_are_typed_commands_only() {
        let agentd = started_agentd();
        let controller =
            TuiRuntimeController::new(temp_tui_paths("palette-suggestions")).expect("controller");
        controller.dispatch_line(&agentd, "intent.submit recover nginx service");
        for _ in 0..8 {
            let output = controller.dispatch_line(&agentd, "run.advance latest").text;
            if output.contains("state=AwaitingApproval") {
                break;
            }
        }

        let snapshot = controller.projection_snapshot(&agentd);
        let context = CommandPaletteContext::from_snapshot(&snapshot).with_step("restart-service");
        let suggestions = CommandPalette::suggestions(&context);

        assert!(
            suggestions
                .iter()
                .any(|item| item.command == "dashboard.show")
        );
        assert!(suggestions.iter().any(|item| item.command == "refresh"));
        assert!(
            suggestions
                .iter()
                .any(|item| item.command.contains("run.approve")
                    && item.requires_preview
                    && item.risk == PaletteRisk::Approval)
        );
        assert!(
            suggestions
                .iter()
                .any(|item| item.command.contains("run.deny")
                    && item.requires_preview
                    && item.risk == PaletteRisk::Approval)
        );
        for suggestion in suggestions {
            TuiCommand::parse(&suggestion.command)
                .unwrap_or_else(|_| panic!("suggestion must parse: {}", suggestion.command));
            assert!(!suggestion.command.contains('|'), "{}", suggestion.command);
            assert!(!suggestion.command.contains(';'), "{}", suggestion.command);
            assert!(
                !suggestion.command.contains("shell.exec"),
                "{}",
                suggestion.command
            );
        }
    }

    #[test]
    fn tui_command_palette_high_risk_preview_describes_target_and_authority() {
        let approve = CommandPalette::preview("run.approve latest restart-service actor=operator")
            .expect("approve preview");
        assert_eq!(approve.risk, PaletteRisk::Approval);
        assert!(approve.requires_preview);
        assert!(approve.dispatch_allowed);
        assert!(approve.target.contains("run=latest"));
        assert!(approve.target.contains("step=restart-service"));
        assert!(
            approve
                .authority_path
                .contains("SecurityExecutionEngine audit binding")
        );
        assert!(
            approve
                .expected_state_change
                .contains("exact approval token")
        );

        let activation = CommandPalette::preview(
            "aom.activate.preview agentos:workflow-pack/agentos/service-recovery@1.0.0",
        )
        .expect("activation preview");
        assert_eq!(activation.risk, PaletteRisk::ActivationPreview);
        assert!(activation.requires_preview);
        assert!(
            activation
                .expected_state_change
                .contains("without mutating active set")
        );
        assert!(activation.authority_path.contains("agent_core::ecosystem"));
    }

    #[test]
    fn tui_command_palette_rejects_unsafe_input_without_normalizing_it() {
        for line in [
            "dashboard.show | sh",
            "run.approve latest restart-service actor=operator; id",
            "intent.submit recover nginx token=abc123",
            "shell.exec cmd=id",
            "aom.stage agentos:workflow-pack/agentos/service-recovery@1.0.0 && aom.activate.preview agentos:workflow-pack/agentos/service-recovery@1.0.0",
        ] {
            let error = CommandPalette::preview(line).expect_err("unsafe preview must fail");
            assert!(
                error.reason.contains("not accepted") || error.reason.contains("secret-like value"),
                "{line}: {}",
                error.reason
            );
        }
    }

    #[test]
    fn tui_command_palette_preview_command_does_not_execute_target() {
        let agentd = started_agentd();
        let controller =
            TuiRuntimeController::new(temp_tui_paths("palette-preview")).expect("controller");
        let output = controller
            .dispatch_line(
                &agentd,
                "palette.preview intent.submit recover nginx service",
            )
            .text;

        assert!(output.contains("Command Preview"), "{output}");
        assert!(
            output.contains("command=\"intent.submit recover nginx service\""),
            "{output}"
        );
        assert!(output.contains("requires_preview=true"), "{output}");
        assert!(
            controller
                .journal()
                .latest_run()
                .expect("latest run lookup")
                .is_none(),
            "palette preview must not accept intent or create a run"
        );
    }

    #[test]
    fn runtime_controller_drives_durable_agent_core_run_and_denies_restart() {
        let agentd = started_agentd();
        let paths = temp_tui_paths("runtime-deny");
        let controller = TuiRuntimeController::new(paths.clone()).expect("controller");

        let submitted = controller.dispatch_line(&agentd, "intent.submit recover nginx service");
        assert!(submitted.text.contains("TUI Run"));
        assert!(submitted.text.contains("state=Planned"));
        let run_id = run_id_from_output(&submitted.text);
        assert!(has_snapshot(&paths.run_store_root));

        let mut awaiting = String::new();
        for _ in 0..8 {
            awaiting = controller.dispatch_line(&agentd, "run.advance latest").text;
            if awaiting.contains("state=AwaitingApproval") {
                break;
            }
        }
        assert!(awaiting.contains("state=AwaitingApproval"), "{awaiting}");
        assert!(awaiting.contains("step=restart-service"), "{awaiting}");

        let denied = controller.dispatch_line(
            &agentd,
            "run.deny latest restart-service actor=operator reason=operator declined",
        );
        assert!(denied.text.contains("state=Denied"), "{}", denied.text);

        let timeline = controller
            .journal()
            .run_timeline(&run_id)
            .expect("run timeline");
        assert!(!timeline.iter().any(|line| {
            line.contains("\"event_type\":\"EffectPrepared\"")
                && line.contains("\"step_id\":\"restart-service\"")
        }));
    }

    #[test]
    fn tui_approval_queue_renders_exact_binding_and_denial_hint() {
        let agentd = started_agentd();
        let controller =
            TuiRuntimeController::new(temp_tui_paths("approval-queue")).expect("controller");
        controller.dispatch_line(&agentd, "intent.submit recover nginx service");
        for _ in 0..8 {
            let output = controller.dispatch_line(&agentd, "run.advance latest").text;
            if output.contains("state=AwaitingApproval") {
                break;
            }
        }

        let approvals = controller
            .dispatch_line(&agentd, "approvals.show latest")
            .text;
        assert!(approvals.contains("TUI Approvals"), "{approvals}");
        assert!(
            approvals.contains("source=run-store+audit-journal"),
            "{approvals}"
        );
        assert!(
            approvals.contains("exact_binding_required=true"),
            "{approvals}"
        );
        assert!(approvals.contains("queue_status=pending"), "{approvals}");
        assert!(approvals.contains("actor=operator"), "{approvals}");
        assert!(approvals.contains("tool=svc.restart"), "{approvals}");
        assert!(approvals.contains("resource=nginx"), "{approvals}");
        assert!(approvals.contains("parameter_hash="), "{approvals}");
        assert!(
            approvals.contains("policy_version=policy-v1"),
            "{approvals}"
        );
        assert!(approvals.contains("expires_at=60"), "{approvals}");
        assert!(
            approvals.contains("approve=\"run.approve latest restart-service actor=operator\""),
            "{approvals}"
        );
        assert!(
            approvals
                .contains("deny=\"run.deny latest restart-service actor=operator reason=<text>\""),
            "{approvals}"
        );
        assert!(!approvals.contains("password="), "{approvals}");
    }

    #[test]
    fn tui_approval_center_renders_actionable_exact_binding() {
        let (agentd, controller) = controller_at_approval("approval-center-actionable");

        let center = controller
            .dispatch_line(&agentd, "approvals.show latest")
            .text;

        assert!(center.contains("TUI Approvals"), "{center}");
        assert!(center.contains("panel=approval-center"), "{center}");
        assert!(
            center.contains("source=run-store+audit-journal"),
            "{center}"
        );
        assert!(center.contains("exact_binding_required=true"), "{center}");
        assert!(center.contains("command_weight=equal"), "{center}");
        assert!(center.contains("section=actionable count=1"), "{center}");
        assert!(
            center.contains("section=non-actionable count=0"),
            "{center}"
        );
        assert!(center.contains("actionable=true"), "{center}");
        assert!(center.contains("exact_binding_available=true"), "{center}");
        assert!(center.contains("tool=svc.restart"), "{center}");
        assert!(center.contains("resource=nginx"), "{center}");
        assert!(center.contains("parameter_hash="), "{center}");
        assert!(center.contains("policy_version=policy-v1"), "{center}");
        assert!(
            center.contains("policy_reason=\"decision=pause-for-approval"),
            "{center}"
        );
        assert!(
            center.contains("rollback_consequence=\"side_effects_closed_until_approval\""),
            "{center}"
        );
        assert!(
            center.contains("approve=\"run.approve latest restart-service actor=operator\""),
            "{center}"
        );
        assert!(
            center
                .contains("deny=\"run.deny latest restart-service actor=operator reason=<text>\""),
            "{center}"
        );
    }

    #[test]
    fn tui_approval_center_shows_expired_as_non_actionable() {
        let (agentd, controller) = controller_at_approval("approval-center-expired");
        controller.dispatch_line(&agentd, "run.suspend latest reason=operator timeout");

        let center = controller
            .dispatch_line(&agentd, "approvals.show latest")
            .text;

        assert!(center.contains("panel=approval-center"), "{center}");
        assert!(center.contains("queue_status=expired"), "{center}");
        assert!(center.contains("section=actionable count=0"), "{center}");
        assert!(
            center.contains("section=non-actionable count=1"),
            "{center}"
        );
        assert!(center.contains("approval=Expired"), "{center}");
        assert!(center.contains("expired=true"), "{center}");
        assert!(center.contains("actionable=false"), "{center}");
        assert!(center.contains("approve=\"-\""), "{center}");
        assert!(center.contains("deny=\"-\""), "{center}");
    }

    #[test]
    fn tui_approval_center_shows_denied_as_non_actionable() {
        let (agentd, controller) = controller_at_approval("approval-center-denied");
        controller.dispatch_line(
            &agentd,
            "run.deny latest restart-service actor=operator reason=operator declined",
        );

        let center = controller
            .dispatch_line(&agentd, "approvals.show latest")
            .text;

        assert!(center.contains("panel=approval-center"), "{center}");
        assert!(center.contains("queue_status=denied"), "{center}");
        assert!(center.contains("section=actionable count=0"), "{center}");
        assert!(
            center.contains("section=non-actionable count=1"),
            "{center}"
        );
        assert!(center.contains("approval=Denied"), "{center}");
        assert!(center.contains("denied=true"), "{center}");
        assert!(center.contains("actionable=false"), "{center}");
        assert!(center.contains("reason=\"operator declined\""), "{center}");
        assert!(center.contains("approve=\"-\""), "{center}");
        assert!(center.contains("deny=\"-\""), "{center}");
    }

    #[test]
    fn tui_approval_center_fails_closed_without_exact_binding() {
        let run = crate::agent_core::run_loop::RunProjection {
            run_id: "run-missing-binding".to_string(),
            plan_id: "plan-missing-binding".to_string(),
            frozen_plan_hash: "hash-missing-binding".to_string(),
            state: crate::agent_core::model::RunState::AwaitingApproval,
            current_step_id: Some("restart-service".to_string()),
            approval_status: crate::agent_core::model::ApprovalStatus::Pending,
            approval_id: Some("approval-run-missing-binding-restart-service".to_string()),
            approval_reason: "high-risk action requires exact approval token".to_string(),
            recovery_status: crate::agent_core::model::RecoveryStatus::None,
            recovery_reason: "none".to_string(),
            observation_count: 0,
            memory_count: 0,
        };

        let error = ApprovalCenterPanel::collect(&run, None).expect_err("missing binding");

        assert!(
            error.contains("missing exact binding context for actionable approval"),
            "{error}"
        );
    }

    #[test]
    fn tui_approval_center_redacts_secret_like_render_text() {
        let mut run = crate::agent_core::run_loop::RunProjection {
            run_id: "run-secret-binding".to_string(),
            plan_id: "plan-secret-binding".to_string(),
            frozen_plan_hash: "hash-secret-binding".to_string(),
            state: crate::agent_core::model::RunState::Denied,
            current_step_id: Some("restart-service".to_string()),
            approval_status: crate::agent_core::model::ApprovalStatus::Denied,
            approval_id: Some("approval-denied-run-secret-binding-restart-service".to_string()),
            approval_reason: "operator declined password=hunter2 token=abc123".to_string(),
            recovery_status: crate::agent_core::model::RecoveryStatus::None,
            recovery_reason: "none".to_string(),
            observation_count: 0,
            memory_count: 0,
        };
        let center = ApprovalCenterPanel::collect(&run, None)
            .expect("denied approval can render without binding")
            .render();
        assert!(!center.contains("password=hunter2"), "{center}");
        assert!(!center.contains("token=abc123"), "{center}");
        assert!(center.contains("[REDACTED]"), "{center}");

        run.approval_reason = "operator declined access_token=hidden".to_string();
        let nested = ApprovalCenterPanel::collect(&run, None)
            .expect("denied approval can render without binding")
            .render();
        assert!(!nested.contains("access_token=hidden"), "{nested}");
        assert!(nested.contains("[REDACTED]"), "{nested}");
    }

    #[test]
    fn tui_approval_binding_renders_hash_summary_and_expiry() {
        let (agentd, controller) = controller_at_approval("approval-binding-match");

        let center = controller
            .dispatch_line(&agentd, "approvals.show latest")
            .text;

        assert!(
            center.contains("parameter_summary=\"tool=svc.restart resource=nginx hash="),
            "{center}"
        );
        assert!(center.contains("requested_binding_hash="), "{center}");
        assert!(center.contains("bound_token_hash="), "{center}");
        assert!(center.contains("binding_diff=match"), "{center}");
        assert!(center.contains("expires_at=60"), "{center}");
        assert!(center.contains("expires_in=60"), "{center}");
        assert!(center.contains("preview_state=ready"), "{center}");
        assert!(center.contains("disabled_reason=\"-\""), "{center}");
        assert!(!center.contains("password="), "{center}");
        assert!(!center.contains("token=abc123"), "{center}");
    }

    #[test]
    fn tui_approval_binding_mutation_renders_denied_preview_without_commands() {
        let (agentd, controller) = controller_at_approval("approval-binding-mutation");
        let run_id = controller
            .journal()
            .latest_run()
            .expect("latest run lookup")
            .expect("latest run");
        let mut mutated = crate::audit::AuditEvent::new(
            crate::audit::AuditEventType::PolicyEvaluated,
            &run_id,
            "restart-service",
            "operator",
            "decision=deny tool=svc.restart resource=ssh risk=privileged-with-human-approval reason=parameter mutation",
        );
        mutated.policy_version = "policy-v1".to_string();
        mutated.parameter_hash = "hash-mutated-ssh".to_string();
        controller
            .journal()
            .append(&mutated)
            .expect("mutated policy event");

        let center = controller
            .dispatch_line(&agentd, "approvals.show latest")
            .text;

        assert!(center.contains("panel=approval-center"), "{center}");
        assert!(center.contains("section=actionable count=0"), "{center}");
        assert!(
            center.contains("section=non-actionable count=1"),
            "{center}"
        );
        assert!(
            center.contains("requested_binding_hash=hash-mutated-ssh"),
            "{center}"
        );
        assert!(
            center.contains("binding_diff=mismatch-denied-preview"),
            "{center}"
        );
        assert!(center.contains("preview_state=denied-preview"), "{center}");
        assert!(center.contains("stale=true"), "{center}");
        assert!(center.contains("actionable=false"), "{center}");
        assert!(
            center.contains(
                "disabled_reason=\"approval binding mismatch denied before effect preparation\""
            ),
            "{center}"
        );
        assert!(center.contains("approve=\"-\""), "{center}");
        assert!(center.contains("deny=\"-\""), "{center}");
        assert!(!center.contains("password="), "{center}");
    }

    #[test]
    fn tui_approval_binding_expired_panel_and_palette_disable_submission() {
        let (agentd, controller) = controller_at_approval("approval-binding-expired");
        controller.dispatch_line(&agentd, "run.suspend latest reason=operator timeout");

        let center = controller
            .dispatch_line(&agentd, "approvals.show latest")
            .text;
        let snapshot = controller.projection_snapshot(&agentd);
        let context = CommandPaletteContext::from_snapshot(&snapshot).with_step("restart-service");
        let suggestions = CommandPalette::suggestions(&context);

        assert!(center.contains("approval=Expired"), "{center}");
        assert!(center.contains("preview_state=expired"), "{center}");
        assert!(
            center.contains("disabled_reason=\"expired approval cannot be submitted\""),
            "{center}"
        );
        assert!(center.contains("approve=\"-\""), "{center}");
        assert!(center.contains("deny=\"-\""), "{center}");
        assert!(
            suggestions
                .iter()
                .all(|item| !item.command.contains("run.approve")),
            "{suggestions:?}"
        );
    }

    #[test]
    fn tui_approval_binding_stale_shortcut_reuse_fails_before_effect() {
        let (agentd, controller) = controller_at_approval("approval-binding-stale-shortcut");
        let run_id = controller
            .journal()
            .latest_run()
            .expect("latest run lookup")
            .expect("latest run");
        controller.dispatch_line(&agentd, "run.suspend latest reason=operator timeout");

        let rejected = controller
            .dispatch_line(&agentd, "run.approve latest restart-service actor=operator")
            .text;
        let timeline = controller
            .journal()
            .run_timeline(&run_id)
            .expect("run timeline");

        assert!(rejected.contains("TUI Error\nkind=runtime"), "{rejected}");
        assert!(rejected.contains("stale-or-expired"), "{rejected}");
        assert!(!timeline.iter().any(|line| {
            line.contains("\"event_type\":\"EffectPrepared\"")
                && line.contains("\"step_id\":\"restart-service\"")
        }));
    }

    #[test]
    fn tui_recovery_view_uses_run_store_audit_source_and_no_model_replay() {
        let agentd = started_agentd();
        let controller =
            TuiRuntimeController::new(temp_tui_paths("recovery-view")).expect("controller");
        controller.dispatch_line(&agentd, "intent.submit recover nginx service");
        for _ in 0..8 {
            let output = controller.dispatch_line(&agentd, "run.advance latest").text;
            if output.contains("state=AwaitingApproval") {
                break;
            }
        }
        controller.dispatch_line(&agentd, "run.suspend latest reason=operator paused");

        let recovery = controller
            .dispatch_line(&agentd, "recovery.show latest")
            .text;
        assert!(recovery.contains("TUI Recovery"), "{recovery}");
        assert!(
            recovery.contains("source=run-store+audit-journal"),
            "{recovery}"
        );
        assert!(recovery.contains("no-model-replay=true"), "{recovery}");
        assert!(recovery.contains("state=Suspended"), "{recovery}");
        assert!(recovery.contains("panel=recovery-workbench"), "{recovery}");
        assert!(
            recovery.contains("group needs-human-review count=1"),
            "{recovery}"
        );
        assert!(recovery.contains("human_review=true"), "{recovery}");
        assert!(
            recovery.contains("degraded_optional_dependencies=visible"),
            "{recovery}"
        );
        assert!(recovery.contains("baseline_operable=true"), "{recovery}");
        assert!(recovery.contains("audit_ref=\"audit:"), "{recovery}");
        assert!(recovery.contains("action=\"run.recover run-"), "{recovery}");
    }

    #[test]
    fn tui_recovery_workbench_groups_human_review_and_preserves_state() {
        let (agentd, controller) = controller_at_approval("recovery-workbench-human");

        let before = controller.dispatch_line(&agentd, "run.show latest").text;
        let recovery = controller
            .dispatch_line(&agentd, "recovery.show latest")
            .text;
        let after = controller.dispatch_line(&agentd, "run.show latest").text;

        assert_eq!(before, after);
        assert!(recovery.contains("TUI Recovery"), "{recovery}");
        assert!(recovery.contains("panel=recovery-workbench"), "{recovery}");
        assert!(
            recovery.contains("source=run-store+audit-journal"),
            "{recovery}"
        );
        assert!(recovery.contains("no-model-replay=true"), "{recovery}");
        assert!(
            recovery.contains("group needs-human-review count=1"),
            "{recovery}"
        );
        assert!(
            recovery.contains("selected_class=needs-human-review"),
            "{recovery}"
        );
        assert!(recovery.contains("human_review=true"), "{recovery}");
        assert!(recovery.contains("action=\"run.recover run-"), "{recovery}");
        assert!(recovery.contains("audit_ref=\"audit:"), "{recovery}");
        assert!(!recovery.contains("Plan Preview"), "{recovery}");
    }

    #[test]
    fn tui_recovery_workbench_keeps_rollback_pending_visible() {
        let (agentd, controller) = controller_at_approval("recovery-workbench-rollback");
        let run_id = controller
            .journal()
            .latest_run()
            .expect("latest run lookup")
            .expect("latest run");
        let mut prepared = crate::audit::AuditEvent::new(
            crate::audit::AuditEventType::EffectPrepared,
            &run_id,
            "write-config",
            "operator",
            "prepared tool=fs.write.diff rollback_id=rb-tui target=/tmp/nginx.conf",
        );
        prepared.parameter_hash = "hash-write-config".to_string();
        controller
            .journal()
            .append(&prepared)
            .expect("prepared effect");
        let mut rollback = crate::audit::AuditEvent::new(
            crate::audit::AuditEventType::RollbackPending,
            &run_id,
            "write-config",
            "operator",
            "rollback pending write-with-diff verification failed rollback_id=rb-tui",
        );
        rollback.parameter_hash = "hash-write-config".to_string();
        controller
            .journal()
            .append(&rollback)
            .expect("rollback pending");

        let recovery = controller
            .dispatch_line(&agentd, "recovery.show latest")
            .text;
        let dashboard = controller.dispatch_line(&agentd, "dashboard.show").text;

        assert!(
            recovery.contains("group needs-rollback count=1"),
            "{recovery}"
        );
        assert!(
            recovery.contains("selected_class=needs-rollback"),
            "{recovery}"
        );
        assert!(recovery.contains("rollback_pending=true"), "{recovery}");
        assert!(
            recovery.contains("unresolved[0] source=audit-journal"),
            "{recovery}"
        );
        assert!(recovery.contains("rollback_id=rb-tui"), "{recovery}");
        assert!(
            recovery.contains("rollback_preview source=run-store+audit-journal"),
            "{recovery}"
        );
        assert!(recovery.contains("execution=preview-only"), "{recovery}");
        assert!(recovery.contains("mutates_state=false"), "{recovery}");
        assert!(recovery.contains("safe_next=\"audit.show "), "{recovery}");
        assert!(
            dashboard.contains("recovery status=") || dashboard.contains("rollback_pending="),
            "{dashboard}"
        );
    }

    #[test]
    fn tui_rollback_preview_renders_consequence_from_audit_truth() {
        let (agentd, controller) = controller_at_approval("rollback-preview-audit-truth");
        let run_id = controller
            .journal()
            .latest_run()
            .expect("latest run lookup")
            .expect("latest run");
        let mut prepared = crate::audit::AuditEvent::new(
            crate::audit::AuditEventType::EffectPrepared,
            &run_id,
            "write-config",
            "operator",
            "prepared tool=fs.write.diff rollback_id=rb-tui target=/tmp/nginx.conf base_hash=base-123 proposed_hash=next-456",
        );
        prepared.parameter_hash = "hash-write-config".to_string();
        controller
            .journal()
            .append(&prepared)
            .expect("prepared effect");
        let mut rollback = crate::audit::AuditEvent::new(
            crate::audit::AuditEventType::RollbackPending,
            &run_id,
            "write-config",
            "operator",
            "rollback pending write-with-diff verification failed rollback_id=rb-tui target=/tmp/nginx.conf final_hash=broken password=hunter2",
        );
        rollback.parameter_hash = "hash-write-config".to_string();
        controller
            .journal()
            .append(&rollback)
            .expect("rollback pending");

        let recovery = controller
            .dispatch_line(&agentd, "recovery.show latest")
            .text;

        assert!(
            recovery.contains("rollback_preview source=run-store+audit-journal"),
            "{recovery}"
        );
        assert!(
            recovery.contains("truth_source=audit-journal"),
            "{recovery}"
        );
        assert!(recovery.contains("execution=preview-only"), "{recovery}");
        assert!(recovery.contains("mutates_state=false"), "{recovery}");
        assert!(
            recovery.contains("rollback_preview[0] step=write-config"),
            "{recovery}"
        );
        assert!(recovery.contains("rollback_id=rb-tui"), "{recovery}");
        assert!(
            recovery.contains("target=\"/tmp/nginx.conf\""),
            "{recovery}"
        );
        assert!(recovery.contains("affected_kind=file"), "{recovery}");
        assert!(recovery.contains("base_hash=base-123"), "{recovery}");
        assert!(recovery.contains("proposed_hash=next-456"), "{recovery}");
        assert!(recovery.contains("final_hash=broken"), "{recovery}");
        assert!(
            recovery.contains("mode=requires-human-review"),
            "{recovery}"
        );
        assert!(recovery.contains("automatic=false"), "{recovery}");
        assert!(
            recovery.contains("human_review_required=true"),
            "{recovery}"
        );
        assert!(recovery.contains("failed_verification=true"), "{recovery}");
        assert!(recovery.contains("half_committed=true"), "{recovery}");
        assert!(
            recovery.contains("rollback would restore /tmp/nginx.conf to base_hash=base-123"),
            "{recovery}"
        );
        assert!(recovery.contains("rollback_evidence[0:0]"), "{recovery}");
        assert!(recovery.contains("event=EffectPrepared"), "{recovery}");
        assert!(recovery.contains("event=RollbackPending"), "{recovery}");
        assert!(!recovery.contains("password=hunter2"), "{recovery}");
        assert!(recovery.contains("[REDACTED]"), "{recovery}");
    }

    #[test]
    fn tui_rollback_preview_rendering_does_not_mutate_recovery_state() {
        let (agentd, controller) = controller_at_approval("rollback-preview-no-mutate");
        let run_id = controller
            .journal()
            .latest_run()
            .expect("latest run lookup")
            .expect("latest run");
        let mut prepared = crate::audit::AuditEvent::new(
            crate::audit::AuditEventType::EffectPrepared,
            &run_id,
            "write-config",
            "operator",
            "prepared tool=fs.write.diff rollback_id=rb-no-mutate target=/tmp/nginx.conf base_hash=base",
        );
        prepared.parameter_hash = "hash-no-mutate".to_string();
        controller
            .journal()
            .append(&prepared)
            .expect("prepared effect");
        let mut rollback = crate::audit::AuditEvent::new(
            crate::audit::AuditEventType::RollbackPending,
            &run_id,
            "write-config",
            "operator",
            "rollback pending write-with-diff verification failed rollback_id=rb-no-mutate",
        );
        rollback.parameter_hash = "hash-no-mutate".to_string();
        controller
            .journal()
            .append(&rollback)
            .expect("rollback pending");

        let before = controller.dispatch_line(&agentd, "run.show latest").text;
        let event_count_before = controller
            .journal()
            .run_timeline(&run_id)
            .expect("timeline before")
            .len();
        let recovery_a = controller
            .dispatch_line(&agentd, "recovery.show latest")
            .text;
        let recovery_b = controller
            .dispatch_line(&agentd, "recovery.show latest")
            .text;
        let after = controller.dispatch_line(&agentd, "run.show latest").text;
        let timeline_after = controller
            .journal()
            .run_timeline(&run_id)
            .expect("timeline after");

        assert_eq!(before, after);
        assert_eq!(recovery_a, recovery_b);
        assert_eq!(event_count_before, timeline_after.len());
        assert!(
            recovery_a.contains("execution=preview-only"),
            "{recovery_a}"
        );
        assert!(recovery_a.contains("mutates_state=false"), "{recovery_a}");
        assert!(
            !timeline_after
                .iter()
                .any(|line| line.contains("\"event_type\":\"RollbackObserved\"")),
            "{timeline_after:?}"
        );
    }

    #[test]
    fn tui_recovery_workbench_empty_state_is_explicit() {
        let agentd = started_agentd();
        let controller = TuiRuntimeController::new(temp_tui_paths("recovery-workbench-empty"))
            .expect("controller");

        let recovery = controller
            .dispatch_line(&agentd, "recovery.show latest")
            .text;

        assert!(recovery.contains("TUI Recovery"), "{recovery}");
        assert!(recovery.contains("panel=recovery-workbench"), "{recovery}");
        assert!(recovery.contains("status=no-run"), "{recovery}");
        assert!(
            recovery.contains("source=run-store+audit-journal"),
            "{recovery}"
        );
        assert!(recovery.contains("no-model-replay=true"), "{recovery}");
        assert!(recovery.contains("action=\"inspect-only\""), "{recovery}");
        assert!(
            recovery.contains("group needs-rollback count=0"),
            "{recovery}"
        );
    }

    #[test]
    fn tui_recovery_workbench_redacts_secret_like_audit_text() {
        let (agentd, controller) = controller_at_approval("recovery-workbench-redaction");
        let run_id = controller
            .journal()
            .latest_run()
            .expect("latest run lookup")
            .expect("latest run");
        let mut prepared = crate::audit::AuditEvent::new(
            crate::audit::AuditEventType::EffectPrepared,
            &run_id,
            "write-secret-config",
            "operator",
            "prepared tool=fs.write.diff rollback_id=rb-secret password=hunter2 token=abc123",
        );
        prepared.parameter_hash = "hash-secret-write".to_string();
        controller
            .journal()
            .append(&prepared)
            .expect("secret-like effect");

        let recovery = controller
            .dispatch_line(&agentd, "recovery.show latest")
            .text;

        assert!(recovery.contains("panel=recovery-workbench"), "{recovery}");
        assert!(!recovery.contains("password=hunter2"), "{recovery}");
        assert!(!recovery.contains("token=abc123"), "{recovery}");
        assert!(recovery.contains("[REDACTED]"), "{recovery}");
    }

    #[test]
    fn tui_snapshot_redacts_secret_and_preserves_deterministic_views() {
        let agentd = started_agentd();
        let controller = TuiRuntimeController::new(temp_tui_paths("snapshot")).expect("controller");
        controller.dispatch_line(&agentd, "intent.submit recover nginx service");
        for _ in 0..8 {
            let output = controller.dispatch_line(&agentd, "run.advance latest").text;
            if output.contains("state=AwaitingApproval") {
                break;
            }
        }

        let dashboard_a = controller.dispatch_line(&agentd, "dashboard.show").text;
        let dashboard_b = controller.dispatch_line(&agentd, "dashboard.show").text;
        assert_eq!(dashboard_a, dashboard_b);
        assert!(dashboard_a.contains("TUI Dashboard"));
        assert!(dashboard_a.contains("redaction=secret-values-redacted"));

        let approvals = controller
            .dispatch_line(&agentd, "approvals.show latest")
            .text;
        let run = controller.dispatch_line(&agentd, "run.show latest").text;
        let recovery = controller
            .dispatch_line(&agentd, "recovery.show latest")
            .text;
        for (name, view) in [
            ("dashboard", dashboard_a.as_str()),
            ("approvals", approvals.as_str()),
            ("run", run.as_str()),
            ("recovery", recovery.as_str()),
        ] {
            assert!(
                !view.contains("password="),
                "{name} leaked password token: {view}"
            );
            assert!(
                !view.contains("token=abc123"),
                "{name} leaked token value: {view}"
            );
        }
        assert!(approvals.contains("approval=Pending"));
        assert!(recovery.contains("source=run-store+audit-journal"));
    }

    #[test]
    fn tui_projection_snapshot_rebuilds_from_durable_sources_with_stable_hash() {
        let agentd = started_agentd();
        let controller =
            TuiRuntimeController::new(temp_tui_paths("projection-snapshot")).expect("controller");
        controller.dispatch_line(&agentd, "intent.submit recover nginx service");
        for _ in 0..8 {
            let output = controller.dispatch_line(&agentd, "run.advance latest").text;
            if output.contains("state=AwaitingApproval") {
                break;
            }
        }

        let first = controller.projection_snapshot(&agentd);
        let second = controller.projection_snapshot(&agentd);

        assert_eq!(first.schema_version, PROJECTION_SNAPSHOT_SCHEMA_VERSION);
        assert!(first.immutable_render_input);
        assert!(!first.source_of_truth);
        assert_eq!(first.snapshot_hash, second.snapshot_hash);
        assert_eq!(first.runs.source_hash, second.runs.source_hash);
        assert_eq!(first.audit.source_hash, second.audit.source_hash);
        assert_eq!(first.approvals.source_hash, second.approvals.source_hash);
        assert_eq!(first.recovery.source_hash, second.recovery.source_hash);
        assert!(first.latest_run_id.is_some());
        assert_eq!(first.runs.status, "AwaitingApproval");
        assert_eq!(first.audit.status, "present");
        assert_eq!(first.approvals.status, "pending");
        assert_eq!(first.approvals.freshness, "exact-binding");
        assert!(!first.approvals.degraded);
        assert!(first.recovery.degraded);
        assert!(first.recovery.detail.contains("human_review=true"));
        assert!(first.to_json().contains("\"source_of_truth\":false"));
    }

    #[test]
    fn tui_refresh_is_deterministic_and_does_not_mutate_state() {
        let agentd = started_agentd();
        let controller = TuiRuntimeController::new(temp_tui_paths("refresh")).expect("controller");
        controller.dispatch_line(&agentd, "intent.submit recover nginx service");
        for _ in 0..8 {
            let output = controller.dispatch_line(&agentd, "run.advance latest").text;
            if output.contains("state=AwaitingApproval") {
                break;
            }
        }
        let before = controller.dispatch_line(&agentd, "run.show latest").text;
        let refresh_a = controller.dispatch_line(&agentd, "refresh").text;
        let refresh_b = controller.dispatch_line(&agentd, "refresh").text;
        let after_error = controller
            .dispatch_line(&agentd, "dashboard.show | sh")
            .text;
        let after = controller.dispatch_line(&agentd, "run.show latest").text;

        assert_eq!(refresh_a, refresh_b);
        assert!(before.contains("state=AwaitingApproval"), "{before}");
        assert!(
            after_error.contains("TUI Error\nkind=parse"),
            "{after_error}"
        );
        assert!(after.contains("state=AwaitingApproval"), "{after}");
    }

    #[test]
    fn tui_refresh_projection_snapshot_keeps_approval_and_recovery_state_visible() {
        let agentd = started_agentd();
        let controller =
            TuiRuntimeController::new(temp_tui_paths("refresh-projection")).expect("controller");
        controller.dispatch_line(&agentd, "intent.submit recover nginx service");
        for _ in 0..8 {
            let output = controller.dispatch_line(&agentd, "run.advance latest").text;
            if output.contains("state=AwaitingApproval") {
                break;
            }
        }

        let before = controller.projection_snapshot(&agentd);
        let refresh = controller.dispatch_line(&agentd, "refresh").text;
        let after = controller.projection_snapshot(&agentd);

        assert_eq!(before.snapshot_hash, after.snapshot_hash);
        assert_eq!(after.runs.status, "AwaitingApproval");
        assert_eq!(after.approvals.status, "pending");
        assert_eq!(after.approvals.freshness, "exact-binding");
        assert!(after.recovery.degraded);
        assert!(refresh.contains("Projection Snapshot"), "{refresh}");
        assert!(refresh.contains("source_of_truth=false"), "{refresh}");
        assert!(refresh.contains("approvals status=pending"), "{refresh}");
        assert!(refresh.contains("recovery status="), "{refresh}");
        assert!(
            refresh.contains("authority=\"AgentCore RunStore\""),
            "{refresh}"
        );
    }

    #[test]
    fn tui_event_feed_renders_bounded_durable_events() {
        let (agentd, controller) = controller_at_approval("event-feed-bounded");

        let feed = controller.dispatch_line(&agentd, "events.show 3").text;

        assert!(feed.contains("TUI Event Feed"), "{feed}");
        assert!(
            feed.contains("source=projection-snapshot+audit-journal"),
            "{feed}"
        );
        assert!(
            feed.contains("cursor_authority=\"none; derived render cursor only\""),
            "{feed}"
        );
        assert!(feed.contains("source_of_truth=false"), "{feed}");
        assert!(feed.contains("visible_events=3"), "{feed}");
        assert!(feed.contains("event[0] sequence="), "{feed}");
        assert!(feed.contains("source=audit-journal kind="), "{feed}");
        for source in [
            "source runs ",
            "source audit ",
            "source approvals ",
            "source recovery ",
        ] {
            assert!(feed.contains(source), "missing {source}: {feed}");
        }
    }

    #[test]
    fn tui_event_feed_refresh_does_not_mutate_run_state() {
        let (agentd, controller) = controller_at_approval("event-feed-refresh");

        let before = controller.dispatch_line(&agentd, "run.show latest").text;
        let feed_a = controller.dispatch_line(&agentd, "events.show 5").text;
        let feed_b = controller.dispatch_line(&agentd, "events.show 5").text;
        let after = controller.dispatch_line(&agentd, "run.show latest").text;

        assert_eq!(feed_a, feed_b);
        assert_eq!(before, after);
        assert!(after.contains("state=AwaitingApproval"), "{after}");
    }

    #[test]
    fn tui_event_feed_redacts_secret_like_audit_text() {
        let (agentd, controller) = controller_at_approval("event-feed-redaction");
        let run_id = controller
            .journal()
            .latest_run()
            .expect("latest run lookup")
            .expect("latest run");
        controller
            .journal()
            .append(&crate::audit::AuditEvent::new(
                crate::audit::AuditEventType::SandboxDenied,
                &run_id,
                "secret-step",
                "operator",
                "reason=password=hunter2 token=abc123 nested=\"access_token=hidden\"",
            ))
            .expect("secret audit event");

        let feed = controller.dispatch_line(&agentd, "events.show 12").text;

        assert!(feed.contains("TUI Event Feed"), "{feed}");
        assert!(!feed.contains("password=hunter2"), "{feed}");
        assert!(!feed.contains("token=abc123"), "{feed}");
        assert!(!feed.contains("access_token=hidden"), "{feed}");
        assert!(feed.contains("[REDACTED]"), "{feed}");
    }

    #[test]
    fn tui_event_feed_empty_run_shows_missing_sources() {
        let agentd = started_agentd();
        let controller =
            TuiRuntimeController::new(temp_tui_paths("event-feed-empty")).expect("controller");

        let feed = controller.dispatch_line(&agentd, "events.show 4").text;

        assert!(feed.contains("TUI Event Feed"), "{feed}");
        assert!(feed.contains("selected_run=-"), "{feed}");
        assert!(feed.contains("total_events=0"), "{feed}");
        assert!(feed.contains("visible_events=0"), "{feed}");
        assert!(
            feed.contains("event[none] reason=\"no durable audit events for selected run\""),
            "{feed}"
        );
        assert!(feed.contains("source runs status=no-run"), "{feed}");
        assert!(feed.contains("source audit status=no-events"), "{feed}");
        assert!(feed.contains("source approvals status=no-run"), "{feed}");
        assert!(feed.contains("source recovery status=no-run"), "{feed}");
        assert!(feed.contains("degraded_sources="), "{feed}");
    }

    #[test]
    fn tui_support_console_status_is_read_only_and_panelized() {
        let agentd = started_agentd();
        let controller = TuiRuntimeController::new(temp_tui_paths("support-console-status"))
            .expect("controller");
        let support_path = controller.paths().support_bundle_path.clone();

        let support = controller
            .dispatch_line(&agentd, "support.bundle status")
            .text;

        assert!(support.contains("TUI Support Bundle"), "{support}");
        assert!(support.contains("TUI Support Console"), "{support}");
        assert!(support.contains("panel=support-console"), "{support}");
        assert!(support.contains("status=ready"), "{support}");
        assert!(support.contains("export_written=false"), "{support}");
        assert!(support.contains("last_export_path=\"-\""), "{support}");
        assert!(
            support.contains("typed_export=\"support.bundle export\""),
            "{support}"
        );
        assert!(support.contains("preview_required=true"), "{support}");
        assert!(support.contains("deterministic=true"), "{support}");
        assert!(
            support.contains("redaction=secret-values-redacted"),
            "{support}"
        );
        assert!(support.contains("includes_raw_secret=false"), "{support}");
        assert!(
            support.contains("runtime_health state=running"),
            "{support}"
        );
        assert!(
            support.contains("audit_status local_authoritative=true"),
            "{support}"
        );
        assert!(
            support.contains("remote_authoritative_for_recovery=false"),
            "{support}"
        );
        assert!(
            support.contains("ecosystem_state status=gated"),
            "{support}"
        );
        assert!(support.contains("release_evidence status="), "{support}");
        assert!(support.contains("degraded_state degraded="), "{support}");
        assert!(support.contains("\"manifest\":{"), "{support}");
        assert!(
            !support_path.exists(),
            "status view must not export support bundle: {}",
            support_path.display()
        );
    }

    #[test]
    fn tui_support_console_exports_redacted_bundle_through_typed_command() {
        let (agentd, controller) = controller_at_approval("support-console-export");
        let run_id = controller
            .journal()
            .latest_run()
            .expect("latest run lookup")
            .expect("latest run");
        controller
            .journal()
            .append(&crate::audit::AuditEvent::new(
                crate::audit::AuditEventType::SandboxDenied,
                &run_id,
                "support-secret",
                "operator",
                "diagnostic failed password=hunter2 token=abc123 secret://kept-handle",
            ))
            .expect("secret audit event");

        let support = controller
            .dispatch_line(&agentd, "support.bundle export")
            .text;
        let support_path = controller.paths().support_bundle_path.clone();
        let exported = std::fs::read_to_string(&support_path).expect("exported bundle");

        assert!(support.contains("panel=support-console"), "{support}");
        assert!(support.contains("status=exported"), "{support}");
        assert!(support.contains("export_written=true"), "{support}");
        assert!(support.contains("last_export_path=\""), "{support}");
        assert!(support_path.is_file(), "bundle must be exported");
        assert!(
            support.contains("action=\"inspect-exported-bundle\""),
            "{support}"
        );
        assert!(
            support.contains("redaction=secret-values-redacted"),
            "{support}"
        );
        assert!(support.contains("includes_raw_secret=false"), "{support}");
        assert!(
            support.contains("remote_authoritative_for_recovery=false"),
            "{support}"
        );
        assert!(!support.contains("password=hunter2"), "{support}");
        assert!(!support.contains("token=abc123"), "{support}");
        assert!(!exported.contains("password=hunter2"), "{exported}");
        assert!(!exported.contains("token=abc123"), "{exported}");
        assert!(exported.contains("secret-values-redacted"), "{exported}");
    }

    #[test]
    fn tui_support_console_identifies_degraded_and_remote_mirror_state() {
        let (agentd, controller) = controller_at_approval("support-console-degraded");
        let run_id = controller
            .journal()
            .latest_run()
            .expect("latest run lookup")
            .expect("latest run");
        let mut prepared = crate::audit::AuditEvent::new(
            crate::audit::AuditEventType::EffectPrepared,
            &run_id,
            "write-config",
            "operator",
            "prepared tool=fs.write.diff rollback_id=rb-support target=/tmp/nginx.conf",
        );
        prepared.parameter_hash = "hash-support-write".to_string();
        controller
            .journal()
            .append(&prepared)
            .expect("prepared effect");
        controller
            .journal()
            .append(&crate::audit::AuditEvent::new(
                crate::audit::AuditEventType::PolicyEvaluated,
                "remote-audit-mirror",
                "mirror-failure",
                "agentos",
                "remote-audit-mirror failure policy=fail-closed status=failed-closed profile=regulated attempted_records=3 reason=not-json",
            ))
            .expect("remote mirror failure");

        let support = controller
            .dispatch_line(&agentd, "support.bundle status")
            .text;

        assert!(support.contains("panel=support-console"), "{support}");
        assert!(
            support.contains("readiness=ready-with-degraded-state"),
            "{support}"
        );
        assert!(
            support.contains("loop_status=needs-reconciliation"),
            "{support}"
        );
        assert!(support.contains("unresolved_effects=1"), "{support}");
        assert!(
            support.contains("degraded_state degraded=true"),
            "{support}"
        );
        assert!(support.contains("support_degraded=true"), "{support}");
        assert!(
            support.contains("recovery_status\":\"needs-human-review"),
            "{support}"
        );
        assert!(
            support.contains("remote_mirror status=failed-closed"),
            "{support}"
        );
        assert!(
            support.contains("local_audit_authoritative=true"),
            "{support}"
        );
        assert!(
            support.contains("remote_authoritative_for_recovery=false"),
            "{support}"
        );
        assert!(support.contains("failure_policy=fail-closed"), "{support}");
        assert!(
            support.contains("non_local_side_effects_allowed=false"),
            "{support}"
        );
        assert!(
            support.contains("action=\"support.bundle export\""),
            "{support}"
        );
    }

    #[test]
    fn tui_degraded_explainer_lists_cause_impact_source_and_action() {
        let (agentd, controller) = controller_at_approval("degraded-explainer-fields");
        let run_id = controller
            .journal()
            .latest_run()
            .expect("latest run lookup")
            .expect("latest run");
        let mut prepared = crate::audit::AuditEvent::new(
            crate::audit::AuditEventType::EffectPrepared,
            &run_id,
            "write-config",
            "operator",
            "prepared tool=fs.write.diff rollback_id=rb-degraded target=/tmp/nginx.conf",
        );
        prepared.parameter_hash = "hash-degraded-write".to_string();
        controller
            .journal()
            .append(&prepared)
            .expect("prepared effect");

        let support = controller
            .dispatch_line(&agentd, "support.bundle status")
            .text;

        assert!(
            support.contains("degraded_explainer schema=agentos.tui-degraded-state-explainer.v1"),
            "{support}"
        );
        assert!(support.contains("source=recovery"), "{support}");
        assert!(
            support.contains(
                "authority=\"AgentCore RunStore + SecurityExecutionEngine AuditJournal\""
            ),
            "{support}"
        );
        assert!(support.contains("cause=\"status="), "{support}");
        assert!(support.contains("impact=\"manual review"), "{support}");
        assert!(
            support.contains("next_action=\"recovery.show latest\""),
            "{support}"
        );
        assert!(support.contains("evidence_path=\"audit:"), "{support}");
    }

    #[test]
    fn tui_degraded_evidence_paths_are_redacted_and_safe() {
        let root = std::env::temp_dir().join(format!(
            "agentd-tui-degraded-path-token=abc123-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("temp root");
        let paths = TuiRuntimePaths::new(root.join("runs"), root.join("audit.jsonl"))
            .with_support_bundle_path(root.join("support-password=hunter2.json"));
        let agentd = started_agentd();
        let controller = TuiRuntimeController::new(paths).expect("controller");
        controller.dispatch_line(&agentd, "intent.submit recover nginx service");
        for _ in 0..8 {
            let output = controller.dispatch_line(&agentd, "run.advance latest").text;
            if output.contains("state=AwaitingApproval") {
                break;
            }
        }
        let run_id = controller
            .journal()
            .latest_run()
            .expect("latest run lookup")
            .expect("latest run");
        let mut prepared = crate::audit::AuditEvent::new(
            crate::audit::AuditEventType::EffectPrepared,
            &run_id,
            "write-config",
            "operator",
            "prepared tool=fs.write.diff rollback_id=rb-path target=/tmp/nginx.conf",
        );
        prepared.parameter_hash = "hash-path-write".to_string();
        controller
            .journal()
            .append(&prepared)
            .expect("prepared effect");

        let support = controller
            .dispatch_line(&agentd, "support.bundle status")
            .text;

        assert!(
            support.contains("evidence_path=\"[REDACTED-PATH]\""),
            "{support}"
        );
        for forbidden in [
            "password=hunter2",
            "token=abc123",
            "file://",
            "explorer",
            "powershell",
            "pwsh",
            "cmd",
            "open ",
        ] {
            assert!(
                !support.to_ascii_lowercase().contains(forbidden),
                "support output contained forbidden fragment {forbidden}: {support}"
            );
        }
    }

    #[test]
    fn tui_degraded_optional_dependency_does_not_block_baseline() {
        let (agentd, controller) = controller_at_approval("degraded-optional-dependency");
        let run_id = controller
            .journal()
            .latest_run()
            .expect("latest run lookup")
            .expect("latest run");
        controller
            .journal()
            .append(&crate::audit::AuditEvent::new(
                crate::audit::AuditEventType::PolicyEvaluated,
                &run_id,
                "mirror-failure",
                "agentos",
                "remote-audit-mirror failure policy=warn status=warning profile=optional attempted_records=3 reason=timeout",
            ))
            .expect("remote mirror failure");

        let support = controller
            .dispatch_line(&agentd, "support.bundle status")
            .text;

        assert!(support.contains("source=remote-mirror"), "{support}");
        assert!(support.contains("optional_dependency=true"), "{support}");
        assert!(support.contains("baseline_blocking=false"), "{support}");
        assert!(support.contains("baseline_operable=true"), "{support}");
        assert!(
            support.contains("local audit remains recovery authority"),
            "{support}"
        );
        assert!(
            support.contains("remote_authoritative_for_recovery=false"),
            "{support}"
        );
        assert!(
            support.contains(&format!("run={run_id}")) || support.contains("audit:"),
            "{support}"
        );
    }

    #[test]
    fn tui_capability_index_renders_read_only_projection() {
        let agentd = started_agentd();
        let controller =
            TuiRuntimeController::new(temp_tui_paths("capability-index")).expect("controller");

        let catalog = controller.dispatch_line(&agentd, "capabilities.show").text;

        assert!(catalog.contains("TUI Capability Catalog"), "{catalog}");
        assert!(
            catalog.contains("schema=agentos.tui-capability-index.v1"),
            "{catalog}"
        );
        assert!(catalog.contains("read_only=true"), "{catalog}");
        assert!(
            catalog.contains("projection_controller_only=true"),
            "{catalog}"
        );
        assert!(
            catalog.contains("direct_execution_allowed=false"),
            "{catalog}"
        );
        assert!(catalog.contains("planner_logic=false"), "{catalog}");
        assert!(catalog.contains("resolver_logic=false"), "{catalog}");
        assert!(
            catalog.contains("resolver_owner=agent_core::ecosystem"),
            "{catalog}"
        );
        for capability in [
            "id=aom.activation.preview",
            "id=content.inspect",
            "id=package.install",
            "id=rootfs.update",
            "id=service.recovery",
            "id=support.bundle",
        ] {
            assert!(
                catalog.contains(capability),
                "missing {capability}: {catalog}"
            );
        }
    }

    #[test]
    fn tui_capability_index_launch_paths_are_intent_or_preview_only() {
        let agentd = started_agentd();
        let controller = TuiRuntimeController::new(temp_tui_paths("capability-index-launch"))
            .expect("controller");
        let support_path = controller.paths().support_bundle_path.clone();

        let catalog = controller.dispatch_line(&agentd, "capability.list").text;

        assert!(catalog.contains("launch_kind=intent"), "{catalog}");
        assert!(catalog.contains("launch_kind=preview"), "{catalog}");
        assert!(
            catalog.contains("launch_path=\"intent.submit recover nginx service\""),
            "{catalog}"
        );
        assert!(
            catalog.contains(
                "launch_path=\"aom.activate.preview agentos:workflow-pack/agentos/service-recovery@1.0.0\""
            ),
            "{catalog}"
        );
        assert!(
            catalog.contains("launch_path=\"palette.preview support.bundle export\""),
            "{catalog}"
        );
        assert!(catalog.contains("preview_only=true"), "{catalog}");
        assert!(!catalog.contains("direct_execute=true"), "{catalog}");
        assert!(!catalog.contains("shell.exec"), "{catalog}");
        assert!(!catalog.contains("powershell"), "{catalog}");
        assert!(!catalog.contains("cmd "), "{catalog}");
        assert!(
            !support_path.exists(),
            "catalog projection must not export support bundle: {}",
            support_path.display()
        );
    }

    #[test]
    fn tui_capability_index_marks_degraded_or_unavailable_with_reason_and_source() {
        let agentd = started_agentd();
        let controller = TuiRuntimeController::new(temp_tui_paths("capability-index-degraded"))
            .expect("controller");

        let catalog = controller.dispatch_line(&agentd, "capabilities.show").text;

        assert!(catalog.contains("id=rootfs.update"), "{catalog}");
        assert!(catalog.contains("status=degraded"), "{catalog}");
        assert!(
            catalog.contains("source=\"OperatorProjection.update\""),
            "{catalog}"
        );
        assert!(
            catalog.contains("unavailable_reason=\"update projection status=not-configured"),
            "{catalog}"
        );
        assert!(
            catalog.contains("required_approvals=\"signed update metadata|inactive slot validation|rollback evidence|exact approval token for activation\""),
            "{catalog}"
        );
    }

    #[test]
    fn tui_capability_index_alias_and_palette_preview_are_read_only() {
        let agentd = started_agentd();
        let controller = TuiRuntimeController::new(temp_tui_paths("capability-index-alias"))
            .expect("controller");

        assert!(matches!(
            TuiCommand::parse("capabilities.show"),
            Ok(TuiCommand::CapabilityIndexShow)
        ));
        assert!(matches!(
            TuiCommand::parse("capability.list"),
            Ok(TuiCommand::CapabilityIndexShow)
        ));

        let preview = controller
            .dispatch_line(&agentd, "palette.preview capabilities.show")
            .text;
        assert!(preview.contains("Command Preview"), "{preview}");
        assert!(preview.contains("risk=read-only"), "{preview}");
        assert!(
            preview.contains("read-only capability catalog projection"),
            "{preview}"
        );

        let catalog = controller.dispatch_line(&agentd, "capability.list").text;
        assert!(catalog.contains("TUI Capability Catalog"), "{catalog}");
    }

    #[test]
    fn tui_workflow_catalog_groups_operational_workflows() {
        let agentd = started_agentd();
        let controller =
            TuiRuntimeController::new(temp_tui_paths("workflow-catalog")).expect("controller");

        let catalog = controller.dispatch_line(&agentd, "workflows.show").text;

        assert!(catalog.contains("TUI Workflow Catalog"), "{catalog}");
        assert!(
            catalog.contains("schema=agentos.tui-workflow-catalog.v1"),
            "{catalog}"
        );
        assert!(catalog.contains("read_only=true"), "{catalog}");
        assert!(
            catalog.contains("projection_controller_only=true"),
            "{catalog}"
        );
        assert!(
            catalog.contains("direct_execution_allowed=false"),
            "{catalog}"
        );
        assert!(catalog.contains("plan_spec_created=false"), "{catalog}");
        for category in [
            "category=service",
            "category=package",
            "category=content",
            "category=update",
            "category=support",
            "category=ecosystem",
        ] {
            assert!(catalog.contains(category), "missing {category}: {catalog}");
        }
        for workflow in [
            "id=service.recovery",
            "id=package.install",
            "id=content.inspect",
            "id=rootfs.update",
            "id=support.bundle",
            "id=aom.activation.preview",
        ] {
            assert!(catalog.contains(workflow), "missing {workflow}: {catalog}");
        }
    }

    #[test]
    fn tui_workflow_catalog_detail_shows_risk_approval_rollback_and_evidence() {
        let agentd = started_agentd();
        let controller = TuiRuntimeController::new(temp_tui_paths("workflow-catalog-detail"))
            .expect("controller");

        let package = controller
            .dispatch_line(&agentd, "workflows.show package.install")
            .text;
        let ecosystem = controller
            .dispatch_line(&agentd, "workflow.show aom.activation.preview")
            .text;

        assert!(
            package.contains("workflow_detail id=package.install"),
            "{package}"
        );
        assert!(
            package.contains("risk=privileged-with-human-approval"),
            "{package}"
        );
        assert!(
            package.contains("exact approval token for pkg.host.install"),
            "{package}"
        );
        assert!(
            package.contains("rollback id before host mutation"),
            "{package}"
        );
        assert!(package.contains("audit.show latest"), "{package}");
        assert!(package.contains("support.bundle status"), "{package}");
        assert!(
            package.contains("launch_preview=\"palette.preview intent.submit install package through isolated validation\""),
            "{package}"
        );
        assert!(package.contains("direct_execute=false"), "{package}");
        assert!(package.contains("plan_spec_created=false"), "{package}");

        assert!(
            ecosystem.contains("workflow_detail id=aom.activation.preview"),
            "{ecosystem}"
        );
        assert!(ecosystem.contains("risk=activation-gated"), "{ecosystem}");
        assert!(ecosystem.contains("rollback handle"), "{ecosystem}");
        assert!(
            ecosystem.contains(".workflow/artifacts/ecosystem-replay/result.json"),
            "{ecosystem}"
        );
    }

    #[test]
    fn tui_workflow_catalog_external_dependencies_are_optional_for_baseline() {
        let agentd = started_agentd();
        let controller = TuiRuntimeController::new(temp_tui_paths("workflow-catalog-external"))
            .expect("controller");

        let catalog = controller.dispatch_line(&agentd, "workflows.show").text;

        assert!(catalog.contains("baseline_local_only=true"), "{catalog}");
        assert!(
            catalog.contains("external_dependency_required=false"),
            "{catalog}"
        );
        assert!(
            catalog.contains("host package manager optional; baseline does not require it"),
            "{catalog}"
        );
        assert!(
            catalog.contains("network fetch optional; baseline accepts pinned local file content"),
            "{catalog}"
        );
        assert!(
            catalog.contains(
                "QEMU optional for smoke; baseline evidence is local artifact projection"
            ),
            "{catalog}"
        );
        assert!(
            catalog
                .contains("remote registry optional; baseline uses pinned local registry snapshot"),
            "{catalog}"
        );
    }

    #[test]
    fn tui_workflow_catalog_palette_preview_does_not_create_run_or_plan() {
        let agentd = started_agentd();
        let controller = TuiRuntimeController::new(temp_tui_paths("workflow-catalog-preview"))
            .expect("controller");
        let run_store = controller.paths().run_store_root.clone();

        assert!(matches!(
            TuiCommand::parse("workflows.show service.recovery"),
            Ok(TuiCommand::WorkflowCatalogShow {
                workflow_id: Some(id)
            }) if id == "service.recovery"
        ));

        let before_has_snapshot = has_snapshot(&run_store);
        let preview = controller
            .dispatch_line(&agentd, "palette.preview workflows.show service.recovery")
            .text;
        let detail = controller
            .dispatch_line(&agentd, "workflows.show service.recovery")
            .text;
        let after_has_snapshot = has_snapshot(&run_store);

        assert!(!before_has_snapshot);
        assert!(!after_has_snapshot);
        assert!(preview.contains("risk=read-only"), "{preview}");
        assert!(
            preview.contains("read-only workflow catalog projection"),
            "{preview}"
        );
        assert!(detail.contains("plan_spec_created=false"), "{detail}");
        assert!(detail.contains("direct_execute=false"), "{detail}");
        assert!(!detail.contains("shell.exec"), "{detail}");
        assert!(!detail.contains("powershell"), "{detail}");
    }

    #[test]
    fn tui_launch_preview_never_executes_directly() {
        let agentd = started_agentd();
        let controller = TuiRuntimeController::new(temp_tui_paths("launch-preview-readonly"))
            .expect("controller");
        let run_store = controller.paths().run_store_root.clone();

        assert!(matches!(
            TuiCommand::parse("launch.preview service.recovery service=nginx"),
            Ok(TuiCommand::LaunchPreview {
                workflow_id,
                inputs
            }) if workflow_id == "service.recovery" && inputs == vec!["service=nginx"]
        ));

        let before_has_snapshot = has_snapshot(&run_store);
        let preview = controller
            .dispatch_line(&agentd, "launch.preview service.recovery service=nginx")
            .text;
        let after_has_snapshot = has_snapshot(&run_store);

        assert!(!before_has_snapshot);
        assert!(!after_has_snapshot);
        assert!(preview.contains("TUI Launch Intent Preview"), "{preview}");
        assert!(
            preview.contains("schema=agentos.tui-launch-intent-preview.v1"),
            "{preview}"
        );
        assert!(preview.contains("workflow=service.recovery"), "{preview}");
        assert!(preview.contains("dispatch_required=true"), "{preview}");
        assert!(
            preview.contains("explicit_dispatch_required=true"),
            "{preview}"
        );
        assert!(preview.contains("direct_execute=false"), "{preview}");
        assert!(preview.contains("plan_spec_created=false"), "{preview}");
        assert!(preview.contains("side_effects_prepared=false"), "{preview}");
        assert!(
            preview.contains(
                "typed_intent=\"intent.submit recover nginx service input.service=nginx\""
            ),
            "{preview}"
        );
        assert!(
            controller
                .journal()
                .latest_run()
                .expect("latest run lookup")
                .is_none(),
            "launch preview must not accept intent or create a run"
        );
    }

    #[test]
    fn tui_launch_preview_high_risk_shows_approval_and_rollback() {
        let agentd = started_agentd();
        let controller = TuiRuntimeController::new(temp_tui_paths("launch-preview-high-risk"))
            .expect("controller");

        let package = controller
            .dispatch_line(
                &agentd,
                "launch.preview package.install package_identity=nginx package_digest=sha256:pkg rollback_id=rb-001",
            )
            .text;
        let rootfs = controller
            .dispatch_line(
                &agentd,
                "capability.launch.preview rootfs.update inactive_slot=B release_manifest_sha256=sha256:release rootfs_sha256=sha256:rootfs",
            )
            .text;

        assert!(
            package.contains("risk=privileged-with-human-approval"),
            "{package}"
        );
        assert!(
            package.contains("authority_path=\"AgentCore planner -> SecurityExecutionEngine -> approval -> rollback\""),
            "{package}"
        );
        assert!(
            package.contains("exact approval token for pkg.host.install"),
            "{package}"
        );
        assert!(package.contains("rollback_id"), "{package}");
        assert!(
            package.contains("host package promotion requires rollback id before host mutation"),
            "{package}"
        );
        assert!(package.contains("audit.show latest"), "{package}");
        assert!(package.contains("support.bundle status"), "{package}");

        assert!(
            rootfs.contains("risk=privileged-with-human-approval"),
            "{rootfs}"
        );
        assert!(
            rootfs.contains("signed update metadata|inactive slot validation|rollback evidence|exact approval token for activation"),
            "{rootfs}"
        );
        assert!(
            rootfs.contains("A/B slot activation requires rollback evidence"),
            "{rootfs}"
        );
    }

    #[test]
    fn tui_launch_preview_rejects_unsafe_input_before_intent_submission() {
        let agentd = started_agentd();
        let controller =
            TuiRuntimeController::new(temp_tui_paths("launch-preview-unsafe")).expect("controller");
        let run_store = controller.paths().run_store_root.clone();

        for line in [
            "launch.preview service.recovery service=nginx;id",
            "launch.preview service.recovery cmd=powershell",
            "launch.preview service.recovery shell=shell.exec",
            "launch.preview service.recovery token=abc123",
            "capability.launch.preview rootfs.update command=cmd",
        ] {
            let output = controller.dispatch_line(&agentd, line).text;
            assert!(output.contains("TUI Error"), "{line}: {output}");
            assert!(
                output.contains("kind=parse") || output.contains("kind=runtime"),
                "{line}: {output}"
            );
        }

        assert!(!has_snapshot(&run_store));
        assert!(
            controller
                .journal()
                .latest_run()
                .expect("latest run lookup")
                .is_none(),
            "unsafe launch preview must fail before intent submission"
        );
    }

    #[test]
    fn tui_launch_preview_redacts_secret_handles_and_is_deterministic() {
        let agentd = started_agentd();
        let controller = TuiRuntimeController::new(temp_tui_paths("launch-preview-redaction"))
            .expect("controller");

        let line = "launch.preview content.inspect source_uri=secret://content/source content_digest=sha256:abc max_bytes=4096";
        let first = controller.dispatch_line(&agentd, line).text;
        let second = controller.dispatch_line(&agentd, line).text;

        assert_eq!(first, second);
        assert!(first.contains("deterministic=true"), "{first}");
        assert!(
            first.contains("redaction=secret-values-redacted"),
            "{first}"
        );
        assert!(first.contains("redaction_applied=true"), "{first}");
        assert!(first.contains("[REDACTED]"), "{first}");
        assert!(!first.contains("secret://content/source"), "{first}");
        assert!(!first.contains("password="), "{first}");
        assert!(!first.contains("token=abc123"), "{first}");
    }

    #[test]
    fn tui_aom_artifact_detail_explains_trust_compatibility_and_activation_gate() {
        let coordinate = "agentos:workflow-pack/agentos/tui-aom@1.0.0";
        let root = temp_aom_fixture_root("detail");
        let registry_path = write_aom_registry(
            &root,
            coordinate,
            false,
            "0.1.0",
            "0.9.0",
            &["audit-journal", "rollback-store"],
            &["kvm"],
        );
        let staging_root = write_aom_staging(&root, coordinate);
        let active_set_path = write_aom_active_set(&root, None);

        let panel = AomArtifactPanel::collect_from_paths(
            coordinate,
            registry_path,
            staging_root,
            active_set_path,
        )
        .expect("aom artifact panel")
        .render();

        assert!(panel.contains("TUI AOM Artifact"), "{panel}");
        assert!(
            panel.contains("schema=agentos.tui-aom-artifact-panel.v1"),
            "{panel}"
        );
        assert!(panel.contains("read_only=true"), "{panel}");
        assert!(panel.contains("projection_controller_only=true"), "{panel}");
        assert!(panel.contains("resolver_logic=false"), "{panel}");
        assert!(
            panel.contains("resolver_owner=agent_core::ecosystem"),
            "{panel}"
        );
        assert!(panel.contains("trust_tier=core"), "{panel}");
        assert!(panel.contains("production_eligible=true"), "{panel}");
        assert!(panel.contains("signature_verified=true"), "{panel}");
        assert!(panel.contains("sbom_verified=true"), "{panel}");
        assert!(panel.contains("accepted_for_production=true"), "{panel}");
        assert!(panel.contains("lifecycle_state=staged-inert"), "{panel}");
        assert!(panel.contains("staged=true"), "{panel}");
        assert!(panel.contains("active=false"), "{panel}");
        assert!(panel.contains("stage_inert=true"), "{panel}");
        assert!(panel.contains("activation_prepared=false"), "{panel}");
        assert!(
            panel.contains("compatibility_status status=compatible"),
            "{panel}"
        );
        assert!(
            panel.contains("missing_optional_features=\"kvm\""),
            "{panel}"
        );
        assert!(
            panel.contains("security_execution_required=true"),
            "{panel}"
        );
        assert!(
            panel.contains("agent_core_plan_spec_required=true"),
            "{panel}"
        );
        assert!(panel.contains("direct_activate=false"), "{panel}");
        assert!(panel.contains("trust_ui_authority=false"), "{panel}");
    }

    #[test]
    fn tui_aom_artifact_blocks_revoked_or_incompatible_artifacts() {
        let revoked_coordinate = "agentos:workflow-pack/agentos/revoked@1.0.0";
        let revoked_root = temp_aom_fixture_root("revoked");
        let revoked_registry = write_aom_registry(
            &revoked_root,
            revoked_coordinate,
            true,
            "0.1.0",
            "0.9.0",
            &["audit-journal"],
            &[],
        );
        let revoked_staging = revoked_root.join("staged");
        std::fs::create_dir_all(&revoked_staging).expect("revoked staging root");
        let revoked_active = write_aom_active_set(&revoked_root, Some(revoked_coordinate));

        let revoked = AomArtifactPanel::collect_from_paths(
            revoked_coordinate,
            revoked_registry,
            revoked_staging,
            revoked_active,
        )
        .expect("revoked panel")
        .render();

        assert!(
            revoked.contains("lifecycle_state=blocked-revoked"),
            "{revoked}"
        );
        assert!(revoked.contains("blocked=true"), "{revoked}");
        assert!(revoked.contains("revoked=true"), "{revoked}");
        assert!(revoked.contains("degraded=true"), "{revoked}");
        assert!(
            revoked.contains("activation_preview status=blocked"),
            "{revoked}"
        );
        assert!(revoked.contains("can_activate=false"), "{revoked}");

        let incompatible_coordinate = "agentos:workflow-pack/agentos/incompatible@1.0.0";
        let incompatible_root = temp_aom_fixture_root("incompatible");
        let incompatible_registry = write_aom_registry(
            &incompatible_root,
            incompatible_coordinate,
            false,
            "0.2.0",
            "0.9.0",
            &["audit-journal", "missing-gpu"],
            &[],
        );
        let incompatible_staging = incompatible_root.join("staged");
        std::fs::create_dir_all(&incompatible_staging).expect("incompatible staging root");
        let incompatible_active = write_aom_active_set(&incompatible_root, None);

        let incompatible = AomArtifactPanel::collect_from_paths(
            incompatible_coordinate,
            incompatible_registry,
            incompatible_staging,
            incompatible_active,
        )
        .expect("incompatible panel")
        .render();

        assert!(
            incompatible.contains("lifecycle_state=blocked-incompatible"),
            "{incompatible}"
        );
        assert!(incompatible.contains("blocked=true"), "{incompatible}");
        assert!(incompatible.contains("incompatible=true"), "{incompatible}");
        assert!(
            incompatible.contains("compatibility_status status=incompatible"),
            "{incompatible}"
        );
        assert!(
            incompatible.contains("missing_required_features=\"missing-gpu\""),
            "{incompatible}"
        );
        assert!(
            incompatible.contains("activation_preview status=blocked"),
            "{incompatible}"
        );
    }

    #[test]
    fn tui_aom_artifact_command_and_palette_are_read_only() {
        let agentd = started_agentd();
        let controller =
            TuiRuntimeController::new(temp_tui_paths("aom-artifact-command")).expect("controller");
        let run_store = controller.paths().run_store_root.clone();
        let coordinate = "agentos:workflow-pack/agentos/service-recovery@1.0.0";

        assert!(matches!(
            TuiCommand::parse(&format!("aom.artifact.show {coordinate}")),
            Ok(TuiCommand::AomArtifactShow { coordinate: parsed }) if parsed == coordinate
        ));

        let before_has_snapshot = has_snapshot(&run_store);
        let panel = controller
            .dispatch_line(&agentd, &format!("aom.artifact.show {coordinate}"))
            .text;
        let after_has_snapshot = has_snapshot(&run_store);
        let preview = controller
            .dispatch_line(
                &agentd,
                &format!("palette.preview aom.artifact.show {coordinate}"),
            )
            .text;

        assert!(!before_has_snapshot);
        assert!(!after_has_snapshot);
        assert!(panel.contains("TUI AOM Artifact"), "{panel}");
        assert!(panel.contains("direct_execute=false"), "{panel}");
        assert!(panel.contains("activation_prepared=false"), "{panel}");
        assert!(panel.contains("agentd_resolver_logic=false"), "{panel}");
        assert!(!panel.contains("EffectPrepared"), "{panel}");
        assert!(!panel.contains("shell.exec"), "{panel}");
        assert!(preview.contains("Command Preview"), "{preview}");
        assert!(preview.contains("risk=read-only"), "{preview}");
        assert!(
            preview.contains("read-only artifact trust and activation gate projection"),
            "{preview}"
        );
    }

    #[test]
    fn tui_release_provenance_panel_projects_candidate_evidence_read_only() {
        let root = temp_release_fixture_root("ready-warning");
        write_release_fixture(&root, true, &[]);

        let panel = ReleaseProvenancePanel::collect_from_dir(&root).render();

        assert!(panel.contains("TUI Release Provenance"), "{panel}");
        assert!(
            panel.contains("schema=agentos.tui-release-provenance-panel.v1"),
            "{panel}"
        );
        assert!(panel.contains("read_only=true"), "{panel}");
        assert!(panel.contains("projection_controller_only=true"), "{panel}");
        assert!(panel.contains("release_authority=false"), "{panel}");
        assert!(panel.contains("promotion_authority=false"), "{panel}");
        assert!(panel.contains("direct_sign=false"), "{panel}");
        assert!(panel.contains("direct_promote=false"), "{panel}");
        assert!(panel.contains("provenance status=warning"), "{panel}");
        assert!(panel.contains("present=true"), "{panel}");
        assert!(panel.contains("source_commit=\"abc123\""), "{panel}");
        assert!(panel.contains("source_branch=\"main\""), "{panel}");
        assert!(panel.contains("promotion status=promotable"), "{panel}");
        assert!(panel.contains("dirty_worktree=true"), "{panel}");
        assert!(panel.contains("warnings=\"dirty-worktree\""), "{panel}");
        assert!(panel.contains("gate_summary total=2 passed=2"), "{panel}");
        assert!(
            panel.contains("dependency_inventory_packages=2 sbom_packages=2"),
            "{panel}"
        );
        assert!(
            panel.contains("update_metadata_signature_policy=\"candidate-hash-bound\""),
            "{panel}"
        );
        assert!(panel.contains("artifact name=agentd_binary"), "{panel}");
        assert!(
            panel.contains("gate_artifact name=qemu_runtime_smoke"),
            "{panel}"
        );
        assert!(
            panel.contains("detached_signature name=provenance status=present"),
            "{panel}"
        );
        assert!(
            panel.contains("artifact_generation_in_tui=false"),
            "{panel}"
        );
        assert!(
            panel.contains("production_ready_claim_by_tui=false"),
            "{panel}"
        );
        assert!(!panel.contains("EffectPrepared"), "{panel}");
        assert!(!panel.contains("shell.exec"), "{panel}");
    }

    #[test]
    fn tui_release_provenance_missing_evidence_is_blocked_visible() {
        let root = temp_release_fixture_root("missing");

        let panel = ReleaseProvenancePanel::collect_from_dir(&root).render();

        assert!(panel.contains("TUI Release Provenance"), "{panel}");
        assert!(panel.contains("provenance status=blocked"), "{panel}");
        assert!(panel.contains("present=false"), "{panel}");
        assert!(panel.contains("missing_provenance=true"), "{panel}");
        assert!(panel.contains("promotion status=blocked"), "{panel}");
        assert!(
            panel.contains("release-file-missing:provenance.json"),
            "{panel}"
        );
        assert!(panel.contains("provenance-missing"), "{panel}");
        assert!(
            panel.contains("detached_signature name=provenance status=missing"),
            "{panel}"
        );
        assert!(panel.contains("direct_promote=false"), "{panel}");
    }

    #[test]
    fn tui_release_provenance_command_and_palette_are_read_only() {
        let agentd = started_agentd();
        let controller = TuiRuntimeController::new(temp_tui_paths("release-provenance-command"))
            .expect("controller");
        let run_store = controller.paths().run_store_root.clone();

        assert!(matches!(
            TuiCommand::parse("release.provenance.show"),
            Ok(TuiCommand::ReleaseProvenanceShow)
        ));

        let before_has_snapshot = has_snapshot(&run_store);
        let panel = controller
            .dispatch_line(&agentd, "release.provenance.show")
            .text;
        let after_has_snapshot = has_snapshot(&run_store);
        let preview = controller
            .dispatch_line(&agentd, "palette.preview release.provenance.show")
            .text;

        assert!(!before_has_snapshot);
        assert!(!after_has_snapshot);
        assert!(panel.contains("TUI Release Provenance"), "{panel}");
        assert!(panel.contains("read_only=true"), "{panel}");
        assert!(panel.contains("direct_sign=false"), "{panel}");
        assert!(panel.contains("direct_promote=false"), "{panel}");
        assert!(!panel.contains("EffectPrepared"), "{panel}");
        assert!(preview.contains("Command Preview"), "{preview}");
        assert!(preview.contains("risk=read-only"), "{preview}");
        assert!(
            preview.contains("read-only release provenance projection"),
            "{preview}"
        );
    }

    #[test]
    fn tui_promotion_blockers_groups_release_blockers_and_safe_actions() {
        let root = temp_release_fixture_root("promotion-blockers-groups");
        write_release_fixture(
            &root,
            false,
            &[
                "tests-skipped",
                "qemu-runtime-smoke-skipped",
                "functional-replay-skipped",
                "signature-missing:provenance",
                "release-file-missing:sbom.json",
                "active-artifact-update-readiness-failed",
            ],
        );

        let panel = PromotionBlockerPanel::collect_from_dir(&root).render();

        assert!(panel.contains("TUI Promotion Blockers"), "{panel}");
        assert!(
            panel.contains("schema=agentos.tui-promotion-blocker-panel.v1"),
            "{panel}"
        );
        assert!(panel.contains("read_only=true"), "{panel}");
        assert!(panel.contains("projection_controller_only=true"), "{panel}");
        assert!(panel.contains("release_authority=false"), "{panel}");
        assert!(panel.contains("blocker_override_allowed=false"), "{panel}");
        assert!(panel.contains("clear_blocker_allowed=false"), "{panel}");
        assert!(panel.contains("direct_sign=false"), "{panel}");
        assert!(panel.contains("direct_promote=false"), "{panel}");
        assert!(
            panel.contains("artifact_generation_in_tui=false"),
            "{panel}"
        );
        assert!(
            panel.contains("provenance_mutation_in_tui=false"),
            "{panel}"
        );
        assert!(
            panel.contains("promotion_summary status=blocked blocker_count=6"),
            "{panel}"
        );
        for category in [
            "tests",
            "boot-smoke",
            "replay",
            "signing",
            "provenance",
            "ecosystem-readiness",
        ] {
            assert!(
                panel.contains(&format!("blocker_group category={category}")),
                "{panel}"
            );
        }
        assert!(
            panel.contains("blocker id=\"tests-skipped\" category=tests"),
            "{panel}"
        );
        assert!(
            panel.contains(
                "safe_next_command=\"cargo test -p agentd\" message=\"required release gate is skipped: tests-skipped\""
            ),
            "{panel}"
        );
        assert!(
            panel.contains("blocker id=\"qemu-runtime-smoke-skipped\" category=boot-smoke"),
            "{panel}"
        );
        assert!(
            panel.contains(
                "scripts/boot-smoke-test.ps1 -QemuPath E:\\\\qemu\\\\qemu-system-x86_64.exe"
            ),
            "{panel}"
        );
        assert!(
            panel.contains("blocker id=\"functional-replay-skipped\" category=replay"),
            "{panel}"
        );
        assert!(
            panel.contains("scripts/functional-capability-replay.ps1"),
            "{panel}"
        );
        assert!(
            panel.contains("blocker id=\"signature-missing:provenance\" category=signing"),
            "{panel}"
        );
        assert!(
            panel.contains("blocker id=\"release-file-missing:sbom.json\" category=provenance"),
            "{panel}"
        );
        assert!(
            panel.contains(
                "blocker id=\"active-artifact-update-readiness-failed\" category=ecosystem-readiness"
            ),
            "{panel}"
        );
        assert!(
            panel.contains("scripts/ecosystem-replay.ps1")
                || panel.contains("scripts/build-release.ps1"),
            "{panel}"
        );
        assert!(panel.contains("tui_can_clear_blockers=false"), "{panel}");
        assert!(!panel.contains("EffectPrepared"), "{panel}");
        assert!(!panel.contains("shell.exec"), "{panel}");
    }

    #[test]
    fn tui_promotion_blockers_treats_skipped_required_gates_as_blockers() {
        let root = temp_release_fixture_root("promotion-blockers-skipped-gates");
        write_release_fixture_with_gates(
            &root,
            false,
            &[],
            &[
                (
                    "cargo test -p agentd",
                    "cargo test -p agentd",
                    "skipped",
                    ".workflow/artifacts/release/cargo-test-agentd.json",
                ),
                (
                    "QEMU runtime smoke",
                    "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/boot-smoke-test.ps1 -QemuPath E:\\qemu\\qemu-system-x86_64.exe -TimeoutSeconds 120",
                    "skipped",
                    ".workflow/artifacts/boot/boot-smoke-result.json",
                ),
                (
                    "ecosystem replay",
                    "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/ecosystem-replay.ps1",
                    "skipped",
                    ".workflow/artifacts/ecosystem-replay/result.json",
                ),
            ],
        );

        let panel = PromotionBlockerPanel::collect_from_dir(&root).render();

        assert!(
            panel.contains(
                "promotion_summary status=promotable blocker_count=3 skipped_required_gate_count=3"
            ),
            "{panel}"
        );
        assert!(
            panel.contains("skipped_required_gates_are_blockers=true"),
            "{panel}"
        );
        assert!(
            panel.contains(
                "blocker id=\"required-gate-skipped:cargo-test--p-agentd\" category=tests"
            ),
            "{panel}"
        );
        assert!(
            panel.contains("evidence_path=\".workflow/artifacts/release/cargo-test-agentd.json\""),
            "{panel}"
        );
        assert!(
            panel.contains("safe_next_command=\"cargo test -p agentd\""),
            "{panel}"
        );
        assert!(
            panel.contains(
                "blocker id=\"required-gate-skipped:qemu-runtime-smoke\" category=boot-smoke"
            ),
            "{panel}"
        );
        assert!(
            panel.contains("evidence_path=\".workflow/artifacts/boot/boot-smoke-result.json\""),
            "{panel}"
        );
        assert!(
            panel.contains(
                "blocker id=\"required-gate-skipped:ecosystem-replay\" category=ecosystem-readiness"
            ),
            "{panel}"
        );
        assert!(
            panel.contains("evidence_path=\".workflow/artifacts/ecosystem-replay/result.json\""),
            "{panel}"
        );
        assert!(
            panel.contains("blocker_group category=tests")
                && panel.contains("blocker_group category=boot-smoke")
                && panel.contains("blocker_group category=ecosystem-readiness"),
            "{panel}"
        );
        assert!(!panel.contains("clear_blocker_allowed=true"), "{panel}");
        assert!(!panel.contains("direct_promote=true"), "{panel}");
    }

    #[test]
    fn tui_promotion_blockers_command_and_palette_are_read_only() {
        let agentd = started_agentd();
        let controller = TuiRuntimeController::new(temp_tui_paths("promotion-blockers-command"))
            .expect("controller");
        let run_store = controller.paths().run_store_root.clone();

        assert!(matches!(
            TuiCommand::parse("promotion.blockers.show"),
            Ok(TuiCommand::PromotionBlockersShow)
        ));
        assert!(matches!(
            TuiCommand::parse("release.blockers.show"),
            Ok(TuiCommand::PromotionBlockersShow)
        ));

        let before_has_snapshot = has_snapshot(&run_store);
        let panel = controller
            .dispatch_line(&agentd, "promotion.blockers.show")
            .text;
        let after_has_snapshot = has_snapshot(&run_store);
        let preview = controller
            .dispatch_line(&agentd, "palette.preview promotion.blockers.show")
            .text;

        assert!(!before_has_snapshot);
        assert!(!after_has_snapshot);
        assert!(panel.contains("TUI Promotion Blockers"), "{panel}");
        assert!(panel.contains("read_only=true"), "{panel}");
        assert!(panel.contains("blocker_override_allowed=false"), "{panel}");
        assert!(panel.contains("clear_blocker_allowed=false"), "{panel}");
        assert!(panel.contains("direct_promote=false"), "{panel}");
        assert!(!panel.contains("EffectPrepared"), "{panel}");
        assert!(preview.contains("Command Preview"), "{preview}");
        assert!(preview.contains("risk=read-only"), "{preview}");
        assert!(
            preview.contains("read-only promotion blocker projection"),
            "{preview}"
        );
        assert!(
            preview.contains("no blocker override or promotion mutation"),
            "{preview}"
        );
    }

    #[test]
    fn tui_update_rollback_projects_release_update_metadata_read_only() {
        let root = temp_release_fixture_root("update-rollback-ready");
        write_release_fixture(&root, false, &[]);

        let panel = UpdateRollbackPanel::collect_from_dir(&root).render();

        assert!(panel.contains("TUI Update Rollback"), "{panel}");
        assert!(
            panel.contains("schema=agentos.tui-update-rollback-panel.v1"),
            "{panel}"
        );
        assert!(panel.contains("read_only=true"), "{panel}");
        assert!(panel.contains("projection_controller_only=true"), "{panel}");
        assert!(panel.contains("update_authority=false"), "{panel}");
        assert!(panel.contains("rollback_authority=false"), "{panel}");
        assert!(panel.contains("direct_update=false"), "{panel}");
        assert!(panel.contains("direct_rollback=false"), "{panel}");
        assert!(panel.contains("host_mutation_in_tui=false"), "{panel}");
        assert!(
            panel.contains("promotion_blocker_link=\"promotion.blockers.show\""),
            "{panel}"
        );
        assert!(
            panel.contains(
                "mutation_path=\"AgentCore rootfs_update + SecurityExecutionEngine only\""
            ),
            "{panel}"
        );
        assert!(
            panel.contains("schema=\"agentos.candidate-update-metadata.v1\""),
            "{panel}"
        );
        assert!(
            panel.contains("signature_policy_status=\"candidate-hash-bound\""),
            "{panel}"
        );
        assert!(
            panel.contains("unsigned_metadata_acceptable=false"),
            "{panel}"
        );
        assert!(panel.contains("mode=\"ab-rootfs\""), "{panel}");
        assert!(panel.contains("stage_target=\"inactive-slot\""), "{panel}");
        assert!(
            panel.contains("active_slot_modified_in_place=false"),
            "{panel}"
        );
        assert!(panel.contains("health_gate_required=true"), "{panel}");
        assert!(panel.contains("rollback_required=true"), "{panel}");
        assert!(panel.contains("operations_preview_only=true"), "{panel}");
        assert!(panel.contains("active_slot_write_allowed=false"), "{panel}");
        assert!(
            panel.contains("slot_summary active_slot=active-artifact-set pending_slot=inactive-slot rollback_slot=previous-active-set"),
            "{panel}"
        );
        assert!(panel.contains("health_gate state=passed"), "{panel}");
        assert!(panel.contains("rollback_drill status=passed"), "{panel}");
        assert!(panel.contains("previous_equals_restored=true"), "{panel}");
        assert!(
            panel.contains("failure_link blocker_count=0 release_provenance_blocker_count=0"),
            "{panel}"
        );
        assert!(panel.contains("slot_evidence role=active"), "{panel}");
        assert!(panel.contains("slot_evidence role=pending"), "{panel}");
        assert!(panel.contains("slot_evidence role=rollback"), "{panel}");
        assert!(
            panel.contains("update_artifact name=active_artifact_set"),
            "{panel}"
        );
        assert!(
            panel.contains("update_artifact name=ecosystem_replay"),
            "{panel}"
        );
        assert!(
            panel.contains("update_artifact name=rootfs_runtime_manifest"),
            "{panel}"
        );
        assert!(panel.contains("update_blocker id=none"), "{panel}");
        assert!(panel.contains("slot_mutation_in_tui=false"), "{panel}");
        assert!(panel.contains("rollback_execution_in_tui=false"), "{panel}");
        assert!(!panel.contains("EffectPrepared"), "{panel}");
        assert!(!panel.contains("shell.exec"), "{panel}");
    }

    #[test]
    fn tui_update_rollback_failed_readiness_links_promotion_blockers() {
        let root = temp_release_fixture_root("update-rollback-blocked");
        write_release_fixture(&root, false, &["active-artifact-update-readiness-failed"]);
        std::fs::write(
            root.join("update-metadata.json"),
            r#"{"schema":"agentos.candidate-update-metadata.v1","generated_at":"1970-01-01T00:00:00Z","production_ready_claim":false,"source":{"git_commit":"abc123","git_branch":"main"},"update_strategy":{"mode":"ab-rootfs","stage_target":"active-slot","active_slot_modified_in_place":true,"health_gate_required":false,"rollback_required":true},"artifacts":{"active_artifact_set":{"path":"missing-active-set.json","sha256":"sha256:active-set","required":true},"ecosystem_replay":{"path":"missing-ecosystem-replay.json","sha256":"sha256:ecosystem","required":true}},"update_readiness":{"active_artifact_set_hash":"sha256:active-set","active_artifact_set_path":"missing-active-set.json","active_artifact_set_present":false,"runtime_contract_compatibility_checked":false,"incompatible_active_artifacts":["agentos:workflow-pack/agentos/blocked@1.0.0"],"rollback_preserves_previous_active_set":false,"previous_active_set_hash":"sha256:previous-active-set","restored_active_set_hash":"sha256:restored-active-set","ecosystem_replay_status":"failed","promotion_allowed":false},"signature_policy":{"status":"missing"}}"#,
        )
        .expect("blocked update metadata");

        let panel = UpdateRollbackPanel::collect_from_dir(&root).render();

        assert!(panel.contains("TUI Update Rollback"), "{panel}");
        assert!(panel.contains("health_gate state=blocked"), "{panel}");
        assert!(panel.contains("rollback_drill status=blocked"), "{panel}");
        assert!(panel.contains("failed_visible=true"), "{panel}");
        assert!(
            panel.contains("safe_next_command=\"promotion.blockers.show\""),
            "{panel}"
        );
        assert!(panel.contains("promotion_status=blocked"), "{panel}");
        assert!(panel.contains("active-slot-modified-in-place"), "{panel}");
        assert!(
            panel.contains("update-stage-target-not-inactive-slot"),
            "{panel}"
        );
        assert!(
            panel.contains("pending-slot-health-gate-not-required"),
            "{panel}"
        );
        assert!(
            panel.contains("runtime-contract-compatibility-not-checked"),
            "{panel}"
        );
        assert!(panel.contains("incompatible-active-artifacts"), "{panel}");
        assert!(panel.contains("ecosystem-replay-not-passed"), "{panel}");
        assert!(
            panel.contains("update-readiness-promotion-not-allowed"),
            "{panel}"
        );
        assert!(panel.contains("rollback-preservation-failed"), "{panel}");
        assert!(
            panel.contains("update-metadata-signature-policy-unacceptable"),
            "{panel}"
        );
        assert!(
            panel.contains("release-provenance:active-artifact-update-readiness-failed"),
            "{panel}"
        );
        assert!(panel.contains("direct_update=false"), "{panel}");
        assert!(panel.contains("direct_rollback=false"), "{panel}");
        assert!(!panel.contains("clear_blocker_allowed=true"), "{panel}");
    }

    #[test]
    fn tui_update_rollback_command_and_palette_are_read_only() {
        let agentd = started_agentd();
        let controller = TuiRuntimeController::new(temp_tui_paths("update-rollback-command"))
            .expect("controller");
        let run_store = controller.paths().run_store_root.clone();

        assert!(matches!(
            TuiCommand::parse("update.rollback.show"),
            Ok(TuiCommand::UpdateRollbackShow)
        ));
        assert!(matches!(
            TuiCommand::parse("release.update.show"),
            Ok(TuiCommand::UpdateRollbackShow)
        ));

        let before_has_snapshot = has_snapshot(&run_store);
        let panel = controller
            .dispatch_line(&agentd, "update.rollback.show")
            .text;
        let after_has_snapshot = has_snapshot(&run_store);
        let preview = controller
            .dispatch_line(&agentd, "palette.preview update.rollback.show")
            .text;

        assert!(!before_has_snapshot);
        assert!(!after_has_snapshot);
        assert!(panel.contains("TUI Update Rollback"), "{panel}");
        assert!(panel.contains("read_only=true"), "{panel}");
        assert!(panel.contains("direct_update=false"), "{panel}");
        assert!(panel.contains("direct_rollback=false"), "{panel}");
        assert!(panel.contains("host_mutation_in_tui=false"), "{panel}");
        assert!(!panel.contains("EffectPrepared"), "{panel}");
        assert!(preview.contains("Command Preview"), "{preview}");
        assert!(preview.contains("risk=read-only"), "{preview}");
        assert!(
            preview.contains("read-only update and rollback projection"),
            "{preview}"
        );
        assert!(
            preview.contains("no slot mutation or rollback execution"),
            "{preview}"
        );
    }

    #[test]
    fn tui_gate_status_projects_qemu_rootfs_and_replay_evidence_read_only() {
        let root = temp_release_fixture_root("gate-status-ready");
        write_gate_status_fixture(&root);

        let panel = GateStatusPanel::collect_from_dir(&root).render();

        assert!(panel.contains("TUI Gate Status"), "{panel}");
        assert!(
            panel.contains("schema=agentos.tui-gate-status-panel.v1"),
            "{panel}"
        );
        assert!(panel.contains("read_only=true"), "{panel}");
        assert!(panel.contains("projection_controller_only=true"), "{panel}");
        assert!(panel.contains("gate_execution_authority=false"), "{panel}");
        assert!(panel.contains("qemu_execution_in_tui=false"), "{panel}");
        assert!(panel.contains("rootfs_validation_in_tui=false"), "{panel}");
        assert!(panel.contains("replay_execution_in_tui=false"), "{panel}");
        assert!(
            panel.contains("artifact_generation_in_tui=false"),
            "{panel}"
        );
        assert!(
            panel.contains(
                "gate_summary status=passed total=6 passed=6 degraded=0 missing=0 blocker_count=0"
            ),
            "{panel}"
        );
        assert!(
            panel.contains(
                "qemu_gate status=passed observed_all_markers=true tui_console_ready=true runtime_artifacts_ok=true"
            ),
            "{panel}"
        );
        assert!(
            panel.contains("AGENTOS_RUNTIME_MANIFEST_SHA256=sha256:runtime-manifest"),
            "{panel}"
        );
        assert!(
            panel.contains(
                "rootfs_manifest status=passed schema=\"agentos.rootfs-runtime-manifest.v1\""
            ),
            "{panel}"
        );
        assert!(
            panel.contains("recorded_sha256=\"sha256:runtime-manifest\""),
            "{panel}"
        );
        assert!(
            panel.contains("runtime_manifest_sha256=\"sha256:runtime-manifest\""),
            "{panel}"
        );
        assert!(
            panel.contains("hash_tied_to_release_provenance=true"),
            "{panel}"
        );
        assert!(panel.contains("artifact_count=12"), "{panel}");
        assert!(panel.contains("required_artifact_count=12"), "{panel}");
        assert!(
            panel.contains("tui_marker=\"AGENTOS_TUI_CONSOLE_READY\""),
            "{panel}"
        );
        assert!(panel.contains("tui_marker_observed=true"), "{panel}");
        for gate in [
            "qemu_runtime_smoke",
            "alpha_rootfs_validation",
            "functional_capability_replay",
            "ecosystem_replay",
            "tui_replay",
            "production_runbook_smoke",
        ] {
            assert!(
                panel.contains(&format!("gate name={gate} status=passed")),
                "{panel}"
            );
        }
        assert!(panel.contains("gate_blocker id=none"), "{panel}");
        assert!(!panel.contains("EffectPrepared"), "{panel}");
        assert!(!panel.contains("shell.exec"), "{panel}");
    }

    #[test]
    fn tui_gate_status_missing_gate_artifact_is_blocked_visible() {
        let root = temp_release_fixture_root("gate-status-missing");
        write_gate_status_fixture(&root);
        std::fs::remove_file(root.join("functional-replay-result.json"))
            .expect("remove functional replay fixture");

        let panel = GateStatusPanel::collect_from_dir(&root).render();

        assert!(panel.contains("TUI Gate Status"), "{panel}");
        assert!(panel.contains("gate_summary status=blocked"), "{panel}");
        assert!(panel.contains("missing=1"), "{panel}");
        assert!(panel.contains("missing_gate_artifact=true"), "{panel}");
        assert!(
            panel.contains("gate name=functional_capability_replay status=missing"),
            "{panel}"
        );
        assert!(panel.contains("present=false"), "{panel}");
        assert!(
            panel.contains("gate_blocker id=\"gate-not-passed:functional_capability_replay\""),
            "{panel}"
        );
        assert!(
            panel.contains("message=\"required gate evidence is missing: gate-not-passed:functional_capability_replay\""),
            "{panel}"
        );
        assert!(!panel.contains("gate_blocker id=none"), "{panel}");
        assert!(panel.contains("replay_execution_in_tui=false"), "{panel}");
    }

    #[test]
    fn tui_gate_status_command_and_palette_are_read_only() {
        let agentd = started_agentd();
        let controller =
            TuiRuntimeController::new(temp_tui_paths("gate-status-command")).expect("controller");
        let run_store = controller.paths().run_store_root.clone();

        assert!(matches!(
            TuiCommand::parse("gate.status.show"),
            Ok(TuiCommand::GateStatusShow)
        ));
        assert!(matches!(
            TuiCommand::parse("release.gates.show"),
            Ok(TuiCommand::GateStatusShow)
        ));

        let before_has_snapshot = has_snapshot(&run_store);
        let panel = controller.dispatch_line(&agentd, "gate.status.show").text;
        let after_has_snapshot = has_snapshot(&run_store);
        let preview = controller
            .dispatch_line(&agentd, "palette.preview gate.status.show")
            .text;

        assert!(!before_has_snapshot);
        assert!(!after_has_snapshot);
        assert!(panel.contains("TUI Gate Status"), "{panel}");
        assert!(panel.contains("read_only=true"), "{panel}");
        assert!(panel.contains("qemu_execution_in_tui=false"), "{panel}");
        assert!(panel.contains("rootfs_validation_in_tui=false"), "{panel}");
        assert!(panel.contains("replay_execution_in_tui=false"), "{panel}");
        assert!(!panel.contains("EffectPrepared"), "{panel}");
        assert!(preview.contains("Command Preview"), "{preview}");
        assert!(preview.contains("risk=read-only"), "{preview}");
        assert!(
            preview.contains("read-only gate evidence projection"),
            "{preview}"
        );
        assert!(
            preview.contains("no QEMU boot, rootfs validation, or replay execution"),
            "{preview}"
        );
    }

    #[test]
    fn tui_signing_status_projects_candidate_signatures_read_only() {
        let root = temp_release_fixture_root("signing-status-candidate");
        write_release_fixture(&root, false, &[]);
        std::fs::write(
            root.join("provenance.json.sig.json"),
            r#"{"schema":"agentos.release-detached-signature.v1","artifact":{"name":"provenance","path":"provenance.json","sha256":"sha256:provenance"},"signature":{"algorithm":"sha256-hash-bound-candidate-signature-v1","value":"sig-provenance"},"key":{"key_id":"agentos-candidate-release-hash-bound-v1","production_key_required":false,"private_key_path":"E:\\secret\\production-root.pem","secret":"token=abc123"},"policy":{"detached":true,"fail_closed":true}}"#,
        )
        .expect("signature with non-rendered private fields");

        let panel = SigningStatusPanel::collect_from_dir(&root).render();

        assert!(panel.contains("TUI Signing Status"), "{panel}");
        assert!(
            panel.contains("schema=agentos.tui-signing-status-panel.v1"),
            "{panel}"
        );
        assert!(panel.contains("read_only=true"), "{panel}");
        assert!(panel.contains("projection_controller_only=true"), "{panel}");
        assert!(panel.contains("signing_authority=false"), "{panel}");
        assert!(
            panel.contains("production_signing_authority=false"),
            "{panel}"
        );
        assert!(panel.contains("direct_sign=false"), "{panel}");
        assert!(panel.contains("direct_promote=false"), "{panel}");
        assert!(
            panel.contains("private_key_material_visible=false"),
            "{panel}"
        );
        assert!(panel.contains("key_path_visible=false"), "{panel}");
        assert!(panel.contains("scope=candidate-only"), "{panel}");
        assert!(
            panel.contains("candidate_is_production_signature=false"),
            "{panel}"
        );
        assert!(
            panel.contains("candidate_signature_satisfies_production=false"),
            "{panel}"
        );
        assert!(panel.contains("production_ready_claim=false"), "{panel}");
        assert!(
            panel.contains("algorithm=\"sha256-hash-bound-candidate-signature-v1\""),
            "{panel}"
        );
        assert!(
            panel.contains("key_id=\"agentos-candidate-release-hash-bound-v1\""),
            "{panel}"
        );
        assert!(panel.contains("production_key_required=false"), "{panel}");
        assert!(panel.contains("fail_closed=true"), "{panel}");
        for name in [
            "dependency_inventory",
            "sbom",
            "update_metadata",
            "provenance",
        ] {
            assert!(
                panel.contains(&format!("candidate_signature name={name} status=present")),
                "{panel}"
            );
        }
        assert!(panel.contains("candidate_only=true"), "{panel}");
        assert!(panel.contains("production_signature=false"), "{panel}");
        assert!(!panel.contains("production-root.pem"), "{panel}");
        assert!(!panel.contains("token=abc123"), "{panel}");
        assert!(!panel.contains("EffectPrepared"), "{panel}");
        assert!(!panel.contains("shell.exec"), "{panel}");
    }

    #[test]
    fn tui_signing_status_missing_production_signature_is_non_ga_blocker() {
        let root = temp_release_fixture_root("signing-status-missing-production");
        write_release_fixture(&root, false, &[]);

        let panel = SigningStatusPanel::collect_from_dir(&root).render();

        assert!(panel.contains("TUI Signing Status"), "{panel}");
        assert!(
            panel.contains("candidate_signing status=candidate-present"),
            "{panel}"
        );
        assert!(
            panel.contains("production_signing status=missing"),
            "{panel}"
        );
        assert!(panel.contains("required_for_ga=true"), "{panel}");
        assert!(panel.contains("production_ready=false"), "{panel}");
        assert!(
            panel.contains("missing_production_signature=true"),
            "{panel}"
        );
        assert!(
            panel.contains("verification_result_present=false"),
            "{panel}"
        );
        assert!(
            panel.contains("production-signature-verification-missing"),
            "{panel}"
        );
        assert!(
            panel.contains("production-signature-missing:provenance"),
            "{panel}"
        );
        assert!(!panel.contains("signing_blocker id=none"), "{panel}");
        assert!(!panel.contains("production_ready=true"), "{panel}");
        assert!(
            panel.contains("scripts/verify-production-signatures.ps1"),
            "{panel}"
        );
    }

    #[test]
    fn tui_signing_status_command_and_palette_are_read_only() {
        let agentd = started_agentd();
        let controller = TuiRuntimeController::new(temp_tui_paths("signing-status-command"))
            .expect("controller");
        let run_store = controller.paths().run_store_root.clone();

        assert!(matches!(
            TuiCommand::parse("signing.status.show"),
            Ok(TuiCommand::SigningStatusShow)
        ));
        assert!(matches!(
            TuiCommand::parse("release.signing.show"),
            Ok(TuiCommand::SigningStatusShow)
        ));

        let before_has_snapshot = has_snapshot(&run_store);
        let panel = controller
            .dispatch_line(&agentd, "signing.status.show")
            .text;
        let after_has_snapshot = has_snapshot(&run_store);
        let preview = controller
            .dispatch_line(&agentd, "palette.preview signing.status.show")
            .text;

        assert!(!before_has_snapshot);
        assert!(!after_has_snapshot);
        assert!(panel.contains("TUI Signing Status"), "{panel}");
        assert!(panel.contains("read_only=true"), "{panel}");
        assert!(panel.contains("signing_authority=false"), "{panel}");
        assert!(
            panel.contains("production_signing_authority=false"),
            "{panel}"
        );
        assert!(panel.contains("direct_sign=false"), "{panel}");
        assert!(panel.contains("direct_promote=false"), "{panel}");
        assert!(!panel.contains("EffectPrepared"), "{panel}");
        assert!(!panel.contains("shell.exec"), "{panel}");
        assert!(preview.contains("Command Preview"), "{preview}");
        assert!(preview.contains("risk=read-only"), "{preview}");
        assert!(
            preview.contains("read-only signing evidence projection"),
            "{preview}"
        );
        assert!(
            preview.contains("no signing, key handling, or production promotion"),
            "{preview}"
        );
    }

    #[test]
    fn tui_rollout_ring_projection_is_preview_only() {
        let root = temp_release_fixture_root("rollout-ring-ready");
        write_rollout_ring_artifacts(&root, true);

        let panel = RolloutRingPanel::collect_from_artifact_root(&root).render();

        assert!(panel.contains("TUI Rollout Rings"), "{panel}");
        assert!(
            panel.contains("schema=agentos.tui-rollout-ring-panel.v1"),
            "{panel}"
        );
        assert!(panel.contains("read_only=true"), "{panel}");
        assert!(panel.contains("projection_controller_only=true"), "{panel}");
        assert!(panel.contains("preview_only=true"), "{panel}");
        assert!(panel.contains("fleet_manager=false"), "{panel}");
        assert!(panel.contains("remote_rollout_authority=false"), "{panel}");
        assert!(panel.contains("direct_rollout=false"), "{panel}");
        assert!(panel.contains("remote_command_dispatch=false"), "{panel}");
        assert!(panel.contains("local_agentcore_required=true"), "{panel}");
        assert!(
            panel.contains("security_execution_required=true"),
            "{panel}"
        );
        assert!(panel.contains("production_ready_claim=false"), "{panel}");
        assert!(panel.contains("local_proof_ready=true"), "{panel}");
        assert!(panel.contains("ring_count=4"), "{panel}");
        assert!(panel.contains("total_nodes=1"), "{panel}");
        assert!(
            panel.contains("rollout_sources")
                && panel.contains("release_provenance_present=true")
                && panel.contains("tui_replay_status=passed")
                && panel.contains("production_runbook_status=passed")
                && panel.contains("ecosystem_replay_status=passed")
                && panel.contains("production_signature_verification_status=blocked"),
            "{panel}"
        );
        assert!(
            panel.contains("rollout_execution_in_tui=false")
                && panel.contains("remote_rollout_execution_in_tui=false")
                && panel.contains("rollout_mutation_in_tui=false")
                && panel.contains("remote_operator_bypass=false")
                && panel.contains("production_promotion_in_tui=false")
                && panel.contains("rollback_execution_in_tui=false")
                && panel.contains("fixture_projection_only=true"),
            "{panel}"
        );
        assert!(
            panel.contains("rollout_ring name=local")
                && panel.contains("status=local-proof-ready")
                && panel.contains("gate_status=passed")
                && panel.contains("rollback_readiness=local-rollback-evidence-present"),
            "{panel}"
        );
        for ring in ["canary", "staging", "production"] {
            assert!(
                panel.contains(&format!("rollout_ring name={ring}"))
                    && panel.contains("status=preview-blocked"),
                "{panel}"
            );
        }
        for blocker in [
            "remote-fleet-authority-not-implemented",
            "multi-node-health-gate-missing",
            "multi-node-rollback-drill-missing",
            "production-rollout-authority-not-implemented",
            "production-signatures-not-verified",
            "production-signature-blockers-present",
        ] {
            assert!(panel.contains(blocker), "{panel}");
        }
        assert!(panel.contains("rollback_readiness=requires-ring-health-and-rollback-drill"));
        assert!(panel.contains("remote_execution_allowed=false"), "{panel}");
        assert!(panel.contains("command_enabled=false"), "{panel}");
        assert!(!panel.contains("EffectPrepared"), "{panel}");
        assert!(!panel.contains("shell.exec"), "{panel}");
    }

    #[test]
    fn tui_rollout_ring_missing_local_evidence_blocks_local_ring() {
        let root = temp_release_fixture_root("rollout-ring-missing-local-evidence");
        write_rollout_ring_artifacts(&root, false);

        let panel = RolloutRingPanel::collect_from_artifact_root(&root).render();

        assert!(panel.contains("TUI Rollout Rings"), "{panel}");
        assert!(panel.contains("local_proof_ready=false"), "{panel}");
        assert!(
            panel.contains("rollout_ring name=local")
                && panel.contains("status=blocked")
                && panel.contains("gate_status=blocked")
                && panel.contains("blockers=\"local-proof-gates-not-passed\""),
            "{panel}"
        );
        assert!(panel.contains("ecosystem_replay_status=missing"), "{panel}");
        assert!(
            panel.contains("rollout_blocker id=\"local-proof-gates-not-passed\""),
            "{panel}"
        );
        assert!(
            panel.contains(
                "single-node local proof gates must pass before fleet preview can advance"
            ),
            "{panel}"
        );
        assert!(panel.contains("remote_execution_allowed=false"), "{panel}");
        assert!(panel.contains("command_enabled=false"), "{panel}");
    }

    #[test]
    fn tui_rollout_ring_command_and_palette_are_read_only() {
        let agentd = started_agentd();
        let controller =
            TuiRuntimeController::new(temp_tui_paths("rollout-ring-command")).expect("controller");
        let run_store = controller.paths().run_store_root.clone();

        assert!(matches!(
            TuiCommand::parse("rollout.rings.show"),
            Ok(TuiCommand::RolloutRingsShow)
        ));
        assert!(matches!(
            TuiCommand::parse("fleet.rollout.show"),
            Ok(TuiCommand::RolloutRingsShow)
        ));

        let before_has_snapshot = has_snapshot(&run_store);
        let panel = controller.dispatch_line(&agentd, "rollout.rings.show").text;
        let after_has_snapshot = has_snapshot(&run_store);
        let preview = controller
            .dispatch_line(&agentd, "palette.preview rollout.rings.show")
            .text;

        assert!(!before_has_snapshot);
        assert!(!after_has_snapshot);
        assert!(panel.contains("TUI Rollout Rings"), "{panel}");
        assert!(panel.contains("read_only=true"), "{panel}");
        assert!(panel.contains("preview_only=true"), "{panel}");
        assert!(panel.contains("remote_rollout_authority=false"), "{panel}");
        assert!(panel.contains("direct_rollout=false"), "{panel}");
        assert!(panel.contains("remote_command_dispatch=false"), "{panel}");
        assert!(panel.contains("rollback_execution_in_tui=false"), "{panel}");
        assert!(!panel.contains("EffectPrepared"), "{panel}");
        assert!(!panel.contains("shell.exec"), "{panel}");
        assert!(preview.contains("Command Preview"), "{preview}");
        assert!(preview.contains("risk=read-only"), "{preview}");
        assert!(
            preview.contains("read-only rollout ring projection"),
            "{preview}"
        );
        assert!(
            preview.contains("no remote rollout execution, fleet mutation, or rollback execution"),
            "{preview}"
        );
    }

    #[test]
    fn tui_adversarial_rejects_shell_activation_and_secret_fixtures() {
        for line in [
            "sh -c id",
            "powershell -NoProfile id",
            "dashboard.show | sh",
            "run.approve latest restart-service actor=operator; id",
            "intent.submit recover nginx $(id)",
            "intent.submit recover nginx `id`",
            "intent.submit recover nginx token=abc123",
            "launch.preview service.recovery service=nginx;id",
            "launch.preview service.recovery cmd=powershell",
            "launch.preview service.recovery token=abc123",
            "capability.launch.preview package.install command=cmd",
            "aom.stage agentos:workflow-pack/agentos/service-recovery@1.0.0 && aom.activate.preview agentos:workflow-pack/agentos/service-recovery@1.0.0",
            "shell.exec cmd=id",
        ] {
            assert!(
                TuiCommand::parse(line).is_err(),
                "{line} should fail closed"
            );
        }

        let agentd = started_agentd();
        let controller =
            TuiRuntimeController::new(temp_tui_paths("adversarial")).expect("controller");
        controller.dispatch_line(&agentd, "intent.submit recover nginx service");
        for _ in 0..8 {
            let output = controller.dispatch_line(&agentd, "run.advance latest").text;
            if output.contains("state=AwaitingApproval") {
                break;
            }
        }
        let mutated = controller
            .dispatch_line(&agentd, "run.approve latest other-step actor=operator")
            .text;
        assert!(mutated.contains("TUI Error"), "{mutated}");
        assert!(
            !controller
                .journal()
                .run_timeline(
                    &controller
                        .journal()
                        .latest_run()
                        .expect("latest")
                        .expect("run")
                )
                .expect("timeline")
                .iter()
                .any(|line| line.contains("\"event_type\":\"EffectPrepared\"")
                    && line.contains("\"step_id\":\"restart-service\""))
        );
    }

    #[test]
    fn scripted_lines_render_durable_projection_and_fail_closed_errors() {
        let agentd = started_agentd();
        let controller = TuiRuntimeController::new(temp_tui_paths("scripted")).expect("controller");
        let lines = [
            "dashboard.show",
            "intent.submit recover nginx service",
            "run.show latest",
            "approvals.show latest",
            "recovery.show latest",
            "audit.show latest",
            "support.bundle status",
            "dashboard.show | sh",
        ]
        .into_iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();

        let output = run_scripted_lines(&agentd, &controller, &lines);
        assert!(output.contains("TUI Dashboard"));
        assert!(output.contains("mode=durable projection_controller=true"));
        assert!(output.contains("TUI Run"));
        assert!(output.contains("TUI Approvals"));
        assert!(output.contains("TUI Recovery"));
        assert!(output.contains("TUI Audit"));
        assert!(output.contains("TUI Support Bundle"));
        assert!(output.contains("TUI Support Console"));
        assert!(output.contains("TUI Error\nkind=parse"));
        assert!(!output.contains("Plan Preview"));
    }
}
