use std::path::PathBuf;

use crate::agent_core::ecosystem::{
    ActivationPlanningRequest, ArtifactStagingStore, EcosystemActivationPlanner, EcosystemResolver,
    EcosystemResolverConfig, LocalArtifactRecord, LocalRegistrySnapshot,
};
use crate::api::escape_json;
use crate::runtime_contracts::{ArtifactCoordinate, stable_contract_hash};

pub const AOM_OUTPUT_SCHEMA_VERSION: &str = "agentos.aom-local-lifecycle.v1";
pub const AOM_EXPLAIN_SCHEMA_VERSION: &str = "agentos.aom-artifact-explain.v1";
pub const DEFAULT_LOCAL_REGISTRY_PATH: &str =
    "packaging/agentos/rootfs/etc/agentos/ecosystem/registry-snapshot.json";
pub const DEFAULT_STAGING_ROOT: &str = ".workflow/artifacts/aom/staged";

pub fn run_aom(args: &[String]) -> Result<String, String> {
    let command = args.first().map(String::as_str).unwrap_or("search");
    match command {
        "search" => {
            let registry_path = registry_path(args, 1);
            let snapshot =
                LocalRegistrySnapshot::from_file(&registry_path).map_err(|error| error.reason())?;
            Ok(search_json(&registry_path, &snapshot))
        }
        "show" => {
            let coordinate = coordinate_arg(args, 1)?;
            let registry_path = registry_path(args, 2);
            let snapshot =
                LocalRegistrySnapshot::from_file(&registry_path).map_err(|error| error.reason())?;
            let artifact = artifact(&snapshot, &coordinate)?;
            Ok(show_json(&registry_path, &snapshot, artifact))
        }
        "verify" => {
            let coordinate = coordinate_arg(args, 1)?;
            let registry_path = registry_path(args, 2);
            let snapshot =
                LocalRegistrySnapshot::from_file(&registry_path).map_err(|error| error.reason())?;
            let resolution = resolver()
                .map_err(|error| error.reason())?
                .resolve(&snapshot, vec![coordinate])
                .map_err(|error| error.reason())?;
            Ok(format!(
                "{{\"schema\":\"{}\",\"command\":\"verify\",\"registry_path\":\"{}\",\"registry_snapshot_digest\":\"{}\",\"local_only\":true,\"network_required\":{},\"lock_hash\":\"{}\",\"resolution\":{}}}",
                AOM_OUTPUT_SCHEMA_VERSION,
                escape_json(&registry_path),
                escape_json(&snapshot.snapshot_digest),
                resolution.network_required,
                escape_json(&resolution.lock.stable_hash()),
                resolution.to_json()
            ))
        }
        "stage" => {
            let coordinate = coordinate_arg(args, 1)?;
            let registry_path = registry_path(args, 2);
            let staging_root = args
                .get(3)
                .cloned()
                .unwrap_or_else(|| DEFAULT_STAGING_ROOT.to_string());
            let snapshot =
                LocalRegistrySnapshot::from_file(&registry_path).map_err(|error| error.reason())?;
            let resolution = resolver()
                .map_err(|error| error.reason())?
                .resolve(&snapshot, vec![coordinate])
                .map_err(|error| error.reason())?;
            let staged = ArtifactStagingStore::new(PathBuf::from(&staging_root))
                .stage_resolution(&snapshot, &resolution)
                .map_err(|error| error.reason())?;
            let staged_json = staged
                .iter()
                .map(|artifact| artifact.to_json())
                .collect::<Vec<_>>()
                .join(",");
            Ok(format!(
                "{{\"schema\":\"{}\",\"command\":\"stage\",\"registry_path\":\"{}\",\"staging_root\":\"{}\",\"staged_count\":{},\"staged_only\":true,\"active\":false,\"activation_prepared\":false,\"lock_hash\":\"{}\",\"artifacts\":[{}]}}",
                AOM_OUTPUT_SCHEMA_VERSION,
                escape_json(&registry_path),
                escape_json(&staging_root),
                staged.len(),
                escape_json(&resolution.lock.stable_hash()),
                staged_json
            ))
        }
        "explain" => {
            let coordinate = coordinate_arg(args, 1)?;
            let registry_path = registry_path(args, 2);
            let snapshot =
                LocalRegistrySnapshot::from_file(&registry_path).map_err(|error| error.reason())?;
            let artifact = artifact(&snapshot, &coordinate)?;
            Ok(explain_json(&registry_path, &snapshot, artifact))
        }
        "activate" => {
            let coordinate = coordinate_arg(args, 1)?;
            let registry_path = registry_path(args, 2);
            let staging_root = args
                .get(3)
                .cloned()
                .unwrap_or_else(|| DEFAULT_STAGING_ROOT.to_string());
            let snapshot =
                LocalRegistrySnapshot::from_file(&registry_path).map_err(|error| error.reason())?;
            let resolution = resolver()
                .map_err(|error| error.reason())?
                .resolve(&snapshot, vec![coordinate])
                .map_err(|error| error.reason())?;
            let staged = ArtifactStagingStore::new(PathBuf::from(&staging_root))
                .stage_resolution(&snapshot, &resolution)
                .map_err(|error| error.reason())?;
            let request = ActivationPlanningRequest::new(
                "operator",
                staged,
                stable_contract_hash("aom-local-replay-v1"),
                stable_contract_hash("aom-local-compatibility-v1"),
            )
            .map_err(|error| error.reason())?;
            let preview = EcosystemActivationPlanner
                .plan(&request)
                .map_err(|error| error.reason())?;
            Ok(format!(
                "{{\"schema\":\"{}\",\"command\":\"activate\",\"registry_path\":\"{}\",\"staging_root\":\"{}\",\"status\":\"{}\",\"active\":false,\"activation_prepared\":false,\"planner_can_execute_directly\":false,\"security_execution_required\":true,\"approval_required\":{},\"rollback_required\":{},\"lock_hash\":\"{}\",\"plan_spec\":{},\"activation_plan_preview\":{}}}",
                AOM_OUTPUT_SCHEMA_VERSION,
                escape_json(&registry_path),
                escape_json(&staging_root),
                escape_json(&preview.status),
                preview.approval_required,
                preview.rollback_required,
                escape_json(&resolution.lock.stable_hash()),
                preview.plan.to_json(),
                preview.to_json()
            ))
        }
        other => Err(format!("unknown aom command: {other}")),
    }
}

pub fn explain_json(
    registry_path: &str,
    snapshot: &LocalRegistrySnapshot,
    artifact: &LocalArtifactRecord,
) -> String {
    let dependencies = artifact
        .dependencies
        .iter()
        .map(ArtifactCoordinate::as_string)
        .collect::<Vec<_>>();
    let capabilities = artifact_capabilities(artifact);
    let blocked = vec![
        "AgentCore PlanSpec activation planning",
        "SecurityExecutionEngine side-effect execution",
        "exact approval token for activation",
        "rollback handle for active set",
        "ecosystem replay gate",
    ]
    .into_iter()
    .map(ToString::to_string)
    .collect::<Vec<_>>();
    format!(
        "{{\"schema\":\"{}\",\"registry_path\":\"{}\",\"registry_snapshot_digest\":\"{}\",\"coordinate\":\"{}\",\"artifact_kind\":\"{}\",\"trust_tier\":\"{}\",\"publisher\":\"{}\",\"source_uri\":\"{}\",\"lifecycle_state\":\"registry-only\",\"staged\":false,\"active\":false,\"activation_prepared\":false,\"revoked\":{},\"advisory_refs\":{},\"dependencies\":{},\"capabilities\":{},\"risk\":\"activation-gated\",\"activation_requirements\":[\"AgentCore PlanSpec\",\"SecurityExecutionEngine\",\"audit\",\"rollback\",\"exact approval\"],\"blocked_prerequisites\":{},\"replay_status\":\"required-before-activation\",\"secret_policy\":\"handle-only; raw secret-like content is forbidden\",\"explanation_hash\":\"{}\"}}",
        AOM_EXPLAIN_SCHEMA_VERSION,
        escape_json(registry_path),
        escape_json(&snapshot.snapshot_digest),
        escape_json(&artifact.coordinate.as_string()),
        artifact.coordinate.kind.as_str(),
        artifact.trust_tier.as_str(),
        escape_json(&artifact.coordinate.publisher),
        escape_json(&artifact.source_uri),
        artifact.revoked,
        string_array_json(&artifact.advisory_refs),
        string_array_json(&dependencies),
        string_array_json(&capabilities),
        string_array_json(&blocked),
        escape_json(&stable_contract_hash(&artifact.to_json()))
    )
}

fn search_json(registry_path: &str, snapshot: &LocalRegistrySnapshot) -> String {
    let mut artifacts = snapshot
        .artifacts
        .iter()
        .map(|artifact| {
            format!(
                "{{\"coordinate\":\"{}\",\"artifact_kind\":\"{}\",\"trust_tier\":\"{}\",\"revoked\":{},\"source_uri\":\"{}\"}}",
                escape_json(&artifact.coordinate.as_string()),
                artifact.coordinate.kind.as_str(),
                artifact.trust_tier.as_str(),
                artifact.revoked,
                escape_json(&artifact.source_uri)
            )
        })
        .collect::<Vec<_>>();
    artifacts.sort();
    format!(
        "{{\"schema\":\"{}\",\"command\":\"search\",\"registry_path\":\"{}\",\"registry_snapshot_digest\":\"{}\",\"local_only\":true,\"artifact_count\":{},\"artifacts\":[{}]}}",
        AOM_OUTPUT_SCHEMA_VERSION,
        escape_json(registry_path),
        escape_json(&snapshot.snapshot_digest),
        snapshot.artifacts.len(),
        artifacts.join(",")
    )
}

fn show_json(
    registry_path: &str,
    snapshot: &LocalRegistrySnapshot,
    artifact: &LocalArtifactRecord,
) -> String {
    format!(
        "{{\"schema\":\"{}\",\"command\":\"show\",\"registry_path\":\"{}\",\"registry_snapshot_digest\":\"{}\",\"staged\":false,\"active\":false,\"artifact\":{}}}",
        AOM_OUTPUT_SCHEMA_VERSION,
        escape_json(registry_path),
        escape_json(&snapshot.snapshot_digest),
        artifact.to_json()
    )
}

fn resolver() -> Result<EcosystemResolver, crate::agent_core::ecosystem::EcosystemResolverError> {
    EcosystemResolver::new(EcosystemResolverConfig::local_only(
        "0.1.0",
        "x86_64",
        vec!["audit-journal", "rollback-store"],
        "2026-05-25T00:00:00Z",
    )?)
}

fn coordinate_arg(args: &[String], index: usize) -> Result<ArtifactCoordinate, String> {
    let value = args
        .get(index)
        .ok_or_else(|| "missing artifact coordinate".to_string())?;
    ArtifactCoordinate::parse(value).map_err(|error| error.reason())
}

fn registry_path(args: &[String], index: usize) -> String {
    args.get(index)
        .cloned()
        .unwrap_or_else(|| DEFAULT_LOCAL_REGISTRY_PATH.to_string())
}

fn artifact<'a>(
    snapshot: &'a LocalRegistrySnapshot,
    coordinate: &ArtifactCoordinate,
) -> Result<&'a LocalArtifactRecord, String> {
    snapshot.artifact(coordinate).ok_or_else(|| {
        format!(
            "artifact is missing from local registry: {}",
            coordinate.as_string()
        )
    })
}

fn artifact_capabilities(artifact: &LocalArtifactRecord) -> Vec<String> {
    let mut capabilities = match artifact.coordinate.kind.as_str() {
        "policy-pack" => vec![
            "policy rules",
            "approval constraints",
            "core safety invariants",
        ],
        "workflow-pack" => vec![
            "operator workflow",
            "runbook steps",
            "audit-visible plan inputs",
        ],
        "test-replay-pack" => vec![
            "release replay fixture",
            "regression gate input",
            "provenance evidence",
        ],
        _ => vec!["ecosystem artifact"],
    }
    .into_iter()
    .map(ToString::to_string)
    .collect::<Vec<_>>();
    capabilities.sort();
    capabilities
}

fn string_array_json(values: &[String]) -> String {
    let mut values = values.to_vec();
    values.sort();
    format!(
        "[{}]",
        values
            .iter()
            .map(|value| format!("\"{}\"", escape_json(value)))
            .collect::<Vec<_>>()
            .join(",")
    )
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static AOM_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn coord(name: &str) -> String {
        format!("agentos:workflow-pack/agentos/{name}@1.0.0")
    }

    fn fixture_json() -> String {
        format!(
            "{{\"schema\":\"agentos.local-registry-snapshot.v1\",\"snapshot_id\":\"agentos-local-alpha\",\"generated_at\":\"2026-05-25T01:00:00Z\",\"expires_at\":\"2026-06-01T00:00:00Z\",\"local_pinned\":true,\"snapshot_digest\":\"sha256:local-snapshot\",\"artifacts\":[{{\"coordinate\":\"{}\",\"manifest_digest\":\"sha256:manifest-base\",\"artifact_digest\":\"sha256:artifact-base\",\"declared_artifact_digest\":\"sha256:artifact-base\",\"trust_tier\":\"core\",\"source_uri\":\"file:///etc/agentos/ecosystem/artifacts/base-workflow.json\",\"revoked\":false,\"min_runtime_contract_version\":\"0.1.0\",\"max_runtime_contract_version\":\"0.9.0\",\"architectures\":[\"x86_64\"],\"required_host_features\":[\"audit-journal\"],\"optional_host_features\":[],\"dependencies\":[],\"advisory_refs\":[]}},{{\"coordinate\":\"{}\",\"manifest_digest\":\"sha256:manifest-setup\",\"artifact_digest\":\"sha256:artifact-setup\",\"declared_artifact_digest\":\"sha256:artifact-setup\",\"trust_tier\":\"core\",\"source_uri\":\"file:///etc/agentos/ecosystem/artifacts/setup-workflow.json\",\"revoked\":false,\"min_runtime_contract_version\":\"0.1.0\",\"max_runtime_contract_version\":\"0.9.0\",\"architectures\":[\"x86_64\"],\"required_host_features\":[\"audit-journal\"],\"optional_host_features\":[\"kvm\"],\"dependencies\":[\"{}\"],\"advisory_refs\":[]}}]}}",
            coord("base"),
            coord("setup"),
            coord("base")
        )
    }

    fn fixture_path(name: &str) -> std::path::PathBuf {
        let counter = AOM_COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "agentd-aom-{name}-{counter}-{}.json",
            std::process::id()
        ));
        fs::write(&path, fixture_json()).expect("write fixture");
        path
    }

    #[test]
    fn aom_search_show_verify_and_explain_are_local_only() {
        let path = fixture_path("local");
        let path_arg = path.to_string_lossy().to_string();
        let coordinate = coord("setup");

        let search = run_aom(&["search".to_string(), path_arg.clone()]).expect("search");
        assert!(search.contains("\"local_only\":true"));
        assert!(search.contains(&coordinate));
        assert!(!search.contains("shell.exec"));

        let show =
            run_aom(&["show".to_string(), coordinate.clone(), path_arg.clone()]).expect("show");
        assert!(show.contains("\"staged\":false"));
        assert!(show.contains("\"active\":false"));

        let verify =
            run_aom(&["verify".to_string(), coordinate.clone(), path_arg.clone()]).expect("verify");
        assert!(verify.contains("\"network_required\":false"));
        assert!(verify.contains("\"lock_hash\":\"sha256:agentos-stable-v1-"));

        let explain = run_aom(&["explain".to_string(), coordinate, path_arg]).expect("explain");
        assert!(explain.contains(AOM_EXPLAIN_SCHEMA_VERSION));
        assert!(explain.contains("\"risk\":\"activation-gated\""));
        assert!(explain.contains("\"staged\":false"));
        assert!(explain.contains("\"active\":false"));
        assert!(!explain.contains("password="));
    }

    #[test]
    fn aom_stage_is_inert_and_activate_yields_plan_preview() {
        let path = fixture_path("stage");
        let path_arg = path.to_string_lossy().to_string();
        let stage_root =
            std::env::temp_dir().join(format!("agentd-aom-stage-{}", std::process::id()));
        let _ = fs::remove_dir_all(&stage_root);
        let stage_root_arg = stage_root.to_string_lossy().to_string();

        let output = run_aom(&[
            "stage".to_string(),
            coord("setup"),
            path_arg.clone(),
            stage_root_arg.clone(),
        ])
        .expect("stage");
        assert!(output.contains("\"staged_only\":true"));
        assert!(output.contains("\"active\":false"));
        assert!(output.contains("\"activation_prepared\":false"));
        assert!(!stage_root.join("active").exists());

        let activate = run_aom(&[
            "activate".to_string(),
            coord("setup"),
            path_arg,
            stage_root_arg,
        ])
        .expect("activate");
        assert!(activate.contains("\"command\":\"activate\""));
        assert!(activate.contains("\"status\":\"awaiting-operator-approval\""));
        assert!(activate.contains("\"plan_spec\":"));
        assert!(activate.contains("\"activation_plan_preview\":"));
        assert!(activate.contains("\"ecosystem.activate\""));
        assert!(activate.contains("\"planner_can_execute_directly\":false"));
        assert!(activate.contains("\"active\":false"));
        assert!(activate.contains("\"activation_prepared\":false"));
        assert!(activate.contains("\"approval_required\":true"));
        assert!(activate.contains("\"rollback_required\":true"));
        assert!(!stage_root.join("active").exists());
    }
}
