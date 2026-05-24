use std::io;

use runtime_contracts::SupportBundleManifest;

use crate::audit::AuditJournal;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportBundleProjection {
    pub manifest: SupportBundleManifest,
    pub audit_excerpt_count: usize,
    pub deterministic: bool,
}

impl SupportBundleProjection {
    pub fn from_journal(
        journal: &AuditJournal,
        bundle_id: impl Into<String>,
        run_ids: Vec<impl Into<String>>,
    ) -> io::Result<Self> {
        let run_ids = run_ids.into_iter().map(Into::into).collect::<Vec<_>>();
        let lines = journal.event_lines()?;
        let first = if lines.is_empty() { 0 } else { 1 };
        let last = lines.len();
        let manifest = SupportBundleManifest::new(
            bundle_id,
            run_ids,
            format!("{first}..{last}"),
            audit_hash_chain(&lines),
            "secret-values-redacted",
            false,
        )
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.reason()))?;
        Ok(Self {
            manifest,
            audit_excerpt_count: lines.len(),
            deterministic: true,
        })
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"manifest\":{},\"audit_excerpt_count\":{},\"deterministic\":{}}}",
            self.manifest.to_json(),
            self.audit_excerpt_count,
            self.deterministic
        )
    }
}

fn audit_hash_chain(lines: &[String]) -> String {
    let mut state: u64 = 0xcbf29ce484222325;
    for line in lines {
        for byte in line.as_bytes() {
            state ^= *byte as u64;
            state = state.wrapping_mul(0x100000001b3);
        }
    }
    format!("fnv64:{state:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditEvent, AuditEventType};

    #[test]
    fn support_bundle_manifest_links_runs_and_redacts() {
        let path = std::env::temp_dir().join(format!(
            "agentd-support-bundle-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let journal = AuditJournal::new(path);
        journal
            .append(&AuditEvent::new(
                AuditEventType::PolicyEvaluated,
                "run-support",
                "step-read",
                "operator",
                "decision=allow token=abc123 secret://handle",
            ))
            .expect("append");

        let projection =
            SupportBundleProjection::from_journal(&journal, "bundle-run-support", vec!["run-support"])
                .expect("projection");

        assert_eq!(projection.audit_excerpt_count, 1);
        assert!(projection.deterministic);
        let json = projection.to_json();
        assert!(json.contains("agentos.support-bundle-manifest.v1"));
        assert!(json.contains("\"redaction_status\":\"secret-values-redacted\""));
        assert!(json.contains("\"includes_raw_secret\":false"));
        assert!(json.contains("run-support"));
    }
}
