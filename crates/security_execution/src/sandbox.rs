use crate::escape_json;
    use runtime_contracts::RiskClass;
use crate::audit::{AuditEvent, AuditEventType, AuditJournal};
use crate::policy::CapabilityLease;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxError {
    EmptyResource,
    UnsupportedRisk(RiskClass),
}

impl SandboxError {
    pub fn reason(&self) -> String {
        match self {
            SandboxError::EmptyResource => "sandbox profile requires a bounded resource".to_string(),
            SandboxError::UnsupportedRisk(risk) => {
                format!("sandbox profile does not support {} leases", risk.as_str())
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileAccess {
    ReadOnly,
    ReadWrite,
}

impl FileAccess {
    pub fn as_str(self) -> &'static str {
        match self {
            FileAccess::ReadOnly => "read-only",
            FileAccess::ReadWrite => "read-write",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountBind {
    pub source: String,
    pub target: String,
    pub access: FileAccess,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceSet {
    pub user: bool,
    pub mount: bool,
    pub pid: bool,
    pub network: bool,
    pub cgroup: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupLimits {
    pub cpu_quota_us: u64,
    pub cpu_period_us: u64,
    pub memory_max_bytes: u64,
    pub io_weight: u16,
    pub pids_max: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeccompProfile {
    pub default_action: &'static str,
    pub allowed_syscalls: Vec<&'static str>,
    pub denied_syscalls: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemPolicy {
    pub read_only_binds: Vec<MountBind>,
    pub writable_tmpfs: Vec<String>,
    pub persistent_write_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LandlockPolicy {
    pub enabled_when_supported: bool,
    pub allowed_read_paths: Vec<String>,
    pub allowed_write_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPolicy {
    pub allow_network: bool,
    pub allowlist: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxProfile {
    pub name: String,
    pub lease_id: String,
    pub tool: String,
    pub resource: String,
    pub parameter_hash: String,
    pub policy_version: String,
    pub risk: RiskClass,
    pub no_new_privs: bool,
    pub namespaces: NamespaceSet,
    pub cgroup: CgroupLimits,
    pub seccomp: SeccompProfile,
    pub filesystem: FilesystemPolicy,
    pub landlock: LandlockPolicy,
    pub network: NetworkPolicy,
}

impl SandboxProfile {
    pub fn to_json(&self) -> String {
        let binds = self
            .filesystem
            .read_only_binds
            .iter()
            .map(|bind| {
                format!(
                    "{{\"source\":\"{}\",\"target\":\"{}\",\"access\":\"{}\"}}",
                    escape_json(&bind.source),
                    escape_json(&bind.target),
                    bind.access.as_str()
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let writable_tmpfs = string_array_json(&self.filesystem.writable_tmpfs);
        let allowed_syscalls = static_string_array_json(&self.seccomp.allowed_syscalls);
        let denied_syscalls = static_string_array_json(&self.seccomp.denied_syscalls);
        let landlock_read_paths = string_array_json(&self.landlock.allowed_read_paths);
        let landlock_write_paths = string_array_json(&self.landlock.allowed_write_paths);
        let network_allowlist = string_array_json(&self.network.allowlist);
        format!(
            "{{\"name\":\"{}\",\"lease_id\":\"{}\",\"tool\":\"{}\",\"resource\":\"{}\",\"parameter_hash\":\"{}\",\"policy_version\":\"{}\",\"risk\":\"{}\",\"no_new_privs\":{},\"namespaces\":{{\"user\":{},\"mount\":{},\"pid\":{},\"network\":{},\"cgroup\":{}}},\"cgroup\":{{\"cpu_quota_us\":{},\"cpu_period_us\":{},\"memory_max_bytes\":{},\"io_weight\":{},\"pids_max\":{}}},\"seccomp\":{{\"default_action\":\"{}\",\"allowed_syscalls\":{},\"denied_syscalls\":{}}},\"filesystem\":{{\"persistent_write_allowed\":{},\"read_only_binds\":[{}],\"writable_tmpfs\":{}}},\"landlock\":{{\"enabled_when_supported\":{},\"allowed_read_paths\":{},\"allowed_write_paths\":{}}},\"network\":{{\"allow_network\":{},\"allowlist\":{}}}}}",
            escape_json(&self.name),
            escape_json(&self.lease_id),
            escape_json(&self.tool),
            escape_json(&self.resource),
            escape_json(&self.parameter_hash),
            escape_json(&self.policy_version),
            self.risk.as_str(),
            self.no_new_privs,
            self.namespaces.user,
            self.namespaces.mount,
            self.namespaces.pid,
            self.namespaces.network,
            self.namespaces.cgroup,
            self.cgroup.cpu_quota_us,
            self.cgroup.cpu_period_us,
            self.cgroup.memory_max_bytes,
            self.cgroup.io_weight,
            self.cgroup.pids_max,
            escape_json(self.seccomp.default_action),
            allowed_syscalls,
            denied_syscalls,
            self.filesystem.persistent_write_allowed,
            binds,
            writable_tmpfs,
            self.landlock.enabled_when_supported,
            landlock_read_paths,
            landlock_write_paths,
            self.network.allow_network,
            network_allowlist
        )
    }
}

fn string_array_json(values: &[String]) -> String {
    let items = values
        .iter()
        .map(|value| format!("\"{}\"", escape_json(value)))
        .collect::<Vec<_>>()
        .join(",");
    format!("[{items}]")
}

fn static_string_array_json(values: &[&'static str]) -> String {
    let items = values
        .iter()
        .map(|value| format!("\"{}\"", escape_json(value)))
        .collect::<Vec<_>>()
        .join(",");
    format!("[{items}]")
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SandboxCompiler;

impl SandboxCompiler {
    pub fn compile(&self, lease: &CapabilityLease) -> Result<SandboxProfile, SandboxError> {
        if lease.resource.trim().is_empty() {
            return Err(SandboxError::EmptyResource);
        }
        match lease.risk {
            RiskClass::ReadOnly => Ok(self.read_only_profile(lease)),
            RiskClass::WriteWithDiff
            | RiskClass::ExecuteWithConfirmation
            | RiskClass::PrivilegedWithHumanApproval
            | RiskClass::Never => Err(SandboxError::UnsupportedRisk(lease.risk)),
        }
    }

    fn read_only_profile(&self, lease: &CapabilityLease) -> SandboxProfile {
        let mut read_paths = vec!["/proc".to_string(), "/run".to_string()];
        if lease.tool == "fs.read" {
            read_paths.push(lease.resource.clone());
        }

        let network = if lease.tool == "http.check" {
            NetworkPolicy {
                allow_network: true,
                allowlist: vec![lease.resource.clone()],
            }
        } else {
            NetworkPolicy {
                allow_network: false,
                allowlist: Vec::new(),
            }
        };

        SandboxProfile {
            name: "read-only-diagnostic-v1".to_string(),
            lease_id: lease.lease_id.clone(),
            tool: lease.tool.clone(),
            resource: lease.resource.clone(),
            parameter_hash: lease.parameter_hash.clone(),
            policy_version: lease.policy_version.clone(),
            risk: lease.risk,
            no_new_privs: true,
            namespaces: NamespaceSet {
                user: true,
                mount: true,
                pid: true,
                network: true,
                cgroup: true,
            },
            cgroup: CgroupLimits {
                cpu_quota_us: 50_000,
                cpu_period_us: 100_000,
                memory_max_bytes: 128 * 1024 * 1024,
                io_weight: 100,
                pids_max: 32,
            },
            seccomp: SeccompProfile {
                default_action: "errno",
                allowed_syscalls: vec![
                    "read",
                    "write",
                    "openat",
                    "close",
                    "newfstatat",
                    "mmap",
                    "munmap",
                    "brk",
                    "clock_gettime",
                    "rt_sigaction",
                    "rt_sigprocmask",
                    "futex",
                    "exit",
                    "exit_group",
                ],
                denied_syscalls: vec![
                    "mount",
                    "umount2",
                    "ptrace",
                    "bpf",
                    "init_module",
                    "finit_module",
                    "delete_module",
                    "reboot",
                    "swapon",
                    "swapoff",
                ],
            },
            filesystem: FilesystemPolicy {
                read_only_binds: read_paths
                    .iter()
                    .map(|path| MountBind {
                        source: path.clone(),
                        target: path.clone(),
                        access: FileAccess::ReadOnly,
                    })
                    .collect(),
                writable_tmpfs: vec!["/tmp/agentd-sandbox".to_string()],
                persistent_write_allowed: false,
            },
            landlock: LandlockPolicy {
                enabled_when_supported: true,
                allowed_read_paths: read_paths,
                allowed_write_paths: vec!["/tmp/agentd-sandbox".to_string()],
            },
            network,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxOperation {
    ReadDiagnostic { label: String },
    WritePersistentPath { path: String },
    SpawnProcesses { count: u32 },
    Syscall { name: String },
    NetworkConnect { target: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxDecision {
    Allowed,
    Denied,
}

impl SandboxDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            SandboxDecision::Allowed => "allowed",
            SandboxDecision::Denied => "denied",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxLogEntry {
    pub event: &'static str,
    pub detail: String,
}

impl SandboxLogEntry {
    fn to_json(&self) -> String {
        format!(
            "{{\"event\":\"{}\",\"detail\":\"{}\"}}",
            self.event,
            escape_json(&self.detail)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxReport {
    pub profile_name: String,
    pub lease_id: String,
    pub tool: String,
    pub parameter_hash: String,
    pub decision: SandboxDecision,
    pub reason: String,
    pub logs: Vec<SandboxLogEntry>,
}

impl SandboxReport {
    pub fn to_json(&self) -> String {
        let logs = self
            .logs
            .iter()
            .map(SandboxLogEntry::to_json)
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"profile_name\":\"{}\",\"lease_id\":\"{}\",\"tool\":\"{}\",\"parameter_hash\":\"{}\",\"decision\":\"{}\",\"reason\":\"{}\",\"logs\":[{}]}}",
            escape_json(&self.profile_name),
            escape_json(&self.lease_id),
            escape_json(&self.tool),
            escape_json(&self.parameter_hash),
            self.decision.as_str(),
            escape_json(&self.reason),
            logs
        )
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SandboxExecutor;

impl SandboxExecutor {
    pub fn evaluate(&self, profile: &SandboxProfile, operation: SandboxOperation) -> SandboxReport {
        match operation {
            SandboxOperation::ReadDiagnostic { label } => {
                self.allow(profile, format!("read-only diagnostic completed: {label}"))
            }
            SandboxOperation::WritePersistentPath { path } => {
                if !profile.filesystem.persistent_write_allowed
                    && !profile.filesystem.writable_tmpfs.iter().any(|tmp| path.starts_with(tmp))
                {
                    self.deny(
                        profile,
                        format!("read-only sandbox denied persistent write to {path}"),
                    )
                } else {
                    self.allow(profile, format!("write constrained to sandbox tmpfs: {path}"))
                }
            }
            SandboxOperation::SpawnProcesses { count } => {
                if count > profile.cgroup.pids_max {
                    self.deny(
                        profile,
                        format!(
                            "pids.max={} denied process fanout count={count}",
                            profile.cgroup.pids_max
                        ),
                    )
                } else {
                    self.allow(
                        profile,
                        format!("process fanout count={count} stayed within pids.max"),
                    )
                }
            }
            SandboxOperation::Syscall { name } => {
                if profile.seccomp.denied_syscalls.iter().any(|syscall| *syscall == name) {
                    self.deny(profile, format!("seccomp denied syscall {name}"))
                } else {
                    self.allow(profile, format!("syscall {name} allowed by profile"))
                }
            }
            SandboxOperation::NetworkConnect { target } => {
                if profile.network.allow_network
                    && profile.network.allowlist.iter().any(|allowed| target.starts_with(allowed))
                {
                    self.allow(profile, format!("network target allowed: {target}"))
                } else {
                    self.deny(profile, format!("network target denied: {target}"))
                }
            }
        }
    }

    pub fn record_report(
        &self,
        journal: &AuditJournal,
        run_id: impl Into<String>,
        step_id: impl Into<String>,
        report: &SandboxReport,
    ) -> std::io::Result<()> {
        if report.decision != SandboxDecision::Denied {
            return Ok(());
        }
        let mut event = AuditEvent::new(
            AuditEventType::SandboxDenied,
            run_id,
            step_id,
            "sandbox",
            format!("{} {}", report.tool, report.reason),
        );
        event.tool_version = "sandbox-v1".to_string();
        event.parameter_hash = report.parameter_hash.clone();
        journal.append(&event)
    }

    fn allow(&self, profile: &SandboxProfile, reason: String) -> SandboxReport {
        SandboxReport {
            profile_name: profile.name.clone(),
            lease_id: profile.lease_id.clone(),
            tool: profile.tool.clone(),
            parameter_hash: profile.parameter_hash.clone(),
            decision: SandboxDecision::Allowed,
            reason,
            logs: Vec::new(),
        }
    }

    fn deny(&self, profile: &SandboxProfile, reason: String) -> SandboxReport {
        SandboxReport {
            profile_name: profile.name.clone(),
            lease_id: profile.lease_id.clone(),
            tool: profile.tool.clone(),
            parameter_hash: profile.parameter_hash.clone(),
            decision: SandboxDecision::Denied,
            logs: vec![SandboxLogEntry {
                event: "SandboxDenied",
                detail: reason.clone(),
            }],
            reason,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease_for(tool: &str, resource: &str, risk: RiskClass) -> CapabilityLease {
        CapabilityLease {
            lease_id: format!("lease-{tool}-hash"),
            actor: "operator".to_string(),
            tool: tool.to_string(),
            resource: resource.to_string(),
            parameter_hash: "hash".to_string(),
            expires_at: 60,
            policy_version: "policy-v1".to_string(),
            risk,
        }
    }

    fn test_journal(name: &str) -> AuditJournal {
        let path = std::env::temp_dir().join(format!(
            "agentd-sandbox-{name}-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        AuditJournal::new(path)
    }

    #[test]
    fn read_only_lease_compiles_profile_from_capability_metadata() {
        let lease = lease_for("fs.read", "/var/log/agentd.log", RiskClass::ReadOnly);
        let profile = SandboxCompiler.compile(&lease).expect("profile");
        assert_eq!(profile.risk, RiskClass::ReadOnly);
        assert_eq!(profile.tool, "fs.read");
        assert_eq!(profile.resource, "/var/log/agentd.log");
        assert_eq!(profile.parameter_hash, "hash");
        assert!(profile.no_new_privs);
        assert!(profile.namespaces.user);
        assert!(profile.namespaces.mount);
        assert!(profile.namespaces.pid);
        assert!(profile.namespaces.cgroup);
        assert!(!profile.filesystem.persistent_write_allowed);
        assert!(profile
            .filesystem
            .read_only_binds
            .iter()
            .any(|bind| bind.source == "/var/log/agentd.log" && bind.access == FileAccess::ReadOnly));
        assert!(profile.landlock.enabled_when_supported);
    }

    #[test]
    fn read_only_profile_denies_persistent_host_writes() {
        let profile = SandboxCompiler
            .compile(&lease_for("fs.read", "/var/log/agentd.log", RiskClass::ReadOnly))
            .expect("profile");
        let report = SandboxExecutor.evaluate(
            &profile,
            SandboxOperation::WritePersistentPath {
                path: "/etc/passwd".to_string(),
            },
        );
        assert_eq!(report.decision, SandboxDecision::Denied);
        assert!(report.reason.contains("persistent write"));
        assert!(report.logs.iter().any(|entry| entry.event == "SandboxDenied"));
    }

    #[test]
    fn fork_bomb_simulation_is_limited_by_pids_and_budget() {
        let profile = SandboxCompiler
            .compile(&lease_for("svc.status", "agentd", RiskClass::ReadOnly))
            .expect("profile");
        assert_eq!(profile.cgroup.pids_max, 32);
        assert_eq!(profile.cgroup.memory_max_bytes, 128 * 1024 * 1024);
        assert_eq!(profile.cgroup.cpu_quota_us, 50_000);
        let report = SandboxExecutor.evaluate(
            &profile,
            SandboxOperation::SpawnProcesses {
                count: profile.cgroup.pids_max + 1,
            },
        );
        assert_eq!(report.decision, SandboxDecision::Denied);
        assert!(report.reason.contains("pids.max"));
    }

    #[test]
    fn denied_syscall_fails_predictably_and_is_logged() {
        let profile = SandboxCompiler
            .compile(&lease_for("svc.status", "agentd", RiskClass::ReadOnly))
            .expect("profile");
        let report = SandboxExecutor.evaluate(
            &profile,
            SandboxOperation::Syscall {
                name: "mount".to_string(),
            },
        );
        assert_eq!(report.decision, SandboxDecision::Denied);
        assert!(report.reason.contains("seccomp denied syscall mount"));
        assert!(report.to_json().contains("SandboxDenied"));

        let journal = test_journal("syscall");
        SandboxExecutor
            .record_report(&journal, "run-sandbox", "step-syscall", &report)
            .expect("record denial");
        let lines = journal.event_lines().expect("read journal");
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("\"event_type\":\"SandboxDenied\""));
        assert!(lines[0].contains("seccomp denied syscall mount"));
        assert!(lines[0].contains("\"parameter_hash\":\"hash\""));
    }

    #[test]
    fn profile_selection_rejects_non_read_only_leases() {
        let error = SandboxCompiler
            .compile(&lease_for(
                "fs.write.diff",
                "/etc/agentd.conf",
                RiskClass::WriteWithDiff,
            ))
            .expect_err("write-with-diff uses rollback flow");
        assert!(error.reason().contains("write-with-diff"));
    }
}
