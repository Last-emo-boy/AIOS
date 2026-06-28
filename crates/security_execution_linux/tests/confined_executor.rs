//! 完整受限执行器集成测试（ADR-004 cp5）。
//!
//! 验证 namespace + Landlock + seccomp 的**完整栈**协同施加，且内核在每个向量上
//! 真实强制。helper 内部按 cp5 正确顺序施加（user ns→maps→其他 ns→/proc→nnp→
//! landlock→seccomp last→fork 进 pidns），子进程 SIGSYS 经 reraise 上浮。
#![cfg(target_os = "linux")]

use runtime_contracts::RiskClass;
use security_execution::policy::CapabilityLease;
use security_execution::sandbox::{SandboxCompiler, SandboxProfile};
use security_execution_linux::{EnforcementOutcome, LinuxEnforcer};

fn helper() -> &'static str {
    env!("CARGO_BIN_EXE_sandbox_probe")
}

fn landlock_in_lsm() -> bool {
    std::fs::read_to_string("/sys/kernel/security/lsm")
        .map(|s| s.split(',').any(|x| x.trim() == "landlock"))
        .unwrap_or(false)
}

fn read_only_profile() -> SandboxProfile {
    let lease = CapabilityLease {
        lease_id: "lease-test".into(),
        actor: "operator".into(),
        tool: "svc.status".into(),
        resource: "agentd".into(),
        parameter_hash: "h".into(),
        expires_at: 60,
        policy_version: "policy-v1".into(),
        risk: RiskClass::ReadOnly,
    };
    SandboxCompiler.compile(&lease).expect("read-only profile compiles")
}

/// seccomp 在**完整 namespace 栈**（user+mount+pid+net）下仍被内核强制：
/// 用冻结 profile 的 allowlist（不含 getpid）施加，getpid → 内核 SIGSYS。
#[test]
fn seccomp_enforced_through_full_namespace_stack() {
    let p = read_only_profile();
    let enf = LinuxEnforcer::new();
    let csv = enf.compile_seccomp_allow_csv(&p).expect("resolve allowlist");
    match enf
        .enforce_confined(helper(), "user,mount,pid,net", &csv, "", "getpid", "")
        .expect("spawn confined helper")
    {
        EnforcementOutcome::KernelDenied { .. } => {} // 内核穿透 ns 栈强制
        EnforcementOutcome::Confined => {
            panic!("seccomp must stay enforced through the full namespace stack")
        }
    }
}

/// pidns 身份：受限子进程在它自己的新 PID namespace 里是 PID 1（内核真隔离）。
#[test]
fn pidns_identity_in_confined_child() {
    match LinuxEnforcer::new()
        .enforce_confined(helper(), "user,pid", "", "", "fork", "")
        .expect("spawn confined helper")
    {
        EnforcementOutcome::Confined => {} // exit 0 = child getpid()==1
        EnforcementOutcome::KernelDenied { reason } => {
            panic!("pidns identity probe should be confined, got denial: {reason}")
        }
    }
}

/// Landlock 在 namespace 栈下仍以 EACCES 拒绝越界读（带 baseline，排除 DAC）。
#[test]
fn landlock_enforced_through_namespace_stack_with_baseline() {
    if !landlock_in_lsm() {
        eprintln!("SKIP: landlock not in active LSM (genuinely unavailable)");
        return;
    }
    let enf = LinuxEnforcer::new();
    let forbidden = "/etc/hostname";

    // baseline：同 uid 无沙箱必须能读（否则 EACCES 来自 DAC 而非 Landlock）。
    assert!(
        enf.baseline_can_read(helper(), forbidden).expect("spawn helper"),
        "baseline read of {forbidden} must succeed"
    );

    let dir = std::env::temp_dir().join(format!("aios_conf_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let dir_s = dir.to_str().unwrap();

    let r = enf.enforce_confined(helper(), "user,mount,pid", "", dir_s, "open", forbidden);
    std::fs::remove_dir_all(&dir).ok();

    match r.expect("landlock must be fully enforced (fail-closed)") {
        EnforcementOutcome::KernelDenied { .. } => {} // EACCES 穿透 ns 栈
        EnforcementOutcome::Confined => {
            panic!("landlock must deny out-of-scope read through the namespace stack")
        }
    }
}
