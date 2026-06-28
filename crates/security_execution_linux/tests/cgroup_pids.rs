//! 真 cgroup v2 pids.max 强制 + 差分 oracle（ADR-004 cp5 / D2）。
//!
//! helper 加入一个预设 `pids.max` 的 cgroup，连续 fork；超额时内核以 EAGAIN 拒绝。
//! 对接冻结 `SandboxExecutor` 的 `SpawnProcesses{count}`（count>pids_max ⇒ Denied），
//! 断言内核与 oracle 在「超额即拒绝」上一致（real ⊇ oracle 拒绝）。
//! 仅当 pids 控制器未在 root cgroup 委派时才 loud-skip（genuinely unavailable）。
#![cfg(target_os = "linux")]

use runtime_contracts::RiskClass;
use security_execution::policy::CapabilityLease;
use security_execution::sandbox::{
    SandboxCompiler, SandboxDecision, SandboxExecutor, SandboxOperation, SandboxProfile,
};
use security_execution_linux::{EnforcementOutcome, LinuxEnforcer};

fn helper() -> &'static str {
    env!("CARGO_BIN_EXE_sandbox_probe")
}

fn pids_delegated() -> bool {
    std::fs::read_to_string("/sys/fs/cgroup/cgroup.subtree_control")
        .map(|s| s.split_whitespace().any(|c| c == "pids"))
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

fn run_in_cgroup(enf: &LinuxEnforcer, max: u32, fork_n: i32) -> std::io::Result<EnforcementOutcome> {
    let cg = format!("/sys/fs/cgroup/aios-pids-{}-{}", std::process::id(), max);
    std::fs::create_dir_all(&cg)?;
    std::fs::write(format!("{cg}/pids.max"), max.to_string())?;
    let r = enf.enforce_cgroup_pids(helper(), &cg, fork_n);
    std::fs::remove_dir(&cg).ok(); // rmdir（helper 退出后 cgroup 应空）
    r
}

#[test]
fn cgroup_pids_max_is_kernel_enforced() {
    if !pids_delegated() {
        eprintln!("SKIP: pids controller not delegated in root cgroup");
        return;
    }
    let enf = LinuxEnforcer::new();
    // pids.max=4：helper 自身占 1，fork 10 → 第 4 个起 EAGAIN（内核拒绝）。
    let denied = run_in_cgroup(&enf, 4, 10).expect("spawn helper");
    // pids.max=4：fork 2（zombie 占额 current≤3）→ 配额内放行。
    let allowed = run_in_cgroup(&enf, 4, 2).expect("spawn helper");

    match denied {
        EnforcementOutcome::KernelDenied { .. } => {}
        EnforcementOutcome::Confined => panic!("fork beyond pids.max must be kernel-denied (EAGAIN)"),
    }
    assert!(
        matches!(allowed, EnforcementOutcome::Confined),
        "fork within pids.max must be allowed"
    );
}

/// 差分：内核 pids.max=profile(32) 下 fork>max 被拒，与冻结 oracle 的
/// SpawnProcesses{count>pids_max}=Denied 一致（real ⊇ oracle 拒绝集）。
#[test]
fn cgroup_pids_differential_vs_oracle() {
    if !pids_delegated() {
        eprintln!("SKIP: pids controller not delegated");
        return;
    }
    let p = read_only_profile();
    let max = p.cgroup.pids_max; // 32
    let enf = LinuxEnforcer::new();

    // 内核：pids.max=32，fork max+8 → 拒绝。
    let real = run_in_cgroup(&enf, max, (max + 8) as i32).expect("spawn helper");
    // oracle：SpawnProcesses{count} Denied iff count > pids_max。
    let rep = SandboxExecutor.evaluate(&p, SandboxOperation::SpawnProcesses { count: max + 8 });

    assert_eq!(
        rep.decision,
        SandboxDecision::Denied,
        "oracle denies count>pids_max"
    );
    match real {
        EnforcementOutcome::KernelDenied { .. } => {} // real ⊇ oracle 拒绝
        EnforcementOutcome::Confined => panic!("kernel must also deny count>pids_max"),
    }
}
