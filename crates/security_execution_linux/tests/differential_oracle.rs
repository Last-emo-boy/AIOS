//! 差分 oracle 测试（ADR-004 D2：real-stricter-than-oracle passes）。
//!
//! 把冻结 `security_execution::SandboxExecutor`（Vec-based 模拟 oracle）与真内核
//! `LinuxEnforcer`（seccomp default-deny，经 execve helper）对照。
//!
//! 诚实性约束：oracle 的 `Syscall` 判定是 **denylist**（默认 allow），内核是
//! **default-deny allowlist** —— 方向相反。因此只断言「内核拒绝集 ⊇ oracle 拒绝
//! 集」（结构性），并在 getpid 上执行 real-stricter / selective 两个可执行点；
//! 不假装逐一执行每个 syscall。
#![cfg(target_os = "linux")]

use runtime_contracts::RiskClass;
use security_execution::policy::CapabilityLease;
use security_execution::sandbox::{
    SandboxCompiler, SandboxDecision, SandboxExecutor, SandboxOperation, SandboxProfile,
};
use security_execution_linux::{resolve_syscall_name, EnforcementOutcome, LinuxEnforcer};

fn helper() -> &'static str {
    env!("CARGO_BIN_EXE_sandbox_probe")
}

fn read_only_profile() -> SandboxProfile {
    // ReadOnly lease（全 pub 字段，直接构造）→ 冻结编译器产出 read-only-diagnostic-v1。
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

/// 冻结 allowlist 完全可解析为内核号（fail-closed 编译成功）。
#[test]
fn frozen_profile_compiles_to_kernel_allowlist() {
    let p = read_only_profile();
    let csv = LinuxEnforcer::new()
        .compile_seccomp_allow_csv(&p)
        .expect("all frozen allowlist names must resolve");
    assert_eq!(csv.split(',').count(), p.seccomp.allowed_syscalls.len());
}

/// 结构性 real-stricter：内核 allowlist（profile.allowed_syscalls）与 oracle
/// denylist（profile.denied_syscalls）不相交 —— 凡 oracle 拒绝的 syscall，内核
/// default-deny 也会拒绝（real 拒绝集 ⊇ oracle 拒绝集）。
#[test]
fn kernel_allowlist_disjoint_from_oracle_denylist() {
    let p = read_only_profile();
    let allow: std::collections::HashSet<&str> =
        p.seccomp.allowed_syscalls.iter().copied().collect();
    for denied in &p.seccomp.denied_syscalls {
        // oracle 确实拒绝它。
        let rep = SandboxExecutor.evaluate(
            &p,
            SandboxOperation::Syscall {
                name: denied.to_string(),
            },
        );
        assert_eq!(rep.decision, SandboxDecision::Denied, "oracle must deny {denied}");
        // 内核 allowlist 不含它 → default-deny 也拒绝。
        assert!(
            !allow.contains(*denied),
            "kernel allowlist must not contain oracle-denied syscall {denied}"
        );
    }
}

/// 可执行 real-stricter：getpid 在 oracle 下 Allowed（denylist 不含），但用冻结
/// profile 编译的 allowlist（不含 getpid）施加到内核时被 SIGSYS —— 内核更严（D2 通过）。
#[test]
fn real_kernel_is_stricter_than_oracle_on_getpid() {
    let p = read_only_profile();
    assert!(
        !p.seccomp.allowed_syscalls.contains(&"getpid"),
        "precondition: getpid not in frozen allowlist"
    );

    // oracle：Allowed（Syscall 是 denylist）。
    let rep = SandboxExecutor.evaluate(
        &p,
        SandboxOperation::Syscall {
            name: "getpid".into(),
        },
    );
    assert_eq!(rep.decision, SandboxDecision::Allowed, "oracle allows getpid (denylist)");

    // 内核：用冻结 profile 编译的 allowlist → getpid 被拒（real-stricter）。
    let enf = LinuxEnforcer::new();
    let csv = enf.compile_seccomp_allow_csv(&p).expect("resolve");
    match enf.seccomp_probe(helper(), &csv, "getpid").expect("spawn helper") {
        EnforcementOutcome::KernelDenied { .. } => {} // PASS：real 比 oracle 严
        EnforcementOutcome::Confined => panic!("kernel must be stricter than oracle on getpid"),
    }
}

/// selective：把 getpid 加入 allowlist → 内核放行（证明强制是选择性的，且名→号
/// 编译路径正确）。
#[test]
fn kernel_allows_when_syscall_in_allowlist() {
    let p = read_only_profile();
    let enf = LinuxEnforcer::new();
    let mut csv = enf.compile_seccomp_allow_csv(&p).expect("resolve");
    let getpid_nr = resolve_syscall_name("getpid").expect("getpid resolves");
    csv.push(',');
    csv.push_str(&getpid_nr.to_string());
    match enf.seccomp_probe(helper(), &csv, "getpid").expect("spawn helper") {
        EnforcementOutcome::Confined => {} // 放行
        EnforcementOutcome::KernelDenied { .. } => panic!("allowlisted getpid must be permitted"),
    }
}
