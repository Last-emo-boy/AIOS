//! 真内核沙箱强制集成测试（ADR-004 cp5）。
//!
//! 经 execve-based confined helper（`sandbox_probe`）证明内核**真的**强制了
//! seccomp default-deny 与 Landlock，而非冻结沙箱的 `Vec::contains` 模拟。
//! 关键反假绿手段：
//! - seccomp：default-deny → 非 allowlist syscall 被 SIGSYS 杀；allowlist 内放行。
//! - Landlock：先 baseline 证明同 uid 无沙箱本可读 forbidden（排除 DAC/ENOENT），
//!   再断言有沙箱时 forbidden 被 EACCES 拒绝；未 FullyEnforced 直接硬失败。
//! - 仅当 Landlock 确实不在内核 LSM 链时才 loud-skip（genuinely unavailable）。
#![cfg(target_os = "linux")]

use security_execution_linux::{EnforcementOutcome, LinuxEnforcer};

fn helper() -> &'static str {
    env!("CARGO_BIN_EXE_sandbox_probe")
}

fn landlock_in_lsm() -> bool {
    std::fs::read_to_string("/sys/kernel/security/lsm")
        .map(|s| s.split(',').any(|x| x.trim() == "landlock"))
        .unwrap_or(false)
}

#[test]
fn seccomp_default_deny_is_kernel_enforced() {
    let enf = LinuxEnforcer::new();

    // 非 allowlist 的 syscall 必须被内核杀死。
    match enf.prove_seccomp_default_deny(helper()).expect("spawn helper") {
        EnforcementOutcome::KernelDenied { .. } => {}
        EnforcementOutcome::Confined => {
            panic!("seccomp default-deny NOT enforced: non-allowlisted syscall survived")
        }
    }

    // allowlist 内的 syscall 必须被放行（证明强制是选择性的）。
    assert!(
        enf.seccomp_allows_allowlisted(helper()).expect("spawn helper"),
        "allowlisted getpid must be permitted (kernel over-killed)"
    );
}

#[test]
fn landlock_is_kernel_enforced_with_baseline_delta() {
    use std::io::Write;

    if !landlock_in_lsm() {
        eprintln!("SKIP: landlock not in /sys/kernel/security/lsm (genuinely unavailable)");
        return;
    }

    let enf = LinuxEnforcer::new();
    let forbidden = "/etc/hostname";

    // baseline：同 uid 无沙箱必须能读 forbidden，否则后续 EACCES 来自 DAC 而非 Landlock。
    assert!(
        enf.baseline_can_read(helper(), forbidden).expect("spawn helper"),
        "baseline open of {forbidden} must succeed (else EACCES would be DAC, not Landlock)"
    );

    // 私有临时目录作为 allowed_dir（避免 /tmp 固定名 TOCTOU）。
    let dir = std::env::temp_dir().join(format!("aios_ll_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let inside = dir.join("inside.txt");
    std::fs::File::create(&inside)
        .and_then(|mut f| f.write_all(b"ok"))
        .expect("write probe");
    let dir_s = dir.to_str().unwrap();
    let inside_s = inside.to_str().unwrap();

    // 授权目录内可读。
    let inside_ok = enf
        .landlock_allows_inside(helper(), dir_s, inside_s)
        .expect("spawn helper");

    // 授权目录外（forbidden）被内核 EACCES 拒绝；未 FullyEnforced 则 prove 返回 Err → 失败。
    let denied = enf.prove_landlock_denies(helper(), dir_s, forbidden);

    std::fs::remove_dir_all(&dir).ok();

    assert!(inside_ok, "read inside the allowed dir must be permitted");
    match denied.expect("landlock must be fully enforced (fail-closed)") {
        EnforcementOutcome::KernelDenied { .. } => {}
        EnforcementOutcome::Confined => {
            panic!("landlock NOT enforced: read outside the allowed dir was permitted")
        }
    }
}
