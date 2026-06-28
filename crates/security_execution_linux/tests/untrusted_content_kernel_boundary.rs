//! 内核证明：不可信内容**不能外泄网络 / spawn shell / 写出沙箱**（ADR-000 第三 MVP / Part B）。
//!
//! 三条腿各由**单独一层**强制，并带 baseline 排除假绿（layer honesty）：
//! - 网络外泄：仅 netns（空 seccomp + 无 Landlock）强制 => connect ENETUNREACH(41)。
//!   baseline（不进 netns）对**同** addr 返回 != 41，证明 41 来自 netns 而非坏地址。
//! - shell：仅 seccomp（无 clone/execve）强制 => Command spawn 被 SIGSYS。
//!   baseline（无 seccomp）能 spawn，证明拦截源是 seccomp 而非环境本身。
//! - 磁盘：仅 Landlock 强制 => 越界写 EACCES（复用 `run_write_denied`）。
//!
//! honesty cross-check（文档化，不强制运行）：
//! - 若 `run_confined_connect` 去掉 net ns，连接会落到 baseline 路径（!=41），断言翻成 Confined。
//! - 若 `run_confined_exec` 去掉 seccomp，Command 能 spawn，断言翻成 Confined。
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

/// 探一个可路由非 loopback 目标：宿主出网源 IP 的一个高位（大概率关闭）端口。
/// 宿主上连它会被立即 ECONNREFUSED（本地 IP、无监听）—— 与 netns 内的 ENETUNREACH 形成
/// 干净对照。若无法判定出网 IP，则回退 TEST-NET-1（宿主上超时，netns 内不可达）。
fn routable_target() -> String {
    use std::net::UdpSocket;
    match UdpSocket::bind("0.0.0.0:0").and_then(|s| {
        s.connect("192.168.0.1:1")?;
        Ok(s.local_addr()?.ip())
    }) {
        Ok(ip) if !ip.is_loopback() => format!("{ip}:59999"),
        _ => "192.0.2.1:80".to_string(),
    }
}

#[test]
fn untrusted_network_egress_blocked_by_netns_with_baseline_delta() {
    let enf = LinuxEnforcer::new();
    let addr = routable_target();

    // netns 内：不可信内容连不出去（内核以 ENETUNREACH/超时类拒绝）。
    match enf.run_connect_denied(helper(), &addr).expect("connect probe runs") {
        EnforcementOutcome::KernelDenied { .. } => {}
        EnforcementOutcome::Confined => {
            panic!("netns NOT enforced: untrusted content reached {addr}")
        }
    }

    // baseline（无 netns）：同 addr 的分类码 != 41 —— 证明 41 来自 netns 隔离而非地址本身。
    let base = enf.baseline_connect(helper(), &addr).expect("baseline connect runs");
    assert_ne!(
        base, 41,
        "baseline (no netns) must not classify {addr} as netns-unreachable; got code {base}"
    );
}

#[test]
fn untrusted_shell_exec_blocked_by_seccomp_with_baseline_delta() {
    let enf = LinuxEnforcer::new();
    // prog 保证存在（sandbox_probe 自身）；真要 exec 的是任意外部程序。
    let prog = env!("CARGO_BIN_EXE_sandbox_probe");

    // 受限：不可信内容 spawn 子进程被内核 SIGSYS（clone/execve 非 allowlist）。
    match enf.run_exec_denied(helper(), prog).expect("exec probe runs") {
        EnforcementOutcome::KernelDenied { .. } => {}
        EnforcementOutcome::Confined => {
            panic!("seccomp NOT enforced: untrusted content spawned an external program")
        }
    }

    // baseline（无 seccomp）：能 spawn —— 证明拦截源是 seccomp 而非环境本身不能起子进程。
    assert!(
        enf.baseline_can_exec(helper(), prog).expect("baseline exec runs"),
        "baseline (no seccomp) must be able to spawn — proves seccomp is the blocker"
    );
}

#[test]
fn untrusted_disk_write_blocked_by_landlock() {
    if !landlock_in_lsm() {
        eprintln!("SKIP: landlock not in /sys/kernel/security/lsm (genuinely unavailable)");
        return;
    }
    let enf = LinuxEnforcer::new();

    let root = std::env::temp_dir().join(format!("aios_ucb_{}", std::process::id()));
    let granted = root.join("granted");
    let forbidden_dir = root.join("forbidden");
    std::fs::create_dir_all(&granted).expect("mkdir granted");
    std::fs::create_dir_all(&forbidden_dir).expect("mkdir forbidden");
    let forbidden = forbidden_dir.join("escape.txt");
    let out = granted.join("out.json");

    // baseline：无沙箱时该路径 DAC 可写（排除 EACCES 来自 DAC 而非 Landlock）。
    std::fs::write(&forbidden, b"baseline").expect("forbidden path is DAC-writable");
    std::fs::remove_file(&forbidden).expect("clean baseline file");

    let outcome = enf
        .run_write_denied(
            helper(),
            out.to_str().unwrap(),
            granted.to_str().unwrap(),
            forbidden.to_str().unwrap(),
            "untrusted-content-payload",
        )
        .expect("landlock must be fully enforced (fail-closed)");

    let escaped = forbidden.exists();
    std::fs::remove_dir_all(&root).ok();

    match outcome {
        EnforcementOutcome::KernelDenied { .. } => {}
        EnforcementOutcome::Confined => {
            panic!("landlock NOT enforced: untrusted content wrote outside the sandbox")
        }
    }
    assert!(!escaped, "denied write must not have created the forbidden file");
}
