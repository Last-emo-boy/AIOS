//! real_qemu_cp8_recovery —— AIOS cp8 真持久 + post-crash recovery 的 3-boot 端到端断言（ADR-004 cp8）。
//!
//! 薄封装 `appliance/cp8-recovery-smoke.sh`（真实现）：用 build-disk-image.sh 产的 disk.img 可写副本，
//! 3 次从盘 boot 同一副本——boot1 持久写 v1、boot2 跨 reboot verify v1 + 装弹 mid-commit 真崩溃、
//! boot3 recovery-first 真回滚 v2→v1，再 host 端 loop-mount vda3 独立复核 app.conf==v1 + journal
//! 含 RollbackObserved。反假绿（跨 power-cycle 持久 + 真回滚到 base）由脚本断言，PASS 串口含
//! `CP8-RECOVERY PASS`。
//!
//! `#[ignore]`：需 root（losetup/mount seed + host 复核）+ qemu + 预构建 disk.img + 3 次 TCG boot（慢）。
//! CI tcg-cp8-recovery job 提供；本机一键见 appliance/cp8-recovery-smoke.sh。缺前提诚实 SKIP，
//! AIOS_QEMU_REQUIRED=1 时硬 FAIL。

#[cfg(target_os = "linux")]
#[test]
#[ignore = "需 root + qemu + 预构建 disk.img；3-boot TCG 慢；CI tcg-cp8-recovery job / 本机 cp8-recovery-smoke.sh"]
fn real_qemu_cp8_recovery_persists_and_rolls_back() {
    let required = std::env::var_os("AIOS_QEMU_REQUIRED").is_some();
    macro_rules! skip_or_fail {
        ($($arg:tt)*) => {{
            let msg = format!($($arg)*);
            if required { panic!("FAIL(AIOS_QEMU_REQUIRED 已设): {msg}"); }
            eprintln!("SKIP real_qemu_cp8_recovery: {msg}");
            return;
        }};
    }

    if !is_root() {
        skip_or_fail!("需 root（losetup/mount seed cp8-control + host 端复核）");
    }
    if which("qemu-system-x86_64").is_none() {
        skip_or_fail!("缺 qemu-system-x86_64");
    }
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/../../appliance/cp8-recovery-smoke.sh");
    let img = std::env::var("AIOS_DISK_IMAGE")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../../appliance/disk.img").to_string());
    if !std::path::Path::new(&img).exists() {
        skip_or_fail!("缺磁盘镜像 {img}（先 build-disk-image.sh）");
    }

    let output = std::process::Command::new("bash")
        .arg(script)
        .arg(&img)
        .output()
        .expect("run cp8-recovery-smoke.sh");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("--- cp8-recovery-smoke.sh stdout ---\n{stdout}\n--- stderr ---\n{stderr}");

    assert!(
        output.status.success() && stdout.contains("CP8-RECOVERY PASS"),
        "FAIL: cp8-recovery-smoke.sh 未通过（跨 reboot 持久 / 崩溃回滚 / host 复核某项失败）"
    );
}

#[cfg(target_os = "linux")]
fn is_root() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn which(exe: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(exe))
        .find(|p| p.is_file())
}

#[cfg(not(target_os = "linux"))]
#[test]
fn real_qemu_cp8_recovery_linux_only() {}
