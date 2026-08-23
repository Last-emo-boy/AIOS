//! real_qemu_disk_boot —— AIOS cp7 真磁盘 boot + pivot 的机器可验证断言（ADR-004 cp7）。
//!
//! 用 build-disk-image.sh 产的 GPT+ext4+GRUB(BIOS) 磁盘镜像，QEMU(TCG，无 /dev/kvm) 从**磁盘**
//! boot（无 -kernel/-initrd）：SeaBIOS→GRUB→kernel+initramfs→early_init finit_module 加载
//! virtio_blk/ext4→挂磁盘 ext4 根→switch_root→exec disk_init→真 PID1 自检 + 反假绿→power_off。
//!
//! 比 cp4 real_qemu_boot 更强：证明**真 pivot 到磁盘 ext4 根**（非还在 initramfs）。
//! `#[ignore]`：需 qemu + 预构建磁盘镜像（build-disk-image.sh 须 root）。CI disk-boot job 提供；
//! 本机一键见 appliance/disk-boot-smoke.sh。
//!
//! 反假绿（全运行时派生，硬编码 stub 伪造不出）：
//!   - root_dev maj:min 的 major != 0（磁盘分区；anon-bdev rootfs/tmpfs major=0）；
//!   - root_fstype == ext4；root_src 以 /dev/vda 开头（真挂的磁盘分区）；
//!   - manifest_sha == sidecar 的 per-build 值（运行时重算 /etc/agentos/runtime-manifest）；
//!   - reaped >= 1（真 fork+waitpid）。
//!
//! 超时→kill→FAIL；串口 CONTENT 唯一权威（退出码 poweroff/panic 都 0）。

#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
#[test]
#[ignore = "需 qemu + 预构建磁盘镜像（build-disk-image.sh 须 root）；CI disk-boot job / 本机 disk-boot-smoke.sh"]
fn real_qemu_disk_boot_pivots_to_ext4_root() {
    let required = std::env::var_os("AIOS_QEMU_REQUIRED").is_some();
    macro_rules! skip_or_fail {
        ($($arg:tt)*) => {{
            let msg = format!($($arg)*);
            if required { panic!("FAIL(AIOS_QEMU_REQUIRED 已设): {msg}"); }
            eprintln!("SKIP real_qemu_disk_boot: {msg}");
            return;
        }};
    }

    let qemu = "qemu-system-x86_64";
    if which(qemu).is_none() {
        skip_or_fail!("缺 {qemu}（apt install qemu-system-x86）");
    }
    let img = match std::env::var("AIOS_DISK_IMAGE") {
        Ok(p) => p,
        Err(_) => skip_or_fail!("未设 AIOS_DISK_IMAGE（指向 build-disk-image.sh 产的磁盘镜像）"),
    };
    if !std::path::Path::new(&img).exists() {
        skip_or_fail!("磁盘镜像不存在: {img}");
    }
    let expected_sha = match std::env::var("AIOS_DISK_MANIFEST_SHA") {
        Ok(s) => s.trim().to_string(),
        Err(_) => skip_or_fail!("未设 AIOS_DISK_MANIFEST_SHA（<img>.manifest.sha256 的内容）"),
    };

    let timeout_secs: u64 = std::env::var("AIOS_QEMU_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(240);

    let tmp = env!("CARGO_TARGET_TMPDIR");
    let serial = format!("{tmp}/aios-disk-serial.log");
    let _ = std::fs::remove_file(&serial);

    // 从磁盘 boot（无 -kernel/-initrd）；snapshot=on 使重跑幂等、不写回 backing 镜像。
    let mut child = std::process::Command::new(qemu)
        .args([
            "-accel", "tcg", "-machine", "pc", "-m", "768", "-no-reboot",
            "-display", "none", "-monitor", "none", "-nodefaults", "-no-user-config",
            "-drive", &format!("file={img},format=raw,if=virtio,snapshot=on"),
            "-serial", &format!("file:{serial}"),
        ])
        .spawn()
        .expect("spawn qemu");

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        match child.try_wait().expect("try_wait qemu") {
            Some(_) => break,
            None => {
                if Instant::now() > deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    let log = std::fs::read_to_string(&serial).unwrap_or_default();
                    panic!("FAIL: VM {timeout_secs}s 内未 poweroff（hang/panic-loop）；超时-kill != 成功\n--- 串口 ---\n{log}");
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }

    let log = std::fs::read_to_string(&serial).expect("读串口日志");
    assert!(
        !log.contains("Kernel panic") && !log.contains("Attempted to kill init"),
        "FAIL: 内核 panic（PID1 死）：\n{log}"
    );
    assert!(
        !log.contains("AGENTD_DISK_FAIL"),
        "FAIL: early_init/disk_init 报 AGENTD_DISK_FAIL：\n{log}"
    );
    let line = log
        .lines()
        .find(|l| l.contains("AGENTD_DISK_READY"))
        .unwrap_or_else(|| panic!("FAIL: 串口无 AGENTD_DISK_READY（未 pivot 到磁盘 PID1）：\n{log}"));

    let root_dev = parse_kv(line, "root_dev").expect("root_dev=maj:min");
    let major: i64 = root_dev
        .split(':')
        .next()
        .and_then(|s| s.parse().ok())
        .expect("maj:min");
    let root_fstype = parse_kv(line, "root_fstype").expect("root_fstype=");
    let root_src = parse_kv(line, "root_src").expect("root_src=");
    let manifest_sha = parse_kv(line, "manifest_sha").expect("manifest_sha=");
    let reaped: i64 = parse_kv(line, "reaped")
        .and_then(|s| s.parse().ok())
        .expect("reaped=N");

    // 全运行时派生反假绿：
    assert!(
        major != 0,
        "FAIL: root_dev={root_dev} major=0（仍在 initramfs ramfs/tmpfs，未真 pivot）"
    );
    assert_eq!(root_fstype, "ext4", "FAIL: root_fstype={root_fstype}，根不是磁盘 ext4");
    assert!(
        root_src.starts_with("/dev/vda"),
        "FAIL: root_src={root_src}，非磁盘分区"
    );
    assert_eq!(
        manifest_sha, expected_sha,
        "FAIL: manifest_sha 不匹配 sidecar（运行时重算 != 构建期 expected）"
    );
    assert!(reaped >= 1, "FAIL: reaped={reaped}，受监督 child 未被 reap");
    let state_write = parse_kv(line, "state_write").expect("state_write=");
    assert_eq!(
        state_write, "ok",
        "FAIL: state_write={state_write}，持久分区 vda3 未挂/不可写"
    );

    eprintln!(
        "PASS: 真 pivot 到磁盘 ext4 根 + 持久分区可写 + 干净 poweroff（{}）",
        line.trim()
    );
}

#[cfg(target_os = "linux")]
fn parse_kv(line: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=");
    line.split_whitespace()
        .find_map(|t| t.strip_prefix(&needle))
        .map(|s| s.to_string())
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
fn real_qemu_disk_boot_linux_only() {}
