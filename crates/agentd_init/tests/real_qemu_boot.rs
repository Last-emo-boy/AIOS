//! real_qemu_boot —— AIOS appliance 真开机的机器可验证断言（ADR-004 cp4）。
//!
//! 用宿主内核 + 含 musl 静态 `boot_smoke` 为 `/init` 的 initramfs，在 QEMU(TCG，本机无
//! `/dev/kvm`) 里真 boot 到真 PID1，断言串口出现**运行时派生**的 READY 标记。这比 userns
//! 探针 `boot_probe` 证明更强的命题：真 devtmpfs 挂载 + 完整特权 PID1 在真内核下运行。
//!
//! `#[ignore]`：需 qemu + musl 静态 boot_smoke + 可读内核且 TCG 耗时，默认
//! `cargo test --workspace` 不跑它，保持快速无依赖。本机一键复跑见 appliance/boot-smoke.sh；
//! CI 见 real-ci.yml 的 tcg-boot job（置 AIOS_QEMU_REQUIRED=1）。
//!
//! 反假绿三重保障：
//!   1. 标记带运行时派生整数（真 `fork` 的 supervised_pid、真 `waitpid` 的 reaped 计数）——
//!      硬编码 stub `/init` 不实现 fork+waitpid 就产不出正确值；断言 reaped>=1 且 supervised_pid>1
//!      （注：initial pidns 内核线程占低位 PID，真 child 远大于 2，这正是真 boot 而非 userns）。
//!   2. 超时 → kill → panic(FAIL)，绝不下落成 pass（hang / panic-loop 必现为失败）。
//!   3. 串口 CONTENT 是唯一权威信号（退出码不可用：poweroff 与 kernel panic 都退 0）；
//!      断言不含 AGENTD_BOOT_FAIL、不含 'Kernel panic'。
//!
//! 缺前提时：本机诚实 SKIP（带日志）；CI 置 AIOS_QEMU_REQUIRED=1 使缺失=硬 FAIL，杜绝静默绿。

#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
#[test]
#[ignore = "需 qemu + musl 静态 boot_smoke + 可读内核（TCG 耗时）；CI tcg-boot job / 本机 boot-smoke.sh"]
fn real_qemu_boot_reaches_pid1_and_powers_off() {
    let required = std::env::var_os("AIOS_QEMU_REQUIRED").is_some();

    // 缺前提：CI（AIOS_QEMU_REQUIRED=1）硬 FAIL，本机诚实 SKIP（绝不静默绿）。
    macro_rules! skip_or_fail {
        ($($arg:tt)*) => {{
            let msg = format!($($arg)*);
            if required { panic!("FAIL(AIOS_QEMU_REQUIRED 已设): {msg}"); }
            eprintln!("SKIP real_qemu_boot: {msg}");
            return;
        }};
    }

    let qemu = "qemu-system-x86_64";
    if which(qemu).is_none() {
        skip_or_fail!("缺 {qemu}（apt install qemu-system-x86）");
    }

    // musl 静态 /init：必须由调用方经 env 指向（CARGO_BIN_EXE_* 是 host glibc 动态，VM 内跑不了）。
    let init_bin = match std::env::var("AIOS_AGENTD_INIT_MUSL") {
        Ok(p) => p,
        Err(_) => skip_or_fail!(
            "未设 AIOS_AGENTD_INIT_MUSL（指向 x86_64-unknown-linux-musl 静态 boot_smoke）"
        ),
    };
    if !std::path::Path::new(&init_bin).exists() {
        skip_or_fail!("AIOS_AGENTD_INIT_MUSL 指向的文件不存在: {init_bin}");
    }
    // 静态校验：动态 /init 在 initramfs 无 ld.so，会 ENOENT 死在内核 exec 那刻。
    // 判据=**排除** dynamically linked（与 pack-initramfs.sh 一致）：musl 默认产 static-pie，
    // file 输出 'static-pie linked' 而非 'statically linked'，两者都是静态、只动态才致命。
    match std::process::Command::new("file").arg("-L").arg(&init_bin).output() {
        Ok(o) => {
            let desc = String::from_utf8_lossy(&o.stdout);
            if desc.contains("dynamically linked") {
                skip_or_fail!("/init 是动态链接（initramfs 无 ld.so）: {}", desc.trim());
            }
        }
        Err(e) => skip_or_fail!("无法运行 file 校验 /init: {e}"),
    }

    let kernel = std::env::var("AIOS_QEMU_KERNEL").unwrap_or_else(|_| {
        let rel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        format!("/boot/vmlinuz-{rel}")
    });
    if !std::path::Path::new(&kernel).exists() {
        skip_or_fail!("内核不存在: {kernel}（设 AIOS_QEMU_KERNEL 覆盖）");
    }

    let timeout_secs: u64 = std::env::var("AIOS_QEMU_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(120);

    // 打包 initramfs：经 appliance/pack-initramfs.sh（本仓库唯一打包器）。
    let pack = concat!(env!("CARGO_MANIFEST_DIR"), "/../../appliance/pack-initramfs.sh");
    let tmp = env!("CARGO_TARGET_TMPDIR");
    let cpio = format!("{tmp}/aios-boot-initramfs.cpio.gz");
    let serial = format!("{tmp}/aios-boot-serial.log");
    let _ = std::fs::remove_file(&serial);

    let pack_status = std::process::Command::new("bash")
        .arg(pack)
        .arg(&init_bin)
        .arg(&cpio)
        .status()
        .expect("运行 pack-initramfs.sh");
    assert!(pack_status.success(), "FAIL: pack-initramfs.sh 打包失败");

    // spawn QEMU(TCG)：串口写入文件；退出码仅 advisory（poweroff/panic 都退 0）。
    let mut child = std::process::Command::new(qemu)
        .args([
            "-accel", "tcg", "-machine", "pc", "-m", "512", "-no-reboot",
            "-display", "none", "-monitor", "none", "-nodefaults", "-no-user-config",
            "-kernel", &kernel, "-initrd", &cpio,
            "-append", "console=ttyS0 panic=-1 rdinit=/init loglevel=4",
            "-serial", &format!("file:{serial}"),
        ])
        .spawn()
        .expect("spawn qemu");

    // 轮询至 deadline；超时 → kill → panic(FAIL)，绝不当成功。
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        match child.try_wait().expect("try_wait qemu") {
            Some(_) => break,
            None => {
                if Instant::now() > deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    let log = std::fs::read_to_string(&serial).unwrap_or_default();
                    panic!(
                        "FAIL: VM {timeout_secs}s 内未 poweroff（TCG hang / panic-loop）；超时-kill != 成功\n--- 串口 ---\n{log}"
                    );
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }

    // 串口 CONTENT 断言（唯一权威信号）。
    let log = std::fs::read_to_string(&serial).expect("读串口日志");
    assert!(
        !log.contains("Kernel panic") && !log.contains("Attempted to kill init"),
        "FAIL: 内核 panic（PID1 未 poweroff 就死了）：\n{log}"
    );
    assert!(
        !log.contains("AGENTD_BOOT_FAIL"),
        "FAIL: boot_smoke 报告 AGENTD_BOOT_FAIL（init 序列某步失败）：\n{log}"
    );
    let line = log
        .lines()
        .find(|l| l.contains("AGENTD_BOOT_READY"))
        .unwrap_or_else(|| panic!("FAIL: 串口无 AGENTD_BOOT_READY（未 boot 到我们的 PID1）：\n{log}"));

    // 运行时派生整数：reaped>=1（真 waitpid 回收）、supervised_pid>1（真 fork 的 child pid）。
    let reaped = parse_kv(line, "reaped").expect("READY 行含 reaped=N");
    let supervised_pid = parse_kv(line, "supervised_pid").expect("READY 行含 supervised_pid=P");
    assert!(reaped >= 1, "FAIL: reaped={reaped}，受监督 agent_runtime child 未被 reap");
    assert!(
        supervised_pid > 1,
        "FAIL: supervised_pid={supervised_pid}，非真 fork 的 child（PID1 自身=1）"
    );

    eprintln!("PASS: 真 PID1 自检 + 干净 poweroff（{}）", line.trim());
}

/// 从 "key=N" token 解析整数。
#[cfg(target_os = "linux")]
fn parse_kv(line: &str, key: &str) -> Option<i64> {
    let needle = format!("{key}=");
    line.split_whitespace()
        .find_map(|t| t.strip_prefix(&needle))
        .and_then(|v| v.parse().ok())
}

/// PATH 查找可执行（无依赖）。
#[cfg(target_os = "linux")]
fn which(exe: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(exe))
        .find(|p| p.is_file())
}

#[cfg(not(target_os = "linux"))]
#[test]
fn real_qemu_boot_linux_only() {
    // 非 Linux：appliance 真开机不适用，留一个占位以保证测试文件可编译。
}
