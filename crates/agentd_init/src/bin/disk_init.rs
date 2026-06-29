//! disk_init —— AIOS 磁盘 rootfs 上的 `/sbin/init`（ADR-004 cp7）。
//!
//! early_init（initramfs /init）switch_root 到磁盘 ext4 根后 `exec_replace` 到本进程，
//! PID 仍为 1。本进程 = cp4 `boot_smoke` 的磁盘演进：跑真 [`agentd_init::run_pid1`] 生产
//! 序列（在磁盘 ext4 根重挂 /proc /sys /dev，run_pid1 一字不改），受监督 agent_runtime
//! 子进程被 reap 后，打印**三层运行时派生**的反假绿标记再 `power_off`：
//!   1. `statfs("/")` == `EXT4_SUPER_MAGIC`（0xEF53）—— 根真是磁盘 ext4，非 initramfs ramfs/tmpfs；
//!   2. `/proc/self/mountinfo` 的 `/` 行 maj:min（磁盘分区 major!=0；anon-bdev rootfs/tmpfs major=0）
//!      + 源设备（/dev/vda2）；
//!   3. `/etc/agentos/runtime-manifest`（仅存在于磁盘 ext4 根）运行时重算 SHA-256（per-build，
//!      硬编码 stub 伪造不出，且跨 build 变化）。
//! 成功：`AGENTD_DISK_READY pid=1 root_dev=<maj:min> root_fstype=<fs> root_src=<dev> manifest_sha=<hex> reaped=<N>`。
//! 失败：`AGENTD_DISK_FAIL stage=<s> errno=<n>`，再 power_off（PID1 退出=内核 panic，harness 凭 CONTENT 判 FAIL）。
//!
//! 保持 `#![forbid(unsafe_code)]`：下电/statfs 等只经 platform_sys 安全封装；无 unwrap/println!/panic。
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
fn main() {
    use agentd_init::{run_pid1, Pid1Config};
    use sha2::{Digest, Sha256};
    use std::io::Write;

    fn mark(line: &str) {
        if let Ok(mut c) = std::fs::OpenOptions::new().write(true).open("/dev/console") {
            let _ = writeln!(c, "{line}");
            let _ = c.flush();
        }
    }
    // 失败收敛：写 FAIL 标记 → 干净下电（避免 PID1 退出=kernel panic 噪声）→ 兜底 exit_now。
    fn fail(reason: &str) -> ! {
        mark(&format!("AGENTD_DISK_FAIL {reason}"));
        let _ = platform_sys::power_off();
        platform_sys::exit_now(1)
    }

    if platform_sys::getpid() != 1 {
        platform_sys::exit_now(1);
    }

    // 真 PID1 生产序列：在磁盘 ext4 根重挂 /proc /sys /dev（devtmpfs 内核全局、重挂无损），
    // fork 受监督子进程跑一步 agent_runtime 运行循环，run_once 使回收循环 reap 后返回 Report。
    let report = match run_pid1(&Pid1Config::boot_smoke()) {
        Ok(r) => r,
        Err(e) => fail(&format!("stage=init-seq errno={}", e.raw_os_error().unwrap_or(-1))),
    };

    // 反假绿 1：statfs("/") 证明根是磁盘 ext4（0xEF53）。
    let ft = match platform_sys::statfs_type("/") {
        Ok(t) => t,
        Err(e) => fail(&format!("stage=statfs errno={}", e.raw_os_error().unwrap_or(-1))),
    };
    if ft != platform_sys::EXT4_SUPER_MAGIC {
        fail(&format!("stage=root-not-ext4 root_fstype=0x{ft:x}"));
    }

    // 反假绿 2：/proc/self/mountinfo 的 "/" 行——maj:min（磁盘分区 major!=0）+ fstype + 源设备。
    let (root_dev, root_fstype, root_src) = match parse_root_mount() {
        Some(v) => v,
        None => fail("stage=mountinfo"),
    };

    // 反假绿 3：运行时重算 /etc/agentos/runtime-manifest 的 SHA-256（per-build，伪造不出）。
    let manifest = match std::fs::read("/etc/agentos/runtime-manifest") {
        Ok(b) => b,
        Err(e) => fail(&format!("stage=manifest-read errno={}", e.raw_os_error().unwrap_or(-1))),
    };
    let sha_hex: String = Sha256::digest(&manifest).iter().map(|b| format!("{b:02x}")).collect();

    // 反假绿 4：持久分区 /var/lib/agentos（vda3）写 + sync_all + 读回，证明真可写
    //（cp8 fs.write.diff/rollback/recovery 依赖；也证明 vda3 真挂对——root vda2 只读，
    // 若 vda3 未挂则写落到只读 root 失败 → state-write FAIL）。
    if let Err(e) = probe_state_write("/var/lib/agentos/.aios-boot-probe") {
        fail(&format!("stage=state-write errno={}", e.raw_os_error().unwrap_or(-1)));
    }

    mark(&format!(
        "AGENTD_DISK_READY pid=1 root_dev={root_dev} root_fstype={root_fstype} root_src={root_src} manifest_sha={sha_hex} reaped={} state_write=ok",
        report.reaped
    ));

    // 干净下电；返回即下电失败 → best-effort 记录后兜底退出（harness 凭 CONTENT 判 FAIL）。
    let err = platform_sys::power_off();
    fail(&format!("stage=poweroff errno={}", err.raw_os_error().unwrap_or(-1)));
}

/// 从 `/proc/self/mountinfo` 取根挂载（mountpoint=`/`）的 `maj:min`、fstype、源设备。
/// mountinfo 行格式：`id pid maj:min root mountpoint opts... - fstype src superopts`。
#[cfg(target_os = "linux")]
fn parse_root_mount() -> Option<(String, String, String)> {
    let mi = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    for line in mi.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 || fields[4] != "/" {
            continue;
        }
        let majmin = fields[2].to_string();
        let dash = fields.iter().position(|&f| f == "-")?;
        let fstype = fields.get(dash + 1)?.to_string();
        let src = fields.get(dash + 2)?.to_string();
        return Some((majmin, fstype, src));
    }
    None
}

/// 持久分区写探针：写 token → `sync_all`(journal/fsync per ADR) → 读回比对。证明
/// `/var/lib/agentos`（vda3）真挂载且可写（root vda2 只读，未挂 vda3 则写落只读 root 失败）。
#[cfg(target_os = "linux")]
fn probe_state_write(path: &str) -> std::io::Result<()> {
    use std::io::{Read, Write};
    let token: &[u8] = b"aios-cp7-state-probe";
    {
        let mut f = std::fs::File::create(path)?;
        f.write_all(token)?;
        f.sync_all()?;
    }
    let mut buf = Vec::new();
    std::fs::File::open(path)?.read_to_end(&mut buf)?;
    if buf == token {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "state probe readback mismatch",
        ))
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    std::process::exit(2);
}
