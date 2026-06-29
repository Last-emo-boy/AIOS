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
    // cp8 失败收敛（同 fail，但 AGENTD_CP8_FAIL 前缀，便于 harness 区分 cp7/cp8 阶段）。
    fn fail_cp8(reason: &str) -> ! {
        mark(&format!("AGENTD_CP8_FAIL {reason}"));
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

    // ── cp8：真持久 fs.write.diff + post-crash recovery（gated；cp7 pristine disk.img no-op）──
    // gate = /var/lib/agentos/cp8-control 存在 OR 非空 unresolved_effects()。cp7 镜像两者皆无 →
    // 整块跳过 → 上面 AGENTD_DISK_READY 字节一致 → cp7 real_qemu_disk_boot/disk-boot-smoke 不受影响。
    {
        use agentd_init::cp8;
        use security_execution::rollback::content_hash;
        const V1: &str = "mode=prod\nport=8080\n";
        const V2: &str = "mode=prod\nport=9090\n";
        let phase_path = "/var/lib/agentos/cp8-phase";

        let l = cp8::layout("/var/lib/agentos");
        let gated = std::path::Path::new("/var/lib/agentos/cp8-control").exists()
            || cp8::unresolved_count(&l).unwrap_or(0) > 0;
        if gated {
            // recovery-first：无条件回滚上次崩溃残留（boot3 在此真回滚 boot2 装弹的 unresolved）。
            let rec = match cp8::recover(&l) {
                Ok(r) => r,
                Err(e) => fail_cp8(&format!("stage=recover errno={}", e.raw_os_error().unwrap_or(-1))),
            };
            // phase 文件驱动跨 reboot 状态机。target_hash 闭包：独立复读目标算 hash。
            let target_hash = || content_hash(&std::fs::read_to_string(&l.target).unwrap_or_default());
            match std::fs::read_to_string(phase_path).unwrap_or_default().trim() {
                "" => {
                    // boot1：正常持久写 v1 → 落 A_DONE phase。
                    let r = match cp8::run_effect(&l, "cp8-boot", "cp8-A-write", "agentd-init", "param-A", V1) {
                        Ok(r) => r,
                        Err(e) => fail_cp8(&format!("stage=produce-A errno={}", e.raw_os_error().unwrap_or(-1))),
                    };
                    if let Err(e) = write_phase(phase_path, "A_DONE") {
                        fail_cp8(&format!("stage=phase-A errno={}", e.raw_os_error().unwrap_or(-1)));
                    }
                    mark(&format!(
                        "AGENTD_CP8_A_COMMIT committed=1 target_hash={} base_hash={} audit_unresolved={} verify=reread-ok",
                        r.final_hash, r.base_hash, cp8::unresolved_count(&l).unwrap_or(99)
                    ));
                }
                "A_DONE" => {
                    // boot2：先 verify-by-re-read（跨 reboot 持久证据）→ 装弹 mid-commit 崩溃。
                    mark(&format!("AGENTD_CP8_A_VERIFY persisted=1 reread_hash={}", target_hash()));
                    let arm = match cp8::arm_crash(&l, "cp8-boot", "cp8-B-write", "agentd-init", "param-B", V2) {
                        Ok(a) => a,
                        Err(e) => fail_cp8(&format!("stage=arm-B errno={}", e.raw_os_error().unwrap_or(-1))),
                    };
                    if let Err(e) = write_phase(phase_path, "B_ARMED") {
                        fail_cp8(&format!("stage=phase-B errno={}", e.raw_os_error().unwrap_or(-1)));
                    }
                    mark(&format!(
                        "AGENTD_CP8_B_ARMED rollback_id={} base_hash={} proposed_hash={} unresolved={}",
                        arm.rollback_id, arm.base_hash, arm.proposed_hash, cp8::unresolved_count(&l).unwrap_or(99)
                    ));
                    // 下面 power_off = 装弹后无 CommitSealed 的真崩溃（target=v2 已 fsync，EffectPrepared 已落）。
                }
                "B_ARMED" => {
                    // boot3：recovery-first 已回滚 boot2 的未完成 effect；报告 + 落 DONE。
                    if let Err(e) = write_phase(phase_path, "DONE") {
                        fail_cp8(&format!("stage=phase-done errno={}", e.raw_os_error().unwrap_or(-1)));
                    }
                    mark(&format!(
                        "AGENTD_CP8_B_RECOVERED restored=1 restored_hash={} reread_hash={} rolled_back={} unresolved_after={}",
                        rec.restored_hash, target_hash(), rec.rolled_back, rec.unresolved_after
                    ));
                }
                _ => {} // DONE / 未知：幂等无操作。
            }
        }
    }

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

/// 跨 reboot 持久写 cp8 phase 文件 + fsync（文件 + 父目录 dirent），确保崩溃不丢 phase。
#[cfg(target_os = "linux")]
fn write_phase(path: &str, phase: &str) -> std::io::Result<()> {
    use std::io::Write;
    {
        let mut f = std::fs::File::create(path)?;
        f.write_all(phase.as_bytes())?;
        f.sync_all()?;
    }
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    std::process::exit(2);
}
