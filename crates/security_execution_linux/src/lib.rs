//! security_execution_linux —— 真实内核强制执行后端（ADR-004 D2 / cp5）。
//!
//! 取代冻结的 `security_execution` 中以 `Vec::contains` / 字符串前缀模拟的沙箱：
//! 经 `platform_sys` 的 execve-based confined helper（`sandbox_probe`）把沙箱真正
//! 施加到一个全新单线程子进程，并由真内核证明（seccomp default-deny → SIGSYS；
//! Landlock fail-closed → EACCES）。
//!
//! 差分 oracle（D2，real-stricter-passes）：消费冻结 `SandboxProfile`，把它的
//! `seccomp.allowed_syscalls`（名）编译成内核 allowlist。冻结 `SandboxExecutor` 的
//! Syscall 判定是 **denylist**（默认 allow），内核是 **default-deny allowlist**——
//! 方向相反，故只能诚实断言「内核拒绝集 ⊇ oracle 拒绝集」，不逐一执行每个 syscall。
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
use security_execution::policy::ApprovalToken;
#[cfg(target_os = "linux")]
use security_execution::sandbox::SandboxProfile;

/// 一次强制执行的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnforcementOutcome {
    /// 子进程在内核约束下完成（未触发被禁动作 / 被显式放行）。
    Confined,
    /// 内核阻止了一次越权尝试（seccomp SIGSYS / Landlock EACCES）。
    KernelDenied { reason: String },
}

/// `fs.read` 工具在受限沙箱内读取一个文件后回传的真实观测。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsReadObservation {
    /// 沙箱内是否成功读到文件（Landlock 越界 / 文件缺失 => false）。
    pub ok: bool,
    /// 文件真实字节长度。
    pub len: usize,
    /// 首行字节的稳定哈希（16 位十六进制，固定种子 `DefaultHasher`，可跨进程复现）。
    pub first_line_hash: String,
}

/// `svc.status` 工具在受限沙箱内探测一个进程后回传的真实观测。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SvcStatusObservation {
    /// `/proc/<pid>/comm` 可读 => 进程在宿主 pidns 存活。
    pub alive: bool,
    /// 进程 comm 名（不存活时为空）。
    pub comm: String,
}

/// 真 write-with-diff 事务在受限沙箱内完成后回传的真实观测（与冻结
/// `CommitReport` 同形：committed + 三个内容哈希 + rollback_id）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteDiffObservation {
    /// 回读校验是否等于 proposed_hash（沙箱内真实写入并回读后判定）。
    pub committed: bool,
    /// 回滚句柄 id，`rb-{parameter_hash}-{proposed_hash}`，与冻结 oracle 同形。
    pub rollback_id: String,
    /// 期望的基线哈希（事务前 target 应有的内容哈希）。
    pub base_hash: String,
    /// 拟写入内容的哈希。
    pub proposed_hash: String,
    /// 写入并回读后的实际内容哈希。
    pub final_hash: String,
}

/// 一次真 write-with-diff 的结局。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteDiffOutcome {
    /// 写入成功并回读校验通过（final_hash == proposed_hash）。
    Committed(WriteDiffObservation),
    /// 写入了但回读校验未通过：需回滚（rollback pending）。
    RollbackPending(WriteDiffObservation),
    /// 事务前 target 的实际哈希与期望 base_hash 不符：未改动 target（与 oracle 一致）。
    BaseHashMismatch { expected: String, actual: String },
    /// 内核阻止了写入（Landlock EACCES / seccomp SIGSYS）。
    KernelDenied { reason: String },
}

/// 真 write-with-diff 回滚在受限沙箱内完成后回传的真实观测。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackObservation {
    /// 回读校验是否等于 base_hash（恢复成功）。
    pub restored: bool,
    /// 回写并回读后的实际内容哈希。
    pub restored_hash: String,
}

/// 极简 JSON 字段抽取（仅服务于 helper 自产的良构观测，无需 serde 依赖）。
#[cfg(target_os = "linux")]
fn json_uint(s: &str, key: &str) -> Option<u64> {
    let k = format!("\"{key}\":");
    let rest = &s[s.find(&k)? + k.len()..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

#[cfg(target_os = "linux")]
fn json_bool(s: &str, key: &str) -> Option<bool> {
    let k = format!("\"{key}\":");
    let rest = &s[s.find(&k)? + k.len()..];
    if rest.starts_with("true") {
        Some(true)
    } else if rest.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn json_str(s: &str, key: &str) -> Option<String> {
    let k = format!("\"{key}\":\"");
    let rest = &s[s.find(&k)? + k.len()..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// 把 syscall 名解析为 x86_64 syscall 号（fail-closed：未知名返回 `None`，
/// 调用方据此拒绝构建过滤器）。`libc::SYS_*` 为目标 arch 的权威号。
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn resolve_syscall_name(name: &str) -> Option<i64> {
    let n: libc::c_long = match name {
        "read" => libc::SYS_read,
        "write" => libc::SYS_write,
        "openat" => libc::SYS_openat,
        "close" => libc::SYS_close,
        "newfstatat" => libc::SYS_newfstatat,
        "mmap" => libc::SYS_mmap,
        "munmap" => libc::SYS_munmap,
        "brk" => libc::SYS_brk,
        "clock_gettime" => libc::SYS_clock_gettime,
        "rt_sigaction" => libc::SYS_rt_sigaction,
        "rt_sigprocmask" => libc::SYS_rt_sigprocmask,
        "futex" => libc::SYS_futex,
        "exit" => libc::SYS_exit,
        "exit_group" => libc::SYS_exit_group,
        "getpid" => libc::SYS_getpid,
        _ => return None,
    };
    Some(n as i64)
}

/// 非 x86_64 Linux：尚无 syscall 号表，fail-closed 返回 `None`。
#[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
pub fn resolve_syscall_name(_name: &str) -> Option<i64> {
    None
}

/// 真实沙箱后端：经 confined helper 施加并验证内核强制。
#[derive(Debug, Default)]
pub struct LinuxEnforcer {}

#[cfg(target_os = "linux")]
impl LinuxEnforcer {
    pub fn new() -> Self {
        Self::default()
    }

    /// 把冻结 `SandboxProfile.seccomp.allowed_syscalls`（名）编译成内核 allowlist
    /// 的逗号分隔号串（fail-closed：任一名解析失败则整体拒绝）。
    pub fn compile_seccomp_allow_csv(&self, profile: &SandboxProfile) -> Result<String, String> {
        let mut nums: Vec<String> = Vec::with_capacity(profile.seccomp.allowed_syscalls.len());
        for name in &profile.seccomp.allowed_syscalls {
            let nr = resolve_syscall_name(name)
                .ok_or_else(|| format!("unknown syscall name (fail-closed): {name}"))?;
            nums.push(nr.to_string());
        }
        Ok(nums.join(","))
    }

    /// 用给定的 allowlist（号 csv）施加 seccomp default-deny，并触发 `sel` syscall。
    /// `sel` 不在 allowlist → 内核 SIGSYS（KernelDenied）；在 allowlist → Confined。
    pub fn seccomp_probe(
        &self,
        helper: &str,
        allow_csv: &str,
        sel: &str,
    ) -> std::io::Result<EnforcementOutcome> {
        use platform_sys::{ChildExit, SIGSYS};
        match platform_sys::spawn_and_wait(helper, &["seccomp-probe", allow_csv, sel])? {
            ChildExit::KilledBySignal(s) if s == SIGSYS => Ok(EnforcementOutcome::KernelDenied {
                reason: format!("seccomp: {sel} not in allowlist → SIGSYS({s})"),
            }),
            ChildExit::Exited(21) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "seccomp setup failed inside helper",
            )),
            ChildExit::Exited(0) => Ok(EnforcementOutcome::Confined),
            ChildExit::Exited(c) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("unexpected helper exit {c}"),
            )),
            ChildExit::KilledBySignal(s) => Ok(EnforcementOutcome::KernelDenied {
                reason: format!("child killed by signal {s}"),
            }),
        }
    }

    /// 基线对照：无沙箱时同 uid 能否读 `target`（排除 DAC/ENOENT 误判）。
    pub fn baseline_can_read(&self, helper: &str, target: &str) -> std::io::Result<bool> {
        Ok(matches!(
            platform_sys::spawn_and_wait(helper, &["baseline-open", target])?,
            platform_sys::ChildExit::Exited(0)
        ))
    }

    /// 证明 seccomp **default-deny** 被内核强制：非 allowlist syscall → SIGSYS。
    pub fn prove_seccomp_default_deny(&self, helper: &str) -> std::io::Result<EnforcementOutcome> {
        use platform_sys::{ChildExit, SIGSYS};
        match platform_sys::spawn_and_wait(helper, &["seccomp-deny-getpid"])? {
            ChildExit::KilledBySignal(s) if s == SIGSYS => Ok(EnforcementOutcome::KernelDenied {
                reason: format!("seccomp default-deny: non-allowlisted syscall killed by SIGSYS({s})"),
            }),
            ChildExit::Exited(21) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "seccomp setup failed inside helper",
            )),
            ChildExit::Exited(_) => Ok(EnforcementOutcome::Confined),
            ChildExit::KilledBySignal(s) => Ok(EnforcementOutcome::KernelDenied {
                reason: format!("child killed by signal {s}"),
            }),
        }
    }

    /// 证明 allowlist 内 syscall 被放行（强制是选择性的，而非无脑全杀）。
    pub fn seccomp_allows_allowlisted(&self, helper: &str) -> std::io::Result<bool> {
        Ok(matches!(
            platform_sys::spawn_and_wait(helper, &["seccomp-allow-getpid"])?,
            platform_sys::ChildExit::Exited(0)
        ))
    }

    /// 证明 Landlock 读授权内文件被放行。
    pub fn landlock_allows_inside(
        &self,
        helper: &str,
        allowed_dir: &str,
        target: &str,
    ) -> std::io::Result<bool> {
        Ok(matches!(
            platform_sys::spawn_and_wait(helper, &["landlock-open", allowed_dir, target])?,
            platform_sys::ChildExit::Exited(0)
        ))
    }

    /// 证明 Landlock 拒绝 `forbidden`（须落在 `allowed_dir` 之外）的读取。
    /// Fail-closed：未 FullyEnforced（退出码 20）/ 文件缺失（11）均映射为硬 `Err`。
    pub fn prove_landlock_denies(
        &self,
        helper: &str,
        allowed_dir: &str,
        forbidden: &str,
    ) -> std::io::Result<EnforcementOutcome> {
        use platform_sys::ChildExit;
        let mkerr = |m: &str| std::io::Error::new(std::io::ErrorKind::Other, m.to_string());
        match platform_sys::spawn_and_wait(helper, &["landlock-open", allowed_dir, forbidden])? {
            ChildExit::Exited(10) => Ok(EnforcementOutcome::KernelDenied {
                reason: format!("landlock: read of {forbidden} outside {allowed_dir} denied (EACCES)"),
            }),
            ChildExit::Exited(0) => Ok(EnforcementOutcome::Confined),
            ChildExit::Exited(11) => Err(mkerr("forbidden file missing (ENOENT) — cannot prove")),
            ChildExit::Exited(20) => Err(mkerr("landlock not FullyEnforced — fail-closed")),
            ChildExit::Exited(22) => Err(mkerr("landlock setup error in helper")),
            ChildExit::Exited(c) => Err(mkerr(&format!("unexpected helper exit {c}"))),
            ChildExit::KilledBySignal(s) => Err(mkerr(&format!("helper killed by signal {s}"))),
        }
    }

    /// 完整受限执行器：在 user/mount/pid/net namespace + no_new_privs + Landlock +
    /// seccomp（default-deny）的完整栈下运行一个探针向量，验证内核强制。helper 内部
    /// 按正确顺序施加（user ns→maps→其他 ns→make-rprivate→fork→[child: /proc→nnp→
    /// landlock→seccomp LAST→vector]），子进程 SIGSYS 经 reraise 上浮为外层信号。
    pub fn enforce_confined(
        &self,
        helper: &str,
        ns_csv: &str,
        seccomp_csv: &str,
        landlock_dir: &str,
        vector: &str,
        varg: &str,
    ) -> std::io::Result<EnforcementOutcome> {
        use platform_sys::{ChildExit, SIGSYS};
        let mkerr = |m: String| std::io::Error::new(std::io::ErrorKind::Other, m);
        match platform_sys::spawn_and_wait(
            helper,
            &["confined", ns_csv, seccomp_csv, landlock_dir, vector, varg],
        )? {
            ChildExit::KilledBySignal(s) if s == SIGSYS => Ok(EnforcementOutcome::KernelDenied {
                reason: format!("seccomp SIGSYS({s}) through full namespace stack"),
            }),
            ChildExit::Exited(0) => Ok(EnforcementOutcome::Confined),
            ChildExit::Exited(10) => Ok(EnforcementOutcome::KernelDenied {
                reason: "landlock EACCES through namespace stack".into(),
            }),
            ChildExit::Exited(11) => Err(mkerr("forbidden file missing (ENOENT)".into())),
            ChildExit::Exited(20) => Err(mkerr("landlock not FullyEnforced — fail-closed".into())),
            ChildExit::Exited(30) => Ok(EnforcementOutcome::Confined),
            ChildExit::Exited(c) => Err(mkerr(format!("confined setup/probe failure code {c}"))),
            ChildExit::KilledBySignal(s) => Ok(EnforcementOutcome::KernelDenied {
                reason: format!("child killed by signal {s}"),
            }),
        }
    }

    /// 真 cgroup v2 pids.max 强制：helper 加入 `cgroup_path`（测试预设 pids.max），
    /// 连续 fork `fork_n` 个；超出配额时内核以 EAGAIN 拒绝（KernelDenied）。对接冻结
    /// oracle 的 `SandboxOperation::SpawnProcesses{count}`（count>pids_max ⇒ Denied）。
    pub fn enforce_cgroup_pids(
        &self,
        helper: &str,
        cgroup_path: &str,
        fork_n: i32,
    ) -> std::io::Result<EnforcementOutcome> {
        use platform_sys::ChildExit;
        let mkerr = |m: String| std::io::Error::new(std::io::ErrorKind::Other, m);
        match platform_sys::spawn_and_wait(
            helper,
            &["cgroup-pids", cgroup_path, &fork_n.to_string()],
        )? {
            ChildExit::Exited(60) => Ok(EnforcementOutcome::KernelDenied {
                reason: "cgroup pids.max: fork denied by kernel (EAGAIN)".into(),
            }),
            ChildExit::Exited(0) => Ok(EnforcementOutcome::Confined),
            ChildExit::Exited(28) => Err(mkerr("cgroup join (cgroup.procs write) failed".into())),
            ChildExit::Exited(c) => Err(mkerr(format!("cgroup probe failure code {c}"))),
            ChildExit::KilledBySignal(s) => Err(mkerr(format!("cgroup helper killed by signal {s}"))),
        }
    }

    /// 真实工具 `fs.read`：在完整受限沙箱（user/mount/pid/net ns + Landlock 限定到
    /// **文件父目录** + seccomp default-deny）内真实读取 `file` 的字节，helper 把观测
    /// JSON 写入 `out_path`（沙箱施加前打开的侧信道 fd），父进程在此读回并解析为
    /// 真实字节长度 + 首行哈希。helper 非 0 退出 / 被信号杀（如 seccomp SIGSYS）=> Err。
    pub fn run_fs_read(
        &self,
        helper: &str,
        out_path: &str,
        file: &str,
    ) -> std::io::Result<FsReadObservation> {
        use platform_sys::ChildExit;
        let mkerr = |m: String| std::io::Error::new(std::io::ErrorKind::Other, m);
        match platform_sys::spawn_and_wait(helper, &["tool-fs-read", out_path, file])? {
            ChildExit::Exited(0) => {
                let s = std::fs::read_to_string(out_path)?;
                let ok = json_bool(&s, "ok").unwrap_or(false);
                let len = json_uint(&s, "len")
                    .ok_or_else(|| mkerr(format!("observation missing len: {s}")))?
                    as usize;
                let first_line_hash = json_str(&s, "first_line_hash")
                    .ok_or_else(|| mkerr(format!("observation missing first_line_hash: {s}")))?;
                Ok(FsReadObservation {
                    ok,
                    len,
                    first_line_hash,
                })
            }
            ChildExit::Exited(70) => Err(mkerr("fs.read: helper could not open out file".into())),
            ChildExit::Exited(c) => Err(mkerr(format!("fs.read helper exit {c}"))),
            ChildExit::KilledBySignal(s) => {
                Err(mkerr(format!("fs.read helper killed by signal {s}")))
            }
        }
    }

    /// 真实工具 `svc.status`：在受限沙箱（user ns + Landlock 限定到 `/proc` 只读 +
    /// seccomp default-deny；不进 pid/mount ns 以保留宿主 /proc）内读取
    /// `/proc/<pid>/comm`，helper 把观测 JSON 写入 `out_path`，父进程读回并解析为
    /// `alive + comm`（进程不存在 => alive=false）。
    pub fn run_svc_status(
        &self,
        helper: &str,
        out_path: &str,
        pid: i32,
    ) -> std::io::Result<SvcStatusObservation> {
        use platform_sys::ChildExit;
        let mkerr = |m: String| std::io::Error::new(std::io::ErrorKind::Other, m);
        match platform_sys::spawn_and_wait(helper, &["tool-svc-status", out_path, &pid.to_string()])?
        {
            ChildExit::Exited(0) => {
                let s = std::fs::read_to_string(out_path)?;
                let alive = json_bool(&s, "alive")
                    .ok_or_else(|| mkerr(format!("observation missing alive: {s}")))?;
                let comm = json_str(&s, "comm").unwrap_or_default();
                Ok(SvcStatusObservation { alive, comm })
            }
            ChildExit::Exited(70) => {
                Err(mkerr("svc.status: helper could not open out file".into()))
            }
            ChildExit::Exited(c) => Err(mkerr(format!("svc.status helper exit {c}"))),
            ChildExit::KilledBySignal(s) => {
                Err(mkerr(format!("svc.status helper killed by signal {s}")))
            }
        }
    }

    /// 从 out 文件解析 helper 回传的 write-with-diff 观测（committed + 三哈希）。
    /// `rollback_id` 由调用方（与 helper 同形计算）提供，不在 JSON 内回传。
    fn parse_write_diff_obs(
        &self,
        out: &str,
        rollback_id: String,
    ) -> std::io::Result<WriteDiffObservation> {
        let mkerr = |m: String| std::io::Error::new(std::io::ErrorKind::Other, m);
        let s = std::fs::read_to_string(out)?;
        let committed = json_bool(&s, "committed").unwrap_or(false);
        let base_hash = json_str(&s, "base_hash")
            .ok_or_else(|| mkerr(format!("observation missing base_hash: {s}")))?;
        let proposed_hash = json_str(&s, "proposed_hash")
            .ok_or_else(|| mkerr(format!("observation missing proposed_hash: {s}")))?;
        let final_hash = json_str(&s, "final_hash")
            .ok_or_else(|| mkerr(format!("observation missing final_hash: {s}")))?;
        Ok(WriteDiffObservation {
            committed,
            rollback_id,
            base_hash,
            proposed_hash,
            final_hash,
        })
    }

    /// 真 write-with-diff：在 confined helper 内运行事务（Landlock 限定到 target 父目录 +
    /// shadow 目录读写 + seccomp default-deny）。父进程预建 `shadow_root/{rollback_id}` 并把
    /// proposed 暂存为 `proposed.txt`（沙箱内不创建目录）；`rollback_id` 与冻结 oracle 的
    /// `RollbackHandle.rollback_id` 同形 `rb-{parameter_hash}-{proposed_hash}`。helper 在事务前
    /// 校验 base_hash：不符则不动 target（exit 81 → BaseHashMismatch，保持 oracle 不变量）。
    pub fn run_write_diff(
        &self,
        helper: &str,
        out: &str,
        shadow_root: &str,
        target: &str,
        proposed: &str,
        base_hash: &str,
        parameter_hash: &str,
    ) -> std::io::Result<WriteDiffOutcome> {
        use platform_sys::{ChildExit, SIGSYS};
        let mkerr = |m: String| std::io::Error::new(std::io::ErrorKind::Other, m);

        // 与冻结 oracle 同形：用同一个 content_hash 计算 proposed_hash / rollback_id。
        let proposed_hash = security_execution::rollback::content_hash(proposed);
        let rollback_id = format!("rb-{parameter_hash}-{proposed_hash}");
        let shadow_dir = format!("{shadow_root}/{rollback_id}");
        // 父进程预建 shadow 目录并 stage proposed.txt（沙箱内只读写、不建目录）。
        std::fs::create_dir_all(&shadow_dir)?;
        let proposed_path = format!("{shadow_dir}/proposed.txt");
        std::fs::write(&proposed_path, proposed.as_bytes())?;

        match platform_sys::spawn_and_wait(
            helper,
            &[
                "tool-write-diff",
                out,
                target,
                base_hash,
                &proposed_path,
                &shadow_dir,
            ],
        )? {
            ChildExit::Exited(0) => Ok(WriteDiffOutcome::Committed(
                self.parse_write_diff_obs(out, rollback_id)?,
            )),
            ChildExit::Exited(82) => Ok(WriteDiffOutcome::RollbackPending(
                self.parse_write_diff_obs(out, rollback_id)?,
            )),
            ChildExit::Exited(81) => {
                let s = std::fs::read_to_string(out)?;
                let actual = json_str(&s, "actual_base").ok_or_else(|| {
                    mkerr(format!("base-mismatch observation missing actual_base: {s}"))
                })?;
                Ok(WriteDiffOutcome::BaseHashMismatch {
                    expected: base_hash.to_string(),
                    actual,
                })
            }
            ChildExit::Exited(10) => Ok(WriteDiffOutcome::KernelDenied {
                reason: format!("landlock EACCES writing {target}"),
            }),
            ChildExit::Exited(20) => Err(mkerr("landlock not FullyEnforced — fail-closed".into())),
            ChildExit::Exited(70) => {
                Err(mkerr("write.diff: helper could not open out file".into()))
            }
            ChildExit::Exited(c) => Err(mkerr(format!("write.diff helper exit {c}"))),
            ChildExit::KilledBySignal(s) if s == SIGSYS => Ok(WriteDiffOutcome::KernelDenied {
                reason: format!("seccomp SIGSYS({s}) inside write.diff"),
            }),
            ChildExit::KilledBySignal(s) => {
                Err(mkerr(format!("write.diff helper killed by signal {s}")))
            }
        }
    }

    /// 真 write-with-diff 回滚：在 confined helper 内把 `shadow_root/{rollback_id}/previous.txt`
    /// 写回 target，回读校验 restored_hash == base_hash。
    pub fn run_rollback(
        &self,
        helper: &str,
        out: &str,
        target: &str,
        shadow_root: &str,
        rollback_id: &str,
        base_hash: &str,
    ) -> std::io::Result<RollbackObservation> {
        use platform_sys::ChildExit;
        let mkerr = |m: String| std::io::Error::new(std::io::ErrorKind::Other, m);
        let shadow_dir = format!("{shadow_root}/{rollback_id}");
        match platform_sys::spawn_and_wait(
            helper,
            &["tool-write-rollback", out, target, &shadow_dir, base_hash],
        )? {
            ChildExit::Exited(0) => {
                let s = std::fs::read_to_string(out)?;
                let restored = json_bool(&s, "restored")
                    .ok_or_else(|| mkerr(format!("rollback observation missing restored: {s}")))?;
                let restored_hash = json_str(&s, "restored_hash").ok_or_else(|| {
                    mkerr(format!("rollback observation missing restored_hash: {s}"))
                })?;
                Ok(RollbackObservation {
                    restored,
                    restored_hash,
                })
            }
            ChildExit::Exited(10) => Err(mkerr(format!("landlock EACCES restoring {target}"))),
            ChildExit::Exited(70) => {
                Err(mkerr("rollback: helper could not open out file".into()))
            }
            ChildExit::Exited(c) => Err(mkerr(format!("rollback helper exit {c}"))),
            ChildExit::KilledBySignal(s) => {
                Err(mkerr(format!("rollback helper killed by signal {s}")))
            }
        }
    }

    /// 负面证明：沙箱只授权 `granted` 读写，却尝试写沙箱外的 `forbidden`。内核以
    /// Landlock EACCES 拒绝 => `KernelDenied`；若写成功 => `Confined`（逃逸，调用测试应失败）。
    pub fn run_write_denied(
        &self,
        helper: &str,
        out: &str,
        granted: &str,
        forbidden: &str,
        content: &str,
    ) -> std::io::Result<EnforcementOutcome> {
        use platform_sys::{ChildExit, SIGSYS};
        let mkerr = |m: String| std::io::Error::new(std::io::ErrorKind::Other, m);
        match platform_sys::spawn_and_wait(
            helper,
            &["tool-write-denied", out, granted, forbidden, content],
        )? {
            ChildExit::Exited(10) => Ok(EnforcementOutcome::KernelDenied {
                reason: format!("landlock: write of {forbidden} outside {granted} denied (EACCES)"),
            }),
            ChildExit::Exited(0) => Ok(EnforcementOutcome::Confined), // 逃逸：调用测试应失败
            ChildExit::Exited(20) => Err(mkerr("landlock not FullyEnforced — fail-closed".into())),
            ChildExit::Exited(70) => {
                Err(mkerr("write.denied: helper could not open out file".into()))
            }
            ChildExit::Exited(c) => Err(mkerr(format!("write.denied helper exit {c}"))),
            ChildExit::KilledBySignal(s) if s == SIGSYS => {
                Err(mkerr(format!("write.denied SIGSYS({s}) — unexpected")))
            }
            ChildExit::KilledBySignal(s) => {
                Err(mkerr(format!("write.denied helper killed by signal {s}")))
            }
        }
    }
}

// ===== 真服务监督（ServiceSupervisor）：over platform_sys，forbid unsafe =====

/// 受监督服务的规格（被监督的 workload 是 `sandbox_probe service-sleep`，直接进程）。
#[derive(Debug, Clone)]
pub struct ServiceSpec {
    /// helper 可执行路径（`sandbox_probe`，承载 `service-sleep` 模式）。
    pub helper: String,
    /// 服务写入心跳的 health 文件路径（首拍即落盘，供 await_health 轮询）。
    pub health_file: String,
    /// 记录当前实例 pid 的文件路径。
    pub pid_file: String,
    /// 服务自然存活秒数（取够长，测试用 fail()/restart() 主动杀，避免自然退出）。
    pub secs: u64,
}

/// 一次 svc.status 真探活的观测。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceStatus {
    /// 当前实例 pid。
    pub pid: i32,
    /// 宿主 /proc/<pid> 是否存在（已 reap 的进程 => false）。
    pub alive: bool,
    /// health 文件首行（心跳计数；缺失为空）。
    pub heartbeat: String,
}

/// 真服务监督：经 [`platform_sys`] 拉起 / 探活 / 杀掉 / 重启一个直接子进程服务。
/// 不施加沙箱（监督的是 workload），svc.status 走宿主 /proc（不进 pid/mount ns）。
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct ServiceSupervisor {
    spec: ServiceSpec,
    current: Option<i32>,
}

#[cfg(target_os = "linux")]
impl ServiceSupervisor {
    pub fn new(spec: ServiceSpec) -> Self {
        Self {
            spec,
            current: None,
        }
    }

    /// 当前实例 pid（未启动则 None）。
    pub fn current_pid(&self) -> Option<i32> {
        self.current
    }

    fn require_current(&self) -> std::io::Result<i32> {
        self.current.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "no current service instance")
        })
    }

    /// 启动一个新实例：spawn_service → 写 pid_file → await_health（有界轮询，超时 Err）。
    pub fn start(&mut self) -> std::io::Result<i32> {
        let pid = self.spawn_instance()?;
        self.current = Some(pid);
        Ok(pid)
    }

    /// 真探活：alive = 宿主 /proc/<pid> 存在；heartbeat = health 文件首行。
    pub fn status(&self) -> std::io::Result<ServiceStatus> {
        let pid = self.require_current()?;
        let alive = std::path::Path::new(&format!("/proc/{pid}")).exists();
        let heartbeat = std::fs::read_to_string(&self.spec.health_file)
            .ok()
            .and_then(|s| s.lines().next().map(str::to_string))
            .unwrap_or_default();
        Ok(ServiceStatus {
            pid,
            alive,
            heartbeat,
        })
    }

    /// 模拟服务挂掉：SIGKILL 当前实例并回收 zombie（否则 /proc/<pid> 残留致 alive 误判）。
    pub fn fail(&mut self) -> std::io::Result<()> {
        let pid = self.require_current()?;
        // kill 命中 zombie 也返回 Ok；命中已 reap 的 pid 则 ESRCH（视为已死）。
        match platform_sys::kill(pid, platform_sys::SIGKILL) {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => return Ok(()),
            Err(e) => return Err(e),
        }
        Self::reap_bounded(pid, 200)?;
        Ok(())
    }

    /// 重启（**消费 token** —— 参数即 consume-once 的执行许可证明）：先优雅终止旧实例并
    /// **在 spawn 新实例之前阻塞回收**（否则 /proc/old 残留导致 alive 误判），再拉起新实例、
    /// 更新 pid_file 与 current、await_health，返回新 pid。
    pub fn restart(&mut self, token: ApprovalToken) -> std::io::Result<i32> {
        let _consumed = token; // consume-once：拿到此参数即证明 policy gate 已放行。
        let old = self.require_current()?;
        // 优雅终止；若旧实例已死（fail() 已回收）则 ESRCH，直接进入重启。
        let already_gone = match platform_sys::kill(old, platform_sys::SIGTERM) {
            Ok(()) => false,
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => true,
            Err(e) => return Err(e),
        };
        if !already_gone {
            // 宽限期内非阻塞轮询回收；超时则 SIGKILL + 阻塞回收，确保 old 在 spawn 前已 reaped。
            if !Self::reap_bounded(old, 100)? {
                let _ = platform_sys::kill(old, platform_sys::SIGKILL);
                match platform_sys::wait_child(old) {
                    Ok(_) => {}
                    Err(e) if e.raw_os_error() == Some(libc::ECHILD) => {}
                    Err(e) => return Err(e),
                }
            }
        }
        // old 已回收（/proc/old 消失），拉起新实例。
        let new = self.spawn_instance()?;
        self.current = Some(new);
        Ok(new)
    }

    /// 测试清理：杀掉并回收当前实例（无僵尸泄漏），清空 current。Drop 为安全网。
    pub fn shutdown(&mut self) -> std::io::Result<()> {
        if let Some(pid) = self.current.take() {
            match platform_sys::kill(pid, platform_sys::SIGKILL) {
                Ok(()) => {
                    Self::reap_bounded(pid, 200)?;
                }
                Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// 拉起一个新 `service-sleep` 实例：先清陈旧心跳（使 await_health 有意义）→
    /// spawn_service → 写 pid_file → await_health。
    fn spawn_instance(&self) -> std::io::Result<i32> {
        let _ = std::fs::remove_file(&self.spec.health_file);
        let secs = self.spec.secs.to_string();
        let pid = platform_sys::spawn_service(
            &self.spec.helper,
            &["service-sleep", &self.spec.health_file, &secs],
        )?;
        std::fs::write(&self.spec.pid_file, pid.to_string())?;
        self.await_health()?;
        Ok(pid)
    }

    /// 有界轮询等待 health 文件出现且非空（服务就绪）；超时 => `TimedOut` Err。
    fn await_health(&self) -> std::io::Result<()> {
        for _ in 0..400 {
            if let Ok(s) = std::fs::read_to_string(&self.spec.health_file) {
                if !s.trim().is_empty() {
                    return Ok(());
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "service health did not appear within bound",
        ))
    }

    /// 有界非阻塞回收：轮询 try_wait 直到子进程可 reap（返回 true）或耗尽配额（false）。
    fn reap_bounded(pid: i32, attempts: u32) -> std::io::Result<bool> {
        for _ in 0..attempts {
            if platform_sys::try_wait(pid)?.is_some() {
                return Ok(true);
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        Ok(false)
    }
}

/// 安全网：Drop 时 best-effort 杀掉并回收当前实例，防止测试遗漏导致僵尸泄漏。
#[cfg(target_os = "linux")]
impl Drop for ServiceSupervisor {
    fn drop(&mut self) {
        if let Some(pid) = self.current.take() {
            // kill 命中 zombie 返回 Ok（需 reap）；命中已 reap 的 pid 返回 ESRCH（无需回收）。
            if platform_sys::kill(pid, platform_sys::SIGKILL).is_ok() {
                let _ = Self::reap_bounded(pid, 200);
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
impl LinuxEnforcer {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skeleton_constructs() {
        let _ = LinuxEnforcer::new();
        let denied = EnforcementOutcome::KernelDenied {
            reason: "stub".into(),
        };
        assert!(matches!(denied, EnforcementOutcome::KernelDenied { .. }));
    }

    /// 冻结 read-only profile 的每个 allowed syscall 名都必须能解析（否则
    /// compile_seccomp_allow_csv 会 fail-closed 拒绝整个 profile）。
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn frozen_readonly_allowlist_fully_resolves() {
        for name in [
            "read", "write", "openat", "close", "newfstatat", "mmap", "munmap", "brk",
            "clock_gettime", "rt_sigaction", "rt_sigprocmask", "futex", "exit", "exit_group",
        ] {
            assert!(resolve_syscall_name(name).is_some(), "must resolve {name}");
        }
        assert!(resolve_syscall_name("no_such_syscall").is_none(), "unknown must fail-closed");
    }
}
