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
