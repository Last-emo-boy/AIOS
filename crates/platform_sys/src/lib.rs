//! platform_sys —— AgentOS 的内核系统调用边界（ADR-004 D1）。
//!
//! 设计约束：
//! - 本 crate 是 workspace 中**唯一**允许直接 libc/syscall FFI 或包含
//!   syscall `unsafe` 的 crate；其余 crate 一律 `#![forbid(unsafe_code)]`。
//! - 对外只暴露安全、可失败的封装（`io::Result`）；每个 `unsafe` 块都带
//!   `// SAFETY:` 说明，并由真内核测试覆盖。
//! - 沙箱施加走 **execve-based confined helper** 模式：`spawn_and_wait` 只在
//!   `fork` 后立刻 `execve`（async-signal-safe），由全新单线程映像在内部
//!   apply seccomp/Landlock —— 不在 fork 后的子进程里跑可能分配的库代码。
//! - seccomp 用受审计的 `seccompiler`（default-deny allowlist，arch 由 cfg 派生）；
//!   Landlock 用 `landlock` crate 并 **fail-closed**（仅 FullyEnforced 才算成功）。

use std::io;

#[cfg(target_os = "linux")]
mod ffi {
    use core::ffi::c_int;
    // ADR-004 D1：直接绑定内核入口。
    unsafe extern "C" {
        pub fn getpid() -> c_int;
        pub fn fork() -> c_int;
        pub fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
        pub fn _exit(status: c_int) -> !;
        // cp4 待补：mount, umount2, pivot_root, setns, clone3, unshare(via clone), reboot 等。
    }
}

/// 子进程结局：正常退出，或被信号终止（seccomp `KillProcess` => `SIGSYS`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildExit {
    Exited(i32),
    KilledBySignal(i32),
}

/// `SIGSYS` —— 内核对 seccomp `KillProcess` 违例发出的信号。
#[cfg(target_os = "linux")]
pub const SIGSYS: i32 = libc::SIGSYS;
#[cfg(not(target_os = "linux"))]
pub const SIGSYS: i32 = 31;

/// 立即退出当前进程（`_exit`，async-signal-safe、不 flush）。供 confined helper
/// 在 apply 沙箱后以最少 syscall 退出。
#[cfg(target_os = "linux")]
pub fn exit_now(code: i32) -> ! {
    // SAFETY: _exit(2) 是 async-signal-safe 且 noreturn。
    unsafe { ffi::_exit(code) }
}

/// 返回调用进程的 PID（验证 FFI 通路 / 供 seccomp 探针触发一次 getpid syscall）。
#[cfg(target_os = "linux")]
pub fn getpid() -> i32 {
    // SAFETY: getpid(2) 无参数、无副作用、永不失败。
    unsafe { ffi::getpid() }
}

/// 当前构建目标对应的 seccomp arch（arch-guard 由 seccompiler 内建，ADR-004 D1）。
#[cfg(target_os = "linux")]
fn target_arch() -> seccompiler::TargetArch {
    #[cfg(target_arch = "x86_64")]
    {
        seccompiler::TargetArch::x86_64
    }
    #[cfg(target_arch = "aarch64")]
    {
        seccompiler::TargetArch::aarch64
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        compile_error!("platform_sys: seccomp TargetArch only wired for x86_64/aarch64")
    }
}

/// 施加一个 **default-deny** 的 seccomp 过滤器：`allowed` 列表内的 syscall 放行，
/// 其余一律 `KillProcess`（ADR-004 D5 的默认拒绝 allowlist 姿态）。经 `seccompiler`
/// 生成（含 arch guard / x32 处理），不手写 BPF。施加到调用线程及其后代。
#[cfg(target_os = "linux")]
pub fn apply_seccomp_allowlist(allowed: &[i64]) -> io::Result<()> {
    use seccompiler::{SeccompAction, SeccompFilter, SeccompRule};
    use std::collections::BTreeMap;

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for &nr in allowed {
        rules.insert(nr, Vec::new()); // 空规则 = 无条件匹配 → match_action(Allow)
    }
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::KillProcess, // 默认（不在 allowlist）→ 内核杀进程
        SeccompAction::Allow,       // allowlist 内 → 放行
        target_arch(),
    )
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("seccomp build: {e}")))?;
    let prog = seccompiler::BpfProgram::try_from(filter)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("seccomp compile: {e}")))?;
    seccompiler::apply_filter(&prog)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("seccomp apply: {e}")))?;
    Ok(())
}

/// 施加 Landlock：仅授权读取 `allowed_dir` 子树，其余文件访问由内核拒绝。
///
/// **Fail-closed**（ADR-004 D5）：仅当 `restrict_self` 报告
/// `RulesetStatus::FullyEnforced` 且 `no_new_privs` 时返回 `Ok(true)`；内核不支持
/// Landlock 时返回 `Ok(false)`（调用方据此硬失败），绝不静默降级为无强制。
#[cfg(target_os = "linux")]
pub fn apply_landlock_readonly(allowed_dir: &str) -> io::Result<bool> {
    use landlock::{
        Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
        RulesetStatus, ABI,
    };

    let abi = ABI::V1;
    let fd = PathFd::new(allowed_dir)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("landlock path: {e}")))?;
    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("landlock handle: {e}")))?
        .create()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("landlock create: {e}")))?
        .add_rule(PathBeneath::new(fd, AccessFs::from_read(abi)))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("landlock rule: {e}")))?
        .restrict_self()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("landlock restrict: {e}")))?;
    Ok(matches!(status.ruleset, RulesetStatus::FullyEnforced) && status.no_new_privs)
}

/// `fork` + `execve` 一个 helper 程序并等待其结束（EINTR-safe）。
///
/// 子进程在 `fork` 后**只**做 `execve`（async-signal-safe），因此 helper 在一个
/// 全新的、单线程的程序映像里施加 seccomp/Landlock —— 根除「在多线程进程 fork
/// 出的子进程里跑可能分配的库代码」这一并发隐患（ADR-004 D1）。
#[cfg(target_os = "linux")]
pub fn spawn_and_wait(exe: &str, args: &[&str]) -> io::Result<ChildExit> {
    use core::ffi::{c_char, c_int};
    use std::ffi::CString;

    let exe_c =
        CString::new(exe).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "nul in exe"))?;
    let mut argv_owned: Vec<CString> = Vec::with_capacity(args.len() + 1);
    argv_owned.push(exe_c.clone());
    for a in args {
        argv_owned.push(
            CString::new(*a)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "nul in arg"))?,
        );
    }
    let mut argv_ptrs: Vec<*const c_char> = argv_owned.iter().map(|c| c.as_ptr()).collect();
    argv_ptrs.push(core::ptr::null());

    // SAFETY: fork(2) 无参数。
    let pid = unsafe { ffi::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        // 子进程：立即 execve（async-signal-safe）。argv 在父进程已完整构建。
        // SAFETY: exe_c / argv_ptrs 指向有效、NUL 结尾的数据；execv 仅在失败时返回。
        unsafe { libc::execv(exe_c.as_ptr(), argv_ptrs.as_ptr()) };
        // execv 失败：
        // SAFETY: _exit noreturn。
        unsafe { ffi::_exit(127) };
    }
    // 父进程：EINTR-safe waitpid。
    loop {
        let mut status: c_int = 0;
        // SAFETY: status 指向栈上有效 c_int。
        let w = unsafe { ffi::waitpid(pid, &mut status as *mut c_int, 0) };
        if w < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        }
        if libc::WIFEXITED(status) {
            return Ok(ChildExit::Exited(libc::WEXITSTATUS(status)));
        }
        if libc::WIFSIGNALED(status) {
            return Ok(ChildExit::KilledBySignal(libc::WTERMSIG(status)));
        }
        // stopped / continued：继续等待最终结局。
    }
}

// ===== 非 Linux host 下的同名 stub（保证 workspace 跨平台可编译）=====

#[cfg(not(target_os = "linux"))]
pub fn exit_now(code: i32) -> ! {
    std::process::exit(code)
}

#[cfg(not(target_os = "linux"))]
pub fn getpid() -> i32 {
    std::process::id() as i32
}

#[cfg(not(target_os = "linux"))]
pub fn apply_seccomp_allowlist(_allowed: &[i64]) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "platform_sys: seccomp is Linux-only",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn apply_landlock_readonly(_allowed_dir: &str) -> io::Result<bool> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "platform_sys: Landlock is Linux-only",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn spawn_and_wait(_exe: &str, _args: &[&str]) -> io::Result<ChildExit> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "platform_sys: spawn_and_wait is Linux-only",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_path_works() {
        assert_eq!(getpid(), std::process::id() as i32);
    }

    /// execve helper 机制：不存在的程序 → 子进程 execv 失败 → Exited(127)。
    /// （安全性：fork 后子进程只 execv，多线程下也无 async-signal-safety 隐患。）
    #[cfg(target_os = "linux")]
    #[test]
    fn spawn_and_wait_reports_exec_failure() {
        match spawn_and_wait("/nonexistent/aios-helper-xyz", &[]) {
            Ok(ChildExit::Exited(127)) => {}
            other => panic!("expected Exited(127) on exec failure, got {other:?}"),
        }
    }
}
