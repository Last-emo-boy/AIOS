//! platform_sys —— AgentOS 的内核系统调用边界（ADR-004 D1）。
//!
//! 设计约束：
//! - 本 crate 是 workspace 中**唯一**允许直接 libc/syscall FFI 或包含
//!   syscall `unsafe` 的 crate；其余 crate 一律 `#![forbid(unsafe_code)]`。
//! - 对外只暴露安全、可失败的封装（`io::Result`）；每个 `unsafe` 块都带
//!   `// SAFETY:` 说明，并由真内核测试覆盖。
//! - 沙箱施加走 **execve-based confined helper**：`spawn_and_wait` 只在 `fork`
//!   后立刻 `execve`（async-signal-safe）；helper 在全新单线程映像里施加
//!   namespace/mount/seccomp/Landlock（单线程下 fork-child 可安全分配）。
//! - seccomp 用 `seccompiler`（default-deny allowlist），Landlock 用 `landlock`
//!   crate（fail-closed，仅 FullyEnforced 才算施加）。

use std::ffi::CString;
use std::io;

/// Linux namespace 标志位（`unshare(2)` / `clone(2)`）。
#[cfg(target_os = "linux")]
pub mod clone_flags {
    pub const CLONE_NEWNS: i32 = libc::CLONE_NEWNS;
    pub const CLONE_NEWUSER: i32 = libc::CLONE_NEWUSER;
    pub const CLONE_NEWPID: i32 = libc::CLONE_NEWPID;
    pub const CLONE_NEWNET: i32 = libc::CLONE_NEWNET;
    pub const CLONE_NEWIPC: i32 = libc::CLONE_NEWIPC;
    pub const CLONE_NEWUTS: i32 = libc::CLONE_NEWUTS;
}

#[cfg(target_os = "linux")]
mod ffi {
    use core::ffi::c_int;
    unsafe extern "C" {
        pub fn getpid() -> c_int;
        pub fn fork() -> c_int;
        pub fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
        pub fn _exit(status: c_int) -> !;
    }
}

/// 子进程结局：正常退出，或被信号终止（seccomp `KillProcess` => `SIGSYS`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildExit {
    Exited(i32),
    KilledBySignal(i32),
}

/// `fork(2)` 在父/子两侧的返回。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkResult {
    Parent(i32),
    Child,
}

/// `SIGSYS` —— 内核对 seccomp `KillProcess` 违例发出的信号。
#[cfg(target_os = "linux")]
pub const SIGSYS: i32 = libc::SIGSYS;
#[cfg(not(target_os = "linux"))]
pub const SIGSYS: i32 = 31;

/// 立即退出（`_exit`，async-signal-safe、不 flush）。
#[cfg(target_os = "linux")]
pub fn exit_now(code: i32) -> ! {
    // SAFETY: _exit(2) async-signal-safe 且 noreturn。
    unsafe { ffi::_exit(code) }
}

/// 返回调用进程的 PID。
#[cfg(target_os = "linux")]
pub fn getpid() -> i32 {
    // SAFETY: getpid(2) 无参数、无副作用、永不失败。
    unsafe { ffi::getpid() }
}

/// 调用进程的真实 UID（用于在新 userns 写 uid_map）。
#[cfg(target_os = "linux")]
pub fn getuid() -> u32 {
    // SAFETY: getuid(2) 无副作用、永不失败。
    unsafe { libc::getuid() }
}

/// 调用进程的真实 GID（用于在新 userns 写 gid_map）。
#[cfg(target_os = "linux")]
pub fn getgid() -> u32 {
    // SAFETY: getgid(2) 无副作用、永不失败。
    unsafe { libc::getgid() }
}

/// `unshare(2)`：把调用线程从指定 namespace 分离。`flags` 由 [`clone_flags`] 组合。
///
/// 注意：`CLONE_NEWPID` 不移动当前进程，只让随后第一个 `fork` 的子进程成为新
/// pidns 的 PID 1。`CLONE_NEWUSER` 在多线程进程中会 `EINVAL` —— 仅可在全新
/// 单线程映像（execve 后的 helper）里调用。
#[cfg(target_os = "linux")]
pub fn unshare(flags: i32) -> io::Result<()> {
    // SAFETY: unshare(2) 仅接受整型标志位。
    let rc = unsafe { libc::unshare(flags) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)` —— 进入新 mountns 后必须调用，
/// 否则后续 `/proc` 挂载会 `EINVAL` 或传播回宿主 mountns。
#[cfg(target_os = "linux")]
pub fn make_root_private() -> io::Result<()> {
    let root = CString::new("/").expect("static");
    // SAFETY: mount(2)，source/fstype/data 为 NULL，target="/"，递归私有传播。
    let rc = unsafe {
        libc::mount(
            core::ptr::null(),
            root.as_ptr(),
            core::ptr::null(),
            (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong,
            core::ptr::null(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// 在 `target` 挂载一个全新的 `proc`。必须由**新 pidns 内**的进程（fork 后的
/// child）执行 —— procfs 反映挂载者所在的 pidns。
#[cfg(target_os = "linux")]
pub fn mount_proc(target: &str) -> io::Result<()> {
    let proc_c = CString::new("proc").expect("static");
    let target_c =
        CString::new(target).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "nul in path"))?;
    // SAFETY: mount(2) 挂载 proc 文件系统，flags 禁 suid/dev/exec，data 为 NULL。
    let rc = unsafe {
        libc::mount(
            proc_c.as_ptr(),
            target_c.as_ptr(),
            proc_c.as_ptr(),
            (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as libc::c_ulong,
            core::ptr::null(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `prctl(PR_SET_NO_NEW_PRIVS, 1)` —— 安装 seccomp / Landlock 的前置条件。
#[cfg(target_os = "linux")]
pub fn set_no_new_privs() -> io::Result<()> {
    // SAFETY: prctl(2) 设置布尔标志，其余参数 0。
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `fork(2)`。子进程分支内只应做 async-signal-safe 操作，除非父进程是单线程
/// （execve helper），此时 fork-child 可安全分配。
#[cfg(target_os = "linux")]
pub fn fork() -> io::Result<ForkResult> {
    // SAFETY: fork(2) 无参数。
    let pid = unsafe { ffi::fork() };
    if pid < 0 {
        Err(io::Error::last_os_error())
    } else if pid == 0 {
        Ok(ForkResult::Child)
    } else {
        Ok(ForkResult::Parent(pid))
    }
}

/// EINTR-safe 等待指定子进程结束。
#[cfg(target_os = "linux")]
pub fn wait_child(pid: i32) -> io::Result<ChildExit> {
    loop {
        let mut status: core::ffi::c_int = 0;
        // SAFETY: status 指向栈上有效 c_int。
        let w = unsafe { ffi::waitpid(pid, &mut status as *mut core::ffi::c_int, 0) };
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
        // stopped/continued：继续等。
    }
}

/// 反复 `waitpid(-1)` reap 所有子进程（含 re-parented 孤儿），返回 reap 数。
/// 供真 PID1 的回收循环使用；阻塞至 `ECHILD`（无更多子进程）。
#[cfg(target_os = "linux")]
pub fn reap_all() -> io::Result<usize> {
    let mut n = 0usize;
    loop {
        let mut status: core::ffi::c_int = 0;
        // SAFETY: waitpid(-1) 等待任意子进程；status 指向栈上有效 c_int。
        let w = unsafe { ffi::waitpid(-1, &mut status as *mut core::ffi::c_int, 0) };
        if w < 0 {
            let e = io::Error::last_os_error();
            match e.raw_os_error() {
                Some(c) if c == libc::EINTR => continue,
                Some(c) if c == libc::ECHILD => return Ok(n),
                _ => return Err(e),
            }
        }
        n += 1;
    }
}

/// 恢复默认信号处置并重新发出 `sig`，使外层进程链观测到相同的信号
/// （否则 helper 内的 SIGSYS 会塌缩成普通退出码，导致强制测试假绿）。
#[cfg(target_os = "linux")]
pub fn reraise(sig: i32) -> ! {
    // SAFETY: 恢复 SIG_DFL 后 raise；raise 应当立即终止本进程。
    unsafe {
        libc::signal(sig as libc::c_int, libc::SIG_DFL);
        libc::raise(sig as libc::c_int);
    }
    exit_now(126)
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

/// 施加 **default-deny** seccomp 过滤器：`allowed` 内放行，其余 `KillProcess`。
#[cfg(target_os = "linux")]
pub fn apply_seccomp_allowlist(allowed: &[i64]) -> io::Result<()> {
    use seccompiler::{SeccompAction, SeccompFilter, SeccompRule};
    use std::collections::BTreeMap;

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for &nr in allowed {
        rules.insert(nr, Vec::new());
    }
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::KillProcess,
        SeccompAction::Allow,
        target_arch(),
    )
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("seccomp build: {e}")))?;
    let prog = seccompiler::BpfProgram::try_from(filter)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("seccomp compile: {e}")))?;
    seccompiler::apply_filter(&prog)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("seccomp apply: {e}")))?;
    Ok(())
}

/// 施加 Landlock 只读授权（单目录）。Fail-closed：仅 FullyEnforced + no_new_privs
/// 返回 `Ok(true)`；内核不支持返回 `Ok(false)`（调用方硬失败）。
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

/// `fork` + `execve` 一个 helper 程序并等待其结束（EINTR-safe）。子进程在 `fork`
/// 后**只**做 `execve`（async-signal-safe）。
#[cfg(target_os = "linux")]
pub fn spawn_and_wait(exe: &str, args: &[&str]) -> io::Result<ChildExit> {
    use core::ffi::c_char;

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
        // SAFETY: exe_c/argv_ptrs 有效、NUL 结尾；execv 仅在失败时返回。
        unsafe { libc::execv(exe_c.as_ptr(), argv_ptrs.as_ptr()) };
        // SAFETY: noreturn。
        unsafe { ffi::_exit(127) };
    }
    wait_child(pid)
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
pub fn unshare(_flags: i32) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Linux-only"))
}
#[cfg(not(target_os = "linux"))]
pub fn make_root_private() -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Linux-only"))
}
#[cfg(not(target_os = "linux"))]
pub fn mount_proc(_target: &str) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Linux-only"))
}
#[cfg(not(target_os = "linux"))]
pub fn set_no_new_privs() -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Linux-only"))
}
#[cfg(not(target_os = "linux"))]
pub fn fork() -> io::Result<ForkResult> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Linux-only"))
}
#[cfg(not(target_os = "linux"))]
pub fn wait_child(_pid: i32) -> io::Result<ChildExit> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Linux-only"))
}
#[cfg(not(target_os = "linux"))]
pub fn reap_all() -> io::Result<usize> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Linux-only"))
}
#[cfg(not(target_os = "linux"))]
pub fn reraise(code: i32) -> ! {
    std::process::exit(code)
}
#[cfg(not(target_os = "linux"))]
pub fn apply_seccomp_allowlist(_allowed: &[i64]) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Linux-only"))
}
#[cfg(not(target_os = "linux"))]
pub fn apply_landlock_readonly(_allowed_dir: &str) -> io::Result<bool> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Linux-only"))
}
#[cfg(not(target_os = "linux"))]
pub fn spawn_and_wait(_exe: &str, _args: &[&str]) -> io::Result<ChildExit> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Linux-only"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_path_works() {
        assert_eq!(getpid(), std::process::id() as i32);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn spawn_and_wait_reports_exec_failure() {
        match spawn_and_wait("/nonexistent/aios-helper-xyz", &[]) {
            Ok(ChildExit::Exited(127)) => {}
            other => panic!("expected Exited(127) on exec failure, got {other:?}"),
        }
    }
}
