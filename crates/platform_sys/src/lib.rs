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

/// `SIGCHLD` —— 子进程状态变更信号；真 PID1 的 reap 循环通过 signalfd 观测它。
#[cfg(target_os = "linux")]
pub const SIGCHLD: i32 = libc::SIGCHLD;
#[cfg(not(target_os = "linux"))]
pub const SIGCHLD: i32 = 17;

/// `SIGTERM` —— 优雅终止信号（服务监督先发 SIGTERM 宽限，再 SIGKILL 兜底）。
#[cfg(target_os = "linux")]
pub const SIGTERM: i32 = libc::SIGTERM;
#[cfg(not(target_os = "linux"))]
pub const SIGTERM: i32 = 15;

/// `SIGKILL` —— 不可捕获的强制终止信号（模拟服务挂掉 / 宽限超时兜底回收）。
#[cfg(target_os = "linux")]
pub const SIGKILL: i32 = libc::SIGKILL;
#[cfg(not(target_os = "linux"))]
pub const SIGKILL: i32 = 9;

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

/// 在 `target` 挂载一个全新的 `sysfs`。flags 禁 suid/dev/exec。
///
/// 注意：在 user namespace 内挂 sysfs 需调用者**拥有**对应的 network namespace
/// （否则 `EPERM`）——真 PID1 在完整特权的根 netns 下不受此限；userns 测试需先
/// `unshare(CLONE_NEWNET)`。
#[cfg(target_os = "linux")]
pub fn mount_sysfs(target: &str) -> io::Result<()> {
    let sysfs_c = CString::new("sysfs").expect("static");
    let target_c =
        CString::new(target).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "nul in path"))?;
    // SAFETY: mount(2) 挂载 sysfs 文件系统，flags 禁 suid/dev/exec，data 为 NULL。
    let rc = unsafe {
        libc::mount(
            sysfs_c.as_ptr(),
            target_c.as_ptr(),
            sysfs_c.as_ptr(),
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

/// 在 `target` 挂载 `devtmpfs`（内核维护的 /dev）。flags 禁 suid。
///
/// 注意：devtmpfs 未标记 `FS_USERNS_MOUNT`，**无法**在任何 user namespace 内挂载
/// （恒 `EPERM`）——仅真 PID1（完整特权、非 userns）可成功。
#[cfg(target_os = "linux")]
pub fn mount_devtmpfs(target: &str) -> io::Result<()> {
    let dev_c = CString::new("devtmpfs").expect("static");
    let target_c =
        CString::new(target).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "nul in path"))?;
    // SAFETY: mount(2) 挂载 devtmpfs，flags 禁 suid，data 为 NULL。
    let rc = unsafe {
        libc::mount(
            dev_c.as_ptr(),
            target_c.as_ptr(),
            dev_c.as_ptr(),
            libc::MS_NOSUID as libc::c_ulong,
            core::ptr::null(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `sigprocmask(SIG_BLOCK, {SIGCHLD})` —— 屏蔽 SIGCHLD 的默认/异步投递，使其只能
/// 经 signalfd 同步消费。**必须在 fork 受监督子进程之前调用**，否则子进程在 reap
/// 循环建立前退出会丢失唤醒。
#[cfg(target_os = "linux")]
pub fn block_sigchld() -> io::Result<()> {
    // SAFETY: sigset_t 为 POD，zeroed 后由 sigemptyset/sigaddset 正确初始化。
    let mut mask: libc::sigset_t = unsafe { core::mem::zeroed() };
    // SAFETY: mask 指向栈上有效 sigset_t。
    unsafe {
        libc::sigemptyset(&mut mask);
        libc::sigaddset(&mut mask, libc::SIGCHLD);
    }
    // SAFETY: 第三参 NULL（不取旧掩码）；mask 有效。
    let rc = unsafe { libc::sigprocmask(libc::SIG_BLOCK, &mask, core::ptr::null_mut()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `signalfd(2)` —— 为 SIGCHLD 创建可读 fd（`SFD_CLOEXEC`）。配合
/// [`block_sigchld`] 使 PID1 用 `read` 同步消费子进程退出事件，再 `reap_all`。
/// 返回 `OwnedFd`（drop 即 close，无 fd 泄漏）。
#[cfg(target_os = "linux")]
pub fn signalfd_sigchld() -> io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    // SAFETY: sigset_t POD，zeroed 后由 sigemptyset/sigaddset 初始化。
    let mut mask: libc::sigset_t = unsafe { core::mem::zeroed() };
    // SAFETY: mask 指向栈上有效 sigset_t。
    unsafe {
        libc::sigemptyset(&mut mask);
        libc::sigaddset(&mut mask, libc::SIGCHLD);
    }
    // SAFETY: signalfd(2)，fd=-1 新建；mask 有效；SFD_CLOEXEC 防 exec 泄漏。
    let fd = unsafe { libc::signalfd(-1, &mask, libc::SFD_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: signalfd 成功返回一个全新拥有的内核 fd，转交 OwnedFd 管理生命周期。
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

/// 从 signalfd 阻塞读取一条 `signalfd_siginfo`，返回其 `ssi_signo`（应为
/// [`SIGCHLD`]）。短读视为错误（不静默吞掉损坏的事件）。
#[cfg(target_os = "linux")]
pub fn read_sigchld(fd: std::os::fd::RawFd) -> io::Result<u32> {
    let sz = core::mem::size_of::<libc::signalfd_siginfo>();
    // SAFETY: signalfd_siginfo 为 POD（全整型字段），zeroed 是合法初值。
    let mut si: libc::signalfd_siginfo = unsafe { core::mem::zeroed() };
    // SAFETY: read(2) 写入 si（恰 sz 字节）；&mut si 指向栈上有效缓冲。
    let n = unsafe { libc::read(fd, (&mut si as *mut libc::signalfd_siginfo).cast(), sz) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if (n as usize) < sz {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short signalfd read",
        ));
    }
    Ok(si.ssi_signo)
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

/// 施加 Landlock 读 + 写授权（多目录）。`read_paths` 仅授予读，`write_paths` 授予写
/// （含创建/截断，V1 由 WriteFile 管，无独立 Truncate 权限）。同时需读写的目录必须同时
/// 出现在两个切片里。handle_access **必须**是 read|write 的并集——未 handle 的访问类型
/// 不受 Landlock 限制。Fail-closed：仅 FullyEnforced + no_new_privs 返回 `Ok(true)`。
#[cfg(target_os = "linux")]
pub fn apply_landlock(read_paths: &[&str], write_paths: &[&str]) -> io::Result<bool> {
    // 注意：`from_read`/`from_write` 经 `AccessFs` 的 trait 实现解析，无需在此 `use Access`
    // （只读版用 `from_all` 才需要 `Access` trait；本函数不用，故省去以免 unused 告警）。
    use landlock::{
        AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
        ABI,
    };

    let abi = ABI::V1;
    // 必须 union：只 handle read 会让 write 不受限（反之亦然），未 handle 的权限恒放行。
    let handled = AccessFs::from_read(abi) | AccessFs::from_write(abi);
    let mut rs = Ruleset::default()
        .handle_access(handled)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("landlock handle: {e}")))?
        .create()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("landlock create: {e}")))?;
    for p in read_paths {
        let fd = PathFd::new(p)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("landlock path: {e}")))?;
        rs = rs
            .add_rule(PathBeneath::new(fd, AccessFs::from_read(abi)))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("landlock rule: {e}")))?;
    }
    for p in write_paths {
        let fd = PathFd::new(p)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("landlock path: {e}")))?;
        rs = rs
            .add_rule(PathBeneath::new(fd, AccessFs::from_write(abi)))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("landlock rule: {e}")))?;
    }
    let status = rs
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

/// `kill(2)`：向 `pid` 发送信号 `sig`。`-1` => last_os_error（如 `ESRCH` 表示进程
/// 已不存在，调用方据此判定服务已死）。
#[cfg(target_os = "linux")]
pub fn kill(pid: i32, sig: i32) -> io::Result<()> {
    // SAFETY: kill(2) 仅接受整型 pid/signal，无内存副作用。
    let rc = unsafe { libc::kill(pid, sig) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `fork` + `execve` 一个 helper 程序并**立即返回子 pid（父不 wait）**：用于把一个
/// 长期存活的工作负载（受监督的真服务）拉起为直接子进程。子进程在 `fork` 后**只**
/// 做 `execve`（async-signal-safe），失败则 `_exit(127)`。回收由调用方负责
/// （[`try_wait`] 非阻塞轮询 / [`wait_child`] 阻塞）。即 [`spawn_and_wait`] 去掉 wait。
#[cfg(target_os = "linux")]
pub fn spawn_service(exe: &str, args: &[&str]) -> io::Result<i32> {
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
        // SAFETY: exe_c/argv_ptrs 有效、NUL 结尾；execv 仅在失败时返回（async-signal-safe）。
        unsafe { libc::execv(exe_c.as_ptr(), argv_ptrs.as_ptr()) };
        // SAFETY: noreturn。
        unsafe { ffi::_exit(127) };
    }
    Ok(pid)
}

/// 非阻塞回收：`waitpid(pid, &st, WNOHANG)`。子进程仍在运行（返回 0）或已无该子进程
/// （`ECHILD`）=> `Ok(None)`；`EINTR` => 重试；已结束 => `Ok(Some(ChildExit))`。
#[cfg(target_os = "linux")]
pub fn try_wait(pid: i32) -> io::Result<Option<ChildExit>> {
    loop {
        let mut status: core::ffi::c_int = 0;
        // SAFETY: status 指向栈上有效 c_int；WNOHANG 使其非阻塞。
        let w = unsafe { ffi::waitpid(pid, &mut status as *mut core::ffi::c_int, libc::WNOHANG) };
        if w < 0 {
            let e = io::Error::last_os_error();
            match e.raw_os_error() {
                Some(c) if c == libc::EINTR => continue,
                Some(c) if c == libc::ECHILD => return Ok(None),
                _ => return Err(e),
            }
        }
        if w == 0 {
            return Ok(None); // 仍在运行，尚不可回收
        }
        if libc::WIFEXITED(status) {
            return Ok(Some(ChildExit::Exited(libc::WEXITSTATUS(status))));
        }
        if libc::WIFSIGNALED(status) {
            return Ok(Some(ChildExit::KilledBySignal(libc::WTERMSIG(status))));
        }
        // stopped/continued：尚未真正退出，视为不可回收。
        return Ok(None);
    }
}

/// `reboot(2)`：以 `cmd` 执行下电/重启/停机。成功时随系统下电**永不返回**，故唯一可达
/// 的返回是失败（如缺 `CAP_SYS_BOOT` => `EPERM`），直接返回 `io::Error`。真 PID1
///（initramfs 内 uid0、初始 namespace）持有 `CAP_SYS_BOOT`。
#[cfg(target_os = "linux")]
pub fn reboot(cmd: i32) -> io::Error {
    // SAFETY: reboot(2) 的 libc 单参封装内部填入 LINUX_REBOOT_MAGIC1/MAGIC2，仅接受整型
    // cmd、无内存参数。POWER_OFF/HALT/RESTART 成功随机器关机永不返回；返回即失败。
    unsafe { libc::reboot(cmd) };
    io::Error::last_os_error()
}

/// 便捷封装：`reboot(RB_POWER_OFF)` —— 干净 ACPI 下电，使 QEMU 干净退出（exit 0）。
/// 真 PID1 自检完成后的唯一下电调用点。
#[cfg(target_os = "linux")]
pub fn power_off() -> io::Error {
    reboot(libc::RB_POWER_OFF)
}

// ───── cp7 磁盘/pivot syscall（ADR-004 cp7；仍是唯一 unsafe 边界）─────

/// `statfs(2)` 的 `f_type` 魔数——根 fs 身份证明（反假绿：磁盘 ext4 产 `EXT4_SUPER_MAGIC`，
/// initramfs 的 ramfs/tmpfs 产不出 0xEF53）。
#[cfg(target_os = "linux")]
pub const EXT4_SUPER_MAGIC: i64 = 0xEF53;
#[cfg(target_os = "linux")]
pub const TMPFS_MAGIC: i64 = 0x0102_1994;
#[cfg(target_os = "linux")]
pub const RAMFS_MAGIC: i64 = 0x8584_58f6;

/// `finit_module(2)` flag：模块文件是压缩的（.ko.xz），内核解压（需 `CONFIG_MODULE_DECOMPRESS=y`）。
#[cfg(target_os = "linux")]
pub const MODULE_INIT_COMPRESSED_FILE: i32 = 4;

/// `umount2(2)` flags。
#[cfg(target_os = "linux")]
pub mod umount_flags {
    pub const MNT_FORCE: i32 = libc::MNT_FORCE;
    pub const MNT_DETACH: i32 = libc::MNT_DETACH;
}

/// `mount(2)` 把块设备文件系统（如 ext4 磁盘根）挂到 `target`。
/// flags 仅 `MS_RDONLY`(若 `read_only`) | `MS_NOSUID`——**绝不**设 `MS_NOEXEC`/`MS_NODEV`：
/// 磁盘根必须可 `exec /sbin/init` 且可持有设备节点（与 mount_proc 的 NOEXEC|NODEV 相反，
/// 照抄会让磁盘根不可执行、boot 死在 exec）。
#[cfg(target_os = "linux")]
pub fn mount_block(source_dev: &str, target: &str, fstype: &str, read_only: bool) -> io::Result<()> {
    let src = CString::new(source_dev)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "nul in dev"))?;
    let tgt = CString::new(target)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "nul in target"))?;
    let fst = CString::new(fstype)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "nul in fstype"))?;
    let mut flags: libc::c_ulong = libc::MS_NOSUID;
    if read_only {
        flags |= libc::MS_RDONLY;
    }
    // SAFETY: mount(2) 挂载块设备 fs；source/target/fstype 为有效 NUL 结尾指针，data 为 NULL。
    let rc = unsafe {
        libc::mount(src.as_ptr(), tgt.as_ptr(), fst.as_ptr(), flags, core::ptr::null())
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `mount(source, target, NULL, MS_MOVE, NULL)` —— 把已挂载子树整体迁到新挂载点
/// （子挂载随父子树迁移）。switch_root 的核心：把新根 move 成 `/`。
#[cfg(target_os = "linux")]
pub fn mount_move(source: &str, target: &str) -> io::Result<()> {
    let src = CString::new(source)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "nul in source"))?;
    let tgt = CString::new(target)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "nul in target"))?;
    // SAFETY: mount(2) MS_MOVE；source 已是挂载点、target 为有效 NUL 结尾指针，fstype/data NULL。
    let rc = unsafe {
        libc::mount(
            src.as_ptr(),
            tgt.as_ptr(),
            core::ptr::null(),
            libc::MS_MOVE as libc::c_ulong,
            core::ptr::null(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `chroot(2)`。
#[cfg(target_os = "linux")]
pub fn chroot(path: &str) -> io::Result<()> {
    let p = CString::new(path)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "nul in path"))?;
    // SAFETY: chroot(2) 仅接受有效 NUL 结尾路径指针。
    let rc = unsafe { libc::chroot(p.as_ptr()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `chdir(2)`。
#[cfg(target_os = "linux")]
pub fn chdir(path: &str) -> io::Result<()> {
    let p = CString::new(path)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "nul in path"))?;
    // SAFETY: chdir(2) 仅接受有效 NUL 结尾路径指针。
    let rc = unsafe { libc::chdir(p.as_ptr()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `umount2(2)`。
#[cfg(target_os = "linux")]
pub fn umount2(target: &str, flags: i32) -> io::Result<()> {
    let t = CString::new(target)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "nul in target"))?;
    // SAFETY: umount2(2) 接受有效 NUL 结尾路径 + flag 整数。
    let rc = unsafe { libc::umount2(t.as_ptr(), flags) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// 从 initramfs（ramfs/tmpfs 根）切到真磁盘根的 **switch_root 序列**：
/// `chdir(new_root)` → `mount(".","/",MS_MOVE)` → `chroot(".")` → `chdir("/")`。
/// 不能用 [`pivot_root`]——initramfs 的 `/` 是 rootfs、无父挂载，pivot_root 恒 `EINVAL`。
#[cfg(target_os = "linux")]
pub fn switch_root(new_root: &str) -> io::Result<()> {
    chdir(new_root)?;
    mount_move(".", "/")?;
    chroot(".")?;
    chdir("/")?;
    Ok(())
}

/// `pivot_root(2)`（经 `SYS_pivot_root`，libc 无包装）。
///
/// **注意**：从 initramfs 的 rootfs 调用恒返回 `EINVAL`（rootfs 无父挂载、不可移动）；
/// boot 路径用 [`switch_root`]。本封装保留给 cp5 沙箱子进程的**真挂载** rootfs 切换
/// （旧根是真挂载、可干净 umount，pivot_root 比 switch_root 更安全）。
#[cfg(target_os = "linux")]
pub fn pivot_root(new_root: &str, put_old: &str) -> io::Result<()> {
    let new = CString::new(new_root)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "nul in new_root"))?;
    let old = CString::new(put_old)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "nul in put_old"))?;
    // SAFETY: pivot_root(2) 经 syscall(SYS_pivot_root)；两参为有效 NUL 结尾路径指针。
    let rc = unsafe { libc::syscall(libc::SYS_pivot_root, new.as_ptr(), old.as_ptr()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `statfs(2)`：返回 `path` 所在文件系统的 `f_type` 魔数（ext4=`EXT4_SUPER_MAGIC`）。
/// 反假绿用：运行时证明根 fs 真是磁盘 ext4 而非 initramfs ramfs/tmpfs。
#[cfg(target_os = "linux")]
pub fn statfs_type(path: &str) -> io::Result<i64> {
    let p = CString::new(path)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "nul in path"))?;
    // SAFETY: libc::statfs 是 POD，全零是合法初值（紧接着被 statfs(2) 覆写）。
    let mut buf: libc::statfs = unsafe { core::mem::zeroed() };
    // SAFETY: statfs(2)；path 为有效 NUL 结尾指针，buf 指向栈上有效 statfs。
    let rc = unsafe { libc::statfs(p.as_ptr(), &mut buf) };
    if rc == 0 {
        Ok(buf.f_type as i64)
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `finit_module(2)`（经 `SYS_finit_module`）：从已打开 fd 加载内核模块。
/// `flags` 含 [`MODULE_INIT_COMPRESSED_FILE`] 时直接吃 .ko.xz（需 `CONFIG_MODULE_DECOMPRESS=y`）。
#[cfg(target_os = "linux")]
pub fn finit_module(module_fd: std::os::fd::RawFd, params: &str, flags: i32) -> io::Result<()> {
    let p = CString::new(params)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "nul in params"))?;
    // SAFETY: finit_module(2) 经 syscall；fd 为已打开模块文件，params 为有效 NUL 结尾指针。
    let rc = unsafe { libc::syscall(libc::SYS_finit_module, module_fd, p.as_ptr(), flags) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// 打开模块文件并 `finit_module` 加载之。`compressed=true` 走 .ko.xz 直读。
/// 已加载（`EEXIST`）视为成功（幂等）。
#[cfg(target_os = "linux")]
pub fn load_module_file(path: &str, compressed: bool) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let f = std::fs::File::open(path)?;
    let flags = if compressed { MODULE_INIT_COMPRESSED_FILE } else { 0 };
    match finit_module(f.as_raw_fd(), "", flags) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => Ok(()),
        Err(e) => Err(e),
    }
}

/// `execv(2)` **不 fork**，原地用 `exe` 替换当前进程映像（PID 不变）。
/// 仅在 `execv` 失败时返回 `io::Error`（成功则永不返回）。early_init 用它把 PID1
/// 映像交接给磁盘 `/sbin/init`（agentd_init 继承 PID1，系统始终只有一个 PID1 映像）。
#[cfg(target_os = "linux")]
pub fn exec_replace(exe: &str, args: &[&str]) -> io::Error {
    use core::ffi::c_char;
    let exe_c = match CString::new(exe) {
        Ok(c) => c,
        Err(_) => return io::Error::new(io::ErrorKind::InvalidInput, "nul in exe"),
    };
    let mut argv_owned: Vec<CString> = Vec::with_capacity(args.len() + 1);
    argv_owned.push(exe_c.clone());
    for a in args {
        match CString::new(*a) {
            Ok(c) => argv_owned.push(c),
            Err(_) => return io::Error::new(io::ErrorKind::InvalidInput, "nul in arg"),
        }
    }
    let mut argv_ptrs: Vec<*const c_char> = argv_owned.iter().map(|c| c.as_ptr()).collect();
    argv_ptrs.push(core::ptr::null());
    // SAFETY: execv(2) 替换当前映像；exe_c/argv_ptrs 有效、NUL 结尾、argv 以 NULL 收尾；
    // 仅失败时返回。
    unsafe { libc::execv(exe_c.as_ptr(), argv_ptrs.as_ptr()) };
    io::Error::last_os_error()
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
pub fn mount_sysfs(_target: &str) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Linux-only"))
}
#[cfg(not(target_os = "linux"))]
pub fn mount_devtmpfs(_target: &str) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Linux-only"))
}
#[cfg(not(target_os = "linux"))]
pub fn block_sigchld() -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Linux-only"))
}
#[cfg(not(target_os = "linux"))]
pub fn signalfd_sigchld() -> io::Result<std::os::fd::OwnedFd> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Linux-only"))
}
#[cfg(not(target_os = "linux"))]
pub fn read_sigchld(_fd: std::os::fd::RawFd) -> io::Result<u32> {
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
pub fn apply_landlock(_read_paths: &[&str], _write_paths: &[&str]) -> io::Result<bool> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Linux-only"))
}
#[cfg(not(target_os = "linux"))]
pub fn spawn_and_wait(_exe: &str, _args: &[&str]) -> io::Result<ChildExit> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Linux-only"))
}
#[cfg(not(target_os = "linux"))]
pub fn kill(_pid: i32, _sig: i32) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Linux-only"))
}
#[cfg(not(target_os = "linux"))]
pub fn spawn_service(_exe: &str, _args: &[&str]) -> io::Result<i32> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Linux-only"))
}
#[cfg(not(target_os = "linux"))]
pub fn try_wait(_pid: i32) -> io::Result<Option<ChildExit>> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Linux-only"))
}
#[cfg(not(target_os = "linux"))]
pub fn reboot(_cmd: i32) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "Linux-only")
}
#[cfg(not(target_os = "linux"))]
pub fn power_off() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "Linux-only")
}
#[cfg(not(target_os = "linux"))]
pub const EXT4_SUPER_MAGIC: i64 = 0xEF53;
#[cfg(not(target_os = "linux"))]
pub const TMPFS_MAGIC: i64 = 0x0102_1994;
#[cfg(not(target_os = "linux"))]
pub const RAMFS_MAGIC: i64 = 0x8584_58f6;
#[cfg(not(target_os = "linux"))]
pub const MODULE_INIT_COMPRESSED_FILE: i32 = 4;
#[cfg(not(target_os = "linux"))]
pub mod umount_flags {
    pub const MNT_FORCE: i32 = 1;
    pub const MNT_DETACH: i32 = 2;
}
#[cfg(not(target_os = "linux"))]
pub fn mount_block(_source_dev: &str, _target: &str, _fstype: &str, _read_only: bool) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Linux-only"))
}
#[cfg(not(target_os = "linux"))]
pub fn mount_move(_source: &str, _target: &str) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Linux-only"))
}
#[cfg(not(target_os = "linux"))]
pub fn chroot(_path: &str) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Linux-only"))
}
#[cfg(not(target_os = "linux"))]
pub fn chdir(_path: &str) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Linux-only"))
}
#[cfg(not(target_os = "linux"))]
pub fn umount2(_target: &str, _flags: i32) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Linux-only"))
}
#[cfg(not(target_os = "linux"))]
pub fn switch_root(_new_root: &str) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Linux-only"))
}
#[cfg(not(target_os = "linux"))]
pub fn pivot_root(_new_root: &str, _put_old: &str) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Linux-only"))
}
#[cfg(not(target_os = "linux"))]
pub fn statfs_type(_path: &str) -> io::Result<i64> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Linux-only"))
}
#[cfg(not(target_os = "linux"))]
pub fn finit_module(_module_fd: std::os::fd::RawFd, _params: &str, _flags: i32) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Linux-only"))
}
#[cfg(not(target_os = "linux"))]
pub fn load_module_file(_path: &str, _compressed: bool) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Linux-only"))
}
#[cfg(not(target_os = "linux"))]
pub fn exec_replace(_exe: &str, _args: &[&str]) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "Linux-only")
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

    // SIGCHLD 屏蔽 + signalfd 创建是确定性的，可在多线程 test harness 里安全验证。
    // 完整的 “子进程退出 → signalfd 可读 → reap” 闭环需单线程 PID1 进程，由
    // agentd_init 的 boot_probe 集成测试覆盖（避免 harness 多线程下的信号投递竞态）。
    #[cfg(target_os = "linux")]
    #[test]
    fn block_sigchld_and_signalfd_create_ok() {
        use std::os::fd::AsRawFd;
        block_sigchld().expect("block SIGCHLD");
        let fd = signalfd_sigchld().expect("create signalfd");
        assert!(fd.as_raw_fd() >= 0, "signalfd must be a valid descriptor");
    }

    /// spawn_service 返回的子 pid 在被信号杀后可经 try_wait 非阻塞回收（无僵尸泄漏）。
    #[cfg(target_os = "linux")]
    #[test]
    fn spawn_service_kill_and_try_wait_reaps() {
        let pid = spawn_service("/bin/sleep", &["100"]).expect("spawn sleeper");
        assert!(pid > 0, "parent must observe a real child pid");
        // 进程存活时 try_wait 返回 None（仍在运行）。
        assert_eq!(try_wait(pid).expect("try_wait running"), None);
        kill(pid, SIGKILL).expect("kill sleeper");
        // SIGKILL 后有界轮询直到回收（zombie 变为可 reap）。
        let mut reaped = None;
        for _ in 0..200 {
            if let Some(exit) = try_wait(pid).expect("try_wait reap") {
                reaped = Some(exit);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(
            reaped,
            Some(ChildExit::KilledBySignal(SIGKILL)),
            "SIGKILL'd child must be reaped as KilledBySignal(SIGKILL)"
        );
    }
}
