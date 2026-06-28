//! agentd_init —— 真实 PID1 / init 监督器（ADR-004 D3.2 / D5 / cp4）。
//!
//! [`run_pid1`] 是真 init 序列：在（调用方建立的）全新 mount namespace 内挂载
//! `/proc`、`/sys`、`/dev`（devtmpfs）→ `set_no_new_privs` → 屏蔽 SIGCHLD 并建立
//! signalfd → fork 一个受监督子进程托管 [`agent_runtime`] 运行循环 → 父进程进入
//! 由 signalfd 驱动、调用 `reap_all` 的回收循环。
//!
//! 生产形态（[`Pid1Config::production`]）的回收循环**永不返回**；测试形态
//! （`run_once = true`）在受监督子进程被 reap 后返回，使 `cargo test`（非 PID1）
//! 可断言行为而无需真正成为 1 号进程。
//!
//! 所有系统调用经 `platform_sys` 安全封装，本 crate 保持 `#![forbid(unsafe_code)]`。
#![forbid(unsafe_code)]

use std::io;

use agent_runtime::{AgentRuntime, RunState, StepConfiner, StepOutcome};
use platform_sys::ForkResult;

/// 真 PID1 init 序列的配置。
#[derive(Debug, Clone)]
pub struct Pid1Config {
    /// `/proc` 挂载点（反映本进程所在 pidns）。
    pub proc_target: String,
    /// `/sys` 挂载点。
    pub sys_target: String,
    /// `/dev` 挂载点（devtmpfs）。
    pub dev_target: String,
    /// 是否挂 devtmpfs。生产真 PID1 为 `true`；userns 测试为 `false`
    /// （devtmpfs 无法在任何 user namespace 内挂载）。
    pub mount_dev: bool,
    /// 挂载前是否把根传播改为 `MS_REC|MS_PRIVATE`（进入新 mountns 后必需）。
    pub make_private: bool,
    /// `true`：受监督子进程被 reap 后回收循环返回（测试）。
    /// `false`：回收循环永不返回（生产）。
    pub run_once: bool,
}

impl Pid1Config {
    /// 生产真 PID1：挂 /proc /sys /dev，私有根传播，回收循环永不返回。
    pub fn production() -> Self {
        Self {
            proc_target: "/proc".to_string(),
            sys_target: "/sys".to_string(),
            dev_target: "/dev".to_string(),
            mount_dev: true,
            make_private: true,
            run_once: false,
        }
    }

    /// 真开机自检形态（ADR-004 cp4，QEMU 内真 PID1 用）：生产挂载（含真 devtmpfs）+
    /// `run_once`（受监督子进程被 reap 后回收循环返回 [`Pid1Report`]，供 `boot_smoke` bin
    /// 打印 READY 标记并 `power_off`）。仅供初始 namespace 的完整特权 PID 1 使用——userns
    /// 探针挂不了 devtmpfs，故不能复用此形态。
    pub fn boot_smoke() -> Self {
        Self {
            proc_target: "/proc".to_string(),
            sys_target: "/sys".to_string(),
            dev_target: "/dev".to_string(),
            mount_dev: true,
            make_private: true,
            run_once: true,
        }
    }
}

/// 回收循环返回时的事实（仅 `run_once` 形态可达；生产形态永不返回）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pid1Report {
    /// 受监督子进程 PID。
    pub supervised_pid: i32,
    /// 累计 reap 到的进程数（含 re-parented 孤儿）。应 `>= 1`。
    pub reaped: usize,
}

/// 平凡的 `StepConfiner`：永远返回 `Confined`（真后端在 cp3 已由
/// `security_execution_linux::LinuxEnforcer` 实现；此处用于 init 自检一步运行循环）。
struct AlwaysConfined;

impl StepConfiner for AlwaysConfined {
    fn confine(&self, _step_id: &str) -> io::Result<StepOutcome> {
        Ok(StepOutcome::Confined)
    }
}

/// 真 PID1 init 核心序列。
///
/// 前置条件（由调用方建立）：本进程已在全新 mount namespace 内，且应是其 pid
/// namespace 的 PID 1。本函数不做 `unshare`——namespace 拓扑是 boot 阶段（D5）
/// 或测试 helper 的职责。
///
/// 子进程分支调用 `exit_now` 永不返回；父进程分支在 `run_once` 下返回
/// [`Pid1Report`]，否则永不返回（生产 init）。
#[cfg(target_os = "linux")]
pub fn run_pid1(cfg: &Pid1Config) -> io::Result<Pid1Report> {
    // 0. 私有根传播：否则后续挂载会 EINVAL 或泄漏回宿主 mountns。
    if cfg.make_private {
        platform_sys::make_root_private()?;
    }

    // 1. 挂载内核文件系统。/proc 反映本 pidns；/sys 与（可选）devtmpfs 提供设备视图。
    platform_sys::mount_proc(&cfg.proc_target)?;
    platform_sys::mount_sysfs(&cfg.sys_target)?;
    if cfg.mount_dev {
        platform_sys::mount_devtmpfs(&cfg.dev_target)?;
    }

    // 2. no_new_privs：此后 exec 无法获得新特权（seccomp/Landlock 前置条件）。
    platform_sys::set_no_new_privs()?;

    // 3. 屏蔽 SIGCHLD 并建立 signalfd —— 必须在 fork 之前，否则子进程在回收循环
    //    建立前退出会丢失唤醒。
    platform_sys::block_sigchld()?;
    let sigfd = platform_sys::signalfd_sigchld()?;

    // 4. fork 受监督子进程托管运行循环。
    match platform_sys::fork()? {
        ForkResult::Child => {
            // 受监督子进程：跑一步真实运行循环（accept → plan → confine → 封存）。
            // 单线程映像 + 父单线程 → fork 后可安全分配。
            let mut runtime = AgentRuntime::new();
            let state = runtime.run_step("agentd-init", "boot-confine", &AlwaysConfined);
            // Completed = 运行循环按内核结果正确封存；否则非 0 让父进程观测到失败。
            platform_sys::exit_now(if state == RunState::Completed { 0 } else { 70 });
        }
        ForkResult::Parent(supervised_pid) => supervise(sigfd, supervised_pid, cfg.run_once),
    }
}

/// 由 signalfd 驱动的 PID1 回收循环：阻塞读 SIGCHLD → `reap_all`。
///
/// `run_once`：reap 到受监督子进程后返回。生产（`run_once=false`）：永不返回。
#[cfg(target_os = "linux")]
fn supervise(
    sigfd: std::os::fd::OwnedFd,
    supervised_pid: i32,
    run_once: bool,
) -> io::Result<Pid1Report> {
    use std::os::fd::AsRawFd;

    let mut reaped = 0usize;
    loop {
        // 阻塞直到有子进程状态变更事件（SIGCHLD 经 signalfd 同步投递）。
        let signo = platform_sys::read_sigchld(sigfd.as_raw_fd())?;
        if signo != platform_sys::SIGCHLD as u32 {
            // signalfd 只注册了 SIGCHLD；其它信号不应出现，忽略以保持循环健壮。
            continue;
        }
        // reap 所有已退出的子进程（含 re-parented 孤儿），阻塞至 ECHILD。
        reaped += platform_sys::reap_all()?;
        if run_once {
            return Ok(Pid1Report {
                supervised_pid,
                reaped,
            });
        }
        // 生产 init：继续监听下一批子进程退出，永不返回。
    }
}

#[cfg(not(target_os = "linux"))]
pub fn run_pid1(_cfg: &Pid1Config) -> io::Result<Pid1Report> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "run_pid1 is Linux-only",
    ))
}
