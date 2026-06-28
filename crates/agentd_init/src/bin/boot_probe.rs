//! boot_probe —— 真 PID1 监督器 [`agentd_init::run_pid1`] 的内核级验证（ADR-004 cp4）。
//!
//! 由集成测试以普通 fork+exec 启动（execve 后单线程映像），自身进入
//! user+pid+mount+net namespace：
//!   - userns + uid/gid map → 在 userns 内取得 CAP_SYS_ADMIN；
//!   - pidns → 随后 fork 的 child 成为新 pidns 的 **PID 1**；
//!   - mountns → run_pid1 的挂载只影响本 namespace；
//!   - netns → 在 userns 内挂 sysfs 需拥有对应 network namespace（否则 EPERM）。
//!
//! fork 的 child（PID1）调用 `run_pid1`（run_once、mount_dev=false——devtmpfs 无法
//! 在任何 userns 内挂载）。其核心序列被断言成立：getpid()==1、/proc 与 /sys 挂载
//! 成功、fork 的受监督子进程跑完 agent_runtime 一步运行循环并被 reap。
//! 退出码 0 = 行为正确；任何非 0 = 某步失败（不伪造绿灯）。
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
fn main() {
    use agentd_init::{run_pid1, Pid1Config};
    use platform_sys::{clone_flags as cf, ChildExit, ForkResult};

    // STAGE A：user ns（外层 uid 须在 unshare 前取）+ maps + pid + mount + net。
    let uid = platform_sys::getuid();
    let gid = platform_sys::getgid();
    if platform_sys::unshare(cf::CLONE_NEWUSER).is_err() {
        platform_sys::exit_now(23);
    }
    let _ = std::fs::write("/proc/self/setgroups", "deny");
    if std::fs::write("/proc/self/uid_map", format!("0 {uid} 1")).is_err()
        || std::fs::write("/proc/self/gid_map", format!("0 {gid} 1")).is_err()
    {
        platform_sys::exit_now(25);
    }
    // CLONE_NEWNET：拥有 network namespace 才能在 userns 内挂 sysfs；CLONE_NEWNS：
    // 全新 mountns 供 run_pid1 挂载；CLONE_NEWPID：使下面 fork 的 child 成为 PID1。
    if platform_sys::unshare(cf::CLONE_NEWPID | cf::CLONE_NEWNS | cf::CLONE_NEWNET).is_err() {
        platform_sys::exit_now(23);
    }

    // STAGE B：fork，child = 新 pidns 的 PID 1，执行真 init 序列。
    match platform_sys::fork() {
        Err(_) => platform_sys::exit_now(26),
        Ok(ForkResult::Parent(pid)) => match platform_sys::wait_child(pid) {
            Ok(ChildExit::Exited(c)) => platform_sys::exit_now(c),
            _ => platform_sys::exit_now(40),
        },
        Ok(ForkResult::Child) => {
            // 1. 必须是新 pidns 的 PID 1。
            if platform_sys::getpid() != 1 {
                platform_sys::exit_now(50);
            }
            // 2. run_pid1 核心序列（make_private + 挂 /proc /sys；devtmpfs 跳过，因 userns
            //    无法挂；run_once 使回收循环在受监督子进程被 reap 后返回）。
            let cfg = Pid1Config {
                proc_target: "/proc".to_string(),
                sys_target: "/sys".to_string(),
                dev_target: "/dev".to_string(),
                mount_dev: false,
                make_private: true,
                run_once: true,
            };
            match run_pid1(&cfg) {
                // 受监督子进程必须被 reap（>=1）；否则运行循环/回收语义未成立。
                Ok(report) if report.reaped >= 1 => platform_sys::exit_now(0),
                Ok(_) => platform_sys::exit_now(51),
                // run_pid1 的某步内核调用失败（/proc 或 /sys 挂载、signalfd、fork 等）。
                Err(_) => platform_sys::exit_now(60),
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    std::process::exit(2);
}
