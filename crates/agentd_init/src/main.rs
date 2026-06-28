//! agentd_init —— 真实 PID1 / init（ADR-004 D3.2 / D5 / cp4）。
//!
//! 目标形态：最小 static-musl appliance 的唯一 PID1。boot（D5）把内核拓扑交给
//! 本进程后，调用 [`agentd_init::run_pid1`] 进入真 init 序列：挂载 /proc /sys /dev
//! → no_new_privs → 屏蔽 SIGCHLD + signalfd → fork 受监督子进程托管运行循环 →
//! 父进程进入永不返回的 signalfd 驱动回收循环。
#![forbid(unsafe_code)]

use agentd_init::{run_pid1, Pid1Config};

fn main() -> std::io::Result<()> {
    let pid = platform_sys::getpid();
    if pid != 1 {
        // 真 init 必须是 PID 1；否则回收语义（孤儿 re-parent 到 1 号）不成立。
        // 打印诊断后以非 0 退出，绝不伪装成功（Fix, don't hide）。
        eprintln!("agentd_init: refusing to run as non-PID1 (pid={pid})");
        std::process::exit(1);
    }
    // 生产形态：回收循环永不返回；run_pid1 只在 Err（某步内核失败）时返回。
    run_pid1(&Pid1Config::production())?;
    unreachable!("production run_pid1 reap loop never returns");
}
