//! 真 PID1 监督器 [`agentd_init::run_pid1`] 集成测试（ADR-004 cp4）。
//!
//! 启动 boot_probe：它自身进入 user+pid+mount+net namespace，其 fork 的 child 成为
//! 新 pidns 的 PID 1 并执行 run_pid1 的核心序列——getpid()==1、挂载 /proc 与 /sys
//! 成功、fork 受监督子进程跑完 agent_runtime 一步运行循环并经 signalfd 驱动的回收
//! 循环 reap。退出码 0 = 行为正确；任何非 0 = 某步失败（boot_probe 不伪造绿灯）。
//!
//! 之所以走 exec 出的独立进程而非进程内调用：run_pid1 的回收循环依赖 SIGCHLD 经
//! signalfd 同步投递，需单线程映像；cargo test harness 是多线程，信号投递不确定。
#![cfg(target_os = "linux")]

#[test]
fn run_pid1_mounts_proc_sys_and_reaps_supervised_runtime_child() {
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_boot_probe"))
        .status()
        .expect("spawn boot_probe");
    assert_eq!(
        status.code(),
        Some(0),
        "run_pid1 core sequence (getpid==1 / mount /proc+/sys / supervised agent_runtime \
         child reaped via signalfd) failed: {status:?}"
    );
}
