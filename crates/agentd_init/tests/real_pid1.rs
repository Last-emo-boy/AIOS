//! 真 PID1 init 序列集成测试（ADR-004 cp4）。
//!
//! 启动 init_probe，它自身进入 user+pid+mount namespace，其 fork 的 child 成为
//! 新 pidns 的 PID 1 并执行真 init 序列（getpid()==1 / mount /proc / reap 孤儿）。
//! 退出码 0 = 行为正确；任何非 0 = 某步失败（init_probe 不伪造绿灯）。
#![cfg(target_os = "linux")]

#[test]
fn agentd_init_acts_as_real_pid1() {
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_init_probe"))
        .status()
        .expect("spawn init_probe");
    assert_eq!(
        status.code(),
        Some(0),
        "real PID1 init sequence (getpid==1 / mount /proc / reap orphans) failed: {status:?}"
    );
}
