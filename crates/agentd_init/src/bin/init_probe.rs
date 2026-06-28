//! init_probe —— 真 PID1 init 序列验证（ADR-004 cp4）。
//!
//! 由集成测试以普通 fork+exec 启动（execve 后单线程映像），自身进入
//! user+pid+mount namespace；fork 出的 child 成为新 pidns 的 **PID 1**，执行真
//! init 序列并断言其成立：getpid()==1、mount 自己的 /proc、reap re-parented 的
//! 孤儿 zombie。退出码 0 = PID1 行为正确，非 0 = 某步失败（无假绿）。
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
fn main() {
    use platform_sys::{clone_flags as cf, ChildExit, ForkResult};

    // STAGE A：user ns（外层 uid 须在 unshare 前取）+ maps + pid + mount。
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
    if platform_sys::unshare(cf::CLONE_NEWPID | cf::CLONE_NEWNS).is_err() {
        platform_sys::exit_now(23);
    }
    if platform_sys::make_root_private().is_err() {
        platform_sys::exit_now(24);
    }

    // STAGE B：fork，child = 新 pidns 的 PID 1。
    match platform_sys::fork() {
        Err(_) => platform_sys::exit_now(26),
        Ok(ForkResult::Parent(pid)) => match platform_sys::wait_child(pid) {
            Ok(ChildExit::Exited(c)) => platform_sys::exit_now(c),
            _ => platform_sys::exit_now(40),
        },
        Ok(ForkResult::Child) => {
            // ===== 真 PID1 init 序列 =====
            // 1. 必须是新 pidns 的 PID 1。
            if platform_sys::getpid() != 1 {
                platform_sys::exit_now(50);
            }
            // 2. 挂载自己的 /proc（反映新 pidns）。
            if platform_sys::mount_proc("/proc").is_err() {
                platform_sys::exit_now(24);
            }
            // 3. 植入 re-parented 孤儿：fork A；A fork B 后立即退出 → B 成为 PID1 的孤儿。
            match platform_sys::fork() {
                Err(_) => platform_sys::exit_now(53),
                Ok(ForkResult::Child) => match platform_sys::fork() {
                    Ok(ForkResult::Child) => platform_sys::exit_now(0), // B → zombie
                    Ok(ForkResult::Parent(_)) => platform_sys::exit_now(0), // A 退出 → B 孤儿
                    Err(_) => platform_sys::exit_now(0),
                },
                Ok(ForkResult::Parent(_a)) => {
                    // 4. PID1 回收循环：应 reap 到 A（直接子）+ B（re-parented 孤儿）= 2。
                    match platform_sys::reap_all() {
                        Ok(n) if n >= 2 => platform_sys::exit_now(0),
                        Ok(_) => platform_sys::exit_now(51),
                        Err(_) => platform_sys::exit_now(52),
                    }
                }
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    std::process::exit(2);
}
