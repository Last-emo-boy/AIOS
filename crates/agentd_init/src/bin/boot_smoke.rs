//! boot_smoke —— AIOS appliance 真开机自检 `/init`（ADR-004 cp4）。
//!
//! QEMU 用宿主内核 + 含本二进制为 `/init` 的 initramfs 直接 boot 到真 PID1：本进程作为
//! 初始 namespace 的 **PID 1**（完整特权，非 userns），跑真 [`agentd_init::run_pid1`] 的
//! 生产序列（含真 **devtmpfs** 挂载——userns 探针 `boot_probe` 无法覆盖的增量），受监督子
//! 进程跑完 `agent_runtime` 一步运行循环并被 reap 后，向 `/dev/console` 打印**运行时派生**
//! 的 READY 标记（含真 `fork` 的 pid 与真 `waitpid` 的 reaped 计数，硬编码 stub 无法伪造），
//! 再 [`platform_sys::power_off`] 干净下电使 QEMU 退出。
//!
//! 成功判据是串口 **CONTENT**（退出码不可用——poweroff 与 kernel panic 在 `panic=-1
//! -no-reboot` 下都退 0）：
//!   `AGENTD_BOOT_READY pid=1 supervised_pid=<P> reaped=<N>`（N>=1）出现，
//!   且无 `AGENTD_BOOT_FAIL`、无 `Kernel panic`。
//!
//! PID1 退出/panic = 内核 panic，故任何错误路径都 best-effort 写 `AGENTD_BOOT_FAIL` 标记
//! 后仍 `power_off`，绝不 `return`/`unwrap`/`println!`（防 panic 塌缩成 kernel panic 噪声）。
//! 保持 `#![forbid(unsafe_code)]`，下电只经 `platform_sys` 安全封装。
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
fn main() {
    use agentd_init::{run_pid1, Pid1Config};
    use std::io::Write;

    // /dev/console：run_pid1 挂上 devtmpfs 后才存在；best-effort 打开，写失败一律忽略
    //（PID1 内 println!/unwrap 触发 panic = 内核 panic）。内核 panic 文本经 console=ttyS0
    // 驱动直达串口、独立于此 fd，故失败始终可观测。
    fn mark(line: &str) {
        if let Ok(mut c) = std::fs::OpenOptions::new().write(true).open("/dev/console") {
            let _ = writeln!(c, "{line}");
            let _ = c.flush();
        }
    }

    // 必须是 PID 1，否则回收语义（孤儿 re-parent 到 1 号）不成立、power_off 语义危险。
    if platform_sys::getpid() != 1 {
        platform_sys::exit_now(1);
    }

    // 真 PID1 生产序列：make_private + 挂 /proc /sys /dev(真 devtmpfs) → no_new_privs →
    // signalfd → fork 受监督子进程跑一步运行循环 → run_once 使回收循环 reap 后返回 Report。
    match run_pid1(&Pid1Config::boot_smoke()) {
        Ok(report) => mark(&format!(
            "AGENTD_BOOT_READY pid=1 supervised_pid={} reaped={}",
            report.supervised_pid, report.reaped
        )),
        Err(e) => mark(&format!(
            "AGENTD_BOOT_FAIL stage=init-seq errno={}",
            e.raw_os_error().unwrap_or(-1)
        )),
    }

    // 干净下电：成功随系统关机永不返回。返回即下电失败 → best-effort 记录后兜底退出。
    // PID1 退出 = 内核 panic，会被 harness 凭 CONTENT 判 FAIL，绝不塌缩成假绿。
    let err = platform_sys::power_off();
    mark(&format!(
        "AGENTD_BOOT_FAIL stage=poweroff errno={}",
        err.raw_os_error().unwrap_or(-1)
    ));
    platform_sys::exit_now(1);
}

#[cfg(not(target_os = "linux"))]
fn main() {
    std::process::exit(2);
}
