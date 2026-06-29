//! early_init 的 `/init` 入口（initramfs，ADR-004 cp7）。详见 crate 文档。
//!
//! 作为 PID1：组 [`EarlyInitConfig`] → [`run_early_init`]（成功经 `exec_replace` 交接、
//! 永不返回）。任何错误路径 best-effort 向 `/dev/console` 写 `AGENTD_DISK_FAIL` 标记后
//! `exit_now(1)`（→ 内核 panic → harness 凭串口 CONTENT 判 FAIL）。绝不 unwrap/println!/panic。
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
fn main() {
    use early_init::{run_early_init, EarlyInitConfig};
    use std::io::Write;

    // PID1 串口标记：best-effort，写失败一律忽略（println!/unwrap 触发 panic = 内核 panic）。
    fn mark(line: &str) {
        if let Ok(mut c) = std::fs::OpenOptions::new().write(true).open("/dev/console") {
            let _ = writeln!(c, "{line}");
            let _ = c.flush();
        }
    }

    // 必须是 PID 1（initramfs /init）。
    if platform_sys::getpid() != 1 {
        platform_sys::exit_now(1);
    }

    let cfg = EarlyInitConfig {
        proc_target: "/proc".to_string(),
        dev_target: "/dev".to_string(),
        newroot: "/newroot".to_string(),
        root_dev: "/dev/vda2".to_string(),
        state_dev: Some("/dev/vda3".to_string()),
        state_mount: "/var/lib/agentos".to_string(),
        init_path: "/sbin/init".to_string(),
        // Path A：宿主内核 virtio_blk/ext4=m，按依赖序加载 .ko.xz（实测可加载）。
        // 依赖序：virtio_blk(无依赖)；ext4 需 crc16+mbcache+jbd2；metadata_csum 需 crc32c。
        modules: vec![
            "/mods/virtio_blk.ko.xz".to_string(),
            "/mods/crc16.ko.xz".to_string(),
            "/mods/crc32c_generic.ko.xz".to_string(),
            "/mods/mbcache.ko.xz".to_string(),
            "/mods/jbd2.ko.xz".to_string(),
            "/mods/ext4.ko.xz".to_string(),
        ],
    };

    // 成功永不返回（exec_replace 交接给磁盘 /sbin/init）。run_early_init 返回 Result<Infallible>，
    // Ok 不可构造，故 match 只有 Err 臂即穷尽（避免 irrefutable if-let warning）。
    let Err(e) = run_early_init(&cfg);
    mark(&format!(
        "AGENTD_DISK_FAIL stage=early-init errno={}",
        e.raw_os_error().unwrap_or(-1)
    ));
    platform_sys::exit_now(1);
}

#[cfg(not(target_os = "linux"))]
fn main() {
    std::process::exit(2);
}
