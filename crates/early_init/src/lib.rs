//! early_init —— AIOS 的早期 init（initramfs `/init`，ADR-004 cp7）。
//!
//! GRUB 加载 kernel + 本 initramfs 后，内核 exec 本进程为 **PID 1**（在 initramfs 的
//! ramfs/tmpfs 根上）。本进程唯一职责：挂内核 fs → 加载块/文件系统模块（宿主内核
//! `virtio_blk`/`ext4`=m）→ 挂磁盘 ext4 根 → **switch_root** 到磁盘根 → `exec_replace`
//! 交接给磁盘 `/sbin/init`（agentd_init 继承 PID1，系统始终只有一个 PID1 映像）。
//!
//! 从 initramfs 的 rootfs **不能** `pivot_root`（恒 EINVAL，无父挂载）——用 switch_root 序列。
//! 模块列表为空时（vendored builtin-ext4 内核）模块加载是 no-op，同一代码路径两用。
//!
//! 保持 `#![forbid(unsafe_code)]`：一切 syscall 经 platform_sys 安全封装。PID1 退出/panic
//! = 内核 panic，故错误经返回值上报、由 main 写串口 FAIL 标记后 `exit_now`，绝不 unwrap/panic。
#![forbid(unsafe_code)]

use std::io;

/// early_init 序列配置。
#[derive(Debug, Clone)]
pub struct EarlyInitConfig {
    /// `/proc` 挂载点（initramfs 内，用于读 `/proc/cmdline`）。
    pub proc_target: String,
    /// `/dev` 挂载点（devtmpfs，模块加载后 `/dev/vdaN` 出现于此）。
    pub dev_target: String,
    /// 磁盘根挂载点（initramfs 内预建的空目录，如 `/newroot`）。
    pub newroot: String,
    /// 磁盘根设备（如 `/dev/vda2`）；可被 `/proc/cmdline` 的 `root=` 覆盖。
    pub root_dev: String,
    /// 持久状态分区设备（如 `/dev/vda3`）；`None` 则不挂状态分区。
    pub state_dev: Option<String>,
    /// 状态分区挂载点（相对磁盘根，如 `/var/lib/agentos`）。
    pub state_mount: String,
    /// 交接目标（磁盘根上的 `/sbin/init`）。
    pub init_path: String,
    /// 有序 `.ko.xz` 路径（Path A，宿主模块内核）；空 = builtin-ext4 内核（Path B，no-op）。
    pub modules: Vec<String>,
}

/// 从内核 cmdline 取 `root=` token（如 `root=/dev/vda2`）。纯函数，可单测。
/// `PARTUUID=`/`LABEL=` 解析需扫 GPT/udev，minimal initramfs 无 udev，留作后续。
pub fn parse_root_dev(cmdline: &str) -> Option<String> {
    cmdline
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix("root="))
        .map(|s| s.to_string())
}

/// 有界轮询等待设备节点出现（`finit_module(virtio_blk)` 后 `/dev/vdaN` 由 devtmpfs 异步建）。
/// 绝不无限等（hang = harness 超时 FAIL）。
#[cfg(target_os = "linux")]
fn wait_for_dev(dev: &str) -> io::Result<()> {
    for _ in 0..200 {
        if std::path::Path::new(dev).exists() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("device {dev} did not appear after ~2s"),
    ))
}

/// early_init 核心序列。成功时已 `exec_replace` 交接、**永不返回**（返回类型
/// `io::Result<Infallible>` 编码"成功不返回"）；仅在某步失败时返回 `Err`。
#[cfg(target_os = "linux")]
pub fn run_early_init(cfg: &EarlyInitConfig) -> io::Result<std::convert::Infallible> {
    // 0. 私有根传播（否则后续挂载 EINVAL 或泄漏回宿主 mountns）。
    platform_sys::make_root_private()?;
    // 1. 挂 /proc（读 cmdline）+ /dev（devtmpfs，模块加载后 /dev/vdaN 出现于此）。
    platform_sys::mount_proc(&cfg.proc_target)?;
    platform_sys::mount_devtmpfs(&cfg.dev_target)?;
    // 2. 加载根所需模块（Path A，依赖序）。空列表 = builtin 内核（Path B），循环 no-op。
    for m in &cfg.modules {
        platform_sys::load_module_file(m, true)?;
    }
    // 3. 从 cmdline 取 root=（grub.cfg 传入）覆盖默认；解析失败回退 cfg.root_dev。
    let root_dev = std::fs::read_to_string("/proc/cmdline")
        .ok()
        .and_then(|c| parse_root_dev(&c))
        .unwrap_or_else(|| cfg.root_dev.clone());
    // 4. 等设备节点出现（有界）→ 挂磁盘 ext4 根（只读）。
    wait_for_dev(&root_dev)?;
    platform_sys::mount_block(&root_dev, &cfg.newroot, "ext4", true)?;
    // 5. 持久状态分区挂在 newroot 之下（随 switch_root 的 MS_MOVE 整棵迁移）。读写。
    if let Some(sd) = &cfg.state_dev {
        wait_for_dev(sd)?;
        let state_target = format!("{}{}", cfg.newroot, cfg.state_mount);
        platform_sys::mount_block(sd, &state_target, "ext4", false)?;
    }
    // 6. switch_root 到磁盘根（initramfs rootfs 不可 pivot_root=EINVAL）。
    platform_sys::switch_root(&cfg.newroot)?;
    // 7. 交接 PID1 给磁盘 /sbin/init（execv 不 fork，agentd_init 继承 PID1）。仅失败才返回。
    Err(platform_sys::exec_replace(&cfg.init_path, &[&cfg.init_path]))
}

#[cfg(not(target_os = "linux"))]
pub fn run_early_init(_cfg: &EarlyInitConfig) -> io::Result<std::convert::Infallible> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Linux-only"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_root_dev_extracts_device() {
        assert_eq!(
            parse_root_dev("BOOT_IMAGE=/boot/vmlinuz root=/dev/vda2 console=ttyS0 panic=-1"),
            Some("/dev/vda2".to_string())
        );
    }

    #[test]
    fn parse_root_dev_absent_is_none() {
        assert_eq!(parse_root_dev("console=ttyS0 panic=-1"), None);
    }

    #[test]
    fn parse_root_dev_first_token() {
        assert_eq!(
            parse_root_dev("root=/dev/sda1 rw"),
            Some("/dev/sda1".to_string())
        );
    }
}
