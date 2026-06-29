#!/usr/bin/env bash
# pack-initramfs.sh —— 把一个静态 /init 二进制打包成 QEMU 可直接 `-initrd` 的 initramfs.cpio.gz。
#
# ADR-004 D3.2 / D5 cp4：真 initramfs，/init = 静态 musl `agentd_init`，内核 boot 直进真 PID1。
# 本脚本与「哪个二进制当 /init」解耦：输入任意静态 ELF（生产 agentd_init 或 smoke 变体），
# 输出一份最小、可重复构建的 newc cpio.gz。
#
# 布局（最小）：
#   /init                = 入参二进制，0755（内核默认 exec /init，无需 init=）
#   /proc /sys /dev      = 空挂载点目录（agentd_init 直接 mount(2)，自身不 mkdir → 目录须预建，
#                          否则 mount 目标 ENOENT，PID1 第一步即失败）
#   /dev/console (c 5:1) = 早期串口节点：内核在 exec /init 前打开 /dev/console 接 fd0/1/2。
#                          CONFIG_DEVTMPFS_MOUNT 未开 → 内核不自动挂 devtmpfs，无此静态节点
#                          则 agentd_init 挂上 devtmpfs 之前的所有串口输出（含失败诊断）丢失。
#   /dev/null (c 1:3)    = std 运行时友好的兜底；devtmpfs 挂载后被真实节点覆盖。
#
# root 可选：root 运行会额外建 /dev/console、/dev/null 静态节点（pre-devtmpfs 串口/兜底）；非 root
# （如 CI）跳过设备节点仍产出有效 initramfs —— boot_smoke 在 run_pid1 挂 devtmpfs 之后才开
# /dev/console，且 kernel panic 文本经 console=ttyS0 直达串口、独立于设备节点，故标记与失败均可观测。
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
用法: sudo ./pack-initramfs.sh <static-init-binary> [输出路径]

  <static-init-binary>  作为 /init 的静态 ELF（musl static，无动态解释器）
  [输出路径]            默认 <脚本目录>/initramfs.cpio.gz

环境变量:
  SOURCE_DATE_EPOCH     归一化 mtime 以做可重复构建（默认 0 = 1970-01-01）

构建静态二进制示例:
  cargo build --release --target x86_64-unknown-linux-musl -p agentd_init
  产物: target/x86_64-unknown-linux-musl/release/agentd_init
EOF
  exit 2
}

[ $# -ge 1 ] || usage
INIT_BIN="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${2:-$SCRIPT_DIR/initramfs.cpio.gz}"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"

# 1. 前置校验 —— 失败要真失败，绝不静默兜底（Fix, don't hide）。
[ -f "$INIT_BIN" ]   || { echo "错误: init 二进制不存在: $INIT_BIN" >&2; exit 1; }
IS_ROOT=0; [ "$(id -u)" -eq 0 ] && IS_ROOT=1
[ "$IS_ROOT" -eq 1 ] || echo "提示: 非 root 运行，跳过 /dev/console、/dev/null 静态节点（CI 友好；见文件头说明）" >&2

# 静态校验：initramfs 内没有动态加载器（ld.so / ld-musl），动态链接的 /init 必 ENOENT 死在内核
# exec 那一刻，且无任何输出 —— 提前在打包期拦截。
file_desc="$(file -L "$INIT_BIN")"
echo "$file_desc" | grep -q "ELF"               || { echo "错误: $INIT_BIN 不是 ELF" >&2; exit 1; }
if echo "$file_desc" | grep -q "dynamically linked"; then
  echo "错误: $INIT_BIN 是动态链接；initramfs 无动态加载器，/init 必须静态。" >&2
  echo "      用 x86_64-unknown-linux-musl target 重新构建。" >&2
  exit 1
fi

# 2. 干净 staging 目录。
STAGING="$(mktemp -d "${TMPDIR:-/tmp}/initramfs-stage.XXXXXX")"
trap 'rm -rf "$STAGING"' EXIT

# 3. 铺设最小布局。
install -D -m 0755 "$INIT_BIN" "$STAGING/init"
mkdir -m 0755 "$STAGING/proc" "$STAGING/sys" "$STAGING/dev"
# /newroot：cp7 switch_root 落点（early_init 把磁盘 ext4 根挂这里再 MS_MOVE 成 /）。cp4 无害。
mkdir -m 0755 "$STAGING/newroot"
# 设备节点需 root（mknod）：root 时建，非 root 跳过（boot_smoke 挂 devtmpfs 后自有 /dev/console）。
if [ "$IS_ROOT" -eq 1 ]; then
  mknod -m 0600 "$STAGING/dev/console" c 5 1
  mknod -m 0666 "$STAGING/dev/null"    c 1 3
fi

# 3b. cp7：bundle 根所需内核模块（env MODS=空格分隔模块名，按依赖序，默认空）。宿主内核
#     ext4/virtio_blk=m 时 early_init 须 finit_module 加载它们才能挂磁盘 ext4 根；builtin-ext4
#     内核（CI/vendored）留 MODS 空即 no-op（同一脚本两用）。从 /lib/modules/$(uname -r) 按名
#     找 .ko.xz 复制到 /mods（early_init 以 compressed=true / MODULE_INIT_COMPRESSED_FILE 加载）。
MODS="${MODS:-}"
if [ -n "$MODS" ]; then
  MODDIR="/lib/modules/$(uname -r)"
  mkdir -m 0755 "$STAGING/mods"
  for m in $MODS; do
    ko="$(find "$MODDIR" -name "${m}.ko.xz" 2>/dev/null | head -1)"
    [ -n "$ko" ] || { echo "错误: 模块 ${m}.ko.xz 未在 $MODDIR 找到（内核模块版本不匹配？）" >&2; exit 1; }
    cp "$ko" "$STAGING/mods/"
  done
  echo "  bundled modules (/mods): $MODS" >&2
fi

# 4. 归一化 mtime —— 可重复构建（不依赖打包时刻）。
find "$STAGING" -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

# 5. cpio newc + gzip。
#    --owner=root:root  强制 uid/gid=0，无视 staging 属主 → 可重复。
#    --reproducible     归一化 residing-fs 的 c_dev/c_ino（每次 mktemp 的 inode 不同会破坏可重复）；
#                       只动归属设备号，保留 c_rdev（/dev/console 的 5:1 设备身份不受影响）。
#    sort -z            稳定条目顺序 → 可重复。
#    gzip -n            不写文件名/时间戳进 gzip 头 → 字节级可重复。
( cd "$STAGING" \
    && find . -print0 | LC_ALL=C sort -z \
    | cpio --null --create --format=newc --owner=root:root --reproducible --quiet \
    | gzip -9 -n ) > "$OUT"

echo "OK  initramfs -> $OUT  ($(du -h "$OUT" | cut -f1))"
echo "内容:"
gzip -dc "$OUT" | cpio --list --quiet 2>/dev/null | LC_ALL=C sort | sed 's/^/  /'
