#!/usr/bin/env bash
# disk-boot-smoke.sh —— 从磁盘镜像真 boot + **真 pivot** 到 ext4 根，机器可验证（cp7 full-pivot）。
#
# 链路：SeaBIOS→GRUB→kernel→initramfs(early_init)→finit_module 加载 virtio_blk/ext4→挂磁盘 ext4 根→
#   switch_root→exec disk_init→真 PID1 自检 + 反假绿→power_off。
#
# 本机无 /dev/kvm → 纯 TCG（慢）。成功判据=串口 CONTENT（退出码不可用：poweroff/panic 都退 0）：
#   1. GRUB 标记；
#   2. AGENTD_DISK_READY 且 root_fstype=ext4（真切到磁盘 ext4，非 initramfs）且 reaped>=1
#      且 manifest_sha 匹配 sidecar（运行时重算 == 构建期 expected）；
#   3. 无 AGENTD_DISK_FAIL / Kernel panic / Attempted to kill init；超时→FAIL，绝不当成功。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMG="${1:-$SCRIPT_DIR/disk.img}"
TIMEOUT="${TIMEOUT:-240}"

[ -f "$IMG" ] || { echo "错误: 缺磁盘镜像 $IMG（先跑 build-disk-image.sh）" >&2; exit 1; }
[ -f "$IMG.manifest.sha256" ] || { echo "错误: 缺 manifest sidecar $IMG.manifest.sha256" >&2; exit 1; }
command -v qemu-system-x86_64 >/dev/null || { echo "错误: 缺 qemu-system-x86_64" >&2; exit 1; }
EXPECT_SHA="$(cat "$IMG.manifest.sha256")"

LOG="$(mktemp)"; trap 'rm -f "$LOG"' EXIT

set +e
timeout --foreground "${TIMEOUT}" \
  qemu-system-x86_64 \
    -accel tcg -machine pc -m 768 -no-reboot \
    -display none -monitor none -serial stdio \
    -drive file="$IMG",format=raw,if=virtio,snapshot=on \
  | tee "$LOG"
qemu_rc=${PIPESTATUS[0]}
set -e

echo "----"
READY_LINE="$(grep "AGENTD_DISK_READY" "$LOG" | head -1)"
ok=1
grep -q "GRUB:" "$LOG"                                  || { echo "  → 未见 GRUB 标记（SeaBIOS→GRUB 失败）" >&2; ok=0; }
[ -n "$READY_LINE" ]                                    || { echo "  → 未见 AGENTD_DISK_READY（未 pivot 到磁盘 PID1）" >&2; ok=0; }
grep -q "AGENTD_DISK_FAIL" "$LOG"                       && { echo "  → 见 AGENTD_DISK_FAIL（early_init/disk_init 某步失败）" >&2; ok=0; }
grep -qE "Kernel panic|Attempted to kill init" "$LOG"   && { echo "  → 内核 panic：PID1 死（真失败）" >&2; ok=0; }
[ "$qemu_rc" -eq 124 ]                                  && { echo "  → 超时未退出（hang）" >&2; ok=0; }
if [ -n "$READY_LINE" ]; then
  echo "$READY_LINE" | grep -q "root_fstype=ext4"           || { echo "  → root_fstype != ext4（未真切到磁盘 ext4 根）" >&2; ok=0; }
  echo "$READY_LINE" | grep -qE "reaped=[1-9]"              || { echo "  → reaped<1（受监督 child 未被 reap）" >&2; ok=0; }
  echo "$READY_LINE" | grep -q "manifest_sha=$EXPECT_SHA"   || { echo "  → manifest_sha 不匹配 sidecar（$EXPECT_SHA）" >&2; ok=0; }
fi

if [ "$ok" -eq 1 ]; then
  echo "DISK-PIVOT PASS: SeaBIOS→GRUB→initramfs(early_init)→switch_root→磁盘 ext4 PID1→干净 poweroff"
  echo "  $READY_LINE"
  exit 0
fi
echo "DISK-PIVOT FAIL (qemu_rc=$qemu_rc)" >&2
exit 1
