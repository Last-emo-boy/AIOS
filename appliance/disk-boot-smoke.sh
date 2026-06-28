#!/usr/bin/env bash
# disk-boot-smoke.sh —— 从**磁盘镜像**真 boot（SeaBIOS→GRUB→kernel→initramfs→PID1），机器可验证（cp7）。
#
# 与 boot-smoke.sh（cp4，直接 -kernel/-initrd）的差别：本脚本**不**用 -kernel/-initrd，而是
# `-drive if=virtio` 挂磁盘镜像，让 QEMU 默认 SeaBIOS 从盘引导 → 走完真 GRUB 引导链。这验证
# 的是 cp7 新增的「磁盘→GRUB→加载 kernel/initramfs」段，而非 cp4 已验证的「kernel→PID1」段。
#
# 本机无 /dev/kvm → 纯 TCG（慢）。成功判据=串口 CONTENT（退出码不可用：poweroff/panic 都退 0）：
#   1. 见 GRUB 输出（"GRUB: loading AIOS kernel"）——证明 SeaBIOS→GRUB→读到 GPT ext4 的 grub.cfg；
#   2. 见 AGENTD_BOOT_READY 且 reaped>=1 ——证明 GRUB 真加载了 kernel+initramfs 且 boot 到真 PID1；
#   3. 无 Kernel panic / Attempted to kill init / AGENTD_BOOT_FAIL；
#   4. QEMU 在超时内自行退出（boot_smoke power_off 触发）。超时→kill→FAIL，绝不当成功。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMG="${1:-$SCRIPT_DIR/disk.img}"
TIMEOUT="${TIMEOUT:-240}"

[ -f "$IMG" ] || { echo "错误: 缺磁盘镜像 $IMG（先跑 build-disk-image.sh）" >&2; exit 1; }
command -v qemu-system-x86_64 >/dev/null || { echo "错误: 缺 qemu-system-x86_64" >&2; exit 1; }

LOG="$(mktemp)"; trap 'rm -f "$LOG"' EXIT

set +e
timeout --foreground "${TIMEOUT}" \
  qemu-system-x86_64 \
    -accel tcg \
    -machine pc \
    -m 512 \
    -no-reboot \
    -display none -monitor none -serial stdio \
    -drive file="$IMG",format=raw,if=virtio \
  | tee "$LOG"
qemu_rc=${PIPESTATUS[0]}
set -e

echo "----"
if grep -q "GRUB: loading AIOS kernel" "$LOG" \
   && grep -qE "AGENTD_BOOT_READY .*reaped=[1-9]" "$LOG" \
   && ! grep -q "AGENTD_BOOT_FAIL" "$LOG" \
   && ! grep -qE "Kernel panic|Attempted to kill init" "$LOG"; then
  echo "DISK-BOOT PASS: SeaBIOS→GRUB(GPT ext4)→kernel+initramfs→真 PID1→干净 poweroff"
  exit 0
fi

echo "DISK-BOOT FAIL (qemu_rc=$qemu_rc)" >&2
grep -q "GRUB: loading AIOS kernel" "$LOG" || echo "  → 未见 GRUB 标记：SeaBIOS 未引导到 GRUB 或 GRUB 未读到 grub.cfg（core.img/ef02/prefix 问题）" >&2
grep -qE "AGENTD_BOOT_READY" "$LOG"        || echo "  → 未见 AGENTD_BOOT_READY：GRUB 未成功加载 kernel/initramfs 或未 boot 到 PID1" >&2
grep -q  "AGENTD_BOOT_FAIL" "$LOG"         && echo "  → 见 AGENTD_BOOT_FAIL：init 序列某步失败" >&2
[ "$qemu_rc" -eq 124 ]                     && echo "  → 超时未退出（hang）" >&2
grep -qE "Kernel panic|Attempted to kill init" "$LOG" && echo "  → 内核 panic：PID1 退出（真失败）" >&2
exit 1
