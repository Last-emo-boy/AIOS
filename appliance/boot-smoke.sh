#!/usr/bin/env bash
# boot-smoke.sh —— 用宿主内核 + 打好的 initramfs 在 QEMU 里真 boot 到 /init（ADR-004 cp4）。
#
# 本机无 /dev/kvm → 纯 TCG 软件模拟（慢但可用）。直接 `-kernel`/`-initrd` 启动，不需自编内核、
# 不需磁盘镜像（GPT+GRUB+pivot_root 是 cp7，本阶段 initramfs 即根）。
#
# 成功判据（机器可验证，二者缺一即 FAIL）：
#   1. 串口出现成功标记 $MARKER —— 由 /init 在干净退出前主动打印；
#   2. QEMU 在超时内自行退出 —— 由 /init 调 reboot(RB_POWER_OFF) 触发（配 -no-reboot → QEMU 退出）。
#
# /init 必须是 boot_smoke 变体（crates/agentd_init/src/bin/boot_smoke.rs，musl 静态）：它跑通真
# PID1 序列后向 /dev/console 打印 AGENTD_BOOT_READY（含运行时派生 reaped 计数）再 power_off()。
# 生产 agentd_init 的回收循环「永不返回」（D3.2 语义保持不动），直接打包它跑本脚本会永久 hang、
# 被判 FAIL（诚实结果）—— 干净退出只属 boot_smoke 形态。下电经 platform_sys::power_off 安全封装。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KERNEL="${KERNEL:-/boot/vmlinuz-6.12.94+deb13-amd64}"
INITRD="${1:-$SCRIPT_DIR/initramfs.cpio.gz}"
TIMEOUT="${TIMEOUT:-180}"

[ -f "$KERNEL" ] || { echo "错误: 缺内核 $KERNEL" >&2; exit 1; }
[ -f "$INITRD" ] || { echo "错误: 缺 initramfs $INITRD（先跑 pack-initramfs.sh）" >&2; exit 1; }

LOG="$(mktemp)"; trap 'rm -f "$LOG"' EXIT

# 内核 cmdline：
#   console=ttyS0   串口控制台（/dev/console 5:1 → ttyS0），内核早期 + /init 输出全进串口
#   panic=-1        panic 立即重启；配 -no-reboot → QEMU 退出。PID1 退出/panic = 内核 panic
#                   ("Attempted to kill init")，于是「失败」也能确定性观测到（不会假绿/不会卡死）
#   rdinit=/init    显式指定 initramfs 内 /init（内核默认即 /init，写明更清晰）
#   loglevel=7      打开早期诊断
CMDLINE="console=ttyS0 panic=-1 rdinit=/init loglevel=7"

set +e
timeout --foreground "${TIMEOUT}" \
  qemu-system-x86_64 \
    -accel tcg \
    -machine pc \
    -m 512 \
    -no-reboot \
    -display none -serial stdio -monitor none \
    -kernel "$KERNEL" \
    -initrd "$INITRD" \
    -append "$CMDLINE" \
  | tee "$LOG"
qemu_rc=${PIPESTATUS[0]}
set -e

echo "----"
# 成功判据（串口 CONTENT，三者全中；退出码不可用——poweroff 与 panic 都退 0）：
#   1. AGENTD_BOOT_READY 行且 reaped>=1（运行时派生计数，硬编码 stub 无法伪造）
#   2. 无 AGENTD_BOOT_FAIL（init 序列任一步失败的诚实标记）
#   3. 无 Kernel panic / Attempted to kill init（PID1 退出/panic）
if grep -qE "AGENTD_BOOT_READY .*reaped=[1-9]" "$LOG" \
   && ! grep -q "AGENTD_BOOT_FAIL" "$LOG" \
   && ! grep -qE "Kernel panic|Attempted to kill init" "$LOG"; then
  echo "SMOKE PASS: 真 PID1 自检 + 干净 poweroff（串口 READY 标记，reaped>=1）"
  exit 0
fi

echo "SMOKE FAIL (qemu_rc=$qemu_rc)" >&2
grep -qE "AGENTD_BOOT_READY" "$LOG" || echo "  → 未见 AGENTD_BOOT_READY：未 boot 到我们的 PID1 或自检未完成" >&2
grep -q  "AGENTD_BOOT_FAIL" "$LOG"  && echo "  → 见 AGENTD_BOOT_FAIL：真 init 序列某步失败（见标记 stage/errno）" >&2
[ "$qemu_rc" -eq 124 ]              && echo "  → 超时未退出：/init 既未打标记也未 power_off（hang）" >&2
grep -qE "Kernel panic|Attempted to kill init" "$LOG" && echo "  → 内核 panic：PID1 退出（真失败，非假绿）" >&2
exit 1
