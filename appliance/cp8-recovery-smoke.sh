#!/usr/bin/env bash
# cp8-recovery-smoke.sh —— cp8 真持久 fs.write.diff + post-crash recovery 的 3-boot 端到端验证（cp8）。
#
# 用 build-disk-image.sh 产的 disk.img 的**可写副本**（去 snapshot=on，写累积跨 reboot），
# loop-mount p3(vda3=/var/lib/agentos) seed cp8-control 触发 cp8 gate，3 次从盘 boot 同一副本：
#   boot1: AGENTD_CP8_A_COMMIT  —— 持久写 v1（commit + Barrier fsync + verify-by-re-read）
#   boot2: AGENTD_CP8_A_VERIFY  —— 跨 reboot 真读到 boot1 的 v1（持久铁证）
#          AGENTD_CP8_B_ARMED   —— 装弹 v1→v2 半落盘 + EffectPrepared 后 power_off（mid-commit 真崩溃，无 seal）
#   boot3: AGENTD_CP8_B_RECOVERED —— recovery-first 从已持久 audit+shadow 真回滚 v2→v1
#
# 反假绿（串口 CONTENT 唯一权威 + host 端独立复核；退出码 poweroff/panic 都 0）：
#   boot2.reread == boot1.target_hash（跨 power-cycle 持久——进程内产物活不过真关机）
#   boot3.restored == boot2.base_hash 且 boot3.reread != boot2.proposed_hash（真回滚到 base，非半写 v2）
#   boot3.unresolved_after == 0 且 rolled_back >= 1
#   host loop-mount p3：state/app.conf == v1 且 journal.jsonl 含 RollbackObserved
#   任一 boot 见 Kernel panic / AGENTD_CP8_FAIL / 超时 = FAIL，绝不当成功。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_IMG="${1:-$SCRIPT_DIR/disk.img}"
CRASH_IMG="${CRASH_IMG:-$SCRIPT_DIR/cp8-crash.img}"
TIMEOUT="${TIMEOUT:-300}"
V1="$(printf 'mode=prod\nport=8080\n')"

[ -f "$SRC_IMG" ] || { echo "错误: 缺源磁盘镜像 $SRC_IMG（先 build-disk-image.sh）" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "错误: 须 root（losetup/mount seed + host 验证）" >&2; exit 1; }
command -v qemu-system-x86_64 >/dev/null || { echo "错误: 缺 qemu-system-x86_64" >&2; exit 1; }

WORK="${CP8_WORK:-$(mktemp -d)}"
mkdir -p "$WORK"
# cleanup 只解 loop/mount，**不删** WORK（保留 boot 串口日志供失败调试）；成功末尾才清。
cleanup() { set +e; [ -n "${MNT:-}" ] && { mountpoint -q "$MNT" && umount "$MNT"; }; [ -n "${LOOP:-}" ] && losetup -d "$LOOP" 2>/dev/null; }
trap cleanup EXIT
LOOP=""; MNT=""
echo "工作目录(boot 串口日志): $WORK"

# 取空格分隔 key=value 的 value（第一处）。tr 去 CR/LF：串口是 CRLF，行尾 token 带 \r 会破坏比较。
kv() { grep -oE "$2=[^ ]+" "$1" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '\r\n'; }

mount_p3() {  # $1=用途；设置全局 LOOP/MNT
  LOOP="$(losetup --find --partscan --show "$CRASH_IMG")"
  for _ in $(seq 1 20); do [ -b "${LOOP}p3" ] && break; sleep 0.1; done
  [ -b "${LOOP}p3" ] || { echo "错误: ${LOOP}p3 未出现" >&2; exit 1; }
  MNT="$WORK/mnt"; mkdir -p "$MNT"; mount "${LOOP}p3" "$MNT"
}
umount_p3() { sync; umount "$MNT"; MNT=""; losetup -d "$LOOP"; LOOP=""; }

boot_once() {  # $1=日志路径
  local log="$1" rc
  set +e
  timeout "$TIMEOUT" qemu-system-x86_64 -accel tcg -machine pc -m 768 -no-reboot \
    -display none -monitor none -serial stdio \
    -drive file="$CRASH_IMG",format=raw,if=virtio > "$log" 2>&1
  rc=$?
  set -e
  grep -qE "Kernel panic|Attempted to kill init" "$log" && { echo "FAIL: kernel panic（$log）" >&2; exit 1; }
  grep -q "AGENTD_CP8_FAIL" "$log" && { echo "FAIL: $(grep AGENTD_CP8_FAIL "$log" | head -1)" >&2; exit 1; }
  grep -q "AGENTD_DISK_FAIL" "$log" && { echo "FAIL: $(grep AGENTD_DISK_FAIL "$log" | head -1)" >&2; exit 1; }
  [ "$rc" -eq 124 ] && { echo "FAIL: boot 超时（$log）" >&2; exit 1; }
  return 0  # 显式成功返回（否则上一行 test 在 rc!=124 时返回 1，触发调用方 set -e 误退出）。
}

echo "==> 0/5 可写副本 + seed cp8-control（触发 cp8 gate）"
cp --reflink=auto "$SRC_IMG" "$CRASH_IMG"
mount_p3 seed
: > "$MNT/cp8-control"
umount_p3

echo "==> 1/5 boot1：持久写 v1"
boot_once "$WORK/boot1.log"
grep -q "AGENTD_CP8_A_COMMIT" "$WORK/boot1.log" || { echo "FAIL: boot1 无 AGENTD_CP8_A_COMMIT" >&2; exit 1; }
H1="$(kv "$WORK/boot1.log" target_hash)"
echo "    boot1 target_hash(H1)=$H1  committed=$(kv "$WORK/boot1.log" committed) audit_unresolved=$(kv "$WORK/boot1.log" audit_unresolved)"

echo "==> 2/5 boot2：跨 reboot verify v1 + 装弹 mid-commit 崩溃"
boot_once "$WORK/boot2.log"
grep -q "AGENTD_CP8_A_VERIFY" "$WORK/boot2.log" || { echo "FAIL: boot2 无 AGENTD_CP8_A_VERIFY" >&2; exit 1; }
grep -q "AGENTD_CP8_B_ARMED"  "$WORK/boot2.log" || { echo "FAIL: boot2 无 AGENTD_CP8_B_ARMED" >&2; exit 1; }
VERIFY_REREAD="$(kv "$WORK/boot2.log" reread_hash)"
B_BASE="$(kv "$WORK/boot2.log" base_hash)"
B_PROPOSED="$(kv "$WORK/boot2.log" proposed_hash)"
echo "    boot2 verify reread=$VERIFY_REREAD  armed base=$B_BASE proposed=$B_PROPOSED"
# 跨 reboot 持久铁证：boot2 读到的 == boot1 写的。
[ "$VERIFY_REREAD" = "$H1" ] || { echo "FAIL: 跨 reboot 持久断言 boot2.reread($VERIFY_REREAD) != boot1.target($H1)" >&2; exit 1; }

echo "==> 3/5 boot3：recovery-first 真回滚 v2→v1"
boot_once "$WORK/boot3.log"
grep -q "AGENTD_CP8_B_RECOVERED" "$WORK/boot3.log" || { echo "FAIL: boot3 无 AGENTD_CP8_B_RECOVERED" >&2; exit 1; }
R_RESTORED="$(kv "$WORK/boot3.log" restored_hash)"
R_REREAD="$(kv "$WORK/boot3.log" reread_hash)"
R_ROLLED="$(kv "$WORK/boot3.log" rolled_back)"
R_UNRES="$(kv "$WORK/boot3.log" unresolved_after)"
echo "    boot3 restored=$R_RESTORED reread=$R_REREAD rolled_back=$R_ROLLED unresolved_after=$R_UNRES"
# 真回滚铁证：回到 base（v1），不是半写 v2。
[ "$R_RESTORED" = "$B_BASE" ] || { echo "FAIL: boot3.restored($R_RESTORED) != boot2.base($B_BASE)" >&2; exit 1; }
[ "$R_REREAD" = "$H1" ]       || { echo "FAIL: boot3.reread($R_REREAD) != v1($H1)" >&2; exit 1; }
[ "$R_REREAD" != "$B_PROPOSED" ] || { echo "FAIL: boot3.reread == 未完成的 v2（未真回滚）" >&2; exit 1; }
[ "$R_UNRES" = "0" ]          || { echo "FAIL: boot3.unresolved_after=$R_UNRES != 0" >&2; exit 1; }
[ "${R_ROLLED:-0}" -ge 1 ]    || { echo "FAIL: boot3.rolled_back=$R_ROLLED < 1" >&2; exit 1; }

echo "==> 4/5 host 端 loop-mount 独立复核（不信串口，亲自读盘）"
mount_p3 verify
HOST_CONTENT="$(cat "$MNT/state/app.conf" 2>/dev/null || echo MISSING)"
HOST_ROLLBACK=0; grep -q "RollbackObserved" "$MNT/audit/journal.jsonl" 2>/dev/null && HOST_ROLLBACK=1
umount_p3
[ "$HOST_CONTENT" = "$V1" ] || { echo "FAIL: host state/app.conf != v1（实际: $(printf '%q' "$HOST_CONTENT")）" >&2; exit 1; }
[ "$HOST_ROLLBACK" = 1 ]    || { echo "FAIL: host journal 无 RollbackObserved" >&2; exit 1; }
echo "    host: state/app.conf == v1 ✓  journal 含 RollbackObserved ✓"

echo "==> 5/5 清理可写副本 + 日志"
rm -f "$CRASH_IMG"; rm -rf "$WORK"
echo
echo "CP8-RECOVERY PASS: 跨 reboot 持久（boot2 读到 boot1 的 v1）+ mid-commit 真崩溃回滚（boot3 v2→v1）+ host 独立复核"
