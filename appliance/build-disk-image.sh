#!/usr/bin/env bash
# build-disk-image.sh —— 构建 GPT + ext4 + GRUB(BIOS, i386-pc) 可启动磁盘镜像（ADR-004 cp7 第一版）。
#
# 目标 boot 拓扑（本里程碑实测到的最长链路）：
#   SeaBIOS → GRUB(i386-pc, core.img 嵌在 BIOS boot 分区) → 从 GPT ext4 root 分区读
#   /boot/grub/grub.cfg → linux /boot/vmlinuz + initrd /boot/initramfs.cpio.gz → 真 PID1。
#
# 范围决策（务实、incremental，见任务上下文与 ADR-004 D5）：
#   - **BIOS-only**：本机 GRUB 平台目录只有 i386-pc（无 x86_64-efi），QEMU SeaBIOS 默认 BIOS。
#     UEFI（ESP + grub-efi + mtools）是后续子任务，本脚本不假装做。
#   - **宿主内核第一版**：默认 /boot/vmlinuz-$(uname -r)（cp4 已验证可 boot）。vendored+pinned
#     内核是独立子任务。
#   - **initramfs-as-root（暂不 pivot_root）**：本机宿主内核 CONFIG_VIRTIO_BLK=m / EXT4_FS=m
#     （均为模块，非 built-in），module-less initramfs 无法 mount root=/dev/vda2。故 /init=
#     boot_smoke 留在 initramfs 内完成自检即 power_off；root 分区的 /sbin/init 仅作 pivot 落点
#     占位。真 pivot_root→ext4 root 依赖 vendored 内核把 virtio_blk/ext4 编 built-in（或 initramfs
#     带 .ko + modprobe），是下一子任务。grub.cfg 的 root=/dev/vda2 此刻被传入但 boot_smoke 不消费。
#
# 产物：appliance/disk.img（raw，GPT，3 分区）。可启动验证见 appliance/disk-boot-smoke.sh。
#
# 须 root（losetup / mkfs / mount / grub-install 写引导扇区）。可重复：每次从零重建，trap 清理。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── 入参（env 可覆盖）────────────────────────────────────────────────────────
# /init：放进 initramfs 的 musl 静态二进制（默认 boot_smoke：跑通真 PID1 自检后 power_off，
# 使「磁盘 boot 到 PID1」可被串口 CONTENT 反假绿验证）。
INIT_BIN="${INIT_BIN:-$REPO_ROOT/target/x86_64-unknown-linux-musl/release/boot_smoke}"
# pivot 落点占位（root 分区 /sbin/init）：生产 agentd_init（never-exit PID1）。
ROOTFS_INIT="${ROOTFS_INIT:-$REPO_ROOT/target/x86_64-unknown-linux-musl/release/agentd_init}"
KERNEL="${KERNEL:-/boot/vmlinuz-$(uname -r)}"
OUT="${OUT:-$SCRIPT_DIR/disk.img}"

# 分区尺寸（MiB）。root 需容 kernel(~12M)+initramfs+grub 模块(~5M)，留足余量。
BIOS_BOOT_MIB="${BIOS_BOOT_MIB:-1}"
ROOT_MIB="${ROOT_MIB:-256}"
VAR_MIB="${VAR_MIB:-64}"
# 镜像总尺寸 = 各分区 + GPT 前后开销(2MiB 对齐余量)。
IMG_MIB=$(( 2 + BIOS_BOOT_MIB + ROOT_MIB + VAR_MIB + 2 ))

# 固定 GUID/UUID → 布局确定（可重复；非字节级，ext4 仍有内部时间戳，见文件尾注）。
DISK_GUID="A105105A-0000-4000-8000-000000000001"
ROOT_PARTUUID="A105105A-0000-4000-8000-000000000002"
VAR_PARTUUID="A105105A-0000-4000-8000-000000000003"
ROOT_FS_UUID="a105105a-0000-4000-8000-0000000000a2"
VAR_FS_UUID="a105105a-0000-4000-8000-0000000000a3"

# ── 前置校验（失败要真失败，不静默兜底）────────────────────────────────────
[ "$(id -u)" -eq 0 ] || { echo "错误: 须 root（losetup/mkfs/mount/grub-install）" >&2; exit 1; }
[ -f "$INIT_BIN" ]   || { echo "错误: 缺 /init 二进制: $INIT_BIN（先 cargo build --release --target x86_64-unknown-linux-musl -p agentd_init --bin boot_smoke）" >&2; exit 1; }
[ -f "$KERNEL" ]     || { echo "错误: 缺内核: $KERNEL" >&2; exit 1; }
for t in sgdisk losetup mkfs.ext4 mount umount grub-install qemu-img; do
  command -v "$t" >/dev/null 2>&1 || { echo "错误: 缺工具 $t" >&2; exit 1; }
done
# 本机 GRUB 必须有 i386-pc 平台（BIOS 引导）。
[ -d /usr/lib/grub/i386-pc ] || { echo "错误: 缺 GRUB i386-pc 平台目录（apt install grub-pc-bin）" >&2; exit 1; }
# /init 必须静态（initramfs 无 ld.so）。
file -L "$INIT_BIN" | grep -q "dynamically linked" && { echo "错误: $INIT_BIN 是动态链接；须 musl 静态" >&2; exit 1; }

# ── 清理（trap）────────────────────────────────────────────────────────────
LOOP=""; MNT=""
cleanup() {
  set +e
  [ -n "$MNT" ] && mountpoint -q "$MNT" && { sync; umount "$MNT"; }
  [ -n "$LOOP" ] && losetup -d "$LOOP"
  [ -n "$MNT" ] && rmdir "$MNT" 2>/dev/null
}
trap cleanup EXIT

echo "==> 1/7 建 raw 镜像 ${IMG_MIB}MiB: $OUT"
rm -f "$OUT"
qemu-img create -f raw "$OUT" "${IMG_MIB}M" >/dev/null

echo "==> 2/7 写 GPT（sgdisk）：ef02 BIOS-boot + ext4 root + ext4 var"
# -a 1：1 扇区对齐前提下用 MiB 起点（sgdisk 默认 2048 扇区对齐，下方 +NMiB 自动对齐）。
# 1: BIOS boot partition（type ef02）——GPT 无 MBR gap，GRUB i386-pc core.img 必须嵌这里。
# 2: ext4 root（type 8300 = Linux filesystem）——/boot/grub + kernel + initramfs。
# 3: ext4 持久状态（/var/lib/agentos）——fs.write.diff/rollback/recovery 落点。
sgdisk --zap-all "$OUT" >/dev/null
sgdisk \
  -U "$DISK_GUID" \
  -n "1:0:+${BIOS_BOOT_MIB}MiB" -t 1:ef02 -c 1:"BIOS-boot" \
  -n "2:0:+${ROOT_MIB}MiB"      -t 2:8300 -c 2:"agentos-root" -u "2:$ROOT_PARTUUID" \
  -n "3:0:0"                    -t 3:8300 -c 3:"agentos-var"  -u "3:$VAR_PARTUUID" \
  "$OUT" >/dev/null
sgdisk -p "$OUT"

echo "==> 3/7 losetup -P（分区扫描，产生 p1/p2/p3 节点）"
LOOP="$(losetup --find --partscan --show "$OUT")"
echo "    loop = $LOOP"
# losetup -P 后内核异步建分区节点；最多等 2s 确认 p2/p3 出现（无 partprobe 可用）。
for i in $(seq 1 20); do
  [ -b "${LOOP}p2" ] && [ -b "${LOOP}p3" ] && break
  sleep 0.1
done
[ -b "${LOOP}p1" ] && [ -b "${LOOP}p2" ] && [ -b "${LOOP}p3" ] \
  || { echo "错误: 分区节点未出现（losetup -P 失败？）：$(ls -l ${LOOP}* 2>&1)" >&2; exit 1; }
ls -l "${LOOP}"p[123]

echo "==> 4/7 mkfs.ext4 root/var（p1 是 BIOS-boot 裸分区，不格式化）"
mkfs.ext4 -q -F -L agentos-root -U "$ROOT_FS_UUID" "${LOOP}p2"
mkfs.ext4 -q -F -L agentos-var  -U "$VAR_FS_UUID"  "${LOOP}p3"

echo "==> 5/7 mount root + 铺 rootfs 占位"
MNT="$(mktemp -d /tmp/aios-disk.XXXXXX)"
mount "${LOOP}p2" "$MNT"
# 最小 rootfs：挂载点（proc/sys/dev）+ /boot + pivot 落点 /sbin/init + /var/lib/agentos。
mkdir -p "$MNT"/{proc,sys,dev,boot,sbin,var/lib/agentos}
# /sbin/init 与 /init：pivot 落点占位（生产 agentd_init，never-exit PID1）。本里程碑未 pivot，
# 仅作下一子任务（真 pivot_root→ext4 root）的就位证据。
install -D -m 0755 "$ROOTFS_INIT" "$MNT/sbin/init"
ln -sf /sbin/init "$MNT/init"

echo "==> 6/7 放 kernel + 打 initramfs 到 root 分区 /boot"
cp "$KERNEL" "$MNT/boot/vmlinuz"
INITRAMFS="$MNT/boot/initramfs.cpio.gz"
bash "$SCRIPT_DIR/pack-initramfs.sh" "$INIT_BIN" "$INITRAMFS" >/dev/null
echo "    kernel    -> /boot/vmlinuz ($(du -h "$MNT/boot/vmlinuz" | cut -f1))"
echo "    initramfs -> /boot/initramfs.cpio.gz ($(du -h "$INITRAMFS" | cut -f1))"

echo "==> 7/7 grub-install（i386-pc，core.img 嵌 BIOS-boot 分区）+ 手写 grub.cfg"
# --boot-directory=$MNT/boot → 模块装到 $MNT/boot/grub/i386-pc，core.img 的 prefix=
#   (hd0,gpt2)/boot/grub，$root 自动指向 root 分区（gpt2）。装到整盘 $LOOP（非分区）。
# part_gpt+ext2：core.img 必须能解析 GPT 分区表并读 ext4 才能找到 grub.cfg。
grub-install \
  --target=i386-pc \
  --boot-directory="$MNT/boot" \
  --modules="part_gpt ext2 biosdisk" \
  --no-floppy \
  "$LOOP"

# 手写 grub.cfg：串口终端（QEMU -serial stdio 才看得见菜单）+ 单一启动项。
# 路径相对 $root=(hd0,gpt2)：/boot/vmlinuz、/boot/initramfs.cpio.gz 即 root 分区内路径。
# cmdline 带 ADR-004 必需项：console=ttyS0 串口；lsm=landlock,yama,bpf；panic=-1；root=/dev/vda2
#   （virtio → vda；本里程碑 boot_smoke 不消费，为 pivot 子任务就位）；rdinit=/init。
cat > "$MNT/boot/grub/grub.cfg" <<'GRUBCFG'
set timeout=3
set default=0

# 串口控制台：无此三行则 GRUB 菜单只走 VGA，QEMU -serial stdio 看不到。
serial --unit=0 --speed=115200
terminal_input serial console
terminal_output serial console

menuentry "AIOS appliance (BIOS, i386-pc)" {
    insmod part_gpt
    insmod ext2
    echo "GRUB: loading AIOS kernel + initramfs from GPT ext4 root..."
    linux /boot/vmlinuz root=/dev/vda2 console=ttyS0 lsm=landlock,yama,bpf panic=-1 rdinit=/init loglevel=4
    initrd /boot/initramfs.cpio.gz
    echo "GRUB: booting."
}
GRUBCFG

sync
echo
echo "OK  磁盘镜像就绪: $OUT  ($(du -h "$OUT" | cut -f1))"
echo "    布局: [1 ef02 BIOS-boot ${BIOS_BOOT_MIB}M][2 ext4 root ${ROOT_MIB}M][3 ext4 var ${VAR_MIB}M]"
echo "    验证: sudo bash $SCRIPT_DIR/disk-boot-smoke.sh"
