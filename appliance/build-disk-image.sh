#!/usr/bin/env bash
# build-disk-image.sh —— 构建 GPT + ext4 + GRUB(BIOS) 可启动磁盘镜像，**真 pivot** 到磁盘 ext4 根
# （ADR-004 cp7 full-pivot 形态）。
#
# boot 拓扑：
#   SeaBIOS → GRUB(i386-pc, core.img 嵌 ef02) → GPT ext4 root /boot/grub.cfg →
#   linux /boot/vmlinuz + initrd /boot/initramfs.cpio.gz(/init=early_init) →
#   early_init(PID1, initramfs): finit_module(virtio_blk..ext4) → mount ext4 /dev/vda2 →
#   switch_root → exec /sbin/init(disk_init) → disk_init(PID1, 磁盘 ext4 根): run_pid1 自检 +
#   反假绿(statfs 0xEF53 + mountinfo maj:min/src + manifest SHA-256) → AGENTD_DISK_READY → power_off。
#
# 范围：BIOS-only（本机 GRUB 仅 i386-pc）、宿主内核（virtio_blk/ext4=m → early_init finit_module）。
# 须 root（losetup/mkfs/mount/grub-install）。可重复：每次从零，trap 清理。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MUSL_REL="$REPO_ROOT/target/x86_64-unknown-linux-musl/release"

# ── 入参（env 可覆盖）────────────────────────────────────────────────────────
# initramfs /init = early_init（挂盘 + switch_root + 交接 PID1）。
INIT_BIN="${INIT_BIN:-$MUSL_REL/early_init}"
# 磁盘 ext4 根的 /sbin/init = disk_init（pivot 落点，真 PID1 自检 + 反假绿 + power_off）。
ROOTFS_INIT="${ROOTFS_INIT:-$MUSL_REL/disk_init}"
KERNEL="${KERNEL:-/boot/vmlinuz-$(uname -r)}"
OUT="${OUT:-$SCRIPT_DIR/disk.img}"
# early_init 须 finit_module 加载的根模块（宿主内核 ext4/virtio_blk=m，依赖序）。builtin 内核留空。
MODS="${MODS:-virtio_blk crc16 crc32c_generic mbcache jbd2 ext4}"

BIOS_BOOT_MIB="${BIOS_BOOT_MIB:-1}"
ROOT_MIB="${ROOT_MIB:-256}"
VAR_MIB="${VAR_MIB:-64}"
IMG_MIB=$(( 2 + BIOS_BOOT_MIB + ROOT_MIB + VAR_MIB + 2 ))

DISK_GUID="A105105A-0000-4000-8000-000000000001"
ROOT_PARTUUID="A105105A-0000-4000-8000-000000000002"
VAR_PARTUUID="A105105A-0000-4000-8000-000000000003"
ROOT_FS_UUID="a105105a-0000-4000-8000-0000000000a2"
VAR_FS_UUID="a105105a-0000-4000-8000-0000000000a3"

# ── 前置校验（失败要真失败）─────────────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || { echo "错误: 须 root（losetup/mkfs/mount/grub-install）" >&2; exit 1; }
[ -f "$INIT_BIN" ]   || { echo "错误: 缺 early_init: $INIT_BIN（cargo build -p early_init --target x86_64-unknown-linux-musl --release）" >&2; exit 1; }
[ -f "$ROOTFS_INIT" ]|| { echo "错误: 缺 disk_init: $ROOTFS_INIT（cargo build -p agentd_init --bin disk_init --target x86_64-unknown-linux-musl --release）" >&2; exit 1; }
[ -f "$KERNEL" ]     || { echo "错误: 缺内核: $KERNEL" >&2; exit 1; }
for t in sgdisk losetup mkfs.ext4 mount umount grub-install qemu-img sha256sum; do
  command -v "$t" >/dev/null 2>&1 || { echo "错误: 缺工具 $t" >&2; exit 1; }
done
[ -d /usr/lib/grub/i386-pc ] || { echo "错误: 缺 GRUB i386-pc（apt install grub-pc-bin）" >&2; exit 1; }
# 两个 init 都须 musl 静态（initramfs/ext4 根均无 ld.so，动态 init 必 ENOENT 死在 exec）。
for b in "$INIT_BIN" "$ROOTFS_INIT"; do
  file -L "$b" | grep -q "dynamically linked" && { echo "错误: $b 是动态链接；须 musl 静态" >&2; exit 1; }
done

# ── 清理（trap）────────────────────────────────────────────────────────────
LOOP=""; MNT=""
cleanup() {
  set +e
  [ -n "$MNT" ] && mountpoint -q "$MNT" && { sync; umount "$MNT"; }
  [ -n "$LOOP" ] && losetup -d "$LOOP"
  [ -n "$MNT" ] && rmdir "$MNT" 2>/dev/null
}
trap cleanup EXIT

echo "==> 1/8 建 raw 镜像 ${IMG_MIB}MiB: $OUT"
rm -f "$OUT" "$OUT.manifest.sha256"
qemu-img create -f raw "$OUT" "${IMG_MIB}M" >/dev/null

echo "==> 2/8 GPT（sgdisk）：ef02 BIOS-boot + ext4 root + ext4 var"
sgdisk --zap-all "$OUT" >/dev/null
sgdisk \
  -U "$DISK_GUID" \
  -n "1:0:+${BIOS_BOOT_MIB}MiB" -t 1:ef02 -c 1:"BIOS-boot" \
  -n "2:0:+${ROOT_MIB}MiB"      -t 2:8300 -c 2:"agentos-root" -u "2:$ROOT_PARTUUID" \
  -n "3:0:0"                    -t 3:8300 -c 3:"agentos-var"  -u "3:$VAR_PARTUUID" \
  "$OUT" >/dev/null
sgdisk -p "$OUT"

echo "==> 3/8 losetup -P（分区扫描）"
LOOP="$(losetup --find --partscan --show "$OUT")"
echo "    loop = $LOOP"
for i in $(seq 1 20); do [ -b "${LOOP}p2" ] && [ -b "${LOOP}p3" ] && break; sleep 0.1; done
[ -b "${LOOP}p1" ] && [ -b "${LOOP}p2" ] && [ -b "${LOOP}p3" ] \
  || { echo "错误: 分区节点未出现：$(ls -l ${LOOP}* 2>&1)" >&2; exit 1; }

echo "==> 4/8 mkfs.ext4 root/var（p1 ef02 裸分区不格式化）"
mkfs.ext4 -q -F -L agentos-root -U "$ROOT_FS_UUID" "${LOOP}p2"
mkfs.ext4 -q -F -L agentos-var  -U "$VAR_FS_UUID"  "${LOOP}p3"

echo "==> 5/8 mount root + 铺 rootfs（/sbin/init=disk_init + 预建挂载点）"
MNT="$(mktemp -d /tmp/aios-disk.XXXXXX)"
mount "${LOOP}p2" "$MNT"
# ext4 根：disk_init 作 /sbin/init；预建 early_init switch_root 后由 disk_init/run_pid1 重挂的
# /proc /sys /dev 挂载点；/var/lib/agentos（持久状态挂载点）；/etc/agentos（runtime-manifest）。
mkdir -p "$MNT"/{proc,sys,dev,boot,sbin,etc/agentos,var/lib/agentos}
install -D -m 0755 "$ROOTFS_INIT" "$MNT/sbin/init"

echo "==> 6/8 生成 build-unique runtime-manifest + sidecar SHA-256（反假绿）"
# manifest 内容 per-build 变化（kernel + 两 init 的 sha256 + 随机 nonce）→ disk_init 运行时重算其
# SHA-256 并打印，harness 比对 sidecar；硬编码 sha 跨 build 失效，真切到 ext4 才读得到此文件。
DISK_INIT_SHA="$(sha256sum "$ROOTFS_INIT" | cut -d' ' -f1)"
EARLY_INIT_SHA="$(sha256sum "$INIT_BIN" | cut -d' ' -f1)"
BUILD_NONCE="$(head -c 16 /dev/urandom | sha256sum | cut -d' ' -f1)"
{
  echo "kernel=$(uname -r)"
  echo "disk_init_sha256=$DISK_INIT_SHA"
  echo "early_init_sha256=$EARLY_INIT_SHA"
  echo "build_nonce=$BUILD_NONCE"
} > "$MNT/etc/agentos/runtime-manifest"
MANIFEST_SHA="$(sha256sum "$MNT/etc/agentos/runtime-manifest" | cut -d' ' -f1)"
echo "$MANIFEST_SHA" > "$MNT/etc/agentos/runtime-manifest.sha256"
echo "$MANIFEST_SHA" > "$OUT.manifest.sha256"   # sidecar：harness 独立读取比对
echo "    manifest sha256 = $MANIFEST_SHA"

echo "==> 7/8 放 kernel + 打 initramfs（/init=early_init + 根模块）到 root 分区 /boot"
cp "$KERNEL" "$MNT/boot/vmlinuz"
INITRAMFS="$MNT/boot/initramfs.cpio.gz"
MODS="$MODS" bash "$SCRIPT_DIR/pack-initramfs.sh" "$INIT_BIN" "$INITRAMFS" >/dev/null
echo "    /init=early_init, /sbin/init=disk_init, modules=[$MODS]"

echo "==> 8/8 grub-install（i386-pc）+ grub.cfg（full-pivot cmdline）"
grub-install --target=i386-pc --boot-directory="$MNT/boot" \
  --modules="part_gpt ext2 biosdisk" --no-floppy "$LOOP"
# cmdline：root=/dev/vda2（early_init 从此 parse）；aios.state=/dev/vda3（持久分区，early_init 挂）；
# console=ttyS0 + lsm=landlock,yama,bpf（ADR-004 必需）；panic=-1；rdinit=/init（早期 init=early_init）。
cat > "$MNT/boot/grub/grub.cfg" <<'GRUBCFG'
set timeout=3
set default=0

serial --unit=0 --speed=115200
terminal_input serial console
terminal_output serial console

menuentry "AIOS appliance (BIOS, i386-pc, disk-pivot)" {
    insmod part_gpt
    insmod ext2
    echo "GRUB: loading AIOS kernel + initramfs (early_init pivot to ext4 root)..."
    linux /boot/vmlinuz root=/dev/vda2 aios.state=/dev/vda3 console=ttyS0 lsm=landlock,yama,bpf panic=-1 rootfstype=ext4 rw rdinit=/init loglevel=4
    initrd /boot/initramfs.cpio.gz
    echo "GRUB: booting."
}
GRUBCFG

sync
echo
echo "OK  磁盘镜像就绪: $OUT  ($(du -h "$OUT" | cut -f1))"
echo "    manifest sidecar: $OUT.manifest.sha256 = $MANIFEST_SHA"
echo "    布局: [1 ef02 BIOS-boot ${BIOS_BOOT_MIB}M][2 ext4 root ${ROOT_MIB}M][3 ext4 var ${VAR_MIB}M]"
echo "    验证: sudo bash $SCRIPT_DIR/disk-boot-smoke.sh"
