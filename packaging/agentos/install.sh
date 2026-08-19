#!/usr/bin/env bash
# agentd 发行版安装脚本 —— 部署二进制 + systemd unit + 配置到目标 rootfs。
#
# 用法：
#   ./packaging/agentos/install.sh [DESTDIR]
#   默认 DESTDIR=/（系统安装）；传 rootfs 路径则安装到该前缀（镜像构建）。
#
# 冻结控制平面：只复制文件，不改裁决逻辑。安装后需 systemd enable + start。
set -euo pipefail

DESTDIR="${1:-/}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# 二进制：优先 musl 静态构建产物（发行版要求静态链接）。
BIN_SRC="$REPO_ROOT/target/x86_64-unknown-linux-musl/release/agentd_daemon"
if [[ ! -x "$BIN_SRC" ]]; then
    BIN_SRC="$REPO_ROOT/target/release/agentd_daemon"
fi
if [[ ! -x "$BIN_SRC" ]]; then
    echo "错误：未找到 agentd_daemon 二进制。请先运行：" >&2
    echo "  cargo build --target x86_64-unknown-linux-musl --release --bins -p agentd" >&2
    exit 1
fi

install -d "$DESTDIR/usr/local/bin"
install -d "$DESTDIR/etc/agentos"
install -d "$DESTDIR/etc/systemd/system"
install -d "$DESTDIR/var/lib/agentos/audit"
install -d "$DESTDIR/var/log/agentos/audit"
install -d "$DESTDIR/var/lib/agentos/runs"

install -m 0755 "$BIN_SRC" "$DESTDIR/usr/local/bin/agentd_daemon"
install -m 0644 "$SCRIPT_DIR/rootfs/etc/agentos/agentd.conf" "$DESTDIR/etc/agentos/agentd.conf"
install -m 0644 "$SCRIPT_DIR/rootfs/etc/systemd/system/agentd.service" "$DESTDIR/etc/systemd/system/agentd.service"

# 创建 agentos 系统用户（若不存在）——最小权限，无 shell 登录。
if [[ -z "${DESTDIR:-}" || "$DESTDIR" == "/" ]]; then
    if ! id agentos &>/dev/null; then
        useradd --system --no-create-home --shell /usr/sbin/nologin --home-dir /var/lib/agentos agentos
    fi
    chown -R agentos:agentos /var/lib/agentos /var/log/agentos 2>/dev/null || true
fi

echo "agentd 已安装到 $DESTDIR"
echo ""
echo "启用并启动服务："
echo "  sudo systemctl daemon-reload"
echo "  sudo systemctl enable --now agentd"
echo ""
echo "验证："
echo "  curl http://127.0.0.1:8421/health"
echo "  curl http://127.0.0.1:8421/config"
