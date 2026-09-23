#!/bin/sh
#
# 把 zig-dnsmasq 的 init 脚本 / UCI 配置 / LuCI 页面安装到路由器。
#
# 用法：
#   ./install.sh [目标IP]       默认为 192.168.0.1
#
# 依赖：与本文件同级的 helper 脚本 rsh.sh / rcp.sh / askpass.sh
#       （默认在 /home/ovo/.cache/dnsmasq-deploy/）

set -e

HOST="${1:-192.168.0.1}"
ROOT_USER="root@${HOST}"
HELPER_DIR="${HELPER_DIR:-/home/ovo/.cache/dnsmasq-deploy}"
HERE="$(cd "$(dirname "$0")" && pwd)"

RSH="${HELPER_DIR}/rsh.sh"
RCP="${HELPER_DIR}/rcp.sh"
export SSH_ASKPASS="${SSH_ASKPASS:-${HELPER_DIR}/askpass.sh}"
export SSH_ASKPASS_REQUIRE=force

for f in "${RSH}" "${RCP}"; do
	[ -x "$f" ] || { echo "缺少 helper: $f"; exit 1; }
done

echo "==> 目标 ${HOST}"

echo "==> 建立目标目录"
setsid -w "${RSH}" "${ROOT_USER}" \
	'mkdir -p /var/etc /usr/share/rpcd/acl.d /usr/share/luci/menu.d \
	          /www/luci-static/resources/view/zig-dnsmasq'

echo "==> 安装 init 脚本"
setsid -w "${RCP}" "${HERE}/etc/init.d/zig-dnsmasq" "${ROOT_USER}:/etc/init.d/zig-dnsmasq"
setsid -w "${RSH}" "${ROOT_USER}" 'chmod +x /etc/init.d/zig-dnsmasq'

echo "==> 安装 UCI 默认配置（已存在则保留）"
setsid -w "${RSH}" "${ROOT_USER}" \
	'[ -f /etc/config/zig-dnsmasq ] && echo "  已存在，跳过" || echo "  待写入"'
if setsid -w "${RSH}" "${ROOT_USER}" '[ ! -f /etc/config/zig-dnsmasq ]'; then
	setsid -w "${RCP}" "${HERE}/etc/config/zig-dnsmasq" "${ROOT_USER}:/etc/config/zig-dnsmasq"
	echo "  已写入默认配置（enabled=0，不会自动抢 DNS）"
fi

echo "==> 安装 rpcd ACL 与 LuCI 菜单"
setsid -w "${RCP}" "${HERE}/usr/share/rpcd/acl.d/luci-app-zig-dnsmasq.json" \
	"${ROOT_USER}:/usr/share/rpcd/acl.d/luci-app-zig-dnsmasq.json"
setsid -w "${RCP}" "${HERE}/usr/share/luci/menu.d/luci-app-zig-dnsmasq.json" \
	"${ROOT_USER}:/usr/share/luci/menu.d/luci-app-zig-dnsmasq.json"

echo "==> 安装 LuCI 视图"
setsid -w "${RCP}" "${HERE}/www/luci-static/resources/view/zig-dnsmasq/settings.js" \
	"${ROOT_USER}:/www/luci-static/resources/view/zig-dnsmasq/settings.js"
setsid -w "${RCP}" "${HERE}/www/luci-static/resources/view/zig-dnsmasq/status.js" \
	"${ROOT_USER}:/www/luci-static/resources/view/zig-dnsmasq/status.js"

echo "==> 刷新 uhttpd / rpcd 缓存"
setsid -w "${RSH}" "${ROOT_USER}" '
	rm -rf /tmp/luci-indexcache* /tmp/luci-modulecache 2>/dev/null || true
	/etc/init.d/rpcd restart >/dev/null 2>&1 || true
	/etc/init.d/uhttpd restart >/dev/null 2>&1 || true
	clear_console >/dev/null 2>&1 || true
'

echo "==> 安装完成"
echo ""
echo "下一步（在路由器上执行）："
echo "  查看默认配置:   uci show zig-dnsmasq"
echo "  试运行:         uci set zig-dnsmasq.main.enabled=1"
echo "                  uci set zig-dnsmasq.main.port=5353"
echo "                  uci commit zig-dnsmasq"
echo "                  service zig-dnsmasq start"
echo "  确认无误后接管: service zig-dnsmasq takeover   # 内部会 enable，重启后自动运行"
echo "  回退:           service zig-dnsmasq revert     # 内部会 disable"
echo ""
echo "  ★ 注意 enable 与 enabled 是两件事，别只设后者："
echo "      enable          建 /etc/rc.d/S60zig-dnsmasq 开机自启链接"
echo "      uci enabled=1   只控制「本次 start 是否真正启动」"
echo "    只设 enabled=1 而没跑 enable，重启后服务不会起来"
echo "    （LuCI 的「启用」开关现在会同时调 enable/disable，走命令行时请自己补）"
echo ""
echo "LuCI 入口：服务(Services) → Zig DNSMasq"
