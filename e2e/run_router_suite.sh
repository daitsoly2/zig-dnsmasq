#!/usr/bin/env bash
# 路由器侧 A/B 回归套件（对照线上 zig 实例与 C 参考实例）。
#
# 与 run_all.sh 的分工：
#   * run_all.sh      —— 本地套件：自己起一个守护进程（15353），跑语义/并发/压测/接口绑定。
#   * 本脚本          —— 路由器套件：直连 192.168.0.1，把**线上 zig(53)** 与
#                        **C 版参考实例(5352)** 逐字段对照。抓出本轮两处真差异
#                        （AA 权威位、address 规则本地应答）的正是这几套。
#
# 前置条件：
#   * 路由器 192.168.0.1 上跑着 zig-dnsmasq（53）
#   * C 版参考实例在 5352：/tmp/dnsmasq-c293 -C /tmp/c293.conf -k
#     （缺了它，各套件的「与 C 对比」环节会自动跳过，只做自断言）
#   * 若要把地址规则套件也跑起来，需要 DEPLOY_DIR 下存在 rsh.sh（密码走 askpass）
#
# 用法：
#   ./run_router_suite.sh              # 跑全部自包含套件 + 负缓存串扰 + 地址规则套件
#   SKIP_NEG=1 ./run_router_suite.sh   # 跳过负缓存串扰套件（需端口 5561 临时实例）
#   SKIP_ADDR=1 ./run_router_suite.sh  # 跳过需要起临时实例的地址规则套件
#   WITH_DIFF=1 ./run_router_suite.sh  # 额外跑完整 762 组全量对照（较慢，数分钟）
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
PYTHON="${PYTHON:-python3}"
DEPLOY_DIR="${DEPLOY_DIR:-$HOME/.cache/dnsmasq-deploy}"
HOST="${ROUTER:-192.168.0.1}"
FAILED=0

cd "$HERE"

banner() { echo; echo "==================== $1 ===================="; }

# 探活：直接查一个必然存在的名字，避免依赖 ping/ssh
probe_port() {
  "$PYTHON" - "$1" "$2" <<'PY'
import socket, struct, sys
port = int(sys.argv[1]); name = sys.argv[2]
q = struct.pack(">HHHHHH", 0x2A2A, 0x0100, 1, 0, 0, 0)
for lab in name.encode().split(b"."):
    if lab:
        q += bytes([len(lab)]) + lab
q += b"\x00" + struct.pack(">HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(4)
try:
    s.sendto(q, ("192.168.0.1", port)); s.recvfrom(4096)
    sys.exit(0)
except Exception:
    sys.exit(1)
finally:
    s.close()
PY
}

banner "0. 环境探活"
if probe_port 53 localhost; then
  echo "  zig 实例 (53)     : 在"
else
  echo "  zig 实例 (53)     : 无应答 —— 后续套件必然失败，中止"; exit 1
fi
if probe_port 5352 localhost; then
  echo "  C 参考实例 (5352) : 在"
  HAVE_C=1
else
  echo "  C 参考实例 (5352) : 不在（各套件的「与 C 对比」环节将跳过）"
  HAVE_C=0
fi

run_suite() {
  local name="$1"
  banner "$name"
  ( "$PYTHON" "$name.py" ) || FAILED=1
}

# 1) 上游应答 qdcount 必须为 1（投毒根因回归）
run_suite verify_qdcount_fix

# 2) 本地已知名查非地址类型不得误判 NXDOMAIN
run_suite verify_local_name_nodata

# 3) AA（权威）位归属：hosts/DHCP 派生 -> 1；上游转发/负记录 -> 0
run_suite verify_aa_bit

# 4) 投毒回归：对真实名连打 PTR 后，正向 A 仍正常
run_suite poison_regression

# 5) 负缓存类型串扰：AAAA 的 NODATA 不得截胡同名的 A（需要**缓存干净**的临时实例）
if [ "${SKIP_NEG:-0}" = "1" ]; then
  banner "verify_neg_nodata_type（已按 SKIP_NEG=1 跳过）"
elif [ ! -x "$DEPLOY_DIR/rsh.sh" ]; then
  banner "verify_neg_nodata_type（跳过：$DEPLOY_DIR/rsh.sh 不存在，无法起临时实例）"
else
  banner "setup 临时实例（负缓存串扰，端口 5561）"
  if sh setup_neg_instance.sh "root@$HOST"; then
    sleep 2
    ( "$PYTHON" verify_neg_nodata_type.py --port 5561 ) || FAILED=1
  else
    echo "  临时实例启动失败，跳过该套件"; FAILED=1
  fi
  banner "teardown 临时实例（负缓存串扰）"
  sh setup_neg_instance.sh "root@$HOST" stop || true
fi

# 6) address 规则路径（需要两个带 address= 的临时实例）
if [ "${SKIP_ADDR:-0}" = "1" ]; then
  banner "verify_address_rule（已按 SKIP_ADDR=1 跳过）"
elif [ ! -x "$DEPLOY_DIR/rsh.sh" ]; then
  banner "verify_address_rule（跳过：$DEPLOY_DIR/rsh.sh 不存在，无法起临时实例）"
else
  banner "setup 临时实例（address 规则）"
  if sh setup_addr_instances.sh "root@$HOST"; then
    sleep 2
    ( "$PYTHON" verify_address_rule.py ) || FAILED=1
  else
    echo "  临时实例启动失败，跳过该套件"; FAILED=1
  fi
  banner "teardown 临时实例"
  # setup_addr_instances.sh 的 stop 按 PID 文件精确清理（见该脚本头部运维说明），
  # 不再需要任何 pgrep/pkill 兜底 —— 它们会匹配到 ssh 自身命令行而误杀。
  sh setup_addr_instances.sh "root@$HOST" stop || true
fi

# 6) 完整 762 组全量对照（慢；默认不跑）
if [ "${WITH_DIFF:-0}" = "1" ]; then
  banner "diff_vs_c（762 组，冷/热缓存各一遍）"
  ( "$PYTHON" diff_vs_c.py ) || FAILED=1
else
  banner "diff_vs_c（已跳过；需要时用 WITH_DIFF=1 开启）"
fi

banner "结果"
if [ "$FAILED" = "0" ]; then
  echo "全部通过"
else
  echo "存在失败项"
fi
exit $FAILED
