#!/usr/bin/env bash
# zig-dnsmasq 端到端验证一键脚本。
#
# 依次跑：
#   1. 单元测试（zig build test）
#   2. 语义端到端（e2e.py）：hosts / 反查 / address / local / domain-needed / 转发 / 缓存 / TCP / 并发
#   3. 异步转发引擎（async.py）：并发加速比 / txid 解复用 / 缓存回写 / 类型不串台 / 截断转 TCP
#   4. 接口绑定（iface.py）：--interface/--except-interface 是否真的限制了监听地址
#   5. 多线程并行度（concurrency.py）：慢上游下测加速比
#   6. 上游负载均衡策略（balance.py）：5 种策略的分流特征 + dynamic 的重适应能力
#   7. 500 域名压测（stress.py）：缓存加速比、故障熔断与恢复
#   8. 真实上游解析（可选，需要能访问 8.8.8.8）
# 注意：2~6 全部以默认（异步引擎）模式运行；--sync-forward 只用于对比实验，
# 回归套件必须覆盖真正在跑的默认路径。
#
# 本脚本只跑**本地**套件（自己起守护进程，端口 15353）。
# 路由器侧的 A/B 回归（对照线上 zig 与 C 参考实例）是另一套，见 run_router_suite.sh。
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
PORT=15353
FAILED=0

cd "$ROOT"

stop_daemon() {
  pkill -x zig-dnsmasq 2>/dev/null
  sleep 0.3
}

echo "==================== 1. 编译 + 单元测试 ===================="
# 注意：必须显式指定优化级别。`zig build` 默认是 Debug，安全检查和未内联会让
# 热缓存吞吐掉到 ReleaseFast 的 1/4 左右（实测 25.7k vs 110.6k qps），
# 拿 Debug 构建做压测会得到完全没有参考价值的数字。
OPT="${OPT:-ReleaseFast}"
echo "构建模式: $OPT"
zig build -Doptimize="$OPT" || { echo "编译失败"; exit 1; }
zig build test -Doptimize="$OPT" || { echo "单元测试失败"; exit 1; }
echo "单元测试通过"

echo
echo "==================== 2. 语义端到端 ===================="
stop_daemon
./zig-out/bin/zig-dnsmasq -C "$HERE/dnsmasq-test.conf" -H "$HERE/hosts.txt" --threads=4 \
  > "$HERE/daemon.log" 2>&1 &
D=$!
sleep 1.3
(cd "$HERE" && python3 e2e.py) || FAILED=1
kill $D 2>/dev/null; wait $D 2>/dev/null

echo
echo "==================== 3. 异步转发引擎 ===================="
# async.py 自带假上游（UDP 15355 / TCP 15355），自己管好上游生命周期，
# 只需要我们按 async.conf 起一个守护进程。
stop_daemon
./zig-out/bin/zig-dnsmasq -C "$HERE/async.conf" > "$HERE/async-daemon.log" 2>&1 &
D=$!
sleep 1.3
(cd "$HERE" && python3 async.py) || FAILED=1
kill $D 2>/dev/null; wait $D 2>/dev/null

echo
echo "==================== 4. 接口绑定 ===================="
# iface.py 自己管理守护进程生命周期（要反复换配置重启），这里只需先清干净。
stop_daemon
(cd "$HERE" && python3 iface.py) || FAILED=1
stop_daemon

echo
echo "==================== 5. 多线程并行度 ===================="
stop_daemon
./zig-out/bin/zig-dnsmasq -C "$HERE/slow.conf" --threads=4 > "$HERE/slow.log" 2>&1 &
D=$!
sleep 1.3
(cd "$HERE" && python3 concurrency.py) || FAILED=1
kill $D 2>/dev/null; wait $D 2>/dev/null

echo
echo "==================== 6. 上游负载均衡策略 ===================="
stop_daemon
(cd "$HERE" && python3 balance.py) || FAILED=1
stop_daemon

echo
echo "==================== 7. 500 域名压测 ===================="
stop_daemon
(cd "$HERE" && python3 stress.py) || FAILED=1
stop_daemon

echo
echo "==================== 8. 真实上游解析（可选） ===================="
stop_daemon
./zig-out/bin/zig-dnsmasq -C "$HERE/real.conf" --threads=4 > "$HERE/real.log" 2>&1 &
D=$!
sleep 1.3
python3 - "$PORT" <<'PY' || echo "（真实上游不可用，已跳过）"
import socket, struct, sys
port = int(sys.argv[1])
def enc(n):
    o = b""
    for p in n.split("."):
        if p:
            o += bytes([len(p)]) + p.encode()
    return o + b"\x00"
try:
    msg = struct.pack("!HHHHHH", 0x4444, 0x0100, 1, 0, 0, 0) + enc("example.com") + struct.pack("!HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(6)
    s.sendto(msg, ("127.0.0.1", port))
    d, _ = s.recvfrom(4096); s.close()
    an = struct.unpack("!H", d[6:8])[0]
    rcode = struct.unpack("!H", d[2:4])[0] & 0xF
    print(f"example.com A -> rcode={rcode} ancount={an} len={len(d)}")
    sys.exit(0 if (rcode == 0 and an > 0) else 1)
except Exception as e:
    print("查询失败:", e)
    sys.exit(1)
PY
kill $D 2>/dev/null; wait $D 2>/dev/null

stop_daemon
echo
if [ "$FAILED" = "0" ]; then
  echo "==================== 全部通过 ===================="
else
  echo "==================== 存在失败项 ===================="
fi
echo "提示：路由器侧的 A/B 回归请另跑 ./run_router_suite.sh"
exit $FAILED
