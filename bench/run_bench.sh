#!/usr/bin/env bash
# run_bench.sh — C 版 dnsmasq 与 Zig 版同条件吞吐对比
#
# 关键点：
#   · 两者使用**完全相同的配置**与**同一组**零延迟假上游
#   · 关闭 log-queries（dnsmasq 的 --log-queries 是调试开关，
#     开着它测出来的是磁盘/终端写入速度，不是 DNS 能力）
#   · 用 C 写的 dnsbench 做负载，避免 Python GIL 成为瓶颈
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
PORT=15355
UP_PORTS="15361 15362 15363 15364"
THREADS="${THREADS:-8}"
DUR="${DUR:-5}"
WINDOW="${WINDOW:-64}"
HOT_NAMES="${HOT_NAMES:-1000}"
COLD_NAMES="${COLD_NAMES:-200000}"

CONF="$HERE/bench.conf"
cat > "$CONF" <<EOF
port=$PORT
cache-size=2000
no-resolv
no-poll
listen-address=127.0.0.1
server=127.0.0.1#15361
server=127.0.0.1#15362
server=127.0.0.1#15363
server=127.0.0.1#15364
EOF

# 单上游配置：与 Zig 版 sticky 模式比对时使用（C 版默认对同组上游会全部转发）
CONF1="$HERE/bench1.conf"
cat > "$CONF1" <<EOF
port=$PORT
cache-size=2000
no-resolv
no-poll
listen-address=127.0.0.1
server=127.0.0.1#15361
EOF

cleanup() {
  [ -n "${UP_PID:-}" ] && kill "$UP_PID" 2>/dev/null
  [ -n "${S_PID:-}" ] && kill "$S_PID" 2>/dev/null
  wait 2>/dev/null
}
trap cleanup EXIT

"$HERE/mockup" $UP_PORTS &
UP_PID=$!
sleep 0.4

start_server() {
  local which="$1"
  case "$which" in
    c)
      # C 版：前台运行，不用 root 特性
      /mnt/c/dnsmasq-2.93/src/dnsmasq -C "$CONF" -k --user="$(id -un)" \
        --pid-file=/tmp/bench-dnsmasq.pid --log-facility=/tmp/bench-c.log &
      ;;
    c1)
      /mnt/c/dnsmasq-2.93/src/dnsmasq -C "$CONF1" -k --user="$(id -un)" \
        --pid-file=/tmp/bench-dnsmasq.pid --log-facility=/tmp/bench-c1.log &
      ;;
    zig)
      "$ROOT/zig-out/bin/zig-dnsmasq" -C "$CONF" --balance=sticky \
        --threads="$THREADS" > /tmp/bench-zig.log 2>&1 &
      ;;
    zig1)
      "$ROOT/zig-out/bin/zig-dnsmasq" -C "$CONF1" --balance=sticky \
        --threads="$THREADS" > /tmp/bench-zig1.log 2>&1 &
      ;;
    zig-dbg)
      "$ROOT/zig-out-debug/bin/zig-dnsmasq" -C "$CONF" --balance=sticky \
        --threads="$THREADS" > /tmp/bench-zigdbg.log 2>&1 &
      ;;
  esac
  S_PID=$!
  sleep 1.2
}

run_case() {
  local which="$1" label="$2"
  echo "───────────────────────────────────────────────────────────────"
  echo "  服务器: $label   线程=$THREADS 窗口=$WINDOW 时长=${DUR}s"
  echo "───────────────────────────────────────────────────────────────"

  echo "  [热缓存] 预热 $HOT_NAMES 个域名后反复查询（纯缓存命中路径）"
  "$HERE/dnsbench" -t "$THREADS" -d "$DUR" -w "$WINDOW" -p "$PORT" \
      --mode=hot --names="$HOT_NAMES" 2>/dev/null | sed 's/^/    /'

  echo "  [冷转发] 每次查询都是全新域名（完整转发路径）"
  "$HERE/dnsbench" -t "$THREADS" -d "$DUR" -w "$WINDOW" -p "$PORT" \
      --mode=cold --names="$COLD_NAMES" 2>/dev/null | sed 's/^/    /'

  echo "  [固定名] 永远查同一个名字（单条目缓存，最热路径）"
  "$HERE/dnsbench" -t "$THREADS" -d "$DUR" -w "$WINDOW" -p "$PORT" \
      --mode=fixed --names=1 2>/dev/null | sed 's/^/    /'
  echo
}

echo "==============================================================="
echo " DNS 吞吐基准：C dnsmasq 2.93  vs  Zig 0.16 移植版"
echo " CPU: $(nproc) 核    $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)"
echo "==============================================================="
echo

for which in "$@"; do
  case "$which" in
    c)     start_server c     && run_case c     "C dnsmasq 2.93 (-O2)，4 上游" ;;
    c1)    start_server c1    && run_case c1    "C dnsmasq 2.93 (-O2)，单上游" ;;
    zig)   start_server zig   && run_case zig   "Zig 0.16 ReleaseFast，4 上游 sticky" ;;
    zig1)  start_server zig1  && run_case zig1  "Zig 0.16 ReleaseFast，单上游 sticky" ;;
    zig-dbg) start_server zig-dbg && run_case zig-dbg "Zig 0.16 Debug，4 上游 sticky" ;;
  esac
  kill "$S_PID" 2>/dev/null; wait "$S_PID" 2>/dev/null
  sleep 0.5
done
