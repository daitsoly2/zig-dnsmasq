#!/usr/bin/env bash
# cpu_bench.sh — 用「服务器自身消耗的 CPU 时间」度量效率
#
# 前面的端到端 QPS 受限于负载生成器：客户端和服务器抢同一批 8 个核。
# 这里改测 /proc/<pid>/stat 的 utime+stime 增量，得到「每处理一个查询
# 花多少微秒 CPU」——与客户端快慢、核数多少都无关，可以横向比较。
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
PORT=15355
THREADS="${THREADS:-6}"
DUR="${DUR:-5}"
WINDOW="${WINDOW:-64}"
MODE="${MODE:-hot}"
HOT_NAMES="${HOT_NAMES:-1000}"

CONF="$HERE/bench1.conf"
cat > "$CONF" <<EOF
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

pkill -9 -x mockup 2>/dev/null
"$HERE/mockup" 15361 &
UP_PID=$!
sleep 0.4

# 读进程累计 CPU 时间（单位 jiffies，含所有线程）
cpu_jiffies() {
  awk '{print $14+$15}' "/proc/$1/stat" 2>/dev/null || echo 0
}

measure() {
  local which="$1" label="$2"
  case "$which" in
    c)   /mnt/c/dnsmasq-2.93/src/dnsmasq -C "$CONF" -k --user="$(id -un)" \
           --pid-file=/tmp/cb.pid --log-facility=/tmp/cb-c.log & ;;
    zig) "$ROOT/zig-out/bin/zig-dnsmasq" -C "$CONF" --balance=sticky \
           --threads="$THREADS" > /tmp/cb-zig.log 2>&1 & ;;
    old) "${OLD_BIN:-/tmp/zig-rf}" -C "$CONF" --balance=sticky \
           --threads="$THREADS" > /tmp/cb-old.log 2>&1 & ;;
    dbg) "$ROOT/zig-out-debug/bin/zig-dnsmasq" -C "$CONF" --balance=sticky \
           --threads="$THREADS" > /tmp/cb-dbg.log 2>&1 & ;;
  esac
  S_PID=$!
  sleep 1.2

  local c0 c1 out
  c0=$(cpu_jiffies "$S_PID")
  out=$("$HERE/dnsbench" -t "$THREADS" -d "$DUR" -w "$WINDOW" -p "$PORT" \
        --mode="$MODE" --names="$HOT_NAMES" 2>/dev/null)
  c1=$(cpu_jiffies "$S_PID")

  local recv qps cpu_us
  recv=$(echo "$out" | sed -n 's/.*recv=\([0-9]*\).*/\1/p')
  qps=$(echo "$out"  | sed -n 's/.*qps=\([0-9]*\).*/\1/p')
  if [ "${recv:-0}" -gt 0 ]; then
    # jiffies -> µs：HZ 通常为 100，即 1 jiffy = 10000 µs
    cpu_us=$(awk -v d="$((c1-c0))" -v n="$recv" 'BEGIN{printf "%.1f", d*10000/n}')
  else
    cpu_us="n/a"
  fi
  printf "  %-34s 完成 %-9s qps=%-8s 服务器CPU %6s µs/查询\n" \
         "$label" "$recv" "${qps:-0}" "$cpu_us"
  kill "$S_PID" 2>/dev/null; wait "$S_PID" 2>/dev/null
  sleep 0.4
}

echo "==============================================================="
echo " 单查询 CPU 开销对比  模式=$MODE  负载线程=$THREADS  时长=${DUR}s"
echo "==============================================================="
if [ "$#" -eq 0 ]; then
  set -- c zig dbg
fi
for which in "$@"; do
  case "$which" in
    c)   measure c   "C dnsmasq 2.93 (-O2)" ;;
    zig) measure zig "Zig 0.16 ReleaseFast" ;;
    old) measure old "Zig 0.16 ReleaseFast（优化前）" ;;
    dbg) measure dbg "Zig 0.16 Debug" ;;
  esac
done
echo
echo "说明：µs/查询 越小越好，该指标不受负载生成器性能影响。"
