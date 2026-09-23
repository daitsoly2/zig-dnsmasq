#!/bin/sh
# 为 verify_address_rule.py 起两个带 address= 规则的临时实例（C 5362 / zig 54）。
# 用法：sh setup_addr_instances.sh root@192.168.0.1          （启动）
#      sh setup_addr_instances.sh root@192.168.0.1 stop    （停止并清理）
#
# 运维要点（本项目踩过的坑）：
#   * 绝不要用 `pkill -f '... -C /tmp/xxx.conf'`：该模式会匹配到 ssh 自身的命令行，
#     导致 ssh 会话被自己杀掉、命令提前中断，而目标进程反而活着（静默失败）。
#   * zig 侧临时实例与线上服务同名（/usr/bin/zig-dnsmasq），`killall zig-dnsmasq`
#     会一并误杀线上进程。因此一律按 PID 文件精确操作。
#   * 启动后必须校验 PID 文件非空；停止时先 TERM、再 KILL 兜底，最后删 PID/conf。
set -e
D=/home/ovo/.cache/dnsmasq-deploy
HOST=${1:?host}
ACTION=${2:-start}

run() { "$D/rsh.sh" "$HOST" "$1"; }

CONF_C=/tmp/c293-addr.conf
CONF_Z=/tmp/zig-addr.conf
PID_C=/tmp/c293-addr.pid
PID_Z=/tmp/zig-addr.pid

if [ "$ACTION" = "stop" ]; then
  # 按 PID 文件精确杀，绝不按进程名/命令行匹配。
  # 对每个 PID：先 TERM，睡 1s 仍存活则 KILL；随后清理 pid 与 conf。
  run "
    for pf in $PID_C $PID_Z; do
      if [ -s \$pf ]; then
        pid=\$(cat \$pf)
        if kill -0 \$pid 2>/dev/null; then
          kill \$pid 2>/dev/null
          sleep 1
          kill -0 \$pid 2>/dev/null && kill -9 \$pid 2>/dev/null
        fi
      fi
    done
    rm -f $PID_C $PID_Z $CONF_C $CONF_Z /tmp/c293-addr.log /tmp/zig-addr.log
    echo stopped"
  exit 0
fi

# 启动前先确保没有上一轮残留（避免端口占用/同名混淆）。
run "if [ -s $PID_C ]; then kill \$(cat $PID_C) 2>/dev/null; fi;
     if [ -s $PID_Z ]; then kill \$(cat $PID_Z) 2>/dev/null; fi;
     sleep 1; rm -f $PID_C $PID_Z"

run "cat > $CONF_C <<'EOF'
port=5362
cache-size=800
interface=br-lan
resolv-file=/tmp/resolv.conf.d/resolv.conf.auto
all-servers
domain=lan
local=/lan/
expand-hosts
domain-needed
address=/aat4.example/10.9.9.9
address=/aat6.example/fd00::9
address=/aatboth.example/10.9.9.8
address=/aatboth.example/fd00::8
address=/aat4.qq.com/10.9.9.9
EOF
sed 's/port=5362/port=54/' $CONF_C > $CONF_Z
nohup /tmp/dnsmasq-c293      -C $CONF_C -k < /dev/null > /tmp/c293-addr.log 2>&1 &
echo \$! > $PID_C
nohup /usr/bin/zig-dnsmasq   -C $CONF_Z -k < /dev/null > /tmp/zig-addr.log  2>&1 &
echo \$! > $PID_Z
sleep 3
[ -s $PID_C ] && [ -s $PID_Z ] && echo started || { echo 'PID file empty' >&2; exit 1; }"
