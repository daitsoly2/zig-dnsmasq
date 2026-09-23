#!/bin/sh
# 为 verify_neg_nodata_type.py 起一个**缓存干净**的临时 zig 实例（默认 5561）。
#
# 用法：
#   sh setup_neg_instance.sh root@192.168.0.1              # 用线上二进制
#   BIN=/tmp/zig-candidate sh setup_neg_instance.sh root@192.168.0.1
#   sh setup_neg_instance.sh root@192.168.0.1 stop
#
# 配置直接取自线上 /var/etc/zig-dnsmasq.conf，只把 port 换掉 —— 保证测试实例与
# 线上行为一致（同样的上游、cache-size、threads、localise-queries 等）。
#
# 运维要点：起/停一律按 PID 文件，绝不用 pkill -f（会匹配 ssh 自身命令行而自杀），
# 也不用 killall（临时实例与线上同名 /usr/bin/zig-dnsmasq，会误杀线上服务）。
set -e
D=/home/ovo/.cache/dnsmasq-deploy
HOST=${1:?host}
ACTION=${2:-start}
PORT=${PORT:-5561}
BIN=${BIN:-/usr/bin/zig-dnsmasq}

run() { "$D/rsh.sh" "$HOST" "$1"; }

CONF=/tmp/zig-neg.conf
PIDF=/tmp/zig-neg.pid
LOG=/tmp/zig-neg.log
GEN=/var/etc/zig-dnsmasq.conf

if [ "$ACTION" = "stop" ]; then
  run "
    if [ -s $PIDF ]; then
      pid=\$(cat $PIDF)
      if kill -0 \$pid 2>/dev/null; then
        kill \$pid 2>/dev/null; sleep 1
        kill -0 \$pid 2>/dev/null && kill -9 \$pid 2>/dev/null
      fi
    fi
    rm -f $PIDF $CONF $LOG
    echo stopped"
  exit 0
fi

run "
  # 先清掉上一轮残留
  if [ -s $PIDF ]; then kill \$(cat $PIDF) 2>/dev/null; sleep 1; kill -9 \$(cat $PIDF) 2>/dev/null; fi
  rm -f $PIDF
  sed 's/^port=53/port=$PORT/' $GEN > $CONF
  grep -q '^port=$PORT' $CONF || { echo '配置里没有 port=53，无法改写' >&2; exit 1; }
  setsid nohup $BIN -C $CONF -k < /dev/null > $LOG 2>&1 &
  echo \$! > $PIDF
  sleep 3
  [ -s $PIDF ] || { echo 'PID 文件为空' >&2; exit 1; }
  echo \"started port=$PORT bin=$BIN pid=\$(cat $PIDF)\""
