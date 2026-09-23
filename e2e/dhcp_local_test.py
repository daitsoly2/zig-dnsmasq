#!/usr/bin/env python3
"""DHCPv4 本机握手回归测试（完全走回环，不打扰局域网）。

为什么要这么测
--------------
路由器上的 67 端口一旦对外服务，就会和上游那个 DHCP 服务器抢答，广播域里
所有设备都会收到两个 OFFER —— 这是不能接受的调试方式。而这个测试的做法是：
**把地址池设成 127.0.0.2**，客户端从 127.0.0.2 发包给 127.0.0.1:67。

于是：
  * 服务端收到的是「本机到本机」的报文，不会出现在任何物理网卡上；
  * 服务端按 odhcpd 的 `dhcpv4_set_dest_addr()` 逻辑，会把应答单播到
    yiaddr（= 127.0.0.2）:68 —— 127.0.0.0/8 整段都是本机地址，
    所以应答也只在回环里交付，客户端收得到。

这样一来，整条链路（收包 → 解析 → 分配 → 构造报文 → 选目标地址 → 发包）
都被真实地跑了一遍，却一个字节都没上局域网。

用法
----
    e2e/dhcp_local_test.py <被测试的二进制或其软链接> [--pool BASE]

默认池为 127.0.0.2/8。脚本会自己起/停守护进程，并使用独立的
/tmp/zd-dhcp 目录与 pid 文件，不会碰到系统上任何现有服务。
"""

import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

# 本机测试用非特权端口。理由：容器/沙箱里即使 uid=0 也可能没有
# CAP_NET_BIND_SERVICE，绑 67/68 会直接 EACCES。协议语义与端口无关
# （服务端比较的只是 chaddr/ciaddr/option 内容），换个端口测一样有效。
CLIENT_PORT = 6868
SERVER_PORT = 6767
MAGIC = b"\x63\x82\x53\x63"

MSG = {
    1: "DISCOVER",
    2: "OFFER",
    3: "REQUEST",
    4: "DECLINE",
    5: "ACK",
    6: "NAK",
    7: "RELEASE",
    8: "INFORM",
}

# 选项号
O_NETMASK = 1
O_ROUTER = 3
O_DNS = 6
O_HOSTNAME = 12
O_DOMAIN = 15
O_REQUESTED_IP = 50
O_LEASE_TIME = 51
O_MSG = 53
O_SERVER_ID = 54
O_T1 = 58
O_T2 = 59
O_CLIENT_ID = 61


def ip2b(s):
    return socket.inet_aton(s)


def b2ip(b):
    return socket.inet_ntoa(b)


def build(op, xid, mac, opts, ciaddr="0.0.0.0", flags=0, sname=b"", bootfile=b""):
    """拼一个 DHCP 报文（RFC2131 §2 的定长头 + magic cookie + TLV）"""
    pkt = struct.pack("!BBBBIHH", op, 1, len(mac), 0, xid, 0, flags)
    pkt += ip2b(ciaddr)
    pkt += b"\x00" * 4  # yiaddr
    pkt += b"\x00" * 4  # siaddr
    pkt += b"\x00" * 4  # giaddr
    pkt += mac + b"\x00" * (16 - len(mac))
    pkt += sname.ljust(64, b"\x00")[:64]
    pkt += bootfile.ljust(128, b"\x00")[:128]
    pkt += MAGIC
    for code, data in opts:
        pkt += bytes([code, len(data)]) + data
    pkt += b"\xff"
    if len(pkt) < 300:
        pkt += b"\x00" * (300 - len(pkt))
    return pkt


def parse(pkt):
    """解析应答，返回 (字段 dict, 选项 dict)"""
    if len(pkt) < 240 or pkt[236:240] != MAGIC:
        raise ValueError("不是 DHCP 报文（magic cookie 不对）")
    h = struct.unpack("!BBBBIHH", pkt[0:12])
    f = {
        "op": h[0],
        "htype": h[1],
        "hlen": h[2],
        "xid": h[4],
        "flags": h[6],
        "ciaddr": b2ip(pkt[12:16]),
        "yiaddr": b2ip(pkt[16:20]),
        "siaddr": b2ip(pkt[20:24]),
        "giaddr": b2ip(pkt[24:28]),
        "chaddr": pkt[28 : 28 + h[2]],
    }
    opts = {}
    i = 240
    while i < len(pkt):
        c = pkt[i]
        if c == 255:
            break
        if c == 0:
            i += 1
            continue
        if i + 1 >= len(pkt):
            break
        ln = pkt[i + 1]
        if i + 2 + ln > len(pkt):
            break
        opts.setdefault(c, []).append(pkt[i + 2 : i + 2 + ln])
        i += 2 + ln
    return f, opts


def msgtype(opts):
    v = opts.get(O_MSG)
    return v[0][0] if v else 0


def one(opts, code, default=None):
    v = opts.get(code)
    return v[0] if v else default


class Client:
    """模拟一个还没拿到地址的 DHCP 客户端（ciaddr = 自己的目标地址）"""

    def __init__(self, myip):
        self.myip = myip
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind((myip, CLIENT_PORT))
        self.sock.settimeout(3.0)
        self.mac = bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])

    def send(self, pkt):
        self.sock.sendto(pkt, ("127.0.0.1", SERVER_PORT))

    def recv(self):
        data, _peer = self.sock.recvfrom(2048)
        # parse() 返回 (字段, 选项) 二元组，直接透传给调用方解包
        return parse(data)

    def close(self):
        self.sock.close()


def run(binary, pool="127.0.0.2", netmask="255.0.0.0", lease="1h", static_ip="127.0.0.10"):
    # 临时目录可用环境变量覆盖：某些环境里 /tmp 是小的私有 tmpfs
    # （实测本机 /tmp 只有 10MB 且被沙箱叠加），写进去的日志会随会话消失，
    # 排查时看不到服务端输出。切到工作区内即可。
    tmpdir = os.environ.get("ZD_TEST_TMPDIR", "/tmp/zd-dhcp")
    shutil.rmtree(tmpdir, ignore_errors=True)
    os.makedirs(tmpdir, exist_ok=True)
    pidfile = os.path.join(tmpdir, "odhcpd.pid")
    statefile = os.path.join(tmpdir, "odhcpd.state")

    # 关键：**用软链接调用**，让 argv[0] 是 "odhcpd"。
    # 这样测的就是路由器上 procd 的真实启动方式（`command /usr/sbin/odhcpd`，
    # 不带任何参数），而不是靠 --applet= 走捷径。
    link = os.path.join(tmpdir, "odhcpd")
    os.symlink(os.path.abspath(binary), link)

    # v4 的权威文件（dnsmasq 格式）：2026-09-21 起 v4 只写这里、状态文件只写 v6。
    # 命令行模式必须显式指定，否则 v4 租约不持久化（重启即丢）。
    leasefile = os.path.join(tmpdir, "dhcp.leases")

    args = [
        link,
        # 池必须**大于**被保留的范围：保留地址不进动态池（dnsmasq 语义），
        # 若池里唯一的地址正好被保留，其它客户端会直接 PoolExhausted
        # （本夹具原来正是 `pool,pool` + 同址静态，加保留规则后就废了）。
        f"--dhcp-range={pool},{static_ip},{netmask},{lease}",
        # 静态绑定的地址必须**不同于**动态客户端要的地址，否则会被保留规则挡住，
        # 就测不到动态分配本身了。
        f"--dhcp-host=02:00:00:00:00:02,{static_ip},static-pc,2h",
        "--zd-server-id=127.0.0.1",
        f"--zd-hosts-dir={tmpdir}",
        # 单实例锁也放 tmpdir：闸门是全局的，不隔离的话几份测试会互相抢锁
        f"--zd-lock-file={os.path.join(tmpdir, 'odhcpd.lock')}",
        f"--dhcp-leasefile={statefile}",
        f"--zd-dnsmasq-leasefile={leasefile}",
        "--domain=test.lan",
        "--zd-port=%d" % SERVER_PORT,
        "--zd-client-port=%d" % CLIENT_PORT,
        "--log-dhcp",
        "-k",
    ]
    logf = open(os.path.join(tmpdir, "server.log"), "wb")
    proc = subprocess.Popen(args, stdout=logf, stderr=subprocess.STDOUT)
    time.sleep(0.6)

    fails = []

    def check(name, cond, extra=""):
        print(("  [OK]   " if cond else "  [FAIL] ") + name + ("" if cond else "  " + extra))
        if not cond:
            fails.append(name)

    try:
        if proc.poll() is not None:
            print("守护进程未能启动，日志：")
            print(open(os.path.join(tmpdir, "server.log")).read())
            return 1

        c = Client(pool)
        xid = 0x12345678
        mac = c.mac
        hostname = b"ziptest"
        cid = b"\x01" + mac

        # ---- 1. DISCOVER -> OFFER ----
        print("== 1. DISCOVER -> OFFER ==")
        c.send(
            build(
                1,
                xid,
                mac,
                [
                    (O_MSG, bytes([1])),
                    (O_REQUESTED_IP, ip2b(pool)),
                    (O_CLIENT_ID, cid),
                    (O_HOSTNAME, hostname),
                ],
            )
        )
        f, o = c.recv()
        check("op = BOOTREPLY(2)", f["op"] == 2, f"op={f['op']}")
        check("chaddr 回显", f["chaddr"] == mac, f"{f['chaddr'].hex()}")
        check("xid 回显", f["xid"] == xid)
        check("消息类型 = OFFER(2)", msgtype(o) == 2, MSG.get(msgtype(o), msgtype(o)))
        check("yiaddr = 池地址", f["yiaddr"] == pool, f"yiaddr={f['yiaddr']}")
        check(
            "动态客户端拿不到被静态保留的地址",
            f["yiaddr"] != static_ip,
            f"yiaddr={f['yiaddr']} 是保留给 02:00:00:00:00:02 的",
        )
        check("option 54 服务器标识", one(o, O_SERVER_ID) == ip2b("127.0.0.1"), str(one(o, O_SERVER_ID)))
        check("option 1 掩码", one(o, O_NETMASK) == ip2b(netmask))
        lt = struct.unpack("!I", one(o, O_LEASE_TIME))[0]
        check("option 51 租期 = 3600", lt == 3600, f"lease={lt}")
        t1 = struct.unpack("!I", one(o, O_T1))[0]
        t2 = struct.unpack("!I", one(o, O_T2))[0]
        check("option 58 T1 = 租期/2", t1 == 1800, f"t1={t1}")
        check("option 59 T2 = 租期*7/8", t2 == 3150, f"t2={t2}")
        check("option 15 域名", one(o, O_DOMAIN) == b"test.lan")
        sid = one(o, O_SERVER_ID)

        # ---- 2. REQUEST -> ACK ----
        print("== 2. REQUEST -> ACK ==")
        xid2 = 0x12345679
        c.send(
            build(
                1,
                xid2,
                mac,
                [
                    (O_MSG, bytes([3])),
                    (O_REQUESTED_IP, ip2b(pool)),
                    (O_SERVER_ID, sid),
                    (O_CLIENT_ID, cid),
                    (O_HOSTNAME, hostname),
                ],
            )
        )
        f2, o2 = c.recv()
        check("消息类型 = ACK(5)", msgtype(o2) == 5, MSG.get(msgtype(o2), msgtype(o2)))
        check("yiaddr 一致", f2["yiaddr"] == pool, f"yiaddr={f2['yiaddr']}")
        check("ACK 不带 option 54 以外的新服务器标识", one(o2, O_SERVER_ID) == sid)

        # ---- 3. 报表文件 ----
        print("== 3. 租约文件 ==")
        hosts = os.path.join(tmpdir, "odhcpd.hosts.lan")
        check("hosts 文件已生成", os.path.exists(hosts))
        if os.path.exists(hosts):
            content = open(hosts).read()
            print("    hosts 内容: " + repr(content))
            check(
                "hosts 行格式 ip<TAB>name.domain<TAB>name",
                content.strip() == "%s\tziptest.test.lan\tziptest" % pool,
                repr(content),
            )
        check("状态文件已生成", os.path.exists(statefile))
        if os.path.exists(statefile):
            st = open(statefile).read()
            print("    状态文件: " + repr(st))
            # 2026-09-21 起状态文件**只**写 v6 行：v4 若也写这里，LuCI 的
            # getDHCPLeases 会把同一批 v4 租约读两遍（一次带 macaddr、一次带 duid）。
            check("状态文件不再写 v4 行", " ipv4 " not in st, repr(st))
        # v4 的权威文件：dnsmasq 格式，MAC 带冒号（对照 C lease.c:286）
        check("v4 租约文件已生成", os.path.exists(leasefile))
        if os.path.exists(leasefile):
            lf = open(leasefile).read()
            print("    v4 租约文件: " + repr(lf))
            check("v4 租约文件含本次租约（MAC 带冒号）",
                  c.mac.hex(":") in lf and pool in lf, repr(lf))

        # ---- 4. 静态绑定：另一个 MAC 不应当拿到静态地址 ----
        print("== 4. 静态绑定（地址已被动态租出时的优先级）==")
        # 客户端 socket 绑的是**自己会被单播到的那个地址**（Client 会 bind
        # (myip, CLIENT_PORT)），所以这里必须用 static_ip —— 它拿到的 OFFER 是
        # 单播到 127.0.0.10 的，绑在 .2 上收不到。
        c2 = Client(static_ip)
        c2.mac = bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x02])
        c2.send(
            build(
                1,
                0xAA000001,
                c2.mac,
                [(O_MSG, bytes([1])), (O_CLIENT_ID, b"\x01" + c2.mac)],
            )
        )
        try:
            f3, o3 = c2.recv()
            check(
                "静态绑定客户端拿到它的保留地址",
                f3["yiaddr"] == static_ip,
                f"yiaddr={f3['yiaddr']} 期望={static_ip}",
            )
        except socket.timeout:
            check("静态绑定客户端应当收到 OFFER", False, "超时（池只有 1 个地址，可能已耗尽）")
        c2.close()

        # ---- 5. 畸形包必须被丢弃且不影响服务 ----
        print("== 5. 畸形报文 ==")
        bogus = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        bogus.sendto(b"\x01\x02\x03" + b"\x00" * 300, ("127.0.0.1", SERVER_PORT))
        bogus.sendto(b"\x01" * 240 + b"\xde\xad\xbe\xef" + b"\xff", ("127.0.0.1", SERVER_PORT))
        time.sleep(0.2)
        check("服务端仍然存活", proc.poll() is None)

        c.close()
    finally:
        try:
            proc.send_signal(signal.SIGTERM)
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
        logf.close()

    print()
    if fails:
        print("失败 %d 项: %s" % (len(fails), ", ".join(fails)))
        print("--- 守护进程日志 ---")
        print(open(os.path.join(tmpdir, "server.log")).read())
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(run(sys.argv[1]))
