#!/usr/bin/env python3
"""squat_test.py —— 地址冲突/保留地址的回归测试（回环，不出物理网卡）

背景（2026-09-21 用户报告）：手机持有一份有效租约时，PC 重连后拿到了同一个
地址，导致重复 IP、局域网卡死。本脚本用回环复现这些场景，确认服务端行为：

  场景 1  有效租约保护：A 持有 X，B 点名要 X → B 不能拿到 X
  场景 2  过期后可回收：A 的租约过期后，B 点名要 X 可以被授予
  场景 3  保留地址排他：X 被 --dhcp-host 保留给 C，A/B 都不能拿到 X
  场景 4  租约复用不串名：地址被回收给新客户端时，不能带着上一个客户端的
          主机名（DNS 里会出现「同名两址」的假象）

用法：e2e/squat_test.py <二进制> [--verbose]
注意：客户端必须绑 0.0.0.0（绑具体 127.x 收不到单播到池地址的 OFFER）。
"""

import os
import shutil
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dhcp_local_test import build, parse, msgtype, one, CLIENT_PORT, SERVER_PORT  # noqa: E402

POOL_START = "127.0.0.10"
POOL_END = "127.0.0.20"
NETMASK = "255.0.0.0"
# 临时目录可用环境变量覆盖（理由见 dhcp_local_test.py 里的同名说明）
TMPDIR = os.environ.get("ZD_TEST_TMPDIR", "/tmp/zd-squat")


class Client:
    def __init__(self, mac_hex, hostname=None):
        self.mac = bytes.fromhex(mac_hex)
        self.hostname = hostname
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind(("0.0.0.0", CLIENT_PORT))
        self.sock.settimeout(2.5)
        self.xid = 0x2000

    def close(self):
        self.sock.close()

    def _opts(self, kind, want, sid):
        opts = [(53, bytes([kind]))]
        if want:
            opts.append((50, bytes(int(x) for x in want.split("."))))
        if self.hostname:
            opts.append((12, self.hostname.encode()))
        if sid is not None:
            opts.append((54, bytes(sid)))
        return opts

    def discover(self, want=None):
        self.xid += 1
        self.sock.sendto(build(1, self.xid, self.mac, self._opts(1, want, None)), ("127.0.0.1", SERVER_PORT))
        f, o = parse(self.sock.recv(2048))
        return f["yiaddr"], one(o, 54)

    def request(self, want, sid):
        self.xid += 1
        self.sock.sendto(build(1, self.xid, self.mac, self._opts(3, want, sid)), ("127.0.0.1", SERVER_PORT))
        try:
            f, o = parse(self.sock.recv(2048))
        except socket.timeout:
            return None, "TIMEOUT"
        return f["yiaddr"], msgtype(o)

    def handshake(self, want=None):
        """DISCOVER -> REQUEST，返回 (地址, ACK类型)；无应答返回 (None, ...)"""
        ip, sid = self.discover(want)
        if sid is None:
            return None, "NO-SID"
        return self.request(want or ip, sid)


def stop_server(proc):
    """停服务端并**等它真的退出**。

    ★ 不能只 terminate 就 sleep：旧进程还活着时，下一次 start_server 会
    rmtree(TMPDIR) 把锁文件删掉，旧进程仍握着旧 inode 的锁，新进程新建一个
    空的锁文件就"抢到"了 —— 于是单实例闸门检测到旧进程仍在跑而拒绝启动，
    表现为「服务端起不来、客户端超时」。实测踩过。
    """
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=3)


def start_server(binary, extra=()):
    shutil.rmtree(TMPDIR, ignore_errors=True)
    os.makedirs(TMPDIR, exist_ok=True)
    link = os.path.join(TMPDIR, "odhcpd")
    os.symlink(os.path.abspath(binary), link)
    args = [link,
            f"--dhcp-range={POOL_START},{POOL_END},{NETMASK},1h",
            "--zd-server-id=127.0.0.1",
            f"--zd-hosts-dir={TMPDIR}",
            # 单实例锁也放 TMPDIR：闸门是全局的，不隔离的话会和别的测试抢锁
            f"--zd-lock-file={TMPDIR}/odhcpd.lock",
            f"--dhcp-leasefile={TMPDIR}/state",
            # v4 的权威文件（dnsmasq 格式）。2026-09-21 起 v4 只写这里，
            # 状态文件只留 v6 行；不指定的话 v4 租约不持久化。
            f"--zd-dnsmasq-leasefile={TMPDIR}/dhcp.leases",
            "--domain=test.lan",
            f"--zd-port={SERVER_PORT}", f"--zd-client-port={CLIENT_PORT}",
            "--log-dhcp", "-k", *extra]
    logf = open(os.path.join(TMPDIR, "server.log"), "wb")
    proc = subprocess.Popen(args, stdout=logf, stderr=subprocess.STDOUT)
    time.sleep(0.8)
    return proc


def state_rows():
    """返回 {ip: (mac, hostname)}，来自 **v4 的权威文件**（dnsmasq 格式）。

    2026-09-21 起 v4 不再写状态文件（状态文件只留 v6 行，否则 LuCI 的
    getDHCPLeases 会把同一批 v4 租约读两遍），所以这里读 TMPDIR/dhcp.leases。
    格式：`<到期epoch> <mac> <ip> <主机名|*> <clid|*>`。
    主机名 `*` 归一化成 `-`，与调用方原本对状态文件的判断口径保持一致。
    """
    out = {}
    path = os.path.join(TMPDIR, "dhcp.leases")
    if not os.path.exists(path):
        return out
    for line in open(path):
        f = line.split()
        if len(f) >= 4:
            out[f[2]] = (f[1], "-" if f[3] == "*" else f[3])
    return out


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    binary = sys.argv[1]
    fails = []

    def check(name, cond, extra=""):
        print(("  [OK]   " if cond else "  [FAIL] ") + name + ("" if cond else "   " + extra))
        if not cond:
            fails.append(name)

    # ---------------- 场景 1：有效租约保护 ----------------
    print("== 场景 1：A 持有 X，B 点名要 X ==")
    proc = start_server(binary)
    try:
        a = Client("020000aa0011", "phone")
        ipa, ta = a.handshake()
        check("A 拿到地址", ipa is not None and ta == 5, f"ip={ipa} type={ta}")
        b = Client("020000aa0022", "pc")
        off_b, _ = b.discover(want=ipa)
        check("B 的 OFFER 不等于 A 的地址", off_b != ipa, f"offer={off_b} A={ipa}")
        ipb, tb = b.handshake(want=ipa)
        check("B 不能拿到 A 的地址", ipb != ipa, f"B={ipb} A={ipa} type={tb}")
        rows = state_rows()
        check("状态文件里 A 的地址归属未变", rows.get(ipa, ("?",))[0] == "02:00:00:aa:00:11",
              f"rows={rows}")
        a.close()
        b.close()
    finally:
        stop_server(proc)

    # ---------------- 场景 2：过期后可以回收 ----------------
    print("== 场景 2：A 的租约过期后，B 点名要 X ==")
    proc = start_server(binary, extra=["--dhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,1h"])
    try:
        a = Client("020000aa0011", "phone")
        ipa, _ = a.handshake()
        a.close()
        stop_server(proc)
        # 把 A 的租约写成「已过期」再重启服务端
        # 把 A 的租约写成「已过期」：v4 现在在 dnsmasq 文件里，第 0 字段是到期 epoch
        path = os.path.join(TMPDIR, "dhcp.leases")
        lines = []
        for line in open(path):
            f = line.split()
            if len(f) >= 4:
                f[0] = "1"  # 到期时间放到很久以前
                line = " ".join(f) + "\n"
            lines.append(line)
        open(path, "w").writelines(lines)

        proc = start_server(binary, extra=["--dhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,1h"])
        b = Client("020000aa0022", "pc")
        ipb, tb = b.handshake(want=ipa)
        check("过期地址可被重新分配", ipb == ipa, f"B={ipb} 期望={ipa} type={tb}")
        b.close()
    finally:
        stop_server(proc)

    # ---------------- 场景 3：保留地址排他 ----------------
    print("== 场景 3：X 被 --dhcp-host 保留给 C ==")
    reserve = POOL_START
    proc = start_server(binary, extra=[f"--dhcp-host=02:00:00:aa:00:33,{reserve},server-box"])
    try:
        a = Client("020000aa0011", "phone")
        ipa, _ = a.handshake()
        check("普通客户端不会拿到保留地址", ipa != reserve, f"A={ipa} 保留={reserve}")
        b = Client("020000aa0022", "pc")
        ipb, _ = b.handshake(want=reserve)
        check("点名要保留地址也拿不到", ipb != reserve, f"B={ipb} 保留={reserve}")
        c = Client("020000aa0033", "server-box")
        ipc, tc = c.handshake()
        check("保留者本人拿到该地址", ipc == reserve, f"C={ipc} 期望={reserve} type={tc}")
        a.close()
        b.close()
        c.close()
    finally:
        stop_server(proc)

    # ---------------- 场景 4：回收地址不带旧主机名 ----------------
    print("== 场景 4：地址回收后不携带上一个客户端的主机名 ==")
    proc = start_server(binary)
    try:
        a = Client("020000aa0011", "phone")
        ipa, _ = a.handshake()
        a.close()
        # A 释放：给 B 一个更长租期占满池里其它地址前，直接让 B 点名要 X 且 A 已过期
        stop_server(proc)
        # 把 A 的租约写成「已过期」：v4 现在在 dnsmasq 文件里，第 0 字段是到期 epoch
        path = os.path.join(TMPDIR, "dhcp.leases")
        lines = []
        for line in open(path):
            f = line.split()
            if len(f) >= 4:
                f[0] = "1"  # 到期时间放到很久以前
                line = " ".join(f) + "\n"
            lines.append(line)
        open(path, "w").writelines(lines)
        proc = start_server(binary)
        b = Client("020000aa0022", "pc")
        ipb, _ = b.handshake(want=ipa)
        rows = state_rows()
        name = rows.get(ipb, ("", "-"))[1]
        check("新客户端行内不残留旧主机名", name in ("-", "pc"), f"rows={rows}")
        b.close()
    finally:
        stop_server(proc)

    print()
    if fails:
        print(f"失败 {len(fails)} 项: {fails}")
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
