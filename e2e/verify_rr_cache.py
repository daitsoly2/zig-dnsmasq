#!/usr/bin/env python3
"""路由器侧：判定各 RR 类型是否被**本地缓存**（并暴露重复记录堆积）。

背景：dnsmasq 只对 A/AAAA/CNAME，外加 SRV/PTR（`flags |= F_RR`，见 rfc1035.c:810-812）
      做正向缓存；TXT/MX 等不入缓存（insert = 0）。本移植的 flags 映射
      （rfc1035.zig 的 `want`/extractAddresses 头部 switch）只覆盖 A/AAAA/CNAME，
      且 insertEx 无条件新建记录、没有 C 的 cache_scan_free 去重步骤。

方法：用守护进程自己的 SIGUSR1 统计做「预热 1 次 + 连打 N 次」，
      看 cache miss（Zig）/ queries forwarded（C）的增量。
        ≈1  → 本地缓存命中
        ≈N  → 每次都转发，本地未缓存
      同时打一个 A 作对照，抵消家用路由器上的背景流量。

用法：
  verify_rr_cache.py [N] [--zig-port 53] [--c-port 5352] [--zig-pid auto] [--c-pid auto]
需要：~/.cache/dnsmasq-deploy/rsh.sh 能免密登录 root@192.168.0.1
"""
import argparse
import re
import socket
import struct
import subprocess
import sys
import time

RSH = "/home/ovo/.cache/dnsmasq-deploy/rsh.sh"
HOST = "root@192.168.0.1"

CASES = [
    ("A(对照)", "www.baidu.com", 1),
    ("AAAA", "www.baidu.com", 28),
    ("CNAME", "www.github.com", 5),
    ("SRV", "_sip._tcp.sip2sip.info", 33),
    ("PTR", "8.8.8.8.in-addr.arpa", 12),
    ("TXT", "cloudflare.com", 16),
    ("MX", "gmail.com", 15),
]


def sh(cmd):
    return subprocess.run([RSH, HOST, cmd], capture_output=True, text=True).stdout


def mk(name, qtype, tid=0x4B4B):
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for lab in name.encode().split(b"."):
        if lab:
            q += bytes([len(lab)]) + lab
    return q + b"\x00" + struct.pack(">HH", qtype, 1)


def ask(port, name, qtype, timeout=4):
    """返回 ancount（-1 表示无应答）"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(mk(name, qtype), ("192.168.0.1", port))
        d, _ = s.recvfrom(4096)
        return struct.unpack(">H", d[6:8])[0] if len(d) > 12 else -1
    except Exception:
        return -1
    finally:
        s.close()


class Stat:
    """从 SIGUSR1 输出里取「转发计数」：Zig 用 cache miss，C 用 queries forwarded。"""

    def __init__(self, kind, port, pid):
        self.kind, self.pid = kind, pid
        self.port = port

    def read(self):
        sh(f"kill -USR1 {self.pid}")
        time.sleep(1.3)
        if self.kind == "zig":
            out = sh("logread | grep -E 'cache entries=' | tail -1")
            m = re.search(r"miss=(\d+)", out)
        else:
            out = sh("logread | grep -E 'queries forwarded' | tail -1")
            m = re.search(r"forwarded (\d+)", out)
        if not m:
            raise SystemExit(f"解析 {self.kind} 统计失败：{out!r}")
        return int(m.group(1))


def auto_pid(kind):
    if kind == "zig":
        return sh("pgrep -P $(pgrep -x zig-dnsmasq)").strip().split("\n")[0]
    return sh("pgrep -f dnsmasq-c293").strip().split("\n")[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("n", nargs="?", type=int, default=10)
    ap.add_argument("--zig-port", type=int, default=53)
    ap.add_argument("--c-port", type=int, default=5352)
    ap.add_argument("--zig-pid", default="auto")
    ap.add_argument("--c-pid", default="auto")
    a = ap.parse_args()

    zig = Stat("zig", a.zig_port, auto_pid("zig") if a.zig_pid == "auto" else a.zig_pid)
    c = Stat("c", a.c_port, auto_pid("c") if a.c_pid == "auto" else a.c_pid)
    if not zig.pid:
        raise SystemExit("找不到 zig-dnsmasq 真实 PID")
    if not c.pid:
        print("警告：找不到 C 参考实例，仅测 Zig（C 侧会显示 --）")

    print(f"预热 1 次 + 连打 {a.n} 次；转发增量 ≈1 → 本地缓存，≈{a.n} → 每次都转发\n")
    print(f"{'类型':9s} {'名字':30s} | {'Zig 转发':>8s} {'Zig 判读':<12s} | {'C 转发':>7s} {'C 判读':<12s} | 对比")
    print("-" * 118)

    for label, name, qt in CASES:
        an1 = ask(zig.port, name, qt)
        z0 = zig.read()
        seq = [ask(zig.port, name, qt) for _ in range(a.n)]
        z1 = zig.read()
        dz = z1 - z0

        dc = None
        if c.pid:
            ask(c.port, name, qt)
            c0 = c.read()
            for _ in range(a.n):
                ask(c.port, name, qt)
            c1 = c.read()
            dc = c1 - c0

        def verdict(d):
            if d is None:
                return "--"
            return "本地缓存" if d <= 2 else ("每次转发" if d >= a.n else "部分转发")

        vz, vc = verdict(dz), verdict(dc)
        if dc is None:
            note = "--"
        elif vz == vc:
            note = "一致"
        else:
            note = "** 不一致 **"
        print(f"{label:9s} {name:30s} | {dz:8d} {vz:<12s} | "
              f"{(dc if dc is not None else 0):7d} {vc:<12s} | {note}")

        if len(set(seq)) > 1:
            print(f"{'':41s} 注意：Zig 的 an 在同组内变化 {seq} —— 可能是重复记录堆积或上游竞速")
        elif seq and seq[0] > 0:
            # 记录一次 an 稳定性（重复记录堆积的直观指标）
            print(f"{'':41s} Zig an 稳定 = {seq[0]}")


if __name__ == "__main__":
    main()
