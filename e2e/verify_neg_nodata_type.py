#!/usr/bin/env python3
"""负缓存类型串扰回归：AAAA 的 NODATA 不得截胡同名的 A 查询。

为什么单独一个套件
------------------
上游对「有 A、没有 AAAA」的名字（ghfast.top / api.github.com / github.io /
dev.to …）回 AAAA 的 NODATA 后，本移植曾把这条**按类型**的负记录当成
「这个名字没有记录」，于是同名的 A 查询也回空应答 —— 客户端表现为
「个别域名解析不了」，而且要等到负数 TTL（最长 1h）到期才自愈；
期间只要还有客户端查 AAAA，负记录就被不断刷新，看起来像永久故障。

根因（rfc1035.zig 的负缓存分支）：查找负记录时只按 F_NEG 匹配、
**没有校验记录自己的类型位**（F_IPV4 / F_IPV6），接着又只用
`want != 0`（只表示"这是 A/AAAA 查询"）当门槛，于是 AAAA 的记录
也能回答 A 的查询。C 版不会踩到：它那个位置的查找只匹配
F_CNAME | F_NXDOMAIN，纯 NODATA 记录根本进不来，NODATA 只在按类型
过滤的循环里被使用。

最小复现（确定性，无需并发）
--------------------------
    1) 查 <name>/AAAA  → NODATA（该名字确实没有 AAAA，正确）
    2) 紧接着查 <name>/A → 应为 A 记录；旧实现回 NODATA（错）

因此本套件必须跑在**缓存干净**的实例上：若 A 记录已缓存，第 2 步会
从缓存直接答出而掩盖问题。用 setup_neg_instance.sh 起一个临时实例，
它每次都是干净启动。

用法：
    sh setup_neg_instance.sh root@192.168.0.1          # 起临时实例(5561)
    python3 verify_neg_nodata_type.py --port 5561
    sh setup_neg_instance.sh root@192.168.0.1 stop     # 收拾
"""
import argparse
import socket
import struct
import sys

T_A, T_AAAA = 1, 28

# 「有 A、无 AAAA」的候选名（上游实测确认）。第 1 步验证它们确实没有 AAAA，
# 若有 AAAA 则跳过该名字 —— 那样就没有负记录，测不到本 bug。
NAMES = ["ghfast.top", "api.github.com", "github.io", "dev.to", "gitclone.com"]


def mk(name, qtype, tid=0x2A2A):
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for lab in name.encode().split(b"."):
        if lab:
            q += bytes([len(lab)]) + lab
    q += b"\x00" + struct.pack(">HH", qtype, 1)
    return q


def ask(port, name, qtype, host="192.168.0.1", timeout=6):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(mk(name, qtype), (host, port))
        d, _ = s.recvfrom(4096)
    except Exception:
        return None
    finally:
        s.close()
    f, = struct.unpack(">H", d[2:4])
    an, ns, _ = struct.unpack(">HHH", d[6:12])
    return {"rc": f & 0xF, "an": an, "ns": ns}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=5561, help="临时 zig 实例端口")
    ap.add_argument("--host", default="192.168.0.1")
    a = ap.parse_args()

    if ask(a.port, "example.com", T_A, a.host) is None:
        print(f"端口 {a.port} 无应答 —— 请先按文件头用 setup_neg_instance.sh 起临时实例")
        return 2

    fails = 0
    tested = 0
    print(f"{'name':22s} {'步骤1 AAAA':>14s}  {'步骤2 A':>14s}   结论")
    for n in NAMES:
        # 步骤 1：查 AAAA。该名字没有 AAAA → 实例应缓存一条「AAAA 的 NODATA」
        aaaa = ask(a.port, n, T_AAAA, a.host)
        if aaaa is None:
            print(f"{n:22s} {'TIMEOUT':>14s}  {'-':>14s}   跳过")
            continue
        if aaaa["an"] != 0:
            # 这个名字有 AAAA，构造不出「AAAA 的 NODATA」，不适用
            print(f"{n:22s} {'an=%d' % aaaa['an']:>14s}  {'-':>14s}   不适用(有 AAAA)")
            continue

        # 步骤 2：紧接着查 A。必须拿到 A 记录，不能被那条 AAAA 负记录回答
        a_ = ask(a.port, n, T_A, a.host)
        tested += 1
        ok = a_ is not None and a_["an"] > 0
        if not ok:
            fails += 1
        print(f"{n:22s} {'an=0(NODATA)':>14s}  "
              f"{('an=%d' % a_['an']) if a_ else 'TIMEOUT':>14s}   "
              f"{'OK' if ok else '<== 失败：A 被 AAAA 的负记录截胡'}")

    print("\n" + "=" * 62)
    if tested == 0:
        print("没有适用样本（可能实例缓存已热）—— 请重启临时实例后重跑")
        return 2
    if fails == 0:
        print(f"结论：通过（{tested} 个适用名字，A 查询均未被 AAAA 负记录截胡）")
        return 0
    print(f"结论：失败 {fails} / {tested}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
