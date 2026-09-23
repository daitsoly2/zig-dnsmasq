#!/usr/bin/env python3
"""AA（权威应答）位回归套件。

背景（实机 A/B 抓包发现）：
  C 版 answer_request() 末尾有一句
      /* authoritative - only hosts and DHCP derived names. */
      if (auth) header->hb3 |= HB3_AA;
  即 **只有** 由 hosts / DHCP 派生的记录应答时才置 AA；从上游转发缓存里取出的
  地址记录、以及负记录（F_NEG）应答都不置。

  本移植原先完全没有这套机制，表现为：
    * localhost / ip6-localhost 的 A/AAAA 由 /etc/hosts 应答，C 回 AA=1，我们回 AA=0；
    * HTTP 默认端口 53 的线上实例（/usr/bin/zig-dnsmasq）与 C 参考实例
      （/tmp/dnsmasq-c293，端口 5352）对比即可复现。

同时覆盖 --address=/dom/ip 规则路径的 AA（对应 make_local_answer 收到
F_IPV4/F_IPV6 时的 setup_reply）：规则命中一律本地权威应答，AA=1，且
「没有该地址族 / 非地址类型」的查询必须回 NODATA 而不是 NXDOMAIN。
后者见 verify_address_rule.py（需要临时实例，另行运行）。

用法：python3 verify_aa_bit.py
"""
import socket
import struct
import sys

Z = ("192.168.0.1", 53)     # 线上 zig 实例
C = ("192.168.0.1", 5352)   # C 版 dnsmasq 2.93 参考实例

T_A, T_NS, T_CNAME, T_MX, T_TXT, T_AAAA, T_PTR = 1, 2, 5, 15, 16, 28, 12

# (名字, 类型, 期望 AA)：期望值取自 C 版实测
EXPECT_AA_1 = [
    ("localhost", T_A),          # /etc/hosts 的 127.0.0.1
    ("localhost", T_AAAA),       # /etc/hosts 的 ::1
    ("ip6-localhost", T_AAAA),
    ("ip6-loopback", T_AAAA),
]
EXPECT_AA_0 = [
    ("www.baidu.com", T_A),      # 上游转发
    ("www.baidu.com", T_AAAA),
    ("www.sohu.com", T_A),
    ("example.com", T_MX),
    ("RAX3000M.lan", T_A),       # 本地区域里不存在的名字 -> NXDOMAIN
]

# 注意：`localhost` PTR/MX 这类「本地名 + 本地没有的类型」**不进**上面的期望表。
# 本地名在本地查不到该类型时 dnsmasq 会转发上游，答案是上游相关的：
#   * 上游回 NODATA（如 223.5.5.5）-> 原样转发，AA=0；
#   * 上游回 NXDOMAIN（如 1.0.0.1）-> 走 forward.c:795-804 的
#     「本地已知名的 NXDOMAIN 改写成 NODATA」并置 AA=1。
# 两端逻辑一致，只是 all-servers 竞速下谁先到不同，故 AA 不确定。
# 用只配单个上游的实例可验证两端一致：
#   上游只有 1.0.0.1 时，本地名 PTR/MX 两端都是 rc=0 aa=1 an=0 ns=1（已实测）。


def mk(name, qtype, tid=0x2A2A):
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for lab in name.encode().split(b"."):
        if lab:
            q += bytes([len(lab)]) + lab
    q += b"\x00" + struct.pack(">HH", qtype, 1)
    return q


def ask(target, name, qtype, timeout=6):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(mk(name, qtype), target)
        d, _ = s.recvfrom(4096)
    except Exception:
        return None
    finally:
        s.close()
    flags = struct.unpack(">H", d[2:4])[0]
    qd, an, ns, ar = struct.unpack(">HHHH", d[4:12])
    return {"rc": flags & 0xF, "aa": (flags >> 10) & 1,
            "qd": qd, "an": an, "ns": ns, "ar": ar}


def main():
    fails = 0

    print("=== 1) hosts/DHCP 派生 -> AA 必须为 1 ===")
    for name, t in EXPECT_AA_1:
        r = ask(Z, name, t)
        if r is None:
            print(f"  {name:18s} t={t:3d}  TIMEOUT            [FAIL]")
            fails += 1
            continue
        ok = r["aa"] == 1 and r["rc"] == 0
        print(f"  {name:18s} t={t:3d}  aa={r['aa']} rc={r['rc']} an={r['an']}   "
              f"{'[OK]' if ok else '[FAIL]'}")
        if not ok:
            fails += 1

    print("\n=== 2) 上游转发 / 负记录 -> AA 必须为 0 ===")
    for name, t in EXPECT_AA_0:
        r = ask(Z, name, t)
        if r is None:
            print(f"  {name:18s} t={t:3d}  TIMEOUT            [FAIL]")
            fails += 1
            continue
        ok = r["aa"] == 0
        print(f"  {name:18s} t={t:3d}  aa={r['aa']} rc={r['rc']} an={r['an']}   "
              f"{'[OK]' if ok else '[FAIL]'}")
        if not ok:
            fails += 1

    print("\n=== 3) 与 C 参考实例逐条对比（若在运行） ===")
    compared = 0
    for name, t in EXPECT_AA_1 + EXPECT_AA_0:
        rc = ask(C, name, t)
        rz = ask(Z, name, t)
        if rc is None or rz is None:
            continue
        compared += 1
        # 只比 AA 与 rcode：应答条数会随 CDN 轮转变化，不作判据
        same = rc["aa"] == rz["aa"] and rc["rc"] == rz["rc"]
        print(f"  {name:18s} t={t:3d}  C(aa={rc['aa']},rc={rc['rc']}) "
              f"Z(aa={rz['aa']},rc={rz['rc']})   {'[OK]' if same else '[DIFF]'}")
        if not same:
            fails += 1
    if compared == 0:
        print("  （C 参考实例未运行，跳过）")

    print("\n" + "=" * 60)
    if fails == 0:
        print("结论：通过")
        return 0
    print(f"结论：失败 {fails} 项")
    return 1


if __name__ == "__main__":
    sys.exit(main())
