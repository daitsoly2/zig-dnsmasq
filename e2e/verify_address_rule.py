#!/usr/bin/env python3
"""--address=/dom/ip 规则路径回归套件（需要临时实例）。

为什么单独一个套件：生产配置（/var/etc/zig-dnsmasq.conf）没有 address= 规则，
所以 diff_vs_c.py 的全量对照覆盖不到这条路径，而它是本次实机 A/B 才发现问题的
地方。必须另起两个带 address= 规则的临时实例来对照。

背景（实机 A/B 发现）：
  C 版把 address= 规则注册成 SERV_LITERAL_ADDRESS 服务器（带 SERV_4ADDR /
  SERV_6ADDR，见 option.c:3098-3102），应答走
      lookup_domain -> is_local_answer -> make_local_answer
  由此产生两条必须逐字复刻的语义：
    1) 命中规则的名字一律本地权威应答（NOERROR + AA=1），绝不转发上游；
       「没有该地址族 / 查询非地址类型」时回 NODATA，**不是** NXDOMAIN。
       本移植曾因规则只落在 address_list、未进 serverarray，导致这类查询
       漏到上游拿回 NXDOMAIN —— 下游负缓存后连该名字的 A 记录都解析不了。
    2) 同一域名的多条规则（address=/dom/1.2.3.4 与 address=/dom/::1 是两条）
       必须合并生效；扫描时命中但本条答不出要继续找后面的规则，不能提前返回。

用法：
    # 先起临时实例（见下方 setup_instances.sh），再运行：
    python3 verify_address_rule.py [--c-port 5362] [--zig-port 54]

setup（在路由器上，或通过 deploy 目录的 rsh.sh 执行）：
    cat > /tmp/c293-addr.conf <<'EOF'
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
    sed 's/port=5362/port=54/' /tmp/c293-addr.conf > /tmp/zig-addr.conf
    nohup /tmp/dnsmasq-c293   -C /tmp/c293-addr.conf -k < /dev/null > /tmp/c293-addr.log 2>&1 &
    nohup /usr/bin/zig-dnsmasq -C /tmp/zig-addr.conf  -k < /dev/null > /tmp/zig-addr.log  2>&1 &
"""
import argparse
import socket
import struct
import sys

T_A, T_NS, T_CNAME, T_SOA, T_PTR, T_MX, T_TXT, T_AAAA, T_SRV, T_ANY = (
    1, 2, 5, 6, 12, 15, 16, 28, 33, 255)

# (名字, 类型)：期望两端在 rcode / AA / ancount 上完全一致
CASES = [
    # 匹配地址族 -> 回地址 + AA
    ("aat4.example", T_A),
    ("aat6.example", T_AAAA),
    ("aatboth.example", T_A),
    ("aatboth.example", T_AAAA),
    ("aatboth.example", T_ANY),
    ("aat4.example", T_ANY),
    # 错地址族 -> NODATA + AA（绝不能 NXDOMAIN、也不能转上游）
    ("aat4.example", T_AAAA),
    ("aat6.example", T_A),
    # 非地址类型 -> NODATA + AA
    ("aat4.example", T_NS),
    ("aat4.example", T_CNAME),
    ("aat4.example", T_SOA),
    ("aat4.example", T_PTR),
    ("aat4.example", T_MX),
    ("aat4.example", T_TXT),
    # 子域同样命中（hostname_issubdomain）
    ("sub.aat4.example", T_A),
    ("sub.aat4.example", T_AAAA),
    # 真实 TLD：上游对 aat4.qq.com 一律回 NXDOMAIN；命中规则必须本地应答
    ("aat4.qq.com", T_A),
    ("aat4.qq.com", T_AAAA),
    ("sub.aat4.qq.com", T_A),
    ("sub.aat4.qq.com", T_AAAA),
]


def mk(name, qtype, tid=0x2A2A):
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for lab in name.encode().split(b"."):
        if lab:
            q += bytes([len(lab)]) + lab
    q += b"\x00" + struct.pack(">HH", qtype, 1)
    return q


def ask(port, name, qtype, timeout=6):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(mk(name, qtype), ("192.168.0.1", port))
        d, _ = s.recvfrom(4096)
    except Exception:
        return None
    finally:
        s.close()
    f = struct.unpack(">H", d[2:4])[0]
    _, an, ns, _ = struct.unpack(">HHHH", d[4:12])
    return {"rc": f & 0xF, "aa": (f >> 10) & 1, "an": an, "ns": ns}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--c-port", type=int, default=5362)
    ap.add_argument("--zig-port", type=int, default=54)
    a = ap.parse_args()

    # 探活
    for label, port in (("C", a.c_port), ("zig", a.zig_port)):
        if ask(port, "aat4.example", T_A) is None:
            print(f"端口 {port}（{label} 实例）无应答 —— 请先按文件头的 setup 起临时实例")
            return 2

    fails = 0
    print(f"{'name':22s} {'t':>3s}  {'C':26s} {'ZIG':26s}")
    for name, t in CASES:
        c = ask(a.c_port, name, t)
        z = ask(a.zig_port, name, t)
        cs = f"rc={c['rc']} aa={c['aa']} an={c['an']}" if c else "TIMEOUT"
        zs = f"rc={z['rc']} aa={z['aa']} an={z['an']}" if z else "TIMEOUT"
        same = c is not None and z is not None and (c["rc"], c["aa"], c["an"]) == (z["rc"], z["aa"], z["an"])
        print(f"{name:22s} {t:3d}  {cs:26s} {zs:26s}{'' if same else '  <== DIFF'}")
        if not same:
            fails += 1

    print()
    print("=" * 60)
    if fails == 0:
        print(f"结论：通过（{len(CASES)} 组全部一致）")
        return 0
    print(f"结论：失败 {fails} / {len(CASES)} 组")
    return 1


if __name__ == "__main__":
    sys.exit(main())
