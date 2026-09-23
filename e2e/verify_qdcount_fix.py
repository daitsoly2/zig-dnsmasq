#!/usr/bin/env python3
"""验证「上游 qdcount != 1 的应答必须丢弃」这一修复（对应 C 版 forward.c:1177）。

背景
----
C 版 reply_query() 开头：
    if (n < sizeof(header) || !(header->hb3 & HB3_QR) ||
        ntohs(header->qdcount) != 1)
      return;                       /* 直接丢弃 */

本路由器上游 119.29.29.29 对**存在**名字的 PTR 查询会回 qd=0 的
NXDOMAIN + SOA（TTL 86400）。修复前的 Zig 只在 txid 上判定、把它收下并回给
客户端，还会据此写负缓存 —— 客户端收到畸形应答，正向名字的解析也被污染。

本脚本断言（无需 C 实例，仅打 zig）：
  1. 任何应答的 qdcount 必须为 1（畸形报文零容忍）；
  2. 正向名的 PTR 查询必须稳定拿到 qd=1 的应答（丢弃 dnspod 那份后，
     交由其它上游应答；若全部上游都失败则允许 SERVFAIL，但不允许 qd=0）；
  3. 顺手跑一遍正向名，确认常规解析未被误伤。

用法：
    python3 verify_qdcount_fix.py [router_ip]
"""
import socket, struct, sys

ROUTER = sys.argv[1] if len(sys.argv) > 1 else "192.168.0.1"
ZIG = (ROUTER, 53)


def mk(name, qtype, tid):
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for lab in name.encode().split(b"."):
        if lab:
            q += bytes([len(lab)]) + lab
    q += b"\x00" + struct.pack(">HH", qtype, 1)
    return q


def ask(server, name, qtype, timeout=4.0):
    """返回 (rcode, qd, an, ns, ar) 或 ('ERR', 文本, '', '', '')。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(mk(name, qtype, 0x5A5A), server)
        d, _ = s.recvfrom(4096)
        f = struct.unpack(">H", d[2:4])[0]
        qd, an, ns, ar = struct.unpack(">HHHH", d[4:12])
        return (f & 0xF, qd, an, ns, ar)
    except Exception as e:
        return ("ERR", type(e).__name__, "", "", "")
    finally:
        s.close()


def qd_of(name, qtype):
    r = ask(ZIG, name, qtype)
    if r[0] == "ERR":
        return None, r[1]
    return r[1], f"rc={r[0]} an={r[2]} ns={r[3]}"


def main():
    ok = True

    print("### 1) 正向名 PTR：修复前会拿到 qd=0 的 NXDOMAIN，现在应全部 qd=1")
    ptr_targets = ["example.com", "www.qq.com", "www.baidu.com", "github.com",
                   "www.163.com", "www.taobao.com"]
    for name in ptr_targets:
        qd, txt = qd_of(name, 12)
        flag = "OK" if qd == 1 else ("DROP-ALL" if qd is None else "BAD")
        if qd not in (1, None):
            ok = False
        print(f"  {name:18s} PTR -> qd={qd} {txt}   [{flag}]")

    print("\n### 2) 反向名 PTR：本来就正常，回归确认")
    for name in ["114.114.114.114.in-addr.arpa", "223.5.5.5.in-addr.arpa"]:
        qd, txt = qd_of(name, 12)
        print(f"  {name:30s} -> qd={qd} {txt}")

    print("\n### 3) 常规解析：A/AAAA/MX/TXT 不能受影响")
    for name, qt in [("www.baidu.com", 1), ("www.qq.com", 1), ("github.com", 1),
                     ("www.baidu.com", 28), ("example.com", 15), ("example.com", 16)]:
        qd, txt = qd_of(name, qt)
        flag = "OK" if qd == 1 else "BAD"
        if qd != 1:
            ok = False
        print(f"  {name:18s} type={qt:3d} -> qd={qd} {txt}   [{flag}]")

    print("\n### 4) 全部应答的 qdcount 必须为 1（畸形零容忍）")
    all_qd1 = True
    for name in ptr_targets + ["www.qq.com", "github.com"]:
        for qt in (1, 28, 5, 12, 15, 16):
            qd, _ = qd_of(name, qt)
            if qd is not None and qd != 1:
                all_qd1 = False
                print(f"  !! {name} type={qt} -> qd={qd}")
    print(f"  畸形应答：{'无' if all_qd1 else '存在'}")

    print(f"\n{'='*60}\n结论：{'通过' if (ok and all_qd1) else '存在异常，需复查'}")
    return 0 if (ok and all_qd1) else 1


if __name__ == "__main__":
    sys.exit(main())
