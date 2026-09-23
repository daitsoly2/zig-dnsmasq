#!/usr/bin/env python3
"""本地名字（hosts / 本域）在「非地址类型」下应回本地 NODATA，绝不能转发上游。

C 版行为：名字在 hosts 里存在（F_HOSTS/F_DHCP/F_CONFIG），但查询类型没有对应
记录时 -> 直接回 NODATA（rcode=0, 空应答），**不转发**。
Zig 版曾经对这类查询（localhost 的 MX/TXT/CNAME/SRV/PTR）直接转发上游，
拿回 qd=1 的 NXDOMAIN+SOA —— 相当于告诉客户端「localhost 这个名字不存在」。

用法：python3 verify_local_name_nodata.py [router_ip]
"""
import socket, struct, sys

ROUTER = sys.argv[1] if len(sys.argv) > 1 else "192.168.0.1"
C = (ROUTER, 5352)
Z = (ROUTER, 53)

TYPES = [(1, "A"), (28, "AAAA"), (5, "CNAME"), (15, "MX"), (16, "TXT"),
         (2, "NS"), (12, "PTR"), (33, "SRV"), (6, "SOA")]


def mk(name, qtype, tid=0x7C7C):
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for lab in name.encode().split(b"."):
        if lab:
            q += bytes([len(lab)]) + lab
    q += b"\x00" + struct.pack(">HH", qtype, 1)
    return q


def ask(server, name, qtype, timeout=5.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(mk(name, qtype), server)
        d, _ = s.recvfrom(4096)
        f = struct.unpack(">H", d[2:4])[0]
        qd, an, ns, ar = struct.unpack(">HHHH", d[4:12])
        return f & 0xF, qd, an, ns, ar
    except Exception:
        return None, None, None, None, None
    finally:
        s.close()


def main():
    names = ["localhost", "ip6-localhost", "ip6-loopback"]
    bad = 0
    for name in names:
        print(f"### {name}")
        for qt, tn in TYPES:
            cr = ask(C, name, qt)
            zr = ask(Z, name, qt)
            c_txt = f"rc={cr[0]} an={cr[2]} ns={cr[3]}" if cr[0] is not None else "TIMEOUT"
            z_txt = f"rc={zr[0]} an={zr[2]} ns={zr[3]}" if zr[0] is not None else "TIMEOUT"
            mark = ""
            # C 对存在但类型缺失的名字回 NODATA；zig 若回 NXDOMAIN 即为不一致
            if cr[0] == 0 and zr[0] == 3:
                mark = "   <<< zig 回了 NXDOMAIN（错）"
                bad += 1
            print(f"  {tn:6s} C: {c_txt:20s} | ZIG: {z_txt:20s}{mark}")
        print()
    print(f"{'='*60}")
    print(f"错判为 NXDOMAIN 的组数：{bad}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
