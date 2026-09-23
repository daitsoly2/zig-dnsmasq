#!/usr/bin/env python3
"""模拟"坏上游"（复刻 119.29.29.29 对 PTR 的行为），用于确定性对照实验：

  * qtype == A      -> NOERROR + A 1.2.3.4
  * qtype == AAAA   -> NOERROR + AAAA 2001:db8::1
  * 其它任何 qtype  -> NXDOMAIN + 权威段 SOA(owner=com., ttl=86400)

这正是 DNSPod 对「存在的名字 + PTR 查询」给出的应答。
用法: python3 fake_upstream.py [port]
"""
import socket, struct, sys, threading

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 53


def enc(name_b):
    out = b""
    if name_b:
        for lab in name_b.split(b"."):
            out += bytes([len(lab)]) + lab
    return out + b"\x00"


def handle(data, addr, sock):
    if len(data) < 12:
        return
    tid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    p = 12
    labels = []
    while p < len(data) and data[p] != 0:
        l = data[p]
        if l & 0xC0:
            p += 2
            break
        labels.append(data[p + 1:p + 1 + l])
        p += l + 1
    p += 1
    qname = b".".join(labels)
    qtype, qclass = struct.unpack(">HH", data[p:p + 4])
    qend = p + 4
    question = data[12:qend]

    if qtype in (1, 28):
        rflag = 0x8180
        ans = b""
        if qtype == 1:
            ans = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + bytes([1, 2, 3, 4])
        else:
            ans = b"\xc0\x0c" + struct.pack(">HHIH", 28, 1, 300, 16) + socket.inet_pton(
                socket.AF_INET6, "2001:db8::1")
        nscount = 0
        rcode = 0
    else:
        rflag = 0x8183  # QR|RD|RA + NXDOMAIN
        ans = b""
        nscount = 1
        rcode = 3
        # 权威段：SOA owner=com.（压缩指针指向问题名里的 "com" 标签不易定位，直接写完整名字）
        soa_owner = enc(b"com")
        soa_rdata = enc(b"ns.example") + enc(b"hostmaster.example") + struct.pack(
            ">IIIII", 86400, 7200, 604800, 86400, 86400)
        soa = soa_owner + struct.pack(">HHIH", 6, 1, 86400, len(soa_rdata)) + soa_rdata
    hdr = struct.pack(">HHHHHH", tid, rflag, 1, 1 if ans else 0, nscount, 0)
    sock.sendto(hdr + question + ans + (soa if not ans and nscount else b""), addr)


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", PORT))
    print(f"fake upstream on :{PORT}", flush=True)
    while True:
        data, addr = s.recvfrom(4096)
        try:
            handle(data, addr, s)
        except Exception as e:
            print("err", e, flush=True)


if __name__ == "__main__":
    main()
