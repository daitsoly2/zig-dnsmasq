#!/usr/bin/env python3
"""C(5353) vs zig(53) 解析行为逐条对照。

比较项：rcode、应答段 RR 集合（类型+规范化值，忽略 TTL 与顺序）、
        权威段是否有 SOA、附加段 OPT 等关键差异。
两遍：冷缓存对比 + 热缓存对比（热缓存才走本地应答/缓存逻辑）。
"""
import socket, struct, random, sys, time, concurrent.futures

C = ("192.168.0.1", 5352)   # C 版 dnsmasq 2.93（5353 被系统 umdns 占用，改 5352）
Z = ("192.168.0.1", 53)     # zig 版

TYPES = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 2: "NS",
         6: "SOA", 12: "PTR", 33: "SRV", 257: "CAA", 255: "ANY", 3: "MD",
         13: "HINFO", 65535: "ANY?"}

REAL = """
www.baidu.com www.qq.com www.163.com www.sina.com.cn www.sohu.com www.taobao.com
www.jd.com www.weibo.com www.zhihu.com www.bilibili.com api.bilibili.com
data.bilibili.com i0.hdslb.com www.douban.com www.douyu.com www.huya.com
www.iqiyi.com www.toutiao.com gitee.com www.aliyun.com cloud.tencent.com
www.csdn.net www.jianshu.com mobile.qq.com im.qq.com qzone.qq.com graph.qq.com
www.12306.cn www.ctrip.com www.meituan.com www.dianping.com www.amap.com
restapi.amap.com lbs.qq.com map.qq.com www.deepin.org bbs.deepin.org
mirrors.aliyun.com mirrors.tuna.tsinghua.edu.cn www.workbuddy.cn static.workbuddy.cn
copilot.tencent.com galileotelemetry.tencent.com docs.qq.com doc.weixin.qq.com
git.woa.com pay.weixin.qq.com mp.weixin.qq.com work.weixin.qq.com
example.com github.com raw.githubusercontent.com api.github.com gitlab.com
stackoverflow.com www.google.com accounts.google.com www.googleapis.com
cloudflare.com cdnjs.cloudflare.com cdn.jsdelivr.net registry.npmjs.org pypi.org
nodejs.org www.microsoft.com login.microsoftonline.com login.live.com www.apple.com
www.wikipedia.org www.reddit.com twitter.com www.facebook.com www.youtube.com
www.linkedin.com medium.com dev.to news.ycombinator.com openwrt.org immortalwrt.org
kernel.org www.linux.org www.apache.org download.docker.com hub.docker.com
fonts.googleapis.com developer.mozilla.org www.w3.org www.iconfont.cn
r.bing.com th.bing.com cn.bing.com www.bing.com ts1.tc.mm.bing.net vcf.bing.com
www.msn.com static.cloudflareinsights.com www.google-analytics.com
www.googletagmanager.com storage.deepin.org.cn tracking.miui.com wx.qlogo.cn
loc.map.baidu.com ssw.live.com cdn.bootcdn.net img.alicdn.com gtms02.alicdn.com
alicdn.com www.126.com mail.163.com mail.qq.com www.cnki.net www.chinanews.com
www.people.com.cn www.xinhuanet.com www.cctv.com tv.cctv.com www.gov.cn
code.aliyun.com oss.aliyuncs.com download.qt.io mirrors.huaweicloud.com
mirrors.cloud.tencent.com pypi.tuna.tsinghua.edu.cn www.smzdm.com www.xiaomi.com
www.mi.com order.mi.com api.m.jd.com www.vip.com www.suning.com www.huawei.com
consumer.huawei.com www.oppo.com www.vivo.com.cn www.meizu.com www.lenovo.com.cn
www.zte.com.cn www.h3c.com www.ruijie.com.cn www.tp-link.com.cn www.asus.com.cn
www.seagate.com www.kingston.com www.intel.cn www.nvidia.cn www.amd.com
www.vmware.com www.redhat.com www.suse.com www.debian.org www.ubuntu.com
www.centos.org www.fedoraproject.org www.archlinux.org www.gentoo.org
www.alpinelinux.org busybox.net www.musl-libc.org www.gnu.org www.freebsd.org
mirrors.ustc.edu.cn mirrors.163.com deb.debian.org archive.ubuntu.com
security.ubuntu.com ftp.gnu.org www.python.org docs.python.org dict.youdao.com
fanyi.baidu.com update.googleapis.com clientservices.googleapis.com
play.googleapis.com android.clients.google.com fonts.gstatic.com ajax.googleapis.com
store.steampowered.com steamcommunity.com api.steampowered.com cdn.akamai.net
code.jquery.com unpkg.com deno.land crates.io docs.rs static.crates.io
sh.rustup.rs static.rust-lang.org www.rust-lang.org ziglang.org
objects.githubusercontent.com codeload.github.com mirrors.kernel.org
www.postgresql.org www.mysql.com dev.mysql.com www.mongodb.com kubernetes.io helm.sh
www.notion.so www.figma.com slack.com discord.com cdn.discordapp.com
www.telegram.org core.telegram.org
""".split()

EDGE_NAMES = [
    # 大小写
    "WWW.BAIDU.COM", "WwW.GoOgLe.CoM", "WWW.WORKBUDDY.CN",
    # 尾点
    "www.baidu.com.", "example.com.", "www.workbuddy.cn.",
    # 本地域 / hosts / 无点名字
    "router", "router.lan", "OpenWrt.lan", "br-lan.lan", "lan",
    "localhost", "localhost.lan", "workbuddy", "nonexistent",
    # 反查
    "1.1.1.1.in-addr.arpa", "8.8.8.8.in-addr.arpa", "223.5.5.5.in-addr.arpa",
    "192.168.0.1.in-addr.arpa", "127.0.0.1.in-addr.arpa", "10.0.0.1.in-addr.arpa",
    "114.114.114.114.in-addr.arpa",
    # 不存在 / 边界
    "nonexistent-zzz-12345.example.com", "a.b.c.d.e.f.g.h.example.com",
    "xn--fiqs8s.example.com", "_dmarc.example.com", "_sip._tcp.example.com",
    "verylonglabelverylonglabelverylonglabelverylonglabelverylonglabel12.example.com",
    "a" * 63 + ".example.com", "example", "com", "", ".",
    # TXT / SOA / 特殊
    "example.com", "google.com", "cloudflare.com",
]

DOMAINS = list(dict.fromkeys(REAL))
EDGE = [d for d in EDGE_NAMES if d]


def mk(name, qtype, tid=None):
    if tid is None:
        tid = random.randint(0, 65535)
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    if name == "":
        q += b"\x00"
    else:
        for lab in name.rstrip(".").encode("ascii", "replace").split(b"."):
            q += bytes([len(lab)]) + lab
        if name.endswith("."):
            pass
        q += b"\x00"
    q += struct.pack(">HH", qtype, 1)
    return q


def rdname(d, off):
    parts, jumped, orig, guard = [], False, off, 0
    while True:
        guard += 1
        if guard > 128 or off >= len(d):
            raise ValueError("bad name")
        l = d[off]
        if l & 0xC0:
            ptr = ((l & 0x3F) << 8) | d[off + 1]
            if not jumped:
                orig = off + 2
            off = ptr
            jumped = True
            continue
        if l == 0:
            off += 1
            if not jumped:
                orig = off
            break
        parts.append(d[off + 1:off + 1 + l])
        off += l + 1
    return b".".join(parts).decode("ascii", "replace").lower(), (orig if jumped else off)


def rdata_text(d, rt, off, rl):
    end = off + rl
    if rt == 1 and rl == 4:
        return ".".join(str(b) for b in d[off:end])
    if rt == 28 and rl == 16:
        return socket.inet_ntop(socket.AF_INET6, d[off:end])
    if rt in (5, 2, 12, 39):
        n, _ = rdname(d, off)
        return n
    if rt == 15:
        pref = struct.unpack(">H", d[off:off + 2])[0]
        n, _ = rdname(d, off + 2)
        return f"{pref} {n}"
    if rt == 16:
        parts, p = [], off
        while p < end:
            l = d[p]
            parts.append(d[p + 1:p + 1 + l].decode("utf8", "replace"))
            p += l + 1
        return "|".join(parts)
    if rt == 6:
        mname, p = rdname(d, off)
        rname, p = rdname(d, p)
        vals = struct.unpack(">IIIII", d[p:p + 20])
        return f"{mname} {rname} {' '.join(str(v) for v in vals[:4])}"
    if rt == 33:
        pri, w, port = struct.unpack(">HHH", d[off:off + 6])
        n, _ = rdname(d, off + 6)
        return f"{pri} {w} {port} {n}"
    if rt == 257:
        flags, tl = d[off], d[off + 1]
        return f"{flags} {d[off+2:off+2+tl].decode('utf8','replace')}"
    if rt == 41:
        return f"OPT udp={struct.unpack('>H', d[off-2:off])[0]}"
    return d[off:end].hex()


def parse(d):
    if len(d) < 12:
        return None
    _t, f, qd, an, ns, ar = struct.unpack(">HHHHHH", d[:12])
    out = {"rcode": f & 0xF, "flags": f, "an": [], "has_soa_auth": False, "ar_opt": False}
    try:
        p = 12
        for _ in range(qd):
            _, p = rdname(d, p)
            p += 4
        for _ in range(an):
            _, p = rdname(d, p)
            rt, rc, ttl, rl = struct.unpack(">HHIH", d[p:p + 10])
            p += 10
            out["an"].append((TYPES.get(rt, str(rt)), rdata_text(d, rt, p, rl)))
            p += rl
        for _ in range(ns):
            _, p = rdname(d, p)
            rt, rc, ttl, rl = struct.unpack(">HHIH", d[p:p + 10])
            p += 10
            if rt == 6:
                out["has_soa_auth"] = True
            p += rl
        for _ in range(ar):
            _, p = rdname(d, p)
            rt, rc, ttl, rl = struct.unpack(">HHIH", d[p:p + 10])
            p += 10
            if rt == 41:
                out["ar_opt"] = True
            p += rl
    except Exception as e:
        out["parse_err"] = str(e)
    return out


def query(server, name, qtype, timeout=4.0, retries=2):
    for _ in range(retries + 1):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(mk(name, qtype), server)
            d, _ = s.recvfrom(4096)
            return parse(d)
        except Exception:
            pass
        finally:
            s.close()
    return None


def canon(r):
    """结构化指纹：忽略 TTL 与 A/AAAA 具体值（CDN 轮转/上游不同会变），
    但保留 CNAME 链、类型多重集、rcode、SOA、空答性质。"""
    if r is None:
        return "TIMEOUT"
    if "parse_err" in r:
        return f"PARSE-ERR({r['parse_err']})"
    types = sorted(t for t, _ in r["an"])
    cnames = [v for t, v in r["an"] if t == "CNAME"]
    other = sorted((t, v) for t, v in r["an"] if t not in ("A", "AAAA", "CNAME"))
    has_a = any(t == "A" for t, _ in r["an"])
    has_aaaa = any(t == "AAAA" for t, _ in r["an"])
    return (f"rc={r['rcode']} types={types} cname={cnames} other={other} "
            f"a={has_a} aaaa={has_aaaa} soa={r['has_soa_auth']}")


def classify(c, z):
    """把一组差异归到最可能的成因桶，便于区分『真差异』与『上游/CDN 轮转噪声』。"""
    def field(s, key):
        for tok in s.split(" "):
            if tok.startswith(key + "="):
                return tok[len(key) + 1:]
        return None
    if c == "TIMEOUT" or z == "TIMEOUT" or c.startswith("PARSE") or z.startswith("PARSE"):
        return "超时/解析错误"
    if field(c, "rc") != field(z, "rc"):
        return "rcode 不同"
    if field(c, "soa") != field(z, "soa"):
        return "SOA 权威段不同"
    if field(c, "types") != field(z, "types"):
        return "RR 类型集合不同"
    if field(c, "cname") != field(z, "cname"):
        return "CNAME 链不同"
    if field(c, "other") != field(z, "other"):
        return "其他 RR 值不同"
    return "值/顺序噪声"


def main():
    for pass_no in (1, 2):
        label = "冷缓存" if pass_no == 1 else "热缓存"
        print(f"\n{'='*72}\n=== 第 {pass_no} 遍（{label}）差异报告 ===\n{'='*72}", flush=True)
        diffs = []
        checks = 0

        def work(job):
            name, qt = job
            rc = query(C, name, qt)
            rz = query(Z, name, qt)
            return (name, qt, canon(rc), canon(rz))

        jobs = [(n, qt) for n in DOMAINS for qt in (1, 28)]
        jobs += [(n, qt) for n in EDGE for qt in (1, 28, 5, 15, 16, 2, 6, 12, 33, 255)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            for name, qt, c, z in ex.map(work, jobs):
                checks += 1
                if c != z:
                    diffs.append((name, TYPES.get(qt, str(qt)), c, z, classify(c, z)))

        print(f"共对照 {checks} 组（域名×类型），差异 {len(diffs)} 组\n", flush=True)
        buckets = {}
        for d in diffs:
            buckets.setdefault(d[4], []).append(d)
        print("按成因归类：")
        for kind, items in sorted(buckets.items(), key=lambda kv: -len(kv[1])):
            print(f"  {kind:16s} {len(items):4d} 组", flush=True)

        # 逐桶打印样本（每桶最多 6 组）
        for kind, items in sorted(buckets.items(), key=lambda kv: -len(kv[1])):
            print(f"\n--- 【{kind}】共 {len(items)} 组，样例：", flush=True)
            for name, t, c, z, _kind in items[:6]:
                print(f"[{t:5s}] {name or '(空名)'}")
                print(f"        C : {c}")
                print(f"        zig: {z}")


if __name__ == "__main__":
    main()
