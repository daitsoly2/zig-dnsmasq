#!/usr/bin/env python3
"""5 分钟 / 500 条不同域名 / 多线程循环压测（zig 版 dnsmasq @192.168.0.1:53）

指标：QPS、成功率、rcode 分布、延迟 p50/p95/p99、路由器侧 RSS/CPU 采样。
用法: python3 stress500.py [时长秒] [并发数] [域名数]
"""
import socket, struct, random, time, sys, os
import subprocess, threading, concurrent.futures

TARGET = ("192.168.0.1", 53)
GW = "192.168.0.1"
SSH = "/home/ovo/.cache/dnsmasq-deploy/rsh.sh"
# 真正的 dnsmasq 跑在 ujail 沙箱里，取 ujail 的子进程才是被测进程
PIDQ = 'PID=$(pgrep -P $(pgrep -x zig-dnsmasq | head -1) | head -1); [ -z "$PID" ] && PID=$(pgrep -x zig-dnsmasq | head -1); '

DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 300
WORKERS = int(sys.argv[2]) if len(sys.argv) > 2 else 32
WANT = int(sys.argv[3]) if len(sys.argv) > 3 else 500

# ---------------- 域名池 ----------------
REAL = """
www.baidu.com www.qq.com www.163.com www.sina.com.cn www.sohu.com www.taobao.com
www.tmall.com www.jd.com www.weibo.com www.zhihu.com www.bilibili.com api.bilibili.com
data.bilibili.com i0.hdslb.com i1.hdslb.com i2.hdslb.com s1.hdslb.com s2.hdslb.com
www.douban.com www.douyu.com www.huya.com www.iqiyi.com www.youku.com v.qq.com
www.toutiao.com www.36kr.com www.infoq.cn www.oschina.net gitee.com www.aliyun.com
cloud.tencent.com developer.aliyun.com www.csdn.net www.jianshu.com www.51cto.com
www.pconline.com.cn www.zol.com.cn mobile.qq.com im.qq.com qzone.qq.com graph.qq.com
lol.qq.com www.12306.cn www.ctrip.com www.qunar.com flights.ctrip.com hotels.ctrip.com
www.meituan.com www.dianping.com www.ele.me www.amap.com restapi.amap.com lbs.qq.com
map.qq.com apistore.baidu.com api.map.baidu.com www.deepin.org bbs.deepin.org
www.chinaunix.net www.linuxidc.com mirrors.aliyun.com mirrors.tuna.tsinghua.edu.cn
www.workbuddy.cn static.workbuddy.cn staging.workbuddy.cn copilot.tencent.com
galileotelemetry.tencent.com docs.qq.com doc.weixin.qq.com git.woa.com
pay.weixin.qq.com mp.weixin.qq.com work.weixin.qq.com
example.com github.com raw.githubusercontent.com api.github.com gist.github.com
gitlab.com bitbucket.org stackoverflow.com www.google.com accounts.google.com
www.googleapis.com cloudflare.com www.cloudflare.com cdnjs.cloudflare.com
cdn.jsdelivr.net registry.npmjs.org pypi.org nodejs.org www.microsoft.com
login.microsoftonline.com login.live.com www.apple.com www.wikipedia.org
www.reddit.com twitter.com www.facebook.com www.youtube.com www.instagram.com
www.linkedin.com medium.com dev.to news.ycombinator.com immortalwrt.org
openwrt.org www.openwrt.org kernel.org www.linux.org www.apache.org
maven.apache.org download.docker.com hub.docker.com fonts.googleapis.com
developer.mozilla.org www.w3.org getbootstrap.com www.iconfont.cn
translate.google.com time.google.com ntp.ubuntu.com
r.bing.com th.bing.com cn.bing.com www.bing.com ts1.tc.mm.bing.net
ts2.tc.mm.bing.net ts3.tc.mm.bing.net vcf.bing.com www.msn.com
static.cloudflareinsights.com www.google-analytics.com www.googletagmanager.com
storage.deepin.org.cn tracking.miui.com wx.qlogo.cn loc.map.baidu.com
broadcast.chat.bilibili.com tk.mm.bing.net ssw.live.com cdn.bootcdn.net
img.alicdn.com gtms02.alicdn.com alicdn.com
www.126.com mail.163.com mail.qq.com mail.sina.com.cn www.cnki.net
www.wanfangdata.com.cn xueshu.baidu.com www.chinanews.com www.people.com.cn
www.xinhuanet.com www.cctv.com tv.cctv.com www.gov.cn www.moe.gov.cn
code.aliyun.com bbs.aliyun.com help.aliyun.com oss.aliyuncs.com
download.qt.io mirrors.huaweicloud.com mirrors.cloud.tencent.com pypi.tuna.tsinghua.edu.cn
www.smzdm.com www.xiaomi.com www.mi.com order.mi.com h5.mi.com api.m.jd.com
www.vip.com www.suning.com www.gome.com.cn www.kaola.com www.huawei.com
consumer.huawei.com www.oppo.com www.vivo.com.cn www.oneplus.com www.realme.com
www.meizu.com www.lenovo.com.cn newsupport.lenovo.com.cn www.zte.com.cn
www.h3c.com www.ruijie.com.cn www.tp-link.com.cn www.netgear.com www.asus.com.cn
www.msi.com www.seagate.com www.wdc.com www.kingston.com www.crucial.com
www.intel.cn www.nvidia.cn www.amd.com www.nvidia.com www.vmware.com
www.citrix.com www.redhat.com www.suse.com www.debian.org www.ubuntu.com
www.centos.org www.fedoraproject.org www.archlinux.org www.gentoo.org
www.alpinelinux.org busybox.net www.musl-libc.org www.gnu.org
www.freebsd.org www.openbsd.org
mirrors.ustc.edu.cn mirrors.163.com deb.debian.org archive.ubuntu.com
security.ubuntu.com pkg.freebsd.org distro.ibiblio.org ftp.gnu.org
www.python.org docs.python.org pypi.doubanio.com mirrors.tencenty.com
translate.google.cn www.google.com.hk www.bing.com.cn dict.youdao.com
www.youdao.com fanyi.baidu.com cn.bing.com dict.bing.com.cn
update.googleapis.com optimizationguide-pa.googleapis.com
clientservices.googleapis.com play.googleapis.com android.clients.google.com
www.googleapis.cn fonts.gstatic.com ajax.googleapis.com
store.steampowered.com steamcommunity.com api.steampowered.com
cdn.akamai.net img1.akamai.net static.akamai.com
d1fhz5c1uof6r1.cloudfront.net d3js.org cdn.plot.ly
code.jquery.com unpkg.com esm.sh deno.land crates.io docs.rs
static.crates.io index.crates.io sh.rustup.rs static.rust-lang.org
www.rust-lang.org play.rust-lang.org ziglang.org github.io
raw.github.com objects.githubusercontent.com avatars.githubusercontent.com
codeload.github.com gist.githubusercontent.com
mirrors.kernel.org www.postgresql.org www.mysql.com dev.mysql.com
www.mongodb.com www.redis.io www.elastic.co www.docker.io
kubernetes.io helm.sh gitlab.io cdn.gitlab.com
www.notion.so www.figma.com www.figma.cn www.zeplin.io
www.trello.com slack.com discord.com cdn.discordapp.com
www.telegram.org web.telegram.org core.telegram.org
""".split()

# 用常见主机前缀 + 真实主域构造更多不同域名（覆盖 CNAME/CDN 场景）
PREFIX = ["cdn", "img", "static", "api", "m", "www2", "img1", "img2", "s1", "s2",
          "pic", "video", "app", "web", "mail", "cdn1", "cdn2", "live", "vod", "dl"]
BASES = ["baidu.com", "qq.com", "taobao.com", "jd.com", "bilibili.com", "aliyun.com",
         "tencent.com", "workbuddy.cn", "hdslb.com", "alicdn.com", "qlogo.cn",
         "bing.com", "mi.com", "huawei.com", "163.com", "sina.com.cn",
         "zhihu.com", "weibo.com", "douyu.com", "iqiyi.com", "cloudfront.net",
         "akamai.net", "cloudflare.com", "github.com", "googleapis.com",
         "centos.org", "ubuntu.com", "debian.org", "openwrt.org", "deepin.org"]

DOMAINS = [d.strip() for d in REAL if d.strip()]
DOMAINS = list(dict.fromkeys(DOMAINS))
i = 0
while len(DOMAINS) < WANT and i < len(PREFIX) * len(BASES):
    d = f"{PREFIX[i % len(PREFIX)]}.{BASES[i // len(PREFIX)]}"
    if d not in DOMAINS:
        DOMAINS.append(d)
    i += 1
random.Random(42).shuffle(DOMAINS)
DOMAINS = DOMAINS[:WANT]
assert len(DOMAINS) == WANT, f"域名数不足: {len(DOMAINS)}"

# ---------------- 查询 ----------------
def mk(name, qtype):
    tid = random.randint(0, 65535)
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for lab in name.encode().split(b'.'):
        q += bytes([len(lab)]) + lab
    q += b'\x00' + struct.pack(">HH", qtype, 1)
    return q


lock = threading.Lock()
stat = {"ok": 0, "fail": 0, "nodata": 0, "nx": 0, "servfail": 0, "other": 0}
rcodes = {}
lat = []
fail_detail = {}
qps_bucket = {}   # sec -> n  (仅在锁内更新)

stop = threading.Event()


def worker(wid: int, deadline: float):
    idx = wid
    while not stop.is_set() and time.time() < deadline:
        nm = DOMAINS[idx % len(DOMAINS)]
        idx += WORKERS
        qt = 1 if random.random() < 0.7 else 28
        t0 = time.perf_counter()
        rc = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(4.0)
            try:
                s.sendto(mk(nm, qt), TARGET)
                d, _ = s.recvfrom(4096)
                if len(d) >= 12:
                    _tid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", d[:12])
                    rc = (flags & 0xF, an)
            finally:
                s.close()
        except Exception:
            rc = None
        dt = (time.perf_counter() - t0) * 1000.0

        with lock:
            sec = int(time.time())
            qps_bucket[sec] = qps_bucket.get(sec, 0) + 1
            if rc is None:
                stat["fail"] += 1
                fail_detail[nm] = fail_detail.get(nm, 0) + 1
            else:
                r, an = rc
                rcodes[r] = rcodes.get(r, 0) + 1
                if len(lat) < 400000:
                    lat.append(dt)
                if r == 0:
                    if an == 0:
                        stat["nodata"] += 1
                        fail_detail[nm] = fail_detail.get(nm, 0) + 1
                    else:
                        stat["ok"] += 1
                elif r == 3:
                    stat["nx"] += 1
                elif r == 2:
                    stat["servfail"] += 1
                    fail_detail[nm] = fail_detail.get(nm, 0) + 1
                else:
                    stat["other"] += 1
                    fail_detail[nm] = fail_detail.get(nm, 0) + 1


# ---------------- 路由器侧资源采样 ----------------
samples = []


def sample_loop(deadline: float):
    while not stop.is_set() and time.time() < deadline:
        try:
            out = subprocess.run(
                [SSH, GW, PIDQ +
                 'awk \'/VmRSS/{r=$2} END{print r}\' /proc/$PID/status; '
                 'awk \'{print $14+$15}\' /proc/$PID/stat || echo DEAD'],
                capture_output=True, text=True, timeout=12)
            txt = out.stdout.strip().split("\n")
            if not txt or "DEAD" in txt[0]:
                samples.append((time.time(), None, 0))
            else:
                try:
                    rss = int(txt[0].split()[0])
                except Exception:
                    rss = None
                cpu = int(txt[1]) if len(txt) > 1 and txt[1].strip().isdigit() else 0
                samples.append((time.time(), rss, cpu))
        except Exception:
            samples.append((time.time(), None, None, None))
        time.sleep(15)


# ---------------- 主流程 ----------------
rsh_ok = subprocess.run([SSH, GW, PIDQ + 'echo "pid=$PID"; md5sum /usr/bin/zig-dnsmasq; '
                                       'grep -E "VmRSS|VmPeak" /proc/$PID/status'],
                        capture_output=True, text=True, timeout=15)
print("=== 5 分钟 / 500 域名 多线程循环压测（zig 版）===", flush=True)
print(f"目标: {TARGET}   时长: {DURATION}s   并发线程: {WORKERS}   域名数: {len(DOMAINS)}", flush=True)
print("被测进程: " + rsh_ok.stdout.strip().replace("\n", "  |  "), flush=True)
print(flush=True)

t0 = time.time()
deadline = t0 + DURATION
# 起始基线采样
try:
    out = subprocess.run([SSH, GW, PIDQ + 'awk \'/VmRSS/{r=$2} END{print r}\' /proc/$PID/status; '
                                          'awk \'{print $14+$15}\' /proc/$PID/stat'],
                         capture_output=True, text=True, timeout=15)
    t = out.stdout.strip().split("\n")
    samples.append((t0, int(t[0].split()[0]), int(t[1]) if len(t) > 1 and t[1].strip().isdigit() else 0))
except Exception:
    pass
mon = threading.Thread(target=sample_loop, args=(deadline,), daemon=True)
mon.start()

with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as ex:
    futs = [ex.submit(worker, i, deadline) for i in range(WORKERS)]
    next_report = t0 + 15
    while time.time() < deadline:
        time.sleep(2)
        if time.time() >= next_report:
            with lock:
                done = stat["ok"] + stat["nodata"] + stat["nx"] + stat["servfail"] + stat["other"] + stat["fail"]
                el = time.time() - t0
                rss = [s[1] for s in samples if s[1]]
                print(f"[+{int(el):3d}s] 查询={done:6d}  qps={done/el:7.1f}  "
                      f"ok={stat['ok']:6d} 超时={stat['fail']:3d} 空答={stat['nodata']:3d} "
                      f"NX={stat['nx']:5d} SERVFAIL={stat['servfail']:3d}  "
                      f"rss={rss[-1] if rss else 'N/A'}kB", flush=True)
            next_report = time.time() + 15
    for f in futs:
        f.result()

el = time.time() - t0
stop.set()
time.sleep(0.5)

total = sum(stat.values())
answered = total - stat["fail"]
print(f"\n=== 压测结束 ===", flush=True)
print(f"耗时 {el:.1f}s   总查询 {total}   平均 QPS {total/el:.1f}")
print(f"收到应答 {answered} ({(answered/total*100) if total else 0:.2f}%)   超时/丢包 {stat['fail']}")
print(f"应答细分: 有记录={stat['ok']}  空应答(NODATA)={stat['nodata']}  "
      f"NXDOMAIN={stat['nx']}  SERVFAIL={stat['servfail']}  其他={stat['other']}")
print(f"rcode 分布: {dict(sorted(rcodes.items()))}")

if lat:
    s = sorted(lat)
    def pct(p):
        return s[min(len(s) - 1, int(len(s) * p))]
    print(f"延迟 ms: p50={pct(.50):.2f}  p90={pct(.90):.2f}  p95={pct(.95):.2f}  "
          f"p99={pct(.99):.2f}  max={s[-1]:.2f}  avg={sum(s)/len(s):.2f}")

rss = [s for s in samples if s[1]]
if len(rss) >= 2:
    print(f"\n内存: 起始={rss[0][1]}kB  峰值={max(x[1] for x in rss)}kB  末尾={rss[-1][1]}kB  "
          f"变化={rss[-1][1]-rss[0][1]:+d}kB {'⚠ 持续增长' if rss[-1][1]-rss[0][1] > 20000 else '✓ 稳定'}")
    cpu0, cpu1 = rss[0][2], rss[-1][2]
    wall = rss[-1][0] - rss[0][0]
    print(f"CPU: 累计 tick 增量={cpu1-cpu0} (100tick=1s)  采样窗口={wall:.0f}s  "
          f"=> 占用约 {(cpu1-cpu0)/100/wall*100:.1f}%")
    if total:
        print(f"     单查询 CPU 成本约 {(cpu1-cpu0)/100*1e6/total:.1f} µs")

if fail_detail:
    print(f"\n=== 异常域名 top 10（超时/NODATA/SERVFAIL）===")
    for nm, c in sorted(fail_detail.items(), key=lambda x: -x[1])[:10]:
        print(f"  {nm:35s} {c} 次")
else:
    print("\n✓ 零超时、零空应答、零 SERVFAIL")
