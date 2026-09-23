/*
 * dnsbench.c — 高吞吐 DNS 负载生成器
 *
 * 为什么不用 Python：CPython 的多线程受 GIL 限制，且「每次查询新建一个
 * socket」的 syscall 开销比被测服务器本身的处理开销还大。用它测出来的
 * 数字是**客户端的天花板**，不是服务器的能力。
 *
 * 本工具的设计：
 *   · 每个线程一个 connected UDP socket（非阻塞）
 *   · 每线程维持 W 个在途查询（pipelining），先灌满再收，把服务器压饱和
 *   · txid 低 8 位编码「槽位」，收回包时精确匹配，可算逐条 RTT
 *   · 域名模板定长（"n%09u.bench.test"），可原地改字节，无字符串拼接开销
 *
 * 用法：
 *   dnsbench -t 8 -d 5 -w 64 --mode=hot   -p 15353
 *   dnsbench -t 8 -d 5 -w 64 --mode=cold  -p 15353 --names=200000
 *   dnsbench -t 8 -d 5 -w 64 --mode=fixed -p 15353   # 全部查同一个名字
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAX_WINDOW 512
#define NQNAME_OFF 12 /* 查询报文里 qname 起始偏移 */
#define DIGIT_OFF 1   /* "n%09u" 里第一个数字的偏移 */
#define NDIGITS 9

enum mode { MODE_HOT, MODE_COLD, MODE_FIXED };

static int g_port = 15353;
static const char *g_addr = "127.0.0.1";
static double g_duration = 5.0;
static int g_threads = 8;
static int g_window = 64;
static enum mode g_mode = MODE_HOT;
static unsigned g_names = 200000;
static int g_tcp = 0; /* 用 TCP 而不是 UDP（仅连通性验证） */

/* 共享统计 */
static atomic_ulong st_sent, st_recv, st_err, st_timeout;
static double st_lat[MAX_WINDOW * 64]; /* 按槽累加，最后汇总成近似分位数 */
static atomic_int st_lat_n;

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* 构造定长查询：n000000001.bench.test A IN */
static size_t build_template(unsigned char *buf, const char *suffix) {
    size_t p = 0;
    buf[p++] = 0x12; buf[p++] = 0x34; /* id（稍后覆盖） */
    buf[p++] = 0x01; buf[p++] = 0x00; /* flags: RD */
    buf[p++] = 0x00; buf[p++] = 0x01; /* qdcount */
    buf[p++] = 0x00; buf[p++] = 0x00;
    buf[p++] = 0x00; buf[p++] = 0x00;
    buf[p++] = 0x00; buf[p++] = 0x00;
    buf[p++] = 0x0A;                  /* label 长度 10 */
    buf[p++] = 'n';
    for (int i = 0; i < NDIGITS; i++) buf[p++] = '0';
    /* 后缀：".bench.test" -> 5"bench" 4"test" 0 */
    (void)suffix;
    buf[p++] = 5; memcpy(buf + p, "bench", 5); p += 5;
    buf[p++] = 4; memcpy(buf + p, "test", 4); p += 4;
    buf[p++] = 0x00;
    buf[p++] = 0x00; buf[p++] = 0x01; /* qtype A */
    buf[p++] = 0x00; buf[p++] = 0x01; /* qclass IN */
    return p;
}

static inline void patch_id(unsigned char *b, uint16_t id) {
    b[0] = (unsigned char)(id >> 8);
    b[1] = (unsigned char)(id & 0xff);
}

static inline void patch_name(unsigned char *b, unsigned v) {
    for (int i = NDIGITS - 1; i >= 0; i--) {
        b[NQNAME_OFF + DIGIT_OFF + i] = (unsigned char)('0' + (v % 10));
        v /= 10;
    }
}

typedef struct {
    int tid;
    unsigned char pkt[MAX_WINDOW][512];
    double sent_at[MAX_WINDOW];
    size_t plen;
    int expected;
    unsigned rr; /* HOT 模式下的轮转计数器 */
    unsigned long local_sent, local_recv, local_err;
    double lats[4096];
    int nlat;
} worker_t;

static void *worker(void *arg) {
    worker_t *w = arg;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)g_port);
    inet_pton(AF_INET, g_addr, &sa.sin_addr);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return NULL; }
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
        perror("connect"); close(fd); return NULL;
    }
    int one = 1 << 20;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &one, sizeof one);
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &one, sizeof one);
    fcntl(fd, F_SETFL, O_NONBLOCK);

    unsigned base = 1u;
    unsigned span = g_names ? g_names : 1u;
    unsigned seq = (unsigned)w->tid * 7919u + 17u;

    double t_end = now_s() + g_duration;
    double t_hard = t_end + 3.0; /* 硬上限：上游挂了也不能死循环 */
    int outstanding = 0;
    unsigned char rbuf[4096];

    while (now_s() < t_hard && (now_s() < t_end || outstanding > 0)) {
        /* 灌满窗口 */
        while (outstanding < w->expected && now_s() < t_end) {
            int slot = -1;
            for (int i = 0; i < w->expected; i++) {
                /* 用轮转覆盖已回收的槽；sent_at 为 0 表示空闲 */
                if (w->sent_at[i] == 0.0) { slot = i; break; }
            }
            if (slot < 0) break;

            memcpy(w->pkt[slot], w->pkt[0], w->plen); /* 模板在 slot0 里 */
            uint16_t id = (uint16_t)(((unsigned)w->tid << 8) | (unsigned)slot);
            patch_id(w->pkt[slot], id);
            unsigned v;
            if (g_mode == MODE_FIXED) {
                v = base;
            } else if (g_mode == MODE_HOT) {
                /* 轮转遍历预热过的名字，保证条条命中缓存 */
                w->rr++;
                if (w->rr >= span) w->rr = 0;
                v = base + w->rr;
            } else {
                seq = seq * 1103515245u + 12345u;
                v = base + ((seq >> 8) % span);
            }
            patch_name(w->pkt[slot], v);

            w->sent_at[slot] = now_s();
            ssize_t n = send(fd, w->pkt[slot], w->plen, 0);
            if (n < 0) {
                w->sent_at[slot] = 0.0;
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                w->local_err++;
                continue;
            }
            w->local_sent++;
            outstanding++;
        }

        /* 收包 */
        int got_any = 0;
        for (;;) {
            ssize_t n = recv(fd, rbuf, sizeof rbuf, 0);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                if (errno == ECONNREFUSED) { w->local_err++; continue; }
                break;
            }
            if (n < 12) continue;
            uint16_t id = (uint16_t)((rbuf[0] << 8) | rbuf[1]);
            int slot = id & 0xff;
            if ((id >> 8) != (uint16_t)w->tid) continue;
            if (slot >= w->expected || w->sent_at[slot] == 0.0) continue;
            double lat = (now_s() - w->sent_at[slot]) * 1e6; /* µs */
            if (w->nlat < 4096) w->lats[w->nlat++] = lat;
            w->sent_at[slot] = 0.0;
            w->local_recv++;
            outstanding--;
            got_any = 1;
        }

        if (!got_any) {
            struct timespec ts = {0, 200000}; /* 200µs */
            nanosleep(&ts, NULL);
        }
    }

    close(fd);
    atomic_fetch_add(&st_sent, w->local_sent);
    atomic_fetch_add(&st_recv, w->local_recv);
    atomic_fetch_add(&st_err, w->local_err);
    for (int i = 0; i < w->nlat && atomic_load(&st_lat_n) < (int)(sizeof st_lat / sizeof st_lat[0]); i++)
        st_lat[atomic_fetch_add(&st_lat_n, 1)] = w->lats[i];
    return NULL;
}

static int cmp_double(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static double pct(double *v, int n, double p) {
    if (n <= 0) return 0;
    int i = (int)(n * p);
    if (i >= n) i = n - 1;
    return v[i];
}

int main(int argc, char **argv) {
    /* 先把 "--key=value" 拆成两个 argv，简化后续解析 */
    char *av[64];
    int ac = 0;
    av[ac++] = argv[0];
    for (int i = 1; i < argc && ac < 62; i++) {
        char *eq = (argv[i][0] == '-' && argv[i][1] == '-') ? strchr(argv[i], '=') : NULL;
        if (eq) {
            *eq = '\0';
            av[ac++] = argv[i];
            av[ac++] = eq + 1;
        } else {
            av[ac++] = argv[i];
        }
    }
    argc = ac;
    argv = av;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-t") && i + 1 < argc) g_threads = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-d") && i + 1 < argc) g_duration = atof(argv[++i]);
        else if (!strcmp(argv[i], "-w") && i + 1 < argc) g_window = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-p") && i + 1 < argc) g_port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-a") && i + 1 < argc) g_addr = argv[++i];
        else if (!strcmp(argv[i], "--names") && i + 1 < argc) g_names = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--mode") && i + 1 < argc) {
            if (!strcmp(argv[i + 1], "hot")) g_mode = MODE_HOT;
            else if (!strcmp(argv[i + 1], "cold")) g_mode = MODE_COLD;
            else if (!strcmp(argv[i + 1], "fixed")) g_mode = MODE_FIXED;
            i++;
        } else {
            fprintf(stderr, "unknown arg: %s\n", argv[i]);
            return 2;
        }
    }
    if (g_window > MAX_WINDOW) g_window = MAX_WINDOW;
    if (g_threads < 1) g_threads = 1;

    /* 预热：hot 模式先把条目灌进服务器缓存，避免把冷启动算进热态吞吐 */
    worker_t *tmpl = calloc(1, sizeof(worker_t));
    if (!tmpl) { perror("calloc"); return 1; }
    tmpl->plen = build_template(tmpl->pkt[0], "");

    if (g_mode == MODE_HOT) {
        int pfd = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        sa.sin_port = htons((uint16_t)g_port);
        inet_pton(AF_INET, g_addr, &sa.sin_addr);
        connect(pfd, (struct sockaddr *)&sa, sizeof sa);
        fcntl(pfd, F_SETFL, O_NONBLOCK);
        int one = 4 << 20;
        setsockopt(pfd, SOL_SOCKET, SO_RCVBUF, &one, sizeof one);

        unsigned sent_w = 0, recv_w = 0;
        double deadline = now_s() + 30.0;
        while (recv_w < g_names && now_s() < deadline) {
            while (sent_w < g_names) {
                unsigned char q[512];
                memcpy(q, tmpl->pkt[0], tmpl->plen);
                sent_w++;
                patch_name(q, sent_w);
                patch_id(q, (uint16_t)(sent_w & 0xffff));
                if (send(pfd, q, tmpl->plen, 0) < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) { sent_w--; break; }
                }
            }
            unsigned char rb[2048];
            ssize_t n = recv(pfd, rb, sizeof rb, 0);
            if (n >= 12) recv_w++;
            else {
                struct timespec ts = {0, 500000};
                nanosleep(&ts, NULL);
            }
        }
        fprintf(stderr, "[warmup] 预热 %u 个域名：发出 %u，回收 %u\n",
                g_names, sent_w, recv_w);
        close(pfd);
    }
    free(tmpl);

    worker_t *ws = calloc((size_t)g_threads, sizeof(worker_t));
    pthread_t *th = calloc((size_t)g_threads, sizeof(pthread_t));
    if (!ws || !th) { perror("calloc"); return 1; }

    worker_t base;
    memset(&base, 0, sizeof base);
    base.plen = build_template(base.pkt[0], "");
    for (int i = 0; i < g_threads; i++) {
        ws[i].tid = i;
        ws[i].plen = base.plen;
        ws[i].expected = g_window;
        for (int k = 0; k < g_window; k++)
            memcpy(ws[i].pkt[k], base.pkt[0], base.plen);
    }

    double t0 = now_s();
    for (int i = 0; i < g_threads; i++)
        pthread_create(&th[i], NULL, worker, &ws[i]);
    for (int i = 0; i < g_threads; i++)
        pthread_join(th[i], NULL);
    double wall = now_s() - t0;

    unsigned long sent = atomic_load(&st_sent);
    unsigned long recv_ = atomic_load(&st_recv);
    unsigned long err = atomic_load(&st_err);
    int nlat = atomic_load(&st_lat_n);
    qsort(st_lat, (size_t)nlat, sizeof st_lat[0], cmp_double);

    printf("RESULT threads=%d window=%d wall=%.3f sent=%lu recv=%lu err=%lu "
           "qps=%.0f p50=%.1fus p95=%.1fus p99=%.1fus max=%.1fus\n",
           g_threads, g_window, wall, sent, recv_, err,
           wall > 0 ? (double)recv_ / wall : 0.0,
           pct(st_lat, nlat, 0.50), pct(st_lat, nlat, 0.95),
           pct(st_lat, nlat, 0.99), nlat ? st_lat[nlat - 1] : 0.0);
    free(ws); free(th);
    return 0;
}
