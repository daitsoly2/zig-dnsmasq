/*
 * mockup.c — 零延迟 DNS 假上游
 *
 * 用途：给 C 版 dnsmasq 与 Zig 版用**同一组**上游做对比基准，
 * 排除上游延迟这个变量。收到查询立刻回一个固定 A 记录。
 *
 * 用法：mockup 15361 15362 15363 15364
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAXFDS 16

static int encode_name(unsigned char *dst, const unsigned char *q, size_t qlen) {
    size_t i = 0, o = 0;
    while (i < qlen) {
        unsigned l = q[i];
        if (l == 0) { dst[o++] = 0; i++; break; }
        if (l > 63 || i + 1 + l > qlen) return -1;
        memcpy(dst + o, q + i, 1 + l);
        o += 1 + l;
        i += 1 + l;
    }
    return (int)o;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: mockup PORT [PORT...]\n"); return 2; }
    int n = argc - 1;
    if (n > MAXFDS) n = MAXFDS;

    struct pollfd pfd[MAXFDS];
    for (int i = 0; i < n; i++) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        int rcv = 4 << 20;
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof rcv);
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        sa.sin_port = htons((uint16_t)atoi(argv[i + 1]));
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
            perror("bind"); return 1;
        }
        pfd[i].fd = fd;
        pfd[i].events = POLLIN;
    }

    unsigned char rbuf[4096], obuf[4096];
    for (;;) {
        if (poll(pfd, (nfds_t)n, -1) <= 0) continue;
        for (int i = 0; i < n; i++) {
            if (!(pfd[i].revents & POLLIN)) continue;
            struct sockaddr_in cli;
            socklen_t cl = sizeof cli;
            ssize_t rn = recvfrom(pfd[i].fd, rbuf, sizeof rbuf, 0,
                                  (struct sockaddr *)&cli, &cl);
            if (rn < 12) continue;

            int qn = encode_name(obuf + 12, rbuf + 12, (size_t)rn - 12);
            if (qn < 0) continue;

            /* qname 之后必须原样带上 QTYPE/QCLASS，否则应答的问题是畸形
             * 报文（qdcount=1 却没有 type/class），上游会被解析器丢弃。 */
            if (12 + (size_t)qn + 4 > (size_t)rn) continue;

            memcpy(obuf, rbuf, 12);
            obuf[2] = 0x81; obuf[3] = 0x80;          /* QR=1, RD, RA */
            obuf[4] = 0; obuf[5] = 1;                /* qdcount */
            obuf[6] = 0; obuf[7] = 1;                /* ancount */
            obuf[8] = 0; obuf[9] = 0;
            obuf[10] = 0; obuf[11] = 0;

            size_t o = 12 + (size_t)qn;
            memcpy(obuf + o, rbuf + 12 + qn, 4);     /* QTYPE + QCLASS */
            o += 4;
            obuf[o++] = 0xC0; obuf[o++] = 0x0C;      /* 指针指向 qname */
            obuf[o++] = 0x00; obuf[o++] = 0x01;      /* A */
            obuf[o++] = 0x00; obuf[o++] = 0x01;      /* IN */
            obuf[o++] = 0x00; obuf[o++] = 0x00;
            obuf[o++] = 0x00; obuf[o++] = 0x3C;      /* TTL 60 */
            obuf[o++] = 0x00; obuf[o++] = 0x04;
            obuf[o++] = 10; obuf[o++] = 0; obuf[o++] = 0; obuf[o++] = (unsigned char)(1 + (i % 4));

            sendto(pfd[i].fd, obuf, o, 0, (struct sockaddr *)&cli, cl);
        }
    }
    return 0;
}
