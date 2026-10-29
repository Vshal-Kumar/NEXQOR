/*
 * security_lab/monitoring/server_health.c
 *
 * Implements server health probes, process tracking, and PID discovery.
 */

#include "server_health.h"
#include "protocol_framer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <poll.h>
#include <sys/socket.h>
#include <arpa/inet.h>

bool server_health_check_pid(pid_t pid) {
    if (pid <= 0) return false;
    return (kill(pid, 0) == 0);
}

pid_t server_health_find_server_pid(const char *suite_name) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "pgrep -f '%s/server' | head -n 1", suite_name ? suite_name : "pqc");

    FILE *f = popen(cmd, "r");
    if (!f) return -1;

    char line[64];
    pid_t pid = -1;
    if (fgets(line, sizeof(line), f)) {
        pid = (pid_t)atoi(line);
    }
    pclose(f);
    return pid;
}

int server_health_probe_udp(const char *ip_str, uint16_t port, double *out_rtt_us) {
    if (!ip_str) return -1;

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;

    struct sockaddr_in srv;
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_port = htons(port);
    if (inet_pton(AF_INET, ip_str, &srv.sin_addr) != 1) {
        close(s);
        return -1;
    }

    uint8_t probe[PKT_HDR_BYTES + 32];
    int plen = pkt_build_frame(probe, sizeof(probe), 0, PKT_DISCOVERY_PROBE, 0,
                               (const uint8_t *)"HEALTH_PROBE", 12);
    if (plen < 0) {
        close(s);
        return -1;
    }

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    if (sendto(s, probe, (size_t)plen, 0, (struct sockaddr *)&srv, sizeof(srv)) != plen) {
        close(s);
        return -1;
    }

    struct pollfd pfd = { .fd = s, .events = POLLIN };
    int prc = poll(&pfd, 1, 350); /* 350 ms timeout */
    if (prc <= 0) {
        close(s);
        return -1;
    }

    uint8_t resp[256];
    struct sockaddr_in from;
    socklen_t flen = sizeof(from);
    ssize_t n = recvfrom(s, resp, sizeof(resp), 0, (struct sockaddr *)&from, &flen);
    close(s);

    if (n < PKT_HDR_BYTES) return -1;

    clock_gettime(CLOCK_MONOTONIC, &t1);
    if (out_rtt_us) {
        *out_rtt_us = (double)(t1.tv_sec - t0.tv_sec) * 1e6 +
                      (double)(t1.tv_nsec - t0.tv_nsec) * 1e-3;
    }

    return 0;
}
