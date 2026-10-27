/*
 * hybrid/transport.c — Low-latency UDP Transport, Fragmentation & Discovery
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "transport.h"
#include "crypto/aead.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <endian.h>

/* ── Timing ──────────────────────────────────────────────────────── */
double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

void now_hms(char *buf, int sz) {
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    snprintf(buf, sz, "%02d:%02d:%02d", tm.tm_hour, tm.tm_min, tm.tm_sec);
}

/* ── Connection Lifecycle ────────────────────────────────────────── */
void conn_init(conn_t *c, int sock) {
    if (!c) return;
    memset(c, 0, sizeof(conn_t));
    c->sock = sock;
    c->tx_seq = 1;
    c->tx_nonce_ctr = 0;
    c->established = 0;
    replay_window_init(&c->replay_win);
}

void conn_destroy(conn_t *c) {
    if (!c) return;
    explicit_bzero(c->tx_key, sizeof(c->tx_key));
    explicit_bzero(c->rx_key, sizeof(c->rx_key));
    replay_window_destroy(&c->replay_win);
    c->established = 0;
}

/* ── Nonce Generation with Exhaustion Refusal ─────────────────────── */
static int make_nonce(uint8_t nonce[12], uint64_t ctr) {
    if (ctr >= 0xFFFFFFFFFFFFFF00ULL) {
        fprintf(stderr, "[hybrid-transport] CRITICAL: Nonce counter exhaustion!\n");
        return -1;
    }
    uint64_t le_ctr = htole64(ctr);
    memcpy(nonce, &le_ctr, 8);
    memset(nonce + 8, 0, 4);
    return 0;
}

/* ── Sockets Creation ────────────────────────────────────────────── */
int make_server_sock(void) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;

    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    int buf_sz = 16 * 1024 * 1024;
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &buf_sz, sizeof(buf_sz));
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, &buf_sz, sizeof(buf_sz));

    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons(SERVER_PORT);

    if (bind(s, (struct sockaddr *)&a, sizeof(a)) < 0) {
        close(s);
        return -1;
    }
    return s;
}

int make_client_sock(void) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;

    int buf_sz = 16 * 1024 * 1024;
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &buf_sz, sizeof(buf_sz));
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, &buf_sz, sizeof(buf_sz));
    return s;
}

/* ── Send / Receive Low-Level Operations ──────────────────────────── */
ssize_t pkt_send(conn_t *c, uint8_t type, const uint8_t *payload, uint16_t payload_len) {
    uint8_t raw[PKT_BUF_MAX];
    pkt_hdr_t *hdr = (pkt_hdr_t *)raw;
    hdr->seq = htonl(c->tx_seq++);
    hdr->type = type;
    hdr->len = htons(payload_len);
    hdr->session_id = htobe64(c->session_id);

    if (payload && payload_len > 0) {
        memcpy(raw + PKT_HDR_BYTES, payload, payload_len);
    }
    return sendto(c->sock, raw, PKT_HDR_BYTES + payload_len, 0,
                  (struct sockaddr *)&c->peer, c->peer_len);
}

ssize_t pkt_recv(conn_t *c, pkt_hdr_t *hdr, uint8_t *payload_out,
                 size_t payload_max, int timeout_us) {
    if (timeout_us > 0) {
        struct pollfd pfd = { .fd = c->sock, .events = POLLIN };
        int ms = timeout_us / 1000;
        if (ms == 0) ms = 1;
        int pr = poll(&pfd, 1, ms);
        if (pr <= 0) return -1;
    }

    uint8_t raw[PKT_BUF_MAX];
    struct sockaddr_in sender;
    socklen_t slen = sizeof(sender);
    ssize_t n = recvfrom(c->sock, raw, sizeof(raw), 0, (struct sockaddr *)&sender, &slen);
    if (n < (ssize_t)PKT_HDR_BYTES) return -1;

    pkt_hdr_t *h = (pkt_hdr_t *)raw;
    hdr->seq = ntohl(h->seq);
    hdr->type = h->type;
    hdr->len = ntohs(h->len);
    hdr->session_id = be64toh(h->session_id);

    if (c->peer_len == 0) {
        c->peer = sender;
        c->peer_len = slen;
    }

    size_t plen = n - PKT_HDR_BYTES;
    if (plen > payload_max) plen = payload_max;
    if (plen > 0 && payload_out) {
        memcpy(payload_out, raw + PKT_HDR_BYTES, plen);
    }
    return (ssize_t)plen;
}

void send_ack(conn_t *c, uint32_t ack_seq) {
    uint8_t ack_payload[4];
    ack_payload[0] = (uint8_t)(ack_seq >> 24);
    ack_payload[1] = (uint8_t)(ack_seq >> 16);
    ack_payload[2] = (uint8_t)(ack_seq >> 8);
    ack_payload[3] = (uint8_t)(ack_seq);
    pkt_send(c, PKT_ACK, ack_payload, 4);
}

int pkt_send_reliable(conn_t *c, uint8_t type, const uint8_t *payload, uint16_t payload_len) {
    for (int attempt = 0; attempt < RETX_MAX; attempt++) {
        uint32_t our_seq = c->tx_seq;
        if (pkt_send(c, type, payload, payload_len) < 0) return -1;

        pkt_hdr_t hdr;
        uint8_t buf[256];
        double deadline = now_ms() + ACK_TIMEOUT_US / 1000.0;

        for (;;) {
            int remaining_us = (int)((deadline - now_ms()) * 1000.0);
            if (remaining_us <= 0) break;

            ssize_t n = pkt_recv(c, &hdr, buf, sizeof(buf), remaining_us);
            if (n < 0) break;

            if (hdr.type == PKT_DISCONNECT) return -2;

            if (hdr.type == PKT_ACK && n >= 4) {
                uint32_t acked = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
                                 ((uint32_t)buf[2] << 8) | (uint32_t)buf[3];
                if (acked == our_seq) return 0;
            }
        }
    }
    return -1;
}

/* ── Fragmentation & Reassembly ──────────────────────────────────── */
void reassembly_init(reassembly_ctx_t *ctx) {
    if (!ctx) return;
    memset(ctx, 0, sizeof(*ctx));
}

void reassembly_cleanup(reassembly_ctx_t *ctx) {
    if (!ctx) return;
    if (ctx->buf) {
        free(ctx->buf);
        ctx->buf = NULL;
    }
    ctx->active = 0;
}

int reassembly_feed_frag(reassembly_ctx_t *ctx, const frag_hdr_t *fhdr, const uint8_t *frag_data) {
    if (!ctx || !fhdr || !frag_data) return -1;

    uint16_t msg_id = ntohs(fhdr->msg_id);
    uint8_t orig_type = fhdr->orig_type;
    uint8_t frag_idx = fhdr->frag_idx;
    uint8_t frag_total = fhdr->frag_total;
    uint16_t frag_len = ntohs(fhdr->frag_len);
    uint32_t total_len = ntohl(fhdr->total_len);

    if (total_len == 0 || total_len > 65536 || frag_total == 0 || frag_idx >= frag_total) {
        return -1;
    }

    if (ctx->active && ctx->msg_id != msg_id) {
        reassembly_cleanup(ctx);
    }

    if (!ctx->active) {
        ctx->buf = malloc(total_len);
        if (!ctx->buf) return -1;
        ctx->msg_id = msg_id;
        ctx->orig_type = orig_type;
        ctx->frag_count = frag_total;
        ctx->frag_received = 0;
        ctx->total_len = total_len;
        ctx->received_bytes = 0;
        memset(ctx->bitmap, 0, sizeof(ctx->bitmap));
        ctx->start_time_ns = now_ns();
        ctx->active = 1;
    }

    int byte_idx = frag_idx / 8;
    int bit_idx = frag_idx % 8;
    if (ctx->bitmap[byte_idx] & (1 << bit_idx)) {
        return 0; /* Duplicate fragment */
    }

    uint32_t offset = (uint32_t)frag_idx * FRAG_PAYLOAD_MAX;
    if (offset + frag_len > ctx->total_len) {
        return -1;
    }

    memcpy(ctx->buf + offset, frag_data, frag_len);
    ctx->bitmap[byte_idx] |= (1 << bit_idx);
    ctx->frag_received++;
    ctx->received_bytes += frag_len;

    if (ctx->frag_received == ctx->frag_count && ctx->received_bytes == ctx->total_len) {
        return 1; /* Complete reassembly */
    }
    return 0;
}

int pkt_send_fragmented(conn_t *c, uint8_t orig_type, const uint8_t *payload,
                        uint32_t payload_len, uint16_t max_frag_sz) {
    if (!c || !payload || payload_len == 0) return -1;
    if (max_frag_sz == 0 || max_frag_sz > FRAG_PAYLOAD_MAX) max_frag_sz = FRAG_PAYLOAD_MAX;

    uint8_t frag_total = (uint8_t)((payload_len + max_frag_sz - 1) / max_frag_sz);
    static uint16_t g_msg_id = 1;
    uint16_t mid = g_msg_id++;

    uint8_t packet_buf[PKT_BUF_MAX];

    for (uint8_t i = 0; i < frag_total; i++) {
        uint32_t off = (uint32_t)i * max_frag_sz;
        uint16_t flen = (uint16_t)((payload_len - off > max_frag_sz) ? max_frag_sz : (payload_len - off));

        frag_hdr_t *fhdr = (frag_hdr_t *)packet_buf;
        fhdr->msg_id = htons(mid);
        fhdr->orig_type = orig_type;
        fhdr->frag_idx = i;
        fhdr->frag_total = frag_total;
        fhdr->frag_len = htons(flen);
        fhdr->total_len = htonl(payload_len);

        memcpy(packet_buf + FRAG_HDR_BYTES, payload + off, flen);

        if (pkt_send_reliable(c, PKT_FRAG, packet_buf, FRAG_HDR_BYTES + flen) != 0) {
            return -1;
        }
    }
    return 0;
}

/* ── Directional Authenticated Data Transfer ─────────────────────── */
int data_send(conn_t *c, metrics_t *m, const uint8_t *msg, uint32_t msg_len) {
    uint32_t offset = 0;
    while (offset < msg_len) {
        uint32_t chunk = msg_len - offset;
        if (chunk > DATA_CHUNK_MAX) chunk = DATA_CHUNK_MAX;

        uint8_t pkt[12 + 16 + DATA_CHUNK_MAX];
        uint8_t nonce[12];
        if (make_nonce(nonce, c->tx_nonce_ctr++) != 0) return -1;
        memcpy(pkt, nonce, 12);

        pkt_hdr_t wire_hdr;
        wire_hdr.seq = htonl(c->tx_seq);
        wire_hdr.type = PKT_DATA;
        wire_hdr.len = htons((uint16_t)(chunk + 28));
        wire_hdr.session_id = htobe64(c->session_id);

        double t0 = now_ms();
        int ct_len = aead_encrypt(msg + offset, (int)chunk,
                                  (const uint8_t *)&wire_hdr, PKT_HDR_BYTES,
                                  c->tx_key, nonce,
                                  pkt + 28, pkt + 12);
        double enc_us = (now_ms() - t0) * 1000.0;
        if (ct_len < 0) return -1;

        if (m) {
            m->total_encrypt_us += enc_us;
            m->encrypt_count++;
            m->msg_count++;
            m->bytes_sent += (uint64_t)(PKT_HDR_BYTES + 28 + chunk);
            m->last_send_ns = now_ns();
        }

        ssize_t sent = pkt_send(c, PKT_DATA, pkt, (uint16_t)(28 + chunk));
        if (sent < 0) return -1;
        offset += chunk;
    }
    return 0;
}

ssize_t data_recv(conn_t *c, uint8_t *out, size_t out_max) {
    pkt_hdr_t hdr;
    uint8_t raw[12 + 16 + DATA_CHUNK_MAX + 64];

    for (;;) {
        ssize_t n = pkt_recv(c, &hdr, raw, sizeof(raw), -1);
        if (n < 0) return -1;
        if (hdr.type == PKT_DISCONNECT) return -2;
        if (hdr.type != PKT_DATA || n < 28) continue;

        if (replay_window_check(&c->replay_win, hdr.seq) != 0) continue;

        const uint8_t *nonce = raw;
        const uint8_t *tag   = raw + 12;
        const uint8_t *ct    = raw + 28;
        int ct_len = (int)n - 28;
        if ((size_t)ct_len > out_max) return -1;

        pkt_hdr_t wire_hdr;
        wire_hdr.seq = htonl(hdr.seq);
        wire_hdr.type = hdr.type;
        wire_hdr.len = htons(hdr.len);
        wire_hdr.session_id = htobe64(hdr.session_id);

        int pt_len = aead_decrypt(ct, ct_len, (const uint8_t *)&wire_hdr, PKT_HDR_BYTES,
                                  c->rx_key, nonce, tag, out);
        if (pt_len <= 0) continue;

        replay_window_update(&c->replay_win, hdr.seq);
        send_ack(c, hdr.seq);
        return pt_len;
    }
}

/* ── Dynamic Discovery & Resolution ──────────────────────────────── */
int resolve_server_address(const char *input_target, struct sockaddr_in *out_peer,
                           char *resolved_ip_str, size_t str_len) {
    if (!out_peer) return -1;
    char target[128] = "";

    /* 1. Command-line specified argument */
    if (input_target && strlen(input_target) > 0) {
        strncpy(target, input_target, sizeof(target) - 1);
    }
    /* 2. Environment variable: HYBRID_SERVER_IP (fallback PQC_SERVER_IP) */
    else if (getenv(ENV_SERVER_IP)) {
        strncpy(target, getenv(ENV_SERVER_IP), sizeof(target) - 1);
    } else if (getenv("PQC_SERVER_IP")) {
        strncpy(target, getenv("PQC_SERVER_IP"), sizeof(target) - 1);
    }
    /* 3. Endpoint discovery files */
    else {
        FILE *f = fopen(SERVER_DISCOVERY_SYS_FILE, "r");
        if (!f) f = fopen(SERVER_DISCOVERY_FILE, "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                if (strncmp(line, "TAILSCALE_IP=", 13) == 0) {
                    char *nl = strchr(line + 13, '\n');
                    if (nl) *nl = '\0';
                    strncpy(target, line + 13, sizeof(target) - 1);
                    break;
                } else if (strncmp(line, "LAN_IP=", 7) == 0 && strlen(target) == 0) {
                    char *nl = strchr(line + 7, '\n');
                    if (nl) *nl = '\0';
                    strncpy(target, line + 7, sizeof(target) - 1);
                }
            }
            fclose(f);
        }
    }

    if (strlen(target) == 0) {
        strncpy(target, DEFAULT_SERVER_ADDR, sizeof(target) - 1);
    }

    memset(out_peer, 0, sizeof(*out_peer));
    out_peer->sin_family = AF_INET;
    out_peer->sin_port = htons(SERVER_PORT);

    if (inet_pton(AF_INET, target, &out_peer->sin_addr) <= 0) {
        struct hostent *he = gethostbyname(target);
        if (!he) return -1;
        memcpy(&out_peer->sin_addr, he->h_addr_list[0], he->h_length);
    }

    if (resolved_ip_str && str_len > 0) {
        inet_ntop(AF_INET, &out_peer->sin_addr, resolved_ip_str, str_len);
    }
    return 0;
}

int server_publish_endpoints(char *lan_ip, size_t lan_len,
                             char *vpn_ip, size_t vpn_len) {
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) return -1;

    char detected_lan[INET_ADDRSTRLEN] = "";
    char detected_vpn[INET_ADDRSTRLEN] = "";

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;

        char host[INET_ADDRSTRLEN];
        struct sockaddr_in *p = (struct sockaddr_in *)ifa->ifa_addr;
        inet_ntop(AF_INET, &p->sin_addr, host, sizeof(host));

        if (strncmp(host, "100.", 4) == 0 || strstr(ifa->ifa_name, "tailscale") != NULL) {
            strncpy(detected_vpn, host, sizeof(detected_vpn) - 1);
        } else if (strlen(detected_lan) == 0) {
            strncpy(detected_lan, host, sizeof(detected_lan) - 1);
        }
    }
    freeifaddrs(ifaddr);

    if (lan_ip && lan_len > 0) strncpy(lan_ip, detected_lan, lan_len);
    if (vpn_ip && vpn_len > 0) strncpy(vpn_ip, detected_vpn, vpn_len);

    /* Write publication files */
    FILE *f = fopen(SERVER_DISCOVERY_FILE, "w");
    if (f) {
        fprintf(f, "# QRYPTONEX Hybrid Endpoint Discovery\n");
        fprintf(f, "PORT=%d\n", SERVER_PORT);
        if (strlen(detected_lan) > 0) fprintf(f, "LAN_IP=%s\n", detected_lan);
        if (strlen(detected_vpn) > 0) fprintf(f, "TAILSCALE_IP=%s\n", detected_vpn);
        fclose(f);
    }

    f = fopen(SERVER_DISCOVERY_SYS_FILE, "w");
    if (f) {
        if (strlen(detected_vpn) > 0) fprintf(f, "TAILSCALE_IP=%s\n", detected_vpn);
        if (strlen(detected_lan) > 0) fprintf(f, "LAN_IP=%s\n", detected_lan);
        fclose(f);
    }
    return 0;
}

void metrics_print(const metrics_t *m) {
    if (!m) return;
    printf("\n── Telemetry Metrics ───────────────────────────────\n");
    printf("  Packets Received:       %lu\n", m->msg_count);
    printf("  Bytes Sent / Recv:      %lu / %lu\n", m->bytes_sent, m->bytes_recv);
    printf("  Avg Round-Trip Time:    %.2f ms (min: %.2f ms, max: %.2f ms)\n",
           m->msg_avg_rtt_ms, m->msg_min_rtt_ms, m->msg_max_rtt_ms);
    printf("  RFC 3550 Jitter:        %.2f ms\n", m->jitter_ms);
    printf("  Avg Decrypt Duration:   %.1f µs\n",
           m->decrypt_count > 0 ? (m->total_decrypt_us / (double)m->decrypt_count) : 0.0);
    printf("────────────────────────────────────────────────────\n");
}

void metrics_update_rtt(metrics_t *m, uint64_t recv_ns) {
    if (!m) return;
    m->msg_count++;
    if (m->last_send_ns > 0 && recv_ns >= m->last_send_ns) {
        double rtt = (double)(recv_ns - m->last_send_ns) / 1e6;
        m->msg_last_rtt_ms = rtt;
        if (m->msg_count == 1 || rtt < m->msg_min_rtt_ms) m->msg_min_rtt_ms = rtt;
        if (rtt > m->msg_max_rtt_ms) m->msg_max_rtt_ms = rtt;

        m->msg_avg_rtt_ms = (m->msg_count == 1)
                            ? rtt
                            : (m->msg_avg_rtt_ms * 0.9 + rtt * 0.1);

        if (m->prev_rtt_ms > 0) {
            double d = rtt - m->prev_rtt_ms;
            if (d < 0) d = -d;
            m->jitter_ms += (d - m->jitter_ms) / 16.0;
        }
        m->prev_rtt_ms = rtt;
    }
}
