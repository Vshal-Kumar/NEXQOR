/*
 * hybrid/transport.h — Reliable UDP Transport & Dynamic Discovery for Hybrid Suite
 *
 * Implements low-latency UDP transport, packet fragmentation/reassembly,
 * ChaCha20-Poly1305 directional encryption, anti-replay sliding window,
 * and 5-tier zero-config dynamic server discovery.
 */

#ifndef HYBRID_TRANSPORT_H
#define HYBRID_TRANSPORT_H

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#if defined(__x86_64__) || defined(_M_X64)
#define cpu_pause() __builtin_ia32_pause()
#elif defined(__aarch64__) || defined(_M_ARM64)
#define cpu_pause() __asm__ __volatile__("yield" ::: "memory")
#else
#define cpu_pause() do { } while (0)
#endif

#include "crypto/replay_window.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Timing ──────────────────────────────────────────────────────── */
double   now_ms(void);
uint64_t now_ns(void);
void     now_hms(char *buf, int sz);

/* ── Endpoint & Dynamic Discovery ────────────────────────────────── */
#define SERVER_PORT                9879
#define DEFAULT_SERVER_ADDR        "127.0.0.1"
#define SERVER_DISCOVERY_FILE      "server_endpoint.info"
#define SERVER_DISCOVERY_SYS_FILE  "/tmp/hybrid_server.ip"
#define ENV_SERVER_IP              "HYBRID_SERVER_IP"

/* ── Packet Types ────────────────────────────────────────────────── */
#define PKT_CLIENT_HELLO     0x01
#define PKT_SERVER_HELLO     0x02
#define PKT_CLIENT_AUTH      0x03
#define PKT_FRAG             0x05
#define PKT_DATA             0x10
#define PKT_ACK              0x11
#define PKT_PING             0x12
#define PKT_PONG             0x13
#define PKT_BUSY             0x14
#define PKT_DISCONNECT       0x15
#define PKT_DISCOVERY_PROBE  0x16
#define PKT_DISCOVERY_OFFER  0x17

/* ── Sizing & Bounds ─────────────────────────────────────────────── */
#define DATA_CHUNK_MAX       16384
#define PKT_BUF_MAX          16512
#define FRAG_PAYLOAD_MAX     1024
#define SESSION_ID_BYTES     8

/* ── Reliability Parameters ──────────────────────────────────────── */
#define ACK_TIMEOUT_US       1000000
#define DATA_ACK_TIMEOUT_US  200000
#define RETX_MAX             10
#define DATA_RETX_MAX        5
#define RX_POLL_TIMEOUT_US   10000

/* ── Canonical On-Wire Packet Header (15 bytes) ──────────────────── */
typedef struct __attribute__((packed)) {
    uint32_t seq;
    uint8_t  type;
    uint16_t len;
    uint64_t session_id;
} pkt_hdr_t;

#define PKT_HDR_BYTES sizeof(pkt_hdr_t)

/* ── Fragmentation Header (11 bytes) ─────────────────────────────── */
typedef struct __attribute__((packed)) {
    uint16_t msg_id;
    uint8_t  orig_type;
    uint8_t  frag_idx;
    uint8_t  frag_total;
    uint16_t frag_len;
    uint32_t total_len;
} frag_hdr_t;

#define FRAG_HDR_BYTES sizeof(frag_hdr_t)

/* ── Connection State ────────────────────────────────────────────── */
typedef struct {
    int                sock;
    struct sockaddr_in peer;
    socklen_t          peer_len;

    uint8_t            tx_key[32];          /* Directional encryption key */
    uint8_t            rx_key[32];          /* Directional decryption key */
    uint32_t           tx_seq;
    uint64_t           tx_nonce_ctr;
    uint64_t           session_id;

    int                established;
    replay_window_t    replay_win;          /* Sliding replay protection window */
} conn_t;

void conn_init(conn_t *c, int sock);
void conn_destroy(conn_t *c);

/* ── Telemetry & Connection Metrics ──────────────────────────────── */
typedef struct {
    /* Handshake breakdown */
    double   hs_kem_keygen_ms;
    double   hs_dsa_keygen_ms;
    double   hs_encap_ms;
    double   hs_sign_ms;
    double   hs_verify_ms;
    double   hs_total_ms;

    /* Per-message transport */
    double   msg_last_rtt_ms;
    double   msg_avg_rtt_ms;
    double   msg_min_rtt_ms;
    double   msg_max_rtt_ms;
    uint64_t msg_count;
    uint64_t retransmissions;
    uint64_t bytes_sent;
    uint64_t bytes_recv;

    /* AEAD cost accumulators */
    double   total_encrypt_us;
    double   total_decrypt_us;
    uint64_t encrypt_count;
    uint64_t decrypt_count;

    /* Jitter (RFC 3550 EWMA) */
    double   jitter_ms;
    double   prev_rtt_ms;

    /* Timestamps */
    uint64_t last_send_ns;
    uint64_t prev_recv_ns;
    uint64_t session_start_ns;
} metrics_t;

/* ── Sockets & Transport Operations ──────────────────────────────── */
int make_server_sock(void);
int make_client_sock(void);

ssize_t pkt_send(conn_t *c, uint8_t type, const uint8_t *payload, uint16_t payload_len);
ssize_t pkt_recv(conn_t *c, pkt_hdr_t *hdr, uint8_t *payload_out, size_t payload_max, int timeout_us);
int pkt_send_reliable(conn_t *c, uint8_t type, const uint8_t *payload, uint16_t payload_len);
void send_ack(conn_t *c, uint32_t ack_seq);

/* ── Fragmentation & Reassembly API ──────────────────────────────── */
typedef struct {
    uint16_t msg_id;
    uint8_t  orig_type;
    uint8_t  frag_count;
    uint8_t  frag_received;
    uint32_t total_len;
    uint32_t received_bytes;
    uint8_t  bitmap[32];
    uint8_t *buf;
    uint64_t start_time_ns;
    int      active;
} reassembly_ctx_t;

void reassembly_init(reassembly_ctx_t *ctx);
void reassembly_cleanup(reassembly_ctx_t *ctx);
int reassembly_feed_frag(reassembly_ctx_t *ctx, const frag_hdr_t *fhdr, const uint8_t *frag_data);
int pkt_send_fragmented(conn_t *c, uint8_t orig_type, const uint8_t *payload, uint32_t payload_len, uint16_t max_frag_sz);

/* ── Authenticated Data Transfer ─────────────────────────────────── */
int data_send(conn_t *c, metrics_t *m, const uint8_t *msg, uint32_t msg_len);
ssize_t data_recv(conn_t *c, uint8_t *out, size_t out_max);

void metrics_print(const metrics_t *m);
void metrics_update_rtt(metrics_t *m, uint64_t recv_ns);

/* ── Dynamic Server Resolution & Discovery API ───────────────────── */
int resolve_server_address(const char *input_target, struct sockaddr_in *out_peer,
                           char *resolved_ip_str, size_t str_len);
int server_publish_endpoints(char *lan_ip, size_t lan_len,
                             char *vpn_ip, size_t vpn_len);

#ifdef __cplusplus
}
#endif

#endif /* HYBRID_TRANSPORT_H */
