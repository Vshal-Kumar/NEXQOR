/*
 * transport.h — Minimal low-latency UDP transport for local testing
 *
 * CHANGES vs original (multi-client revision):
 *  ► net_metrics_t REMOVED from PKT_DATA wire format.
 *    Metrics are now tracked entirely via local timestamps on both
 *    sender and receiver sides.  Zero wire overhead per packet.
 *  ► data_send() signature unchanged; metrics_t parameter still used
 *    for local accounting but nothing is embedded in the packet.
 *  ► PKT_DATA payload format is now simply:
 *      NONCE(12) | TAG(16) | CIPHERTEXT(n)
 *
 * Packet wire format (unchanged):
 *   +--------+-------+-------+------------------+
 *   | seq(4) |type(1)|len(2) | payload          |
 *   +--------+-------+-------+------------------+
 *         7 bytes header
 *
 * PKT_DATA payload:  NONCE(12) | TAG(16) | CIPHERTEXT(n)
 * Other types:       raw bytes
 */

#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#if defined(__x86_64__) || defined(_M_X64)
#define cpu_pause() __builtin_ia32_pause()
#elif defined(__aarch64__) || defined(_M_ARM64)
#define cpu_pause() __asm__ __volatile__("yield" ::: "memory")

#else
#define cpu_pause()                                                            \
  do {                                                                         \
  } while (0)
#endif

#include "crypto/replay_window.h"

/* ── Endpoint ────────────────────────────────────────────────────── */
#define SERVER_PORT 9877
#define SERVER_ADDR "192.168.137.168"

/* ── Packet types ────────────────────────────────────────────────── */
#define PKT_CLIENT_HELLO 0x01
#define PKT_SERVER_HELLO 0x02
#define PKT_CLIENT_AUTH  0x03
#define PKT_FRAG         0x05
#define PKT_DATA         0x10
#define PKT_ACK          0x11
#define PKT_PING         0x12
#define PKT_PONG         0x13
#define PKT_BUSY         0x14
#define PKT_DISCONNECT   0x15

/* ── Sizing ──────────────────────────────────────────────────────── */
#define DATA_CHUNK_MAX 16384
#define PKT_BUF_MAX 16512
#define FRAG_PAYLOAD_MAX 1024

/* ── Reliability ─────────────────────────────────────────────────── */
#define ACK_TIMEOUT_US 1000000
#define DATA_ACK_TIMEOUT_US 200000 /* 200 ms */
#define RETX_MAX 10
#define DATA_RETX_MAX 5
#define RX_POLL_TIMEOUT_US 10000 /* 10 ms */

/* ── Session ID ──────────────────────────────────────────────────── */
#define SESSION_ID_BYTES 8

/* ── On-wire header (15 bytes canonical) ─────────────────────────── */
typedef struct __attribute__((packed)) {
  uint32_t seq;
  uint8_t  type;
  uint16_t len;
  uint64_t session_id;
} pkt_hdr_t;

#define PKT_HDR_BYTES sizeof(pkt_hdr_t)

/* ── Fragmentation header (11 bytes) ─────────────────────────────── */
typedef struct __attribute__((packed)) {
  uint16_t msg_id;
  uint8_t  orig_type;
  uint8_t  frag_idx;
  uint8_t  frag_total;
  uint16_t frag_len;
  uint32_t total_len;
} frag_hdr_t;

#define FRAG_HDR_BYTES sizeof(frag_hdr_t)

/* ── Connection state ────────────────────────────────────────────── */
typedef struct {
  int sock;
  struct sockaddr_in peer;
  socklen_t peer_len;

  uint8_t tx_key[32];          /* Directional encryption key */
  uint8_t rx_key[32];          /* Directional decryption key */
  uint32_t tx_seq;
  uint64_t tx_nonce_ctr;
  uint64_t session_id;

  int established;
  replay_window_t replay_win;  /* Sliding replay protection window */
} conn_t;

void conn_init(conn_t *c, int sock);
void conn_destroy(conn_t *c);

/* ── Metrics ─────────────────────────────────────────────────────── */
/*
 * All metrics are tracked locally on each side.
 * Nothing is embedded in the PKT_DATA wire payload.
 */
typedef struct {
  /* Handshake — PQC breakdown */
  double hs_kem_keygen_ms;
  double hs_dsa_keygen_ms;
  double hs_encap_ms;
  double hs_sign_ms;
  double hs_verify_ms;
  double hs_total_ms;

  /* Per-message transport */
  double msg_last_rtt_ms;
  double msg_avg_rtt_ms;
  double msg_min_rtt_ms;
  double msg_max_rtt_ms;
  uint64_t msg_count;
  uint64_t retransmissions;
  uint64_t bytes_sent;
  uint64_t bytes_recv;

  /* AEAD cost accumulators (µs) */
  double total_encrypt_us;
  double total_decrypt_us;
  uint64_t encrypt_count;
  uint64_t decrypt_count;

  /* Jitter (RFC 3550 EWMA) */
  double jitter_ms;
  double prev_rtt_ms;

  /* Timestamps for latency tracking (ns) */
  uint64_t last_send_ns;
  uint64_t prev_recv_ns;
  uint64_t session_start_ns;
} metrics_t;

/* ── Socket creation ─────────────────────────────────────────────── */
int make_server_sock(void);
int make_client_sock(void);

/* ── Send / receive ──────────────────────────────────────────────── */
ssize_t pkt_send(conn_t *c, uint8_t type, const uint8_t *payload,
                 uint16_t payload_len);

ssize_t pkt_recv(conn_t *c, pkt_hdr_t *hdr, uint8_t *payload_out,
                 size_t payload_max, int timeout_us);

int pkt_send_reliable(conn_t *c, uint8_t type, const uint8_t *payload,
                      uint16_t payload_len);

void send_ack(conn_t *c, uint32_t ack_seq);

/* ── Fragmentation & Reassembly API ─────────────────────────────── */
typedef struct {
  uint16_t msg_id;
  uint8_t  orig_type;
  uint8_t  frag_count;
  uint8_t  frag_received;
  uint32_t total_len;
  uint32_t received_bytes;
  uint8_t  bitmap[32]; /* Up to 256 fragments */
  uint8_t *buf;
  uint64_t start_time_ns;
  int active;
} reassembly_ctx_t;

void reassembly_init(reassembly_ctx_t *ctx);
void reassembly_cleanup(reassembly_ctx_t *ctx);
int reassembly_feed_frag(reassembly_ctx_t *ctx, const frag_hdr_t *fhdr,
                         const uint8_t *frag_data);

int pkt_send_fragmented(conn_t *c, uint8_t orig_type, const uint8_t *payload,
                        uint32_t payload_len, uint16_t max_frag_sz);


/* ── Data send / receive ─────────────────────────────────────────── */
/*
 * data_send():
 *   Encrypts msg with AEAD, sends NONCE|TAG|CIPHERTEXT.
 *   Measures encrypt cost into m->total_encrypt_us locally.
 *   Nothing extra is embedded in the packet.
 */
int data_send(conn_t *c, metrics_t *m, const uint8_t *msg, uint32_t msg_len);

ssize_t data_recv(conn_t *c, uint8_t *out, size_t out_max);

/* ── Metrics ─────────────────────────────────────────────────────── */
void metrics_print(const metrics_t *m);
void metrics_update_rtt(metrics_t *m, uint64_t recv_ns);

/* ── Timing ──────────────────────────────────────────────────────── */
double now_ms(void);
uint64_t now_ns(void);
void now_hms(char *buf, int sz);

#endif /* TRANSPORT_H */
