/*
 * transport.c — Hardened Low-latency UDP transport for NEXQOR / QRYPTONEX
 *
 * Implements:
 *  - Directional traffic keys (tx_key and rx_key separation)
 *  - Authenticated Associated Data (AAD) binding wire header (pkt_hdr_t, 15 bytes)
 *  - Nonce exhaustion protection and monotonic tracking
 *  - Sliding replay window verification (pre-auth check, post-auth commit)
 *  - Bounded application-level reliability and telemetry acknowledgements
 *  - Application-level fragmentation and reassembly for oversized PQC messages
 *  - Local monotonic metric tracking
 */

#define _POSIX_C_SOURCE 200809L

#include "transport.h"
#include "crypto/aead.h"

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <net/if.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

/* ── Timing ──────────────────────────────────────────────────────── */
double now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec * 1e3 + (double)ts.tv_nsec * 1e-6;
}

uint64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

void now_hms(char *buf, int sz) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  struct tm *t = localtime(&ts.tv_sec);
  if (t)
    snprintf(buf, (size_t)sz, "%02d:%02d:%02d.%03ld", t->tm_hour, t->tm_min,
             t->tm_sec, ts.tv_nsec / 1000000L);
  else
    snprintf(buf, (size_t)sz, "??:??:??.???");
}

/* ── Socket helpers ──────────────────────────────────────────────── */
static int configure_sock(int s) {
  int buf = 16 * 1024 * 1024;
  setsockopt(s, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
  setsockopt(s, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf));

  int tos = 0x18; /* DSCP AF21: low-delay + throughput */
  setsockopt(s, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));

  int one = 1;
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  int prio = 6; /* highest unprivileged egress priority */
  setsockopt(s, SOL_SOCKET, SO_PRIORITY, &prio, sizeof(prio));

  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = 50000; /* 50 ms default timeout */
  setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  return 0;
}

int make_server_sock(void) {
  int s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s < 0) {
    perror("socket");
    return -1;
  }
  configure_sock(s);

  struct sockaddr_in addr = {0};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(SERVER_PORT);
  addr.sin_addr.s_addr = INADDR_ANY;

  if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("bind");
    close(s);
    return -1;
  }
  return s;
}

int make_client_sock(void) {
  int s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s < 0) {
    perror("socket");
    return -1;
  }
  configure_sock(s);
  return s;
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

/* ── Counter nonce with strict exhaustion check ──────────────────── */
static int make_nonce(uint8_t nonce[12], uint64_t ctr) {
  if (ctr >= 0xFFFFFFFFFFFFFF00ULL) {
    fprintf(stderr, "[transport] CRITICAL: Nonce counter exhaustion! Rejecting to prevent reuse.\n");
    return -1;
  }
  uint64_t le_ctr = htole64(ctr);
  memcpy(nonce, &le_ctr, 8);
  memset(nonce + 8, 0, 4);
  return 0;
}

/* ── pkt_send ────────────────────────────────────────────────────── */
ssize_t pkt_send(conn_t *c, uint8_t type, const uint8_t *payload,
                 uint16_t payload_len) {
  pkt_hdr_t hdr;
  hdr.seq = htonl(c->tx_seq++);
  hdr.type = type;
  hdr.len = htons(payload_len);
  hdr.session_id = htobe64(c->session_id);

  struct iovec iov[2];
  iov[0].iov_base = &hdr;
  iov[0].iov_len = PKT_HDR_BYTES;
  iov[1].iov_base = (void *)payload;
  iov[1].iov_len = payload_len;

  struct msghdr msg = {0};
  msg.msg_name = &c->peer;
  msg.msg_namelen = c->peer_len;
  msg.msg_iov = iov;
  msg.msg_iovlen = (payload_len > 0) ? 2 : 1;

  return sendmsg(c->sock, &msg, 0);
}

/* ── pkt_recv ────────────────────────────────────────────────────── */
ssize_t pkt_recv(conn_t *c, pkt_hdr_t *hdr, uint8_t *payload_out,
                 size_t payload_max, int timeout_us) {
  uint8_t raw[PKT_BUF_MAX];
  struct sockaddr_in from = {0};
  socklen_t from_len = sizeof(from);
  ssize_t n = -1;

  if (timeout_us > 0) {
    struct pollfd pfd;
    pfd.fd = c->sock;
    pfd.events = POLLIN;
    int prc = poll(&pfd, 1, timeout_us / 1000);
    if (prc <= 0) return -1;
  }

  n = recvfrom(c->sock, raw, sizeof(raw), 0, (struct sockaddr *)&from,
               &from_len);

  if (n < 0)
    return -1;
  if (n < (ssize_t)PKT_HDR_BYTES)
    return -1;

  memcpy(hdr, raw, PKT_HDR_BYTES);
  hdr->seq = ntohl(hdr->seq);
  hdr->len = ntohs(hdr->len);
  hdr->session_id = be64toh(hdr->session_id);

  c->peer = from;
  c->peer_len = from_len;

  ssize_t payload_len = n - PKT_HDR_BYTES;
  if (payload_len < 0)
    payload_len = 0;
  if ((size_t)payload_len > payload_max)
    payload_len = (ssize_t)payload_max;
  if (payload_len > 0 && payload_out)
    memcpy(payload_out, raw + PKT_HDR_BYTES, (size_t)payload_len);

  return payload_len;
}

/* ── send_ack ────────────────────────────────────────────────────── */
void send_ack(conn_t *c, uint32_t ack_seq) {
  uint8_t pl[4];
  pl[0] = (ack_seq >> 24) & 0xFF;
  pl[1] = (ack_seq >> 16) & 0xFF;
  pl[2] = (ack_seq >> 8) & 0xFF;
  pl[3] = ack_seq & 0xFF;
  pkt_send(c, PKT_ACK, pl, 4);
}

/* ── pkt_send_reliable ───────────────────────────────────────────── */
int pkt_send_reliable(conn_t *c, uint8_t type, const uint8_t *payload,
                       uint16_t payload_len) {
  uint32_t our_seq = c->tx_seq;

  for (int attempt = 0; attempt < RETX_MAX; attempt++) {
    if (attempt > 0) {
      c->tx_seq = our_seq;
      /* Desynchronize retry waves with jitter */
      usleep((useconds_t)(5000 + (rand() % 25000)));
    }

    ssize_t sent = pkt_send(c, type, payload, payload_len);
    if (sent < 0) {
      fprintf(stderr, "[transport] pkt_send attempt %d failed: %s (errno=%d)\n",
              attempt + 1, strerror(errno), errno);
      usleep(1000);
      continue;
    }

    pkt_hdr_t hdr;
    uint8_t buf[256];
    double deadline = now_ms() + ACK_TIMEOUT_US / 1000.0;

    for (;;) {
      int remaining_us = (int)((deadline - now_ms()) * 1000.0);
      if (remaining_us <= 0)
        break;

      struct timeval tv;
      tv.tv_sec = remaining_us / 1000000;
      tv.tv_usec = remaining_us % 1000000;
      if (tv.tv_sec == 0 && tv.tv_usec < 1000)
        tv.tv_usec = 1000;
      setsockopt(c->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

      ssize_t n = pkt_recv(c, &hdr, buf, sizeof(buf), remaining_us);
      if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          break;
        }
        continue;
      }

      if (hdr.type == PKT_DISCONNECT) {
        return -2;
      }

      if (hdr.type == PKT_ACK && n >= 4) {
        uint32_t acked = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
                         ((uint32_t)buf[2] << 8) | (uint32_t)buf[3];
        if (acked == our_seq)
          return 0;
      }
    }
  }
  return -1;
}

/* ── data_send ───────────────────────────────────────────────────── */
/*
 * Directional encryption with ChaCha20-Poly1305.
 * Uses c->tx_key (client_write_key for client, server_write_key for server).
 * Binds wire header (pkt_hdr_t, 15 bytes canonical) as Authenticated Associated Data (AAD).
 */
int data_send(conn_t *c, metrics_t *m, const uint8_t *msg, uint32_t msg_len) {
  uint32_t offset = 0;
  while (offset < msg_len) {
    uint32_t chunk = msg_len - offset;
    if (chunk > DATA_CHUNK_MAX)
      chunk = DATA_CHUNK_MAX;

    /* payload = NONCE(12) | TAG(16) | CIPHERTEXT(chunk) */
    uint8_t pkt[12 + 16 + DATA_CHUNK_MAX];

    uint8_t nonce[12];
    if (make_nonce(nonce, c->tx_nonce_ctr++) != 0) {
      return -1;
    }
    memcpy(pkt, nonce, 12);

    /* Construct canonical wire header as AAD */
    uint32_t current_seq = c->tx_seq;
    uint16_t pkt_len = (uint16_t)(12 + 16 + chunk);

    pkt_hdr_t wire_hdr;
    wire_hdr.seq = htonl(current_seq);
    wire_hdr.type = PKT_DATA;
    wire_hdr.len = htons(pkt_len);
    wire_hdr.session_id = htobe64(c->session_id);

    /* Measure AEAD encrypt cost locally */
    double enc_t0 = now_ms();
    int ct_len = aead_encrypt(msg + offset, (int)chunk,
                              (const uint8_t *)&wire_hdr, PKT_HDR_BYTES,
                              c->tx_key, nonce,
                              pkt + 12 + 16, /* ciphertext */
                              pkt + 12);     /* tag        */
    double enc_us = (now_ms() - enc_t0) * 1000.0;

    if (ct_len < 0)
      return -1;

    if (m) {
      m->total_encrypt_us += enc_us;
      m->encrypt_count++;
      m->msg_count++;
      m->bytes_sent += (uint64_t)(PKT_HDR_BYTES + 12 + 16 + (uint32_t)ct_len);
      m->last_send_ns = now_ns();
    }

    ssize_t sent = pkt_send(c, PKT_DATA, pkt, pkt_len);
    if (sent < 0)
      return -1;

    offset += chunk;
  }
  return 0;
}

/* ── data_recv ───────────────────────────────────────────────────── */
/*
 * Directional decryption with ChaCha20-Poly1305.
 * Uses c->rx_key.
 * Verifies wire header (pkt_hdr_t, 15 bytes canonical) as AAD.
 * Evaluates sliding replay window: pre-auth check, post-auth commit.
 * Suppresses duplicate application delivery while re-acknowledging duplicate packets.
 */
ssize_t data_recv(conn_t *c, uint8_t *out, size_t out_max) {
  for (;;) {
    pkt_hdr_t hdr;
    uint8_t raw[12 + 16 + DATA_CHUNK_MAX + 64];

    ssize_t n = pkt_recv(c, &hdr, raw, sizeof(raw), 0);
    if (n < 0)
      return -1;
    if (hdr.type != PKT_DATA)
      continue;
    if (n < (12 + 16))
      continue;

    /* Verify session ID if established */
    if (c->session_id != 0 && hdr.session_id != 0 && hdr.session_id != c->session_id) {
      fprintf(stderr, "[rx] Session ID mismatch: got %llu, expected %llu — drop\n",
              (unsigned long long)hdr.session_id, (unsigned long long)c->session_id);
      continue;
    }

    /* Clean layout: NONCE(12) | TAG(16) | CIPHERTEXT(n) */
    const uint8_t *nonce = raw;
    const uint8_t *tag = raw + 12;
    const uint8_t *ct = raw + 28;
    int ct_len = (int)n - 28;
    if (ct_len <= 0 || ct_len > DATA_CHUNK_MAX || (size_t)ct_len > out_max)
      continue;

    /* Construct canonical wire header as AAD */
    pkt_hdr_t wire_hdr;
    wire_hdr.seq = htonl(hdr.seq);
    wire_hdr.type = hdr.type;
    wire_hdr.len = htons(hdr.len);
    wire_hdr.session_id = htobe64(hdr.session_id);

    /* Pre-auth replay window check */
    int rcheck = replay_window_check(&c->replay_win, hdr.seq);
    if (rcheck != 0) {
      /* Duplicate or out-of-window. Check auth before re-acking */
      uint8_t dummy_pt[DATA_CHUNK_MAX];
      int auth_rc = aead_decrypt(ct, ct_len, (const uint8_t *)&wire_hdr, PKT_HDR_BYTES,
                                 c->rx_key, nonce, tag, dummy_pt);
      if (auth_rc >= 0) {
        send_ack(c, hdr.seq);
      }
      continue;
    }

    /* Decrypt and authenticate associated data */
    int pt_len = aead_decrypt(ct, ct_len, (const uint8_t *)&wire_hdr, PKT_HDR_BYTES,
                              c->rx_key, nonce, tag, out);
    if (pt_len < 0) {
      fprintf(stderr, "[rx] AEAD auth failure (tampered ciphertext or header AAD) — drop\n");
      continue;
    }

    /* Post-auth replay commit */
    replay_window_update(&c->replay_win, hdr.seq);

    /* Send ACK */
    send_ack(c, hdr.seq);

    return (ssize_t)pt_len;
  }
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

int reassembly_feed_frag(reassembly_ctx_t *ctx, const frag_hdr_t *fhdr,
                         const uint8_t *frag_data) {
  if (!ctx || !fhdr || !frag_data) return -1;

  uint16_t msg_id = ntohs(fhdr->msg_id);
  uint8_t orig_type = fhdr->orig_type;
  uint8_t frag_idx = fhdr->frag_idx;
  uint8_t frag_total = fhdr->frag_total;
  uint16_t frag_len = ntohs(fhdr->frag_len);
  uint32_t total_len = ntohl(fhdr->total_len);

  /* Bounded sanity checks: max 64KB message, max 256 fragments */
  if (total_len == 0 || total_len > 65536 || frag_total == 0 || frag_idx >= frag_total) {
    return -1;
  }

  /* Reset if a new message arrives */
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

  /* Check if fragment already received */
  int byte_idx = frag_idx / 8;
  int bit_idx = frag_idx % 8;
  if (ctx->bitmap[byte_idx] & (1 << bit_idx)) {
    return 0; /* Duplicate fragment */
  }

  /* Bounds check for fragment placement */
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

  return 0; /* Pending more fragments */
}

int pkt_send_fragmented(conn_t *c, uint8_t orig_type, const uint8_t *payload,
                        uint32_t payload_len, uint16_t max_frag_sz) {
  if (!c || !payload || payload_len == 0) return -1;
  if (max_frag_sz == 0 || max_frag_sz > FRAG_PAYLOAD_MAX)
    max_frag_sz = FRAG_PAYLOAD_MAX;

  static uint16_t s_msg_id = 1;
  uint16_t msg_id = s_msg_id++;
  uint8_t total_frags = (uint8_t)((payload_len + max_frag_sz - 1) / max_frag_sz);

  uint8_t buf[FRAG_HDR_BYTES + FRAG_PAYLOAD_MAX];
  uint32_t offset = 0;

  for (uint8_t i = 0; i < total_frags; i++) {
    uint16_t flen = (uint16_t)((payload_len - offset < max_frag_sz) ? (payload_len - offset) : max_frag_sz);

    frag_hdr_t *fhdr = (frag_hdr_t *)buf;
    fhdr->msg_id = htons(msg_id);
    fhdr->orig_type = orig_type;
    fhdr->frag_idx = i;
    fhdr->frag_total = total_frags;
    fhdr->frag_len = htons(flen);
    fhdr->total_len = htonl(payload_len);

    memcpy(buf + FRAG_HDR_BYTES, payload + offset, flen);

    ssize_t sent = pkt_send(c, PKT_FRAG, buf, FRAG_HDR_BYTES + flen);
    if (sent < 0) return -1;

    offset += flen;
  }

  return 0;
}

/* ── metrics_update_rtt ──────────────────────────────────────────── */
void metrics_update_rtt(metrics_t *m, uint64_t recv_ns) {
  if (m->prev_recv_ns == 0) {
    m->prev_recv_ns = recv_ns;
    return;
  }

  double ia_ms = (double)(recv_ns - m->prev_recv_ns) / 1e6;
  m->prev_recv_ns = recv_ns;
  if (ia_ms < 0.0)
    ia_ms = 0.0;

  m->msg_last_rtt_ms = ia_ms;

  uint64_t n = m->decrypt_count;
  if (n == 0)
    n = 1;
  m->msg_avg_rtt_ms = (m->msg_avg_rtt_ms * (double)(n - 1) + ia_ms) / (double)n;

  if (ia_ms < m->msg_min_rtt_ms)
    m->msg_min_rtt_ms = ia_ms;
  if (ia_ms > m->msg_max_rtt_ms)
    m->msg_max_rtt_ms = ia_ms;

  double diff = ia_ms - m->jitter_ms;
  if (diff < 0.0)
    diff = -diff;
  m->jitter_ms += (diff - m->jitter_ms) / 16.0;
}

/* ── metrics_print ───────────────────────────────────────────────── */
void metrics_print(const metrics_t *m) {
  char ts[16];
  now_hms(ts, sizeof(ts));

  double elapsed_s = 0.0;
  if (m->session_start_ns > 0)
    elapsed_s = (double)(now_ns() - m->session_start_ns) / 1e9;

  printf("\n╔══════════════════════════════════════════════╗\n");
  printf("║     SESSION METRICS  [%s]          ║\n", ts);
  printf("╠══════════════════════════════════════════════╣\n");

  printf("║  PQC HANDSHAKE BREAKDOWN                     ║\n");
  printf("║  ─────────────────────────────────────────── ║\n");
  printf("║  KEM keygen        : %8.3f ms             ║\n",
         m->hs_kem_keygen_ms);
  printf("║  DSA keygen        : %8.3f ms             ║\n",
         m->hs_dsa_keygen_ms);
  printf("║  KEM Encap/Decap   : %8.3f ms             ║\n", m->hs_encap_ms);
  printf("║  DSA Sign          : %8.3f ms             ║\n", m->hs_sign_ms);
  printf("║  DSA Verify        : %8.3f ms             ║\n", m->hs_verify_ms);
  printf("║  Handshake Total   : %8.3f ms  %s        ║\n", m->hs_total_ms,
         m->hs_total_ms <= 1.0 ? "✓ <1ms" : "⚠ >1ms");
  printf("║                                              ║\n");

  printf("║  AEAD (ChaCha20-Poly1305 + AAD)              ║\n");
  printf("║  ─────────────────────────────────────────── ║\n");
  if (m->encrypt_count > 0)
    printf("║  Avg encrypt       : %8.2f µs             ║\n",
           m->total_encrypt_us / (double)m->encrypt_count);
  if (m->decrypt_count > 0)
    printf("║  Avg decrypt       : %8.2f µs             ║\n",
           m->total_decrypt_us / (double)m->decrypt_count);
  printf("║                                              ║\n");

  printf("║  NETWORK                                     ║\n");
  printf("║  ─────────────────────────────────────────── ║\n");
  printf("║  Messages sent     : %8llu                ║\n",
         (unsigned long long)m->msg_count);
  printf("║  Bytes sent        : %8llu B              ║\n",
         (unsigned long long)m->bytes_sent);
  printf("║  Bytes received    : %8llu B              ║\n",
         (unsigned long long)m->bytes_recv);

  if (elapsed_s > 0.01) {
    double tx_kbps = (double)m->bytes_sent * 8.0 / elapsed_s / 1000.0;
    double rx_kbps = (double)m->bytes_recv * 8.0 / elapsed_s / 1000.0;
    printf("║  TX bandwidth      : %8.2f kbps           ║\n", tx_kbps);
    printf("║  RX bandwidth      : %8.2f kbps           ║\n", rx_kbps);
    printf("║  Session duration  : %8.3f s              ║\n", elapsed_s);
  }

  printf("║  Retransmissions   : %8llu                ║\n",
         (unsigned long long)m->retransmissions);

  if (m->decrypt_count > 1) {
    double ia_min = (m->msg_min_rtt_ms >= 1e14) ? 0.0 : m->msg_min_rtt_ms;
    printf("║  Inter-arrival avg : %7.3f ms              ║\n",
           m->msg_avg_rtt_ms);
    printf("║  Inter-arrival min : %7.3f ms              ║\n", ia_min);
    printf("║  Inter-arrival max : %7.3f ms              ║\n",
           m->msg_max_rtt_ms);
    printf("║  Jitter (RFC3550)  : %7.3f ms              ║\n", m->jitter_ms);
  } else {
    printf("║  Jitter            :   N/A (need 2+ msgs)  ║\n");
  }
  printf("╚══════════════════════════════════════════════╝\n\n");
}

/* ── Dynamic Server Resolution & Auto-Discovery ──────────────────── */
int server_publish_endpoints(char *lan_ip, size_t lan_len,
                             char *vpn_ip, size_t vpn_len) {
  if (lan_ip && lan_len > 0)
    snprintf(lan_ip, lan_len, "None");
  if (vpn_ip && vpn_len > 0)
    snprintf(vpn_ip, vpn_len, "None");

  struct ifaddrs *ifaddr = NULL;
  if (getifaddrs(&ifaddr) == -1) {
    return -1;
  }

  char best_lan[INET_ADDRSTRLEN] = "";
  char best_vpn[INET_ADDRSTRLEN] = "";

  for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
      continue;

    /* Check if interface is UP */
    if (!(ifa->ifa_flags & IFF_UP))
      continue;

    /* Skip loopback */
    if (ifa->ifa_flags & IFF_LOOPBACK)
      continue;

    struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
    char ip_str[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str)))
      continue;

    /* Detect Tailscale / Wireguard / VPN interfaces or CGNAT 100.64.0.0/10 */
    int is_vpn = 0;
    if (strncmp(ifa->ifa_name, "tailscale", 9) == 0 ||
        strncmp(ifa->ifa_name, "ts", 2) == 0 ||
        strncmp(ifa->ifa_name, "wg", 2) == 0 ||
        strncmp(ifa->ifa_name, "tun", 3) == 0 ||
        strncmp(ip_str, "100.", 4) == 0) {
      is_vpn = 1;
    }

    if (is_vpn) {
      if (best_vpn[0] == '\0') {
        strncpy(best_vpn, ip_str, sizeof(best_vpn) - 1);
      }
    } else {
      /* Prioritize Ethernet/Wi-Fi or standard private subnets */
      if (best_lan[0] == '\0' || strncmp(ifa->ifa_name, "wl", 2) == 0 ||
          strncmp(ifa->ifa_name, "eth", 3) == 0 || strncmp(ifa->ifa_name, "en", 2) == 0) {
        strncpy(best_lan, ip_str, sizeof(best_lan) - 1);
      }
    }
  }

  freeifaddrs(ifaddr);

  if (lan_ip && lan_len > 0 && best_lan[0] != '\0') {
    snprintf(lan_ip, lan_len, "%s", best_lan);
  }
  if (vpn_ip && vpn_len > 0 && best_vpn[0] != '\0') {
    snprintf(vpn_ip, vpn_len, "%s", best_vpn);
  }

  /* Publish to local discovery file */
  FILE *f = fopen(SERVER_DISCOVERY_FILE, "w");
  if (f) {
    fprintf(f, "# NEXQOR / QRYPTONEX Active Server Endpoints\n");
    fprintf(f, "PORT=%d\n", SERVER_PORT);
    fprintf(f, "LOCAL=127.0.0.1\n");
    if (best_lan[0] != '\0')
      fprintf(f, "LAN=%s\n", best_lan);
    if (best_vpn[0] != '\0')
      fprintf(f, "VPN=%s\n", best_vpn);
    fclose(f);
  }

  /* Publish preferred IP to system temporary discovery file */
  const char *primary_ip = (best_lan[0] != '\0') ? best_lan :
                           (best_vpn[0] != '\0') ? best_vpn : DEFAULT_SERVER_ADDR;
  FILE *ftmp = fopen(SERVER_DISCOVERY_SYS_FILE, "w");
  if (ftmp) {
    fprintf(ftmp, "%s\n", primary_ip);
    fclose(ftmp);
  }

  return 0;
}

int resolve_server_address(const char *input_target, struct sockaddr_in *out_peer,
                           char *resolved_ip_str, size_t str_len) {
  char candidate[128] = "";

  /* Priority 1: User explicitly supplied argument (IP, hostname, Tailscale MagicDNS) */
  if (input_target && input_target[0] != '\0') {
    snprintf(candidate, sizeof(candidate), "%s", input_target);
  }

  /* Priority 2: Environment variables (PQC_SERVER_IP, SERVER_IP, NEXQOR_SERVER) */
  if (candidate[0] == '\0') {
    const char *env_ip = getenv(ENV_SERVER_IP);
    if (!env_ip || env_ip[0] == '\0') env_ip = getenv("SERVER_IP");
    if (!env_ip || env_ip[0] == '\0') env_ip = getenv("NEXQOR_SERVER");
    if (env_ip && env_ip[0] != '\0') {
      snprintf(candidate, sizeof(candidate), "%s", env_ip);
    }
  }

  /* Priority 3: Local system discovery file (/tmp/nexqor_server.ip or ./server_endpoint.info) */
  if (candidate[0] == '\0') {
    FILE *f = fopen(SERVER_DISCOVERY_SYS_FILE, "r");
    if (f) {
      char line[128];
      if (fgets(line, sizeof(line), f)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        char *cr = strchr(line, '\r');
        if (cr) *cr = '\0';
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (strlen(p) > 0) {
          snprintf(candidate, sizeof(candidate), "%s", p);
        }
      }
      fclose(f);
    }
  }

  if (candidate[0] == '\0') {
    FILE *f = fopen(SERVER_DISCOVERY_FILE, "r");
    if (f) {
      char line[256];
      while (fgets(line, sizeof(line), f)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        if (strncmp(line, "LAN=", 4) == 0 && strlen(line + 4) > 0) {
          snprintf(candidate, sizeof(candidate), "%s", line + 4);
          break;
        } else if (strncmp(line, "VPN=", 4) == 0 && strlen(line + 4) > 0) {
          snprintf(candidate, sizeof(candidate), "%s", line + 4);
        }
      }
      fclose(f);
    }
  }

  /* Priority 4: Dynamic LAN Broadcast Discovery Probe (UDP broadcast to port 9877) */
  if (candidate[0] == '\0') {
    int bsock = socket(AF_INET, SOCK_DGRAM, 0);
    if (bsock >= 0) {
      int bcast_enable = 1;
      setsockopt(bsock, SOL_SOCKET, SO_BROADCAST, &bcast_enable, sizeof(bcast_enable));

      /* Fast probe timeout: 200 ms */
      struct timeval tv;
      tv.tv_sec = 0;
      tv.tv_usec = 200000;
      setsockopt(bsock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

      struct sockaddr_in baddr;
      memset(&baddr, 0, sizeof(baddr));
      baddr.sin_family = AF_INET;
      baddr.sin_port = htons(SERVER_PORT);
      baddr.sin_addr.s_addr = htonl(INADDR_BROADCAST);

      pkt_hdr_t probe;
      memset(&probe, 0, sizeof(probe));
      probe.type = PKT_DISCOVERY_PROBE;
      probe.seq = htonl(1);
      probe.len = 0;
      probe.session_id = 0;

      sendto(bsock, &probe, sizeof(probe), 0, (struct sockaddr *)&baddr, sizeof(baddr));

      /* Also broadcast on specific subnet broadcast addresses if found */
      struct ifaddrs *iflist = NULL;
      if (getifaddrs(&iflist) == 0) {
        for (struct ifaddrs *ifa = iflist; ifa; ifa = ifa->ifa_next) {
          if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET &&
              (ifa->ifa_flags & IFF_UP) && !(ifa->ifa_flags & IFF_LOOPBACK) &&
              (ifa->ifa_flags & IFF_BROADCAST) && ifa->ifa_broadaddr) {
            struct sockaddr_in *sin_b = (struct sockaddr_in *)ifa->ifa_broadaddr;
            sin_b->sin_port = htons(SERVER_PORT);
            sendto(bsock, &probe, sizeof(probe), 0, (struct sockaddr *)sin_b, sizeof(*sin_b));
          }
        }
        freeifaddrs(iflist);
      }

      uint8_t rbuf[128];
      struct sockaddr_in from;
      socklen_t fromlen = sizeof(from);
      ssize_t n = recvfrom(bsock, rbuf, sizeof(rbuf), 0, (struct sockaddr *)&from, &fromlen);
      if (n >= (ssize_t)PKT_HDR_BYTES) {
        pkt_hdr_t rhdr;
        memcpy(&rhdr, rbuf, sizeof(rhdr));
        if (rhdr.type == PKT_DISCOVERY_OFFER) {
          char discovered_ip[INET_ADDRSTRLEN];
          if (inet_ntop(AF_INET, &from.sin_addr, discovered_ip, sizeof(discovered_ip))) {
            snprintf(candidate, sizeof(candidate), "%s", discovered_ip);
          }
        }
      }
      close(bsock);
    }
  }

  /* Priority 5: Default Fallback to Loopback (127.0.0.1) */
  if (candidate[0] == '\0') {
    snprintf(candidate, sizeof(candidate), "%s", DEFAULT_SERVER_ADDR);
  }

  /* Resolve candidate string via getaddrinfo (handles IPv4 numeric, hostname, and Tailscale DNS) */
  struct addrinfo hints, *res = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;

  int ret = getaddrinfo(candidate, NULL, &hints, &res);
  if (ret != 0 || res == NULL) {
    /* Fallback direct inet_pton check */
    struct in_addr direct_addr;
    if (inet_pton(AF_INET, candidate, &direct_addr) != 1) {
      return -1;
    }
    if (out_peer) {
      memset(out_peer, 0, sizeof(*out_peer));
      out_peer->sin_family = AF_INET;
      out_peer->sin_port = htons(SERVER_PORT);
      out_peer->sin_addr = direct_addr;
    }
    if (resolved_ip_str && str_len > 0) {
      snprintf(resolved_ip_str, str_len, "%s", candidate);
    }
    return 0;
  }

  struct sockaddr_in *sin_res = (struct sockaddr_in *)res->ai_addr;
  if (out_peer) {
    memset(out_peer, 0, sizeof(*out_peer));
    out_peer->sin_family = AF_INET;
    out_peer->sin_port = htons(SERVER_PORT);
    out_peer->sin_addr = sin_res->sin_addr;
  }
  if (resolved_ip_str && str_len > 0) {
    inet_ntop(AF_INET, &sin_res->sin_addr, resolved_ip_str, (socklen_t)str_len);
  }

  freeaddrinfo(res);
  return 0;
}
