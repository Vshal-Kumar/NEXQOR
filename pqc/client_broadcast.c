/*
 * client_broadcast.c — Continuous IoT Sensor Telemetry Broadcast Client
 *
 * Designed for embedded IoT nodes (ESP32, Raspberry Pi, ARM64/ARM32, x86_64)
 * communicating with NEXQOR / QRYPTONEX Post-Quantum Server Core.
 *
 * Features:
 *   1. Establishes post-quantum secure session via 4-way handshake (ML-KEM-768 + ML-DSA-65).
 *   2. In-band Trust-On-First-Use (TOFU) server identity verification.
 *   3. Derives directional traffic keys via domain-separated SHAKE256.
 *   4. Streams continuous, authenticated IoT sensor telemetry (temperature, humidity,
 *      pressure, battery voltage, 3-axis accelerometer, device status, sequence, uptime).
 *   5. Encrypts every telemetry datagram using ChaCha20-Poly1305 with canonical 15-byte
 *      wire header as Associated Authenticated Data (AAD).
 *   6. Background RX thread receives ACKs and echoes, tracking live RTT, packet loss, and jitter.
 *   7. Configurable broadcast interval (e.g. 100ms, 500ms, 1000ms) and device ID.
 *   8. Clean shutdown on Ctrl+C (SIGINT/SIGTERM) with final performance telemetry summary.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <math.h>

#include "transport.h"
#include "crypto/aead.h"
#include "crypto/trust_store.h"
#include "wrappers/kem_wrapper.h"
#include "wrappers/dsa_wrapper.h"

#include <openssl/rand.h>
#include <openssl/evp.h>

static int shake256_hash(uint8_t out[64], const uint8_t *in, size_t in_len) {
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) return -1;
  if (EVP_DigestInit_ex(ctx, EVP_shake256(), NULL) != 1) {
    EVP_MD_CTX_free(ctx);
    return -1;
  }
  if (EVP_DigestUpdate(ctx, in, in_len) != 1) {
    EVP_MD_CTX_free(ctx);
    return -1;
  }
  if (EVP_DigestFinalXOF(ctx, out, 64) != 1) {
    EVP_MD_CTX_free(ctx);
    return -1;
  }
  EVP_MD_CTX_free(ctx);
  return 0;
}

/* ── Key Material ────────────────────────────────────────────────── */
typedef struct {
  uint8_t kem_pk[KEM_PK_BYTES];
  uint8_t kem_sk[KEM_SK_BYTES];
  uint8_t dsa_pk[DSA_PK_BYTES];
  uint8_t dsa_sk[DSA_SK_BYTES];
  double  kem_keygen_ms;
  double  dsa_keygen_ms;
} keygen_result_t;

static keygen_result_t g_keys;
static volatile int    g_stop = 0;
static void on_signal(int s) { (void)s; g_stop = 1; }

/* ── Recv Helper (handshake only) ────────────────────────────────── */
static ssize_t recv_type(conn_t *c, uint8_t want_type,
                         uint8_t *payload, size_t payload_max) {
  pkt_hdr_t hdr;
  for (;;) {
    ssize_t n = pkt_recv(c, &hdr, payload, payload_max, 0);
    if (n < 0) return -1;
    if (hdr.type == PKT_DISCONNECT) {
      fprintf(stderr, "\n[broadcast] Server disconnected during handshake.\n");
      exit(1);
    }
    if (hdr.type == want_type) {
      send_ack(c, hdr.seq);
      return n;
    }
    if (hdr.type != PKT_ACK && hdr.type != PKT_DATA) {
      send_ack(c, hdr.seq);
    }
  }
}

/* ── Background RX Thread (Telemetry ACKs & Echoes) ──────────────── */
typedef struct {
  conn_t       *conn;
  metrics_t    *metrics;
  volatile int  stop;
  uint64_t      echoes_received;
  double        last_rtt_ms;
} broadcast_rx_args_t;

static void *broadcast_rx_thread(void *arg) {
  broadcast_rx_args_t *a = (broadcast_rx_args_t *)arg;
  uint8_t pt[DATA_CHUNK_MAX + 16];

  while (!a->stop && !g_stop) {
    pkt_hdr_t hdr;
    uint8_t raw[12 + 16 + DATA_CHUNK_MAX + 64];
    ssize_t n = pkt_recv(a->conn, &hdr, raw, sizeof(raw), RX_POLL_TIMEOUT_US);
    if (n < 0) continue;

    if (hdr.type == PKT_DISCONNECT) {
      printf("\n\033[1;31m[broadcast] Server signaled disconnection.\033[0m\n");
      g_stop = 1;
      break;
    }

    if (hdr.type != PKT_DATA) continue;
    if (n < 28) continue; /* Must contain at least NONCE(12) + TAG(16) */

    /* Pre-auth replay check */
    if (replay_window_check(&a->conn->replay_win, hdr.seq) != 0) {
      continue;
    }

    uint64_t recv_ns = now_ns();
    const uint8_t *nonce = raw;
    const uint8_t *tag   = raw + 12;
    const uint8_t *ct    = raw + 28;
    int ct_len = (int)n - 28;
    if (ct_len <= 0) continue;

    /* Reconstruct canonical 15-byte wire header as AAD */
    pkt_hdr_t wire_hdr;
    wire_hdr.seq = htonl(hdr.seq);
    wire_hdr.type = hdr.type;
    wire_hdr.len = htons(hdr.len);
    wire_hdr.session_id = htobe64(hdr.session_id);

    /* Decrypt using server_write_key */
    int pt_len = aead_decrypt(ct, ct_len, (const uint8_t *)&wire_hdr, PKT_HDR_BYTES,
                              a->conn->rx_key, nonce, tag, pt);

    if (pt_len <= 0) {
      /* Authentication failure: tampered ciphertext or AAD */
      continue;
    }

    /* Post-auth commit */
    replay_window_update(&a->conn->replay_win, hdr.seq);
    send_ack(a->conn, hdr.seq);

    a->echoes_received++;
    a->metrics->bytes_recv += (uint64_t)(PKT_HDR_BYTES + 28 + ct_len);
    metrics_update_rtt(a->metrics, recv_ns);
    a->last_rtt_ms = a->metrics->msg_last_rtt_ms;
  }
  return NULL;
}

/* ── 4-Way PQC Handshake ─────────────────────────────────────────── */
static int do_handshake(conn_t *c, metrics_t *m, const keygen_result_t *k) {
  double t0, t1;
  double hs_start = now_ms();

  uint8_t srv_dsa_pk[DSA_PK_BYTES];
  uint8_t kem_ct[KEM_CT_BYTES];
  uint8_t shared_secret[KEM_SS_BYTES];
  uint8_t session_id[SESSION_ID_BYTES];
  uint8_t sig[DSA_SIG_BYTES];
  size_t  sig_len = 0;

  m->hs_kem_keygen_ms = k->kem_keygen_ms;
  m->hs_dsa_keygen_ms = k->dsa_keygen_ms;

  /* Generate client nonce */
  uint8_t c_nonce[16];
  if (RAND_bytes(c_nonce, 16) != 1) {
    fprintf(stderr, "[broadcast] Nonce generation failed\n");
    return -1;
  }

  /* Phase 1: Send CLIENT_HELLO */
  uint8_t hello[KEM_PK_BYTES + DSA_PK_BYTES + 16];
  memcpy(hello,                            k->kem_pk, KEM_PK_BYTES);
  memcpy(hello + KEM_PK_BYTES,             k->dsa_pk, DSA_PK_BYTES);
  memcpy(hello + KEM_PK_BYTES + DSA_PK_BYTES, c_nonce, 16);

  if (pkt_send_reliable(c, PKT_CLIENT_HELLO, hello, (uint16_t)sizeof(hello)) != 0) {
    fprintf(stderr, "[broadcast] CLIENT_HELLO send failed\n");
    return -1;
  }

  /* Phase 2: Receive SERVER_HELLO */
  size_t srv_hello_min = DSA_PK_BYTES + KEM_CT_BYTES + SESSION_ID_BYTES + 16 + DSA_SIG_BYTES;
  uint8_t srv_hello[DSA_PK_BYTES + KEM_CT_BYTES + SESSION_ID_BYTES + 16 + DSA_SIG_BYTES + 128];
  ssize_t srv_len = recv_type(c, PKT_SERVER_HELLO, srv_hello, sizeof(srv_hello));
  if (srv_len < (ssize_t)srv_hello_min) {
    fprintf(stderr, "[broadcast] SERVER_HELLO too short\n");
    return -1;
  }

  uint8_t s_nonce[16];
  uint8_t srv_sig[DSA_SIG_BYTES];
  {
    size_t off = 0;
    memcpy(srv_dsa_pk, srv_hello + off, DSA_PK_BYTES);    off += DSA_PK_BYTES;
    memcpy(kem_ct,     srv_hello + off, KEM_CT_BYTES);    off += KEM_CT_BYTES;
    memcpy(session_id, srv_hello + off, SESSION_ID_BYTES); off += SESSION_ID_BYTES;
    memcpy(s_nonce,    srv_hello + off, 16);              off += 16;
    memcpy(srv_sig,    srv_hello + off, DSA_SIG_BYTES);
  }

  /* Verify server identity against trust store (pins server DSA public key with TOFU) */
  if (trust_store_client_verify_server(srv_dsa_pk, "server_identity.pub") != 0) {
    fprintf(stderr, "\033[1;31m[broadcast] CRITICAL: Server public key NOT trusted! Possible MITM attack.\033[0m\n");
    return -1;
  }

  /* Reconstruct and verify server signature */
  size_t tx_len = 16 + 16 + SESSION_ID_BYTES + KEM_PK_BYTES + DSA_PK_BYTES + DSA_PK_BYTES + KEM_CT_BYTES;
  uint8_t *tx = malloc(tx_len);
  if (!tx) return -1;
  size_t tx_off = 0;
  memcpy(tx + tx_off, c_nonce, 16);                   tx_off += 16;
  memcpy(tx + tx_off, s_nonce, 16);                   tx_off += 16;
  memcpy(tx + tx_off, session_id, SESSION_ID_BYTES);  tx_off += SESSION_ID_BYTES;
  memcpy(tx + tx_off, k->kem_pk, KEM_PK_BYTES);       tx_off += KEM_PK_BYTES;
  memcpy(tx + tx_off, k->dsa_pk, DSA_PK_BYTES);       tx_off += DSA_PK_BYTES;
  memcpy(tx + tx_off, srv_dsa_pk, DSA_PK_BYTES);      tx_off += DSA_PK_BYTES;
  memcpy(tx + tx_off, kem_ct, KEM_CT_BYTES);

  uint8_t server_tx_digest[64];
  if (shake256_hash(server_tx_digest, tx, tx_len) != 0) {
    free(tx);
    return -1;
  }

  t0 = now_ms();
  if (dsa_verify(srv_sig, DSA_SIG_BYTES, server_tx_digest, 64, srv_dsa_pk) != 0) {
    fprintf(stderr, "[broadcast] Server signature verification failed\n");
    free(tx);
    return -1;
  }

  /* KEM decapsulate */
  t0 = now_ms();
  if (kem_dec(shared_secret, kem_ct, k->kem_sk) != 0) {
    fprintf(stderr, "[broadcast] KEM decaps failed\n");
    free(tx);
    return -1;
  }
  t1 = now_ms();
  m->hs_encap_ms = t1 - t0;

  uint64_t sid64 = 0;
  for (int i = 0; i < SESSION_ID_BYTES; i++) {
    sid64 = (sid64 << 8) | session_id[i];
  }
  c->session_id = sid64;

  /* Derive distinct directional keys: client_write_key and server_write_key */
  kem_derive_directional_keys(c->tx_key, c->rx_key, shared_secret, c_nonce, s_nonce, sid64);

  /* DSA sign client transcript */
  size_t cl_tx_len = tx_len + DSA_SIG_BYTES;
  uint8_t *cl_tx = malloc(cl_tx_len);
  if (!cl_tx) {
    free(tx);
    return -1;
  }
  memcpy(cl_tx, tx, tx_len);
  memcpy(cl_tx + tx_len, srv_sig, DSA_SIG_BYTES);
  free(tx);

  uint8_t client_tx_digest[64];
  if (shake256_hash(client_tx_digest, cl_tx, cl_tx_len) != 0) {
    free(cl_tx);
    return -1;
  }
  free(cl_tx);

  t0 = now_ms();
  if (dsa_sign(sig, &sig_len, client_tx_digest, 64, k->dsa_sk) != 0) {
    fprintf(stderr, "[broadcast] DSA sign failed\n");
    explicit_bzero(shared_secret, sizeof(shared_secret));
    return -1;
  }
  m->hs_sign_ms = now_ms() - t0;

  /* Phase 3: Send CLIENT_AUTH */
  if (pkt_send_reliable(c, PKT_CLIENT_AUTH, sig, (uint16_t)sig_len) != 0) {
    fprintf(stderr, "[broadcast] CLIENT_AUTH send failed\n");
    explicit_bzero(shared_secret, sizeof(shared_secret));
    return -1;
  }

  c->established = 1;
  explicit_bzero(shared_secret, sizeof(shared_secret));
  explicit_bzero(sig, sizeof(sig));

  m->hs_total_ms = now_ms() - hs_start;

  return 0;
}

/* ── Realistic Dynamic IoT Sensor Simulator ──────────────────────── */
typedef struct {
  char     device_id[32];
  uint64_t seq;
  double   temp_c;
  double   humidity_pct;
  double   pressure_hpa;
  double   v_bat;
  double   accel_x;
  double   accel_y;
  double   accel_z;
  uint32_t uptime_s;
} sensor_state_t;

static void sensor_init(sensor_state_t *s, const char *device_id) {
  strncpy(s->device_id, device_id ? device_id : "ESP32-NODE-01", sizeof(s->device_id) - 1);
  s->seq = 1;
  s->temp_c = 25.5;
  s->humidity_pct = 55.0;
  s->pressure_hpa = 1013.25;
  s->v_bat = 4.12;
  s->accel_x = 0.02;
  s->accel_y = -0.01;
  s->accel_z = 0.98;
  s->uptime_s = 0;
}

static void sensor_sample(sensor_state_t *s, char *out_json, size_t out_max) {
  /* Random-walk fluctuation for realistic dynamic telemetry */
  double r1 = ((double)rand() / (double)RAND_MAX) - 0.5;
  double r2 = ((double)rand() / (double)RAND_MAX) - 0.5;
  double r3 = ((double)rand() / (double)RAND_MAX) - 0.5;

  s->temp_c += r1 * 0.15;
  if (s->temp_c < 18.0) s->temp_c = 18.0;
  if (s->temp_c > 42.0) s->temp_c = 42.0;

  s->humidity_pct += r2 * 0.4;
  if (s->humidity_pct < 30.0) s->humidity_pct = 30.0;
  if (s->humidity_pct > 85.0) s->humidity_pct = 85.0;

  s->pressure_hpa += r3 * 0.05;
  s->v_bat -= 0.0001; /* Slow battery discharge simulation */
  if (s->v_bat < 3.30) s->v_bat = 4.20;

  s->accel_x = 0.01 + (((double)rand() / (double)RAND_MAX) - 0.5) * 0.08;
  s->accel_y = -0.01 + (((double)rand() / (double)RAND_MAX) - 0.5) * 0.08;
  s->accel_z = 0.98 + (((double)rand() / (double)RAND_MAX) - 0.5) * 0.04;

  const char *status = (s->temp_c > 38.0) ? "WARN_HIGH_TEMP" :
                       (s->v_bat < 3.40)  ? "WARN_LOW_BAT"  : "NOMINAL";

  snprintf(out_json, out_max,
           "{\"node\":\"%s\",\"seq\":%llu,\"temp\":%.2f,\"hum\":%.1f,\"press\":%.2f,"
           "\"vbat\":%.2f,\"accel\":[%.2f,%.2f,%.2f],\"status\":\"%s\",\"uptime\":%u}",
           s->device_id,
           (unsigned long long)s->seq,
           s->temp_c,
           s->humidity_pct,
           s->pressure_hpa,
           s->v_bat,
           s->accel_x, s->accel_y, s->accel_z,
           status,
           s->uptime_s);
  s->seq++;
}

/* ════════════════════════════════════════════════════════════════
 * main()
 * ════════════════════════════════════════════════════════════════ */
int main(int argc, char *argv[]) {
  signal(SIGINT,  on_signal);
  signal(SIGTERM, on_signal);
  signal(SIGPIPE, SIG_IGN);

  char server_ip[64] = "";
  const char *target = (argc > 1 && strcmp(argv[1], "auto") != 0) ? argv[1] : NULL;
  int interval_ms = (argc > 2) ? atoi(argv[2]) : 500;
  if (interval_ms < 10) interval_ms = 10;
  const char *device_id = (argc > 3) ? argv[3] : "ESP32-NODE-01";

  int sock = make_client_sock();
  if (sock < 0) return 1;

  conn_t c;
  conn_init(&c, sock);
  c.peer_len = sizeof(c.peer);
  if (resolve_server_address(target, &c.peer, server_ip, sizeof(server_ip)) != 0) {
    fprintf(stderr, "[broadcast] Error: Unable to resolve server address '%s'\n", target ? target : "auto");
    close(sock);
    return 1;
  }
  const char *net_type = "Direct UDP (LAN / Wi-Fi)";
  if (strncmp(server_ip, "127.", 4) == 0 || strcmp(server_ip, "::1") == 0) {
    net_type = "Localhost Loopback (IPC)";
  } else if (strncmp(server_ip, "100.", 4) == 0) {
    net_type = "Tailscale Mesh VPN (Overlay Routing)";
  }

  printf("\n\033[1;36m╔══════════════════════════════════════════════════════════════════════════╗\033[0m\n");
  printf("\033[1;36m║     QRYPTONEX — Post-Quantum IoT Telemetry Broadcaster (NEXQOR)          ║\033[0m\n");
  printf("\033[1;36m╚══════════════════════════════════════════════════════════════════════════╝\033[0m\n");
  printf("  \033[1;33m• Server Target   :\033[0m %s:%d\n", server_ip, SERVER_PORT);
  printf("  \033[1;33m• Network Link    :\033[0m %s\n", net_type);
  printf("  \033[1;33m• Transport Layer :\033[0m Raw UDP Datagrams (Zero External Encryption)\n");
  printf("  \033[1;33m• PQC Stack       :\033[0m ML-KEM-768 + ML-DSA-65 + ChaCha20-Poly1305\n");
  printf("  \033[1;33m• Device ID       :\033[0m %s (Interval: %d ms)\n\n", device_id, interval_ms);

  /* Serial KEM + DSA Key Generation */
  kem_warmup();
  dsa_warmup();
  memset(&g_keys, 0, sizeof(g_keys));

  double t0 = now_ms();
  if (kem_keypair(g_keys.kem_pk, g_keys.kem_sk) != 0) {
    fprintf(stderr, "[broadcast] KEM keygen failed\n");
    close(sock);
    return 1;
  }
  g_keys.kem_keygen_ms = now_ms() - t0;

  t0 = now_ms();
  if (dsa_keypair(g_keys.dsa_pk, g_keys.dsa_sk) != 0) {
    fprintf(stderr, "[broadcast] DSA keygen failed\n");
    close(sock);
    return 1;
  }
  g_keys.dsa_keygen_ms = now_ms() - t0;

  printf("  \033[1;32m[PQC KeyGen]\033[0m ML-KEM-768: %.3f ms (1,184 B PK) | ML-DSA-65: %.3f ms (1,952 B PK)\n",
         g_keys.kem_keygen_ms, g_keys.dsa_keygen_ms);

  /* Serial Handshake */
  metrics_t metrics = {0};
  metrics.msg_min_rtt_ms = 1e15;

  if (do_handshake(&c, &metrics, &g_keys) != 0) {
    fprintf(stderr, "[broadcast] Handshake failed\n");
    close(sock);
    conn_destroy(&c);
    return 1;
  }

  explicit_bzero(g_keys.kem_sk, sizeof(g_keys.kem_sk));
  explicit_bzero(g_keys.dsa_sk, sizeof(g_keys.dsa_sk));

  char ts[16];
  now_hms(ts, sizeof(ts));
  printf("  \033[1;32m[PQC Handshake]\033[0m Completed in %.3f ms (KEM Decap: %.3f ms, DSA Sign: %.3f ms)\n",
         metrics.hs_total_ms, metrics.hs_encap_ms, metrics.hs_sign_ms);
  printf("  \033[1;32m[Session Keys]\033[0m  Client TX Key : %02x%02x%02x%02x%02x%02x%02x%02x... (256-bit)\n",
         c.tx_key[0], c.tx_key[1], c.tx_key[2], c.tx_key[3],
         c.tx_key[4], c.tx_key[5], c.tx_key[6], c.tx_key[7]);
  printf("                  Server RX Key : %02x%02x%02x%02x%02x%02x%02x%02x... (256-bit)\n",
         c.rx_key[0], c.rx_key[1], c.rx_key[2], c.rx_key[3],
         c.rx_key[4], c.rx_key[5], c.rx_key[6], c.rx_key[7]);
  printf("  \033[1;32m[Wire Security]\033[0m Poly1305 15B AAD Header Binding + RFC 6479 Replay Window\n");
  printf("\n\033[1;32m[%s] Connected to %s:%d (Session ID: %016llx)\033[0m\n",
         ts, server_ip, SERVER_PORT, (unsigned long long)c.session_id);
  printf("[%s] Streaming encrypted IoT telemetry from device '%s' (interval: %dms)...\n",
         ts, device_id, interval_ms);

  metrics.session_start_ns = now_ns();

  /* Start background RX thread for ACKs / Echoes */
  broadcast_rx_args_t rx_args = {
    .conn = &c,
    .metrics = &metrics,
    .stop = 0,
    .echoes_received = 0,
    .last_rtt_ms = 0.0
  };
  pthread_t rx_tid;
  pthread_create(&rx_tid, NULL, broadcast_rx_thread, &rx_args);

  /* Initialize Sensor Simulation */
  sensor_state_t sensor;
  sensor_init(&sensor, device_id);

  char json_buf[512];
  uint64_t broadcast_count = 0;
  double broadcast_start_ms = now_ms();

  while (!g_stop) {
    sensor_sample(&sensor, json_buf, sizeof(json_buf));
    uint32_t payload_len = (uint32_t)strlen(json_buf);

    if (data_send(&c, &metrics, (const uint8_t *)json_buf, payload_len) != 0) {
      fprintf(stderr, "\r[broadcast] send failed at packet %llu\n",
              (unsigned long long)broadcast_count);
    }
    broadcast_count++;

    now_hms(ts, sizeof(ts));
    printf("[%s] #%-5llu | Temp: %4.1f°C | Hum: %4.1f%% | Press: %6.1fhPa | Vbat: %4.2fV | Status: %-4.4s\n",
           ts,
           (unsigned long long)broadcast_count,
           sensor.temp_c,
           sensor.humidity_pct,
           sensor.pressure_hpa,
           sensor.v_bat,
           (sensor.temp_c > 38.0) ? "WARN" : "OK");
    fflush(stdout);

    usleep((useconds_t)(interval_ms * 1000));
    sensor.uptime_s = (uint32_t)((now_ms() - broadcast_start_ms) / 1000.0);
  }

  rx_args.stop = 1;
  pthread_join(rx_tid, NULL);

  pkt_send(&c, PKT_DISCONNECT, NULL, 0);
  metrics_print(&metrics);
  close(sock);
  conn_destroy(&c);

  now_hms(ts, sizeof(ts));
  printf("\n[%s] Disconnected. Streamed %llu telemetry packets.\n",
         ts, (unsigned long long)broadcast_count);
  return 0;
}
