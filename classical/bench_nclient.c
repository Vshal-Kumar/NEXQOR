/*
 * classical/bench_nclient.c — N-Client Concurrent Classical IoT Handshake Benchmark
 *
 * Spawns N client threads in a single process, each performing the full
 * 4-way classical handshake (X25519 + Ed25519 + AES-128-CCM + SHA-256 + HKDF-SHA-256)
 * against the running server, optionally followed by M encrypted message round-trips.
 *
 * Usage:
 *   ./bench_nclient              # 64 clients, 10 messages each
 *   ./bench_nclient 128          # 128 clients, handshake only
 *   ./bench_nclient 128 50       # 128 clients, 50 messages each
 *
 * REQUIRES: ./server running in another terminal
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>

#include "crypto/aead.h"
#include "crypto/trust_store.h"
#include "transport.h"
#include "wrappers/kem_wrapper.h"
#include "wrappers/dsa_wrapper.h"
#include "wrappers/hash_wrapper.h"
#include "wrappers/kdf_wrapper.h"
#include "perf_monitor.h"

#include <openssl/rand.h>

#define DEFAULT_NUM_CLIENTS 64
#define DEFAULT_NUM_MSGS 10

static char g_server_ip[64] = "";
static struct sockaddr_in g_server_peer;

/* CPU Tick Stats Structure */
typedef struct {
  unsigned long long user, nice, system, idle, iowait, irq, softirq, steal;
} cpu_ticks_t;

static int get_cpu_ticks(cpu_ticks_t *ticks) {
  FILE *f = fopen("/proc/stat", "r");
  if (!f)
    return -1;
  char buf[256];
  if (fgets(buf, sizeof(buf), f)) {
    int parsed =
        sscanf(buf, "cpu  %llu %llu %llu %llu %llu %llu %llu %llu",
               &ticks->user, &ticks->nice, &ticks->system, &ticks->idle,
               &ticks->iowait, &ticks->irq, &ticks->softirq, &ticks->steal);
    fclose(f);
    return (parsed >= 4) ? 0 : -1;
  }
  fclose(f);
  return -1;
}

static double calculate_cpu_utilization(const cpu_ticks_t *start,
                                        const cpu_ticks_t *end) {
  unsigned long long start_idle = start->idle + start->iowait;
  unsigned long long end_idle = end->idle + end->iowait;

  unsigned long long start_total = start->user + start->nice + start->system +
                                   start->idle + start->iowait + start->irq +
                                   start->softirq + start->steal;
  unsigned long long end_total = end->user + end->nice + end->system +
                                 end->idle + end->iowait + end->irq +
                                 end->softirq + end->steal;

  if (end_total <= start_total)
    return 0.0;
  unsigned long long total_diff = end_total - start_total;
  unsigned long long idle_diff = end_idle - start_idle;
  return 100.0 * (1.0 - ((double)idle_diff / (double)total_diff));
}

/* Timer */
static inline uint64_t ns_now(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static inline uint64_t cpu_now(void) {
  struct timespec ts;
  clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* Per-client result */
typedef struct {
  int success;
  double hs_wall_ms;
  double x25519_keygen_us;
  double ed25519_keygen_us;
  double ed25519_sign_us;
  double ed25519_verify_us;
  double x25519_ecdh_us;
  double hkdf_us;
  int msgs_sent;
  int msgs_recv;
  double msg_min_rtt_ms;
  double msg_max_rtt_ms;
  double msg_avg_rtt_ms;
  uint64_t start_ns;
  uint64_t end_ns;
} client_result_t;

/* Shared state */
static int g_num_clients = DEFAULT_NUM_CLIENTS;
static int g_num_msgs = DEFAULT_NUM_MSGS;
static client_result_t *g_results = NULL;
static pthread_barrier_t g_start_barrier;
static volatile int g_stop = 0;

static void on_signal(int s) {
  (void)s;
  g_stop = 1;
}

static ssize_t recv_type_timeout(conn_t *c, uint8_t want, uint8_t *payload,
                                 size_t max, int timeout_ms) {
  pkt_hdr_t hdr;
  ssize_t result = -1;

  struct timeval tv;
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
  if (tv.tv_sec == 0 && tv.tv_usec < 1000)
    tv.tv_usec = 1000;
  setsockopt(c->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  double deadline = now_ms() + timeout_ms;
  for (;;) {
    double remaining = deadline - now_ms();
    if (remaining <= 0.0)
      break;

    ssize_t n = pkt_recv(c, &hdr, payload, max, 0);
    if (n < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        break;
      }
      continue;
    }

    if (hdr.type == want) {
      result = n;
      break;
    }
  }

  struct timeval tv_def;
  tv_def.tv_sec = 0;
  tv_def.tv_usec = 50000;
  setsockopt(c->sock, SOL_SOCKET, SO_RCVTIMEO, &tv_def, sizeof(tv_def));

  return result;
}

/* Client worker thread */
static void *client_thread(void *arg) {
  int idx = (int)(intptr_t)arg;
  client_result_t *r = &g_results[idx];
  memset(r, 0, sizeof(*r));

  uint8_t c_eph_pk[X25519_PK_BYTES], c_eph_sk[X25519_SK_BYTES];
  uint8_t c_id_pk[ED25519_PK_BYTES], c_id_sk[ED25519_SK_BYTES];

  /* Generate keys */
  uint64_t t0 = cpu_now();
  x25519_generate_keypair(c_eph_pk, c_eph_sk);
  r->x25519_keygen_us = (double)(cpu_now() - t0) / 1000.0;

  t0 = cpu_now();
  ed25519_generate_keypair(c_id_pk, c_id_sk);
  r->ed25519_keygen_us = (double)(cpu_now() - t0) / 1000.0;

  int sock = make_client_sock();
  if (sock < 0)
    return NULL;

  conn_t c;
  conn_init(&c, sock);
  c.peer = g_server_peer;
  c.peer_len = sizeof(c.peer);

  /* Synchronize: all clients start simultaneously */
  pthread_barrier_wait(&g_start_barrier);

  /* Stagger client startup smoothly to prevent instantaneous buffer overflow */
  if (g_num_clients > 10) {
    uint32_t delay_us = (g_num_clients > 256) ? 1500 : 400;
    usleep((useconds_t)(idx * delay_us));
  }

  r->start_ns = ns_now();

  uint8_t c_nonce[16];
  if (RAND_bytes(c_nonce, 16) != 1)
    goto fail;

  /* ── Phase 1 & 2: PKT_CLIENT_HELLO (80B) & PKT_SERVER_HELLO (152B) ── */
  uint8_t hello[X25519_PK_BYTES + ED25519_PK_BYTES + 16];
  memcpy(hello, c_eph_pk, 32);
  memcpy(hello + 32, c_id_pk, 32);
  memcpy(hello + 64, c_nonce, 16);

  size_t min_srv_hello_len = 32 + 32 + 8 + 16 + 64; /* 152 bytes */
  uint8_t srv_hello[256];
  ssize_t n = -1;

  for (int attempt = 0; attempt < 10; attempt++) {
    if (attempt > 0) {
      c.tx_seq = 1;
      usleep((useconds_t)(10000 + (rand() % 30000)));
    }
    if (pkt_send(&c, PKT_CLIENT_HELLO, hello, (uint16_t)sizeof(hello)) < 0)
      goto fail;

    int timeout_ms = 2000 + (rand() % 500);
    n = recv_type_timeout(&c, PKT_SERVER_HELLO, srv_hello, sizeof(srv_hello), timeout_ms);
    if (n >= (ssize_t)min_srv_hello_len) {
      break;
    }
  }
  if (n < (ssize_t)min_srv_hello_len)
    goto fail;

  {
    uint8_t s_id_pk[ED25519_PK_BYTES];
    uint8_t s_eph_pk[X25519_PK_BYTES];
    uint8_t session_id_bytes[8];
    uint8_t s_nonce[16];
    uint8_t srv_sig[ED25519_SIG_BYTES];
    uint8_t shared_secret[X25519_SS_BYTES];

    size_t off = 0;
    memcpy(s_id_pk, srv_hello + off, 32); off += 32;
    memcpy(s_eph_pk, srv_hello + off, 32); off += 32;
    memcpy(session_id_bytes, srv_hello + off, 8); off += 8;
    memcpy(s_nonce, srv_hello + off, 16); off += 16;
    memcpy(srv_sig, srv_hello + off, 64); off += 64;

    /* Verify server identity against trust store (pinned server_identity.pub) */
    if (trust_store_client_verify_server(s_id_pk, "server_identity.pub") != 0) {
      goto fail;
    }

    /* Construct Server Transcript: c_nonce(16) | s_nonce(16) | sid(8) | c_eph(32) | c_id(32) | s_id(32) | s_eph(32) = 168 bytes */
    uint8_t tx[168];
    size_t tx_off = 0;
    memcpy(tx + tx_off, c_nonce, 16); tx_off += 16;
    memcpy(tx + tx_off, s_nonce, 16); tx_off += 16;
    memcpy(tx + tx_off, session_id_bytes, 8); tx_off += 8;
    memcpy(tx + tx_off, c_eph_pk, 32); tx_off += 32;
    memcpy(tx + tx_off, c_id_pk, 32); tx_off += 32;
    memcpy(tx + tx_off, s_id_pk, 32); tx_off += 32;
    memcpy(tx + tx_off, s_eph_pk, 32); tx_off += 32;

    uint8_t tx_digest[SHA256_DIGEST_BYTES];
    if (sha256_digest(tx, tx_off, tx_digest) != 0)
      goto fail;

    t0 = cpu_now();
    if (ed25519_verify(srv_sig, ED25519_SIG_BYTES, tx_digest, SHA256_DIGEST_BYTES, s_id_pk) != 0)
      goto fail;
    r->ed25519_verify_us = (double)(cpu_now() - t0) / 1000.0;

    /* Compute X25519 shared secret */
    t0 = cpu_now();
    if (x25519_derive_shared_secret(shared_secret, c_eph_sk, s_eph_pk) != 0)
      goto fail;
    r->x25519_ecdh_us = (double)(cpu_now() - t0) / 1000.0;

    uint64_t sid64 = 0;
    for (int k = 0; k < 8; k++)
      sid64 = (sid64 << 8) | session_id_bytes[k];
    c.session_id = sid64;

    /* Derive directional traffic keys */
    t0 = cpu_now();
    kem_derive_directional_keys(c.tx_key, c.rx_key, shared_secret, c_nonce, s_nonce, sid64);
    r->hkdf_us = (double)(cpu_now() - t0) / 1000.0;
    explicit_bzero(shared_secret, sizeof(shared_secret));

    /* ── Phase 3: Client Authentication ── */
    /* Client Transcript: server transcript (168) | srv_sig (64) = 232 bytes */
    uint8_t cl_tx[232];
    memcpy(cl_tx, tx, 168);
    memcpy(cl_tx + 168, srv_sig, 64);

    uint8_t cl_tx_digest[SHA256_DIGEST_BYTES];
    if (sha256_digest(cl_tx, sizeof(cl_tx), cl_tx_digest) != 0)
      goto fail;

    uint8_t client_sig[ED25519_SIG_BYTES];
    size_t sig_len = 0;
    t0 = cpu_now();
    if (ed25519_sign(client_sig, &sig_len, cl_tx_digest, SHA256_DIGEST_BYTES, c_id_sk) != 0)
      goto fail;
    r->ed25519_sign_us = (double)(cpu_now() - t0) / 1000.0;

    /* Send PKT_CLIENT_AUTH (64 bytes) */
    c.tx_seq = 2;
    if (pkt_send(&c, PKT_CLIENT_AUTH, client_sig, (uint16_t)sizeof(client_sig)) < 0)
      goto fail;

    /* Wait for PKT_ACK or first data packet */
    uint8_t ack_payload[64];
    n = recv_type_timeout(&c, PKT_ACK, ack_payload, sizeof(ack_payload), 2000);
    if (n < 0) {
      /* If no ACK, proceed if server directly accepts traffic */
    }

    c.established = 1;
    r->end_ns = ns_now();
    r->hs_wall_ms = (double)(r->end_ns - r->start_ns) / 1e6;
    r->success = 1;

    /* ── Optional Data Message Phase ── */
    if (g_num_msgs > 0) {
      double rtt_sum = 0.0;
      r->msg_min_rtt_ms = 999999.0;
      r->msg_max_rtt_ms = 0.0;

      for (int m = 0; m < g_num_msgs && !g_stop; m++) {
        char msg_buf[128];
        snprintf(msg_buf, sizeof(msg_buf), "Client %d Msg %d Classical IoT AES-128-CCM", idx, m);

        uint64_t msg_t0 = ns_now();
        if (data_send(&c, NULL, (const uint8_t *)msg_buf, (uint32_t)strlen(msg_buf)) < 0)
          break;
        r->msgs_sent++;

        uint8_t rx_buf[256];
        int rx_len = data_recv(&c, rx_buf, sizeof(rx_buf));
        if (rx_len > 0) {
          uint64_t msg_t1 = ns_now();
          double rtt_ms = (double)(msg_t1 - msg_t0) / 1e6;
          rtt_sum += rtt_ms;
          if (rtt_ms < r->msg_min_rtt_ms) r->msg_min_rtt_ms = rtt_ms;
          if (rtt_ms > r->msg_max_rtt_ms) r->msg_max_rtt_ms = rtt_ms;
          r->msgs_recv++;
        }
        usleep(5000);
      }
      if (r->msgs_recv > 0)
        r->msg_avg_rtt_ms = rtt_sum / r->msgs_recv;
    }
  }

fail:
  conn_destroy(&c);
  explicit_bzero(c_eph_sk, sizeof(c_eph_sk));
  explicit_bzero(c_id_sk, sizeof(c_id_sk));
  return NULL;
}

int main(int argc, char *argv[]) {
  signal(SIGINT, on_signal);
  signal(SIGTERM, on_signal);

  if (argc > 1) {
    g_num_clients = atoi(argv[1]);
    if (g_num_clients <= 0) g_num_clients = DEFAULT_NUM_CLIENTS;
  }
  if (argc > 2) {
    g_num_msgs = atoi(argv[2]);
    if (g_num_msgs < 0) g_num_msgs = 0;
  }

  printf("\n");
  printf("========================================================================\n");
  printf("  QRYPTONEX Classical IoT Multi-Client Handshake Benchmark\n");
  printf("  Clients: %d | Encrypted Messages/Client: %d\n", g_num_clients, g_num_msgs);
  printf("  Suite: X25519 (ECDH) + Ed25519 + AES-128-CCM + SHA-256 + HKDF-SHA-256\n");
  printf("========================================================================\n\n");

  /* Dynamic endpoint resolution */
  if (resolve_server_address(NULL, &g_server_peer, g_server_ip, sizeof(g_server_ip)) != 0) {
    strncpy(g_server_ip, "127.0.0.1", sizeof(g_server_ip) - 1);
    memset(&g_server_peer, 0, sizeof(g_server_peer));
    g_server_peer.sin_family = AF_INET;
    g_server_peer.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, g_server_ip, &g_server_peer.sin_addr);
  }
  printf("[*] Connecting to Classical Server at %s:%d\n", g_server_ip, SERVER_PORT);

  g_results = calloc(g_num_clients, sizeof(client_result_t));
  pthread_barrier_init(&g_start_barrier, NULL, (unsigned)g_num_clients);

  pthread_t *threads = calloc(g_num_clients, sizeof(pthread_t));

  cpu_ticks_t cpu_start, cpu_end;
  get_cpu_ticks(&cpu_start);
  perf_temp_monitor_t temp_mon;
  perf_temp_init(&temp_mon);
  perf_mem_monitor_t mem_mon;
  perf_mem_init(&mem_mon);

  uint64_t bench_start = ns_now();

  for (int i = 0; i < g_num_clients; i++) {
    pthread_create(&threads[i], NULL, client_thread, (void *)(intptr_t)i);
  }

  for (int i = 0; i < g_num_clients; i++) {
    pthread_join(threads[i], NULL);
  }

  uint64_t bench_end = ns_now();
  get_cpu_ticks(&cpu_end);
  perf_temp_finalize(&temp_mon);
  perf_mem_finalize(&mem_mon);

  double total_wall_sec = (double)(bench_end - bench_start) / 1e9;
  double cpu_util = calculate_cpu_utilization(&cpu_start, &cpu_end);

  /* Aggregate stats */
  int success_count = 0;
  double hs_wall_sum = 0.0;
  double *latencies = malloc(g_num_clients * sizeof(double));
  int lat_count = 0;

  for (int i = 0; i < g_num_clients; i++) {
    if (g_results[i].success) {
      success_count++;
      hs_wall_sum += g_results[i].hs_wall_ms;
      latencies[lat_count++] = g_results[i].hs_wall_ms;
    }
  }

  /* Compute percentiles */
  double hs_min = 0, hs_max = 0, hs_median = 0, hs_p95 = 0, hs_p99 = 0;
  if (lat_count > 0) {
    /* sort */
    for (int i = 0; i < lat_count - 1; i++) {
      for (int j = i + 1; j < lat_count; j++) {
        if (latencies[i] > latencies[j]) {
          double tmp = latencies[i];
          latencies[i] = latencies[j];
          latencies[j] = tmp;
        }
      }
    }
    hs_min = latencies[0];
    hs_max = latencies[lat_count - 1];
    hs_median = latencies[lat_count / 2];
    hs_p95 = latencies[(int)(lat_count * 0.95)];
    hs_p99 = latencies[(int)(lat_count * 0.99)];
  }

  printf("\n========================================================================\n");
  printf("  Benchmark Results Summary\n");
  printf("========================================================================\n");
  printf("  Clients Attempted     : %d\n", g_num_clients);
  printf("  Handshakes Succeeded  : %d (%.1f%%)\n", success_count, (100.0 * success_count / g_num_clients));
  printf("  Total Wall Time       : %.3f s\n", total_wall_sec);
  printf("  Handshake Throughput  : %.1f handshakes/sec\n", (double)success_count / total_wall_sec);
  printf("  Overall CPU Util      : %.1f%%\n", cpu_util);
  printf("  Initial Memory RAM    : %.3f MB\n", mem_mon.initial_ram_mb);
  printf("  Peak Memory RSS       : %.3f MB\n", mem_mon.peak_ram_mb);
  printf("  Heap Memory Usage     : %.3f MB\n", mem_mon.heap_usage_mb);
  if (mem_mon.stack_usage_kb > 0.0) {
    printf("  Stack Memory Usage    : %.2f KB\n", mem_mon.stack_usage_kb);
  }
  if (temp_mon.available) {
    printf("  Hardware Sensor       : %s (%s)\n", temp_mon.sensor_path, temp_mon.sensor_type);
    printf("  System Temperature    : Initial: %.2f °C | Final: %.2f °C | Delta: %+.2f °C\n",
           temp_mon.initial_temp_c, temp_mon.final_temp_c, temp_mon.final_temp_c - temp_mon.initial_temp_c);
  } else {
    printf("  System Temperature    : Unavailable (No sysfs thermal sensor)\n");
  }
  printf("------------------------------------------------------------------------\n");
  printf("  Handshake Latency Distribution (ms):\n");
  printf("    Min: %.2f ms | Median: %.2f ms | Mean: %.2f ms | Max: %.2f ms\n",
         hs_min, hs_median, (success_count ? hs_wall_sum / success_count : 0), hs_max);
  printf("    p95: %.2f ms | p99: %.2f ms\n", hs_p95, hs_p99);
  printf("========================================================================\n\n");

  free(latencies);
  free(threads);
  free(g_results);
  pthread_barrier_destroy(&g_start_barrier);

  return (success_count > 0) ? 0 : 1;
}
