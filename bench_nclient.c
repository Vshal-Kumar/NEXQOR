/*
 * bench_nclient.c — N-Client Concurrent PQC Handshake Benchmark
 *
 * Spawns N client threads in a single process, each performing the full
 * 4-way PQC handshake against the running server, optionally followed
 * by M encrypted message round-trips.
 *
 * Usage:
 *   ./bench_nclient              # 64 clients, 10 messages each
 *   ./bench_nclient 128          # 128 clients, handshake only
 *   ./bench_nclient 128 50       # 128 clients, 50 messages each
 *
 * REQUIRES: ./server running in another terminal
 */

#define _GNU_SOURCE
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

#include "crypto/aead.h"
#include "transport.h"
#include "wrappers/dsa_wrapper.h"
#include "wrappers/kem_wrapper.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

static int shake256_hash(uint8_t out[64], const uint8_t *in, size_t in_len) {
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx)
    return -1;
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

/* ── Defaults ────────────────────────────────────────────────────── */
#define DEFAULT_NUM_CLIENTS 64
#define DEFAULT_NUM_MSGS 10

#define AUTH_CTX_LEN (SESSION_ID_BYTES + DSA_PK_BYTES + KEM_SS_BYTES)

static const char *g_server_ip = SERVER_ADDR;

#include <sys/resource.h>

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

  unsigned long long total_diff = end_total - start_total;
  unsigned long long idle_diff = end_idle - start_idle;

  if (total_diff == 0)
    return 0.0;
  double util = 100.0 * (1.0 - (double)idle_diff / (double)total_diff);
  return (util < 0.0) ? 0.0 : (util > 100.0) ? 100.0 : util;
}

static double get_cpu_temp(void) {
  FILE *f = fopen("/sys/class/thermal/thermal_zone0/temp", "r");
  if (!f)
    return 0.0;
  long temp = 0;
  if (fscanf(f, "%ld", &temp) == 1) {
    fclose(f);
    return (double)temp / 1000.0;
  }
  fclose(f);
  return 0.0;
}

static double get_peak_ram(void) {
  struct rusage usage;
  if (getrusage(RUSAGE_SELF, &usage) == 0) {
    /* ru_maxrss is in kilobytes on Linux */
    return (double)usage.ru_maxrss / 1024.0;
  }
  return 0.0;
}

/* ── Timer ───────────────────────────────────────────────────────── */
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

/* ── Statistics ──────────────────────────────────────────────────── */
typedef struct {
  double min_us, max_us, sum_us, sum_sq_us;
  int n;
} stats_t;

static void stats_init(stats_t *s) {
  s->min_us = 1e18;
  s->max_us = 0;
  s->sum_us = 0;
  s->sum_sq_us = 0;
  s->n = 0;
}

static void stats_add(stats_t *s, double us) {
  if (us < s->min_us)
    s->min_us = us;
  if (us > s->max_us)
    s->max_us = us;
  s->sum_us += us;
  s->sum_sq_us += us * us;
  s->n++;
}

static double stats_mean(const stats_t *s) {
  return s->n > 0 ? s->sum_us / s->n : 0;
}

static double stats_stddev(const stats_t *s) {
  if (s->n < 2)
    return 0;
  double m = stats_mean(s);
  double v = (s->sum_sq_us / s->n) - (m * m);
  return v > 0 ? sqrt(v) : 0;
}

/* ── Per-client result ───────────────────────────────────────────── */
typedef struct {
  int success; /* 1 = handshake OK */
  double kem_keygen_us;
  double dsa_keygen_us;
  double kem_decaps_us;
  double dsa_sign_us;
  double dsa_verify_us;
  double hs_total_us; /* wall-clock handshake time */
  double avg_encrypt_us;
  double avg_decrypt_us;
  int msgs_sent;
  int msgs_recv;
  double msg_min_rtt_ms;
  double msg_max_rtt_ms;
  double msg_avg_rtt_ms;
  uint64_t start_ns; /* when handshake started */
  uint64_t end_ns;   /* when handshake finished */
} client_result_t;

/* ── Shared state ────────────────────────────────────────────────── */
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

  /* Restore default timeout */
  struct timeval tv_def;
  tv_def.tv_sec = 0;
  tv_def.tv_usec = 50000;
  setsockopt(c->sock, SOL_SOCKET, SO_RCVTIMEO, &tv_def, sizeof(tv_def));

  return result;
}

/* ── Client thread ───────────────────────────────────────────────── */
static void *client_thread(void *arg) {
  int idx = (int)(intptr_t)arg;
  client_result_t *r = &g_results[idx];
  memset(r, 0, sizeof(*r));

  /* Let the OS scheduler freely place client threads across all cores for
   * optimal resource usage */

  /* Generate keys before barrier */
  uint8_t kem_pk[KEM_PK_BYTES], kem_sk[KEM_SK_BYTES];
  uint8_t dsa_pk[DSA_PK_BYTES], dsa_sk[DSA_SK_BYTES];

  /* Silent thread-level warmup of all cryptographic functions to avoid
   * cold-start penalties */
  {
    uint8_t d_kpk[KEM_PK_BYTES], d_ksk[KEM_SK_BYTES];
    uint8_t d_kct[KEM_CT_BYTES], d_kss[KEM_SS_BYTES];
    uint8_t d_dpk[DSA_PK_BYTES], d_dsk[DSA_SK_BYTES];
    uint8_t d_sig[DSA_SIG_BYTES];
    size_t d_siglen = 0;
    uint8_t d_ctx[64] = {0};

    kem_keypair(d_kpk, d_ksk);
    kem_enc(d_kct, d_kss, d_kpk);
    kem_dec(d_kss, d_kct, d_ksk);

    dsa_keypair(d_dpk, d_dsk);
    dsa_sign(d_sig, &d_siglen, d_ctx, sizeof(d_ctx), d_dsk);
    dsa_verify(d_sig, d_siglen, d_ctx, sizeof(d_ctx), d_dpk);
  }

  uint64_t t0 = cpu_now();
  kem_keypair(kem_pk, kem_sk);
  r->kem_keygen_us = (double)(cpu_now() - t0) / 1000.0;

  t0 = cpu_now();
  dsa_keypair(dsa_pk, dsa_sk);
  r->dsa_keygen_us = (double)(cpu_now() - t0) / 1000.0;

  /* Create socket */
  int sock = make_client_sock();
  if (sock < 0) {
    return NULL;
  }

  conn_t c = {0};
  c.sock = sock;
  c.peer_len = sizeof(c.peer);
  c.peer.sin_family = AF_INET;
  c.peer.sin_port = htons(SERVER_PORT);
  inet_pton(AF_INET, g_server_ip, &c.peer.sin_addr);
  c.tx_seq = 1;

  /* fcntl(sock, F_SETFL, O_NONBLOCK); */

  /* Synchronize: all clients start handshake simultaneously */
  pthread_barrier_wait(&g_start_barrier);

  /* Stagger startup smoothly based on client count to pace network injection */
  if (g_num_clients > 10) {
    uint32_t delay_us = (g_num_clients > 256) ? 1500 : 500;
    usleep((useconds_t)(idx * delay_us));
  }

  r->start_ns = ns_now();

  /* Generate client nonce */
  uint8_t c_nonce[16];
  if (RAND_bytes(c_nonce, 16) != 1)
    goto fail;

  /* ── Phase 1 & 2: CLIENT_HELLO & SERVER_HELLO (Reliable implicitly) ── */
  uint8_t hello[KEM_PK_BYTES + DSA_PK_BYTES + 16];
  memcpy(hello, kem_pk, KEM_PK_BYTES);
  memcpy(hello + KEM_PK_BYTES, dsa_pk, DSA_PK_BYTES);
  memcpy(hello + KEM_PK_BYTES + DSA_PK_BYTES, c_nonce, 16);

  size_t min_len =
      DSA_PK_BYTES + KEM_CT_BYTES + SESSION_ID_BYTES + 16 + DSA_SIG_BYTES;
  uint8_t srv_hello[DSA_PK_BYTES + KEM_CT_BYTES + SESSION_ID_BYTES + 16 +
                    DSA_SIG_BYTES + 128];
  ssize_t n = -1;

  for (int attempt = 0; attempt < 12; attempt++) {
    if (attempt > 0) {
      c.tx_seq = 1;
      /* Desynchronize retry waves with randomized jitter */
      usleep((useconds_t)(10000 + (rand() % 50000)));
    }
    if (pkt_send(&c, PKT_CLIENT_HELLO, hello, (uint16_t)sizeof(hello)) < 0)
      goto fail;

    int timeout_ms = 2500 + (rand() % 500);
    n = recv_type_timeout(&c, PKT_SERVER_HELLO, srv_hello, sizeof(srv_hello),
                          timeout_ms);
    if (n >= (ssize_t)min_len) {
      break;
    }
  }
  if (n < (ssize_t)min_len)
    goto fail;

  {
    uint8_t srv_dsa_pk[DSA_PK_BYTES];
    uint8_t kem_ct[KEM_CT_BYTES];
    uint8_t session_id[SESSION_ID_BYTES];
    uint8_t s_nonce[16];
    uint8_t srv_sig[DSA_SIG_BYTES];
    uint8_t shared_secret[KEM_SS_BYTES];

    size_t off = 0;
    memcpy(srv_dsa_pk, srv_hello + off, DSA_PK_BYTES);
    off += DSA_PK_BYTES;
    memcpy(kem_ct, srv_hello + off, KEM_CT_BYTES);
    off += KEM_CT_BYTES;
    memcpy(session_id, srv_hello + off, SESSION_ID_BYTES);
    off += SESSION_ID_BYTES;
    memcpy(s_nonce, srv_hello + off, 16);
    off += 16;
    memcpy(srv_sig, srv_hello + off, DSA_SIG_BYTES);

    /* Construct Server Handshake Transcript */
    size_t tx_len = 16 + 16 + SESSION_ID_BYTES + KEM_PK_BYTES + DSA_PK_BYTES +
                    DSA_PK_BYTES + KEM_CT_BYTES;
    uint8_t *tx = malloc(tx_len);
    if (!tx)
      goto fail;
    size_t tx_off = 0;
    memcpy(tx + tx_off, c_nonce, 16);
    tx_off += 16;
    memcpy(tx + tx_off, s_nonce, 16);
    tx_off += 16;
    memcpy(tx + tx_off, session_id, SESSION_ID_BYTES);
    tx_off += SESSION_ID_BYTES;
    memcpy(tx + tx_off, kem_pk, KEM_PK_BYTES);
    tx_off += KEM_PK_BYTES;
    memcpy(tx + tx_off, dsa_pk, DSA_PK_BYTES);
    tx_off += DSA_PK_BYTES;
    memcpy(tx + tx_off, srv_dsa_pk, DSA_PK_BYTES);
    tx_off += DSA_PK_BYTES;
    memcpy(tx + tx_off, kem_ct, KEM_CT_BYTES);

    /* Hash Server Transcript */
    uint8_t server_tx_digest[64];
    if (shake256_hash(server_tx_digest, tx, tx_len) != 0) {
      free(tx);
      goto fail;
    }

    /* Verify Server Signature */
    t0 = cpu_now();
    if (dsa_verify(srv_sig, DSA_SIG_BYTES, server_tx_digest, 64, srv_dsa_pk) !=
        0) {
      free(tx);
      goto fail;
    }
    r->dsa_verify_us = (double)(cpu_now() - t0) / 1000.0;

    /* KEM decaps */
    t0 = cpu_now();
    if (kem_dec(shared_secret, kem_ct, kem_sk) != 0) {
      free(tx);
      goto fail;
    }
    r->kem_decaps_us = (double)(cpu_now() - t0) / 1000.0;

    uint64_t sid64 = 0;
    for (int k = 0; k < SESSION_ID_BYTES; k++) {
      sid64 = (sid64 << 8) | session_id[k];
    }
    c.session_id = sid64;

    /* Derive key using KDF bound to nonces and session ID */
    uint8_t derived_key[DERIVED_KEY_BYTES];
    kem_derive_key(derived_key, shared_secret, c_nonce, s_nonce, sid64);
    memcpy(c.session_key, derived_key, 32);
    explicit_bzero(derived_key, sizeof(derived_key));
    explicit_bzero(shared_secret, sizeof(shared_secret));

    /* Construct Client Handshake Transcript */
    size_t cl_tx_len = tx_len + DSA_SIG_BYTES;
    uint8_t *cl_tx = malloc(cl_tx_len);
    if (!cl_tx) {
      free(tx);
      goto fail;
    }
    memcpy(cl_tx, tx, tx_len);
    memcpy(cl_tx + tx_len, srv_sig, DSA_SIG_BYTES);
    free(tx);

    /* Hash Client Transcript */
    uint8_t client_tx_digest[64];
    if (shake256_hash(client_tx_digest, cl_tx, cl_tx_len) != 0) {
      free(cl_tx);
      goto fail;
    }
    free(cl_tx);

    /* Sign Client Transcript */
    uint8_t sig[DSA_SIG_BYTES];
    size_t siglen = 0;
    t0 = cpu_now();
    if (dsa_sign(sig, &siglen, client_tx_digest, 64, dsa_sk) != 0) {
      goto fail;
    }
    r->dsa_sign_us = (double)(cpu_now() - t0) / 1000.0;

    /* Phase 3: CLIENT_AUTH */
    if (pkt_send_reliable(&c, PKT_CLIENT_AUTH, sig, (uint16_t)siglen) != 0) {
      goto fail;
    }

    /* Phase 4: session active */
    c.established = 1;

    uint64_t sid = 0;
    for (int i = 0; i < SESSION_ID_BYTES; i++)
      sid = (sid << 8) | session_id[i];
    c.session_id = sid;
  }

  r->end_ns = ns_now();
  r->hs_total_us = (double)(r->end_ns - r->start_ns) / 1000.0;
  r->success = 1;

  /* Restore socket to blocking mode for data/message loop */
  int flags = fcntl(sock, F_GETFL, 0);
  fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);

  /* ── Optional: send M encrypted messages ────────────────── */
  if (g_num_msgs > 0 && !g_stop) {
    metrics_t m = {0};
    m.msg_min_rtt_ms = 1e15;

    char msg_buf[64];
    for (int i = 0; i < g_num_msgs && !g_stop; i++) {
      int len =
          snprintf(msg_buf, sizeof(msg_buf), "bench-client-%d-msg-%d", idx, i);
      uint64_t t_send = ns_now();
      if (data_send(&c, &m, (const uint8_t *)msg_buf, (uint32_t)len) == 0) {
        r->msgs_sent++;

        /* Wait for echo response */
        pkt_hdr_t rx_hdr;
        uint8_t rx_raw[12 + 16 + DATA_CHUNK_MAX + 64];
        /* Timeout: 50 ms */
        ssize_t rx_n = pkt_recv(&c, &rx_hdr, rx_raw, sizeof(rx_raw), 50000);
        if (rx_n >= (12 + 16) && rx_hdr.type == PKT_DATA) {
          const uint8_t *nonce = rx_raw;
          const uint8_t *tag = rx_raw + 12;
          const uint8_t *ct = rx_raw + 28;
          int ct_len = (int)rx_n - 28;
          if (ct_len > 0 && ct_len <= DATA_CHUNK_MAX) {
            uint8_t rx_pt[DATA_CHUNK_MAX];
            int rx_pt_len =
                aead_decrypt(ct, ct_len, c.session_key, nonce, tag, rx_pt);
            if (rx_pt_len >= 0) {
              uint64_t t_recv = ns_now();
              double rtt_ms = (double)(t_recv - t_send) / 1e6;

              m.msg_last_rtt_ms = rtt_ms;
              m.msg_avg_rtt_ms = (m.msg_avg_rtt_ms * r->msgs_recv + rtt_ms) /
                                 (r->msgs_recv + 1);
              if (rtt_ms < m.msg_min_rtt_ms)
                m.msg_min_rtt_ms = rtt_ms;
              if (rtt_ms > m.msg_max_rtt_ms)
                m.msg_max_rtt_ms = rtt_ms;

              r->msgs_recv++;
            }
          }
        }
      }
      usleep(1000); /* 1ms pacing to avoid UDP drops */
    }

    r->avg_encrypt_us = (m.encrypt_count > 0)
                            ? m.total_encrypt_us / (double)m.encrypt_count
                            : 0;
    r->msg_avg_rtt_ms = (r->msgs_recv > 0) ? m.msg_avg_rtt_ms : 0.0;
    r->msg_min_rtt_ms = (r->msgs_recv > 0) ? m.msg_min_rtt_ms : 0.0;
    r->msg_max_rtt_ms = (r->msgs_recv > 0) ? m.msg_max_rtt_ms : 0.0;
  }

  pkt_send(&c, PKT_DISCONNECT, NULL, 0);
  close(sock);
  explicit_bzero(kem_sk, sizeof(kem_sk));
  explicit_bzero(dsa_sk, sizeof(dsa_sk));
  explicit_bzero(c.session_key, sizeof(c.session_key));
  return NULL;

fail:
  r->end_ns = ns_now();
  r->hs_total_us = (double)(r->end_ns - r->start_ns) / 1000.0;
  pkt_send(&c, PKT_DISCONNECT, NULL, 0);
  close(sock);
  explicit_bzero(kem_sk, sizeof(kem_sk));
  explicit_bzero(dsa_sk, sizeof(dsa_sk));
  return NULL;
}

/* ═══════════════════════════════════════════════════════════════════
 * main()
 * ═══════════════════════════════════════════════════════════════════ */
int main(int argc, char *argv[]) {
  signal(SIGINT, on_signal);
  signal(SIGTERM, on_signal);
  signal(SIGPIPE, SIG_IGN);

  /* Ensure sufficient file descriptors for high concurrency */
  struct rlimit rlim;
  if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
    if (rlim.rlim_cur < 65536) {
      rlim.rlim_cur = (rlim.rlim_max >= 65536) ? 65536 : rlim.rlim_max;
      setrlimit(RLIMIT_NOFILE, &rlim);
    }
  }

  g_num_msgs = 5; /* Handshake + 5 data messages for metrics by default */
  if (argc > 4) {
    fprintf(stderr,
            "Usage: %s [num_clients 1-4096] [num_messages >= 0] [server_ip]\n",
            argv[0]);
    return 1;
  }
  if (argc > 1) {
    g_num_clients = atoi(argv[1]);
  }
  if (argc > 2) {
    g_num_msgs = atoi(argv[2]);
  }
  if (argc > 3) {
    g_server_ip = argv[3];
  }
  if (g_num_clients < 1 || g_num_clients > 4096) {
    fprintf(stderr,
            "Usage: %s [num_clients 1-4096] [num_messages >= 0] [server_ip]\n",
            argv[0]);
    return 1;
  }
  if (g_num_msgs < 0) {
    fprintf(stderr, "Error: Number of messages must be >= 0.\n");
    return 1;
  }

  printf("\n");
  printf("╔══════════════════════════════════════════════════════════════╗\n");
  printf("║     N-Client Concurrent PQC Handshake Benchmark              ║\n");
  printf("║  ML-KEM-768  +  ML-DSA-65  +  ChaCha20-Poly1305             ║\n");
  printf("╚══════════════════════════════════════════════════════════════╝\n");
  printf("  Clients    : %d\n", g_num_clients);
  printf("  Messages   : %d per client %s\n", g_num_msgs,
         g_num_msgs == 0 ? "(handshake only)" : "");
  printf("  Server     : %s:%d\n", g_server_ip, SERVER_PORT);
  printf("  Timer      : CLOCK_MONOTONIC (ns resolution)\n\n");

  /* Allocate results */
  g_results = calloc((size_t)g_num_clients, sizeof(client_result_t));
  if (!g_results) {
    perror("calloc");
    return 1;
  }

  pthread_barrier_init(&g_start_barrier, NULL, (unsigned)g_num_clients);

  /* Spawn all client threads with customized stack size */
  printf("  Spawning %d client threads...\n", g_num_clients);
  pthread_t *tids = malloc(sizeof(pthread_t) * (size_t)g_num_clients);

  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setstacksize(&attr, 512 * 1024); /* 512 KB per thread */

  uint64_t wall_start = ns_now();
  cpu_ticks_t cpu_start, cpu_end;
  get_cpu_ticks(&cpu_start);

  for (int i = 0; i < g_num_clients; i++) {
    pthread_create(&tids[i], &attr, client_thread, (void *)(intptr_t)i);
  }
  pthread_attr_destroy(&attr);

  /* Wait for all to finish */
  for (int i = 0; i < g_num_clients; i++) {
    pthread_join(tids[i], NULL);
  }

  get_cpu_ticks(&cpu_end);
  uint64_t wall_end = ns_now();
  double wall_ms = (double)(wall_end - wall_start) / 1e6;
  double cpu_util = calculate_cpu_utilization(&cpu_start, &cpu_end);

  /* ── Aggregate results ───────────────────────────────────── */
  int success = 0, failed = 0;
  stats_t s_kem_kg, s_dsa_kg, s_kem_dec, s_dsa_sign, s_dsa_verify;
  stats_t s_hs_net_rtt, s_hs_serial, s_hs_parallel;
  stats_t s_enc, s_dec;
  stats_t s_msg_rtt;
  stats_init(&s_kem_kg);
  stats_init(&s_dsa_kg);
  stats_init(&s_kem_dec);
  stats_init(&s_dsa_sign);
  stats_init(&s_dsa_verify);
  stats_init(&s_hs_net_rtt);
  stats_init(&s_hs_serial);
  stats_init(&s_hs_parallel);
  stats_init(&s_enc);
  stats_init(&s_dec);
  stats_init(&s_msg_rtt);
  int total_msgs_sent = 0;
  int total_msgs_recv = 0;

  for (int i = 0; i < g_num_clients; i++) {
    client_result_t *r = &g_results[i];
    if (r->success) {
      success++;
      double serial_hs = r->kem_keygen_us + r->dsa_keygen_us + r->hs_total_us;
      double max_kg = (r->kem_keygen_us > r->dsa_keygen_us) ? r->kem_keygen_us
                                                            : r->dsa_keygen_us;
      double parallel_hs = max_kg + r->hs_total_us;

      stats_add(&s_kem_kg, r->kem_keygen_us);
      stats_add(&s_dsa_kg, r->dsa_keygen_us);
      stats_add(&s_kem_dec, r->kem_decaps_us);
      stats_add(&s_dsa_sign, r->dsa_sign_us);
      stats_add(&s_dsa_verify, r->dsa_verify_us);
      stats_add(&s_hs_net_rtt, r->hs_total_us);
      stats_add(&s_hs_serial, serial_hs);
      stats_add(&s_hs_parallel, parallel_hs);
      if (r->avg_encrypt_us > 0)
        stats_add(&s_enc, r->avg_encrypt_us);
      if (r->msgs_recv > 0) {
        stats_add(&s_msg_rtt, r->msg_avg_rtt_ms * 1000.0);
      }
      total_msgs_sent += r->msgs_sent;
      total_msgs_recv += r->msgs_recv;
    } else {
      failed++;
    }
  }

  /* ── Per-Client Metrics Table ────────────────────────────── */
  if (g_num_clients <= 128) {
    printf("┌─ Per-Client Handshake & Secure Communication Metrics "
           "───────────────────────────────────────────────────────────────────"
           "─────────────────────────────────────┐\n");
    printf(
        "│  Client ID  │  Status  │  Total HS (ms)  │  Msgs Sent  │  Msgs Recv "
        " │  Min Msg RTT (ms)  │  Max Msg RTT (ms)  │  Avg Msg RTT (ms)  │\n");
    printf(
        "│  "
        "───────────┼──────────┼─────────────────┼─────────────┼─────────────┼─"
        "───────────────────┼────────────────────┼────────────────────│\n");
    for (int i = 0; i < g_num_clients; i++) {
      client_result_t *r = &g_results[i];
      printf("│  %-9d  │  %-6s  │  %15.3f  │  %11d  │  %11d  │  %18.3f  │  "
             "%18.3f  │  %18.3f  │\n",
             i, r->success ? "Active" : "Failed", r->hs_total_us / 1000.0,
             r->msgs_sent, r->msgs_recv, r->msg_min_rtt_ms, r->msg_max_rtt_ms,
             r->msg_avg_rtt_ms);
    }
    printf("└──────────────────────────────────────────────────────────────────"
           "───────────────────────────────────────────────────────────────────"
           "─────────────────────────┘\n\n");
  }

  /* ── System-Wide & Communication Metrics Table ────────────────────── */
  double temp = get_cpu_temp();
  double peak_ram = get_peak_ram();
  double success_rate = 100.0 * (double)success / (double)g_num_clients;
  double hs_throughput =
      (wall_ms > 0) ? ((double)success / (wall_ms / 1000.0)) : 0.0;
  double msg_throughput =
      (wall_ms > 0) ? ((double)total_msgs_recv / (wall_ms / 1000.0)) : 0.0;
  double energy_j = 0.0;
  if (success > 0) {
    energy_j =
        (15.0 * (cpu_util / 100.0) * (wall_ms / 1000.0)) / (double)success;
  }
  double energy_mwh = energy_j / 3.6;

  printf("┌─ System-Wide & Communication Metrics "
         "──────────────────────────────────────────────────┐\n");
  printf("│  Metric                             │    Value              │  "
         "Unit                    │\n");
  printf("│  "
         "───────────────────────────────────┼───────────────────────┼─────────"
         "─────────────────│\n");
  printf("│  Handshake Success Rate             │  %20.1f   │  %%              "
         "         │\n",
         success_rate);
  printf("│  Handshake Throughput               │  %20.1f   │  handshakes/sec  "
         "        │\n",
         hs_throughput);
  printf("│  Network Handshake RTT (Average)    │  %20.3f   │  ms              "
         "        │\n",
         stats_mean(&s_hs_net_rtt) / 1000.0);
  printf("│  Total Handshake (Serial Avg)       │  %20.3f   │  ms              "
         "        │\n",
         stats_mean(&s_hs_serial) / 1000.0);
  printf("│  Total Handshake (Parallel Avg)     │  %20.3f   │  ms              "
         "        │\n",
         stats_mean(&s_hs_parallel) / 1000.0);
  printf("│  End-to-End Message RTT (Average)   │  %20.3f   │  ms              "
         "        │\n",
         stats_mean(&s_msg_rtt) / 1000.0);
  printf("│  Message Throughput                 │  %20.1f   │  messages/sec    "
         "        │\n",
         msg_throughput);
  printf("│  CPU Utilization                    │  %20.1f   │  %%              "
         "         │\n",
         cpu_util);
  printf("│  Peak RAM Usage                     │  %20.1f   │  MB              "
         "        │\n",
         peak_ram);
  if (success > 0) {
    char energy_buf[64];
    snprintf(energy_buf, sizeof(energy_buf), "%.3f (%.3f mWh)", energy_j,
             energy_mwh);
    printf("│  Energy per Handshake (Estimated)   │  %20s   │  Joules (TDP "
           "assumed 15W)│\n",
           energy_buf);
  } else {
    printf("│  Energy per Handshake (Estimated)   │  %20s   │  Joules          "
           "        │\n",
           "N/A");
  }
  if (temp > 0.0) {
    printf("│  CPU Temperature (End of Bench)     │  %20.1f   │  °C            "
           "          │\n",
           temp);
  } else {
    printf("│  CPU Temperature (End of Bench)     │  %20s   │  °C              "
           "        │\n",
           "N/A");
  }
  printf("└────────────────────────────────────────────────────────────────────"
         "────────────────────┘\n\n");

  printf("┌─ Cryptographic Operation Summary Metrics "
         "──────────────────────────────────────────────────────────────┐\n");
  printf("│  Metric                        │    Mean (ms)  │  Stddev (ms)  │   "
         "  Min (ms)  │     Max (ms)  │  Count  │\n");
  printf("│  "
         "──────────────────────────────┼───────────────┼───────────────┼──────"
         "─────────┼───────────────┼─────────│\n");

  printf("│  ML-KEM Keypair Gen (Client)   │  %12.3f  │  %11.3f  │  %11.3f  │  "
         "%11.3f  │  %5d  │\n",
         stats_mean(&s_kem_kg) / 1000.0, stats_stddev(&s_kem_kg) / 1000.0,
         (s_kem_kg.n > 0 ? s_kem_kg.min_us : 0.0) / 1000.0,
         (s_kem_kg.n > 0 ? s_kem_kg.max_us : 0.0) / 1000.0, s_kem_kg.n);

  printf("│  ML-DSA Keypair Gen (Client)   │  %12.3f  │  %11.3f  │  %11.3f  │  "
         "%11.3f  │  %5d  │\n",
         stats_mean(&s_dsa_kg) / 1000.0, stats_stddev(&s_dsa_kg) / 1000.0,
         (s_dsa_kg.n > 0 ? s_dsa_kg.min_us : 0.0) / 1000.0,
         (s_dsa_kg.n > 0 ? s_dsa_kg.max_us : 0.0) / 1000.0, s_dsa_kg.n);

  printf("│  ML-KEM Decapsulate (Client)   │  %12.3f  │  %11.3f  │  %11.3f  │  "
         "%11.3f  │  %5d  │\n",
         stats_mean(&s_kem_dec) / 1000.0, stats_stddev(&s_kem_dec) / 1000.0,
         (s_kem_dec.n > 0 ? s_kem_dec.min_us : 0.0) / 1000.0,
         (s_kem_dec.n > 0 ? s_kem_dec.max_us : 0.0) / 1000.0, s_kem_dec.n);

  printf("│  ML-DSA Sign (Client)          │  %12.3f  │  %11.3f  │  %11.3f  │  "
         "%11.3f  │  %5d  │\n",
         stats_mean(&s_dsa_sign) / 1000.0, stats_stddev(&s_dsa_sign) / 1000.0,
         (s_dsa_sign.n > 0 ? s_dsa_sign.min_us : 0.0) / 1000.0,
         (s_dsa_sign.n > 0 ? s_dsa_sign.max_us : 0.0) / 1000.0, s_dsa_sign.n);

  printf("│  ML-DSA Verify (Client)        │  %12.3f  │  %11.3f  │  %11.3f  │  "
         "%11.3f  │  %5d  │\n",
         stats_mean(&s_dsa_verify) / 1000.0,
         stats_stddev(&s_dsa_verify) / 1000.0,
         (s_dsa_verify.n > 0 ? s_dsa_verify.min_us : 0.0) / 1000.0,
         (s_dsa_verify.n > 0 ? s_dsa_verify.max_us : 0.0) / 1000.0,
         s_dsa_verify.n);

  printf("│  Network Handshake RTT (Net RTT)    │  %12.3f  │  %11.3f  │  "
         "%11.3f  │  "
         "%11.3f  │  %5d  │\n",
         stats_mean(&s_hs_net_rtt) / 1000.0,
         stats_stddev(&s_hs_net_rtt) / 1000.0,
         (s_hs_net_rtt.n > 0 ? s_hs_net_rtt.min_us : 0.0) / 1000.0,
         (s_hs_net_rtt.n > 0 ? s_hs_net_rtt.max_us : 0.0) / 1000.0,
         s_hs_net_rtt.n);

  printf("│  Total Handshake (Serial Est.)      │  %12.3f  │  %11.3f  │  "
         "%11.3f  │  "
         "%11.3f  │  %5d  │\n",
         stats_mean(&s_hs_serial) / 1000.0, stats_stddev(&s_hs_serial) / 1000.0,
         (s_hs_serial.n > 0 ? s_hs_serial.min_us : 0.0) / 1000.0,
         (s_hs_serial.n > 0 ? s_hs_serial.max_us : 0.0) / 1000.0,
         s_hs_serial.n);

  printf("│  Total Handshake (Parallel Est.)    │  %12.3f  │  %11.3f  │  "
         "%11.3f  │  "
         "%11.3f  │  %5d  │\n",
         stats_mean(&s_hs_parallel) / 1000.0,
         stats_stddev(&s_hs_parallel) / 1000.0,
         (s_hs_parallel.n > 0 ? s_hs_parallel.min_us : 0.0) / 1000.0,
         (s_hs_parallel.n > 0 ? s_hs_parallel.max_us : 0.0) / 1000.0,
         s_hs_parallel.n);

  printf("└────────────────────────────────────────────────────────────────────"
         "────────────────────────────────────┘\n");

  free(g_results);
  free(tids);
  pthread_barrier_destroy(&g_start_barrier);

  printf("[bench_nclient] Done. %d/%d handshakes succeeded.\n\n", success,
         g_num_clients);
  return (failed > 0) ? 1 : 0;
}
