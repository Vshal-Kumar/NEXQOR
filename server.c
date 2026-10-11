/*
 * server.c — High-Performance Asynchronous io_uring PQC Multi-Client Chat
 * Server
 *
 * Project: Performance Evaluation of SIMD-Accelerated Post-Quantum
 *          Cryptography on Embedded ARM Platforms
 *
 * Architecture:
 *  - Core 1: Network Event Loop (Main Thread)
 *            - io_uring asynchronous UDP engine (Zero-copy/pre-allocated
 * buffers)
 *            - Thread-confined session table (Actor model style, no locks)
 *            - Synchronous polling of io_uring CQ & lock-free Completion Queue
 *            - Adaptive load controller & rate limiting
 *  - Cores 2-7: Crypto Worker Thread Pool
 *            - Dequeue jobs from lock-free SPMC Queue
 *            - Execute heavy ML-KEM encapsulation & ML-DSA verification
 *            - Push completion to lock-free MPSC Queue
 *  - Core 8: Warm-path (KEM Keypair pre-generator, IPC terminals)
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <liburing.h>
#include <math.h>
#include <netinet/in.h>
#include <openssl/rand.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <semaphore.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "client_registry.h"
#include "crypto/aead.h"
#include "ipc.h"
#include "transport.h"
#include <openssl/evp.h>

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
#include "wrappers/dsa_wrapper.h"
#include "wrappers/kem_wrapper.h"

/* ── Sizing and Bounds ───────────────────────────────────────────── */
#define MAX_SESSIONS 10000
#define SESSION_HASH_SIZE (MAX_SESSIONS * 2)
#define JOB_QUEUE_SIZE 8192
#define WORKER_COMP_QUEUE_SIZE 4096
#define NUM_RECV_BUFFERS 1024
#define NUM_WORKERS 3
#define RATE_LIMIT_HASH_SIZE 16384

#define AUTH_CTX_LEN (SESSION_ID_BYTES + DSA_PK_BYTES + KEM_SS_BYTES)

/* ── Long-term identity ──────────────────────────────────────────── */
static uint8_t g_srv_dsa_pk[DSA_PK_BYTES];
static uint8_t g_srv_dsa_sk[DSA_SK_BYTES];
static double g_dsa_keygen_ms = 0.0;

/* Ephemeral KEM PK removed to optimize bandwidth (no longer sent in
 * SERVER_HELLO) */

static volatile int g_stop = 0;
static void on_signal(int s) {
  (void)s;
  g_stop = 1;
}

static void make_nonce(uint8_t nonce[12], uint64_t ctr) {
  uint64_t le_ctr = ctr;
  memcpy(nonce, &le_ctr, 8);
  memset(nonce + 8, 0, 4);
}

static int g_listen_sock = -1;
static pthread_mutex_t g_sock_send_mu = PTHREAD_MUTEX_INITIALIZER;

static int g_ipc_rx_fd = -1;
static int g_ipc_tx_fd = -1;
static pthread_mutex_t g_ipc_rx_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_ipc_tx_mu = PTHREAD_MUTEX_INITIALIZER;

/* ── Queue Definitions ───────────────────────────────────────────── */
typedef struct {
  uint64_t job_id;
  uint32_t session_id;
  uint64_t generation;
  uint8_t type;

  /* Input payload pointers (zero-copy addresses) */
  const uint8_t *client_kem_pk;
  const uint8_t *client_dsa_pk;
  const uint8_t *client_nonce;
  const uint8_t *server_nonce;
  uint64_t session_id_val;
  const uint8_t *sig;
  uint32_t sig_len;
  const uint8_t *auth_ctx;

  /* Output payload pointers (zero-copy addresses) */
  uint8_t *kem_ct;
  uint8_t *session_key;
  uint8_t *srv_sig;

  /* Timing fields */
  uint64_t enqueue_ns;
} crypto_job_t;

typedef struct {
  uint64_t job_id;
  uint32_t session_id;
  uint64_t generation;
  uint8_t type;
  int status;
} crypto_completion_t;

typedef struct {
  crypto_job_t jobs[JOB_QUEUE_SIZE];
  unsigned long head;
  unsigned long tail;
} crypto_job_queue_t;

typedef struct {
  crypto_completion_t completions[WORKER_COMP_QUEUE_SIZE];
  unsigned long head __attribute__((aligned(64)));
  unsigned long tail __attribute__((aligned(64)));
} worker_comp_queue_t;

static crypto_job_queue_t g_job_queue;
static worker_comp_queue_t g_worker_comp_queues[NUM_WORKERS];
static pthread_mutex_t g_job_queue_mu = PTHREAD_MUTEX_INITIALIZER;
static sem_t g_job_sem;
static int g_in_flight_jobs = 0;

/* ── Queue Operations ────────────────────────────────────────────── */
static int push_job(const crypto_job_t *job) {
  pthread_mutex_lock(&g_job_queue_mu);
  unsigned long tail = g_job_queue.tail;
  unsigned long head = g_job_queue.head;
  if (tail - head >= JOB_QUEUE_SIZE) {
    pthread_mutex_unlock(&g_job_queue_mu);
    return -1; /* Queue full */
  }
  g_job_queue.jobs[tail % JOB_QUEUE_SIZE] = *job;
  g_job_queue.tail = tail + 1;
  __atomic_add_fetch(&g_in_flight_jobs, 1, __ATOMIC_SEQ_CST);
  pthread_mutex_unlock(&g_job_queue_mu);
  sem_post(&g_job_sem);
  return 0;
}

static int pop_job(crypto_job_t *job_out) {
  pthread_mutex_lock(&g_job_queue_mu);
  unsigned long head = g_job_queue.head;
  unsigned long tail = g_job_queue.tail;
  if (head == tail) {
    pthread_mutex_unlock(&g_job_queue_mu);
    return -1; /* Queue empty */
  }
  *job_out = g_job_queue.jobs[head % JOB_QUEUE_SIZE];
  g_job_queue.head = head + 1;
  pthread_mutex_unlock(&g_job_queue_mu);
  return 0;
}

static inline int push_worker_completion(int worker_idx, const crypto_completion_t *comp) {
  if (worker_idx < 0 || worker_idx >= NUM_WORKERS) return -1;
  worker_comp_queue_t *q = &g_worker_comp_queues[worker_idx];
  unsigned long tail = q->tail;
  unsigned long head = __atomic_load_n(&q->head, __ATOMIC_ACQUIRE);
  if (tail - head >= WORKER_COMP_QUEUE_SIZE) {
    return -1; /* Queue full */
  }
  q->completions[tail % WORKER_COMP_QUEUE_SIZE] = *comp;
  __atomic_store_n(&q->tail, tail + 1, __ATOMIC_RELEASE);
  return 0;
}

static inline int pop_worker_completion(int worker_idx, crypto_completion_t *comp_out) {
  if (worker_idx < 0 || worker_idx >= NUM_WORKERS) return -1;
  worker_comp_queue_t *q = &g_worker_comp_queues[worker_idx];
  unsigned long head = q->head;
  unsigned long tail = __atomic_load_n(&q->tail, __ATOMIC_ACQUIRE);
  if (head == tail) {
    return -1; /* Queue empty */
  }
  *comp_out = q->completions[head % WORKER_COMP_QUEUE_SIZE];
  __atomic_store_n(&q->head, head + 1, __ATOMIC_RELEASE);
  __atomic_sub_fetch(&g_in_flight_jobs, 1, __ATOMIC_SEQ_CST);
  return 0;
}

/* ── Session States ──────────────────────────────────────────────── */
typedef enum {
  SESSION_FREE,
  SESSION_WAIT_KEM_ENC,
  SESSION_WAIT_AUTH,
  SESSION_WAIT_AUTH_VER,
  SESSION_ESTABLISHED
} session_state_t;

typedef struct {
  uint32_t session_id;
  uint64_t generation;
  uint32_t ip;
  uint16_t port;
  uint8_t state;

  uint8_t client_kem_pk[KEM_PK_BYTES];
  uint8_t client_dsa_pk[DSA_PK_BYTES];
  uint8_t kem_ct[KEM_CT_BYTES];
  uint8_t session_key[KEM_SS_BYTES];
  uint8_t sig[DSA_SIG_BYTES];
  uint8_t auth_ctx[AUTH_CTX_LEN];
  uint64_t session_id_val;

  uint8_t client_nonce[16];
  uint8_t server_nonce[16];
  uint8_t srv_sig[DSA_SIG_BYTES];

  uint32_t rx_seq;
  uint32_t tx_seq;
  uint32_t auth_seq;
  uint64_t tx_nonce_ctr;

  uint64_t current_job_id;
  metrics_t metrics;
  uint64_t last_seen_ns;
  uint64_t established_time_ns;
  int client_registry_id;
} session_t;

static session_t g_sessions[MAX_SESSIONS] __attribute__((aligned(64)));
static uint32_t g_free_sessions[MAX_SESSIONS];
static int g_free_session_count = MAX_SESSIONS;

typedef struct {
  uint32_t ip;
  uint16_t port;
  uint32_t session_idx;
  int occupied;
} session_hash_entry_t;

static session_hash_entry_t g_session_hash[SESSION_HASH_SIZE];

/* ── Hash Map Operations ─────────────────────────────────────────── */
static inline uint32_t session_hash(uint32_t ip, uint16_t port) {
  uint32_t h = 2166136261u;
  const uint8_t *b = (const uint8_t *)&ip;
  for (int i = 0; i < 4; i++) {
    h ^= b[i];
    h *= 16777619u;
  }
  h ^= (uint8_t)(port & 0xFF);
  h *= 16777619u;
  h ^= (uint8_t)(port >> 8);
  h *= 16777619u;
  return h;
}

static void session_hash_insert(uint32_t ip, uint16_t port, uint32_t idx) {
  uint32_t h = session_hash(ip, port) % SESSION_HASH_SIZE;
  for (int i = 0; i < SESSION_HASH_SIZE; i++) {
    int slot = (int)((h + (uint32_t)i) % SESSION_HASH_SIZE);
    if (!g_session_hash[slot].occupied) {
      g_session_hash[slot].ip = ip;
      g_session_hash[slot].port = port;
      g_session_hash[slot].session_idx = idx;
      g_session_hash[slot].occupied = 1;
      return;
    }
  }
}

static int session_hash_lookup(uint32_t ip, uint16_t port) {
  uint32_t h = session_hash(ip, port) % SESSION_HASH_SIZE;
  for (int i = 0; i < SESSION_HASH_SIZE; i++) {
    int slot = (int)((h + (uint32_t)i) % SESSION_HASH_SIZE);
    if (!g_session_hash[slot].occupied)
      return -1;
    if (g_session_hash[slot].ip == ip && g_session_hash[slot].port == port)
      return (int)g_session_hash[slot].session_idx;
  }
  return -1;
}

static void session_hash_remove(uint32_t ip, uint16_t port) {
  uint32_t h = session_hash(ip, port) % SESSION_HASH_SIZE;
  int found = -1;
  for (int i = 0; i < SESSION_HASH_SIZE; i++) {
    int slot = (int)((h + (uint32_t)i) % SESSION_HASH_SIZE);
    if (!g_session_hash[slot].occupied)
      return;
    if (g_session_hash[slot].ip == ip && g_session_hash[slot].port == port) {
      found = slot;
      break;
    }
  }
  if (found < 0)
    return;

  int empty = found;
  g_session_hash[empty].occupied = 0;
  for (int i = 1; i < SESSION_HASH_SIZE; i++) {
    int slot = (empty + i) % SESSION_HASH_SIZE;
    if (!g_session_hash[slot].occupied)
      break;
    uint32_t ideal =
        session_hash(g_session_hash[slot].ip, g_session_hash[slot].port) %
        SESSION_HASH_SIZE;
    int needs_shift = 0;
    if (empty < slot)
      needs_shift = (int)(ideal <= (uint32_t)empty || ideal > (uint32_t)slot);
    else
      needs_shift = (int)(ideal <= (uint32_t)empty && ideal > (uint32_t)slot);
    if (needs_shift) {
      g_session_hash[empty] = g_session_hash[slot];
      g_session_hash[slot].occupied = 0;
      empty = slot;
    }
  }
}

static int session_alloc(uint32_t ip, uint16_t port) {
  if (g_free_session_count == 0)
    return -1;
  uint32_t idx = g_free_sessions[--g_free_session_count];
  session_t *s = &g_sessions[idx];
  uint64_t saved_gen = s->generation;
  memset(s, 0, sizeof(session_t));
  s->generation = saved_gen;

  s->session_id = idx;
  s->ip = ip;
  s->port = port;
  s->state = SESSION_WAIT_KEM_ENC;
  s->rx_seq = 0;
  s->tx_seq = 1;
  s->tx_nonce_ctr = 0;
  s->current_job_id = 0;
  s->last_seen_ns = now_ns();
  s->established_time_ns = 0;
  s->client_registry_id = -1;
  memset(&s->metrics, 0, sizeof(metrics_t));
  s->metrics.msg_min_rtt_ms = 1e15;

  session_hash_insert(ip, port, idx);
  return (int)idx;
}

static void session_free(int idx) {
  session_t *s = &g_sessions[idx];
  if (s->state == SESSION_FREE)
    return;

  session_hash_remove(s->ip, s->port);
  if (s->client_registry_id > 0) {
    registry_remove(s->client_registry_id);
  }

  /* Zeroize sensitive session data */
  explicit_bzero(s->session_key, sizeof(s->session_key));
  explicit_bzero(s->sig, sizeof(s->sig));
  explicit_bzero(s->auth_ctx, SESSION_ID_BYTES);
  explicit_bzero(s->auth_ctx + SESSION_ID_BYTES + DSA_PK_BYTES, KEM_SS_BYTES);

  s->state = SESSION_FREE;
  s->generation++;
  g_free_sessions[g_free_session_count++] = (uint32_t)idx;
}

/* ── Rate Limiter ────────────────────────────────────────────────── */
typedef struct {
  uint32_t ip;
  uint16_t port;
  double tokens;
  uint64_t last_update_ns;
  int occupied;
} rate_limit_entry_t;

static rate_limit_entry_t g_rate_limit_table[RATE_LIMIT_HASH_SIZE];
static int g_disable_rate_limit = 0;

static inline uint32_t rate_limit_hash(uint32_t ip, uint16_t port) {
  uint32_t h = session_hash(ip, port);
  return h % RATE_LIMIT_HASH_SIZE;
}

static int rate_limit_check(uint32_t ip, uint16_t port) {
  if (g_disable_rate_limit) {
    return 1;
  }
  uint32_t host_ip = ntohl(ip);
  if ((host_ip >> 24) == 127) {
    return 1;
  }
  uint32_t h = rate_limit_hash(ip, port);
  uint64_t now = now_ns();
  for (int i = 0; i < 8; i++) {
    int slot = (int)((h + (uint32_t)i) % RATE_LIMIT_HASH_SIZE);
    rate_limit_entry_t *e = &g_rate_limit_table[slot];
    if (!e->occupied || (e->ip == ip && e->port == port)) {
      if (!e->occupied || (e->ip != ip || e->port != port)) {
        e->ip = ip;
        e->port = port;
        e->tokens = 20.0; /* Burst allowance of 20 */
        e->last_update_ns = now;
        e->occupied = 1;
        return 1;
      }
      double elapsed_sec = (double)(now - e->last_update_ns) / 1e9;
      e->tokens += elapsed_sec * 50.0; /* 50 packets per second refill rate */
      if (e->tokens > 20.0)
        e->tokens = 20.0;
      e->last_update_ns = now;
      if (e->tokens >= 1.0) {
        e->tokens -= 1.0;
        return 1;
      }
      return 0;
    }
  }
  return 1;
}

/* ── io_uring Recv Buffers ───────────────────────────────────────── */
typedef struct {
  uint8_t buffer[PKT_BUF_MAX];
  struct sockaddr_in peer_addr;
  struct iovec iov;
  struct msghdr msg;
  int idx;
} recv_buf_t;

static recv_buf_t g_recv_bufs[NUM_RECV_BUFFERS];
static struct io_uring g_ring;

static void submit_recv_request(int idx) {
  struct io_uring_sqe *sqe = io_uring_get_sqe(&g_ring);
  if (!sqe) {
    io_uring_submit(&g_ring);
    sqe = io_uring_get_sqe(&g_ring);
    if (!sqe)
      return;
  }
  io_uring_prep_recvmsg(sqe, g_listen_sock, &g_recv_bufs[idx].msg, 0);
  io_uring_sqe_set_data(sqe, (void *)(intptr_t)idx);
}

/* ── Thread-Safe Outbound Send ───────────────────────────────────── */
static ssize_t server_send_packet(int sock, const struct sockaddr_in *peer,
                                  uint32_t seq, uint8_t type,
                                  const uint8_t *payload,
                                  uint16_t payload_len) {
  static uint8_t wire[PKT_HDR_BYTES + 8192];
  pkt_hdr_t hdr;
  hdr.seq = htonl(seq);
  hdr.type = type;
  hdr.len = htons(payload_len);

  pthread_mutex_lock(&g_sock_send_mu);
  memcpy(wire, &hdr, PKT_HDR_BYTES);
  if (payload_len > 0) {
    memcpy(wire + PKT_HDR_BYTES, payload, payload_len);
  }
  ssize_t n = sendto(sock, wire, PKT_HDR_BYTES + payload_len, 0,
                     (const struct sockaddr *)peer, sizeof(*peer));
  pthread_mutex_unlock(&g_sock_send_mu);
  return n;
}

static ssize_t server_send_packet_zero_copy(int sock,
                                            const struct sockaddr_in *peer,
                                            uint32_t seq, uint8_t type,
                                            const struct iovec *iovs,
                                            int iov_cnt) {
  pkt_hdr_t hdr;
  hdr.seq = htonl(seq);
  hdr.type = type;

  uint16_t payload_len = 0;
  for (int i = 0; i < iov_cnt; i++) {
    payload_len += iovs[i].iov_len;
  }
  hdr.len = htons(payload_len);

  struct iovec msg_iov[iov_cnt + 1];
  msg_iov[0].iov_base = &hdr;
  msg_iov[0].iov_len = PKT_HDR_BYTES;
  for (int i = 0; i < iov_cnt; i++) {
    msg_iov[i + 1] = iovs[i];
  }

  struct msghdr msg = {0};
  msg.msg_name = (void *)peer;
  msg.msg_namelen = sizeof(*peer);
  msg.msg_iov = msg_iov;
  msg.msg_iovlen = iov_cnt + 1;

  pthread_mutex_lock(&g_sock_send_mu);
  ssize_t n = sendmsg(sock, &msg, 0);
  pthread_mutex_unlock(&g_sock_send_mu);
  return n;
}

static void server_send_ack(int sock, const struct sockaddr_in *peer,
                            uint32_t ack_seq) {
  uint8_t pl[4];
  pl[0] = (ack_seq >> 24) & 0xFF;
  pl[1] = (ack_seq >> 16) & 0xFF;
  pl[2] = (ack_seq >> 8) & 0xFF;
  pl[3] = ack_seq & 0xFF;
  server_send_packet(sock, peer, 0, PKT_ACK, pl, 4);
}

/* ── IPC helper wrappers ─────────────────────────────────────────── */
static void ipc_push_rx_msg(int cid, const char *ip, uint16_t port,
                            uint64_t sid, const uint8_t *msg,
                            uint32_t msg_len) {
  pthread_mutex_lock(&g_ipc_rx_mu);
  if (g_ipc_rx_fd < 0) {
    pthread_mutex_unlock(&g_ipc_rx_mu);
    return;
  }

  uint8_t buf[sizeof(ipc_rx_payload_t) + DATA_CHUNK_MAX];
  ipc_rx_payload_t *p = (ipc_rx_payload_t *)buf;
  p->client_id = (uint16_t)cid;
  strncpy(p->ip_str, ip, sizeof(p->ip_str) - 1);
  p->ip_str[sizeof(p->ip_str) - 1] = '\0';
  p->port = port;
  p->session_id = sid;
  p->msg_len = msg_len;
  if (msg_len <= DATA_CHUNK_MAX)
    memcpy(buf + sizeof(ipc_rx_payload_t), msg, msg_len);

  ipc_send_frame(g_ipc_rx_fd, IPC_MSG_RX, (uint16_t)cid, buf,
                 (uint32_t)(sizeof(ipc_rx_payload_t) + msg_len));
  pthread_mutex_unlock(&g_ipc_rx_mu);
}

static void ipc_push_rx_metrics(int cid, float dec_us, float ia_ms,
                                float jitter, float avg_dec,
                                uint64_t bytes_recv, uint32_t seq) {
  pthread_mutex_lock(&g_ipc_rx_mu);
  if (g_ipc_rx_fd < 0) {
    pthread_mutex_unlock(&g_ipc_rx_mu);
    return;
  }

  ipc_metrics_rx_t m = {0};
  m.client_id = (uint16_t)cid;
  m.decrypt_us = dec_us;
  m.interarrival_ms = ia_ms;
  m.jitter_ms = jitter;
  m.avg_decrypt_us = avg_dec;
  m.bytes_recv = bytes_recv;
  m.pkt_seq = seq;
  ipc_send_frame(g_ipc_rx_fd, IPC_METRICS_RX, (uint16_t)cid, &m, sizeof(m));
  pthread_mutex_unlock(&g_ipc_rx_mu);
}

static void ipc_push_client_list(void) {
  pthread_mutex_lock(&g_ipc_tx_mu);
  if (g_ipc_tx_fd < 0) {
    pthread_mutex_unlock(&g_ipc_tx_mu);
    return;
  }

  client_info_t infos[MAX_CLIENTS];
  int cnt = registry_get_snapshot(infos, MAX_CLIENTS);

  size_t sz = sizeof(uint16_t) + (size_t)cnt * sizeof(ipc_client_entry_t);
  uint8_t *buf = malloc(sz);
  if (!buf) {
    pthread_mutex_unlock(&g_ipc_tx_mu);
    return;
  }

  uint16_t c16 = (uint16_t)cnt;
  memcpy(buf, &c16, sizeof(c16));
  ipc_client_entry_t *e = (ipc_client_entry_t *)(buf + sizeof(uint16_t));
  for (int i = 0; i < cnt; i++) {
    e[i].client_id = (uint16_t)infos[i].client_id;
    memcpy(e[i].ip_str, infos[i].ip_str, sizeof(e[i].ip_str));
    e[i].port = infos[i].port;
    e[i].session_id = infos[i].session_id;
    e[i].hs_total_ms = (float)infos[i].hs_total_ms;
    e[i].msg_count = (uint32_t)infos[i].msg_count;
    e[i].bytes_sent_kb = (uint32_t)(infos[i].bytes_sent / 1024);
    e[i].bytes_recv_kb = (uint32_t)(infos[i].bytes_recv / 1024);
  }
  ipc_send_frame(g_ipc_tx_fd, IPC_CLIENT_LIST, 0, buf, (uint32_t)sz);
  free(buf);
  pthread_mutex_unlock(&g_ipc_tx_mu);
}

#include <sys/resource.h>

/* CPU ticks stats for server CPU utilization */
typedef struct {
  unsigned long long user, nice, system, idle, iowait, irq, softirq, steal;
} server_cpu_ticks_t;

static server_cpu_ticks_t g_server_cpu_start, g_server_cpu_end;

static int get_server_cpu_ticks(server_cpu_ticks_t *ticks) {
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

static double calculate_server_cpu_util(const server_cpu_ticks_t *start,
                                        const server_cpu_ticks_t *end) {
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

static double get_server_peak_ram(void) {
  struct rusage usage;
  if (getrusage(RUSAGE_SELF, &usage) == 0) {
    return (double)usage.ru_maxrss / 1024.0;
  }
  return 0.0;
}

static double read_server_cpu_temp(void) {
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

/* Telemetry arrays */
#define MAX_TELEMETRY_SAMPLES 100000
static double g_queue_wait_samples[MAX_TELEMETRY_SAMPLES];
static double g_crypto_proc_samples[MAX_TELEMETRY_SAMPLES];
static int g_telemetry_sample_count = 0;
static pthread_mutex_t g_telemetry_mu = PTHREAD_MUTEX_INITIALIZER;

/* Worker busy times */
static uint64_t g_worker_busy_ns[4] = {0}; // index 1 to 3
static uint64_t g_server_start_ns = 0;

/* Temperature stats */
static double g_temp_sum = 0.0;
static double g_temp_peak = 0.0;
static int g_temp_samples = 0;
static uint64_t g_last_temp_sample_ns = 0;

static void sample_temp_if_needed(void) {
  uint64_t now = now_ns();
  if (now - g_last_temp_sample_ns >= 1000000000ULL) { // 1 second
    double temp = read_server_cpu_temp();
    if (temp > 0.0) {
      g_temp_sum += temp;
      g_temp_samples++;
      if (temp > g_temp_peak) {
        g_temp_peak = temp;
      }
    }
    g_last_temp_sample_ns = now;
  }
}

static int compare_telemetry_doubles(const void *a, const void *b) {
  double da = *(const double *)a;
  double db = *(const double *)b;
  return (da > db) - (da < db);
}

typedef struct {
  double mean;
  double median;
  double min;
  double max;
  double p95;
  double p99;
  double stddev;
} server_stats_t;

static void compute_server_stats(double *samples, int n, server_stats_t *out) {
  if (n <= 0) {
    memset(out, 0, sizeof(*out));
    return;
  }
  qsort(samples, n, sizeof(double), compare_telemetry_doubles);
  out->min = samples[0];
  out->max = samples[n - 1];

  double sum = 0.0;
  for (int i = 0; i < n; i++)
    sum += samples[i];
  out->mean = sum / n;

  if (n % 2 == 1) {
    out->median = samples[n / 2];
  } else {
    out->median = (samples[n / 2 - 1] + samples[n / 2]) / 2.0;
  }
  out->p95 = samples[(int)(n * 0.95)];
  out->p99 = samples[(int)(n * 0.99)];

  double sum_sq_diff = 0.0;
  for (int i = 0; i < n; i++) {
    double diff = samples[i] - out->mean;
    sum_sq_diff += diff * diff;
  }
  out->stddev = sqrt(sum_sq_diff / n);
}

/* ── Crypto Worker Threads ───────────────────────────────────────── */
static void *crypto_worker_thread(void *arg) {
  int core_id = (int)(intptr_t)arg;
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(core_id, &cpuset);
  pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

  int idle_spin = 0;
  while (!g_stop) {
    crypto_job_t job;
    if (pop_job(&job) == 0) {
      idle_spin = 0;

      /* Consume semaphore token */
      sem_trywait(&g_job_sem);

      uint64_t t_popped = now_ns();
      uint64_t wait_ns = t_popped - job.enqueue_ns;

      crypto_completion_t comp;
      comp.job_id = job.job_id;
      comp.session_id = job.session_id;
      comp.generation = job.generation;
      comp.type = job.type;
      comp.status = -1;

      if (job.type == PKT_CLIENT_HELLO) {
        int rc = kem_enc(job.kem_ct, job.session_key, job.client_kem_pk);
        if (rc == 0) {
          size_t tx_len = 16 + 16 + SESSION_ID_BYTES + KEM_PK_BYTES +
                          DSA_PK_BYTES + DSA_PK_BYTES + KEM_CT_BYTES;
          uint8_t *tx = malloc(tx_len);
          if (tx) {
            size_t tx_off = 0;
            memcpy(tx + tx_off, job.client_nonce, 16);
            tx_off += 16;
            memcpy(tx + tx_off, job.server_nonce, 16);
            tx_off += 16;

            uint64_t sid64 = job.session_id_val;
            for (int k = 0; k < SESSION_ID_BYTES; k++) {
              tx[tx_off + k] =
                  (sid64 >> ((SESSION_ID_BYTES - 1 - k) * 8)) & 0xFF;
            }
            tx_off += SESSION_ID_BYTES;

            memcpy(tx + tx_off, job.client_kem_pk, KEM_PK_BYTES);
            tx_off += KEM_PK_BYTES;
            memcpy(tx + tx_off, job.client_dsa_pk, DSA_PK_BYTES);
            tx_off += DSA_PK_BYTES;
            memcpy(tx + tx_off, g_srv_dsa_pk, DSA_PK_BYTES);
            tx_off += DSA_PK_BYTES;
            memcpy(tx + tx_off, job.kem_ct, KEM_CT_BYTES);

            uint8_t digest[64];
            if (shake256_hash(digest, tx, tx_len) == 0) {
              size_t siglen = 0;
              rc = dsa_sign(job.srv_sig, &siglen, digest, 64, g_srv_dsa_sk);
            } else {
              rc = -1;
            }
            free(tx);
          } else {
            rc = -1;
          }
        }
        comp.status = rc;
      } else if (job.type == PKT_CLIENT_AUTH) {
        size_t tx_len = 16 + 16 + SESSION_ID_BYTES + KEM_PK_BYTES +
                        DSA_PK_BYTES + DSA_PK_BYTES + KEM_CT_BYTES;
        size_t cl_tx_len = tx_len + DSA_SIG_BYTES;
        uint8_t *cl_tx = malloc(cl_tx_len);
        int rc = -1;
        if (cl_tx) {
          size_t tx_off = 0;
          memcpy(cl_tx + tx_off, job.client_nonce, 16);
          tx_off += 16;
          memcpy(cl_tx + tx_off, job.server_nonce, 16);
          tx_off += 16;

          uint64_t sid64 = job.session_id_val;
          for (int k = 0; k < SESSION_ID_BYTES; k++) {
            cl_tx[tx_off + k] =
                (sid64 >> ((SESSION_ID_BYTES - 1 - k) * 8)) & 0xFF;
          }
          tx_off += SESSION_ID_BYTES;

          memcpy(cl_tx + tx_off, job.client_kem_pk, KEM_PK_BYTES);
          tx_off += KEM_PK_BYTES;
          memcpy(cl_tx + tx_off, job.client_dsa_pk, DSA_PK_BYTES);
          tx_off += DSA_PK_BYTES;
          memcpy(cl_tx + tx_off, g_srv_dsa_pk, DSA_PK_BYTES);
          tx_off += DSA_PK_BYTES;
          memcpy(cl_tx + tx_off, job.kem_ct, KEM_CT_BYTES);
          tx_off += KEM_CT_BYTES;
          memcpy(cl_tx + tx_off, job.srv_sig, DSA_SIG_BYTES);

          uint8_t digest[64];
          if (shake256_hash(digest, cl_tx, cl_tx_len) == 0) {
            rc =
                dsa_verify(job.sig, job.sig_len, digest, 64, job.client_dsa_pk);
          }
          free(cl_tx);
        }
        comp.status = rc;
      }

      uint64_t t_done = now_ns();
      uint64_t proc_ns = t_done - t_popped;

      if (core_id >= 1 && core_id <= 3) {
        __atomic_fetch_add(&g_worker_busy_ns[core_id], proc_ns,
                           __ATOMIC_RELAXED);
      }

      pthread_mutex_lock(&g_telemetry_mu);
      if (g_telemetry_sample_count < MAX_TELEMETRY_SAMPLES) {
        g_queue_wait_samples[g_telemetry_sample_count] =
            (double)wait_ns / 1000.0;
        g_crypto_proc_samples[g_telemetry_sample_count] =
            (double)proc_ns / 1000.0;
        g_telemetry_sample_count++;
      }
      pthread_mutex_unlock(&g_telemetry_mu);

      int worker_idx = core_id - 1;
      while (push_worker_completion(worker_idx, &comp) != 0) {
        cpu_pause();
      }
    } else {
      if (++idle_spin > 1000) {
        sem_wait(&g_job_sem);
        idle_spin = 0;
      } else {
        cpu_pause();
      }
    }
  }
  return NULL;
}

/* ── IPC acceptor threads (Warm Path) ────────────────────────────── */
static void *ipc_rx_accept_thread(void *arg) {
  int lfd = *(int *)arg;
  free(arg);
  while (!g_stop) {
    int fd = accept(lfd, NULL, NULL);
    if (fd < 0) {
      if (g_stop)
        break;
      usleep(100000);
      continue;
    }
    printf("[server] server_rx connected\n");
    pthread_mutex_lock(&g_ipc_rx_mu);
    if (g_ipc_rx_fd >= 0)
      close(g_ipc_rx_fd);
    g_ipc_rx_fd = fd;
    pthread_mutex_unlock(&g_ipc_rx_mu);
  }
  close(lfd);
  return NULL;
}

static void *ipc_tx_rx_loop(void *arg) {
  int fd = (int)(intptr_t)arg;
  uint8_t buf[sizeof(ipc_tx_cmd_t) + DATA_CHUNK_MAX + 64];
  char ts[16];

  while (!g_stop) {
    ipc_hdr_t hdr;
    ssize_t n = ipc_recv_frame(fd, &hdr, buf, sizeof(buf));
    if (n < 0)
      break;

    if (hdr.type == IPC_MSG_TX_CMD) {
      if (n < (ssize_t)sizeof(ipc_tx_cmd_t))
        continue;
      ipc_tx_cmd_t *cmd = (ipc_tx_cmd_t *)buf;
      uint32_t msg_len = cmd->msg_len;
      uint16_t target = cmd->client_id;
      const uint8_t *msg = buf + sizeof(ipc_tx_cmd_t);
      if (msg_len == 0 || msg_len > DATA_CHUNK_MAX)
        continue;

      now_hms(ts, sizeof(ts));
      if (target == 0) {
        int ok = registry_broadcast(msg, msg_len);
        printf("[%s] BROADCAST → %d client(s): %.*s\n", ts, ok, (int)msg_len,
               msg);
      } else {
        if (registry_send((int)target, msg, msg_len) == 0) {
          printf("[%s] TX → CLIENT-%02d: %.*s\n", ts, target, (int)msg_len,
                 msg);

          metrics_t *m = registry_get_metrics((int)target);
          if (m) {
            ipc_metrics_tx_t mt = {0};
            mt.client_id = target;
            mt.encrypt_us =
                (m->encrypt_count > 0)
                    ? (float)(m->total_encrypt_us / (double)m->encrypt_count)
                    : 0.f;
            mt.avg_encrypt_us = mt.encrypt_us;
            mt.bytes_sent = m->bytes_sent;
            mt.msg_count = (uint32_t)m->msg_count;
            mt.retransmissions = (uint32_t)m->retransmissions;
            pthread_mutex_lock(&g_ipc_tx_mu);
            ipc_send_frame(fd, IPC_METRICS_TX, target, &mt, sizeof(mt));
            pthread_mutex_unlock(&g_ipc_tx_mu);
          }
        } else {
          fprintf(stderr, "[server] TX to CLIENT-%02d failed\n", target);
        }
      }
      ipc_push_client_list();
    }
  }
  pthread_mutex_lock(&g_ipc_tx_mu);
  if (g_ipc_tx_fd == fd)
    g_ipc_tx_fd = -1;
  pthread_mutex_unlock(&g_ipc_tx_mu);
  close(fd);
  printf("[server] server_tx disconnected\n");
  return NULL;
}

static void *ipc_tx_accept_thread(void *arg) {
  int lfd = *(int *)arg;
  free(arg);
  while (!g_stop) {
    int fd = accept(lfd, NULL, NULL);
    if (fd < 0) {
      if (g_stop)
        break;
      usleep(100000);
      continue;
    }
    printf("[server] server_tx connected\n");
    pthread_mutex_lock(&g_ipc_tx_mu);
    if (g_ipc_tx_fd >= 0)
      close(g_ipc_tx_fd);
    g_ipc_tx_fd = fd;
    pthread_mutex_unlock(&g_ipc_tx_mu);

    pthread_t tid;
    pthread_create(&tid, NULL, ipc_tx_rx_loop, (void *)(intptr_t)fd);
    pthread_detach(tid);
  }
  close(lfd);
  return NULL;
}

static int make_ipc_server(const char *path) {
  unlink(path);
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    perror("socket(ipc)");
    return -1;
  }
  struct sockaddr_un a = {0};
  a.sun_family = AF_UNIX;
  strncpy(a.sun_path, path, sizeof(a.sun_path) - 1);
  if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0) {
    perror("bind(ipc)");
    close(fd);
    return -1;
  }
  if (listen(fd, 4) < 0) {
    perror("listen(ipc)");
    close(fd);
    return -1;
  }
  return fd;
}

/* ── Main Loop and State Processing ──────────────────────────────── */
static void process_completion(const crypto_completion_t *comp) {
  uint32_t s_idx = comp->session_id;
  if (s_idx >= MAX_SESSIONS)
    return;

  session_t *s = &g_sessions[s_idx];
  if (s->state == SESSION_FREE || s->generation != comp->generation ||
      s->current_job_id != comp->job_id) {
    return; /* Ignore stale job completions */
  }

  struct sockaddr_in peer;
  peer.sin_family = AF_INET;
  peer.sin_port = s->port;
  peer.sin_addr.s_addr = s->ip;

  if (comp->type == PKT_CLIENT_HELLO) {
    if (s->state != SESSION_WAIT_KEM_ENC)
      return;

    if (comp->status != 0) {
      session_free(s_idx);
      return;
    }

    /* Derive key using KDF bound to nonces and session ID */
    uint8_t derived_key[DERIVED_KEY_BYTES];
    kem_derive_key(derived_key, s->session_key, s->client_nonce,
                   s->server_nonce, s->session_id_val);
    memcpy(s->session_key, derived_key, 32);
    explicit_bzero(derived_key, sizeof(derived_key));

    struct iovec iovs[5];
    iovs[0].iov_base = g_srv_dsa_pk;
    iovs[0].iov_len = DSA_PK_BYTES;
    iovs[1].iov_base = s->kem_ct;
    iovs[1].iov_len = KEM_CT_BYTES;

    uint8_t sid_buf[SESSION_ID_BYTES];
    uint64_t sid64 = s->session_id_val;
    for (int k = 0; k < SESSION_ID_BYTES; k++) {
      sid_buf[k] = (sid64 >> ((SESSION_ID_BYTES - 1 - k) * 8)) & 0xFF;
    }
    iovs[2].iov_base = sid_buf;
    iovs[2].iov_len = SESSION_ID_BYTES;
    iovs[3].iov_base = s->server_nonce;
    iovs[3].iov_len = 16;
    iovs[4].iov_base = s->srv_sig;
    iovs[4].iov_len = DSA_SIG_BYTES;

    s->state = SESSION_WAIT_AUTH;
    s->last_seen_ns = now_ns();

    server_send_packet_zero_copy(g_listen_sock, &peer, s->tx_seq,
                                 PKT_SERVER_HELLO, iovs, 5);
  } else if (comp->type == PKT_CLIENT_AUTH) {
    if (s->state != SESSION_WAIT_AUTH_VER)
      return;

    if (comp->status != 0) {
      session_free(s_idx);
      return;
    }

    conn_t c = {0};
    c.sock = g_listen_sock;
    c.peer = peer;
    c.peer_len = sizeof(peer);
    c.tx_seq = s->tx_seq;
    c.established = 1;
    memcpy(c.session_key, s->session_key, KEM_SS_BYTES);
    c.session_id = s->session_id_val;

    s->metrics.hs_total_ms = (double)(now_ns() - s->last_seen_ns) / 1e6;
    int cid = registry_add(&c, &s->metrics);
    if (cid < 0) {
      session_free(s_idx);
      return;
    }

    s->client_registry_id = cid;
    s->state = SESSION_ESTABLISHED;
    s->established_time_ns = now_ns();
    s->last_seen_ns = now_ns();

    server_send_ack(g_listen_sock, &peer, s->auth_seq);

    ipc_push_client_list();
    pthread_mutex_lock(&g_ipc_tx_mu);
    if (g_ipc_tx_fd >= 0) {
      ipc_client_entry_t ce = {0};
      ce.client_id = (uint16_t)cid;
      char ip_str[16];
      inet_ntop(AF_INET, &peer.sin_addr, ip_str, sizeof(ip_str));
      strncpy(ce.ip_str, ip_str, sizeof(ce.ip_str) - 1);
      ce.port = ntohs(peer.sin_port);
      ce.session_id = s->session_id_val;
      ce.hs_total_ms = (float)s->metrics.hs_total_ms;
      ipc_send_frame(g_ipc_tx_fd, IPC_CLIENT_CONNECT, (uint16_t)cid, &ce,
                     sizeof(ce));
    }
    pthread_mutex_unlock(&g_ipc_tx_mu);

    char ip_str[16];
    inet_ntop(AF_INET, &peer.sin_addr, ip_str, sizeof(ip_str));
    char ts[16];
    now_hms(ts, sizeof(ts));
    printf("[%s] \033[1;32m✓ CLIENT-%02d\033[0m  %s:%u  SID=%016llx  HS=%.3fms "
           " Active=%d\n\n",
           ts, cid, ip_str, ntohs(peer.sin_port),
           (unsigned long long)s->session_id_val, s->metrics.hs_total_ms,
           registry_count());
  }
}

static void sweep_timeouts(void) {
  static uint64_t last_sweep_ns = 0;
  uint64_t now = now_ns();
  if (now - last_sweep_ns < 1000000000ULL)
    return; /* Sweep once a second */
  last_sweep_ns = now;

  for (int i = 0; i < MAX_SESSIONS; i++) {
    session_t *s = &g_sessions[i];
    if (s->state == SESSION_FREE)
      continue;

    uint64_t elapsed_ns = now - s->last_seen_ns;
    if (s->state == SESSION_ESTABLISHED) {
      if (elapsed_ns > 60000000000ULL) { /* 60 seconds timeout */
        char ip_str[16];
        inet_ntop(AF_INET, &s->ip, ip_str, sizeof(ip_str));
        char ts[16];
        now_hms(ts, sizeof(ts));
        printf("[%s] Client timeout: %s:%u\n", ts, ip_str, ntohs(s->port));

        int cid = s->client_registry_id;
        session_free(i);

        ipc_push_client_list();
        pthread_mutex_lock(&g_ipc_tx_mu);
        if (g_ipc_tx_fd >= 0) {
          ipc_send_frame(g_ipc_tx_fd, IPC_CLIENT_DISCONNECT, (uint16_t)cid,
                         NULL, 0);
        }
        pthread_mutex_unlock(&g_ipc_tx_mu);
      }
    } else {
      if (elapsed_ns > 5000000000ULL) { /* 5 seconds handshake timeout */
        session_free(i);
      }
    }
  }
}

static void server_print_bench_report(void) {
  get_server_cpu_ticks(&g_server_cpu_end);
  uint64_t uptime_ns = now_ns() - g_server_start_ns;
  double uptime_ms = (double)uptime_ns / 1000000.0;

  double cpu_util =
      calculate_server_cpu_util(&g_server_cpu_start, &g_server_cpu_end);
  double peak_ram = get_server_peak_ram();

  server_stats_t wait_stats, proc_stats;
  pthread_mutex_lock(&g_telemetry_mu);
  int n_samples = g_telemetry_sample_count;
  compute_server_stats(g_queue_wait_samples, n_samples, &wait_stats);
  compute_server_stats(g_crypto_proc_samples, n_samples, &proc_stats);
  pthread_mutex_unlock(&g_telemetry_mu);

  printf("\n");
  printf("====================================================================="
         "====\n");
  printf("                  PQC SERVER BENCHMARK REPORT                        "
         "    \n");
  printf("====================================================================="
         "====\n\n");

  /* TABLE 12 — Queuing Latency Breakdown */
  printf("┌────────────────────────────────────────────────────────────────────"
         "─────┐\n");
  printf("│ TABLE 12 — Queuing & Processing Latency Breakdown (%-6d samples)   "
         "    │\n",
         n_samples);
  printf("├──────────────────────┬─────────────────────────┬───────────────────"
         "─────┤\n");
  printf("│ Metric               │ Queue Wait Time (µs)    │ Crypto Processing "
         "(µs) │\n");
  printf("├──────────────────────┼─────────────────────────┼───────────────────"
         "─────┤\n");
  printf("│ Mean                 │ %23.3f │ %22.3f │\n", wait_stats.mean,
         proc_stats.mean);
  printf("│ Median               │ %23.3f │ %22.3f │\n", wait_stats.median,
         proc_stats.median);
  printf("│ Minimum              │ %23.3f │ %22.3f │\n", wait_stats.min,
         proc_stats.min);
  printf("│ Maximum              │ %23.3f │ %22.3f │\n", wait_stats.max,
         proc_stats.max);
  printf("│ 95th Percentile      │ %23.3f │ %22.3f │\n", wait_stats.p95,
         proc_stats.p95);
  printf("│ 99th Percentile      │ %23.3f │ %22.3f │\n", wait_stats.p99,
         proc_stats.p99);
  printf("│ Standard Deviation   │ %23.3f │ %22.3f │\n", wait_stats.stddev,
         proc_stats.stddev);
  printf("└──────────────────────┴─────────────────────────┴───────────────────"
         "─────┘\n\n");

  /* TABLE 13 — Worker Core Utilization */
  printf("┌────────────────────────────────────────────────────────────────────"
         "─────┐\n");
  printf("│ TABLE 13 — Worker Thread Core Utilization                          "
         "     │\n");
  printf("├──────────────────────┬─────────────────┬─────────────────┬─────────"
         "─────┤\n");
  printf("│ Worker Thread        │ Busy Time (ms)  │ Total Time (ms) │ Util "
         "(%%)     │\n");
  printf("├──────────────────────┼─────────────────┼─────────────────┼─────────"
         "─────┤\n");
  for (int i = 1; i <= NUM_WORKERS; i++) {
    double busy_ms = (double)g_worker_busy_ns[i] / 1000000.0;
    double util_pct = (uptime_ms > 0.0) ? (busy_ms / uptime_ms * 100.0) : 0.0;
    printf("│ Worker %d (Core %d)    │ %15.3f │ %15.3f │ %11.2f%% │\n", i, i,
           busy_ms, uptime_ms, util_pct);
  }
  printf("└──────────────────────┴─────────────────┴─────────────────┴─────────"
         "─────┘\n\n");

  /* TABLE 14 — CPU Temperature */
  double avg_temp = (g_temp_samples > 0) ? (g_temp_sum / g_temp_samples) : 0.0;
  printf("┌────────────────────────────────────────────────────────────────────"
         "─────┐\n");
  printf("│ TABLE 14 — Server CPU Temperature Profile                          "
         "     │\n");
  printf("├─────────────────────────────────────────┬──────────────────────────"
         "─────┤\n");
  printf("│ Metric                                  │ Value                    "
         "     │\n");
  printf("├─────────────────────────────────────────┼──────────────────────────"
         "─────┤\n");
  if (g_temp_samples > 0) {
    printf("│ Average Temperature                     │ %25.1f °C              "
           "       │\n",
           avg_temp);
    printf("│ Peak Temperature                        │ %25.1f °C              "
           "       │\n",
           g_temp_peak);
  } else {
    printf("│ Average Temperature                     │ %29s │\n",
           "N/A (No thermal data)");
    printf("│ Peak Temperature                        │ %29s │\n",
           "N/A (No thermal data)");
  }
  printf("└─────────────────────────────────────────┴──────────────────────────"
         "─────┘\n\n");

  /* TABLE 19 — Server CPU & Memory Utilization */
  printf("┌────────────────────────────────────────────────────────────────────"
         "─────┐\n");
  printf("│ TABLE 19 — Server CPU & Memory Utilization                         "
         "     │\n");
  printf("├─────────────────────────────────────────┬──────────────────────────"
         "─────┤\n");
  printf("│ Metric                                  │ Value                    "
         "     │\n");
  printf("├─────────────────────────────────────────┼──────────────────────────"
         "─────┤\n");
  printf("│ Server CPU Utilization                  │ %27.2f%%                 "
         "   │\n",
         cpu_util);
  printf("│ Server Peak RSS Memory                  │ %25.3f MB                "
         "   │\n",
         peak_ram);
  printf("└─────────────────────────────────────────┴──────────────────────────"
         "─────┘\n\n");

  /* TABLE 20 — Thread Core Mapping */
  printf("┌────────────────────────────────────────────────────────────────────"
         "─────┐\n");
  printf("│ TABLE 20 — Thread Core Mapping (Affinity)                          "
         "     │\n");
  printf("├─────────────────────────────────────────┬──────────────┬───────────"
         "─────┤\n");
  printf("│ Thread                                  │ Target Core  │ Role      "
         "     │\n");
  printf("├─────────────────────────────────────────┼──────────────┼───────────"
         "─────┤\n");
  printf("│ Main Event Thread                       │ Core 0       │ Network "
         "I/O    │\n");
  printf("│ Worker Thread 1                         │ Core 1       │ "
         "Cryptography   │\n");
  printf("│ Worker Thread 2                         │ Core 2       │ "
         "Cryptography   │\n");
  printf("│ Worker Thread 3                         │ Core 3       │ "
         "Cryptography   │\n");
  printf("└─────────────────────────────────────────┴──────────────┴───────────"
         "─────┘\n\n");
}

int main(void) {
  signal(SIGINT, on_signal);
  signal(SIGTERM, on_signal);
  signal(SIGPIPE, SIG_IGN);

  g_server_start_ns = now_ns();
  get_server_cpu_ticks(&g_server_cpu_start);

  /* Pin main network thread to Core 0 */
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(0, &cpuset);
  sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);

  char ts[16];
  now_hms(ts, sizeof(ts));
  printf("[%s] High-Performance Asynchronous io_uring PQC Server\n", ts);
  printf("  Protocol : ML-KEM-768 + ML-DSA-65 + ChaCha20-Poly1305\n");
  printf("  Address  : 0.0.0.0:%d  |  Max clients: %d\n\n", SERVER_PORT,
         MAX_CLIENTS);

  registry_init();

  /* Generate identity keypairs */
  double dsa_t0 = now_ms();
  if (dsa_keypair(g_srv_dsa_pk, g_srv_dsa_sk) != 0) {
    fprintf(stderr, "[server] DSA keygen failed\n");
    return 1;
  }
  g_dsa_keygen_ms = now_ms() - dsa_t0;

  /* Ephemeral KEM keypair generation removed (dead field) */

  /* Warm up cryptographic operations on the server */
  {
    uint8_t d_kem_pk[KEM_PK_BYTES], d_kem_sk[KEM_SK_BYTES];
    uint8_t d_kem_ct[KEM_CT_BYTES], d_kem_ss[KEM_SS_BYTES];
    uint8_t d_dsa_pk[DSA_PK_BYTES], d_dsa_sk[DSA_SK_BYTES];
    uint8_t d_sig[DSA_SIG_BYTES];
    size_t d_siglen = 0;
    uint8_t d_ctx[64] = {0};

    kem_keypair(d_kem_pk, d_kem_sk);
    kem_enc(d_kem_ct, d_kem_ss, d_kem_pk);
    kem_dec(d_kem_ss, d_kem_ct, d_kem_sk);

    dsa_keypair(d_dsa_pk, d_dsa_sk);
    dsa_sign(d_sig, &d_siglen, d_ctx, sizeof(d_ctx), d_dsa_sk);
    dsa_verify(d_sig, d_siglen, d_ctx, sizeof(d_ctx), d_dsa_pk);
  }

  printf("  DSA keygen : %.3f ms (long-term identity)\n", g_dsa_keygen_ms);

  /* Initialize session allocations */
  for (int i = 0; i < MAX_SESSIONS; i++) {
    g_sessions[i].state = SESSION_FREE;
    g_sessions[i].generation = 0;
    g_free_sessions[i] = (uint32_t)i;
    memcpy(g_sessions[i].auth_ctx + SESSION_ID_BYTES, g_srv_dsa_pk,
           DSA_PK_BYTES);
  }
  memset(g_session_hash, 0, sizeof(g_session_hash));
  memset(g_rate_limit_table, 0, sizeof(g_rate_limit_table));

  char *env_rl = getenv("PQC_DISABLE_RATE_LIMIT");
  if (env_rl && strcmp(env_rl, "1") == 0) {
    g_disable_rate_limit = 1;
    printf("  Rate limiting: DISABLED (via env var)\n");
  } else {
    printf("  Rate limiting: ENABLED (50 pkts/s, burst 20)\n");
  }

  /* Initialize queues */
  memset(&g_job_queue, 0, sizeof(g_job_queue));
  memset(g_worker_comp_queues, 0, sizeof(g_worker_comp_queues));
  sem_init(&g_job_sem, 0, 0);

  /* Spawn Crypto Worker Threads (Cores 1-3) */
  for (int i = 0; i < NUM_WORKERS; i++) {
    pthread_t tid;
    pthread_create(&tid, NULL, crypto_worker_thread, (void *)(intptr_t)(1 + i));
    pthread_detach(tid);
  }
  printf("  Crypto workers: %d threads spawned (pinned to Cores 1-3)\n",
         NUM_WORKERS);

  /* Start IPC servers */
  {
    int rx_lfd = make_ipc_server(IPC_RX_PATH);
    int tx_lfd = make_ipc_server(IPC_TX_PATH);
    if (rx_lfd < 0 || tx_lfd < 0)
      return 1;
    printf("  IPC RX : %s\n  IPC TX : %s\n\n", IPC_RX_PATH, IPC_TX_PATH);

    int *rp = malloc(sizeof(int));
    *rp = rx_lfd;
    int *tp = malloc(sizeof(int));
    *tp = tx_lfd;
    pthread_t rt, tt;
    pthread_create(&rt, NULL, ipc_rx_accept_thread, rp);
    pthread_create(&tt, NULL, ipc_tx_accept_thread, tp);
    pthread_detach(rt);
    pthread_detach(tt);
  }

  /* Initialize io_uring */
  g_listen_sock = make_server_sock();
  if (g_listen_sock < 0)
    return 1;

  struct io_uring_params params;
  memset(&params, 0, sizeof(params));
  if (io_uring_queue_init_params(4096, &g_ring, &params) < 0) {
    perror("io_uring_queue_init");
    return 1;
  }

  /* Submit initial receives */
  for (int i = 0; i < NUM_RECV_BUFFERS; i++) {
    g_recv_bufs[i].idx = i;
    g_recv_bufs[i].iov.iov_base = g_recv_bufs[i].buffer;
    g_recv_bufs[i].iov.iov_len = sizeof(g_recv_bufs[i].buffer);
    g_recv_bufs[i].msg.msg_name = &g_recv_bufs[i].peer_addr;
    g_recv_bufs[i].msg.msg_namelen = sizeof(g_recv_bufs[i].peer_addr);
    g_recv_bufs[i].msg.msg_iov = &g_recv_bufs[i].iov;
    g_recv_bufs[i].msg.msg_iovlen = 1;
    submit_recv_request(i);
  }
  io_uring_submit(&g_ring);

  printf("\033[1;32m╔══════════════════════════════════════════╗\033[0m\n");
  printf("\033[1;32m║  PQC Server — Multi-Client Mode          ║\033[0m\n");
  printf("\033[1;32m║  Run: ./server_rx  (receiver terminal)   ║\033[0m\n");
  printf("\033[1;32m║  Run: ./server_tx  (sender terminal)     ║\033[0m\n");
  printf("\033[1;32m╚══════════════════════════════════════════╝\033[0m\n\n");

  /* ── Main Network Event Loop ─────────────────────────────────── */
  int main_idle_spin = 0;
  while (!g_stop) {
    int worked = 0;
    /* 1. Process worker completions across all worker queues */
    for (int w = 0; w < NUM_WORKERS; w++) {
      crypto_completion_t comp;
      while (pop_worker_completion(w, &comp) == 0) {
        process_completion(&comp);
        worked = 1;
      }
    }

    /* 2. Poll io_uring CQ (non-blocking) */
    struct io_uring_cqe *cqe;
    unsigned head;
    int count = 0;
    io_uring_for_each_cqe(&g_ring, head, cqe) {
      int res = cqe->res;
      int buf_idx = (int)(intptr_t)io_uring_cqe_get_data(cqe);

      if (res >= PKT_HDR_BYTES) {
        uint8_t *pkt = g_recv_bufs[buf_idx].buffer;
        uint16_t pkt_len = (uint16_t)res;
        struct sockaddr_in *peer = &g_recv_bufs[buf_idx].peer_addr;
        uint32_t ip = peer->sin_addr.s_addr;
        uint16_t port = peer->sin_port;

        pkt_hdr_t hdr;
        memcpy(&hdr, pkt, PKT_HDR_BYTES);
        hdr.seq = ntohl(hdr.seq);
        hdr.len = ntohs(hdr.len);
        uint8_t *payload = pkt + PKT_HDR_BYTES;
        uint16_t payload_len = pkt_len - PKT_HDR_BYTES;

        int s_idx = session_hash_lookup(ip, port);
        if (s_idx < 0) {
          if (hdr.type == PKT_CLIENT_HELLO) {
            if (rate_limit_check(ip, port)) {
              unsigned long queue_load =
                  g_job_queue.tail - g_job_queue.head;
              if (queue_load >= (JOB_QUEUE_SIZE - 64)) {
                static uint64_t last_busy_ns = 0;
                uint64_t now = now_ns();
                if (now - last_busy_ns > 10000000ULL) {
                  last_busy_ns = now;
                  server_send_packet(g_listen_sock, peer, 0, PKT_BUSY, NULL, 0);
                }
              } else {
                if (payload_len >= KEM_PK_BYTES + DSA_PK_BYTES + 16) {
                  s_idx = session_alloc(ip, port);
                  if (s_idx >= 0) {
                    server_send_ack(g_listen_sock, peer, hdr.seq);
                    session_t *s = &g_sessions[s_idx];
                    s->state = SESSION_WAIT_KEM_ENC;
                    s->last_seen_ns = now_ns();
                    s->current_job_id++;

                    memcpy(s->client_kem_pk, payload, KEM_PK_BYTES);
                    memcpy(s->client_dsa_pk, payload + KEM_PK_BYTES,
                           DSA_PK_BYTES);
                    memcpy(s->client_nonce,
                           payload + KEM_PK_BYTES + DSA_PK_BYTES, 16);

                    RAND_bytes(s->server_nonce, 16);

                    uint8_t sid[SESSION_ID_BYTES];
                    RAND_bytes(sid, SESSION_ID_BYTES);
                    uint64_t sid64 = 0;
                    for (int i = 0; i < SESSION_ID_BYTES; i++) {
                      sid64 = (sid64 << 8) | sid[i];
                    }
                    s->session_id_val = sid64;

                    crypto_job_t job;
                    job.job_id = s->current_job_id;
                    job.session_id = (uint32_t)s_idx;
                    job.generation = s->generation;
                    job.type = PKT_CLIENT_HELLO;
                    job.client_kem_pk = s->client_kem_pk;
                    job.client_dsa_pk = s->client_dsa_pk;
                    job.client_nonce = s->client_nonce;
                    job.server_nonce = s->server_nonce;
                    job.session_id_val = s->session_id_val;
                    job.sig = NULL;
                    job.sig_len = 0;
                    job.auth_ctx = NULL;
                    job.kem_ct = s->kem_ct;
                    job.session_key = s->session_key;
                    job.srv_sig = s->srv_sig;
                    job.enqueue_ns = now_ns();

                    if (push_job(&job) != 0) {
                      session_free(s_idx);
                    }
                  }
                }
              }
            }
          }
        } else {
          session_t *s = &g_sessions[s_idx];
          s->last_seen_ns = now_ns();

          if (hdr.type == PKT_DISCONNECT) {
            session_free(s_idx);
          } else if (hdr.type == PKT_CLIENT_HELLO) {
            if (s->state == SESSION_WAIT_KEM_ENC) {
              server_send_ack(g_listen_sock, peer, hdr.seq);
            } else if (s->state == SESSION_WAIT_AUTH ||
                       s->state == SESSION_ESTABLISHED) {
              struct iovec iovs[5];
              iovs[0].iov_base = g_srv_dsa_pk;
              iovs[0].iov_len = DSA_PK_BYTES;
              iovs[1].iov_base = s->kem_ct;
              iovs[1].iov_len = KEM_CT_BYTES;

              uint8_t sid_buf[SESSION_ID_BYTES];
              uint64_t sid64 = s->session_id_val;
              for (int k = 0; k < SESSION_ID_BYTES; k++) {
                sid_buf[k] = (sid64 >> ((SESSION_ID_BYTES - 1 - k) * 8)) & 0xFF;
              }
              iovs[2].iov_base = sid_buf;
              iovs[2].iov_len = SESSION_ID_BYTES;
              iovs[3].iov_base = s->server_nonce;
              iovs[3].iov_len = 16;
              iovs[4].iov_base = s->srv_sig;
              iovs[4].iov_len = DSA_SIG_BYTES;

              server_send_ack(g_listen_sock, peer, hdr.seq);
              server_send_packet_zero_copy(g_listen_sock, peer, s->tx_seq,
                                           PKT_SERVER_HELLO, iovs, 5);
            }
          } else if (hdr.type == PKT_CLIENT_AUTH) {
            if (s->state == SESSION_WAIT_AUTH) {
              if (payload_len >= DSA_SIG_BYTES) {
                s->state = SESSION_WAIT_AUTH_VER;
                s->auth_seq = hdr.seq;
                s->current_job_id++;

                memcpy(s->sig, payload, DSA_SIG_BYTES);

                crypto_job_t job;
                job.job_id = s->current_job_id;
                job.session_id = (uint32_t)s_idx;
                job.generation = s->generation;
                job.type = PKT_CLIENT_AUTH;
                job.client_kem_pk = s->client_kem_pk;
                job.client_dsa_pk = s->client_dsa_pk;
                job.client_nonce = s->client_nonce;
                job.server_nonce = s->server_nonce;
                job.session_id_val = s->session_id_val;
                job.sig = s->sig;
                job.sig_len = DSA_SIG_BYTES;
                job.auth_ctx = NULL;
                job.kem_ct = s->kem_ct;
                job.srv_sig = s->srv_sig;
                job.session_key = NULL;
                job.enqueue_ns = now_ns();

                if (push_job(&job) != 0) {
                  session_free(s_idx);
                }
              }
            } else if (s->state == SESSION_WAIT_AUTH_VER ||
                       s->state == SESSION_ESTABLISHED) {
              server_send_ack(g_listen_sock, peer, hdr.seq);
            }
          } else if (hdr.type == PKT_DATA) {
            if (s->state == SESSION_ESTABLISHED && hdr.seq > s->rx_seq) {
              if (payload_len >= 12 + 16) {
                const uint8_t *nonce = payload;
                const uint8_t *tag = payload + 12;
                const uint8_t *ct = payload + 28;
                int ct_len = (int)payload_len - 28;
                if (ct_len > DATA_CHUNK_MAX) {
                  continue; /* Prevent stack buffer overflow */
                }

                uint8_t plaintext[DATA_CHUNK_MAX];
                double dec_t0 = now_ms();
                int pt_len = aead_decrypt(ct, ct_len, s->session_key, nonce,
                                          tag, plaintext);
                double dec_us = (now_ms() - dec_t0) * 1000.0;

                if (pt_len >= 0) {
                  s->rx_seq = hdr.seq;
                  s->metrics.bytes_recv += pkt_len;
                  s->metrics.msg_count++;
                  s->metrics.total_decrypt_us += dec_us;
                  s->metrics.decrypt_count++;

                  metrics_t *rm = registry_get_metrics(s->client_registry_id);
                  if (rm) {
                    rm->bytes_recv = s->metrics.bytes_recv;
                    rm->msg_count = s->metrics.msg_count;
                    rm->total_decrypt_us = s->metrics.total_decrypt_us;
                    rm->decrypt_count = s->metrics.decrypt_count;
                  }

                  char ip_str[16];
                  inet_ntop(AF_INET, &peer->sin_addr, ip_str, sizeof(ip_str));
                  uint16_t rport = ntohs(peer->sin_port);
                  ipc_push_rx_msg(s->client_registry_id, ip_str, rport,
                                  s->session_id_val, plaintext, pt_len);

                  float avg_dec =
                      (s->metrics.decrypt_count > 0)
                          ? (float)(s->metrics.total_decrypt_us /
                                    (double)s->metrics.decrypt_count)
                          : 0.0f;
                  ipc_push_rx_metrics(s->client_registry_id, (float)dec_us,
                                      0.0f, 0.0f, avg_dec,
                                      s->metrics.bytes_recv, hdr.seq);

                  /* Echo back to client */
                  uint8_t echo_pkt[12 + 16 + DATA_CHUNK_MAX];
                  uint8_t echo_nonce[12];
                  make_nonce(echo_nonce, s->tx_nonce_ctr++);
                  memcpy(echo_pkt, echo_nonce, 12);

                  int echo_ct_len = aead_encrypt(
                      plaintext, pt_len, s->session_key, echo_nonce,
                      echo_pkt + 12 + 16, /* ciphertext */
                      echo_pkt + 12);     /* tag */
                  if (echo_ct_len >= 0) {
                    uint16_t echo_pkt_len = (uint16_t)(12 + 16 + echo_ct_len);
                    server_send_packet(g_listen_sock, peer, s->tx_seq++,
                                       PKT_DATA, echo_pkt, echo_pkt_len);
                  }
                }
              }
            }
          }
        }
      }

      submit_recv_request(buf_idx);
      count++;
    }
    if (count > 0) {
      io_uring_cq_advance(&g_ring, count);
      io_uring_submit(&g_ring);
      worked = 1;
    }

    /* 3. Inactive Session Cleanup Sweep */
    sweep_timeouts();
    sample_temp_if_needed();

    /* 4. Sleep/Yield based on CPU activity and pending worker jobs */
    if (worked) {
      main_idle_spin = 0;
    } else {
      if (++main_idle_spin > 1000) {
        if (__atomic_load_n(&g_in_flight_jobs, __ATOMIC_ACQUIRE) == 0) {
          struct io_uring_cqe *wait_cqe;
          struct __kernel_timespec ts_cqe = {0, 1000000}; // 1 ms timeout
          io_uring_wait_cqe_timeout(&g_ring, &wait_cqe, &ts_cqe);
        } else {
          sched_yield();
        }
        main_idle_spin = 0;
      } else {
        cpu_pause();
      }
    }
  }

  /* Broadcast PKT_DISCONNECT to all active sessions to shut down clients
   * cleanly */
  for (int i = 0; i < MAX_SESSIONS; i++) {
    session_t *s = &g_sessions[i];
    if (s->state == SESSION_ESTABLISHED) {
      struct sockaddr_in peer;
      peer.sin_family = AF_INET;
      peer.sin_port = s->port;
      peer.sin_addr.s_addr = s->ip;
      server_send_packet(g_listen_sock, &peer, s->tx_seq, PKT_DISCONNECT, NULL,
                         0);
    }
  }

  close(g_listen_sock);
  io_uring_queue_exit(&g_ring);
  unlink(IPC_RX_PATH);
  unlink(IPC_TX_PATH);
  explicit_bzero(g_srv_dsa_sk, sizeof(g_srv_dsa_sk));
  /* Ephemeral KEM keypair zeroization removed (dead field) */
  sem_destroy(&g_job_sem);
  server_print_bench_report();
  printf("\n[server] Shutdown complete.\n");
  return 0;
}