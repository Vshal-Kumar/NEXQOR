/*
 * classical/server.c — High-Performance Asynchronous io_uring Classical IoT Multi-Client Server
 *
 * Classical IoT Cryptographic Suite:
 *   - Key Establishment:  X25519 ECDH (RFC 7748)
 *   - Digital Signatures: Ed25519 (RFC 8032)
 *   - AEAD Encryption:    AES-128-CCM (RFC 3610 / NIST SP 800-38C)
 *   - Digest:             SHA-256 (FIPS 180-4)
 *   - Key Derivation:     HKDF-SHA-256 (RFC 5869)
 *   - Message Auth:       HMAC-SHA-256 (RFC 2104)
 *
 * Architecture:
 *  - Core 1: Network Event Loop (Main Thread)
 *            - io_uring asynchronous UDP engine (Zero-copy/pre-allocated buffers)
 *            - Thread-confined session table (Actor model style, no locks)
 *            - Synchronous polling of io_uring CQ & lock-free Completion Queue
 *            - Adaptive load controller & rate limiting
 *  - Cores 2-4: Crypto Worker Thread Pool
 *            - Lock-free SPMC Queue
 *            - Hardware-accelerated X25519 ECDH & Ed25519 verification
 *            - Lock-free MPSC Completion Queue
 *  - Warm-path: Identity management, IPC terminals
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

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
#include <endian.h>
#include <sys/resource.h>

#include "client_registry.h"
#include "crypto/aead.h"
#include "crypto/trust_store.h"
#include "ipc.h"
#include "transport.h"
#include "wrappers/kem_wrapper.h"
#include "wrappers/dsa_wrapper.h"
#include "wrappers/hash_wrapper.h"
#include "wrappers/kdf_wrapper.h"

/* ── Sizing and Bounds ───────────────────────────────────────────── */
#define MAX_SESSIONS 10000
#define SESSION_HASH_SIZE (MAX_SESSIONS * 2)
#define JOB_QUEUE_SIZE 8192
#define WORKER_COMP_QUEUE_SIZE 4096
#define NUM_RECV_BUFFERS 1024
#define NUM_WORKERS 3
#define RATE_LIMIT_HASH_SIZE 16384

#define AUTH_CTX_LEN (SESSION_ID_BYTES + DSA_PK_BYTES + KEM_SS_BYTES)

/* ── Canonical Transcript Lengths ─────────────────────────────────── */
/* Server Transcript: c_nonce(16) + s_nonce(16) + sid(8) + c_eph_pk(32) + c_id_pk(32) + s_id_pk(32) + s_eph_pk(32) = 168 bytes */
#define SERVER_TRANSCRIPT_LEN (16 + 16 + SESSION_ID_BYTES + KEM_PK_BYTES + DSA_PK_BYTES + DSA_PK_BYTES + KEM_CT_BYTES)
/* Client Transcript: server_transcript(168) + srv_sig(64) = 232 bytes */
#define CLIENT_TRANSCRIPT_LEN (SERVER_TRANSCRIPT_LEN + DSA_SIG_BYTES)

/* ── Long-term identity ──────────────────────────────────────────── */
static uint8_t g_srv_dsa_pk[DSA_PK_BYTES];
static uint8_t g_srv_dsa_sk[DSA_SK_BYTES];

static volatile int g_stop = 0;
static void on_signal(int s) {
  (void)s;
  g_stop = 1;
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
  const uint8_t *confirm_tag;

  /* Output payload pointers (zero-copy addresses) */
  uint8_t *server_eph_pk;
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
    return -1;
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
    return -1;
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
    return -1;
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
    return -1;
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

  uint8_t client_kem_pk[KEM_PK_BYTES];    /* Client X25519 ephemeral PK */
  uint8_t client_dsa_pk[DSA_PK_BYTES];    /* Client Ed25519 identity PK */
  uint8_t server_eph_pk[KEM_CT_BYTES];    /* Server X25519 ephemeral PK */
  uint8_t session_key[KEM_SS_BYTES];      /* X25519 shared secret */
  uint8_t client_write_key[16];           /* AES-128 client-to-server key */
  uint8_t server_write_key[16];           /* AES-128 server-to-client key */
  uint8_t client_confirm_key[32];         /* Key confirmation key */
  uint8_t server_confirm_key[32];         /* Server confirmation key */

  replay_window_t replay_win;
  uint8_t sig[DSA_SIG_BYTES];
  uint8_t client_confirm_tag[32];
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
  replay_window_init(&s->replay_win);
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

  /* Securely erase sensitive keys */
  explicit_bzero(s->session_key, sizeof(s->session_key));
  explicit_bzero(s->client_write_key, sizeof(s->client_write_key));
  explicit_bzero(s->server_write_key, sizeof(s->server_write_key));
  explicit_bzero(s->client_confirm_key, sizeof(s->client_confirm_key));
  explicit_bzero(s->server_confirm_key, sizeof(s->server_confirm_key));
  replay_window_destroy(&s->replay_win);
  explicit_bzero(s->sig, sizeof(s->sig));

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
        e->tokens = 20.0;
        e->last_update_ns = now;
        e->occupied = 1;
        return 1;
      }
      double elapsed_sec = (double)(now - e->last_update_ns) / 1e9;
      e->tokens += elapsed_sec * 50.0;
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
                                  uint64_t session_id,
                                  const uint8_t *payload,
                                  uint16_t payload_len) {
  static uint8_t wire[PKT_HDR_BYTES + 8192];
  pkt_hdr_t hdr;
  hdr.seq = htonl(seq);
  hdr.type = type;
  hdr.len = htons(payload_len);
  hdr.session_id = htobe64(session_id);

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
                                            uint64_t session_id,
                                            const struct iovec *iovs,
                                            int iov_cnt) {
  pkt_hdr_t hdr;
  hdr.seq = htonl(seq);
  hdr.type = type;
  hdr.session_id = htobe64(session_id);

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
                            uint32_t ack_seq, uint64_t session_id) {
  uint8_t pl[4];
  pl[0] = (ack_seq >> 24) & 0xFF;
  pl[1] = (ack_seq >> 16) & 0xFF;
  pl[2] = (ack_seq >> 8) & 0xFF;
  pl[3] = ack_seq & 0xFF;
  server_send_packet(sock, peer, 0, PKT_ACK, session_id, pl, 4);
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

/* ── Crypto Worker Threads (X25519 ECDH + Ed25519 Sign/Verify) ───── */
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
      sem_trywait(&g_job_sem);

      crypto_completion_t comp;
      comp.job_id = job.job_id;
      comp.session_id = job.session_id;
      comp.generation = job.generation;
      comp.type = job.type;
      comp.status = -1;

      if (job.type == PKT_CLIENT_HELLO) {
        /* 1. Generate server ephemeral X25519 keypair */
        uint8_t s_eph_sk[X25519_SK_BYTES];
        if (x25519_generate_keypair(job.server_eph_pk, s_eph_sk) == 0) {
          /* 2. Compute X25519 shared secret: ss = X25519(s_eph_sk, client_eph_pk) */
          if (x25519_derive_shared_secret(job.session_key, s_eph_sk, job.client_kem_pk) == 0) {
            /* 3. Construct canonical server handshake transcript:
             *    c_nonce(16) | s_nonce(16) | sid(8) | c_eph_pk(32) | c_id_pk(32) | s_id_pk(32) | s_eph_pk(32) */
            uint8_t tx[SERVER_TRANSCRIPT_LEN];
            size_t tx_off = 0;
            memcpy(tx + tx_off, job.client_nonce, 16);
            tx_off += 16;
            memcpy(tx + tx_off, job.server_nonce, 16);
            tx_off += 16;

            uint64_t sid64 = htobe64(job.session_id_val);
            memcpy(tx + tx_off, &sid64, SESSION_ID_BYTES);
            tx_off += SESSION_ID_BYTES;

            memcpy(tx + tx_off, job.client_kem_pk, KEM_PK_BYTES);
            tx_off += KEM_PK_BYTES;
            memcpy(tx + tx_off, job.client_dsa_pk, DSA_PK_BYTES);
            tx_off += DSA_PK_BYTES;
            memcpy(tx + tx_off, g_srv_dsa_pk, DSA_PK_BYTES);
            tx_off += DSA_PK_BYTES;
            memcpy(tx + tx_off, job.server_eph_pk, KEM_CT_BYTES);
            tx_off += KEM_CT_BYTES;

            /* 4. SHA-256 transcript digest */
            uint8_t digest[SHA256_DIGEST_BYTES];
            if (sha256_digest(tx, tx_off, digest) == 0) {
              /* 5. Ed25519 signature over digest */
              size_t siglen = 0;
              if (ed25519_sign(job.srv_sig, &siglen, digest, SHA256_DIGEST_BYTES, g_srv_dsa_sk) == 0) {
                comp.status = 0;
              }
            }
          }
          explicit_bzero(s_eph_sk, sizeof(s_eph_sk));
        }
      } else if (job.type == PKT_CLIENT_AUTH) {
        /* Reconstruct canonical client transcript:
         * server_transcript(168) | srv_sig(64) */
        uint8_t cl_tx[CLIENT_TRANSCRIPT_LEN];
        size_t tx_off = 0;
        memcpy(cl_tx + tx_off, job.client_nonce, 16);
        tx_off += 16;
        memcpy(cl_tx + tx_off, job.server_nonce, 16);
        tx_off += 16;

        uint64_t sid64 = htobe64(job.session_id_val);
        memcpy(cl_tx + tx_off, &sid64, SESSION_ID_BYTES);
        tx_off += SESSION_ID_BYTES;

        memcpy(cl_tx + tx_off, job.client_kem_pk, KEM_PK_BYTES);
        tx_off += KEM_PK_BYTES;
        memcpy(cl_tx + tx_off, job.client_dsa_pk, DSA_PK_BYTES);
        tx_off += DSA_PK_BYTES;
        memcpy(cl_tx + tx_off, g_srv_dsa_pk, DSA_PK_BYTES);
        tx_off += DSA_PK_BYTES;
        memcpy(cl_tx + tx_off, job.server_eph_pk, KEM_CT_BYTES);
        tx_off += KEM_CT_BYTES;

        memcpy(cl_tx + tx_off, job.srv_sig, DSA_SIG_BYTES);
        tx_off += DSA_SIG_BYTES;

        uint8_t cl_digest[SHA256_DIGEST_BYTES];
        if (sha256_digest(cl_tx, tx_off, cl_digest) == 0) {
          /* Verify client identity against authorized enrollment database */
          if (trust_store_server_verify_client(job.client_dsa_pk, NULL) == 0) {
            /* Verify client's Ed25519 digital signature */
            if (ed25519_verify(job.sig, job.sig_len, cl_digest, SHA256_DIGEST_BYTES, job.client_dsa_pk) == 0) {
              comp.status = 0;
            } else {
              fprintf(stderr, "[server] Client verification failed: Bad Ed25519 signature!\n");
            }
          } else {
            fprintf(stderr, "[server] Client verification failed: Unauthorized client public key!\n");
          }
        }
      }

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
      if (g_stop) break;
      usleep(100000);
      continue;
    }
    printf("[server] Dashboard Incoming Stream (Server Receive Channel) connected\n");
    pthread_mutex_lock(&g_ipc_rx_mu);
    if (g_ipc_rx_fd >= 0) close(g_ipc_rx_fd);
    g_ipc_rx_fd = fd;
    pthread_mutex_unlock(&g_ipc_rx_mu);
  }
  close(lfd);
  return NULL;
}

static void *ipc_tx_worker_thread(void *arg) {
  int lfd = *(int *)arg;
  free(arg);
  while (!g_stop) {
    int fd = accept(lfd, NULL, NULL);
    if (fd < 0) {
      if (g_stop) break;
      usleep(100000);
      continue;
    }
    printf("[server] Dashboard Outgoing Stream (Server Transmit Channel) connected\n");
    pthread_mutex_lock(&g_ipc_tx_mu);
    if (g_ipc_tx_fd >= 0) close(g_ipc_tx_fd);
    g_ipc_tx_fd = fd;
    pthread_mutex_unlock(&g_ipc_tx_mu);
    ipc_push_client_list();

    uint8_t cmd_buf[sizeof(ipc_tx_cmd_t) + DATA_CHUNK_MAX];
    while (!g_stop) {
      ipc_hdr_t hdr;
      ssize_t n = ipc_recv_frame(fd, &hdr, cmd_buf, sizeof(cmd_buf));
      if (n < 0) break;
      if (hdr.type == IPC_MSG_TX_CMD && n >= (ssize_t)sizeof(ipc_tx_cmd_t)) {
        ipc_tx_cmd_t *cmd = (ipc_tx_cmd_t *)cmd_buf;
        const uint8_t *msg = cmd_buf + sizeof(ipc_tx_cmd_t);
        uint32_t mlen = cmd->msg_len;
        if (cmd->client_id == 0) {
          registry_broadcast(msg, mlen);
        } else {
          registry_send((int)cmd->client_id, msg, mlen);
        }
        ipc_push_client_list();
      }
    }
  }
  close(lfd);
  return NULL;
}

static int start_ipc_server(const char *path, void *(*thread_fn)(void *)) {
  unlink(path);
  int s = socket(AF_UNIX, SOCK_STREAM, 0);
  if (s < 0) return -1;

  struct sockaddr_un addr = {0};
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

  if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    close(s);
    return -1;
  }
  if (listen(s, 5) < 0) {
    close(s);
    return -1;
  }

  int *pfd = malloc(sizeof(int));
  *pfd = s;
  pthread_t tid;
  pthread_create(&tid, NULL, thread_fn, pfd);
  pthread_detach(tid);
  return 0;
}

/* ── Completion Processor ────────────────────────────────────────── */
static void process_worker_completion(const crypto_completion_t *comp) {
  uint32_t s_idx = comp->session_id;
  if (s_idx >= MAX_SESSIONS) return;
  session_t *s = &g_sessions[s_idx];
  if (s->generation != comp->generation) return;

  struct sockaddr_in peer;
  peer.sin_family = AF_INET;
  peer.sin_port = s->port;
  peer.sin_addr.s_addr = s->ip;

  if (comp->type == PKT_CLIENT_HELLO) {
    if (s->state != SESSION_WAIT_KEM_ENC) return;
    if (comp->status != 0) {
      session_free(s_idx);
      return;
    }

    /* Derive directional traffic keys via HKDF-SHA-256 */
    kem_derive_directional_keys(s->client_write_key, s->server_write_key,
                                s->session_key, s->client_nonce,
                                s->server_nonce, s->session_id_val);

    /* Derive key confirmation secrets */
    kdf_derive_confirmation_keys(s->client_confirm_key, s->server_confirm_key,
                                 s->session_key, s->client_nonce,
                                 s->server_nonce, s->session_id_val);

    /* Construct Phase 2: SERVER_HELLO
     * iovs: [ srv_id_pk (32) | s_eph_pk (32) | sid (8) | s_nonce (16) | srv_sig (64) ] */
    struct iovec iovs[5];
    iovs[0].iov_base = g_srv_dsa_pk;
    iovs[0].iov_len = DSA_PK_BYTES;
    iovs[1].iov_base = s->server_eph_pk;
    iovs[1].iov_len = KEM_CT_BYTES;

    uint8_t sid_buf[SESSION_ID_BYTES];
    uint64_t sid64 = htobe64(s->session_id_val);
    memcpy(sid_buf, &sid64, SESSION_ID_BYTES);

    iovs[2].iov_base = sid_buf;
    iovs[2].iov_len = SESSION_ID_BYTES;
    iovs[3].iov_base = s->server_nonce;
    iovs[3].iov_len = 16;
    iovs[4].iov_base = s->srv_sig;
    iovs[4].iov_len = DSA_SIG_BYTES;

    s->state = SESSION_WAIT_AUTH;
    s->last_seen_ns = now_ns();

    server_send_packet_zero_copy(g_listen_sock, &peer, s->tx_seq,
                                 PKT_SERVER_HELLO, s->session_id_val, iovs, 5);
  } else if (comp->type == PKT_CLIENT_AUTH) {
    if (s->state != SESSION_WAIT_AUTH_VER) return;
    if (comp->status != 0) {
      session_free(s_idx);
      return;
    }

    conn_t c;
    conn_init(&c, g_listen_sock);
    c.peer = peer;
    c.peer_len = sizeof(peer);
    c.tx_seq = s->tx_seq;
    c.established = 1;
    memcpy(c.tx_key, s->server_write_key, 16);
    memcpy(c.rx_key, s->client_write_key, 16);
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

    /* Send ACK confirming session activation */
    server_send_ack(g_listen_sock, &peer, s->auth_seq, s->session_id_val);

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
      ipc_send_frame(g_ipc_tx_fd, IPC_CLIENT_CONNECT, (uint16_t)cid, &ce, sizeof(ce));
    }
    pthread_mutex_unlock(&g_ipc_tx_mu);

    char ip_str[16];
    inet_ntop(AF_INET, &peer.sin_addr, ip_str, sizeof(ip_str));
    char ts[16];
    now_hms(ts, sizeof(ts));
    const char *link_type = (strncmp(ip_str, "100.", 4) == 0) ? "Tailscale VPN" :
                            (strncmp(ip_str, "127.", 4) == 0) ? "Localhost" : "LAN / Wi-Fi";
    printf("[%s] \033[1;32m✓ CLIENT-%02d\033[0m [%s] %s:%u  SID=%016llx  HS=%.3fms  Active=%d\n\n",
           ts, cid, link_type, ip_str, ntohs(peer.sin_port),
           (unsigned long long)s->session_id_val, s->metrics.hs_total_ms,
           registry_count());
  }
}

/* ════════════════════════════════════════════════════════════════════
 * main() — Linux io_uring Event Loop Server
 * ════════════════════════════════════════════════════════════════════ */
int main(void) {
  signal(SIGINT, on_signal);
  signal(SIGTERM, on_signal);
  signal(SIGPIPE, SIG_IGN);

  printf("\033[1;36m");
  printf("╔══════════════════════════════════════════════════════════╗\n");
  printf("║   QRYPTONEX Secure Server Core ─ Classical IoT Suite     ║\n");
  printf("║   Architecture: Linux io_uring + Multi-Worker Pool       ║\n");
  printf("║   Suite: X25519 + Ed25519 + AES-128-CCM + SHA-256        ║\n");
  printf("╚══════════════════════════════════════════════════════════╝\n");
  printf("\033[0m\n");

  /* Initialize trust store and load/create server Ed25519 identity */
  if (trust_store_load_or_create_server_keys(g_srv_dsa_pk, g_srv_dsa_sk,
                                             TRUST_SERVER_PUB_DEFAULT,
                                             TRUST_SERVER_SEC_DEFAULT) != 0) {
    fprintf(stderr, "[server] Failed to load or generate Ed25519 identity!\n");
    return 1;
  }
  printf("[server] Ed25519 Server Identity Public Key Loaded (32 bytes)\n");

  /* Initialize client registry and queue semaphore */
  registry_init();
  sem_init(&g_job_sem, 0, 0);

  /* Initialize session pool */
  for (int i = 0; i < MAX_SESSIONS; i++) {
    g_free_sessions[i] = (uint32_t)(MAX_SESSIONS - 1 - i);
    g_sessions[i].state = SESSION_FREE;
  }
  g_free_session_count = MAX_SESSIONS;

  /* Start crypto worker pool (Cores 2-4) */
  pthread_t worker_threads[NUM_WORKERS];
  for (int i = 0; i < NUM_WORKERS; i++) {
    pthread_create(&worker_threads[i], NULL, crypto_worker_thread,
                   (void *)(intptr_t)(i + 1));
    pthread_detach(worker_threads[i]);
  }

  /* Start UNIX domain socket IPC endpoints */
  const char *rx_path = getenv("NEXQOR_IPC_RX_PATH");
  if (!rx_path || rx_path[0] == '\0') rx_path = IPC_RX_PATH;
  const char *tx_path = getenv("NEXQOR_IPC_TX_PATH");
  if (!tx_path || tx_path[0] == '\0') tx_path = IPC_TX_PATH;

  start_ipc_server(rx_path, ipc_rx_accept_thread);
  start_ipc_server(tx_path, ipc_tx_worker_thread);

  /* Create UDP listen socket on port 9877 */
  g_listen_sock = make_server_sock();
  if (g_listen_sock < 0) {
    fprintf(stderr, "[server] Failed to bind server UDP socket on port %d\n", SERVER_PORT);
    return 1;
  }

  /* Publish discovered endpoints */
  char lan_ip[64] = "", vpn_ip[64] = "";
  server_publish_endpoints(lan_ip, sizeof(lan_ip), vpn_ip, sizeof(vpn_ip));
  printf("[server] Active Endpoints:\n");
  printf("  • Localhost : 127.0.0.1:%d\n", SERVER_PORT);
  if (strcmp(lan_ip, "None") != 0)
    printf("  • LAN / Wi-Fi: %s:%d\n", lan_ip, SERVER_PORT);
  if (strcmp(vpn_ip, "None") != 0)
    printf("  • Tailscale / VPN: %s:%d\n", vpn_ip, SERVER_PORT);
  printf("  • Discovery Probe: UDP Broadcast on port %d\n\n", SERVER_PORT);

  /* Setup Linux io_uring asynchronous engine */
  struct io_uring_params params = {0};
  if (io_uring_queue_init_params(NUM_RECV_BUFFERS, &g_ring, &params) < 0) {
    perror("io_uring_queue_init");
    close(g_listen_sock);
    return 1;
  }

  /* Prepare pre-allocated recv buffers */
  for (int i = 0; i < NUM_RECV_BUFFERS; i++) {
    recv_buf_t *rb = &g_recv_bufs[i];
    rb->idx = i;
    rb->iov.iov_base = rb->buffer;
    rb->iov.iov_len = sizeof(rb->buffer);
    rb->msg.msg_name = &rb->peer_addr;
    rb->msg.msg_namelen = sizeof(rb->peer_addr);
    rb->msg.msg_iov = &rb->iov;
    rb->msg.msg_iovlen = 1;
    submit_recv_request(i);
  }
  io_uring_submit(&g_ring);

  printf("[server] io_uring Event Loop Running. Ready for clients.\n\n");

  /* ── io_uring Event Loop (Core 1) ──────────────────────────────── */
  while (!g_stop) {
    /* 1. Drain worker completion queues */
    for (int w = 0; w < NUM_WORKERS; w++) {
      crypto_completion_t comp;
      while (pop_worker_completion(w, &comp) == 0) {
        process_worker_completion(&comp);
      }
    }

    /* 2. Process io_uring network events */
    struct io_uring_cqe *cqe;
    struct __kernel_timespec ts = {.tv_sec = 0, .tv_nsec = 1000000}; /* 1 ms */
    int ret = io_uring_wait_cqe_timeout(&g_ring, &cqe, &ts);
    if (ret < 0) {
      continue;
    }

    unsigned head;
    unsigned count = 0;
    io_uring_for_each_cqe(&g_ring, head, cqe) {
      count++;
      int buf_idx = (int)(intptr_t)io_uring_cqe_get_data(cqe);
      int res = cqe->res;

      if (res > (int)PKT_HDR_BYTES) {
        recv_buf_t *rb = &g_recv_bufs[buf_idx];
        struct sockaddr_in *peer = &rb->peer_addr;
        uint32_t ip = peer->sin_addr.s_addr;
        uint16_t port = peer->sin_port;
        uint8_t *pkt = rb->buffer;
        uint16_t pkt_len = (uint16_t)res;

        pkt_hdr_t hdr;
        memcpy(&hdr, pkt, PKT_HDR_BYTES);
        hdr.seq = ntohl(hdr.seq);
        hdr.len = ntohs(hdr.len);
        hdr.session_id = be64toh(hdr.session_id);

        uint8_t *payload = pkt + PKT_HDR_BYTES;
        uint16_t payload_len = pkt_len - PKT_HDR_BYTES;

        int s_idx = session_hash_lookup(ip, port);
        if (s_idx < 0) {
          if (hdr.type == PKT_DISCOVERY_PROBE || hdr.type == PKT_PING) {
            uint8_t offer[32] = "NEXQOR_OFFER";
            server_send_packet(g_listen_sock, peer, 0, PKT_DISCOVERY_OFFER, hdr.seq, offer, 12);
          } else if (hdr.type == PKT_CLIENT_HELLO) {
            if (rate_limit_check(ip, port)) {
              unsigned long queue_load = g_job_queue.tail - g_job_queue.head;
              if (queue_load >= (JOB_QUEUE_SIZE - 64)) {
                server_send_packet(g_listen_sock, peer, 0, PKT_BUSY, 0, NULL, 0);
              } else {
                /* CLIENT_HELLO payload: c_eph_pk(32) | c_id_pk(32) | c_nonce(16) = 80 bytes */
                if (payload_len >= KEM_PK_BYTES + DSA_PK_BYTES + 16) {
                  s_idx = session_alloc(ip, port);
                  if (s_idx >= 0) {
                    server_send_ack(g_listen_sock, peer, hdr.seq, 0);
                    session_t *s = &g_sessions[s_idx];
                    s->state = SESSION_WAIT_KEM_ENC;
                    s->last_seen_ns = now_ns();
                    s->current_job_id++;

                    memcpy(s->client_kem_pk, payload, KEM_PK_BYTES);
                    memcpy(s->client_dsa_pk, payload + KEM_PK_BYTES, DSA_PK_BYTES);
                    memcpy(s->client_nonce, payload + KEM_PK_BYTES + DSA_PK_BYTES, 16);

                    RAND_bytes(s->server_nonce, 16);

                    uint8_t sid[SESSION_ID_BYTES];
                    RAND_bytes(sid, SESSION_ID_BYTES);
                    uint64_t sid64 = 0;
                    for (int k = 0; k < SESSION_ID_BYTES; k++) {
                      sid64 = (sid64 << 8) | sid[k];
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
                    job.confirm_tag = NULL;
                    job.server_eph_pk = s->server_eph_pk;
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
              server_send_ack(g_listen_sock, peer, hdr.seq, s->session_id_val);
            } else if (s->state == SESSION_WAIT_AUTH || s->state == SESSION_ESTABLISHED) {
              struct iovec iovs[5];
              iovs[0].iov_base = g_srv_dsa_pk;
              iovs[0].iov_len = DSA_PK_BYTES;
              iovs[1].iov_base = s->server_eph_pk;
              iovs[1].iov_len = KEM_CT_BYTES;

              uint8_t sid_buf[SESSION_ID_BYTES];
              uint64_t sid64 = htobe64(s->session_id_val);
              memcpy(sid_buf, &sid64, SESSION_ID_BYTES);

              iovs[2].iov_base = sid_buf;
              iovs[2].iov_len = SESSION_ID_BYTES;
              iovs[3].iov_base = s->server_nonce;
              iovs[3].iov_len = 16;
              iovs[4].iov_base = s->srv_sig;
              iovs[4].iov_len = DSA_SIG_BYTES;

              server_send_ack(g_listen_sock, peer, hdr.seq, s->session_id_val);
              server_send_packet_zero_copy(g_listen_sock, peer, s->tx_seq,
                                           PKT_SERVER_HELLO, s->session_id_val, iovs, 5);
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
                job.server_eph_pk = s->server_eph_pk;
                job.srv_sig = s->srv_sig;
                job.session_key = NULL;
                job.enqueue_ns = now_ns();

                if (push_job(&job) != 0) {
                  session_free(s_idx);
                }
              }
            } else if (s->state == SESSION_WAIT_AUTH_VER || s->state == SESSION_ESTABLISHED) {
              server_send_ack(g_listen_sock, peer, hdr.seq, s->session_id_val);
            }
          } else if (hdr.type == PKT_DATA) {
            if (s->state == SESSION_ESTABLISHED) {
              if (payload_len >= 12 + 16) {
                const uint8_t *nonce = payload;
                const uint8_t *tag = payload + 12;
                const uint8_t *ct = payload + 28;
                int ct_len = (int)payload_len - 28;
                if (ct_len <= DATA_CHUNK_MAX) {
                  pkt_hdr_t wire_hdr;
                  wire_hdr.seq = htonl(hdr.seq);
                  wire_hdr.type = hdr.type;
                  wire_hdr.len = htons(payload_len);
                  wire_hdr.session_id = htobe64(hdr.session_id);

                  /* Pre-auth replay window check */
                  int rcheck = replay_window_check(&s->replay_win, hdr.seq);
                  if (rcheck != 0) {
                    uint8_t dummy_pt[DATA_CHUNK_MAX];
                    int auth_rc = aead_decrypt(ct, ct_len, (const uint8_t *)&wire_hdr, PKT_HDR_BYTES,
                                               s->client_write_key, nonce, tag, dummy_pt);
                    if (auth_rc >= 0) {
                      server_send_ack(g_listen_sock, peer, hdr.seq, s->session_id_val);
                    }
                  } else {
                    uint8_t plaintext[DATA_CHUNK_MAX];
                    double dec_t0 = now_ms();
                    int pt_len = aead_decrypt(ct, ct_len, (const uint8_t *)&wire_hdr, PKT_HDR_BYTES,
                                              s->client_write_key, nonce, tag, plaintext);
                    double dec_us = (now_ms() - dec_t0) * 1000.0;

                    if (pt_len >= 0) {
                      replay_window_update(&s->replay_win, hdr.seq);
                      server_send_ack(g_listen_sock, peer, hdr.seq, s->session_id_val);

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
                                      s->session_id_val, plaintext, (uint32_t)pt_len);
                      ipc_push_rx_metrics(s->client_registry_id, (float)dec_us,
                                          0.0f, 0.0f,
                                          (float)(s->metrics.total_decrypt_us / s->metrics.decrypt_count),
                                          s->metrics.bytes_recv, hdr.seq);
                    }
                  }
                }
              }
            }
          }
        }
      }

      submit_recv_request(buf_idx);
    }
    if (count > 0) {
      io_uring_cq_advance(&g_ring, count);
      io_uring_submit(&g_ring);
    }
  }

  printf("\n[server] Shutting down...\n");
  io_uring_queue_exit(&g_ring);
  close(g_listen_sock);
  unlink(rx_path);
  unlink(tx_path);
  printf("[server] Goodbye.\n");
  return 0;
}
