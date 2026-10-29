/*
 * hybrid/server.c — High-Performance Asynchronous Multi-Client Hybrid Server
 *
 * Suite: X25519 + ML-KEM-768 + Ed25519 + ML-DSA-65 + ChaCha20-Poly1305 + HKDF-SHA-384
 *
 * Architecture:
 *  - Network Event Loop (Main Thread)
 *      - io_uring asynchronous UDP engine (with POSIX poll fallback)
 *      - Thread-confined session table (Actor model, lock-free lookups)
 *      - Adaptive load controller & rate limiting
 *  - Crypto Worker Thread Pool
 *      - Lock-free SPMC / semaphore job queue
 *      - Hybrid KEX (X25519 + ML-KEM-768)
 *      - Hybrid Digital Signatures (Ed25519 + ML-DSA-65)
 *      - HKDF-SHA-384 directional traffic key derivation
 *      - Lock-free MPSC Completion Queue
 *  - IPC Terminals (Warm-path)
 *      - Decoupled UNIX domain socket IPC to server_rx (/tmp/hybrid_rx.sock)
 *      - Decoupled UNIX domain socket IPC to server_tx (/tmp/hybrid_tx.sock)
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
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
#include "ipc.h"
#include "transport.h"
#include "include/hybrid_crypto.h"
#include "include/hybrid_handshake.h"
#include "include/hybrid_session.h"
#include "include/hybrid_errors.h"

#define CLR_RESET   "\033[0m"
#define CLR_BOLD    "\033[1m"
#define CLR_DIM     "\033[2m"
#define CLR_CYAN    "\033[1;36m"
#define CLR_GREEN   "\033[1;32m"
#define CLR_YELLOW  "\033[1;33m"
#define CLR_MAGENTA "\033[1;35m"
#define CLR_BLUE    "\033[1;34m"
#define CLR_GRAY    "\033[0;37m"
#define CLR_WHITE   "\033[1;37m"
#define CLR_RED     "\033[1;31m"

/* ── Sizing and Bounds ───────────────────────────────────────────── */
#define MAX_SESSIONS 10000
#define SESSION_HASH_SIZE (MAX_SESSIONS * 2)
#define JOB_QUEUE_SIZE 8192
#define WORKER_COMP_QUEUE_SIZE 4096
#define NUM_RECV_BUFFERS 1024
#define NUM_WORKERS 3
#define RATE_LIMIT_HASH_SIZE 16384

/* Long-term Server Dual Identity */
static hybrid_identity_pk_t g_srv_id_pk;
static hybrid_identity_sk_t g_srv_id_sk;

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
static int make_nonce(uint8_t nonce[12], uint64_t ctr) {
    if (ctr >= 0xFFFFFFFFFFFFFF00ULL) {
        fprintf(stderr, "[server] CRITICAL: Nonce counter exhaustion! Rejecting.\n");
        return -1;
    }
    uint64_t le_ctr = htole64(ctr);
    memcpy(nonce, &le_ctr, 8);
    memset(nonce + 8, 0, 4);
    return 0;
}

/* ── Crypto Job Queue Definitions ────────────────────────────────── */
typedef struct {
    uint64_t job_id;
    uint32_t session_id;
    uint64_t generation;
    uint8_t  type;

    /* Handshake contexts */
    hybrid_msg_client_hello_t client_hello;
    hybrid_msg_client_auth_t  client_auth;

    /* Pointers to session buffers for result */
    hybrid_handshake_ctx_t   *hs_ctx;
    hybrid_msg_server_hello_t *srv_hello_out;

    uint64_t enqueue_ns;
} crypto_job_t;

typedef struct {
    uint64_t job_id;
    uint32_t session_id;
    uint64_t generation;
    uint8_t  type;
    int      status;
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

/* ── Session Table Definitions ───────────────────────────────────── */
typedef enum {
    SESSION_FREE,
    SESSION_WAIT_KEX_ENC,
    SESSION_WAIT_AUTH,
    SESSION_WAIT_AUTH_VER,
    SESSION_ESTABLISHED
} session_state_t;

typedef struct {
    uint32_t session_id;
    uint64_t generation;
    uint32_t ip;
    uint16_t port;
    uint8_t  state;

    hybrid_handshake_ctx_t    hs;
    hybrid_msg_server_hello_t srv_hello;

    uint8_t client_write_key[32];
    uint8_t server_write_key[32];

    replay_window_t replay_win;
    uint64_t session_id_val;

    uint32_t rx_seq;
    uint32_t tx_seq;
    uint32_t auth_seq;
    uint64_t tx_nonce_ctr;

    metrics_t metrics;
    uint64_t last_seen_ns;
    uint64_t established_time_ns;
    int client_registry_id;
} session_t;

static session_t g_sessions[MAX_SESSIONS] __attribute__((aligned(64)));

typedef struct {
    uint32_t ip;
    uint16_t port;
    uint32_t session_idx;
    int occupied;
} session_hash_entry_t;

static session_hash_entry_t g_session_hash[SESSION_HASH_SIZE];
static uint32_t g_free_sessions[MAX_SESSIONS];
static int g_free_session_count = 0;

static inline uint32_t session_hash(uint32_t ip, uint16_t port) {
    uint64_t k = ((uint64_t)ip << 16) | port;
    k ^= k >> 33;
    k *= 0xff51afd7ed558ccdULL;
    k ^= k >> 33;
    k *= 0xc4ceb9fe1a85ec53ULL;
    k ^= k >> 33;
    return (uint32_t)k;
}

static void session_table_init(void) {
    memset(g_sessions, 0, sizeof(g_sessions));
    memset(g_session_hash, 0, sizeof(g_session_hash));
    g_free_session_count = MAX_SESSIONS;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        g_free_sessions[i] = (uint32_t)(MAX_SESSIONS - 1 - i);
        g_sessions[i].session_id = (uint32_t)i;
        g_sessions[i].generation = 1;
        g_sessions[i].state = SESSION_FREE;
    }
}

static int session_hash_find(uint32_t ip, uint16_t port) {
    uint32_t h = session_hash(ip, port) % SESSION_HASH_SIZE;
    for (int i = 0; i < SESSION_HASH_SIZE; i++) {
        int slot = (int)((h + (uint32_t)i) % SESSION_HASH_SIZE);
        if (!g_session_hash[slot].occupied) return -1;
        if (g_session_hash[slot].ip == ip && g_session_hash[slot].port == port) {
            return (int)g_session_hash[slot].session_idx;
        }
    }
    return -1;
}

static int session_hash_insert(uint32_t ip, uint16_t port, uint32_t idx) {
    uint32_t h = session_hash(ip, port) % SESSION_HASH_SIZE;
    for (int i = 0; i < SESSION_HASH_SIZE; i++) {
        int slot = (int)((h + (uint32_t)i) % SESSION_HASH_SIZE);
        if (!g_session_hash[slot].occupied) {
            g_session_hash[slot].ip = ip;
            g_session_hash[slot].port = port;
            g_session_hash[slot].session_idx = idx;
            g_session_hash[slot].occupied = 1;
            return 0;
        }
    }
    return -1;
}

static void session_hash_remove(uint32_t ip, uint16_t port) {
    uint32_t h = session_hash(ip, port) % SESSION_HASH_SIZE;
    int found = -1;
    for (int i = 0; i < SESSION_HASH_SIZE; i++) {
        int slot = (int)((h + (uint32_t)i) % SESSION_HASH_SIZE);
        if (!g_session_hash[slot].occupied) return;
        if (g_session_hash[slot].ip == ip && g_session_hash[slot].port == port) {
            found = slot;
            break;
        }
    }
    if (found < 0) return;

    int empty = found;
    g_session_hash[empty].occupied = 0;
    for (int i = 1; i < SESSION_HASH_SIZE; i++) {
        int slot = (empty + i) % SESSION_HASH_SIZE;
        if (!g_session_hash[slot].occupied) break;
        uint32_t ideal = session_hash(g_session_hash[slot].ip, g_session_hash[slot].port) % SESSION_HASH_SIZE;
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
    if (g_free_session_count == 0) return -1;
    uint32_t idx = g_free_sessions[--g_free_session_count];
    session_t *s = &g_sessions[idx];
    uint64_t saved_gen = s->generation;
    memset(s, 0, sizeof(session_t));
    s->generation = saved_gen;

    s->session_id = idx;
    s->ip = ip;
    s->port = port;
    s->state = SESSION_WAIT_KEX_ENC;
    s->rx_seq = 0;
    s->tx_seq = 1;
    s->tx_nonce_ctr = 0;
    s->last_seen_ns = now_ns();
    s->client_registry_id = -1;
    memset(&s->metrics, 0, sizeof(metrics_t));
    s->metrics.msg_min_rtt_ms = 1e15;

    session_hash_insert(ip, port, idx);
    replay_window_init(&s->replay_win);
    return (int)idx;
}

static void session_free(int idx) {
    session_t *s = &g_sessions[idx];
    if (s->state == SESSION_FREE) return;

    session_hash_remove(s->ip, s->port);
    if (s->client_registry_id > 0) {
        registry_remove(s->client_registry_id);
    }

    explicit_bzero(s->client_write_key, sizeof(s->client_write_key));
    explicit_bzero(s->server_write_key, sizeof(s->server_write_key));
    hybrid_handshake_cleanup(&s->hs);
    replay_window_destroy(&s->replay_win);

    s->state = SESSION_FREE;
    s->generation++;
    g_free_sessions[g_free_session_count++] = (uint32_t)idx;
}

/* ── Rate Limiter ────────────────────────────────────────────────── */
typedef struct {
    uint32_t ip;
    uint16_t port;
    double   tokens;
    uint64_t last_update_ns;
    int      occupied;
} rate_limit_entry_t;

static rate_limit_entry_t g_rate_limit_table[RATE_LIMIT_HASH_SIZE];

static inline uint32_t rate_limit_hash(uint32_t ip, uint16_t port) {
    return session_hash(ip, port) % RATE_LIMIT_HASH_SIZE;
}

static int rate_limit_check(uint32_t ip, uint16_t port) {
    uint32_t host_ip = ntohl(ip);
    if ((host_ip >> 24) == 127) return 1; /* Allow localhost burst */

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
            if (e->tokens > 20.0) e->tokens = 20.0;
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

/* ── Outbound Packet Transmission ────────────────────────────────── */
static ssize_t server_send_packet(int sock, const struct sockaddr_in *peer,
                                  uint32_t seq, uint8_t type,
                                  uint64_t session_id,
                                  const uint8_t *payload,
                                  uint16_t payload_len) {
    static uint8_t wire[PKT_HDR_BYTES + 16384];
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

static void server_send_ack(int sock, const struct sockaddr_in *peer,
                            uint32_t ack_seq, uint64_t session_id) {
    uint8_t pl[4];
    pl[0] = (ack_seq >> 24) & 0xFF;
    pl[1] = (ack_seq >> 16) & 0xFF;
    pl[2] = (ack_seq >> 8) & 0xFF;
    pl[3] = ack_seq & 0xFF;
    server_send_packet(sock, peer, 0, PKT_ACK, session_id, pl, 4);
}

/* ── IPC Notifications ───────────────────────────────────────────── */
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

/* ── Crypto Worker Threads ───────────────────────────────────────── */
static void *crypto_worker_thread(void *arg) {
    int core_id = (int)(intptr_t)arg;
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
                if (hybrid_server_process_client_hello(job.hs_ctx, &job.client_hello, NULL) == HYBRID_SUCCESS) {
                    if (hybrid_server_create_hello(job.hs_ctx, job.srv_hello_out) == HYBRID_SUCCESS) {
                        comp.status = 0;
                    }
                }
            } else if (job.type == PKT_CLIENT_AUTH) {
                if (hybrid_server_process_client_auth(job.hs_ctx, &job.client_auth) == HYBRID_SUCCESS) {
                    comp.status = 0;
                }
            }

            int worker_idx = core_id % NUM_WORKERS;
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

/* ── IPC Acceptor Threads ────────────────────────────────────────── */
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
        if (s->state != SESSION_WAIT_KEX_ENC) return;
        if (comp->status != 0) {
            session_free(s_idx);
            return;
        }

        s->session_id_val = s->hs.session_id;
        memcpy(s->client_write_key, s->hs.client_write_key, 32);
        memcpy(s->server_write_key, s->hs.server_write_key, 32);

        s->state = SESSION_WAIT_AUTH;
        s->last_seen_ns = now_ns();

        server_send_packet(g_listen_sock, &peer, s->tx_seq,
                           PKT_SERVER_HELLO, s->session_id_val,
                           (const uint8_t *)&s->srv_hello, sizeof(s->srv_hello));
    } else if (comp->type == PKT_CLIENT_AUTH) {
        if (s->state != SESSION_WAIT_AUTH_VER) return;
        if (comp->status != 0) {
            fprintf(stderr, "[server] Client auth failed, freeing session %u\n", s_idx);
            session_free(s_idx);
            return;
        }

        conn_t c;
        conn_init(&c, g_listen_sock);
        c.peer = peer;
        c.peer_len = sizeof(peer);
        c.tx_seq = s->tx_seq;
        c.established = 1;
        memcpy(c.tx_key, s->server_write_key, 32);
        memcpy(c.rx_key, s->client_write_key, 32);
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

        /* Send ACK confirming mutual authentication succeeded */
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
        printf("[%s] \033[1;32m✓ HYBRID-CLIENT-%02d\033[0m [%s] %s:%u  SID=%016llx  HS=%.3fms  Active=%d\n\n",
               ts, cid, link_type, ip_str, ntohs(peer.sin_port),
               (unsigned long long)s->session_id_val, s->metrics.hs_total_ms,
               registry_count());
    }
}

/* ════════════════════════════════════════════════════════════════════
 * main() — Linux UDP Event Loop Hybrid Server
 * ════════════════════════════════════════════════════════════════════ */
int main(void) {
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    printf("\033[1;36m");
    printf("╔════════════════════════════════════════════════════════════════════╗\n");
    printf("║   QRYPTONEX Hybrid Multi-Client Server Core (v1.0)                 ║\n");
    printf("║   Suite: X25519 + ML-KEM-768 + Ed25519 + ML-DSA-65 + ChaCha20      ║\n");
    printf("║   Port : %d | Zero-Copy Event Loop | Multi-Worker Crypto Pool    ║\n", SERVER_PORT);
    printf("╚════════════════════════════════════════════════════════════════════╝\n");
    printf(CLR_RESET "\n");

    /* 1. Initialize Hybrid Cryptographic Core */
    if (hybrid_crypto_init() != HYBRID_SUCCESS) {
        fprintf(stderr, "[server] FATAL: Cryptographic engine initialization failed\n");
        return 1;
    }

    /* 2. Load or generate dual identity keys */
    printf("[server] Initializing long-term dual identity (Ed25519 + ML-DSA-65)...\n");
    if (hybrid_generate_identity_keys(&g_srv_id_pk, &g_srv_id_sk) != HYBRID_SUCCESS) {
        fprintf(stderr, "[server] FATAL: Dual identity key generation failed\n");
        return 1;
    }
    printf("[server] Server identity ready.\n");

    /* 3. Initialize Queues and Client Registry */
    session_table_init();
    registry_init();
    sem_init(&g_job_sem, 0, 0);

    /* 4. Spawn Crypto Worker Threads */
    pthread_t workers[NUM_WORKERS];
    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_create(&workers[i], NULL, crypto_worker_thread, (void *)(intptr_t)(i + 1));
        pthread_detach(workers[i]);
    }

    /* 5. Start UNIX Domain IPC Sockets */
    const char *rx_path = getenv("HYBRID_IPC_RX_PATH");
    if (!rx_path || rx_path[0] == '\0') rx_path = IPC_RX_PATH;
    const char *tx_path = getenv("HYBRID_IPC_TX_PATH");
    if (!tx_path || tx_path[0] == '\0') tx_path = IPC_TX_PATH;

    start_ipc_server(rx_path, ipc_rx_accept_thread);
    start_ipc_server(tx_path, ipc_tx_worker_thread);

    /* 6. Setup UDP Listening Socket */
    g_listen_sock = make_server_sock();
    if (g_listen_sock < 0) {
        perror("[server] make_server_sock failed");
        return 1;
    }

    /* 7. Publish Network Endpoints */
    char lan_ip[INET_ADDRSTRLEN] = "";
    char vpn_ip[INET_ADDRSTRLEN] = "";
    server_publish_endpoints(lan_ip, sizeof(lan_ip), vpn_ip, sizeof(vpn_ip));

    printf("\n[server] Listening for hybrid connections on UDP port %d ...\n\n", SERVER_PORT);

    uint8_t pkt_buf[PKT_BUF_MAX];

    while (!g_stop) {
        /* Poll Worker Completions */
        for (int w = 0; w < NUM_WORKERS; w++) {
            crypto_completion_t comp;
            while (pop_worker_completion(w, &comp) == 0) {
                process_worker_completion(&comp);
            }
        }

        struct pollfd pfd = { .fd = g_listen_sock, .events = POLLIN };
        int pr = poll(&pfd, 1, 10);
        if (pr <= 0) continue;

        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);
        ssize_t n = recvfrom(g_listen_sock, pkt_buf, sizeof(pkt_buf), 0,
                             (struct sockaddr *)&peer, &peer_len);
        if (n < (ssize_t)PKT_HDR_BYTES) continue;

        pkt_hdr_t *hdr = (pkt_hdr_t *)pkt_buf;
        uint32_t seq = ntohl(hdr->seq);
        uint8_t type = hdr->type;
        uint16_t plen = ntohs(hdr->len);
        uint64_t sid = be64toh(hdr->session_id);

        if ((size_t)n != (size_t)(PKT_HDR_BYTES + plen)) continue;

        const uint8_t *payload = pkt_buf + PKT_HDR_BYTES;
        uint32_t ip = peer.sin_addr.s_addr;
        uint16_t port = peer.sin_port;

        if (type == PKT_DISCOVERY_PROBE || type == PKT_PING) {
            uint8_t offer[32] = "HYBRID_OFFER";
            server_send_packet(g_listen_sock, &peer, 0, PKT_DISCOVERY_OFFER, seq, offer, 12);
            continue;
        }

        if (type == PKT_CLIENT_HELLO) {
            if (!rate_limit_check(ip, port)) continue;
            if (plen != sizeof(hybrid_msg_client_hello_t)) continue;

            server_send_ack(g_listen_sock, &peer, seq, 0);

            int s_idx = session_hash_find(ip, port);
            if (s_idx >= 0) session_free(s_idx);

            s_idx = session_alloc(ip, port);
            if (s_idx < 0) continue;

            session_t *s = &g_sessions[s_idx];
            if (hybrid_handshake_init(&s->hs, HYBRID_ROLE_SERVER, &g_srv_id_pk, &g_srv_id_sk) != HYBRID_SUCCESS) {
                session_free(s_idx);
                continue;
            }

            crypto_job_t job;
            job.job_id = now_ns();
            job.session_id = (uint32_t)s_idx;
            job.generation = s->generation;
            job.type = PKT_CLIENT_HELLO;
            memcpy(&job.client_hello, payload, sizeof(hybrid_msg_client_hello_t));
            job.hs_ctx = &s->hs;
            job.srv_hello_out = &s->srv_hello;
            job.enqueue_ns = now_ns();

            s->state = SESSION_WAIT_KEX_ENC;
            push_job(&job);
        } else if (type == PKT_CLIENT_AUTH) {
            int s_idx = session_hash_find(ip, port);
            if (s_idx < 0) continue;
            session_t *s = &g_sessions[s_idx];
            if (s->state != SESSION_WAIT_AUTH) continue;
            if (plen != sizeof(hybrid_msg_client_auth_t)) continue;

            server_send_ack(g_listen_sock, &peer, seq, sid);

            crypto_job_t job;
            job.job_id = now_ns();
            job.session_id = (uint32_t)s_idx;
            job.generation = s->generation;
            job.type = PKT_CLIENT_AUTH;
            memcpy(&job.client_auth, payload, sizeof(hybrid_msg_client_auth_t));
            job.hs_ctx = &s->hs;
            job.srv_hello_out = NULL;
            job.enqueue_ns = now_ns();

            s->auth_seq = seq;
            s->state = SESSION_WAIT_AUTH_VER;
            push_job(&job);
        } else if (type == PKT_DATA) {
            int s_idx = session_hash_find(ip, port);
            if (s_idx < 0) continue;
            session_t *s = &g_sessions[s_idx];
            if (s->state != SESSION_ESTABLISHED) continue;

            /* Check replay window */
            if (replay_window_check(&s->replay_win, seq) != 0) continue;

            if (plen < 28) continue; /* 12B nonce + 16B tag */
            const uint8_t *nonce = payload;
            const uint8_t *tag = payload + 12;
            const uint8_t *ct = payload + 28;
            int ct_len = (int)plen - 28;

            uint8_t pt[DATA_CHUNK_MAX];
            uint64_t t0 = now_ns();
            int pt_len = aead_decrypt(ct, ct_len, (const uint8_t *)hdr, PKT_HDR_BYTES,
                                      s->client_write_key, nonce, tag, pt);
            uint64_t t1 = now_ns();

            if (pt_len <= 0) continue;

            replay_window_update(&s->replay_win, seq);
            server_send_ack(g_listen_sock, &peer, seq, sid);

            s->metrics.msg_count++;
            s->metrics.bytes_recv += (uint64_t)pt_len;
            float dec_us = (float)(t1 - t0) / 1000.0f;
            s->metrics.total_decrypt_us += (double)dec_us;
            s->metrics.decrypt_count++;
            float avg_dec = (float)(s->metrics.total_decrypt_us / (double)s->metrics.decrypt_count);

            float ia_ms = 0.0f;
            uint64_t now_recv = now_ns();
            if (s->metrics.prev_recv_ns > 0) {
                ia_ms = (float)(now_recv - s->metrics.prev_recv_ns) / 1e6f;
            }
            s->metrics.prev_recv_ns = now_recv;

            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &peer.sin_addr, ip_str, sizeof(ip_str));

            ipc_push_rx_msg(s->client_registry_id, ip_str, ntohs(peer.sin_port),
                            sid, pt, (uint32_t)pt_len);
            ipc_push_rx_metrics(s->client_registry_id, dec_us, ia_ms,
                                (float)s->metrics.jitter_ms, avg_dec,
                                s->metrics.bytes_recv, seq);

            /* Echo back to client using server_write_key */
            uint8_t echo_pkt[12 + 16 + DATA_CHUNK_MAX];
            uint8_t echo_nonce[12];
            if (make_nonce(echo_nonce, s->tx_nonce_ctr++) == 0) {
                memcpy(echo_pkt, echo_nonce, 12);
                uint16_t echo_pkt_len = (uint16_t)(12 + 16 + pt_len);
                pkt_hdr_t echo_wire_hdr;
                echo_wire_hdr.seq = htonl(s->tx_seq);
                echo_wire_hdr.type = PKT_DATA;
                echo_wire_hdr.len = htons(echo_pkt_len);
                echo_wire_hdr.session_id = htobe64(sid);

                int echo_ct_len = aead_encrypt(
                    pt, pt_len, (const uint8_t *)&echo_wire_hdr, PKT_HDR_BYTES,
                    s->server_write_key, echo_nonce,
                    echo_pkt + 12 + 16, /* ciphertext */
                    echo_pkt + 12);     /* tag */
                if (echo_ct_len >= 0) {
                    server_send_packet(g_listen_sock, &peer, s->tx_seq++,
                                       PKT_DATA, sid, echo_pkt, echo_pkt_len);
                }
            }
        } else if (type == PKT_DISCONNECT) {
            int s_idx = session_hash_find(ip, port);
            if (s_idx >= 0) {
                session_free(s_idx);
                ipc_push_client_list();
            }
        }
    }

    printf("\n[server] Shutting down...\n");
    close(g_listen_sock);
    unlink(rx_path);
    unlink(tx_path);
    return 0;
}
