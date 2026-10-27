/*
 * hybrid/bench_nclient.c — N-Client Concurrent Hybrid Handshake Benchmark
 *
 * Suite: X25519 + ML-KEM-768 + Ed25519 + ML-DSA-65 + ChaCha20-Poly1305 + HKDF-SHA-384
 *
 * Spawns N concurrent client threads, each performing the full 4-way
 * hybrid mutual-authentication handshake against the running hybrid server (port 9879),
 * optionally followed by M encrypted message round-trips.
 *
 * Usage:
 *   ./bench_nclient              # 32 clients, 5 messages each
 *   ./bench_nclient 64           # 64 clients, handshake only
 *   ./bench_nclient 64 10        # 64 clients, 10 messages each
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

#include "transport.h"
#include "crypto/aead.h"
#include "include/hybrid_crypto.h"
#include "include/hybrid_handshake.h"
#include "include/hybrid_session.h"
#include "include/hybrid_errors.h"

#define DEFAULT_NUM_CLIENTS 32
#define DEFAULT_NUM_MSGS    5

static char g_server_ip[64] = "";
static struct sockaddr_in g_server_peer;

typedef struct {
    unsigned long long user, nice, system, idle, iowait, irq, softirq, steal;
} cpu_ticks_t;

static int get_cpu_ticks(cpu_ticks_t *ticks) {
    FILE *f = fopen("/proc/stat", "r");
    if (!f) return -1;
    char buf[256];
    if (fgets(buf, sizeof(buf), f)) {
        int parsed = sscanf(buf, "cpu  %llu %llu %llu %llu %llu %llu %llu %llu",
                            &ticks->user, &ticks->nice, &ticks->system, &ticks->idle,
                            &ticks->iowait, &ticks->irq, &ticks->softirq, &ticks->steal);
        fclose(f);
        return (parsed >= 4) ? 0 : -1;
    }
    fclose(f);
    return -1;
}

static double calculate_cpu_utilization(const cpu_ticks_t *start, const cpu_ticks_t *end) {
    unsigned long long start_idle = start->idle + start->iowait;
    unsigned long long end_idle = end->idle + end->iowait;

    unsigned long long start_total = start->user + start->nice + start->system +
                                     start->idle + start->iowait + start->irq +
                                     start->softirq + start->steal;
    unsigned long long end_total = end->user + end->nice + end->system +
                                   end->idle + end->iowait + end->irq +
                                   end->softirq + end->steal;

    if (end_total <= start_total) return 0.0;
    unsigned long long total_diff = end_total - start_total;
    unsigned long long idle_diff = end_idle - start_idle;
    return 100.0 * (1.0 - ((double)idle_diff / (double)total_diff));
}

static inline uint64_t ns_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

typedef struct {
    int      success;
    double   hs_wall_ms;
    int      msgs_sent;
    int      msgs_recv;
    double   msg_min_rtt_ms;
    double   msg_max_rtt_ms;
    double   msg_avg_rtt_ms;
    uint64_t start_ns;
    uint64_t end_ns;
} client_result_t;

static int g_num_clients = DEFAULT_NUM_CLIENTS;
static int g_num_msgs    = DEFAULT_NUM_MSGS;
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
    if (tv.tv_sec == 0 && tv.tv_usec < 1000) tv.tv_usec = 1000;
    setsockopt(c->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    double deadline = now_ms() + timeout_ms;
    for (;;) {
        if (now_ms() >= deadline) break;
        ssize_t n = pkt_recv(c, &hdr, payload, max, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            continue;
        }
        if (hdr.type == want) {
            result = n;
            break;
        }
    }

    struct timeval tv_def = { .tv_sec = 0, .tv_usec = 50000 };
    setsockopt(c->sock, SOL_SOCKET, SO_RCVTIMEO, &tv_def, sizeof(tv_def));
    return result;
}

static void *client_thread(void *arg) {
    int idx = (int)(intptr_t)arg;
    client_result_t *r = &g_results[idx];
    memset(r, 0, sizeof(*r));

    hybrid_identity_pk_t id_pk;
    hybrid_identity_sk_t id_sk;
    hybrid_generate_identity_keys(&id_pk, &id_sk);

    int sock = make_client_sock();
    if (sock < 0) return NULL;

    conn_t c;
    conn_init(&c, sock);
    c.peer = g_server_peer;
    c.peer_len = sizeof(c.peer);

    /* Barrier sync for concurrent launch */
    pthread_barrier_wait(&g_start_barrier);

    if (g_num_clients > 10) {
        usleep((useconds_t)(idx * 500));
    }

    r->start_ns = ns_now();

    hybrid_handshake_ctx_t hs;
    if (hybrid_handshake_init(&hs, HYBRID_ROLE_CLIENT, &id_pk, &id_sk) != HYBRID_SUCCESS) {
        goto fail;
    }

    /* Phase 1: CLIENT_HELLO */
    hybrid_msg_client_hello_t hello;
    if (hybrid_client_create_hello(&hs, &hello) != HYBRID_SUCCESS) {
        hybrid_handshake_cleanup(&hs);
        goto fail;
    }

    hybrid_msg_server_hello_t srv_hello;
    ssize_t n = -1;

    for (int attempt = 0; attempt < 10; attempt++) {
        if (attempt > 0) {
            c.tx_seq = 1;
            usleep((useconds_t)(10000 + (rand() % 30000)));
        }
        if (pkt_send(&c, PKT_CLIENT_HELLO, (const uint8_t *)&hello, (uint16_t)sizeof(hello)) < 0) {
            hybrid_handshake_cleanup(&hs);
            goto fail;
        }

        n = recv_type_timeout(&c, PKT_SERVER_HELLO, (uint8_t *)&srv_hello, sizeof(srv_hello), 2500);
        if (n == (ssize_t)sizeof(srv_hello)) break;
    }

    if (n != (ssize_t)sizeof(srv_hello)) {
        hybrid_handshake_cleanup(&hs);
        goto fail;
    }

    /* Phase 2: Process SERVER_HELLO */
    if (hybrid_client_process_server_hello(&hs, &srv_hello, NULL) != HYBRID_SUCCESS) {
        hybrid_handshake_cleanup(&hs);
        goto fail;
    }

    /* Phase 3: CLIENT_AUTH */
    hybrid_msg_client_auth_t cl_auth;
    if (hybrid_client_create_auth(&hs, &cl_auth) != HYBRID_SUCCESS) {
        hybrid_handshake_cleanup(&hs);
        goto fail;
    }

    if (pkt_send_reliable(&c, PKT_CLIENT_AUTH, (const uint8_t *)&cl_auth, (uint16_t)sizeof(cl_auth)) != 0) {
        hybrid_handshake_cleanup(&hs);
        goto fail;
    }

    /* Server ACK */
    uint8_t ack_payload[64];
    recv_type_timeout(&c, PKT_ACK, ack_payload, sizeof(ack_payload), 2000);

    c.established = 1;
    c.session_id = hs.session_id;
    memcpy(c.tx_key, hs.client_write_key, 32);
    memcpy(c.rx_key, hs.server_write_key, 32);

    r->end_ns = ns_now();
    r->hs_wall_ms = (double)(r->end_ns - r->start_ns) / 1e6;
    r->success = 1;

    hybrid_handshake_cleanup(&hs);

    /* Stream M test messages if requested */
    if (g_num_msgs > 0) {
        metrics_t m = {0};
        m.msg_min_rtt_ms = 1e15;
        double sum_rtt = 0.0;
        int rtt_cnt = 0;

        char msg_buf[128];
        for (int m_idx = 0; m_idx < g_num_msgs && !g_stop; m_idx++) {
            snprintf(msg_buf, sizeof(msg_buf), "Bench packet #%d from client %d", m_idx + 1, idx);
            if (data_send(&c, &m, (const uint8_t *)msg_buf, (uint32_t)strlen(msg_buf)) == 0) {
                r->msgs_sent++;
                r->msgs_recv++;
                sum_rtt += m.msg_last_rtt_ms;
                rtt_cnt++;
            }
            usleep(10000);
        }
        if (rtt_cnt > 0) {
            r->msg_avg_rtt_ms = sum_rtt / (double)rtt_cnt;
            r->msg_min_rtt_ms = m.msg_min_rtt_ms;
            r->msg_max_rtt_ms = m.msg_max_rtt_ms;
        }
    }

    pkt_send(&c, PKT_DISCONNECT, NULL, 0);
    conn_destroy(&c);
    close(sock);
    return NULL;

fail:
    r->success = 0;
    conn_destroy(&c);
    close(sock);
    return NULL;
}

int main(int argc, char *argv[]) {
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    if (argc > 1) g_num_clients = atoi(argv[1]);
    if (argc > 2) g_num_msgs = atoi(argv[2]);

    if (g_num_clients <= 0) g_num_clients = DEFAULT_NUM_CLIENTS;
    if (g_num_msgs < 0) g_num_msgs = 0;

    printf("\n╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                 QRYPTONEX High-Concurrency Hybrid Handshake Benchmark                                            ║\n");
    printf("║  Suite: X25519 + ML-KEM-768 + Ed25519 + ML-DSA-65 + ChaCha20-Poly1305 + HKDF-SHA-384                              ║\n");
    printf("║  Clients: %-4d | Messages/Client: %-3d | Server Port: %d                                                         ║\n",
           g_num_clients, g_num_msgs, SERVER_PORT);
    printf("╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝\n\n");

    if (hybrid_crypto_init() != HYBRID_SUCCESS) {
        fprintf(stderr, "Crypto init failed\n");
        return 1;
    }

    if (resolve_server_address(NULL, &g_server_peer, g_server_ip, sizeof(g_server_ip)) != 0) {
        fprintf(stderr, "Error resolving server address\n");
        return 1;
    }
    printf("[bench] Target Hybrid Server: %s:%d\n", g_server_ip, SERVER_PORT);

    g_results = calloc(g_num_clients, sizeof(client_result_t));
    pthread_barrier_init(&g_start_barrier, NULL, (unsigned)g_num_clients + 1);

    pthread_t *tids = malloc(g_num_clients * sizeof(pthread_t));
    for (int i = 0; i < g_num_clients; i++) {
        pthread_create(&tids[i], NULL, client_thread, (void *)(intptr_t)i);
    }

    cpu_ticks_t cpu_start, cpu_end;
    get_cpu_ticks(&cpu_start);
    uint64_t bench_start = ns_now();

    printf("[bench] Launching %d concurrent client threads...\n", g_num_clients);
    pthread_barrier_wait(&g_start_barrier);

    for (int i = 0; i < g_num_clients; i++) {
        pthread_join(tids[i], NULL);
    }

    uint64_t bench_end = ns_now();
    get_cpu_ticks(&cpu_end);
    double total_wall_sec = (double)(bench_end - bench_start) / 1e9;
    double cpu_util = calculate_cpu_utilization(&cpu_start, &cpu_end);

    int successes = 0;
    double sum_hs_ms = 0.0;
    int total_msgs = 0;

    for (int i = 0; i < g_num_clients; i++) {
        if (g_results[i].success) {
            successes++;
            sum_hs_ms += g_results[i].hs_wall_ms;
            total_msgs += g_results[i].msgs_sent;
        }
    }

    double avg_hs_ms = (successes > 0) ? (sum_hs_ms / (double)successes) : 0.0;
    double hs_per_sec = (total_wall_sec > 0.0) ? ((double)successes / total_wall_sec) : 0.0;

    printf("\n╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                                    BENCHMARK EXECUTION RESULTS                                                   ║\n");
    printf("╠══════════════════════════════════════════════════════════════════════════════════════════════════════════════════╣\n");
    printf("║  Successful Handshakes : %d / %d (%.1f%%)                                                                     \n",
           successes, g_num_clients, ((double)successes / (double)g_num_clients) * 100.0);
    printf("║  Total Wall Time       : %.3f s                                                                               \n", total_wall_sec);
    printf("║  Average Handshake Time: %.2f ms                                                                              \n", avg_hs_ms);
    printf("║  Throughput            : %.2f handshakes / sec                                                                \n", hs_per_sec);
    printf("║  CPU Utilization       : %.2f%%                                                                               \n", cpu_util);
    if (g_num_msgs > 0) {
        printf("║  Encrypted Msgs Exchanged: %d datagrams                                                                       \n", total_msgs);
    }
    printf("╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝\n\n");

    free(tids);
    free(g_results);
    pthread_barrier_destroy(&g_start_barrier);
    return 0;
}
