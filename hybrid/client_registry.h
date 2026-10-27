/*
 * hybrid/client_registry.h — Thread-safe multi-client registry for Hybrid Suite
 *
 * Tracks all active Hybrid sessions (X25519 + ML-KEM-768 + Ed25519 + ML-DSA-65).
 * Each entry holds the conn_t, metrics, client IP string, assigned client ID (1..MAX_CLIENTS),
 * and a per-client mutex so the TX terminal can safely send to a specific client without
 * blocking others.
 */

#ifndef HYBRID_CLIENT_REGISTRY_H
#define HYBRID_CLIENT_REGISTRY_H

#include <stdint.h>
#include <pthread.h>
#include <netinet/in.h>
#include "transport.h"
#include "ipc.h"

#define CLIENT_TAG_MAX  48

/* ── Per-client slot ─────────────────────────────────────────────── */
typedef struct {
    conn_t      conn;
    metrics_t   metrics;

    int         client_id;
    char        ip_str[INET_ADDRSTRLEN];
    uint16_t    port;
    char        tag[CLIENT_TAG_MAX];
    uint64_t    session_id;

    int         active;
    double      connect_time_ms;

    pthread_mutex_t tx_mutex;

    uint64_t    last_send_ns;
    uint64_t    last_recv_ns;
} client_slot_t;

/* ── Snapshot entry ──────────────────────────────────────────────── */
typedef struct {
    int      client_id;
    char     tag[CLIENT_TAG_MAX];
    char     ip_str[INET_ADDRSTRLEN];
    uint16_t port;
    uint64_t session_id;
    double   hs_total_ms;
    uint64_t msg_count;
    uint64_t bytes_sent;
    uint64_t bytes_recv;
    double   jitter_ms;
} client_info_t;

/* ── Registry API ────────────────────────────────────────────────── */
void registry_init(void);
int registry_add(const conn_t *conn, const metrics_t *metrics);
void registry_remove(int client_id);
int registry_send(int client_id, const uint8_t *msg, uint32_t len);
int registry_broadcast(const uint8_t *msg, uint32_t len);
void registry_mark_recv(int client_id, uint64_t recv_ns);
int registry_get_snapshot(client_info_t *out, int max);
conn_t *registry_get_conn(int client_id);
metrics_t *registry_get_metrics(int client_id);
int registry_count(void);

#endif /* HYBRID_CLIENT_REGISTRY_H */
