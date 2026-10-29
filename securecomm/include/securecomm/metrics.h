/*
 * securecomm/include/securecomm/metrics.h
 *
 * Performance, latency, memory RSS, and throughput monitoring for SecureComm.
 */

#ifndef SECURECOMM_METRICS_H
#define SECURECOMM_METRICS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t start_time_sec;
    uint64_t uptime_sec;
    
    /* Memory Metrics */
    uint64_t peak_rss_kb;
    uint64_t current_rss_kb;
    
    /* Network & Throughput */
    uint64_t bytes_sent;
    uint64_t bytes_recv;
    uint64_t packets_sent;
    uint64_t packets_recv;
    uint64_t packets_replayed;
    uint64_t packets_dropped;
    
    /* Handshake Metrics */
    uint32_t handshakes_attempted;
    uint32_t handshakes_succeeded;
    uint32_t handshakes_failed;
    double   avg_handshake_latency_ms;
    double   min_handshake_latency_ms;
    double   max_handshake_latency_ms;
    
    /* Concurrency */
    uint32_t active_sessions;
    uint32_t peak_concurrent_sessions;
} securecomm_metrics_t;

void securecomm_metrics_init(securecomm_metrics_t *m);
void securecomm_metrics_update_memory(securecomm_metrics_t *m);
void securecomm_metrics_record_handshake(securecomm_metrics_t *m, double latency_ms, bool success);
void securecomm_metrics_record_packet_tx(securecomm_metrics_t *m, size_t bytes);
void securecomm_metrics_record_packet_rx(securecomm_metrics_t *m, size_t bytes);
void securecomm_metrics_print(const securecomm_metrics_t *m, FILE *out);

#ifdef __cplusplus
}
#endif

#endif /* SECURECOMM_METRICS_H */
