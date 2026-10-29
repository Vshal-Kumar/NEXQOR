/*
 * securecomm/src/monitoring/metrics.c
 *
 * Real-time performance, latency, memory RSS, and throughput monitoring for SecureComm.
 */

#define _POSIX_C_SOURCE 200809L
#include "securecomm/metrics.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <unistd.h>

void securecomm_metrics_init(securecomm_metrics_t *m) {
    if (!m) return;
    memset(m, 0, sizeof(*m));
    
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    m->start_time_sec = (uint64_t)ts.tv_sec;
    m->min_handshake_latency_ms = 999999.0;
    
    securecomm_metrics_update_memory(m);
}

void securecomm_metrics_update_memory(securecomm_metrics_t *m) {
    if (!m) return;

    /* Peak RSS via getrusage */
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) == 0) {
        m->peak_rss_kb = (uint64_t)ru.ru_maxrss;
    }

    /* Current RSS via /proc/self/statm */
    FILE *fp = fopen("/proc/self/statm", "r");
    if (fp) {
        long pages = 0;
        long resident = 0;
        if (fscanf(fp, "%ld %ld", &pages, &resident) == 2) {
            long page_size_kb = sysconf(_SC_PAGESIZE) / 1024;
            m->current_rss_kb = (uint64_t)(resident * page_size_kb);
        }
        fclose(fp);
    }

    /* Update uptime */
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    if ((uint64_t)ts.tv_sec >= m->start_time_sec) {
        m->uptime_sec = (uint64_t)ts.tv_sec - m->start_time_sec;
    }
}

void securecomm_metrics_record_handshake(securecomm_metrics_t *m, double latency_ms, bool success) {
    if (!m) return;

    m->handshakes_attempted++;
    if (success) {
        m->handshakes_succeeded++;
        if (latency_ms < m->min_handshake_latency_ms) {
            m->min_handshake_latency_ms = latency_ms;
        }
        if (latency_ms > m->max_handshake_latency_ms) {
            m->max_handshake_latency_ms = latency_ms;
        }

        /* Running average */
        if (m->handshakes_succeeded == 1) {
            m->avg_handshake_latency_ms = latency_ms;
        } else {
            m->avg_handshake_latency_ms =
                ((m->avg_handshake_latency_ms * (m->handshakes_succeeded - 1)) + latency_ms) / m->handshakes_succeeded;
        }
    } else {
        m->handshakes_failed++;
    }
    securecomm_metrics_update_memory(m);
}

void securecomm_metrics_record_packet_tx(securecomm_metrics_t *m, size_t bytes) {
    if (!m) return;
    m->packets_sent++;
    m->bytes_sent += bytes;
}

void securecomm_metrics_record_packet_rx(securecomm_metrics_t *m, size_t bytes) {
    if (!m) return;
    m->packets_recv++;
    m->bytes_recv += bytes;
}

void securecomm_metrics_print(const securecomm_metrics_t *m, FILE *out) {
    if (!m || !out) return;

    fprintf(out, "=========================================================\n");
    fprintf(out, "               SECURECOMM METRICS & HEALTH               \n");
    fprintf(out, "=========================================================\n");
    fprintf(out, " Uptime                     : %lu seconds\n", (unsigned long)m->uptime_sec);
    fprintf(out, " Current Memory RSS         : %lu KB\n", (unsigned long)m->current_rss_kb);
    fprintf(out, " Peak Memory RSS            : %lu KB\n", (unsigned long)m->peak_rss_kb);
    fprintf(out, " Active Sessions            : %u\n", m->active_sessions);
    fprintf(out, " Peak Concurrent Sessions   : %u\n", m->peak_concurrent_sessions);
    fprintf(out, "---------------------------------------------------------\n");
    fprintf(out, " Handshakes (Attempted)     : %u\n", m->handshakes_attempted);
    fprintf(out, " Handshakes (Succeeded)     : %u\n", m->handshakes_succeeded);
    fprintf(out, " Handshakes (Failed)        : %u\n", m->handshakes_failed);
    if (m->handshakes_succeeded > 0) {
        fprintf(out, " Handshake Latency (Min)    : %.3f ms\n", m->min_handshake_latency_ms);
        fprintf(out, " Handshake Latency (Avg)    : %.3f ms\n", m->avg_handshake_latency_ms);
        fprintf(out, " Handshake Latency (Max)    : %.3f ms\n", m->max_handshake_latency_ms);
    }
    fprintf(out, "---------------------------------------------------------\n");
    fprintf(out, " Packets Transmitted (TX)   : %lu packets (%lu bytes)\n",
            (unsigned long)m->packets_sent, (unsigned long)m->bytes_sent);
    fprintf(out, " Packets Received (RX)      : %lu packets (%lu bytes)\n",
            (unsigned long)m->packets_recv, (unsigned long)m->bytes_recv);
    fprintf(out, " Packets Replayed (Dropped) : %lu\n", (unsigned long)m->packets_replayed);
    fprintf(out, " Packets Dropped/Corrupt    : %lu\n", (unsigned long)m->packets_dropped);
    fprintf(out, "=========================================================\n");
}
