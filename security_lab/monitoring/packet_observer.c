/*
 * security_lab/monitoring/packet_observer.c
 *
 * Implements packet counting, type distribution, and traffic observation.
 */

#include "packet_observer.h"
#include <string.h>
#include <time.h>

void packet_observer_init(packet_observer_stats_t *obs) {
    if (!obs) return;
    memset(obs, 0, sizeof(*obs));
}

void packet_observer_record(packet_observer_stats_t *obs, uint8_t type, size_t len) {
    if (!obs) return;

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    double now_ms = (double)ts.tv_sec * 1e3 + (double)ts.tv_nsec * 1e-6;

    if (obs->total_packets_seen == 0) {
        obs->first_packet_ts_ms = now_ms;
    }
    obs->last_packet_ts_ms = now_ms;

    obs->total_packets_seen++;
    obs->total_bytes_seen += len;

    if (type < 32) {
        obs->count_by_type[type]++;
    }
}
