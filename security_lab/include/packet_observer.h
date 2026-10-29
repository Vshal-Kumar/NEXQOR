/*
 * security_lab/include/packet_observer.h
 *
 * Real-time packet observation, packet counters, length histograms,
 * and event capture during security testing.
 */

#ifndef SECURITY_LAB_PACKET_OBSERVER_H
#define SECURITY_LAB_PACKET_OBSERVER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t total_packets_seen;
    uint64_t total_bytes_seen;
    uint32_t count_by_type[32];
    double   first_packet_ts_ms;
    double   last_packet_ts_ms;
} packet_observer_stats_t;

/* Initializes observer statistics */
void packet_observer_init(packet_observer_stats_t *obs);

/* Records an observed packet */
void packet_observer_record(packet_observer_stats_t *obs, uint8_t type, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* SECURITY_LAB_PACKET_OBSERVER_H */
