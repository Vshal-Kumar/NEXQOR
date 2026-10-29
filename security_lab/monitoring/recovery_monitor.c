/*
 * security_lab/monitoring/recovery_monitor.c
 *
 * Implements recovery latency measurement to verify normal communication resumption.
 */

#include "recovery_monitor.h"
#include <stdio.h>
#include <unistd.h>
#include <time.h>

double recovery_monitor_await_clean_service(suite_adapter_t *adapter, double baseline_rtt_us, int max_wait_ms) {
    if (!adapter) return -1.0;

    struct timespec t0, now;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    double threshold_us = (baseline_rtt_us > 0) ? (baseline_rtt_us * 2.5) : 50000.0;
    if (threshold_us < 5000.0) threshold_us = 5000.0;

    int elapsed_ms = 0;
    while (elapsed_ms < max_wait_ms) {
        double rtt = 0;
        if (suite_adapter_probe_health(adapter, &rtt) == 0) {
            if (rtt <= threshold_us) {
                clock_gettime(CLOCK_MONOTONIC, &now);
                return (double)(now.tv_sec - t0.tv_sec) * 1e3 +
                       (double)(now.tv_nsec - t0.tv_nsec) * 1e-6;
            }
        }
        usleep(20000); /* 20 ms poll */
        elapsed_ms += 20;
    }

    return -1.0; /* Timed out */
}
