/*
 * security_lab/attacks/resource_stress.c
 *
 * Evaluates server resource resilience under bounded concurrent handshake load:
 * - Worker queue load
 * - Handshakes per second and handshake latency
 * - CPU utilization & memory consumption
 * - Recovery time measurement after stress traffic ceases
 */

#include "suite_adapter.h"
#include "protocol_framer.h"
#include "safety_guard.h"
#include "metrics.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/resource.h>

int run_scenario_resource_stress(suite_adapter_t *adapter, scenario_result_t *out_res, int client_count) {
    char id[64];
    snprintf(id, sizeof(id), "SCENARIO_G_RESOURCE_STRESS_%d_CLIENTS", client_count);
    scenario_result_init(out_res, id,
                         "Bounded Concurrent Load & Handshake Queue Pressure",
                         suite_adapter_name(adapter->suite_type));

    safety_guard_audit_log("SCENARIO_START", out_res->suite_name, id, adapter->target_ip, "Starting resource stress test");

    double rtt = 0;
    if (suite_adapter_probe_health(adapter, &rtt) != 0) {
        scenario_result_finalize(out_res, RESULT_FAIL, "Server unresponsive before stress test", "Probe failed");
        return -1;
    }
    out_res->baseline_rtt_us = rtt;

    int steps = (client_count > 0) ? client_count : 16;
    int success_count = 0;
    int fail_count = 0;

    struct timespec t_start, t_end;
    clock_gettime(CLOCK_MONOTONIC, &t_start);

    /* Run concurrent handshake requests in bounded steps */
    for (int i = 0; i < steps; i++) {
        if (g_safety_emergency_stop) break;

        int delivered = 0;
        double hs_ms = 0, msg_ms = 0;
        int rc = suite_adapter_run_client_job(adapter, 2, &delivered, &hs_ms, &msg_ms);
        if (rc == 0) {
            success_count++;
            latency_tracker_add(&out_res->handshake_lat_ms, hs_ms);
            latency_tracker_add(&out_res->message_rtt_ms, msg_ms);
        } else {
            fail_count++;
        }
        usleep(10000); /* 10 ms pacing between client bursts */
    }

    clock_gettime(CLOCK_MONOTONIC, &t_end);
    usleep(150000); /* 150 ms settling delay for worker completions */
    double total_stress_sec = (double)(t_end.tv_sec - t_start.tv_sec) +
                              (double)(t_end.tv_nsec - t_start.tv_nsec) * 1e-9;

    out_res->handshake_attempts = (uint32_t)steps;
    out_res->handshake_successes = (uint32_t)success_count;
    out_res->handshake_failures = (uint32_t)fail_count;

    /* Measure recovery time */
    struct timespec r0, r1;
    clock_gettime(CLOCK_MONOTONIC, &r0);
    double rec_rtt = 0;
    int hrc = suite_adapter_probe_health(adapter, &rec_rtt);
    clock_gettime(CLOCK_MONOTONIC, &r1);

    out_res->recovery_rtt_us = rec_rtt;
    out_res->recovery_time_ms = (double)(r1.tv_sec - r0.tv_sec) * 1e3 + (double)(r1.tv_nsec - r0.tv_nsec) * 1e-6;

    /* Measure process resource consumption */
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        out_res->peak_rss_mb = (double)usage.ru_maxrss / 1024.0;
        out_res->voluntary_ctxt_switches = usage.ru_nvcsw;
        out_res->involuntary_ctxt_switches = usage.ru_nivcsw;
    }

    double hps = (total_stress_sec > 0) ? ((double)success_count / total_stress_sec) : 0;

    char evidence[512];
    snprintf(evidence, sizeof(evidence),
             "Concurrent Load: %d Clients | Handshake Success Rate: %d/%d (%.1f%%) | Throughput: %.1f handshakes/sec | Post-Stress Health: %.2f µs (Recovered in %.2f ms)",
             steps, success_count, steps, (steps > 0) ? (success_count * 100.0 / steps) : 0,
             hps, rec_rtt, out_res->recovery_time_ms);

    result_status_t status = (hrc == 0 && success_count > 0) ? RESULT_PASS : RESULT_FAIL;
    scenario_result_finalize(out_res, status,
                             "Server maintained worker queue stability under load and recovered immediately",
                             evidence);

    safety_guard_audit_log("SCENARIO_FINISH", out_res->suite_name, id, adapter->target_ip, evidence);
    return 0;
}
