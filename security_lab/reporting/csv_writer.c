/*
 * security_lab/reporting/csv_writer.c
 *
 * Implements CSV formatting and export for security testing runs.
 */

#include "report_writer.h"
#include <stdio.h>
#include <stdlib.h>

int report_write_metrics_csv(const run_metadata_t *meta,
                             const scenario_result_t *results, size_t count) {
    if (!meta || !results) return -1;

    char csv_path[512];
    snprintf(csv_path, sizeof(csv_path), "%s/metrics.csv", meta->run_dir);

    FILE *f = fopen(csv_path, "w");
    if (!f) return -1;

    /* Header row */
    fprintf(f, "suite,scenario_id,status,duration_sec,handshake_attempts,handshake_success,hs_mean_ms,hs_p95_ms,msg_sent,msg_acked,msg_lost,replays_injected,replays_accepted,tampered_injected,tampered_accepted,malformed_injected,crashes,baseline_rtt_us,recovery_rtt_us,recovery_time_ms\n");

    for (size_t i = 0; i < count; i++) {
        const scenario_result_t *r = &results[i];
        double hs_mean = 0, hs_p50 = 0, hs_p95 = 0, hs_p99 = 0;
        latency_tracker_calc(&r->handshake_lat_ms, &hs_mean, &hs_p50, &hs_p95, &hs_p99);

        fprintf(f, "%s,%s,%s,%.4f,%u,%u,%.3f,%.3f,%u,%u,%u,%u,%u,%u,%u,%u,%u,%.2f,%.2f,%.2f\n",
                r->suite_name,
                r->scenario_id,
                result_status_string(r->status),
                r->duration_sec,
                r->handshake_attempts,
                r->handshake_successes,
                hs_mean,
                hs_p95,
                r->messages_sent,
                r->messages_acked,
                r->messages_lost,
                r->injected_replays,
                r->accepted_replays,
                r->injected_tampered,
                r->accepted_tampered,
                r->injected_malformed,
                r->server_crashes,
                r->baseline_rtt_us,
                r->recovery_rtt_us,
                r->recovery_time_ms);
    }

    fclose(f);
    return 0;
}
