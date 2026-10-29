/*
 * security_lab/include/metrics.h
 *
 * Performance and security testing metrics tracker, percentiles (P50, P95, P99),
 * statistical aggregations, and result status definitions.
 */

#ifndef SECURITY_LAB_METRICS_H
#define SECURITY_LAB_METRICS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    RESULT_PASS = 0,
    RESULT_FAIL,
    RESULT_INCONCLUSIVE,
    RESULT_NOT_IMPLEMENTED,
    RESULT_NOT_APPLICABLE,
    RESULT_ERROR,
    RESULT_ABORTED
} result_status_t;

const char *result_status_string(result_status_t status);

#define METRICS_MAX_SAMPLES 4096

typedef struct {
    double samples[METRICS_MAX_SAMPLES];
    size_t count;
    double min_val;
    double max_val;
    double sum_val;
} latency_tracker_t;

typedef struct {
    char            scenario_id[64];
    char            scenario_name[128];
    char            suite_name[32];
    result_status_t status;
    char            status_rationale[256];
    char            evidence_summary[512];

    uint64_t        start_mono_ns;
    uint64_t        end_mono_ns;
    double          duration_sec;

    /* Handshake Metrics */
    uint32_t        handshake_attempts;
    uint32_t        handshake_successes;
    uint32_t        handshake_failures;
    latency_tracker_t handshake_lat_ms;

    /* Application / Telemetry Metrics */
    uint32_t        messages_sent;
    uint32_t        messages_acked;
    uint32_t        messages_lost;
    latency_tracker_t message_rtt_ms;

    /* Security Attack Counters */
    uint32_t        injected_replays;
    uint32_t        accepted_replays;       /* MUST BE 0 for PASS */
    uint32_t        rejected_replays;

    uint32_t        injected_tampered;
    uint32_t        accepted_tampered;      /* MUST BE 0 for PASS */
    uint32_t        rejected_tampered;

    uint32_t        injected_malformed;
    uint32_t        rejected_malformed;
    uint32_t        server_crashes;         /* MUST BE 0 for PASS */

    /* Resilience & Recovery */
    double          baseline_rtt_us;
    double          impaired_rtt_us;
    double          recovery_rtt_us;
    double          recovery_time_ms;

    /* System Resource Utilization */
    double          cpu_utilization_pct;
    double          peak_rss_mb;
    long            voluntary_ctxt_switches;
    long            involuntary_ctxt_switches;
} scenario_result_t;

/* Initializes a latency tracker */
void latency_tracker_init(latency_tracker_t *lt);

/* Adds a measured sample */
void latency_tracker_add(latency_tracker_t *lt, double val);

/* Calculates percentiles (p50, p95, p99) and mean */
void latency_tracker_calc(const latency_tracker_t *lt,
                          double *out_mean, double *out_p50,
                          double *out_p95, double *out_p99);

/* Initializes a scenario result object */
void scenario_result_init(scenario_result_t *res, const char *scenario_id,
                          const char *scenario_name, const char *suite_name);

/* Finalizes a scenario result object, computes duration and status */
void scenario_result_finalize(scenario_result_t *res, result_status_t status,
                              const char *rationale, const char *evidence);

#ifdef __cplusplus
}
#endif

#endif /* SECURITY_LAB_METRICS_H */
