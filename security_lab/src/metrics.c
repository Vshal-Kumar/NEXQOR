/*
 * security_lab/src/metrics.c
 *
 * Implements statistical latency calculation, percentiles (P50, P95, P99),
 * and scenario result management.
 */

#include "metrics.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

const char *result_status_string(result_status_t status) {
    switch (status) {
        case RESULT_PASS:            return "PASS";
        case RESULT_FAIL:            return "FAIL";
        case RESULT_INCONCLUSIVE:    return "INCONCLUSIVE";
        case RESULT_NOT_IMPLEMENTED: return "NOT_IMPLEMENTED";
        case RESULT_NOT_APPLICABLE:  return "NOT_APPLICABLE";
        case RESULT_ERROR:           return "ERROR";
        case RESULT_ABORTED:         return "ABORTED";
        default:                     return "UNKNOWN";
    }
}

void latency_tracker_init(latency_tracker_t *lt) {
    if (!lt) return;
    memset(lt, 0, sizeof(*lt));
    lt->min_val = 1e9;
}

void latency_tracker_add(latency_tracker_t *lt, double val) {
    if (!lt) return;
    if (lt->count < METRICS_MAX_SAMPLES) {
        lt->samples[lt->count++] = val;
    }
    if (val < lt->min_val) lt->min_val = val;
    if (val > lt->max_val) lt->max_val = val;
    lt->sum_val += val;
}

static int compare_doubles(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    if (da < db) return -1;
    if (da > db) return 1;
    return 0;
}

void latency_tracker_calc(const latency_tracker_t *lt,
                          double *out_mean, double *out_p50,
                          double *out_p95, double *out_p99) {
    if (!lt || lt->count == 0) {
        if (out_mean) *out_mean = 0.0;
        if (out_p50)  *out_p50  = 0.0;
        if (out_p95)  *out_p95  = 0.0;
        if (out_p99)  *out_p99  = 0.0;
        return;
    }

    if (out_mean) *out_mean = lt->sum_val / (double)lt->count;

    /* Sort copy of samples for percentiles */
    double *sorted = malloc(lt->count * sizeof(double));
    if (!sorted) return;
    memcpy(sorted, lt->samples, lt->count * sizeof(double));
    qsort(sorted, lt->count, sizeof(double), compare_doubles);

    if (out_p50) {
        size_t idx = (size_t)((double)lt->count * 0.50);
        if (idx >= lt->count) idx = lt->count - 1;
        *out_p50 = sorted[idx];
    }
    if (out_p95) {
        size_t idx = (size_t)((double)lt->count * 0.95);
        if (idx >= lt->count) idx = lt->count - 1;
        *out_p95 = sorted[idx];
    }
    if (out_p99) {
        size_t idx = (size_t)((double)lt->count * 0.99);
        if (idx >= lt->count) idx = lt->count - 1;
        *out_p99 = sorted[idx];
    }

    free(sorted);
}

void scenario_result_init(scenario_result_t *res, const char *scenario_id,
                          const char *scenario_name, const char *suite_name) {
    if (!res) return;
    memset(res, 0, sizeof(*res));

    strncpy(res->scenario_id, scenario_id ? scenario_id : "UNKNOWN", sizeof(res->scenario_id) - 1);
    strncpy(res->scenario_name, scenario_name ? scenario_name : "Unnamed Scenario", sizeof(res->scenario_name) - 1);
    strncpy(res->suite_name, suite_name ? suite_name : "pqc", sizeof(res->suite_name) - 1);
    res->status = RESULT_INCONCLUSIVE;

    latency_tracker_init(&res->handshake_lat_ms);
    latency_tracker_init(&res->message_rtt_ms);

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    res->start_mono_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

void scenario_result_finalize(scenario_result_t *res, result_status_t status,
                              const char *rationale, const char *evidence) {
    if (!res) return;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    res->end_mono_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
    res->duration_sec = (double)(res->end_mono_ns - res->start_mono_ns) * 1e-9;

    res->status = status;
    if (rationale) {
        strncpy(res->status_rationale, rationale, sizeof(res->status_rationale) - 1);
    }
    if (evidence) {
        strncpy(res->evidence_summary, evidence, sizeof(res->evidence_summary) - 1);
    }
}
