/*
 * security_lab/tests/test_metrics.c
 *
 * Unit tests for statistical metric calculation, percentiles (P50, P95, P99),
 * and status transitions.
 */

#include "metrics.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "\033[1;31mFAIL: %s (%s:%d)\033[0m\n", msg, __FILE__, __LINE__); \
        return 1; \
    } else { \
        printf("  [PASS] %s\n", msg); \
    } \
} while(0)

int main(void) {
    printf("\n=== Running Metrics Unit Tests ===\n");

    /* Test 1: Latency tracker initialization */
    latency_tracker_t lt;
    latency_tracker_init(&lt);
    TEST_ASSERT(lt.count == 0, "Initial count is zero");

    /* Test 2: Add 100 deterministic samples: 1.0 to 100.0 */
    for (int i = 1; i <= 100; i++) {
        latency_tracker_add(&lt, (double)i);
    }
    TEST_ASSERT(lt.count == 100, "100 samples recorded");
    TEST_ASSERT(lt.min_val == 1.0, "Min value is 1.0");
    TEST_ASSERT(lt.max_val == 100.0, "Max value is 100.0");

    double mean = 0, p50 = 0, p95 = 0, p99 = 0;
    latency_tracker_calc(&lt, &mean, &p50, &p95, &p99);
    TEST_ASSERT(fabs(mean - 50.5) < 0.01, "Mean is 50.5");
    TEST_ASSERT(fabs(p50 - 51.0) <= 1.0, "P50 is ~51.0");
    TEST_ASSERT(fabs(p95 - 96.0) <= 1.0, "P95 is ~96.0");
    TEST_ASSERT(fabs(p99 - 100.0) <= 1.0, "P99 is ~100.0");

    /* Test 3: Status string mappings */
    TEST_ASSERT(strcmp(result_status_string(RESULT_PASS), "PASS") == 0, "RESULT_PASS string");
    TEST_ASSERT(strcmp(result_status_string(RESULT_FAIL), "FAIL") == 0, "RESULT_FAIL string");
    TEST_ASSERT(strcmp(result_status_string(RESULT_INCONCLUSIVE), "INCONCLUSIVE") == 0, "RESULT_INCONCLUSIVE string");

    /* Test 4: Scenario result finalization */
    scenario_result_t res;
    scenario_result_init(&res, "TEST_01", "Test Scenario", "pqc");
    TEST_ASSERT(res.status == RESULT_INCONCLUSIVE, "Initial status is INCONCLUSIVE");

    scenario_result_finalize(&res, RESULT_PASS, "All checks passed", "Evidence details");
    TEST_ASSERT(res.status == RESULT_PASS, "Final status is PASS");
    TEST_ASSERT(strcmp(res.status_rationale, "All checks passed") == 0, "Rationale matches");
    TEST_ASSERT(strcmp(res.evidence_summary, "Evidence details") == 0, "Evidence matches");

    printf("\nAll Metrics Tests Passed Successfully!\n\n");
    return 0;
}
