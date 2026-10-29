/*
 * security_lab/include/report_writer.h
 *
 * Exporters for structured JSON, JSONL, CSV, and Markdown comparative reports.
 */

#ifndef SECURITY_LAB_REPORT_WRITER_H
#define SECURITY_LAB_REPORT_WRITER_H

#include "metrics.h"
#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char run_id[64];
    char run_dir[256];
    char target_ip[64];
    char environment_type[64]; /* "LAN", "Gateway", "VPN" */
    char host_arch[64];
    char os_info[128];
    char compiler_info[128];
    time_t timestamp;
} run_metadata_t;

/* Initializes a run results directory and metadata */
int report_writer_init_run(run_metadata_t *meta, const char *env_type, const char *target_ip);

/* Writes metadata.json */
int report_write_metadata_json(const run_metadata_t *meta);

/* Writes scenario_results.json */
int report_write_scenario_results_json(const run_metadata_t *meta,
                                       const scenario_result_t *results, size_t count);

/* Writes metrics.csv */
int report_write_metrics_csv(const run_metadata_t *meta,
                             const scenario_result_t *results, size_t count);

/* Writes events.jsonl */
int report_write_events_jsonl(const run_metadata_t *meta,
                              const scenario_result_t *results, size_t count);

/* Writes summary.json */
int report_write_summary_json(const run_metadata_t *meta,
                              const scenario_result_t *results, size_t count);

/* Generates comprehensive comparative Markdown report across Classical, Hybrid, and Pure PQC */
int report_write_comparison_md(const run_metadata_t *meta,
                               const scenario_result_t *results, size_t count);

#ifdef __cplusplus
}
#endif

#endif /* SECURITY_LAB_REPORT_WRITER_H */
