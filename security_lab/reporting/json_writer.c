/*
 * security_lab/reporting/json_writer.c
 *
 * Implements JSON and JSON Lines structured artifact exporters.
 */

#include "report_writer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/utsname.h>

int report_writer_init_run(run_metadata_t *meta, const char *env_type, const char *target_ip) {
    if (!meta) return -1;
    memset(meta, 0, sizeof(*meta));

    meta->timestamp = time(NULL);
    struct tm tm_buf;
    localtime_r(&meta->timestamp, &tm_buf);

    strftime(meta->run_id, sizeof(meta->run_id), "run_%Y%m%d_%H%M%S", &tm_buf);
    snprintf(meta->run_dir, sizeof(meta->run_dir), "security_lab/results/%s", meta->run_id);

    snprintf(meta->target_ip, sizeof(meta->target_ip), "%s", target_ip ? target_ip : "127.0.0.1");
    snprintf(meta->environment_type, sizeof(meta->environment_type), "%s", env_type ? env_type : "LAN");

    struct utsname un;
    if (uname(&un) == 0) {
        snprintf(meta->host_arch, sizeof(meta->host_arch), "%.63s", un.machine);
        snprintf(meta->os_info, sizeof(meta->os_info), "%.40s %.40s (%.40s)", un.sysname, un.release, un.version);
    } else {
        strcpy(meta->host_arch, "x86_64");
        strcpy(meta->os_info, "Linux");
    }

#if defined(__clang__)
    snprintf(meta->compiler_info, sizeof(meta->compiler_info), "Clang %s", __clang_version__);
#elif defined(__GNUC__)
    snprintf(meta->compiler_info, sizeof(meta->compiler_info), "GCC %d.%d.%d", __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#else
    strcpy(meta->compiler_info, "Standard C11 Compiler");
#endif

    mkdir("security_lab", 0755);
    mkdir("security_lab/results", 0755);
    mkdir(meta->run_dir, 0755);

    return 0;
}

int report_write_metadata_json(const run_metadata_t *meta) {
    if (!meta) return -1;

    char path[512];
    snprintf(path, sizeof(path), "%s/metadata.json", meta->run_dir);

    FILE *f = fopen(path, "w");
    if (!f) return -1;

    char time_str[64];
    struct tm tm_buf;
    localtime_r(&meta->timestamp, &tm_buf);
    strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);

    fprintf(f, "{\n");
    fprintf(f, "  \"run_id\": \"%s\",\n", meta->run_id);
    fprintf(f, "  \"timestamp\": \"%s\",\n", time_str);
    fprintf(f, "  \"target_ip\": \"%s\",\n", meta->target_ip);
    fprintf(f, "  \"environment\": \"%s\",\n", meta->environment_type);
    fprintf(f, "  \"architecture\": \"%s\",\n", meta->host_arch);
    fprintf(f, "  \"operating_system\": \"%s\",\n", meta->os_info);
    fprintf(f, "  \"compiler\": \"%s\",\n", meta->compiler_info);
    fprintf(f, "  \"framework\": \"QRYPTONEX C Security Testing Framework (Pure C)\"\n");
    fprintf(f, "}\n");

    fclose(f);
    return 0;
}

int report_write_scenario_results_json(const run_metadata_t *meta,
                                       const scenario_result_t *results, size_t count) {
    if (!meta || !results) return -1;

    char path[512];
    snprintf(path, sizeof(path), "%s/scenario_results.json", meta->run_dir);

    FILE *f = fopen(path, "w");
    if (!f) return -1;

    fprintf(f, "{\n  \"run_id\": \"%s\",\n  \"total_scenarios\": %zu,\n  \"scenarios\": [\n",
            meta->run_id, count);

    for (size_t i = 0; i < count; i++) {
        const scenario_result_t *r = &results[i];
        double hs_mean = 0, hs_p50 = 0, hs_p95 = 0, hs_p99 = 0;
        latency_tracker_calc(&r->handshake_lat_ms, &hs_mean, &hs_p50, &hs_p95, &hs_p99);

        double msg_mean = 0, msg_p50 = 0, msg_p95 = 0, msg_p99 = 0;
        latency_tracker_calc(&r->message_rtt_ms, &msg_mean, &msg_p50, &msg_p95, &msg_p99);

        fprintf(f, "    {\n");
        fprintf(f, "      \"scenario_id\": \"%s\",\n", r->scenario_id);
        fprintf(f, "      \"name\": \"%s\",\n", r->scenario_name);
        fprintf(f, "      \"suite\": \"%s\",\n", r->suite_name);
        fprintf(f, "      \"status\": \"%s\",\n", result_status_string(r->status));
        fprintf(f, "      \"duration_sec\": %.4f,\n", r->duration_sec);
        fprintf(f, "      \"rationale\": \"%s\",\n", r->status_rationale);
        fprintf(f, "      \"evidence\": \"%s\",\n", r->evidence_summary);
        fprintf(f, "      \"metrics\": {\n");
        fprintf(f, "        \"handshake\": {\n");
        fprintf(f, "          \"attempts\": %u,\n", r->handshake_attempts);
        fprintf(f, "          \"success\": %u,\n", r->handshake_successes);
        fprintf(f, "          \"mean_ms\": %.3f,\n", hs_mean);
        fprintf(f, "          \"p50_ms\": %.3f,\n", hs_p50);
        fprintf(f, "          \"p95_ms\": %.3f,\n", hs_p95);
        fprintf(f, "          \"p99_ms\": %.3f\n", hs_p99);
        fprintf(f, "        },\n");
        fprintf(f, "        \"messages\": {\n");
        fprintf(f, "          \"sent\": %u,\n", r->messages_sent);
        fprintf(f, "          \"acked\": %u,\n", r->messages_acked);
        fprintf(f, "          \"lost\": %u,\n", r->messages_lost);
        fprintf(f, "          \"mean_rtt_ms\": %.3f\n", msg_mean);
        fprintf(f, "        },\n");
        fprintf(f, "        \"security_counters\": {\n");
        fprintf(f, "          \"replays_injected\": %u,\n", r->injected_replays);
        fprintf(f, "          \"replays_accepted\": %u,\n", r->accepted_replays);
        fprintf(f, "          \"replays_rejected\": %u,\n", r->rejected_replays);
        fprintf(f, "          \"tampered_injected\": %u,\n", r->injected_tampered);
        fprintf(f, "          \"tampered_accepted\": %u,\n", r->accepted_tampered);
        fprintf(f, "          \"tampered_rejected\": %u,\n", r->rejected_tampered);
        fprintf(f, "          \"malformed_injected\": %u,\n", r->injected_malformed);
        fprintf(f, "          \"server_crashes\": %u\n", r->server_crashes);
        fprintf(f, "        },\n");
        fprintf(f, "        \"recovery\": {\n");
        fprintf(f, "          \"baseline_rtt_us\": %.2f,\n", r->baseline_rtt_us);
        fprintf(f, "          \"recovery_rtt_us\": %.2f,\n", r->recovery_rtt_us);
        fprintf(f, "          \"recovery_time_ms\": %.2f\n", r->recovery_time_ms);
        fprintf(f, "        }\n");
        fprintf(f, "      }\n");
        fprintf(f, "    }%s\n", (i + 1 < count) ? "," : "");
    }

    fprintf(f, "  ]\n}\n");
    fclose(f);
    return 0;
}

int report_write_events_jsonl(const run_metadata_t *meta,
                              const scenario_result_t *results, size_t count) {
    if (!meta || !results) return -1;

    char path[512];
    snprintf(path, sizeof(path), "%s/events.jsonl", meta->run_dir);

    FILE *f = fopen(path, "w");
    if (!f) return -1;

    for (size_t i = 0; i < count; i++) {
        const scenario_result_t *r = &results[i];
        fprintf(f, "{\"event\":\"scenario_result\",\"scenario_id\":\"%s\",\"suite\":\"%s\",\"status\":\"%s\",\"duration_sec\":%.4f,\"evidence\":\"%s\"}\n",
                r->scenario_id, r->suite_name, result_status_string(r->status), r->duration_sec, r->evidence_summary);
    }

    fclose(f);
    return 0;
}

int report_write_summary_json(const run_metadata_t *meta,
                              const scenario_result_t *results, size_t count) {
    if (!meta || !results) return -1;

    char path[512];
    snprintf(path, sizeof(path), "%s/summary.json", meta->run_dir);

    FILE *f = fopen(path, "w");
    if (!f) return -1;

    uint32_t pass_cnt = 0, fail_cnt = 0, err_cnt = 0;
    for (size_t i = 0; i < count; i++) {
        if (results[i].status == RESULT_PASS) pass_cnt++;
        else if (results[i].status == RESULT_FAIL) fail_cnt++;
        else err_cnt++;
    }

    fprintf(f, "{\n");
    fprintf(f, "  \"run_id\": \"%s\",\n", meta->run_id);
    fprintf(f, "  \"environment\": \"%s\",\n", meta->environment_type);
    fprintf(f, "  \"total_scenarios_evaluated\": %zu,\n", count);
    fprintf(f, "  \"passed\": %u,\n", pass_cnt);
    fprintf(f, "  \"failed\": %u,\n", fail_cnt);
    fprintf(f, "  \"other\": %u,\n", err_cnt);
    fprintf(f, "  \"pass_rate_pct\": %.1f\n", (count > 0) ? (pass_cnt * 100.0 / count) : 0.0);
    fprintf(f, "}\n");

    fclose(f);
    return 0;
}
