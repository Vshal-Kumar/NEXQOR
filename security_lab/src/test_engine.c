/*
 * security_lab/src/test_engine.c
 *
 * Implements test controller, scenario orchestration, argument parsing,
 * and comprehensive result publishing.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "test_engine.h"
#include "network_test.h"
#include "protocol_framer.h"
#include "report_writer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

/* Forward declarations of scenario runners in attacks/ */
int run_scenario_replay(suite_adapter_t *adapter, scenario_result_t *out_res);
int run_scenario_tampering(suite_adapter_t *adapter, scenario_result_t *out_res);
int run_scenario_authentication(suite_adapter_t *adapter, scenario_result_t *out_res);
int run_scenario_handshake(suite_adapter_t *adapter, scenario_result_t *out_res);
int run_scenario_malformed(suite_adapter_t *adapter, scenario_result_t *out_res);
int run_scenario_resource_stress(suite_adapter_t *adapter, scenario_result_t *out_res, int client_count);
int run_scenario_session_isolation(suite_adapter_t *adapter, scenario_result_t *out_res);

void test_engine_init_config(engine_config_t *cfg) {
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));
    cfg->suite_filter = (suite_type_t)-1; /* All suites by default */
    cfg->scenario_filter = SCENARIO_ALL;  /* All scenarios */
    strcpy(cfg->target_ip, "127.0.0.1");
    strcpy(cfg->environment, "LAN");
    cfg->trials = 3;
    cfg->auto_start_servers = true;
}

static scenario_type_t parse_scenario_name(const char *name) {
    if (!name) return SCENARIO_UNKNOWN;
    if (strcasecmp(name, "all") == 0) return SCENARIO_ALL;
    if (strcasecmp(name, "baseline") == 0) return SCENARIO_BASELINE;
    if (strcasecmp(name, "loss") == 0 || strcasecmp(name, "network_loss") == 0) return SCENARIO_LOSS;
    if (strcasecmp(name, "delay") == 0 || strcasecmp(name, "delay_jitter") == 0) return SCENARIO_DELAY_JITTER;
    if (strcasecmp(name, "reorder") == 0) return SCENARIO_REORDER;
    if (strcasecmp(name, "duplication") == 0) return SCENARIO_DUPLICATION;
    if (strcasecmp(name, "disconnect") == 0) return SCENARIO_DISCONNECT;
    if (strcasecmp(name, "mtu") == 0) return SCENARIO_MTU;
    if (strcasecmp(name, "replay") == 0 || strcasecmp(name, "replay_validation") == 0) return SCENARIO_REPLAY;
    if (strcasecmp(name, "tampering") == 0 || strcasecmp(name, "integrity") == 0) return SCENARIO_TAMPERING;
    if (strcasecmp(name, "auth") == 0 || strcasecmp(name, "authentication") == 0) return SCENARIO_AUTHENTICATION;
    if (strcasecmp(name, "handshake") == 0) return SCENARIO_HANDSHAKE;
    if (strcasecmp(name, "malformed") == 0 || strcasecmp(name, "fuzz") == 0) return SCENARIO_MALFORMED;
    if (strcasecmp(name, "stress") == 0 || strcasecmp(name, "resource_stress") == 0) return SCENARIO_RESOURCE_STRESS;
    if (strcasecmp(name, "isolation") == 0 || strcasecmp(name, "session_isolation") == 0) return SCENARIO_SESSION_ISOLATION;
    return SCENARIO_UNKNOWN;
}

int test_engine_parse_args(engine_config_t *cfg, int argc, char **argv) {
    if (!cfg) return -1;

    static struct option long_options[] = {
        {"help",            no_argument,       0, 'h'},
        {"suite",           required_argument, 0, 's'},
        {"scenario",        required_argument, 0, 'c'},
        {"target",          required_argument, 0, 't'},
        {"port",            required_argument, 0, 'p'},
        {"environment",     required_argument, 0, 'e'},
        {"dry-run",         no_argument,       0, 'd'},
        {"trials",          required_argument, 0, 'n'},
        {"list-suites",     no_argument,       0, 1001},
        {"list-scenarios",  no_argument,       0, 1002},
        {"results",         optional_argument, 0, 1003},
        {0, 0, 0, 0}
    };

    int opt, idx = 0;
    while ((opt = getopt_long(argc, argv, "hs:c:t:p:e:dn:", long_options, &idx)) != -1) {
        switch (opt) {
            case 'h':
                test_engine_print_help(argv[0]);
                exit(0);
            case 's':
                if (strcasecmp(optarg, "all") == 0) {
                    cfg->suite_filter = (suite_type_t)-1;
                } else {
                    cfg->suite_filter = suite_adapter_parse_name(optarg);
                    if ((int)cfg->suite_filter == -1) {
                        fprintf(stderr, "Error: Unknown suite '%s'. Run --list-suites for options.\n", optarg);
                        return -1;
                    }
                }
                break;
            case 'c':
                cfg->scenario_filter = parse_scenario_name(optarg);
                if (cfg->scenario_filter == SCENARIO_UNKNOWN) {
                    fprintf(stderr, "Error: Unknown scenario '%s'. Run --list-scenarios for options.\n", optarg);
                    return -1;
                }
                break;
            case 't':
                strncpy(cfg->target_ip, optarg, sizeof(cfg->target_ip) - 1);
                break;
            case 'p':
                cfg->target_port = (uint16_t)atoi(optarg);
                break;
            case 'e':
                strncpy(cfg->environment, optarg, sizeof(cfg->environment) - 1);
                break;
            case 'd':
                cfg->dry_run = true;
                break;
            case 'n':
                cfg->trials = atoi(optarg);
                if (cfg->trials <= 0) cfg->trials = 1;
                break;
            case 1001:
                cfg->list_suites_only = true;
                return 0;
            case 1002:
                cfg->list_scenarios_only = true;
                return 0;
            case 1003:
                cfg->show_latest_results = true;
                return 0;
            default:
                test_engine_print_help(argv[0]);
                return -1;
        }
    }
    return 0;
}

void test_engine_print_help(const char *prog_name) {
    printf("╔══════════════════════════════════════════════════════════════════════════╗\n");
    printf("║    QRYPTONEX Unified Pure-C Real-Network Security Testing Framework      ║\n");
    printf("╚══════════════════════════════════════════════════════════════════════════╝\n\n");
    printf("Usage:\n");
    printf("  %s [options]\n\n", prog_name);
    printf("Options:\n");
    printf("  --suite <name|all>        Select cryptographic suite (classical, hybrid, pqc, all)\n");
    printf("  --scenario <name|all>     Select security scenario (see --list-scenarios)\n");
    printf("  --target <ip>             Authorized target IP address (default: 127.0.0.1)\n");
    printf("  --port <port>             Target UDP port (default: auto per suite)\n");
    printf("  --environment <type>      Test environment: LAN, Gateway, VPN (default: LAN)\n");
    printf("  --dry-run                 Simulate execution without sending test packets or altering config\n");
    printf("  --trials <n>              Number of trial iterations (default: 3)\n");
    printf("  --list-suites             Display list of supported cryptographic suites\n");
    printf("  --list-scenarios          Display list of implemented attack scenarios\n");
    printf("  --results [latest]        Display path and summary of latest test run\n");
    printf("  --help, -h                Display this help reference\n\n");
    printf("Examples:\n");
    printf("  %s --list-suites\n", prog_name);
    printf("  %s --suite pqc --scenario baseline --dry-run\n", prog_name);
    printf("  %s --suite hybrid --scenario replay --target 127.0.0.1\n", prog_name);
    printf("  %s --suite classical --scenario tampering\n", prog_name);
    printf("  %s --suite all --scenario all\n\n", prog_name);
}

void test_engine_list_suites(void) {
    printf("\nSupported Cryptographic Implementations:\n");
    printf("  1. classical  - X25519 + Ed25519 + AES-128-CCM (Port 9877)\n");
    printf("  2. hybrid     - Dual X25519/ML-KEM-768 + Dual Ed25519/ML-DSA-65 + ChaCha20-Poly1305 (Port 9879)\n");
    printf("  3. pqc        - Pure Post-Quantum ML-KEM-768 + ML-DSA-65 + ChaCha20-Poly1305 (Port 9877)\n");
    printf("  4. all        - Execute comparative evaluation across all 3 suites sequentially\n\n");
}

void test_engine_list_scenarios(void) {
    printf("\nSupported Security Test Scenarios:\n");
    printf("  • baseline           - Legitimate session baseline & latency benchmarking\n");
    printf("  • loss               - Controlled packet loss resilience (15%% drop profile)\n");
    printf("  • delay_jitter       - Bounded delay (30ms) & variable jitter (±15ms)\n");
    printf("  • reorder            - Controlled out-of-order packet delivery\n");
    printf("  • duplication        - Duplicate packet injection & rejection\n");
    printf("  • disconnect         - Temporary link blackhole & recovery measurement\n");
    printf("  • mtu                - Path MTU boundaries (512B to 4096B)\n");
    printf("  • replay             - Replay protection (duplicate seq, stale seq, cross-session)\n");
    printf("  • tampering          - AEAD integrity (ciphertext bit-flip, tag mutation, AAD header tampering)\n");
    printf("  • auth               - Digital signature verification & forged credential defense\n");
    printf("  • handshake          - Handshake state machine & incomplete handshake cleanup\n");
    printf("  • malformed          - Truncated frames, invalid types, inconsistent lengths, random fuzzing\n");
    printf("  • stress             - Bounded concurrent client load & worker queue pressure\n");
    printf("  • isolation          - Session isolation & multi-client blast radius containment\n");
    printf("  • all                - Complete security validation suite (all scenarios)\n\n");
}

static void run_suite_scenarios(suite_adapter_t *adapter, scenario_type_t filter, int trials,
                                scenario_result_t *out_results, size_t *inout_count, size_t max_results) {
    #define EXEC_SCENARIO(sc_enum, fn_call) do { \
        if (g_safety_emergency_stop) { \
            printf("  [ABORTED] Emergency Stop Triggered — Halting remaining scenarios.\n"); \
            return; \
        } \
        if (filter == SCENARIO_ALL || filter == sc_enum) { \
            if (*inout_count < max_results) { \
                scenario_result_t *r = &out_results[(*inout_count)++]; \
                printf("  [SCENARIO] Running %s on %s...\n", #sc_enum, adapter->name); \
                fn_call; \
                printf("  [RESULT]   Verdict: %s | %s\n\n", result_status_string(r->status), r->status_rationale); \
            } \
        } \
    } while (0)

    EXEC_SCENARIO(SCENARIO_BASELINE, run_scenario_baseline(adapter, r, trials));
    EXEC_SCENARIO(SCENARIO_LOSS, run_scenario_loss(adapter, r, 15));
    EXEC_SCENARIO(SCENARIO_DELAY_JITTER, run_scenario_delay_jitter(adapter, r, 30, 15));
    EXEC_SCENARIO(SCENARIO_REORDER, run_scenario_reorder(adapter, r, 25));
    EXEC_SCENARIO(SCENARIO_DUPLICATION, run_scenario_duplication(adapter, r, 25));
    EXEC_SCENARIO(SCENARIO_DISCONNECT, run_scenario_disconnection(adapter, r, 2));
    EXEC_SCENARIO(SCENARIO_MTU, run_scenario_mtu(adapter, r));
    EXEC_SCENARIO(SCENARIO_REPLAY, run_scenario_replay(adapter, r));
    EXEC_SCENARIO(SCENARIO_TAMPERING, run_scenario_tampering(adapter, r));
    EXEC_SCENARIO(SCENARIO_AUTHENTICATION, run_scenario_authentication(adapter, r));
    EXEC_SCENARIO(SCENARIO_HANDSHAKE, run_scenario_handshake(adapter, r));
    EXEC_SCENARIO(SCENARIO_MALFORMED, run_scenario_malformed(adapter, r));
    EXEC_SCENARIO(SCENARIO_RESOURCE_STRESS, run_scenario_resource_stress(adapter, r, 16));
    EXEC_SCENARIO(SCENARIO_SESSION_ISOLATION, run_scenario_session_isolation(adapter, r));

    #undef EXEC_SCENARIO
}

int test_engine_run(const engine_config_t *cfg) {
    if (!cfg) return -1;

    if (cfg->list_suites_only) {
        test_engine_list_suites();
        return 0;
    }
    if (cfg->list_scenarios_only) {
        test_engine_list_scenarios();
        return 0;
    }
    if (cfg->show_latest_results) {
        printf("\nLatest Results Pointer:\n");
        system("ls -ld security_lab/results/latest 2>/dev/null || ls -lt security_lab/results | head -n 3");
        return 0;
    }

    /* 1. Initialize Safety Controls & Allowlist */
    safety_guard_init(cfg->dry_run);
    safety_guard_register_signals();

    if (safety_guard_validate_target(cfg->target_ip, cfg->target_port) != 0) {
        fprintf(stderr, "Aborting execution due to safety guard target validation failure.\n");
        return -1;
    }

    char iface[64];
    safety_guard_validate_route(cfg->target_ip, iface, sizeof(iface));

    printf("\n\033[1;36m╔══════════════════════════════════════════════════════════════════════════════════════════╗\033[0m\n");
    printf("\033[1;36m║             QRYPTONEX Real-Network Security Evaluation & Resilience Lab                  ║\033[0m\n");
    printf("\033[1;36m╚══════════════════════════════════════════════════════════════════════════════════════════╝\033[0m\n");
    printf("  • Target Host       : %s\n", cfg->target_ip);
    printf("  • Routing Interface : %s (%s)\n", iface, cfg->environment);
    printf("  • Execution Mode    : %s\n", cfg->dry_run ? "\033[1;33mDRY-RUN (Simulated Traffic Only)\033[0m" : "\033[1;32mACTIVE REAL-NETWORK TESTING\033[0m");
    printf("  • Safety Allowlist  : Strictly Enforced\n\n");

    /* 2. Initialize Run Results Directory */
    run_metadata_t meta;
    report_writer_init_run(&meta, cfg->environment, cfg->target_ip);

    scenario_result_t results[64];
    size_t result_count = 0;

    suite_type_t suites_to_test[3];
    int suite_count = 0;

    if ((int)cfg->suite_filter == -1) {
        suites_to_test[0] = SUITE_TYPE_CLASSICAL;
        suites_to_test[1] = SUITE_TYPE_HYBRID;
        suites_to_test[2] = SUITE_TYPE_PQC;
        suite_count = 3;
    } else {
        suites_to_test[0] = cfg->suite_filter;
        suite_count = 1;
    }

    /* 3. Execute Suite Testing Matrix */
    for (int s = 0; s < suite_count; s++) {
        if (g_safety_emergency_stop) {
            printf("\n[ABORTED] Emergency Stop Triggered — Terminating multi-suite run.\n");
            break;
        }
        suite_type_t st = suites_to_test[s];
        suite_adapter_t adapter;
        if (suite_adapter_init(&adapter, st, cfg->target_ip, cfg->target_port) != 0) {
            fprintf(stderr, "Failed to initialize suite adapter for %s\n", suite_adapter_name(st));
            continue;
        }

        printf("\033[1;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n");
        printf("\033[1;34m▶ EVALUATING SUITE [%d/%d]: %s\033[0m\n", s + 1, suite_count, adapter.name);
        printf("  Stack: %s | Target Port: %u\n", adapter.crypto_stack, adapter.target_port);
        printf("\033[1;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n");

        /* Ensure server is running */
        if (!suite_adapter_is_server_alive(&adapter)) {
            if (cfg->auto_start_servers) {
                printf("  [SETUP] Server not active on port %u. Starting suite server daemon...\n", adapter.target_port);
                suite_adapter_start_server(&adapter);
            }
        }

        run_suite_scenarios(&adapter, cfg->scenario_filter, cfg->trials, results, &result_count, 64);

        suite_adapter_cleanup(&adapter);
        usleep(100000); /* Inter-suite settling time */
    }

    /* 4. Write Artifacts */
    report_write_metadata_json(&meta);
    report_write_scenario_results_json(&meta, results, result_count);
    report_write_events_jsonl(&meta, results, result_count);
    report_write_metrics_csv(&meta, results, result_count);
    report_write_summary_json(&meta, results, result_count);
    report_write_comparison_md(&meta, results, result_count);

    /* Update latest symlink */
    unlink("security_lab/results/latest");
    symlink(meta.run_id, "security_lab/results/latest");

    /* 5. Print Terminal Summary */
    printf("\n\033[1;32m╔══════════════════════════════════════════════════════════════════════════════════════════╗\033[0m\n");
    printf("\033[1;32m║                             TEST EXECUTION SUMMARY MATRIX                                ║\033[0m\n");
    printf("\033[1;32m╚══════════════════════════════════════════════════════════════════════════════════════════╝\033[0m\n\n");

    uint32_t total_pass = 0, total_fail = 0, total_inc = 0;
    for (size_t i = 0; i < result_count; i++) {
        const scenario_result_t *r = &results[i];
        if (r->status == RESULT_PASS) total_pass++;
        else if (r->status == RESULT_FAIL) total_fail++;
        else total_inc++;

        const char *status_color = (r->status == RESULT_PASS) ? "\033[1;32mPASS\033[0m" :
                                   (r->status == RESULT_FAIL) ? "\033[1;31mFAIL\033[0m" : "\033[1;33mINCONCLUSIVE\033[0m";

        printf("  [%-12s] %-32s -> %s\n", r->suite_name, r->scenario_id, status_color);
    }

    printf("\n  Results Saved to: \033[1;36m%s/\033[0m\n", meta.run_dir);
    printf("    • Comparative Report   : %s/report.md\n", meta.run_dir);
    printf("    • Scenario Metrics CSV : %s/metrics.csv\n", meta.run_dir);
    printf("    • Structured JSON Run  : %s/scenario_results.json\n", meta.run_dir);
    printf("    • Audit Trace Log      : security_lab/results/audit.log\n");
    printf("  Summary: \033[1;32m%u Passed\033[0m | \033[1;31m%u Failed\033[0m | Total: %zu Scenarios\n\n",
           total_pass, total_fail, result_count);

    return (total_fail == 0) ? 0 : 1;
}
