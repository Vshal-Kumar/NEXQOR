/*
 * security_lab/include/test_engine.h
 *
 * Core test execution engine for the QRYPTONEX pure-C security lab.
 * Coordinates preflight, baseline, scenario execution, cleanup, and validation.
 */

#ifndef SECURITY_LAB_TEST_ENGINE_H
#define SECURITY_LAB_TEST_ENGINE_H

#include "suite_adapter.h"
#include "safety_guard.h"
#include "metrics.h"
#include "report_writer.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SCENARIO_ALL = 0,
    SCENARIO_BASELINE,
    SCENARIO_LOSS,
    SCENARIO_DELAY_JITTER,
    SCENARIO_REORDER,
    SCENARIO_DUPLICATION,
    SCENARIO_DISCONNECT,
    SCENARIO_MTU,
    SCENARIO_REPLAY,
    SCENARIO_TAMPERING,
    SCENARIO_AUTHENTICATION,
    SCENARIO_HANDSHAKE,
    SCENARIO_MALFORMED,
    SCENARIO_RESOURCE_STRESS,
    SCENARIO_SESSION_ISOLATION,
    SCENARIO_UNKNOWN = -1
} scenario_type_t;

typedef struct {
    suite_type_t    suite_filter;       /* SUITE_TYPE_PQC, etc. or -1 for all */
    scenario_type_t scenario_filter;    /* SCENARIO_ALL or specific */
    char            target_ip[64];
    uint16_t        target_port;
    char            environment[64];    /* "LAN", "Gateway", "VPN" */
    bool            dry_run;
    int             trials;
    bool            auto_start_servers;
    bool            list_suites_only;
    bool            list_scenarios_only;
    bool            show_latest_results;
} engine_config_t;

/* Initializes engine configuration with defaults */
void test_engine_init_config(engine_config_t *cfg);

/* Parses command-line arguments */
int test_engine_parse_args(engine_config_t *cfg, int argc, char **argv);

/* Executes test suite and scenario matrix */
int test_engine_run(const engine_config_t *cfg);

/* Displays help text and usage options */
void test_engine_print_help(const char *prog_name);

/* Lists supported suites */
void test_engine_list_suites(void);

/* Lists supported security test scenarios */
void test_engine_list_scenarios(void);

#ifdef __cplusplus
}
#endif

#endif /* SECURITY_LAB_TEST_ENGINE_H */
