/*
 * security_lab/include/network_test.h
 *
 * User-space network impairment gateway and active network resilience scenarios
 * (Loss, Delay/Jitter, Reordering, Duplication, Temporary Disconnect, MTU bounds).
 */

#ifndef SECURITY_LAB_NETWORK_TEST_H
#define SECURITY_LAB_NETWORK_TEST_H

#include "suite_adapter.h"
#include "metrics.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint16_t proxy_listen_port;
    char     target_ip[64];
    uint16_t target_server_port;

    int      loss_pct;           /* 0 to 100 */
    int      delay_ms;           /* Added latency */
    int      jitter_ms;          /* Variable jitter */
    int      reorder_pct;        /* Probability of delaying a packet behind next */
    int      duplicate_pct;      /* Probability of duplicating packet */
    bool     blackhole_active;   /* Disconnect simulation */

    int      proxy_sock;
    pthread_t thread_id;
    volatile bool running;
} net_impairment_gateway_t;

/* Starts the user-space in-transit impairment gateway */
int net_gateway_start(net_impairment_gateway_t *gw, uint16_t listen_port,
                      const char *target_ip, uint16_t target_port);

/* Stops the impairment gateway */
void net_gateway_stop(net_impairment_gateway_t *gw);

/* Configures real-time impairment parameters */
void net_gateway_set_impairment(net_impairment_gateway_t *gw,
                                int loss_pct, int delay_ms, int jitter_ms,
                                int reorder_pct, int duplicate_pct, bool blackhole);

/* ── Scenario B Execution Functions ───────────────────────────────── */
int run_scenario_baseline(suite_adapter_t *adapter, scenario_result_t *out_res, int trials);
int run_scenario_loss(suite_adapter_t *adapter, scenario_result_t *out_res, int loss_pct);
int run_scenario_delay_jitter(suite_adapter_t *adapter, scenario_result_t *out_res, int delay_ms, int jitter_ms);
int run_scenario_reorder(suite_adapter_t *adapter, scenario_result_t *out_res, int reorder_pct);
int run_scenario_duplication(suite_adapter_t *adapter, scenario_result_t *out_res, int dup_pct);
int run_scenario_disconnection(suite_adapter_t *adapter, scenario_result_t *out_res, int disconnect_duration_sec);
int run_scenario_mtu(suite_adapter_t *adapter, scenario_result_t *out_res);

#ifdef __cplusplus
}
#endif

#endif /* SECURITY_LAB_NETWORK_TEST_H */
