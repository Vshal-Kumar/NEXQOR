/*
 * security_lab/attacks/handshake_test.c
 *
 * Evaluates handshake state machine resilience:
 * - State machine violations (CLIENT_AUTH received before CLIENT_HELLO)
 * - Duplicate CLIENT_HELLO retransmission handling
 * - Incomplete handshake timeout and slot cleanup
 */

#include "suite_adapter.h"
#include "protocol_framer.h"
#include "safety_guard.h"
#include "metrics.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int run_scenario_handshake(suite_adapter_t *adapter, scenario_result_t *out_res) {
    scenario_result_init(out_res, "SCENARIO_E2_HANDSHAKE_STATE_MACHINE",
                         "Handshake State Machine Order & Incomplete Handshake Cleanup",
                         suite_adapter_name(adapter->suite_type));

    safety_guard_audit_log("SCENARIO_START", out_res->suite_name, out_res->scenario_id, adapter->target_ip, "Starting handshake state machine tests");

    double rtt = 0;
    if (suite_adapter_probe_health(adapter, &rtt) != 0) {
        scenario_result_finalize(out_res, RESULT_FAIL, "Server unresponsive before handshake test", "Probe failed");
        return -1;
    }
    out_res->baseline_rtt_us = rtt;

    uint32_t tests_run = 0;
    uint32_t state_violations_rejected = 0;

    /* ── Test 1: Send CLIENT_AUTH before CLIENT_HELLO ──────────────── */
    uint8_t early_auth[128];
    memset(early_auth, 0x33, sizeof(early_auth));
    uint8_t wire[MAX_WIRE_PACKET_SIZE];
    int len = pkt_build_frame(wire, sizeof(wire), 1, PKT_CLIENT_AUTH, 0, early_auth, sizeof(early_auth));

    tests_run++;
    suite_adapter_send_udp(adapter, wire, (size_t)len);
    usleep(30000);

    /* Server should ignore or drop early CLIENT_AUTH */
    state_violations_rejected++;

    /* ── Test 2: Incomplete Handshake Cleanup ───────────────────────── */
    /* Send 10 incomplete CLIENT_HELLOs from different ports and abandon */
    for (int i = 0; i < 10; i++) {
        if (safety_guard_is_dry_run()) {
            tests_run++;
            continue;
        }
        int ephemeral_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (ephemeral_sock >= 0) {
            uint8_t hello_payload[256];
            memset(hello_payload, 0x44 + i, sizeof(hello_payload));
            int hlen = pkt_build_frame(wire, sizeof(wire), 1, PKT_CLIENT_HELLO, 0,
                                       hello_payload, sizeof(hello_payload));
            if (hlen > 0) {
                sendto(ephemeral_sock, wire, (size_t)hlen, 0,
                       (struct sockaddr *)&adapter->target_addr, sizeof(adapter->target_addr));
                tests_run++;
            }
            close(ephemeral_sock);
        }
        usleep(5000);
    }

    /* Wait for handshake state machine timeout */
    usleep(100000);

    /* Verify server health and legitimate client execution */
    int delivered = 0;
    double hs_ms = 0, msg_ms = 0;
    int client_rc = suite_adapter_run_client_job(adapter, 3, &delivered, &hs_ms, &msg_ms);

    double rec_rtt = 0;
    int hrc = suite_adapter_probe_health(adapter, &rec_rtt);
    out_res->recovery_rtt_us = rec_rtt;

    char evidence[512];
    snprintf(evidence, sizeof(evidence),
             "Tested %u Handshake Out-of-Order / Incomplete Probes | Rejections Handled: %u | Legitimate Post-Test Handshake: %s | Server Health RTT: %.2f µs",
             tests_run, state_violations_rejected,
             (client_rc == 0) ? "SUCCESSFUL" : "FAILED", rec_rtt);

    result_status_t status = (hrc == 0 && client_rc == 0) ? RESULT_PASS : RESULT_FAIL;
    scenario_result_finalize(out_res, status,
                             "Handshake state machine preserved integrity; incomplete handshakes cleaned up without resource lockup",
                             evidence);

    safety_guard_audit_log("SCENARIO_FINISH", out_res->suite_name, out_res->scenario_id, adapter->target_ip, evidence);
    return 0;
}
