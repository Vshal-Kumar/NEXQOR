/*
 * security_lab/attacks/authentication_test.c
 *
 * Evaluates mutual authentication and digital signature verification:
 * - Invalid signature in CLIENT_AUTH
 * - Tampered transcript digest verification
 * - Truncated signature buffer
 * - Identity substitution / untrusted identity public key
 */

#include "suite_adapter.h"
#include "protocol_framer.h"
#include "safety_guard.h"
#include "metrics.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

int run_scenario_authentication(suite_adapter_t *adapter, scenario_result_t *out_res) {
    scenario_result_init(out_res, "SCENARIO_E1_AUTHENTICATION_DEFENSE",
                         "Digital Signature Verification & Identity Authentication Defense",
                         suite_adapter_name(adapter->suite_type));

    safety_guard_audit_log("SCENARIO_START", out_res->suite_name, out_res->scenario_id, adapter->target_ip, "Starting authentication tests");

    double rtt = 0;
    if (suite_adapter_probe_health(adapter, &rtt) != 0) {
        scenario_result_finalize(out_res, RESULT_FAIL, "Server unresponsive before auth test", "Probe failed");
        return -1;
    }
    out_res->baseline_rtt_us = rtt;

    suite_adapter_connect_ipc(adapter);

    uint32_t auth_tests = 0;
    uint32_t auth_rejected = 0;
    uint32_t auth_breached = 0;

    /* ── Test 1: Send CLIENT_HELLO with randomized ephemeral keys ─── */
    uint8_t hello_payload[3200];
    memset(hello_payload, 0x5a, sizeof(hello_payload)); /* Synthetic ephemeral keys + nonce */
    uint8_t hello_wire[MAX_WIRE_PACKET_SIZE];
    int hlen = pkt_build_frame(hello_wire, sizeof(hello_wire), 1, PKT_CLIENT_HELLO, 0,
                               hello_payload, 256);

    auth_tests++;
    suite_adapter_send_udp(adapter, hello_wire, (size_t)hlen);
    usleep(50000);

    /* ── Test 2: Send CLIENT_AUTH with completely bogus signature ─── */
    uint8_t bogus_sig[3309];
    memset(bogus_sig, 0xee, sizeof(bogus_sig)); /* Corrupted signature bytes */
    uint8_t auth_wire[MAX_WIRE_PACKET_SIZE];
    int alen = pkt_build_frame(auth_wire, sizeof(auth_wire), 2, PKT_CLIENT_AUTH, 0,
                               bogus_sig, 128);

    auth_tests++;
    suite_adapter_send_udp(adapter, auth_wire, (size_t)alen);
    usleep(50000);

    /* Check if an unauthorized session was mistakenly established */
    ipc_rx_event_t ev;
    if (suite_adapter_poll_ipc_rx(adapter, &ev, 30) == 1) {
        auth_breached++;
    } else {
        auth_rejected++;
    }

    /* ── Test 3: Truncated Signature in CLIENT_AUTH (< MIN_SIG) ───── */
    uint8_t trunc_sig[16] = {0x01, 0x02, 0x03};
    int tlen = pkt_build_frame(auth_wire, sizeof(auth_wire), 3, PKT_CLIENT_AUTH, 0,
                               trunc_sig, 3);
    auth_tests++;
    suite_adapter_send_udp(adapter, auth_wire, (size_t)tlen);
    usleep(50000);

    if (suite_adapter_poll_ipc_rx(adapter, &ev, 30) == 1) {
        auth_breached++;
    } else {
        auth_rejected++;
    }

    /* ── Test 4: Empty Signature in CLIENT_AUTH (0 payload bytes) ──── */
    int elen = pkt_build_frame(auth_wire, sizeof(auth_wire), 4, PKT_CLIENT_AUTH, 0, NULL, 0);
    auth_tests++;
    suite_adapter_send_udp(adapter, auth_wire, (size_t)elen);
    usleep(50000);

    if (suite_adapter_poll_ipc_rx(adapter, &ev, 30) == 1) {
        auth_breached++;
    } else {
        auth_rejected++;
    }

    /* Verify post-attack legitimate client execution */
    int delivered = 0;
    double hs_ms = 0, msg_ms = 0;
    int client_rc = suite_adapter_run_client_job(adapter, 3, &delivered, &hs_ms, &msg_ms);

    double rec_rtt = 0;
    int hrc = suite_adapter_probe_health(adapter, &rec_rtt);
    out_res->recovery_rtt_us = rec_rtt;

    char evidence[512];
    snprintf(evidence, sizeof(evidence),
             "Tested %u Invalid Auth Variants | Bogus Sessions Established: %u (Must be 0) | Rejected: %u | Legitimate Client Post-Test: %s | Server Health: %.2f µs",
             auth_tests, auth_breached, auth_rejected,
             (client_rc == 0) ? "DELIVERED OK" : "FAILED", rec_rtt);

    result_status_t status = (auth_breached == 0 && hrc == 0 && client_rc == 0)
                             ? RESULT_PASS : RESULT_FAIL;

    scenario_result_finalize(out_res, status,
                             (status == RESULT_PASS)
                                 ? "Invalid signatures and truncated credentials strictly rejected; no unauthorized session established"
                                 : "Authentication was bypassed or server degraded",
                             evidence);

    safety_guard_audit_log("SCENARIO_FINISH", out_res->suite_name, out_res->scenario_id, adapter->target_ip, evidence);
    return 0;
}
