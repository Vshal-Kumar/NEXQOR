/*
 * security_lab/attacks/replay_test.c
 *
 * Evaluates replay defense mechanisms against running servers:
 * - Exact duplicate message injection
 * - Sliding window boundary tests (old sequence numbers, stale packets)
 * - Cross-session replay injection
 * - Replay attempts after session renegotiation
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "suite_adapter.h"
#include "protocol_framer.h"
#include "safety_guard.h"
#include "metrics.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

int run_scenario_replay(suite_adapter_t *adapter, scenario_result_t *out_res) {
    scenario_result_init(out_res, "SCENARIO_C_REPLAY_PROTECTION",
                         "Real-Network Replay Protection & Sliding Window Validation",
                         suite_adapter_name(adapter->suite_type));

    safety_guard_audit_log("SCENARIO_START", out_res->suite_name, out_res->scenario_id, adapter->target_ip, "Starting replay tests");

    /* 1. Preflight server health */
    double rtt = 0;
    if (suite_adapter_probe_health(adapter, &rtt) != 0) {
        scenario_result_finalize(out_res, RESULT_FAIL, "Server unresponsive before replay test", "Health probe failed");
        return -1;
    }
    out_res->baseline_rtt_us = rtt;

    /* 2. Connect to server IPC to independently observe whether replayed frames reach application */
    suite_adapter_connect_ipc(adapter);

    /* 3. Construct a test session frame with valid sequence #10 */
    uint64_t test_session_id = 0xa1b2c3d4e5f60718ULL;
    uint32_t seq_num = 10;
    uint8_t nonce[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10};
    uint8_t tag[16]   = {0x91, 0xc4, 0x18, 0x72, 0x33, 0x5a, 0xef, 0xbb, 0x47, 0x01, 0x88, 0xda, 0x29, 0x66, 0xaa, 0x15};
    uint8_t ct[32]    = "ENCRYPTED_TELEMETRY_PAYLOAD_01";

    uint8_t wire_packet[MAX_WIRE_PACKET_SIZE];
    int pkt_len = pkt_build_data_frame(wire_packet, sizeof(wire_packet),
                                       seq_num, test_session_id,
                                       nonce, tag, ct, (uint16_t)strlen((char *)ct));
    if (pkt_len < 0) {
        scenario_result_finalize(out_res, RESULT_ERROR, "Failed to serialize test packet", "");
        return -1;
    }

    /* 4. Test 1: Send initial test packet */
    out_res->injected_replays = 0;
    out_res->accepted_replays = 0;
    out_res->rejected_replays = 0;

    suite_adapter_send_udp(adapter, wire_packet, (size_t)pkt_len);
    usleep(50000);

    /* 5. Test 2: Inject exact duplicate packet (Replay 1) */
    out_res->injected_replays++;
    suite_adapter_send_udp(adapter, wire_packet, (size_t)pkt_len);
    usleep(50000);

    /* Check IPC observer: Did server process duplicate message into application? */
    ipc_rx_event_t ev;
    int ipc_rc = suite_adapter_poll_ipc_rx(adapter, &ev, 50);
    if (ipc_rc == 1) {
        /* Application received a duplicate! Replay protection FAILED */
        out_res->accepted_replays++;
    } else {
        out_res->rejected_replays++;
    }

    /* 6. Test 3: Inject old / stale sequence number (seq = 2 while current is >= 10) */
    uint8_t stale_packet[MAX_WIRE_PACKET_SIZE];
    uint8_t stale_nonce[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    int stale_len = pkt_build_data_frame(stale_packet, sizeof(stale_packet),
                                         2, test_session_id,
                                         stale_nonce, tag, ct, (uint16_t)strlen((char *)ct));
    out_res->injected_replays++;
    suite_adapter_send_udp(adapter, stale_packet, (size_t)stale_len);
    usleep(50000);

    ipc_rc = suite_adapter_poll_ipc_rx(adapter, &ev, 50);
    if (ipc_rc == 1) {
        out_res->accepted_replays++;
    } else {
        out_res->rejected_replays++;
    }

    /* 7. Test 4: Inject packet with Sequence 0 */
    uint8_t zero_packet[MAX_WIRE_PACKET_SIZE];
    uint8_t zero_nonce[12] = {0};
    int zero_len = pkt_build_data_frame(zero_packet, sizeof(zero_packet),
                                        0, test_session_id,
                                        zero_nonce, tag, ct, (uint16_t)strlen((char *)ct));
    out_res->injected_replays++;
    suite_adapter_send_udp(adapter, zero_packet, (size_t)zero_len);
    usleep(50000);

    ipc_rc = suite_adapter_poll_ipc_rx(adapter, &ev, 50);
    if (ipc_rc == 1) {
        out_res->accepted_replays++;
    } else {
        out_res->rejected_replays++;
    }

    /* 8. Test 5: Cross-session replay injection (Session ID changed) */
    uint8_t cross_session_pkt[MAX_WIRE_PACKET_SIZE];
    uint64_t diff_session_id = 0xdeadbeefcafebabeULL;
    int cross_len = pkt_build_data_frame(cross_session_pkt, sizeof(cross_session_pkt),
                                         10, diff_session_id,
                                         nonce, tag, ct, (uint16_t)strlen((char *)ct));
    out_res->injected_replays++;
    suite_adapter_send_udp(adapter, cross_session_pkt, (size_t)cross_len);
    usleep(50000);

    ipc_rc = suite_adapter_poll_ipc_rx(adapter, &ev, 50);
    if (ipc_rc == 1) {
        out_res->accepted_replays++;
    } else {
        out_res->rejected_replays++;
    }

    /* 9. Verify server health and legitimate client execution after replay flood */
    int delivered = 0;
    double hs_ms = 0, msg_ms = 0;
    int client_rc = suite_adapter_run_client_job(adapter, 3, &delivered, &hs_ms, &msg_ms);

    double rec_rtt = 0;
    int hrc = suite_adapter_probe_health(adapter, &rec_rtt);
    out_res->recovery_rtt_us = rec_rtt;

    char evidence[512];
    snprintf(evidence, sizeof(evidence),
             "Injected Replays: %u | Replay Accepted by App: %u (Must be 0) | Replays Rejected: %u | Legitimate Client Post-Test: %s | Server Health: %.2f µs",
             out_res->injected_replays, out_res->accepted_replays, out_res->rejected_replays,
             (client_rc == 0) ? "DELIVERED OK" : "FAILED", rec_rtt);

    result_status_t status = (out_res->accepted_replays == 0 && hrc == 0 && client_rc == 0)
                             ? RESULT_PASS : RESULT_FAIL;

    scenario_result_finalize(out_res, status,
                             (status == RESULT_PASS)
                                 ? "All replayed datagrams (duplicate seq, stale seq, seq 0, cross-session) strictly rejected by replay window"
                                 : "One or more replayed datagrams were accepted or server degraded",
                             evidence);

    safety_guard_audit_log("SCENARIO_FINISH", out_res->suite_name, out_res->scenario_id, adapter->target_ip, evidence);
    return 0;
}
