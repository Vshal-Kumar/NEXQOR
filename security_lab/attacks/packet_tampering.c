/*
 * security_lab/attacks/packet_tampering.c
 *
 * Evaluates AEAD cryptographic integrity against running servers:
 * - Ciphertext bit-flipping
 * - Authentication tag (MAC) corruption
 * - Nonce mutation
 * - Associated Authenticated Data (AAD) header mutation (seq, type, len, session_id)
 * - Invalid frame type injection
 */

#include "suite_adapter.h"
#include "protocol_framer.h"
#include "safety_guard.h"
#include "metrics.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int run_scenario_tampering(suite_adapter_t *adapter, scenario_result_t *out_res) {
    scenario_result_init(out_res, "SCENARIO_D_AEAD_INTEGRITY",
                         "AEAD Cryptographic Integrity & Header Tampering Verification",
                         suite_adapter_name(adapter->suite_type));

    safety_guard_audit_log("SCENARIO_START", out_res->suite_name, out_res->scenario_id, adapter->target_ip, "Starting AEAD tampering tests");

    double rtt = 0;
    if (suite_adapter_probe_health(adapter, &rtt) != 0) {
        scenario_result_finalize(out_res, RESULT_FAIL, "Server unresponsive before tampering test", "Health probe failed");
        return -1;
    }
    out_res->baseline_rtt_us = rtt;

    suite_adapter_connect_ipc(adapter);

    uint64_t session_id = 0x1122334455667788ULL;
    uint32_t seq = 20;
    uint8_t nonce[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20};
    uint8_t tag[16]   = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99};
    uint8_t ct[32]    = "AUTHENTICATED_CIPHERTEXT_SAMPLE";

    uint8_t base_pkt[MAX_WIRE_PACKET_SIZE];
    int base_len = pkt_build_data_frame(base_pkt, sizeof(base_pkt), seq, session_id,
                                        nonce, tag, ct, (uint16_t)strlen((char *)ct));
    if (base_len < 0) {
        scenario_result_finalize(out_res, RESULT_ERROR, "Failed to serialize base frame", "");
        return -1;
    }

    out_res->injected_tampered = 0;
    out_res->accepted_tampered = 0;
    out_res->rejected_tampered = 0;

    /* ── Test 1: Bit-flip in Ciphertext ────────────────────────────── */
    uint8_t ct_flip_pkt[MAX_WIRE_PACKET_SIZE];
    memcpy(ct_flip_pkt, base_pkt, (size_t)base_len);
    ct_flip_pkt[PKT_HDR_BYTES + AEAD_OVERHEAD_BYTES + 3] ^= 0x40; /* Flip 1 bit */
    out_res->injected_tampered++;
    suite_adapter_send_udp(adapter, ct_flip_pkt, (size_t)base_len);
    usleep(30000);

    ipc_rx_event_t ev;
    if (suite_adapter_poll_ipc_rx(adapter, &ev, 30) == 1) {
        out_res->accepted_tampered++;
    } else {
        out_res->rejected_tampered++;
    }

    /* ── Test 2: Bit-flip in Authentication Tag (Poly1305 / CCM MAC) ── */
    uint8_t tag_flip_pkt[MAX_WIRE_PACKET_SIZE];
    memcpy(tag_flip_pkt, base_pkt, (size_t)base_len);
    tag_flip_pkt[PKT_HDR_BYTES + AEAD_NONCE_BYTES + 5] ^= 0x80; /* Flip 1 bit in tag */
    out_res->injected_tampered++;
    suite_adapter_send_udp(adapter, tag_flip_pkt, (size_t)base_len);
    usleep(30000);

    if (suite_adapter_poll_ipc_rx(adapter, &ev, 30) == 1) {
        out_res->accepted_tampered++;
    } else {
        out_res->rejected_tampered++;
    }

    /* ── Test 3: Nonce Mutation ────────────────────────────────────── */
    uint8_t nonce_flip_pkt[MAX_WIRE_PACKET_SIZE];
    memcpy(nonce_flip_pkt, base_pkt, (size_t)base_len);
    nonce_flip_pkt[PKT_HDR_BYTES + 11] ^= 0x01; /* Mutate nonce counter */
    out_res->injected_tampered++;
    suite_adapter_send_udp(adapter, nonce_flip_pkt, (size_t)base_len);
    usleep(30000);

    if (suite_adapter_poll_ipc_rx(adapter, &ev, 30) == 1) {
        out_res->accepted_tampered++;
    } else {
        out_res->rejected_tampered++;
    }

    /* ── Test 4: Header AAD Mutation (Tamper Wire Type) ────────────── */
    uint8_t type_flip_pkt[MAX_WIRE_PACKET_SIZE];
    memcpy(type_flip_pkt, base_pkt, (size_t)base_len);
    type_flip_pkt[4] = 0x15; /* Change type from PKT_DATA to PKT_DISCONNECT in header */
    out_res->injected_tampered++;
    suite_adapter_send_udp(adapter, type_flip_pkt, (size_t)base_len);
    usleep(30000);

    if (suite_adapter_poll_ipc_rx(adapter, &ev, 30) == 1) {
        out_res->accepted_tampered++;
    } else {
        out_res->rejected_tampered++;
    }

    /* ── Test 5: Header AAD Mutation (Tamper Session ID) ───────────── */
    uint8_t sid_flip_pkt[MAX_WIRE_PACKET_SIZE];
    memcpy(sid_flip_pkt, base_pkt, (size_t)base_len);
    sid_flip_pkt[7] ^= 0xff; /* Mutate session ID in header */
    out_res->injected_tampered++;
    suite_adapter_send_udp(adapter, sid_flip_pkt, (size_t)base_len);
    usleep(30000);

    if (suite_adapter_poll_ipc_rx(adapter, &ev, 30) == 1) {
        out_res->accepted_tampered++;
    } else {
        out_res->rejected_tampered++;
    }

    /* ── Test 6: Invalid Undefined Frame Type (0xEE) ───────────────── */
    uint8_t invalid_type_pkt[MAX_WIRE_PACKET_SIZE];
    memcpy(invalid_type_pkt, base_pkt, (size_t)base_len);
    invalid_type_pkt[4] = 0xEE;
    out_res->injected_tampered++;
    suite_adapter_send_udp(adapter, invalid_type_pkt, (size_t)base_len);
    usleep(30000);

    if (suite_adapter_poll_ipc_rx(adapter, &ev, 30) == 1) {
        out_res->accepted_tampered++;
    } else {
        out_res->rejected_tampered++;
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
             "Injected Tampered Frames: %u | Cryptographically Accepted: %u (Must be 0) | Rejected: %u | Legitimate Client Post-Test: %s | Server Health: %.2f µs",
             out_res->injected_tampered, out_res->accepted_tampered, out_res->rejected_tampered,
             (client_rc == 0) ? "DELIVERED OK" : "FAILED", rec_rtt);

    result_status_t status = (out_res->accepted_tampered == 0 && hrc == 0 && client_rc == 0)
                             ? RESULT_PASS : RESULT_FAIL;

    scenario_result_finalize(out_res, status,
                             (status == RESULT_PASS)
                                 ? "All modified ciphertexts, tags, nonces, and AAD headers strictly rejected by AEAD authentication; zero plaintext leaked"
                                 : "One or more tampered packets passed authentication or server degraded",
                             evidence);

    safety_guard_audit_log("SCENARIO_FINISH", out_res->suite_name, out_res->scenario_id, adapter->target_ip, evidence);
    return 0;
}
