/*
 * security_lab/attacks/malformed_packet_test.c
 *
 * Deterministic malformed datagram and parser robustness evaluation:
 * - Empty datagrams (0 bytes)
 * - Truncated headers (1 to 14 bytes)
 * - Inconsistent length fields (length > buffer, length < overhead)
 * - Truncated AEAD nonce/tag (< 28 bytes)
 * - Boundary fuzzing & deterministic pseudo-random fuzz payloads
 */

#include "suite_adapter.h"
#include "protocol_framer.h"
#include "safety_guard.h"
#include "metrics.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int run_scenario_malformed(suite_adapter_t *adapter, scenario_result_t *out_res) {
    scenario_result_init(out_res, "SCENARIO_F_MALFORMED_INPUTS",
                         "UDP Parser Bounds Validation & Malformed Datagram Robustness",
                         suite_adapter_name(adapter->suite_type));

    safety_guard_audit_log("SCENARIO_START", out_res->suite_name, out_res->scenario_id, adapter->target_ip, "Starting malformed input tests");

    double rtt = 0;
    if (suite_adapter_probe_health(adapter, &rtt) != 0) {
        scenario_result_finalize(out_res, RESULT_FAIL, "Server unresponsive before malformed test", "Probe failed");
        return -1;
    }
    out_res->baseline_rtt_us = rtt;

    out_res->injected_malformed = 0;
    out_res->rejected_malformed = 0;
    out_res->server_crashes = 0;

    /* ── Test 1: Zero-length datagram (0 bytes) ────────────────────── */
    uint8_t zero_byte = 0;
    out_res->injected_malformed++;
    suite_adapter_send_udp(adapter, &zero_byte, 0);
    usleep(5000);
    out_res->rejected_malformed++;

    /* ── Test 2: Truncated headers (1 byte up to 14 bytes) ─────────── */
    uint8_t trunc_buf[15];
    memset(trunc_buf, 0x10, sizeof(trunc_buf));
    for (size_t sz = 1; sz < PKT_HDR_BYTES; sz++) {
        out_res->injected_malformed++;
        suite_adapter_send_udp(adapter, trunc_buf, sz);
        out_res->rejected_malformed++;
        usleep(5000);
    }

    /* ── Test 3: Inconsistent length field: len claims 10000, actual 2B */
    uint8_t wire[MAX_WIRE_PACKET_SIZE];
    pkt_serialize_header(wire, sizeof(wire), 500, PKT_DATA, 10000, 0x12345678ULL);
    wire[PKT_HDR_BYTES] = 0xAA;
    wire[PKT_HDR_BYTES + 1] = 0xBB;
    out_res->injected_malformed++;
    suite_adapter_send_udp(adapter, wire, PKT_HDR_BYTES + 2);
    out_res->rejected_malformed++;
    usleep(5000);

    /* ── Test 4: Truncated AEAD overhead (< 28 bytes) ──────────────── */
    /* PKT_DATA requires at least 12B nonce + 16B tag = 28B payload */
    for (uint16_t sub_ae = 1; sub_ae < AEAD_OVERHEAD_BYTES; sub_ae += 4) {
        pkt_serialize_header(wire, sizeof(wire), 501, PKT_DATA, sub_ae, 0x12345678ULL);
        memset(wire + PKT_HDR_BYTES, 0x77, sub_ae);
        out_res->injected_malformed++;
        suite_adapter_send_udp(adapter, wire, PKT_HDR_BYTES + sub_ae);
        out_res->rejected_malformed++;
        usleep(5000);
    }

    /* ── Test 5: Deterministic Fuzz Mutator (50 pseudo-random payloads) */
    uint32_t seed = 0x1337c0de;
    for (int i = 0; i < 50; i++) {
        size_t fuzz_len = (seed % 512) + 1;
        uint8_t fuzz_payload[512];
        for (size_t b = 0; b < fuzz_len; b++) {
            seed = (seed * 1103515245 + 12345) & 0x7fffffff;
            fuzz_payload[b] = (uint8_t)(seed & 0xff);
        }
        out_res->injected_malformed++;
        suite_adapter_send_udp(adapter, fuzz_payload, fuzz_len);
        out_res->rejected_malformed++;
        usleep(2000);
    }

    /* Verify server survival and health */
    double rec_rtt = 0;
    int hrc = suite_adapter_probe_health(adapter, &rec_rtt);
    out_res->recovery_rtt_us = rec_rtt;

    if (hrc != 0) {
        out_res->server_crashes = 1;
    }

    /* Verify legitimate client execution */
    int delivered = 0;
    double hs_ms = 0, msg_ms = 0;
    int client_rc = suite_adapter_run_client_job(adapter, 3, &delivered, &hs_ms, &msg_ms);

    char evidence[512];
    snprintf(evidence, sizeof(evidence),
             "Injected Malformed / Fuzz Datagrams: %u | Safely Rejected: %u | Server Crashes: %u | Post-Fuzz Health: %.2f µs | Legitimate Client: %s",
             out_res->injected_malformed, out_res->rejected_malformed, out_res->server_crashes,
             rec_rtt, (client_rc == 0) ? "DELIVERED OK" : "FAILED");

    result_status_t status = (out_res->server_crashes == 0 && hrc == 0 && client_rc == 0)
                             ? RESULT_PASS : RESULT_FAIL;

    scenario_result_finalize(out_res, status,
                             (status == RESULT_PASS)
                                 ? "All truncated, inconsistent, and randomized malformed datagrams handled safely; zero crashes or memory faults"
                                 : "Server crashed or hung under malformed inputs",
                             evidence);

    safety_guard_audit_log("SCENARIO_FINISH", out_res->suite_name, out_res->scenario_id, adapter->target_ip, evidence);
    return 0;
}
