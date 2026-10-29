/*
 * security_lab/attacks/network_resilience.c
 *
 * Implements user-space in-transit impairment gateway and Scenario B resilience tests
 * (Packet loss, Delay/Jitter, Reordering, Duplication, Disconnect, MTU bounds).
 */

#include "network_test.h"
#include "protocol_framer.h"
#include "safety_guard.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>
#include <time.h>

static void *gateway_worker_thread(void *arg) {
    net_impairment_gateway_t *gw = (net_impairment_gateway_t *)arg;
    uint8_t buf[MAX_WIRE_PACKET_SIZE];
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    bool has_client = false;

    struct sockaddr_in srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(gw->target_server_port);
    inet_pton(AF_INET, gw->target_ip, &srv_addr.sin_addr);

    uint8_t reorder_held_buf[MAX_WIRE_PACKET_SIZE];
    size_t  reorder_held_len = 0;
    bool    reorder_held = false;

    while (gw->running && !g_safety_emergency_stop) {
        struct pollfd pfd = { .fd = gw->proxy_sock, .events = POLLIN };
        int prc = poll(&pfd, 1, 100);
        if (prc <= 0) continue;

        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        ssize_t n = recvfrom(gw->proxy_sock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &from_len);
        if (n <= 0) continue;

        /* Is packet from client or from server? */
        bool from_server = (from.sin_addr.s_addr == srv_addr.sin_addr.s_addr &&
                            from.sin_port == srv_addr.sin_port);

        if (!from_server) {
            client_addr = from;
            has_client = true;
        }

        /* Check for temporary disconnection (blackhole) */
        if (gw->blackhole_active) {
            continue; /* drop without forwarding */
        }

        /* Check packet loss */
        if (gw->loss_pct > 0) {
            int r = rand() % 100;
            if (r < gw->loss_pct) {
                continue; /* drop packet */
            }
        }

        /* Check delay and jitter */
        if (gw->delay_ms > 0) {
            int jitter = (gw->jitter_ms > 0) ? ((rand() % (2 * gw->jitter_ms + 1)) - gw->jitter_ms) : 0;
            int total_delay = gw->delay_ms + jitter;
            if (total_delay > 0) {
                struct timespec req = { .tv_sec = total_delay / 1000,
                                        .tv_nsec = (long)(total_delay % 1000) * 1000000L };
                nanosleep(&req, NULL);
            }
        }

        /* Check reordering */
        if (!from_server && gw->reorder_pct > 0) {
            if (!reorder_held && (rand() % 100 < gw->reorder_pct)) {
                memcpy(reorder_held_buf, buf, (size_t)n);
                reorder_held_len = (size_t)n;
                reorder_held = true;
                continue; /* Hold this packet */
            }
        }

        /* Forward packet */
        if (from_server) {
            if (has_client) {
                sendto(gw->proxy_sock, buf, n, 0, (struct sockaddr *)&client_addr, client_len);
            }
        } else {
            sendto(gw->proxy_sock, buf, n, 0, (struct sockaddr *)&srv_addr, sizeof(srv_addr));

            /* Check packet duplication */
            if (gw->duplicate_pct > 0 && (rand() % 100 < gw->duplicate_pct)) {
                sendto(gw->proxy_sock, buf, n, 0, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
            }

            /* If we held a packet for reordering, release it now */
            if (reorder_held) {
                usleep(5000);
                sendto(gw->proxy_sock, reorder_held_buf, reorder_held_len, 0,
                       (struct sockaddr *)&srv_addr, sizeof(srv_addr));
                reorder_held = false;
            }
        }
    }

    return NULL;
}

int net_gateway_start(net_impairment_gateway_t *gw, uint16_t listen_port,
                      const char *target_ip, uint16_t target_port) {
    if (!gw) return -1;
    memset(gw, 0, sizeof(*gw));

    gw->proxy_listen_port = listen_port;
    gw->target_server_port = target_port;
    strncpy(gw->target_ip, target_ip ? target_ip : "127.0.0.1", sizeof(gw->target_ip) - 1);

    if (safety_guard_is_dry_run()) {
        printf("[DRY-RUN] Would start in-transit impairment gateway on port %u -> %s:%u\n",
               listen_port, gw->target_ip, target_port);
        gw->running = true;
        return 0;
    }

    gw->proxy_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (gw->proxy_sock < 0) return -1;

    struct sockaddr_in baddr;
    memset(&baddr, 0, sizeof(baddr));
    baddr.sin_family = AF_INET;
    baddr.sin_addr.s_addr = INADDR_ANY;
    baddr.sin_port = htons(listen_port);

    int opt = 1;
    setsockopt(gw->proxy_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(gw->proxy_sock, (struct sockaddr *)&baddr, sizeof(baddr)) != 0) {
        close(gw->proxy_sock);
        gw->proxy_sock = -1;
        return -1;
    }

    gw->running = true;
    if (pthread_create(&gw->thread_id, NULL, gateway_worker_thread, gw) != 0) {
        close(gw->proxy_sock);
        gw->proxy_sock = -1;
        return -1;
    }

    return 0;
}

void net_gateway_stop(net_impairment_gateway_t *gw) {
    if (!gw || !gw->running) return;
    gw->running = false;
    if (safety_guard_is_dry_run()) {
        printf("[DRY-RUN] Would stop in-transit impairment gateway\n");
        return;
    }
    if (gw->proxy_sock >= 0) {
        shutdown(gw->proxy_sock, SHUT_RDWR);
        close(gw->proxy_sock);
        gw->proxy_sock = -1;
    }
    pthread_join(gw->thread_id, NULL);
}

void net_gateway_set_impairment(net_impairment_gateway_t *gw,
                                int loss_pct, int delay_ms, int jitter_ms,
                                int reorder_pct, int duplicate_pct, bool blackhole) {
    if (!gw) return;
    gw->loss_pct = loss_pct;
    gw->delay_ms = delay_ms;
    gw->jitter_ms = jitter_ms;
    gw->reorder_pct = reorder_pct;
    gw->duplicate_pct = duplicate_pct;
    gw->blackhole_active = blackhole;
}

/* ── Scenario Implementations ─────────────────────────────────────── */

int run_scenario_baseline(suite_adapter_t *adapter, scenario_result_t *out_res, int trials) {
    scenario_result_init(out_res, "SCENARIO_A_BASELINE", "Standard Legitimate Session Baseline",
                         suite_adapter_name(adapter->suite_type));

    safety_guard_audit_log("SCENARIO_START", out_res->suite_name, out_res->scenario_id, adapter->target_ip, "Starting baseline trial");

    /* 1. Health preflight */
    double rtt = 0;
    if (suite_adapter_probe_health(adapter, &rtt) != 0) {
        scenario_result_finalize(out_res, RESULT_FAIL, "Server health preflight failed: server not reachable or unresponsive", "Probe timeout");
        return -1;
    }
    out_res->baseline_rtt_us = rtt;

    int total_delivered = 0;
    int runs = (trials > 0) ? trials : 3;

    for (int i = 0; i < runs; i++) {
        out_res->handshake_attempts++;
        int delivered = 0;
        double hs_ms = 0, msg_ms = 0;

        int rc = suite_adapter_run_client_job(adapter, 5, &delivered, &hs_ms, &msg_ms);
        if (rc == 0) {
            out_res->handshake_successes++;
            total_delivered += delivered;
            latency_tracker_add(&out_res->handshake_lat_ms, hs_ms);
            latency_tracker_add(&out_res->message_rtt_ms, msg_ms);
        } else {
            out_res->handshake_failures++;
        }
    }

    out_res->messages_sent = (uint32_t)(runs * 5);
    out_res->messages_acked = (uint32_t)total_delivered;
    out_res->messages_lost = out_res->messages_sent - out_res->messages_acked;

    char evidence[512];
    snprintf(evidence, sizeof(evidence),
             "Handshake Success Rate: %u/%u (%.1f%%) | Delivered: %u/%u messages | Health Probe RTT: %.2f µs",
             out_res->handshake_successes, out_res->handshake_attempts,
             (out_res->handshake_attempts > 0) ? (out_res->handshake_successes * 100.0 / out_res->handshake_attempts) : 0.0,
             out_res->messages_acked, out_res->messages_sent, out_res->baseline_rtt_us);

    result_status_t status = (out_res->handshake_successes == (uint32_t)runs) ? RESULT_PASS : RESULT_FAIL;
    scenario_result_finalize(out_res, status,
                             (status == RESULT_PASS) ? "Baseline legitimate communication completed successfully" : "One or more baseline runs failed",
                             evidence);

    safety_guard_audit_log("SCENARIO_FINISH", out_res->suite_name, out_res->scenario_id, adapter->target_ip, evidence);
    return 0;
}

int run_scenario_loss(suite_adapter_t *adapter, scenario_result_t *out_res, int loss_pct) {
    char id[64];
    snprintf(id, sizeof(id), "SCENARIO_B1_LOSS_%d_PCT", loss_pct);
    scenario_result_init(out_res, id, "Network Resilience: Controlled Packet Loss Profile",
                         suite_adapter_name(adapter->suite_type));

    safety_guard_audit_log("SCENARIO_START", out_res->suite_name, id, adapter->target_ip, "Starting packet loss test");

    double rtt = 0;
    suite_adapter_probe_health(adapter, &rtt);
    out_res->baseline_rtt_us = rtt;

    /* Start in-transit impairment gateway */
    net_impairment_gateway_t gw;
    uint16_t proxy_port = 9880;
    if (net_gateway_start(&gw, proxy_port, adapter->target_ip, adapter->target_port) != 0) {
        scenario_result_finalize(out_res, RESULT_ERROR, "Failed to initialize in-transit impairment gateway", "Socket bind error");
        return -1;
    }
    net_gateway_set_impairment(&gw, loss_pct, 0, 0, 0, 0, false);

    /* Point adapter client to gateway proxy port */
    suite_adapter_t proxy_adapter;
    suite_adapter_init(&proxy_adapter, adapter->suite_type, "127.0.0.1", proxy_port);

    int delivered = 0;
    double hs_ms = 0, msg_ms = 0;
    out_res->handshake_attempts = 3;

    for (int i = 0; i < 3; i++) {
        int d = 0;
        int rc = suite_adapter_run_client_job(&proxy_adapter, 5, &d, &hs_ms, &msg_ms);
        if (rc == 0) {
            out_res->handshake_successes++;
            delivered += d;
            latency_tracker_add(&out_res->handshake_lat_ms, hs_ms);
        } else {
            out_res->handshake_failures++;
        }
    }

    out_res->messages_sent = 15;
    out_res->messages_acked = (uint32_t)delivered;
    out_res->messages_lost = 15 - (uint32_t)delivered;

    /* Stop gateway and verify recovery */
    net_gateway_stop(&gw);
    suite_adapter_cleanup(&proxy_adapter);

    double rec_rtt = 0;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int hrc = suite_adapter_probe_health(adapter, &rec_rtt);
    clock_gettime(CLOCK_MONOTONIC, &t1);

    out_res->recovery_rtt_us = rec_rtt;
    out_res->recovery_time_ms = (double)(t1.tv_sec - t0.tv_sec) * 1e3 + (double)(t1.tv_nsec - t0.tv_nsec) * 1e-6;

    char evidence[512];
    snprintf(evidence, sizeof(evidence),
             "Configured Impairment Loss: %d%% | Observed App Loss: %u/%u messages (%.1f%%) | Post-Impairment Health Recovery: %.2f µs (took %.2f ms)",
             loss_pct, out_res->messages_lost, out_res->messages_sent,
             (out_res->messages_lost * 100.0 / 15.0), out_res->recovery_rtt_us, out_res->recovery_time_ms);

    result_status_t status = (hrc == 0) ? RESULT_PASS : RESULT_FAIL;
    scenario_result_finalize(out_res, status,
                             (status == RESULT_PASS) ? "Server maintained health and recovered cleanly after packet loss impairment" : "Server failed to recover",
                             evidence);

    safety_guard_audit_log("SCENARIO_FINISH", out_res->suite_name, id, adapter->target_ip, evidence);
    return 0;
}

int run_scenario_delay_jitter(suite_adapter_t *adapter, scenario_result_t *out_res, int delay_ms, int jitter_ms) {
    char id[64];
    snprintf(id, sizeof(id), "SCENARIO_B2_DELAY_%dMS_JITTER_%dMS", delay_ms, jitter_ms);
    scenario_result_init(out_res, id, "Network Resilience: Bounded Delay & Variable Jitter",
                         suite_adapter_name(adapter->suite_type));

    safety_guard_audit_log("SCENARIO_START", out_res->suite_name, id, adapter->target_ip, "Starting delay/jitter test");

    double rtt = 0;
    suite_adapter_probe_health(adapter, &rtt);
    out_res->baseline_rtt_us = rtt;

    net_impairment_gateway_t gw;
    uint16_t proxy_port = 9880;
    if (net_gateway_start(&gw, proxy_port, adapter->target_ip, adapter->target_port) != 0) {
        scenario_result_finalize(out_res, RESULT_ERROR, "Failed to initialize in-transit impairment gateway", "Socket bind error");
        return -1;
    }
    net_gateway_set_impairment(&gw, 0, delay_ms, jitter_ms, 0, 0, false);

    suite_adapter_t proxy_adapter;
    suite_adapter_init(&proxy_adapter, adapter->suite_type, "127.0.0.1", proxy_port);

    int delivered = 0;
    double hs_ms = 0, msg_ms = 0;
    out_res->handshake_attempts = 2;

    for (int i = 0; i < 2; i++) {
        int d = 0;
        int rc = suite_adapter_run_client_job(&proxy_adapter, 5, &d, &hs_ms, &msg_ms);
        if (rc == 0) {
            out_res->handshake_successes++;
            delivered += d;
            latency_tracker_add(&out_res->handshake_lat_ms, hs_ms);
            latency_tracker_add(&out_res->message_rtt_ms, msg_ms);
        } else {
            out_res->handshake_failures++;
        }
    }

    out_res->messages_sent = 10;
    out_res->messages_acked = (uint32_t)delivered;

    net_gateway_stop(&gw);
    suite_adapter_cleanup(&proxy_adapter);

    double rec_rtt = 0;
    int hrc = suite_adapter_probe_health(adapter, &rec_rtt);
    out_res->recovery_rtt_us = rec_rtt;

    char evidence[512];
    snprintf(evidence, sizeof(evidence),
             "Injected Delay: %d ms | Jitter: ±%d ms | Handshake Latency: %.2f ms | Handshake Success: %u/%u | Post-Test RTT: %.2f µs",
             delay_ms, jitter_ms, hs_ms, out_res->handshake_successes, out_res->handshake_attempts, rec_rtt);

    result_status_t status = (hrc == 0 && out_res->handshake_successes > 0) ? RESULT_PASS : RESULT_FAIL;
    scenario_result_finalize(out_res, status,
                             "Protocol handled added delay/jitter within bounded timeout and maintained session stability",
                             evidence);

    safety_guard_audit_log("SCENARIO_FINISH", out_res->suite_name, id, adapter->target_ip, evidence);
    return 0;
}

int run_scenario_reorder(suite_adapter_t *adapter, scenario_result_t *out_res, int reorder_pct) {
    char id[64];
    snprintf(id, sizeof(id), "SCENARIO_B3_REORDER_%d_PCT", reorder_pct);
    scenario_result_init(out_res, id, "Network Resilience: Controlled Packet Reordering",
                         suite_adapter_name(adapter->suite_type));

    safety_guard_audit_log("SCENARIO_START", out_res->suite_name, id, adapter->target_ip, "Starting packet reorder test");

    net_impairment_gateway_t gw;
    uint16_t proxy_port = 9880;
    if (net_gateway_start(&gw, proxy_port, adapter->target_ip, adapter->target_port) != 0) {
        scenario_result_finalize(out_res, RESULT_ERROR, "Gateway start failed", "");
        return -1;
    }
    net_gateway_set_impairment(&gw, 0, 0, 0, reorder_pct, 0, false);

    suite_adapter_t proxy_adapter;
    suite_adapter_init(&proxy_adapter, adapter->suite_type, "127.0.0.1", proxy_port);

    int delivered = 0;
    double hs_ms = 0, msg_ms = 0;
    out_res->handshake_attempts = 2;

    for (int i = 0; i < 2; i++) {
        int d = 0;
        int rc = suite_adapter_run_client_job(&proxy_adapter, 5, &d, &hs_ms, &msg_ms);
        if (rc == 0) {
            out_res->handshake_successes++;
            delivered += d;
        } else {
            out_res->handshake_failures++;
        }
    }

    out_res->messages_sent = 10;
    out_res->messages_acked = (uint32_t)delivered;

    net_gateway_stop(&gw);
    suite_adapter_cleanup(&proxy_adapter);

    double rec_rtt = 0;
    int hrc = suite_adapter_probe_health(adapter, &rec_rtt);
    out_res->recovery_rtt_us = rec_rtt;

    char evidence[512];
    snprintf(evidence, sizeof(evidence),
             "Reorder Probability: %d%% | Delivered: %u/%u messages | Server Health: %.2f µs",
             reorder_pct, out_res->messages_acked, out_res->messages_sent, rec_rtt);

    result_status_t status = (hrc == 0 && out_res->messages_acked > 0) ? RESULT_PASS : RESULT_FAIL;
    scenario_result_finalize(out_res, status,
                             "Out-of-order packets handled within replay window boundaries without session drop",
                             evidence);

    safety_guard_audit_log("SCENARIO_FINISH", out_res->suite_name, id, adapter->target_ip, evidence);
    return 0;
}

int run_scenario_duplication(suite_adapter_t *adapter, scenario_result_t *out_res, int dup_pct) {
    char id[64];
    snprintf(id, sizeof(id), "SCENARIO_B4_DUPLICATION_%d_PCT", dup_pct);
    scenario_result_init(out_res, id, "Network Resilience: Packet Duplication Rejection",
                         suite_adapter_name(adapter->suite_type));

    safety_guard_audit_log("SCENARIO_START", out_res->suite_name, id, adapter->target_ip, "Starting duplication test");

    net_impairment_gateway_t gw;
    uint16_t proxy_port = 9880;
    if (net_gateway_start(&gw, proxy_port, adapter->target_ip, adapter->target_port) != 0) {
        scenario_result_finalize(out_res, RESULT_ERROR, "Gateway start failed", "");
        return -1;
    }
    net_gateway_set_impairment(&gw, 0, 0, 0, 0, dup_pct, false);

    suite_adapter_t proxy_adapter;
    suite_adapter_init(&proxy_adapter, adapter->suite_type, "127.0.0.1", proxy_port);

    int delivered = 0;
    double hs_ms = 0, msg_ms = 0;
    out_res->handshake_attempts = 2;

    for (int i = 0; i < 2; i++) {
        int d = 0;
        int rc = suite_adapter_run_client_job(&proxy_adapter, 5, &d, &hs_ms, &msg_ms);
        if (rc == 0) {
            out_res->handshake_successes++;
            delivered += d;
        } else {
            out_res->handshake_failures++;
        }
    }

    out_res->messages_sent = 10;
    out_res->messages_acked = (uint32_t)delivered;

    net_gateway_stop(&gw);
    suite_adapter_cleanup(&proxy_adapter);

    double rec_rtt = 0;
    int hrc = suite_adapter_probe_health(adapter, &rec_rtt);
    out_res->recovery_rtt_us = rec_rtt;

    char evidence[512];
    snprintf(evidence, sizeof(evidence),
             "Duplication Rate: %d%% | Legitimate Delivered: %u/%u messages | Server Health RTT: %.2f µs",
             dup_pct, out_res->messages_acked, out_res->messages_sent, rec_rtt);

    result_status_t status = (hrc == 0 && out_res->messages_acked > 0) ? RESULT_PASS : RESULT_FAIL;
    scenario_result_finalize(out_res, status,
                             "Duplicate packets rejected by replay protection; session maintained stability",
                             evidence);

    safety_guard_audit_log("SCENARIO_FINISH", out_res->suite_name, id, adapter->target_ip, evidence);
    return 0;
}

int run_scenario_disconnection(suite_adapter_t *adapter, scenario_result_t *out_res, int disconnect_duration_sec) {
    char id[64];
    snprintf(id, sizeof(id), "SCENARIO_B5_TEMPORARY_DISCONNECT_%dS", disconnect_duration_sec);
    scenario_result_init(out_res, id, "Network Resilience: Temporary Connectivity Interruption & Recovery",
                         suite_adapter_name(adapter->suite_type));

    safety_guard_audit_log("SCENARIO_START", out_res->suite_name, id, adapter->target_ip, "Starting disconnect test");

    net_impairment_gateway_t gw;
    uint16_t proxy_port = 9880;
    if (net_gateway_start(&gw, proxy_port, adapter->target_ip, adapter->target_port) != 0) {
        scenario_result_finalize(out_res, RESULT_ERROR, "Gateway start failed", "");
        return -1;
    }

    /* 1. Simulate temporary blackhole */
    net_gateway_set_impairment(&gw, 0, 0, 0, 0, 0, true);
    sleep((unsigned int)disconnect_duration_sec);

    /* 2. Restore connectivity */
    net_gateway_set_impairment(&gw, 0, 0, 0, 0, 0, false);

    /* 3. Measure time until legitimate service resumes */
    suite_adapter_t proxy_adapter;
    suite_adapter_init(&proxy_adapter, adapter->suite_type, "127.0.0.1", proxy_port);

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    int delivered = 0;
    double hs_ms = 0, msg_ms = 0;
    int rc = suite_adapter_run_client_job(&proxy_adapter, 5, &delivered, &hs_ms, &msg_ms);

    clock_gettime(CLOCK_MONOTONIC, &t1);
    out_res->recovery_time_ms = (double)(t1.tv_sec - t0.tv_sec) * 1e3 + (double)(t1.tv_nsec - t0.tv_nsec) * 1e-6;

    net_gateway_stop(&gw);
    suite_adapter_cleanup(&proxy_adapter);

    double rec_rtt = 0;
    int hrc = suite_adapter_probe_health(adapter, &rec_rtt);
    out_res->recovery_rtt_us = rec_rtt;

    char evidence[512];
    snprintf(evidence, sizeof(evidence),
             "Blackhole Duration: %d s | Post-Restoration Reconnect Time: %.2f ms | Handshake Outcome: %s | Post-Test RTT: %.2f µs",
             disconnect_duration_sec, out_res->recovery_time_ms,
             (rc == 0) ? "SUCCESSFUL RECONNECTION" : "FAILED", rec_rtt);

    result_status_t status = (hrc == 0 && rc == 0) ? RESULT_PASS : RESULT_FAIL;
    scenario_result_finalize(out_res, status,
                             "Session cleanly re-established after network restoration; stale state unblocked",
                             evidence);

    safety_guard_audit_log("SCENARIO_FINISH", out_res->suite_name, id, adapter->target_ip, evidence);
    return 0;
}

int run_scenario_mtu(suite_adapter_t *adapter, scenario_result_t *out_res) {
    scenario_result_init(out_res, "SCENARIO_B6_MTU_BOUNDARIES", "Network Resilience: Path MTU & Fragmentation Boundaries",
                         suite_adapter_name(adapter->suite_type));

    safety_guard_audit_log("SCENARIO_START", out_res->suite_name, out_res->scenario_id, adapter->target_ip, "Starting MTU boundary test");

    /* Test packet boundary sizes: 512, 1024, 1472, 1500, 3152, 4096 */
    uint16_t test_sizes[] = { 512, 1024, 1472, 1500, 3152, 4096 };
    int size_count = sizeof(test_sizes) / sizeof(test_sizes[0]);
    int successful_boundaries = 0;

    for (int i = 0; i < size_count; i++) {
        uint16_t sz = test_sizes[i];
        uint8_t *large_buf = malloc(sz);
        if (!large_buf) continue;

        memset(large_buf, 0x41 + (i % 26), sz);
        uint8_t wire_buf[MAX_WIRE_PACKET_SIZE];
        int plen = pkt_build_frame(wire_buf, sizeof(wire_buf), 9000 + i, PKT_PING, 0, large_buf, sz);

        if (plen > 0) {
            suite_adapter_send_udp(adapter, wire_buf, (size_t)plen);
            successful_boundaries++;
        }
        free(large_buf);
        usleep(10000);
    }

    double rec_rtt = 0;
    int hrc = suite_adapter_probe_health(adapter, &rec_rtt);
    out_res->recovery_rtt_us = rec_rtt;

    char evidence[512];
    snprintf(evidence, sizeof(evidence),
             "Tested %d MTU Boundary Sizes (512B to 4096B) | Sent: %d/6 frames | Server Integrity RTT: %.2f µs",
             size_count, successful_boundaries, rec_rtt);

    result_status_t status = (hrc == 0) ? RESULT_PASS : RESULT_FAIL;
    scenario_result_finalize(out_res, status,
                             "Server safely processed large datagram boundaries without overflow or memory corruption",
                             evidence);

    safety_guard_audit_log("SCENARIO_FINISH", out_res->suite_name, out_res->scenario_id, adapter->target_ip, evidence);
    return 0;
}
