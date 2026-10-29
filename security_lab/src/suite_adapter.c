#include "suite_adapter.h"
#include "protocol_framer.h"
#include "safety_guard.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#define IPC_MSG_RX      0x01
#define IPC_METRICS_RX  0x06

typedef struct __attribute__((packed)) {
    uint8_t  type;
    uint8_t  _pad;
    uint16_t client_id;
    uint32_t len;
} raw_ipc_hdr_t;

typedef struct __attribute__((packed)) {
    uint16_t client_id;
    char     ip_str[16];
    uint16_t port;
    uint64_t session_id;
    uint32_t msg_len;
} raw_ipc_rx_payload_t;

typedef struct __attribute__((packed)) {
    uint16_t client_id;
    float    decrypt_us;
    float    jitter_ms;
    float    interarrival_ms;
    float    avg_decrypt_us;
    uint64_t bytes_recv;
    uint32_t pkt_seq;
} raw_ipc_metrics_rx_t;

suite_type_t suite_adapter_parse_name(const char *name_str) {
    if (!name_str) return SUITE_TYPE_UNKNOWN;
    if (strcasecmp(name_str, "classical") == 0) return SUITE_TYPE_CLASSICAL;
    if (strcasecmp(name_str, "hybrid") == 0) return SUITE_TYPE_HYBRID;
    if (strcasecmp(name_str, "pqc") == 0 || strcasecmp(name_str, "post-quantum") == 0) return SUITE_TYPE_PQC;
    return SUITE_TYPE_UNKNOWN;
}

const char *suite_adapter_name(suite_type_t suite) {
    switch (suite) {
        case SUITE_TYPE_CLASSICAL: return "classical";
        case SUITE_TYPE_HYBRID:    return "hybrid";
        case SUITE_TYPE_PQC:       return "pqc";
        default:                   return "unknown";
    }
}

int suite_adapter_init(suite_adapter_t *adapter, suite_type_t suite,
                       const char *target_ip, uint16_t override_port) {
    if (!adapter) return -1;
    memset(adapter, 0, sizeof(*adapter));

    adapter->suite_type = suite;
    adapter->udp_sock = -1;
    adapter->ipc_rx_fd = -1;
    adapter->ipc_tx_fd = -1;
    adapter->server_pid = -1;

    const char *default_ip = (target_ip && strlen(target_ip) > 0) ? target_ip : "127.0.0.1";
    strncpy(adapter->target_ip, default_ip, sizeof(adapter->target_ip) - 1);

    char cwd[256];
    if (!getcwd(cwd, sizeof(cwd))) strcpy(cwd, ".");

    /* Strip /security_lab if running from subfolder */
    size_t clen = strlen(cwd);
    if (clen >= 13 && strcmp(cwd + clen - 13, "/security_lab") == 0) {
        cwd[clen - 13] = '\0';
    }

    switch (suite) {
        case SUITE_TYPE_CLASSICAL:
            strncpy(adapter->name, "Classical IoT Cryptography Suite", sizeof(adapter->name) - 1);
            strncpy(adapter->description, "X25519 ECDH + Ed25519 + AES-128-CCM + SHA-256 + HKDF", sizeof(adapter->description) - 1);
            strncpy(adapter->crypto_stack, "Classical (Pre-Quantum)", sizeof(adapter->crypto_stack) - 1);
            adapter->target_port = override_port ? override_port : PORT_CLASSICAL;
            snprintf(adapter->server_dir, sizeof(adapter->server_dir), "%s/classical", cwd);
            snprintf(adapter->server_bin, sizeof(adapter->server_bin), "%s/classical/server", cwd);
            snprintf(adapter->client_bin, sizeof(adapter->client_bin), "%s/classical/client", cwd);
            strncpy(adapter->ipc_rx_path, "/tmp/classical_rx.sock", sizeof(adapter->ipc_rx_path) - 1);
            strncpy(adapter->ipc_tx_path, "/tmp/classical_tx.sock", sizeof(adapter->ipc_tx_path) - 1);
            break;

        case SUITE_TYPE_HYBRID:
            strncpy(adapter->name, "Hybrid Quantum-Safe Suite", sizeof(adapter->name) - 1);
            strncpy(adapter->description, "Dual X25519/ML-KEM-768 + Dual Ed25519/ML-DSA-65 + ChaCha20-Poly1305", sizeof(adapter->description) - 1);
            strncpy(adapter->crypto_stack, "Hybrid Dual-KEM / Dual-DSA", sizeof(adapter->crypto_stack) - 1);
            adapter->target_port = override_port ? override_port : PORT_HYBRID;
            snprintf(adapter->server_dir, sizeof(adapter->server_dir), "%s/hybrid", cwd);
            snprintf(adapter->server_bin, sizeof(adapter->server_bin), "%s/hybrid/server", cwd);
            snprintf(adapter->client_bin, sizeof(adapter->client_bin), "%s/hybrid/client", cwd);
            strncpy(adapter->ipc_rx_path, "/tmp/hybrid_rx.sock", sizeof(adapter->ipc_rx_path) - 1);
            strncpy(adapter->ipc_tx_path, "/tmp/hybrid_tx.sock", sizeof(adapter->ipc_tx_path) - 1);
            break;

        case SUITE_TYPE_PQC:
        default:
            adapter->suite_type = SUITE_TYPE_PQC;
            strncpy(adapter->name, "Pure Post-Quantum Cryptography Suite (NEXQOR)", sizeof(adapter->name) - 1);
            strncpy(adapter->description, "ML-KEM-768 (Kyber) + ML-DSA-65 (Dilithium) + ChaCha20-Poly1305 + SHAKE-256", sizeof(adapter->description) - 1);
            strncpy(adapter->crypto_stack, "NIST FIPS 203 & 204 Pure PQC", sizeof(adapter->crypto_stack) - 1);
            adapter->target_port = override_port ? override_port : PORT_PQC;
            snprintf(adapter->server_dir, sizeof(adapter->server_dir), "%s/pqc", cwd);
            snprintf(adapter->server_bin, sizeof(adapter->server_bin), "%s/pqc/server", cwd);
            snprintf(adapter->client_bin, sizeof(adapter->client_bin), "%s/pqc/client", cwd);
            strncpy(adapter->ipc_rx_path, "/tmp/pqc_rx.sock", sizeof(adapter->ipc_rx_path) - 1);
            strncpy(adapter->ipc_tx_path, "/tmp/pqc_tx.sock", sizeof(adapter->ipc_tx_path) - 1);
            break;
    }

    /* Configure sockaddr_in */
    memset(&adapter->target_addr, 0, sizeof(adapter->target_addr));
    adapter->target_addr.sin_family = AF_INET;
    adapter->target_addr.sin_port = htons(adapter->target_port);
    if (inet_pton(AF_INET, adapter->target_ip, &adapter->target_addr.sin_addr) != 1) {
        return -1;
    }

    /* Open UDP socket for active test traffic */
    adapter->udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (adapter->udp_sock < 0) return -1;

    int opt = 1;
    setsockopt(adapter->udp_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    return 0;
}

void suite_adapter_cleanup(suite_adapter_t *adapter) {
    if (!adapter) return;
    if (adapter->udp_sock >= 0) {
        close(adapter->udp_sock);
        adapter->udp_sock = -1;
    }
    if (adapter->ipc_rx_fd >= 0) {
        close(adapter->ipc_rx_fd);
        adapter->ipc_rx_fd = -1;
    }
    if (adapter->ipc_tx_fd >= 0) {
        close(adapter->ipc_tx_fd);
        adapter->ipc_tx_fd = -1;
    }
    if (adapter->server_started_by_adapter) {
        suite_adapter_stop_server(adapter);
    }
}

int suite_adapter_start_server(suite_adapter_t *adapter) {
    if (!adapter) return -1;
    if (safety_guard_is_dry_run()) {
        printf("[DRY-RUN] Would start server in %s: %s\n", adapter->server_dir, adapter->server_bin);
        return 0;
    }

    /* Verify if server already responds */
    double rtt = 0;
    if (suite_adapter_probe_health(adapter, &rtt) == 0) {
        return 0; /* Already running */
    }

    pid_t pid = fork();
    if (pid == 0) {
        /* Child */
        if (chdir(adapter->server_dir) != 0) {
            perror("chdir server_dir");
            exit(1);
        }
        /* Redirect stdout/stderr to log file to avoid terminal spam */
        int fd = open("/tmp/security_lab_server.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) {
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            close(fd);
        }
        execl("./server", "./server", NULL);
        perror("execl ./server");
        exit(1);
    } else if (pid > 0) {
        adapter->server_pid = pid;
        adapter->server_started_by_adapter = true;
        usleep(300000); /* 300 ms warm-up */
        return 0;
    }
    return -1;
}

void suite_adapter_stop_server(suite_adapter_t *adapter) {
    if (!adapter || adapter->server_pid <= 0) return;
    if (!adapter->server_started_by_adapter) return; /* Never terminate external running servers */
    if (safety_guard_is_dry_run()) {
        printf("[DRY-RUN] Would terminate server PID %d\n", adapter->server_pid);
        return;
    }

    kill(adapter->server_pid, SIGINT);
    int status;
    for (int i = 0; i < 20; i++) {
        pid_t p = waitpid(adapter->server_pid, &status, WNOHANG);
        if (p == adapter->server_pid) break;
        usleep(50000);
    }
    kill(adapter->server_pid, SIGKILL);
    waitpid(adapter->server_pid, &status, WNOHANG);
    adapter->server_pid = -1;
    adapter->server_started_by_adapter = false;
}

bool suite_adapter_is_server_alive(suite_adapter_t *adapter) {
    if (!adapter) return false;
    double rtt = 0;
    return (suite_adapter_probe_health(adapter, &rtt) == 0);
}

int suite_adapter_probe_health(suite_adapter_t *adapter, double *out_rtt_us) {
    if (!adapter) return -1;
    if (safety_guard_is_dry_run()) {
        if (out_rtt_us) *out_rtt_us = 120.0;
        return 0;
    }
    if (adapter->udp_sock < 0) return -1;

    uint8_t probe_pkt[PKT_HDR_BYTES + 32];
    uint8_t offer_buf[256];

    /* Build Discovery Probe frame */
    int pkt_len = pkt_build_frame(probe_pkt, sizeof(probe_pkt),
                                  0, PKT_DISCOVERY_PROBE, 0,
                                  (const uint8_t *)"NEXQOR_PROBE", 12);
    if (pkt_len < 0) return -1;

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    for (int retry = 0; retry < 2; retry++) {
        if (sendto(adapter->udp_sock, probe_pkt, pkt_len, 0,
                   (struct sockaddr *)&adapter->target_addr, sizeof(adapter->target_addr)) != pkt_len) {
            continue;
        }

        struct pollfd pfd = { .fd = adapter->udp_sock, .events = POLLIN };
        int prc = poll(&pfd, 1, 400); /* 400 ms timeout */
        if (prc <= 0) continue;

        struct sockaddr_in from;
        socklen_t flen = sizeof(from);
        ssize_t n = recvfrom(adapter->udp_sock, offer_buf, sizeof(offer_buf), 0,
                             (struct sockaddr *)&from, &flen);
        if (n < PKT_HDR_BYTES) continue;

        clock_gettime(CLOCK_MONOTONIC, &t1);

        pkt_host_hdr_t resp_hdr;
        if (pkt_parse_header(offer_buf, (size_t)n, &resp_hdr) == 0) {
            if (resp_hdr.type == PKT_DISCOVERY_OFFER || resp_hdr.type == PKT_PONG || resp_hdr.type == PKT_ACK) {
                if (out_rtt_us) {
                    *out_rtt_us = (double)(t1.tv_sec - t0.tv_sec) * 1e6 +
                                  (double)(t1.tv_nsec - t0.tv_nsec) * 1e-3;
                }
                return 0;
            }
        }
    }

    return -1;
}

int suite_adapter_send_udp(suite_adapter_t *adapter, const uint8_t *data, size_t len) {
    if (!adapter || adapter->udp_sock < 0 || !data) return -1;
    if (safety_guard_is_dry_run()) {
        printf("[DRY-RUN] Would send %zu UDP bytes to %s:%u\n", len, adapter->target_ip, adapter->target_port);
        return (int)len;
    }

    safety_guard_throttle_pps();
    ssize_t n = sendto(adapter->udp_sock, data, len, 0,
                       (struct sockaddr *)&adapter->target_addr, sizeof(adapter->target_addr));
    return (int)n;
}

int suite_adapter_recv_udp(suite_adapter_t *adapter, uint8_t *buf, size_t max_len,
                           int timeout_ms, struct sockaddr_in *out_peer) {
    if (!adapter || adapter->udp_sock < 0 || !buf) return -1;

    struct pollfd pfd = { .fd = adapter->udp_sock, .events = POLLIN };
    int prc = poll(&pfd, 1, timeout_ms);
    if (prc <= 0) return 0; /* timeout or signal */

    struct sockaddr_in peer;
    socklen_t plen = sizeof(peer);
    ssize_t n = recvfrom(adapter->udp_sock, buf, max_len, 0, (struct sockaddr *)&peer, &plen);
    if (n > 0 && out_peer) {
        *out_peer = peer;
    }
    return (int)n;
}

int suite_adapter_connect_ipc(suite_adapter_t *adapter) {
    if (!adapter) return -1;
    if (adapter->ipc_rx_fd >= 0) return 0; /* Already connected */

    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%.107s", adapter->ipc_rx_path);

    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(s);
        return -1;
    }

    int flags = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, flags | O_NONBLOCK);

    adapter->ipc_rx_fd = s;
    return 0;
}

int suite_adapter_poll_ipc_rx(suite_adapter_t *adapter, ipc_rx_event_t *out_ev, int timeout_ms) {
    if (!adapter || !out_ev) return -1;
    if (adapter->ipc_rx_fd < 0) {
        if (suite_adapter_connect_ipc(adapter) != 0) return -1;
    }

    struct pollfd pfd = { .fd = adapter->ipc_rx_fd, .events = POLLIN };
    int prc = poll(&pfd, 1, timeout_ms);
    if (prc <= 0) return 0;

    raw_ipc_hdr_t hdr;
    ssize_t n = recv(adapter->ipc_rx_fd, &hdr, sizeof(hdr), MSG_PEEK);
    if (n < (ssize_t)sizeof(hdr)) return 0;

    size_t frame_total = sizeof(hdr) + hdr.len;
    uint8_t *frame_buf = malloc(frame_total);
    if (!frame_buf) return -1;

    ssize_t rn = recv(adapter->ipc_rx_fd, frame_buf, frame_total, 0);
    if (rn < (ssize_t)frame_total) {
        free(frame_buf);
        return 0;
    }

    int result = 0;
    if (hdr.type == IPC_MSG_RX && hdr.len >= sizeof(raw_ipc_rx_payload_t)) {
        raw_ipc_rx_payload_t *p = (raw_ipc_rx_payload_t *)(frame_buf + sizeof(hdr));
        out_ev->client_id = p->client_id;
        snprintf(out_ev->ip_str, sizeof(out_ev->ip_str), "%s", p->ip_str);
        out_ev->port = p->port;
        out_ev->session_id = p->session_id;

        const char *txt = (const char *)(frame_buf + sizeof(hdr) + sizeof(raw_ipc_rx_payload_t));
        uint32_t tlen = p->msg_len;
        if (tlen > sizeof(out_ev->plaintext) - 1) tlen = sizeof(out_ev->plaintext) - 1;
        memcpy(out_ev->plaintext, txt, tlen);
        out_ev->plaintext[tlen] = '\0';
        out_ev->plaintext_len = tlen;
        result = 1;
    }

    free(frame_buf);
    return result;
}

int suite_adapter_run_client_job(suite_adapter_t *adapter, int msg_count,
                                 int *out_delivered, double *out_hs_ms, double *out_msg_ms) {
    if (!adapter) return -1;
    if (safety_guard_is_dry_run()) {
        printf("[DRY-RUN] Would run client %s -> %s (msg_count: %d)\n",
               adapter->client_bin, adapter->target_ip, msg_count);
        if (out_delivered) *out_delivered = msg_count;
        if (out_hs_ms) *out_hs_ms = 4.5;
        if (out_msg_ms) *out_msg_ms = 1.2;
        return 0;
    }

    int pipe_out[2];
    int pipe_in[2];
    if (pipe(pipe_out) != 0) return -1;
    if (pipe(pipe_in) != 0) {
        close(pipe_out[0]);
        close(pipe_out[1]);
        return -1;
    }

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    pid_t pid = fork();
    if (pid == 0) {
        /* Child: redirect stdin to pipe_in[0] */
        dup2(pipe_in[0], STDIN_FILENO);
        close(pipe_in[0]);
        close(pipe_in[1]);

        /* Redirect stdout & stderr to pipe_out[1] */
        dup2(pipe_out[1], STDOUT_FILENO);
        dup2(pipe_out[1], STDERR_FILENO);
        close(pipe_out[0]);
        close(pipe_out[1]);

        if (chdir(adapter->server_dir) != 0) exit(1);
        if (adapter->target_port != 0 && adapter->target_port != 9877 && adapter->target_port != 9879) {
            char pstr[16];
            snprintf(pstr, sizeof(pstr), "%u", adapter->target_port);
            setenv("SERVER_PORT", pstr, 1);
        }
        execl(adapter->client_bin, adapter->client_bin, adapter->target_ip, NULL);
        exit(1);
    }

    /* Parent */
    close(pipe_in[0]);
    close(pipe_out[1]);

    /* Give client 150ms to complete KEM/DSA warmup and 4-way handshake */
    usleep(150000);

    /* Feed deterministic synthetic telemetry into client stdin */
    int count = (msg_count > 0) ? msg_count : 1;
    for (int m = 1; m <= count; m++) {
        char msg_line[128];
        int mlen = snprintf(msg_line, sizeof(msg_line), "SYNTHETIC_TELEMETRY_%d: seq=%d temp=24.5C\n", m, m);
        if (write(pipe_in[1], msg_line, mlen) <= 0) break;
        usleep(40000); /* 40 ms between telemetry samples */
    }

    /* Close stdin to signal clean EOF and disconnect to client */
    close(pipe_in[1]);

    int status = 0;
    waitpid(pid, &status, 0);
    clock_gettime(CLOCK_MONOTONIC, &t1);

    double total_ms = (double)(t1.tv_sec - t0.tv_sec) * 1e3 +
                      (double)(t1.tv_nsec - t0.tv_nsec) * 1e-6;

    char out_buf[8192];
    ssize_t nr = read(pipe_out[0], out_buf, sizeof(out_buf) - 1);
    close(pipe_out[0]);
    if (nr > 0) out_buf[nr] = '\0';
    else out_buf[0] = '\0';

    bool success = (WIFEXITED(status) && WEXITSTATUS(status) == 0);
    if (out_delivered) *out_delivered = success ? count : 0;

    /* Parse actual handshake duration if reported in stdout */
    double parsed_hs_ms = 0;
    char *hs_pos = strstr(out_buf, "Secure Handshake completed in ");
    if (hs_pos && sscanf(hs_pos, "Secure Handshake completed in %lf ms", &parsed_hs_ms) == 1) {
        if (out_hs_ms) *out_hs_ms = parsed_hs_ms;
        if (out_msg_ms) *out_msg_ms = (total_ms > parsed_hs_ms) ? (total_ms - parsed_hs_ms) / count : 1.0;
    } else {
        if (out_hs_ms) *out_hs_ms = total_ms * 0.6;
        if (out_msg_ms) *out_msg_ms = (total_ms * 0.4) / count;
    }

    return success ? 0 : -1;
}
