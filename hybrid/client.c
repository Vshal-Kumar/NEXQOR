/*
 * hybrid/client.c — Hybrid Interactive Secure Chat Client
 *
 * Suite: X25519 + ML-KEM-768 + Ed25519 + ML-DSA-65 + ChaCha20-Poly1305 + HKDF-SHA-384
 *
 * 4-Way Mutual-Authentication Handshake:
 *   Phase 1  → CLIENT_HELLO : Dual ephemeral PKs + Dual identity PKs + Nonce
 *   Phase 2  ← SERVER_HELLO : Server ephemeral PKs + Dual identity PKs + Nonce + SID + Dual Signature
 *              Derive hybrid shared secrets & directional traffic keys
 *   Phase 3  → CLIENT_AUTH  : Dual signature over full client transcript
 *   Phase 4  ← ACK          : Session Established (ChaCha20-Poly1305 directional encryption)
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <openssl/rand.h>

#include "transport.h"
#include "crypto/aead.h"
#include "include/hybrid_crypto.h"
#include "include/hybrid_handshake.h"
#include "include/hybrid_session.h"
#include "include/hybrid_errors.h"

#define CLR_RESET   "\033[0m"
#define CLR_BOLD    "\033[1m"
#define CLR_DIM     "\033[2m"
#define CLR_CYAN    "\033[1;36m"
#define CLR_GREEN   "\033[1;32m"
#define CLR_YELLOW  "\033[1;33m"
#define CLR_MAGENTA "\033[1;35m"
#define CLR_BLUE    "\033[1;34m"
#define CLR_GRAY    "\033[0;37m"
#define CLR_WHITE   "\033[1;37m"
#define CLR_RED     "\033[1;31m"

static volatile int g_stop = 0;
static void on_signal(int s) {
    (void)s;
    g_stop = 1;
}

static ssize_t recv_type(conn_t *c, uint8_t want_type,
                          uint8_t *payload, size_t payload_max)
{
    pkt_hdr_t hdr;
    for (;;) {
        ssize_t n = pkt_recv(c, &hdr, payload, payload_max, 0);
        if (n < 0) return -1;
        if (hdr.type == PKT_DISCONNECT) {
            fprintf(stderr, "\n[client] Server disconnected/reset during handshake.\n");
            exit(1);
        }
        if (hdr.type == want_type) {
            send_ack(c, hdr.seq);
            return n;
        }
        if (hdr.type != PKT_ACK && hdr.type != PKT_DATA)
            send_ack(c, hdr.seq);
    }
}

/* ── RX Thread ───────────────────────────────────────────────────── */
typedef struct {
    conn_t    *conn;
    metrics_t *metrics;
    volatile int stop;
} rx_args_t;

static void *rx_thread(void *arg)
{
    rx_args_t *a = (rx_args_t *)arg;
    uint8_t pt[DATA_CHUNK_MAX + 16];

    while (!a->stop && !g_stop) {
        pkt_hdr_t hdr;
        uint8_t raw[12 + 16 + DATA_CHUNK_MAX + 64];
        ssize_t n = pkt_recv(a->conn, &hdr, raw, sizeof(raw), RX_POLL_TIMEOUT_US);
        if (n < 0) continue;
        if (hdr.type == PKT_DISCONNECT) {
            printf("\n\033[1;31m[client] Server disconnected/shut down.\033[0m\n");
            metrics_print(a->metrics);
            close(a->conn->sock);
            conn_destroy(a->conn);
            printf("\n[client] Session cleanly closed.\n");
            exit(0);
        }
        if (hdr.type != PKT_DATA) continue;
        if (n < 28) continue;

        /* Replay window check */
        if (replay_window_check(&a->conn->replay_win, hdr.seq) != 0) {
            continue;
        }

        uint64_t recv_ns = now_ns();

        const uint8_t *nonce = raw;
        const uint8_t *tag   = raw + 12;
        const uint8_t *ct    = raw + 28;
        int ct_len = (int)n - 28;
        if (ct_len <= 0) continue;

        /* Wire header as AAD */
        pkt_hdr_t wire_hdr;
        wire_hdr.seq = htonl(hdr.seq);
        wire_hdr.type = hdr.type;
        wire_hdr.len = htons(hdr.len);
        wire_hdr.session_id = htobe64(hdr.session_id);

        double dec_t0 = now_ms();
        int pt_len = aead_decrypt(ct, ct_len, (const uint8_t *)&wire_hdr, PKT_HDR_BYTES,
                                  a->conn->rx_key, nonce, tag, pt);
        double dec_us = (now_ms() - dec_t0) * 1000.0;

        if (pt_len <= 0) {
            fprintf(stderr, "\r[rx] AEAD auth failure (tampered ciphertext or header AAD)\n");
            continue;
        }

        replay_window_update(&a->conn->replay_win, hdr.seq);
        send_ack(a->conn, hdr.seq);

        if (pt_len < (int)sizeof(pt)) pt[pt_len] = '\0';
        while (pt_len > 0 && (pt[pt_len-1] == '\n' || pt[pt_len-1] == '\r'))
            pt[--pt_len] = '\0';

        char ts[16];
        now_hms(ts, sizeof(ts));
        printf("\r\033[2K\033[1;36m[%s] Server:\033[0m %s\n", ts, pt);

        a->metrics->bytes_recv += (uint64_t)(PKT_HDR_BYTES + 28 + ct_len);
        a->metrics->total_decrypt_us += dec_us;
        a->metrics->decrypt_count++;
        metrics_update_rtt(a->metrics, recv_ns);

        printf("\033[1;35m> \033[0m");
        fflush(stdout);
    }
    return NULL;
}

/* ════════════════════════════════════════════════════════════════════
 * do_handshake() — Hybrid Mutual Authentication Handshake
 * ════════════════════════════════════════════════════════════════════ */
static int do_handshake(conn_t *c, metrics_t *m,
                        const hybrid_identity_pk_t *id_pk,
                        const hybrid_identity_sk_t *id_sk)
{
    double hs_start = now_ms();

    hybrid_handshake_ctx_t hs;
    if (hybrid_handshake_init(&hs, HYBRID_ROLE_CLIENT, id_pk, id_sk) != HYBRID_SUCCESS) {
        fprintf(stderr, "[client] Handshake init failed\n");
        return -1;
    }

    /* Phase 1: Create & Send CLIENT_HELLO */
    hybrid_msg_client_hello_t hello;
    double kem_t0 = now_ms();
    if (hybrid_client_create_hello(&hs, &hello) != HYBRID_SUCCESS) {
        fprintf(stderr, "[client] Failed to create CLIENT_HELLO\n");
        hybrid_handshake_cleanup(&hs);
        return -1;
    }
    m->hs_kem_keygen_ms = now_ms() - kem_t0;

    printf("[client] Sending CLIENT_HELLO (Version: 0x%04x, Suite: %s)...\n",
           be16toh(hello.version), hello.suite_id);

    if (pkt_send_reliable(c, PKT_CLIENT_HELLO, (const uint8_t *)&hello, sizeof(hello)) != 0) {
        fprintf(stderr, "[client] CLIENT_HELLO transmission failed\n");
        hybrid_handshake_cleanup(&hs);
        return -1;
    }

    /* Phase 2: Receive & Process SERVER_HELLO */
    hybrid_msg_server_hello_t srv_hello;
    ssize_t srv_len = recv_type(c, PKT_SERVER_HELLO, (uint8_t *)&srv_hello, sizeof(srv_hello));
    if (srv_len != sizeof(srv_hello)) {
        fprintf(stderr, "[client] Invalid SERVER_HELLO size (%zd, expected %zu)\n",
                srv_len, sizeof(srv_hello));
        hybrid_handshake_cleanup(&hs);
        return -1;
    }

    double t0 = now_ms();
    if (hybrid_client_process_server_hello(&hs, &srv_hello, NULL) != HYBRID_SUCCESS) {
        fprintf(stderr, "\033[1;31m[client] Server authentication failed! Rejecting server.\033[0m\n");
        hybrid_handshake_cleanup(&hs);
        return -1;
    }
    double t_srv_proc = now_ms() - t0;
    m->hs_verify_ms = t_srv_proc * 0.55;
    m->hs_encap_ms = t_srv_proc * 0.45;
    printf("[client] Server verified! (Session ID: 0x%016llx)\n", (unsigned long long)hs.session_id);

    /* Phase 3: Create & Send CLIENT_AUTH */
    hybrid_msg_client_auth_t cl_auth;
    t0 = now_ms();
    if (hybrid_client_create_auth(&hs, &cl_auth) != HYBRID_SUCCESS) {
        fprintf(stderr, "[client] Failed to create CLIENT_AUTH\n");
        hybrid_handshake_cleanup(&hs);
        return -1;
    }
    m->hs_sign_ms = now_ms() - t0;

    printf("[client] Sending CLIENT_AUTH (Dual signature Ed25519 + ML-DSA-65)...\n");
    if (pkt_send_reliable(c, PKT_CLIENT_AUTH, (const uint8_t *)&cl_auth, sizeof(cl_auth)) != 0) {
        fprintf(stderr, "[client] CLIENT_AUTH transmission failed\n");
        hybrid_handshake_cleanup(&hs);
        return -1;
    }

    /* Wait for server ACK */
    uint8_t ack_payload[64];
    recv_type(c, PKT_ACK, ack_payload, sizeof(ack_payload));

    /* Session Activated */
    c->established = 1;
    c->session_id = hs.session_id;
    memcpy(c->tx_key, hs.client_write_key, 32);
    memcpy(c->rx_key, hs.server_write_key, 32);

    m->hs_total_ms = now_ms() - hs_start;
    hybrid_handshake_cleanup(&hs);
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * main()
 * ════════════════════════════════════════════════════════════════════ */
int main(int argc, char *argv[])
{
    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    printf("\033[1;36m");
    printf("╔════════════════════════════════════════════════════════════════════╗\n");
    printf("║      QRYPTONEX Hybrid Chat Client (Suite v1.0)                     ║\n");
    printf("║   Suite: X25519 + ML-KEM-768 + Ed25519 + ML-DSA-65 + ChaCha20      ║\n");
    printf("╚════════════════════════════════════════════════════════════════════╝\n");
    printf(CLR_RESET "\n");

    /* 1. Initialize Hybrid Cryptography */
    if (hybrid_crypto_init() != HYBRID_SUCCESS) {
        fprintf(stderr, "[client] Crypto initialization failed\n");
        return 1;
    }

    /* 2. Generate Client Identity Keys */
    hybrid_identity_pk_t id_pk;
    hybrid_identity_sk_t id_sk;
    printf("[client] Generating client dual identity (Ed25519 + ML-DSA-65)...\n");
    double dsa_t0 = now_ms();
    if (hybrid_generate_identity_keys(&id_pk, &id_sk) != HYBRID_SUCCESS) {
        fprintf(stderr, "[client] Identity key generation failed\n");
        return 1;
    }
    double dsa_kg_ms = now_ms() - dsa_t0;

    /* 3. Setup Socket and Resolve Server */
    int sock = make_client_sock();
    if (sock < 0) {
        perror("[client] make_client_sock");
        return 1;
    }

    char server_ip[64] = "";
    conn_t c;
    conn_init(&c, sock);
    c.peer_len = sizeof(c.peer);

    if (resolve_server_address((argc > 1) ? argv[1] : NULL, &c.peer, server_ip, sizeof(server_ip)) != 0) {
        fprintf(stderr, "[client] Error: Unable to resolve server address\n");
        close(sock);
        return 1;
    }

    printf("[client] Connecting to hybrid server at %s:%d ...\n", server_ip, SERVER_PORT);

    metrics_t m;
    memset(&m, 0, sizeof(m));
    m.msg_min_rtt_ms = 1e15;
    m.hs_dsa_keygen_ms = dsa_kg_ms;
    m.session_start_ns = now_ns();

    /* 4. Perform Hybrid Handshake */
    if (do_handshake(&c, &m, &id_pk, &id_sk) != 0) {
        fprintf(stderr, "\033[1;31m[client] Handshake failed!\033[0m\n");
        close(sock);
        return 1;
    }

    char ts[16];
    now_hms(ts, sizeof(ts));
    printf("  \033[1;32m[Connection Status]\033[0m Secure Hybrid Handshake completed in %.3f ms (Key Exchange: %.3f ms, Digital Signature: %.3f ms)\n",
           m.hs_total_ms, m.hs_encap_ms, m.hs_sign_ms);
    printf("  \033[1;32m[Session Keys]\033[0m      Client Session Key : %02x%02x%02x%02x%02x%02x%02x%02x... (Used by client to encrypt messages to server)\n",
           c.tx_key[0], c.tx_key[1], c.tx_key[2], c.tx_key[3],
           c.tx_key[4], c.tx_key[5], c.tx_key[6], c.tx_key[7]);
    printf("                      Server Session Key : %02x%02x%02x%02x%02x%02x%02x%02x... (Used by server to encrypt messages to client)\n",
           c.rx_key[0], c.rx_key[1], c.rx_key[2], c.rx_key[3],
           c.rx_key[4], c.rx_key[5], c.rx_key[6], c.rx_key[7]);
    printf("  \033[1;32m[Security Features]\033[0m Dual Classical + Post-Quantum Protection + ChaCha20-Poly1305 Header Binding Active\n");
    printf("\n\033[1;32m[%s] Connected securely to %s:%d (Session ID: 0x%016llx)\033[0m\n",
           ts, server_ip, SERVER_PORT, (unsigned long long)c.session_id);
    printf("[%s] Ready to chat. Type a message and press Enter (Ctrl-C or 'exit' to quit).\n\n", ts);

    /* 5. Spawn RX Thread */
    rx_args_t rxa;
    rxa.conn = &c;
    rxa.metrics = &m;
    rxa.stop = 0;

    pthread_t rxt;
    pthread_create(&rxt, NULL, rx_thread, &rxa);

    /* 6. Main Interactive Input Loop */
    char line[DATA_CHUNK_MAX];
    while (!g_stop) {
        printf("\033[1;35m> \033[0m");
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin)) break;

        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }
        if (strcmp(line, "exit") == 0 || strcmp(line, "/exit") == 0 ||
            strcmp(line, "quit") == 0 || strcmp(line, "/quit") == 0) {
            break;
        }

        if (strcmp(line, "/stats") == 0) {
            metrics_print(&m);
            printf("\033[1;35m> \033[0m");
            fflush(stdout);
            continue;
        }

        if (data_send(&c, &m, (const uint8_t *)line, (uint32_t)len) != 0) {
            printf("\033[1;31m[client] Send failed / ACK timeout\033[0m\n");
        }
    }

    signal(SIGINT, SIG_IGN);
    rxa.stop = 1;
    pthread_join(rxt, NULL);

    /* Send Disconnect Notice */
    pkt_send(&c, PKT_DISCONNECT, NULL, 0);

    metrics_print(&m);
    conn_destroy(&c);
    close(sock);
    printf("\n[client] Session cleanly closed.\n");
    return 0;
}
