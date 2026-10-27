/*
 * classical/client.c — Classical IoT Secure Chat Client
 *
 * Classical IoT Cryptographic Suite:
 *   - Key Establishment:  X25519 ECDH (RFC 7748)
 *   - Digital Signatures: Ed25519 (RFC 8032)
 *   - AEAD Encryption:    AES-128-CCM (RFC 3610 / NIST SP 800-38C)
 *   - Digest:             SHA-256 (FIPS 180-4)
 *   - Key Derivation:     HKDF-SHA-256 (RFC 5869)
 *
 * 4-Way Handshake — Client Role:
 *  Phase 1  → CLIENT_HELLO : c_eph_pk (32) ‖ c_id_pk (32) ‖ c_nonce (16)
 *  Phase 2  ← SERVER_HELLO : s_id_pk (32) ‖ s_eph_pk (32) ‖ SID (8) ‖ s_nonce (16) ‖ srv_sig (64)
 *             Derive X25519 shared secret
 *  Phase 3  → CLIENT_AUTH  : Ed25519_sign(client_transcript) (64)
 *  Phase 4  → Session Active (AES-128-CCM directional encryption)
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
#include "crypto/trust_store.h"
#include "wrappers/kem_wrapper.h"
#include "wrappers/dsa_wrapper.h"
#include "wrappers/hash_wrapper.h"
#include "wrappers/kdf_wrapper.h"

/* Canonical transcript lengths */
#define SERVER_TRANSCRIPT_LEN (16 + 16 + SESSION_ID_BYTES + KEM_PK_BYTES + DSA_PK_BYTES + DSA_PK_BYTES + KEM_CT_BYTES)
#define CLIENT_TRANSCRIPT_LEN (SERVER_TRANSCRIPT_LEN + DSA_SIG_BYTES)

/* ── Key material ────────────────────────────────────────────────── */
typedef struct {
    uint8_t kem_pk[KEM_PK_BYTES];    /* Ephemeral X25519 PK */
    uint8_t kem_sk[KEM_SK_BYTES];    /* Ephemeral X25519 SK */
    uint8_t dsa_pk[DSA_PK_BYTES];    /* Identity Ed25519 PK */
    uint8_t dsa_sk[DSA_SK_BYTES];    /* Identity Ed25519 SK */
    double  kem_keygen_ms;
    double  dsa_keygen_ms;
} keygen_result_t;

static keygen_result_t g_keys;
static volatile int    g_stop = 0;
static void on_signal(int s) { (void)s; g_stop = 1; }

/* ── Recv helper (handshake only) ────────────────────────────────── */
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
        if (hdr.type == want_type) { send_ack(c, hdr.seq); return n; }
        if (hdr.type != PKT_ACK && hdr.type != PKT_DATA)
            send_ack(c, hdr.seq);
    }
}

/* ── RX thread ───────────────────────────────────────────────────── */
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
            printf("[client] Exit.\n");
            exit(0);
        }
        if (hdr.type != PKT_DATA) continue;
        if (n < 28) continue;

        /* Replay window pre-auth check */
        if (replay_window_check(&a->conn->replay_win, hdr.seq) != 0) {
            continue;
        }

        uint64_t recv_ns = now_ns();

        const uint8_t *nonce = raw;
        const uint8_t *tag   = raw + 12;
        const uint8_t *ct    = raw + 28;
        int ct_len = (int)n - 28;
        if (ct_len <= 0) continue;

        /* Reconstruct canonical wire header as AAD */
        pkt_hdr_t wire_hdr;
        wire_hdr.seq = htonl(hdr.seq);
        wire_hdr.type = hdr.type;
        wire_hdr.len = htons(hdr.len);
        wire_hdr.session_id = htobe64(hdr.session_id);

        /* Measure AES-128-CCM decrypt cost locally */
        double dec_t0  = now_ms();
        int pt_len = aead_decrypt(ct, ct_len, (const uint8_t *)&wire_hdr, PKT_HDR_BYTES,
                                  a->conn->rx_key, nonce, tag, pt);
        double dec_us  = (now_ms() - dec_t0) * 1000.0;

        if (pt_len <= 0) {
            fprintf(stderr, "\r[rx] AEAD auth failure (tampered ciphertext or header AAD)\n");
            continue;
        }

        /* Post-auth replay commit and ACK */
        replay_window_update(&a->conn->replay_win, hdr.seq);
        send_ack(a->conn, hdr.seq);

        if (pt_len < (int)sizeof(pt)) pt[pt_len] = '\0';
        while (pt_len > 0 && (pt[pt_len-1] == '\n' || pt[pt_len-1] == '\r'))
            pt[--pt_len] = '\0';

        char ts[16]; now_hms(ts, sizeof(ts));
        printf("\r\033[2K\033[1;36m[%s] Server:\033[0m %s\n", ts, pt);

        /* Update local metrics */
        a->metrics->bytes_recv        += (uint64_t)(PKT_HDR_BYTES + 28 + ct_len);
        a->metrics->total_decrypt_us  += dec_us;
        a->metrics->decrypt_count++;
        metrics_update_rtt(a->metrics, recv_ns);

        printf("\033[1;35m> \033[0m");
        fflush(stdout);
    }
    return NULL;
}

/* ════════════════════════════════════════════════════════════════════
 * do_handshake() — 4-Way Classical IoT Handshake (Client Role)
 * ════════════════════════════════════════════════════════════════════ */
static int do_handshake(conn_t *c, metrics_t *m, const keygen_result_t *k)
{
    double t0, t1;
    double hs_start = now_ms();

    uint8_t srv_dsa_pk[DSA_PK_BYTES];
    uint8_t srv_eph_pk[KEM_CT_BYTES];
    uint8_t shared_secret[KEM_SS_BYTES];
    uint8_t session_id[SESSION_ID_BYTES];
    uint8_t sig[DSA_SIG_BYTES];
    size_t  sig_len = 0;

    m->hs_kem_keygen_ms = k->kem_keygen_ms;
    m->hs_dsa_keygen_ms = k->dsa_keygen_ms;

    /* 1. Generate client random nonce */
    uint8_t c_nonce[16];
    if (RAND_bytes(c_nonce, 16) != 1) {
        fprintf(stderr, "[client] Nonce generation failed\n"); return -1;
    }

    /* Phase 1: Send CLIENT_HELLO
     * Layout: c_eph_pk(32) | c_id_pk(32) | c_nonce(16) = 80 bytes */
    uint8_t hello[KEM_PK_BYTES + DSA_PK_BYTES + 16];
    memcpy(hello,                            k->kem_pk, KEM_PK_BYTES);
    memcpy(hello + KEM_PK_BYTES,             k->dsa_pk, DSA_PK_BYTES);
    memcpy(hello + KEM_PK_BYTES + DSA_PK_BYTES, c_nonce, 16);

    if (pkt_send_reliable(c, PKT_CLIENT_HELLO, hello, (uint16_t)sizeof(hello)) != 0) {
        fprintf(stderr, "[client] CLIENT_HELLO send failed\n"); return -1;
    }

    /* Phase 2: Receive SERVER_HELLO
     * Layout: s_id_pk(32) | s_eph_pk(32) | sid(8) | s_nonce(16) | srv_sig(64) = 152 bytes */
    size_t srv_hello_min = DSA_PK_BYTES + KEM_CT_BYTES + SESSION_ID_BYTES + 16 + DSA_SIG_BYTES;
    uint8_t srv_hello[DSA_PK_BYTES + KEM_CT_BYTES + SESSION_ID_BYTES + 16 + DSA_SIG_BYTES + 128];
    ssize_t srv_len = recv_type(c, PKT_SERVER_HELLO, srv_hello, sizeof(srv_hello));
    if (srv_len < (ssize_t)srv_hello_min) {
        fprintf(stderr, "[client] SERVER_HELLO too short\n"); return -1;
    }

    uint8_t s_nonce[16];
    uint8_t srv_sig[DSA_SIG_BYTES];
    {
        size_t off = 0;
        memcpy(srv_dsa_pk, srv_hello + off, DSA_PK_BYTES);    off += DSA_PK_BYTES;
        memcpy(srv_eph_pk, srv_hello + off, KEM_CT_BYTES);    off += KEM_CT_BYTES;
        memcpy(session_id, srv_hello + off, SESSION_ID_BYTES); off += SESSION_ID_BYTES;
        memcpy(s_nonce,    srv_hello + off, 16);              off += 16;
        memcpy(srv_sig,    srv_hello + off, DSA_SIG_BYTES);
    }

    /* Verify server identity against trust store (pinned server Ed25519 identity) */
    if (trust_store_client_verify_server(srv_dsa_pk, "server_identity.pub") != 0) {
        fprintf(stderr, "\033[1;31m[client] CRITICAL: Server identity key NOT trusted! Possible MITM attack.\033[0m\n");
        return -1;
    }

    /* Reconstruct canonical server handshake transcript:
     * c_nonce(16) | s_nonce(16) | sid(8) | c_eph_pk(32) | c_id_pk(32) | srv_dsa_pk(32) | srv_eph_pk(32) */
    uint8_t tx[SERVER_TRANSCRIPT_LEN];
    size_t tx_off = 0;
    memcpy(tx + tx_off, c_nonce, 16); tx_off += 16;
    memcpy(tx + tx_off, s_nonce, 16); tx_off += 16;
    memcpy(tx + tx_off, session_id, SESSION_ID_BYTES); tx_off += SESSION_ID_BYTES;
    memcpy(tx + tx_off, k->kem_pk, KEM_PK_BYTES); tx_off += KEM_PK_BYTES;
    memcpy(tx + tx_off, k->dsa_pk, DSA_PK_BYTES); tx_off += DSA_PK_BYTES;
    memcpy(tx + tx_off, srv_dsa_pk, DSA_PK_BYTES); tx_off += DSA_PK_BYTES;
    memcpy(tx + tx_off, srv_eph_pk, KEM_CT_BYTES); tx_off += KEM_CT_BYTES;

    uint8_t server_tx_digest[SHA256_DIGEST_BYTES];
    if (sha256_digest(tx, tx_off, server_tx_digest) != 0) {
        return -1;
    }

    t0 = now_ms();
    if (ed25519_verify(srv_sig, DSA_SIG_BYTES, server_tx_digest, SHA256_DIGEST_BYTES, srv_dsa_pk) != 0) {
        fprintf(stderr, "[client] Server Ed25519 signature verification failed\n");
        return -1;
    }
    t1 = now_ms();
    m->hs_verify_ms = t1 - t0;

    /* Compute X25519 shared secret: ss = X25519(c_eph_sk, srv_eph_pk) */
    t0 = now_ms();
    if (x25519_derive_shared_secret(shared_secret, k->kem_sk, srv_eph_pk) != 0) {
        fprintf(stderr, "[client] X25519 shared secret derivation failed\n");
        return -1;
    }
    t1 = now_ms();
    m->hs_encap_ms = t1 - t0;

    uint64_t sid64 = 0;
    for (int i = 0; i < SESSION_ID_BYTES; i++) sid64 = (sid64 << 8) | session_id[i];

    /* Derive distinct directional traffic keys via HKDF-SHA-256 */
    kem_derive_directional_keys(c->tx_key, c->rx_key, shared_secret, c_nonce, s_nonce, sid64);

    /* Construct client transcript: server_transcript(168) | srv_sig(64) = 232 bytes */
    uint8_t cl_tx[CLIENT_TRANSCRIPT_LEN];
    memcpy(cl_tx, tx, SERVER_TRANSCRIPT_LEN);
    memcpy(cl_tx + SERVER_TRANSCRIPT_LEN, srv_sig, DSA_SIG_BYTES);

    uint8_t client_tx_digest[SHA256_DIGEST_BYTES];
    if (sha256_digest(cl_tx, CLIENT_TRANSCRIPT_LEN, client_tx_digest) != 0) {
        explicit_bzero(shared_secret, sizeof(shared_secret));
        return -1;
    }

    t0 = now_ms();
    if (ed25519_sign(sig, &sig_len, client_tx_digest, SHA256_DIGEST_BYTES, k->dsa_sk) != 0) {
        fprintf(stderr, "[client] Ed25519 sign failed\n");
        explicit_bzero(shared_secret, sizeof(shared_secret));
        return -1;
    }
    t1 = now_ms();
    m->hs_sign_ms = t1 - t0;

    /* Phase 3: Send CLIENT_AUTH (64 bytes Ed25519 signature) */
    if (pkt_send_reliable(c, PKT_CLIENT_AUTH, sig, (uint16_t)sig_len) != 0) {
        fprintf(stderr, "[client] CLIENT_AUTH send failed\n");
        explicit_bzero(shared_secret, sizeof(shared_secret));
        return -1;
    }

    /* Phase 4: Session Active */
    c->established = 1;
    explicit_bzero(shared_secret, sizeof(shared_secret));
    explicit_bzero(sig, sizeof(sig));

    c->session_id = sid64;
    m->hs_total_ms = now_ms() - hs_start;

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

    char server_ip[64] = "";

    int sock = make_client_sock();
    if (sock < 0) return 1;

    conn_t c;
    conn_init(&c, sock);
    c.peer_len = sizeof(c.peer);
    if (resolve_server_address((argc > 1) ? argv[1] : NULL, &c.peer, server_ip, sizeof(server_ip)) != 0) {
        fprintf(stderr, "[client] Error: Unable to resolve server address '%s'\n", (argc > 1) ? argv[1] : "auto");
        close(sock);
        return 1;
    }

    printf("\033[1;36m");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║   QRYPTONEX Secure Chat ─ Classical IoT Client           ║\n");
    printf("║   Suite: X25519 + Ed25519 + AES-128-CCM + SHA-256        ║\n");
    printf("║   Server Target: %-40s║\n", server_ip);
    printf("╚══════════════════════════════════════════════════════════╝\n");
    printf("\033[0m\n");

    /* Warmup primitives */
    kem_warmup();
    dsa_warmup();

    /* Generate ephemeral X25519 keypair and Ed25519 identity keypair */
    double t0 = now_ms();
    if (x25519_generate_keypair(g_keys.kem_pk, g_keys.kem_sk) != 0) {
        fprintf(stderr, "[client] X25519 keypair generation failed\n");
        close(sock);
        return 1;
    }
    g_keys.kem_keygen_ms = now_ms() - t0;

    t0 = now_ms();
    if (ed25519_generate_keypair(g_keys.dsa_pk, g_keys.dsa_sk) != 0) {
        fprintf(stderr, "[client] Ed25519 keypair generation failed\n");
        close(sock);
        return 1;
    }
    g_keys.dsa_keygen_ms = now_ms() - t0;

    printf("[client] Keygen completed: X25519=%.3fms  Ed25519=%.3fms\n",
           g_keys.kem_keygen_ms, g_keys.dsa_keygen_ms);
    printf("[client] Initiating 4-way mutual authentication handshake...\n");

    metrics_t metrics = {0};
    metrics.session_start_ns = now_ns();
    metrics.msg_min_rtt_ms = 1e15;

    if (do_handshake(&c, &metrics, &g_keys) != 0) {
        fprintf(stderr, "\033[1;31m[client] Handshake failed!\033[0m\n");
        close(sock);
        return 1;
    }

    /* Zeroize private keys no longer needed */
    explicit_bzero(g_keys.kem_sk, sizeof(g_keys.kem_sk));
    explicit_bzero(g_keys.dsa_sk, sizeof(g_keys.dsa_sk));

    printf("\033[1;32m✓ Session established in %.3f ms (SID=%016llx)\033[0m\n\n",
           metrics.hs_total_ms, (unsigned long long)c.session_id);
    printf("Type messages and press Enter. Ctrl+C to exit.\n\n");

    /* Spawn background RX thread */
    rx_args_t rx_args = { .conn = &c, .metrics = &metrics, .stop = 0 };
    pthread_t rx_tid;
    pthread_create(&rx_tid, NULL, rx_thread, &rx_args);

    /* TX main loop */
    char line[DATA_CHUNK_MAX];
    printf("\033[1;35m> \033[0m");
    fflush(stdout);

    while (!g_stop && fgets(line, sizeof(line), stdin)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';

        if (len == 0) {
            printf("\033[1;35m> \033[0m");
            fflush(stdout);
            continue;
        }

        if (strcmp(line, "/stats") == 0) {
            metrics_print(&metrics);
            printf("\033[1;35m> \033[0m");
            fflush(stdout);
            continue;
        }

        if (strcmp(line, "/quit") == 0 || strcmp(line, "/exit") == 0) {
            break;
        }

        /* Send authenticated encrypted packet via AES-128-CCM */
        if (data_send(&c, &metrics, (const uint8_t *)line, (uint32_t)len) != 0) {
            fprintf(stderr, "[client] data_send failed\n");
        }

        printf("\033[1;35m> \033[0m");
        fflush(stdout);
    }

    rx_args.stop = 1;
    pthread_cancel(rx_tid);
    pthread_join(rx_tid, NULL);

    /* Send disconnect */
    pkt_send(&c, PKT_DISCONNECT, NULL, 0);

    metrics_print(&metrics);
    conn_destroy(&c);
    close(sock);

    printf("\n[client] Goodbye.\n");
    return 0;
}
