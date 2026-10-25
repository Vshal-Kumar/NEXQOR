/*
 * client.c — PQC Chat Client  (multi-client server revision)
 *
 * Project: Performance Evaluation of SIMD-Accelerated Post-Quantum
 *          Cryptography on Embedded ARM Platforms
 *
 * 4-Way Handshake — Client Role (unchanged):
 *
 *  Phase 1  → CLIENT_HELLO : client_KEM_PK ‖ client_DSA_PK
 *  Phase 2  ← SERVER_HELLO : server_KEM_PK ‖ server_DSA_PK ‖ KEM_CT ‖ SID
 *             Decapsulate KEM_CT → shared secret
 *  Phase 3  → CLIENT_AUTH  : DSA_sign(SID ‖ srv_DSA_PK ‖ SS)
 *  Phase 4  → (session active)
 *
 * CHANGE vs previous client.c:
 *   PKT_DATA wire format simplified — net_metrics_t prefix REMOVED.
 *   New payload:  NONCE(12) | TAG(16) | CIPHERTEXT(n)
 *   All metrics tracked locally via timestamps; nothing sent in-packet.
 *
 * Everything else is unchanged:
 *   Parallel KEM+DSA keygen, warmup, handshake, RX thread, TX loop.
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

#include "transport.h"
#include "crypto/aead.h"
#include "crypto/trust_store.h"
#include "wrappers/kem_wrapper.h"
#include "wrappers/dsa_wrapper.h"

#include <openssl/rand.h>
#include <openssl/evp.h>

static int shake256_hash(uint8_t out[64], const uint8_t *in, size_t in_len) {
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) return -1;
  if (EVP_DigestInit_ex(ctx, EVP_shake256(), NULL) != 1) {
    EVP_MD_CTX_free(ctx);
    return -1;
  }
  if (EVP_DigestUpdate(ctx, in, in_len) != 1) {
    EVP_MD_CTX_free(ctx);
    return -1;
  }
  if (EVP_DigestFinalXOF(ctx, out, 64) != 1) {
    EVP_MD_CTX_free(ctx);
    return -1;
  }
  EVP_MD_CTX_free(ctx);
  return 0;
}

/* ── Auth context ────────────────────────────────────────────────── */
#define AUTH_CTX_LEN  (SESSION_ID_BYTES + DSA_PK_BYTES + KEM_SS_BYTES)

/* ── Key material ────────────────────────────────────────────────── */
typedef struct {
    uint8_t kem_pk[KEM_PK_BYTES];
    uint8_t kem_sk[KEM_SK_BYTES];
    uint8_t dsa_pk[DSA_PK_BYTES];
    uint8_t dsa_sk[DSA_SK_BYTES];
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
        /*
         * Clean wire format: NONCE(12) | TAG(16) | CIPHERTEXT(n)
         * No net_metrics_t prefix — 56 bytes less overhead per packet.
         */
        uint8_t raw[12 + 16 + DATA_CHUNK_MAX + 64];
        ssize_t n = pkt_recv(a->conn, &hdr, raw, sizeof(raw),
                             RX_POLL_TIMEOUT_US);
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
        if (n < 28) continue;    /* need at least NONCE+TAG */

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

        /* Construct canonical wire header as AAD */
        pkt_hdr_t wire_hdr;
        wire_hdr.seq = htonl(hdr.seq);
        wire_hdr.type = hdr.type;
        wire_hdr.len = htons(hdr.len);
        wire_hdr.session_id = htobe64(hdr.session_id);

        /* Measure decrypt cost locally */
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

/* ════════════════════════════════════════════════════════════════
 * do_handshake() — 4-way PQC handshake, client side (unchanged)
 * ════════════════════════════════════════════════════════════════ */
static int do_handshake(conn_t *c, metrics_t *m,
                        const keygen_result_t *k)
{
    double t0, t1;
    double hs_start = now_ms();

    uint8_t srv_dsa_pk[DSA_PK_BYTES];
    uint8_t kem_ct[KEM_CT_BYTES];
    uint8_t shared_secret[KEM_SS_BYTES];
    uint8_t session_id[SESSION_ID_BYTES];
    uint8_t sig[DSA_SIG_BYTES];
    size_t  sig_len = 0;

    m->hs_kem_keygen_ms = k->kem_keygen_ms;
    m->hs_dsa_keygen_ms = k->dsa_keygen_ms;

    /* Generate client nonce */
    uint8_t c_nonce[16];
    if (RAND_bytes(c_nonce, 16) != 1) {
        fprintf(stderr, "[client] Nonce generation failed\n"); return -1;
    }

    /* Phase 1: Send CLIENT_HELLO */
    uint8_t hello[KEM_PK_BYTES + DSA_PK_BYTES + 16];
    memcpy(hello,              k->kem_pk, KEM_PK_BYTES);
    memcpy(hello + KEM_PK_BYTES, k->dsa_pk, DSA_PK_BYTES);
    memcpy(hello + KEM_PK_BYTES + DSA_PK_BYTES, c_nonce, 16);
    if (pkt_send_reliable(c, PKT_CLIENT_HELLO, hello, (uint16_t)sizeof(hello)) != 0) {
        fprintf(stderr, "[client] CLIENT_HELLO send failed\n"); return -1;
    }

    /* Phase 2: Receive SERVER_HELLO */
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
        memcpy(kem_ct,     srv_hello + off, KEM_CT_BYTES);    off += KEM_CT_BYTES;
        memcpy(session_id, srv_hello + off, SESSION_ID_BYTES); off += SESSION_ID_BYTES;
        memcpy(s_nonce,    srv_hello + off, 16);              off += 16;
        memcpy(srv_sig,    srv_hello + off, DSA_SIG_BYTES);
    }

    /* Verify server identity against trust store (pins server DSA public key) */
    if (trust_store_client_verify_server(srv_dsa_pk, "server_identity.pub") != 0) {
        fprintf(stderr, "\033[1;31m[client] CRITICAL: Server public key NOT trusted! Possible MITM attack.\033[0m\n");
        return -1;
    }

    /* Reconstruct and verify server signature */
    size_t tx_len = 16 + 16 + SESSION_ID_BYTES + KEM_PK_BYTES + DSA_PK_BYTES + DSA_PK_BYTES + KEM_CT_BYTES;
    uint8_t *tx = malloc(tx_len);
    if (!tx) return -1;
    size_t tx_off = 0;
    memcpy(tx + tx_off, c_nonce, 16); tx_off += 16;
    memcpy(tx + tx_off, s_nonce, 16); tx_off += 16;
    memcpy(tx + tx_off, session_id, SESSION_ID_BYTES); tx_off += SESSION_ID_BYTES;
    memcpy(tx + tx_off, k->kem_pk, KEM_PK_BYTES); tx_off += KEM_PK_BYTES;
    memcpy(tx + tx_off, k->dsa_pk, DSA_PK_BYTES); tx_off += DSA_PK_BYTES;
    memcpy(tx + tx_off, srv_dsa_pk, DSA_PK_BYTES); tx_off += DSA_PK_BYTES;
    memcpy(tx + tx_off, kem_ct, KEM_CT_BYTES);

    uint8_t server_tx_digest[64];
    if (shake256_hash(server_tx_digest, tx, tx_len) != 0) {
        free(tx);
        return -1;
    }

    t0 = now_ms();
    if (dsa_verify(srv_sig, DSA_SIG_BYTES, server_tx_digest, 64, srv_dsa_pk) != 0) {
        fprintf(stderr, "[client] Server signature verification failed\n");
        free(tx);
        return -1;
    }

    /* KEM decapsulate */
    t0 = now_ms();
    if (kem_dec(shared_secret, kem_ct, k->kem_sk) != 0) {
        fprintf(stderr, "[client] KEM decaps failed\n"); free(tx); return -1;
    }
    t1 = now_ms();
    m->hs_encap_ms = t1 - t0;

    uint64_t sid64 = 0;
    for (int i = 0; i < SESSION_ID_BYTES; i++) sid64 = (sid64 << 8) | session_id[i];

    /* Derive distinct directional keys: client_write_key (tx_key) and server_write_key (rx_key) */
    kem_derive_directional_keys(c->tx_key, c->rx_key, shared_secret, c_nonce, s_nonce, sid64);

    /* DSA sign client transcript */
    size_t cl_tx_len = tx_len + DSA_SIG_BYTES;
    uint8_t *cl_tx = malloc(cl_tx_len);
    if (!cl_tx) {
        free(tx);
        return -1;
    }
    memcpy(cl_tx, tx, tx_len);
    memcpy(cl_tx + tx_len, srv_sig, DSA_SIG_BYTES);
    free(tx);

    uint8_t client_tx_digest[64];
    if (shake256_hash(client_tx_digest, cl_tx, cl_tx_len) != 0) {
        free(cl_tx);
        return -1;
    }
    free(cl_tx);

    t0 = now_ms();
    if (dsa_sign(sig, &sig_len, client_tx_digest, 64, k->dsa_sk) != 0) {
        fprintf(stderr, "[client] DSA sign failed\n");
        explicit_bzero(shared_secret, sizeof(shared_secret));
        return -1;
    }
    t1 = now_ms();
    m->hs_sign_ms = t1 - t0;

    /* Phase 3: Send CLIENT_AUTH */
    if (pkt_send_reliable(c, PKT_CLIENT_AUTH, sig, (uint16_t)sig_len) != 0) {
        fprintf(stderr, "[client] CLIENT_AUTH send failed\n");
        explicit_bzero(shared_secret, sizeof(shared_secret));
        return -1;
    }

    /* Phase 4: session active */
    c->established = 1;
    explicit_bzero(shared_secret, sizeof(shared_secret));
    explicit_bzero(sig, sizeof(sig));

    c->session_id = sid64;
    m->hs_total_ms = now_ms() - hs_start;

    return 0;
}

/* ════════════════════════════════════════════════════════════════
 * main()
 * ════════════════════════════════════════════════════════════════ */
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
    printf("  Server target : %s:%d\n", server_ip, SERVER_PORT);

    /* Serial KEM + DSA key generation */
    kem_warmup();
    dsa_warmup();
    memset(&g_keys, 0, sizeof(g_keys));

    double t0 = now_ms();
    if (kem_keypair(g_keys.kem_pk, g_keys.kem_sk) != 0) {
        fprintf(stderr, "[client] KEM keygen failed\n");
        close(sock);
        return 1;
    }
    g_keys.kem_keygen_ms = now_ms() - t0;

    t0 = now_ms();
    if (dsa_keypair(g_keys.dsa_pk, g_keys.dsa_sk) != 0) {
        fprintf(stderr, "[client] DSA keygen failed\n");
        close(sock);
        return 1;
    }
    g_keys.dsa_keygen_ms = now_ms() - t0;

    /* Serial Handshake */
    metrics_t metrics = {0};
    metrics.msg_min_rtt_ms = 1e15;

    if (do_handshake(&c, &metrics, &g_keys) != 0) {
        fprintf(stderr, "[client] Handshake failed\n");
        close(sock); return 1;
    }

    explicit_bzero(g_keys.kem_sk, sizeof(g_keys.kem_sk));
    explicit_bzero(g_keys.dsa_sk, sizeof(g_keys.dsa_sk));

    char ts[16];
    now_hms(ts, sizeof(ts));
    printf("[%s] Connected to %s:%d (Session ID: %016llx)\n",
           ts, server_ip, SERVER_PORT, (unsigned long long)c.session_id);
    printf("[%s] Ready to chat. Type a message and press Enter (Ctrl-C to exit).\n", ts);

    metrics.session_start_ns = now_ns();

    /* Start RX thread */
    rx_args_t rx_args = { .conn = &c, .metrics = &metrics, .stop = 0 };
    pthread_t rx_tid;
    pthread_create(&rx_tid, NULL, rx_thread, &rx_args);

    /* TX loop */
    printf("\033[1;35m> \033[0m");
    fflush(stdout);

    char line[DATA_CHUNK_MAX];
    while (!g_stop && fgets(line, sizeof(line), stdin)) {
        size_t len = strlen(line);
        if (len == 0 || (len == 1 && (line[0] == '\n' || line[0] == '\r'))) {
            printf("\033[1;35m> \033[0m");
            fflush(stdout);
            continue;
        }

        if (data_send(&c, &metrics, (const uint8_t *)line, (uint32_t)len) != 0) {
            fprintf(stderr, "[client] send failed\n");
        }

        printf("\033[1;35m> \033[0m");
        fflush(stdout);
    }

    rx_args.stop = 1;
    pthread_join(rx_tid, NULL);

    pkt_send(&c, PKT_DISCONNECT, NULL, 0);
    close(sock);
    conn_destroy(&c);
    printf("\n[client] Disconnected.\n");
    return 0;
}
