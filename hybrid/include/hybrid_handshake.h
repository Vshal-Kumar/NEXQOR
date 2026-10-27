/*
 * hybrid/include/hybrid_handshake.h
 *
 * Mutual-Authentication Hybrid Handshake Protocol State Machine.
 */

#ifndef HYBRID_HANDSHAKE_H
#define HYBRID_HANDSHAKE_H

#include <stdint.h>
#include <stddef.h>
#include "hybrid_crypto.h"
#include "hybrid_kex.h"
#include "hybrid_signature.h"
#include "hybrid_kdf.h"
#include "hybrid_errors.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Handshake State Machine ──────────────────────────────────────── */
typedef enum {
    HYBRID_STATE_INIT = 0,
    HYBRID_STATE_CLIENT_HELLO_SENT,
    HYBRID_STATE_CLIENT_HELLO_RECV,
    HYBRID_STATE_SERVER_HELLO_SENT,
    HYBRID_STATE_SERVER_HELLO_RECV,
    HYBRID_STATE_KEY_ESTABLISHED,
    HYBRID_STATE_CLIENT_AUTH_SENT,
    HYBRID_STATE_CLIENT_AUTH_RECV,
    HYBRID_STATE_AUTHENTICATED,
    HYBRID_STATE_ESTABLISHED,
    HYBRID_STATE_FAILED,
    HYBRID_STATE_CLOSED
} hybrid_state_t;

typedef enum {
    HYBRID_ROLE_CLIENT = 1,
    HYBRID_ROLE_SERVER = 2
} hybrid_role_t;

/* Handshake Message Identifiers */
#define HYBRID_MSG_CLIENT_HELLO 0x01
#define HYBRID_MSG_SERVER_HELLO 0x02
#define HYBRID_MSG_CLIENT_AUTH  0x03

/* ── Wire Message Definitions ─────────────────────────────────────── */

/*
 * CLIENT_HELLO (Total: 3283 bytes):
 * Offered version, cipher suite, fresh client nonce,
 * ephemeral public keys (X25519 + ML-KEM-768), and
 * client identity public keys (Ed25519 + ML-DSA-65).
 */
typedef struct __attribute__((packed)) {
    uint16_t version;                                          /* 0x0100 */
    uint16_t suite_id_len;                                     /* 49 */
    char     suite_id[HYBRID_SUITE_ID_LEN];
    uint8_t  client_nonce[HYBRID_SESSION_NONCE_BYTES];         /* 32 bytes */
    uint8_t  client_eph_x25519_pk[HYBRID_X25519_PK_BYTES];     /* 32 bytes */
    uint8_t  client_eph_mlkem_pk[HYBRID_MLKEM768_PK_BYTES];    /* 1184 bytes */
    uint8_t  client_id_ed25519_pk[HYBRID_ED25519_PK_BYTES];    /* 32 bytes */
    uint8_t  client_id_mldsa_pk[HYBRID_MLDSA65_PK_BYTES];      /* 1952 bytes */
} hybrid_msg_client_hello_t;

#define HYBRID_CLIENT_HELLO_WIRE_BYTES sizeof(hybrid_msg_client_hello_t)

/*
 * SERVER_HELLO (Total: 6539 bytes):
 * Negotiated version, cipher suite, fresh server nonce, session ID,
 * server ephemeral X25519 public key, ML-KEM-768 ciphertext,
 * server identity public keys, and dual signature over Server Transcript.
 */
typedef struct __attribute__((packed)) {
    uint16_t version;                                          /* 0x0100 */
    uint16_t suite_id_len;                                     /* 49 */
    char     suite_id[HYBRID_SUITE_ID_LEN];
    uint8_t  server_nonce[HYBRID_SESSION_NONCE_BYTES];         /* 32 bytes */
    uint64_t session_id;                                       /* 8 bytes */
    uint8_t  server_eph_x25519_pk[HYBRID_X25519_PK_BYTES];     /* 32 bytes */
    uint8_t  server_mlkem_ct[HYBRID_MLKEM768_CT_BYTES];        /* 1088 bytes */
    uint8_t  server_id_ed25519_pk[HYBRID_ED25519_PK_BYTES];    /* 32 bytes */
    uint8_t  server_id_mldsa_pk[HYBRID_MLDSA65_PK_BYTES];      /* 1952 bytes */
    uint8_t  server_sig[HYBRID_SIG_WIRE_BYTES];                /* 3378 bytes */
} hybrid_msg_server_hello_t;

#define HYBRID_SERVER_HELLO_WIRE_BYTES sizeof(hybrid_msg_server_hello_t)

/*
 * CLIENT_AUTH (Total: 3386 bytes):
 * Session ID and dual signature over Client Transcript.
 */
typedef struct __attribute__((packed)) {
    uint64_t session_id;                                       /* 8 bytes */
    uint8_t  client_sig[HYBRID_SIG_WIRE_BYTES];                /* 3378 bytes */
} hybrid_msg_client_auth_t;

#define HYBRID_CLIENT_AUTH_WIRE_BYTES sizeof(hybrid_msg_client_auth_t)

/* ── Handshake Protocol Context ───────────────────────────────────── */
typedef struct {
    hybrid_role_t            role;
    hybrid_state_t           state;
    uint16_t                 negotiated_version;
    uint64_t                 session_id;

    /* Nonces */
    uint8_t                  client_nonce[HYBRID_SESSION_NONCE_BYTES];
    uint8_t                  server_nonce[HYBRID_SESSION_NONCE_BYTES];

    /* Identity keys */
    hybrid_identity_pk_t     our_id_pk;
    hybrid_identity_sk_t     our_id_sk;
    hybrid_identity_pk_t     peer_id_pk;

    /* Ephemeral key agreement state */
    hybrid_kex_public_key_t  our_eph_pk;
    hybrid_kex_secret_key_t  our_eph_sk;
    hybrid_kex_public_key_t  peer_eph_pk;
    hybrid_kex_ciphertext_t  kex_ct;

    /* Wire copies of signatures */
    uint8_t                  server_sig_wire[HYBRID_SIG_WIRE_BYTES];
    uint8_t                  client_sig_wire[HYBRID_SIG_WIRE_BYTES];

    /* Canonical transcript digests */
    uint8_t                  server_transcript_digest[HYBRID_SHA384_DIGEST_BYTES];
    uint8_t                  client_transcript_digest[HYBRID_SHA384_DIGEST_BYTES];

    /* Hybrid secrets */
    uint8_t                  combined_ikm[HYBRID_IKM_BYTES];
    uint8_t                  client_write_key[HYBRID_TRAFFIC_KEY_BYTES];
    uint8_t                  server_write_key[HYBRID_TRAFFIC_KEY_BYTES];

    int                      established;
} hybrid_handshake_ctx_t;

/* ── Lifecycle & API ──────────────────────────────────────────────── */

int hybrid_handshake_init(hybrid_handshake_ctx_t *ctx,
                          hybrid_role_t role,
                          const hybrid_identity_pk_t *our_id_pk,
                          const hybrid_identity_sk_t *our_id_sk);

void hybrid_handshake_cleanup(hybrid_handshake_ctx_t *ctx);

/* ── Client Phase Procedures ──────────────────────────────────────── */

int hybrid_client_create_hello(hybrid_handshake_ctx_t *ctx,
                               hybrid_msg_client_hello_t *msg);

int hybrid_client_process_server_hello(hybrid_handshake_ctx_t *ctx,
                                       const hybrid_msg_server_hello_t *msg,
                                       const char *pinned_server_pub_path);

int hybrid_client_create_auth(hybrid_handshake_ctx_t *ctx,
                              hybrid_msg_client_auth_t *msg);

/* ── Server Phase Procedures ──────────────────────────────────────── */

int hybrid_server_process_client_hello(hybrid_handshake_ctx_t *ctx,
                                       const hybrid_msg_client_hello_t *msg,
                                       const char *client_trust_db_path);

int hybrid_server_create_hello(hybrid_handshake_ctx_t *ctx,
                               hybrid_msg_server_hello_t *msg);

int hybrid_server_process_client_auth(hybrid_handshake_ctx_t *ctx,
                                      const hybrid_msg_client_auth_t *msg);

/* ── Transcript Digest Construction ───────────────────────────────── */

int hybrid_compute_server_transcript_digest(const hybrid_handshake_ctx_t *ctx,
                                            uint8_t digest[HYBRID_SHA384_DIGEST_BYTES]);

int hybrid_compute_client_transcript_digest(const hybrid_handshake_ctx_t *ctx,
                                            const uint8_t server_sig[HYBRID_SIG_WIRE_BYTES],
                                            uint8_t digest[HYBRID_SHA384_DIGEST_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* HYBRID_HANDSHAKE_H */
