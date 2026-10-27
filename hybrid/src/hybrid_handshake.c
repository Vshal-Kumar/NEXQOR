/*
 * hybrid/src/hybrid_handshake.c
 *
 * Mutual-Authentication Hybrid Handshake Protocol Implementation.
 */

#include "hybrid_handshake.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/rand.h>

#define HYBRID_LABEL_TRANSCRIPT_SERVER "QRYPTONEX-HYBRID-TRANSCRIPT-v1-SERVER"
#define HYBRID_LABEL_TRANSCRIPT_CLIENT "QRYPTONEX-HYBRID-TRANSCRIPT-v1-CLIENT"

int hybrid_handshake_init(hybrid_handshake_ctx_t *ctx,
                          hybrid_role_t role,
                          const hybrid_identity_pk_t *our_id_pk,
                          const hybrid_identity_sk_t *our_id_sk) {
    if (!ctx || !our_id_pk || !our_id_sk) {
        return HYBRID_ERR_INVALID_ARG;
    }
    memset(ctx, 0, sizeof(hybrid_handshake_ctx_t));
    ctx->role = role;
    ctx->state = HYBRID_STATE_INIT;
    ctx->negotiated_version = HYBRID_PROTOCOL_VERSION;

    memcpy(&ctx->our_id_pk, our_id_pk, sizeof(hybrid_identity_pk_t));
    memcpy(&ctx->our_id_sk, our_id_sk, sizeof(hybrid_identity_sk_t));

    return HYBRID_SUCCESS;
}

void hybrid_handshake_cleanup(hybrid_handshake_ctx_t *ctx) {
    if (!ctx) return;
    hybrid_cleanse(&ctx->our_id_sk, sizeof(hybrid_identity_sk_t));
    hybrid_cleanse(&ctx->our_eph_sk, sizeof(hybrid_kex_secret_key_t));
    hybrid_cleanse(ctx->combined_ikm, sizeof(ctx->combined_ikm));
    hybrid_cleanse(ctx->client_write_key, sizeof(ctx->client_write_key));
    hybrid_cleanse(ctx->server_write_key, sizeof(ctx->server_write_key));
    ctx->state = HYBRID_STATE_CLOSED;
    ctx->established = 0;
}

/* ── Transcript Construction ──────────────────────────────────────── */

int hybrid_compute_server_transcript_digest(const hybrid_handshake_ctx_t *ctx,
                                            uint8_t digest[HYBRID_SHA384_DIGEST_BYTES]) {
    if (!ctx || !digest) return HYBRID_ERR_INVALID_ARG;

    hybrid_sha384_ctx_t hctx;
    int rc = hybrid_sha384_init(&hctx);
    if (rc != HYBRID_SUCCESS) return rc;

    uint16_t ver_be = htobe16(ctx->negotiated_version);
    uint16_t suite_len_be = htobe16(HYBRID_SUITE_ID_LEN);
    uint64_t sid_be = htobe64(ctx->session_id);

    /* Chronological binding of all handshake parameters */
    hybrid_sha384_update(&hctx, HYBRID_LABEL_TRANSCRIPT_SERVER, sizeof(HYBRID_LABEL_TRANSCRIPT_SERVER) - 1);
    hybrid_sha384_update(&hctx, &ver_be, 2);
    hybrid_sha384_update(&hctx, &suite_len_be, 2);
    hybrid_sha384_update(&hctx, HYBRID_SUITE_ID, HYBRID_SUITE_ID_LEN);
    hybrid_sha384_update(&hctx, ctx->client_nonce, HYBRID_SESSION_NONCE_BYTES);
    hybrid_sha384_update(&hctx, ctx->server_nonce, HYBRID_SESSION_NONCE_BYTES);
    hybrid_sha384_update(&hctx, &sid_be, 8);

    if (ctx->role == HYBRID_ROLE_CLIENT) {
        hybrid_sha384_update(&hctx, ctx->our_eph_pk.x25519_pk, HYBRID_X25519_PK_BYTES);
        hybrid_sha384_update(&hctx, ctx->our_eph_pk.mlkem_pk, HYBRID_MLKEM768_PK_BYTES);
        hybrid_sha384_update(&hctx, ctx->kex_ct.x25519_pk, HYBRID_X25519_PK_BYTES);
        hybrid_sha384_update(&hctx, ctx->kex_ct.mlkem_ct, HYBRID_MLKEM768_CT_BYTES);
        hybrid_sha384_update(&hctx, ctx->our_id_pk.ed25519_pk, HYBRID_ED25519_PK_BYTES);
        hybrid_sha384_update(&hctx, ctx->our_id_pk.mldsa_pk, HYBRID_MLDSA65_PK_BYTES);
        hybrid_sha384_update(&hctx, ctx->peer_id_pk.ed25519_pk, HYBRID_ED25519_PK_BYTES);
        hybrid_sha384_update(&hctx, ctx->peer_id_pk.mldsa_pk, HYBRID_MLDSA65_PK_BYTES);
    } else {
        hybrid_sha384_update(&hctx, ctx->peer_eph_pk.x25519_pk, HYBRID_X25519_PK_BYTES);
        hybrid_sha384_update(&hctx, ctx->peer_eph_pk.mlkem_pk, HYBRID_MLKEM768_PK_BYTES);
        hybrid_sha384_update(&hctx, ctx->kex_ct.x25519_pk, HYBRID_X25519_PK_BYTES);
        hybrid_sha384_update(&hctx, ctx->kex_ct.mlkem_ct, HYBRID_MLKEM768_CT_BYTES);
        hybrid_sha384_update(&hctx, ctx->peer_id_pk.ed25519_pk, HYBRID_ED25519_PK_BYTES);
        hybrid_sha384_update(&hctx, ctx->peer_id_pk.mldsa_pk, HYBRID_MLDSA65_PK_BYTES);
        hybrid_sha384_update(&hctx, ctx->our_id_pk.ed25519_pk, HYBRID_ED25519_PK_BYTES);
        hybrid_sha384_update(&hctx, ctx->our_id_pk.mldsa_pk, HYBRID_MLDSA65_PK_BYTES);
    }

    return hybrid_sha384_final(&hctx, digest);
}

int hybrid_compute_client_transcript_digest(const hybrid_handshake_ctx_t *ctx,
                                            const uint8_t server_sig[HYBRID_SIG_WIRE_BYTES],
                                            uint8_t digest[HYBRID_SHA384_DIGEST_BYTES]) {
    if (!ctx || !server_sig || !digest) return HYBRID_ERR_INVALID_ARG;

    hybrid_sha384_ctx_t hctx;
    int rc = hybrid_sha384_init(&hctx);
    if (rc != HYBRID_SUCCESS) return rc;

    hybrid_sha384_update(&hctx, HYBRID_LABEL_TRANSCRIPT_CLIENT, sizeof(HYBRID_LABEL_TRANSCRIPT_CLIENT) - 1);
    hybrid_sha384_update(&hctx, ctx->server_transcript_digest, HYBRID_SHA384_DIGEST_BYTES);
    hybrid_sha384_update(&hctx, server_sig, HYBRID_SIG_WIRE_BYTES);

    return hybrid_sha384_final(&hctx, digest);
}

/* ── Client State Machine Handlers ────────────────────────────────── */

int hybrid_client_create_hello(hybrid_handshake_ctx_t *ctx,
                               hybrid_msg_client_hello_t *msg) {
    if (!ctx || !msg) return HYBRID_ERR_INVALID_ARG;
    if (ctx->role != HYBRID_ROLE_CLIENT || ctx->state != HYBRID_STATE_INIT) {
        return HYBRID_ERR_INVALID_STATE;
    }

    /* 1. Protocol version and suite negotiation */
    msg->version = htobe16(HYBRID_PROTOCOL_VERSION);
    msg->suite_id_len = htobe16(HYBRID_SUITE_ID_LEN);
    memcpy(msg->suite_id, HYBRID_SUITE_ID, HYBRID_SUITE_ID_LEN);

    /* 2. Fresh 32-byte client nonce */
    if (RAND_bytes(ctx->client_nonce, HYBRID_SESSION_NONCE_BYTES) != 1) {
        return HYBRID_ERR_CRYPTO_FAIL;
    }
    memcpy(msg->client_nonce, ctx->client_nonce, HYBRID_SESSION_NONCE_BYTES);

    /* 3. Ephemeral hybrid keypair generation (X25519 + ML-KEM-768) */
    int rc = hybrid_kex_generate_keypair(&ctx->our_eph_pk, &ctx->our_eph_sk);
    if (rc != HYBRID_SUCCESS) return rc;

    memcpy(msg->client_eph_x25519_pk, ctx->our_eph_pk.x25519_pk, HYBRID_X25519_PK_BYTES);
    memcpy(msg->client_eph_mlkem_pk, ctx->our_eph_pk.mlkem_pk, HYBRID_MLKEM768_PK_BYTES);

    /* 4. Client identity public keys (Ed25519 + ML-DSA-65) */
    memcpy(msg->client_id_ed25519_pk, ctx->our_id_pk.ed25519_pk, HYBRID_ED25519_PK_BYTES);
    memcpy(msg->client_id_mldsa_pk, ctx->our_id_pk.mldsa_pk, HYBRID_MLDSA65_PK_BYTES);

    ctx->state = HYBRID_STATE_CLIENT_HELLO_SENT;
    return HYBRID_SUCCESS;
}

int hybrid_client_process_server_hello(hybrid_handshake_ctx_t *ctx,
                                       const hybrid_msg_server_hello_t *msg,
                                       const char *pinned_server_pub_path) {
    if (!ctx || !msg) return HYBRID_ERR_INVALID_ARG;
    if (ctx->role != HYBRID_ROLE_CLIENT || ctx->state != HYBRID_STATE_CLIENT_HELLO_SENT) {
        return HYBRID_ERR_INVALID_STATE;
    }

    /* 1. Validate version and prevent downgrade attack */
    if (be16toh(msg->version) != HYBRID_PROTOCOL_VERSION) {
        ctx->state = HYBRID_STATE_FAILED;
        return HYBRID_ERR_VERSION_UNSUPPORTED;
    }

    /* 2. Validate cipher suite ID */
    if (be16toh(msg->suite_id_len) != HYBRID_SUITE_ID_LEN ||
        memcmp(msg->suite_id, HYBRID_SUITE_ID, HYBRID_SUITE_ID_LEN) != 0) {
        ctx->state = HYBRID_STATE_FAILED;
        return HYBRID_ERR_DOWNGRADE_DETECTED;
    }

    /* 3. Extract server response fields */
    memcpy(ctx->server_nonce, msg->server_nonce, HYBRID_SESSION_NONCE_BYTES);
    ctx->session_id = be64toh(msg->session_id);

    memcpy(ctx->kex_ct.x25519_pk, msg->server_eph_x25519_pk, HYBRID_X25519_PK_BYTES);
    memcpy(ctx->kex_ct.mlkem_ct, msg->server_mlkem_ct, HYBRID_MLKEM768_CT_BYTES);

    memcpy(ctx->peer_id_pk.ed25519_pk, msg->server_id_ed25519_pk, HYBRID_ED25519_PK_BYTES);
    memcpy(ctx->peer_id_pk.mldsa_pk, msg->server_id_mldsa_pk, HYBRID_MLDSA65_PK_BYTES);
    memcpy(ctx->server_sig_wire, msg->server_sig, HYBRID_SIG_WIRE_BYTES);

    /* 4. Trust Store: Verify server identity against pinned store if specified */
    if (pinned_server_pub_path) {
        int fd = open(pinned_server_pub_path, O_RDONLY);
        if (fd >= 0) {
            uint8_t pin_buf[sizeof(hybrid_identity_pk_t)];
            ssize_t r = read(fd, pin_buf, sizeof(pin_buf));
            close(fd);
            if (r == sizeof(hybrid_identity_pk_t)) {
                /* Full dual identity pinned */
                if (memcmp(pin_buf, &ctx->peer_id_pk, sizeof(hybrid_identity_pk_t)) != 0) {
                    ctx->state = HYBRID_STATE_FAILED;
                    return HYBRID_ERR_UNTRUSTED_PEER;
                }
            } else if (r == HYBRID_MLDSA65_PK_BYTES) {
                /* ML-DSA-65 only pinned */
                if (memcmp(pin_buf, ctx->peer_id_pk.mldsa_pk, HYBRID_MLDSA65_PK_BYTES) != 0) {
                    ctx->state = HYBRID_STATE_FAILED;
                    return HYBRID_ERR_UNTRUSTED_PEER;
                }
            }
        }
    }

    /* 5. Compute canonical Server Transcript digest */
    int rc = hybrid_compute_server_transcript_digest(ctx, ctx->server_transcript_digest);
    if (rc != HYBRID_SUCCESS) {
        ctx->state = HYBRID_STATE_FAILED;
        return rc;
    }

    /* 6. Verify Server Dual Signatures (Ed25519 + ML-DSA-65) over the transcript digest */
    hybrid_signature_t srv_sig;
    rc = hybrid_signature_deserialize(&srv_sig, msg->server_sig, HYBRID_SIG_WIRE_BYTES);
    if (rc != HYBRID_SUCCESS) {
        ctx->state = HYBRID_STATE_FAILED;
        return rc;
    }

    rc = hybrid_verify_transcript(&srv_sig, ctx->server_transcript_digest, &ctx->peer_id_pk);
    if (rc != HYBRID_SUCCESS) {
        ctx->state = HYBRID_STATE_FAILED;
        return HYBRID_ERR_SIG_VERIFY_FAIL;
    }

    /* 7. Decapsulate hybrid secrets: recover ss_x25519 and ss_mlkem */
    rc = hybrid_kex_decapsulate(ctx->combined_ikm, &ctx->kex_ct, &ctx->our_eph_sk);
    if (rc != HYBRID_SUCCESS) {
        ctx->state = HYBRID_STATE_FAILED;
        return rc;
    }

    /* 8. Derive directional traffic keys via HKDF-SHA-384 bound to transcript hash */
    rc = hybrid_kdf_derive_traffic_keys(ctx->client_write_key, ctx->server_write_key,
                                        ctx->combined_ikm, ctx->server_transcript_digest,
                                        ctx->client_nonce, ctx->server_nonce,
                                        ctx->session_id);
    if (rc != HYBRID_SUCCESS) {
        ctx->state = HYBRID_STATE_FAILED;
        return rc;
    }

    /* 9. Compute Client Transcript digest for mutual authentication */
    rc = hybrid_compute_client_transcript_digest(ctx, ctx->server_sig_wire,
                                                 ctx->client_transcript_digest);
    if (rc != HYBRID_SUCCESS) {
        ctx->state = HYBRID_STATE_FAILED;
        return rc;
    }

    ctx->state = HYBRID_STATE_KEY_ESTABLISHED;
    return HYBRID_SUCCESS;
}

int hybrid_client_create_auth(hybrid_handshake_ctx_t *ctx,
                              hybrid_msg_client_auth_t *msg) {
    if (!ctx || !msg) return HYBRID_ERR_INVALID_ARG;
    if (ctx->role != HYBRID_ROLE_CLIENT || ctx->state != HYBRID_STATE_KEY_ESTABLISHED) {
        return HYBRID_ERR_INVALID_STATE;
    }

    msg->session_id = htobe64(ctx->session_id);

    /* Generate Client Dual Signature over Client Transcript Digest */
    hybrid_signature_t cl_sig;
    int rc = hybrid_sign_transcript(&cl_sig, ctx->client_transcript_digest, &ctx->our_id_sk);
    if (rc != HYBRID_SUCCESS) {
        ctx->state = HYBRID_STATE_FAILED;
        return rc;
    }

    size_t sig_len = 0;
    rc = hybrid_signature_serialize(msg->client_sig, sizeof(msg->client_sig), &sig_len, &cl_sig);
    if (rc != HYBRID_SUCCESS || sig_len != HYBRID_SIG_WIRE_BYTES) {
        ctx->state = HYBRID_STATE_FAILED;
        return rc;
    }
    memcpy(ctx->client_sig_wire, msg->client_sig, HYBRID_SIG_WIRE_BYTES);

    ctx->state = HYBRID_STATE_ESTABLISHED;
    ctx->established = 1;
    return HYBRID_SUCCESS;
}

/* ── Server State Machine Handlers ────────────────────────────────── */

int hybrid_server_process_client_hello(hybrid_handshake_ctx_t *ctx,
                                       const hybrid_msg_client_hello_t *msg,
                                       const char *client_trust_db_path) {
    if (!ctx || !msg) return HYBRID_ERR_INVALID_ARG;
    if (ctx->role != HYBRID_ROLE_SERVER || ctx->state != HYBRID_STATE_INIT) {
        return HYBRID_ERR_INVALID_STATE;
    }

    /* 1. Protocol version validation */
    if (be16toh(msg->version) != HYBRID_PROTOCOL_VERSION) {
        ctx->state = HYBRID_STATE_FAILED;
        return HYBRID_ERR_VERSION_UNSUPPORTED;
    }

    /* 2. Supported suite validation */
    if (be16toh(msg->suite_id_len) != HYBRID_SUITE_ID_LEN ||
        memcmp(msg->suite_id, HYBRID_SUITE_ID, HYBRID_SUITE_ID_LEN) != 0) {
        ctx->state = HYBRID_STATE_FAILED;
        return HYBRID_ERR_DOWNGRADE_DETECTED;
    }

    /* 3. Extract client parameters */
    memcpy(ctx->client_nonce, msg->client_nonce, HYBRID_SESSION_NONCE_BYTES);
    memcpy(ctx->peer_eph_pk.x25519_pk, msg->client_eph_x25519_pk, HYBRID_X25519_PK_BYTES);
    memcpy(ctx->peer_eph_pk.mlkem_pk, msg->client_eph_mlkem_pk, HYBRID_MLKEM768_PK_BYTES);

    memcpy(ctx->peer_id_pk.ed25519_pk, msg->client_id_ed25519_pk, HYBRID_ED25519_PK_BYTES);
    memcpy(ctx->peer_id_pk.mldsa_pk, msg->client_id_mldsa_pk, HYBRID_MLDSA65_PK_BYTES);

    /* 4. Trust Store verification of client identity if database configured */
    if (client_trust_db_path) {
        int fd = open(client_trust_db_path, O_RDONLY);
        if (fd >= 0) {
            uint8_t rec[sizeof(hybrid_identity_pk_t)];
            int found = 0;
            while (read(fd, rec, sizeof(rec)) == sizeof(rec)) {
                if (memcmp(rec, &ctx->peer_id_pk, sizeof(hybrid_identity_pk_t)) == 0) {
                    found = 1;
                    break;
                }
            }
            close(fd);
            if (!found) {
                ctx->state = HYBRID_STATE_FAILED;
                return HYBRID_ERR_UNTRUSTED_PEER;
            }
        }
    }

    ctx->state = HYBRID_STATE_CLIENT_HELLO_RECV;
    return HYBRID_SUCCESS;
}

int hybrid_server_create_hello(hybrid_handshake_ctx_t *ctx,
                               hybrid_msg_server_hello_t *msg) {
    if (!ctx || !msg) return HYBRID_ERR_INVALID_ARG;
    if (ctx->role != HYBRID_ROLE_SERVER || ctx->state != HYBRID_STATE_CLIENT_HELLO_RECV) {
        return HYBRID_ERR_INVALID_STATE;
    }

    /* 1. Protocol version and suite response */
    msg->version = htobe16(HYBRID_PROTOCOL_VERSION);
    msg->suite_id_len = htobe16(HYBRID_SUITE_ID_LEN);
    memcpy(msg->suite_id, HYBRID_SUITE_ID, HYBRID_SUITE_ID_LEN);

    /* 2. Generate fresh 32-byte server nonce and 64-bit session ID */
    if (RAND_bytes(ctx->server_nonce, HYBRID_SESSION_NONCE_BYTES) != 1 ||
        RAND_bytes((uint8_t *)&ctx->session_id, sizeof(ctx->session_id)) != 1) {
        ctx->state = HYBRID_STATE_FAILED;
        return HYBRID_ERR_CRYPTO_FAIL;
    }
    memcpy(msg->server_nonce, ctx->server_nonce, HYBRID_SESSION_NONCE_BYTES);
    msg->session_id = htobe64(ctx->session_id);

    /* 3. Encapsulate hybrid secrets against client's ephemeral public keys */
    int rc = hybrid_kex_encapsulate(&ctx->kex_ct, ctx->combined_ikm, &ctx->peer_eph_pk);
    if (rc != HYBRID_SUCCESS) {
        ctx->state = HYBRID_STATE_FAILED;
        return rc;
    }

    memcpy(msg->server_eph_x25519_pk, ctx->kex_ct.x25519_pk, HYBRID_X25519_PK_BYTES);
    memcpy(msg->server_mlkem_ct, ctx->kex_ct.mlkem_ct, HYBRID_MLKEM768_CT_BYTES);

    /* 4. Server identity public keys */
    memcpy(msg->server_id_ed25519_pk, ctx->our_id_pk.ed25519_pk, HYBRID_ED25519_PK_BYTES);
    memcpy(msg->server_id_mldsa_pk, ctx->our_id_pk.mldsa_pk, HYBRID_MLDSA65_PK_BYTES);

    /* 5. Compute canonical Server Transcript digest */
    rc = hybrid_compute_server_transcript_digest(ctx, ctx->server_transcript_digest);
    if (rc != HYBRID_SUCCESS) {
        ctx->state = HYBRID_STATE_FAILED;
        return rc;
    }

    /* 6. Sign Server Transcript Digest with server identity keys */
    hybrid_signature_t srv_sig;
    rc = hybrid_sign_transcript(&srv_sig, ctx->server_transcript_digest, &ctx->our_id_sk);
    if (rc != HYBRID_SUCCESS) {
        ctx->state = HYBRID_STATE_FAILED;
        return rc;
    }

    size_t sig_len = 0;
    rc = hybrid_signature_serialize(msg->server_sig, sizeof(msg->server_sig), &sig_len, &srv_sig);
    if (rc != HYBRID_SUCCESS || sig_len != HYBRID_SIG_WIRE_BYTES) {
        ctx->state = HYBRID_STATE_FAILED;
        return rc;
    }
    memcpy(ctx->server_sig_wire, msg->server_sig, HYBRID_SIG_WIRE_BYTES);

    /* 7. Derive directional traffic keys via HKDF-SHA-384 bound to transcript hash */
    rc = hybrid_kdf_derive_traffic_keys(ctx->client_write_key, ctx->server_write_key,
                                        ctx->combined_ikm, ctx->server_transcript_digest,
                                        ctx->client_nonce, ctx->server_nonce,
                                        ctx->session_id);
    if (rc != HYBRID_SUCCESS) {
        ctx->state = HYBRID_STATE_FAILED;
        return rc;
    }

    /* 8. Pre-compute expected Client Transcript digest */
    rc = hybrid_compute_client_transcript_digest(ctx, ctx->server_sig_wire,
                                                 ctx->client_transcript_digest);
    if (rc != HYBRID_SUCCESS) {
        ctx->state = HYBRID_STATE_FAILED;
        return rc;
    }

    ctx->state = HYBRID_STATE_SERVER_HELLO_SENT;
    return HYBRID_SUCCESS;
}

int hybrid_server_process_client_auth(hybrid_handshake_ctx_t *ctx,
                                      const hybrid_msg_client_auth_t *msg) {
    if (!ctx || !msg) return HYBRID_ERR_INVALID_ARG;
    if (ctx->role != HYBRID_ROLE_SERVER || ctx->state != HYBRID_STATE_SERVER_HELLO_SENT) {
        return HYBRID_ERR_INVALID_STATE;
    }

    /* 1. Verify session ID match */
    if (be64toh(msg->session_id) != ctx->session_id) {
        ctx->state = HYBRID_STATE_FAILED;
        return HYBRID_ERR_INVALID_STATE;
    }

    /* 2. Deserialize Client Dual Signature */
    hybrid_signature_t cl_sig;
    int rc = hybrid_signature_deserialize(&cl_sig, msg->client_sig, HYBRID_SIG_WIRE_BYTES);
    if (rc != HYBRID_SUCCESS) {
        ctx->state = HYBRID_STATE_FAILED;
        return rc;
    }

    /* 3. Verify Client Dual Signature over Client Transcript Digest */
    rc = hybrid_verify_transcript(&cl_sig, ctx->client_transcript_digest, &ctx->peer_id_pk);
    if (rc != HYBRID_SUCCESS) {
        ctx->state = HYBRID_STATE_FAILED;
        return HYBRID_ERR_SIG_VERIFY_FAIL;
    }

    memcpy(ctx->client_sig_wire, msg->client_sig, HYBRID_SIG_WIRE_BYTES);

    /* Mutual authentication complete */
    ctx->state = HYBRID_STATE_ESTABLISHED;
    ctx->established = 1;
    return HYBRID_SUCCESS;
}
