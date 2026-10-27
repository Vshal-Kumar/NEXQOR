/*
 * hybrid/src/hybrid_session.c
 *
 * Authenticated Session Encryption & Replay Protection using ChaCha20-Poly1305.
 */

#include "hybrid_session.h"
#include "crypto/aead.h"

#include <string.h>
#include <endian.h>

static int make_session_nonce(uint8_t nonce[HYBRID_AEAD_NONCE_BYTES], uint64_t ctr) {
    if (ctr >= 0xFFFFFFFFFFFFFF00ULL) {
        return HYBRID_ERR_NONCE_EXHAUSTED;
    }
    uint64_t le_ctr = htole64(ctr);
    memcpy(nonce, &le_ctr, 8);
    memset(nonce + 8, 0, 4);
    return HYBRID_SUCCESS;
}

int hybrid_session_init_from_handshake(hybrid_session_t *session,
                                       const hybrid_handshake_ctx_t *hs) {
    if (!session || !hs) return HYBRID_ERR_INVALID_ARG;
    if (!hs->established) return HYBRID_ERR_INVALID_STATE;

    return hybrid_session_init(session, hs->role, hs->session_id,
                               hs->client_write_key, hs->server_write_key);
}

int hybrid_session_init(hybrid_session_t *session,
                        hybrid_role_t role,
                        uint64_t session_id,
                        const uint8_t client_write_key[HYBRID_TRAFFIC_KEY_BYTES],
                        const uint8_t server_write_key[HYBRID_TRAFFIC_KEY_BYTES]) {
    if (!session || !client_write_key || !server_write_key) {
        return HYBRID_ERR_INVALID_ARG;
    }

    memset(session, 0, sizeof(hybrid_session_t));
    session->role = role;
    session->session_id = session_id;
    session->tx_seq = 1;
    session->tx_nonce_ctr = 0;

    /*
     * Directional Key Assignment:
     * Client transmits under client_write_key, receives under server_write_key.
     * Server transmits under server_write_key, receives under client_write_key.
     */
    if (role == HYBRID_ROLE_CLIENT) {
        memcpy(session->tx_key, client_write_key, HYBRID_TRAFFIC_KEY_BYTES);
        memcpy(session->rx_key, server_write_key, HYBRID_TRAFFIC_KEY_BYTES);
    } else {
        memcpy(session->tx_key, server_write_key, HYBRID_TRAFFIC_KEY_BYTES);
        memcpy(session->rx_key, client_write_key, HYBRID_TRAFFIC_KEY_BYTES);
    }

    replay_window_init(&session->rx_replay_win);
    session->active = 1;
    return HYBRID_SUCCESS;
}

int hybrid_session_encrypt(hybrid_session_t *session,
                           const uint8_t *plaintext, size_t pt_len,
                           const uint8_t *aad, size_t aad_len,
                           uint8_t *ciphertext_out, size_t ct_cap,
                           size_t *ct_len_out) {
    if (!session || !session->active || !ciphertext_out) {
        return HYBRID_ERR_INVALID_ARG;
    }
    if (pt_len > 0 && !plaintext) return HYBRID_ERR_INVALID_ARG;
    if (aad_len > 0 && !aad) return HYBRID_ERR_INVALID_ARG;

    size_t req_cap = HYBRID_PACKET_OVERHEAD + pt_len;
    if (ct_cap < req_cap) {
        return HYBRID_ERR_BUFFER_TOO_SMALL;
    }

    /* 1. Monotonic nonce generation and exhaustion prevention */
    uint8_t nonce[HYBRID_AEAD_NONCE_BYTES];
    int rc = make_session_nonce(nonce, session->tx_nonce_ctr++);
    if (rc != HYBRID_SUCCESS) {
        return rc;
    }

    /* 2. Format on-wire packet layout: [NONCE (12) | TAG (16) | CIPHERTEXT (pt_len)] */
    memcpy(ciphertext_out, nonce, HYBRID_AEAD_NONCE_BYTES);
    uint8_t *tag_ptr = ciphertext_out + HYBRID_AEAD_NONCE_BYTES;
    uint8_t *ct_ptr  = tag_ptr + HYBRID_AEAD_TAG_BYTES;

    /* 3. Encrypt and authenticate with ChaCha20-Poly1305 */
    int ct_len = aead_encrypt(plaintext, (int)pt_len,
                              aad, (int)aad_len,
                              session->tx_key, nonce,
                              ct_ptr, tag_ptr);
    if (ct_len < 0 || (size_t)ct_len != pt_len) {
        return HYBRID_ERR_AEAD_FAIL;
    }

    if (ct_len_out) *ct_len_out = req_cap;
    return HYBRID_SUCCESS;
}

int hybrid_session_decrypt(hybrid_session_t *session,
                           uint32_t seq,
                           const uint8_t *wire_payload, size_t payload_len,
                           const uint8_t *aad, size_t aad_len,
                           uint8_t *plaintext_out, size_t pt_cap,
                           size_t *pt_len_out) {
    if (!session || !session->active || !wire_payload || !plaintext_out) {
        return HYBRID_ERR_INVALID_ARG;
    }
    if (aad_len > 0 && !aad) return HYBRID_ERR_INVALID_ARG;
    if (payload_len < HYBRID_PACKET_OVERHEAD) {
        return HYBRID_ERR_BUFFER_TOO_SMALL;
    }

    size_t ct_len = payload_len - HYBRID_PACKET_OVERHEAD;
    if (pt_cap < ct_len) {
        return HYBRID_ERR_BUFFER_TOO_SMALL;
    }

    /* 1. Pre-authentication Replay Protection Check */
    if (replay_window_check(&session->rx_replay_win, seq) != 0) {
        return HYBRID_ERR_REPLAY_DETECTED;
    }

    /* 2. Parse wire payload: [NONCE (12) | TAG (16) | CIPHERTEXT (ct_len)] */
    const uint8_t *nonce = wire_payload;
    const uint8_t *tag   = wire_payload + HYBRID_AEAD_NONCE_BYTES;
    const uint8_t *ct    = tag + HYBRID_AEAD_TAG_BYTES;

    /* 3. Decrypt and verify Poly1305 tag over ciphertext and AAD */
    int pt_len = aead_decrypt(ct, (int)ct_len,
                              aad, (int)aad_len,
                              session->rx_key, nonce, tag,
                              plaintext_out);
    if (pt_len < 0 || (size_t)pt_len != ct_len) {
        return HYBRID_ERR_AEAD_FAIL;
    }

    /* 4. Post-authentication Replay Window Commit */
    if (replay_window_update(&session->rx_replay_win, seq) != 0) {
        hybrid_cleanse(plaintext_out, pt_len);
        return HYBRID_ERR_REPLAY_DETECTED;
    }

    if (pt_len_out) *pt_len_out = (size_t)pt_len;
    return HYBRID_SUCCESS;
}

void hybrid_session_close(hybrid_session_t *session) {
    if (!session) return;
    hybrid_cleanse(session->tx_key, sizeof(session->tx_key));
    hybrid_cleanse(session->rx_key, sizeof(session->rx_key));
    replay_window_destroy(&session->rx_replay_win);
    session->active = 0;
}
