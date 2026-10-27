/*
 * hybrid/include/hybrid_session.h
 *
 * Authenticated Session Encryption & Replay Protection using ChaCha20-Poly1305.
 */

#ifndef HYBRID_SESSION_H
#define HYBRID_SESSION_H

#include <stdint.h>
#include <stddef.h>
#include "hybrid_crypto.h"
#include "hybrid_handshake.h"
#include "hybrid_errors.h"
#include "crypto/replay_window.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Canonical On-Wire Packet Header (15 bytes) */
typedef struct __attribute__((packed)) {
    uint32_t seq;
    uint8_t  type;
    uint16_t len;
    uint64_t session_id;
} hybrid_pkt_hdr_t;

#define HYBRID_PKT_HDR_BYTES      sizeof(hybrid_pkt_hdr_t)
#define HYBRID_PACKET_OVERHEAD    (HYBRID_AEAD_NONCE_BYTES + HYBRID_AEAD_TAG_BYTES)

/* Session State Context */
typedef struct {
    uint8_t          tx_key[HYBRID_TRAFFIC_KEY_BYTES];
    uint8_t          rx_key[HYBRID_TRAFFIC_KEY_BYTES];
    uint64_t         session_id;
    uint32_t         tx_seq;
    uint64_t         tx_nonce_ctr;
    replay_window_t  rx_replay_win;
    int              active;
    hybrid_role_t    role;
} hybrid_session_t;

/* ── Lifecycle ────────────────────────────────────────────────────── */

/*
 * hybrid_session_init_from_handshake()
 * Initializes session context from established handshake state.
 * Assigns directional tx_key and rx_key based on local role:
 *   Client: tx_key = client_write_key, rx_key = server_write_key
 *   Server: tx_key = server_write_key, rx_key = client_write_key
 */
int hybrid_session_init_from_handshake(hybrid_session_t *session,
                                       const hybrid_handshake_ctx_t *hs);

/*
 * hybrid_session_init()
 * Direct initialization with directional traffic keys and session ID.
 */
int hybrid_session_init(hybrid_session_t *session,
                        hybrid_role_t role,
                        uint64_t session_id,
                        const uint8_t client_write_key[HYBRID_TRAFFIC_KEY_BYTES],
                        const uint8_t server_write_key[HYBRID_TRAFFIC_KEY_BYTES]);

/*
 * hybrid_session_encrypt()
 * Encrypts application plaintext with ChaCha20-Poly1305 under tx_key.
 * Produces on-wire payload: [NONCE (12 bytes) | TAG (16 bytes) | CIPHERTEXT (pt_len)]
 * Nonce is generated deterministically from monotonic tx_nonce_ctr:
 *   little-endian 64-bit counter followed by 4 zero bytes.
 * Monotonic sequence number is incremented and authenticated as AAD.
 */
int hybrid_session_encrypt(hybrid_session_t *session,
                           const uint8_t *plaintext, size_t pt_len,
                           const uint8_t *aad, size_t aad_len,
                           uint8_t *ciphertext_out, size_t ct_cap,
                           size_t *ct_len_out);

/*
 * hybrid_session_decrypt()
 * Decrypts and authenticates on-wire payload under rx_key.
 * Performs two-phase replay protection:
 *   1. Pre-auth replay window check on seq (drops duplicates/stale without state commit).
 *   2. Cryptographic Poly1305 tag & AAD verification.
 *   3. Post-auth commit: updates sliding replay window ONLY after tag verification succeeds.
 */
int hybrid_session_decrypt(hybrid_session_t *session,
                           uint32_t seq,
                           const uint8_t *wire_payload, size_t payload_len,
                           const uint8_t *aad, size_t aad_len,
                           uint8_t *plaintext_out, size_t pt_cap,
                           size_t *pt_len_out);

/*
 * hybrid_session_close()
 * Securely destroys session: wipes tx_key, rx_key, resets replay window.
 */
void hybrid_session_close(hybrid_session_t *session);

#ifdef __cplusplus
}
#endif

#endif /* HYBRID_SESSION_H */
