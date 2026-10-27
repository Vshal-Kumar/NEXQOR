/*
 * hybrid/include/hybrid_kdf.h
 *
 * SHA-384 and HKDF-SHA-384 (RFC 5869) key derivation for the hybrid suite.
 */

#ifndef HYBRID_KDF_H
#define HYBRID_KDF_H

#include <stdint.h>
#include <stddef.h>
#include <openssl/evp.h>
#include "hybrid_crypto.h"
#include "hybrid_errors.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Domain-separation labels */
#define HYBRID_LABEL_PRK             "QRYPTONEX-HYBRID-v1-PRK"
#define HYBRID_LABEL_C2S_KEY         "QRYPTONEX-HYBRID-v1-C2S-KEY"
#define HYBRID_LABEL_S2C_KEY         "QRYPTONEX-HYBRID-v1-S2C-KEY"
#define HYBRID_LABEL_CLIENT_CONFIRM  "QRYPTONEX-HYBRID-v1-CLIENT-CONFIRM"
#define HYBRID_LABEL_SERVER_CONFIRM  "QRYPTONEX-HYBRID-v1-SERVER-CONFIRM"

/* Streaming SHA-384 context */
typedef struct {
    EVP_MD_CTX *ctx;
} hybrid_sha384_ctx_t;

/* ── SHA-384 API ──────────────────────────────────────────────────── */

int hybrid_sha384_init(hybrid_sha384_ctx_t *ctx);
int hybrid_sha384_update(hybrid_sha384_ctx_t *ctx, const void *data, size_t len);
int hybrid_sha384_final(hybrid_sha384_ctx_t *ctx, uint8_t out[HYBRID_SHA384_DIGEST_BYTES]);
void hybrid_sha384_free(hybrid_sha384_ctx_t *ctx);
int hybrid_sha384_digest(const void *data, size_t len, uint8_t out[HYBRID_SHA384_DIGEST_BYTES]);

/* ── HKDF-SHA-384 (RFC 5869) Core API ─────────────────────────────── */

/*
 * hybrid_hkdf_extract()
 * PRK = HMAC-SHA-384(salt, IKM)
 * If salt is NULL or salt_len is 0, a string of 48 zeros is used per RFC 5869.
 */
int hybrid_hkdf_extract(uint8_t prk[HYBRID_SHA384_DIGEST_BYTES],
                        const uint8_t *salt, size_t salt_len,
                        const uint8_t *ikm, size_t ikm_len);

/*
 * hybrid_hkdf_expand()
 * OKM = HKDF-Expand(PRK, info, okm_len) using SHA-384
 */
int hybrid_hkdf_expand(uint8_t *okm, size_t okm_len,
                       const uint8_t prk[HYBRID_SHA384_DIGEST_BYTES],
                       const uint8_t *info, size_t info_len);

/*
 * hybrid_hkdf_derive()
 * Complete Extract-and-Expand workflow.
 */
int hybrid_hkdf_derive(uint8_t *okm, size_t okm_len,
                       const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *salt, size_t salt_len,
                       const uint8_t *info, size_t info_len);

/* ── Hybrid Directional Key Derivation ────────────────────────────── */

/*
 * hybrid_kdf_derive_traffic_keys()
 * Derives 32-byte client_write_key and 32-byte server_write_key from
 * the combined hybrid IKM, bound to the handshake transcript hash, nonces,
 * and session ID using distinct domain-separated info strings.
 */
int hybrid_kdf_derive_traffic_keys(uint8_t client_write_key[HYBRID_TRAFFIC_KEY_BYTES],
                                   uint8_t server_write_key[HYBRID_TRAFFIC_KEY_BYTES],
                                   const uint8_t combined_ikm[HYBRID_IKM_BYTES],
                                   const uint8_t transcript_hash[HYBRID_SHA384_DIGEST_BYTES],
                                   const uint8_t client_nonce[HYBRID_SESSION_NONCE_BYTES],
                                   const uint8_t server_nonce[HYBRID_SESSION_NONCE_BYTES],
                                   uint64_t session_id);

#ifdef __cplusplus
}
#endif

#endif /* HYBRID_KDF_H */
