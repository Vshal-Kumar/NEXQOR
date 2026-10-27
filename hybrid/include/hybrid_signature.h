/*
 * hybrid/include/hybrid_signature.h
 *
 * Hybrid Digital Signatures combining Ed25519 (RFC 8032) and ML-DSA-65 (FIPS 204).
 */

#ifndef HYBRID_SIGNATURE_H
#define HYBRID_SIGNATURE_H

#include <stdint.h>
#include <stddef.h>
#include "hybrid_crypto.h"
#include "hybrid_errors.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Canonical framed wire length:
 *   version (1) + ed25519_len (2) + ed25519_sig (64) + mldsa_len (2) + mldsa_sig (3309)
 *   = 3378 bytes
 */
#define HYBRID_SIG_FORMAT_VERSION 0x01
#define HYBRID_SIG_WIRE_BYTES     (1 + 2 + HYBRID_ED25519_SIG_BYTES + 2 + HYBRID_MLDSA65_SIG_BYTES)

typedef struct {
    uint8_t  version;
    uint16_t ed25519_sig_len;
    uint8_t  ed25519_sig[HYBRID_ED25519_SIG_BYTES];
    uint16_t mldsa_sig_len;
    uint8_t  mldsa_sig[HYBRID_MLDSA65_SIG_BYTES];
} hybrid_signature_t;

/* ── Primary Combined Interfaces ──────────────────────────────────── */

/*
 * hybrid_sign_transcript()
 * Signs the 48-byte SHA-384 transcript digest with both Ed25519 and ML-DSA-65.
 * Returns HYBRID_SUCCESS (0) on success, or negative error code.
 */
int hybrid_sign_transcript(hybrid_signature_t *sig,
                           const uint8_t transcript_digest[HYBRID_SHA384_DIGEST_BYTES],
                           const hybrid_identity_sk_t *sk);

/*
 * hybrid_verify_transcript()
 * Verifies both Ed25519 and ML-DSA-65 signatures over the 48-byte transcript digest.
 * Fails if either signature is missing, invalid, or length mismatched.
 * Returns HYBRID_SUCCESS (0) if BOTH signatures verify, or HYBRID_ERR_SIG_VERIFY_FAIL.
 */
int hybrid_verify_transcript(const hybrid_signature_t *sig,
                             const uint8_t transcript_digest[HYBRID_SHA384_DIGEST_BYTES],
                             const hybrid_identity_pk_t *pk);

/*
 * hybrid_signature_serialize()
 * Serializes hybrid_signature_t into canonical framed wire format.
 */
int hybrid_signature_serialize(uint8_t *out, size_t out_cap, size_t *out_len,
                               const hybrid_signature_t *sig);

/*
 * hybrid_signature_deserialize()
 * Deserializes canonical framed wire format into hybrid_signature_t.
 */
int hybrid_signature_deserialize(hybrid_signature_t *sig,
                                 const uint8_t *in, size_t in_len);

/* ── Individual Primitive Interfaces (Directly exposed for testing) ─ */

int hybrid_ed25519_keygen(uint8_t pk[HYBRID_ED25519_PK_BYTES],
                          uint8_t sk[HYBRID_ED25519_SK_BYTES]);

int hybrid_ed25519_sign(uint8_t sig[HYBRID_ED25519_SIG_BYTES], size_t *siglen,
                        const uint8_t *m, size_t mlen,
                        const uint8_t sk[HYBRID_ED25519_SK_BYTES]);

int hybrid_ed25519_verify(const uint8_t *sig, size_t siglen,
                          const uint8_t *m, size_t mlen,
                          const uint8_t pk[HYBRID_ED25519_PK_BYTES]);

int hybrid_mldsa65_keygen(uint8_t pk[HYBRID_MLDSA65_PK_BYTES],
                          uint8_t sk[HYBRID_MLDSA65_SK_BYTES]);

int hybrid_mldsa65_sign(uint8_t sig[HYBRID_MLDSA65_SIG_BYTES], size_t *siglen,
                        const uint8_t *m, size_t mlen,
                        const uint8_t sk[HYBRID_MLDSA65_SK_BYTES]);

int hybrid_mldsa65_verify(const uint8_t *sig, size_t siglen,
                          const uint8_t *m, size_t mlen,
                          const uint8_t pk[HYBRID_MLDSA65_PK_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* HYBRID_SIGNATURE_H */
