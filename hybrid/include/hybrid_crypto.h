/*
 * hybrid/include/hybrid_crypto.h
 *
 * Core definitions and cryptographic interface declarations for:
 * QRYPTONEX-HYBRID-X25519-MLKEM768-ED25519-MLDSA65
 */

#ifndef HYBRID_CRYPTO_H
#define HYBRID_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include "hybrid_errors.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Protocol & Suite Constants ───────────────────────────────────── */
#define HYBRID_SUITE_ID                "QRYPTONEX-HYBRID-X25519-MLKEM768-ED25519-MLDSA65"
#define HYBRID_SUITE_ID_LEN            49

#define HYBRID_PROTOCOL_VERSION_MAJOR  1
#define HYBRID_PROTOCOL_VERSION_MINOR  0
#define HYBRID_PROTOCOL_VERSION        0x0100

/* ── Primitive Buffer Sizes ───────────────────────────────────────── */
/* Classical Key Exchange: X25519 (RFC 7748) */
#define HYBRID_X25519_PK_BYTES         32
#define HYBRID_X25519_SK_BYTES         32
#define HYBRID_X25519_SS_BYTES         32

/* Post-Quantum Key Encapsulation: ML-KEM-768 (FIPS 203) */
#define HYBRID_MLKEM768_PK_BYTES       1184
#define HYBRID_MLKEM768_SK_BYTES       2400
#define HYBRID_MLKEM768_CT_BYTES       1088
#define HYBRID_MLKEM768_SS_BYTES       32

/* Classical Digital Signature: Ed25519 (RFC 8032) */
#define HYBRID_ED25519_PK_BYTES        32
#define HYBRID_ED25519_SK_BYTES        32
#define HYBRID_ED25519_SIG_BYTES       64

/* Post-Quantum Digital Signature: ML-DSA-65 (FIPS 204) */
#define HYBRID_MLDSA65_PK_BYTES        1952
#define HYBRID_MLDSA65_SK_BYTES        4032
#define HYBRID_MLDSA65_SIG_BYTES       3309

/* Hashing and KDF: SHA-384 / HKDF-SHA-384 (RFC 5869) */
#define HYBRID_SHA384_DIGEST_BYTES     48
#define HYBRID_TRAFFIC_KEY_BYTES       32
#define HYBRID_AEAD_NONCE_BYTES        12
#define HYBRID_AEAD_TAG_BYTES          16
#define HYBRID_SESSION_NONCE_BYTES     32
#define HYBRID_SESSION_ID_BYTES        8

/* Length-prefixed combined IKM: 2 + 32 + 2 + 32 = 68 bytes */
#define HYBRID_IKM_BYTES               68

/* ── Hybrid Identity Key Structures ───────────────────────────────── */
typedef struct {
    uint8_t ed25519_pk[HYBRID_ED25519_PK_BYTES];
    uint8_t mldsa_pk[HYBRID_MLDSA65_PK_BYTES];
} hybrid_identity_pk_t;

typedef struct {
    uint8_t ed25519_sk[HYBRID_ED25519_SK_BYTES];
    uint8_t mldsa_sk[HYBRID_MLDSA65_SK_BYTES];
} hybrid_identity_sk_t;

/* ── High-Level Cryptographic Management ──────────────────────────── */

/*
 * hybrid_crypto_init()
 * Initializes cryptographic libraries (OpenSSL, liboqs), DRBG seeding,
 * and performs one-time hardware / AVX2 / NEON CPU warmup.
 * Returns HYBRID_SUCCESS (0) on success, or a negative error code.
 */
int hybrid_crypto_init(void);

/*
 * hybrid_generate_identity_keys()
 * Generates both Ed25519 and ML-DSA-65 identity keypairs.
 */
int hybrid_generate_identity_keys(hybrid_identity_pk_t *pk,
                                  hybrid_identity_sk_t *sk);

/*
 * hybrid_save_identity_keys()
 * Writes persistent dual identity keys to disk with strict 0600 file permissions.
 */
int hybrid_save_identity_keys(const hybrid_identity_pk_t *pk,
                              const hybrid_identity_sk_t *sk,
                              const char *pub_path,
                              const char *sec_path);

/*
 * hybrid_load_identity_keys()
 * Reads dual identity keys from disk.
 */
int hybrid_load_identity_keys(hybrid_identity_pk_t *pk,
                              hybrid_identity_sk_t *sk,
                              const char *pub_path,
                              const char *sec_path);

/*
 * hybrid_cleanse()
 * Securely wipes memory buffers using explicit_bzero.
 */
void hybrid_cleanse(void *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* HYBRID_CRYPTO_H */
