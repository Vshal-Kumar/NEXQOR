/*
 * classical/wrappers/dsa_wrapper.h — Ed25519 Digital Signature Wrapper
 *
 * Classical IoT Cryptographic Suite:
 *   - Digital Signatures: Ed25519 (RFC 8032 / FIPS 186-5) via OpenSSL 3.x EVP
 */

#ifndef DSA_WRAPPER_H
#define DSA_WRAPPER_H

#include <stddef.h>
#include <stdint.h>

/* Buffer sizes for Ed25519 */
#define ED25519_PK_BYTES   32   /* Raw 32-byte public key */
#define ED25519_SK_BYTES   32   /* Raw 32-byte private key seed */
#define ED25519_SIG_BYTES  64   /* Detached 64-byte signature */

/* Protocol abstraction macros for seamless architectural alignment */
#define DSA_PK_BYTES       ED25519_PK_BYTES
#define DSA_SK_BYTES       ED25519_SK_BYTES
#define DSA_SIG_BYTES      ED25519_SIG_BYTES

/* ── Primary Ed25519 Interfaces ──────────────────────────────────── */

/*
 * ed25519_generate_keypair()
 *   Generates a fresh 32-byte public key and 32-byte private key seed.
 *   Returns 0 on success, -1 on failure.
 */
int ed25519_generate_keypair(uint8_t pk[ED25519_PK_BYTES], uint8_t sk[ED25519_SK_BYTES]);

/*
 * ed25519_sign()
 *   Computes a 64-byte detached signature over message m[0..mlen).
 *   Returns 0 on success, -1 on failure.
 */
int ed25519_sign(uint8_t sig[ED25519_SIG_BYTES], size_t *siglen,
                 const uint8_t *m, size_t mlen,
                 const uint8_t sk[ED25519_SK_BYTES]);

/*
 * ed25519_verify()
 *   Verifies a 64-byte detached signature over message m[0..mlen).
 *   Returns 0 if valid, non-zero (-1) if invalid or on error.
 */
int ed25519_verify(const uint8_t *sig, size_t siglen,
                   const uint8_t *m, size_t mlen,
                   const uint8_t pk[ED25519_PK_BYTES]);

/* ── Protocol Abstraction Helpers ────────────────────────────────── */

int dsa_keypair(uint8_t pk[DSA_PK_BYTES], uint8_t sk[DSA_SK_BYTES]);

int dsa_sign(uint8_t sig[DSA_SIG_BYTES], size_t *siglen,
             const uint8_t *m, size_t mlen,
             const uint8_t sk[DSA_SK_BYTES]);

int dsa_verify(const uint8_t *sig, size_t siglen,
               const uint8_t *m, size_t mlen,
               const uint8_t pk[DSA_PK_BYTES]);

void dsa_warmup(void);

#endif /* DSA_WRAPPER_H */
