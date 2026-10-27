/*
 * hybrid/include/hybrid_kex.h
 *
 * Hybrid Key Establishment combining X25519 (RFC 7748) and ML-KEM-768 (FIPS 203).
 */

#ifndef HYBRID_KEX_H
#define HYBRID_KEX_H

#include <stdint.h>
#include <stddef.h>
#include "hybrid_crypto.h"
#include "hybrid_errors.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Combined Ephemeral Public Key (Offered by Client) */
typedef struct {
    uint8_t x25519_pk[HYBRID_X25519_PK_BYTES];
    uint8_t mlkem_pk[HYBRID_MLKEM768_PK_BYTES];
} hybrid_kex_public_key_t;

/* Combined Ephemeral Secret Key (Held by Client) */
typedef struct {
    uint8_t x25519_sk[HYBRID_X25519_SK_BYTES];
    uint8_t mlkem_sk[HYBRID_MLKEM768_SK_BYTES];
} hybrid_kex_secret_key_t;

/* Combined Response Ciphertext (Returned by Server) */
typedef struct {
    uint8_t x25519_pk[HYBRID_X25519_PK_BYTES];  /* Server ephemeral public key */
    uint8_t mlkem_ct[HYBRID_MLKEM768_CT_BYTES];  /* ML-KEM-768 ciphertext */
} hybrid_kex_ciphertext_t;

/* ── Primary Combined Interfaces ──────────────────────────────────── */

/*
 * hybrid_kex_generate_keypair()
 * Generates fresh ephemeral X25519 keypair and ML-KEM-768 keypair.
 * Returns HYBRID_SUCCESS (0) on success, or negative error code.
 */
int hybrid_kex_generate_keypair(hybrid_kex_public_key_t *pk,
                                hybrid_kex_secret_key_t *sk);

/*
 * hybrid_kex_encapsulate()
 * Executed by Server:
 * 1. Generates ephemeral server X25519 keypair.
 * 2. Computes ss_x25519 = X25519(srv_eph_sk, client_eph_pk). Checks non-zero.
 * 3. Encapsulates ML-KEM-768: (ct, ss_mlkem) = Encaps(client_mlkem_pk).
 * 4. Combines both secrets with unambiguous length-prefix encoding.
 * 5. Fills ct->x25519_pk and ct->mlkem_ct.
 * Fails closed if either X25519 or ML-KEM fails.
 */
int hybrid_kex_encapsulate(hybrid_kex_ciphertext_t *ct,
                           uint8_t combined_ikm[HYBRID_IKM_BYTES],
                           const hybrid_kex_public_key_t *peer_pk);

/*
 * hybrid_kex_decapsulate()
 * Executed by Client:
 * 1. Computes ss_x25519 = X25519(client_eph_sk, ct->x25519_pk). Checks non-zero.
 * 2. Decapsulates ML-KEM-768: ss_mlkem = Decaps(ct->mlkem_ct, client_mlkem_sk).
 * 3. Combines both secrets with unambiguous length-prefix encoding.
 * Fails closed if either X25519 or ML-KEM fails.
 */
int hybrid_kex_decapsulate(uint8_t combined_ikm[HYBRID_IKM_BYTES],
                           const hybrid_kex_ciphertext_t *ct,
                           const hybrid_kex_secret_key_t *sk);

/*
 * hybrid_kex_encode_ikm()
 * Unambiguous length-prefix encoding:
 * [uint16_t(32) in BE][ss_x25519 (32 bytes)][uint16_t(32) in BE][ss_mlkem (32 bytes)]
 * Total: 68 bytes.
 */
int hybrid_kex_encode_ikm(uint8_t combined_ikm[HYBRID_IKM_BYTES],
                          const uint8_t ss_x25519[HYBRID_X25519_SS_BYTES],
                          const uint8_t ss_mlkem[HYBRID_MLKEM768_SS_BYTES]);

/* ── Individual Primitive Interfaces (Directly exposed for testing) ─ */

int hybrid_x25519_keygen(uint8_t pk[HYBRID_X25519_PK_BYTES],
                         uint8_t sk[HYBRID_X25519_SK_BYTES]);

int hybrid_x25519_shared_secret(uint8_t ss[HYBRID_X25519_SS_BYTES],
                                const uint8_t our_sk[HYBRID_X25519_SK_BYTES],
                                const uint8_t peer_pk[HYBRID_X25519_PK_BYTES]);

int hybrid_mlkem768_keygen(uint8_t pk[HYBRID_MLKEM768_PK_BYTES],
                           uint8_t sk[HYBRID_MLKEM768_SK_BYTES]);

int hybrid_mlkem768_enc(uint8_t ct[HYBRID_MLKEM768_CT_BYTES],
                        uint8_t ss[HYBRID_MLKEM768_SS_BYTES],
                        const uint8_t peer_pk[HYBRID_MLKEM768_PK_BYTES]);

int hybrid_mlkem768_dec(uint8_t ss[HYBRID_MLKEM768_SS_BYTES],
                        const uint8_t ct[HYBRID_MLKEM768_CT_BYTES],
                        const uint8_t sk[HYBRID_MLKEM768_SK_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* HYBRID_KEX_H */
