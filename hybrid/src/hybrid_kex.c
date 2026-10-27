/*
 * hybrid/src/hybrid_kex.c
 *
 * Hybrid Key Establishment implementation combining X25519 and ML-KEM-768.
 */

#include "hybrid_kex.h"
#include "wrappers/kem_wrapper.h"

#include <string.h>
#include <endian.h>
#include <openssl/evp.h>

/* ── Primitive: X25519 (RFC 7748) via OpenSSL 3.x EVP ─────────────── */

int hybrid_x25519_keygen(uint8_t pk[HYBRID_X25519_PK_BYTES],
                         uint8_t sk[HYBRID_X25519_SK_BYTES]) {
    if (!pk || !sk) return HYBRID_ERR_INVALID_ARG;

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx) return HYBRID_ERR_CRYPTO_FAIL;

    if (EVP_PKEY_keygen_init(pctx) != 1) {
        EVP_PKEY_CTX_free(pctx);
        return HYBRID_ERR_CRYPTO_FAIL;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) != 1 || !pkey) {
        EVP_PKEY_CTX_free(pctx);
        return HYBRID_ERR_CRYPTO_FAIL;
    }

    size_t pk_len = HYBRID_X25519_PK_BYTES;
    size_t sk_len = HYBRID_X25519_SK_BYTES;
    int rc = HYBRID_ERR_CRYPTO_FAIL;

    if (EVP_PKEY_get_raw_public_key(pkey, pk, &pk_len) == 1 &&
        EVP_PKEY_get_raw_private_key(pkey, sk, &sk_len) == 1 &&
        pk_len == HYBRID_X25519_PK_BYTES && sk_len == HYBRID_X25519_SK_BYTES) {
        rc = HYBRID_SUCCESS;
    }

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return rc;
}

int hybrid_x25519_shared_secret(uint8_t ss[HYBRID_X25519_SS_BYTES],
                                const uint8_t our_sk[HYBRID_X25519_SK_BYTES],
                                const uint8_t peer_pk[HYBRID_X25519_PK_BYTES]) {
    if (!ss || !our_sk || !peer_pk) return HYBRID_ERR_INVALID_ARG;

    EVP_PKEY *our_pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                                      our_sk, HYBRID_X25519_SK_BYTES);
    if (!our_pkey) return HYBRID_ERR_INVALID_KEY;

    EVP_PKEY *peer_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                                      peer_pk, HYBRID_X25519_PK_BYTES);
    if (!peer_pkey) {
        EVP_PKEY_free(our_pkey);
        return HYBRID_ERR_INVALID_KEY;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(our_pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(peer_pkey);
        EVP_PKEY_free(our_pkey);
        return HYBRID_ERR_CRYPTO_FAIL;
    }

    int rc = HYBRID_ERR_CRYPTO_FAIL;
    size_t ss_len = HYBRID_X25519_SS_BYTES;

    if (EVP_PKEY_derive_init(ctx) == 1 &&
        EVP_PKEY_derive_set_peer(ctx, peer_pkey) == 1 &&
        EVP_PKEY_derive(ctx, ss, &ss_len) == 1 &&
        ss_len == HYBRID_X25519_SS_BYTES) {
        /*
         * RFC 7748 Section 6: Contributory behavior test.
         * Must reject non-contributory / all-zero shared secrets.
         */
        uint8_t or_acc = 0;
        for (int i = 0; i < HYBRID_X25519_SS_BYTES; i++) {
            or_acc |= ss[i];
        }
        if (or_acc != 0) {
            rc = HYBRID_SUCCESS;
        } else {
            rc = HYBRID_ERR_INVALID_KEY;
        }
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_pkey);
    EVP_PKEY_free(our_pkey);
    return rc;
}

/* ── Primitive: ML-KEM-768 (FIPS 203) via Project Wrappers ────────── */

int hybrid_mlkem768_keygen(uint8_t pk[HYBRID_MLKEM768_PK_BYTES],
                           uint8_t sk[HYBRID_MLKEM768_SK_BYTES]) {
    if (!pk || !sk) return HYBRID_ERR_INVALID_ARG;
    return (kem_keypair(pk, sk) == 0) ? HYBRID_SUCCESS : HYBRID_ERR_CRYPTO_FAIL;
}

int hybrid_mlkem768_enc(uint8_t ct[HYBRID_MLKEM768_CT_BYTES],
                        uint8_t ss[HYBRID_MLKEM768_SS_BYTES],
                        const uint8_t peer_pk[HYBRID_MLKEM768_PK_BYTES]) {
    if (!ct || !ss || !peer_pk) return HYBRID_ERR_INVALID_ARG;
    return (kem_enc(ct, ss, peer_pk) == 0) ? HYBRID_SUCCESS : HYBRID_ERR_CRYPTO_FAIL;
}

int hybrid_mlkem768_dec(uint8_t ss[HYBRID_MLKEM768_SS_BYTES],
                        const uint8_t ct[HYBRID_MLKEM768_CT_BYTES],
                        const uint8_t sk[HYBRID_MLKEM768_SK_BYTES]) {
    if (!ss || !ct || !sk) return HYBRID_ERR_INVALID_ARG;
    return (kem_dec(ss, ct, sk) == 0) ? HYBRID_SUCCESS : HYBRID_ERR_CRYPTO_FAIL;
}

/* ── Combined Hybrid Key Establishment Implementation ─────────────── */

int hybrid_kex_encode_ikm(uint8_t combined_ikm[HYBRID_IKM_BYTES],
                          const uint8_t ss_x25519[HYBRID_X25519_SS_BYTES],
                          const uint8_t ss_mlkem[HYBRID_MLKEM768_SS_BYTES]) {
    if (!combined_ikm || !ss_x25519 || !ss_mlkem) {
        return HYBRID_ERR_INVALID_ARG;
    }

    /*
     * Unambiguous 2-byte big-endian length prefix encoding:
     * [len_x25519: 2 bytes][ss_x25519: 32 bytes][len_mlkem: 2 bytes][ss_mlkem: 32 bytes]
     * Total = 68 bytes.
     */
    uint16_t len1 = htobe16(HYBRID_X25519_SS_BYTES);
    uint16_t len2 = htobe16(HYBRID_MLKEM768_SS_BYTES);

    memcpy(combined_ikm, &len1, 2);
    memcpy(combined_ikm + 2, ss_x25519, HYBRID_X25519_SS_BYTES);
    memcpy(combined_ikm + 2 + HYBRID_X25519_SS_BYTES, &len2, 2);
    memcpy(combined_ikm + 2 + HYBRID_X25519_SS_BYTES + 2, ss_mlkem, HYBRID_MLKEM768_SS_BYTES);

    return HYBRID_SUCCESS;
}

int hybrid_kex_generate_keypair(hybrid_kex_public_key_t *pk,
                                hybrid_kex_secret_key_t *sk) {
    if (!pk || !sk) return HYBRID_ERR_INVALID_ARG;

    int rc = hybrid_x25519_keygen(pk->x25519_pk, sk->x25519_sk);
    if (rc != HYBRID_SUCCESS) {
        hybrid_cleanse(sk, sizeof(hybrid_kex_secret_key_t));
        return rc;
    }

    rc = hybrid_mlkem768_keygen(pk->mlkem_pk, sk->mlkem_sk);
    if (rc != HYBRID_SUCCESS) {
        hybrid_cleanse(sk, sizeof(hybrid_kex_secret_key_t));
        return rc;
    }

    return HYBRID_SUCCESS;
}

int hybrid_kex_encapsulate(hybrid_kex_ciphertext_t *ct,
                           uint8_t combined_ikm[HYBRID_IKM_BYTES],
                           const hybrid_kex_public_key_t *peer_pk) {
    if (!ct || !combined_ikm || !peer_pk) {
        return HYBRID_ERR_INVALID_ARG;
    }

    uint8_t srv_eph_sk[HYBRID_X25519_SK_BYTES];
    uint8_t ss_x25519[HYBRID_X25519_SS_BYTES];
    uint8_t ss_mlkem[HYBRID_MLKEM768_SS_BYTES];

    /* 1. Generate fresh ephemeral server X25519 keypair */
    int rc = hybrid_x25519_keygen(ct->x25519_pk, srv_eph_sk);
    if (rc != HYBRID_SUCCESS) {
        return rc;
    }

    /* 2. Compute X25519 shared secret against client's ephemeral public key */
    rc = hybrid_x25519_shared_secret(ss_x25519, srv_eph_sk, peer_pk->x25519_pk);
    hybrid_cleanse(srv_eph_sk, sizeof(srv_eph_sk));
    if (rc != HYBRID_SUCCESS) {
        hybrid_cleanse(ct, sizeof(hybrid_kex_ciphertext_t));
        return rc;
    }

    /* 3. Encapsulate ML-KEM-768 using client's ML-KEM public key */
    rc = hybrid_mlkem768_enc(ct->mlkem_ct, ss_mlkem, peer_pk->mlkem_pk);
    if (rc != HYBRID_SUCCESS) {
        hybrid_cleanse(ss_x25519, sizeof(ss_x25519));
        hybrid_cleanse(ct, sizeof(hybrid_kex_ciphertext_t));
        return rc;
    }

    /* 4. Combine both shared secrets into length-prefixed IKM */
    rc = hybrid_kex_encode_ikm(combined_ikm, ss_x25519, ss_mlkem);

    /* Zeroize intermediate shared secrets immediately */
    hybrid_cleanse(ss_x25519, sizeof(ss_x25519));
    hybrid_cleanse(ss_mlkem, sizeof(ss_mlkem));

    return rc;
}

int hybrid_kex_decapsulate(uint8_t combined_ikm[HYBRID_IKM_BYTES],
                           const hybrid_kex_ciphertext_t *ct,
                           const hybrid_kex_secret_key_t *sk) {
    if (!combined_ikm || !ct || !sk) {
        return HYBRID_ERR_INVALID_ARG;
    }

    uint8_t ss_x25519[HYBRID_X25519_SS_BYTES];
    uint8_t ss_mlkem[HYBRID_MLKEM768_SS_BYTES];

    /* 1. Compute X25519 shared secret using client's ephemeral secret key and server's ephemeral public key */
    int rc = hybrid_x25519_shared_secret(ss_x25519, sk->x25519_sk, ct->x25519_pk);
    if (rc != HYBRID_SUCCESS) {
        return rc;
    }

    /* 2. Decapsulate ML-KEM-768 ciphertext using client's ephemeral ML-KEM decapsulation key */
    rc = hybrid_mlkem768_dec(ss_mlkem, ct->mlkem_ct, sk->mlkem_sk);
    if (rc != HYBRID_SUCCESS) {
        hybrid_cleanse(ss_x25519, sizeof(ss_x25519));
        return rc;
    }

    /* 3. Combine both shared secrets into length-prefixed IKM */
    rc = hybrid_kex_encode_ikm(combined_ikm, ss_x25519, ss_mlkem);

    /* Zeroize intermediate shared secrets */
    hybrid_cleanse(ss_x25519, sizeof(ss_x25519));
    hybrid_cleanse(ss_mlkem, sizeof(ss_mlkem));

    return rc;
}
