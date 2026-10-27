/*
 * classical/wrappers/kem_wrapper.c — X25519 ECDH Key Establishment Implementation
 */

#include "kem_wrapper.h"
#include "kdf_wrapper.h"

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

int x25519_generate_keypair(uint8_t pk[X25519_PK_BYTES], uint8_t sk[X25519_SK_BYTES]) {
    if (!pk || !sk) return -1;

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx) return -1;

    if (EVP_PKEY_keygen_init(pctx) != 1) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) != 1 || !pkey) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    size_t pk_len = X25519_PK_BYTES;
    size_t sk_len = X25519_SK_BYTES;
    int rc = -1;

    if (EVP_PKEY_get_raw_public_key(pkey, pk, &pk_len) == 1 &&
        EVP_PKEY_get_raw_private_key(pkey, sk, &sk_len) == 1 &&
        pk_len == X25519_PK_BYTES && sk_len == X25519_SK_BYTES) {
        rc = 0;
    }

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return rc;
}

int x25519_derive_shared_secret(uint8_t ss[X25519_SS_BYTES],
                                const uint8_t our_sk[X25519_SK_BYTES],
                                const uint8_t peer_pk[X25519_PK_BYTES]) {
    if (!ss || !our_sk || !peer_pk) return -1;

    EVP_PKEY *our_pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, our_sk, X25519_SK_BYTES);
    if (!our_pkey) return -1;

    EVP_PKEY *peer_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pk, X25519_PK_BYTES);
    if (!peer_pkey) {
        EVP_PKEY_free(our_pkey);
        return -1;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(our_pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(peer_pkey);
        EVP_PKEY_free(our_pkey);
        return -1;
    }

    int rc = -1;
    size_t ss_len = X25519_SS_BYTES;

    if (EVP_PKEY_derive_init(ctx) == 1 &&
        EVP_PKEY_derive_set_peer(ctx, peer_pkey) == 1 &&
        EVP_PKEY_derive(ctx, ss, &ss_len) == 1 &&
        ss_len == X25519_SS_BYTES) {
        /* RFC 7748 check: Ensure shared secret is not all zeros (non-contributory) */
        uint8_t or_acc = 0;
        for (int i = 0; i < X25519_SS_BYTES; i++) {
            or_acc |= ss[i];
        }
        if (or_acc != 0) {
            rc = 0;
        }
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_pkey);
    EVP_PKEY_free(our_pkey);
    return rc;
}

int kem_keypair(uint8_t pk[KEM_PK_BYTES], uint8_t sk[KEM_SK_BYTES]) {
    return x25519_generate_keypair(pk, sk);
}

int kem_enc(uint8_t ct[KEM_CT_BYTES],
            uint8_t ss[KEM_SS_BYTES],
            const uint8_t peer_pk[KEM_PK_BYTES]) {
    uint8_t eph_sk[X25519_SK_BYTES];
    if (x25519_generate_keypair(ct, eph_sk) != 0) {
        return -1;
    }
    int rc = x25519_derive_shared_secret(ss, eph_sk, peer_pk);
    explicit_bzero(eph_sk, sizeof(eph_sk));
    return rc;
}

int kem_dec(uint8_t ss[KEM_SS_BYTES],
            const uint8_t ct[KEM_CT_BYTES],
            const uint8_t sk[KEM_SK_BYTES]) {
    return x25519_derive_shared_secret(ss, sk, ct);
}

void kem_derive_directional_keys(uint8_t client_write_key[TRAFFIC_KEY_BYTES],
                                uint8_t server_write_key[TRAFFIC_KEY_BYTES],
                                const uint8_t ss[KEM_SS_BYTES],
                                const uint8_t c_nonce[16],
                                const uint8_t s_nonce[16],
                                uint64_t session_id) {
    kdf_derive_directional_keys(client_write_key, server_write_key,
                                ss, c_nonce, s_nonce, session_id);
}

void kem_warmup(void) {
    uint8_t pk[X25519_PK_BYTES];
    uint8_t sk[X25519_SK_BYTES];
    uint8_t ss[X25519_SS_BYTES];
    if (x25519_generate_keypair(pk, sk) == 0) {
        x25519_derive_shared_secret(ss, sk, pk);
    }
    explicit_bzero(sk, sizeof(sk));
    explicit_bzero(ss, sizeof(ss));
}
