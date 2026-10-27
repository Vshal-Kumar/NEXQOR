/*
 * classical/wrappers/dsa_wrapper.c — Ed25519 Digital Signature Implementation
 */

#include "dsa_wrapper.h"

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

int ed25519_generate_keypair(uint8_t pk[ED25519_PK_BYTES], uint8_t sk[ED25519_SK_BYTES]) {
    if (!pk || !sk) return -1;

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
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

    size_t pk_len = ED25519_PK_BYTES;
    size_t sk_len = ED25519_SK_BYTES;
    int rc = -1;

    if (EVP_PKEY_get_raw_public_key(pkey, pk, &pk_len) == 1 &&
        EVP_PKEY_get_raw_private_key(pkey, sk, &sk_len) == 1 &&
        pk_len == ED25519_PK_BYTES && sk_len == ED25519_SK_BYTES) {
        rc = 0;
    }

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return rc;
}

int ed25519_sign(uint8_t sig[ED25519_SIG_BYTES], size_t *siglen,
                 const uint8_t *m, size_t mlen,
                 const uint8_t sk[ED25519_SK_BYTES]) {
    if (!sig || !sk) return -1;
    if (mlen > 0 && !m) return -1;

    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, sk, ED25519_SK_BYTES);
    if (!pkey) return -1;

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    int rc = -1;
    size_t slen = ED25519_SIG_BYTES;

    if (EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, pkey) == 1 &&
        EVP_DigestSign(md_ctx, sig, &slen, m ? m : (const uint8_t *)"", mlen) == 1 &&
        slen == ED25519_SIG_BYTES) {
        if (siglen) *siglen = slen;
        rc = 0;
    }

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    return rc;
}

int ed25519_verify(const uint8_t *sig, size_t siglen,
                   const uint8_t *m, size_t mlen,
                   const uint8_t pk[ED25519_PK_BYTES]) {
    if (!sig || siglen != ED25519_SIG_BYTES || !pk) return -1;
    if (mlen > 0 && !m) return -1;

    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pk, ED25519_PK_BYTES);
    if (!pkey) return -1;

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    int rc = -1;
    if (EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pkey) == 1) {
        int v = EVP_DigestVerify(md_ctx, sig, siglen, m ? m : (const uint8_t *)"", mlen);
        if (v == 1) {
            rc = 0; /* Valid signature */
        }
    }

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    return rc;
}

int dsa_keypair(uint8_t pk[DSA_PK_BYTES], uint8_t sk[DSA_SK_BYTES]) {
    return ed25519_generate_keypair(pk, sk);
}

int dsa_sign(uint8_t sig[DSA_SIG_BYTES], size_t *siglen,
             const uint8_t *m, size_t mlen,
             const uint8_t sk[DSA_SK_BYTES]) {
    return ed25519_sign(sig, siglen, m, mlen, sk);
}

int dsa_verify(const uint8_t *sig, size_t siglen,
               const uint8_t *m, size_t mlen,
               const uint8_t pk[DSA_PK_BYTES]) {
    return ed25519_verify(sig, siglen, m, mlen, pk);
}

void dsa_warmup(void) {
    uint8_t pk[ED25519_PK_BYTES];
    uint8_t sk[ED25519_SK_BYTES];
    uint8_t sig[ED25519_SIG_BYTES];
    size_t siglen = 0;
    const uint8_t test_msg[] = "WARMUP";

    if (ed25519_generate_keypair(pk, sk) == 0) {
        if (ed25519_sign(sig, &siglen, test_msg, sizeof(test_msg) - 1, sk) == 0) {
            ed25519_verify(sig, siglen, test_msg, sizeof(test_msg) - 1, pk);
        }
    }
    explicit_bzero(sk, sizeof(sk));
}
