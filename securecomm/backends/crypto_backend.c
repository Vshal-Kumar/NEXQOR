/*
 * securecomm/backends/crypto_backend.c
 *
 * Concrete Cryptographic Backend implementations for Classical, Pure PQC, and Hybrid profiles.
 * Integrates OpenSSL 3.x EVP, liboqs (FIPS 203/204), and libhybrid.
 */

#define _POSIX_C_SOURCE 200809L
#include "securecomm/crypto_backend.h"
#include "securecomm/error.h"
#include "securecomm/logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <oqs/oqs.h>

/* Hybrid backend headers */
#include "../../hybrid/include/hybrid_kex.h"
#include "../../hybrid/include/hybrid_signature.h"
#include "../../hybrid/include/hybrid_kdf.h"

/* ══════════════════════════════════════════════════════════════════════
 * 1. CLASSICAL BACKEND (X25519 + Ed25519 + AES-128-CCM + HKDF-SHA256)
 * ══════════════════════════════════════════════════════════════════════ */

static int classical_init(crypto_backend_t *self) {
    (void)self;
    return SECURECOMM_SUCCESS;
}

static void classical_cleanup(crypto_backend_t *self) {
    (void)self;
}

static int classical_kex_keypair(crypto_backend_t *self, uint8_t *public_key, size_t *pk_len,
                                 uint8_t *secret_key, size_t *sk_len) {
    (void)self;
    if (!public_key || !pk_len || !secret_key || !sk_len) return SECURECOMM_ERR_INVALID_ARG;

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx) return SECURECOMM_ERR_INTERNAL;

    if (EVP_PKEY_keygen_init(pctx) != 1) {
        EVP_PKEY_CTX_free(pctx);
        return SECURECOMM_ERR_INTERNAL;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) != 1 || !pkey) {
        EVP_PKEY_CTX_free(pctx);
        return SECURECOMM_ERR_INTERNAL;
    }

    size_t pl = 32, sl = 32;
    int rc = SECURECOMM_ERR_INTERNAL;
    if (EVP_PKEY_get_raw_public_key(pkey, public_key, &pl) == 1 &&
        EVP_PKEY_get_raw_private_key(pkey, secret_key, &sl) == 1) {
        *pk_len = pl;
        *sk_len = sl;
        rc = SECURECOMM_SUCCESS;
    }

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return rc;
}

static int classical_kex_encapsulate(crypto_backend_t *self, const uint8_t *peer_pk, size_t peer_pk_len,
                                     uint8_t *ciphertext, size_t *ct_len,
                                     uint8_t *shared_secret, size_t *ss_len) {
    (void)self;
    if (!peer_pk || peer_pk_len != 32 || !ciphertext || !ct_len || !shared_secret || !ss_len) {
        return SECURECOMM_ERR_INVALID_ARG;
    }

    /* Ephemeral X25519 keypair */
    uint8_t eph_sk[32];
    size_t eph_pk_len = 32, eph_sk_len = 32;
    if (classical_kex_keypair(self, ciphertext, &eph_pk_len, eph_sk, &eph_sk_len) != 0) {
        return SECURECOMM_ERR_INTERNAL;
    }
    *ct_len = 32;

    EVP_PKEY *our_pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, eph_sk, 32);
    EVP_PKEY *peer_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pk, 32);
    if (!our_pkey || !peer_pkey) {
        if (our_pkey) EVP_PKEY_free(our_pkey);
        if (peer_pkey) EVP_PKEY_free(peer_pkey);
        return SECURECOMM_ERR_INTERNAL;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(our_pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(our_pkey);
        EVP_PKEY_free(peer_pkey);
        return SECURECOMM_ERR_INTERNAL;
    }

    int rc = SECURECOMM_ERR_INTERNAL;
    size_t derived_len = 32;
    if (EVP_PKEY_derive_init(ctx) == 1 &&
        EVP_PKEY_derive_set_peer(ctx, peer_pkey) == 1 &&
        EVP_PKEY_derive(ctx, shared_secret, &derived_len) == 1 &&
        derived_len == 32) {
        *ss_len = 32;
        rc = SECURECOMM_SUCCESS;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_pkey);
    EVP_PKEY_free(our_pkey);
    return rc;
}

static int classical_kex_decapsulate(crypto_backend_t *self, const uint8_t *ciphertext, size_t ct_len,
                                     const uint8_t *secret_key, size_t sk_len,
                                     uint8_t *shared_secret, size_t *ss_len) {
    (void)self;
    if (!ciphertext || ct_len != 32 || !secret_key || sk_len != 32 || !shared_secret || !ss_len) {
        return SECURECOMM_ERR_INVALID_ARG;
    }

    EVP_PKEY *our_pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, secret_key, 32);
    EVP_PKEY *peer_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, ciphertext, 32);
    if (!our_pkey || !peer_pkey) {
        if (our_pkey) EVP_PKEY_free(our_pkey);
        if (peer_pkey) EVP_PKEY_free(peer_pkey);
        return SECURECOMM_ERR_INTERNAL;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(our_pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(our_pkey);
        EVP_PKEY_free(peer_pkey);
        return SECURECOMM_ERR_INTERNAL;
    }

    int rc = SECURECOMM_ERR_INTERNAL;
    size_t derived_len = 32;
    if (EVP_PKEY_derive_init(ctx) == 1 &&
        EVP_PKEY_derive_set_peer(ctx, peer_pkey) == 1 &&
        EVP_PKEY_derive(ctx, shared_secret, &derived_len) == 1 &&
        derived_len == 32) {
        *ss_len = 32;
        rc = SECURECOMM_SUCCESS;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_pkey);
    EVP_PKEY_free(our_pkey);
    return rc;
}

static int classical_dsa_keypair(crypto_backend_t *self, uint8_t *public_key, size_t *pk_len,
                                 uint8_t *secret_key, size_t *sk_len) {
    (void)self;
    if (!public_key || !pk_len || !secret_key || !sk_len) return SECURECOMM_ERR_INVALID_ARG;

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!pctx) return SECURECOMM_ERR_INTERNAL;
    if (EVP_PKEY_keygen_init(pctx) != 1) {
        EVP_PKEY_CTX_free(pctx);
        return SECURECOMM_ERR_INTERNAL;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) != 1 || !pkey) {
        EVP_PKEY_CTX_free(pctx);
        return SECURECOMM_ERR_INTERNAL;
    }

    size_t pl = 32, sl = 32;
    int rc = SECURECOMM_ERR_INTERNAL;
    if (EVP_PKEY_get_raw_public_key(pkey, public_key, &pl) == 1 &&
        EVP_PKEY_get_raw_private_key(pkey, secret_key, &sl) == 1) {
        *pk_len = pl;
        *sk_len = sl;
        rc = SECURECOMM_SUCCESS;
    }

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return rc;
}

static int classical_dsa_sign(crypto_backend_t *self, const uint8_t *message, size_t msg_len,
                              const uint8_t *secret_key, size_t sk_len,
                              uint8_t *signature, size_t *sig_len) {
    (void)self;
    if (!secret_key || sk_len != 32 || !signature || !sig_len) return SECURECOMM_ERR_INVALID_ARG;

    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, secret_key, 32);
    if (!pkey) return SECURECOMM_ERR_INTERNAL;

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pkey);
        return SECURECOMM_ERR_INTERNAL;
    }

    int rc = SECURECOMM_ERR_INTERNAL;
    size_t slen = 64;
    if (EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, pkey) == 1 &&
        EVP_DigestSign(md_ctx, signature, &slen, message ? message : (const uint8_t *)"", msg_len) == 1) {
        *sig_len = slen;
        rc = SECURECOMM_SUCCESS;
    }

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    return rc;
}

static int classical_dsa_verify(crypto_backend_t *self, const uint8_t *message, size_t msg_len,
                                const uint8_t *signature, size_t sig_len,
                                const uint8_t *public_key, size_t pk_len) {
    (void)self;
    if (!public_key || pk_len != 32 || !signature || sig_len != 64) return SECURECOMM_ERR_INVALID_ARG;

    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, public_key, 32);
    if (!pkey) return SECURECOMM_ERR_INTERNAL;

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pkey);
        return SECURECOMM_ERR_INTERNAL;
    }

    int rc = SECURECOMM_ERR_AUTH_FAILED;
    if (EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pkey) == 1 &&
        EVP_DigestVerify(md_ctx, signature, sig_len, message ? message : (const uint8_t *)"", msg_len) == 1) {
        rc = SECURECOMM_SUCCESS;
    }

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    return rc;
}

static int classical_kdf_derive_session_keys(crypto_backend_t *self,
                                            const uint8_t *shared_secret, size_t ss_len,
                                            const uint8_t *salt, size_t salt_len,
                                            uint8_t *c2s_key, size_t c2s_key_len,
                                            uint8_t *s2c_key, size_t s2c_key_len) {
    (void)self;
    if (!shared_secret || ss_len == 0 || !c2s_key || !s2c_key) return SECURECOMM_ERR_INVALID_ARG;

    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) return SECURECOMM_ERR_INTERNAL;

    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx) return SECURECOMM_ERR_INTERNAL;

    uint8_t out[64];
    OSSL_PARAM params[5];
    char md[] = "SHA256";
    params[0] = OSSL_PARAM_construct_utf8_string("digest", md, strlen(md));
    params[1] = OSSL_PARAM_construct_octet_string("key", (void *)shared_secret, ss_len);
    params[2] = OSSL_PARAM_construct_octet_string("salt", (void *)salt, salt_len);
    params[3] = OSSL_PARAM_construct_octet_string("info", (void *)"securecomm classical traffic keys", 33);
    params[4] = OSSL_PARAM_construct_end();

    int rc = SECURECOMM_ERR_INTERNAL;
    if (EVP_KDF_derive(kctx, out, sizeof(out), params) == 1) {
        memcpy(c2s_key, out, c2s_key_len);
        memcpy(s2c_key, out + 32, s2c_key_len);
        rc = SECURECOMM_SUCCESS;
    }

    EVP_KDF_CTX_free(kctx);
    return rc;
}

static int classical_aead_encrypt(crypto_backend_t *self,
                                  const uint8_t *plaintext, size_t pt_len,
                                  const uint8_t *aad, size_t aad_len,
                                  const uint8_t *nonce, size_t nonce_len,
                                  const uint8_t *key, size_t key_len,
                                  uint8_t *ciphertext, size_t *ct_len,
                                  uint8_t *tag, size_t tag_len) {
    (void)self;
    if (!key || key_len < 16 || !nonce || nonce_len != 12 || !tag || tag_len != 16) {
        return SECURECOMM_ERR_INVALID_ARG;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return SECURECOMM_ERR_INTERNAL;

    int outlen = 0;
    int rc = SECURECOMM_ERR_INTERNAL;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, NULL) == 1 &&
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) == 1 &&
        EVP_EncryptUpdate(ctx, NULL, &outlen, NULL, (int)pt_len) == 1) {
        
        if (aad && aad_len > 0) {
            EVP_EncryptUpdate(ctx, NULL, &outlen, aad, (int)aad_len);
        }

        if (pt_len > 0) {
            EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, (int)pt_len);
            *ct_len = outlen;
        } else {
            *ct_len = 0;
        }

        if (EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &outlen) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) == 1) {
            rc = SECURECOMM_SUCCESS;
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

static int classical_aead_decrypt(crypto_backend_t *self,
                                  const uint8_t *ciphertext, size_t ct_len,
                                  const uint8_t *aad, size_t aad_len,
                                  const uint8_t *tag, size_t tag_len,
                                  const uint8_t *nonce, size_t nonce_len,
                                  const uint8_t *key, size_t key_len,
                                  uint8_t *plaintext, size_t *pt_len) {
    (void)self;
    if (!key || key_len < 16 || !nonce || nonce_len != 12 || !tag || tag_len != 16) {
        return SECURECOMM_ERR_INVALID_ARG;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return SECURECOMM_ERR_INTERNAL;

    int outlen = 0;
    int rc = SECURECOMM_ERR_AUTH_FAILED;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void *)tag) == 1 &&
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) == 1 &&
        EVP_DecryptUpdate(ctx, NULL, &outlen, NULL, (int)ct_len) == 1) {

        if (aad && aad_len > 0) {
            EVP_DecryptUpdate(ctx, NULL, &outlen, aad, (int)aad_len);
        }

        if (ct_len > 0) {
            if (EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, (int)ct_len) == 1) {
                *pt_len = outlen;
                rc = SECURECOMM_SUCCESS;
            }
        } else {
            *pt_len = 0;
            rc = SECURECOMM_SUCCESS;
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

/* ══════════════════════════════════════════════════════════════════════
 * 2. PURE PQC BACKEND (ML-KEM-768 + ML-DSA-65 + ChaCha20-Poly1305)
 * ══════════════════════════════════════════════════════════════════════ */

static int pqc_init(crypto_backend_t *self) {
    (void)self;
    return SECURECOMM_SUCCESS;
}

static void pqc_cleanup(crypto_backend_t *self) {
    (void)self;
}

static int pqc_kex_keypair(crypto_backend_t *self, uint8_t *public_key, size_t *pk_len,
                           uint8_t *secret_key, size_t *sk_len) {
    (void)self;
    OQS_KEM *kem = OQS_KEM_new("ML-KEM-768");
    if (!kem) return SECURECOMM_ERR_BACKEND_MISSING;

    int rc = SECURECOMM_ERR_INTERNAL;
    if (OQS_KEM_keypair(kem, public_key, secret_key) == OQS_SUCCESS) {
        *pk_len = kem->length_public_key;
        *sk_len = kem->length_secret_key;
        rc = SECURECOMM_SUCCESS;
    }
    OQS_KEM_free(kem);
    return rc;
}

static int pqc_kex_encapsulate(crypto_backend_t *self, const uint8_t *peer_pk, size_t peer_pk_len,
                               uint8_t *ciphertext, size_t *ct_len,
                               uint8_t *shared_secret, size_t *ss_len) {
    (void)self;
    (void)peer_pk_len;
    OQS_KEM *kem = OQS_KEM_new("ML-KEM-768");
    if (!kem) return SECURECOMM_ERR_BACKEND_MISSING;

    int rc = SECURECOMM_ERR_INTERNAL;
    if (OQS_KEM_encaps(kem, ciphertext, shared_secret, peer_pk) == OQS_SUCCESS) {
        *ct_len = kem->length_ciphertext;
        *ss_len = kem->length_shared_secret;
        rc = SECURECOMM_SUCCESS;
    }
    OQS_KEM_free(kem);
    return rc;
}

static int pqc_kex_decapsulate(crypto_backend_t *self, const uint8_t *ciphertext, size_t ct_len,
                               const uint8_t *secret_key, size_t sk_len,
                               uint8_t *shared_secret, size_t *ss_len) {
    (void)self;
    (void)ct_len;
    (void)sk_len;
    OQS_KEM *kem = OQS_KEM_new("ML-KEM-768");
    if (!kem) return SECURECOMM_ERR_BACKEND_MISSING;

    int rc = SECURECOMM_ERR_INTERNAL;
    if (OQS_KEM_decaps(kem, shared_secret, ciphertext, secret_key) == OQS_SUCCESS) {
        *ss_len = kem->length_shared_secret;
        rc = SECURECOMM_SUCCESS;
    }
    OQS_KEM_free(kem);
    return rc;
}

static int pqc_dsa_keypair(crypto_backend_t *self, uint8_t *public_key, size_t *pk_len,
                           uint8_t *secret_key, size_t *sk_len) {
    (void)self;
    OQS_SIG *sig = OQS_SIG_new("ML-DSA-65");
    if (!sig) return SECURECOMM_ERR_BACKEND_MISSING;

    int rc = SECURECOMM_ERR_INTERNAL;
    if (OQS_SIG_keypair(sig, public_key, secret_key) == OQS_SUCCESS) {
        *pk_len = sig->length_public_key;
        *sk_len = sig->length_secret_key;
        rc = SECURECOMM_SUCCESS;
    }
    OQS_SIG_free(sig);
    return rc;
}

static int pqc_dsa_sign(crypto_backend_t *self, const uint8_t *message, size_t msg_len,
                        const uint8_t *secret_key, size_t sk_len,
                        uint8_t *signature, size_t *sig_len) {
    (void)self;
    (void)sk_len;
    OQS_SIG *sig = OQS_SIG_new("ML-DSA-65");
    if (!sig) return SECURECOMM_ERR_BACKEND_MISSING;

    int rc = SECURECOMM_ERR_INTERNAL;
    size_t actual_sig_len = 0;
    if (OQS_SIG_sign(sig, signature, &actual_sig_len, message, msg_len, secret_key) == OQS_SUCCESS) {
        *sig_len = actual_sig_len;
        rc = SECURECOMM_SUCCESS;
    }
    OQS_SIG_free(sig);
    return rc;
}

static int pqc_dsa_verify(crypto_backend_t *self, const uint8_t *message, size_t msg_len,
                          const uint8_t *signature, size_t sig_len,
                          const uint8_t *public_key, size_t pk_len) {
    (void)self;
    (void)pk_len;
    OQS_SIG *sig = OQS_SIG_new("ML-DSA-65");
    if (!sig) return SECURECOMM_ERR_BACKEND_MISSING;

    int rc = SECURECOMM_ERR_AUTH_FAILED;
    if (OQS_SIG_verify(sig, message, msg_len, signature, sig_len, public_key) == OQS_SUCCESS) {
        rc = SECURECOMM_SUCCESS;
    }
    OQS_SIG_free(sig);
    return rc;
}

static int chacha20_poly1305_encrypt(crypto_backend_t *self,
                                     const uint8_t *plaintext, size_t pt_len,
                                     const uint8_t *aad, size_t aad_len,
                                     const uint8_t *nonce, size_t nonce_len,
                                     const uint8_t *key, size_t key_len,
                                     uint8_t *ciphertext, size_t *ct_len,
                                     uint8_t *tag, size_t tag_len) {
    (void)self;
    if (!key || key_len != 32 || !nonce || nonce_len != 12 || !tag || tag_len != 16) {
        return SECURECOMM_ERR_INVALID_ARG;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return SECURECOMM_ERR_INTERNAL;

    int outlen = 0;
    int rc = SECURECOMM_ERR_INTERNAL;

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) == 1 &&
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) == 1) {

        if (aad && aad_len > 0) {
            EVP_EncryptUpdate(ctx, NULL, &outlen, aad, (int)aad_len);
        }

        if (pt_len > 0) {
            EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, (int)pt_len);
            *ct_len = outlen;
        } else {
            *ct_len = 0;
        }

        if (EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &outlen) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) == 1) {
            rc = SECURECOMM_SUCCESS;
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

static int chacha20_poly1305_decrypt(crypto_backend_t *self,
                                     const uint8_t *ciphertext, size_t ct_len,
                                     const uint8_t *aad, size_t aad_len,
                                     const uint8_t *tag, size_t tag_len,
                                     const uint8_t *nonce, size_t nonce_len,
                                     const uint8_t *key, size_t key_len,
                                     uint8_t *plaintext, size_t *pt_len) {
    (void)self;
    if (!key || key_len != 32 || !nonce || nonce_len != 12 || !tag || tag_len != 16) {
        return SECURECOMM_ERR_INVALID_ARG;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return SECURECOMM_ERR_INTERNAL;

    int outlen = 0;
    int rc = SECURECOMM_ERR_AUTH_FAILED;

    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void *)tag) == 1 &&
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) == 1) {

        if (aad && aad_len > 0) {
            EVP_DecryptUpdate(ctx, NULL, &outlen, aad, (int)aad_len);
        }

        if (ct_len > 0) {
            if (EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, (int)ct_len) == 1 &&
                EVP_DecryptFinal_ex(ctx, plaintext + outlen, &outlen) == 1) {
                *pt_len = ct_len;
                rc = SECURECOMM_SUCCESS;
            }
        } else {
            if (EVP_DecryptFinal_ex(ctx, plaintext, &outlen) == 1) {
                *pt_len = 0;
                rc = SECURECOMM_SUCCESS;
            }
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

static int pqc_kdf_derive_session_keys(crypto_backend_t *self,
                                       const uint8_t *shared_secret, size_t ss_len,
                                       const uint8_t *salt, size_t salt_len,
                                       uint8_t *c2s_key, size_t c2s_key_len,
                                       uint8_t *s2c_key, size_t s2c_key_len) {
    (void)self;
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) return SECURECOMM_ERR_INTERNAL;

    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx) return SECURECOMM_ERR_INTERNAL;

    uint8_t out[64];
    OSSL_PARAM params[5];
    char md[] = "SHA256";
    params[0] = OSSL_PARAM_construct_utf8_string("digest", md, strlen(md));
    params[1] = OSSL_PARAM_construct_octet_string("key", (void *)shared_secret, ss_len);
    params[2] = OSSL_PARAM_construct_octet_string("salt", (void *)salt, salt_len);
    params[3] = OSSL_PARAM_construct_octet_string("info", (void *)"securecomm pqc traffic keys", 27);
    params[4] = OSSL_PARAM_construct_end();

    int rc = SECURECOMM_ERR_INTERNAL;
    if (EVP_KDF_derive(kctx, out, sizeof(out), params) == 1) {
        memcpy(c2s_key, out, c2s_key_len);
        memcpy(s2c_key, out + 32, s2c_key_len);
        rc = SECURECOMM_SUCCESS;
    }

    EVP_KDF_CTX_free(kctx);
    return rc;
}

/* ══════════════════════════════════════════════════════════════════════
 * 3. HYBRID BACKEND (X25519 + ML-KEM-768, Ed25519 + ML-DSA-65)
 * ══════════════════════════════════════════════════════════════════════ */

static int hybrid_init(crypto_backend_t *self) {
    (void)self;
    return SECURECOMM_SUCCESS;
}

static void hybrid_cleanup(crypto_backend_t *self) {
    (void)self;
}

static int hybrid_backend_kex_keypair(crypto_backend_t *self, uint8_t *public_key, size_t *pk_len,
                                      uint8_t *secret_key, size_t *sk_len) {
    (void)self;
    uint8_t x_pk[32], x_sk[32];
    size_t x_pl = 32, x_sl = 32;
    if (classical_kex_keypair(self, x_pk, &x_pl, x_sk, &x_sl) != 0) return SECURECOMM_ERR_INTERNAL;

    uint8_t pqc_pk[1184], pqc_sk[2400];
    size_t pqc_pl = 1184, pqc_sl = 2400;
    if (pqc_kex_keypair(self, pqc_pk, &pqc_pl, pqc_sk, &pqc_sl) != 0) return SECURECOMM_ERR_INTERNAL;

    memcpy(public_key, x_pk, 32);
    memcpy(public_key + 32, pqc_pk, pqc_pl);
    *pk_len = 32 + pqc_pl;

    memcpy(secret_key, x_sk, 32);
    memcpy(secret_key + 32, pqc_sk, pqc_sl);
    *sk_len = 32 + pqc_sl;

    return SECURECOMM_SUCCESS;
}

static int hybrid_backend_kex_encapsulate(crypto_backend_t *self, const uint8_t *peer_pk, size_t peer_pk_len,
                                          uint8_t *ciphertext, size_t *ct_len,
                                          uint8_t *shared_secret, size_t *ss_len) {
    (void)self;
    if (peer_pk_len < 32 + 1184) return SECURECOMM_ERR_INVALID_ARG;

    /* Classical X25519 part */
    uint8_t x_ct[32], x_ss[32];
    size_t x_ctl = 32, x_ssl = 32;
    if (classical_kex_encapsulate(self, peer_pk, 32, x_ct, &x_ctl, x_ss, &x_ssl) != 0) {
        return SECURECOMM_ERR_INTERNAL;
    }

    /* PQC ML-KEM-768 part */
    uint8_t pqc_ct[1088], pqc_ss[32];
    size_t pqc_ctl = 1088, pqc_ssl = 32;
    if (pqc_kex_encapsulate(self, peer_pk + 32, 1184, pqc_ct, &pqc_ctl, pqc_ss, &pqc_ssl) != 0) {
        return SECURECOMM_ERR_INTERNAL;
    }

    memcpy(ciphertext, x_ct, 32);
    memcpy(ciphertext + 32, pqc_ct, pqc_ctl);
    *ct_len = 32 + pqc_ctl;

    /* Combine secrets via HKDF-Extract-like step */
    uint8_t combined[64];
    memcpy(combined, x_ss, 32);
    memcpy(combined + 32, pqc_ss, 32);

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx) return SECURECOMM_ERR_INTERNAL;
    unsigned int dlen = 48;
    if (EVP_DigestInit_ex(mctx, EVP_sha384(), NULL) == 1 &&
        EVP_DigestUpdate(mctx, combined, sizeof(combined)) == 1 &&
        EVP_DigestFinal_ex(mctx, shared_secret, &dlen) == 1) {
        *ss_len = dlen;
    }
    EVP_MD_CTX_free(mctx);
    return SECURECOMM_SUCCESS;
}

static int hybrid_backend_kex_decapsulate(crypto_backend_t *self, const uint8_t *ciphertext, size_t ct_len,
                                          const uint8_t *secret_key, size_t sk_len,
                                          uint8_t *shared_secret, size_t *ss_len) {
    (void)self;
    if (ct_len < 32 + 1088 || sk_len < 32 + 2400) return SECURECOMM_ERR_INVALID_ARG;

    uint8_t x_ss[32];
    size_t x_ssl = 32;
    if (classical_kex_decapsulate(self, ciphertext, 32, secret_key, 32, x_ss, &x_ssl) != 0) {
        return SECURECOMM_ERR_INTERNAL;
    }

    uint8_t pqc_ss[32];
    size_t pqc_ssl = 32;
    if (pqc_kex_decapsulate(self, ciphertext + 32, 1088, secret_key + 32, 2400, pqc_ss, &pqc_ssl) != 0) {
        return SECURECOMM_ERR_INTERNAL;
    }

    uint8_t combined[64];
    memcpy(combined, x_ss, 32);
    memcpy(combined + 32, pqc_ss, 32);

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx) return SECURECOMM_ERR_INTERNAL;
    unsigned int dlen = 48;
    if (EVP_DigestInit_ex(mctx, EVP_sha384(), NULL) == 1 &&
        EVP_DigestUpdate(mctx, combined, sizeof(combined)) == 1 &&
        EVP_DigestFinal_ex(mctx, shared_secret, &dlen) == 1) {
        *ss_len = dlen;
    }
    EVP_MD_CTX_free(mctx);
    return SECURECOMM_SUCCESS;
}

static int hybrid_backend_dsa_keypair(crypto_backend_t *self, uint8_t *public_key, size_t *pk_len,
                                      uint8_t *secret_key, size_t *sk_len) {
    uint8_t ed_pk[32], ed_sk[32];
    size_t ed_pl = 32, ed_sl = 32;
    if (classical_dsa_keypair(self, ed_pk, &ed_pl, ed_sk, &ed_sl) != 0) return SECURECOMM_ERR_INTERNAL;

    uint8_t pqc_pk[1952], pqc_sk[4032];
    size_t pqc_pl = 1952, pqc_sl = 4032;
    if (pqc_dsa_keypair(self, pqc_pk, &pqc_pl, pqc_sk, &pqc_sl) != 0) return SECURECOMM_ERR_INTERNAL;

    memcpy(public_key, ed_pk, 32);
    memcpy(public_key + 32, pqc_pk, pqc_pl);
    *pk_len = 32 + pqc_pl;

    memcpy(secret_key, ed_sk, 32);
    memcpy(secret_key + 32, pqc_sk, pqc_sl);
    *sk_len = 32 + pqc_sl;

    return SECURECOMM_SUCCESS;
}

static int hybrid_backend_dsa_sign(crypto_backend_t *self, const uint8_t *message, size_t msg_len,
                                   const uint8_t *secret_key, size_t sk_len,
                                   uint8_t *signature, size_t *sig_len) {
    if (sk_len < 32 + 4032) return SECURECOMM_ERR_INVALID_ARG;

    uint8_t ed_sig[64];
    size_t ed_sl = 64;
    if (classical_dsa_sign(self, message, msg_len, secret_key, 32, ed_sig, &ed_sl) != 0) {
        return SECURECOMM_ERR_INTERNAL;
    }

    uint8_t pqc_sig[3309];
    size_t pqc_sl = 3309;
    if (pqc_dsa_sign(self, message, msg_len, secret_key + 32, sk_len - 32, pqc_sig, &pqc_sl) != 0) {
        return SECURECOMM_ERR_INTERNAL;
    }

    memcpy(signature, ed_sig, 64);
    memcpy(signature + 64, pqc_sig, pqc_sl);
    *sig_len = 64 + pqc_sl;
    return SECURECOMM_SUCCESS;
}

static int hybrid_backend_dsa_verify(crypto_backend_t *self, const uint8_t *message, size_t msg_len,
                                     const uint8_t *signature, size_t sig_len,
                                     const uint8_t *public_key, size_t pk_len) {
    if (sig_len < 64 + 3309 || pk_len < 32 + 1952) return SECURECOMM_ERR_INVALID_ARG;

    /* Both Classical AND Post-Quantum signatures MUST verify */
    if (classical_dsa_verify(self, message, msg_len, signature, 64, public_key, 32) != 0) {
        SECURECOMM_LOG_ERROR("Hybrid verification: Ed25519 component failed");
        return SECURECOMM_ERR_AUTH_FAILED;
    }

    if (pqc_dsa_verify(self, message, msg_len, signature + 64, sig_len - 64, public_key + 32, pk_len - 32) != 0) {
        SECURECOMM_LOG_ERROR("Hybrid verification: ML-DSA-65 component failed");
        return SECURECOMM_ERR_AUTH_FAILED;
    }

    return SECURECOMM_SUCCESS;
}

static int hybrid_backend_kdf_derive_session_keys(crypto_backend_t *self,
                                                  const uint8_t *shared_secret, size_t ss_len,
                                                  const uint8_t *salt, size_t salt_len,
                                                  uint8_t *c2s_key, size_t c2s_key_len,
                                                  uint8_t *s2c_key, size_t s2c_key_len) {
    (void)self;
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) return SECURECOMM_ERR_INTERNAL;

    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx) return SECURECOMM_ERR_INTERNAL;

    uint8_t out[64];
    OSSL_PARAM params[5];
    char md[] = "SHA384";
    params[0] = OSSL_PARAM_construct_utf8_string("digest", md, strlen(md));
    params[1] = OSSL_PARAM_construct_octet_string("key", (void *)shared_secret, ss_len);
    params[2] = OSSL_PARAM_construct_octet_string("salt", (void *)salt, salt_len);
    params[3] = OSSL_PARAM_construct_octet_string("info", (void *)"securecomm hybrid traffic keys", 30);
    params[4] = OSSL_PARAM_construct_end();

    int rc = SECURECOMM_ERR_INTERNAL;
    if (EVP_KDF_derive(kctx, out, sizeof(out), params) == 1) {
        memcpy(c2s_key, out, c2s_key_len);
        memcpy(s2c_key, out + 32, s2c_key_len);
        rc = SECURECOMM_SUCCESS;
    }

    EVP_KDF_CTX_free(kctx);
    return rc;
}

/* ══════════════════════════════════════════════════════════════════════
 * BACKEND FACTORY & DESTRUCTOR
 * ══════════════════════════════════════════════════════════════════════ */

crypto_backend_t *securecomm_crypto_backend_create(const securecomm_profile_t *profile) {
    if (!profile) return NULL;

    crypto_backend_t *backend = calloc(1, sizeof(*backend));
    if (!backend) return NULL;

    backend->profile = profile;

    if (profile->mode == SECURECOMM_MODE_CLASSICAL) {
        backend->init = classical_init;
        backend->cleanup = classical_cleanup;
        backend->kex_keypair = classical_kex_keypair;
        backend->kex_encapsulate = classical_kex_encapsulate;
        backend->kex_decapsulate = classical_kex_decapsulate;
        backend->dsa_keypair = classical_dsa_keypair;
        backend->dsa_sign = classical_dsa_sign;
        backend->dsa_verify = classical_dsa_verify;
        backend->kdf_derive_session_keys = classical_kdf_derive_session_keys;
        backend->aead_encrypt = classical_aead_encrypt;
        backend->aead_decrypt = classical_aead_decrypt;
    } else if (profile->mode == SECURECOMM_MODE_PQC) {
        backend->init = pqc_init;
        backend->cleanup = pqc_cleanup;
        backend->kex_keypair = pqc_kex_keypair;
        backend->kex_encapsulate = pqc_kex_encapsulate;
        backend->kex_decapsulate = pqc_kex_decapsulate;
        backend->dsa_keypair = pqc_dsa_keypair;
        backend->dsa_sign = pqc_dsa_sign;
        backend->dsa_verify = pqc_dsa_verify;
        backend->kdf_derive_session_keys = pqc_kdf_derive_session_keys;
        backend->aead_encrypt = chacha20_poly1305_encrypt;
        backend->aead_decrypt = chacha20_poly1305_decrypt;
    } else {
        /* Hybrid and Adaptive default */
        backend->init = hybrid_init;
        backend->cleanup = hybrid_cleanup;
        backend->kex_keypair = hybrid_backend_kex_keypair;
        backend->kex_encapsulate = hybrid_backend_kex_encapsulate;
        backend->kex_decapsulate = hybrid_backend_kex_decapsulate;
        backend->dsa_keypair = hybrid_backend_dsa_keypair;
        backend->dsa_sign = hybrid_backend_dsa_sign;
        backend->dsa_verify = hybrid_backend_dsa_verify;
        backend->kdf_derive_session_keys = hybrid_backend_kdf_derive_session_keys;
        backend->aead_encrypt = chacha20_poly1305_encrypt;
        backend->aead_decrypt = chacha20_poly1305_decrypt;
    }

    if (backend->init(backend) != 0) {
        free(backend);
        return NULL;
    }

    return backend;
}

void securecomm_crypto_backend_free(crypto_backend_t *backend) {
    if (!backend) return;
    if (backend->cleanup) {
        backend->cleanup(backend);
    }
    free(backend);
}
