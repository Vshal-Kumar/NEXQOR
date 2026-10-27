/*
 * hybrid/src/hybrid_kdf.c
 *
 * SHA-384 and HKDF-SHA-384 (RFC 5869) Implementation using OpenSSL 3.x EVP.
 */

#include "hybrid_kdf.h"

#include <string.h>
#include <endian.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

/* ── SHA-384 Digest Operations ────────────────────────────────────── */

int hybrid_sha384_init(hybrid_sha384_ctx_t *ctx) {
    if (!ctx) return HYBRID_ERR_INVALID_ARG;
    ctx->ctx = EVP_MD_CTX_new();
    if (!ctx->ctx) return HYBRID_ERR_CRYPTO_FAIL;
    if (EVP_DigestInit_ex(ctx->ctx, EVP_sha384(), NULL) != 1) {
        EVP_MD_CTX_free(ctx->ctx);
        ctx->ctx = NULL;
        return HYBRID_ERR_CRYPTO_FAIL;
    }
    return HYBRID_SUCCESS;
}

int hybrid_sha384_update(hybrid_sha384_ctx_t *ctx, const void *data, size_t len) {
    if (!ctx || !ctx->ctx) return HYBRID_ERR_INVALID_ARG;
    if (len == 0) return HYBRID_SUCCESS;
    if (!data) return HYBRID_ERR_INVALID_ARG;
    if (EVP_DigestUpdate(ctx->ctx, data, len) != 1) {
        return HYBRID_ERR_CRYPTO_FAIL;
    }
    return HYBRID_SUCCESS;
}

int hybrid_sha384_final(hybrid_sha384_ctx_t *ctx, uint8_t out[HYBRID_SHA384_DIGEST_BYTES]) {
    if (!ctx || !ctx->ctx || !out) return HYBRID_ERR_INVALID_ARG;
    unsigned int dlen = 0;
    int rc = (EVP_DigestFinal_ex(ctx->ctx, out, &dlen) == 1 && dlen == HYBRID_SHA384_DIGEST_BYTES)
             ? HYBRID_SUCCESS : HYBRID_ERR_CRYPTO_FAIL;
    EVP_MD_CTX_free(ctx->ctx);
    ctx->ctx = NULL;
    return rc;
}

void hybrid_sha384_free(hybrid_sha384_ctx_t *ctx) {
    if (ctx && ctx->ctx) {
        EVP_MD_CTX_free(ctx->ctx);
        ctx->ctx = NULL;
    }
}

int hybrid_sha384_digest(const void *data, size_t len, uint8_t out[HYBRID_SHA384_DIGEST_BYTES]) {
    if (!out) return HYBRID_ERR_INVALID_ARG;
    if (len > 0 && !data) return HYBRID_ERR_INVALID_ARG;

    hybrid_sha384_ctx_t ctx;
    int rc = hybrid_sha384_init(&ctx);
    if (rc != HYBRID_SUCCESS) return rc;

    if (len > 0) {
        rc = hybrid_sha384_update(&ctx, data, len);
        if (rc != HYBRID_SUCCESS) {
            hybrid_sha384_free(&ctx);
            return rc;
        }
    }
    return hybrid_sha384_final(&ctx, out);
}

/* ── HKDF-SHA-384 Operations ──────────────────────────────────────── */

int hybrid_hkdf_extract(uint8_t prk[HYBRID_SHA384_DIGEST_BYTES],
                        const uint8_t *salt, size_t salt_len,
                        const uint8_t *ikm, size_t ikm_len) {
    if (!prk || !ikm || ikm_len == 0) return HYBRID_ERR_INVALID_ARG;

    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) return HYBRID_ERR_CRYPTO_FAIL;

    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) {
        EVP_KDF_free(kdf);
        return HYBRID_ERR_CRYPTO_FAIL;
    }

    int mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
    char md_name[] = "SHA384";
    OSSL_PARAM params[5];
    int p = 0;
    params[p++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    params[p++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, md_name, 0);
    params[p++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)ikm, ikm_len);
    if (salt && salt_len > 0) {
        params[p++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, salt_len);
    }
    params[p] = OSSL_PARAM_construct_end();

    int rc = (EVP_KDF_derive(kctx, prk, HYBRID_SHA384_DIGEST_BYTES, params) == 1)
             ? HYBRID_SUCCESS : HYBRID_ERR_CRYPTO_FAIL;

    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return rc;
}

int hybrid_hkdf_expand(uint8_t *okm, size_t okm_len,
                       const uint8_t prk[HYBRID_SHA384_DIGEST_BYTES],
                       const uint8_t *info, size_t info_len) {
    if (!okm || okm_len == 0 || !prk) return HYBRID_ERR_INVALID_ARG;

    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) return HYBRID_ERR_CRYPTO_FAIL;

    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) {
        EVP_KDF_free(kdf);
        return HYBRID_ERR_CRYPTO_FAIL;
    }

    int mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
    char md_name[] = "SHA384";
    OSSL_PARAM params[5];
    int p = 0;
    params[p++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    params[p++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, md_name, 0);
    params[p++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)prk, HYBRID_SHA384_DIGEST_BYTES);
    if (info && info_len > 0) {
        params[p++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)info, info_len);
    }
    params[p] = OSSL_PARAM_construct_end();

    int rc = (EVP_KDF_derive(kctx, okm, okm_len, params) == 1)
             ? HYBRID_SUCCESS : HYBRID_ERR_CRYPTO_FAIL;

    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return rc;
}

int hybrid_hkdf_derive(uint8_t *okm, size_t okm_len,
                       const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *salt, size_t salt_len,
                       const uint8_t *info, size_t info_len) {
    if (!okm || okm_len == 0 || !ikm || ikm_len == 0) return HYBRID_ERR_INVALID_ARG;

    uint8_t prk[HYBRID_SHA384_DIGEST_BYTES];
    int rc = hybrid_hkdf_extract(prk, salt, salt_len, ikm, ikm_len);
    if (rc != HYBRID_SUCCESS) return rc;

    rc = hybrid_hkdf_expand(okm, okm_len, prk, info, info_len);
    hybrid_cleanse(prk, sizeof(prk));
    return rc;
}

/* ── Directional Traffic Key Derivation ────────────────────────────── */

int hybrid_kdf_derive_traffic_keys(uint8_t client_write_key[HYBRID_TRAFFIC_KEY_BYTES],
                                   uint8_t server_write_key[HYBRID_TRAFFIC_KEY_BYTES],
                                   const uint8_t combined_ikm[HYBRID_IKM_BYTES],
                                   const uint8_t transcript_hash[HYBRID_SHA384_DIGEST_BYTES],
                                   const uint8_t client_nonce[HYBRID_SESSION_NONCE_BYTES],
                                   const uint8_t server_nonce[HYBRID_SESSION_NONCE_BYTES],
                                   uint64_t session_id) {
    if (!client_write_key || !server_write_key || !combined_ikm ||
        !transcript_hash || !client_nonce || !server_nonce) {
        return HYBRID_ERR_INVALID_ARG;
    }

    /*
     * 1. Extract Pseudorandom Key (PRK) from combined IKM using transcript hash as salt:
     *    PRK = HKDF-Extract(salt = transcript_hash, IKM = combined_ikm)
     */
    uint8_t prk[HYBRID_SHA384_DIGEST_BYTES];
    int rc = hybrid_hkdf_extract(prk, transcript_hash, HYBRID_SHA384_DIGEST_BYTES,
                                 combined_ikm, HYBRID_IKM_BYTES);
    if (rc != HYBRID_SUCCESS) return rc;

    /*
     * 2. Build domain-separated Info structures:
     *    info = Label || Client_Nonce || Server_Nonce || Session_ID (BE 64-bit)
     */
    uint64_t sid_be = htobe64(session_id);

    /* Derive Client-to-Server Traffic Key */
    {
        uint8_t info_c2s[sizeof(HYBRID_LABEL_C2S_KEY) - 1 + 32 + 32 + 8];
        size_t off = 0;
        memcpy(info_c2s + off, HYBRID_LABEL_C2S_KEY, sizeof(HYBRID_LABEL_C2S_KEY) - 1);
        off += sizeof(HYBRID_LABEL_C2S_KEY) - 1;
        memcpy(info_c2s + off, client_nonce, HYBRID_SESSION_NONCE_BYTES);
        off += HYBRID_SESSION_NONCE_BYTES;
        memcpy(info_c2s + off, server_nonce, HYBRID_SESSION_NONCE_BYTES);
        off += HYBRID_SESSION_NONCE_BYTES;
        memcpy(info_c2s + off, &sid_be, 8);
        off += 8;

        rc = hybrid_hkdf_expand(client_write_key, HYBRID_TRAFFIC_KEY_BYTES, prk, info_c2s, off);
        hybrid_cleanse(info_c2s, sizeof(info_c2s));
        if (rc != HYBRID_SUCCESS) {
            hybrid_cleanse(prk, sizeof(prk));
            return rc;
        }
    }

    /* Derive Server-to-Client Traffic Key */
    {
        uint8_t info_s2c[sizeof(HYBRID_LABEL_S2C_KEY) - 1 + 32 + 32 + 8];
        size_t off = 0;
        memcpy(info_s2c + off, HYBRID_LABEL_S2C_KEY, sizeof(HYBRID_LABEL_S2C_KEY) - 1);
        off += sizeof(HYBRID_LABEL_S2C_KEY) - 1;
        memcpy(info_s2c + off, client_nonce, HYBRID_SESSION_NONCE_BYTES);
        off += HYBRID_SESSION_NONCE_BYTES;
        memcpy(info_s2c + off, server_nonce, HYBRID_SESSION_NONCE_BYTES);
        off += HYBRID_SESSION_NONCE_BYTES;
        memcpy(info_s2c + off, &sid_be, 8);
        off += 8;

        rc = hybrid_hkdf_expand(server_write_key, HYBRID_TRAFFIC_KEY_BYTES, prk, info_s2c, off);
        hybrid_cleanse(info_s2c, sizeof(info_s2c));
        if (rc != HYBRID_SUCCESS) {
            hybrid_cleanse(client_write_key, HYBRID_TRAFFIC_KEY_BYTES);
            hybrid_cleanse(prk, sizeof(prk));
            return rc;
        }
    }

    hybrid_cleanse(prk, sizeof(prk));
    return HYBRID_SUCCESS;
}
