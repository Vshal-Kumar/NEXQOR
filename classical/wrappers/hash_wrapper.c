/*
 * classical/wrappers/hash_wrapper.c — SHA-256 Cryptographic Hash Wrapper Implementation
 */

#include "hash_wrapper.h"
#include <string.h>

int sha256_digest(const uint8_t *data, size_t len, uint8_t out[SHA256_DIGEST_BYTES]) {
    if (!out) return -1;
    if (len > 0 && !data) return -1;

    unsigned int out_len = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, data ? data : (const uint8_t *)"", len) != 1 ||
        EVP_DigestFinal_ex(ctx, out, &out_len) != 1 ||
        out_len != SHA256_DIGEST_BYTES) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
    return 0;
}

int sha256_init(sha256_ctx_t *ctx) {
    if (!ctx) return -1;
    ctx->ctx = EVP_MD_CTX_new();
    if (!ctx->ctx) return -1;
    if (EVP_DigestInit_ex(ctx->ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx->ctx);
        ctx->ctx = NULL;
        return -1;
    }
    return 0;
}

int sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len) {
    if (!ctx || !ctx->ctx) return -1;
    if (len == 0) return 0;
    if (!data) return -1;
    return (EVP_DigestUpdate(ctx->ctx, data, len) == 1) ? 0 : -1;
}

int sha256_final(sha256_ctx_t *ctx, uint8_t out[SHA256_DIGEST_BYTES]) {
    if (!ctx || !ctx->ctx || !out) return -1;
    unsigned int out_len = 0;
    int rc = (EVP_DigestFinal_ex(ctx->ctx, out, &out_len) == 1 && out_len == SHA256_DIGEST_BYTES) ? 0 : -1;
    EVP_MD_CTX_free(ctx->ctx);
    ctx->ctx = NULL;
    return rc;
}

void sha256_free(sha256_ctx_t *ctx) {
    if (ctx && ctx->ctx) {
        EVP_MD_CTX_free(ctx->ctx);
        ctx->ctx = NULL;
    }
}
