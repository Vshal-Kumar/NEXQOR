/*
 * classical/wrappers/hash_wrapper.h — SHA-256 Cryptographic Hash Wrapper
 *
 * Implements FIPS 180-4 SHA-256 digest and streaming hashing using OpenSSL EVP.
 */

#ifndef HASH_WRAPPER_H
#define HASH_WRAPPER_H

#include <stdint.h>
#include <stddef.h>
#include <openssl/evp.h>

#define SHA256_DIGEST_BYTES 32

typedef struct {
    EVP_MD_CTX *ctx;
} sha256_ctx_t;

/* Compute SHA-256 digest in a single call */
int sha256_digest(const uint8_t *data, size_t len, uint8_t out[SHA256_DIGEST_BYTES]);

/* Streaming SHA-256 API */
int sha256_init(sha256_ctx_t *ctx);
int sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len);
int sha256_final(sha256_ctx_t *ctx, uint8_t out[SHA256_DIGEST_BYTES]);
void sha256_free(sha256_ctx_t *ctx);

#endif /* HASH_WRAPPER_H */
