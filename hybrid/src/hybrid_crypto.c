/*
 * hybrid/src/hybrid_crypto.c
 *
 * Core initialization and identity key management implementation.
 */

#define _POSIX_C_SOURCE 200809L

#include "hybrid_crypto.h"
#include "hybrid_signature.h"
#include "wrappers/kem_wrapper.h"
#include "wrappers/dsa_wrapper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

void hybrid_cleanse(void *ptr, size_t len) {
    if (!ptr || len == 0) return;
#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25))
    explicit_bzero(ptr, len);
#else
    OPENSSL_cleanse(ptr, len);
#endif
}

int hybrid_crypto_init(void) {
    /* Step 1: Force OpenSSL DRBG initialization */
    uint8_t seed_buf[32];
    if (RAND_bytes(seed_buf, sizeof(seed_buf)) != 1) {
        return HYBRID_ERR_CRYPTO_FAIL;
    }
    hybrid_cleanse(seed_buf, sizeof(seed_buf));

    /* Step 2: Warm up hardware PQC acceleration (AVX2/NEON) and liboqs CPU dispatch */
    kem_warmup();
    dsa_warmup();

    return HYBRID_SUCCESS;
}

int hybrid_generate_identity_keys(hybrid_identity_pk_t *pk, hybrid_identity_sk_t *sk) {
    if (!pk || !sk) {
        return HYBRID_ERR_INVALID_ARG;
    }

    /* Classical identity key: Ed25519 */
    if (hybrid_ed25519_keygen(pk->ed25519_pk, sk->ed25519_sk) != HYBRID_SUCCESS) {
        hybrid_cleanse(sk, sizeof(hybrid_identity_sk_t));
        return HYBRID_ERR_CRYPTO_FAIL;
    }

    /* Post-quantum identity key: ML-DSA-65 */
    if (hybrid_mldsa65_keygen(pk->mldsa_pk, sk->mldsa_sk) != HYBRID_SUCCESS) {
        hybrid_cleanse(sk, sizeof(hybrid_identity_sk_t));
        return HYBRID_ERR_CRYPTO_FAIL;
    }

    return HYBRID_SUCCESS;
}

int hybrid_save_identity_keys(const hybrid_identity_pk_t *pk,
                              const hybrid_identity_sk_t *sk,
                              const char *pub_path,
                              const char *sec_path) {
    if (!pk || !sk || !pub_path || !sec_path) {
        return HYBRID_ERR_INVALID_ARG;
    }

    /* Save public keys */
    int pub_fd = open(pub_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (pub_fd < 0) return HYBRID_ERR_CRYPTO_FAIL;

    ssize_t w1 = write(pub_fd, pk, sizeof(hybrid_identity_pk_t));
    close(pub_fd);
    if (w1 != sizeof(hybrid_identity_pk_t)) return HYBRID_ERR_CRYPTO_FAIL;

    /* Save private keys with strict 0600 permissions */
    int sec_fd = open(sec_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (sec_fd < 0) return HYBRID_ERR_CRYPTO_FAIL;

    ssize_t w2 = write(sec_fd, sk, sizeof(hybrid_identity_sk_t));
    close(sec_fd);
    if (w2 != sizeof(hybrid_identity_sk_t)) return HYBRID_ERR_CRYPTO_FAIL;

    return HYBRID_SUCCESS;
}

int hybrid_load_identity_keys(hybrid_identity_pk_t *pk,
                              hybrid_identity_sk_t *sk,
                              const char *pub_path,
                              const char *sec_path) {
    if (!pk || !sk || !pub_path || !sec_path) {
        return HYBRID_ERR_INVALID_ARG;
    }

    int pub_fd = open(pub_path, O_RDONLY);
    if (pub_fd < 0) return HYBRID_ERR_CRYPTO_FAIL;
    ssize_t r1 = read(pub_fd, pk, sizeof(hybrid_identity_pk_t));
    close(pub_fd);
    if (r1 != sizeof(hybrid_identity_pk_t)) return HYBRID_ERR_CRYPTO_FAIL;

    int sec_fd = open(sec_path, O_RDONLY);
    if (sec_fd < 0) return HYBRID_ERR_CRYPTO_FAIL;
    ssize_t r2 = read(sec_fd, sk, sizeof(hybrid_identity_sk_t));
    close(sec_fd);
    if (r2 != sizeof(hybrid_identity_sk_t)) return HYBRID_ERR_CRYPTO_FAIL;

    return HYBRID_SUCCESS;
}
