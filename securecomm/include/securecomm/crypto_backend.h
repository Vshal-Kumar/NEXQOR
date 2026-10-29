/*
 * securecomm/include/securecomm/crypto_backend.h
 *
 * Generic cryptographic backend abstraction for SecureComm.
 * Interfaces with Classical (OpenSSL), Pure PQC (liboqs), and Hybrid implementations.
 */

#ifndef SECURECOMM_CRYPTO_BACKEND_H
#define SECURECOMM_CRYPTO_BACKEND_H

#include "common.h"
#include "profile_registry.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct crypto_backend_s crypto_backend_t;

struct crypto_backend_s {
    const securecomm_profile_t *profile;
    void *ctx; /* Backend-specific private context */
    
    int (*init)(crypto_backend_t *self);
    void (*cleanup)(crypto_backend_t *self);
    
    /* Key Exchange (KEX) */
    int (*kex_keypair)(crypto_backend_t *self, uint8_t *public_key, size_t *pk_len,
                       uint8_t *secret_key, size_t *sk_len);
    int (*kex_encapsulate)(crypto_backend_t *self, const uint8_t *peer_pk, size_t peer_pk_len,
                           uint8_t *ciphertext, size_t *ct_len,
                           uint8_t *shared_secret, size_t *ss_len);
    int (*kex_decapsulate)(crypto_backend_t *self, const uint8_t *ciphertext, size_t ct_len,
                           const uint8_t *secret_key, size_t sk_len,
                           uint8_t *shared_secret, size_t *ss_len);
    
    /* Digital Signatures (DSA) */
    int (*dsa_keypair)(crypto_backend_t *self, uint8_t *public_key, size_t *pk_len,
                       uint8_t *secret_key, size_t *sk_len);
    int (*dsa_sign)(crypto_backend_t *self, const uint8_t *message, size_t msg_len,
                    const uint8_t *secret_key, size_t sk_len,
                    uint8_t *signature, size_t *sig_len);
    int (*dsa_verify)(crypto_backend_t *self, const uint8_t *message, size_t msg_len,
                      const uint8_t *signature, size_t sig_len,
                      const uint8_t *public_key, size_t pk_len);
    
    /* Key Derivation (KDF) */
    int (*kdf_derive_session_keys)(crypto_backend_t *self,
                                   const uint8_t *shared_secret, size_t ss_len,
                                   const uint8_t *salt, size_t salt_len,
                                   uint8_t *c2s_key, size_t c2s_key_len,
                                   uint8_t *s2c_key, size_t s2c_key_len);
    
    /* Authenticated Encryption with Associated Data (AEAD) */
    int (*aead_encrypt)(crypto_backend_t *self,
                        const uint8_t *plaintext, size_t pt_len,
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *nonce, size_t nonce_len,
                        const uint8_t *key, size_t key_len,
                        uint8_t *ciphertext, size_t *ct_len,
                        uint8_t *tag, size_t tag_len);
    int (*aead_decrypt)(crypto_backend_t *self,
                        const uint8_t *ciphertext, size_t ct_len,
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *tag, size_t tag_len,
                        const uint8_t *nonce, size_t nonce_len,
                        const uint8_t *key, size_t key_len,
                        uint8_t *plaintext, size_t *pt_len);
};

/* Factory function to create backend instance for profile */
crypto_backend_t *securecomm_crypto_backend_create(const securecomm_profile_t *profile);
void              securecomm_crypto_backend_free(crypto_backend_t *backend);

#ifdef __cplusplus
}
#endif

#endif /* SECURECOMM_CRYPTO_BACKEND_H */
