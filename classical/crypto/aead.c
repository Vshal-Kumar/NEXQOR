/*
 * classical/crypto/aead.c — Hardware-Accelerated AES-128-CCM Authenticated Encryption
 *
 * Implements RFC 3610 / NIST SP 800-38C Authenticated Encryption with Associated Data (AEAD)
 * using OpenSSL 3.x EVP interfaces.
 *
 * Parameters:
 *   Algorithm:  AES-128-CCM
 *   Key size:   16 bytes (128 bits)
 *   Nonce size: 12 bytes (96 bits)
 *   Tag size:   16 bytes (128 bits)
 */

#include "aead.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

/* ── High-resolution timer ─────────────────────────────────────── */
double get_time_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

/* ── Standard AES-128-CCM Encrypt with AAD ──────────────────────── */
int aes128_ccm_encrypt(const uint8_t *plaintext,   int plaintext_len,
                       const uint8_t *aad,         int aad_len,
                       const uint8_t *key,
                       const uint8_t *nonce,
                       uint8_t       *ciphertext,
                       uint8_t       *tag)
{
    if (!plaintext || plaintext_len < 0 || !key || !nonce || !ciphertext || !tag) {
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (__builtin_expect(!ctx, 0)) return -1;

    int outlen = 0;
    int ct_len = 0;

    /* 1. Initialize cipher context with AES-128-CCM */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* 2. Configure 12-byte nonce length */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, AEAD_NONCE_BYTES, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* 3. Configure 16-byte authentication tag length */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, AEAD_TAG_BYTES, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* 4. Bind key and nonce */
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* 5. CCM requirement: supply total plaintext length before processing */
    if (EVP_EncryptUpdate(ctx, NULL, &outlen, NULL, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* 6. Supply Associated Authenticated Data (AAD) if present */
    if (aad && aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &outlen, aad, aad_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }

    /* 7. Encrypt plaintext payload */
    if (plaintext_len > 0) {
        if (EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, plaintext_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
        ct_len = outlen;
    }

    /* 8. Finalize encryption */
    if (EVP_EncryptFinal_ex(ctx, ciphertext + ct_len, &outlen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ct_len += outlen;

    /* 9. Extract MAC authentication tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, AEAD_TAG_BYTES, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    return ct_len;
}

int aead_encrypt(const uint8_t *plaintext,   int plaintext_len,
                 const uint8_t *aad,         int aad_len,
                 const uint8_t *key,
                 const uint8_t *nonce,
                 uint8_t       *ciphertext,
                 uint8_t       *tag)
{
    return aes128_ccm_encrypt(plaintext, plaintext_len, aad, aad_len, key, nonce, ciphertext, tag);
}

/* ── Standard AES-128-CCM Decrypt with AAD ──────────────────────── */
int aes128_ccm_decrypt(const uint8_t *ciphertext,  int ciphertext_len,
                       const uint8_t *aad,         int aad_len,
                       const uint8_t *key,
                       const uint8_t *nonce,
                       const uint8_t *tag,
                       uint8_t       *plaintext)
{
    if (!ciphertext || ciphertext_len < 0 || !key || !nonce || !tag || !plaintext) {
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (__builtin_expect(!ctx, 0)) return -1;

    int outlen = 0;
    int pt_len = 0;

    /* 1. Initialize cipher context with AES-128-CCM */
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* 2. Configure 12-byte nonce length */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, AEAD_NONCE_BYTES, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* 3. CCM requirement: Set expected authentication tag prior to decryption */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, AEAD_TAG_BYTES, (void *)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* 4. Bind key and nonce */
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* 5. CCM requirement: supply total ciphertext length before processing */
    if (EVP_DecryptUpdate(ctx, NULL, &outlen, NULL, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* 6. Supply Associated Authenticated Data (AAD) if present */
    if (aad && aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &outlen, aad, aad_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }

    /* 7. Strict security requirement: decrypt into temporary buffer to avoid leaking
     * unauthenticated plaintext on authentication failure. */
    size_t alloc_sz = (ciphertext_len > 0) ? (size_t)ciphertext_len : 1;
    uint8_t *tmp_pt = malloc(alloc_sz);
    if (!tmp_pt) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (ciphertext_len > 0) {
        int rv = EVP_DecryptUpdate(ctx, tmp_pt, &outlen, ciphertext, ciphertext_len);
        if (rv <= 0) {
            explicit_bzero(tmp_pt, alloc_sz);
            free(tmp_pt);
            EVP_CIPHER_CTX_free(ctx);
            return -1; /* Authentication failure */
        }
        pt_len = outlen;
    }

    /* 8. Final verification check */
    int rv = EVP_DecryptFinal_ex(ctx, tmp_pt + pt_len, &outlen);
    if (rv <= 0) {
        explicit_bzero(tmp_pt, alloc_sz);
        free(tmp_pt);
        EVP_CIPHER_CTX_free(ctx);
        return -1; /* Tag verification failed */
    }
    pt_len += outlen;

    /* Authentication succeeded: transfer plaintext to caller */
    if (pt_len > 0) {
        memcpy(plaintext, tmp_pt, (size_t)pt_len);
    }
    explicit_bzero(tmp_pt, alloc_sz);
    free(tmp_pt);
    EVP_CIPHER_CTX_free(ctx);

    return pt_len;
}

int aead_decrypt(const uint8_t *ciphertext,  int ciphertext_len,
                 const uint8_t *aad,         int aad_len,
                 const uint8_t *key,
                 const uint8_t *nonce,
                 const uint8_t *tag,
                 uint8_t       *plaintext)
{
    return aes128_ccm_decrypt(ciphertext, ciphertext_len, aad, aad_len, key, nonce, tag, plaintext);
}

/* ── Packet encrypt (flat [nonce|tag|ct] layout) ─────────────────── */
int aead_encrypt_packet(const uint8_t *key,
                        const uint8_t *pt,  int pt_len,
                        uint8_t       *out)
{
    if (!key || !out || pt_len < 0) return -1;

    uint8_t *nonce = out;
    uint8_t *tag   = out + AEAD_NONCE_BYTES;
    uint8_t *ct    = out + AEAD_NONCE_BYTES + AEAD_TAG_BYTES;

    if (RAND_bytes(nonce, AEAD_NONCE_BYTES) != 1) return -1;

    int ct_len = aes128_ccm_encrypt(pt, pt_len, NULL, 0, key, nonce, ct, tag);
    if (ct_len < 0) return -1;

    return AEAD_PACKET_OVERHEAD + ct_len;
}

/* ── Packet decrypt (flat [nonce|tag|ct] layout) ─────────────────── */
int aead_decrypt_packet(const uint8_t *key,
                        const uint8_t *pkt, int pkt_len,
                        uint8_t       *pt)
{
    if (!key || !pkt || !pt || pkt_len < AEAD_PACKET_OVERHEAD) return -1;

    const uint8_t *nonce = pkt;
    const uint8_t *tag   = pkt + AEAD_NONCE_BYTES;
    const uint8_t *ct    = pkt + AEAD_NONCE_BYTES + AEAD_TAG_BYTES;
    int ct_len = pkt_len - AEAD_PACKET_OVERHEAD;

    return aes128_ccm_decrypt(ct, ct_len, NULL, 0, key, nonce, tag, pt);
}
