/*
 * classical/wrappers/kdf_wrapper.c — HKDF-SHA-256 and HMAC-SHA-256 Implementation
 */

#include "kdf_wrapper.h"

#include <string.h>
#include <endian.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

int hmac_sha256_compute(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t out[HMAC_SHA256_BYTES], size_t *out_len)
{
    if (!key || !out) return -1;
    if (data_len > 0 && !data) return -1;

    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac) return -1;

    EVP_MAC_CTX *mctx = EVP_MAC_CTX_new(mac);
    if (!mctx) {
        EVP_MAC_free(mac);
        return -1;
    }

    char md_name[] = "SHA256";
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, md_name, 0);
    params[1] = OSSL_PARAM_construct_end();

    size_t mac_len = 0;
    int rc = -1;

    if (EVP_MAC_init(mctx, key, key_len, params) == 1 &&
        EVP_MAC_update(mctx, data ? data : (const uint8_t *)"", data_len) == 1 &&
        EVP_MAC_final(mctx, out, &mac_len, HMAC_SHA256_BYTES) == 1 &&
        mac_len == HMAC_SHA256_BYTES) {
        if (out_len) *out_len = mac_len;
        rc = 0;
    }

    EVP_MAC_CTX_free(mctx);
    EVP_MAC_free(mac);
    return rc;
}

int hkdf_sha256_derive(uint8_t *out, size_t out_len,
                       const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *salt, size_t salt_len,
                       const uint8_t *info, size_t info_len)
{
    if (!out || out_len == 0 || !ikm || ikm_len == 0) return -1;

    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) return -1;

    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) {
        EVP_KDF_free(kdf);
        return -1;
    }

    char md_name[] = "SHA256";
    OSSL_PARAM params[5];
    int p_idx = 0;
    params[p_idx++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, md_name, 0);
    params[p_idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)ikm, ikm_len);
    if (salt && salt_len > 0) {
        params[p_idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, salt_len);
    }
    if (info && info_len > 0) {
        params[p_idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)info, info_len);
    }
    params[p_idx] = OSSL_PARAM_construct_end();

    int rc = (EVP_KDF_derive(kctx, out, out_len, params) == 1) ? 0 : -1;

    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return rc;
}

int kdf_derive_directional_keys(uint8_t client_write_key[16],
                                uint8_t server_write_key[16],
                                const uint8_t shared_secret[32],
                                const uint8_t client_nonce[16],
                                const uint8_t server_nonce[16],
                                uint64_t session_id)
{
    if (!client_write_key || !server_write_key || !shared_secret || !client_nonce || !server_nonce) {
        return -1;
    }

    /* Salt: client_nonce || server_nonce (32 bytes) */
    uint8_t salt[32];
    memcpy(salt, client_nonce, 16);
    memcpy(salt + 16, server_nonce, 16);

    uint64_t be_sid = htobe64(session_id);

    /* Context info for Client -> Server: "QRYPTONEX classical client-to-server traffic key" + be_sid */
    const char c2s_label[] = "QRYPTONEX classical client-to-server traffic key";
    uint8_t c2s_info[sizeof(c2s_label) + 8];
    memcpy(c2s_info, c2s_label, sizeof(c2s_label));
    memcpy(c2s_info + sizeof(c2s_label), &be_sid, 8);

    if (hkdf_sha256_derive(client_write_key, 16, shared_secret, 32,
                           salt, sizeof(salt), c2s_info, sizeof(c2s_info)) != 0) {
        return -1;
    }

    /* Context info for Server -> Client: "QRYPTONEX classical server-to-client traffic key" + be_sid */
    const char s2c_label[] = "QRYPTONEX classical server-to-client traffic key";
    uint8_t s2c_info[sizeof(s2c_label) + 8];
    memcpy(s2c_info, s2c_label, sizeof(s2c_label));
    memcpy(s2c_info + sizeof(s2c_label), &be_sid, 8);

    if (hkdf_sha256_derive(server_write_key, 16, shared_secret, 32,
                           salt, sizeof(salt), s2c_info, sizeof(s2c_info)) != 0) {
        explicit_bzero(client_write_key, 16);
        return -1;
    }

    return 0;
}

int kdf_derive_confirmation_keys(uint8_t client_confirm_key[32],
                                 uint8_t server_confirm_key[32],
                                 const uint8_t shared_secret[32],
                                 const uint8_t client_nonce[16],
                                 const uint8_t server_nonce[16],
                                 uint64_t session_id)
{
    if (!client_confirm_key || !server_confirm_key || !shared_secret || !client_nonce || !server_nonce) {
        return -1;
    }

    uint8_t salt[32];
    memcpy(salt, client_nonce, 16);
    memcpy(salt + 16, server_nonce, 16);

    uint64_t be_sid = htobe64(session_id);

    const char c_label[] = "QRYPTONEX classical client finished key";
    uint8_t c_info[sizeof(c_label) + 8];
    memcpy(c_info, c_label, sizeof(c_label));
    memcpy(c_info + sizeof(c_label), &be_sid, 8);

    if (hkdf_sha256_derive(client_confirm_key, 32, shared_secret, 32,
                           salt, sizeof(salt), c_info, sizeof(c_info)) != 0) {
        return -1;
    }

    const char s_label[] = "QRYPTONEX classical server finished key";
    uint8_t s_info[sizeof(s_label) + 8];
    memcpy(s_info, s_label, sizeof(s_label));
    memcpy(s_info + sizeof(s_label), &be_sid, 8);

    if (hkdf_sha256_derive(server_confirm_key, 32, shared_secret, 32,
                           salt, sizeof(salt), s_info, sizeof(s_info)) != 0) {
        explicit_bzero(client_confirm_key, 32);
        return -1;
    }

    return 0;
}
