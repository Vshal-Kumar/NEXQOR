/*
 * classical/wrappers/kdf_wrapper.h — HKDF-SHA-256 and HMAC-SHA-256 Wrappers
 *
 * Implements RFC 5869 HKDF-SHA-256 (Extract-and-Expand) and RFC 2104 / FIPS 198-1 HMAC-SHA-256.
 */

#ifndef KDF_WRAPPER_H
#define KDF_WRAPPER_H

#include <stdint.h>
#include <stddef.h>

#define HMAC_SHA256_BYTES 32

/*
 * hkdf_sha256_derive()
 *   Executes full HKDF (extract + expand) per RFC 5869 using SHA-256.
 *   Returns 0 on success, -1 on error.
 */
int hkdf_sha256_derive(uint8_t *out, size_t out_len,
                       const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *salt, size_t salt_len,
                       const uint8_t *info, size_t info_len);

/*
 * hmac_sha256_compute()
 *   Computes 32-byte HMAC-SHA-256 over data[0..data_len) using key[0..key_len).
 *   Returns 0 on success, -1 on error.
 */
int hmac_sha256_compute(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t out[HMAC_SHA256_BYTES], size_t *out_len);

/*
 * kdf_derive_directional_keys()
 *   Derives distinct 16-byte traffic keys for client-to-server and server-to-client directions.
 *   Uses RFC 5869 extract-and-expand with explicit domain separation.
 */
int kdf_derive_directional_keys(uint8_t client_write_key[16],
                                uint8_t server_write_key[16],
                                const uint8_t shared_secret[32],
                                const uint8_t client_nonce[16],
                                const uint8_t server_nonce[16],
                                uint64_t session_id);

/*
 * kdf_derive_confirmation_keys()
 *   Derives 32-byte confirmation keys for handshake key confirmation MAC tags.
 */
int kdf_derive_confirmation_keys(uint8_t client_confirm_key[32],
                                 uint8_t server_confirm_key[32],
                                 const uint8_t shared_secret[32],
                                 const uint8_t client_nonce[16],
                                 const uint8_t server_nonce[16],
                                 uint64_t session_id);

#endif /* KDF_WRAPPER_H */
