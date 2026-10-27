/*
 * classical/crypto/aead.h — Hardware-Accelerated AES-128-CCM Authenticated Encryption
 *
 * Classical IoT Cryptographic Suite for QRYPTONEX:
 *   - Cipher: AES-128-CCM (NIST SP 800-38C / RFC 3610)
 *   - Key Size: 16 bytes (128 bits)
 *   - Nonce Size: 12 bytes (96 bits)
 *   - Tag Size: 16 bytes (128 bits)
 *   - Associated Authenticated Data (AAD): Wire header binding
 */

#ifndef AEAD_H
#define AEAD_H

#include <stdint.h>
#include <stddef.h>

/* ── Wire constants ──────────────────────────────────────────────── */
#define AEAD_KEY_BYTES    16
#define AEAD_NONCE_BYTES  12
#define AEAD_TAG_BYTES    16

/*
 * Flat on-wire packet layout (no heap allocation required):
 *
 *   [ NONCE (12) | TAG (16) | CIPHERTEXT (n) ]
 *
 * Total wire bytes for a plaintext of length n:
 *   AEAD_PACKET_OVERHEAD + n
 */
#define AEAD_PACKET_OVERHEAD  (AEAD_NONCE_BYTES + AEAD_TAG_BYTES)

/* ── Standard interface ──────────────────────────────────────────── */

/*
 * aead_encrypt() / aes128_ccm_encrypt()
 *   Encrypts plaintext[0..plaintext_len) with AES-128-CCM and authenticates aad[0..aad_len).
 *   Writes ciphertext to *ciphertext (caller allocates >= plaintext_len).
 *   Writes 16-byte tag to *tag.
 *   Returns ciphertext length (== plaintext_len) or -1 on error.
 */
int aead_encrypt(const uint8_t *plaintext,   int plaintext_len,
                 const uint8_t *aad,         int aad_len,
                 const uint8_t *key,
                 const uint8_t *nonce,
                 uint8_t       *ciphertext,
                 uint8_t       *tag);

int aes128_ccm_encrypt(const uint8_t *plaintext,   int plaintext_len,
                       const uint8_t *aad,         int aad_len,
                       const uint8_t *key,
                       const uint8_t *nonce,
                       uint8_t       *ciphertext,
                       uint8_t       *tag);

/*
 * aead_decrypt() / aes128_ccm_decrypt()
 *   Verifies tag and aad[0..aad_len), decrypts ciphertext to *plaintext.
 *   Never leaks unauthenticated plaintext on verification failure.
 *   Returns plaintext length or -1 on authentication failure / bad input.
 */
int aead_decrypt(const uint8_t *ciphertext,  int ciphertext_len,
                 const uint8_t *aad,         int aad_len,
                 const uint8_t *key,
                 const uint8_t *nonce,
                 const uint8_t *tag,
                 uint8_t       *plaintext);

int aes128_ccm_decrypt(const uint8_t *ciphertext,  int ciphertext_len,
                       const uint8_t *aad,         int aad_len,
                       const uint8_t *key,
                       const uint8_t *nonce,
                       const uint8_t *tag,
                       uint8_t       *plaintext);

/* ── Packet interface (flat [nonce|tag|ct] layout) ───────────────── */

/*
 * aead_encrypt_packet()
 *   Writes a complete [ NONCE | TAG | CT ] packet into `out`.
 *   `out` must be at least AEAD_PACKET_OVERHEAD + pt_len bytes.
 *   Nonce is randomly generated internally.
 *   Returns total bytes written (AEAD_PACKET_OVERHEAD + pt_len), or -1 on error.
 */
int aead_encrypt_packet(const uint8_t *key,
                        const uint8_t *pt,  int pt_len,
                        uint8_t       *out);

/*
 * aead_decrypt_packet()
 *   Decrypts a flat [ NONCE | TAG | CT ] packet written by aead_encrypt_packet().
 *   `pkt_len` is the total wire length (>= AEAD_PACKET_OVERHEAD).
 *   Decrypts into `pt` (caller provides >= pkt_len buffer).
 *   Returns plaintext length or -1 on auth failure / bad input.
 */
int aead_decrypt_packet(const uint8_t *key,
                        const uint8_t *pkt, int pkt_len,
                        uint8_t       *pt);

/* ── Benchmark helper ────────────────────────────────────────────── */
double get_time_ms(void);

#endif /* AEAD_H */
