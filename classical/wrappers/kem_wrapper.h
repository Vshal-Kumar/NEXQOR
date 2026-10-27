/*
 * classical/wrappers/kem_wrapper.h — X25519 ECDH Key Establishment Wrapper
 *
 * Classical IoT Cryptographic Suite:
 *   - Key Exchange: X25519 ECDH (RFC 7748) via OpenSSL 3.x EVP
 *   - Key Derivation: HKDF-SHA-256 (RFC 5869)
 */

#ifndef KEM_WRAPPER_H
#define KEM_WRAPPER_H

#include <stdint.h>
#include <stddef.h>

/* Buffer sizes for X25519 (Curve25519 ECDH) */
#define X25519_PK_BYTES   32
#define X25519_SK_BYTES   32
#define X25519_SS_BYTES   32

/* Protocol abstraction macros for seamless architectural alignment */
#define KEM_PK_BYTES      X25519_PK_BYTES
#define KEM_SK_BYTES      X25519_SK_BYTES
#define KEM_CT_BYTES      X25519_PK_BYTES   /* Peer ephemeral public key */
#define KEM_SS_BYTES      X25519_SS_BYTES

/* Derived keys: 16 bytes for AES-128 traffic keys */
#define DERIVED_KEY_BYTES 64
#define TRAFFIC_KEY_BYTES 16

/* ── Primary X25519 Interfaces ───────────────────────────────────── */

/*
 * x25519_generate_keypair()
 *   Generates a fresh ephemeral or identity X25519 keypair.
 *   Returns 0 on success, -1 on failure.
 */
int x25519_generate_keypair(uint8_t pk[X25519_PK_BYTES], uint8_t sk[X25519_SK_BYTES]);

/*
 * x25519_derive_shared_secret()
 *   Computes 32-byte shared secret ss = X25519(our_sk, peer_pk).
 *   Rejects non-contributory outputs (all zeros).
 *   Returns 0 on success, -1 on failure.
 */
int x25519_derive_shared_secret(uint8_t ss[X25519_SS_BYTES],
                                const uint8_t our_sk[X25519_SK_BYTES],
                                const uint8_t peer_pk[X25519_PK_BYTES]);

/* ── Protocol Abstraction Helpers ────────────────────────────────── */

int kem_keypair(uint8_t pk[KEM_PK_BYTES], uint8_t sk[KEM_SK_BYTES]);

int kem_enc(uint8_t ct[KEM_CT_BYTES],
            uint8_t ss[KEM_SS_BYTES],
            const uint8_t peer_pk[KEM_PK_BYTES]);

int kem_dec(uint8_t ss[KEM_SS_BYTES],
            const uint8_t ct[KEM_CT_BYTES],
            const uint8_t sk[KEM_SK_BYTES]);

/*
 * kem_derive_directional_keys()
 *   Derives distinct 16-byte client_write_key and server_write_key via HKDF-SHA-256.
 */
void kem_derive_directional_keys(uint8_t client_write_key[TRAFFIC_KEY_BYTES],
                                uint8_t server_write_key[TRAFFIC_KEY_BYTES],
                                const uint8_t ss[KEM_SS_BYTES],
                                const uint8_t c_nonce[16],
                                const uint8_t s_nonce[16],
                                uint64_t session_id);

void kem_warmup(void);

#endif /* KEM_WRAPPER_H */
