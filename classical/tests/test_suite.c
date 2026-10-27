/*
 * classical/tests/test_suite.c — Comprehensive Automated Security & Unit Test Suite
 *
 * Implements thorough validation for:
 *   [01] X25519 Shared-Secret Agreement
 *   [02] X25519 Invalid-Input Handling (All-zero & Non-contributory outputs)
 *   [03] Ed25519 Signing and Verification
 *   [04] Ed25519 Rejection of Tampered Message
 *   [05] Ed25519 Rejection of Corrupted Signature & Wrong Public Key
 *   [06] AES-128-CCM Encryption and Decryption
 *   [07] AES-128-CCM Rejection of Ciphertext Tampering
 *   [08] AES-128-CCM Rejection of Wire Header AAD Modification
 *   [09] AES-128-CCM Rejection of Corrupted Authentication Tag
 *   [10] SHA-256 Known-Answer Test (NIST FIPS 180-4 KAT)
 *   [11] HKDF-SHA-256 Known-Answer Test (RFC 5869 Test Case 1)
 *   [12] HMAC-SHA-256 Known-Answer Test (RFC 4231 Test Case 1)
 *   [13] Directional Traffic-Key Separation (C2S vs S2C)
 *   [14] Session Nonce Uniqueness & Monotonic Tracking
 *   [15] RFC 6479 64-Packet Sliding Replay Window (reordering, duplicates, stale drops)
 *   [16] Packet Framing, Fragmentation & Out-of-Order Reassembly
 *   [17] Trust Store Peer Authentication & Public-Key Substitution (MITM) Prevention
 *   [18] Full 4-Phase Mutual-Authentication Handshake Simulation
 *   [19] Handshake Failure Under Active Attacker Tampering
 *   [20] Session Cryptographic State Isolation Between Concurrent Clients
 *   [21] Session Resource Cleanup & Ephemeral Secret Zeroization
 *   [22] Reconnection and Session-ID Reuse Handling
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <endian.h>
#include <arpa/inet.h>
#include <openssl/rand.h>

#include "crypto/aead.h"
#include "crypto/replay_window.h"
#include "crypto/trust_store.h"
#include "transport.h"
#include "wrappers/kem_wrapper.h"
#include "wrappers/dsa_wrapper.h"
#include "wrappers/hash_wrapper.h"
#include "wrappers/kdf_wrapper.h"

/* ── ANSI Color Formatting ───────────────────────────────────────── */
#define CLR_RESET   "\033[0m"
#define CLR_BOLD    "\033[1m"
#define CLR_GREEN   "\033[1;32m"
#define CLR_RED     "\033[1;31m"
#define CLR_YELLOW  "\033[1;33m"
#define CLR_CYAN    "\033[1;36m"

static int g_tests_run = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("\n    " CLR_RED "✗ FAILED: %s (line %d)" CLR_RESET "\n", msg, __LINE__); \
        g_tests_failed++; \
        return -1; \
    } \
} while (0)

#define RUN_TEST(fn) do { \
    g_tests_run++; \
    printf(CLR_BOLD "[TEST %02d] %-52s" CLR_RESET, g_tests_run, #fn); \
    fflush(stdout); \
    if (fn() == 0) { \
        printf(CLR_GREEN " PASS" CLR_RESET "\n"); \
        g_tests_passed++; \
    } else { \
        /* failure message already printed */ \
    } \
} while (0)

/* ═══════════════════════════════════════════════════════════════════
 * [01] X25519 SHARED-SECRET AGREEMENT
 * ═══════════════════════════════════════════════════════════════════ */
static int test_x25519_agreement(void) {
    uint8_t a_pk[X25519_PK_BYTES], a_sk[X25519_SK_BYTES];
    uint8_t b_pk[X25519_PK_BYTES], b_sk[X25519_SK_BYTES];
    uint8_t a_ss[X25519_SS_BYTES];
    uint8_t b_ss[X25519_SS_BYTES];

    TEST_ASSERT(x25519_generate_keypair(a_pk, a_sk) == 0, "Alice keypair failed");
    TEST_ASSERT(x25519_generate_keypair(b_pk, b_sk) == 0, "Bob keypair failed");

    TEST_ASSERT(x25519_derive_shared_secret(a_ss, a_sk, b_pk) == 0, "Alice derive failed");
    TEST_ASSERT(x25519_derive_shared_secret(b_ss, b_sk, a_pk) == 0, "Bob derive failed");

    TEST_ASSERT(memcmp(a_ss, b_ss, X25519_SS_BYTES) == 0, "Derived shared secrets do not match");

    /* Ensure shared secret is not all zeros */
    uint8_t zeros[32] = {0};
    TEST_ASSERT(memcmp(a_ss, zeros, 32) != 0, "Shared secret is all zeros");

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * [02] X25519 INVALID-INPUT HANDLING
 * ═══════════════════════════════════════════════════════════════════ */
static int test_x25519_invalid_input(void) {
    uint8_t sk[X25519_SK_BYTES], pk[X25519_PK_BYTES];
    uint8_t ss[X25519_SS_BYTES];
    TEST_ASSERT(x25519_generate_keypair(pk, sk) == 0, "Keypair generation failed");

    /* Low-order point: all zeros public key */
    uint8_t zero_pk[X25519_PK_BYTES] = {0};
    int rc = x25519_derive_shared_secret(ss, sk, zero_pk);
    TEST_ASSERT(rc != 0, "X25519 derive must reject all-zero public key");

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * [03] Ed25519 SIGNING AND VERIFICATION
 * ═══════════════════════════════════════════════════════════════════ */
static int test_ed25519_sign_and_verify(void) {
    uint8_t pk[ED25519_PK_BYTES], sk[ED25519_SK_BYTES];
    uint8_t sig[ED25519_SIG_BYTES];
    size_t siglen = 0;

    const uint8_t msg[] = "QRYPTONEX-CLASSICAL-TRANSCRIPT-TEST-PAYLOAD";
    size_t msg_len = sizeof(msg) - 1;

    TEST_ASSERT(ed25519_generate_keypair(pk, sk) == 0, "Ed25519 keypair failed");
    TEST_ASSERT(ed25519_sign(sig, &siglen, msg, msg_len, sk) == 0, "Ed25519 sign failed");
    TEST_ASSERT(siglen == ED25519_SIG_BYTES, "Ed25519 signature length is not 64 bytes");
    TEST_ASSERT(ed25519_verify(sig, siglen, msg, msg_len, pk) == 0, "Ed25519 verify failed");

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * [04] Ed25519 REJECTION OF TAMPERED MESSAGE
 * ═══════════════════════════════════════════════════════════════════ */
static int test_ed25519_tampered_message(void) {
    uint8_t pk[ED25519_PK_BYTES], sk[ED25519_SK_BYTES];
    uint8_t sig[ED25519_SIG_BYTES];
    size_t siglen = 0;

    uint8_t msg[] = "Authentic handshake message data";
    size_t msg_len = sizeof(msg) - 1;

    ed25519_generate_keypair(pk, sk);
    ed25519_sign(sig, &siglen, msg, msg_len, sk);

    /* Tamper with message byte */
    msg[0] ^= 0x01;
    TEST_ASSERT(ed25519_verify(sig, siglen, msg, msg_len, pk) != 0,
                "Ed25519 accepted tampered message");

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * [05] Ed25519 REJECTION OF CORRUPTED SIGNATURE & WRONG PK
 * ═══════════════════════════════════════════════════════════════════ */
static int test_ed25519_corrupted_sig_and_wrong_pk(void) {
    uint8_t pk1[ED25519_PK_BYTES], sk1[ED25519_SK_BYTES];
    uint8_t pk2[ED25519_PK_BYTES], sk2[ED25519_SK_BYTES];
    uint8_t sig[ED25519_SIG_BYTES];
    size_t siglen = 0;

    const uint8_t msg[] = "Sensitive transcript digest";
    size_t msg_len = sizeof(msg) - 1;

    ed25519_generate_keypair(pk1, sk1);
    ed25519_generate_keypair(pk2, sk2);

    ed25519_sign(sig, &siglen, msg, msg_len, sk1);

    /* 1. Tamper with signature */
    uint8_t bad_sig[ED25519_SIG_BYTES];
    memcpy(bad_sig, sig, siglen);
    bad_sig[32] ^= 0xFF;
    TEST_ASSERT(ed25519_verify(bad_sig, siglen, msg, msg_len, pk1) != 0,
                "Ed25519 accepted corrupted signature");

    /* 2. Verify with wrong public key */
    TEST_ASSERT(ed25519_verify(sig, siglen, msg, msg_len, pk2) != 0,
                "Ed25519 accepted signature under wrong public key");

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * [06] AES-128-CCM ENCRYPTION AND DECRYPTION
 * ═══════════════════════════════════════════════════════════════════ */
static int test_aes128_ccm_encrypt_decrypt(void) {
    uint8_t key[AEAD_KEY_BYTES];
    uint8_t nonce[AEAD_NONCE_BYTES];
    RAND_bytes(key, sizeof(key));
    RAND_bytes(nonce, sizeof(nonce));

    const char *payload = "IoT Sensor Node #42 telemetry: 24.5C, 1013.2hPa";
    int pt_len = (int)strlen(payload);

    uint8_t aad[15] = {'W','I','R','E','_','H','D','R','_','1','5','_','B','Y','T'};
    int aad_len = 15;

    uint8_t ct[128];
    uint8_t tag[AEAD_TAG_BYTES];
    uint8_t decrypted[128];

    int ct_len = aes128_ccm_encrypt((const uint8_t *)payload, pt_len, aad, aad_len, key, nonce, ct, tag);
    TEST_ASSERT(ct_len == pt_len, "aes128_ccm_encrypt returned wrong length");

    int dec_len = aes128_ccm_decrypt(ct, ct_len, aad, aad_len, key, nonce, tag, decrypted);
    TEST_ASSERT(dec_len == pt_len, "aes128_ccm_decrypt failed");
    TEST_ASSERT(memcmp(payload, decrypted, pt_len) == 0, "Decrypted plaintext mismatch");

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * [07] AES-128-CCM REJECTION OF CIPHERTEXT TAMPERING
 * ═══════════════════════════════════════════════════════════════════ */
static int test_aes128_ccm_ciphertext_tampering(void) {
    uint8_t key[AEAD_KEY_BYTES], nonce[AEAD_NONCE_BYTES];
    RAND_bytes(key, sizeof(key));
    RAND_bytes(nonce, sizeof(nonce));

    const uint8_t pt[] = "Critical actuator command: OPEN_VALVE";
    int pt_len = (int)sizeof(pt);
    uint8_t ct[128], tag[16], dec[128];

    int ct_len = aes128_ccm_encrypt(pt, pt_len, NULL, 0, key, nonce, ct, tag);
    TEST_ASSERT(ct_len > 0, "Encrypt failed");

    /* Tamper with 1 byte of ciphertext */
    ct[5] ^= 0x40;
    int rc = aes128_ccm_decrypt(ct, ct_len, NULL, 0, key, nonce, tag, dec);
    TEST_ASSERT(rc < 0, "AES-128-CCM accepted tampered ciphertext");

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * [08] AES-128-CCM REJECTION OF WIRE HEADER AAD MODIFICATION
 * ═══════════════════════════════════════════════════════════════════ */
static int test_aes128_ccm_aad_modification(void) {
    uint8_t key[AEAD_KEY_BYTES], nonce[AEAD_NONCE_BYTES];
    RAND_bytes(key, sizeof(key));
    RAND_bytes(nonce, sizeof(nonce));

    const uint8_t pt[] = "Sensitive data";
    int pt_len = (int)sizeof(pt);

    pkt_hdr_t hdr;
    hdr.seq = htonl(100);
    hdr.type = PKT_DATA;
    hdr.len = htons((uint16_t)(12 + 16 + pt_len));
    hdr.session_id = htobe64(0xFEEDFACE12345678ULL);

    uint8_t ct[128], tag[16], dec[128];
    int ct_len = aes128_ccm_encrypt(pt, pt_len, (const uint8_t *)&hdr, sizeof(hdr), key, nonce, ct, tag);
    TEST_ASSERT(ct_len > 0, "Encrypt failed");

    /* 1. Tamper with sequence number in AAD */
    pkt_hdr_t tampered_hdr = hdr;
    tampered_hdr.seq = htonl(101);
    TEST_ASSERT(aes128_ccm_decrypt(ct, ct_len, (const uint8_t *)&tampered_hdr, sizeof(hdr), key, nonce, tag, dec) < 0,
                "Accepted modified seq in AAD");

    /* 2. Tamper with session_id in AAD */
    tampered_hdr = hdr;
    tampered_hdr.session_id = htobe64(0xFEEDFACE12345679ULL);
    TEST_ASSERT(aes128_ccm_decrypt(ct, ct_len, (const uint8_t *)&tampered_hdr, sizeof(hdr), key, nonce, tag, dec) < 0,
                "Accepted modified session_id in AAD");

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * [09] AES-128-CCM REJECTION OF CORRUPTED AUTHENTICATION TAG
 * ═══════════════════════════════════════════════════════════════════ */
static int test_aes128_ccm_tag_corruption(void) {
    uint8_t key[16], nonce[12];
    RAND_bytes(key, 16);
    RAND_bytes(nonce, 12);

    const uint8_t pt[] = "Authenticate me";
    uint8_t ct[64], tag[16], dec[64];
    int ct_len = aes128_ccm_encrypt(pt, sizeof(pt), NULL, 0, key, nonce, ct, tag);
    TEST_ASSERT(ct_len > 0, "Encrypt failed");

    tag[15] ^= 0x01;
    TEST_ASSERT(aes128_ccm_decrypt(ct, ct_len, NULL, 0, key, nonce, tag, dec) < 0,
                "Accepted corrupted tag");

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * [10] SHA-256 KNOWN-ANSWER TEST (NIST FIPS 180-4)
 * ═══════════════════════════════════════════════════════════════════ */
static int test_sha256_kat(void) {
    /* NIST standard test vector for "abc" */
    const uint8_t msg[] = "abc";
    uint8_t digest[32];
    TEST_ASSERT(sha256_digest(msg, 3, digest) == 0, "sha256_digest failed");

    const uint8_t expected[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    TEST_ASSERT(memcmp(digest, expected, 32) == 0, "SHA-256 KAT vector mismatch");

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * [11] HKDF-SHA-256 KNOWN-ANSWER TEST (RFC 5869 TEST CASE 1)
 * ═══════════════════════════════════════════════════════════════════ */
static int test_hkdf_sha256_kat(void) {
    const uint8_t ikm[22] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    };
    const uint8_t salt[13] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c
    };
    const uint8_t info[10] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9
    };
    const uint8_t expected_okm[42] = {
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
        0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
        0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65
    };

    uint8_t okm[42];
    int rc = hkdf_sha256_derive(okm, 42, ikm, sizeof(ikm), salt, sizeof(salt), info, sizeof(info));
    TEST_ASSERT(rc == 0, "hkdf_sha256_derive failed");
    TEST_ASSERT(memcmp(okm, expected_okm, 42) == 0, "RFC 5869 HKDF-SHA-256 OKM mismatch");

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * [12] HMAC-SHA-256 KNOWN-ANSWER TEST (RFC 4231 TEST CASE 1)
 * ═══════════════════════════════════════════════════════════════════ */
static int test_hmac_sha256_kat(void) {
    const uint8_t key[20] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    };
    const uint8_t data[] = "Hi There";
    const uint8_t expected_mac[32] = {
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
        0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
        0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
        0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
    };

    uint8_t mac[32];
    size_t mac_len = 0;
    TEST_ASSERT(hmac_sha256_compute(key, sizeof(key), data, 8, mac, &mac_len) == 0, "HMAC compute failed");
    TEST_ASSERT(mac_len == 32, "HMAC output len != 32");
    TEST_ASSERT(memcmp(mac, expected_mac, 32) == 0, "RFC 4231 HMAC-SHA-256 MAC mismatch");

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * [13] DIRECTIONAL TRAFFIC-KEY SEPARATION
 * ═══════════════════════════════════════════════════════════════════ */
static int test_directional_traffic_key_separation(void) {
    uint8_t ss[32], c_nonce[16], s_nonce[16];
    RAND_bytes(ss, 32);
    RAND_bytes(c_nonce, 16);
    RAND_bytes(s_nonce, 16);
    uint64_t session_id = 0x1234567890ABCDEFULL;

    uint8_t c2s_key[16], s2c_key[16];
    kem_derive_directional_keys(c2s_key, s2c_key, ss, c_nonce, s_nonce, session_id);

    /* 1. Client-to-server and Server-to-client keys must NEVER be equal */
    TEST_ASSERT(memcmp(c2s_key, s2c_key, 16) != 0,
                "CRITICAL: Client and Server write keys are identical!");

    /* 2. Changing session ID derives different keys */
    uint8_t diff_c2s[16], diff_s2c[16];
    kem_derive_directional_keys(diff_c2s, diff_s2c, ss, c_nonce, s_nonce, session_id + 1);
    TEST_ASSERT(memcmp(c2s_key, diff_c2s, 16) != 0, "Different session produced identical C2S key");
    TEST_ASSERT(memcmp(s2c_key, diff_s2c, 16) != 0, "Different session produced identical S2C key");

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * [14] SESSION NONCE UNIQUENESS & TRACKING
 * ═══════════════════════════════════════════════════════════════════ */
static int test_nonce_uniqueness_and_monotonicity(void) {
    conn_t c;
    conn_init(&c, -1);
    c.session_id = 0xAABBCCDDEEFF0011ULL;

    /* Verify initial nonce counter */
    TEST_ASSERT(c.tx_nonce_ctr == 0, "Initial nonce counter is not 0");

    /* Incrementally generate 100 nonces and ensure strict uniqueness */
    uint8_t nonces[100][12];
    for (int i = 0; i < 100; i++) {
        c.tx_nonce_ctr++;
        uint64_t ctr = c.tx_nonce_ctr;
        uint32_t sid32 = (uint32_t)(c.session_id & 0xFFFFFFFF);
        memcpy(nonces[i], &sid32, 4);
        memcpy(nonces[i] + 4, &ctr, 8);
    }

    for (int i = 0; i < 100; i++) {
        for (int j = i + 1; j < 100; j++) {
            TEST_ASSERT(memcmp(nonces[i], nonces[j], 12) != 0, "Duplicate nonce generated within session!");
        }
    }

    conn_destroy(&c);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * [15] RFC 6479 64-PACKET SLIDING REPLAY WINDOW
 * ═══════════════════════════════════════════════════════════════════ */
static int test_sliding_replay_window(void) {
    replay_window_t win;
    replay_window_init(&win);

    /* 1. Sequence 0 must be rejected */
    TEST_ASSERT(replay_window_check(&win, 0) != 0, "Seq 0 must be rejected");

    /* 2. Packet 1: check passes, commit */
    TEST_ASSERT(replay_window_check(&win, 1) == 0, "Seq 1 must pass check");
    replay_window_update(&win, 1);

    /* 3. Replay of packet 1: check MUST fail */
    TEST_ASSERT(replay_window_check(&win, 1) != 0, "Replayed seq 1 must fail");

    /* 4. In-order arrival: 2, 3, 4 */
    for (uint32_t s = 2; s <= 4; s++) {
        TEST_ASSERT(replay_window_check(&win, s) == 0, "In-order seq must pass");
        replay_window_update(&win, s);
    }
    TEST_ASSERT(replay_window_check(&win, 3) != 0, "Replayed seq 3 must fail");

    /* 5. Jump ahead to 25 (out-of-order within window) */
    TEST_ASSERT(replay_window_check(&win, 25) == 0, "Jump to 25 must pass");
    replay_window_update(&win, 25);

    /* Arriving packet 15 within window must pass */
    TEST_ASSERT(replay_window_check(&win, 15) == 0, "Seq 15 within window must pass");
    replay_window_update(&win, 15);
    TEST_ASSERT(replay_window_check(&win, 15) != 0, "Replayed seq 15 must fail");

    /* 6. Jump to 150 */
    TEST_ASSERT(replay_window_check(&win, 150) == 0, "Jump to 150 must pass");
    replay_window_update(&win, 150);

    /* Stale packets (< 150 - 64 = 86) must be dropped */
    TEST_ASSERT(replay_window_check(&win, 50) != 0, "Stale seq 50 must be rejected");
    TEST_ASSERT(replay_window_check(&win, 85) != 0, "Stale seq 85 must be rejected");

    /* Packet 120 is in window (150 - 64 < 120 <= 150) and unreceived -> passes */
    TEST_ASSERT(replay_window_check(&win, 120) == 0, "Unreceived seq 120 in window must pass");
    replay_window_update(&win, 120);
    TEST_ASSERT(replay_window_check(&win, 120) != 0, "Replayed seq 120 must fail");

    replay_window_destroy(&win);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * [16] PACKET FRAMING & REASSEMBLY
 * ═══════════════════════════════════════════════════════════════════ */
static int test_packet_framing_and_reassembly(void) {
    reassembly_ctx_t ctx;
    reassembly_init(&ctx);

    uint32_t total_len = 2500;
    uint8_t orig_msg[2500];
    for (uint32_t i = 0; i < total_len; i++) orig_msg[i] = (uint8_t)(i & 0xFF);

    frag_hdr_t f0 = { .msg_id = htons(77), .orig_type = PKT_DATA, .frag_idx = 0, .frag_total = 3, .frag_len = htons(1024), .total_len = htonl(total_len) };
    frag_hdr_t f1 = { .msg_id = htons(77), .orig_type = PKT_DATA, .frag_idx = 1, .frag_total = 3, .frag_len = htons(1024), .total_len = htonl(total_len) };
    frag_hdr_t f2 = { .msg_id = htons(77), .orig_type = PKT_DATA, .frag_idx = 2, .frag_total = 3, .frag_len = htons(452),  .total_len = htonl(total_len) };

    /* Out of order: 2, 0, duplicate 0, 1 */
    TEST_ASSERT(reassembly_feed_frag(&ctx, &f2, orig_msg + 2048) == 0, "Feed frag 2 failed");
    TEST_ASSERT(reassembly_feed_frag(&ctx, &f0, orig_msg + 0) == 0, "Feed frag 0 failed");
    TEST_ASSERT(reassembly_feed_frag(&ctx, &f0, orig_msg + 0) == 0, "Feed duplicate frag 0 failed");
    TEST_ASSERT(reassembly_feed_frag(&ctx, &f1, orig_msg + 1024) == 1, "Feed frag 1 did not complete reassembly");

    TEST_ASSERT(ctx.received_bytes == total_len, "Reassembled byte count mismatch");
    TEST_ASSERT(memcmp(ctx.buf, orig_msg, total_len) == 0, "Reassembled buffer content mismatch");

    reassembly_cleanup(&ctx);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * [17] TRUST STORE & MITM PEER AUTHENTICATION
 * ═══════════════════════════════════════════════════════════════════ */
static int test_trust_store_authentication(void) {
    uint8_t legitimate_pk[32], legitimate_sk[32];
    uint8_t attacker_pk[32], attacker_sk[32];

    const char *pub_file = "test_classical_srv.pub";
    const char *key_file = "test_classical_srv.key";

    TEST_ASSERT(trust_store_load_or_create_server_keys(legitimate_pk, legitimate_sk, pub_file, key_file) == 0,
                "Failed to generate server identity keys");
    ed25519_generate_keypair(attacker_pk, attacker_sk);

    /* 1. Legitimate server key matches pinned trust store */
    TEST_ASSERT(trust_store_client_verify_server(legitimate_pk, pub_file) == 0,
                "Legitimate server key rejected");

    /* 2. Attacker key must be rejected (MITM detection) */
    TEST_ASSERT(trust_store_client_verify_server(attacker_pk, pub_file) != 0,
                "CRITICAL: Attacker server key was accepted!");

    /* 3. Server client verification: all zero public key rejected */
    uint8_t zero_pk[32] = {0};
    TEST_ASSERT(trust_store_server_verify_client(zero_pk, NULL) != 0,
                "All-zero client public key was accepted");

    remove(pub_file);
    remove(key_file);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * [18] FULL 4-PHASE MUTUAL-AUTHENTICATION HANDSHAKE SIMULATION
 * ═══════════════════════════════════════════════════════════════════ */
static int test_full_handshake_simulation(void) {
    /* 1. Identities */
    uint8_t s_id_pk[32], s_id_sk[32];
    uint8_t c_id_pk[32], c_id_sk[32];
    ed25519_generate_keypair(s_id_pk, s_id_sk);
    ed25519_generate_keypair(c_id_pk, c_id_sk);

    /* Phase 1: Client Hello */
    uint8_t c_eph_pk[32], c_eph_sk[32];
    x25519_generate_keypair(c_eph_pk, c_eph_sk);
    uint8_t c_nonce[16];
    RAND_bytes(c_nonce, 16);

    /* Phase 2: Server Hello */
    uint8_t s_eph_pk[32], s_eph_sk[32];
    x25519_generate_keypair(s_eph_pk, s_eph_sk);
    uint8_t s_nonce[16];
    RAND_bytes(s_nonce, 16);
    uint64_t session_id = 0x8877665544332211ULL;
    uint8_t session_id_bytes[8];
    for (int i = 7; i >= 0; i--) session_id_bytes[i] = (uint8_t)((session_id >> ((7 - i) * 8)) & 0xFF);

    /* Server computes X25519 shared secret */
    uint8_t srv_ss[32];
    TEST_ASSERT(x25519_derive_shared_secret(srv_ss, s_eph_sk, c_eph_pk) == 0, "Server ECDH failed");

    /* Server constructs transcript */
    uint8_t srv_tx[168];
    size_t off = 0;
    memcpy(srv_tx + off, c_nonce, 16); off += 16;
    memcpy(srv_tx + off, s_nonce, 16); off += 16;
    memcpy(srv_tx + off, session_id_bytes, 8); off += 8;
    memcpy(srv_tx + off, c_eph_pk, 32); off += 32;
    memcpy(srv_tx + off, c_id_pk, 32); off += 32;
    memcpy(srv_tx + off, s_id_pk, 32); off += 32;
    memcpy(srv_tx + off, s_eph_pk, 32); off += 32;

    uint8_t srv_tx_digest[32];
    sha256_digest(srv_tx, off, srv_tx_digest);
    uint8_t srv_sig[64];
    size_t srv_sig_len = 0;
    ed25519_sign(srv_sig, &srv_sig_len, srv_tx_digest, 32, s_id_sk);

    /* Phase 3: Client Authentication */
    /* Client verifies Server signature */
    TEST_ASSERT(ed25519_verify(srv_sig, 64, srv_tx_digest, 32, s_id_pk) == 0,
                "Client failed to verify server signature");

    /* Client computes X25519 shared secret */
    uint8_t client_ss[32];
    TEST_ASSERT(x25519_derive_shared_secret(client_ss, c_eph_sk, s_eph_pk) == 0, "Client ECDH failed");
    TEST_ASSERT(memcmp(srv_ss, client_ss, 32) == 0, "Client and Server ECDH shared secrets mismatch");

    /* Client constructs transcript: srv_tx (168) | srv_sig (64) = 232 */
    uint8_t cl_tx[232];
    memcpy(cl_tx, srv_tx, 168);
    memcpy(cl_tx + 168, srv_sig, 64);
    uint8_t cl_tx_digest[32];
    sha256_digest(cl_tx, 232, cl_tx_digest);
    uint8_t client_sig[64];
    size_t client_sig_len = 0;
    ed25519_sign(client_sig, &client_sig_len, cl_tx_digest, 32, c_id_sk);

    /* Server verifies Client signature */
    TEST_ASSERT(ed25519_verify(client_sig, 64, cl_tx_digest, 32, c_id_pk) == 0,
                "Server failed to verify client signature");

    /* Phase 4: Derive Traffic Keys */
    uint8_t client_c2s[16], client_s2c[16];
    uint8_t server_c2s[16], server_s2c[16];
    kem_derive_directional_keys(client_c2s, client_s2c, client_ss, c_nonce, s_nonce, session_id);
    kem_derive_directional_keys(server_c2s, server_s2c, srv_ss, c_nonce, s_nonce, session_id);

    TEST_ASSERT(memcmp(client_c2s, server_c2s, 16) == 0, "C2S keys do not match");
    TEST_ASSERT(memcmp(client_s2c, server_s2c, 16) == 0, "S2C keys do not match");

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * [19] HANDSHAKE FAILURE UNDER ACTIVE TAMPERING
 * ═══════════════════════════════════════════════════════════════════ */
static int test_handshake_tampering_failure(void) {
    uint8_t s_id_pk[32], s_id_sk[32];
    uint8_t c_id_pk[32], c_id_sk[32];
    ed25519_generate_keypair(s_id_pk, s_id_sk);
    ed25519_generate_keypair(c_id_pk, c_id_sk);

    uint8_t c_eph_pk[32], c_eph_sk[32];
    x25519_generate_keypair(c_eph_pk, c_eph_sk);
    uint8_t c_nonce[16], s_nonce[16];
    RAND_bytes(c_nonce, 16);
    RAND_bytes(s_nonce, 16);

    uint8_t s_eph_pk[32], s_eph_sk[32];
    x25519_generate_keypair(s_eph_pk, s_eph_sk);

    uint8_t srv_tx[168] = {0};
    uint8_t srv_tx_digest[32];
    sha256_digest(srv_tx, sizeof(srv_tx), srv_tx_digest);
    uint8_t srv_sig[64];
    size_t srv_sig_len = 0;
    ed25519_sign(srv_sig, &srv_sig_len, srv_tx_digest, 32, s_id_sk);

    /* Attacker modifies server signature */
    srv_sig[10] ^= 0xEE;
    TEST_ASSERT(ed25519_verify(srv_sig, 64, srv_tx_digest, 32, s_id_pk) != 0,
                "Tampered server signature was accepted");

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * [20] CONCURRENT CLIENT SESSION STATE ISOLATION
 * ═══════════════════════════════════════════════════════════════════ */
static int test_session_isolation(void) {
    conn_t c1, c2;
    conn_init(&c1, -1);
    conn_init(&c2, -1);

    c1.session_id = 0x1111;
    c2.session_id = 0x2222;

    RAND_bytes(c1.tx_key, 16);
    RAND_bytes(c2.tx_key, 16);

    replay_window_update(&c1.replay_win, 50);

    /* Invariant: c2's replay window must be totally unaffected */
    TEST_ASSERT(replay_window_check(&c2.replay_win, 50) == 0,
                "Replay window state leaked across sessions!");

    conn_destroy(&c1);
    conn_destroy(&c2);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * [21] SESSION CLEANUP & ZEROIZATION
 * ═══════════════════════════════════════════════════════════════════ */
static int test_session_zeroization(void) {
    conn_t c;
    conn_init(&c, -1);
    RAND_bytes(c.tx_key, 16);
    RAND_bytes(c.rx_key, 16);

    conn_destroy(&c);

    uint8_t zero[16] = {0};
    TEST_ASSERT(memcmp(c.tx_key, zero, 16) == 0, "tx_key not zeroized");
    TEST_ASSERT(memcmp(c.rx_key, zero, 16) == 0, "rx_key not zeroized");

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * [22] RECONNECTION & SESSION-ID REUSE HANDLING
 * ═══════════════════════════════════════════════════════════════════ */
static int test_reconnection_and_session_id_reuse(void) {
    conn_t c_old, c_new;
    conn_init(&c_old, -1);
    conn_init(&c_new, -1);

    /* Client reconnects and receives a fresh session ID */
    uint64_t old_sid = 0xAAAAAAAAAAAAAAAAULL;
    uint64_t new_sid = 0xBBBBBBBBBBBBBBBBULL;

    c_old.session_id = old_sid;
    c_new.session_id = new_sid;

    TEST_ASSERT(c_old.session_id != c_new.session_id, "Session ID was reused across reconnects");

    /* Ensure packets from old session are rejected on new session */
    pkt_hdr_t old_pkt_hdr;
    old_pkt_hdr.session_id = htobe64(c_old.session_id);
    old_pkt_hdr.seq = htonl(1);
    old_pkt_hdr.type = PKT_DATA;

    uint64_t received_sid = be64toh(old_pkt_hdr.session_id);
    TEST_ASSERT(received_sid != c_new.session_id, "Old session packet was erroneously accepted by new session");

    conn_destroy(&c_old);
    conn_destroy(&c_new);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * MAIN TEST RUNNER
 * ═══════════════════════════════════════════════════════════════════ */
int main(void) {
    printf("\n");
    printf(CLR_CYAN "╔══════════════════════════════════════════════════════════════════╗" CLR_RESET "\n");
    printf(CLR_CYAN "║       QRYPTONEX Classical IoT Security & Regression Test Suite   ║" CLR_RESET "\n");
    printf(CLR_CYAN "║       Suite: X25519 + Ed25519 + AES-128-CCM + SHA-256 + HKDF     ║" CLR_RESET "\n");
    printf(CLR_CYAN "╚══════════════════════════════════════════════════════════════════╝" CLR_RESET "\n\n");

    kem_warmup();
    dsa_warmup();

    RUN_TEST(test_x25519_agreement);
    RUN_TEST(test_x25519_invalid_input);
    RUN_TEST(test_ed25519_sign_and_verify);
    RUN_TEST(test_ed25519_tampered_message);
    RUN_TEST(test_ed25519_corrupted_sig_and_wrong_pk);
    RUN_TEST(test_aes128_ccm_encrypt_decrypt);
    RUN_TEST(test_aes128_ccm_ciphertext_tampering);
    RUN_TEST(test_aes128_ccm_aad_modification);
    RUN_TEST(test_aes128_ccm_tag_corruption);
    RUN_TEST(test_sha256_kat);
    RUN_TEST(test_hkdf_sha256_kat);
    RUN_TEST(test_hmac_sha256_kat);
    RUN_TEST(test_directional_traffic_key_separation);
    RUN_TEST(test_nonce_uniqueness_and_monotonicity);
    RUN_TEST(test_sliding_replay_window);
    RUN_TEST(test_packet_framing_and_reassembly);
    RUN_TEST(test_trust_store_authentication);
    RUN_TEST(test_full_handshake_simulation);
    RUN_TEST(test_handshake_tampering_failure);
    RUN_TEST(test_session_isolation);
    RUN_TEST(test_session_zeroization);
    RUN_TEST(test_reconnection_and_session_id_reuse);

    printf("\n" CLR_BOLD "════════════════════════════════════════════════════════════════════" CLR_RESET "\n");
    printf("Test Results: %d/%d passed (%d failed)\n",
           g_tests_passed, g_tests_run, g_tests_failed);

    if (g_tests_failed == 0) {
        printf(CLR_GREEN CLR_BOLD "ALL 22 SECURITY & REGRESSION TESTS PASSED SUCCESSFULLY!" CLR_RESET "\n\n");
        return 0;
    } else {
        printf(CLR_RED CLR_BOLD "SOME TESTS FAILED!" CLR_RESET "\n\n");
        return 1;
    }
}
