/*
 * hybrid/tests/test_hybrid_kdf.c
 *
 * Automated test suite for SHA-384 and HKDF-SHA-384 (RFC 5869).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hybrid_kdf.h"

#define CLR_RESET   "\033[0m"
#define CLR_BOLD    "\033[1m"
#define CLR_GREEN   "\033[1;32m"
#define CLR_RED     "\033[1;31m"

static int g_failed = 0;

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("\n    " CLR_RED "✗ FAILED: %s (line %d)" CLR_RESET "\n", msg, __LINE__); \
        g_failed = 1; \
        return -1; \
    } \
} while (0)

#define RUN_TEST(fn) do { \
    printf(CLR_BOLD "  %-55s" CLR_RESET, #fn); \
    fflush(stdout); \
    if (fn() == 0) { \
        printf(CLR_GREEN " PASS" CLR_RESET "\n"); \
    } \
} while (0)

/* [01] NIST FIPS 180-4 SHA-384 KAT for "abc" */
static int test_sha384_kat_abc(void) {
    /* NIST SHA-384 KAT:
     * SHA-384("abc") = cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7
     */
    static const uint8_t expected[48] = {
        0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b,
        0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
        0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
        0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
        0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23,
        0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7
    };

    uint8_t out[48];
    TEST_ASSERT(hybrid_sha384_digest("abc", 3, out) == HYBRID_SUCCESS, "Digest failed");
    TEST_ASSERT(memcmp(out, expected, 48) == 0, "SHA-384 KAT mismatch");
    return 0;
}

/* [02] RFC 5869 HKDF-SHA-384 Known-Answer Test */
static int test_hkdf_sha384_kat(void) {
    uint8_t ikm[22];
    memset(ikm, 0x0b, sizeof(ikm));

    uint8_t salt[13];
    for (int i = 0; i < 13; i++) salt[i] = (uint8_t)i;

    uint8_t info[10];
    for (int i = 0; i < 10; i++) info[i] = (uint8_t)(0xf0 + i);

    static const uint8_t expected_prk[48] = {
        0x70, 0x4b, 0x39, 0x99, 0x07, 0x79, 0xce, 0x1d,
        0xc5, 0x48, 0x05, 0x2c, 0x7d, 0xc3, 0x9f, 0x30,
        0x35, 0x70, 0xdd, 0x13, 0xfb, 0x39, 0xf7, 0xac,
        0xc5, 0x64, 0x68, 0x0b, 0xef, 0x80, 0xe8, 0xde,
        0xc7, 0x0e, 0xe9, 0xa7, 0xe1, 0xf3, 0xe2, 0x93,
        0xef, 0x68, 0xec, 0xeb, 0x07, 0x2a, 0x5a, 0xde
    };

    static const uint8_t expected_okm[42] = {
        0x9b, 0x50, 0x97, 0xa8, 0x60, 0x38, 0xb8, 0x05,
        0x30, 0x90, 0x76, 0xa4, 0x4b, 0x3a, 0x9f, 0x38,
        0x06, 0x3e, 0x25, 0xb5, 0x16, 0xdc, 0xbf, 0x36,
        0x9f, 0x39, 0x4c, 0xfa, 0xb4, 0x36, 0x85, 0xf7,
        0x48, 0xb6, 0x45, 0x77, 0x63, 0xe4, 0xf0, 0x20,
        0x4f, 0xc5
    };

    uint8_t prk[48];
    TEST_ASSERT(hybrid_hkdf_extract(prk, salt, sizeof(salt), ikm, sizeof(ikm)) == HYBRID_SUCCESS, "HKDF-Extract");
    TEST_ASSERT(memcmp(prk, expected_prk, 48) == 0, "PRK mismatch");

    uint8_t okm[42];
    TEST_ASSERT(hybrid_hkdf_expand(okm, sizeof(okm), prk, info, sizeof(info)) == HYBRID_SUCCESS, "HKDF-Expand");
    TEST_ASSERT(memcmp(okm, expected_okm, 42) == 0, "OKM mismatch");

    /* Also verify full derive returns matching OKM */
    uint8_t okm2[42];
    TEST_ASSERT(hybrid_hkdf_derive(okm2, sizeof(okm2), ikm, sizeof(ikm), salt, sizeof(salt), info, sizeof(info)) == HYBRID_SUCCESS, "HKDF-Derive");
    TEST_ASSERT(memcmp(okm2, expected_okm, 42) == 0, "Full derive mismatch");

    return 0;
}

/* [03] Directional Traffic Key Separation (C2S != S2C) */
static int test_directional_traffic_key_separation(void) {
    uint8_t client_write_key[HYBRID_TRAFFIC_KEY_BYTES];
    uint8_t server_write_key[HYBRID_TRAFFIC_KEY_BYTES];
    uint8_t combined_ikm[HYBRID_IKM_BYTES];
    uint8_t transcript_hash[HYBRID_SHA384_DIGEST_BYTES];
    uint8_t client_nonce[HYBRID_SESSION_NONCE_BYTES];
    uint8_t server_nonce[HYBRID_SESSION_NONCE_BYTES];
    uint64_t session_id = 0x1122334455667788ULL;

    memset(combined_ikm, 0x77, sizeof(combined_ikm));
    memset(transcript_hash, 0x88, sizeof(transcript_hash));
    memset(client_nonce, 0x01, sizeof(client_nonce));
    memset(server_nonce, 0x02, sizeof(server_nonce));

    TEST_ASSERT(hybrid_kdf_derive_traffic_keys(client_write_key, server_write_key,
                                              combined_ikm, transcript_hash,
                                              client_nonce, server_nonce,
                                              session_id) == HYBRID_SUCCESS, "Traffic keys derive");

    /* C2S and S2C keys must be strictly different */
    TEST_ASSERT(memcmp(client_write_key, server_write_key, HYBRID_TRAFFIC_KEY_BYTES) != 0,
                "Client and server traffic keys are identical");

    /* Changing transcript hash must change both keys */
    uint8_t c_key2[HYBRID_TRAFFIC_KEY_BYTES], s_key2[HYBRID_TRAFFIC_KEY_BYTES];
    transcript_hash[0] ^= 0x01;
    TEST_ASSERT(hybrid_kdf_derive_traffic_keys(c_key2, s_key2,
                                              combined_ikm, transcript_hash,
                                              client_nonce, server_nonce,
                                              session_id) == HYBRID_SUCCESS, "Traffic keys derive 2");

    TEST_ASSERT(memcmp(client_write_key, c_key2, HYBRID_TRAFFIC_KEY_BYTES) != 0, "Client key did not change with transcript");
    TEST_ASSERT(memcmp(server_write_key, s_key2, HYBRID_TRAFFIC_KEY_BYTES) != 0, "Server key did not change with transcript");

    return 0;
}

int main(void) {
    printf("\n=== Running Test Suite: test_hybrid_kdf ===\n");
    RUN_TEST(test_sha384_kat_abc);
    RUN_TEST(test_hkdf_sha384_kat);
    RUN_TEST(test_directional_traffic_key_separation);

    if (g_failed) {
        printf(CLR_RED "FAILED: Some tests in test_hybrid_kdf failed!" CLR_RESET "\n\n");
        return 1;
    }
    printf(CLR_GREEN "SUCCESS: All tests in test_hybrid_kdf passed!" CLR_RESET "\n\n");
    return 0;
}
