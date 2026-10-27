/*
 * hybrid/tests/test_hybrid_kex.c
 *
 * Automated test suite for Hybrid Key Establishment (X25519 + ML-KEM-768).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hybrid_kex.h"
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

/* [01] Both parties derive identical hybrid session secrets */
static int test_hybrid_kex_shared_agreement(void) {
    hybrid_kex_public_key_t alice_pk;
    hybrid_kex_secret_key_t alice_sk;
    hybrid_kex_ciphertext_t bob_ct;
    uint8_t alice_ikm[HYBRID_IKM_BYTES];
    uint8_t bob_ikm[HYBRID_IKM_BYTES];

    TEST_ASSERT(hybrid_kex_generate_keypair(&alice_pk, &alice_sk) == HYBRID_SUCCESS, "Alice keypair");
    TEST_ASSERT(hybrid_kex_encapsulate(&bob_ct, bob_ikm, &alice_pk) == HYBRID_SUCCESS, "Bob encaps");
    TEST_ASSERT(hybrid_kex_decapsulate(alice_ikm, &bob_ct, &alice_sk) == HYBRID_SUCCESS, "Alice decaps");

    TEST_ASSERT(memcmp(alice_ikm, bob_ikm, HYBRID_IKM_BYTES) == 0, "Derived IKM mismatch");

    /* Ensure output is not all zeros */
    uint8_t zeros[HYBRID_IKM_BYTES] = {0};
    TEST_ASSERT(memcmp(alice_ikm, zeros, HYBRID_IKM_BYTES) != 0, "Combined IKM is all zeros");

    return 0;
}

/* [02] Changing X25519 shared secret changes final derived key */
static int test_x25519_secret_contributes_to_final_key(void) {
    uint8_t ss_x25519_1[32], ss_x25519_2[32];
    uint8_t ss_mlkem[32];
    uint8_t ikm1[HYBRID_IKM_BYTES], ikm2[HYBRID_IKM_BYTES];
    uint8_t key1[32], key2[32];

    memset(ss_x25519_1, 0x11, 32);
    memset(ss_x25519_2, 0x22, 32);
    memset(ss_mlkem,    0x33, 32);

    TEST_ASSERT(hybrid_kex_encode_ikm(ikm1, ss_x25519_1, ss_mlkem) == HYBRID_SUCCESS, "Encode 1");
    TEST_ASSERT(hybrid_kex_encode_ikm(ikm2, ss_x25519_2, ss_mlkem) == HYBRID_SUCCESS, "Encode 2");

    uint8_t salt[48] = {0};
    TEST_ASSERT(hybrid_hkdf_derive(key1, 32, ikm1, HYBRID_IKM_BYTES, salt, 48, (const uint8_t *)"info", 4) == HYBRID_SUCCESS, "HKDF 1");
    TEST_ASSERT(hybrid_hkdf_derive(key2, 32, ikm2, HYBRID_IKM_BYTES, salt, 48, (const uint8_t *)"info", 4) == HYBRID_SUCCESS, "HKDF 2");

    TEST_ASSERT(memcmp(key1, key2, 32) != 0, "Derived key did not change when X25519 changed");
    return 0;
}

/* [03] Changing ML-KEM shared secret changes final derived key */
static int test_mlkem_secret_contributes_to_final_key(void) {
    uint8_t ss_x25519[32];
    uint8_t ss_mlkem_1[32], ss_mlkem_2[32];
    uint8_t ikm1[HYBRID_IKM_BYTES], ikm2[HYBRID_IKM_BYTES];
    uint8_t key1[32], key2[32];

    memset(ss_x25519,   0xAA, 32);
    memset(ss_mlkem_1,  0xBB, 32);
    memset(ss_mlkem_2,  0xCC, 32);

    TEST_ASSERT(hybrid_kex_encode_ikm(ikm1, ss_x25519, ss_mlkem_1) == HYBRID_SUCCESS, "Encode 1");
    TEST_ASSERT(hybrid_kex_encode_ikm(ikm2, ss_x25519, ss_mlkem_2) == HYBRID_SUCCESS, "Encode 2");

    uint8_t salt[48] = {0};
    TEST_ASSERT(hybrid_hkdf_derive(key1, 32, ikm1, HYBRID_IKM_BYTES, salt, 48, (const uint8_t *)"info", 4) == HYBRID_SUCCESS, "HKDF 1");
    TEST_ASSERT(hybrid_hkdf_derive(key2, 32, ikm2, HYBRID_IKM_BYTES, salt, 48, (const uint8_t *)"info", 4) == HYBRID_SUCCESS, "HKDF 2");

    TEST_ASSERT(memcmp(key1, key2, 32) != 0, "Derived key did not change when ML-KEM changed");
    return 0;
}

/* [04] All-zero X25519 shared secret is rejected (RFC 7748 contributory check) */
static int test_x25519_all_zero_rejection(void) {
    uint8_t sk[HYBRID_X25519_SK_BYTES];
    uint8_t bad_peer_pk[HYBRID_X25519_PK_BYTES] = {0}; /* Point of order 0 */
    uint8_t ss[HYBRID_X25519_SS_BYTES];

    memset(sk, 0x42, sizeof(sk));
    int rc = hybrid_x25519_shared_secret(ss, sk, bad_peer_pk);
    TEST_ASSERT(rc != HYBRID_SUCCESS, "All-zero X25519 input was not rejected");
    return 0;
}

/* [05] Invalid public keys and null arguments rejected */
static int test_hybrid_kex_invalid_args(void) {
    hybrid_kex_public_key_t pk;
    hybrid_kex_secret_key_t sk;
    hybrid_kex_ciphertext_t ct;
    uint8_t ikm[HYBRID_IKM_BYTES];

    TEST_ASSERT(hybrid_kex_generate_keypair(NULL, &sk) == HYBRID_ERR_INVALID_ARG, "Null pk");
    TEST_ASSERT(hybrid_kex_generate_keypair(&pk, NULL) == HYBRID_ERR_INVALID_ARG, "Null sk");
    TEST_ASSERT(hybrid_kex_encapsulate(NULL, ikm, &pk) == HYBRID_ERR_INVALID_ARG, "Null ct");
    TEST_ASSERT(hybrid_kex_encapsulate(&ct, NULL, &pk) == HYBRID_ERR_INVALID_ARG, "Null ikm");
    TEST_ASSERT(hybrid_kex_encapsulate(&ct, ikm, NULL) == HYBRID_ERR_INVALID_ARG, "Null peer_pk");
    TEST_ASSERT(hybrid_kex_decapsulate(NULL, &ct, &sk) == HYBRID_ERR_INVALID_ARG, "Null ikm");

    return 0;
}

int main(void) {
    printf("\n=== Running Test Suite: test_hybrid_kex ===\n");
    RUN_TEST(test_hybrid_kex_shared_agreement);
    RUN_TEST(test_x25519_secret_contributes_to_final_key);
    RUN_TEST(test_mlkem_secret_contributes_to_final_key);
    RUN_TEST(test_x25519_all_zero_rejection);
    RUN_TEST(test_hybrid_kex_invalid_args);

    if (g_failed) {
        printf(CLR_RED "FAILED: Some tests in test_hybrid_kex failed!" CLR_RESET "\n\n");
        return 1;
    }
    printf(CLR_GREEN "SUCCESS: All tests in test_hybrid_kex passed!" CLR_RESET "\n\n");
    return 0;
}
