/*
 * hybrid/tests/test_hybrid_signatures.c
 *
 * Automated test suite for Hybrid Dual Signatures (Ed25519 + ML-DSA-65).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hybrid_signature.h"

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

/* [01] Both valid signatures are accepted */
static int test_hybrid_signature_sign_and_verify(void) {
    hybrid_identity_pk_t pk;
    hybrid_identity_sk_t sk;
    hybrid_signature_t sig;
    uint8_t digest[HYBRID_SHA384_DIGEST_BYTES];

    memset(digest, 0x5A, sizeof(digest));

    TEST_ASSERT(hybrid_ed25519_keygen(pk.ed25519_pk, sk.ed25519_sk) == HYBRID_SUCCESS, "Ed25519 keygen");
    TEST_ASSERT(hybrid_mldsa65_keygen(pk.mldsa_pk, sk.mldsa_sk) == HYBRID_SUCCESS, "ML-DSA-65 keygen");

    TEST_ASSERT(hybrid_sign_transcript(&sig, digest, &sk) == HYBRID_SUCCESS, "Sign transcript");
    TEST_ASSERT(hybrid_verify_transcript(&sig, digest, &pk) == HYBRID_SUCCESS, "Verify transcript");

    return 0;
}

/* [02] Corrupted Ed25519 signature is rejected */
static int test_corrupted_ed25519_signature_rejected(void) {
    hybrid_identity_pk_t pk;
    hybrid_identity_sk_t sk;
    hybrid_signature_t sig;
    uint8_t digest[HYBRID_SHA384_DIGEST_BYTES];

    memset(digest, 0x5A, sizeof(digest));
    TEST_ASSERT(hybrid_ed25519_keygen(pk.ed25519_pk, sk.ed25519_sk) == HYBRID_SUCCESS, "Keygen");
    TEST_ASSERT(hybrid_mldsa65_keygen(pk.mldsa_pk, sk.mldsa_sk) == HYBRID_SUCCESS, "Keygen");
    TEST_ASSERT(hybrid_sign_transcript(&sig, digest, &sk) == HYBRID_SUCCESS, "Sign");

    /* Flip a byte in Ed25519 signature */
    sig.ed25519_sig[0] ^= 0xFF;

    TEST_ASSERT(hybrid_verify_transcript(&sig, digest, &pk) == HYBRID_ERR_SIG_VERIFY_FAIL, "Did not reject bad Ed25519");
    return 0;
}

/* [03] Corrupted ML-DSA-65 signature is rejected */
static int test_corrupted_mldsa_signature_rejected(void) {
    hybrid_identity_pk_t pk;
    hybrid_identity_sk_t sk;
    hybrid_signature_t sig;
    uint8_t digest[HYBRID_SHA384_DIGEST_BYTES];

    memset(digest, 0x5A, sizeof(digest));
    TEST_ASSERT(hybrid_ed25519_keygen(pk.ed25519_pk, sk.ed25519_sk) == HYBRID_SUCCESS, "Keygen");
    TEST_ASSERT(hybrid_mldsa65_keygen(pk.mldsa_pk, sk.mldsa_sk) == HYBRID_SUCCESS, "Keygen");
    TEST_ASSERT(hybrid_sign_transcript(&sig, digest, &sk) == HYBRID_SUCCESS, "Sign");

    /* Flip a byte in ML-DSA-65 signature */
    sig.mldsa_sig[100] ^= 0xFF;

    TEST_ASSERT(hybrid_verify_transcript(&sig, digest, &pk) == HYBRID_ERR_SIG_VERIFY_FAIL, "Did not reject bad ML-DSA");
    return 0;
}

/* [04] Tampered transcript digest causes verification failure */
static int test_tampered_transcript_digest_rejected(void) {
    hybrid_identity_pk_t pk;
    hybrid_identity_sk_t sk;
    hybrid_signature_t sig;
    uint8_t digest[HYBRID_SHA384_DIGEST_BYTES];
    uint8_t tampered[HYBRID_SHA384_DIGEST_BYTES];

    memset(digest, 0x5A, sizeof(digest));
    memcpy(tampered, digest, sizeof(digest));
    tampered[0] ^= 0x01;

    TEST_ASSERT(hybrid_ed25519_keygen(pk.ed25519_pk, sk.ed25519_sk) == HYBRID_SUCCESS, "Keygen");
    TEST_ASSERT(hybrid_mldsa65_keygen(pk.mldsa_pk, sk.mldsa_sk) == HYBRID_SUCCESS, "Keygen");
    TEST_ASSERT(hybrid_sign_transcript(&sig, digest, &sk) == HYBRID_SUCCESS, "Sign");

    TEST_ASSERT(hybrid_verify_transcript(&sig, tampered, &pk) == HYBRID_ERR_SIG_VERIFY_FAIL, "Did not reject tampered digest");
    return 0;
}

/* [05] Identity-key substitution is rejected */
static int test_identity_substitution_rejected(void) {
    hybrid_identity_pk_t pk1, pk2;
    hybrid_identity_sk_t sk1, sk2;
    hybrid_signature_t sig;
    uint8_t digest[HYBRID_SHA384_DIGEST_BYTES];

    memset(digest, 0x5A, sizeof(digest));
    TEST_ASSERT(hybrid_ed25519_keygen(pk1.ed25519_pk, sk1.ed25519_sk) == HYBRID_SUCCESS, "Keygen 1");
    TEST_ASSERT(hybrid_mldsa65_keygen(pk1.mldsa_pk, sk1.mldsa_sk) == HYBRID_SUCCESS, "Keygen 1");
    TEST_ASSERT(hybrid_ed25519_keygen(pk2.ed25519_pk, sk2.ed25519_sk) == HYBRID_SUCCESS, "Keygen 2");
    TEST_ASSERT(hybrid_mldsa65_keygen(pk2.mldsa_pk, sk2.mldsa_sk) == HYBRID_SUCCESS, "Keygen 2");

    TEST_ASSERT(hybrid_sign_transcript(&sig, digest, &sk1) == HYBRID_SUCCESS, "Sign 1");

    /* Verifying with pk2 must fail */
    TEST_ASSERT(hybrid_verify_transcript(&sig, digest, &pk2) == HYBRID_ERR_SIG_VERIFY_FAIL, "Substituted key accepted");
    return 0;
}

/* [06] Framed wire serialization and roundtrip */
static int test_framed_signature_wire_roundtrip(void) {
    hybrid_identity_pk_t pk;
    hybrid_identity_sk_t sk;
    hybrid_signature_t sig, deserialized;
    uint8_t digest[HYBRID_SHA384_DIGEST_BYTES];
    uint8_t wire[HYBRID_SIG_WIRE_BYTES];
    size_t wire_len = 0;

    memset(digest, 0x33, sizeof(digest));
    TEST_ASSERT(hybrid_ed25519_keygen(pk.ed25519_pk, sk.ed25519_sk) == HYBRID_SUCCESS, "Keygen");
    TEST_ASSERT(hybrid_mldsa65_keygen(pk.mldsa_pk, sk.mldsa_sk) == HYBRID_SUCCESS, "Keygen");
    TEST_ASSERT(hybrid_sign_transcript(&sig, digest, &sk) == HYBRID_SUCCESS, "Sign");

    TEST_ASSERT(hybrid_signature_serialize(wire, sizeof(wire), &wire_len, &sig) == HYBRID_SUCCESS, "Serialize");
    TEST_ASSERT(wire_len == HYBRID_SIG_WIRE_BYTES, "Wire length mismatch");

    TEST_ASSERT(hybrid_signature_deserialize(&deserialized, wire, wire_len) == HYBRID_SUCCESS, "Deserialize");
    TEST_ASSERT(deserialized.version == HYBRID_SIG_FORMAT_VERSION, "Version mismatch");
    TEST_ASSERT(deserialized.ed25519_sig_len == HYBRID_ED25519_SIG_BYTES, "Ed len mismatch");
    TEST_ASSERT(deserialized.mldsa_sig_len == HYBRID_MLDSA65_SIG_BYTES, "ML len mismatch");
    TEST_ASSERT(hybrid_verify_transcript(&deserialized, digest, &pk) == HYBRID_SUCCESS, "Deserialized verify failed");

    /* Truncated wire buffer rejected */
    TEST_ASSERT(hybrid_signature_deserialize(&deserialized, wire, wire_len - 1) == HYBRID_ERR_BUFFER_TOO_SMALL, "Truncated buffer accepted");

    return 0;
}

int main(void) {
    printf("\n=== Running Test Suite: test_hybrid_signatures ===\n");
    RUN_TEST(test_hybrid_signature_sign_and_verify);
    RUN_TEST(test_corrupted_ed25519_signature_rejected);
    RUN_TEST(test_corrupted_mldsa_signature_rejected);
    RUN_TEST(test_tampered_transcript_digest_rejected);
    RUN_TEST(test_identity_substitution_rejected);
    RUN_TEST(test_framed_signature_wire_roundtrip);

    if (g_failed) {
        printf(CLR_RED "FAILED: Some tests in test_hybrid_signatures failed!" CLR_RESET "\n\n");
        return 1;
    }
    printf(CLR_GREEN "SUCCESS: All tests in test_hybrid_signatures passed!" CLR_RESET "\n\n");
    return 0;
}
