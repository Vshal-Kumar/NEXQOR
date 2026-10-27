/*
 * hybrid/tests/test_negative_cases.c
 *
 * Negative and boundary testing for all hybrid cryptographic modules.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hybrid_crypto.h"
#include "hybrid_kex.h"
#include "hybrid_signature.h"
#include "hybrid_kdf.h"
#include "hybrid_handshake.h"
#include "hybrid_session.h"
#include "hybrid_errors.h"

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

/* [01] Null pointer arguments rejected across all public APIs */
static int test_null_pointers_rejected(void) {
    uint8_t buf[64];
    size_t out_len = 0;

    TEST_ASSERT(hybrid_generate_identity_keys(NULL, NULL) == HYBRID_ERR_INVALID_ARG, "Null id keys");
    TEST_ASSERT(hybrid_kex_generate_keypair(NULL, NULL) == HYBRID_ERR_INVALID_ARG, "Null kex keypair");
    TEST_ASSERT(hybrid_hkdf_extract(NULL, NULL, 0, NULL, 0) == HYBRID_ERR_INVALID_ARG, "Null HKDF extract");
    TEST_ASSERT(hybrid_hkdf_expand(NULL, 0, NULL, NULL, 0) == HYBRID_ERR_INVALID_ARG, "Null HKDF expand");
    TEST_ASSERT(hybrid_hkdf_derive(NULL, 0, NULL, 0, NULL, 0, NULL, 0) == HYBRID_ERR_INVALID_ARG, "Null HKDF derive");
    TEST_ASSERT(hybrid_sign_transcript(NULL, NULL, NULL) == HYBRID_ERR_INVALID_ARG, "Null sign transcript");
    TEST_ASSERT(hybrid_verify_transcript(NULL, NULL, NULL) == HYBRID_ERR_INVALID_ARG, "Null verify transcript");
    TEST_ASSERT(hybrid_signature_serialize(NULL, 0, NULL, NULL) == HYBRID_ERR_INVALID_ARG, "Null sig serialize");
    TEST_ASSERT(hybrid_signature_deserialize(NULL, NULL, 0) == HYBRID_ERR_INVALID_ARG, "Null sig deserialize");
    TEST_ASSERT(hybrid_session_encrypt(NULL, NULL, 0, NULL, 0, NULL, 0, NULL) == HYBRID_ERR_INVALID_ARG, "Null session encrypt");
    TEST_ASSERT(hybrid_session_decrypt(NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL) == HYBRID_ERR_INVALID_ARG, "Null session decrypt");

    (void)buf; (void)out_len;
    return 0;
}

/* [02] Handshake state machine rejects out-of-order calls */
static int test_handshake_state_machine_violations(void) {
    hybrid_identity_pk_t id_pk;
    hybrid_identity_sk_t id_sk;
    hybrid_generate_identity_keys(&id_pk, &id_sk);

    hybrid_handshake_ctx_t ctx;
    hybrid_handshake_init(&ctx, HYBRID_ROLE_CLIENT, &id_pk, &id_sk);

    /* Calling client_create_auth before processing server hello must fail */
    hybrid_msg_client_auth_t auth;
    TEST_ASSERT(hybrid_client_create_auth(&ctx, &auth) == HYBRID_ERR_INVALID_STATE, "Create auth before hello accepted");

    /* Calling server_create_hello on a client context must fail */
    hybrid_msg_server_hello_t srv_hello;
    TEST_ASSERT(hybrid_server_create_hello(&ctx, &srv_hello) == HYBRID_ERR_INVALID_STATE, "Server call on client context accepted");

    /* Initializing server context */
    hybrid_handshake_ctx_t srv_ctx;
    hybrid_handshake_init(&srv_ctx, HYBRID_ROLE_SERVER, &id_pk, &id_sk);

    /* Server creating hello before receiving client hello must fail */
    TEST_ASSERT(hybrid_server_create_hello(&srv_ctx, &srv_hello) == HYBRID_ERR_INVALID_STATE, "Server hello without client hello accepted");

    hybrid_handshake_cleanup(&ctx);
    hybrid_handshake_cleanup(&srv_ctx);
    return 0;
}

/* [03] Buffer too small conditions handled safely */
static int test_buffer_capacity_checks(void) {
    hybrid_signature_t sig;
    sig.version = HYBRID_SIG_FORMAT_VERSION;
    sig.ed25519_sig_len = HYBRID_ED25519_SIG_BYTES;
    sig.mldsa_sig_len = HYBRID_MLDSA65_SIG_BYTES;

    uint8_t small_buf[10];
    size_t out_len = 0;
    TEST_ASSERT(hybrid_signature_serialize(small_buf, sizeof(small_buf), &out_len, &sig) == HYBRID_ERR_BUFFER_TOO_SMALL,
                "Serialize into small buffer succeeded");

    /* Session encrypt buffer too small */
    uint8_t key[32] = {0};
    hybrid_session_t sess;
    hybrid_session_init(&sess, HYBRID_ROLE_CLIENT, 1, key, key);

    uint8_t small_ct[5];
    size_t ct_len = 0;
    TEST_ASSERT(hybrid_session_encrypt(&sess, (const uint8_t *)"Hello", 5, NULL, 0,
                                      small_ct, sizeof(small_ct), &ct_len) == HYBRID_ERR_BUFFER_TOO_SMALL,
                "Encrypt into small buffer succeeded");

    hybrid_session_close(&sess);
    return 0;
}

/* [04] Nonce counter near exhaustion triggers refusal */
static int test_nonce_exhaustion_protection(void) {
    uint8_t key[32] = {0};
    hybrid_session_t sess;
    hybrid_session_init(&sess, HYBRID_ROLE_CLIENT, 1, key, key);

    /* Set counter to threshold */
    sess.tx_nonce_ctr = 0xFFFFFFFFFFFFFF00ULL;

    uint8_t ct[128];
    size_t ct_len = 0;
    int rc = hybrid_session_encrypt(&sess, (const uint8_t *)"Data", 4, NULL, 0,
                                   ct, sizeof(ct), &ct_len);

    TEST_ASSERT(rc == HYBRID_ERR_NONCE_EXHAUSTED, "Exhausted nonce counter accepted for encryption");

    hybrid_session_close(&sess);
    return 0;
}

/* [05] Operations on closed session are rejected */
static int test_closed_session_operations(void) {
    uint8_t key[32] = {0};
    hybrid_session_t sess;
    hybrid_session_init(&sess, HYBRID_ROLE_CLIENT, 1, key, key);
    hybrid_session_close(&sess);

    uint8_t ct[128];
    size_t ct_len = 0;
    TEST_ASSERT(hybrid_session_encrypt(&sess, (const uint8_t *)"Data", 4, NULL, 0,
                                      ct, sizeof(ct), &ct_len) == HYBRID_ERR_INVALID_ARG,
                "Encrypt on closed session accepted");

    uint8_t pt[128];
    size_t pt_len = 0;
    TEST_ASSERT(hybrid_session_decrypt(&sess, 1, ct, 30, NULL, 0,
                                      pt, sizeof(pt), &pt_len) == HYBRID_ERR_INVALID_ARG,
                "Decrypt on closed session accepted");

    return 0;
}

/* [06] Error string diagnostic output */
static int test_error_string_mapping(void) {
    TEST_ASSERT(strcmp(hybrid_strerror(HYBRID_SUCCESS), "Success") == 0, "Success string");
    TEST_ASSERT(strcmp(hybrid_strerror(HYBRID_ERR_DOWNGRADE_DETECTED), "Protocol or cipher suite downgrade detected") == 0, "Downgrade string");
    TEST_ASSERT(strcmp(hybrid_strerror(-9999), "Unknown hybrid error") == 0, "Unknown error string");
    return 0;
}

int main(void) {
    printf("\n=== Running Test Suite: test_negative_cases ===\n");
    RUN_TEST(test_null_pointers_rejected);
    RUN_TEST(test_handshake_state_machine_violations);
    RUN_TEST(test_buffer_capacity_checks);
    RUN_TEST(test_nonce_exhaustion_protection);
    RUN_TEST(test_closed_session_operations);
    RUN_TEST(test_error_string_mapping);

    if (g_failed) {
        printf(CLR_RED "FAILED: Some tests in test_negative_cases failed!" CLR_RESET "\n\n");
        return 1;
    }
    printf(CLR_GREEN "SUCCESS: All tests in test_negative_cases passed!" CLR_RESET "\n\n");
    return 0;
}
