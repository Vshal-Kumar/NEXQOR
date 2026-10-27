/*
 * hybrid/tests/test_hybrid_handshake.c
 *
 * Automated test suite for the Mutual-Authentication Hybrid Handshake.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>
#include "hybrid_handshake.h"

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

/* [01] Valid mutual-authentication handshake succeeds */
static int test_full_handshake_success(void) {
    hybrid_identity_pk_t client_id_pk, server_id_pk;
    hybrid_identity_sk_t client_id_sk, server_id_sk;

    TEST_ASSERT(hybrid_generate_identity_keys(&client_id_pk, &client_id_sk) == HYBRID_SUCCESS, "Client id keygen");
    TEST_ASSERT(hybrid_generate_identity_keys(&server_id_pk, &server_id_sk) == HYBRID_SUCCESS, "Server id keygen");

    hybrid_handshake_ctx_t client_ctx, server_ctx;
    TEST_ASSERT(hybrid_handshake_init(&client_ctx, HYBRID_ROLE_CLIENT, &client_id_pk, &client_id_sk) == HYBRID_SUCCESS, "Client hs init");
    TEST_ASSERT(hybrid_handshake_init(&server_ctx, HYBRID_ROLE_SERVER, &server_id_pk, &server_id_sk) == HYBRID_SUCCESS, "Server hs init");

    /* Step 1: Client generates CLIENT_HELLO */
    hybrid_msg_client_hello_t client_hello;
    TEST_ASSERT(hybrid_client_create_hello(&client_ctx, &client_hello) == HYBRID_SUCCESS, "Client hello");

    /* Step 2: Server processes CLIENT_HELLO and responds with SERVER_HELLO */
    TEST_ASSERT(hybrid_server_process_client_hello(&server_ctx, &client_hello, NULL) == HYBRID_SUCCESS, "Server rx hello");
    hybrid_msg_server_hello_t server_hello;
    TEST_ASSERT(hybrid_server_create_hello(&server_ctx, &server_hello) == HYBRID_SUCCESS, "Server tx hello");

    /* Step 3: Client processes SERVER_HELLO and responds with CLIENT_AUTH */
    TEST_ASSERT(hybrid_client_process_server_hello(&client_ctx, &server_hello, NULL) == HYBRID_SUCCESS, "Client rx srv hello");
    hybrid_msg_client_auth_t client_auth;
    TEST_ASSERT(hybrid_client_create_auth(&client_ctx, &client_auth) == HYBRID_SUCCESS, "Client tx auth");

    /* Step 4: Server processes CLIENT_AUTH */
    TEST_ASSERT(hybrid_server_process_client_auth(&server_ctx, &client_auth) == HYBRID_SUCCESS, "Server rx cl auth");

    /* Both parties established */
    TEST_ASSERT(client_ctx.established == 1, "Client not established");
    TEST_ASSERT(server_ctx.established == 1, "Server not established");
    TEST_ASSERT(client_ctx.session_id == server_ctx.session_id, "Session ID mismatch");

    /* Both derived identical directional keys */
    TEST_ASSERT(memcmp(client_ctx.client_write_key, server_ctx.client_write_key, HYBRID_TRAFFIC_KEY_BYTES) == 0, "C2S keys mismatch");
    TEST_ASSERT(memcmp(client_ctx.server_write_key, server_ctx.server_write_key, HYBRID_TRAFFIC_KEY_BYTES) == 0, "S2C keys mismatch");

    hybrid_handshake_cleanup(&client_ctx);
    hybrid_handshake_cleanup(&server_ctx);
    return 0;
}

/* [02] Active MITM tampering with server signature causes client rejection */
static int test_handshake_server_tampering_failure(void) {
    hybrid_identity_pk_t client_id_pk, server_id_pk;
    hybrid_identity_sk_t client_id_sk, server_id_sk;

    TEST_ASSERT(hybrid_generate_identity_keys(&client_id_pk, &client_id_sk) == HYBRID_SUCCESS, "Keygen");
    TEST_ASSERT(hybrid_generate_identity_keys(&server_id_pk, &server_id_sk) == HYBRID_SUCCESS, "Keygen");

    hybrid_handshake_ctx_t client_ctx, server_ctx;
    hybrid_handshake_init(&client_ctx, HYBRID_ROLE_CLIENT, &client_id_pk, &client_id_sk);
    hybrid_handshake_init(&server_ctx, HYBRID_ROLE_SERVER, &server_id_pk, &server_id_sk);

    hybrid_msg_client_hello_t client_hello;
    hybrid_client_create_hello(&client_ctx, &client_hello);

    hybrid_server_process_client_hello(&server_ctx, &client_hello, NULL);
    hybrid_msg_server_hello_t server_hello;
    hybrid_server_create_hello(&server_ctx, &server_hello);

    /* Attacker tampers with server signature */
    server_hello.server_sig[10] ^= 0x55;

    /* Client must reject */
    int rc = hybrid_client_process_server_hello(&client_ctx, &server_hello, NULL);
    TEST_ASSERT(rc == HYBRID_ERR_SIG_VERIFY_FAIL, "Tampered server signature accepted");
    TEST_ASSERT(client_ctx.established == 0, "Client established on invalid signature");

    hybrid_handshake_cleanup(&client_ctx);
    hybrid_handshake_cleanup(&server_ctx);
    return 0;
}

/* [03] Attacker tampering with client authentication causes server rejection */
static int test_handshake_client_tampering_failure(void) {
    hybrid_identity_pk_t client_id_pk, server_id_pk;
    hybrid_identity_sk_t client_id_sk, server_id_sk;

    hybrid_generate_identity_keys(&client_id_pk, &client_id_sk);
    hybrid_generate_identity_keys(&server_id_pk, &server_id_sk);

    hybrid_handshake_ctx_t client_ctx, server_ctx;
    hybrid_handshake_init(&client_ctx, HYBRID_ROLE_CLIENT, &client_id_pk, &client_id_sk);
    hybrid_handshake_init(&server_ctx, HYBRID_ROLE_SERVER, &server_id_pk, &server_id_sk);

    hybrid_msg_client_hello_t client_hello;
    hybrid_client_create_hello(&client_ctx, &client_hello);

    hybrid_server_process_client_hello(&server_ctx, &client_hello, NULL);
    hybrid_msg_server_hello_t server_hello;
    hybrid_server_create_hello(&server_ctx, &server_hello);

    hybrid_client_process_server_hello(&client_ctx, &server_hello, NULL);
    hybrid_msg_client_auth_t client_auth;
    hybrid_client_create_auth(&client_ctx, &client_auth);

    /* Attacker tampers with client auth signature */
    client_auth.client_sig[20] ^= 0xAA;

    int rc = hybrid_server_process_client_auth(&server_ctx, &client_auth);
    TEST_ASSERT(rc == HYBRID_ERR_SIG_VERIFY_FAIL, "Tampered client auth accepted");
    TEST_ASSERT(server_ctx.established == 0, "Server established on invalid auth");

    hybrid_handshake_cleanup(&client_ctx);
    hybrid_handshake_cleanup(&server_ctx);
    return 0;
}

/* [04] Downgrade attack offering unsupported version is rejected */
static int test_downgrade_version_rejected(void) {
    hybrid_identity_pk_t client_id_pk, server_id_pk;
    hybrid_identity_sk_t client_id_sk, server_id_sk;

    hybrid_generate_identity_keys(&client_id_pk, &client_id_sk);
    hybrid_generate_identity_keys(&server_id_pk, &server_id_sk);

    hybrid_handshake_ctx_t client_ctx, server_ctx;
    hybrid_handshake_init(&client_ctx, HYBRID_ROLE_CLIENT, &client_id_pk, &client_id_sk);
    hybrid_handshake_init(&server_ctx, HYBRID_ROLE_SERVER, &server_id_pk, &server_id_sk);

    hybrid_msg_client_hello_t client_hello;
    hybrid_client_create_hello(&client_ctx, &client_hello);

    /* Attempt version downgrade to 0x0090 */
    client_hello.version = htobe16(0x0090);

    int rc = hybrid_server_process_client_hello(&server_ctx, &client_hello, NULL);
    TEST_ASSERT(rc == HYBRID_ERR_VERSION_UNSUPPORTED, "Downgraded version accepted");

    hybrid_handshake_cleanup(&client_ctx);
    hybrid_handshake_cleanup(&server_ctx);
    return 0;
}

/* [05] Downgrade attack offering classical-only or invalid suite is rejected */
static int test_downgrade_suite_rejected(void) {
    hybrid_identity_pk_t client_id_pk, server_id_pk;
    hybrid_identity_sk_t client_id_sk, server_id_sk;

    hybrid_generate_identity_keys(&client_id_pk, &client_id_sk);
    hybrid_generate_identity_keys(&server_id_pk, &server_id_sk);

    hybrid_handshake_ctx_t client_ctx, server_ctx;
    hybrid_handshake_init(&client_ctx, HYBRID_ROLE_CLIENT, &client_id_pk, &client_id_sk);
    hybrid_handshake_init(&server_ctx, HYBRID_ROLE_SERVER, &server_id_pk, &server_id_sk);

    hybrid_msg_client_hello_t client_hello;
    hybrid_client_create_hello(&client_ctx, &client_hello);

    /* Modify suite ID to classical or bogus */
    strncpy(client_hello.suite_id, "CLASSICAL-ONLY-X25519-AES128CCM-SHA256", HYBRID_SUITE_ID_LEN);

    int rc = hybrid_server_process_client_hello(&server_ctx, &client_hello, NULL);
    TEST_ASSERT(rc == HYBRID_ERR_DOWNGRADE_DETECTED, "Bogus cipher suite accepted");

    hybrid_handshake_cleanup(&client_ctx);
    hybrid_handshake_cleanup(&server_ctx);
    return 0;
}

int main(void) {
    printf("\n=== Running Test Suite: test_hybrid_handshake ===\n");
    RUN_TEST(test_full_handshake_success);
    RUN_TEST(test_handshake_server_tampering_failure);
    RUN_TEST(test_handshake_client_tampering_failure);
    RUN_TEST(test_downgrade_version_rejected);
    RUN_TEST(test_downgrade_suite_rejected);

    if (g_failed) {
        printf(CLR_RED "FAILED: Some tests in test_hybrid_handshake failed!" CLR_RESET "\n\n");
        return 1;
    }
    printf(CLR_GREEN "SUCCESS: All tests in test_hybrid_handshake passed!" CLR_RESET "\n\n");
    return 0;
}
