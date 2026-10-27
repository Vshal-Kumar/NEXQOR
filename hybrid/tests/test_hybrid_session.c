/*
 * hybrid/tests/test_hybrid_session.c
 *
 * Automated test suite for ChaCha20-Poly1305 Hybrid Session Encryption.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>
#include <arpa/inet.h>
#include "hybrid_session.h"

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

/* [01] Bidirectional encryption and decryption (Client <-> Server) */
static int test_bidirectional_session_encryption(void) {
    uint8_t c2s_key[32], s2c_key[32];
    memset(c2s_key, 0x11, 32);
    memset(s2c_key, 0x22, 32);
    uint64_t session_id = 0x1234567890ABCDEFULL;

    hybrid_session_t client_sess, server_sess;
    TEST_ASSERT(hybrid_session_init(&client_sess, HYBRID_ROLE_CLIENT, session_id, c2s_key, s2c_key) == HYBRID_SUCCESS, "Client sess init");
    TEST_ASSERT(hybrid_session_init(&server_sess, HYBRID_ROLE_SERVER, session_id, c2s_key, s2c_key) == HYBRID_SUCCESS, "Server sess init");

    /* 1. Client to Server */
    const char *msg_c2s = "Hello Quantum-Resistant Server!";
    size_t pt_len = strlen(msg_c2s);
    uint8_t ct[128];
    size_t ct_len = 0;

    hybrid_pkt_hdr_t hdr_c2s;
    hdr_c2s.seq = htonl(client_sess.tx_seq);
    hdr_c2s.type = 0x10;
    hdr_c2s.len = htons((uint16_t)pt_len);
    hdr_c2s.session_id = htobe64(session_id);

    TEST_ASSERT(hybrid_session_encrypt(&client_sess, (const uint8_t *)msg_c2s, pt_len,
                                      (const uint8_t *)&hdr_c2s, sizeof(hdr_c2s),
                                      ct, sizeof(ct), &ct_len) == HYBRID_SUCCESS, "C2S encrypt");

    uint8_t decrypted[128];
    size_t dec_len = 0;
    TEST_ASSERT(hybrid_session_decrypt(&server_sess, ntohl(hdr_c2s.seq),
                                      ct, ct_len,
                                      (const uint8_t *)&hdr_c2s, sizeof(hdr_c2s),
                                      decrypted, sizeof(decrypted), &dec_len) == HYBRID_SUCCESS, "S2C decrypt");

    TEST_ASSERT(dec_len == pt_len, "Decrypted length mismatch");
    TEST_ASSERT(memcmp(decrypted, msg_c2s, pt_len) == 0, "Decrypted content mismatch");

    /* 2. Server to Client */
    const char *msg_s2c = "Server acknowledges hybrid protected link!";
    pt_len = strlen(msg_s2c);

    hybrid_pkt_hdr_t hdr_s2c;
    hdr_s2c.seq = htonl(server_sess.tx_seq);
    hdr_s2c.type = 0x10;
    hdr_s2c.len = htons((uint16_t)pt_len);
    hdr_s2c.session_id = htobe64(session_id);

    TEST_ASSERT(hybrid_session_encrypt(&server_sess, (const uint8_t *)msg_s2c, pt_len,
                                      (const uint8_t *)&hdr_s2c, sizeof(hdr_s2c),
                                      ct, sizeof(ct), &ct_len) == HYBRID_SUCCESS, "S2C encrypt");

    TEST_ASSERT(hybrid_session_decrypt(&client_sess, ntohl(hdr_s2c.seq),
                                      ct, ct_len,
                                      (const uint8_t *)&hdr_s2c, sizeof(hdr_s2c),
                                      decrypted, sizeof(decrypted), &dec_len) == HYBRID_SUCCESS, "C2S decrypt");

    TEST_ASSERT(dec_len == pt_len, "Server message decrypted length mismatch");
    TEST_ASSERT(memcmp(decrypted, msg_s2c, pt_len) == 0, "Server message content mismatch");

    hybrid_session_close(&client_sess);
    hybrid_session_close(&server_sess);
    return 0;
}

/* [02] Ciphertext tampering causes decryption failure */
static int test_ciphertext_tampering_rejected(void) {
    uint8_t c2s_key[32], s2c_key[32];
    memset(c2s_key, 0x11, 32);
    memset(s2c_key, 0x22, 32);

    hybrid_session_t client_sess, server_sess;
    hybrid_session_init(&client_sess, HYBRID_ROLE_CLIENT, 1, c2s_key, s2c_key);
    hybrid_session_init(&server_sess, HYBRID_ROLE_SERVER, 1, c2s_key, s2c_key);

    const char *msg = "Top secret sensor telemetry";
    uint8_t ct[128];
    size_t ct_len = 0;

    hybrid_pkt_hdr_t hdr;
    hdr.seq = htonl(1);
    hdr.type = 0x10;
    hdr.len = htons((uint16_t)strlen(msg));
    hdr.session_id = htobe64(1);

    hybrid_session_encrypt(&client_sess, (const uint8_t *)msg, strlen(msg),
                          (const uint8_t *)&hdr, sizeof(hdr), ct, sizeof(ct), &ct_len);

    /* Tamper with ciphertext byte (after 12 bytes nonce + 16 bytes tag = byte 28+) */
    ct[30] ^= 0x01;

    uint8_t dec[128];
    size_t dec_len = 0;
    int rc = hybrid_session_decrypt(&server_sess, 1, ct, ct_len,
                                    (const uint8_t *)&hdr, sizeof(hdr),
                                    dec, sizeof(dec), &dec_len);

    TEST_ASSERT(rc == HYBRID_ERR_AEAD_FAIL, "Tampered ciphertext accepted");

    hybrid_session_close(&client_sess);
    hybrid_session_close(&server_sess);
    return 0;
}

/* [03] Poly1305 authentication tag tampering is rejected */
static int test_tag_tampering_rejected(void) {
    uint8_t c2s_key[32], s2c_key[32];
    memset(c2s_key, 0x11, 32);
    memset(s2c_key, 0x22, 32);

    hybrid_session_t client_sess, server_sess;
    hybrid_session_init(&client_sess, HYBRID_ROLE_CLIENT, 1, c2s_key, s2c_key);
    hybrid_session_init(&server_sess, HYBRID_ROLE_SERVER, 1, c2s_key, s2c_key);

    const char *msg = "Authenticated payload";
    uint8_t ct[128];
    size_t ct_len = 0;

    hybrid_pkt_hdr_t hdr;
    hdr.seq = htonl(1);
    hdr.type = 0x10;
    hdr.len = htons((uint16_t)strlen(msg));
    hdr.session_id = htobe64(1);

    hybrid_session_encrypt(&client_sess, (const uint8_t *)msg, strlen(msg),
                          (const uint8_t *)&hdr, sizeof(hdr), ct, sizeof(ct), &ct_len);

    /* Tamper with tag byte (bytes 12 to 27) */
    ct[15] ^= 0x42;

    uint8_t dec[128];
    size_t dec_len = 0;
    int rc = hybrid_session_decrypt(&server_sess, 1, ct, ct_len,
                                    (const uint8_t *)&hdr, sizeof(hdr),
                                    dec, sizeof(dec), &dec_len);

    TEST_ASSERT(rc == HYBRID_ERR_AEAD_FAIL, "Corrupted authentication tag accepted");

    hybrid_session_close(&client_sess);
    hybrid_session_close(&server_sess);
    return 0;
}

/* [04] Associated data (AAD) modification is rejected */
static int test_aad_modification_rejected(void) {
    uint8_t c2s_key[32], s2c_key[32];
    memset(c2s_key, 0x11, 32);
    memset(s2c_key, 0x22, 32);

    hybrid_session_t client_sess, server_sess;
    hybrid_session_init(&client_sess, HYBRID_ROLE_CLIENT, 1, c2s_key, s2c_key);
    hybrid_session_init(&server_sess, HYBRID_ROLE_SERVER, 1, c2s_key, s2c_key);

    const char *msg = "AAD protected packet";
    uint8_t ct[128];
    size_t ct_len = 0;

    hybrid_pkt_hdr_t hdr;
    hdr.seq = htonl(1);
    hdr.type = 0x10;
    hdr.len = htons((uint16_t)strlen(msg));
    hdr.session_id = htobe64(1);

    hybrid_session_encrypt(&client_sess, (const uint8_t *)msg, strlen(msg),
                          (const uint8_t *)&hdr, sizeof(hdr), ct, sizeof(ct), &ct_len);

    /* Modify wire header AAD (e.g. change type or sequence in AAD) */
    hdr.type = 0x11;

    uint8_t dec[128];
    size_t dec_len = 0;
    int rc = hybrid_session_decrypt(&server_sess, 1, ct, ct_len,
                                    (const uint8_t *)&hdr, sizeof(hdr),
                                    dec, sizeof(dec), &dec_len);

    TEST_ASSERT(rc == HYBRID_ERR_AEAD_FAIL, "Modified AAD header accepted");

    hybrid_session_close(&client_sess);
    hybrid_session_close(&server_sess);
    return 0;
}

/* [05] Nonce uniqueness and monotonic progression */
static int test_nonce_uniqueness_and_monotonicity(void) {
    uint8_t c2s_key[32], s2c_key[32];
    memset(c2s_key, 0x11, 32);
    memset(s2c_key, 0x22, 32);

    hybrid_session_t sess;
    hybrid_session_init(&sess, HYBRID_ROLE_CLIENT, 1, c2s_key, s2c_key);

    uint8_t ct1[64], ct2[64];
    size_t len1, len2;

    hybrid_session_encrypt(&sess, (const uint8_t *)"A", 1, NULL, 0, ct1, sizeof(ct1), &len1);
    hybrid_session_encrypt(&sess, (const uint8_t *)"A", 1, NULL, 0, ct2, sizeof(ct2), &len2);

    /* First 12 bytes are the nonces */
    TEST_ASSERT(memcmp(ct1, ct2, 12) != 0, "Sequential nonces are identical! Nonce reuse detected!");

    /* Verify first 8 bytes increment */
    uint64_t n1 = le64toh(*(uint64_t *)ct1);
    uint64_t n2 = le64toh(*(uint64_t *)ct2);
    TEST_ASSERT(n2 == n1 + 1, "Nonce counter did not advance strictly monotonically");

    hybrid_session_close(&sess);
    return 0;
}

/* [06] Session close clears secret material */
static int test_session_closure_clears_secrets(void) {
    uint8_t c2s_key[32], s2c_key[32];
    memset(c2s_key, 0x55, 32);
    memset(s2c_key, 0x66, 32);

    hybrid_session_t sess;
    hybrid_session_init(&sess, HYBRID_ROLE_CLIENT, 1, c2s_key, s2c_key);
    hybrid_session_close(&sess);

    TEST_ASSERT(sess.active == 0, "Session still marked active after close");

    uint8_t zeros[32] = {0};
    TEST_ASSERT(memcmp(sess.tx_key, zeros, 32) == 0, "tx_key was not zeroized on close");
    TEST_ASSERT(memcmp(sess.rx_key, zeros, 32) == 0, "rx_key was not zeroized on close");

    return 0;
}

int main(void) {
    printf("\n=== Running Test Suite: test_hybrid_session ===\n");
    RUN_TEST(test_bidirectional_session_encryption);
    RUN_TEST(test_ciphertext_tampering_rejected);
    RUN_TEST(test_tag_tampering_rejected);
    RUN_TEST(test_aad_modification_rejected);
    RUN_TEST(test_nonce_uniqueness_and_monotonicity);
    RUN_TEST(test_session_closure_clears_secrets);

    if (g_failed) {
        printf(CLR_RED "FAILED: Some tests in test_hybrid_session failed!" CLR_RESET "\n\n");
        return 1;
    }
    printf(CLR_GREEN "SUCCESS: All tests in test_hybrid_session passed!" CLR_RESET "\n\n");
    return 0;
}
