/*
 * hybrid/tests/test_replay_protection.c
 *
 * Automated test suite for RFC 6479 64-Packet Sliding Replay Window Protection.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>
#include <arpa/inet.h>
#include "hybrid_session.h"
#include "crypto/replay_window.h"

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

/* [01] Rejection of duplicate messages in full session */
static int test_session_duplicate_rejection(void) {
    uint8_t c2s_key[32], s2c_key[32];
    memset(c2s_key, 0x11, 32);
    memset(s2c_key, 0x22, 32);

    hybrid_session_t client_sess, server_sess;
    hybrid_session_init(&client_sess, HYBRID_ROLE_CLIENT, 1, c2s_key, s2c_key);
    hybrid_session_init(&server_sess, HYBRID_ROLE_SERVER, 1, c2s_key, s2c_key);

    const char *msg = "Single-use command";
    uint8_t ct[128];
    size_t ct_len = 0;

    hybrid_pkt_hdr_t hdr;
    hdr.seq = htonl(10);
    hdr.type = 0x10;
    hdr.len = htons((uint16_t)strlen(msg));
    hdr.session_id = htobe64(1);

    TEST_ASSERT(hybrid_session_encrypt(&client_sess, (const uint8_t *)msg, strlen(msg),
                                      (const uint8_t *)&hdr, sizeof(hdr),
                                      ct, sizeof(ct), &ct_len) == HYBRID_SUCCESS, "Encrypt");

    /* First arrival: accepted */
    uint8_t dec[128];
    size_t dec_len = 0;
    TEST_ASSERT(hybrid_session_decrypt(&server_sess, 10, ct, ct_len,
                                      (const uint8_t *)&hdr, sizeof(hdr),
                                      dec, sizeof(dec), &dec_len) == HYBRID_SUCCESS, "First recv");

    /* Duplicate replay: rejected by replay protection */
    int rc = hybrid_session_decrypt(&server_sess, 10, ct, ct_len,
                                    (const uint8_t *)&hdr, sizeof(hdr),
                                    dec, sizeof(dec), &dec_len);
    TEST_ASSERT(rc == HYBRID_ERR_REPLAY_DETECTED, "Replayed duplicate was accepted");

    hybrid_session_close(&client_sess);
    hybrid_session_close(&server_sess);
    return 0;
}

/* [02] Sliding replay window accepts out-of-order within 64 packets */
static int test_sliding_window_out_of_order_acceptance(void) {
    replay_window_t win;
    replay_window_init(&win);

    /* Initialize with seq 100 */
    TEST_ASSERT(replay_window_check(&win, 100) == 0, "Check 100");
    TEST_ASSERT(replay_window_update(&win, 100) == 0, "Update 100");

    /* Out of order within window: seq 95 */
    TEST_ASSERT(replay_window_check(&win, 95) == 0, "Check 95");
    TEST_ASSERT(replay_window_update(&win, 95) == 0, "Update 95");

    /* seq 95 is now a duplicate */
    TEST_ASSERT(replay_window_check(&win, 95) != 0, "Duplicate 95 check");
    TEST_ASSERT(replay_window_update(&win, 95) != 0, "Duplicate 95 update");

    /* Another out of order within window: seq 70 */
    TEST_ASSERT(replay_window_check(&win, 70) == 0, "Check 70");
    TEST_ASSERT(replay_window_update(&win, 70) == 0, "Update 70");

    replay_window_destroy(&win);
    return 0;
}

/* [03] Stale packet rejection (> 64 behind highest accepted) */
static int test_stale_packet_rejection(void) {
    replay_window_t win;
    replay_window_init(&win);

    /* Base sequence: 100 */
    replay_window_update(&win, 100);

    /* Packet at 100 - 63 = 37 is the edge of the 64-packet window */
    TEST_ASSERT(replay_window_check(&win, 37) == 0, "Check 37");

    /* Packet at 36 is stale (100 - 36 = 64 packets behind 100, outside 64-packet window) */
    TEST_ASSERT(replay_window_check(&win, 36) != 0, "Stale 36 was accepted");
    TEST_ASSERT(replay_window_update(&win, 36) != 0, "Stale 36 committed");

    /* Advance window to 200 */
    replay_window_update(&win, 200);

    /* Packet 100 is now stale (200 - 100 = 100 > 64) */
    TEST_ASSERT(replay_window_check(&win, 100) != 0, "Stale 100 accepted after advance");

    replay_window_destroy(&win);
    return 0;
}

/* [04] Two-phase commit: check does not advance window state */
static int test_pre_auth_check_isolation(void) {
    replay_window_t win;
    replay_window_init(&win);

    replay_window_update(&win, 10);

    /* Check sequence 20 multiple times; window must not advance */
    TEST_ASSERT(replay_window_check(&win, 20) == 0, "Check 20 #1");
    TEST_ASSERT(replay_window_check(&win, 20) == 0, "Check 20 #2");
    TEST_ASSERT(replay_window_check(&win, 20) == 0, "Check 20 #3");

    /* Base sequence must still be 10 */
    TEST_ASSERT(win.base_seq == 10, "Base sequence mutated during pre-auth check");

    /* After commit, sequence 20 becomes accepted */
    TEST_ASSERT(replay_window_update(&win, 20) == 0, "Commit 20");
    TEST_ASSERT(win.base_seq == 20, "Base sequence not updated after commit");

    replay_window_destroy(&win);
    return 0;
}

int main(void) {
    printf("\n=== Running Test Suite: test_replay_protection ===\n");
    RUN_TEST(test_session_duplicate_rejection);
    RUN_TEST(test_sliding_window_out_of_order_acceptance);
    RUN_TEST(test_stale_packet_rejection);
    RUN_TEST(test_pre_auth_check_isolation);

    if (g_failed) {
        printf(CLR_RED "FAILED: Some tests in test_replay_protection failed!" CLR_RESET "\n\n");
        return 1;
    }
    printf(CLR_GREEN "SUCCESS: All tests in test_replay_protection passed!" CLR_RESET "\n\n");
    return 0;
}
