/*
 * tests/test_suite.c — Comprehensive Automated Security & Unit Test Suite
 *
 * Implements thorough validation for:
 *   [A] ML-KEM-768 Primitive Agreement & Decapsulation
 *   [B] ML-DSA-65 Digital Signature & Rejection of Tampered Inputs
 *   [C] Directional Key Derivation (C2S vs S2C domain separation & session isolation)
 *   [D] ChaCha20-Poly1305 AEAD with Canonical Header AAD Binding & Tamper Detection
 *   [E] RFC 6479 64-Packet Sliding Replay Window (reordering, duplicates, stale drops)
 *   [F] Trust Store Peer Authentication & Public-Key Substitution (MITM) Prevention
 *   [G] UDP Handshake Message Fragmentation and Out-of-Order Reassembly
 *   [H] Independent Session Cryptographic State & Secure Zeroization
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <endian.h>
#include <openssl/rand.h>

#include "crypto/aead.h"
#include "crypto/replay_window.h"
#include "crypto/trust_store.h"
#include "transport.h"
#include "wrappers/kem_wrapper.h"
#include "wrappers/dsa_wrapper.h"

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
        printf("    " CLR_RED "✗ FAILED: %s (line %d)" CLR_RESET "\n", msg, __LINE__); \
        g_tests_failed++; \
        return -1; \
    } \
} while (0)

#define RUN_TEST(fn) do { \
    g_tests_run++; \
    printf(CLR_BOLD "[TEST %02d] %-48s" CLR_RESET, g_tests_run, #fn); \
    fflush(stdout); \
    if (fn() == 0) { \
        printf(CLR_GREEN " PASS" CLR_RESET "\n"); \
        g_tests_passed++; \
    } else { \
        /* failure message already printed */ \
    } \
} while (0)

/* ═══════════════════════════════════════════════════════════════════
 * [A] ML-KEM-768 TESTS
 * ═══════════════════════════════════════════════════════════════════ */
static int test_kem_agreement_and_negative(void) {
    uint8_t pk[KEM_PK_BYTES];
    uint8_t sk[KEM_SK_BYTES];
    uint8_t ct[KEM_CT_BYTES];
    uint8_t ss_enc[KEM_SS_BYTES];
    uint8_t ss_dec[KEM_SS_BYTES];

    /* 1. Key generation */
    TEST_ASSERT(kem_keypair(pk, sk) == 0, "kem_keypair failed");

    /* 2. Encapsulation */
    TEST_ASSERT(kem_enc(ct, ss_enc, pk) == 0, "kem_enc failed");

    /* 3. Decapsulation */
    TEST_ASSERT(kem_dec(ss_dec, ct, sk) == 0, "kem_dec failed");

    /* 4. Shared secret agreement */
    TEST_ASSERT(memcmp(ss_enc, ss_dec, KEM_SS_BYTES) == 0, "shared secrets do not match");

    /* 5. Negative test: Corrupted ciphertext must NOT produce the same shared secret */
    ct[10] ^= 0xFF;
    uint8_t ss_corrupted[KEM_SS_BYTES];
    kem_dec(ss_corrupted, ct, sk);
    TEST_ASSERT(memcmp(ss_enc, ss_corrupted, KEM_SS_BYTES) != 0,
                "tampered ciphertext produced identical shared secret");

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * [B] ML-DSA-65 TESTS
 * ═══════════════════════════════════════════════════════════════════ */
static int test_dsa_signing_and_tampering(void) {
    uint8_t pk[DSA_PK_BYTES];
    uint8_t sk[DSA_SK_BYTES];
    uint8_t wrong_pk[DSA_PK_BYTES];
    uint8_t wrong_sk[DSA_SK_BYTES];
    uint8_t sig[DSA_SIG_BYTES];
    size_t sig_len = 0;

    const uint8_t msg[] = "NEXQOR-TEST-TRANSCRIPT-DIGEST-DATA-STRING";
    size_t msg_len = sizeof(msg) - 1;

    TEST_ASSERT(dsa_keypair(pk, sk) == 0, "dsa_keypair failed");
    TEST_ASSERT(dsa_keypair(wrong_pk, wrong_sk) == 0, "wrong keypair failed");

    /* 1. Valid sign and verify */
    TEST_ASSERT(dsa_sign(sig, &sig_len, msg, msg_len, sk) == 0, "dsa_sign failed");
    TEST_ASSERT(sig_len > 0, "sig_len is 0");
    TEST_ASSERT(dsa_verify(sig, sig_len, msg, msg_len, pk) == 0, "valid verify failed");

    /* 2. Modified message must fail verification */
    uint8_t tampered_msg[sizeof(msg)];
    memcpy(tampered_msg, msg, sizeof(msg));
    tampered_msg[5] ^= 0xAA;
    TEST_ASSERT(dsa_verify(sig, sig_len, tampered_msg, msg_len, pk) != 0,
                "tampered message unexpectedly verified");

    /* 3. Modified signature must fail verification */
    uint8_t tampered_sig[DSA_SIG_BYTES];
    memcpy(tampered_sig, sig, sig_len);
    tampered_sig[sig_len / 2] ^= 0x55;
    TEST_ASSERT(dsa_verify(tampered_sig, sig_len, msg, msg_len, pk) != 0,
                "corrupted signature unexpectedly verified");

    /* 4. Wrong public key must fail verification */
    TEST_ASSERT(dsa_verify(sig, sig_len, msg, msg_len, wrong_pk) != 0,
                "signature verified with wrong public key");

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * [C] DIRECTIONAL KEY DERIVATION TESTS
 * ═══════════════════════════════════════════════════════════════════ */
static int test_directional_kdf_separation(void) {
    uint8_t shared_secret[KEM_SS_BYTES];
    uint8_t c_nonce[16], s_nonce[16];
    uint64_t session_id = 0x0123456789ABCDEFULL;

    RAND_bytes(shared_secret, sizeof(shared_secret));
    RAND_bytes(c_nonce, sizeof(c_nonce));
    RAND_bytes(s_nonce, sizeof(s_nonce));

    /* Peer A (e.g. client) derives keys */
    uint8_t a_c2s[32], a_s2c[32];
    kem_derive_directional_keys(a_c2s, a_s2c, shared_secret, c_nonce, s_nonce, session_id);

    /* Peer B (e.g. server) derives keys */
    uint8_t b_c2s[32], b_s2c[32];
    kem_derive_directional_keys(b_c2s, b_s2c, shared_secret, c_nonce, s_nonce, session_id);

    /* Invariant 1: Client-to-Server and Server-to-Client keys must NOT be equal */
    TEST_ASSERT(memcmp(a_c2s, a_s2c, 32) != 0,
                "CRITICAL: Client and Server write keys are identical! Nonce reuse vulnerability!");

    /* Invariant 2: Both peers must derive identical matching keys for the same direction */
    TEST_ASSERT(memcmp(a_c2s, b_c2s, 32) == 0, "C2S keys do not match between peers");
    TEST_ASSERT(memcmp(a_s2c, b_s2c, 32) == 0, "S2C keys do not match between peers");

    /* Invariant 3: Changing session ID derives completely different keys */
    uint8_t diff_c2s[32], diff_s2c[32];
    kem_derive_directional_keys(diff_c2s, diff_s2c, shared_secret, c_nonce, s_nonce, session_id + 1);
    TEST_ASSERT(memcmp(a_c2s, diff_c2s, 32) != 0, "Different session produced identical C2S key");
    TEST_ASSERT(memcmp(a_s2c, diff_s2c, 32) != 0, "Different session produced identical S2C key");

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * [D] AEAD WITH AUTHENTICATED ASSOCIATED DATA (AAD) TESTS
 * ═══════════════════════════════════════════════════════════════════ */
static int test_aead_aad_binding_and_tampering(void) {
    uint8_t key[32];
    uint8_t nonce[12];
    RAND_bytes(key, 32);
    RAND_bytes(nonce, 12);

    const char *payload = "SensorTelemetry: temperature=24.5C, pressure=1013hPa";
    int pt_len = (int)strlen(payload);

    /* Construct wire header as AAD */
    pkt_hdr_t hdr;
    hdr.seq = htonl(42);
    hdr.type = PKT_DATA;
    hdr.len = htons((uint16_t)(12 + 16 + pt_len));
    hdr.session_id = htobe64(0xDEADBEEFCAFE0001ULL);

    uint8_t ct[128];
    uint8_t tag[16];
    uint8_t dec_pt[128];

    /* 1. Valid Encrypt and Decrypt with AAD */
    int ct_len = aead_encrypt((const uint8_t *)payload, pt_len,
                              (const uint8_t *)&hdr, sizeof(hdr),
                              key, nonce, ct, tag);
    TEST_ASSERT(ct_len == pt_len, "aead_encrypt failed or length mismatch");

    int dec_len = aead_decrypt(ct, ct_len,
                               (const uint8_t *)&hdr, sizeof(hdr),
                               key, nonce, tag, dec_pt);
    TEST_ASSERT(dec_len == pt_len, "aead_decrypt failed");
    TEST_ASSERT(memcmp(payload, dec_pt, pt_len) == 0, "decrypted text does not match");

    /* 2. Tampering with sequence number in AAD MUST cause decryption rejection */
    pkt_hdr_t tampered_hdr = hdr;
    tampered_hdr.seq = htonl(43); /* Sequence number altered by attacker or reorder */
    int tampered_dec = aead_decrypt(ct, ct_len,
                                    (const uint8_t *)&tampered_hdr, sizeof(tampered_hdr),
                                    key, nonce, tag, dec_pt);
    TEST_ASSERT(tampered_dec < 0, "CRITICAL: Tampered sequence number was silently accepted!");

    /* 3. Tampering with session ID in AAD MUST cause decryption rejection */
    tampered_hdr = hdr;
    tampered_hdr.session_id = htobe64(0xDEADBEEFCAFE0002ULL);
    TEST_ASSERT(aead_decrypt(ct, ct_len, (const uint8_t *)&tampered_hdr, sizeof(tampered_hdr),
                             key, nonce, tag, dec_pt) < 0,
                "CRITICAL: Tampered session_id was silently accepted!");

    /* 4. Tampering with packet type in AAD MUST cause rejection */
    tampered_hdr = hdr;
    tampered_hdr.type = PKT_ACK;
    TEST_ASSERT(aead_decrypt(ct, ct_len, (const uint8_t *)&tampered_hdr, sizeof(tampered_hdr),
                             key, nonce, tag, dec_pt) < 0,
                "CRITICAL: Tampered packet type was silently accepted!");

    /* 5. Tampering with Poly1305 authentication tag */
    uint8_t bad_tag[16];
    memcpy(bad_tag, tag, 16);
    bad_tag[0] ^= 0x01;
    TEST_ASSERT(aead_decrypt(ct, ct_len, (const uint8_t *)&hdr, sizeof(hdr),
                             key, nonce, bad_tag, dec_pt) < 0,
                "Tampered tag was accepted!");

    /* 6. Tampering with ciphertext */
    uint8_t bad_ct[128];
    memcpy(bad_ct, ct, ct_len);
    bad_ct[0] ^= 0x01;
    TEST_ASSERT(aead_decrypt(bad_ct, ct_len, (const uint8_t *)&hdr, sizeof(hdr),
                             key, nonce, tag, dec_pt) < 0,
                "Tampered ciphertext was accepted!");

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * [E] SLIDING REPLAY WINDOW (RFC 6479) TESTS
 * ═══════════════════════════════════════════════════════════════════ */
static int test_sliding_replay_window(void) {
    replay_window_t win;
    replay_window_init(&win);

    /* 1. Initial state: Packet 0 must be rejected */
    TEST_ASSERT(replay_window_check(&win, 0) != 0, "Sequence 0 must be rejected");

    /* 2. Packet 1: check passes, commit */
    TEST_ASSERT(replay_window_check(&win, 1) == 0, "Fresh seq 1 must pass check");
    replay_window_update(&win, 1);

    /* 3. Replay of packet 1: check MUST fail */
    TEST_ASSERT(replay_window_check(&win, 1) != 0, "Replayed seq 1 must be rejected");

    /* 4. In-order arrival: 2, 3, 4 */
    for (uint32_t s = 2; s <= 4; s++) {
        TEST_ASSERT(replay_window_check(&win, s) == 0, "In-order packet check failed");
        replay_window_update(&win, s);
    }
    TEST_ASSERT(replay_window_check(&win, 3) != 0, "Replayed seq 3 must be rejected");

    /* 5. Out-of-order within 64-packet window: jump to 20, then receive 10 */
    TEST_ASSERT(replay_window_check(&win, 20) == 0, "Jump to 20 must pass");
    replay_window_update(&win, 20);

    TEST_ASSERT(replay_window_check(&win, 10) == 0, "Out-of-order seq 10 within window must pass");
    replay_window_update(&win, 10);
    TEST_ASSERT(replay_window_check(&win, 10) != 0, "Replay of out-of-order seq 10 must be rejected");

    /* 6. Large advance: jump to 100 */
    TEST_ASSERT(replay_window_check(&win, 100) == 0, "Jump to 100 must pass");
    replay_window_update(&win, 100);

    /* Packets < 100 - 64 = 36 are now stale and must be rejected */
    TEST_ASSERT(replay_window_check(&win, 30) != 0, "Stale packet 30 must be rejected");
    TEST_ASSERT(replay_window_check(&win, 35) != 0, "Stale packet 35 must be rejected");

    /* Packet 70 is within window (100 - 64 < 70 <= 100) and unreceived, so it passes */
    TEST_ASSERT(replay_window_check(&win, 70) == 0, "Unreceived packet 70 within window must pass");
    replay_window_update(&win, 70);
    TEST_ASSERT(replay_window_check(&win, 70) != 0, "Replay of 70 must fail");

    replay_window_destroy(&win);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * [F] TRUST STORE & PEER AUTHENTICATION (MITM PREVENTION) TESTS
 * ═══════════════════════════════════════════════════════════════════ */
static int test_trust_store_peer_authentication(void) {
    uint8_t legitimate_pk[DSA_PK_BYTES], legitimate_sk[DSA_SK_BYTES];
    uint8_t attacker_pk[DSA_PK_BYTES], attacker_sk[DSA_SK_BYTES];

    const char *test_pub_file = "test_server_identity.pub";
    const char *test_key_file = "test_server_identity.key";

    /* Generate and save legitimate server identity */
    TEST_ASSERT(trust_store_load_or_create_server_keys(legitimate_pk, legitimate_sk,
                                                        test_pub_file, test_key_file) == 0,
                "trust_store_load_or_create_server_keys failed");

    /* Attacker generates their own keypair */
    TEST_ASSERT(dsa_keypair(attacker_pk, attacker_sk) == 0, "Attacker dsa_keypair failed");

    /* Client side verification:
     * Case 1: Legitimate server key matches pinned trust store */
    TEST_ASSERT(trust_store_client_verify_server(legitimate_pk, test_pub_file) == 0,
                "Legitimate server key was unexpectedly rejected");

    /* Case 2: Attacker substitutes server key with their own — MUST BE REJECTED */
    TEST_ASSERT(trust_store_client_verify_server(attacker_pk, test_pub_file) != 0,
                "CRITICAL: Attacker public key was accepted by client trust store! MITM attack possible!");

    /* Server side verification of client keys:
     * In permissive mode (test mode), valid ML-DSA-65 keys are accepted */
    TEST_ASSERT(trust_store_server_verify_client(legitimate_pk, NULL) == 0,
                "Valid client key was rejected in permissive mode");

    /* All-zero invalid public key must be rejected */
    uint8_t zero_pk[DSA_PK_BYTES] = {0};
    TEST_ASSERT(trust_store_server_verify_client(zero_pk, NULL) != 0,
                "All-zero public key was accepted");

    /* Clean up temporary test files */
    remove(test_pub_file);
    remove(test_key_file);

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * [G] UDP PACKET FRAMING & FRAGMENTATION TESTS
 * ═══════════════════════════════════════════════════════════════════ */
static int test_packet_framing_and_reassembly(void) {
    reassembly_ctx_t ctx;
    reassembly_init(&ctx);

    /* Construct a synthetic 2500-byte message */
    uint32_t total_len = 2500;
    uint8_t orig_msg[2500];
    for (uint32_t i = 0; i < total_len; i++) {
        orig_msg[i] = (uint8_t)(i & 0xFF);
    }

    /* 3 fragments: 1000, 1000, 500 */
    uint8_t total_frags = 3;
    uint16_t msg_id = 1234;
    uint8_t orig_type = PKT_CLIENT_HELLO;

    frag_hdr_t fhdr0 = {
        .msg_id = htons(msg_id),
        .orig_type = orig_type,
        .frag_idx = 0,
        .frag_total = total_frags,
        .frag_len = htons(1024),
        .total_len = htonl(total_len)
    };

    frag_hdr_t fhdr1 = {
        .msg_id = htons(msg_id),
        .orig_type = orig_type,
        .frag_idx = 1,
        .frag_total = total_frags,
        .frag_len = htons(1024),
        .total_len = htonl(total_len)
    };

    frag_hdr_t fhdr2 = {
        .msg_id = htons(msg_id),
        .orig_type = orig_type,
        .frag_idx = 2,
        .frag_total = total_frags,
        .frag_len = htons(452),
        .total_len = htonl(total_len)
    };

    /* Feed out of order: frag 2, frag 0, frag 1 */
    int rc2 = reassembly_feed_frag(&ctx, &fhdr2, orig_msg + 2048);
    TEST_ASSERT(rc2 == 0, "Frag 2 feed failed");

    int rc0 = reassembly_feed_frag(&ctx, &fhdr0, orig_msg + 0);
    TEST_ASSERT(rc0 == 0, "Frag 0 feed failed");

    /* Duplicate fragment 0: must return 0 and not corrupt count */
    int rc_dup = reassembly_feed_frag(&ctx, &fhdr0, orig_msg + 0);
    TEST_ASSERT(rc_dup == 0, "Duplicate fragment feed failed");

    /* Final fragment 1 completes the message */
    int rc1 = reassembly_feed_frag(&ctx, &fhdr1, orig_msg + 1024);
    TEST_ASSERT(rc1 == 1, "Final fragment did not trigger completion");

    /* Verify reassembled payload */
    TEST_ASSERT(ctx.received_bytes == total_len, "Reassembled size mismatch");
    TEST_ASSERT(memcmp(ctx.buf, orig_msg, total_len) == 0, "Reassembled content mismatch");

    reassembly_cleanup(&ctx);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * [H] SESSION ISOLATION & ZEROIZATION TESTS
 * ═══════════════════════════════════════════════════════════════════ */
static int test_session_isolation_and_cleanup(void) {
    conn_t c1, c2;
    conn_init(&c1, -1);
    conn_init(&c2, -1);

    c1.session_id = 0x1111;
    c2.session_id = 0x2222;

    RAND_bytes(c1.tx_key, 32);
    RAND_bytes(c2.tx_key, 32);

    /* Advance c1 replay window to 50 */
    replay_window_update(&c1.replay_win, 50);

    /* Invariant: c2's replay window must be completely unaffected */
    TEST_ASSERT(replay_window_check(&c2.replay_win, 50) == 0,
                "Replay window state leaked across sessions!");

    /* Destroy c1: keys must be securely zeroized */
    conn_destroy(&c1);

    uint8_t zero_key[32] = {0};
    TEST_ASSERT(memcmp(c1.tx_key, zero_key, 32) == 0,
                "conn_destroy did not zeroize tx_key!");
    TEST_ASSERT(memcmp(c1.rx_key, zero_key, 32) == 0,
                "conn_destroy did not zeroize rx_key!");

    conn_destroy(&c2);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * MAIN TEST RUNNER
 * ═══════════════════════════════════════════════════════════════════ */
int main(void) {
    printf("\n");
    printf(CLR_CYAN "╔══════════════════════════════════════════════════════════════╗" CLR_RESET "\n");
    printf(CLR_CYAN "║       NEXQOR — Post-Quantum Security & Cryptographic Tests   ║" CLR_RESET "\n");
    printf(CLR_CYAN "╚══════════════════════════════════════════════════════════════╝" CLR_RESET "\n\n");

    RUN_TEST(test_kem_agreement_and_negative);
    RUN_TEST(test_dsa_signing_and_tampering);
    RUN_TEST(test_directional_kdf_separation);
    RUN_TEST(test_aead_aad_binding_and_tampering);
    RUN_TEST(test_sliding_replay_window);
    RUN_TEST(test_trust_store_peer_authentication);
    RUN_TEST(test_packet_framing_and_reassembly);
    RUN_TEST(test_session_isolation_and_cleanup);

    printf("\n" CLR_BOLD "════════════════════════════════════════════════════════════════" CLR_RESET "\n");
    printf("Test Results: %d/%d passed (%d failed)\n",
           g_tests_passed, g_tests_run, g_tests_failed);

    if (g_tests_failed == 0) {
        printf(CLR_GREEN CLR_BOLD "ALL SECURITY & REGRESSION TESTS PASSED SUCCESSFULLY!" CLR_RESET "\n\n");
        return 0;
    } else {
        printf(CLR_RED CLR_BOLD "SOME TESTS FAILED!" CLR_RESET "\n\n");
        return 1;
    }
}
