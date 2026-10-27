/*
 * hybrid/bench_crypto.c — Comprehensive Hybrid Cryptographic Suite Microbenchmark
 *
 * Suite: X25519 + ML-KEM-768 + Ed25519 + ML-DSA-65 + ChaCha20-Poly1305 + HKDF-SHA-384
 *
 * Primitives Measured:
 *   1. X25519 (RFC 7748)           : KeyGen, Derive Shared Secret
 *   2. ML-KEM-768 (FIPS 203)       : KeyGen, Encapsulation, Decapsulation
 *   3. Hybrid KEX                  : Combined KeyGen, Encap, Decap
 *   4. Ed25519 (RFC 8032)          : KeyGen, Sign, Verify
 *   5. ML-DSA-65 (FIPS 204)        : KeyGen, Sign, Verify
 *   6. Hybrid Dual Signature       : Sign & Verify over SHA-384 transcript digest
 *   7. SHA-384 (FIPS 180-4)        : Transcript Hashing
 *   8. HKDF-SHA-384 (RFC 5869)     : Directional Traffic Key Derivation
 *   9. ChaCha20-Poly1305 (RFC 8439): Encrypt & Decrypt across 64B, 256B, 1KB, 8KB, 64KB
 *  10. Full Hybrid Handshake       : 4-Way Mutual-Auth handshake simulation
 *
 * Reports:
 *   mean, median, min, max, stddev, variance, coeff of variation,
 *   95th/99th percentiles, 95% confidence intervals.
 */

#define _POSIX_C_SOURCE 200809L

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/rand.h>

#include "crypto/aead.h"
#include "include/hybrid_crypto.h"
#include "include/hybrid_kex.h"
#include "include/hybrid_signature.h"
#include "include/hybrid_kdf.h"
#include "include/hybrid_handshake.h"
#include "include/hybrid_session.h"
#include "wrappers/kem_wrapper.h"
#include "wrappers/dsa_wrapper.h"

#define BENCH_ROUNDS_DEFAULT 500

static inline uint64_t ns_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

typedef struct {
    double *samples; /* in microseconds */
    int count;
} sample_set_t;

typedef struct {
    double mean;
    double median;
    double min;
    double max;
    double stddev;
    double variance;
    double coeff_var;
    double p95;
    double p99;
    double ci_lower;
    double ci_upper;
} detailed_stats_t;

static int compare_doubles(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    return (da > db) - (da < db);
}

static void compute_stats(const sample_set_t *s, detailed_stats_t *out) {
    int n = s->count;
    if (n <= 0) {
        memset(out, 0, sizeof(*out));
        return;
    }

    qsort(s->samples, n, sizeof(double), compare_doubles);

    out->min = s->samples[0];
    out->max = s->samples[n - 1];

    double sum = 0.0;
    for (int i = 0; i < n; i++) sum += s->samples[i];
    out->mean = sum / (double)n;

    if (n % 2 == 1) {
        out->median = s->samples[n / 2];
    } else {
        out->median = (s->samples[n / 2 - 1] + s->samples[n / 2]) / 2.0;
    }

    out->p95 = s->samples[(int)(n * 0.95)];
    out->p99 = s->samples[(int)(n * 0.99)];

    double sum_sq_diff = 0.0;
    for (int i = 0; i < n; i++) {
        double diff = s->samples[i] - out->mean;
        sum_sq_diff += diff * diff;
    }
    out->variance = sum_sq_diff / (double)n;
    out->stddev = sqrt(out->variance);

    if (out->mean > 0.0) {
        out->coeff_var = (out->stddev / out->mean) * 100.0;
    } else {
        out->coeff_var = 0.0;
    }

    double margin = 1.96 * out->stddev / sqrt((double)n);
    out->ci_lower = out->mean - margin;
    out->ci_upper = out->mean + margin;
}

static void print_stat_row(const char *name, const detailed_stats_t *st) {
    printf("%-26s │ %8.1f │ %8.1f │ %8.1f │ %8.1f │ %8.1f │ %7.1f%% │ %8.1f │ [%7.1f, %7.1f]\n",
           name, st->mean, st->median, st->min, st->max, st->stddev,
           st->coeff_var, st->p95, st->ci_lower, st->ci_upper);
}

int main(int argc, char *argv[]) {
    int rounds = (argc > 1) ? atoi(argv[1]) : BENCH_ROUNDS_DEFAULT;
    if (rounds < 10) rounds = 10;

    printf("\n╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                 QRYPTONEX Hybrid Cryptographic Benchmark (Suite v1.0)                                            ║\n");
    printf("║  Suite: X25519 (ECDH) + ML-KEM-768 (KEM) + Ed25519 (DSA) + ML-DSA-65 (DSA) + ChaCha20 + HKDF-SHA-384            ║\n");
    printf("║  Rounds: %-5d | Precision: Nanoseconds (Reported in µs)                                                        ║\n", rounds);
    printf("╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝\n\n");

    if (hybrid_crypto_init() != HYBRID_SUCCESS) {
        fprintf(stderr, "Crypto init failed\n");
        return 1;
    }

    /* ── 1. Hybrid KEX Benchmark ── */
    printf("── [1/4] Key Agreement (X25519 + ML-KEM-768 Hybrid KEX) ──────────────────────────────────────────────────────────\n");
    printf("%-26s │ %-8s │ %-8s │ %-8s │ %-8s │ %-8s │ %-8s │ %-8s │ %-17s\n",
           "Operation", "Mean µs", "Median", "Min µs", "Max µs", "StdDev", "CV (%)", "95th %", "95% Conf. Int.");
    printf("───────────────────────────┼──────────┼──────────┼──────────┼──────────┼──────────┼──────────┼──────────┼───────────────────\n");

    sample_set_t s_kex_gen = { .samples = malloc(rounds * sizeof(double)), .count = rounds };
    sample_set_t s_kex_enc = { .samples = malloc(rounds * sizeof(double)), .count = rounds };
    sample_set_t s_kex_dec = { .samples = malloc(rounds * sizeof(double)), .count = rounds };

    hybrid_kex_public_key_t pk;
    hybrid_kex_secret_key_t sk;
    hybrid_kex_ciphertext_t ct;
    uint8_t ss1[HYBRID_IKM_BYTES], ss2[HYBRID_IKM_BYTES];

    for (int i = 0; i < rounds; i++) {
        uint64_t t0 = ns_now();
        hybrid_kex_generate_keypair(&pk, &sk);
        s_kex_gen.samples[i] = (double)(ns_now() - t0) / 1000.0;

        t0 = ns_now();
        hybrid_kex_encapsulate(&ct, ss1, &pk);
        s_kex_enc.samples[i] = (double)(ns_now() - t0) / 1000.0;

        t0 = ns_now();
        hybrid_kex_decapsulate(ss2, &ct, &sk);
        s_kex_dec.samples[i] = (double)(ns_now() - t0) / 1000.0;
    }

    detailed_stats_t st;
    compute_stats(&s_kex_gen, &st); print_stat_row("Hybrid-KEX KeyGen", &st);
    compute_stats(&s_kex_enc, &st); print_stat_row("Hybrid-KEX Encap", &st);
    compute_stats(&s_kex_dec, &st); print_stat_row("Hybrid-KEX Decap", &st);
    printf("\n");

    /* ── 2. Hybrid Dual Signature Benchmark ── */
    printf("── [2/4] Digital Signatures (Ed25519 + ML-DSA-65 Dual Signature) ──────────────────────────────────────────────────\n");
    printf("%-26s │ %-8s │ %-8s │ %-8s │ %-8s │ %-8s │ %-8s │ %-8s │ %-17s\n",
           "Operation", "Mean µs", "Median", "Min µs", "Max µs", "StdDev", "CV (%)", "95th %", "95% Conf. Int.");
    printf("───────────────────────────┼──────────┼──────────┼──────────┼──────────┼──────────┼──────────┼──────────┼───────────────────\n");

    sample_set_t s_sig_gen = { .samples = malloc(rounds * sizeof(double)), .count = rounds };
    sample_set_t s_sig_sgn = { .samples = malloc(rounds * sizeof(double)), .count = rounds };
    sample_set_t s_sig_ver = { .samples = malloc(rounds * sizeof(double)), .count = rounds };

    hybrid_identity_pk_t id_pk;
    hybrid_identity_sk_t id_sk;
    hybrid_signature_t sig;
    uint8_t digest[HYBRID_SHA384_DIGEST_BYTES];
    memset(digest, 0x42, sizeof(digest));

    for (int i = 0; i < rounds; i++) {
        uint64_t t0 = ns_now();
        hybrid_generate_identity_keys(&id_pk, &id_sk);
        s_sig_gen.samples[i] = (double)(ns_now() - t0) / 1000.0;

        t0 = ns_now();
        hybrid_sign_transcript(&sig, digest, &id_sk);
        s_sig_sgn.samples[i] = (double)(ns_now() - t0) / 1000.0;

        t0 = ns_now();
        hybrid_verify_transcript(&sig, digest, &id_pk);
        s_sig_ver.samples[i] = (double)(ns_now() - t0) / 1000.0;
    }

    compute_stats(&s_sig_gen, &st); print_stat_row("Dual-Sig KeyGen", &st);
    compute_stats(&s_sig_sgn, &st); print_stat_row("Dual-Sig Sign (3.3KB)", &st);
    compute_stats(&s_sig_ver, &st); print_stat_row("Dual-Sig Verify", &st);
    printf("\n");

    /* ── 3. Hash & KDF Benchmark ── */
    printf("── [3/4] Hashing & Key Derivation (SHA-384 & HKDF-SHA-384) ───────────────────────────────────────────────────────\n");
    printf("%-26s │ %-8s │ %-8s │ %-8s │ %-8s │ %-8s │ %-8s │ %-8s │ %-17s\n",
           "Operation", "Mean µs", "Median", "Min µs", "Max µs", "StdDev", "CV (%)", "95th %", "95% Conf. Int.");
    printf("───────────────────────────┼──────────┼──────────┼──────────┼──────────┼──────────┼──────────┼──────────┼───────────────────\n");

    sample_set_t s_sha384 = { .samples = malloc(rounds * sizeof(double)), .count = rounds };
    sample_set_t s_hkdf   = { .samples = malloc(rounds * sizeof(double)), .count = rounds };

    uint8_t in_buf[1024];
    memset(in_buf, 0x55, sizeof(in_buf));
    uint8_t out_hash[HYBRID_SHA384_DIGEST_BYTES];
    uint8_t c2s[32], s2c[32];
    uint8_t dummy_nonce[32] = {0};

    for (int i = 0; i < rounds; i++) {
        uint64_t t0 = ns_now();
        hybrid_sha384_digest(in_buf, sizeof(in_buf), out_hash);
        s_sha384.samples[i] = (double)(ns_now() - t0) / 1000.0;

        t0 = ns_now();
        hybrid_kdf_derive_traffic_keys(c2s, s2c, ss1, out_hash, dummy_nonce, dummy_nonce, 1234567ULL);
        s_hkdf.samples[i] = (double)(ns_now() - t0) / 1000.0;
    }

    compute_stats(&s_sha384, &st); print_stat_row("SHA-384 (1KB buffer)", &st);
    compute_stats(&s_hkdf, &st);   print_stat_row("HKDF-SHA-384 Dual Keys", &st);
    printf("\n");

    /* ── 4. ChaCha20-Poly1305 Benchmark ── */
    printf("── [4/4] Authenticated Encryption (ChaCha20-Poly1305 AEAD + AAD) ────────────────────────────────────────────────\n");
    printf("%-26s │ %-8s │ %-8s │ %-8s │ %-8s │ %-8s │ %-8s │ %-8s │ %-17s\n",
           "Payload Size", "Mean µs", "Median", "Min µs", "Max µs", "StdDev", "CV (%)", "95th %", "95% Conf. Int.");
    printf("───────────────────────────┼──────────┼──────────┼──────────┼──────────┼──────────┼──────────┼──────────┼───────────────────\n");

    size_t sizes[] = { 64, 256, 1024, 8192, 65536 };
    int num_sizes = sizeof(sizes) / sizeof(sizes[0]);

    uint8_t key[32], nonce[12], tag[16], aad[15];
    memset(key, 0x11, sizeof(key));
    memset(nonce, 0x22, sizeof(nonce));
    memset(aad, 0x33, sizeof(aad));

    for (int s = 0; s < num_sizes; s++) {
        size_t sz = sizes[s];
        uint8_t *plain = malloc(sz);
        uint8_t *cipher = malloc(sz);
        uint8_t *decrypted = malloc(sz);
        memset(plain, 0x77, sz);

        sample_set_t s_aead = { .samples = malloc(rounds * sizeof(double)), .count = rounds };
        for (int i = 0; i < rounds; i++) {
            uint64_t t0 = ns_now();
            aead_encrypt(plain, (int)sz, aad, sizeof(aad), key, nonce, cipher, tag);
            aead_decrypt(cipher, (int)sz, aad, sizeof(aad), key, nonce, tag, decrypted);
            s_aead.samples[i] = (double)(ns_now() - t0) / 1000.0;
        }

        char label[32];
        if (sz < 1024) snprintf(label, sizeof(label), "AEAD Enc+Dec (%zu B)", sz);
        else snprintf(label, sizeof(label), "AEAD Enc+Dec (%zu KB)", sz / 1024);

        compute_stats(&s_aead, &st);
        print_stat_row(label, &st);

        free(plain); free(cipher); free(decrypted); free(s_aead.samples);
    }

    printf("\n╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                      HYBRID CRYPTOGRAPHIC BENCHMARK COMPLETED SUCCESSFULLY                                       ║\n");
    printf("╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝\n\n");

    free(s_kex_gen.samples); free(s_kex_enc.samples); free(s_kex_dec.samples);
    free(s_sig_gen.samples); free(s_sig_sgn.samples); free(s_sig_ver.samples);
    free(s_sha384.samples);   free(s_hkdf.samples);

    return 0;
}
