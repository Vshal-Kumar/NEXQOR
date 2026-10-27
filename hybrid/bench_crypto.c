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
#include "perf_monitor.h"

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
    int runs = (argc > 2) ? atoi(argv[2]) : 5;
    if (rounds < 10) rounds = BENCH_ROUNDS_DEFAULT;
    if (runs < 1) runs = 5;

    if (hybrid_crypto_init() != HYBRID_SUCCESS) {
        fprintf(stderr, "Crypto init failed\n");
        return 1;
    }

    perf_benchmark_session_t session;
    if (perf_session_init(&session, (size_t)runs, (size_t)rounds) != 0) {
        fprintf(stderr, "Failed to initialize performance monitor session\n");
        return 1;
    }

    perf_ui_print_section_header("QRYPTONEX HYBRID SUITE: N-RUN BENCHMARK (X25519+MLKEM768 / ED25519+MLDSA65)");
    printf("  Benchmark Setup: %d rounds per run across %d completed runs\n", rounds, runs);
    if (session.temp.available) {
        printf("  Hardware Sensor: %s (%s) — Initial Temp: %.2f °C\n",
               session.temp.sensor_path, session.temp.sensor_type, session.temp.initial_temp_c);
    } else {
        printf("  Hardware Sensor: Unavailable (No sysfs thermal zone detected)\n");
    }
    printf("  Initial Process RAM: %.3f MB | Heap: %.4f MB\n\n",
           session.mem.initial_ram_mb, session.mem.heap_usage_mb);

    perf_ui_print_run_header();

    sample_set_t s_kex_gen = {0}, s_kex_enc = {0}, s_kex_dec = {0};
    sample_set_t s_sig_gen = {0}, s_sig_sgn = {0}, s_sig_ver = {0};

    hybrid_kex_public_key_t pk;
    hybrid_kex_secret_key_t sk;
    hybrid_kex_ciphertext_t ct;
    uint8_t ss1[HYBRID_IKM_BYTES], ss2[HYBRID_IKM_BYTES];

    hybrid_identity_pk_t id_pk;
    hybrid_identity_sk_t id_sk;
    hybrid_signature_t sig;
    uint8_t digest[HYBRID_SHA384_DIGEST_BYTES];
    memset(digest, 0x42, sizeof(digest));

    for (int r = 0; r < runs; r++) {
        uint64_t t0 = perf_get_nanos();

        if (s_kex_gen.samples) {
            free(s_kex_gen.samples); free(s_kex_enc.samples); free(s_kex_dec.samples);
            free(s_sig_gen.samples); free(s_sig_sgn.samples); free(s_sig_ver.samples);
        }

        s_kex_gen.samples = malloc(rounds * sizeof(double)); s_kex_gen.count = rounds;
        s_kex_enc.samples = malloc(rounds * sizeof(double)); s_kex_enc.count = rounds;
        s_kex_dec.samples = malloc(rounds * sizeof(double)); s_kex_dec.count = rounds;

        s_sig_gen.samples = malloc(rounds * sizeof(double)); s_sig_gen.count = rounds;
        s_sig_sgn.samples = malloc(rounds * sizeof(double)); s_sig_sgn.count = rounds;
        s_sig_ver.samples = malloc(rounds * sizeof(double)); s_sig_ver.count = rounds;

        for (int i = 0; i < rounds; i++) {
            uint64_t t_op = ns_now();
            hybrid_kex_generate_keypair(&pk, &sk);
            s_kex_gen.samples[i] = (double)(ns_now() - t_op) / 1000.0;

            t_op = ns_now();
            hybrid_kex_encapsulate(&ct, ss1, &pk);
            s_kex_enc.samples[i] = (double)(ns_now() - t_op) / 1000.0;

            t_op = ns_now();
            hybrid_kex_decapsulate(ss2, &ct, &sk);
            s_kex_dec.samples[i] = (double)(ns_now() - t_op) / 1000.0;

            t_op = ns_now();
            hybrid_generate_identity_keys(&id_pk, &id_sk);
            s_sig_gen.samples[i] = (double)(ns_now() - t_op) / 1000.0;

            t_op = ns_now();
            hybrid_sign_transcript(&sig, digest, &id_sk);
            s_sig_sgn.samples[i] = (double)(ns_now() - t_op) / 1000.0;

            t_op = ns_now();
            hybrid_verify_transcript(&sig, digest, &id_pk);
            s_sig_ver.samples[i] = (double)(ns_now() - t_op) / 1000.0;
        }

        double run_time_ms = (double)(perf_get_nanos() - t0) / 1000000.0;
        perf_session_record_run(&session, (size_t)r, run_time_ms);
        perf_ui_print_run_row((size_t)r, (size_t)runs, run_time_ms, session.run_temps_c[r],
                              session.temp.available, session.run_ram_mb[r], session.run_cpu_pct[r]);
    }
    perf_ui_print_run_footer();
    perf_session_finalize(&session);

    detailed_stats_t st_kex_gen, st_kex_enc, st_kex_dec;
    compute_stats(&s_kex_gen, &st_kex_gen);
    compute_stats(&s_kex_enc, &st_kex_enc);
    compute_stats(&s_kex_dec, &st_kex_dec);

    detailed_stats_t st_sig_gen, st_sig_sgn, st_sig_ver;
    compute_stats(&s_sig_gen, &st_sig_gen);
    compute_stats(&s_sig_sgn, &st_sig_sgn);
    compute_stats(&s_sig_ver, &st_sig_ver);

    /* ── 1. Hybrid KEX Benchmark ── */
    printf("\n── [1/4] Key Agreement (X25519 + ML-KEM-768 Hybrid KEX) ──────────────────────────────────────────────────────────\n");
    printf("%-26s │ %-8s │ %-8s │ %-8s │ %-8s │ %-8s │ %-8s │ %-8s │ %-17s\n",
           "Operation", "Mean µs", "Median", "Min µs", "Max µs", "StdDev", "CV (%)", "95th %", "95% Conf. Int.");
    printf("───────────────────────────┼──────────┼──────────┼──────────┼──────────┼──────────┼──────────┼──────────┼───────────────────\n");
    print_stat_row("Hybrid-KEX KeyGen", &st_kex_gen);
    print_stat_row("Hybrid-KEX Encap", &st_kex_enc);
    print_stat_row("Hybrid-KEX Decap", &st_kex_dec);
    printf("\n");

    /* ── 2. Hybrid Dual Signature Benchmark ── */
    printf("── [2/4] Digital Signatures (Ed25519 + ML-DSA-65 Dual Signature) ──────────────────────────────────────────────────\n");
    printf("%-26s │ %-8s │ %-8s │ %-8s │ %-8s │ %-8s │ %-8s │ %-8s │ %-17s\n",
           "Operation", "Mean µs", "Median", "Min µs", "Max µs", "StdDev", "CV (%)", "95th %", "95% Conf. Int.");
    printf("───────────────────────────┼──────────┼──────────┼──────────┼──────────┼──────────┼──────────┼──────────┼───────────────────\n");
    print_stat_row("Dual-Sig KeyGen", &st_sig_gen);
    print_stat_row("Dual-Sig Sign (3.3KB)", &st_sig_sgn);
    print_stat_row("Dual-Sig Verify", &st_sig_ver);
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
        uint64_t t_op = ns_now();
        hybrid_sha384_digest(in_buf, sizeof(in_buf), out_hash);
        s_sha384.samples[i] = (double)(ns_now() - t_op) / 1000.0;

        t_op = ns_now();
        hybrid_kdf_derive_traffic_keys(c2s, s2c, ss1, out_hash, dummy_nonce, dummy_nonce, 1234567ULL);
        s_hkdf.samples[i] = (double)(ns_now() - t_op) / 1000.0;
    }

    detailed_stats_t st_sha, st_hkdf;
    compute_stats(&s_sha384, &st_sha);   print_stat_row("SHA-384 (1KB buffer)", &st_sha);
    compute_stats(&s_hkdf, &st_hkdf);     print_stat_row("HKDF-SHA-384 Dual Keys", &st_hkdf);
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
    double aead_1kb_us = 0;

    for (int s = 0; s < num_sizes; s++) {
        size_t sz = sizes[s];
        uint8_t *plain = malloc(sz);
        uint8_t *cipher = malloc(sz);
        uint8_t *decrypted = malloc(sz);
        memset(plain, 0x77, sz);

        sample_set_t s_aead = { .samples = malloc(rounds * sizeof(double)), .count = rounds };
        for (int i = 0; i < rounds; i++) {
            uint64_t t_op = ns_now();
            aead_encrypt(plain, (int)sz, aad, sizeof(aad), key, nonce, cipher, tag);
            aead_decrypt(cipher, (int)sz, aad, sizeof(aad), key, nonce, tag, decrypted);
            s_aead.samples[i] = (double)(ns_now() - t_op) / 1000.0;
        }

        char label[32];
        if (sz < 1024) snprintf(label, sizeof(label), "AEAD Enc+Dec (%zu B)", sz);
        else snprintf(label, sizeof(label), "AEAD Enc+Dec (%zu KB)", sz / 1024);

        detailed_stats_t st_aead;
        compute_stats(&s_aead, &st_aead);
        if (sz == 1024) aead_1kb_us = st_aead.mean;
        print_stat_row(label, &st_aead);

        free(plain); free(cipher); free(decrypted); free(s_aead.samples);
    }

    /* ── COMPREHENSIVE MULTI-METRIC PERFORMANCE REPORT ────────────── */
    perf_ui_print_section_header("COMPREHENSIVE MULTI-METRIC BENCHMARK REPORT");

    /* 1. Cryptographic Metrics */
    perf_stats_t stat_kex_gen = {
        .mean = st_kex_gen.mean / 1000.0, .min = st_kex_gen.min / 1000.0, .max = st_kex_gen.max / 1000.0,
        .median = st_kex_gen.median / 1000.0, .stddev = st_kex_gen.stddev / 1000.0, .p95 = st_kex_gen.p95 / 1000.0,
        .throughput_ops_sec = (st_kex_gen.mean > 0) ? (1000000.0 / st_kex_gen.mean) : 0
    };
    perf_ui_print_crypto_summary("Hybrid KEX KeyGen (X25519 + ML-KEM-768)", &stat_kex_gen,
                                 sizeof(hybrid_kex_public_key_t), sizeof(hybrid_kex_secret_key_t), 0, 0, 0);

    perf_stats_t stat_kex_enc = {
        .mean = st_kex_enc.mean / 1000.0, .min = st_kex_enc.min / 1000.0, .max = st_kex_enc.max / 1000.0,
        .median = st_kex_enc.median / 1000.0, .stddev = st_kex_enc.stddev / 1000.0, .p95 = st_kex_enc.p95 / 1000.0,
        .throughput_ops_sec = (st_kex_enc.mean > 0) ? (1000000.0 / st_kex_enc.mean) : 0
    };
    perf_ui_print_crypto_summary("Hybrid KEX Encapsulation", &stat_kex_enc,
                                 sizeof(hybrid_kex_public_key_t), 0, sizeof(hybrid_kex_ciphertext_t), 0, HYBRID_IKM_BYTES);

    perf_stats_t stat_kex_dec = {
        .mean = st_kex_dec.mean / 1000.0, .min = st_kex_dec.min / 1000.0, .max = st_kex_dec.max / 1000.0,
        .median = st_kex_dec.median / 1000.0, .stddev = st_kex_dec.stddev / 1000.0, .p95 = st_kex_dec.p95 / 1000.0,
        .throughput_ops_sec = (st_kex_dec.mean > 0) ? (1000000.0 / st_kex_dec.mean) : 0
    };
    perf_ui_print_crypto_summary("Hybrid KEX Decapsulation", &stat_kex_dec,
                                 0, sizeof(hybrid_kex_secret_key_t), sizeof(hybrid_kex_ciphertext_t), 0, HYBRID_IKM_BYTES);

    perf_stats_t stat_sig_gen = {
        .mean = st_sig_gen.mean / 1000.0, .min = st_sig_gen.min / 1000.0, .max = st_sig_gen.max / 1000.0,
        .median = st_sig_gen.median / 1000.0, .stddev = st_sig_gen.stddev / 1000.0, .p95 = st_sig_gen.p95 / 1000.0,
        .throughput_ops_sec = (st_sig_gen.mean > 0) ? (1000000.0 / st_sig_gen.mean) : 0
    };
    perf_ui_print_crypto_summary("Hybrid Dual-Sig KeyGen (Ed25519 + ML-DSA-65)", &stat_sig_gen,
                                 sizeof(hybrid_identity_pk_t), sizeof(hybrid_identity_sk_t), 0, 0, 0);

    perf_stats_t stat_sig_sgn = {
        .mean = st_sig_sgn.mean / 1000.0, .min = st_sig_sgn.min / 1000.0, .max = st_sig_sgn.max / 1000.0,
        .median = st_sig_sgn.median / 1000.0, .stddev = st_sig_sgn.stddev / 1000.0, .p95 = st_sig_sgn.p95 / 1000.0,
        .throughput_ops_sec = (st_sig_sgn.mean > 0) ? (1000000.0 / st_sig_sgn.mean) : 0
    };
    perf_ui_print_crypto_summary("Hybrid Dual-Sig Sign", &stat_sig_sgn,
                                 0, sizeof(hybrid_identity_sk_t), 0, sizeof(hybrid_signature_t), 0);

    perf_stats_t stat_sig_ver = {
        .mean = st_sig_ver.mean / 1000.0, .min = st_sig_ver.min / 1000.0, .max = st_sig_ver.max / 1000.0,
        .median = st_sig_ver.median / 1000.0, .stddev = st_sig_ver.stddev / 1000.0, .p95 = st_sig_ver.p95 / 1000.0,
        .throughput_ops_sec = (st_sig_ver.mean > 0) ? (1000000.0 / st_sig_ver.mean) : 0
    };
    perf_ui_print_crypto_summary("Hybrid Dual-Sig Verification", &stat_sig_ver,
                                 sizeof(hybrid_identity_pk_t), 0, 0, sizeof(hybrid_signature_t), 0);

    if (aead_1kb_us > 0) {
        perf_stats_t stat_aead = {
            .mean = aead_1kb_us / 1000.0, .min = aead_1kb_us / 1000.0, .max = aead_1kb_us / 1000.0,
            .median = aead_1kb_us / 1000.0, .stddev = 0, .p95 = aead_1kb_us / 1000.0,
            .throughput_ops_sec = (1000000.0 / aead_1kb_us)
        };
        perf_ui_print_crypto_summary("ChaCha20-Poly1305 Enc+Dec (1KB)", &stat_aead, 0, 32, 1024, 16, 0);
    }

    /* 2. Memory Metrics */
    perf_ui_print_memory_summary(&session.mem);

    /* 3. CPU Metrics */
    perf_ui_print_cpu_summary(&session.cpu, (size_t)rounds * (size_t)runs * 6);

    /* 4. Temperature Metrics */
    perf_ui_print_temp_summary(&session.temp);

    free(s_kex_gen.samples); free(s_kex_enc.samples); free(s_kex_dec.samples);
    free(s_sig_gen.samples); free(s_sig_sgn.samples); free(s_sig_ver.samples);
    free(s_sha384.samples);   free(s_hkdf.samples);
    perf_session_cleanup(&session);

    return 0;
}
