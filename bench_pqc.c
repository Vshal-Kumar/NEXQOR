/*
 * bench_pqc.c — Standalone PQC Cryptographic Operations Benchmark
 *
 * Project: Performance Evaluation of SIMD-Accelerated Post-Quantum
 *          Cryptography on Embedded ARM Platforms
 *
 * Measures execution time of every cryptographic primitive used in
 * the project, using the same optimized implementations:
 *
 *   ML-KEM-768  : keypair, encapsulate, decapsulate, derive_key
 *   ML-DSA-65   : keypair, sign, verify
 *   ChaCha20-Poly1305 AEAD : encrypt, decrypt
 *
 * Statistics reported:
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

#include "crypto/aead.h"
#include "wrappers/dsa_wrapper.h"
#include "wrappers/kem_wrapper.h"

#define BENCH_ROUNDS_DEFAULT 1000

/* Timer: nanosecond resolution */
static inline uint64_t ns_now(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* Sample array wrapper for sorting-based stats */
typedef struct {
  double *samples; /* in microseconds */
  int count;
} sample_set_t;

/* Detailed statistics structure */
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

  // Sort to get percentiles and min/max
  qsort(s->samples, n, sizeof(double), compare_doubles);

  out->min = s->samples[0];
  out->max = s->samples[n - 1];

  double sum = 0.0;
  for (int i = 0; i < n; i++) {
    sum += s->samples[i];
  }
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

/* ── ML-KEM-768 Benchmark ────────────────────────────────────────── */
static void bench_kem(int rounds, sample_set_t *s_keygen,
                      sample_set_t *s_encaps, sample_set_t *s_decaps) {
  uint8_t pk[KEM_PK_BYTES];
  uint8_t sk[KEM_SK_BYTES];
  uint8_t ct[KEM_CT_BYTES];
  uint8_t ss_enc[KEM_SS_BYTES];
  uint8_t ss_dec[KEM_SS_BYTES];

  s_keygen->samples = malloc(rounds * sizeof(double));
  s_encaps->samples = malloc(rounds * sizeof(double));
  s_decaps->samples = malloc(rounds * sizeof(double));
  s_keygen->count = rounds;
  s_encaps->count = rounds;
  s_decaps->count = rounds;

  for (int i = 0; i < rounds; i++) {
    uint64_t t0 = ns_now();
    if (kem_keypair(pk, sk) != 0) {
      fprintf(stderr, "kem_keypair failed\n");
      exit(1);
    }
    s_keygen->samples[i] = (double)(ns_now() - t0) / 1000.0;

    t0 = ns_now();
    if (kem_enc(ct, ss_enc, pk) != 0) {
      fprintf(stderr, "kem_enc failed\n");
      exit(1);
    }
    s_encaps->samples[i] = (double)(ns_now() - t0) / 1000.0;

    t0 = ns_now();
    if (kem_dec(ss_dec, ct, sk) != 0) {
      fprintf(stderr, "kem_dec failed\n");
      exit(1);
    }
    s_decaps->samples[i] = (double)(ns_now() - t0) / 1000.0;
  }

  explicit_bzero(sk, sizeof(sk));
  explicit_bzero(ss_enc, sizeof(ss_enc));
  explicit_bzero(ss_dec, sizeof(ss_dec));
}

/* ── ML-DSA-65 Benchmark ─────────────────────────────────────────── */
static void bench_dsa(int rounds, sample_set_t *s_keygen, sample_set_t *s_sign,
                      sample_set_t *s_verify) {
  uint8_t pk[DSA_PK_BYTES];
  uint8_t sk[DSA_SK_BYTES];
  uint8_t sig[DSA_SIG_BYTES];
  size_t siglen = 0;

  const size_t MSG_LEN = 8 + DSA_PK_BYTES + KEM_SS_BYTES;
  uint8_t msg[8 + DSA_PK_BYTES + KEM_SS_BYTES];
  memset(msg, 0xAB, MSG_LEN);

  s_keygen->samples = malloc(rounds * sizeof(double));
  s_sign->samples = malloc(rounds * sizeof(double));
  s_verify->samples = malloc(rounds * sizeof(double));
  s_keygen->count = rounds;
  s_sign->count = rounds;
  s_verify->count = rounds;

  for (int i = 0; i < rounds; i++) {
    uint64_t t0 = ns_now();
    if (dsa_keypair(pk, sk) != 0) {
      fprintf(stderr, "dsa_keypair failed\n");
      exit(1);
    }
    s_keygen->samples[i] = (double)(ns_now() - t0) / 1000.0;

    t0 = ns_now();
    if (dsa_sign(sig, &siglen, msg, MSG_LEN, sk) != 0) {
      fprintf(stderr, "dsa_sign failed\n");
      exit(1);
    }
    s_sign->samples[i] = (double)(ns_now() - t0) / 1000.0;

    t0 = ns_now();
    int rc = dsa_verify(sig, siglen, msg, MSG_LEN, pk);
    s_verify->samples[i] = (double)(ns_now() - t0) / 1000.0;

    if (i == 0 && rc != 0) {
      fprintf(stderr, "dsa_verify failed on first iteration\n");
      exit(1);
    }
  }

  explicit_bzero(sk, sizeof(sk));
  explicit_bzero(sig, sizeof(sig));
}

/* ── ChaCha20-Poly1305 AEAD Dependency Benchmark ─────────────────── */
static void bench_aead_size(int size, int rounds, double *enc_us_out,
                            double *dec_us_out) {
  uint8_t key[AEAD_KEY_BYTES];
  uint8_t nonce[AEAD_NONCE_BYTES];
  uint8_t *pt = malloc(size);
  uint8_t *ct = malloc(size);
  uint8_t tag[AEAD_TAG_BYTES];
  uint8_t *rt = malloc(size);

  memset(key, 0x42, AEAD_KEY_BYTES);
  memset(nonce, 0x17, AEAD_NONCE_BYTES);
  memset(pt, 0xCC, size);

  uint64_t enc_sum = 0, dec_sum = 0;

  for (int i = 0; i < rounds; i++) {
    uint64_t t0 = ns_now();
    int ct_len = aead_encrypt(pt, size, key, nonce, ct, tag);
    enc_sum += (ns_now() - t0);

    if (ct_len < 0) {
      fprintf(stderr, "aead_encrypt failed\n");
      exit(1);
    }

    t0 = ns_now();
    int pt_len = aead_decrypt(ct, ct_len, key, nonce, tag, rt);
    dec_sum += (ns_now() - t0);

    if (pt_len < 0) {
      fprintf(stderr, "aead_decrypt failed\n");
      exit(1);
    }
  }

  *enc_us_out = (double)enc_sum / (double)rounds / 1000.0;
  *dec_us_out = (double)dec_sum / (double)rounds / 1000.0;

  free(pt);
  free(ct);
  free(rt);
}

/* Print stats utility */
static void print_stat_row(const char *op, const detailed_stats_t *d,
                           const char *unit) {
  printf("│ %-16s │ %10.3f │ %10.3f │ %10.3f │ %10.3f │ %10.3f │ %10.3f │ "
         "%10.3f │ %4s │\n",
         op, d->mean, d->median, d->min, d->max, d->stddev, d->p95, d->p99,
         unit);
}

int main(int argc, char *argv[]) {
  int rounds = BENCH_ROUNDS_DEFAULT;
  if (argc > 1) {
    rounds = atoi(argv[1]);
    if (rounds < 10 || rounds > 100000) {
      fprintf(stderr, "Usage: %s [rounds]  (10 – 100000, default %d)\n",
              argv[0], BENCH_ROUNDS_DEFAULT);
      return 1;
    }
  }

  printf("\n[Warmup] Initializing and seeding cryptographic modules...\n");
  kem_warmup();
  dsa_warmup();
  printf("[Warmup] Complete. Steady state benchmarking starting.\n\n");

  /* ── TABLE 2: ML-KEM-768 Benchmark ────────────────────────────── */
  sample_set_t kem_keygen, kem_encaps, kem_decaps;
  bench_kem(rounds, &kem_keygen, &kem_encaps, &kem_decaps);

  detailed_stats_t d_kem_kg, d_kem_enc, d_kem_dec;
  compute_stats(&kem_keygen, &d_kem_kg);
  compute_stats(&kem_encaps, &d_kem_enc);
  compute_stats(&kem_decaps, &d_kem_dec);

  printf("┌────────────────────────────────────────────────────────────────────"
         "────────────────────────────────────┐\n");
  printf("│ TABLE 2 — ML-KEM-768 Cryptographic Benchmarks (%d rounds)          "
         "                                      │\n",
         rounds);
  printf("├──────────────────┬────────────┬────────────┬────────────┬──────────"
         "──┬────────────┬────────────┬────────────┬──────┤\n");
  printf("│ Operation        │  Mean (µs) │   Median   │    Min     │    Max   "
         "  │  Std Dev   │    P95     │    P99     │ Unit │\n");
  printf("├──────────────────┼────────────┼────────────┼────────────┼──────────"
         "──┼────────────┼────────────┼────────────┼──────┤\n");
  print_stat_row("KeyGen", &d_kem_kg, "µs");
  print_stat_row("Encapsulation", &d_kem_enc, "µs");
  print_stat_row("Decapsulation", &d_kem_dec, "µs");
  printf("└──────────────────┴────────────┴────────────┴────────────┴──────────"
         "──┴────────────┴────────────┴────────────┴──────┘\n\n");

  /* ── TABLE 3: ML-DSA-65 Benchmark ─────────────────────────────── */
  sample_set_t dsa_keygen, dsa_sign, dsa_verify;
  bench_dsa(rounds, &dsa_keygen, &dsa_sign, &dsa_verify);

  detailed_stats_t d_dsa_kg, d_dsa_sig, d_dsa_ver;
  compute_stats(&dsa_keygen, &d_dsa_kg);
  compute_stats(&dsa_sign, &d_dsa_sig);
  compute_stats(&dsa_verify, &d_dsa_ver);

  printf("┌────────────────────────────────────────────────────────────────────"
         "────────────────────────────────────┐\n");
  printf("│ TABLE 3 — ML-DSA-65 Cryptographic Benchmarks (%d rounds)           "
         "                                      │\n",
         rounds);
  printf("├──────────────────┬────────────┬────────────┬────────────┬──────────"
         "──┬────────────┬────────────┬────────────┬──────┤\n");
  printf("│ Operation        │  Mean (µs) │   Median   │    Min     │    Max   "
         "  │  Std Dev   │    P95     │    P99     │ Unit │\n");
  printf("├──────────────────┼────────────┼────────────┼────────────┼──────────"
         "──┼────────────┼────────────┼────────────┼──────┤\n");
  print_stat_row("KeyGen", &d_dsa_kg, "µs");
  print_stat_row("Signing", &d_dsa_sig, "µs");
  print_stat_row("Verification", &d_dsa_ver, "µs");
  printf("└──────────────────┴────────────┴────────────┴────────────┴──────────"
         "──┴────────────┴────────────┴────────────┴──────┘\n\n");

  /* ── TABLE 4: ChaCha20-Poly1305 Payload Dependency ─────────────── */
  int payload_sizes[] = {64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384};
  const char *payload_labels[] = {"64 B", "128 B", "256 B", "512 B", "1 KB",
                                  "2 KB", "4 KB",  "8 KB",  "16 KB"};
  int num_sizes = 9;

  printf("┌────────────────────────────────────────────────────────────────────"
         "─────┐\n");
  printf("│ TABLE 4 — ChaCha20-Poly1305 Payload Dependency Performance         "
         "     │\n");
  printf("├─────────────┬──────────────────┬──────────────────┬────────────────"
         "─────┤\n");
  printf("│ Payload     │ Encrypt Time     │ Decrypt Time     │ Throughput "
         "(MB/s)   │\n");
  printf("│ Size        │ (Mean µs)        │ (Mean µs)        │ (Enc / Dec)    "
         "     │\n");
  printf("├─────────────┼──────────────────┼──────────────────┼────────────────"
         "─────┤\n");
  for (int i = 0; i < num_sizes; i++) {
    double enc_us = 0, dec_us = 0;
    bench_aead_size(payload_sizes[i], rounds, &enc_us, &dec_us);
    double enc_throughput = (double)payload_sizes[i] / enc_us; /* B/µs = MB/s */
    double dec_throughput = (double)payload_sizes[i] / dec_us;
    printf("│ %-11s │ %16.3f │ %16.3f │ %8.1f / %-8.1f │\n", payload_labels[i],
           enc_us, dec_us, enc_throughput, dec_throughput);
  }
  printf("└─────────────┴──────────────────┴──────────────────┴────────────────"
         "─────┘\n\n");

  /* ── TABLE 7: Handshake Phase Breakdown (CPU Execution) ────────── */
  sample_set_t s_hs_ser;
  s_hs_ser.samples = malloc(rounds * sizeof(double));
  s_hs_ser.count = rounds;

  sample_set_t s_hs_par;
  s_hs_par.samples = malloc(rounds * sizeof(double));
  s_hs_par.count = rounds;

  double kem_kg_sum = 0, dsa_kg_sum = 0, enc_sum = 0, dec_sum = 0, sign_sum = 0,
         verify_sum = 0, kdf_sum = 0;

  for (int i = 0; i < rounds; i++) {
    double k_kg = kem_keygen.samples[i];
    double d_kg = dsa_keygen.samples[i];
    double enc = kem_encaps.samples[i];
    double dec = kem_decaps.samples[i];
    double sig = dsa_sign.samples[i];
    double ver = dsa_verify.samples[i];

    // Measure SHAKE KDF
    uint8_t ss[KEM_SS_BYTES];
    uint8_t derived[DERIVED_KEY_BYTES];
    memset(ss, 0x5A, sizeof(ss));
    uint8_t c_nonce[16] = {0};
    uint8_t s_nonce[16] = {0};
    uint64_t t0 = ns_now();
    kem_derive_key(derived, ss, c_nonce, s_nonce, 12345ULL);
    double kdf = (double)(ns_now() - t0) / 1000.0;

    kem_kg_sum += k_kg;
    dsa_kg_sum += d_kg;
    enc_sum += enc;
    dec_sum += dec;
    sign_sum += sig;
    verify_sum += ver;
    kdf_sum += kdf;

    // Serial Handshake: (KEM KeyGen + DSA KeyGen) + Server Encap + Server Sign + Client Decap + Client Verify + Client Sign + Server Verify + Key derivation
    s_hs_ser.samples[i] = k_kg + d_kg + enc + sig + dec + ver + sig + ver + kdf;

    // Parallel Handshake: max(KEM KeyGen, DSA KeyGen) + Server Encap + Server Sign + max(Client Decap, Client Verify) + Client Sign + Server Verify + Key derivation
    double max_keygen = (k_kg > d_kg) ? k_kg : d_kg;
    double max_client_proc = (dec > ver) ? dec : ver;
    s_hs_par.samples[i] = max_keygen + enc + sig + max_client_proc + sig + ver + kdf;
  }

  double avg_k_kg = kem_kg_sum / rounds;
  double avg_d_kg = dsa_kg_sum / rounds;
  double avg_enc = enc_sum / rounds;
  double avg_dec = dec_sum / rounds;
  double avg_sig = sign_sum / rounds;
  double avg_ver = verify_sum / rounds;
  double avg_kdf = kdf_sum / rounds;

  detailed_stats_t d_hs_ser;
  compute_stats(&s_hs_ser, &d_hs_ser);

  detailed_stats_t d_hs_par;
  compute_stats(&s_hs_par, &d_hs_par);

  printf("┌─────────────────────────────────────────┬──────────────────┬──────────────────┐\n");
  printf("│ TABLE 7 — Standalone Cryptographic CPU Execution Handshake Breakdown          │\n");
  printf("├─────────────────────────────────────────┼──────────────────┼──────────────────┤\n");
  printf("│ Phase / Operation                       │ Serial Mean (µs) │ Parallel Mean(µs)│\n");
  printf("├─────────────────────────────────────────┼──────────────────┼──────────────────┤\n");
  printf("│ Client KEM KeyGen                       │ %16.3f │ %16.3f │\n", avg_k_kg, avg_k_kg);
  printf("│ Client DSA KeyGen                       │ %16.3f │ %16.3f │\n", avg_d_kg, avg_d_kg);
  printf("│ Server KEM Encapsulation                │ %16.3f │ %16.3f │\n", avg_enc, avg_enc);
  printf("│ Server DSA Signature                    │ %16.3f │ %16.3f │\n", avg_sig, avg_sig);
  printf("│ Client KEM Decapsulation                │ %16.3f │ %16.3f │\n", avg_dec, avg_dec);
  printf("│ Client DSA Verification                 │ %16.3f │ %16.3f │\n", avg_ver, avg_ver);
  printf("│ Client DSA Signature                    │ %16.3f │ %16.3f │\n", avg_sig, avg_sig);
  printf("│ Server DSA Verification                 │ %16.3f │ %16.3f │\n", avg_ver, avg_ver);
  printf("│ ChaCha20 Key Setup (SHAKE KDF)          │ %16.3f │ %16.3f │\n", avg_kdf, avg_kdf);
  printf("├─────────────────────────────────────────┼──────────────────┼──────────────────┤\n");
  printf("│ Total CPU Handshake Latency             │ %16.3f │ %16.3f │\n", d_hs_ser.mean, d_hs_par.mean);
  printf("└─────────────────────────────────────────┴──────────────────┴──────────────────┘\n\n");

  /* ── TABLE 8: Network Overhead ────────────────────────────────── */
  size_t total_network_bytes =
      KEM_PK_BYTES + DSA_PK_BYTES + 16 +          // CLIENT_HELLO (kem_pk, dsa_pk, c_nonce)
      DSA_PK_BYTES + KEM_CT_BYTES + 8 + 16 + 3309 + // SERVER_HELLO (srv_dsa_pk, kem_ct, sid, s_nonce, srv_sig)
      3309;                                       // CLIENT_AUTH (client_sig)
  printf("┌─────────────────────────────────────────────────────────┐\n");
  printf("│ TABLE 8 — Network Bandwidth / Overhead Breakdown        │\n");
  printf("├─────────────────────────────────────────┬───────────────┤\n");
  printf("│ Handshake Component                     │ Size (Bytes)  │\n");
  printf("├─────────────────────────────────────────┼───────────────┤\n");
  printf("│ Client KEM Public Key                   │ %13d │\n", KEM_PK_BYTES);
  printf("│ Client DSA Public Key                   │ %13d │\n", DSA_PK_BYTES);
  printf("│ Client Nonce                            │ %13d │\n", 16);
  printf("│ Server DSA Public Key                   │ %13d │\n", DSA_PK_BYTES);
  printf("│ KEM Ciphertext                          │ %13d │\n", KEM_CT_BYTES);
  printf("│ Session ID                              │ %13d │\n", 8);
  printf("│ Server Nonce                            │ %13d │\n", 16);
  printf("│ Server Signature (ML-DSA-65)            │ %13d │\n", 3309);
  printf("│ Client Signature (ML-DSA-65)            │ %13d │\n", 3309);
  printf("├─────────────────────────────────────────┼───────────────┤\n");
  printf("│ Total Handshake Size                    │ %13zu │\n",
         total_network_bytes);
  printf("└─────────────────────────────────────────┴───────────────┘\n\n");

  /* ── TABLE 18: Statistical Summary of CPU Handshake Latency ───── */
  printf("┌─────────────────────────────────────────┬──────────────────┬──────────────────┐\n");
  printf("│ TABLE 18 — Standalone CPU Handshake Latency Statistical Summary               │\n");
  printf("├─────────────────────────────────────────┼──────────────────┼──────────────────┤\n");
  printf("│ Metric                                  │ Serial (µs)      │ Parallel (µs)    │\n");
  printf("├─────────────────────────────────────────┼──────────────────┼──────────────────┤\n");
  printf("│ Mean                                    │ %16.3f │ %16.3f │\n", d_hs_ser.mean, d_hs_par.mean);
  printf("│ Median                                  │ %16.3f │ %16.3f │\n", d_hs_ser.median, d_hs_par.median);
  printf("│ Minimum                                 │ %16.3f │ %16.3f │\n", d_hs_ser.min, d_hs_par.min);
  printf("│ Maximum                                 │ %16.3f │ %16.3f │\n", d_hs_ser.max, d_hs_par.max);
  printf("│ Range (Max - Min)                       │ %16.3f │ %16.3f │\n", d_hs_ser.max - d_hs_ser.min, d_hs_par.max - d_hs_par.min);
  printf("│ Variance                                │ %16.3f │ %16.3f │\n", d_hs_ser.variance, d_hs_par.variance);
  printf("│ Standard Deviation                      │ %16.3f │ %16.3f │\n", d_hs_ser.stddev, d_hs_par.stddev);
  printf("│ Coefficient of Variation (CV)           │ %15.2f%% │ %15.2f%% │\n", d_hs_ser.coeff_var, d_hs_par.coeff_var);
  printf("│ 95th Percentile                         │ %16.3f │ %16.3f │\n", d_hs_ser.p95, d_hs_par.p95);
  printf("│ 99th Percentile                         │ %16.3f │ %16.3f │\n", d_hs_ser.p99, d_hs_par.p99);
  printf("│ 95%% Confidence Interval                 │ [%7.1f,%7.1f] │ [%7.1f,%7.1f] │\n",
         d_hs_ser.ci_lower, d_hs_ser.ci_upper, d_hs_par.ci_lower, d_hs_par.ci_upper);
  printf("└─────────────────────────────────────────┴──────────────────┴──────────────────┘\n\n");

  // Free all allocated arrays
  free(kem_keygen.samples);
  free(kem_encaps.samples);
  free(kem_decaps.samples);
  free(dsa_keygen.samples);
  free(dsa_sign.samples);
  free(dsa_verify.samples);
  free(s_hs_ser.samples);
  free(s_hs_par.samples);

  return 0;
}
