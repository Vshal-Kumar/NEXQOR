/*
 * classical/bench_crypto.c — Comprehensive Classical Cryptographic Suite Benchmark
 *
 * Measures execution time of every cryptographic primitive used in
 * the classical IoT implementation:
 *
 *   X25519 (RFC 7748)     : keypair, shared_secret_derivation (ECDH)
 *   Ed25519 (RFC 8032)    : keypair, sign, verify
 *   AES-128-CCM AEAD      : encrypt, decrypt (across sizes 64B to 16KB)
 *   SHA-256 (FIPS 180-4)  : digest
 *   HKDF-SHA-256 (RFC 5869): derive (extract-and-expand)
 *   HMAC-SHA-256 (RFC 2104): compute
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
#include "wrappers/kem_wrapper.h"
#include "wrappers/dsa_wrapper.h"
#include "wrappers/hash_wrapper.h"
#include "wrappers/kdf_wrapper.h"
#include "perf_monitor.h"

#define BENCH_ROUNDS_DEFAULT 500

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

/* ── X25519 ECDH Benchmark ────────────────────────────────────────── */
static void bench_x25519(int rounds, sample_set_t *s_keygen,
                         sample_set_t *s_derive) {
  uint8_t pk1[X25519_PK_BYTES], sk1[X25519_SK_BYTES];
  uint8_t pk2[X25519_PK_BYTES], sk2[X25519_SK_BYTES];
  uint8_t ss[X25519_SS_BYTES];

  s_keygen->samples = malloc(rounds * sizeof(double));
  s_derive->samples = malloc(rounds * sizeof(double));
  s_keygen->count = rounds;
  s_derive->count = rounds;

  /* Generate second keypair for derivation testing */
  x25519_generate_keypair(pk2, sk2);

  for (int i = 0; i < rounds; i++) {
    uint64_t t0 = ns_now();
    if (x25519_generate_keypair(pk1, sk1) != 0) {
      fprintf(stderr, "x25519_generate_keypair failed\n");
      exit(1);
    }
    s_keygen->samples[i] = (double)(ns_now() - t0) / 1000.0;

    t0 = ns_now();
    if (x25519_derive_shared_secret(ss, sk1, pk2) != 0) {
      fprintf(stderr, "x25519_derive_shared_secret failed\n");
      exit(1);
    }
    s_derive->samples[i] = (double)(ns_now() - t0) / 1000.0;
  }

  explicit_bzero(sk1, sizeof(sk1));
  explicit_bzero(sk2, sizeof(sk2));
  explicit_bzero(ss, sizeof(ss));
}

/* ── Ed25519 Benchmark ────────────────────────────────────────────── */
static void bench_ed25519(int rounds, sample_set_t *s_keygen, sample_set_t *s_sign,
                          sample_set_t *s_verify) {
  uint8_t pk[ED25519_PK_BYTES];
  uint8_t sk[ED25519_SK_BYTES];
  uint8_t sig[ED25519_SIG_BYTES];
  size_t siglen = 0;

  const size_t MSG_LEN = 168; /* Canonical server transcript length */
  uint8_t msg[168];
  memset(msg, 0xAB, MSG_LEN);

  s_keygen->samples = malloc(rounds * sizeof(double));
  s_sign->samples = malloc(rounds * sizeof(double));
  s_verify->samples = malloc(rounds * sizeof(double));
  s_keygen->count = rounds;
  s_sign->count = rounds;
  s_verify->count = rounds;

  for (int i = 0; i < rounds; i++) {
    uint64_t t0 = ns_now();
    if (ed25519_generate_keypair(pk, sk) != 0) {
      fprintf(stderr, "ed25519_generate_keypair failed\n");
      exit(1);
    }
    s_keygen->samples[i] = (double)(ns_now() - t0) / 1000.0;

    t0 = ns_now();
    if (ed25519_sign(sig, &siglen, msg, MSG_LEN, sk) != 0) {
      fprintf(stderr, "ed25519_sign failed\n");
      exit(1);
    }
    s_sign->samples[i] = (double)(ns_now() - t0) / 1000.0;

    t0 = ns_now();
    int rc = ed25519_verify(sig, siglen, msg, MSG_LEN, pk);
    s_verify->samples[i] = (double)(ns_now() - t0) / 1000.0;

    if (i == 0 && rc != 0) {
      fprintf(stderr, "ed25519_verify failed on first iteration\n");
      exit(1);
    }
  }

  explicit_bzero(sk, sizeof(sk));
  explicit_bzero(sig, sizeof(sig));
}

/* ── AES-128-CCM AEAD Benchmark ──────────────────────────────────── */
static void bench_aead_size(int size, int rounds, double *enc_us_out,
                            double *dec_us_out) {
  uint8_t key[AEAD_KEY_BYTES];
  uint8_t nonce[AEAD_NONCE_BYTES];
  uint8_t *pt = malloc(size);
  uint8_t *ct = malloc(size);
  uint8_t tag[AEAD_TAG_BYTES];
  uint8_t *rt = malloc(size);

  /* AAD header simulation (15 bytes) */
  uint8_t aad[15] = {0x00, 0x01, 0x02, 0x03, 0x10, 0x00, 0x20, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x00, 0x01};

  memset(key, 0x42, AEAD_KEY_BYTES);
  memset(nonce, 0x17, AEAD_NONCE_BYTES);
  memset(pt, 0xCC, size);

  uint64_t enc_sum = 0, dec_sum = 0;

  for (int i = 0; i < rounds; i++) {
    /* Update nonce monotonically to prevent nonce reuse in real practice */
    nonce[0] = (uint8_t)(i & 0xFF);
    nonce[1] = (uint8_t)((i >> 8) & 0xFF);

    uint64_t t0 = ns_now();
    int ct_len = aes128_ccm_encrypt(pt, size, aad, sizeof(aad), key, nonce, ct, tag);
    enc_sum += (ns_now() - t0);

    if (ct_len < 0) {
      fprintf(stderr, "aes128_ccm_encrypt failed\n");
      exit(1);
    }

    t0 = ns_now();
    int pt_len = aes128_ccm_decrypt(ct, ct_len, aad, sizeof(aad), key, nonce, tag, rt);
    dec_sum += (ns_now() - t0);

    if (pt_len < 0) {
      fprintf(stderr, "aes128_ccm_decrypt failed\n");
      exit(1);
    }
  }

  *enc_us_out = (double)enc_sum / (double)rounds / 1000.0;
  *dec_us_out = (double)dec_sum / (double)rounds / 1000.0;

  free(pt);
  free(ct);
  free(rt);
}

static void bench_aead_detailed(int size, int rounds, sample_set_t *s_enc, sample_set_t *s_dec) {
  uint8_t key[AEAD_KEY_BYTES];
  uint8_t nonce[AEAD_NONCE_BYTES];
  uint8_t *pt = malloc(size);
  uint8_t *ct = malloc(size);
  uint8_t tag[AEAD_TAG_BYTES];
  uint8_t *rt = malloc(size);
  uint8_t aad[15] = {0x00, 0x01, 0x02, 0x03, 0x10, 0x00, 0x20, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x00, 0x01};

  memset(key, 0x42, AEAD_KEY_BYTES);
  memset(nonce, 0x17, AEAD_NONCE_BYTES);
  memset(pt, 0xCC, size);

  s_enc->samples = malloc(rounds * sizeof(double));
  s_dec->samples = malloc(rounds * sizeof(double));
  s_enc->count = rounds;
  s_dec->count = rounds;

  for (int i = 0; i < rounds; i++) {
    nonce[0] = (uint8_t)(i & 0xFF);
    nonce[1] = (uint8_t)((i >> 8) & 0xFF);

    uint64_t t0 = ns_now();
    int ct_len = aes128_ccm_encrypt(pt, size, aad, sizeof(aad), key, nonce, ct, tag);
    s_enc->samples[i] = (double)(ns_now() - t0) / 1000.0; /* µs */

    t0 = ns_now();
    int pt_len = aes128_ccm_decrypt(ct, ct_len, aad, sizeof(aad), key, nonce, tag, rt);
    s_dec->samples[i] = (double)(ns_now() - t0) / 1000.0; /* µs */

    (void)pt_len;
  }

  free(pt);
  free(ct);
  free(rt);
}

static void bench_classical_handshake(int rounds, sample_set_t *s_hs) {
  uint8_t c_xpk[X25519_PK_BYTES], c_xsk[X25519_SK_BYTES];
  uint8_t c_idpk[ED25519_PK_BYTES], c_idsk[ED25519_SK_BYTES];
  uint8_t s_xpk[X25519_PK_BYTES], s_xsk[X25519_SK_BYTES];
  uint8_t s_idpk[ED25519_PK_BYTES], s_idsk[ED25519_SK_BYTES];
  uint8_t s_ss[X25519_SS_BYTES], c_ss[X25519_SS_BYTES];
  uint8_t s_sig[ED25519_SIG_BYTES], c_sig[ED25519_SIG_BYTES];
  size_t s_siglen = 0, c_siglen = 0;
  uint8_t transcript_s[168], transcript_c[168];
  memset(transcript_s, 0x11, sizeof(transcript_s));
  memset(transcript_c, 0x22, sizeof(transcript_c));
  uint8_t k_c2s[16], k_s2c[16];

  s_hs->samples = malloc(rounds * sizeof(double));
  s_hs->count = rounds;

  for (int i = 0; i < rounds; i++) {
    uint64_t t0 = ns_now();

    /* 1. Client key generation */
    x25519_generate_keypair(c_xpk, c_xsk);
    ed25519_generate_keypair(c_idpk, c_idsk);

    /* 2. Server keygen & response */
    x25519_generate_keypair(s_xpk, s_xsk);
    ed25519_generate_keypair(s_idpk, s_idsk);
    x25519_derive_shared_secret(s_ss, s_xsk, c_xpk);
    ed25519_sign(s_sig, &s_siglen, transcript_s, sizeof(transcript_s), s_idsk);

    /* 3. Client process server message & auth */
    x25519_derive_shared_secret(c_ss, c_xsk, s_xpk);
    ed25519_verify(s_sig, s_siglen, transcript_s, sizeof(transcript_s), s_idpk);
    ed25519_sign(c_sig, &c_siglen, transcript_c, sizeof(transcript_c), c_idsk);

    /* 4. Server verify client auth */
    ed25519_verify(c_sig, c_siglen, transcript_c, sizeof(transcript_c), c_idpk);

    /* 5. Directional traffic key derivation */
    uint8_t c_nonce[16] = {0x01}, s_nonce[16] = {0x02};
    kdf_derive_directional_keys(k_c2s, k_s2c, c_ss, c_nonce, s_nonce, 12345ULL);

    s_hs->samples[i] = (double)(ns_now() - t0) / 1000.0; /* µs */
  }

  explicit_bzero(c_xsk, sizeof(c_xsk));
  explicit_bzero(s_xsk, sizeof(s_xsk));
  explicit_bzero(c_idsk, sizeof(c_idsk));
  explicit_bzero(s_idsk, sizeof(s_idsk));
  explicit_bzero(s_ss, sizeof(s_ss));
  explicit_bzero(c_ss, sizeof(c_ss));
}

/* ── SHA-256 Digest Benchmark ────────────────────────────────────── */
static void bench_sha256(int size, int rounds, double *us_out) {
  uint8_t *buf = malloc(size);
  uint8_t digest[SHA256_DIGEST_BYTES];
  memset(buf, 0x5A, size);

  uint64_t sum = 0;
  for (int i = 0; i < rounds; i++) {
    uint64_t t0 = ns_now();
    sha256_digest(buf, size, digest);
    sum += (ns_now() - t0);
  }
  *us_out = (double)sum / (double)rounds / 1000.0;
  free(buf);
}

/* ── HKDF-SHA-256 Benchmark ──────────────────────────────────────── */
static void bench_hkdf(int rounds, double *us_out) {
  uint8_t ikm[32], salt[16], info[32], okm[32];
  memset(ikm, 0x11, sizeof(ikm));
  memset(salt, 0x22, sizeof(salt));
  memset(info, 0x33, sizeof(info));

  uint64_t sum = 0;
  for (int i = 0; i < rounds; i++) {
    uint64_t t0 = ns_now();
    hkdf_sha256_derive(okm, sizeof(okm), ikm, sizeof(ikm), salt, sizeof(salt), info, sizeof(info));
    sum += (ns_now() - t0);
  }
  *us_out = (double)sum / (double)rounds / 1000.0;
}

/* ── HMAC-SHA-256 Benchmark ──────────────────────────────────────── */
static void bench_hmac(int rounds, double *us_out) {
  uint8_t key[32], data[64], mac[32];
  size_t mac_len = 0;
  memset(key, 0x77, sizeof(key));
  memset(data, 0x88, sizeof(data));

  uint64_t sum = 0;
  for (int i = 0; i < rounds; i++) {
    uint64_t t0 = ns_now();
    hmac_sha256_compute(key, sizeof(key), data, sizeof(data), mac, &mac_len);
    sum += (ns_now() - t0);
  }
  *us_out = (double)sum / (double)rounds / 1000.0;
}

static void print_detailed_row(const char *name, const detailed_stats_t *st) {
  printf(" %-22s %9.2f %9.2f %9.2f %9.2f %9.2f %6.1f%% %9.2f %9.2f\n",
         name, st->mean, st->median, st->min, st->max,
         st->stddev, st->coeff_var, st->p95, st->p99);
}

int main(int argc, char *argv[]) {
  int rounds = BENCH_ROUNDS_DEFAULT;
  int runs = 5;
  const char *export_path = NULL;
  int pos_arg = 0;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--export") == 0 && i + 1 < argc) {
      export_path = argv[++i];
    } else if (argv[i][0] != '-') {
      if (pos_arg == 0) {
        rounds = atoi(argv[i]);
        if (rounds <= 0) rounds = BENCH_ROUNDS_DEFAULT;
        pos_arg++;
      } else if (pos_arg == 1) {
        runs = atoi(argv[i]);
        if (runs <= 0) runs = 5;
        pos_arg++;
      }
    }
  }

  /* Warmup OpenSSL algorithms */
  kem_warmup();
  dsa_warmup();

  perf_benchmark_session_t session;
  if (perf_session_init(&session, (size_t)runs, (size_t)rounds) != 0) {
    fprintf(stderr, "Failed to initialize performance monitor session\n");
    return 1;
  }

  perf_ui_print_section_header("QRYPTONEX CLASSICAL IOT SUITE: N-RUN BENCHMARK (X25519 + Ed25519 + AES-128-CCM)");
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

  sample_set_t s_x25519_key = {0}, s_x25519_ecdh = {0};
  sample_set_t s_ed_key = {0}, s_ed_sign = {0}, s_ed_ver = {0};

  for (int r = 0; r < runs; r++) {
    uint64_t t0 = perf_get_nanos();

    if (s_x25519_key.samples) {
      free(s_x25519_key.samples); free(s_x25519_ecdh.samples);
      free(s_ed_key.samples); free(s_ed_sign.samples); free(s_ed_ver.samples);
    }

    bench_x25519(rounds, &s_x25519_key, &s_x25519_ecdh);
    bench_ed25519(rounds, &s_ed_key, &s_ed_sign, &s_ed_ver);

    double run_time_us = (double)(perf_get_nanos() - t0) / 1000.0;
    perf_session_record_run(&session, (size_t)r, run_time_us);
    perf_ui_print_run_row((size_t)r, (size_t)runs, run_time_us, session.run_temps_c[r],
                          session.temp.available, session.run_ram_mb[r], session.run_cpu_pct[r]);
  }
  perf_ui_print_run_footer();
  perf_session_finalize(&session);

  detailed_stats_t st_x25519_key, st_x25519_ecdh;
  compute_stats(&s_x25519_key, &st_x25519_key);
  compute_stats(&s_x25519_ecdh, &st_x25519_ecdh);

  detailed_stats_t st_ed_key, st_ed_sign, st_ed_ver;
  compute_stats(&s_ed_key, &st_ed_key);
  compute_stats(&s_ed_sign, &st_ed_sign);
  compute_stats(&s_ed_ver, &st_ed_ver);

  printf("\n[1] Asymmetric Primitives Execution Time (microseconds µs):\n");
  printf(" %-22s %9s %9s %9s %9s %9s %7s %9s %9s\n",
         "Operation", "Mean", "Median", "Min", "Max", "StdDev", "CV", "p95", "p99");
  printf("-----------------------------------------------------------------------------------------\n");
  print_detailed_row("X25519 KeyGen", &st_x25519_key);
  print_detailed_row("X25519 ECDH Derive", &st_x25519_ecdh);
  print_detailed_row("Ed25519 KeyGen", &st_ed_key);
  print_detailed_row("Ed25519 Sign", &st_ed_sign);
  print_detailed_row("Ed25519 Verify", &st_ed_ver);
  printf("-----------------------------------------------------------------------------------------\n\n");

  /* 3. Symmetric & Hashing Microbenchmarks */
  double sha_64_us, sha_256_us, sha_1024_us, sha_4096_us;
  bench_sha256(64, rounds, &sha_64_us);
  bench_sha256(256, rounds, &sha_256_us);
  bench_sha256(1024, rounds, &sha_1024_us);
  bench_sha256(4096, rounds, &sha_4096_us);

  double hkdf_us, hmac_us;
  bench_hkdf(rounds, &hkdf_us);
  bench_hmac(rounds, &hmac_us);

  printf("[2] Hash, Key Derivation & MAC Performance:\n");
  printf("  SHA-256 (64 B)   : %8.2f µs (%7.2f MB/s)\n", sha_64_us, (64.0 / sha_64_us));
  printf("  SHA-256 (256 B)  : %8.2f µs (%7.2f MB/s)\n", sha_256_us, (256.0 / sha_256_us));
  printf("  SHA-256 (1024 B) : %8.2f µs (%7.2f MB/s)\n", sha_1024_us, (1024.0 / sha_1024_us));
  printf("  SHA-256 (4096 B) : %8.2f µs (%7.2f MB/s)\n", sha_4096_us, (4096.0 / sha_4096_us));
  printf("  HKDF-SHA-256     : %8.2f µs\n", hkdf_us);
  printf("  HMAC-SHA-256     : %8.2f µs\n\n", hmac_us);

  /* 4. AES-128-CCM AEAD Throughput */
  int sizes[] = {64, 256, 1024, 4096, 16384};
  int num_sizes = (int)(sizeof(sizes) / sizeof(sizes[0]));

  printf("[3] AES-128-CCM Authenticated Encryption Throughput (with 15B AAD header binding):\n");
  printf("  Payload Size   Encrypt (µs)   Throughput (MB/s)   Decrypt (µs)   Throughput (MB/s)\n");
  printf("-------------------------------------------------------------------------------------\n");
  for (int s = 0; s < num_sizes; s++) {
    int sz = sizes[s];
    double enc_us, dec_us;
    bench_aead_size(sz, rounds, &enc_us, &dec_us);
    double enc_mb = (double)sz / enc_us;
    double dec_mb = (double)sz / dec_us;
    printf("  %6d B        %9.2f        %10.2f        %9.2f        %10.2f\n",
           sz, enc_us, enc_mb, dec_us, dec_mb);
  }
  printf("=====================================================================================\n\n");

  /* Detailed 1KB AEAD and Handshake samples */
  sample_set_t s_aead_enc = {0}, s_aead_dec = {0}, s_hs = {0};
  bench_aead_detailed(1024, rounds, &s_aead_enc, &s_aead_dec);
  bench_classical_handshake(rounds, &s_hs);

  detailed_stats_t st_aead_enc, st_aead_dec, st_hs;
  compute_stats(&s_aead_enc, &st_aead_enc);
  compute_stats(&s_aead_dec, &st_aead_dec);
  compute_stats(&s_hs, &st_hs);

  /* ── COMPREHENSIVE MULTI-METRIC PERFORMANCE REPORT ────────────── */
  perf_ui_print_section_header("COMPREHENSIVE MULTI-METRIC BENCHMARK REPORT");

  /* 1. Cryptographic Metrics (Values in µs and ms) */
  perf_stats_t stat_x25519_kg = {
    .mean = st_x25519_key.mean, .min = st_x25519_key.min, .max = st_x25519_key.max,
    .median = st_x25519_key.median, .stddev = st_x25519_key.stddev, .p95 = st_x25519_key.p95,
    .throughput_ops_sec = (st_x25519_key.mean > 0) ? (1000000.0 / st_x25519_key.mean) : 0
  };
  perf_ui_print_crypto_summary("1. X25519 Key Generation (RFC 7748)", &stat_x25519_kg, 32, 32, 0, 0, 0);

  perf_stats_t stat_x25519_agree = {
    .mean = st_x25519_ecdh.mean, .min = st_x25519_ecdh.min, .max = st_x25519_ecdh.max,
    .median = st_x25519_ecdh.median, .stddev = st_x25519_ecdh.stddev, .p95 = st_x25519_ecdh.p95,
    .throughput_ops_sec = (st_x25519_ecdh.mean > 0) ? (1000000.0 / st_x25519_ecdh.mean) : 0
  };
  perf_ui_print_crypto_summary("2. X25519 ECDH Shared Secret Agreement", &stat_x25519_agree, 32, 32, 0, 0, 32);

  perf_stats_t stat_x25519_ecdh = {
    .mean = st_x25519_ecdh.mean, .min = st_x25519_ecdh.min, .max = st_x25519_ecdh.max,
    .median = st_x25519_ecdh.median, .stddev = st_x25519_ecdh.stddev, .p95 = st_x25519_ecdh.p95,
    .throughput_ops_sec = (st_x25519_ecdh.mean > 0) ? (1000000.0 / st_x25519_ecdh.mean) : 0
  };
  perf_ui_print_crypto_summary("3. X25519 ECDH Shared Secret Derivation", &stat_x25519_ecdh, 0, 32, 32, 0, 32);

  perf_stats_t stat_ed_kg = {
    .mean = st_ed_key.mean, .min = st_ed_key.min, .max = st_ed_key.max,
    .median = st_ed_key.median, .stddev = st_ed_key.stddev, .p95 = st_ed_key.p95,
    .throughput_ops_sec = (st_ed_key.mean > 0) ? (1000000.0 / st_ed_key.mean) : 0
  };
  perf_ui_print_crypto_summary("4. Ed25519 Key Generation (RFC 8032)", &stat_ed_kg, 32, 32, 0, 0, 0);

  perf_stats_t stat_ed_sign = {
    .mean = st_ed_sign.mean, .min = st_ed_sign.min, .max = st_ed_sign.max,
    .median = st_ed_sign.median, .stddev = st_ed_sign.stddev, .p95 = st_ed_sign.p95,
    .throughput_ops_sec = (st_ed_sign.mean > 0) ? (1000000.0 / st_ed_sign.mean) : 0
  };
  perf_ui_print_crypto_summary("5. Ed25519 Signing", &stat_ed_sign, 0, 32, 0, 64, 0);

  perf_stats_t stat_ed_ver = {
    .mean = st_ed_ver.mean, .min = st_ed_ver.min, .max = st_ed_ver.max,
    .median = st_ed_ver.median, .stddev = st_ed_ver.stddev, .p95 = st_ed_ver.p95,
    .throughput_ops_sec = (st_ed_ver.mean > 0) ? (1000000.0 / st_ed_ver.mean) : 0
  };
  perf_ui_print_crypto_summary("6. Ed25519 Signature Verification", &stat_ed_ver, 32, 0, 0, 64, 0);

  perf_stats_t stat_aead_enc = {
    .mean = st_aead_enc.mean, .min = st_aead_enc.min, .max = st_aead_enc.max,
    .median = st_aead_enc.median, .stddev = st_aead_enc.stddev, .p95 = st_aead_enc.p95,
    .throughput_ops_sec = (st_aead_enc.mean > 0) ? (1000000.0 / st_aead_enc.mean) : 0
  };
  perf_ui_print_crypto_summary("7. AES-128-CCM Encryption (1KB payload)", &stat_aead_enc, 0, 16, 1024, 16, 0);

  perf_stats_t stat_aead_dec = {
    .mean = st_aead_dec.mean, .min = st_aead_dec.min, .max = st_aead_dec.max,
    .median = st_aead_dec.median, .stddev = st_aead_dec.stddev, .p95 = st_aead_dec.p95,
    .throughput_ops_sec = (st_aead_dec.mean > 0) ? (1000000.0 / st_aead_dec.mean) : 0
  };
  perf_ui_print_crypto_summary("8. AES-128-CCM Decryption (1KB payload)", &stat_aead_dec, 0, 16, 1024, 16, 0);

  perf_stats_t stat_hs_full = {
    .mean = st_hs.mean, .min = st_hs.min, .max = st_hs.max,
    .median = st_hs.median, .stddev = st_hs.stddev, .p95 = st_hs.p95,
    .throughput_ops_sec = (st_hs.mean > 0) ? (1000000.0 / st_hs.mean) : 0
  };
  perf_ui_print_crypto_summary("9. Full 4-Way Classical Handshake Simulation", &stat_hs_full, 32, 32, 32, 64, 32);

  /* 2. Memory Metrics */
  perf_ui_print_memory_summary(&session.mem);

  /* 3. CPU Metrics */
  perf_ui_print_cpu_summary(&session.cpu, (size_t)rounds * (size_t)runs * 5);

  /* 4. Temperature Metrics */
  perf_ui_print_temp_summary(&session.temp);

  /* 5. Unified Comparative Operations Summary Table */
  perf_op_comparison_t comparison_ops[] = {
    {"1. KEM/KEX Key Generation", stat_x25519_kg.mean, stat_x25519_kg.p95, stat_x25519_kg.throughput_ops_sec, 32, "pk"},
    {"2. KEM/KEX Encapsulation / Agreement", stat_x25519_agree.mean, stat_x25519_agree.p95, stat_x25519_agree.throughput_ops_sec, 32, "ss"},
    {"3. KEM/KEX Decapsulation / Derivation", stat_x25519_ecdh.mean, stat_x25519_ecdh.p95, stat_x25519_ecdh.throughput_ops_sec, 32, "ss"},
    {"4. Digital Signature Key Generation", stat_ed_kg.mean, stat_ed_kg.p95, stat_ed_kg.throughput_ops_sec, 32, "pk"},
    {"5. Digital Signature Signing", stat_ed_sign.mean, stat_ed_sign.p95, stat_ed_sign.throughput_ops_sec, 64, "sig"},
    {"6. Digital Signature Verification", stat_ed_ver.mean, stat_ed_ver.p95, stat_ed_ver.throughput_ops_sec, 64, "sig"},
    {"7. AEAD Symmetric Encryption (1KB)", stat_aead_enc.mean, stat_aead_enc.p95, stat_aead_enc.throughput_ops_sec, 1024, "ct"},
    {"8. AEAD Symmetric Decryption (1KB)", stat_aead_dec.mean, stat_aead_dec.p95, stat_aead_dec.throughput_ops_sec, 1024, "pt"},
    {"9. Full 4-Way Handshake Simulation", stat_hs_full.mean, stat_hs_full.p95, stat_hs_full.throughput_ops_sec, 296, "net"}
  };
  perf_ui_print_unified_comparison_table("QRYPTONEX Classical IoT Suite (X25519 + Ed25519 + AES-128-CCM)", comparison_ops, 9);

  if (export_path) {
    perf_export_json(export_path, "Classical IoT Suite (X25519 + Ed25519 + AES-128-CCM)",
                     comparison_ops, 9, &session.mem, &session.cpu, &session.temp, (size_t)rounds * (size_t)runs * 5);
  }

  /* Clean up */
  free(s_x25519_key.samples);
  free(s_x25519_ecdh.samples);
  free(s_ed_key.samples);
  free(s_ed_sign.samples);
  free(s_ed_ver.samples);
  free(s_aead_enc.samples);
  free(s_aead_dec.samples);
  free(s_hs.samples);
  perf_session_cleanup(&session);

  return 0;
}
