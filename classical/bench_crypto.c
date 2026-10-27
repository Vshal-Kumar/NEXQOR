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
  if (argc > 1) {
    rounds = atoi(argv[1]);
    if (rounds <= 0)
      rounds = BENCH_ROUNDS_DEFAULT;
  }

  printf("\n");
  printf("=========================================================================================\n");
  printf("  QRYPTONEX Classical IoT Cryptographic Suite Benchmark (%d rounds)\n", rounds);
  printf("  Suite: X25519 (ECDH) + Ed25519 + AES-128-CCM + SHA-256 + HKDF-SHA-256 + HMAC-SHA-256\n");
  printf("=========================================================================================\n\n");

  /* Warmup OpenSSL algorithms */
  kem_warmup();
  dsa_warmup();

  /* 1. X25519 Benchmark */
  sample_set_t s_x25519_key, s_x25519_ecdh;
  bench_x25519(rounds, &s_x25519_key, &s_x25519_ecdh);

  detailed_stats_t st_x25519_key, st_x25519_ecdh;
  compute_stats(&s_x25519_key, &st_x25519_key);
  compute_stats(&s_x25519_ecdh, &st_x25519_ecdh);

  /* 2. Ed25519 Benchmark */
  sample_set_t s_ed_key, s_ed_sign, s_ed_ver;
  bench_ed25519(rounds, &s_ed_key, &s_ed_sign, &s_ed_ver);

  detailed_stats_t st_ed_key, st_ed_sign, st_ed_ver;
  compute_stats(&s_ed_key, &st_ed_key);
  compute_stats(&s_ed_sign, &st_ed_sign);
  compute_stats(&s_ed_ver, &st_ed_ver);

  printf("[1] Asymmetric Primitives Execution Time (microseconds µs):\n");
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

  /* Clean up */
  free(s_x25519_key.samples);
  free(s_x25519_ecdh.samples);
  free(s_ed_key.samples);
  free(s_ed_sign.samples);
  free(s_ed_ver.samples);

  return 0;
}
