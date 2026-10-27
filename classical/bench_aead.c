/*
 * classical/bench_aead.c — Standalone AES-128-CCM Benchmark, Demo, and File Encryption Tool
 *
 * Classical IoT Cryptographic Suite for QRYPTONEX:
 *   - AEAD: AES-128-CCM (NIST SP 800-38C / RFC 3610)
 *   - Key Size: 16 bytes (128 bits)
 *   - Nonce Size: 12 bytes (96 bits)
 *   - Tag Size: 16 bytes (128 bits)
 *   - Associated Data: 15-byte wire header simulation
 *
 * Usage:
 *   1) Benchmark & Demo:
 *      ./bench_aead [rounds]
 *
 *   2) Encrypt a file:
 *      ./bench_aead encrypt <input_file> <output_file> [key_hex]
 *
 *   3) Decrypt a file:
 *      ./bench_aead decrypt <input_file> <output_file> <key_hex>
 */

#define _POSIX_C_SOURCE 200809L

#include <math.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "crypto/aead.h"

#define BENCH_ROUNDS_DEFAULT 1000

static inline uint64_t ns_now(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

typedef struct {
  double *samples;
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

  if (n % 2 == 1) out->median = s->samples[n / 2];
  else out->median = (s->samples[n / 2 - 1] + s->samples[n / 2]) / 2.0;

  out->p95 = s->samples[(int)(n * 0.95)];
  out->p99 = s->samples[(int)(n * 0.99)];

  double sum_sq_diff = 0.0;
  for (int i = 0; i < n; i++) {
    double diff = s->samples[i] - out->mean;
    sum_sq_diff += diff * diff;
  }
  out->variance = sum_sq_diff / (double)n;
  out->stddev = sqrt(out->variance);
  out->coeff_var = (out->mean > 0.0) ? ((out->stddev / out->mean) * 100.0) : 0.0;
}

static void hex_dump(const char *label, const uint8_t *data, size_t len) {
  printf("%s (%zu bytes): ", label, len);
  for (size_t i = 0; i < len; i++) {
    printf("%02x", data[i]);
  }
  printf("\n");
}

static int parse_hex(const char *hex_str, uint8_t *out, size_t expected_len) {
  if (strlen(hex_str) != expected_len * 2) return -1;
  for (size_t i = 0; i < expected_len; i++) {
    unsigned int val;
    if (sscanf(hex_str + i * 2, "%02x", &val) != 1) return -1;
    out[i] = (uint8_t)val;
  }
  return 0;
}

static void run_demo(void) {
  printf("========================================================================\n");
  printf("  AES-128-CCM Authenticated Encryption Demo\n");
  printf("========================================================================\n");

  uint8_t key[AEAD_KEY_BYTES];
  uint8_t nonce[AEAD_NONCE_BYTES];
  RAND_bytes(key, sizeof(key));
  RAND_bytes(nonce, sizeof(nonce));

  const char *msg = "IoT Telemetry Payload: temp=24.5C, humidity=48%, batt=98%";
  int msg_len = (int)strlen(msg);

  uint8_t aad[15] = "CANONICAL-HDR";
  int aad_len = 13;

  uint8_t ct[128];
  uint8_t tag[AEAD_TAG_BYTES];
  uint8_t decrypted[128];

  hex_dump("Key   ", key, sizeof(key));
  hex_dump("Nonce ", nonce, sizeof(nonce));
  printf("Plaintext: \"%s\" (%d bytes)\n", msg, msg_len);

  int ct_len = aes128_ccm_encrypt((const uint8_t *)msg, msg_len, aad, aad_len, key, nonce, ct, tag);
  if (ct_len < 0) {
    printf("Encryption FAILED\n");
    return;
  }
  hex_dump("Ciphertext", ct, ct_len);
  hex_dump("Auth Tag  ", tag, sizeof(tag));

  int pt_len = aes128_ccm_decrypt(ct, ct_len, aad, aad_len, key, nonce, tag, decrypted);
  if (pt_len < 0) {
    printf("Decryption FAILED\n");
    return;
  }
  decrypted[pt_len] = '\0';
  printf("Decrypted: \"%s\" (%d bytes) [MATCH: %s]\n",
         decrypted, pt_len, (strcmp(msg, (char *)decrypted) == 0 ? "YES" : "NO"));

  /* Tamper test */
  printf("\n[Tamper Test] Modifying 1 byte in ciphertext...\n");
  ct[0] ^= 0xFF;
  int tamper_res = aes128_ccm_decrypt(ct, ct_len, aad, aad_len, key, nonce, tag, decrypted);
  printf("Decryption result on tampered ciphertext: %d (Expected: -1 / Rejected: %s)\n",
         tamper_res, (tamper_res < 0 ? "SUCCESS" : "VULNERABILITY"));
  printf("========================================================================\n\n");
}

static int file_encrypt(const char *in_path, const char *out_path, const char *key_hex) {
  uint8_t key[AEAD_KEY_BYTES];
  if (key_hex) {
    if (parse_hex(key_hex, key, sizeof(key)) != 0) {
      fprintf(stderr, "Error: key must be 32 hex chars (16 bytes) for AES-128\n");
      return 1;
    }
  } else {
    RAND_bytes(key, sizeof(key));
    hex_dump("Generated Key", key, sizeof(key));
  }

  FILE *fin = fopen(in_path, "rb");
  if (!fin) { perror("fopen input"); return 1; }
  fseek(fin, 0, SEEK_END);
  long flen = ftell(fin);
  fseek(fin, 0, SEEK_SET);

  uint8_t *pt = malloc(flen);
  if (fread(pt, 1, flen, fin) != (size_t)flen) { perror("fread"); fclose(fin); free(pt); return 1; }
  fclose(fin);

  uint8_t nonce[AEAD_NONCE_BYTES];
  RAND_bytes(nonce, sizeof(nonce));

  uint8_t *ct = malloc(flen);
  uint8_t tag[AEAD_TAG_BYTES];

  int ct_len = aes128_ccm_encrypt(pt, (int)flen, NULL, 0, key, nonce, ct, tag);
  if (ct_len < 0) {
    fprintf(stderr, "aes128_ccm_encrypt failed\n");
    free(pt); free(ct); return 1;
  }

  FILE *fout = fopen(out_path, "wb");
  if (!fout) { perror("fopen output"); free(pt); free(ct); return 1; }

  /* File layout: [ NONCE (12B) | TAG (16B) | CIPHERTEXT ] */
  fwrite(nonce, 1, sizeof(nonce), fout);
  fwrite(tag, 1, sizeof(tag), fout);
  fwrite(ct, 1, ct_len, fout);
  fclose(fout);

  free(pt);
  free(ct);
  printf("Encrypted %ld bytes -> %s successfully.\n", flen, out_path);
  return 0;
}

static int file_decrypt(const char *in_path, const char *out_path, const char *key_hex) {
  if (!key_hex) {
    fprintf(stderr, "Error: key_hex is required for decryption\n");
    return 1;
  }
  uint8_t key[AEAD_KEY_BYTES];
  if (parse_hex(key_hex, key, sizeof(key)) != 0) {
    fprintf(stderr, "Error: key must be 32 hex chars (16 bytes)\n");
    return 1;
  }

  FILE *fin = fopen(in_path, "rb");
  if (!fin) { perror("fopen input"); return 1; }
  fseek(fin, 0, SEEK_END);
  long flen = ftell(fin);
  fseek(fin, 0, SEEK_SET);

  if (flen < (long)(AEAD_NONCE_BYTES + AEAD_TAG_BYTES)) {
    fprintf(stderr, "Error: file too short to be valid ciphertext\n");
    fclose(fin);
    return 1;
  }

  uint8_t nonce[AEAD_NONCE_BYTES];
  uint8_t tag[AEAD_TAG_BYTES];
  if (fread(nonce, 1, sizeof(nonce), fin) != sizeof(nonce) ||
      fread(tag, 1, sizeof(tag), fin) != sizeof(tag)) {
    fclose(fin); return 1;
  }

  long ct_len = flen - (sizeof(nonce) + sizeof(tag));
  uint8_t *ct = malloc(ct_len);
  if (fread(ct, 1, ct_len, fin) != (size_t)ct_len) {
    free(ct); fclose(fin); return 1;
  }
  fclose(fin);

  uint8_t *pt = malloc(ct_len);
  int pt_len = aes128_ccm_decrypt(ct, (int)ct_len, NULL, 0, key, nonce, tag, pt);
  if (pt_len < 0) {
    fprintf(stderr, "CRITICAL: Decryption failed! Authentication tag mismatch or corrupted file.\n");
    free(ct); free(pt);
    return 1;
  }

  FILE *fout = fopen(out_path, "wb");
  if (!fout) { perror("fopen output"); free(ct); free(pt); return 1; }
  fwrite(pt, 1, pt_len, fout);
  fclose(fout);

  free(ct);
  free(pt);
  printf("Decrypted %d bytes -> %s successfully.\n", pt_len, out_path);
  return 0;
}

int main(int argc, char *argv[]) {
  if (argc > 1 && strcmp(argv[1], "encrypt") == 0) {
    if (argc < 4) {
      fprintf(stderr, "Usage: %s encrypt <input_file> <output_file> [key_hex]\n", argv[0]);
      return 1;
    }
    return file_encrypt(argv[2], argv[3], argc > 4 ? argv[4] : NULL);
  }

  if (argc > 1 && strcmp(argv[1], "decrypt") == 0) {
    if (argc < 5) {
      fprintf(stderr, "Usage: %s decrypt <input_file> <output_file> <key_hex>\n", argv[0]);
      return 1;
    }
    return file_decrypt(argv[2], argv[3], argv[4]);
  }

  int rounds = BENCH_ROUNDS_DEFAULT;
  if (argc > 1) {
    rounds = atoi(argv[1]);
    if (rounds <= 0) rounds = BENCH_ROUNDS_DEFAULT;
  }

  run_demo();

  printf("========================================================================\n");
  printf("  AES-128-CCM Throughput Benchmark (%d rounds)\n", rounds);
  printf("========================================================================\n");

  int sizes[] = {64, 256, 1024, 4096, 16384, 65536};
  int num_sizes = (int)(sizeof(sizes) / sizeof(sizes[0]));

  printf(" %-12s %12s %16s %12s %16s\n",
         "Size (Bytes)", "Enc (µs)", "Enc (MB/s)", "Dec (µs)", "Dec (MB/s)");
  printf("------------------------------------------------------------------------\n");

  uint8_t key[AEAD_KEY_BYTES];
  uint8_t nonce[AEAD_NONCE_BYTES];
  RAND_bytes(key, sizeof(key));
  RAND_bytes(nonce, sizeof(nonce));

  uint8_t aad[15] = {0x01, 0x02, 0x03, 0x04, 0x10, 0x00, 0x20, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};

  for (int s = 0; s < num_sizes; s++) {
    int sz = sizes[s];
    uint8_t *pt = malloc(sz);
    uint8_t *ct = malloc(sz);
    uint8_t *rt = malloc(sz);
    uint8_t tag[AEAD_TAG_BYTES];
    memset(pt, 0x55, sz);

    sample_set_t enc_samples = { malloc(rounds * sizeof(double)), rounds };
    sample_set_t dec_samples = { malloc(rounds * sizeof(double)), rounds };

    for (int i = 0; i < rounds; i++) {
      nonce[0] = (uint8_t)(i & 0xFF);
      nonce[1] = (uint8_t)((i >> 8) & 0xFF);

      uint64_t t0 = ns_now();
      int ct_len = aes128_ccm_encrypt(pt, sz, aad, sizeof(aad), key, nonce, ct, tag);
      enc_samples.samples[i] = (double)(ns_now() - t0) / 1000.0;

      t0 = ns_now();
      aes128_ccm_decrypt(ct, ct_len, aad, sizeof(aad), key, nonce, tag, rt);
      dec_samples.samples[i] = (double)(ns_now() - t0) / 1000.0;
    }

    detailed_stats_t enc_st, dec_st;
    compute_stats(&enc_samples, &enc_st);
    compute_stats(&dec_samples, &dec_st);

    double enc_mb = (double)sz / enc_st.mean;
    double dec_mb = (double)sz / dec_st.mean;

    printf(" %-12d %12.2f %16.2f %12.2f %16.2f\n",
           sz, enc_st.mean, enc_mb, dec_st.mean, dec_mb);

    free(pt); free(ct); free(rt);
    free(enc_samples.samples); free(dec_samples.samples);
  }
  printf("========================================================================\n\n");

  return 0;
}
