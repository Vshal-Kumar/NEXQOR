/*
 * hybrid/bench_aead.c — Standalone AEAD (ChaCha20-Poly1305) Benchmark, Demo, and File Encryption Tool
 *
 * Suite: ChaCha20-Poly1305 (RFC 8439) with 15-byte Wire Header AAD Binding
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

static void print_stat_row(const char *name, const detailed_stats_t *st, const char *unit) {
    printf("│ %-16s │ %10.2f │ %10.2f │ %10.2f │ %10.2f │ %10.2f │ %10.2f │ %10.2f │ %-4s │\n",
           name, st->mean, st->median, st->min, st->max, st->stddev,
           st->p95, st->p99, unit);
}

static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("  %-16s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf(" (%zu bytes)\n", len);
}

static int hex_to_bytes(const char *hex, uint8_t *bytes, size_t max_bytes) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0 || hex_len / 2 > max_bytes) return -1;
    size_t byte_len = hex_len / 2;
    for (size_t i = 0; i < byte_len; i++) {
        unsigned int b;
        if (sscanf(hex + 2 * i, "%02x", &b) != 1) return -1;
        bytes[i] = (uint8_t)b;
    }
    return (int)byte_len;
}

static uint8_t *read_entire_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return NULL; }
    fseek(f, 0, SEEK_SET);

    uint8_t *buf = malloc((size_t)sz);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *out_len = (size_t)sz;
    return buf;
}

static int write_entire_file(const char *path, const uint8_t *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    if (fwrite(buf, 1, len, f) != len) { fclose(f); return -1; }
    fclose(f);
    return 0;
}

static int handle_encrypt_file(const char *in_path, const char *out_path, const char *key_hex) {
    size_t pt_len = 0;
    uint8_t *pt = read_entire_file(in_path, &pt_len);
    if (!pt) {
        fprintf(stderr, "Error: Could not read input file '%s'\n", in_path);
        return 1;
    }

    uint8_t key[32];
    if (key_hex) {
        if (hex_to_bytes(key_hex, key, sizeof(key)) != 32) {
            fprintf(stderr, "Error: Key must be 64 hex characters (32 bytes).\n");
            free(pt);
            return 1;
        }
    } else {
        if (RAND_bytes(key, sizeof(key)) != 1) {
            fprintf(stderr, "Error: Failed to generate random key.\n");
            free(pt);
            return 1;
        }
        printf("\n[+] Generated random ChaCha20-Poly1305 key:\n");
        print_hex("Key (hex)", key, sizeof(key));
        printf("Save this key to decrypt the file later!\n\n");
    }

    uint8_t nonce[12];
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        fprintf(stderr, "Error: Nonce generation failed\n");
        free(pt);
        return 1;
    }

    uint8_t tag[16];
    uint8_t *ct = malloc(pt_len);
    if (!ct) { free(pt); return 1; }

    int ct_len = aead_encrypt(pt, (int)pt_len, NULL, 0, key, nonce, ct, tag);
    if (ct_len < 0) {
        fprintf(stderr, "Error: AEAD encryption failed\n");
        free(pt); free(ct);
        return 1;
    }

    /* Output layout: [Nonce(12B)] [Tag(16B)] [Ciphertext(ct_len)] */
    size_t total_out_len = 12 + 16 + (size_t)ct_len;
    uint8_t *out_buf = malloc(total_out_len);
    if (!out_buf) { free(pt); free(ct); return 1; }

    memcpy(out_buf, nonce, 12);
    memcpy(out_buf + 12, tag, 16);
    memcpy(out_buf + 28, ct, (size_t)ct_len);

    if (write_entire_file(out_path, out_buf, total_out_len) != 0) {
        fprintf(stderr, "Error: Could not write output file '%s'\n", out_path);
        free(pt); free(ct); free(out_buf);
        return 1;
    }

    printf("[+] Successfully encrypted %zu bytes -> %zu bytes in '%s'\n", pt_len, total_out_len, out_path);
    free(pt); free(ct); free(out_buf);
    return 0;
}

static int handle_decrypt_file(const char *in_path, const char *out_path, const char *key_hex) {
    if (!key_hex) {
        fprintf(stderr, "Error: Decryption requires a key in hex format.\n");
        return 1;
    }

    uint8_t key[32];
    if (hex_to_bytes(key_hex, key, sizeof(key)) != 32) {
        fprintf(stderr, "Error: Key must be 64 hex characters (32 bytes).\n");
        return 1;
    }

    size_t file_len = 0;
    uint8_t *file_data = read_entire_file(in_path, &file_len);
    if (!file_data) {
        fprintf(stderr, "Error: Could not read input file '%s'\n", in_path);
        return 1;
    }

    if (file_len < 28) {
        fprintf(stderr, "Error: File too small to be a valid encrypted payload\n");
        free(file_data);
        return 1;
    }

    uint8_t nonce[12];
    uint8_t tag[16];
    memcpy(nonce, file_data, 12);
    memcpy(tag, file_data + 12, 16);

    const uint8_t *ct = file_data + 28;
    int ct_len = (int)file_len - 28;

    uint8_t *pt = malloc((size_t)ct_len + 1);
    if (!pt) { free(file_data); return 1; }

    int pt_len = aead_decrypt(ct, ct_len, NULL, 0, key, nonce, tag, pt);
    if (pt_len < 0) {
        fprintf(stderr, "Error: AEAD decryption failed (Authentication failed - invalid key or corrupted file)\n");
        free(file_data); free(pt);
        return 1;
    }

    if (write_entire_file(out_path, pt, (size_t)pt_len) != 0) {
        fprintf(stderr, "Error: Could not write output file '%s'\n", out_path);
        free(file_data); free(pt);
        return 1;
    }

    printf("[+] Successfully decrypted %zu bytes -> %d bytes in '%s'\n", file_len, pt_len, out_path);
    free(file_data); free(pt);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        if (strcmp(argv[1], "encrypt") == 0) {
            if (argc < 4) {
                fprintf(stderr, "Usage: %s encrypt <input_file> <output_file> [key_hex]\n", argv[0]);
                return 1;
            }
            return handle_encrypt_file(argv[2], argv[3], (argc > 4) ? argv[4] : NULL);
        } else if (strcmp(argv[1], "decrypt") == 0) {
            if (argc < 5) {
                fprintf(stderr, "Usage: %s decrypt <input_file> <output_file> <key_hex>\n", argv[0]);
                return 1;
            }
            return handle_decrypt_file(argv[2], argv[3], argv[4]);
        }
    }

    int rounds = BENCH_ROUNDS_DEFAULT;
    if (argc > 1) {
        rounds = atoi(argv[1]);
        if (rounds < 10) rounds = BENCH_ROUNDS_DEFAULT;
    }

    printf("\n╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                 QRYPTONEX Hybrid Suite — ChaCha20-Poly1305 AEAD Benchmark                                        ║\n");
    printf("║  Primitive: ChaCha20-Poly1305 (RFC 8439) with 15-byte Wire Header AAD Binding                                    ║\n");
    printf("╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝\n\n");

    const char *msg_text = "HYBRID-SECURE-PAYLOAD: Encrypted with ChaCha20-Poly1305 and validated with Poly1305 MAC tag!";
    int pt_len = (int)strlen(msg_text);

    uint8_t key[32], nonce[12], tag[16];
    uint8_t *ct = malloc((size_t)pt_len);
    uint8_t *decrypted = malloc((size_t)pt_len + 1);

    RAND_bytes(key, sizeof(key));
    RAND_bytes(nonce, sizeof(nonce));

    printf(" [1] Original Plaintext: \"%s\" (%d bytes)\n", msg_text, pt_len);
    print_hex("AEAD Key (32B)", key, sizeof(key));
    print_hex("Nonce (12B)", nonce, sizeof(nonce));

    int ct_len = aead_encrypt((const uint8_t *)msg_text, pt_len, NULL, 0, key, nonce, ct, tag);
    print_hex("Ciphertext", ct, (size_t)ct_len);
    print_hex("Auth Tag (16B)", tag, sizeof(tag));

    int dec_len = aead_decrypt(ct, ct_len, NULL, 0, key, nonce, tag, decrypted);
    decrypted[dec_len] = '\0';
    printf("  Decrypted Output: \"%s\"\n", decrypted);
    printf("  Integrity Check: \033[1;32m%s\033[0m\n\n", (strcmp(msg_text, (char *)decrypted) == 0) ? "PASS (TAG VALID)" : "FAIL");

    free(ct); free(decrypted);

    /* ── Multi-size benchmark ── */
    int payload_sizes[] = { 64, 256, 1024, 4096, 16384 };
    const char *payload_labels[] = { "64 Bytes", "256 Bytes", "1 KB", "4 KB", "16 KB" };
    int num_sizes = 5;

    for (int i = 0; i < num_sizes; i++) {
        int sz = payload_sizes[i];
        uint8_t *bench_pt = malloc((size_t)sz);
        uint8_t *bench_ct = malloc((size_t)sz);
        uint8_t *bench_rt = malloc((size_t)sz);
        memset(bench_pt, 0xAB, (size_t)sz);

        sample_set_t s_enc = { .samples = malloc((size_t)rounds * sizeof(double)), .count = rounds };
        sample_set_t s_dec = { .samples = malloc((size_t)rounds * sizeof(double)), .count = rounds };

        for (int r = 0; r < rounds; r++) {
            uint8_t b_nonce[12];
            memset(b_nonce, (uint8_t)r, 12);

            uint64_t t0 = ns_now();
            int b_ct_len = aead_encrypt(bench_pt, sz, NULL, 0, key, b_nonce, bench_ct, tag);
            s_enc.samples[r] = (double)(ns_now() - t0) / 1000.0;

            t0 = ns_now();
            aead_decrypt(bench_ct, b_ct_len, NULL, 0, key, b_nonce, tag, bench_rt);
            s_dec.samples[r] = (double)(ns_now() - t0) / 1000.0;
        }

        detailed_stats_t d_enc, d_dec;
        compute_stats(&s_enc, &d_enc);
        compute_stats(&s_dec, &d_dec);

        double enc_throughput = (double)sz / d_enc.mean;
        double dec_throughput = (double)sz / d_dec.mean;

        printf("┌─ Payload Size: %-12s ────────────────────────────────────────────────────────────────────────────┐\n",
               payload_labels[i]);
        printf("├──────────────────┬────────────┬────────────┬────────────┬────────────┬────────────┬────────────┬────────────┬──────┤\n");
        printf("│ Operation        │  Mean (µs) │   Median   │    Min     │    Max     │  Std Dev   │    P95     │    P99     │ Unit │\n");
        printf("├──────────────────┼────────────┼────────────┼────────────┼────────────┼────────────┼────────────┼────────────┼──────┤\n");
        print_stat_row("aead_encrypt", &d_enc, "µs");
        print_stat_row("aead_decrypt", &d_dec, "µs");
        printf("├──────────────────┴────────────┴────────────┴────────────┴────────────┴────────────┴────────────┴────────────┴──────┤\n");
        printf("│ Throughput: Encrypt: %8.1f MB/s  │  Decrypt: %8.1f MB/s                                                  │\n",
               enc_throughput, dec_throughput);
        printf("└──────────────────────────────────────────────────────────────────────────────────────────────────────────────┘\n\n");

        free(bench_pt); free(bench_ct); free(bench_rt);
        free(s_enc.samples); free(s_dec.samples);
    }

    return 0;
}
