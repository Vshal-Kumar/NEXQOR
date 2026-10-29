/*
 * securecomm/include/securecomm/device_profile.h
 *
 * Lightweight, hardware and runtime capability profiler for SecureComm.
 * Evaluates CPU architecture, SIMD extensions, RAM, disk, and crypto backends.
 */

#ifndef SECURECOMM_DEVICE_PROFILE_H
#define SECURECOMM_DEVICE_PROFILE_H

#include "common.h"
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char arch[32];             /* e.g. "x86_64", "aarch64", "armv7l" */
    char os_name[64];          /* e.g. "Linux" */
    char kernel_release[64];   /* e.g. "6.8.0-generic" */
    char cpu_model[128];       /* e.g. "Intel Core i7" or "Cortex-A72" */
    uint32_t cpu_cores;        /* logical CPU core count */
    
    /* Memory & Storage (Megabytes) */
    uint64_t ram_total_mb;
    uint64_t ram_available_mb;
    uint64_t disk_available_mb;
    
    /* Hardware CPU Extensions */
    bool has_avx2;
    bool has_avx512;
    bool has_aes_ni;
    bool has_neon;
    bool has_sha_extensions;
    
    /* Cryptographic Backends & Libraries */
    bool openssl_available;
    char openssl_version[64];
    bool liboqs_available;
    char liboqs_version[64];
    
    /* Compiled Backend Support */
    bool backend_classical_compiled;
    bool backend_pqc_compiled;
    bool backend_hybrid_compiled;
    
    /* Real-Time Runtime Validation Results */
    bool classical_functional;
    bool pqc_functional;
    bool hybrid_functional;
    
    /* Profiling Timestamp */
    uint64_t timestamp_sec;
} securecomm_device_profile_t;

/* Probe system and populate device profile */
int  securecomm_device_profile_collect(securecomm_device_profile_t *out_profile);

/* Print device profile to stream (e.g. stdout) in formatted text */
void securecomm_device_profile_print(const securecomm_device_profile_t *profile, FILE *out);

/* Re-check volatile memory only */
int  securecomm_device_refresh_memory(securecomm_device_profile_t *profile);

#ifdef __cplusplus
}
#endif

#endif /* SECURECOMM_DEVICE_PROFILE_H */
