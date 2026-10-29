/*
 * securecomm/src/profiles/profile_registry.c
 *
 * Cryptographic profile registry implementation.
 */

#include "securecomm/profile_registry.h"
#include <string.h>
#include <stdio.h>

static securecomm_profile_t g_profiles[] = {
    {
        .id = "profile-classical-1",
        .name = "Classical IoT Lightweight (X25519 + Ed25519 + AES-128-CCM)",
        .mode = SECURECOMM_MODE_CLASSICAL,
        .kem_algorithm = "X25519",
        .dsa_algorithm = "Ed25519",
        .aead_algorithm = "AES-128-CCM",
        .kdf_algorithm = "HKDF-SHA-256",
        .protocol_version = 0x0100,
        .default_port = SECURECOMM_PORT_CLASSICAL,
        .estimated_handshake_bytes = 296,
        .min_ram_mb = 16,
        .session_memory_bytes = 2048,
        .quantum_resistant_kex = false,
        .quantum_resistant_auth = false,
        .dual_combiner = false,
        .fips_standardized = false,
        .status = PROFILE_STATUS_VALIDATED,
        .backend_ready = true
    },
    {
        .id = "profile-pqc-1",
        .name = "NIST FIPS 203/204 Pure Post-Quantum (ML-KEM-768 + ML-DSA-65)",
        .mode = SECURECOMM_MODE_PQC,
        .kem_algorithm = "ML-KEM-768",
        .dsa_algorithm = "ML-DSA-65",
        .aead_algorithm = "ChaCha20-Poly1305",
        .kdf_algorithm = "SHAKE256",
        .protocol_version = 0x0100,
        .default_port = SECURECOMM_PORT_PQC,
        .estimated_handshake_bytes = 5824,
        .min_ram_mb = 64,
        .session_memory_bytes = 8192,
        .quantum_resistant_kex = true,
        .quantum_resistant_auth = true,
        .dual_combiner = false,
        .fips_standardized = true,
        .status = PROFILE_STATUS_VALIDATED,
        .backend_ready = true
    },
    {
        .id = "profile-hybrid-1",
        .name = "Hybrid Quantum-Safe (Dual X25519/ML-KEM-768 + Ed25519/ML-DSA-65)",
        .mode = SECURECOMM_MODE_HYBRID,
        .kem_algorithm = "X25519 + ML-KEM-768",
        .dsa_algorithm = "Ed25519 + ML-DSA-65",
        .aead_algorithm = "ChaCha20-Poly1305",
        .kdf_algorithm = "HKDF-SHA-384",
        .protocol_version = 0x0100,
        .default_port = SECURECOMM_PORT_HYBRID,
        .estimated_handshake_bytes = 6540,
        .min_ram_mb = 64,
        .session_memory_bytes = 10240,
        .quantum_resistant_kex = true,
        .quantum_resistant_auth = true,
        .dual_combiner = true,
        .fips_standardized = true,
        .status = PROFILE_STATUS_VALIDATED,
        .backend_ready = true
    },
    {
        /* Future Candidate (Explicitly marked UNAVAILABLE until verified) */
        .id = "profile-pqc-small",
        .name = "Candidate Constrained PQC (ML-KEM-512 + ML-DSA-44)",
        .mode = SECURECOMM_MODE_PQC,
        .kem_algorithm = "ML-KEM-512",
        .dsa_algorithm = "ML-DSA-44",
        .aead_algorithm = "ChaCha20-Poly1305",
        .kdf_algorithm = "SHAKE256",
        .protocol_version = 0x0100,
        .default_port = 9882,
        .estimated_handshake_bytes = 3840,
        .min_ram_mb = 32,
        .session_memory_bytes = 6144,
        .quantum_resistant_kex = true,
        .quantum_resistant_auth = true,
        .dual_combiner = false,
        .fips_standardized = true,
        .status = PROFILE_STATUS_UNAVAILABLE,
        .backend_ready = false
    }
};

static const size_t G_PROFILE_COUNT = sizeof(g_profiles) / sizeof(g_profiles[0]);

int securecomm_profile_registry_init(void) {
    return 0;
}

const securecomm_profile_t *securecomm_profile_find(const char *id) {
    if (!id) return NULL;
    for (size_t i = 0; i < G_PROFILE_COUNT; i++) {
        if (strcmp(g_profiles[i].id, id) == 0) {
            return &g_profiles[i];
        }
    }
    return NULL;
}

const securecomm_profile_t *securecomm_profile_default_for_mode(securecomm_mode_t mode) {
    switch (mode) {
        case SECURECOMM_MODE_CLASSICAL: return securecomm_profile_find("profile-classical-1");
        case SECURECOMM_MODE_PQC:       return securecomm_profile_find("profile-pqc-1");
        case SECURECOMM_MODE_HYBRID:    return securecomm_profile_find("profile-hybrid-1");
        case SECURECOMM_MODE_ADAPTIVE:  return securecomm_profile_find("profile-pqc-1");
        default:                        return NULL;
    }
}

size_t securecomm_profile_list_all(const securecomm_profile_t ***out_profiles) {
    if (out_profiles) {
        static const securecomm_profile_t *ptrs[16];
        for (size_t i = 0; i < G_PROFILE_COUNT; i++) {
            ptrs[i] = &g_profiles[i];
        }
        *out_profiles = ptrs;
    }
    return G_PROFILE_COUNT;
}

bool securecomm_profile_is_supported_on_device(const securecomm_profile_t *p,
                                               const securecomm_device_profile_t *d,
                                               char *out_reason, size_t reason_max) {
    if (!p) {
        if (out_reason && reason_max) snprintf(out_reason, reason_max, "Null profile");
        return false;
    }
    if (p->status != PROFILE_STATUS_VALIDATED) {
        if (out_reason && reason_max) snprintf(out_reason, reason_max, "Profile status is UNAVAILABLE or EXPERIMENTAL");
        return false;
    }
    if (!p->backend_ready) {
        if (out_reason && reason_max) snprintf(out_reason, reason_max, "Backend implementation missing or not compiled");
        return false;
    }
    if (d) {
        if (p->mode == SECURECOMM_MODE_CLASSICAL) {
            if (!d->openssl_available || !d->backend_classical_compiled || !d->classical_functional) {
                if (out_reason && reason_max) snprintf(out_reason, reason_max, "Classical crypto backend not functional on device");
                return false;
            }
        } else if (p->mode == SECURECOMM_MODE_PQC) {
            if (!d->liboqs_available || !d->backend_pqc_compiled || !d->pqc_functional) {
                if (out_reason && reason_max) snprintf(out_reason, reason_max, "PQC crypto backend (liboqs) not functional on device");
                return false;
            }
        } else if (p->mode == SECURECOMM_MODE_HYBRID) {
            if (!d->openssl_available || !d->liboqs_available || !d->backend_hybrid_compiled || !d->hybrid_functional) {
                if (out_reason && reason_max) snprintf(out_reason, reason_max, "Hybrid crypto backend not functional on device");
                return false;
            }
        }
        if (d->ram_available_mb > 0 && d->ram_available_mb < p->min_ram_mb) {
            if (out_reason && reason_max) {
                snprintf(out_reason, reason_max, "Insufficient memory (needs %u MB, device has %llu MB)",
                         p->min_ram_mb, (unsigned long long)d->ram_available_mb);
            }
            return false;
        }
    }
    if (out_reason && reason_max) {
        snprintf(out_reason, reason_max, "Hardware and software verified OK");
    }
    return true;
}

void securecomm_profile_print(const securecomm_profile_t *p, FILE *out) {
    if (!p || !out) return;
    
    const char *status_str = "VALIDATED";
    if (p->status == PROFILE_STATUS_EXPERIMENTAL) status_str = "EXPERIMENTAL";
    if (p->status == PROFILE_STATUS_UNAVAILABLE)  status_str = "UNAVAILABLE";
    
    fprintf(out, "  ┌─ Profile ID: %-22s [%s]\n", p->id, status_str);
    fprintf(out, "  │  Name          : %s\n", p->name);
    fprintf(out, "  │  Operating Mode: %s\n", securecomm_mode_to_string(p->mode));
    fprintf(out, "  │  Key Exchange  : %s\n", p->kem_algorithm);
    fprintf(out, "  │  Signatures    : %s\n", p->dsa_algorithm);
    fprintf(out, "  │  AEAD Cipher   : %s\n", p->aead_algorithm);
    fprintf(out, "  │  Key Derivation: %s\n", p->kdf_algorithm);
    fprintf(out, "  │  Wire Size     : ~%u Bytes | Default Port: %u\n",
            p->estimated_handshake_bytes, p->default_port);
    fprintf(out, "  │  Quantum-Safe  : KEX: %s | Auth: %s | Dual: %s\n",
            p->quantum_resistant_kex ? "YES" : "NO",
            p->quantum_resistant_auth ? "YES" : "NO",
            p->dual_combiner ? "YES" : "NO");
    fprintf(out, "  └─────────────────────────────────────────────────────────\n");
}

const securecomm_profile_t *securecomm_profile_get_all(size_t *out_count) {
    if (out_count) *out_count = G_PROFILE_COUNT;
    return g_profiles;
}

void securecomm_profile_list_print(FILE *out) {
    if (!out) return;
    fprintf(out, "\n=========================================================================================\n");
    fprintf(out, "                          REGISTERED CRYPTOGRAPHIC PROFILES                              \n");
    fprintf(out, "=========================================================================================\n");
    for (size_t i = 0; i < G_PROFILE_COUNT; i++) {
        securecomm_profile_print(&g_profiles[i], out);
    }
    fprintf(out, "=========================================================================================\n\n");
}
