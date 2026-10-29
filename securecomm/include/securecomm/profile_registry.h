/*
 * securecomm/include/securecomm/profile_registry.h
 *
 * Cryptographic Profile Registry for SecureComm.
 * Decouples algorithm configurations from adaptive selection logic.
 */

#ifndef SECURECOMM_PROFILE_REGISTRY_H
#define SECURECOMM_PROFILE_REGISTRY_H

#include "common.h"
#include "device_profile.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PROFILE_STATUS_VALIDATED     = 0,
    PROFILE_STATUS_EXPERIMENTAL  = 1,
    PROFILE_STATUS_UNAVAILABLE   = 2
} securecomm_profile_status_t;

typedef struct {
    char id[SECURECOMM_MAX_PROFILE_NAME];       /* e.g. "profile-pqc-1" */
    char name[128];                             /* e.g. "NIST FIPS 203/204 Pure Post-Quantum" */
    securecomm_mode_t mode;                     /* CLASSICAL, PQC, HYBRID */
    
    /* Primitive Identifiers */
    char kem_algorithm[64];                     /* e.g. "ML-KEM-768", "X25519" */
    char dsa_algorithm[64];                     /* e.g. "ML-DSA-65", "Ed25519" */
    char aead_algorithm[64];                    /* e.g. "ChaCha20-Poly1305", "AES-128-CCM" */
    char kdf_algorithm[64];                     /* e.g. "SHAKE256", "HKDF-SHA-384" */
    
    /* Protocol Attributes */
    uint16_t protocol_version;                  /* e.g. 0x0100 */
    uint16_t default_port;                      /* standard port (9877, 9879, etc.) */
    
    /* Resource & Security Constraints */
    uint32_t estimated_handshake_bytes;         /* unfragmented or fragmented wire size */
    uint32_t min_ram_mb;                        /* minimal RAM to instantiate */
    uint32_t session_memory_bytes;              /* bytes per active session */
    bool quantum_resistant_kex;                 /* protects secrecy against CRQCs */
    bool quantum_resistant_auth;                /* protects authenticity against CRQCs */
    bool dual_combiner;                         /* hybrid fail-closed design */
    bool fips_standardized;                     /* NIST FIPS standardized */
    
    /* Runtime Status */
    securecomm_profile_status_t status;
    bool backend_ready;
} securecomm_profile_t;

int securecomm_profile_registry_init(void);

const securecomm_profile_t *securecomm_profile_find(const char *id);
const securecomm_profile_t *securecomm_profile_default_for_mode(securecomm_mode_t mode);

size_t securecomm_profile_list_all(const securecomm_profile_t ***out_profiles);
const securecomm_profile_t *securecomm_profile_get_all(size_t *out_count);

bool securecomm_profile_is_supported_on_device(const securecomm_profile_t *profile,
                                               const securecomm_device_profile_t *device,
                                               char *out_reason, size_t reason_max);

void securecomm_profile_print(const securecomm_profile_t *profile, FILE *out);
void securecomm_profile_list_print(FILE *out);

/* Inline Convenience Wrappers */
static inline const securecomm_profile_t *securecomm_profile_get_by_id(const char *id) {
    return securecomm_profile_find(id);
}
static inline const securecomm_profile_t *securecomm_profile_get_by_mode(securecomm_mode_t mode) {
    return securecomm_profile_default_for_mode(mode);
}
static inline bool securecomm_profile_is_device_compatible(const securecomm_profile_t *profile,
                                                           const securecomm_device_profile_t *device) {
    return securecomm_profile_is_supported_on_device(profile, device, NULL, 0);
}

#ifdef __cplusplus
}
#endif

#endif /* SECURECOMM_PROFILE_REGISTRY_H */
