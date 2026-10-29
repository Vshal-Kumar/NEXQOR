/*
 * securecomm/include/securecomm/policy.h
 *
 * Security policy rules, constraints, and objective preferences for SecureComm.
 */

#ifndef SECURECOMM_POLICY_H
#define SECURECOMM_POLICY_H

#include "common.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PREF_HIGH_SECURITY  = 0,  /* Prioritize pure PQC or dual-combiner Hybrid */
    PREF_LOW_LATENCY    = 1,  /* Prioritize faster handshake latency */
    PREF_LOW_MEMORY     = 2,  /* Prioritize minimal RAM consumption */
    PREF_BALANCED       = 3   /* Balance quantum-safety with performance */
} securecomm_policy_pref_t;

#define SECURECOMM_PREF_LOW_LATENCY     PREF_LOW_LATENCY
#define SECURECOMM_PREF_LOW_MEMORY      PREF_LOW_MEMORY
#define SECURECOMM_PREF_HIGH_THROUGHPUT PREF_LOW_LATENCY
#define SECURECOMM_PREF_BALANCED        PREF_BALANCED

typedef struct {
    bool require_quantum_resistance;   /* Mandatory quantum-safe key exchange */
    bool require_quantum_auth;         /* Mandatory quantum-safe digital signatures */
    bool require_dual_combiner;        /* Mandatory hybrid defense-in-depth */
    bool allow_classical_fallback;     /* Allow fallback to classical (default: FALSE) */
    bool require_fips_algorithms;      /* Only allow NIST FIPS certified algorithms */
    bool allow_tofu;                   /* Allow Trust-on-First-Use */
    
    uint32_t max_acceptable_latency_ms;/* Maximum acceptable handshake latency */
    uint32_t max_memory_budget_mb;     /* Maximum RAM budget for cryptographic ops */
    uint16_t min_protocol_version;     /* Version floor to prevent downgrade attacks */
    
    securecomm_policy_pref_t preference; /* Optimization goal for ranking */
    securecomm_policy_pref_t pref;       /* Alias for preference */
} securecomm_policy_t;

void securecomm_policy_init_default(securecomm_policy_t *policy);
void securecomm_policy_init_high_security(securecomm_policy_t *policy);
void securecomm_policy_init_iot_constrained(securecomm_policy_t *policy);

const char *securecomm_policy_pref_to_string(securecomm_policy_pref_t pref);
securecomm_policy_pref_t securecomm_policy_pref_from_string(const char *str);

#ifdef __cplusplus
}
#endif

#endif /* SECURECOMM_POLICY_H */
