/*
 * securecomm/src/policy/policy.c
 *
 * Security policy initialization and evaluation presets.
 */

#include "securecomm/policy.h"
#include <string.h>
#include <strings.h>

void securecomm_policy_init_default(securecomm_policy_t *p) {
    if (!p) return;
    memset(p, 0, sizeof(*p));
    p->require_quantum_resistance = true;
    p->require_quantum_auth = false;
    p->require_dual_combiner = false;
    p->allow_classical_fallback = false; /* STRICT: No silent downgrade */
    p->require_fips_algorithms = true;
    p->max_acceptable_latency_ms = 500;
    p->max_memory_budget_mb = 256;
    p->min_protocol_version = 0x0100;
    p->preference = PREF_BALANCED;
}

void securecomm_policy_init_high_security(securecomm_policy_t *p) {
    if (!p) return;
    memset(p, 0, sizeof(*p));
    p->require_quantum_resistance = true;
    p->require_quantum_auth = true;
    p->require_dual_combiner = true;      /* Require Dual-Combiner Hybrid or Pure PQC */
    p->allow_classical_fallback = false;  /* Absolutely no fallback */
    p->require_fips_algorithms = true;
    p->max_acceptable_latency_ms = 1000;
    p->max_memory_budget_mb = 512;
    p->min_protocol_version = 0x0100;
    p->preference = PREF_HIGH_SECURITY;
}

void securecomm_policy_init_iot_constrained(securecomm_policy_t *p) {
    if (!p) return;
    memset(p, 0, sizeof(*p));
    p->require_quantum_resistance = false;
    p->require_quantum_auth = false;
    p->require_dual_combiner = false;
    p->allow_classical_fallback = true;   /* Allow classical for constrained microcontrollers */
    p->require_fips_algorithms = false;
    p->max_acceptable_latency_ms = 100;
    p->max_memory_budget_mb = 32;
    p->min_protocol_version = 0x0100;
    p->preference = PREF_LOW_MEMORY;
}

const char *securecomm_policy_pref_to_string(securecomm_policy_pref_t pref) {
    switch (pref) {
        case PREF_HIGH_SECURITY: return "high-security";
        case PREF_LOW_LATENCY:   return "low-latency";
        case PREF_LOW_MEMORY:    return "low-memory";
        case PREF_BALANCED:      return "balanced";
        default:                 return "balanced";
    }
}

securecomm_policy_pref_t securecomm_policy_pref_from_string(const char *str) {
    if (!str) return PREF_BALANCED;
    if (strcasecmp(str, "high-security") == 0 || strcasecmp(str, "security") == 0) return PREF_HIGH_SECURITY;
    if (strcasecmp(str, "low-latency") == 0 || strcasecmp(str, "latency") == 0) return PREF_LOW_LATENCY;
    if (strcasecmp(str, "low-memory") == 0 || strcasecmp(str, "memory") == 0) return PREF_LOW_MEMORY;
    if (strcasecmp(str, "balanced") == 0) return PREF_BALANCED;
    return PREF_BALANCED;
}
