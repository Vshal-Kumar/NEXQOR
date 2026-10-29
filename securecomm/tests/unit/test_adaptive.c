/*
 * securecomm/tests/unit/test_adaptive.c
 *
 * Unit tests for 5-stage Adaptive Policy Engine and downgrade protection.
 */

#define _POSIX_C_SOURCE 200809L
#include "securecomm/adaptive.h"
#include "securecomm/device_profile.h"
#include "securecomm/policy.h"
#include "securecomm/error.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static void test_adaptive_default(void) {
    securecomm_device_profile_t dev;
    securecomm_device_profile_collect(&dev);

    securecomm_policy_t pol;
    securecomm_policy_init_default(&pol);

    securecomm_adaptive_decision_t dec;
    int rc = securecomm_adaptive_select(&dev, &pol, NULL, 0, &dec);
    assert(rc == SECURECOMM_SUCCESS);
    assert(dec.selected_profile != NULL);
    assert(dec.eligible_count >= 1);
    printf(" [✓] Default adaptive selection: %s (%s)\n",
           dec.selected_profile->name, securecomm_mode_to_string(dec.selected_profile->mode));
}

static void test_adaptive_high_security_quantum_required(void) {
    securecomm_device_profile_t dev;
    securecomm_device_profile_collect(&dev);

    securecomm_policy_t pol;
    securecomm_policy_init_high_security(&pol);
    pol.require_quantum_resistance = true;
    pol.allow_classical_fallback = false;

    securecomm_adaptive_decision_t dec;
    int rc = securecomm_adaptive_select(&dev, &pol, NULL, 0, &dec);
    assert(rc == SECURECOMM_SUCCESS);
    assert(dec.selected_profile != NULL);
    /* Classical must be strictly excluded */
    assert(dec.selected_profile->mode != SECURECOMM_MODE_CLASSICAL);

    /* Verify rejection list contains classical with policy reason */
    bool classical_rejected = false;
    for (size_t i = 0; i < dec.rejected_count; i++) {
        if (dec.rejected_candidates[i].profile->mode == SECURECOMM_MODE_CLASSICAL) {
            classical_rejected = true;
        }
    }
    assert(classical_rejected == true);
    printf(" [✓] High security policy strictly rejected classical profile\n");
}

static void test_adaptive_downgrade_protection(void) {
    /* Simulate device without PQC libraries */
    securecomm_device_profile_t dev;
    securecomm_device_profile_collect(&dev);
    dev.liboqs_available = false;
    dev.backend_pqc_compiled = false;
    dev.backend_hybrid_compiled = false;
    dev.pqc_functional = false;
    dev.hybrid_functional = false;

    securecomm_policy_t pol;
    securecomm_policy_init_high_security(&pol);
    pol.require_quantum_resistance = true;
    pol.allow_classical_fallback = false;

    securecomm_adaptive_decision_t dec;
    int rc = securecomm_adaptive_select(&dev, &pol, NULL, 0, &dec);
    /* Downgrade protection MUST fail selection rather than silently picking Classical! */
    assert(rc == SECURECOMM_ERR_ADAPTIVE_NO_MATCH || rc == SECURECOMM_ERR_NO_COMPAT_PROFILE);
    assert(dec.selected_profile == NULL);
    printf(" [✓] Downgrade protection verified: silent fallback to classical prevented\n");
}

int main(void) {
    printf("Running Adaptive Engine Unit Tests...\n");
    test_adaptive_default();
    test_adaptive_high_security_quantum_required();
    test_adaptive_downgrade_protection();
    printf("All Adaptive Engine Unit Tests PASSED!\n");
    return 0;
}
