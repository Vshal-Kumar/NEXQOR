/*
 * securecomm/tests/unit/test_profiles.c
 *
 * Unit tests for Cryptographic Profile Registry.
 */

#define _POSIX_C_SOURCE 200809L
#include "securecomm/profile_registry.h"
#include "securecomm/device_profile.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

int main(void) {
    printf("Running Profile Registry Unit Tests...\n");

    size_t count = 0;
    const securecomm_profile_t *list = securecomm_profile_get_all(&count);
    assert(list != NULL);
    assert(count >= 3);

    /* Lookup by ID */
    const securecomm_profile_t *p_classic = securecomm_profile_get_by_id("profile-classical-1");
    assert(p_classic != NULL);
    assert(p_classic->mode == SECURECOMM_MODE_CLASSICAL);
    assert(p_classic->status == PROFILE_STATUS_VALIDATED);

    const securecomm_profile_t *p_pqc = securecomm_profile_get_by_id("profile-pqc-1");
    assert(p_pqc != NULL);
    assert(p_pqc->mode == SECURECOMM_MODE_PQC);
    assert(p_pqc->status == PROFILE_STATUS_VALIDATED);

    const securecomm_profile_t *p_hybrid = securecomm_profile_get_by_id("profile-hybrid-1");
    assert(p_hybrid != NULL);
    assert(p_hybrid->mode == SECURECOMM_MODE_HYBRID);
    assert(p_hybrid->status == PROFILE_STATUS_VALIDATED);

    /* Candidate profile check: unverified should not be active */
    const securecomm_profile_t *p_small = securecomm_profile_get_by_id("profile-pqc-small");
    assert(p_small != NULL);
    assert(p_small->status != PROFILE_STATUS_VALIDATED);

    /* Device compatibility */
    securecomm_device_profile_t dev;
    securecomm_device_profile_collect(&dev);

    assert(securecomm_profile_is_device_compatible(p_classic, &dev) == true);
    assert(securecomm_profile_is_device_compatible(p_pqc, &dev) == true);
    assert(securecomm_profile_is_device_compatible(p_hybrid, &dev) == true);
    /* Unverified candidate profile MUST be marked incompatible/unavailable */
    assert(securecomm_profile_is_device_compatible(p_small, &dev) == false);

    printf("All Profile Registry Unit Tests PASSED!\n");
    return 0;
}
