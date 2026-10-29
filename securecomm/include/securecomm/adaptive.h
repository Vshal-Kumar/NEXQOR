/*
 * securecomm/include/securecomm/adaptive.h
 *
 * Deterministic and explainable Adaptive Cryptographic Profile Selection Engine.
 * Implements 5-stage pipeline: Capability -> Policy -> Resource -> Peer -> Ranking.
 */

#ifndef SECURECOMM_ADAPTIVE_H
#define SECURECOMM_ADAPTIVE_H

#include "common.h"
#include "device_profile.h"
#include "profile_registry.h"
#include "policy.h"
#include <stdio.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ADAPTIVE_MAX_CANDIDATES 16

typedef struct {
    const securecomm_profile_t *profile;
    char reason[128];
} adaptive_rejected_candidate_t;

typedef struct {
    const securecomm_profile_t *selected_profile;
    
    size_t eligible_count;
    const securecomm_profile_t *eligible_profiles[ADAPTIVE_MAX_CANDIDATES];
    
    size_t rejected_count;
    adaptive_rejected_candidate_t rejected_candidates[ADAPTIVE_MAX_CANDIDATES];
    
    char decision_summary[512];
    bool policy_violation;
    bool no_compatible_candidate;
} securecomm_adaptive_decision_t;

/* Run full 5-stage adaptive selection */
int securecomm_adaptive_select(const securecomm_device_profile_t *device,
                               const securecomm_policy_t *policy,
                               const char *peer_supported_profiles[],
                               size_t peer_supported_count,
                               securecomm_adaptive_decision_t *out_decision);

/* Formatted explainability report */
void securecomm_adaptive_explain(const securecomm_adaptive_decision_t *decision,
                                 const securecomm_device_profile_t *device,
                                 const securecomm_policy_t *policy,
                                 FILE *out);

#ifdef __cplusplus
}
#endif

#endif /* SECURECOMM_ADAPTIVE_H */
