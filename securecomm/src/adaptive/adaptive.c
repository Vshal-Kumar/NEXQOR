/*
 * securecomm/src/adaptive/adaptive.c
 *
 * Deterministic and explainable Adaptive Cryptographic Profile Selection Engine.
 * 5-Stage Selection: Capability -> Policy -> Resource -> Peer -> Ranking.
 */

#include "securecomm/adaptive.h"
#include "securecomm/error.h"
#include <string.h>
#include <stdio.h>

int securecomm_adaptive_select(const securecomm_device_profile_t *dev,
                               const securecomm_policy_t *policy,
                               const char *peer_supported[],
                               size_t peer_count,
                               securecomm_adaptive_decision_t *d) {
    if (!d) return SECURECOMM_ERR_INVALID_ARG;
    memset(d, 0, sizeof(*d));
    
    const securecomm_profile_t **all_profiles = NULL;
    size_t total_profiles = securecomm_profile_list_all(&all_profiles);
    
    /* ── Iterate Candidates Through 5-Stage Funnel ─────────────────── */
    for (size_t i = 0; i < total_profiles; i++) {
        const securecomm_profile_t *p = all_profiles[i];
        
        /* ── Stage A: Capability Filtering ────────────────────────── */
        char cap_err[128] = "";
        if (!securecomm_profile_is_supported_on_device(p, dev, cap_err, sizeof(cap_err))) {
            if (d->rejected_count < ADAPTIVE_MAX_CANDIDATES) {
                d->rejected_candidates[d->rejected_count].profile = p;
                snprintf(d->rejected_candidates[d->rejected_count].reason,
                         sizeof(d->rejected_candidates[d->rejected_count].reason),
                         "[Stage A: Capability] %s", cap_err);
                d->rejected_count++;
            }
            continue;
        }
        
        /* ── Stage B: Security-Policy Filtering ────────────────────── */
        if (policy) {
            if (policy->require_quantum_resistance && !p->quantum_resistant_kex) {
                if (d->rejected_count < ADAPTIVE_MAX_CANDIDATES) {
                    d->rejected_candidates[d->rejected_count].profile = p;
                    snprintf(d->rejected_candidates[d->rejected_count].reason,
                             sizeof(d->rejected_candidates[d->rejected_count].reason),
                             "[Stage B: Policy] Classical KEX rejected (policy mandates quantum-safe secrecy)");
                    d->rejected_count++;
                }
                continue;
            }
            if (policy->require_quantum_auth && !p->quantum_resistant_auth) {
                if (d->rejected_count < ADAPTIVE_MAX_CANDIDATES) {
                    d->rejected_candidates[d->rejected_count].profile = p;
                    snprintf(d->rejected_candidates[d->rejected_count].reason,
                             sizeof(d->rejected_candidates[d->rejected_count].reason),
                             "[Stage B: Policy] Classical DSA rejected (policy mandates quantum-safe authentication)");
                    d->rejected_count++;
                }
                continue;
            }
            if (policy->require_dual_combiner && !p->dual_combiner) {
                if (d->rejected_count < ADAPTIVE_MAX_CANDIDATES) {
                    d->rejected_candidates[d->rejected_count].profile = p;
                    snprintf(d->rejected_candidates[d->rejected_count].reason,
                             sizeof(d->rejected_candidates[d->rejected_count].reason),
                             "[Stage B: Policy] Single-primitive rejected (policy mandates dual-combiner hybrid)");
                    d->rejected_count++;
                }
                continue;
            }
            if (p->mode == SECURECOMM_MODE_CLASSICAL && !policy->allow_classical_fallback &&
                (policy->require_quantum_resistance || policy->require_quantum_auth)) {
                if (d->rejected_count < ADAPTIVE_MAX_CANDIDATES) {
                    d->rejected_candidates[d->rejected_count].profile = p;
                    snprintf(d->rejected_candidates[d->rejected_count].reason,
                             sizeof(d->rejected_candidates[d->rejected_count].reason),
                             "[Stage B: Policy] Classical fallback prohibited by policy");
                    d->rejected_count++;
                }
                continue;
            }
        }
        
        /* ── Stage C: Resource Feasibility ────────────────────────── */
        if (policy && policy->max_memory_budget_mb > 0 && p->min_ram_mb > policy->max_memory_budget_mb) {
            if (d->rejected_count < ADAPTIVE_MAX_CANDIDATES) {
                d->rejected_candidates[d->rejected_count].profile = p;
                snprintf(d->rejected_candidates[d->rejected_count].reason,
                         sizeof(d->rejected_candidates[d->rejected_count].reason),
                         "[Stage C: Resource] Exceeds memory budget (%u MB > %u MB)",
                         p->min_ram_mb, policy->max_memory_budget_mb);
                d->rejected_count++;
            }
            continue;
        }
        
        /* ── Stage D: Peer Compatibility ──────────────────────────── */
        if (peer_count > 0 && peer_supported) {
            bool peer_has = false;
            for (size_t k = 0; k < peer_count; k++) {
                if (peer_supported[k] && strcmp(peer_supported[k], p->id) == 0) {
                    peer_has = true;
                    break;
                }
            }
            if (!peer_has) {
                if (d->rejected_count < ADAPTIVE_MAX_CANDIDATES) {
                    d->rejected_candidates[d->rejected_count].profile = p;
                    snprintf(d->rejected_candidates[d->rejected_count].reason,
                             sizeof(d->rejected_candidates[d->rejected_count].reason),
                             "[Stage D: Peer] Not supported by remote peer profile list");
                    d->rejected_count++;
                }
                continue;
            }
        }
        
        /* Candidate passed all constraints */
        if (d->eligible_count < ADAPTIVE_MAX_CANDIDATES) {
            d->eligible_profiles[d->eligible_count++] = p;
        }
    }
    
    /* ── Stage E: Ranking ─────────────────────────────────────────── */
    if (d->eligible_count == 0) {
        d->no_compatible_candidate = true;
        snprintf(d->decision_summary, sizeof(d->decision_summary),
                 "No compatible profile satisfies all hardware capabilities and security policy constraints.");
        return SECURECOMM_ERR_NO_COMPAT_PROFILE;
    }
    
    securecomm_policy_pref_t pref = policy ? policy->preference : PREF_BALANCED;
    const securecomm_profile_t *best = d->eligible_profiles[0];
    
    for (size_t i = 1; i < d->eligible_count; i++) {
        const securecomm_profile_t *cur = d->eligible_profiles[i];
        
        if (pref == PREF_HIGH_SECURITY) {
            /* Prefer Hybrid (dual security) then Pure PQC over Classical */
            if (cur->dual_combiner && !best->dual_combiner) best = cur;
            else if (cur->quantum_resistant_kex && !best->quantum_resistant_kex) best = cur;
        } else if (pref == PREF_LOW_LATENCY) {
            /* Prefer lower handshake wire size */
            if (cur->estimated_handshake_bytes < best->estimated_handshake_bytes) best = cur;
        } else if (pref == PREF_LOW_MEMORY) {
            /* Prefer minimal RAM footprint */
            if (cur->min_ram_mb < best->min_ram_mb) best = cur;
        } else {
            /* PREF_BALANCED: Prefer Pure PQC, then Hybrid, then Classical */
            if (cur->quantum_resistant_kex && !best->quantum_resistant_kex) best = cur;
            else if (cur->mode == SECURECOMM_MODE_PQC && best->mode != SECURECOMM_MODE_PQC) best = cur;
        }
    }
    
    d->selected_profile = best;
    snprintf(d->decision_summary, sizeof(d->decision_summary),
             "Selected '%s' based on %zu eligible candidates and '%s' ranking objective.",
             best->id, d->eligible_count, securecomm_policy_pref_to_string(pref));
             
    return 0;
}

void securecomm_adaptive_explain(const securecomm_adaptive_decision_t *d,
                                 const securecomm_device_profile_t *dev,
                                 const securecomm_policy_t *policy,
                                 FILE *out) {
    if (!d || !out) return;
    
    fprintf(out, "╔══════════════════════════════════════════════════════════════════════════╗\n");
    fprintf(out, "║             SecureComm Adaptive Profile Selection Analysis               ║\n");
    fprintf(out, "╚══════════════════════════════════════════════════════════════════════════╝\n");
    
    if (dev) {
        fprintf(out, "  • Host Platform    : %s (%s, %u cores, %llu MB RAM available)\n",
                dev->arch, dev->cpu_model, dev->cpu_cores, (unsigned long long)dev->ram_available_mb);
    }
    if (policy) {
        fprintf(out, "  • Security Policy  : Quantum-Safe KEX: %s | Quantum-Safe Auth: %s\n",
                policy->require_quantum_resistance ? "REQUIRED" : "Optional",
                policy->require_quantum_auth ? "REQUIRED" : "Optional");
        fprintf(out, "  • Fallback Rules   : Classical Fallback %s | Ranking Goal: %s\n",
                policy->allow_classical_fallback ? "PERMITTED" : "STRICTLY PROHIBITED",
                securecomm_policy_pref_to_string(policy->preference));
    }
    
    fprintf(out, "\n  [Decision Outcome]\n");
    if (d->selected_profile) {
        fprintf(out, "  ★ Selected Profile : \033[1;32m%s\033[0m (%s)\n",
                d->selected_profile->id, d->selected_profile->name);
        fprintf(out, "  • Mode             : %s\n", securecomm_mode_to_string(d->selected_profile->mode));
        fprintf(out, "  • Cryptography     : KEX: %s | DSA: %s | AEAD: %s\n",
                d->selected_profile->kem_algorithm,
                d->selected_profile->dsa_algorithm,
                d->selected_profile->aead_algorithm);
        fprintf(out, "  • Wire Size        : ~%u Bytes | Est. Concurrency Memory: %u KB/session\n",
                d->selected_profile->estimated_handshake_bytes,
                d->selected_profile->session_memory_bytes / 1024);
    } else {
        fprintf(out, "  ⚠ Selected Profile : \033[1;31mNONE\033[0m (No candidate satisfies policy/hardware constraints)\n");
    }
    fprintf(out, "  • Evaluation Note  : %s\n", d->decision_summary);
    
    fprintf(out, "\n  [Eligible Candidates (%zu)]\n", d->eligible_count);
    for (size_t i = 0; i < d->eligible_count; i++) {
        const securecomm_profile_t *p = d->eligible_profiles[i];
        bool is_sel = (d->selected_profile && strcmp(d->selected_profile->id, p->id) == 0);
        fprintf(out, "  %s %-20s -> %s (Mode: %s)\n",
                is_sel ? "  ✔ [SELECTED]" : "  • [ELIGIBLE]",
                p->id, p->name, securecomm_mode_to_string(p->mode));
    }
    
    fprintf(out, "\n  [Excluded Candidates (%zu)]\n", d->rejected_count);
    for (size_t i = 0; i < d->rejected_count; i++) {
        fprintf(out, "  ✖ %-20s -> %s\n",
                d->rejected_candidates[i].profile->id,
                d->rejected_candidates[i].reason);
    }
    fprintf(out, "════════════════════════════════════════════════════════════════════════════\n");
}
