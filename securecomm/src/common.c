/*
 * securecomm/src/common.c
 *
 * Mode and role string conversion utilities for SecureComm.
 */

#include "securecomm/common.h"
#include <string.h>
#include <strings.h>

const char *securecomm_mode_to_string(securecomm_mode_t mode) {
    switch (mode) {
        case SECURECOMM_MODE_CLASSICAL: return "classical";
        case SECURECOMM_MODE_PQC:       return "pqc";
        case SECURECOMM_MODE_HYBRID:    return "hybrid";
        case SECURECOMM_MODE_ADAPTIVE:  return "adaptive";
        default:                        return "unknown";
    }
}

securecomm_mode_t securecomm_mode_from_string(const char *str) {
    if (!str) return SECURECOMM_MODE_UNKNOWN;
    if (strcasecmp(str, "classical") == 0) return SECURECOMM_MODE_CLASSICAL;
    if (strcasecmp(str, "pqc") == 0 || strcasecmp(str, "post-quantum") == 0) return SECURECOMM_MODE_PQC;
    if (strcasecmp(str, "hybrid") == 0) return SECURECOMM_MODE_HYBRID;
    if (strcasecmp(str, "adaptive") == 0) return SECURECOMM_MODE_ADAPTIVE;
    return SECURECOMM_MODE_UNKNOWN;
}

const char *securecomm_role_to_string(securecomm_role_t role) {
    switch (role) {
        case SECURECOMM_ROLE_SERVER: return "server";
        case SECURECOMM_ROLE_CLIENT: return "client";
        default:                     return "unknown";
    }
}

securecomm_role_t securecomm_role_from_string(const char *str) {
    if (!str) return SECURECOMM_ROLE_UNKNOWN;
    if (strcasecmp(str, "server") == 0) return SECURECOMM_ROLE_SERVER;
    if (strcasecmp(str, "client") == 0) return SECURECOMM_ROLE_CLIENT;
    return SECURECOMM_ROLE_UNKNOWN;
}
