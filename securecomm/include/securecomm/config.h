/*
 * securecomm/include/securecomm/config.h
 *
 * Persistent configuration schema, validation, and JSON serialization.
 * Enforces secret suppression and atomic file updates.
 */

#ifndef SECURECOMM_CONFIG_H
#define SECURECOMM_CONFIG_H

#include "common.h"
#include "policy.h"
#include "logging.h"
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t version;                                /* Config schema version (e.g. 1) */
    securecomm_role_t role;                          /* SERVER or CLIENT */
    securecomm_mode_t mode;                          /* CLASSICAL, PQC, HYBRID, ADAPTIVE */
    char profile_id[SECURECOMM_MAX_PROFILE_NAME];    /* Target or preferred profile */
    
    /* Network Settings */
    char bind_address[SECURECOMM_MAX_IP_LEN];        /* Server bind IP (e.g. "127.0.0.1") */
    char server_address[SECURECOMM_MAX_IP_LEN];      /* Remote server IP/host for client */
    char server_host[SECURECOMM_MAX_IP_LEN];         /* Alias for server_address */
    uint16_t port;                                   /* UDP port (e.g. 9877, 9879, 9885) */
    uint32_t connect_timeout_ms;                     /* Handshake timeout */
    uint32_t connection_timeout_ms;                  /* Alias for connect_timeout_ms */
    uint32_t reconnect_attempts;                     /* Auto-reconnect count (0=infinite) */
    
    /* Identity & Trust Settings */
    char device_id[SECURECOMM_MAX_ID_LEN];           /* Local device identifier */
    char private_key_path[SECURECOMM_MAX_PATH_LEN];  /* Private key location (0600) */
    char public_key_path[SECURECOMM_MAX_PATH_LEN];   /* Public key location */
    char trust_store_path[SECURECOMM_MAX_PATH_LEN];  /* Pinned peer identities */
    char expected_server_id[SECURECOMM_MAX_ID_LEN];  /* Target server expected identity */
    bool require_client_auth;                        /* Enforce mutual client authentication */
    bool allow_tofu;                                 /* Trust on first use */
    
    /* Resource & Performance Limits */
    uint32_t max_concurrent_sessions;                /* Max concurrent client sessions */
    uint32_t rx_buffer_kb;                           /* Socket receive buffer size */
    uint32_t worker_threads;                         /* Worker thread pool size */
    
    /* Adaptive Policy */
    securecomm_policy_t policy;
    
    /* Logging */
    securecomm_log_level_t log_level;
    char log_filepath[SECURECOMM_MAX_PATH_LEN];
    
    /* System Service Options */
    bool auto_start_service;
} securecomm_config_t;

/* Initialize configuration with sane, safe defaults */
void securecomm_config_init_default(securecomm_config_t *cfg);

static inline void securecomm_config_init_defaults(securecomm_config_t *cfg) {
    securecomm_config_init_default(cfg);
}

/* Load from file (standard JSON parser) */
int  securecomm_config_load(securecomm_config_t *cfg, const char *path);

/* Save to file atomically (writes to temp file, fsync, rename) */
int  securecomm_config_save(const securecomm_config_t *cfg, const char *path);
static inline int securecomm_config_save_atomic(const securecomm_config_t *cfg, const char *path) {
    return securecomm_config_save(cfg, path);
}

/* Validate all settings and enforce security invariants */
int  securecomm_config_validate_full(const securecomm_config_t *cfg, char *out_err, size_t err_max);
static inline int securecomm_config_validate(const securecomm_config_t *cfg) {
    return securecomm_config_validate_full(cfg, NULL, 0);
}

/* Print configuration to stream, redacting all sensitive paths/keys */
void securecomm_config_show(const securecomm_config_t *cfg, FILE *out, bool redact_secrets);
static inline void securecomm_config_print(const securecomm_config_t *cfg, FILE *out) {
    securecomm_config_show(cfg, out, true);
}

/* Auto-detect active configuration path (checks /etc/securecomm then local) */
const char *securecomm_config_find_active_path(void);

#ifdef __cplusplus
}
#endif

#endif /* SECURECOMM_CONFIG_H */
