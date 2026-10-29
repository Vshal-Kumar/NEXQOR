/*
 * securecomm/src/config/config.c
 *
 * Configuration loader, validator, serializer, and atomic writer.
 */

#define _POSIX_C_SOURCE 200809L
#include "securecomm/config.h"
#include "securecomm/error.h"
#include "json_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

void securecomm_config_init_default(securecomm_config_t *cfg) {
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));
    
    cfg->version = 1;
    cfg->role = SECURECOMM_ROLE_SERVER;
    cfg->mode = SECURECOMM_MODE_ADAPTIVE;
    strncpy(cfg->profile_id, "profile-pqc-1", sizeof(cfg->profile_id) - 1);
    
    strncpy(cfg->bind_address, "127.0.0.1", sizeof(cfg->bind_address) - 1);
    strncpy(cfg->server_address, "127.0.0.1", sizeof(cfg->server_address) - 1);
    cfg->port = SECURECOMM_PORT_PQC;
    cfg->connect_timeout_ms = 5000;
    cfg->reconnect_attempts = 5;
    
    strncpy(cfg->device_id, "node-default", sizeof(cfg->device_id) - 1);
    strncpy(cfg->private_key_path, "/etc/securecomm/identity.key", sizeof(cfg->private_key_path) - 1);
    strncpy(cfg->public_key_path, "/etc/securecomm/identity.pub", sizeof(cfg->public_key_path) - 1);
    strncpy(cfg->trust_store_path, "/etc/securecomm/trust_store.db", sizeof(cfg->trust_store_path) - 1);
    cfg->require_client_auth = true;
    
    cfg->max_concurrent_sessions = 64;
    cfg->rx_buffer_kb = 256;
    cfg->worker_threads = 4;
    
    securecomm_policy_init_default(&cfg->policy);
    
    cfg->log_level = SECURECOMM_LOG_INFO;
    strncpy(cfg->log_filepath, "", sizeof(cfg->log_filepath) - 1);
    cfg->auto_start_service = false;
}

const char *securecomm_config_find_active_path(void) {
    if (access(SECURECOMM_DEFAULT_CONFIG, R_OK) == 0) {
        return SECURECOMM_DEFAULT_CONFIG;
    }
    if (access(SECURECOMM_LOCAL_CONFIG, R_OK) == 0) {
        return SECURECOMM_LOCAL_CONFIG;
    }
    return SECURECOMM_LOCAL_CONFIG;
}

int securecomm_config_load(securecomm_config_t *cfg, const char *path) {
    if (!cfg) return SECURECOMM_ERR_INVALID_ARG;
    if (!path) path = securecomm_config_find_active_path();
    
    FILE *f = fopen(path, "rb");
    if (!f) {
        return SECURECOMM_ERR_CONFIG_NOT_FOUND;
    }
    
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (sz <= 0 || sz > 512 * 1024) { /* 512KB sanity max */
        fclose(f);
        return SECURECOMM_ERR_CONFIG_PARSE;
    }
    
    char *buf = (char *)malloc(sz + 1);
    if (!buf) {
        fclose(f);
        return SECURECOMM_ERR_NOMEM;
    }
    
    size_t read_bytes = fread(buf, 1, sz, f);
    fclose(f);
    buf[read_bytes] = '\0';
    
    char err[128] = "";
    json_value_t *root = json_parse(buf, err, sizeof(err));
    free(buf);
    
    if (!root || root->type != JSON_OBJECT) {
        json_free(root);
        return SECURECOMM_ERR_CONFIG_PARSE;
    }
    
    securecomm_config_init_default(cfg);
    
    cfg->version = (uint32_t)json_get_int(json_object_get(root, "version"), 1);
    cfg->role = securecomm_role_from_string(json_get_string(json_object_get(root, "role"), "server"));
    cfg->mode = securecomm_mode_from_string(json_get_string(json_object_get(root, "mode"), "adaptive"));
    
    const char *prof = json_get_string(json_object_get(root, "profile_id"), NULL);
    if (prof) strncpy(cfg->profile_id, prof, sizeof(cfg->profile_id) - 1);
    
    /* Network */
    json_value_t *net = json_object_get(root, "network");
    if (net) {
        const char *bind_ip = json_get_string(json_object_get(net, "bind_address"), NULL);
        if (bind_ip) strncpy(cfg->bind_address, bind_ip, sizeof(cfg->bind_address) - 1);
        
        const char *srv_ip = json_get_string(json_object_get(net, "server_address"), NULL);
        if (!srv_ip) srv_ip = json_get_string(json_object_get(net, "server_host"), NULL);
        if (srv_ip) {
            strncpy(cfg->server_address, srv_ip, sizeof(cfg->server_address) - 1);
            strncpy(cfg->server_host, srv_ip, sizeof(cfg->server_host) - 1);
        }
        
        cfg->port = (uint16_t)json_get_int(json_object_get(net, "port"), cfg->port);
        cfg->connect_timeout_ms = (uint32_t)json_get_int(json_object_get(net, "connect_timeout_ms"), 5000);
        cfg->reconnect_attempts = (uint32_t)json_get_int(json_object_get(net, "reconnect_attempts"), 5);
    }
    
    /* Identity */
    json_value_t *id = json_object_get(root, "identity");
    if (id) {
        const char *dev = json_get_string(json_object_get(id, "device_id"), NULL);
        if (dev) strncpy(cfg->device_id, dev, sizeof(cfg->device_id) - 1);
        
        const char *priv = json_get_string(json_object_get(id, "private_key_path"), NULL);
        if (priv) strncpy(cfg->private_key_path, priv, sizeof(cfg->private_key_path) - 1);
        
        const char *pub = json_get_string(json_object_get(id, "public_key_path"), NULL);
        if (pub) strncpy(cfg->public_key_path, pub, sizeof(cfg->public_key_path) - 1);
        
        const char *trust = json_get_string(json_object_get(id, "trust_store_path"), NULL);
        if (trust) strncpy(cfg->trust_store_path, trust, sizeof(cfg->trust_store_path) - 1);
        
        cfg->require_client_auth = json_get_bool(json_object_get(id, "require_client_auth"), true);
    }
    
    /* Policy */
    json_value_t *pol = json_object_get(root, "policy");
    if (pol) {
        cfg->policy.require_quantum_resistance = json_get_bool(json_object_get(pol, "require_quantum_resistance"), true);
        cfg->policy.require_quantum_auth = json_get_bool(json_object_get(pol, "require_quantum_auth"), false);
        cfg->policy.require_dual_combiner = json_get_bool(json_object_get(pol, "require_dual_combiner"), false);
        cfg->policy.allow_classical_fallback = json_get_bool(json_object_get(pol, "allow_classical_fallback"), false);
        cfg->policy.require_fips_algorithms = json_get_bool(json_object_get(pol, "require_fips_algorithms"), true);
        cfg->policy.max_acceptable_latency_ms = (uint32_t)json_get_int(json_object_get(pol, "max_acceptable_latency_ms"), 500);
        cfg->policy.max_memory_budget_mb = (uint32_t)json_get_int(json_object_get(pol, "max_memory_budget_mb"), 256);
        cfg->policy.preference = securecomm_policy_pref_from_string(json_get_string(json_object_get(pol, "preference"), "balanced"));
        cfg->policy.pref = cfg->policy.preference;
    }
    
    /* Resources */
    json_value_t *res = json_object_get(root, "resources");
    if (res) {
        cfg->max_concurrent_sessions = (uint32_t)json_get_int(json_object_get(res, "max_concurrent_sessions"), 64);
        cfg->rx_buffer_kb = (uint32_t)json_get_int(json_object_get(res, "rx_buffer_kb"), 256);
        cfg->worker_threads = (uint32_t)json_get_int(json_object_get(res, "worker_threads"), 4);
    }
    
    /* Logging */
    json_value_t *log = json_object_get(root, "logging");
    if (log) {
        cfg->log_level = securecomm_log_level_from_string(json_get_string(json_object_get(log, "level"), "info"));
        const char *lp = json_get_string(json_object_get(log, "file"), "");
        if (lp) strncpy(cfg->log_filepath, lp, sizeof(cfg->log_filepath) - 1);
    }
    
    cfg->auto_start_service = json_get_bool(json_object_get(root, "auto_start_service"), false);
    
    json_free(root);
    return SECURECOMM_SUCCESS;
}

int securecomm_config_save(const securecomm_config_t *cfg, const char *path) {
    if (!cfg || !path) return SECURECOMM_ERR_INVALID_ARG;
    
    json_value_t *root = json_create_object();
    if (!root) return SECURECOMM_ERR_NOMEM;
    
    json_object_set(root, "version", json_create_number(cfg->version));
    json_object_set(root, "role", json_create_string(securecomm_role_to_string(cfg->role)));
    json_object_set(root, "mode", json_create_string(securecomm_mode_to_string(cfg->mode)));
    json_object_set(root, "profile_id", json_create_string(cfg->profile_id));
    
    json_value_t *net = json_create_object();
    const char *srv = strlen(cfg->server_address) > 0 ? cfg->server_address : cfg->server_host;
    json_object_set(net, "bind_address", json_create_string(cfg->bind_address));
    json_object_set(net, "server_address", json_create_string(srv));
    json_object_set(net, "server_host", json_create_string(srv));
    json_object_set(net, "port", json_create_number(cfg->port));
    json_object_set(net, "connect_timeout_ms", json_create_number(cfg->connect_timeout_ms));
    json_object_set(net, "reconnect_attempts", json_create_number(cfg->reconnect_attempts));
    json_object_set(root, "network", net);
    
    json_value_t *id = json_create_object();
    json_object_set(id, "device_id", json_create_string(cfg->device_id));
    json_object_set(id, "private_key_path", json_create_string(cfg->private_key_path));
    json_object_set(id, "public_key_path", json_create_string(cfg->public_key_path));
    json_object_set(id, "trust_store_path", json_create_string(cfg->trust_store_path));
    json_object_set(id, "require_client_auth", json_create_bool(cfg->require_client_auth));
    json_object_set(root, "identity", id);
    
    json_value_t *pol = json_create_object();
    json_object_set(pol, "require_quantum_resistance", json_create_bool(cfg->policy.require_quantum_resistance));
    json_object_set(pol, "require_quantum_auth", json_create_bool(cfg->policy.require_quantum_auth));
    json_object_set(pol, "require_dual_combiner", json_create_bool(cfg->policy.require_dual_combiner));
    json_object_set(pol, "allow_classical_fallback", json_create_bool(cfg->policy.allow_classical_fallback));
    json_object_set(pol, "require_fips_algorithms", json_create_bool(cfg->policy.require_fips_algorithms));
    json_object_set(pol, "max_acceptable_latency_ms", json_create_number(cfg->policy.max_acceptable_latency_ms));
    json_object_set(pol, "max_memory_budget_mb", json_create_number(cfg->policy.max_memory_budget_mb));
    securecomm_policy_pref_t p_pref = cfg->policy.pref ? cfg->policy.pref : cfg->policy.preference;
    json_object_set(pol, "preference", json_create_string(securecomm_policy_pref_to_string(p_pref)));
    json_object_set(root, "policy", pol);
    
    json_value_t *res = json_create_object();
    json_object_set(res, "max_concurrent_sessions", json_create_number(cfg->max_concurrent_sessions));
    json_object_set(res, "rx_buffer_kb", json_create_number(cfg->rx_buffer_kb));
    json_object_set(res, "worker_threads", json_create_number(cfg->worker_threads));
    json_object_set(root, "resources", res);
    
    json_value_t *log = json_create_object();
    json_object_set(log, "level", json_create_string(securecomm_log_level_to_string(cfg->log_level)));
    json_object_set(log, "file", json_create_string(cfg->log_filepath));
    json_object_set(root, "logging", log);
    
    json_object_set(root, "auto_start_service", json_create_bool(cfg->auto_start_service));
    
    char *json_text = json_stringify(root, true);
    json_free(root);
    
    if (!json_text) return SECURECOMM_ERR_NOMEM;
    
    /* Atomic write via temporary file */
    char tmp_path[SECURECOMM_MAX_PATH_LEN + 16];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%d", path, (int)getpid());
    
    FILE *f = fopen(tmp_path, "wb");
    if (!f) {
        free(json_text);
        return SECURECOMM_ERR_CONFIG_WRITE;
    }
    
    size_t len = strlen(json_text);
    if (fwrite(json_text, 1, len, f) != len) {
        fclose(f);
        unlink(tmp_path);
        free(json_text);
        return SECURECOMM_ERR_CONFIG_WRITE;
    }
    
    fflush(f);
    fsync(fileno(f));
    fclose(f);
    free(json_text);
    
    /* Set reasonable permissions */
    chmod(tmp_path, 0644);
    
    if (rename(tmp_path, path) != 0) {
        unlink(tmp_path);
        return SECURECOMM_ERR_CONFIG_WRITE;
    }
    
    return SECURECOMM_SUCCESS;
}

int securecomm_config_validate_full(const securecomm_config_t *cfg, char *out_err, size_t err_max) {
    if (!cfg) {
        if (out_err && err_max) snprintf(out_err, err_max, "Null configuration pointer");
        return SECURECOMM_ERR_INVALID_ARG;
    }
    if (cfg->role != SECURECOMM_ROLE_SERVER && cfg->role != SECURECOMM_ROLE_CLIENT) {
        if (out_err && err_max) snprintf(out_err, err_max, "Invalid role (must be 'server' or 'client')");
        return SECURECOMM_ERR_CONFIG_VALIDATE;
    }
    if (cfg->mode < SECURECOMM_MODE_CLASSICAL || cfg->mode > SECURECOMM_MODE_ADAPTIVE) {
        if (out_err && err_max) snprintf(out_err, err_max, "Invalid mode (must be classical, pqc, hybrid, or adaptive)");
        return SECURECOMM_ERR_CONFIG_VALIDATE;
    }
    if (cfg->port == 0) {
        if (out_err && err_max) snprintf(out_err, err_max, "Port cannot be 0");
        return SECURECOMM_ERR_CONFIG_VALIDATE;
    }
    if (cfg->role == SECURECOMM_ROLE_CLIENT && strlen(cfg->server_address) == 0) {
        if (out_err && err_max) snprintf(out_err, err_max, "Client requires non-empty server_address");
        return SECURECOMM_ERR_CONFIG_VALIDATE;
    }
    if (strlen(cfg->device_id) == 0) {
        if (out_err && err_max) snprintf(out_err, err_max, "Device identifier cannot be empty");
        return SECURECOMM_ERR_CONFIG_VALIDATE;
    }
    
    /* Downstream policy check: if PQC or Hybrid is chosen, fallback must not be secretly forced */
    if ((cfg->mode == SECURECOMM_MODE_PQC || cfg->mode == SECURECOMM_MODE_HYBRID) &&
        cfg->policy.allow_classical_fallback) {
        /* Allowed only if explicitly permitted, warn or validate */
    }
    
    return SECURECOMM_SUCCESS;
}

void securecomm_config_show(const securecomm_config_t *cfg, FILE *out, bool redact_secrets) {
    if (!cfg || !out) return;
    
    fprintf(out, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    fprintf(out, "  SecureComm Configuration Summary\n");
    fprintf(out, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    fprintf(out, "  • Schema Version   : %u\n", cfg->version);
    fprintf(out, "  • Device Role      : %s\n", securecomm_role_to_string(cfg->role));
    fprintf(out, "  • Operating Mode   : %s\n", securecomm_mode_to_string(cfg->mode));
    fprintf(out, "  • Target Profile   : %s\n", cfg->profile_id);
    fprintf(out, "  • Device Identifier: %s\n", cfg->device_id);
    
    if (cfg->role == SECURECOMM_ROLE_SERVER) {
        fprintf(out, "  • Bind Address     : %s:%u\n", cfg->bind_address, cfg->port);
        fprintf(out, "  • Max Sessions     : %u\n", cfg->max_concurrent_sessions);
    } else {
        fprintf(out, "  • Server Target    : %s:%u\n", cfg->server_address, cfg->port);
        fprintf(out, "  • Timeout / Retry  : %u ms / %u attempts\n", cfg->connect_timeout_ms, cfg->reconnect_attempts);
    }
    
    fprintf(out, "\n  [Identity & Cryptography]\n");
    if (redact_secrets) {
        fprintf(out, "  • Private Key Path : [REDACTED FOR SECURITY]\n");
    } else {
        fprintf(out, "  • Private Key Path : %s (0600)\n", cfg->private_key_path);
    }
    fprintf(out, "  • Public Key Path  : %s\n", cfg->public_key_path);
    fprintf(out, "  • Trust Store Path : %s\n", cfg->trust_store_path);
    fprintf(out, "  • Client Auth Req  : %s\n", cfg->require_client_auth ? "YES (Mutual Authentication)" : "NO");
    
    fprintf(out, "\n  [Adaptive Security Policy]\n");
    fprintf(out, "  • Require Quantum  : %s\n", cfg->policy.require_quantum_resistance ? "YES" : "NO");
    fprintf(out, "  • Require QuantumAuth: %s\n", cfg->policy.require_quantum_auth ? "YES" : "NO");
    fprintf(out, "  • Require Hybrid   : %s\n", cfg->policy.require_dual_combiner ? "YES" : "NO");
    fprintf(out, "  • Classical Fallback: %s\n", cfg->policy.allow_classical_fallback ? "PERMITTED" : "STRICTLY PROHIBITED");
    fprintf(out, "  • Optimization Goal: %s\n", securecomm_policy_pref_to_string(cfg->policy.preference));
    
    fprintf(out, "\n  [System & Logging]\n");
    fprintf(out, "  • Log Level        : %s\n", securecomm_log_level_to_string(cfg->log_level));
    fprintf(out, "  • Log File         : %s\n", strlen(cfg->log_filepath) ? cfg->log_filepath : "<standard output>");
    fprintf(out, "  • Service AutoStart: %s\n", cfg->auto_start_service ? "YES (systemd)" : "NO");
    fprintf(out, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
}
