/*
 * security_lab/include/safety_guard.h
 *
 * Safety controls, target allowlisting, rate limits, resource bounds,
 * audit logging, and emergency stop enforcement for security testing.
 */

#ifndef SECURITY_LAB_SAFETY_GUARD_H
#define SECURITY_LAB_SAFETY_GUARD_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SAFETY_MAX_ALLOWLIST_ENTRIES 32
#define SAFETY_DEFAULT_MAX_DURATION_SEC 30
#define SAFETY_HARD_CAP_DURATION_SEC   120
#define SAFETY_DEFAULT_MAX_PPS         500
#define SAFETY_HARD_CAP_MAX_PPS        5000
#define SAFETY_DEFAULT_CONCURRENT_MAX  128

typedef struct {
    char ip_str[64];
    uint16_t port;
    bool allow_wildcard_port;
} safety_target_t;

typedef struct {
    safety_target_t allowlist[SAFETY_MAX_ALLOWLIST_ENTRIES];
    size_t          allowlist_count;

    bool     dry_run;
    uint32_t max_duration_sec;
    uint32_t max_pps;
    uint32_t max_concurrent_clients;
    uint32_t max_outstanding_handshakes;
    double   max_cpu_percent_threshold;
    double   max_memory_mb_threshold;
    uint32_t health_check_timeout_ms;

    char     audit_log_path[256];
    bool     initialized;
} safety_config_t;

/* Global emergency stop flag set by signal handlers */
extern volatile bool g_safety_emergency_stop;

/* Initializes safety controls with strict default allowlist (localhost, LAN, Tailscale) */
int safety_guard_init(bool dry_run);

/* Adds an authorized target IP and port to the active allowlist */
int safety_guard_add_allowed_target(const char *ip_str, uint16_t port);

/* Validates whether a target IP and port are authorized. Returns 0 if allowed, -1 if denied. */
int safety_guard_validate_target(const char *ip_str, uint16_t port);

/* Verifies that the network interface and route for an endpoint are approved */
int safety_guard_validate_route(const char *ip_str, char *out_iface, size_t iface_len);

/* Enforces rate-limiting delay if sending packets faster than max_pps */
void safety_guard_throttle_pps(void);

/* Checks if maximum experiment duration has been exceeded */
bool safety_guard_check_timeout(uint64_t start_mono_ns);

/* Registers POSIX signal handlers (SIGINT, SIGTERM) for emergency rollback */
int safety_guard_register_signals(void);

/* Writes an entry to the audit log */
void safety_guard_audit_log(const char *action, const char *suite,
                            const char *scenario, const char *target,
                            const char *status_msg);

/* Returns current dry-run mode */
bool safety_guard_is_dry_run(void);

/* Sets dry-run mode */
void safety_guard_set_dry_run(bool dry_run);

/* Returns pointer to global safety config */
safety_config_t *safety_guard_get_config(void);

#ifdef __cplusplus
}
#endif

#endif /* SECURITY_LAB_SAFETY_GUARD_H */
