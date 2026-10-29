/*
 * security_lab/src/safety_guard.c
 *
 * Implements strict defensive safety guards, allowlisting, rate limits,
 * audit logging, and signal-based emergency stops.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "safety_guard.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <net/if.h>

volatile bool g_safety_emergency_stop = false;
static safety_config_t g_safety_cfg;

static void on_emergency_signal(int sig) {
    (void)sig;
    if (g_safety_emergency_stop) {
        fprintf(stderr, "\n\033[1;31m[SAFETY ALERT] Second interrupt received. Halting process immediately.\033[0m\n");
        _exit(130);
    }
    g_safety_emergency_stop = true;
    fprintf(stderr, "\n\033[1;31m[SAFETY ALERT] Emergency Stop Intercepted (SIGINT/SIGTERM)! Aborting active operations...\033[0m\n");
}

int safety_guard_init(bool dry_run) {
    memset(&g_safety_cfg, 0, sizeof(g_safety_cfg));
    g_safety_cfg.dry_run = dry_run;
    g_safety_cfg.max_duration_sec = SAFETY_DEFAULT_MAX_DURATION_SEC;
    g_safety_cfg.max_pps = SAFETY_DEFAULT_MAX_PPS;
    g_safety_cfg.max_concurrent_clients = SAFETY_DEFAULT_CONCURRENT_MAX;
    g_safety_cfg.max_outstanding_handshakes = 64;
    g_safety_cfg.max_cpu_percent_threshold = 95.0;
    g_safety_cfg.max_memory_mb_threshold = 1024.0;
    g_safety_cfg.health_check_timeout_ms = 1000;
    strncpy(g_safety_cfg.audit_log_path, "security_lab/results/audit.log", sizeof(g_safety_cfg.audit_log_path) - 1);

    /* Built-in authorized lab endpoints */
    safety_guard_add_allowed_target("127.0.0.1", 0);       /* Localhost Loopback */
    safety_guard_add_allowed_target("10.58.4.191", 0);     /* Host Physical LAN IP */
    safety_guard_add_allowed_target("100.113.83.56", 0);   /* Tailscale Mesh VPN IP */
    safety_guard_add_allowed_target("::1", 0);             /* IPv6 Loopback */

    g_safety_cfg.initialized = true;

    /* Ensure results folder exists for audit logging */
    mkdir("security_lab", 0755);
    mkdir("security_lab/results", 0755);

    safety_guard_audit_log("SAFETY_INIT", "GLOBAL", "INIT", "LOCAL",
                           dry_run ? "Safety Guard initialized in DRY-RUN mode" : "Safety Guard initialized in ACTIVE mode");
    return 0;
}

int safety_guard_add_allowed_target(const char *ip_str, uint16_t port) {
    if (!ip_str || g_safety_cfg.allowlist_count >= SAFETY_MAX_ALLOWLIST_ENTRIES) {
        return -1;
    }

    for (size_t i = 0; i < g_safety_cfg.allowlist_count; i++) {
        if (strcmp(g_safety_cfg.allowlist[i].ip_str, ip_str) == 0) {
            if (port == 0 || g_safety_cfg.allowlist[i].port == port) {
                return 0; /* Already allowed */
            }
        }
    }

    safety_target_t *t = &g_safety_cfg.allowlist[g_safety_cfg.allowlist_count++];
    strncpy(t->ip_str, ip_str, sizeof(t->ip_str) - 1);
    t->port = port;
    t->allow_wildcard_port = (port == 0);

    return 0;
}

int safety_guard_validate_target(const char *ip_str, uint16_t port) {
    if (!ip_str) return -1;

    /* Check target IP against approved allowlist */
    bool ip_ok = false;
    for (size_t i = 0; i < g_safety_cfg.allowlist_count; i++) {
        if (strcmp(g_safety_cfg.allowlist[i].ip_str, ip_str) == 0) {
            if (g_safety_cfg.allowlist[i].allow_wildcard_port ||
                g_safety_cfg.allowlist[i].port == port) {
                ip_ok = true;
                break;
            }
        }
    }

    if (!ip_ok) {
        fprintf(stderr, "\033[1;31m[SAFETY GUARD REJECTION] Target IP '%s' is NOT in approved allowlist!\033[0m\n", ip_str);
        safety_guard_audit_log("TARGET_REJECTED", "SECURITY_GUARD", "VALIDATE", ip_str, "Unauthorized target rejected");
        return -1;
    }

    /* Verify approved port bounds (Classical 9877, Hybrid 9879, PQC 9877, Proxy 9880/9881) */
    if (port != 9877 && port != 9879 && port != 9880 && port != 9881 && port != 0) {
        fprintf(stderr, "\033[1;33m[SAFETY GUARD WARNING] Non-standard target port %u specified\033[0m\n", port);
    }

    return 0;
}

int safety_guard_validate_route(const char *ip_str, char *out_iface, size_t iface_len) {
    if (!ip_str || !out_iface || iface_len == 0) return -1;

    if (strncmp(ip_str, "127.", 4) == 0 || strcmp(ip_str, "::1") == 0) {
        snprintf(out_iface, iface_len, "lo");
        return 0;
    } else if (strncmp(ip_str, "100.", 4) == 0) {
        snprintf(out_iface, iface_len, "tailscale0");
        return 0;
    } else if (strncmp(ip_str, "10.58.", 6) == 0) {
        snprintf(out_iface, iface_len, "wlp2s0");
        return 0;
    }

    snprintf(out_iface, iface_len, "default");
    return 0;
}

void safety_guard_throttle_pps(void) {
    static struct timespec last_ts = {0, 0};
    if (g_safety_cfg.max_pps == 0) return;

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    uint64_t min_interval_ns = 1000000000ULL / g_safety_cfg.max_pps;
    uint64_t elapsed_ns = (uint64_t)(now.tv_sec - last_ts.tv_sec) * 1000000000ULL +
                          (uint64_t)(now.tv_nsec - last_ts.tv_nsec);

    if (elapsed_ns < min_interval_ns) {
        uint64_t sleep_ns = min_interval_ns - elapsed_ns;
        struct timespec req = { .tv_sec = (time_t)(sleep_ns / 1000000000ULL),
                                .tv_nsec = (long)(sleep_ns % 1000000000ULL) };
        nanosleep(&req, NULL);
    }

    clock_gettime(CLOCK_MONOTONIC, &last_ts);
}

bool safety_guard_check_timeout(uint64_t start_mono_ns) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    uint64_t now_ns = (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;

    uint64_t elapsed_sec = (now_ns - start_mono_ns) / 1000000000ULL;
    if (elapsed_sec >= g_safety_cfg.max_duration_sec) {
        return true;
    }
    return false;
}

int safety_guard_register_signals(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_emergency_signal;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGINT, &sa, NULL) != 0 || sigaction(SIGTERM, &sa, NULL) != 0) {
        return -1;
    }
    return 0;
}

void safety_guard_audit_log(const char *action, const char *suite,
                            const char *scenario, const char *target,
                            const char *status_msg) {
    FILE *f = fopen(g_safety_cfg.audit_log_path, "a");
    if (!f) return;

    time_t now = time(NULL);
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_buf);

    fprintf(f, "[%s] ACTION=%s SUITE=%s SCENARIO=%s TARGET=%s MSG=\"%s\"\n",
            time_str,
            action ? action : "UNKNOWN",
            suite ? suite : "N/A",
            scenario ? scenario : "N/A",
            target ? target : "N/A",
            status_msg ? status_msg : "");
    fclose(f);
}

bool safety_guard_is_dry_run(void) {
    return g_safety_cfg.dry_run;
}

void safety_guard_set_dry_run(bool dry_run) {
    g_safety_cfg.dry_run = dry_run;
}

safety_config_t *safety_guard_get_config(void) {
    return &g_safety_cfg;
}
