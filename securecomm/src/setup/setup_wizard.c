/*
 * securecomm/src/setup/setup_wizard.c
 *
 * Interactive and automated Setup Wizard for SecureComm.
 * Follows the 14-step onboarding workflow to configure and validate a Server or Client node.
 */

#define _POSIX_C_SOURCE 200809L
#include "setup_wizard.h"
#include "securecomm/device_profile.h"
#include "securecomm/profile_registry.h"
#include "securecomm/identity.h"
#include "securecomm/error.h"
#include "securecomm/logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/stat.h>
#include <arpa/inet.h>

static void read_input(const char *prompt, const char *def_val, char *out, size_t out_sz, bool non_interactive) {
    if (non_interactive || !isatty(STDIN_FILENO)) {
        snprintf(out, out_sz, "%s", def_val);
        printf("%s [%s]: %s\n", prompt, def_val, def_val);
        return;
    }

    printf("%s [%s]: ", prompt, def_val);
    fflush(stdout);

    char buf[512];
    if (fgets(buf, sizeof(buf), stdin)) {
        size_t len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n') {
            buf[len - 1] = '\0';
            len--;
        }
        if (len > 0) {
            snprintf(out, out_sz, "%s", buf);
            return;
        }
    }
    snprintf(out, out_sz, "%s", def_val);
}

int securecomm_setup_wizard_run(const char *config_path, bool non_interactive) {
    printf("\n╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║                SECURECOMM SYSTEM SETUP WIZARD                 ║\n");
    printf("║   Lightweight, Adaptive, Cross-Platform Secure Communication  ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n\n");

    /* ─── Step 1: Detect Device Environment ───────────────────────── */
    printf("[1/8] Detecting Device Hardware & Cryptographic Capabilities...\n");
    securecomm_device_profile_t dev;
    securecomm_device_profile_collect(&dev);
    securecomm_device_profile_print(&dev, stdout);

    securecomm_config_t cfg;
    securecomm_config_init_defaults(&cfg);

    char ans[256];

    /* ─── Step 2: Role Selection ─────────────────────────────────── */
    printf("\n[2/8] Select Device Role:\n");
    printf("  1) Server (Listen for incoming authenticated sessions)\n");
    printf("  2) Client (Initiate authenticated connections to remote server)\n");
    read_input("Select role (1 or 2)", "1", ans, sizeof(ans), non_interactive);
    if (ans[0] == '2' || strcasecmp(ans, "client") == 0) {
        cfg.role = SECURECOMM_ROLE_CLIENT;
    } else {
        cfg.role = SECURECOMM_ROLE_SERVER;
    }

    /* ─── Step 3: Cryptographic Mode ──────────────────────────────── */
    printf("\n[3/8] Select Cryptographic Mode:\n");
    printf("  1) Classical  (X25519 + Ed25519 + AES-128-CCM)\n");
    printf("  2) Pure PQC   (ML-KEM-768 + ML-DSA-65 + ChaCha20-Poly1305)\n");
    printf("  3) Hybrid     (Dual Classical + Post-Quantum Combiner)\n");
    printf("  4) Adaptive   (Deterministic Capability & Policy Engine)\n");
    read_input("Select mode (1-4)", "4", ans, sizeof(ans), non_interactive);
    if (ans[0] == '1' || strcasecmp(ans, "classical") == 0) {
        cfg.mode = SECURECOMM_MODE_CLASSICAL;
    } else if (ans[0] == '2' || strcasecmp(ans, "pqc") == 0) {
        cfg.mode = SECURECOMM_MODE_PQC;
    } else if (ans[0] == '3' || strcasecmp(ans, "hybrid") == 0) {
        cfg.mode = SECURECOMM_MODE_HYBRID;
    } else {
        cfg.mode = SECURECOMM_MODE_ADAPTIVE;
    }

    /* Adjust default port based on mode */
    if (cfg.mode == SECURECOMM_MODE_CLASSICAL || cfg.mode == SECURECOMM_MODE_PQC) {
        cfg.port = SECURECOMM_DEFAULT_PORT_CLASSICAL;
    } else if (cfg.mode == SECURECOMM_MODE_HYBRID) {
        cfg.port = SECURECOMM_DEFAULT_PORT_HYBRID;
    } else {
        cfg.port = SECURECOMM_DEFAULT_PORT_ADAPTIVE;
    }

    /* ─── Step 4: Network Configuration ──────────────────────────── */
    printf("\n[4/8] Network Configuration:\n");
    char port_str[32];
    snprintf(port_str, sizeof(port_str), "%u", cfg.port);

    if (cfg.role == SECURECOMM_ROLE_SERVER) {
        read_input("Server bind address", "0.0.0.0", cfg.bind_address, sizeof(cfg.bind_address), non_interactive);
        read_input("UDP listening port", port_str, ans, sizeof(ans), non_interactive);
        cfg.port = (uint16_t)atoi(ans);
    } else {
        read_input("Remote server address or hostname", "127.0.0.1", cfg.server_host, sizeof(cfg.server_host), non_interactive);
        read_input("Remote server UDP port", port_str, ans, sizeof(ans), non_interactive);
        cfg.port = (uint16_t)atoi(ans);
    }

    /* ─── Step 5: Device Identity & Trust ────────────────────────── */
    printf("\n[5/8] Device Identity & Trust Provisioning:\n");
    char def_dev_id[64] = "node-1";
    char hostname[64];
    if (gethostname(hostname, sizeof(hostname)) == 0 && strlen(hostname) > 0) {
        snprintf(def_dev_id, sizeof(def_dev_id), "%s", hostname);
    }
    read_input("Device Identifier", def_dev_id, cfg.device_id, sizeof(cfg.device_id), non_interactive);

    char base_dir[SECURECOMM_MAX_PATH_LEN] = "/etc/securecomm";
    if (access("/etc", W_OK) != 0) {
        snprintf(base_dir, sizeof(base_dir), "./config");
    }
    snprintf(cfg.private_key_path, sizeof(cfg.private_key_path), "%s/%s.key", base_dir, cfg.device_id);
    snprintf(cfg.public_key_path, sizeof(cfg.public_key_path), "%s/%s.pub", base_dir, cfg.device_id);
    snprintf(cfg.trust_store_path, sizeof(cfg.trust_store_path), "%s/trust_store.txt", base_dir);

    read_input("Private key storage path", cfg.private_key_path, ans, sizeof(ans), non_interactive);
    snprintf(cfg.private_key_path, sizeof(cfg.private_key_path), "%s", ans);

    read_input("Public key storage path", cfg.public_key_path, ans, sizeof(ans), non_interactive);
    snprintf(cfg.public_key_path, sizeof(cfg.public_key_path), "%s", ans);

    read_input("Trust store path", cfg.trust_store_path, ans, sizeof(ans), non_interactive);
    snprintf(cfg.trust_store_path, sizeof(cfg.trust_store_path), "%s", ans);

    if (cfg.role == SECURECOMM_ROLE_CLIENT) {
        read_input("Expected Server Identity (Optional)", "", cfg.expected_server_id, sizeof(cfg.expected_server_id), non_interactive);
    }

    /* ─── Step 6: Security Policy & Trust on First Use ───────────── */
    printf("\n[6/8] Security Policy Configuration:\n");
    read_input("Enable Trust On First Use (TOFU) for unpinned peers? (y/n)", "y", ans, sizeof(ans), non_interactive);
    cfg.allow_tofu = (ans[0] == 'y' || ans[0] == 'Y');

    if (cfg.mode == SECURECOMM_MODE_ADAPTIVE) {
        printf("Adaptive Policy Objectives:\n");
        printf("  1) Lowest Latency (default)\n");
        printf("  2) Lowest Memory Footprint\n");
        printf("  3) Highest Concurrency Capacity\n");
        read_input("Select objective (1-3)", "1", ans, sizeof(ans), non_interactive);
        if (ans[0] == '2') {
            cfg.policy.pref = SECURECOMM_PREF_LOW_MEMORY;
        } else if (ans[0] == '3') {
            cfg.policy.pref = SECURECOMM_PREF_HIGH_THROUGHPUT;
        } else {
            cfg.policy.pref = SECURECOMM_PREF_LOW_LATENCY;
        }
    }

    /* ─── Step 7: Configuration Review ───────────────────────────── */
    printf("\n[7/8] Proposed Configuration Review:\n");
    printf("─────────────────────────────────────────────────────────────────\n");
    printf(" Device Role        : %s\n", securecomm_role_to_string(cfg.role));
    printf(" Operating Mode     : %s\n", securecomm_mode_to_string(cfg.mode));
    if (cfg.role == SECURECOMM_ROLE_SERVER) {
        printf(" Listening Endpoint : %s:%u (UDP)\n", cfg.bind_address, cfg.port);
    } else {
        printf(" Target Server      : %s:%u (UDP)\n", cfg.server_host, cfg.port);
    }
    printf(" Device ID          : %s\n", cfg.device_id);
    printf(" Private Key        : %s (Permissions: 0600)\n", cfg.private_key_path);
    printf(" Public Key         : %s\n", cfg.public_key_path);
    printf(" Trust Store        : %s\n", cfg.trust_store_path);
    printf(" Trust On First Use : %s\n", cfg.allow_tofu ? "Enabled" : "Disabled");
    printf(" Target Config File : %s\n", config_path);
    printf("─────────────────────────────────────────────────────────────────\n");

    read_input("Save configuration and provision identity? (y/n)", "y", ans, sizeof(ans), non_interactive);
    if (ans[0] != 'y' && ans[0] != 'Y') {
        printf("Setup aborted by user.\n");
        return SECURECOMM_SUCCESS;
    }

    /* ─── Step 8: Save & Provision ───────────────────────────────── */
    printf("\n[8/8] Provisioning Identity & Saving Configuration...\n");

    /* Provision identity if key files do not exist */
    securecomm_identity_t ident;
    securecomm_identity_init(&ident, cfg.device_id, cfg.mode, base_dir);
    snprintf(ident.private_key_path, sizeof(ident.private_key_path), "%s", cfg.private_key_path);
    snprintf(ident.public_key_path, sizeof(ident.public_key_path), "%s", cfg.public_key_path);
    snprintf(ident.trust_store_path, sizeof(ident.trust_store_path), "%s", cfg.trust_store_path);

    if (!securecomm_identity_exists(&ident)) {
        printf("Generating cryptographic identity keypair for mode %s...\n",
               securecomm_mode_to_string(cfg.mode));
        int g_rc = securecomm_identity_generate(&ident);
        if (g_rc != SECURECOMM_SUCCESS) {
            printf("Error generating device identity: %s\n", securecomm_strerror(g_rc));
            return g_rc;
        }
        printf(" Identity keypair created successfully.\n");
        printf(" Public Key Fingerprint: %s\n", ident.fingerprint);
    } else {
        printf(" Found existing identity keypair at %s\n", ident.private_key_path);
        securecomm_identity_load(&ident);
        printf(" Public Key Fingerprint: %s\n", ident.fingerprint);
    }

    /* Atomic configuration save */
    int s_rc = securecomm_config_save_atomic(&cfg, config_path);
    if (s_rc != SECURECOMM_SUCCESS) {
        printf("Error saving configuration to '%s': %s\n", config_path, securecomm_strerror(s_rc));
        return s_rc;
    }

    /* Validate configuration */
    int v_rc = securecomm_config_validate(&cfg);
    if (v_rc != SECURECOMM_SUCCESS) {
        printf("Configuration validation failed: %s\n", securecomm_strerror(v_rc));
        return v_rc;
    }

    printf("\n Configuration successfully saved to: %s\n", config_path);
    printf(" You can now run:\n");
    if (cfg.role == SECURECOMM_ROLE_SERVER) {
        printf("   securecomm server start --config %s\n", config_path);
    } else {
        printf("   securecomm client connect --config %s\n", config_path);
    }
    printf("═════════════════════════════════════════════════════════════════\n");
    return SECURECOMM_SUCCESS;
}
