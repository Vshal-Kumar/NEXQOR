/*
 * securecomm/tests/unit/test_config.c
 *
 * Unit tests for SecureComm configuration parser, serializer, validator, and atomic writer.
 */

#define _POSIX_C_SOURCE 200809L
#include "securecomm/config.h"
#include "securecomm/error.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

static void test_config_defaults(void) {
    securecomm_config_t cfg;
    securecomm_config_init_defaults(&cfg);
    assert(cfg.role == SECURECOMM_ROLE_SERVER);
    assert(cfg.mode == SECURECOMM_MODE_ADAPTIVE);
    assert(cfg.port == 9877 || cfg.port == 9885);
    assert(strcmp(cfg.bind_address, "127.0.0.1") == 0 || strcmp(cfg.bind_address, "0.0.0.0") == 0);
    printf(" [✓] test_config_defaults passed\n");
}

static void test_config_validation(void) {
    securecomm_config_t cfg;
    securecomm_config_init_defaults(&cfg);

    /* Valid config */
    assert(securecomm_config_validate(&cfg) == SECURECOMM_SUCCESS);

    /* Invalid Port (0) */
    cfg.port = 0;
    assert(securecomm_config_validate(&cfg) == SECURECOMM_ERR_CONFIG_INVALID);
    cfg.port = 9885;

    /* Invalid Device ID (empty) */
    cfg.device_id[0] = '\0';
    assert(securecomm_config_validate(&cfg) == SECURECOMM_ERR_CONFIG_INVALID);
    strcpy(cfg.device_id, "test-node");

    /* Client with empty server address */
    cfg.role = SECURECOMM_ROLE_CLIENT;
    cfg.server_address[0] = '\0';
    assert(securecomm_config_validate(&cfg) == SECURECOMM_ERR_CONFIG_INVALID);

    printf(" [✓] test_config_validation passed\n");
}

static void test_config_atomic_save_and_load(void) {
    const char *test_path = "/tmp/securecomm_test_cfg.json";
    unlink(test_path);

    securecomm_config_t cfg;
    securecomm_config_init_defaults(&cfg);
    cfg.role = SECURECOMM_ROLE_CLIENT;
    cfg.mode = SECURECOMM_MODE_HYBRID;
    cfg.port = 9879;
    strcpy(cfg.server_address, "127.0.0.1");
    strcpy(cfg.server_host, "127.0.0.1");
    strcpy(cfg.device_id, "client-node-test");
    cfg.policy.pref = SECURECOMM_PREF_LOW_MEMORY;

    int rc = securecomm_config_save_atomic(&cfg, test_path);
    assert(rc == SECURECOMM_SUCCESS);

    securecomm_config_t loaded;
    rc = securecomm_config_load(&loaded, test_path);
    assert(rc == SECURECOMM_SUCCESS);
    assert(loaded.role == SECURECOMM_ROLE_CLIENT);
    assert(loaded.mode == SECURECOMM_MODE_HYBRID);
    assert(loaded.port == 9879);
    assert(strcmp(loaded.server_host, "127.0.0.1") == 0);
    assert(strcmp(loaded.device_id, "client-node-test") == 0);
    assert(loaded.policy.pref == SECURECOMM_PREF_LOW_MEMORY);

    unlink(test_path);
    printf(" [✓] test_config_atomic_save_and_load passed\n");
}

int main(void) {
    printf("Running Configuration Unit Tests...\n");
    test_config_defaults();
    test_config_validation();
    test_config_atomic_save_and_load();
    printf("All Configuration Unit Tests PASSED!\n");
    return 0;
}
