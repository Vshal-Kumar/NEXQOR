/*
 * securecomm/tests/integration/test_client_server.c
 *
 * Real end-to-end integration tests for SecureComm client-server communication.
 * Exercises Classical, Pure PQC, Hybrid, and Adaptive modes with real cryptography and UDP transport.
 */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "securecomm/server.h"
#include "securecomm/client.h"
#include "securecomm/config.h"
#include "securecomm/identity.h"
#include "securecomm/error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <assert.h>
#include <sys/stat.h>

typedef struct {
    securecomm_server_t *server;
    int run_result;
} server_thread_ctx_t;

static void *server_thread_fn(void *arg) {
    server_thread_ctx_t *ctx = (server_thread_ctx_t *)arg;
    ctx->run_result = securecomm_server_run(ctx->server);
    return NULL;
}

static void test_mode_integration(securecomm_mode_t mode, uint16_t port, const char *label) {
    printf("\n--- Testing Integration: %s (Port %u) ---\n", label, port);
    char test_dir[128];
    snprintf(test_dir, sizeof(test_dir), "/tmp/securecomm_integ_%u", port);
    char clean_cmd[256];
    snprintf(clean_cmd, sizeof(clean_cmd), "rm -rf %s && mkdir -p %s", test_dir, test_dir);
    (void)system(clean_cmd);

    /* 1. Setup Server Configuration & Identity */
    securecomm_config_t s_cfg;
    securecomm_config_init_defaults(&s_cfg);
    s_cfg.role = SECURECOMM_ROLE_SERVER;
    s_cfg.mode = mode;
    s_cfg.port = port;
    strcpy(s_cfg.bind_address, "127.0.0.1");
    strcpy(s_cfg.device_id, "server-integ-node");
    s_cfg.allow_tofu = true;

    securecomm_identity_t s_id;
    securecomm_identity_init(&s_id, s_cfg.device_id, mode, test_dir);
    int rc = securecomm_identity_generate(&s_id);
    assert(rc == SECURECOMM_SUCCESS);

    securecomm_server_t *server = securecomm_server_create(&s_cfg, &s_id);
    assert(server != NULL);

    /* Start server in background thread */
    server_thread_ctx_t s_ctx = { .server = server, .run_result = 0 };
    pthread_t s_tid;
    pthread_create(&s_tid, NULL, server_thread_fn, &s_ctx);

    /* Allow server socket to bind */
    usleep(100000); /* 100ms */

    /* 2. Setup Client Configuration & Identity */
    securecomm_config_t c_cfg;
    securecomm_config_init_defaults(&c_cfg);
    c_cfg.role = SECURECOMM_ROLE_CLIENT;
    c_cfg.mode = mode;
    c_cfg.port = port;
    strcpy(c_cfg.server_host, "127.0.0.1");
    strcpy(c_cfg.device_id, "client-integ-node");
    c_cfg.connection_timeout_ms = 3000;

    securecomm_identity_t c_id;
    securecomm_identity_init(&c_id, c_cfg.device_id, mode, test_dir);
    rc = securecomm_identity_generate(&c_id);
    assert(rc == SECURECOMM_SUCCESS);

    securecomm_client_t *client = securecomm_client_create(&c_cfg, &c_id);
    assert(client != NULL);

    /* 3. Connect Client to Server */
    rc = securecomm_client_connect(client);
    assert(rc == SECURECOMM_SUCCESS);
    assert(securecomm_client_is_connected(client) == true);

    /* 4. Transmit Encrypted Application Messages */
    const char *test_msg1 = "Hello, SecureComm Quantum-Safe World!";
    rc = securecomm_client_send(client, (const uint8_t *)test_msg1, strlen(test_msg1));
    assert(rc == SECURECOMM_SUCCESS);

    const char *test_msg2 = "Verifying AEAD authentication and replay window tracking.";
    rc = securecomm_client_send(client, (const uint8_t *)test_msg2, strlen(test_msg2));
    assert(rc == SECURECOMM_SUCCESS);

    /* 5. Graceful Disconnect */
    securecomm_client_disconnect(client);
    securecomm_client_free(client);

    /* Stop server */
    securecomm_server_stop(server);
    pthread_join(s_tid, NULL);
    securecomm_server_free(server);

    printf(" [✓] Mode %s Integration Test PASSED!\n", label);
}

int main(void) {
    printf("=================================================================\n");
    printf("         SECURECOMM REAL CLIENT-SERVER INTEGRATION SUITE         \n");
    printf("=================================================================\n");

    test_mode_integration(SECURECOMM_MODE_CLASSICAL, 9871, "Classical (X25519/Ed25519/AES-CCM)");
    test_mode_integration(SECURECOMM_MODE_PQC,       9872, "Pure PQC (ML-KEM-768/ML-DSA-65)");
    test_mode_integration(SECURECOMM_MODE_HYBRID,    9873, "Hybrid (Combiner)");
    test_mode_integration(SECURECOMM_MODE_ADAPTIVE,  9874, "Adaptive Mode Selection");

    printf("\n=================================================================\n");
    printf("       ALL REAL INTEGRATION TESTS COMPLETED SUCCESSFULLY!        \n");
    printf("=================================================================\n");
    return 0;
}
