/*
 * securecomm/include/securecomm/client.h
 *
 * SecureComm Secure Client Engine.
 * Manages connection, mutual handshake, message streaming, and verified termination.
 */

#ifndef SECURECOMM_CLIENT_H
#define SECURECOMM_CLIENT_H

#include "config.h"
#include "identity.h"
#include "metrics.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct securecomm_client_s securecomm_client_t;

securecomm_client_t *securecomm_client_create(const securecomm_config_t *cfg,
                                              const securecomm_identity_t *ident);
void                 securecomm_client_free(securecomm_client_t *client);

/* Connect to remote server and complete mutual authentication */
int  securecomm_client_connect(securecomm_client_t *client);

/* Send encrypted application message */
int  securecomm_client_send(securecomm_client_t *client, const uint8_t *data, size_t len);

/* Receive decrypted application message (with timeout in ms) */
int  securecomm_client_recv(securecomm_client_t *client, uint8_t *buf, size_t buf_max,
                            size_t *out_len, int timeout_ms);

/* Run interactive chat / messaging loop */
int  securecomm_client_run_interactive(securecomm_client_t *client);

/* Disconnect and send graceful termination frame */
void securecomm_client_disconnect(securecomm_client_t *client);

/* State query */
bool securecomm_client_is_connected(const securecomm_client_t *client);
const securecomm_metrics_t *securecomm_client_get_metrics(const securecomm_client_t *client);

#ifdef __cplusplus
}
#endif

#endif /* SECURECOMM_CLIENT_H */
