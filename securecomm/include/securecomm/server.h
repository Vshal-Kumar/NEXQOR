/*
 * securecomm/include/securecomm/server.h
 *
 * SecureComm High-Performance Server Engine.
 * Manages concurrent sessions, wire protocol dispatcher, and graceful shutdown.
 */

#ifndef SECURECOMM_SERVER_H
#define SECURECOMM_SERVER_H

#include "config.h"
#include "identity.h"
#include "metrics.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct securecomm_server_s securecomm_server_t;

securecomm_server_t *securecomm_server_create(const securecomm_config_t *cfg,
                                              const securecomm_identity_t *ident);
void                 securecomm_server_free(securecomm_server_t *server);

/* Start listening and enter server event loop (blocking until stop requested) */
int  securecomm_server_run(securecomm_server_t *server);

/* Request asynchronous stop */
void securecomm_server_stop(securecomm_server_t *server);

/* Inspect server state */
bool securecomm_server_is_running(const securecomm_server_t *server);
const securecomm_metrics_t *securecomm_server_get_metrics(const securecomm_server_t *server);

#ifdef __cplusplus
}
#endif

#endif /* SECURECOMM_SERVER_H */
