/*
 * ui/ipc_manager.h — Background IPC and Backend Server Manager
 */

#ifndef UI_IPC_MANAGER_H
#define UI_IPC_MANAGER_H

#include "ipc_common.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

/* Forward declarations */
typedef struct ipc_manager_s ipc_manager_t;

/* Callback signatures for UI notification */
typedef void (*ui_rx_msg_cb)(const char *timestamp, uint16_t client_id,
                             const char *ip_str, uint16_t port, uint64_t session_id,
                             const char *msg_text, uint32_t msg_len,
                             float decrypt_us, uint32_t pkt_seq, void *user_data);

typedef void (*ui_client_list_cb)(int count, const ipc_client_entry_t *clients, void *user_data);

typedef void (*ui_tx_metrics_cb)(uint16_t client_id, float encrypt_us, float avg_encrypt_us,
                                 uint64_t bytes_sent, uint32_t msg_count,
                                 uint32_t retransmissions, void *user_data);

typedef void (*ui_status_cb)(bool server_running, bool rx_connected, bool tx_connected,
                             pid_t server_pid, crypto_suite_t suite, void *user_data);

/* IPC Manager lifecycle */
ipc_manager_t *ipc_manager_new(crypto_suite_t default_suite);
void ipc_manager_free(ipc_manager_t *mgr);

/* Set UI callbacks */
void ipc_manager_set_callbacks(ipc_manager_t *mgr,
                               ui_rx_msg_cb on_rx_msg,
                               ui_client_list_cb on_client_list,
                               ui_tx_metrics_cb on_tx_metrics,
                               ui_status_cb on_status,
                               void *user_data);

/* Suite selection */
void ipc_manager_set_suite(ipc_manager_t *mgr, crypto_suite_t suite);
crypto_suite_t ipc_manager_get_suite(ipc_manager_t *mgr);

/* Server process control */
bool ipc_manager_start_server(ipc_manager_t *mgr, const char *workspace_root);
void ipc_manager_stop_server(ipc_manager_t *mgr);
bool ipc_manager_is_server_running(ipc_manager_t *mgr);

/* Outbound message transmission */
int ipc_manager_send_message(ipc_manager_t *mgr, uint16_t target_client_id,
                             const char *text, uint32_t len);

/* Force reconnect to existing running server */
void ipc_manager_reconnect(ipc_manager_t *mgr);

#endif /* UI_IPC_MANAGER_H */
