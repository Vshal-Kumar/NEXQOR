/*
 * security_lab/include/suite_adapter.h
 *
 * Suite adapters for Classical, Hybrid, and Pure Post-Quantum Cryptography implementations.
 * Manages endpoints, verified listening ports, client invocation, IPC events, and health.
 */

#ifndef SECURITY_LAB_SUITE_ADAPTER_H
#define SECURITY_LAB_SUITE_ADAPTER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SUITE_TYPE_CLASSICAL = 0,
    SUITE_TYPE_HYBRID    = 1,
    SUITE_TYPE_PQC       = 2,
    SUITE_TYPE_UNKNOWN   = -1
} suite_type_t;

typedef struct {
    uint16_t client_id;
    char     ip_str[16];
    uint16_t port;
    uint64_t session_id;
    char     plaintext[512];
    uint32_t plaintext_len;
    float    decrypt_us;
    uint32_t pkt_seq;
} ipc_rx_event_t;

typedef struct suite_adapter_s {
    suite_type_t suite_type;
    char         name[64];
    char         description[128];
    char         crypto_stack[128];

    char         target_ip[64];
    uint16_t     target_port;
    struct sockaddr_in target_addr;

    int          udp_sock;
    int          ipc_rx_fd;
    int          ipc_tx_fd;

    char         server_dir[256];
    char         server_bin[256];
    char         client_bin[256];
    char         ipc_rx_path[128];
    char         ipc_tx_path[128];

    pid_t        server_pid;
    bool         server_started_by_adapter;
} suite_adapter_t;

/* Creates and initializes an adapter for the selected suite */
int suite_adapter_init(suite_adapter_t *adapter, suite_type_t suite,
                       const char *target_ip, uint16_t override_port);

/* Closes sockets and cleans up resources */
void suite_adapter_cleanup(suite_adapter_t *adapter);

/* Launches the suite's actual server process if not already listening */
int suite_adapter_start_server(suite_adapter_t *adapter);

/* Terminates server process if started by adapter */
void suite_adapter_stop_server(suite_adapter_t *adapter);

/* Checks if server is alive via PID check and active UDP response */
bool suite_adapter_is_server_alive(suite_adapter_t *adapter);

/* Probes server health via UDP (PKT_PING / PKT_DISCOVERY_PROBE). Returns RTT in microseconds or -1 */
int suite_adapter_probe_health(suite_adapter_t *adapter, double *out_rtt_us);

/* Sends raw UDP packet to server */
int suite_adapter_send_udp(suite_adapter_t *adapter, const uint8_t *data, size_t len);

/* Receives UDP packet with bounded timeout */
int suite_adapter_recv_udp(suite_adapter_t *adapter, uint8_t *buf, size_t max_len,
                           int timeout_ms, struct sockaddr_in *out_peer);

/* Connects to the server's local UNIX domain IPC socket for decrypted event observation */
int suite_adapter_connect_ipc(suite_adapter_t *adapter);

/* Polls IPC socket for incoming decrypted message event. Returns 1 on event, 0 on timeout, -1 error */
int suite_adapter_poll_ipc_rx(suite_adapter_t *adapter, ipc_rx_event_t *out_ev, int timeout_ms);

/* Invokes the legitimate suite client for N messages and returns measured handshake/msg latency */
int suite_adapter_run_client_job(suite_adapter_t *adapter, int msg_count,
                                 int *out_delivered, double *out_hs_ms, double *out_msg_ms);

/* Maps suite name string ("classical", "hybrid", "pqc") to enum */
suite_type_t suite_adapter_parse_name(const char *name_str);

/* Returns suite name string */
const char *suite_adapter_name(suite_type_t suite);

#ifdef __cplusplus
}
#endif

#endif /* SECURITY_LAB_SUITE_ADAPTER_H */
