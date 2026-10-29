/*
 * ui/ipc_common.h — Common IPC definitions and protocol for QRYPTONEX GTK4 Dashboard
 *
 * Interfaces with Classical, Hybrid, and PQC servers via UNIX domain sockets:
 *   - RX socket: server -> dashboard (pushes inbound decrypted msgs & RX metrics)
 *   - TX socket: dashboard -> server (sends outbound msg commands, receives client lists & TX metrics)
 */

#ifndef UI_IPC_COMMON_H
#define UI_IPC_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>

/* ── Socket paths for each cryptographic suite ────────────────────── */
#define PQC_IPC_RX_PATH         "/tmp/pqc_rx.sock"
#define PQC_IPC_TX_PATH         "/tmp/pqc_tx.sock"

#define HYBRID_IPC_RX_PATH      "/tmp/hybrid_rx.sock"
#define HYBRID_IPC_TX_PATH      "/tmp/hybrid_tx.sock"

#define CLASSICAL_IPC_RX_PATH   "/tmp/classical_rx.sock"
#define CLASSICAL_IPC_TX_PATH   "/tmp/classical_tx.sock"

/* ── Suite Identifiers ────────────────────────────────────────────── */
typedef enum {
    SUITE_PQC = 0,
    SUITE_HYBRID = 1,
    SUITE_CLASSICAL = 2
} crypto_suite_t;

#define MAX_UI_CLIENTS 4096

/* ── Frame types ─────────────────────────────────────────────────── */
#define IPC_MSG_RX            0x01  /* Inbound message from client        */
#define IPC_MSG_TX_CMD        0x02  /* TX command -> server: send to cid  */
#define IPC_CLIENT_LIST       0x03  /* Server -> UI: connected clients    */
#define IPC_CLIENT_CONNECT    0x04  /* Server -> UI: new client joined    */
#define IPC_CLIENT_DISCONNECT 0x05  /* Server -> UI: client disconnected  */
#define IPC_METRICS_RX        0x06  /* Server -> UI: RX per-pkt metrics   */
#define IPC_METRICS_TX        0x07  /* Server -> UI: TX per-send metrics  */

/* ── Frame Header (8 bytes) ──────────────────────────────────────── */
typedef struct __attribute__((packed)) {
    uint8_t  type;      /* IPC_* frame type                              */
    uint8_t  _pad;
    uint16_t client_id; /* Relevant client (0 = broadcast)               */
    uint32_t len;       /* Payload length following header               */
} ipc_hdr_t;

#define IPC_HDR_BYTES ((int)sizeof(ipc_hdr_t))

/* ── Inbound Message (IPC_MSG_RX) ────────────────────────────────── */
typedef struct __attribute__((packed)) {
    uint16_t client_id;
    char     ip_str[16];    /* IPv4 string                               */
    uint16_t port;
    uint64_t session_id;
    uint32_t msg_len;       /* Followed by msg_len bytes of message text */
} ipc_rx_payload_t;

/* ── Outbound Command (IPC_MSG_TX_CMD) ───────────────────────────── */
typedef struct __attribute__((packed)) {
    uint16_t client_id;    /* 0 = broadcast, or target client id        */
    uint32_t msg_len;      /* Followed by msg_len bytes of message text */
} ipc_tx_cmd_t;

/* ── Client Entry in List (IPC_CLIENT_LIST) ──────────────────────── */
typedef struct __attribute__((packed)) {
    uint16_t client_id;
    char     ip_str[16];
    uint16_t port;
    uint64_t session_id;
    float    hs_total_ms;
    uint32_t msg_count;
    uint32_t bytes_sent_kb;
    uint32_t bytes_recv_kb;
} ipc_client_entry_t;

/* ── Inbound Telemetry (IPC_METRICS_RX) ──────────────────────────── */
typedef struct __attribute__((packed)) {
    uint16_t client_id;
    float    decrypt_us;
    float    interarrival_ms;
    float    jitter_ms;
    float    avg_decrypt_us;
    uint64_t bytes_recv;
    uint32_t pkt_seq;
} ipc_metrics_rx_t;

/* ── Outbound Telemetry (IPC_METRICS_TX) ─────────────────────────── */
typedef struct __attribute__((packed)) {
    uint16_t client_id;
    float    encrypt_us;
    float    avg_encrypt_us;
    uint64_t bytes_sent;
    uint32_t msg_count;
    uint32_t retransmissions;
} ipc_metrics_tx_t;

/* ── Helper: Send IPC frame ──────────────────────────────────────── */
static inline int ipc_send_frame(int fd, uint8_t type, uint16_t client_id,
                                 const void *payload, uint32_t payload_len)
{
    ipc_hdr_t hdr;
    hdr.type = type;
    hdr._pad = 0;
    hdr.client_id = client_id;
    hdr.len = payload_len;

    if (send(fd, &hdr, IPC_HDR_BYTES, MSG_NOSIGNAL) != IPC_HDR_BYTES)
        return -1;
    if (payload && payload_len > 0) {
        if (send(fd, payload, payload_len, MSG_NOSIGNAL) != (ssize_t)payload_len)
            return -1;
    }
    return 0;
}

/* ── Helper: Receive IPC frame ───────────────────────────────────── */
static inline ssize_t ipc_recv_frame(int fd, ipc_hdr_t *hdr,
                                     void *buf, size_t buf_max)
{
    ssize_t n = recv(fd, hdr, IPC_HDR_BYTES, MSG_WAITALL);
    if (n != IPC_HDR_BYTES) return -1;

    uint32_t to_read = hdr->len;
    if (to_read > buf_max) return -1;

    size_t got = 0;
    while (got < to_read) {
        ssize_t r = recv(fd, (char *)buf + got, to_read - got, 0);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return (ssize_t)got;
}

#endif /* UI_IPC_COMMON_H */
