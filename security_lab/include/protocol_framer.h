/*
 * security_lab/include/protocol_framer.h
 *
 * Canonical on-wire protocol framer shared across Classical, Hybrid, and PQC suites.
 * Strict byte-order handling and bounds validation.
 */

#ifndef SECURITY_LAB_PROTOCOL_FRAMER_H
#define SECURITY_LAB_PROTOCOL_FRAMER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Standard Ports & Paths ───────────────────────────────────────── */
#define PORT_CLASSICAL           9877
#define PORT_HYBRID              9879
#define PORT_PQC                 9877
#define PROXY_PORT_DEFAULT       9880

/* ── Packet Types (Shared Canonical Framing) ─────────────────────── */
#define PKT_CLIENT_HELLO         0x01
#define PKT_SERVER_HELLO         0x02
#define PKT_CLIENT_AUTH          0x03
#define PKT_FRAG                 0x05
#define PKT_DATA                 0x10
#define PKT_ACK                  0x11
#define PKT_PING                 0x12
#define PKT_PONG                 0x13
#define PKT_BUSY                 0x14
#define PKT_DISCONNECT           0x15
#define PKT_DISCOVERY_PROBE      0x16
#define PKT_DISCOVERY_OFFER      0x17

/* ── Sizing Constants ────────────────────────────────────────────── */
#define PKT_HDR_BYTES            15
#define FRAG_HDR_BYTES           11
#define AEAD_NONCE_BYTES         12
#define AEAD_TAG_BYTES           16
#define AEAD_OVERHEAD_BYTES      (AEAD_NONCE_BYTES + AEAD_TAG_BYTES) /* 28 */
#define SESSION_ID_BYTES         8
#define MAX_WIRE_PACKET_SIZE     16512
#define MAX_PAYLOAD_CHUNK        16384

/* ── Canonical 15-Byte On-Wire Header ────────────────────────────── */
typedef struct __attribute__((packed)) {
    uint32_t seq;         /* Network Byte Order on wire (big-endian) */
    uint8_t  type;        /* PKT_* constant                          */
    uint16_t len;         /* Network Byte Order on wire (big-endian) */
    uint64_t session_id;  /* Network Byte Order on wire (big-endian) */
} pkt_wire_hdr_t;

/* ── Host-Order Header Representation ────────────────────────────── */
typedef struct {
    uint32_t seq;
    uint8_t  type;
    uint16_t len;
    uint64_t session_id;
} pkt_host_hdr_t;

/* ── Canonical 11-Byte Fragmentation Header ───────────────────────── */
typedef struct __attribute__((packed)) {
    uint16_t msg_id;      /* Message group identifier                */
    uint8_t  orig_type;   /* Original packet type before fragmentation */
    uint8_t  frag_idx;    /* 0-indexed fragment number               */
    uint8_t  frag_total;  /* Total number of fragments               */
    uint16_t frag_len;    /* Payload bytes in this fragment          */
    uint32_t total_len;   /* Total unfragmented message size         */
} frag_wire_hdr_t;

typedef struct {
    uint16_t msg_id;
    uint8_t  orig_type;
    uint8_t  frag_idx;
    uint8_t  frag_total;
    uint16_t frag_len;
    uint32_t total_len;
} frag_host_hdr_t;

/* ── Packet Serialization & Parsing ──────────────────────────────── */

/* Serializes a canonical wire header into out_buf. Returns bytes written or -1. */
int pkt_serialize_header(uint8_t *out_buf, size_t buf_size,
                         uint32_t seq, uint8_t type, uint16_t payload_len,
                         uint64_t session_id);

/* Parses a wire header into host representation with bounds verification. Returns 0 or -1. */
int pkt_parse_header(const uint8_t *in_buf, size_t in_len, pkt_host_hdr_t *out_hdr);

/* Serializes a fragmentation header into out_buf. Returns bytes written or -1. */
int pkt_serialize_frag_header(uint8_t *out_buf, size_t buf_size,
                              const frag_host_hdr_t *hdr);

/* Parses a fragmentation header. Returns 0 or -1. */
int pkt_parse_frag_header(const uint8_t *in_buf, size_t in_len, frag_host_hdr_t *out_hdr);

/* Encodes a complete raw packet: [15B Header | Payload]. Returns total packet size or -1. */
int pkt_build_frame(uint8_t *out_buf, size_t buf_size,
                    uint32_t seq, uint8_t type, uint64_t session_id,
                    const uint8_t *payload, uint16_t payload_len);

/* Encodes a PKT_DATA packet: [15B Header | 12B Nonce | 16B Tag | Ciphertext]. Returns total size or -1. */
int pkt_build_data_frame(uint8_t *out_buf, size_t buf_size,
                         uint32_t seq, uint64_t session_id,
                         const uint8_t *nonce, const uint8_t *tag,
                         const uint8_t *ciphertext, uint16_t ct_len);

/* Inspects a raw packet buffer and returns human-readable type name. */
const char *pkt_type_name(uint8_t type);

#ifdef __cplusplus
}
#endif

#endif /* SECURITY_LAB_PROTOCOL_FRAMER_H */
