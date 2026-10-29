/*
 * security_lab/src/protocol_framer.c
 *
 * Implements strict canonical wire framing, serialization, and parsing
 * for Classical, Hybrid, and Pure Post-Quantum UDP packets.
 */

#include "protocol_framer.h"
#include <arpa/inet.h>
#include <endian.h>
#include <string.h>

int pkt_serialize_header(uint8_t *out_buf, size_t buf_size,
                         uint32_t seq, uint8_t type, uint16_t payload_len,
                         uint64_t session_id) {
    if (!out_buf || buf_size < PKT_HDR_BYTES) return -1;

    pkt_wire_hdr_t *hdr = (pkt_wire_hdr_t *)out_buf;
    hdr->seq = htonl(seq);
    hdr->type = type;
    hdr->len = htons(payload_len);
    hdr->session_id = htobe64(session_id);

    return PKT_HDR_BYTES;
}

int pkt_parse_header(const uint8_t *in_buf, size_t in_len, pkt_host_hdr_t *out_hdr) {
    if (!in_buf || !out_hdr || in_len < PKT_HDR_BYTES) return -1;

    const pkt_wire_hdr_t *wire = (const pkt_wire_hdr_t *)in_buf;
    out_hdr->seq = ntohl(wire->seq);
    out_hdr->type = wire->type;
    out_hdr->len = ntohs(wire->len);
    out_hdr->session_id = be64toh(wire->session_id);

    return 0;
}

int pkt_serialize_frag_header(uint8_t *out_buf, size_t buf_size,
                              const frag_host_hdr_t *hdr) {
    if (!out_buf || !hdr || buf_size < FRAG_HDR_BYTES) return -1;

    frag_wire_hdr_t *wire = (frag_wire_hdr_t *)out_buf;
    wire->msg_id = htons(hdr->msg_id);
    wire->orig_type = hdr->orig_type;
    wire->frag_idx = hdr->frag_idx;
    wire->frag_total = hdr->frag_total;
    wire->frag_len = htons(hdr->frag_len);
    wire->total_len = htonl(hdr->total_len);

    return FRAG_HDR_BYTES;
}

int pkt_parse_frag_header(const uint8_t *in_buf, size_t in_len, frag_host_hdr_t *out_hdr) {
    if (!in_buf || !out_hdr || in_len < FRAG_HDR_BYTES) return -1;

    const frag_wire_hdr_t *wire = (const frag_wire_hdr_t *)in_buf;
    out_hdr->msg_id = ntohs(wire->msg_id);
    out_hdr->orig_type = wire->orig_type;
    out_hdr->frag_idx = wire->frag_idx;
    out_hdr->frag_total = wire->frag_total;
    out_hdr->frag_len = ntohs(wire->frag_len);
    out_hdr->total_len = ntohl(wire->total_len);

    return 0;
}

int pkt_build_frame(uint8_t *out_buf, size_t buf_size,
                    uint32_t seq, uint8_t type, uint64_t session_id,
                    const uint8_t *payload, uint16_t payload_len) {
    if (!out_buf) return -1;
    size_t total_needed = (size_t)PKT_HDR_BYTES + payload_len;
    if (buf_size < total_needed) return -1;

    if (pkt_serialize_header(out_buf, buf_size, seq, type, payload_len, session_id) < 0) {
        return -1;
    }

    if (payload_len > 0 && payload) {
        memcpy(out_buf + PKT_HDR_BYTES, payload, payload_len);
    }

    return (int)total_needed;
}

int pkt_build_data_frame(uint8_t *out_buf, size_t buf_size,
                         uint32_t seq, uint64_t session_id,
                         const uint8_t *nonce, const uint8_t *tag,
                         const uint8_t *ciphertext, uint16_t ct_len) {
    if (!out_buf || !nonce || !tag) return -1;
    uint16_t payload_len = (uint16_t)(AEAD_OVERHEAD_BYTES + ct_len);
    size_t total_needed = (size_t)PKT_HDR_BYTES + payload_len;
    if (buf_size < total_needed) return -1;

    if (pkt_serialize_header(out_buf, buf_size, seq, PKT_DATA, payload_len, session_id) < 0) {
        return -1;
    }

    uint8_t *p = out_buf + PKT_HDR_BYTES;
    memcpy(p, nonce, AEAD_NONCE_BYTES);
    p += AEAD_NONCE_BYTES;
    memcpy(p, tag, AEAD_TAG_BYTES);
    p += AEAD_TAG_BYTES;
    if (ct_len > 0 && ciphertext) {
        memcpy(p, ciphertext, ct_len);
    }

    return (int)total_needed;
}

const char *pkt_type_name(uint8_t type) {
    switch (type) {
        case PKT_CLIENT_HELLO:    return "PKT_CLIENT_HELLO (0x01)";
        case PKT_SERVER_HELLO:    return "PKT_SERVER_HELLO (0x02)";
        case PKT_CLIENT_AUTH:     return "PKT_CLIENT_AUTH (0x03)";
        case PKT_FRAG:            return "PKT_FRAG (0x05)";
        case PKT_DATA:            return "PKT_DATA (0x10)";
        case PKT_ACK:             return "PKT_ACK (0x11)";
        case PKT_PING:            return "PKT_PING (0x12)";
        case PKT_PONG:            return "PKT_PONG (0x13)";
        case PKT_BUSY:            return "PKT_BUSY (0x14)";
        case PKT_DISCONNECT:      return "PKT_DISCONNECT (0x15)";
        case PKT_DISCOVERY_PROBE: return "PKT_DISCOVERY_PROBE (0x16)";
        case PKT_DISCOVERY_OFFER: return "PKT_DISCOVERY_OFFER (0x17)";
        default:                  return "PKT_UNKNOWN";
    }
}
