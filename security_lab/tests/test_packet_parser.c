/*
 * security_lab/tests/test_packet_parser.c
 *
 * Unit tests for packet parsing, bounds checking, and canonical framing.
 */

#include "protocol_framer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "\033[1;31mFAIL: %s (%s:%d)\033[0m\n", msg, __FILE__, __LINE__); \
        return 1; \
    } else { \
        printf("  [PASS] %s\n", msg); \
    } \
} while(0)

int main(void) {
    printf("\n=== Running Protocol Parser Unit Tests ===\n");

    /* Test 1: Serialize and parse canonical 15-byte header */
    uint8_t buf[64];
    int wlen = pkt_serialize_header(buf, sizeof(buf), 12345, PKT_CLIENT_HELLO, 256, 0xaabbccddeeff0011ULL);
    TEST_ASSERT(wlen == PKT_HDR_BYTES, "Serialized header must be exactly 15 bytes");

    pkt_host_hdr_t parsed;
    int rc = pkt_parse_header(buf, PKT_HDR_BYTES, &parsed);
    TEST_ASSERT(rc == 0, "Header parse succeeds");
    TEST_ASSERT(parsed.seq == 12345, "Sequence number matches");
    TEST_ASSERT(parsed.type == PKT_CLIENT_HELLO, "Type matches PKT_CLIENT_HELLO");
    TEST_ASSERT(parsed.len == 256, "Length matches 256");
    TEST_ASSERT(parsed.session_id == 0xaabbccddeeff0011ULL, "Session ID matches");

    /* Test 2: Truncated header rejection */
    TEST_ASSERT(pkt_parse_header(buf, 14, &parsed) != 0, "14-byte buffer rejected (must be >= 15)");
    TEST_ASSERT(pkt_parse_header(buf, 0, &parsed) != 0, "0-byte buffer rejected");

    /* Test 3: Complete data frame building */
    uint8_t wire[512];
    uint8_t nonce[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    uint8_t tag[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    uint8_t ct[] = "CIPHERTEXT";
    int flen = pkt_build_data_frame(wire, sizeof(wire), 101, 0x5555ULL, nonce, tag, ct, 10);
    TEST_ASSERT(flen == PKT_HDR_BYTES + 12 + 16 + 10, "Data frame size matches exactly (15 + 28 + 10 = 53)");

    pkt_host_hdr_t dhdr;
    pkt_parse_header(wire, flen, &dhdr);
    TEST_ASSERT(dhdr.type == PKT_DATA, "Frame type is PKT_DATA");
    TEST_ASSERT(dhdr.len == 12 + 16 + 10, "Payload length is 38 bytes");

    /* Test 4: Fragmentation header */
    frag_host_hdr_t fhdr = { .msg_id = 42, .orig_type = PKT_CLIENT_HELLO, .frag_idx = 1, .frag_total = 3, .frag_len = 1000, .total_len = 2800 };
    uint8_t fbuf[32];
    int fw = pkt_serialize_frag_header(fbuf, sizeof(fbuf), &fhdr);
    TEST_ASSERT(fw == FRAG_HDR_BYTES, "Frag header is exactly 11 bytes");

    frag_host_hdr_t fparsed;
    TEST_ASSERT(pkt_parse_frag_header(fbuf, FRAG_HDR_BYTES, &fparsed) == 0, "Frag header parses cleanly");
    TEST_ASSERT(fparsed.msg_id == 42 && fparsed.frag_idx == 1 && fparsed.frag_total == 3, "Frag fields match");

    printf("\nAll Protocol Parser Tests Passed Successfully!\n\n");
    return 0;
}
