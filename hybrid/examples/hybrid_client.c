/*
 * hybrid/examples/hybrid_client.c
 *
 * Standalone Hybrid Client Example:
 * Executes mutual-authentication hybrid handshake and exchanges encrypted data.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "hybrid_crypto.h"
#include "hybrid_handshake.h"
#include "hybrid_session.h"

#define DEFAULT_PORT 9888
#define DEFAULT_HOST "127.0.0.1"

int main(int argc, char **argv) {
    const char *host = DEFAULT_HOST;
    int port = DEFAULT_PORT;

    if (argc > 1) host = argv[1];
    if (argc > 2) port = atoi(argv[2]);

    printf("\n╔════════════════════════════════════════════════════════════════╗\n");
    printf("║      QRYPTONEX Hybrid Cryptographic Client (Suite v1.0)        ║\n");
    printf("║   Suite: X25519 + ML-KEM-768 + Ed25519 + ML-DSA-65 + ChaCha20  ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n\n");

    /* 1. Initialize Cryptographic Subsystem */
    printf("[client] Initializing hybrid cryptographic engines...\n");
    if (hybrid_crypto_init() != HYBRID_SUCCESS) {
        fprintf(stderr, "[client] ERROR: Crypto initialization failed\n");
        return 1;
    }

    /* 2. Generate Client Identity Keys */
    hybrid_identity_pk_t client_id_pk;
    hybrid_identity_sk_t client_id_sk;
    printf("[client] Generating client dual identity keys (Ed25519 + ML-DSA-65)...\n");
    if (hybrid_generate_identity_keys(&client_id_pk, &client_id_sk) != HYBRID_SUCCESS) {
        fprintf(stderr, "[client] ERROR: Identity key generation failed\n");
        return 1;
    }

    /* 3. Setup Socket */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("[client] socket");
        return 1;
    }

    struct sockaddr_in srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &srv_addr.sin_addr);

    /* Timeout of 5 seconds */
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    printf("[client] Connecting to hybrid server at %s:%d...\n\n", host, port);

    /* 4. Phase 1: Create and Send CLIENT_HELLO */
    hybrid_handshake_ctx_t hs;
    if (hybrid_handshake_init(&hs, HYBRID_ROLE_CLIENT, &client_id_pk, &client_id_sk) != HYBRID_SUCCESS) {
        fprintf(stderr, "[client] Handshake init failed\n");
        close(sock);
        return 1;
    }

    hybrid_msg_client_hello_t hello;
    if (hybrid_client_create_hello(&hs, &hello) != HYBRID_SUCCESS) {
        fprintf(stderr, "[client] Failed to create CLIENT_HELLO\n");
        close(sock);
        return 1;
    }

    sendto(sock, &hello, sizeof(hello), 0, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
    printf("[client] Sent CLIENT_HELLO (Version: 0x%04x, Suite: %s)\n",
           be16toh(hello.version), hello.suite_id);

    /* 5. Phase 2: Receive SERVER_HELLO */
    hybrid_msg_server_hello_t srv_hello;
    socklen_t srv_len = sizeof(srv_addr);
    ssize_t n = recvfrom(sock, &srv_hello, sizeof(srv_hello), 0, (struct sockaddr *)&srv_addr, &srv_len);
    if (n != sizeof(srv_hello)) {
        fprintf(stderr, "[client] SERVER_HELLO receive failed or timed out (%zd bytes)\n", n);
        close(sock);
        return 1;
    }
    printf("[client] Received SERVER_HELLO (Session ID: 0x%016lx)\n", be64toh(srv_hello.session_id));

    if (hybrid_client_process_server_hello(&hs, &srv_hello, NULL) != HYBRID_SUCCESS) {
        fprintf(stderr, "[client] SERVER AUTHENTICATION FAILED! MITM or invalid signature detected.\n");
        close(sock);
        return 1;
    }
    printf("[client] \033[1;32mServer Dual Signature Verified Successfully!\033[0m\n");

    /* 6. Phase 3: Create and Send CLIENT_AUTH */
    hybrid_msg_client_auth_t cl_auth;
    if (hybrid_client_create_auth(&hs, &cl_auth) != HYBRID_SUCCESS) {
        fprintf(stderr, "[client] Failed to create CLIENT_AUTH\n");
        close(sock);
        return 1;
    }

    sendto(sock, &cl_auth, sizeof(cl_auth), 0, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
    printf("[client] Sent CLIENT_AUTH. Handshake established!\n\n");

    /* 7. Establish Secure Hybrid Session */
    hybrid_session_t session;
    if (hybrid_session_init_from_handshake(&session, &hs) != HYBRID_SUCCESS) {
        fprintf(stderr, "[client] Session init failed\n");
        close(sock);
        return 1;
    }
    hybrid_handshake_cleanup(&hs);

    /* 8. Send Encrypted Application Message */
    const char *payload_text = "Mission telemetry: All post-quantum channels nominal.";
    size_t pt_len = strlen(payload_text);

    uint8_t packet[2048];
    hybrid_pkt_hdr_t *hdr = (hybrid_pkt_hdr_t *)packet;
    hdr->seq = htonl(session.tx_seq);
    hdr->type = 0x10;
    hdr->len = htons((uint16_t)pt_len);
    hdr->session_id = htobe64(session.session_id);

    size_t ct_len = 0;
    hybrid_session_encrypt(&session, (const uint8_t *)payload_text, pt_len,
                          (const uint8_t *)hdr, HYBRID_PKT_HDR_BYTES,
                          packet + HYBRID_PKT_HDR_BYTES,
                          sizeof(packet) - HYBRID_PKT_HDR_BYTES,
                          &ct_len);

    sendto(sock, packet, HYBRID_PKT_HDR_BYTES + ct_len, 0,
           (struct sockaddr *)&srv_addr, sizeof(srv_addr));
    printf("[client] Sent encrypted application payload: \"%s\"\n", payload_text);

    /* 9. Receive Encrypted Response */
    uint8_t resp_buf[2048];
    n = recvfrom(sock, resp_buf, sizeof(resp_buf), 0, (struct sockaddr *)&srv_addr, &srv_len);
    if (n > (ssize_t)HYBRID_PKT_HDR_BYTES) {
        hybrid_pkt_hdr_t *resp_hdr = (hybrid_pkt_hdr_t *)resp_buf;
        uint32_t seq = ntohl(resp_hdr->seq);
        const uint8_t *wire_payload = resp_buf + HYBRID_PKT_HDR_BYTES;
        size_t wire_len = n - HYBRID_PKT_HDR_BYTES;

        uint8_t plaintext[1024];
        size_t dec_len = 0;
        int rc = hybrid_session_decrypt(&session, seq, wire_payload, wire_len,
                                       (const uint8_t *)resp_hdr, HYBRID_PKT_HDR_BYTES,
                                       plaintext, sizeof(plaintext), &dec_len);
        if (rc == HYBRID_SUCCESS) {
            plaintext[dec_len] = '\0';
            printf("[client] Received and verified server response: \"%s\"\n", (char *)plaintext);
        } else {
            fprintf(stderr, "[client] Decryption error: %s\n", hybrid_strerror(rc));
        }
    }

    hybrid_session_close(&session);
    close(sock);
    printf("\n[client] Session cleanly closed. Exiting.\n");
    return 0;
}
