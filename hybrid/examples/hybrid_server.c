/*
 * hybrid/examples/hybrid_server.c
 *
 * Standalone Hybrid Server Example:
 * Executes mutual-authentication hybrid handshake and establishes ChaCha20-Poly1305 session.
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

int main(int argc, char **argv) {
    int port = DEFAULT_PORT;
    if (argc > 1) {
        port = atoi(argv[1]);
        if (port <= 0 || port > 65535) port = DEFAULT_PORT;
    }

    printf("\n╔════════════════════════════════════════════════════════════════╗\n");
    printf("║      QRYPTONEX Hybrid Cryptographic Server (Suite v1.0)        ║\n");
    printf("║   Suite: X25519 + ML-KEM-768 + Ed25519 + ML-DSA-65 + ChaCha20  ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n\n");

    /* 1. Initialize Cryptographic Subsystem */
    printf("[server] Initializing hybrid cryptographic engines...\n");
    if (hybrid_crypto_init() != HYBRID_SUCCESS) {
        fprintf(stderr, "[server] ERROR: Crypto initialization failed\n");
        return 1;
    }

    /* 2. Load or Generate Server Identity Keys */
    hybrid_identity_pk_t srv_id_pk;
    hybrid_identity_sk_t srv_id_sk;
    printf("[server] Generating server dual identity keys (Ed25519 + ML-DSA-65)...\n");
    if (hybrid_generate_identity_keys(&srv_id_pk, &srv_id_sk) != HYBRID_SUCCESS) {
        fprintf(stderr, "[server] ERROR: Identity key generation failed\n");
        return 1;
    }

    /* 3. Setup UDP Socket */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("[server] socket");
        return 1;
    }

    struct sockaddr_in srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    srv_addr.sin_port = htons(port);

    if (bind(sock, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0) {
        perror("[server] bind");
        close(sock);
        return 1;
    }

    printf("[server] Listening for incoming hybrid handshakes on UDP port %d...\n\n", port);

    struct sockaddr_in cl_addr;
    socklen_t cl_len = sizeof(cl_addr);

    /* 4. Phase 1: Receive CLIENT_HELLO */
    hybrid_msg_client_hello_t hello;
    ssize_t n = recvfrom(sock, &hello, sizeof(hello), 0, (struct sockaddr *)&cl_addr, &cl_len);
    if (n != sizeof(hello)) {
        fprintf(stderr, "[server] Invalid CLIENT_HELLO size received (%zd bytes)\n", n);
        close(sock);
        return 1;
    }
    printf("[server] Received CLIENT_HELLO from %s:%d\n",
           inet_ntoa(cl_addr.sin_addr), ntohs(cl_addr.sin_port));

    /* Initialize Handshake State */
    hybrid_handshake_ctx_t hs;
    if (hybrid_handshake_init(&hs, HYBRID_ROLE_SERVER, &srv_id_pk, &srv_id_sk) != HYBRID_SUCCESS) {
        fprintf(stderr, "[server] Handshake init failed\n");
        close(sock);
        return 1;
    }

    if (hybrid_server_process_client_hello(&hs, &hello, NULL) != HYBRID_SUCCESS) {
        fprintf(stderr, "[server] Failed to process CLIENT_HELLO\n");
        close(sock);
        return 1;
    }
    printf("[server] Validated CLIENT_HELLO (Version: 0x%04x, Suite: %s)\n",
           be16toh(hello.version), hello.suite_id);

    /* 5. Phase 2: Send SERVER_HELLO */
    hybrid_msg_server_hello_t srv_hello;
    if (hybrid_server_create_hello(&hs, &srv_hello) != HYBRID_SUCCESS) {
        fprintf(stderr, "[server] Failed to create SERVER_HELLO\n");
        close(sock);
        return 1;
    }

    sendto(sock, &srv_hello, sizeof(srv_hello), 0, (struct sockaddr *)&cl_addr, cl_len);
    printf("[server] Sent SERVER_HELLO (Session ID: 0x%016lx, Dual Signed)\n", hs.session_id);

    /* 6. Phase 3: Receive CLIENT_AUTH */
    hybrid_msg_client_auth_t cl_auth;
    n = recvfrom(sock, &cl_auth, sizeof(cl_auth), 0, (struct sockaddr *)&cl_addr, &cl_len);
    if (n != sizeof(cl_auth)) {
        fprintf(stderr, "[server] Invalid CLIENT_AUTH size received (%zd bytes)\n", n);
        close(sock);
        return 1;
    }

    if (hybrid_server_process_client_auth(&hs, &cl_auth) != HYBRID_SUCCESS) {
        fprintf(stderr, "[server] MUTUAL AUTHENTICATION FAILED! Rejecting peer.\n");
        close(sock);
        return 1;
    }
    printf("[server] \033[1;32mMUTUAL AUTHENTICATION SUCCEEDED!\033[0m Client verified.\n\n");

    /* 7. Establish Secure Hybrid Session */
    hybrid_session_t session;
    if (hybrid_session_init_from_handshake(&session, &hs) != HYBRID_SUCCESS) {
        fprintf(stderr, "[server] Session init failed\n");
        close(sock);
        return 1;
    }
    hybrid_handshake_cleanup(&hs);

    /* 8. Receive Encrypted Application Data */
    uint8_t packet[2048];
    n = recvfrom(sock, packet, sizeof(packet), 0, (struct sockaddr *)&cl_addr, &cl_len);
    if (n > (ssize_t)HYBRID_PKT_HDR_BYTES) {
        hybrid_pkt_hdr_t *hdr = (hybrid_pkt_hdr_t *)packet;
        uint32_t seq = ntohl(hdr->seq);
        const uint8_t *payload = packet + HYBRID_PKT_HDR_BYTES;
        size_t payload_len = n - HYBRID_PKT_HDR_BYTES;

        uint8_t plaintext[1024];
        size_t pt_len = 0;
        int rc = hybrid_session_decrypt(&session, seq, payload, payload_len,
                                       (const uint8_t *)hdr, HYBRID_PKT_HDR_BYTES,
                                       plaintext, sizeof(plaintext), &pt_len);
        if (rc == HYBRID_SUCCESS) {
            plaintext[pt_len] = '\0';
            printf("[server] Decrypted client payload [Seq: %u]: \"%s\"\n", seq, (char *)plaintext);

            /* Send Encrypted Response */
            const char *resp = "ACK: Hybrid secure link confirmed operational!";
            uint8_t resp_packet[2048];
            hybrid_pkt_hdr_t *resp_hdr = (hybrid_pkt_hdr_t *)resp_packet;
            resp_hdr->seq = htonl(session.tx_seq);
            resp_hdr->type = 0x10;
            resp_hdr->len = htons((uint16_t)strlen(resp));
            resp_hdr->session_id = htobe64(session.session_id);

            size_t ct_len = 0;
            hybrid_session_encrypt(&session, (const uint8_t *)resp, strlen(resp),
                                  (const uint8_t *)resp_hdr, HYBRID_PKT_HDR_BYTES,
                                  resp_packet + HYBRID_PKT_HDR_BYTES,
                                  sizeof(resp_packet) - HYBRID_PKT_HDR_BYTES,
                                  &ct_len);

            sendto(sock, resp_packet, HYBRID_PKT_HDR_BYTES + ct_len, 0,
                   (struct sockaddr *)&cl_addr, cl_len);
            printf("[server] Sent encrypted response to client.\n");
        } else {
            fprintf(stderr, "[server] Decryption error: %s\n", hybrid_strerror(rc));
        }
    }

    hybrid_session_close(&session);
    close(sock);
    printf("\n[server] Session cleanly closed. Exiting.\n");
    return 0;
}
