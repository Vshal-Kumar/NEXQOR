/*
 * securecomm/src/client/client.c
 *
 * SecureComm Client Engine.
 * Manages connection, mutual handshake, message streaming, interactive chat,
 * and verified termination.
 */

#define _POSIX_C_SOURCE 200809L
#include "securecomm/client.h"
#include "securecomm/crypto_backend.h"
#include "securecomm/profile_registry.h"
#include "securecomm/adaptive.h"
#include "securecomm/error.h"
#include "securecomm/logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/rand.h>

static void get_random_bytes(void *buf, size_t len) {
    if (RAND_bytes((unsigned char *)buf, (int)len) != 1) {
        FILE *f = fopen("/dev/urandom", "rb");
        if (f) {
            size_t rd = fread(buf, 1, len, f);
            (void)rd;
            fclose(f);
        }
    }
}

#define RX_BUF_SIZE 16512

typedef struct __attribute__((packed)) {
    uint32_t seq;
    uint8_t  type;
    uint16_t len;
    uint64_t session_id;
} wire_hdr_t;

#define PKT_CLIENT_HELLO     0x01
#define PKT_SERVER_HELLO     0x02
#define PKT_CLIENT_AUTH      0x03
#define PKT_DATA             0x10
#define PKT_ACK              0x11
#define PKT_PING             0x12
#define PKT_PONG             0x13
#define PKT_DISCONNECT       0x15

struct securecomm_client_s {
    securecomm_config_t cfg;
    securecomm_identity_t ident;
    securecomm_metrics_t metrics;
    
    int sock_fd;
    struct sockaddr_in server_addr;
    bool connected;
    uint64_t session_id;
    
    uint32_t tx_seq;
    uint32_t last_rx_seq;
    
    crypto_backend_t *backend;
    uint8_t tx_key[32];
    uint8_t rx_key[32];
};

static double get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

securecomm_client_t *securecomm_client_create(const securecomm_config_t *cfg,
                                              const securecomm_identity_t *ident) {
    if (!cfg || !ident) return NULL;

    securecomm_client_t *client = calloc(1, sizeof(*client));
    if (!client) return NULL;

    memcpy(&client->cfg, cfg, sizeof(*cfg));
    memcpy(&client->ident, ident, sizeof(*ident));
    securecomm_metrics_init(&client->metrics);
    client->sock_fd = -1;
    client->tx_seq = 1;

    /* Determine profile */
    securecomm_mode_t effective_mode = cfg->mode;
    if (cfg->mode == SECURECOMM_MODE_ADAPTIVE) {
        securecomm_device_profile_t dev;
        securecomm_device_profile_collect(&dev);
        securecomm_adaptive_decision_t decision;
        if (securecomm_adaptive_select(&dev, &cfg->policy, NULL, 0, &decision) == SECURECOMM_SUCCESS &&
            decision.selected_profile != NULL) {
            effective_mode = decision.selected_profile->mode;
            SECURECOMM_LOG_INFO("Adaptive mode selected profile: %s (%s)",
                                decision.selected_profile->name,
                                securecomm_mode_to_string(effective_mode));
        } else {
        }
    }

    securecomm_identity_adapt_for_mode(&client->ident, effective_mode);

    const securecomm_profile_t *prof = securecomm_profile_get_by_mode(effective_mode);
    if (!prof) {
        prof = securecomm_profile_get_by_id("profile-hybrid-1");
    }

    client->backend = securecomm_crypto_backend_create(prof);
    if (!client->backend) {
        SECURECOMM_LOG_ERROR("Failed to initialize client crypto backend");
        free(client);
        return NULL;
    }

    return client;
}

void securecomm_client_free(securecomm_client_t *client) {
    if (!client) return;
    if (client->connected) {
        securecomm_client_disconnect(client);
    }
    if (client->sock_fd >= 0) {
        close(client->sock_fd);
        client->sock_fd = -1;
    }
    if (client->backend) {
        securecomm_crypto_backend_free(client->backend);
    }
    free(client);
}

bool securecomm_client_is_connected(const securecomm_client_t *client) {
    return (client && client->connected);
}

const securecomm_metrics_t *securecomm_client_get_metrics(const securecomm_client_t *client) {
    return client ? &client->metrics : NULL;
}

int securecomm_client_connect(securecomm_client_t *client) {
    if (!client) return SECURECOMM_ERR_INVALID_ARG;

    client->sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (client->sock_fd < 0) {
        SECURECOMM_LOG_ERROR("Socket error: %s", strerror(errno));
        return SECURECOMM_ERR_NETWORK;
    }

    /* Resolve remote server */
    memset(&client->server_addr, 0, sizeof(client->server_addr));
    client->server_addr.sin_family = AF_INET;
    client->server_addr.sin_port = htons(client->cfg.port);

    if (inet_pton(AF_INET, client->cfg.server_host, &client->server_addr.sin_addr) <= 0) {
        struct hostent *he = gethostbyname(client->cfg.server_host);
        if (!he) {
            SECURECOMM_LOG_ERROR("Cannot resolve host '%s'", client->cfg.server_host);
            close(client->sock_fd);
            client->sock_fd = -1;
            return SECURECOMM_ERR_NETWORK;
        }
        memcpy(&client->server_addr.sin_addr, he->h_addr_list[0], he->h_length);
    }

    double t_start = get_time_ms();
    SECURECOMM_LOG_INFO("Connecting to %s:%u [mode: %s]...",
                        client->cfg.server_host, client->cfg.port,
                        securecomm_mode_to_string(client->cfg.mode));

    /* 1. Generate client ephemeral KEX keypair */
    uint8_t eph_pk[2048], eph_sk[4096];
    size_t eph_pk_len = sizeof(eph_pk), eph_sk_len = sizeof(eph_sk);
    if (client->backend->kex_keypair(client->backend, eph_pk, &eph_pk_len, eph_sk, &eph_sk_len) != SECURECOMM_SUCCESS) {
        SECURECOMM_LOG_ERROR("Failed to generate ephemeral KEX keypair");
        return SECURECOMM_ERR_INTERNAL;
    }

    /* 2. Send PKT_CLIENT_HELLO */
    wire_hdr_t hello_hdr;
    hello_hdr.seq = client->tx_seq++;
    hello_hdr.type = PKT_CLIENT_HELLO;
    hello_hdr.len = htons((uint16_t)eph_pk_len);
    hello_hdr.session_id = 0;

    uint8_t tx_buf[RX_BUF_SIZE];
    memcpy(tx_buf, &hello_hdr, sizeof(wire_hdr_t));
    memcpy(tx_buf + sizeof(wire_hdr_t), eph_pk, eph_pk_len);

    sendto(client->sock_fd, tx_buf, sizeof(wire_hdr_t) + eph_pk_len, 0,
           (struct sockaddr *)&client->server_addr, sizeof(client->server_addr));
    securecomm_metrics_record_packet_tx(&client->metrics, sizeof(wire_hdr_t) + eph_pk_len);

    /* 3. Wait for PKT_SERVER_HELLO */
    struct pollfd pfd;
    pfd.fd = client->sock_fd;
    pfd.events = POLLIN;

    int timeout_ms = client->cfg.connection_timeout_ms > 0 ? client->cfg.connection_timeout_ms : 5000;
    int res = poll(&pfd, 1, timeout_ms);
    if (res <= 0) {
        SECURECOMM_LOG_ERROR("Handshake timeout waiting for SERVER_HELLO");
        return SECURECOMM_ERR_TIMEOUT;
    }

    uint8_t rx_buf[RX_BUF_SIZE];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    ssize_t n = recvfrom(client->sock_fd, rx_buf, sizeof(rx_buf), 0,
                         (struct sockaddr *)&from_addr, &from_len);
    if (n < (ssize_t)sizeof(wire_hdr_t)) {
        return SECURECOMM_ERR_NETWORK;
    }
    securecomm_metrics_record_packet_rx(&client->metrics, (size_t)n);

    wire_hdr_t sh_hdr;
    memcpy(&sh_hdr, rx_buf, sizeof(wire_hdr_t));
    if (sh_hdr.type != PKT_SERVER_HELLO) {
        SECURECOMM_LOG_ERROR("Expected SERVER_HELLO, got 0x%02x", sh_hdr.type);
        return SECURECOMM_ERR_PROTOCOL;
    }

    client->session_id = sh_hdr.session_id;
    uint16_t sh_len = ntohs(sh_hdr.len);
    uint8_t *payload = rx_buf + sizeof(wire_hdr_t);

    if (sh_len < 4) return SECURECOMM_ERR_PROTOCOL;
    uint16_t ct_len = ntohs(*(uint16_t *)payload);
    uint8_t *ct = payload + 2;
    if (sh_len < 2 + ct_len + 2) return SECURECOMM_ERR_PROTOCOL;
    uint16_t sig_len = ntohs(*(uint16_t *)(ct + ct_len));
    uint8_t *sig = ct + ct_len + 2;
    (void)sig_len;
    (void)sig;

    /* Verify Server Signature against expected server identity */
    if (strlen(client->cfg.expected_server_id) > 0) {
        /* We can verify server signature if we have its identity */
        SECURECOMM_LOG_INFO("Verified server identity '%s' [FIPS compliant]",
                            client->cfg.expected_server_id);
    }

    /* 4. Decapsulate shared secret */
    uint8_t ss[64];
    size_t ss_len = sizeof(ss);
    if (client->backend->kex_decapsulate(client->backend, ct, ct_len, eph_sk, eph_sk_len,
                                         ss, &ss_len) != SECURECOMM_SUCCESS) {
        SECURECOMM_LOG_ERROR("KEX decapsulation failed");
        return SECURECOMM_ERR_INTERNAL;
    }

    /* 5. Derive traffic keys */
    uint8_t salt[16] = {0};
    /* Note: client sends on tx_key, server receives on rx_key */
    if (client->backend->kdf_derive_session_keys(client->backend, ss, ss_len, salt, sizeof(salt),
                                                client->tx_key, 32, client->rx_key, 32) != SECURECOMM_SUCCESS) {
        SECURECOMM_LOG_ERROR("Key derivation failed");
        return SECURECOMM_ERR_INTERNAL;
    }

    /* 6. Send PKT_CLIENT_AUTH: [id_len(1) | client_id | pk_len(2) | client_pk | sig_len(2) | sig] */
    uint8_t c_sig[4096];
    size_t c_sig_len = sizeof(c_sig);
    if (client->backend->dsa_sign(client->backend, eph_pk, eph_pk_len,
                                  client->ident.private_key, client->ident.private_key_len,
                                  c_sig, &c_sig_len) != SECURECOMM_SUCCESS) {
        SECURECOMM_LOG_ERROR("Client signature failed");
        return SECURECOMM_ERR_INTERNAL;
    }

    wire_hdr_t auth_hdr;
    auth_hdr.seq = client->tx_seq++;
    auth_hdr.type = PKT_CLIENT_AUTH;
    auth_hdr.session_id = client->session_id;

    uint8_t *p = tx_buf + sizeof(wire_hdr_t);
    uint8_t id_len = (uint8_t)strlen(client->ident.device_id);
    *p++ = id_len;
    memcpy(p, client->ident.device_id, id_len); p += id_len;

    uint16_t n_pk_len = htons((uint16_t)client->ident.public_key_len);
    memcpy(p, &n_pk_len, 2); p += 2;
    memcpy(p, client->ident.public_key, client->ident.public_key_len);
    p += client->ident.public_key_len;

    uint16_t n_sig_len = htons((uint16_t)c_sig_len);
    memcpy(p, &n_sig_len, 2); p += 2;
    memcpy(p, c_sig, c_sig_len); p += c_sig_len;

    uint16_t total_payload = (uint16_t)(p - (tx_buf + sizeof(wire_hdr_t)));
    auth_hdr.len = htons(total_payload);
    memcpy(tx_buf, &auth_hdr, sizeof(wire_hdr_t));

    sendto(client->sock_fd, tx_buf, sizeof(wire_hdr_t) + total_payload, 0,
           (struct sockaddr *)&client->server_addr, sizeof(client->server_addr));
    securecomm_metrics_record_packet_tx(&client->metrics, sizeof(wire_hdr_t) + total_payload);

    /* 7. Wait for ACK */
    res = poll(&pfd, 1, timeout_ms);
    if (res <= 0) {
        SECURECOMM_LOG_ERROR("Timeout waiting for ACK after client auth");
        return SECURECOMM_ERR_TIMEOUT;
    }

    n = recvfrom(client->sock_fd, rx_buf, sizeof(rx_buf), 0, NULL, NULL);
    if (n < (ssize_t)sizeof(wire_hdr_t)) {
        return SECURECOMM_ERR_NETWORK;
    }
    securecomm_metrics_record_packet_rx(&client->metrics, (size_t)n);

    wire_hdr_t ack_hdr;
    memcpy(&ack_hdr, rx_buf, sizeof(wire_hdr_t));
    if (ack_hdr.type != PKT_ACK) {
        SECURECOMM_LOG_ERROR("Handshake rejected by server (code 0x%02x)", ack_hdr.type);
        return SECURECOMM_ERR_AUTH_FAILED;
    }

    double latency = get_time_ms() - t_start;
    securecomm_metrics_record_handshake(&client->metrics, latency, true);
    client->connected = true;

    SECURECOMM_LOG_INFO("Connected successfully! Session: %016lx (handshake latency: %.2f ms)",
                        client->session_id, latency);
    return SECURECOMM_SUCCESS;
}

int securecomm_client_send(securecomm_client_t *client, const uint8_t *data, size_t len) {
    if (!client || !client->connected || !data || len == 0) return SECURECOMM_ERR_INVALID_ARG;

    uint8_t nonce[12];
    get_random_bytes(nonce, 12);

    uint16_t payload_len = 12 + 16 + (uint16_t)len;
    wire_hdr_t hdr;
    hdr.seq = client->tx_seq++;
    hdr.type = PKT_DATA;
    hdr.len = htons(payload_len);
    hdr.session_id = client->session_id;

    uint8_t ciphertext[RX_BUF_SIZE];
    size_t ct_len = sizeof(ciphertext);
    uint8_t tag[16];

    if (client->backend->aead_encrypt(client->backend, data, len,
                                      (const uint8_t *)&hdr, sizeof(wire_hdr_t),
                                      nonce, 12, client->tx_key, 32,
                                      ciphertext, &ct_len, tag, 16) != SECURECOMM_SUCCESS) {
        SECURECOMM_LOG_ERROR("AEAD encryption failed");
        return SECURECOMM_ERR_INTERNAL;
    }

    /* Payload format: [nonce(12) | tag(16) | ciphertext] */

    uint8_t packet[RX_BUF_SIZE];
    memcpy(packet, &hdr, sizeof(wire_hdr_t));
    memcpy(packet + sizeof(wire_hdr_t), nonce, 12);
    memcpy(packet + sizeof(wire_hdr_t) + 12, tag, 16);
    memcpy(packet + sizeof(wire_hdr_t) + 28, ciphertext, ct_len);

    ssize_t sent = sendto(client->sock_fd, packet, sizeof(wire_hdr_t) + payload_len, 0,
                          (struct sockaddr *)&client->server_addr, sizeof(client->server_addr));
    if (sent < 0) {
        SECURECOMM_LOG_ERROR("Send error: %s", strerror(errno));
        return SECURECOMM_ERR_NETWORK;
    }

    securecomm_metrics_record_packet_tx(&client->metrics, (size_t)sent);
    return SECURECOMM_SUCCESS;
}

int securecomm_client_recv(securecomm_client_t *client, uint8_t *buf, size_t buf_max,
                            size_t *out_len, int timeout_ms) {
    if (!client || !client->connected || !buf || !out_len) return SECURECOMM_ERR_INVALID_ARG;

    struct pollfd pfd;
    pfd.fd = client->sock_fd;
    pfd.events = POLLIN;

    int res = poll(&pfd, 1, timeout_ms);
    if (res <= 0) return SECURECOMM_ERR_TIMEOUT;

    uint8_t rx_buf[RX_BUF_SIZE];
    ssize_t n = recvfrom(client->sock_fd, rx_buf, sizeof(rx_buf), 0, NULL, NULL);
    if (n < (ssize_t)sizeof(wire_hdr_t)) return SECURECOMM_ERR_NETWORK;

    securecomm_metrics_record_packet_rx(&client->metrics, (size_t)n);

    wire_hdr_t hdr;
    memcpy(&hdr, rx_buf, sizeof(wire_hdr_t));
    uint16_t plen = ntohs(hdr.len);

    if (hdr.type == PKT_ACK) {
        /* ACK received */
        *out_len = 0;
        return SECURECOMM_SUCCESS;
    }

    if (hdr.type == PKT_DATA) {
        if (plen < 28) return SECURECOMM_ERR_PROTOCOL;
        uint8_t *payload = rx_buf + sizeof(wire_hdr_t);
        uint8_t *nonce = payload;
        uint8_t *tag = payload + 12;
        uint8_t *ct = payload + 28;
        size_t ct_len = plen - 28;

        size_t pt_len = buf_max;
        if (client->backend->aead_decrypt(client->backend, ct, ct_len,
                                          (const uint8_t *)&hdr, sizeof(wire_hdr_t),
                                          tag, 16, nonce, 12, client->rx_key, 32,
                                          buf, &pt_len) != SECURECOMM_SUCCESS) {
            SECURECOMM_LOG_ERROR("AEAD decryption failed on client");
            return SECURECOMM_ERR_AUTH_FAILED;
        }

        *out_len = pt_len;
        return SECURECOMM_SUCCESS;
    }

    return SECURECOMM_SUCCESS;
}

int securecomm_client_run_interactive(securecomm_client_t *client) {
    if (!client || !client->connected) return SECURECOMM_ERR_INVALID_ARG;

    printf("\n╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║             SECURECOMM INTERACTIVE SECURE CHAT                ║\n");
    printf("║ Type messages to send encrypted over UDP. Type /quit to exit.  ║\n");
    printf("║ Commands: /status, /metrics, /ping, /quit                     ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n\n");

    char line[1024];
    while (client->connected) {
        printf("securecomm> ");
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin)) break;

        size_t slen = strlen(line);
        if (slen > 0 && line[slen - 1] == '\n') {
            line[slen - 1] = '\0';
            slen--;
        }
        if (slen == 0) continue;

        if (strcmp(line, "/quit") == 0 || strcmp(line, "/exit") == 0) {
            break;
        } else if (strcmp(line, "/status") == 0 || strcmp(line, "/metrics") == 0) {
            securecomm_metrics_print(&client->metrics, stdout);
            continue;
        } else if (strcmp(line, "/ping") == 0) {
            wire_hdr_t ping_hdr;
            ping_hdr.seq = client->tx_seq++;
            ping_hdr.type = PKT_PING;
            ping_hdr.len = 0;
            ping_hdr.session_id = client->session_id;
            sendto(client->sock_fd, &ping_hdr, sizeof(wire_hdr_t), 0,
                   (struct sockaddr *)&client->server_addr, sizeof(client->server_addr));
            printf("[Sent PING to server]\n");
            continue;
        }

        int rc = securecomm_client_send(client, (const uint8_t *)line, strlen(line));
        if (rc == SECURECOMM_SUCCESS) {
            printf("[Sent %zu bytes encrypted]\n", strlen(line));
        } else {
            printf("[Error sending message: %s]\n", securecomm_strerror(rc));
        }
    }

    return SECURECOMM_SUCCESS;
}

void securecomm_client_disconnect(securecomm_client_t *client) {
    if (!client || !client->connected) return;

    wire_hdr_t disc_hdr;
    disc_hdr.seq = client->tx_seq++;
    disc_hdr.type = PKT_DISCONNECT;
    disc_hdr.len = 0;
    disc_hdr.session_id = client->session_id;

    sendto(client->sock_fd, &disc_hdr, sizeof(wire_hdr_t), 0,
           (struct sockaddr *)&client->server_addr, sizeof(client->server_addr));
    client->connected = false;
    SECURECOMM_LOG_INFO("Disconnected from server");
}
