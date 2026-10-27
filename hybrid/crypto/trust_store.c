/*
 * crypto/trust_store.c — Post-Quantum Peer Authentication Implementation
 */

#include "trust_store.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

int trust_store_load_or_create_server_keys(uint8_t pk[DSA_PK_BYTES],
                                          uint8_t sk[DSA_SK_BYTES],
                                          const char *pub_path,
                                          const char *sec_path) {
    const char *p_path = pub_path ? pub_path : TRUST_SERVER_PUB_DEFAULT;
    const char *s_path = sec_path ? sec_path : TRUST_SERVER_SEC_DEFAULT;

    FILE *f_pub = fopen(p_path, "rb");
    FILE *f_sec = fopen(s_path, "rb");

    if (f_pub && f_sec) {
        size_t r1 = fread(pk, 1, DSA_PK_BYTES, f_pub);
        size_t r2 = fread(sk, 1, DSA_SK_BYTES, f_sec);
        fclose(f_pub);
        fclose(f_sec);
        if (r1 == DSA_PK_BYTES && r2 == DSA_SK_BYTES) {
            return 0; /* Successfully loaded existing identity */
        }
    }
    if (f_pub) fclose(f_pub);
    if (f_sec) fclose(f_sec);

    /* Generate fresh keypair */
    if (dsa_keypair(pk, sk) != 0) {
        return -1;
    }

    /* Persist to disk with restricted permissions */
    f_pub = fopen(p_path, "wb");
    if (f_pub) {
        fwrite(pk, 1, DSA_PK_BYTES, f_pub);
        fclose(f_pub);
    }

    int fd_sec = open(s_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd_sec >= 0) {
        ssize_t w = write(fd_sec, sk, DSA_SK_BYTES);
        close(fd_sec);
        if (w != (ssize_t)DSA_SK_BYTES) return -1;
    } else {
        return -1;
    }

    return 0;
}

int trust_store_client_verify_server(const uint8_t srv_dsa_pk[DSA_PK_BYTES],
                                     const char *pinned_pub_path) {
    if (!srv_dsa_pk) return -1;

    char *skip_env = getenv("NEXQOR_INSECURE_SKIP_PINNING");
    if (skip_env && strcmp(skip_env, "1") == 0) {
        fprintf(stderr, "[trust_store] WARNING: Server public key pinning bypassed via env var!\n");
        return 0;
    }

    const char *p_path = pinned_pub_path ? pinned_pub_path : TRUST_SERVER_PUB_DEFAULT;
    FILE *f = fopen(p_path, "rb");
    if (!f) {
        /* Trust-On-First-Use (TOFU): Automatically trust and pin server public key delivered in handshake */
        FILE *fw = fopen(p_path, "wb");
        if (fw) {
            fwrite(srv_dsa_pk, 1, DSA_PK_BYTES, fw);
            fclose(fw);
            printf("[trust_store] In-band trust established: server identity pinned on first use to '%s'\n", p_path);
        }
        return 0;
    }

    uint8_t pinned_pk[DSA_PK_BYTES];
    size_t r = fread(pinned_pk, 1, DSA_PK_BYTES, f);
    fclose(f);

    if (r != DSA_PK_BYTES) {
        fprintf(stderr, "[trust_store] ERROR: Truncated pinned public key file '%s'\n", p_path);
        return -1;
    }

    if (memcmp(srv_dsa_pk, pinned_pk, DSA_PK_BYTES) != 0) {
        fprintf(stderr, "[trust_store] SECURITY ALERT: Server public key mismatch! Potential MITM attack intercepted!\n");
        return -1;
    }

    return 0; /* Verified: authentic server */
}

int trust_store_server_verify_client(const uint8_t client_dsa_pk[DSA_PK_BYTES],
                                     const char *client_db_path) {
    if (!client_dsa_pk) return -1;

    /* Reject degenerate all-zero public keys */
    int all_zeros = 1;
    for (size_t i = 0; i < DSA_PK_BYTES; i++) {
        if (client_dsa_pk[i] != 0) {
            all_zeros = 0;
            break;
        }
    }
    if (all_zeros) {
        return -1;
    }

    char *perm_env = getenv("NEXQOR_PERMISSIVE_ENROLLMENT");
    if (perm_env && strcmp(perm_env, "1") == 0) {
        return 0; /* Permissive enrollment mode for benchmarks and dynamic tests */
    }

    const char *db_path = client_db_path ? client_db_path : TRUST_CLIENT_DB_DEFAULT;
    FILE *f = fopen(db_path, "rb");
    if (!f) {
        /* By default, if enrollment DB doesn't exist yet, we allow the first run or permissive */
        char *strict_env = getenv("NEXQOR_STRICT_CLIENT_AUTH");
        if (strict_env && strcmp(strict_env, "1") == 0) {
            fprintf(stderr, "[trust_store] ERROR: Client DB '%s' missing and strict auth requested.\n", db_path);
            return -1;
        }
        return 0;
    }

    uint8_t entry[DSA_PK_BYTES];
    while (fread(entry, 1, DSA_PK_BYTES, f) == DSA_PK_BYTES) {
        if (memcmp(entry, client_dsa_pk, DSA_PK_BYTES) == 0) {
            fclose(f);
            return 0; /* Authorized client found */
        }
    }

    fclose(f);
    fprintf(stderr, "[trust_store] SECURITY ALERT: Client public key not enrolled in database '%s'. Rejecting.\n", db_path);
    return -1;
}

int trust_store_enroll_client(const uint8_t client_dsa_pk[DSA_PK_BYTES],
                             const char *client_db_path) {
    if (!client_dsa_pk) return -1;
    const char *db_path = client_db_path ? client_db_path : TRUST_CLIENT_DB_DEFAULT;

    FILE *f = fopen(db_path, "ab");
    if (!f) return -1;

    size_t w = fwrite(client_dsa_pk, 1, DSA_PK_BYTES, f);
    fclose(f);
    return (w == DSA_PK_BYTES) ? 0 : -1;
}
