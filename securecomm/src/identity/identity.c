/*
 * securecomm/src/identity/identity.c
 *
 * Device identity provisioning, keypair storage, fingerprinting, and trust verification.
 * Strict 0600 permissions enforcement on private keys.
 */

#define _POSIX_C_SOURCE 200809L
#include "securecomm/identity.h"
#include "securecomm/error.h"
#include "securecomm/logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <openssl/evp.h>
#include <oqs/oqs.h>

static int ensure_dir_exists(const char *path) {
    char temp[SECURECOMM_MAX_PATH_LEN];
    snprintf(temp, sizeof(temp), "%s", path);
    char *p = strrchr(temp, '/');
    if (!p) return 0;
    if (p == temp) return 0; /* root '/' */
    *p = '\0';

    struct stat st;
    if (stat(temp, &st) == 0) {
        if (S_ISDIR(st.st_mode)) return 0;
        return -1;
    }

    /* Recursive directory creation if needed */
    char sub[SECURECOMM_MAX_PATH_LEN];
    snprintf(sub, sizeof(sub), "%s", temp);
    for (char *s = sub + 1; *s; s++) {
        if (*s == '/') {
            *s = '\0';
            mkdir(sub, 0755);
            *s = '/';
        }
    }
    return mkdir(sub, 0755) == 0 ? 0 : (errno == EEXIST ? 0 : -1);
}

static void fallback_to_user_paths(securecomm_identity_t *ident) {
    const char *home = getenv("HOME");
    char user_dir[SECURECOMM_MAX_PATH_LEN];
    if (home && strlen(home) > 0) {
        snprintf(user_dir, sizeof(user_dir), "%s/.config/securecomm", home);
    } else {
        snprintf(user_dir, sizeof(user_dir), "/tmp/securecomm-%u", (unsigned int)getuid());
    }
    ensure_dir_exists(user_dir);
    snprintf(ident->private_key_path, sizeof(ident->private_key_path), "%s/%s.key", user_dir, ident->device_id);
    snprintf(ident->public_key_path, sizeof(ident->public_key_path), "%s/%s.pub", user_dir, ident->device_id);
    snprintf(ident->trust_store_path, sizeof(ident->trust_store_path), "%s/trust_store.txt", user_dir);
}

int securecomm_identity_compute_fingerprint(const uint8_t *pk, size_t pk_len, char out_hex[65]) {
    if (!pk || pk_len == 0 || !out_hex) {
        return SECURECOMM_ERR_INVALID_ARG;
    }

    unsigned char hash[32];
    unsigned int hash_len = 0;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return SECURECOMM_ERR_INTERNAL;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, pk, pk_len) != 1 ||
        EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return SECURECOMM_ERR_INTERNAL;
    }
    EVP_MD_CTX_free(ctx);

    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(out_hex + (i * 2), "%02x", hash[i]);
    }
    out_hex[64] = '\0';
    return SECURECOMM_SUCCESS;
}

int securecomm_identity_init(securecomm_identity_t *ident, const char *device_id,
                              securecomm_mode_t mode, const char *base_dir) {
    if (!ident || !device_id || !base_dir) return SECURECOMM_ERR_INVALID_ARG;

    memset(ident, 0, sizeof(*ident));
    snprintf(ident->device_id, sizeof(ident->device_id), "%s", device_id);
    ident->mode = mode;

    char resolved_dir[SECURECOMM_MAX_PATH_LEN];
    snprintf(resolved_dir, sizeof(resolved_dir), "%s", base_dir);

    /* If base_dir is /etc/securecomm and not writable by current user, use user config */
    if (strcmp(base_dir, "/etc/securecomm") == 0 && access("/etc/securecomm", W_OK) != 0 && getuid() != 0) {
        const char *home = getenv("HOME");
        if (home && strlen(home) > 0) {
            snprintf(resolved_dir, sizeof(resolved_dir), "%s/.config/securecomm", home);
        } else {
            snprintf(resolved_dir, sizeof(resolved_dir), "/tmp/securecomm-%u", (unsigned int)getuid());
        }
    }

    snprintf(ident->private_key_path, sizeof(ident->private_key_path),
             "%s/%s.key", resolved_dir, device_id);
    snprintf(ident->public_key_path, sizeof(ident->public_key_path),
             "%s/%s.pub", resolved_dir, device_id);
    snprintf(ident->trust_store_path, sizeof(ident->trust_store_path),
             "%s/trust_store.txt", resolved_dir);

    ident->is_provisioned = securecomm_identity_exists(ident);
    return SECURECOMM_SUCCESS;
}

bool securecomm_identity_exists(const securecomm_identity_t *ident) {
    if (!ident) return false;
    if (access(ident->private_key_path, F_OK) == 0 &&
        access(ident->public_key_path, F_OK) == 0) {
        return true;
    }
    const char *home = getenv("HOME");
    if (home && strlen(home) > 0) {
        char user_sk[SECURECOMM_MAX_PATH_LEN], user_pk[SECURECOMM_MAX_PATH_LEN];
        snprintf(user_sk, sizeof(user_sk), "%s/.config/securecomm/%s.key", home, ident->device_id);
        snprintf(user_pk, sizeof(user_pk), "%s/.config/securecomm/%s.pub", home, ident->device_id);
        if (access(user_sk, F_OK) == 0 && access(user_pk, F_OK) == 0) {
            return true;
        }
    }
    return false;
}

int securecomm_identity_generate(securecomm_identity_t *ident) {
    if (!ident) return SECURECOMM_ERR_INVALID_ARG;

    ensure_dir_exists(ident->private_key_path);
    ensure_dir_exists(ident->public_key_path);

    uint8_t ed_pk[32], ed_sk[32];
    size_t ed_pk_len = 32, ed_sk_len = 32;
    uint8_t pqc_pk[1952], pqc_sk[4032];
    size_t pqc_pk_len = 1952, pqc_sk_len = 4032;

    bool need_classical = (ident->mode == SECURECOMM_MODE_CLASSICAL ||
                           ident->mode == SECURECOMM_MODE_HYBRID ||
                           ident->mode == SECURECOMM_MODE_ADAPTIVE);
    bool need_pqc = (ident->mode == SECURECOMM_MODE_PQC ||
                     ident->mode == SECURECOMM_MODE_HYBRID ||
                     ident->mode == SECURECOMM_MODE_ADAPTIVE);

    if (need_classical) {
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
        if (!pctx) return SECURECOMM_ERR_INTERNAL;
        if (EVP_PKEY_keygen_init(pctx) != 1) {
            EVP_PKEY_CTX_free(pctx);
            return SECURECOMM_ERR_INTERNAL;
        }
        EVP_PKEY *pkey = NULL;
        if (EVP_PKEY_keygen(pctx, &pkey) != 1 || !pkey) {
            EVP_PKEY_CTX_free(pctx);
            return SECURECOMM_ERR_INTERNAL;
        }
        if (EVP_PKEY_get_raw_public_key(pkey, ed_pk, &ed_pk_len) != 1 ||
            EVP_PKEY_get_raw_private_key(pkey, ed_sk, &ed_sk_len) != 1) {
            EVP_PKEY_free(pkey);
            EVP_PKEY_CTX_free(pctx);
            return SECURECOMM_ERR_INTERNAL;
        }
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
    }

    if (need_pqc) {
        OQS_SIG *sig = OQS_SIG_new("ML-DSA-65");
        if (!sig) return SECURECOMM_ERR_BACKEND_MISSING;
        if (OQS_SIG_keypair(sig, pqc_pk, pqc_sk) != OQS_SUCCESS) {
            OQS_SIG_free(sig);
            return SECURECOMM_ERR_INTERNAL;
        }
        pqc_pk_len = sig->length_public_key;
        pqc_sk_len = sig->length_secret_key;
        OQS_SIG_free(sig);
    }

    /* Assemble keys based on mode */
    if (ident->mode == SECURECOMM_MODE_CLASSICAL) {
        memcpy(ident->public_key, ed_pk, 32);
        ident->public_key_len = 32;
        memcpy(ident->private_key, ed_sk, 32);
        ident->private_key_len = 32;
    } else if (ident->mode == SECURECOMM_MODE_PQC) {
        memcpy(ident->public_key, pqc_pk, pqc_pk_len);
        ident->public_key_len = pqc_pk_len;
        memcpy(ident->private_key, pqc_sk, pqc_sk_len);
        ident->private_key_len = pqc_sk_len;
    } else {
        /* Hybrid / Adaptive */
        memcpy(ident->public_key, ed_pk, 32);
        memcpy(ident->public_key + 32, pqc_pk, pqc_pk_len);
        ident->public_key_len = 32 + pqc_pk_len;

        memcpy(ident->private_key, ed_sk, 32);
        memcpy(ident->private_key + 32, pqc_sk, pqc_sk_len);
        ident->private_key_len = 32 + pqc_sk_len;
    }

    /* Compute Fingerprint */
    securecomm_identity_compute_fingerprint(ident->public_key, ident->public_key_len, ident->fingerprint);

    /* Write Private Key with STRICT 0600 permissions */
    mode_t old_mask = umask(0077);
    int fd_sk = open(ident->private_key_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    umask(old_mask);
    if (fd_sk < 0) {
        /* If opening private key failed (e.g. Permission Denied), fallback to user directory */
        fallback_to_user_paths(ident);
        ensure_dir_exists(ident->private_key_path);
        ensure_dir_exists(ident->public_key_path);

        old_mask = umask(0077);
        fd_sk = open(ident->private_key_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        umask(old_mask);

        if (fd_sk < 0) {
            SECURECOMM_LOG_ERROR("Failed to write private key to '%s': %s",
                                 ident->private_key_path, strerror(errno));
            return SECURECOMM_ERR_FILE_IO;
        }
    }
    if (write(fd_sk, ident->private_key, ident->private_key_len) != (ssize_t)ident->private_key_len) {
        close(fd_sk);
        return SECURECOMM_ERR_FILE_IO;
    }
    close(fd_sk);

    /* Write Public Key with 0644 permissions */
    int fd_pk = open(ident->public_key_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd_pk < 0) {
        SECURECOMM_LOG_ERROR("Failed to write public key to '%s': %s",
                             ident->public_key_path, strerror(errno));
        return SECURECOMM_ERR_FILE_IO;
    }
    if (write(fd_pk, ident->public_key, ident->public_key_len) != (ssize_t)ident->public_key_len) {
        close(fd_pk);
        return SECURECOMM_ERR_FILE_IO;
    }
    close(fd_pk);

    ident->is_provisioned = true;
    SECURECOMM_LOG_INFO("Provisioned device identity '%s' at %s [fingerprint: %.16s...]",
                        ident->device_id, ident->private_key_path, ident->fingerprint);
    return SECURECOMM_SUCCESS;
}

int securecomm_identity_load(securecomm_identity_t *ident) {
    if (!ident) return SECURECOMM_ERR_INVALID_ARG;

    struct stat st;
    if (stat(ident->private_key_path, &st) != 0) {
        /* Check fallback user path */
        const char *home = getenv("HOME");
        if (home && strlen(home) > 0) {
            char user_sk[SECURECOMM_MAX_PATH_LEN];
            snprintf(user_sk, sizeof(user_sk), "%s/.config/securecomm/%s.key", home, ident->device_id);
            if (stat(user_sk, &st) == 0) {
                fallback_to_user_paths(ident);
            } else {
                return SECURECOMM_ERR_KEY_NOT_FOUND;
            }
        } else {
            return SECURECOMM_ERR_KEY_NOT_FOUND;
        }
    }

    /* Verify strict 0600 permissions */
    if ((st.st_mode & 0077) != 0) {
        SECURECOMM_LOG_WARN("Private key permissions '%o' too permissive, fixing to 0600",
                            (unsigned int)(st.st_mode & 0777));
        chmod(ident->private_key_path, 0600);
    }

    int fd_sk = open(ident->private_key_path, O_RDONLY);
    if (fd_sk < 0) return SECURECOMM_ERR_FILE_IO;
    ssize_t r_sk = read(fd_sk, ident->private_key, sizeof(ident->private_key));
    close(fd_sk);
    if (r_sk <= 0) return SECURECOMM_ERR_FILE_IO;
    ident->private_key_len = (size_t)r_sk;

    int fd_pk = open(ident->public_key_path, O_RDONLY);
    if (fd_pk < 0) return SECURECOMM_ERR_FILE_IO;
    ssize_t r_pk = read(fd_pk, ident->public_key, sizeof(ident->public_key));
    close(fd_pk);
    if (r_pk <= 0) return SECURECOMM_ERR_FILE_IO;
    ident->public_key_len = (size_t)r_pk;

    securecomm_identity_compute_fingerprint(ident->public_key, ident->public_key_len, ident->fingerprint);
    ident->is_provisioned = true;
    return SECURECOMM_SUCCESS;
}

int securecomm_identity_verify_peer(const securecomm_identity_t *ident,
                                    const char *peer_id,
                                    const uint8_t *peer_pk, size_t peer_pk_len,
                                    bool allow_tofu) {
    if (!ident || !peer_id || !peer_pk || peer_pk_len == 0) {
        return SECURECOMM_ERR_INVALID_ARG;
    }

    char peer_fp[65];
    if (securecomm_identity_compute_fingerprint(peer_pk, peer_pk_len, peer_fp) != 0) {
        return SECURECOMM_ERR_INTERNAL;
    }

    /* Check trust store */
    FILE *fp = fopen(ident->trust_store_path, "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            char stored_id[SECURECOMM_MAX_ID_LEN] = {0};
            char stored_fp[128] = {0};
            if (sscanf(line, "%63s %127s", stored_id, stored_fp) == 2) {
                if (strcmp(stored_id, peer_id) == 0) {
                    fclose(fp);
                    if (strcasecmp(stored_fp, peer_fp) == 0) {
                        return SECURECOMM_SUCCESS;
                    } else {
                        SECURECOMM_LOG_ERROR("Pinning mismatch for peer '%s': expected %.16s, got %.16s",
                                             peer_id, stored_fp, peer_fp);
                        return SECURECOMM_ERR_AUTH_FAILED;
                    }
                }
            }
        }
        fclose(fp);
    }

    /* If not found in store */
    if (allow_tofu) {
        ensure_dir_exists(ident->trust_store_path);
        FILE *wfp = fopen(ident->trust_store_path, "a");
        if (!wfp) {
            SECURECOMM_LOG_ERROR("Cannot open trust store for append: %s", strerror(errno));
            return SECURECOMM_ERR_FILE_IO;
        }
        fprintf(wfp, "%s %s\n", peer_id, peer_fp);
        fclose(wfp);
        SECURECOMM_LOG_INFO("Trust On First Use (TOFU): Pinned peer '%s' (FP: %.16s...)",
                            peer_id, peer_fp);
        return SECURECOMM_SUCCESS;
    }

    SECURECOMM_LOG_WARN("Peer '%s' not present in pinned trust store and TOFU disabled", peer_id);
    return SECURECOMM_ERR_AUTH_FAILED;
}

int securecomm_identity_adapt_for_mode(securecomm_identity_t *ident, securecomm_mode_t target_mode) {
    if (!ident) return SECURECOMM_ERR_INVALID_ARG;

    /* If the identity contains composite keys (Classical 32 + PQC 1952) */
    if (ident->public_key_len >= (32 + 1952)) {
        if (target_mode == SECURECOMM_MODE_CLASSICAL) {
            ident->public_key_len = 32;
            ident->private_key_len = 32;
            securecomm_identity_compute_fingerprint(ident->public_key, ident->public_key_len, ident->fingerprint);
        } else if (target_mode == SECURECOMM_MODE_PQC) {
            memmove(ident->public_key, ident->public_key + 32, 1952);
            ident->public_key_len = 1952;
            if (ident->private_key_len >= (32 + 4032)) {
                memmove(ident->private_key, ident->private_key + 32, 4032);
                ident->private_key_len = 4032;
            }
            securecomm_identity_compute_fingerprint(ident->public_key, ident->public_key_len, ident->fingerprint);
        }
    }
    return SECURECOMM_SUCCESS;
}
