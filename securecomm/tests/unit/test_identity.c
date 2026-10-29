/*
 * securecomm/tests/unit/test_identity.c
 *
 * Unit tests for device identity provisioning, 0600 permissions, fingerprinting,
 * and pinned trust store verification with TOFU.
 */

#define _POSIX_C_SOURCE 200809L
#include "securecomm/identity.h"
#include "securecomm/error.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>

int main(void) {
    printf("Running Identity & Trust Unit Tests...\n");
    const char *test_dir = "/tmp/securecomm_test_ident";
    mkdir(test_dir, 0700);

    securecomm_identity_t id;
    int rc = securecomm_identity_init(&id, "test-node-alpha", SECURECOMM_MODE_CLASSICAL, test_dir);
    assert(rc == SECURECOMM_SUCCESS);

    /* Clean old files */
    unlink(id.private_key_path);
    unlink(id.public_key_path);
    unlink(id.trust_store_path);

    /* 1. Generate keypair */
    rc = securecomm_identity_generate(&id);
    assert(rc == SECURECOMM_SUCCESS);
    assert(id.is_provisioned == true);
    assert(strlen(id.fingerprint) == 64);

    /* 2. Check 0600 permissions on private key */
    struct stat st;
    assert(stat(id.private_key_path, &st) == 0);
    assert((st.st_mode & 0077) == 0); /* No group/other permissions */

    /* 3. Load identity */
    securecomm_identity_t id_loaded;
    securecomm_identity_init(&id_loaded, "test-node-alpha", SECURECOMM_MODE_CLASSICAL, test_dir);
    rc = securecomm_identity_load(&id_loaded);
    assert(rc == SECURECOMM_SUCCESS);
    assert(strcmp(id_loaded.fingerprint, id.fingerprint) == 0);
    assert(id_loaded.public_key_len == id.public_key_len);
    assert(memcmp(id_loaded.public_key, id.public_key, id.public_key_len) == 0);

    /* 4. Trust store & TOFU */
    /* First use with TOFU = true -> Should succeed and pin peer */
    uint8_t peer_pk[32] = {0xaa, 0xbb, 0xcc, 0xdd};
    rc = securecomm_identity_verify_peer(&id, "peer-beta", peer_pk, 32, true);
    assert(rc == SECURECOMM_SUCCESS);

    /* Second use with same key -> Should match pinned store */
    rc = securecomm_identity_verify_peer(&id, "peer-beta", peer_pk, 32, false);
    assert(rc == SECURECOMM_SUCCESS);

    /* Pin mismatch -> Different public key for same peer -> MUST FAIL AUTH */
    uint8_t forged_pk[32] = {0x11, 0x22, 0x33, 0x44};
    rc = securecomm_identity_verify_peer(&id, "peer-beta", forged_pk, 32, false);
    assert(rc == SECURECOMM_ERR_AUTH_FAILED);

    /* Clean up */
    unlink(id.private_key_path);
    unlink(id.public_key_path);
    unlink(id.trust_store_path);
    rmdir(test_dir);

    printf("All Identity & Trust Unit Tests PASSED!\n");
    return 0;
}
