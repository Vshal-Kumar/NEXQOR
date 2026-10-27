/*
 * crypto/trust_store.h — Post-Quantum Peer Authentication & Public-Key Pinning
 *
 * Implements trust establishment for ML-DSA-65 digital signatures to eliminate
 * Man-In-The-Middle (MITM) and public-key substitution vulnerabilities.
 *
 * Client Role:
 *   - Pins the authoritative Server ML-DSA-65 public key (from file or embedded store).
 *   - Rejects any server whose signature key does not match the pinned reference.
 *
 * Server Role:
 *   - Maintains authorized client enrollment records.
 *   - Verifies incoming client public keys against the enrollment database.
 *   - Supports permissive enrollment mode for load testing via NEXQOR_PERMISSIVE_ENROLLMENT=1.
 */

#ifndef TRUST_STORE_H
#define TRUST_STORE_H

#include <stdint.h>
#include <stddef.h>
#include "wrappers/dsa_wrapper.h"

#define TRUST_SERVER_PUB_DEFAULT  "server_identity.pub"
#define TRUST_SERVER_SEC_DEFAULT  "server_identity.sec"
#define TRUST_CLIENT_DB_DEFAULT   "authorized_clients.db"

/*
 * trust_store_load_or_create_server_keys():
 *   Loads persistent server ML-DSA-65 identity keys from disk.
 *   If files do not exist, generates a fresh keypair and persists it.
 *   Returns 0 on success, -1 on failure.
 */
int trust_store_load_or_create_server_keys(uint8_t pk[DSA_PK_BYTES],
                                          uint8_t sk[DSA_SK_BYTES],
                                          const char *pub_path,
                                          const char *sec_path);

/*
 * trust_store_client_verify_server():
 *   Invoked by the client upon receiving PKT_SERVER_HELLO.
 *   Compares the server's wire public key against the provisioned reference key.
 *   Returns 0 if trusted, -1 if untrusted / MITM substitution detected.
 */
int trust_store_client_verify_server(const uint8_t srv_dsa_pk[DSA_PK_BYTES],
                                     const char *pinned_pub_path);

/*
 * trust_store_server_verify_client():
 *   Invoked by the server upon receiving PKT_CLIENT_HELLO.
 *   Verifies whether the client's ML-DSA-65 public key is enrolled/authorized.
 *   Returns 0 if authorized, -1 if rejected / unauthorized.
 */
int trust_store_server_verify_client(const uint8_t client_dsa_pk[DSA_PK_BYTES],
                                     const char *client_db_path);

/*
 * trust_store_enroll_client():
 *   Adds a client public key to the authorized database.
 *   Returns 0 on success, -1 on failure.
 */
int trust_store_enroll_client(const uint8_t client_dsa_pk[DSA_PK_BYTES],
                             const char *client_db_path);

#endif /* TRUST_STORE_H */
