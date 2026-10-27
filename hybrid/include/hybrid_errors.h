/*
 * hybrid/include/hybrid_errors.h
 *
 * Error codes and diagnostic interfaces for QRYPTONEX Hybrid Suite:
 * QRYPTONEX-HYBRID-X25519-MLKEM768-ED25519-MLDSA65
 */

#ifndef HYBRID_ERRORS_H
#define HYBRID_ERRORS_H

#ifdef __cplusplus
extern "C" {
#endif

/* Return codes */
#define HYBRID_SUCCESS                       0
#define HYBRID_ERR_INVALID_ARG              -1  
#define HYBRID_ERR_CRYPTO_FAIL              -2
#define HYBRID_ERR_INVALID_KEY              -3
#define HYBRID_ERR_SIG_VERIFY_FAIL          -4
#define HYBRID_ERR_AUTH_FAIL                -5
#define HYBRID_ERR_TRANSCRIPT_MISMATCH      -6
#define HYBRID_ERR_VERSION_UNSUPPORTED      -7
#define HYBRID_ERR_DOWNGRADE_DETECTED       -8
#define HYBRID_ERR_REPLAY_DETECTED          -9
#define HYBRID_ERR_INVALID_STATE           -10
#define HYBRID_ERR_AEAD_FAIL               -11
#define HYBRID_ERR_BUFFER_TOO_SMALL        -12
#define HYBRID_ERR_UNTRUSTED_PEER          -13
#define HYBRID_ERR_NONCE_EXHAUSTED         -14

/*
 * hybrid_strerror()
 * Returns human-readable diagnostic description of error code.
 * Guaranteed never to log or leak secret values.
 */
const char *hybrid_strerror(int err_code);

#ifdef __cplusplus
}
#endif

#endif /* HYBRID_ERRORS_H */
