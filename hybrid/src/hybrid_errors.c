/*
 * hybrid/src/hybrid_errors.c
 *
 * Error string conversion implementation.
 */

#include "hybrid_errors.h"

const char *hybrid_strerror(int err_code) {
    switch (err_code) {
        case HYBRID_SUCCESS:
            return "Success";
        case HYBRID_ERR_INVALID_ARG:
            return "Invalid argument or null pointer";
        case HYBRID_ERR_CRYPTO_FAIL:
            return "Cryptographic operation failed";
        case HYBRID_ERR_INVALID_KEY:
            return "Invalid key material or all-zero shared secret";
        case HYBRID_ERR_SIG_VERIFY_FAIL:
            return "Signature verification failed";
        case HYBRID_ERR_AUTH_FAIL:
            return "Handshake authentication failed";
        case HYBRID_ERR_TRANSCRIPT_MISMATCH:
            return "Handshake transcript digest mismatch";
        case HYBRID_ERR_VERSION_UNSUPPORTED:
            return "Unsupported protocol version";
        case HYBRID_ERR_DOWNGRADE_DETECTED:
            return "Protocol or cipher suite downgrade detected";
        case HYBRID_ERR_REPLAY_DETECTED:
            return "Replayed packet or stale sequence number detected";
        case HYBRID_ERR_INVALID_STATE:
            return "Operation invalid for current protocol state";
        case HYBRID_ERR_AEAD_FAIL:
            return "AEAD encryption or decryption authentication failure";
        case HYBRID_ERR_BUFFER_TOO_SMALL:
            return "Output buffer capacity insufficient";
        case HYBRID_ERR_UNTRUSTED_PEER:
            return "Peer public key not recognized in trust store";
        case HYBRID_ERR_NONCE_EXHAUSTED:
            return "Sequence/nonce counter near exhaustion; key rotation required";
        default:
            return "Unknown hybrid error";
    }
}
