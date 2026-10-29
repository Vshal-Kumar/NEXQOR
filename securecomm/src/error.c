/*
 * securecomm/src/error.c
 *
 * Error string conversion for SecureComm.
 */

#include "securecomm/error.h"

const char *securecomm_strerror(securecomm_error_t err) {
    switch (err) {
        case SECURECOMM_SUCCESS:               return "Success";
        case SECURECOMM_ERR_INVALID_ARG:       return "Invalid argument";
        case SECURECOMM_ERR_NOMEM:             return "Out of memory";
        case SECURECOMM_ERR_IO:                return "Input/output error";
        case SECURECOMM_ERR_PERMISSION:        return "Permission denied";
        
        case SECURECOMM_ERR_CONFIG_NOT_FOUND:  return "Configuration file not found";
        case SECURECOMM_ERR_CONFIG_PARSE:      return "Configuration parse error";
        case SECURECOMM_ERR_CONFIG_VALIDATE:   return "Configuration validation failed";
        case SECURECOMM_ERR_CONFIG_WRITE:      return "Failed to write configuration file";
        
        case SECURECOMM_ERR_DEVICE_PROBE:      return "Device hardware profiling failed";
        case SECURECOMM_ERR_INSUFFICIENT_MEM:  return "Insufficient system memory for operation";
        
        case SECURECOMM_ERR_PROFILE_NOT_FOUND: return "Cryptographic profile not found in registry";
        case SECURECOMM_ERR_PROFILE_UNAVAIL:   return "Cryptographic profile unavailable on this device";
        case SECURECOMM_ERR_POLICY_VIOLATION:  return "Action violates declared security policy";
        case SECURECOMM_ERR_NO_COMPAT_PROFILE: return "No mutually compatible profile found";
        case SECURECOMM_ERR_DOWNGRADE_BLOCKED: return "Cryptographic downgrade attempt blocked by policy";
        
        case SECURECOMM_ERR_IDENTITY_MISSING:  return "Device identity key material missing";
        case SECURECOMM_ERR_IDENTITY_CORRUPT:  return "Device identity key material corrupted or invalid";
        case SECURECOMM_ERR_IDENTITY_GEN:      return "Keypair generation failed";
        case SECURECOMM_ERR_TRUST_VERIFY:      return "Peer identity verification failed";
        case SECURECOMM_ERR_AUTH_REJECTED:     return "Peer authentication rejected by policy";
        
        case SECURECOMM_ERR_SOCKET_INIT:       return "Socket initialization failed";
        case SECURECOMM_ERR_SOCKET_BIND:       return "Failed to bind network socket";
        case SECURECOMM_ERR_CONNECT_TIMEOUT:   return "Connection timed out";
        case SECURECOMM_ERR_NETWORK_SEND:      return "Failed to transmit datagram";
        case SECURECOMM_ERR_NETWORK_RECV:      return "Failed to receive datagram";
        case SECURECOMM_ERR_DISCONNECT:        return "Peer disconnected";
        
        case SECURECOMM_ERR_HANDSHAKE_FAIL:    return "Cryptographic handshake failed";
        case SECURECOMM_ERR_AEAD_VERIFY:       return "AEAD authentication tag verification failed";
        case SECURECOMM_ERR_REPLAY_DETECTED:   return "Duplicate/stale datagram rejected by replay window";
        case SECURECOMM_ERR_MALFORMED_PACKET:  return "Malformed packet rejected by bounds check";
        case SECURECOMM_ERR_BACKEND_INIT:      return "Cryptographic backend initialization failed";
        
        case SECURECOMM_ERR_SERVICE_RUNNING:   return "Service is already running";
        case SECURECOMM_ERR_SERVICE_STOPPED:   return "Service is stopped";
        default:                               return "Unknown error";
    }
}
