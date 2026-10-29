/*
 * securecomm/include/securecomm/common.h
 *
 * Common types, enums, limits, and product constants for SecureComm.
 */

#ifndef SECURECOMM_COMMON_H
#define SECURECOMM_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SECURECOMM_PRODUCT_NAME     "SecureComm"
#define SECURECOMM_VERSION_STRING   "1.0.0"
#define SECURECOMM_DEFAULT_CONFIG   "/etc/securecomm/securecomm.json"
#define SECURECOMM_LOCAL_CONFIG     "config/securecomm.json"
#define SECURECOMM_DEFAULT_VAR_DIR  "/var/lib/securecomm"
#define SECURECOMM_LOCAL_VAR_DIR    "var"
#define SECURECOMM_DEFAULT_LOG_DIR  "/var/log/securecomm"
#define SECURECOMM_LOCAL_LOG_DIR    "logs"

/* Operating Modes */
typedef enum {
    SECURECOMM_MODE_UNKNOWN   = 0,
    SECURECOMM_MODE_CLASSICAL = 1,
    SECURECOMM_MODE_PQC       = 2,
    SECURECOMM_MODE_HYBRID    = 3,
    SECURECOMM_MODE_ADAPTIVE  = 4
} securecomm_mode_t;

/* Device Roles */
typedef enum {
    SECURECOMM_ROLE_UNKNOWN = 0,
    SECURECOMM_ROLE_SERVER  = 1,
    SECURECOMM_ROLE_CLIENT  = 2
} securecomm_role_t;

/* Standard Ports */
#define SECURECOMM_PORT_CLASSICAL 9877
#define SECURECOMM_PORT_PQC       9877
#define SECURECOMM_PORT_HYBRID    9879
#define SECURECOMM_PORT_ADAPTIVE  9885

#define SECURECOMM_DEFAULT_PORT_CLASSICAL SECURECOMM_PORT_CLASSICAL
#define SECURECOMM_DEFAULT_PORT_PQC       SECURECOMM_PORT_PQC
#define SECURECOMM_DEFAULT_PORT_HYBRID    SECURECOMM_PORT_HYBRID
#define SECURECOMM_DEFAULT_PORT_ADAPTIVE  SECURECOMM_PORT_ADAPTIVE

/* Limits */
#define SECURECOMM_MAX_PATH_LEN       1024
#define SECURECOMM_MAX_IP_LEN         64
#define SECURECOMM_MAX_ID_LEN         64
#define SECURECOMM_MAX_LINE_LEN       2048
#define SECURECOMM_MAX_SESSIONS       256
#define SECURECOMM_MAX_PROFILE_NAME   64
#define SECURECOMM_MAX_BUFFER_SIZE    65536

const char *securecomm_mode_to_string(securecomm_mode_t mode);
securecomm_mode_t securecomm_mode_from_string(const char *str);

const char *securecomm_role_to_string(securecomm_role_t role);
securecomm_role_t securecomm_role_from_string(const char *str);

#ifdef __cplusplus
}
#endif

#endif /* SECURECOMM_COMMON_H */
