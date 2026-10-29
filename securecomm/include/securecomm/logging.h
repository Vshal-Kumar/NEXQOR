/*
 * securecomm/include/securecomm/logging.h
 *
 * Structured, lightweight logging for SecureComm.
 * Enforces secret suppression and thread-safe outputs.
 */

#ifndef SECURECOMM_LOGGING_H
#define SECURECOMM_LOGGING_H

#include <stdio.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SECURECOMM_LOG_DEBUG = 0,
    SECURECOMM_LOG_INFO  = 1,
    SECURECOMM_LOG_WARN  = 2,
    SECURECOMM_LOG_ERROR = 3,
    SECURECOMM_LOG_NONE  = 4
} securecomm_log_level_t;

int  securecomm_log_init(securecomm_log_level_t level, const char *log_filepath);
void securecomm_log_close(void);
void securecomm_log_set_level(securecomm_log_level_t level);
securecomm_log_level_t securecomm_log_get_level(void);
securecomm_log_level_t securecomm_log_level_from_string(const char *str);
const char *securecomm_log_level_to_string(securecomm_log_level_t level);

void securecomm_log_write(securecomm_log_level_t level, const char *module,
                          const char *file, int line, const char *fmt, ...)
                          __attribute__((format(printf, 5, 6)));

#define LOG_DEBUG(mod, ...) securecomm_log_write(SECURECOMM_LOG_DEBUG, mod, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_INFO(mod, ...)  securecomm_log_write(SECURECOMM_LOG_INFO,  mod, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_WARN(mod, ...)  securecomm_log_write(SECURECOMM_LOG_WARN,  mod, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_ERROR(mod, ...) securecomm_log_write(SECURECOMM_LOG_ERROR, mod, __FILE__, __LINE__, __VA_ARGS__)

#define SECURECOMM_LOG_DEBUG(...) LOG_DEBUG("CORE", __VA_ARGS__)
#define SECURECOMM_LOG_INFO(...)  LOG_INFO("CORE", __VA_ARGS__)
#define SECURECOMM_LOG_WARN(...)  LOG_WARN("CORE", __VA_ARGS__)
#define SECURECOMM_LOG_ERROR(...) LOG_ERROR("CORE", __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* SECURECOMM_LOGGING_H */
