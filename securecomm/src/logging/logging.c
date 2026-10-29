/*
 * securecomm/src/logging/logging.c
 *
 * Thread-safe, structured logger for SecureComm.
 */

#define _POSIX_C_SOURCE 200809L
#include "securecomm/logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h>
#include <strings.h>

static securecomm_log_level_t g_current_level = SECURECOMM_LOG_INFO;
static FILE *g_log_file = NULL;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

static const char *level_to_str(securecomm_log_level_t level) {
    switch (level) {
        case SECURECOMM_LOG_DEBUG: return "DEBUG";
        case SECURECOMM_LOG_INFO:  return "INFO ";
        case SECURECOMM_LOG_WARN:  return "WARN ";
        case SECURECOMM_LOG_ERROR: return "ERROR";
        default:                   return "LOG  ";
    }
}

const char *securecomm_log_level_to_string(securecomm_log_level_t level) {
    switch (level) {
        case SECURECOMM_LOG_DEBUG: return "debug";
        case SECURECOMM_LOG_INFO:  return "info";
        case SECURECOMM_LOG_WARN:  return "warn";
        case SECURECOMM_LOG_ERROR: return "error";
        case SECURECOMM_LOG_NONE:  return "none";
        default:                   return "info";
    }
}

securecomm_log_level_t securecomm_log_level_from_string(const char *str) {
    if (!str) return SECURECOMM_LOG_INFO;
    if (strcasecmp(str, "debug") == 0) return SECURECOMM_LOG_DEBUG;
    if (strcasecmp(str, "info") == 0)  return SECURECOMM_LOG_INFO;
    if (strcasecmp(str, "warn") == 0 || strcasecmp(str, "warning") == 0) return SECURECOMM_LOG_WARN;
    if (strcasecmp(str, "error") == 0) return SECURECOMM_LOG_ERROR;
    if (strcasecmp(str, "none") == 0)  return SECURECOMM_LOG_NONE;
    return SECURECOMM_LOG_INFO;
}

int securecomm_log_init(securecomm_log_level_t level, const char *log_filepath) {
    pthread_mutex_lock(&g_log_mutex);
    g_current_level = level;
    if (g_log_file && g_log_file != stderr && g_log_file != stdout) {
        fclose(g_log_file);
        g_log_file = NULL;
    }
    
    if (log_filepath && strlen(log_filepath) > 0) {
        g_log_file = fopen(log_filepath, "a");
        if (!g_log_file) {
            pthread_mutex_unlock(&g_log_mutex);
            return -1;
        }
    }
    pthread_mutex_unlock(&g_log_mutex);
    return 0;
}

void securecomm_log_close(void) {
    pthread_mutex_lock(&g_log_mutex);
    if (g_log_file && g_log_file != stderr && g_log_file != stdout) {
        fclose(g_log_file);
        g_log_file = NULL;
    }
    pthread_mutex_unlock(&g_log_mutex);
}

void securecomm_log_set_level(securecomm_log_level_t level) {
    pthread_mutex_lock(&g_log_mutex);
    g_current_level = level;
    pthread_mutex_unlock(&g_log_mutex);
}

securecomm_log_level_t securecomm_log_get_level(void) {
    return g_current_level;
}

void securecomm_log_write(securecomm_log_level_t level, const char *module,
                          const char *file, int line, const char *fmt, ...) {
    (void)file;
    (void)line;
    if (level < g_current_level || level >= SECURECOMM_LOG_NONE) {
        return;
    }

    char time_buf[32];
    time_t now = time(NULL);
    struct tm tm_info;
    localtime_r(&now, &tm_info);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_info);

    char msg_buf[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg_buf, sizeof(msg_buf), fmt, args);
    va_end(args);

    pthread_mutex_lock(&g_log_mutex);
    
    /* Format: [TIMESTAMP] [LEVEL] [MODULE] message */
    FILE *dest = (level >= SECURECOMM_LOG_WARN) ? stderr : stdout;
    fprintf(dest, "[%s] [%s] [%s] %s\n", time_buf, level_to_str(level), module ? module : "CORE", msg_buf);
    fflush(dest);
    
    if (g_log_file) {
        fprintf(g_log_file, "[%s] [%s] [%s] %s\n", time_buf, level_to_str(level), module ? module : "CORE", msg_buf);
        fflush(g_log_file);
    }
    
    pthread_mutex_unlock(&g_log_mutex);
}
