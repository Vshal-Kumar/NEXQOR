/*
 * security_lab/include/server_health.h
 *
 * Real-time server process health checks, active UDP probes, and crash discovery.
 */

#ifndef SECURITY_LAB_SERVER_HEALTH_H
#define SECURITY_LAB_SERVER_HEALTH_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Checks if a process ID is running and alive */
bool server_health_check_pid(pid_t pid);

/* Finds the PID of the currently running server for a given suite */
pid_t server_health_find_server_pid(const char *suite_name);

/* Sends active UDP discovery probe and returns RTT in microseconds */
int server_health_probe_udp(const char *ip_str, uint16_t port, double *out_rtt_us);

#ifdef __cplusplus
}
#endif

#endif /* SECURITY_LAB_SERVER_HEALTH_H */
