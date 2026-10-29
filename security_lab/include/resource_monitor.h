/*
 * security_lab/include/resource_monitor.h
 *
 * Linux system resource metrics: /proc/<pid>/statm, CPU usage %, and context switches.
 */

#ifndef SECURITY_LAB_RESOURCE_MONITOR_H
#define SECURITY_LAB_RESOURCE_MONITOR_H

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    double resident_memory_mb;
    double virtual_memory_mb;
    double cpu_time_ms;
    double cpu_percent;
    long   voluntary_context_switches;
    long   involuntary_context_switches;
} resource_telemetry_t;

/* Samples memory and CPU for a specific PID or self (if pid <= 0) */
int resource_monitor_sample(pid_t pid, resource_telemetry_t *out_sample);

#ifdef __cplusplus
}
#endif

#endif /* SECURITY_LAB_RESOURCE_MONITOR_H */
