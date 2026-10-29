/*
 * security_lab/monitoring/resource_monitor.c
 *
 * Implements Linux resource tracking via /proc/<pid>/statm and getrusage().
 */

#include "resource_monitor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>

int resource_monitor_sample(pid_t pid, resource_telemetry_t *out_sample) {
    if (!out_sample) return -1;
    memset(out_sample, 0, sizeof(*out_sample));

    /* 1. Process memory via /proc/<pid>/statm if pid > 0 */
    if (pid > 0) {
        char statm_path[64];
        snprintf(statm_path, sizeof(statm_path), "/proc/%d/statm", pid);
        FILE *f = fopen(statm_path, "r");
        if (f) {
            unsigned long vm_pages = 0, rss_pages = 0;
            if (fscanf(f, "%lu %lu", &vm_pages, &rss_pages) == 2) {
                long page_sz = sysconf(_SC_PAGESIZE);
                if (page_sz > 0) {
                    out_sample->virtual_memory_mb = (double)(vm_pages * (unsigned long)page_sz) / (1024.0 * 1024.0);
                    out_sample->resident_memory_mb = (double)(rss_pages * (unsigned long)page_sz) / (1024.0 * 1024.0);
                }
            }
            fclose(f);
        }
    }

    /* 2. Process CPU and context switches via getrusage() */
    struct rusage usage;
    int who = (pid <= 0) ? RUSAGE_SELF : RUSAGE_SELF;
    if (getrusage(who, &usage) == 0) {
        if (out_sample->resident_memory_mb == 0.0) {
            out_sample->resident_memory_mb = (double)usage.ru_maxrss / 1024.0;
        }
        out_sample->cpu_time_ms = (double)usage.ru_utime.tv_sec * 1e3 +
                                  (double)usage.ru_utime.tv_usec * 1e-3 +
                                  (double)usage.ru_stime.tv_sec * 1e3 +
                                  (double)usage.ru_stime.tv_usec * 1e-3;
        out_sample->voluntary_context_switches = usage.ru_nvcsw;
        out_sample->involuntary_context_switches = usage.ru_nivcsw;
    }

    return 0;
}
