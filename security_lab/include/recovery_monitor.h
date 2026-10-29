/*
 * security_lab/include/recovery_monitor.h
 *
 * Measures time elapsed until full healthy service restoration following attacks.
 */

#ifndef SECURITY_LAB_RECOVERY_MONITOR_H
#define SECURITY_LAB_RECOVERY_MONITOR_H

#include "suite_adapter.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Actively polls until server responds cleanly with RTT <= baseline * 2.0. Returns recovery time in ms or -1. */
double recovery_monitor_await_clean_service(suite_adapter_t *adapter, double baseline_rtt_us, int max_wait_ms);

#ifdef __cplusplus
}
#endif

#endif /* SECURITY_LAB_RECOVERY_MONITOR_H */
