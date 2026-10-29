/*
 * security_lab/tests/test_safety.c
 *
 * Unit tests for safety controls, target allowlisting, rate limits, and route validation.
 */

#include "safety_guard.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "\033[1;31mFAIL: %s (%s:%d)\033[0m\n", msg, __FILE__, __LINE__); \
        return 1; \
    } else { \
        printf("  [PASS] %s\n", msg); \
    } \
} while(0)

int main(void) {
    printf("\n=== Running Safety Guard Unit Tests ===\n");

    safety_guard_init(true);

    /* Test 1: Default allowlisted targets */
    TEST_ASSERT(safety_guard_validate_target("127.0.0.1", 9877) == 0, "127.0.0.1:9877 must be allowed");
    TEST_ASSERT(safety_guard_validate_target("10.58.4.191", 9879) == 0, "10.58.4.191:9879 must be allowed");
    TEST_ASSERT(safety_guard_validate_target("100.113.83.56", 9877) == 0, "100.113.83.56:9877 must be allowed");

    /* Test 2: Unauthorized target rejection */
    TEST_ASSERT(safety_guard_validate_target("8.8.8.8", 9877) != 0, "External target 8.8.8.8 must be rejected");
    TEST_ASSERT(safety_guard_validate_target("192.168.1.1", 9877) != 0, "Unlisted IP 192.168.1.1 must be rejected");

    /* Test 3: Route interface mapping */
    char iface[64];
    TEST_ASSERT(safety_guard_validate_route("127.0.0.1", iface, sizeof(iface)) == 0 && strcmp(iface, "lo") == 0,
                "Loopback IP maps to lo");
    TEST_ASSERT(safety_guard_validate_route("100.113.83.56", iface, sizeof(iface)) == 0 && strcmp(iface, "tailscale0") == 0,
                "Tailscale IP maps to tailscale0");
    TEST_ASSERT(safety_guard_validate_route("10.58.4.191", iface, sizeof(iface)) == 0 && strcmp(iface, "wlp2s0") == 0,
                "LAN IP maps to wlp2s0");

    /* Test 4: Dynamic allowlist extension */
    TEST_ASSERT(safety_guard_add_allowed_target("192.168.10.50", 9877) == 0, "Adding custom target succeeds");
    TEST_ASSERT(safety_guard_validate_target("192.168.10.50", 9877) == 0, "Custom target now allowed");

    /* Test 5: Dry-run flag state */
    TEST_ASSERT(safety_guard_is_dry_run() == true, "Dry-run flag must be active");
    safety_guard_set_dry_run(false);
    TEST_ASSERT(safety_guard_is_dry_run() == false, "Dry-run flag toggle succeeds");

    printf("\nAll Safety Guard Tests Passed Successfully!\n\n");
    return 0;
}
