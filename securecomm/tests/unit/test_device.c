/*
 * securecomm/tests/unit/test_device.c
 *
 * Unit tests for device capability detection and profiling.
 */

#define _POSIX_C_SOURCE 200809L
#include "securecomm/device_profile.h"
#include "securecomm/error.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

int main(void) {
    printf("Running Device Profiler Unit Tests...\n");
    securecomm_device_profile_t dev;
    int rc = securecomm_device_profile_collect(&dev);
    assert(rc == SECURECOMM_SUCCESS);

    assert(strlen(dev.arch) > 0);
    assert(dev.cpu_cores >= 1);
    assert(dev.ram_total_mb > 0);
    assert(dev.ram_available_mb > 0);
    assert(dev.openssl_available == true);
    assert(dev.liboqs_available == true);
    assert(dev.pqc_functional == true);

    printf(" [✓] Architecture: %s, Cores: %u, RAM: %llu MB\n", dev.arch, dev.cpu_cores, (unsigned long long)dev.ram_total_mb);
    printf(" [✓] Crypto Support: OpenSSL=%d, liboqs=%d, PQC functional=%d\n",
           dev.openssl_available, dev.liboqs_available, dev.pqc_functional);
    printf("All Device Profiler Unit Tests PASSED!\n");
    return 0;
}
