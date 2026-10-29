/*
 * security_lab/src/main.c
 *
 * Main entry point for the QRYPTONEX pure-C security lab executable.
 */

#include "test_engine.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    engine_config_t cfg;
    test_engine_init_config(&cfg);

    if (test_engine_parse_args(&cfg, argc, argv) != 0) {
        return 1;
    }

    int rc = test_engine_run(&cfg);
    return rc;
}
