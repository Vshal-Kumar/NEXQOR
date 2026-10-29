/*
 * securecomm/src/main.c
 *
 * SecureComm: Lightweight, Adaptive, Cross-Platform Secure Communication Framework.
 * Standalone application entry point.
 */

#include "cli/cli.h"
#include "securecomm/logging.h"

int main(int argc, char **argv) {
    securecomm_log_init(SECURECOMM_LOG_INFO, NULL);
    return securecomm_cli_dispatch(argc, argv);
}
