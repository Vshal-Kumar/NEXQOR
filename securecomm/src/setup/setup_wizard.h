/*
 * securecomm/src/setup/setup_wizard.h
 *
 * Interactive and automated Setup Wizard for SecureComm.
 */

#ifndef SECURECOMM_SETUP_WIZARD_H
#define SECURECOMM_SETUP_WIZARD_H

#include "securecomm/config.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

int securecomm_setup_wizard_run(const char *config_path, bool non_interactive);

#ifdef __cplusplus
}
#endif

#endif /* SECURECOMM_SETUP_WIZARD_H */
