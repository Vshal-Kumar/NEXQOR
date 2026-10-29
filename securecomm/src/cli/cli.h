/*
 * securecomm/src/cli/cli.h
 *
 * Command-Line Interface dispatcher and subcommand handlers for SecureComm.
 */

#ifndef SECURECOMM_CLI_H
#define SECURECOMM_CLI_H

#ifdef __cplusplus
extern "C" {
#endif

int securecomm_cli_dispatch(int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif /* SECURECOMM_CLI_H */
