/*
 * security_lab/ui/attack_ui.h — GTK 4 Pure-C Security Testing & Attack Lab UI
 */

#ifndef ATTACK_UI_H
#define ATTACK_UI_H

#include <gtk/gtk.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    UI_SUITE_PQC = 0,
    UI_SUITE_HYBRID = 1,
    UI_SUITE_CLASSICAL = 2,
    UI_SUITE_ALL = 3
} ui_crypto_suite_t;

typedef struct attack_ui_app_s attack_ui_app_t;

void attack_ui_activate(GtkApplication *app, gpointer user_data);

#ifdef __cplusplus
}
#endif

#endif /* ATTACK_UI_H */
