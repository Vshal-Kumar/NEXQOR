/*
 * ui/ui_app.h — Main GTK4 Dashboard Application Interface
 */

#ifndef UI_APP_H
#define UI_APP_H

#include <gtk/gtk.h>
#include "ipc_manager.h"

typedef struct ui_app_s ui_app_t;

/* Initialize and activate the GTK4 application */
void ui_app_activate(GtkApplication *gtk_app, gpointer user_data);

#endif /* UI_APP_H */
