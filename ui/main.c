/*
 * ui/main.c — QRYPTONEX GTK4 Dashboard Entry Point
 */

#include <gtk/gtk.h>
#include "ui_app.h"

int main(int argc, char *argv[]) {
    GtkApplication *app = gtk_application_new("org.qryptonex.dashboard", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(ui_app_activate), NULL);

    int status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);
    return status;
}
