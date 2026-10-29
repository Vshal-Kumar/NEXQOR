/*
 * security_lab/ui/main.c — Entry Point for GTK 4 Security & Attack Lab
 */

#include "attack_ui.h"
#include <gtk/gtk.h>

int main(int argc, char *argv[]) {
    GtkApplication *app = gtk_application_new("org.qryptonex.security_lab", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(attack_ui_activate), NULL);

    int status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);
    return status;
}
