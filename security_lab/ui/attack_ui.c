/*
 * security_lab/ui/attack_ui.c — GTK 4 Pure-C Security Testing & Attack Lab UI
 *
 * Professional graphical interface for launching, observing, and analyzing
 * real-network protocol attacks against Classical, Hybrid, and Pure PQC implementations.
 */

#include "attack_ui.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <time.h>

typedef struct {
    const char *id;
    const char *tag;
    const char *name;
    const char *description;
} attack_scenario_def_t;

static const attack_scenario_def_t G_SCENARIOS[] = {
    { "all",          "[ALL]",  "All Security Scenarios (Full Suite)",        "Runs every network test and attack simulation automatically in sequence" },
    { "baseline",     "[BASE]", "Normal Network Traffic Benchmark",          "Measures standard throughput, latency, and ACK response under clean conditions" },
    { "loss",         "[LOSS]", "Packet Loss Resilience Test (15%)",          "Randomly drops 15% of packets to verify automatic retransmission and recovery" },
    { "delay_jitter", "[JITR]", "Network Lag & Variable Jitter (30ms)",       "Adds unpredictable delay to verify packets do not time out or get stuck" },
    { "reorder",      "[RORD]", "Scrambled Packet Order (25%)",               "Mixes up arrival sequence to verify anti-replay sliding window reorders properly" },
    { "duplication",  "[DUPL]", "Duplicate Packet Flood (25%)",               "Sends duplicate copies to make sure identical packets are ignored and rejected" },
    { "disconnect",   "[DISC]", "Temporary Link Outage (2s Outage)",          "Cuts network for 2 seconds to confirm the connection reconnects smoothly" },
    { "mtu",          "[PMTU]", "Oversized Packet Test (512B - 4KB)",         "Sends large packets to verify buffers handle oversized data without crashing" },
    { "replay",       "[RPLY]", "Replay Attack Simulation",                   "Resends previously captured packets to check they are blocked and ignored" },
    { "tampering",    "[TAMP]", "Data Tampering & Bit-Flipping",              "Flips bits in encrypted packets to verify corrupted data is instantly rejected" },
    { "auth",         "[AUTH]", "Forged Signature & Fake Identity",           "Sends forged cryptographic signatures to ensure unauthorized users cannot connect" },
    { "handshake",    "[HSHK]", "Broken Handshake Order Attack",              "Sends handshake steps in wrong order to ensure server rejects bad flows" },
    { "malformed",    "[FUZZ]", "Malformed Input & Fuzzing Flood",            "Sends random garbage bytes and broken headers to verify the server never crashes" },
    { "stress",       "[STRS]", "High-Traffic Overload Stress Test",          "Simulates 16 simultaneous client connections to test memory limits and queue speed" },
    { "isolation",    "[ISOL]", "Cross-Client Session Snooping",              "Attempts to inject messages into other clients' sessions to test strict separation" }
};

#define SCENARIO_COUNT (sizeof(G_SCENARIOS) / sizeof(G_SCENARIOS[0]))

struct attack_ui_app_s {
    GtkApplication *app;
    GtkWidget *window;
    char workspace_root[1024];

    /* Header Bar */
    GtkWidget *status_badge;
    GtkWidget *target_badge;
    GtkWidget *btn_run;
    GtkWidget *btn_run_all;
    GtkWidget *btn_stop;
    GtkWidget *btn_open_report;

    /* Configuration */
    GtkWidget *entry_target_ip;
    GtkWidget *entry_target_port;
    GtkWidget *dropdown_env;
    GtkWidget *dropdown_suite;
    GtkWidget *switch_dry_run;

    /* Scenario Selection */
    GtkWidget *scenario_list_box;
    char selected_scenario_id[64];

    /* Console Terminal */
    GtkWidget *console_view;
    GtkTextBuffer *console_buf;
    GtkWidget *console_scrolled;

    /* Results Summary */
    GtkWidget *results_list_box;
    GtkWidget *lbl_summary_count;
    GtkWidget *lbl_summary_status;
    GtkWidget *lbl_summary_latency;

    /* Execution State */
    bool is_running;
    pid_t worker_pid;
    pthread_t worker_thread;
    char latest_run_dir[1024];
};

typedef struct {
    attack_ui_app_t *ui;
    char cmd[2048];
} attack_worker_args_t;

typedef struct {
    attack_ui_app_t *ui;
    char *line;
} console_line_msg_t;

/* ── UI Log Stream Dispatcher ──────────────────────────────────────── */
static gboolean cb_append_console_line(gpointer user_data) {
    console_line_msg_t *msg = (console_line_msg_t *)user_data;
    if (!msg || !msg->ui || !msg->ui->console_buf) {
        if (msg) { free(msg->line); free(msg); }
        return G_SOURCE_REMOVE;
    }

    GtkTextIter end_iter;
    gtk_text_buffer_get_end_iter(msg->ui->console_buf, &end_iter);
    gtk_text_buffer_insert(msg->ui->console_buf, &end_iter, msg->line, -1);
    gtk_text_buffer_insert(msg->ui->console_buf, &end_iter, "\n", 1);

    /* Autoscroll to bottom */
    GtkAdjustment *adj = gtk_scrolled_window_get_vadjustment(GTK_SCROLLED_WINDOW(msg->ui->console_scrolled));
    if (adj) {
        gtk_adjustment_set_value(adj, gtk_adjustment_get_upper(adj));
    }

    free(msg->line);
    free(msg);
    return G_SOURCE_REMOVE;
}

static void post_console_line(attack_ui_app_t *ui, const char *line) {
    console_line_msg_t *msg = malloc(sizeof(console_line_msg_t));
    if (!msg) return;
    msg->ui = ui;
    msg->line = strdup(line ? line : "");
    g_idle_add(cb_append_console_line, msg);
}

/* ── Results Visualizer & Table Population ─────────────────────────── */
static void populate_results_card(attack_ui_app_t *ui, const char *scenario_name,
                                  const char *verdict, const char *evidence, const char *suite) {
    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_widget_add_css_class(card, "results-card");

    GtkWidget *top_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *title_lbl = gtk_label_new(scenario_name);
    gtk_widget_add_css_class(title_lbl, "scenario-name");
    gtk_label_set_xalign(GTK_LABEL(title_lbl), 0.0);
    gtk_widget_set_hexpand(title_lbl, TRUE);

    GtkWidget *suite_badge = gtk_label_new(suite);
    gtk_widget_add_css_class(suite_badge, "suite-badge");

    /* Ensure verdict has zero emojis */
    const char *clean_verdict = "PASS";
    bool is_pass = true;
    if (strstr(verdict, "FAIL") || strstr(verdict, "VULN")) {
        clean_verdict = "FAIL";
        is_pass = false;
    } else if (strstr(verdict, "INCON") || strstr(verdict, "WARN")) {
        clean_verdict = "INCONCLUSIVE";
        is_pass = false;
    }

    GtkWidget *verdict_lbl = gtk_label_new(clean_verdict);
    gtk_widget_add_css_class(verdict_lbl, "status-badge");
    if (is_pass) {
        gtk_widget_add_css_class(verdict_lbl, "status-passed");
    } else {
        gtk_widget_add_css_class(verdict_lbl, "status-failed");
    }

    gtk_box_append(GTK_BOX(top_row), title_lbl);
    gtk_box_append(GTK_BOX(top_row), suite_badge);
    gtk_box_append(GTK_BOX(top_row), verdict_lbl);

    GtkWidget *ev_lbl = gtk_label_new(evidence);
    gtk_widget_add_css_class(ev_lbl, "results-evidence");
    gtk_label_set_xalign(GTK_LABEL(ev_lbl), 0.0);
    gtk_label_set_wrap(GTK_LABEL(ev_lbl), TRUE);

    gtk_box_append(GTK_BOX(card), top_row);
    gtk_box_append(GTK_BOX(card), ev_lbl);

    gtk_list_box_append(GTK_LIST_BOX(ui->results_list_box), card);
}

static gboolean cb_on_attack_finished(gpointer user_data) {
    attack_ui_app_t *ui = (attack_ui_app_t *)user_data;
    if (!ui) return G_SOURCE_REMOVE;

    ui->is_running = false;
    ui->worker_pid = 0;

    gtk_widget_set_sensitive(ui->btn_run, TRUE);
    gtk_widget_set_sensitive(ui->btn_run_all, TRUE);
    gtk_widget_set_sensitive(ui->btn_stop, FALSE);
    gtk_widget_set_sensitive(ui->btn_open_report, TRUE);

    gtk_label_set_text(GTK_LABEL(ui->status_badge), "EVALUATION FINISHED");
    gtk_widget_remove_css_class(ui->status_badge, "status-running");
    gtk_widget_add_css_class(ui->status_badge, "status-passed");

    /* Pre-compile formatted PDF report in background */
    char gen_cmd[2560];
    snprintf(gen_cmd, sizeof(gen_cmd), "python3 %.900s/security_lab/reporting/generate_pdf.py '%.900s' >/dev/null 2>&1 &",
             ui->workspace_root, ui->workspace_root);
    int r_gen = system(gen_cmd);
    (void)r_gen;

    /* Clear old result cards */
    GtkWidget *child = gtk_widget_get_first_child(ui->results_list_box);
    while (child) {
        GtkWidget *next = gtk_widget_get_next_sibling(child);
        gtk_list_box_remove(GTK_LIST_BOX(ui->results_list_box), child);
        child = next;
    }

    /* Parse latest run report summary */
    char report_path[1024];
    snprintf(report_path, sizeof(report_path), "%.900s/security_lab/results/latest/report.md", ui->workspace_root);
    FILE *f = fopen(report_path, "r");
    int pass_count = 0;
    int fail_count = 0;

    if (f) {
        char line[1024];
        bool in_matrix = false;
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "## 2. Experimental Scenarios")) {
                in_matrix = true;
                continue;
            }
            if (in_matrix && strstr(line, "## 3.")) {
                in_matrix = false;
                break;
            }
            if (in_matrix && line[0] == '|' && strstr(line, "SCENARIO_")) {
                /* Format: | Scenario ID | Evaluated Property | Suite | Verdict | Evidence / Observed Behavior | */
                char *p = line;
                if (*p == '|') p++; /* Skip leading pipe */

                char sc_id[64] = "", sc_name[128] = "", sc_suite[32] = "", sc_verdict[32] = "", sc_ev[512] = "";
                int col = 0;

                while (*p) {
                    char *next = strchr(p, '|');
                    if (next) *next = '\0';

                    /* Trim leading whitespace, backticks, asterisks */
                    while (*p == ' ' || *p == '`' || *p == '*') p++;
                    char *end = p + strlen(p) - 1;
                    while (end > p && (*end == ' ' || *end == '`' || *end == '*' || *end == '\n' || *end == '\r')) {
                        *end-- = '\0';
                    }

                    if (col == 0) snprintf(sc_id, sizeof(sc_id), "%s", p);
                    else if (col == 1) snprintf(sc_name, sizeof(sc_name), "%s", p);
                    else if (col == 2) snprintf(sc_suite, sizeof(sc_suite), "%s", p);
                    else if (col == 3) snprintf(sc_verdict, sizeof(sc_verdict), "%s", p);
                    else if (col >= 4 && strlen(p) > 0) {
                        if (strlen(sc_ev) > 0 && strlen(sc_ev) < sizeof(sc_ev) - 4) {
                            size_t cur = strlen(sc_ev);
                            snprintf(sc_ev + cur, sizeof(sc_ev) - cur, " | %s", p);
                        } else if (strlen(sc_ev) == 0) {
                            snprintf(sc_ev, sizeof(sc_ev), "%s", p);
                        }
                    }

                    if (!next) break;
                    p = next + 1;
                    col++;
                }

                if (strlen(sc_name) > 0) {
                    populate_results_card(ui, sc_name, sc_verdict, sc_ev, sc_suite);
                    if (strstr(sc_verdict, "PASS")) pass_count++;
                    else fail_count++;
                }
            }
        }
        fclose(f);
    }

    char count_buf[64];
    snprintf(count_buf, sizeof(count_buf), "%d Passed | %d Failed", pass_count, fail_count);
    gtk_label_set_text(GTK_LABEL(ui->lbl_summary_count), count_buf);

    if (fail_count > 0) {
        gtk_label_set_text(GTK_LABEL(ui->lbl_summary_status), "ATTENTION REQUIRED");
        gtk_label_set_text(GTK_LABEL(ui->status_badge), "ATTENTION REQUIRED");
        gtk_widget_remove_css_class(ui->status_badge, "status-passed");
        gtk_widget_add_css_class(ui->status_badge, "status-failed");
    } else {
        gtk_label_set_text(GTK_LABEL(ui->lbl_summary_status), "RESILIENCE VERIFIED");
        gtk_label_set_text(GTK_LABEL(ui->status_badge), "RESILIENCE VERIFIED");
    }

    return G_SOURCE_REMOVE;
}

/* ── Worker Thread for Asynchronous Execution ──────────────────────── */
static void *attack_worker_thread(void *arg) {
    attack_worker_args_t *args = (attack_worker_args_t *)arg;
    attack_ui_app_t *ui = args->ui;

    int pipe_fd[2];
    if (pipe(pipe_fd) != 0) {
        post_console_line(ui, "[ERROR] Failed to allocate execution pipe.");
        g_idle_add(cb_on_attack_finished, ui);
        free(args);
        return NULL;
    }

    pid_t pid = fork();
    if (pid == 0) {
        setpgid(0, 0); /* Put child in its own process group */
        close(pipe_fd[0]);
        dup2(pipe_fd[1], STDOUT_FILENO);
        dup2(pipe_fd[1], STDERR_FILENO);
        close(pipe_fd[1]);

        if (chdir(ui->workspace_root) != 0) exit(1);
        execl("/bin/sh", "sh", "-c", args->cmd, (char *)NULL);
        exit(1);
    }

    close(pipe_fd[1]);
    ui->worker_pid = pid;

    FILE *f = fdopen(pipe_fd[0], "r");
    if (f) {
        char line[1024];
        while (fgets(line, sizeof(line), f)) {
            char *nl = strchr(line, '\n');
            if (nl) *nl = '\0';
            char *cr = strchr(line, '\r');
            if (cr) *cr = '\0';
            post_console_line(ui, line);
        }
        fclose(f);
    }

    int status = 0;
    waitpid(pid, &status, 0);

    g_idle_add(cb_on_attack_finished, ui);
    free(args);
    return NULL;
}

/* ── UI Event Callbacks ────────────────────────────────────────────── */
static void on_run_clicked(GtkWidget *widget, gpointer user_data) {
    (void)widget;
    attack_ui_app_t *ui = (attack_ui_app_t *)user_data;
    if (ui->is_running) return;

    /* Build command line */
    const char *target_ip = gtk_editable_get_text(GTK_EDITABLE(ui->entry_target_ip));
    if (!target_ip || strlen(target_ip) == 0) target_ip = "127.0.0.1";

    const char *target_port = gtk_editable_get_text(GTK_EDITABLE(ui->entry_target_port));

    guint suite_idx = gtk_drop_down_get_selected(GTK_DROP_DOWN(ui->dropdown_suite));
    const char *suite_str = "pqc";
    if (suite_idx == 1) suite_str = "hybrid";
    else if (suite_idx == 2) suite_str = "classical";
    else if (suite_idx == 3) suite_str = "all";

    guint env_idx = gtk_drop_down_get_selected(GTK_DROP_DOWN(ui->dropdown_env));
    const char *env_str = "LAN";
    if (env_idx == 1) env_str = "Gateway";
    else if (env_idx == 2) env_str = "VPN";

    bool dry_run = gtk_switch_get_active(GTK_SWITCH(ui->switch_dry_run));

    attack_worker_args_t *args = malloc(sizeof(attack_worker_args_t));
    if (!args) return;
    args->ui = ui;

    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "./security_lab/security_lab --suite %s --scenario %s --target %s --environment %s %s%s %s",
             suite_str,
             (strlen(ui->selected_scenario_id) > 0) ? ui->selected_scenario_id : "all",
             target_ip,
             env_str,
             (target_port && strlen(target_port) > 0) ? "--port " : "",
             (target_port && strlen(target_port) > 0) ? target_port : "",
             dry_run ? "--dry-run" : "");

    snprintf(args->cmd, sizeof(args->cmd), "%s", cmd);

    /* Update UI State */
    ui->is_running = true;
    gtk_widget_set_sensitive(ui->btn_run, FALSE);
    gtk_widget_set_sensitive(ui->btn_run_all, FALSE);
    gtk_widget_set_sensitive(ui->btn_stop, TRUE);

    gtk_label_set_text(GTK_LABEL(ui->status_badge), "ATTACK IN PROGRESS...");
    gtk_widget_remove_css_class(ui->status_badge, "status-idle");
    gtk_widget_remove_css_class(ui->status_badge, "status-passed");
    gtk_widget_remove_css_class(ui->status_badge, "status-failed");
    gtk_widget_add_css_class(ui->status_badge, "status-running");

    /* Clear console buffer */
    gtk_text_buffer_set_text(ui->console_buf, "", 0);
    post_console_line(ui, "══════════════════════════════════════════════════════════════════════════");
    post_console_line(ui, "  QRYPTONEX Security Evaluation Engine — Launching Live Experiment");
    post_console_line(ui, "══════════════════════════════════════════════════════════════════════════");
    char exec_msg[2300];
    snprintf(exec_msg, sizeof(exec_msg), "[EXEC] Command: %s\n", cmd);
    post_console_line(ui, exec_msg);

    pthread_create(&ui->worker_thread, NULL, attack_worker_thread, args);
    pthread_detach(ui->worker_thread);
}

static void on_run_all_clicked(GtkWidget *widget, gpointer user_data) {
    (void)widget;
    attack_ui_app_t *ui = (attack_ui_app_t *)user_data;
    strcpy(ui->selected_scenario_id, "all");
    on_run_clicked(NULL, ui);
}

static void on_stop_clicked(GtkWidget *widget, gpointer user_data) {
    (void)widget;
    attack_ui_app_t *ui = (attack_ui_app_t *)user_data;
    if (ui->is_running && ui->worker_pid > 0) {
        post_console_line(ui, "\n[ABORT] Attack execution aborted by operator (SIGINT/SIGTERM sent to worker process)");
        gtk_label_set_text(GTK_LABEL(ui->status_badge), "ATTACK ABORTED");
        gtk_widget_remove_css_class(ui->status_badge, "status-running");
        gtk_widget_add_css_class(ui->status_badge, "status-failed");

        /* Signal entire child process group */
        kill(-ui->worker_pid, SIGINT);
        kill(-ui->worker_pid, SIGTERM);

        /* Explicitly terminate security_lab processes if still lingering */
        char pkill_cmd[256];
        snprintf(pkill_cmd, sizeof(pkill_cmd), "pkill -P %d -f security_lab 2>/dev/null || pkill -f security_lab 2>/dev/null || true", (int)ui->worker_pid);
        int r = system(pkill_cmd);
        (void)r;
    }
}

static void on_open_report_clicked(GtkWidget *widget, gpointer user_data) {
    (void)widget;
    attack_ui_app_t *ui = (attack_ui_app_t *)user_data;

    /* Ensure formatted PDF report is compiled */
    char gen_cmd[2560];
    snprintf(gen_cmd, sizeof(gen_cmd), "python3 %.900s/security_lab/reporting/generate_pdf.py '%.900s' >/dev/null 2>&1",
             ui->workspace_root, ui->workspace_root);
    int res_gen = system(gen_cmd);
    (void)res_gen;

    char pdf_path[1024];
    snprintf(pdf_path, sizeof(pdf_path), "%.900s/security_lab/results/latest/report.pdf", ui->workspace_root);

    /* Open PDF via desktop default viewer, falling back to evince or browser */
    char open_cmd[4096];
    snprintf(open_cmd, sizeof(open_cmd), "xdg-open '%.1000s' 2>/dev/null || evince '%.1000s' 2>/dev/null || google-chrome '%.1000s' >/dev/null 2>&1 &",
             pdf_path, pdf_path, pdf_path);
    int res = system(open_cmd);
    (void)res;

    char log_msg[1200];
    snprintf(log_msg, sizeof(log_msg), "[REPORT] Displaying formatted PDF evaluation report: %s", pdf_path);
    post_console_line(ui, log_msg);
}

static void on_target_preset_clicked(GtkWidget *widget, gpointer user_data) {
    attack_ui_app_t *ui = (attack_ui_app_t *)user_data;
    const char *label = gtk_button_get_label(GTK_BUTTON(widget));
    if (strstr(label, "127.0.0.1")) {
        gtk_editable_set_text(GTK_EDITABLE(ui->entry_target_ip), "127.0.0.1");
    } else if (strstr(label, "10.58.4.191")) {
        gtk_editable_set_text(GTK_EDITABLE(ui->entry_target_ip), "10.58.4.191");
    } else if (strstr(label, "100.113.83.56")) {
        gtk_editable_set_text(GTK_EDITABLE(ui->entry_target_ip), "100.113.83.56");
    }
}

static void on_scenario_selected(GtkListBox *box, GtkListBoxRow *row, gpointer user_data) {
    (void)box;
    attack_ui_app_t *ui = (attack_ui_app_t *)user_data;
    if (!row) return;

    int idx = gtk_list_box_row_get_index(row);
    if (idx >= 0 && (size_t)idx < SCENARIO_COUNT) {
        strncpy(ui->selected_scenario_id, G_SCENARIOS[idx].id, sizeof(ui->selected_scenario_id) - 1);
        char buf[128];
        snprintf(buf, sizeof(buf), "Target Attack: %s", G_SCENARIOS[idx].name);
        gtk_label_set_text(GTK_LABEL(ui->target_badge), buf);
    }
}

static void on_suite_changed(GObject *gobject, GParamSpec *pspec, gpointer user_data) {
    (void)pspec;
    attack_ui_app_t *ui = (attack_ui_app_t *)user_data;
    guint sel = gtk_drop_down_get_selected(GTK_DROP_DOWN(gobject));
    if (sel == 0) { /* PQC */
        gtk_editable_set_text(GTK_EDITABLE(ui->entry_target_port), "9877");
    } else if (sel == 1) { /* Hybrid */
        gtk_editable_set_text(GTK_EDITABLE(ui->entry_target_port), "9879");
    } else if (sel == 2) { /* Classical */
        gtk_editable_set_text(GTK_EDITABLE(ui->entry_target_port), "9877");
    }
}

/* ── UI Activation & Window Layout ─────────────────────────────────── */
void attack_ui_activate(GtkApplication *app, gpointer user_data) {
    (void)user_data;
    attack_ui_app_t *ui = calloc(1, sizeof(attack_ui_app_t));
    ui->app = app;
    strcpy(ui->selected_scenario_id, "all");

    if (!getcwd(ui->workspace_root, sizeof(ui->workspace_root))) {
        strcpy(ui->workspace_root, ".");
    }

    ui->window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(ui->window), "QRYPTONEX — Real-Network Security Evaluation & Attack Lab");
    gtk_window_set_default_size(GTK_WINDOW(ui->window), 1360, 880);

    /* Load Cyber CSS */
    GtkCssProvider *css_prov = gtk_css_provider_new();
    char css_path[1024];
    snprintf(css_path, sizeof(css_path), "%s/security_lab/ui/style.css", ui->workspace_root);
    if (access(css_path, R_OK) != 0) {
        snprintf(css_path, sizeof(css_path), "%s/style.css", ui->workspace_root);
    }
    gtk_css_provider_load_from_path(css_prov, css_path);
    gtk_style_context_add_provider_for_display(
        gdk_display_get_default(),
        GTK_STYLE_PROVIDER(css_prov),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);

    GtkWidget *root_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_window_set_child(GTK_WINDOW(ui->window), root_vbox);

    /* ── Top Header Toolbar ─────────────────────────────────────────── */
    GtkWidget *top_bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_widget_add_css_class(top_bar, "top-bar");

    GtkWidget *brand_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *title_lbl = gtk_label_new("QRYPTONEX SECURITY EVALUATION LAB");
    gtk_widget_add_css_class(title_lbl, "lab-title");
    gtk_label_set_xalign(GTK_LABEL(title_lbl), 0.0);

    GtkWidget *sub_lbl = gtk_label_new("Real-Network Attack Simulation & Cryptographic Resilience Testing");
    gtk_widget_add_css_class(sub_lbl, "lab-subtitle");
    gtk_label_set_xalign(GTK_LABEL(sub_lbl), 0.0);

    gtk_box_append(GTK_BOX(brand_vbox), title_lbl);
    gtk_box_append(GTK_BOX(brand_vbox), sub_lbl);
    gtk_box_append(GTK_BOX(top_bar), brand_vbox);

    GtkWidget *spacer = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_widget_set_hexpand(spacer, TRUE);
    gtk_box_append(GTK_BOX(top_bar), spacer);

    ui->target_badge = gtk_label_new("Target Attack: All Scenarios");
    gtk_widget_add_css_class(ui->target_badge, "status-badge");
    gtk_widget_add_css_class(ui->target_badge, "status-idle");
    gtk_box_append(GTK_BOX(top_bar), ui->target_badge);

    ui->status_badge = gtk_label_new("LAB READY (IDLE)");
    gtk_widget_add_css_class(ui->status_badge, "status-badge");
    gtk_widget_add_css_class(ui->status_badge, "status-idle");
    gtk_box_append(GTK_BOX(top_bar), ui->status_badge);

    ui->btn_run = gtk_button_new_with_label("Launch Attack");
    gtk_widget_add_css_class(ui->btn_run, "btn-primary");
    g_signal_connect(ui->btn_run, "clicked", G_CALLBACK(on_run_clicked), ui);
    gtk_box_append(GTK_BOX(top_bar), ui->btn_run);

    ui->btn_run_all = gtk_button_new_with_label("Full Evaluation");
    gtk_widget_add_css_class(ui->btn_run_all, "btn-outline");
    g_signal_connect(ui->btn_run_all, "clicked", G_CALLBACK(on_run_all_clicked), ui);
    gtk_box_append(GTK_BOX(top_bar), ui->btn_run_all);

    ui->btn_stop = gtk_button_new_with_label("Abort Attack");
    gtk_widget_add_css_class(ui->btn_stop, "btn-emergency");
    gtk_widget_set_sensitive(ui->btn_stop, FALSE);
    g_signal_connect(ui->btn_stop, "clicked", G_CALLBACK(on_stop_clicked), ui);
    gtk_box_append(GTK_BOX(top_bar), ui->btn_stop);

    ui->btn_open_report = gtk_button_new_with_label("View PDF Report");
    gtk_widget_add_css_class(ui->btn_open_report, "btn-report");
    g_signal_connect(ui->btn_open_report, "clicked", G_CALLBACK(on_open_report_clicked), ui);
    gtk_box_append(GTK_BOX(top_bar), ui->btn_open_report);

    gtk_box_append(GTK_BOX(root_vbox), top_bar);

    /* ── Main Split View ────────────────────────────────────────────── */
    GtkWidget *paned = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_paned_set_position(GTK_PANED(paned), 470);
    gtk_widget_set_vexpand(paned, TRUE);
    gtk_box_append(GTK_BOX(root_vbox), paned);

    /* ── Left Control Panel (Config & Attack Catalog) ──────────────── */
    GtkWidget *left_panel = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_add_css_class(left_panel, "left-panel");

    GtkWidget *left_scroll = gtk_scrolled_window_new();
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(left_scroll), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(left_scroll), left_panel);
    gtk_paned_set_start_child(GTK_PANED(paned), left_scroll);

    /* Parameters Card */
    GtkWidget *lbl_param_sec = gtk_label_new("Target Environment & Cryptographic Suite");
    gtk_widget_add_css_class(lbl_param_sec, "panel-section-title");
    gtk_label_set_xalign(GTK_LABEL(lbl_param_sec), 0.0);
    gtk_box_append(GTK_BOX(left_panel), lbl_param_sec);

    GtkWidget *param_card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_add_css_class(param_card, "param-card");

    /* Target IP Entry */
    GtkWidget *ip_label = gtk_label_new("Target Host IP Address:");
    gtk_widget_add_css_class(ip_label, "param-label");
    gtk_label_set_xalign(GTK_LABEL(ip_label), 0.0);
    gtk_box_append(GTK_BOX(param_card), ip_label);

    ui->entry_target_ip = gtk_entry_new();
    gtk_editable_set_text(GTK_EDITABLE(ui->entry_target_ip), "127.0.0.1");
    gtk_box_append(GTK_BOX(param_card), ui->entry_target_ip);

    /* Quick Preset Buttons */
    GtkWidget *presets_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *p1 = gtk_button_new_with_label("127.0.0.1 (Loopback)");
    gtk_widget_add_css_class(p1, "btn-outline");
    g_signal_connect(p1, "clicked", G_CALLBACK(on_target_preset_clicked), ui);

    GtkWidget *p2 = gtk_button_new_with_label("10.58.4.191 (LAN)");
    gtk_widget_add_css_class(p2, "btn-outline");
    g_signal_connect(p2, "clicked", G_CALLBACK(on_target_preset_clicked), ui);

    GtkWidget *p3 = gtk_button_new_with_label("100.113.83.56 (VPN)");
    gtk_widget_add_css_class(p3, "btn-outline");
    g_signal_connect(p3, "clicked", G_CALLBACK(on_target_preset_clicked), ui);

    gtk_box_append(GTK_BOX(presets_box), p1);
    gtk_box_append(GTK_BOX(presets_box), p2);
    gtk_box_append(GTK_BOX(presets_box), p3);
    gtk_box_append(GTK_BOX(param_card), presets_box);

    /* Target Port & Environment */
    GtkWidget *row_port_env = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *vbox_port = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *port_lbl = gtk_label_new("Port:");
    gtk_widget_add_css_class(port_lbl, "param-label");
    gtk_label_set_xalign(GTK_LABEL(port_lbl), 0.0);
    ui->entry_target_port = gtk_entry_new();
    gtk_editable_set_text(GTK_EDITABLE(ui->entry_target_port), "9877");
    gtk_box_append(GTK_BOX(vbox_port), port_lbl);
    gtk_box_append(GTK_BOX(vbox_port), ui->entry_target_port);

    GtkWidget *vbox_env = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *env_lbl = gtk_label_new("Network Topology:");
    gtk_widget_add_css_class(env_lbl, "param-label");
    gtk_label_set_xalign(GTK_LABEL(env_lbl), 0.0);
    const char * const env_items[] = { "Same LAN (Direct)", "Controlled Gateway (Proxy 9880)", "Private VPN (Tailscale)", NULL };
    ui->dropdown_env = gtk_drop_down_new_from_strings(env_items);
    gtk_box_append(GTK_BOX(vbox_env), env_lbl);
    gtk_box_append(GTK_BOX(vbox_env), ui->dropdown_env);

    gtk_widget_set_hexpand(vbox_env, TRUE);
    gtk_box_append(GTK_BOX(row_port_env), vbox_port);
    gtk_box_append(GTK_BOX(row_port_env), vbox_env);
    gtk_box_append(GTK_BOX(param_card), row_port_env);

    /* Cryptographic Suite Selector */
    GtkWidget *suite_lbl = gtk_label_new("Cryptographic Implementation Under Test:");
    gtk_widget_add_css_class(suite_lbl, "param-label");
    gtk_label_set_xalign(GTK_LABEL(suite_lbl), 0.0);
    gtk_box_append(GTK_BOX(param_card), suite_lbl);

    const char * const suite_items[] = {
        "Pure Post-Quantum (ML-KEM-768 + ML-DSA-65)",
        "Hybrid Quantum-Safe (Dual X25519/ML-KEM + Ed25519/ML-DSA)",
        "Classical IoT (X25519 + Ed25519 + AES-128-CCM)",
        "All 3 Suites (Comparative Benchmark Run)",
        NULL
    };
    ui->dropdown_suite = gtk_drop_down_new_from_strings(suite_items);
    g_signal_connect(ui->dropdown_suite, "notify::selected", G_CALLBACK(on_suite_changed), ui);
    gtk_box_append(GTK_BOX(param_card), ui->dropdown_suite);

    /* Dry Run Toggle */
    GtkWidget *dry_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *dry_lbl = gtk_label_new("Dry-Run Safety Mode (Audit without transmission):");
    gtk_widget_add_css_class(dry_lbl, "param-label");
    gtk_widget_set_hexpand(dry_lbl, TRUE);
    gtk_label_set_xalign(GTK_LABEL(dry_lbl), 0.0);

    ui->switch_dry_run = gtk_switch_new();
    gtk_switch_set_active(GTK_SWITCH(ui->switch_dry_run), FALSE);

    gtk_box_append(GTK_BOX(dry_box), dry_lbl);
    gtk_box_append(GTK_BOX(dry_box), ui->switch_dry_run);
    gtk_box_append(GTK_BOX(param_card), dry_box);

    gtk_box_append(GTK_BOX(left_panel), param_card);

    /* Attack Scenario Selection List */
    GtkWidget *lbl_scen_sec = gtk_label_new("Select Threat Vector / Security Scenario");
    gtk_widget_add_css_class(lbl_scen_sec, "panel-section-title");
    gtk_label_set_xalign(GTK_LABEL(lbl_scen_sec), 0.0);
    gtk_box_append(GTK_BOX(left_panel), lbl_scen_sec);

    ui->scenario_list_box = gtk_list_box_new();
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(ui->scenario_list_box), GTK_SELECTION_SINGLE);
    g_signal_connect(ui->scenario_list_box, "row-selected", G_CALLBACK(on_scenario_selected), ui);

    for (size_t i = 0; i < SCENARIO_COUNT; i++) {
        GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
        gtk_widget_add_css_class(row, "scenario-row");

        /* Clean text badge tag without emojis */
        GtkWidget *tag_lbl = gtk_label_new(G_SCENARIOS[i].tag);
        gtk_widget_add_css_class(tag_lbl, "scenario-tag");
        gtk_label_set_xalign(GTK_LABEL(tag_lbl), 0.5);
        gtk_box_append(GTK_BOX(row), tag_lbl);

        GtkWidget *text_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
        GtkWidget *name_lbl = gtk_label_new(G_SCENARIOS[i].name);
        gtk_widget_add_css_class(name_lbl, "scenario-name");
        gtk_label_set_xalign(GTK_LABEL(name_lbl), 0.0);

        GtkWidget *desc_lbl = gtk_label_new(G_SCENARIOS[i].description);
        gtk_widget_add_css_class(desc_lbl, "scenario-desc");
        gtk_label_set_xalign(GTK_LABEL(desc_lbl), 0.0);

        gtk_box_append(GTK_BOX(text_vbox), name_lbl);
        gtk_box_append(GTK_BOX(text_vbox), desc_lbl);
        gtk_box_append(GTK_BOX(row), text_vbox);

        gtk_list_box_append(GTK_LIST_BOX(ui->scenario_list_box), row);
    }

    gtk_box_append(GTK_BOX(left_panel), ui->scenario_list_box);

    /* ── Right Panel: Real-Time Terminal & Results Matrix ───────────── */
    GtkWidget *right_panel = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_add_css_class(right_panel, "right-panel");
    gtk_paned_set_end_child(GTK_PANED(paned), right_panel);

    /* Top Half: Live Streaming Terminal Console */
    GtkWidget *lbl_console_title = gtk_label_new("Live Attack Console & Transmission Stream");
    gtk_widget_add_css_class(lbl_console_title, "panel-section-title");
    gtk_label_set_xalign(GTK_LABEL(lbl_console_title), 0.0);
    gtk_box_append(GTK_BOX(right_panel), lbl_console_title);

    ui->console_scrolled = gtk_scrolled_window_new();
    gtk_widget_add_css_class(ui->console_scrolled, "console-container");
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(ui->console_scrolled), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(ui->console_scrolled, TRUE);

    ui->console_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(ui->console_view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(ui->console_view), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(ui->console_view), GTK_WRAP_WORD_CHAR);
    gtk_widget_add_css_class(ui->console_view, "console-text");

    ui->console_buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(ui->console_view));
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(ui->console_scrolled), ui->console_view);
    gtk_box_append(GTK_BOX(right_panel), ui->console_scrolled);

    /* Welcome message in console */
    gtk_text_buffer_set_text(ui->console_buf,
        "========================================================================\n"
        "  QRYPTONEX Real-Network Security Evaluation & Resilience Lab\n"
        "  Evaluation engine ready. Monitoring Classical, Hybrid, and Pure PQC.\n"
        "========================================================================\n"
        "Select target IP and attack scenario, then click 'Launch Attack'.\n", -1);

    /* Bottom Half: Results & Resilience Matrix */
    GtkWidget *res_head_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    GtkWidget *lbl_res_title = gtk_label_new("Evaluation Matrix & Security Results");
    gtk_widget_add_css_class(lbl_res_title, "panel-section-title");
    gtk_label_set_xalign(GTK_LABEL(lbl_res_title), 0.0);
    gtk_widget_set_hexpand(lbl_res_title, TRUE);

    ui->lbl_summary_count = gtk_label_new("0 Passed | 0 Failed");
    gtk_widget_add_css_class(ui->lbl_summary_count, "metric-val");

    ui->lbl_summary_status = gtk_label_new("AWAITING RUN");
    gtk_widget_add_css_class(ui->lbl_summary_status, "status-badge");
    gtk_widget_add_css_class(ui->lbl_summary_status, "status-idle");

    gtk_box_append(GTK_BOX(res_head_box), lbl_res_title);
    gtk_box_append(GTK_BOX(res_head_box), ui->lbl_summary_count);
    gtk_box_append(GTK_BOX(res_head_box), ui->lbl_summary_status);
    gtk_box_append(GTK_BOX(right_panel), res_head_box);

    GtkWidget *res_scroll = gtk_scrolled_window_new();
    gtk_widget_set_size_request(res_scroll, -1, 280);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(res_scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(res_scroll, TRUE);

    ui->results_list_box = gtk_list_box_new();
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(ui->results_list_box), GTK_SELECTION_NONE);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(res_scroll), ui->results_list_box);
    gtk_box_append(GTK_BOX(right_panel), res_scroll);

    /* Present Window */
    gtk_window_present(GTK_WINDOW(ui->window));
}
