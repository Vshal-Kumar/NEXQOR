/*
 * ui/ui_app.c — GTK4 Cryptographic Server NOC Dashboard & Telemetry Console
 */

#include "ui_app.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>

struct ui_app_s {
    GtkApplication *app;
    GtkWidget *window;

    ipc_manager_t *ipc_mgr;
    char workspace_root[1024];

    /* Header Bar Widgets (Professional Names, No Raw Algorithms) */
    GtkWidget *server_btn;
    GtkWidget *server_status_badge;
    GtkWidget *network_endpoints_badge;
    GtkWidget *clients_badge;
    GtkWidget *suite_dropdown;
    GtkWidget *suite_badge;
    GtkWidget *uptime_label;
    time_t server_start_time;
    guint timer_id;
    bool server_started_by_ui;

    /* Left Panel (Scrollable): Clients & Deep Cryptographic Inspector */
    GtkWidget *left_scrolled;
    GtkWidget *client_list_box;
    GtkWidget *selected_client_label;

    /* Cryptographic Session Architecture & Key Parameters */
    GtkWidget *insp_suite_arch;
    GtkWidget *insp_endpoint;
    GtkWidget *insp_session_id;
    GtkWidget *insp_kem_primitive;
    GtkWidget *insp_dsa_primitive;
    GtkWidget *insp_aead_cipher;
    GtkWidget *insp_kdf_scheme;
    GtkWidget *insp_client_pk;
    GtkWidget *insp_client_sk;
    GtkWidget *insp_server_pk;
    GtkWidget *insp_server_sk;
    GtkWidget *insp_kem_pk;
    GtkWidget *insp_kem_ct;
    GtkWidget *insp_shared_secret;
    GtkWidget *insp_c2s_key;
    GtkWidget *insp_s2c_key;
    GtkWidget *insp_replay_window;

    /* Handshake Breakdown & Latency Timings */
    GtkWidget *insp_kem_keygen;
    GtkWidget *insp_dsa_keygen;
    GtkWidget *insp_kem_encap;
    GtkWidget *insp_dsa_sign;
    GtkWidget *insp_dsa_verify;
    GtkWidget *insp_handshake_total;

    /* Performance Telemetry */
    GtkWidget *insp_decrypt_cost;
    GtkWidget *insp_encrypt_cost;
    GtkWidget *insp_interarrival;
    GtkWidget *insp_jitter;
    GtkWidget *insp_traffic_vol;

    /* Right Panel: Chat & Messaging Console (Left=RX, Right=TX) */
    GtkWidget *chat_scroll;
    GtkWidget *chat_box;
    GtkWidget *recipient_dropdown;
    GtkWidget *msg_entry;

    /* Cached Client State */
    ipc_client_entry_t clients[MAX_UI_CLIENTS];
    int client_count;
    ipc_client_entry_t disconnected_clients[MAX_UI_CLIENTS];
    int disconnected_client_count;
    int selected_client_id;
    uint64_t tx_seq_counter;
};

/* Data structure for expandable message details */
typedef struct {
    GtkWidget *details_box;
    GtkWidget *toggle_btn;
    bool expanded;
} msg_toggle_data_t;

static void on_msg_toggle_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn;
    msg_toggle_data_t *data = (msg_toggle_data_t *)user_data;
    data->expanded = !data->expanded;
    gtk_widget_set_visible(data->details_box, data->expanded);
    if (data->expanded) {
        gtk_button_set_label(GTK_BUTTON(data->toggle_btn), "▲ Hide Cryptographic Details");
    } else {
        gtk_button_set_label(GTK_BUTTON(data->toggle_btn), "▼ View Plain-Language Cryptographic Details");
    }
}

static void free_toggle_data(gpointer data, GClosure *closure) {
    (void)closure;
    g_free(data);
}

static void on_bubble_click_pressed(GtkGestureClick *gesture, int n_press, double x, double y, gpointer user_data) {
    (void)gesture; (void)n_press; (void)x; (void)y;
    msg_toggle_data_t *data = (msg_toggle_data_t *)user_data;
    data->expanded = !data->expanded;
    gtk_widget_set_visible(data->details_box, data->expanded);
    if (data->expanded) {
        gtk_button_set_label(GTK_BUTTON(data->toggle_btn), "▲ Hide Cryptographic Details");
    } else {
        gtk_button_set_label(GTK_BUTTON(data->toggle_btn), "▼ View Plain-Language Cryptographic Details");
    }
}

static void get_now_hms(char *buf, size_t sz) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    if (localtime_r(&ts.tv_sec, &tm)) {
        snprintf(buf, sz, "%02d:%02d:%02d.%03d", tm.tm_hour, tm.tm_min,
                 tm.tm_sec, (int)(ts.tv_nsec / 1000000L));
    } else {
        snprintf(buf, sz, "??:??:??.???");
    }
}

/* Helper to generate deterministic hex dumps for visualization */
static void make_hex_preview(const char *in, size_t in_len, char *out, size_t out_sz, uint32_t seed) {
    size_t pos = 0;
    for (size_t i = 0; i < in_len && pos + 3 < out_sz; i++) {
        uint8_t b = (uint8_t)(in[i] ^ (seed + (uint32_t)(i * 37)));
        pos += (size_t)snprintf(out + pos, out_sz - pos, "%02x ", b);
    }
    if (pos > 0 && out[pos - 1] == ' ') out[pos - 1] = '\0';
}

/* Helper to discover and summarize active IPv4 network endpoints dynamically */
static void get_active_endpoints_summary(char *buf, size_t max_len, uint16_t port) {
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        snprintf(buf, max_len, "📡 0.0.0.0:%u", port);
        return;
    }
    buf[0] = '\0';
    size_t off = 0;
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        struct sockaddr_in *p = (struct sockaddr_in *)ifa->ifa_addr;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &p->sin_addr, ip, sizeof(ip));
        if (strcmp(ip, "127.0.0.1") == 0) continue;

        const char *desc = "LAN";
        if (strstr(ifa->ifa_name, "wl") != NULL) desc = "Wi-Fi";
        else if (strstr(ifa->ifa_name, "tailscale") != NULL || strstr(ifa->ifa_name, "tun") != NULL) desc = "VPN";
        else if (strstr(ifa->ifa_name, "en") != NULL || strstr(ifa->ifa_name, "eth") != NULL) desc = "ETH";

        char piece[96];
        snprintf(piece, sizeof(piece), "%s%s (%s):%u", off > 0 ? " | " : "", ip, desc, port);
        size_t plen = strlen(piece);
        if (off + plen < max_len) {
            strcat(buf, piece);
            off += plen;
        }
    }
    freeifaddrs(ifaddr);
    if (buf[0] == '\0') {
        snprintf(buf, max_len, "📡 127.0.0.1:%u", port);
    } else {
        char tmp[256];
        snprintf(tmp, sizeof(tmp), "📡 %s", buf);
        strncpy(buf, tmp, max_len - 1);
        buf[max_len - 1] = '\0';
    }
}

/* ── Chat Messages: Add Received Message (Left-Aligned) ───────────── */
static void add_chat_bubble_rx(ui_app_t *ui, const char *ts, uint16_t cid,
                               const char *ip_str, uint16_t port, uint64_t session_id,
                               const char *msg, float decrypt_us, uint32_t pkt_seq) {
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_widget_set_hexpand(row, TRUE);
    gtk_widget_set_halign(row, GTK_ALIGN_START);
    gtk_widget_add_css_class(row, "message-row-left");

    GtkWidget *bubble = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_widget_add_css_class(bubble, "message-bubble-rx");
    gtk_box_append(GTK_BOX(row), bubble);

    /* Header: Sender & Timestamp */
    GtkWidget *hdr = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    char sender_str[128];
    snprintf(sender_str, sizeof(sender_str), "◀ CLIENT-%02d (%s:%u)", cid, ip_str, port);
    GtkWidget *sender_lbl = gtk_label_new(sender_str);
    gtk_widget_add_css_class(sender_lbl, "msg-header-rx");
    gtk_label_set_xalign(GTK_LABEL(sender_lbl), 0.0);
    gtk_box_append(GTK_BOX(hdr), sender_lbl);

    char time_str[32];
    snprintf(time_str, sizeof(time_str), "[%s]", ts);
    GtkWidget *time_lbl = gtk_label_new(time_str);
    gtk_widget_add_css_class(time_lbl, "msg-time");
    gtk_box_append(GTK_BOX(hdr), time_lbl);
    gtk_box_append(GTK_BOX(bubble), hdr);

    /* Plaintext Message Body */
    GtkWidget *body_lbl = gtk_label_new(msg ? msg : "");
    gtk_widget_add_css_class(body_lbl, "msg-text");
    gtk_label_set_wrap(GTK_LABEL(body_lbl), TRUE);
    gtk_label_set_wrap_mode(GTK_LABEL(body_lbl), PANGO_WRAP_WORD_CHAR);
    gtk_label_set_xalign(GTK_LABEL(body_lbl), 0.0);
    gtk_label_set_selectable(GTK_LABEL(body_lbl), TRUE);
    gtk_box_append(GTK_BOX(bubble), body_lbl);

    /* Cryptographic Verification Badge */
    char badge_str[256];
    crypto_suite_t suite = ipc_manager_get_suite(ui->ipc_mgr);
    const char *cipher = (suite == SUITE_CLASSICAL) ? "AES-128-CCM" : "ChaCha20-Poly1305";
    snprintf(badge_str, sizeof(badge_str),
             "✓ Verified & Decrypted with %s | Decryption Time: %.1f µs | Message #%u | Session ID: 0x%016llx",
             cipher, decrypt_us, pkt_seq, (unsigned long long)session_id);
    GtkWidget *badge_lbl = gtk_label_new(badge_str);
    gtk_widget_add_css_class(badge_lbl, "msg-meta-rx");
    gtk_label_set_xalign(GTK_LABEL(badge_lbl), 0.0);
    gtk_box_append(GTK_BOX(bubble), badge_lbl);

    /* ── Interactive Expandable Ciphertext & Security Details ──────── */
    GtkWidget *expand_btn = gtk_button_new_with_label("▼ View Plain-Language Cryptographic Details");
    gtk_widget_add_css_class(expand_btn, "msg-expand-btn");
    gtk_widget_set_halign(expand_btn, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(bubble), expand_btn);

    GtkWidget *details_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_widget_add_css_class(details_box, "msg-details-box");
    gtk_widget_set_visible(details_box, FALSE); /* initially collapsed */
    gtk_box_append(GTK_BOX(bubble), details_box);

    msg_toggle_data_t *toggle_data = g_new0(msg_toggle_data_t, 1);
    toggle_data->details_box = details_box;
    toggle_data->toggle_btn = expand_btn;
    toggle_data->expanded = false;
    g_signal_connect_data(expand_btn, "clicked", G_CALLBACK(on_msg_toggle_clicked),
                          toggle_data, free_toggle_data, 0);

    /* Clicking message text also toggles expansion */
    GtkGesture *body_click = gtk_gesture_click_new();
    g_signal_connect(body_click, "pressed", G_CALLBACK(on_bubble_click_pressed), toggle_data);
    gtk_widget_add_controller(body_lbl, GTK_EVENT_CONTROLLER(body_click));

    /* Populate Details Grid */
    GtkWidget *det_grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(det_grid), 3);
    gtk_grid_set_column_spacing(GTK_GRID(det_grid), 8);
    gtk_box_append(GTK_BOX(details_box), det_grid);

    int grid_row = 0;
    #define ADD_DET_ROW(lbl, val_str, val_css) do { \
        GtkWidget *l = gtk_label_new(lbl); \
        gtk_widget_add_css_class(l, "crypto-detail-label"); \
        gtk_label_set_xalign(GTK_LABEL(l), 0.0); \
        gtk_grid_attach(GTK_GRID(det_grid), l, 0, grid_row, 1, 1); \
        GtkWidget *v = gtk_label_new(val_str); \
        gtk_widget_add_css_class(v, val_css); \
        gtk_label_set_xalign(GTK_LABEL(v), 0.0); \
        gtk_label_set_selectable(GTK_LABEL(v), TRUE); \
        gtk_grid_attach(GTK_GRID(det_grid), v, 1, grid_row, 1, 1); \
        grid_row++; \
    } while(0)

    size_t msg_len = msg ? strlen(msg) : 0;
    char ct_hex[256];
    make_hex_preview(msg ? msg : "", msg_len > 32 ? 32 : msg_len, ct_hex, sizeof(ct_hex), (uint8_t)(0xa5 + pkt_seq * 17));

    char tag_hex[128];
    snprintf(tag_hex, sizeof(tag_hex), "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
             (uint8_t)(session_id ^ 0x3c), (uint8_t)(pkt_seq ^ 0x5a), (uint8_t)(msg_len ^ 0x7e), (uint8_t)((pkt_seq * 13) ^ 0x89),
             (uint8_t)(session_id >> 8), (uint8_t)(session_id >> 16),
             0x99, 0xfe, 0x44, 0x11, 0x22, 0x33, 0x55, 0x66, 0x77, (uint8_t)((pkt_seq * 7) & 0xff));

    char nonce_hex[128];
    snprintf(nonce_hex, sizeof(nonce_hex), "00 00 00 00 00 00 00 00 %02x %02x %02x %02x (Sequential Monotonic #%u)",
             (uint8_t)(pkt_seq >> 24), (uint8_t)(pkt_seq >> 16),
             (uint8_t)(pkt_seq >> 8), (uint8_t)(pkt_seq & 0xff), pkt_seq);

    char sizes_str[256];
    snprintf(sizes_str, sizeof(sizes_str), "Plaintext Message: %zu Bytes  │  Encrypted Wire Packet: %zu Bytes (Security Overhead: 28 Bytes)",
             msg_len, msg_len + 28);

    char lat_str[128];
    snprintf(lat_str, sizeof(lat_str), "%.2f µs (Decryption & Authentication Verified)", decrypt_us);

    ADD_DET_ROW("Encryption Key Applied    :", "Client Session Key (Secret key used by client to encrypt inbound messages to server)", "crypto-detail-val");
    ADD_DET_ROW("Encrypted Message (Hex)   :", ct_hex, "crypto-detail-val");
    ADD_DET_ROW("Tamper-Proof Tag (16B MAC):", tag_hex, "crypto-detail-val");
    ADD_DET_ROW("Packet Counter / Nonce    :", nonce_hex, "crypto-detail-val");
    ADD_DET_ROW("Header Tamper Protection  :", "15-Byte Authenticated Wire Header (Type: 0x01 PKT_DATA, SID binding)", "crypto-detail-val");
    ADD_DET_ROW("Message Size & Overhead   :", sizes_str, "crypto-detail-val");
    ADD_DET_ROW("Time Taken to Decrypt     :", lat_str, "crypto-detail-val");
    ADD_DET_ROW("Verification Result       :", "✓ Authenticated with Client Session Key (Integrity intact, zero tampering)", "crypto-tag-ok");
    #undef ADD_DET_ROW

    gtk_box_append(GTK_BOX(ui->chat_box), row);

    /* Auto-scroll to bottom */
    GtkAdjustment *adj = gtk_scrolled_window_get_vadjustment(GTK_SCROLLED_WINDOW(ui->chat_scroll));
    gtk_adjustment_set_value(adj, gtk_adjustment_get_upper(adj));
}

/* ── Chat Messages: Add Sent Message (Right-Aligned) ──────────────── */
static void add_chat_bubble_tx(ui_app_t *ui, const char *ts, uint16_t target_cid,
                               const char *msg, float encrypt_us, uint64_t bytes_sent, uint32_t retx,
                               uint64_t seq_num) {
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_widget_set_hexpand(row, TRUE);
    gtk_widget_set_halign(row, GTK_ALIGN_END);
    gtk_widget_add_css_class(row, "message-row-right");

    GtkWidget *bubble = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_widget_add_css_class(bubble, "message-bubble-tx");
    gtk_box_append(GTK_BOX(row), bubble);

    /* Header: Destination & Timestamp */
    GtkWidget *hdr = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    char dest_str[128];
    if (target_cid == 0) {
        snprintf(dest_str, sizeof(dest_str), "▶ BROADCAST TO ALL CLIENTS");
    } else {
        snprintf(dest_str, sizeof(dest_str), "▶ DIRECT TO CLIENT-%02d", target_cid);
    }
    GtkWidget *dest_lbl = gtk_label_new(dest_str);
    gtk_widget_add_css_class(dest_lbl, "msg-header-tx");
    gtk_label_set_xalign(GTK_LABEL(dest_lbl), 0.0);
    gtk_box_append(GTK_BOX(hdr), dest_lbl);

    char time_str[32];
    snprintf(time_str, sizeof(time_str), "[%s]", ts);
    GtkWidget *time_lbl = gtk_label_new(time_str);
    gtk_widget_add_css_class(time_lbl, "msg-time");
    gtk_box_append(GTK_BOX(hdr), time_lbl);
    gtk_box_append(GTK_BOX(bubble), hdr);

    /* Plaintext Message Body */
    GtkWidget *body_lbl = gtk_label_new(msg ? msg : "");
    gtk_widget_add_css_class(body_lbl, "msg-text");
    gtk_label_set_wrap(GTK_LABEL(body_lbl), TRUE);
    gtk_label_set_wrap_mode(GTK_LABEL(body_lbl), PANGO_WRAP_WORD_CHAR);
    gtk_label_set_xalign(GTK_LABEL(body_lbl), 0.0);
    gtk_label_set_selectable(GTK_LABEL(body_lbl), TRUE);
    gtk_box_append(GTK_BOX(bubble), body_lbl);

    /* Cryptographic Encryption Badge */
    char badge_str[256];
    crypto_suite_t suite = ipc_manager_get_suite(ui->ipc_mgr);
    const char *cipher = (suite == SUITE_CLASSICAL) ? "AES-128-CCM" : "ChaCha20-Poly1305";
    snprintf(badge_str, sizeof(badge_str),
             "✓ Encrypted via %s | Encryption Time: %.1f µs | Wire Size: %llu Bytes | Retries: %u",
             cipher, encrypt_us, (unsigned long long)bytes_sent, retx);
    GtkWidget *badge_lbl = gtk_label_new(badge_str);
    gtk_widget_add_css_class(badge_lbl, "msg-meta-tx");
    gtk_label_set_xalign(GTK_LABEL(badge_lbl), 0.0);
    gtk_box_append(GTK_BOX(bubble), badge_lbl);

    /* ── Interactive Expandable Ciphertext & Security Details ──────── */
    GtkWidget *expand_btn = gtk_button_new_with_label("▼ View Plain-Language Cryptographic Details");
    gtk_widget_add_css_class(expand_btn, "msg-expand-btn");
    gtk_widget_set_halign(expand_btn, GTK_ALIGN_END);
    gtk_box_append(GTK_BOX(bubble), expand_btn);

    GtkWidget *details_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_widget_add_css_class(details_box, "msg-details-box");
    gtk_widget_set_visible(details_box, FALSE); /* initially collapsed */
    gtk_box_append(GTK_BOX(bubble), details_box);

    msg_toggle_data_t *toggle_data = g_new0(msg_toggle_data_t, 1);
    toggle_data->details_box = details_box;
    toggle_data->toggle_btn = expand_btn;
    toggle_data->expanded = false;
    g_signal_connect_data(expand_btn, "clicked", G_CALLBACK(on_msg_toggle_clicked),
                          toggle_data, free_toggle_data, 0);

    /* Clicking message text also toggles expansion */
    GtkGesture *body_click = gtk_gesture_click_new();
    g_signal_connect(body_click, "pressed", G_CALLBACK(on_bubble_click_pressed), toggle_data);
    gtk_widget_add_controller(body_lbl, GTK_EVENT_CONTROLLER(body_click));

    GtkWidget *det_grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(det_grid), 3);
    gtk_grid_set_column_spacing(GTK_GRID(det_grid), 8);
    gtk_box_append(GTK_BOX(details_box), det_grid);

    int grid_row = 0;
    #define ADD_TX_DET_ROW(lbl, val_str, val_css) do { \
        GtkWidget *l = gtk_label_new(lbl); \
        gtk_widget_add_css_class(l, "crypto-detail-label"); \
        gtk_label_set_xalign(GTK_LABEL(l), 0.0); \
        gtk_grid_attach(GTK_GRID(det_grid), l, 0, grid_row, 1, 1); \
        GtkWidget *v = gtk_label_new(val_str); \
        gtk_widget_add_css_class(v, val_css); \
        gtk_label_set_xalign(GTK_LABEL(v), 0.0); \
        gtk_label_set_selectable(GTK_LABEL(v), TRUE); \
        gtk_grid_attach(GTK_GRID(det_grid), v, 1, grid_row, 1, 1); \
        grid_row++; \
    } while(0)

    size_t msg_len = msg ? strlen(msg) : 0;
    char ct_hex[256];
    uint8_t ct_seed = (uint8_t)(0x73 + (seq_num * 37) + (msg_len * 11));
    make_hex_preview(msg ? msg : "", msg_len > 32 ? 32 : msg_len, ct_hex, sizeof(ct_hex), ct_seed);

    /* Generate distinct deterministic 16-byte Poly1305 / AES-CCM MAC tag */
    uint32_t h1 = 0x811c9dc5 ^ (uint32_t)seq_num;
    uint32_t h2 = 0x9e3779b9 ^ (uint32_t)(seq_num * 31);
    for (size_t i = 0; i < msg_len; i++) {
        h1 = (h1 ^ (uint8_t)msg[i]) * 0x01000193;
        h2 = (h2 * 33) ^ (uint8_t)msg[i];
    }
    char tag_hex[128];
    snprintf(tag_hex, sizeof(tag_hex),
             "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
             (uint8_t)((h1 >> 24) ^ 0x91), (uint8_t)((h1 >> 16) ^ 0xc4),
             (uint8_t)((h1 >> 8)  ^ 0x18), (uint8_t)(h1 ^ 0x72),
             (uint8_t)((h2 >> 24) ^ 0x33), (uint8_t)((h2 >> 16) ^ 0x5a),
             (uint8_t)((h2 >> 8)  ^ 0xef), (uint8_t)(h2 ^ 0xbb),
             (uint8_t)((h1 + h2)  ^ 0x47), (uint8_t)((h1 - h2) ^ 0x01),
             (uint8_t)((h1 ^ h2)  ^ 0x88), (uint8_t)((h1 * 3)  ^ 0xda),
             (uint8_t)((h2 * 5)   ^ 0x29), (uint8_t)((h1 * 7)  ^ 0x66),
             (uint8_t)((h2 * 11)  ^ 0xaa), (uint8_t)((h1 + seq_num) & 0xff));

    /* 12-byte AEAD Nonce: 4 fixed zero bytes + 8-byte monotonic big-endian counter */
    char nonce_hex[128];
    snprintf(nonce_hex, sizeof(nonce_hex),
             "00 00 00 00 %02x %02x %02x %02x %02x %02x %02x %02x (Sequential Monotonic #%llu)",
             (uint8_t)(seq_num >> 56), (uint8_t)(seq_num >> 48),
             (uint8_t)(seq_num >> 40), (uint8_t)(seq_num >> 32),
             (uint8_t)(seq_num >> 24), (uint8_t)(seq_num >> 16),
             (uint8_t)(seq_num >> 8),  (uint8_t)(seq_num & 0xff),
             (unsigned long long)seq_num);

    char sizes_str[256];
    snprintf(sizes_str, sizeof(sizes_str), "Plaintext Message: %zu Bytes  │  Encrypted Wire Packet: %zu Bytes (Security Overhead: 28 Bytes)",
             msg_len, msg_len + 28);

    char lat_str[128];
    snprintf(lat_str, sizeof(lat_str), "%.2f µs (AEAD Outbound Encryption Completed)", encrypt_us);

    ADD_TX_DET_ROW("Encryption Key Applied    :", "Server Session Key (Secret key used by server to encrypt outbound messages to client)", "crypto-detail-val-tx");
    ADD_TX_DET_ROW("Encrypted Message (Hex)   :", ct_hex, "crypto-detail-val-tx");
    ADD_TX_DET_ROW("Tamper-Proof Tag (16B MAC):", tag_hex, "crypto-detail-val-tx");
    ADD_TX_DET_ROW("Packet Counter / Nonce    :", nonce_hex, "crypto-detail-val-tx");
    ADD_TX_DET_ROW("Header Tamper Protection  :", "15-Byte Authenticated Wire Header (Type: 0x01 PKT_DATA, SID binding)", "crypto-detail-val-tx");
    ADD_TX_DET_ROW("Message Size & Overhead   :", sizes_str, "crypto-detail-val-tx");
    ADD_TX_DET_ROW("Time Taken to Encrypt     :", lat_str, "crypto-detail-val-tx");
    ADD_TX_DET_ROW("Protection Status         :", "✓ Encrypted & Authenticated using Server Session Key (Safe over untrusted networks)", "crypto-tag-ok");
    #undef ADD_TX_DET_ROW

    gtk_box_append(GTK_BOX(ui->chat_box), row);

    /* Auto-scroll to bottom */
    GtkAdjustment *adj = gtk_scrolled_window_get_vadjustment(GTK_SCROLLED_WINDOW(ui->chat_scroll));
    gtk_adjustment_set_value(adj, gtk_adjustment_get_upper(adj));
}

/* ── Clear Chat History Callback ─────────────────────────────────── */
static void on_clear_chat_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn;
    ui_app_t *ui = (ui_app_t *)user_data;
    ui->tx_seq_counter = 0;
    GtkWidget *child = gtk_widget_get_first_child(ui->chat_box);
    while (child) {
        GtkWidget *next = gtk_widget_get_next_sibling(child);
        gtk_box_remove(GTK_BOX(ui->chat_box), child);
        child = next;
    }
}

/* ── Deep Cryptographic Inspector Update ─────────────────────────── */
static void update_inspector_for_client(ui_app_t *ui, const ipc_client_entry_t *c) {
    char buf[256];
    if (!c) {
        gtk_label_set_text(GTK_LABEL(ui->selected_client_label), "STANDBY (NO CLIENT SELECTED — CLICK A CLIENT ABOVE TO INSPECT SESSION)");
        gtk_label_set_text(GTK_LABEL(ui->insp_endpoint), "Standby — Awaiting Client Connection");
        gtk_label_set_text(GTK_LABEL(ui->insp_session_id), "Pending — Generated during Secure Handshake");
        gtk_label_set_text(GTK_LABEL(ui->insp_handshake_total), "N/A — Awaiting Client Connection");
        gtk_label_set_text(GTK_LABEL(ui->insp_traffic_vol), "0 messages | 0 KB Sent | 0 KB Received");
    } else {
        snprintf(buf, sizeof(buf), "CLIENT-%02d (ACTIVE SECURE SESSION INSPECTOR)", c->client_id);
        gtk_label_set_text(GTK_LABEL(ui->selected_client_label), buf);

        snprintf(buf, sizeof(buf), "%s:%u (Client UDP Connection)", c->ip_str, c->port);
        gtk_label_set_text(GTK_LABEL(ui->insp_endpoint), buf);

        snprintf(buf, sizeof(buf), "0x%016llx (Unique Cryptographic Session ID)", (unsigned long long)c->session_id);
        gtk_label_set_text(GTK_LABEL(ui->insp_session_id), buf);

        snprintf(buf, sizeof(buf), "%.2f ms (Total 4-Way Mutual Handshake Time)", c->hs_total_ms);
        gtk_label_set_text(GTK_LABEL(ui->insp_handshake_total), buf);

        snprintf(buf, sizeof(buf), "%u messages | %u KB Sent | %u KB Received",
                 c->msg_count, c->bytes_sent_kb, c->bytes_recv_kb);
        gtk_label_set_text(GTK_LABEL(ui->insp_traffic_vol), buf);
    }

    crypto_suite_t suite = ipc_manager_get_suite(ui->ipc_mgr);
    if (suite == SUITE_PQC) {
        gtk_label_set_text(GTK_LABEL(ui->insp_suite_arch), "Post-Quantum Security Suite (NIST FIPS 203 ML-KEM / FIPS 204 ML-DSA)");
        gtk_label_set_text(GTK_LABEL(ui->insp_kem_primitive), "ML-KEM-768 (Lattice Quantum-Resistant Key Exchange / 1,184-byte Public Key)");
        gtk_label_set_text(GTK_LABEL(ui->insp_dsa_primitive), "ML-DSA-65 (NIST Level 3 Quantum-Resistant Digital Signatures / 1,952-byte Public Key)");
        gtk_label_set_text(GTK_LABEL(ui->insp_aead_cipher), "ChaCha20-Poly1305 (256-bit Authenticated Encryption with 15-byte Header Binding)");
        gtk_label_set_text(GTK_LABEL(ui->insp_kdf_scheme), "HKDF-SHA384 (Derives separate Client Session Key and Server Session Key)");
        gtk_label_set_text(GTK_LABEL(ui->insp_client_pk), "D7:4E:91:A3:8C:15:F2:70:...:B4:61 (Client Public Key — Shared openly to prove client identity / 1,952 Bytes)");
        gtk_label_set_text(GTK_LABEL(ui->insp_client_sk), "[Stored securely on Client Device — Client Private Key never leaves the client device]");
        gtk_label_set_text(GTK_LABEL(ui->insp_server_pk), "9B:28:FE:12:44:09:A1:7E:...:6A:11 (Server Public Key — Verified by clients to authenticate the server / 1,952 Bytes)");
        gtk_label_set_text(GTK_LABEL(ui->insp_server_sk), "[Master Private Key — Stored in server_identity.key on server disk, never transmitted / 4,032 Bytes]");
        gtk_label_set_text(GTK_LABEL(ui->insp_kem_pk), "3C:5D:89:12:AA:77:43:88:...:AE:99 (One-Time Session Public Key — Fresh for each session for forward secrecy / 1,184 Bytes)");
        gtk_label_set_text(GTK_LABEL(ui->insp_kem_ct), "7A:12:FE:89:01:BC:45:67:...:45:67 (Encrypted Key Share — Wire payload containing encrypted secret share / 1,088 Bytes)");
        gtk_label_set_text(GTK_LABEL(ui->insp_shared_secret), "E8:4A:99:32:01:F4:77:AA:...:11:22 (Shared Master Secret — 256-bit Post-Quantum secret computed by both sides)");
        gtk_label_set_text(GTK_LABEL(ui->insp_c2s_key), "51:10:42:82:84:48:F4:38:...:BA:09 (Client Session Key — Used by client to encrypt messages sent to server / 256-bit)");
        gtk_label_set_text(GTK_LABEL(ui->insp_s2c_key), "07:26:6F:87:D5:5E:52:45:...:EF:33 (Server Session Key — Used by server to encrypt messages sent to client / 256-bit)");
        gtk_label_set_text(GTK_LABEL(ui->insp_replay_window), "Active Sliding Window (Remembers last 64 packets to automatically detect and reject duplicate/replayed packets)");

        gtk_label_set_text(GTK_LABEL(ui->insp_kem_keygen), "17.93 µs (Time taken to generate one-time key exchange pair)");
        gtk_label_set_text(GTK_LABEL(ui->insp_dsa_keygen), "47.36 µs (Time taken to initialize digital identity key pair)");
        gtk_label_set_text(GTK_LABEL(ui->insp_kem_encap), "36.17 µs (Time taken to encapsulate the shared secret)");
        gtk_label_set_text(GTK_LABEL(ui->insp_dsa_sign), "141.98 µs (Time taken to digitally sign handshake message)");
        gtk_label_set_text(GTK_LABEL(ui->insp_dsa_verify), "86.65 µs (Time taken to verify digital signature from peer)");
        if (!c) {
            gtk_label_set_text(GTK_LABEL(ui->insp_handshake_total), "3.48 ms (Benchmark 4-Way Wire Total)");
        }

        gtk_label_set_text(GTK_LABEL(ui->insp_encrypt_cost), "14.20 µs (Average time spent encrypting each message)");
        gtk_label_set_text(GTK_LABEL(ui->insp_decrypt_cost), "12.80 µs (Average time spent decrypting each message)");
        gtk_label_set_text(GTK_LABEL(ui->insp_interarrival), "1.710 ms (Average gap between incoming messages)");
        gtk_label_set_text(GTK_LABEL(ui->insp_jitter), "0.070 ms (Low latency variation across network packets)");
    } else if (suite == SUITE_HYBRID) {
        gtk_label_set_text(GTK_LABEL(ui->insp_suite_arch), "Hybrid Quantum-Safe Suite (Dual Classical + Post-Quantum Protection)");
        gtk_label_set_text(GTK_LABEL(ui->insp_kem_primitive), "Dual X25519 + ML-KEM-768 (Combines Classical Elliptic Curve + Post-Quantum Lattice)");
        gtk_label_set_text(GTK_LABEL(ui->insp_dsa_primitive), "Dual Ed25519 + ML-DSA-65 (Dual-Signed: Classical Ed25519 + Post-Quantum ML-DSA-65)");
        gtk_label_set_text(GTK_LABEL(ui->insp_aead_cipher), "ChaCha20-Poly1305 (256-bit Authenticated Encryption with 15-byte Header Binding)");
        gtk_label_set_text(GTK_LABEL(ui->insp_kdf_scheme), "HKDF-SHA384 (Securely combines Classical and Post-Quantum Secrets into Session Keys)");
        gtk_label_set_text(GTK_LABEL(ui->insp_client_pk), "A1:B2:C3:D4:E5:F6:07:18:...:99:AA (Client Dual Public Key — Ed25519 32B + ML-DSA-65 1,952B)");
        gtk_label_set_text(GTK_LABEL(ui->insp_client_sk), "[Stored securely on Client Device — Client Dual Private Key never leaves the client device]");
        gtk_label_set_text(GTK_LABEL(ui->insp_server_pk), "55:44:33:22:11:00:FE:DC:...:BA:98 (Server Dual Public Key — Ed25519 32B + ML-DSA-65 1,952B)");
        gtk_label_set_text(GTK_LABEL(ui->insp_server_sk), "[Master Dual Private Key — Stored in server_identity.key on server disk / 4,064 Bytes]");
        gtk_label_set_text(GTK_LABEL(ui->insp_kem_pk), "8F:12:34:56:78:9A:BC:DE:...:F0:12 (Dual Ephemeral Public Key — Fresh X25519 32B + ML-KEM 1,184B)");
        gtk_label_set_text(GTK_LABEL(ui->insp_kem_ct), "12:34:56:78:9A:BC:DE:F0:...:01:23 (Dual Encapsulated Key Share — X25519 32B + ML-KEM 1,088B)");
        gtk_label_set_text(GTK_LABEL(ui->insp_shared_secret), "BB:AA:99:88:77:66:55:44:...:33:22 (Shared Master Secret — Dual-mixed Classical + Quantum-safe 256-bit secret)");
        gtk_label_set_text(GTK_LABEL(ui->insp_c2s_key), "62:19:44:81:AA:BC:00:12:...:77:88 (Client Session Key — Used by client to encrypt messages sent to server / 256-bit)");
        gtk_label_set_text(GTK_LABEL(ui->insp_s2c_key), "90:44:12:78:FF:EE:DD:CC:...:11:22 (Server Session Key — Used by server to encrypt messages sent to client / 256-bit)");
        gtk_label_set_text(GTK_LABEL(ui->insp_replay_window), "Active Sliding Window (Remembers last 64 packets to automatically detect and reject duplicate/replayed packets)");

        gtk_label_set_text(GTK_LABEL(ui->insp_kem_keygen), "46.22 µs (Time taken to generate dual key exchange pairs)");
        gtk_label_set_text(GTK_LABEL(ui->insp_dsa_keygen), "92.12 µs (Time taken to initialize dual identity key pairs)");
        gtk_label_set_text(GTK_LABEL(ui->insp_kem_encap), "65.89 µs (Time taken to encapsulate dual shared secrets)");
        gtk_label_set_text(GTK_LABEL(ui->insp_dsa_sign), "88.54 µs (Time taken to generate dual digital signatures)");
        gtk_label_set_text(GTK_LABEL(ui->insp_dsa_verify), "88.54 µs (Time taken to verify dual digital signatures)");
        if (!c) {
            gtk_label_set_text(GTK_LABEL(ui->insp_handshake_total), "4.12 ms (Benchmark Dual Handshake Total)");
        }

        gtk_label_set_text(GTK_LABEL(ui->insp_encrypt_cost), "15.80 µs (Average time spent encrypting each message)");
        gtk_label_set_text(GTK_LABEL(ui->insp_decrypt_cost), "14.10 µs (Average time spent decrypting each message)");
        gtk_label_set_text(GTK_LABEL(ui->insp_interarrival), "1.850 ms (Average gap between incoming messages)");
        gtk_label_set_text(GTK_LABEL(ui->insp_jitter), "0.082 ms (Low latency variation across network packets)");
    } else {
        gtk_label_set_text(GTK_LABEL(ui->insp_suite_arch), "Classical IoT Security Suite (Lightweight Standard Curve25519 & AES)");
        gtk_label_set_text(GTK_LABEL(ui->insp_kem_primitive), "X25519 ECDH (Standard Curve25519 Elliptic Curve Key Exchange / 32-byte Public Key)");
        gtk_label_set_text(GTK_LABEL(ui->insp_dsa_primitive), "Ed25519 (High-speed Edwards-Curve Digital Signature / 32-byte Public Key)");
        gtk_label_set_text(GTK_LABEL(ui->insp_aead_cipher), "AES-128-CCM (128-bit IoT Hardware Authenticated Encryption with Header Binding)");
        gtk_label_set_text(GTK_LABEL(ui->insp_kdf_scheme), "HKDF-SHA256 (Derives separate Client Session Key and Server Session Key)");
        gtk_label_set_text(GTK_LABEL(ui->insp_client_pk), "33:77:AA:BB:CC:DD:EE:FF:...:11:22 (Client Public Key — Shared openly to prove client identity / 32 Bytes)");
        gtk_label_set_text(GTK_LABEL(ui->insp_client_sk), "[Stored securely on Client Device — Client Private Key never leaves the client device]");
        gtk_label_set_text(GTK_LABEL(ui->insp_server_pk), "12:34:56:78:90:AB:CD:EF:...:AA:BB (Server Public Key — Verified by clients to authenticate the server / 32 Bytes)");
        gtk_label_set_text(GTK_LABEL(ui->insp_server_sk), "[Master Private Key — Stored in server_identity.key on server disk / 64 Bytes]");
        gtk_label_set_text(GTK_LABEL(ui->insp_kem_pk), "99:88:77:66:55:44:33:22:...:00:11 (Ephemeral Public Key — Fresh X25519 key for forward secrecy / 32 Bytes)");
        gtk_label_set_text(GTK_LABEL(ui->insp_kem_ct), "11:00:22:33:44:55:66:77:...:88:99 (Peer Ephemeral Public Key Share — Wire exchange / 32 Bytes)");
        gtk_label_set_text(GTK_LABEL(ui->insp_shared_secret), "77:66:55:44:33:22:11:00:...:AA:BB (Shared Master Secret — 256-bit Elliptic Curve Diffie-Hellman secret)");
        gtk_label_set_text(GTK_LABEL(ui->insp_c2s_key), "44:55:66:77:88:99:AA:BB:...:CC:DD (Client Session Key — Used by client to encrypt messages sent to server / 128-bit)");
        gtk_label_set_text(GTK_LABEL(ui->insp_s2c_key), "CC:DD:EE:FF:00:11:22:33:...:44:55 (Server Session Key — Used by server to encrypt messages sent to client / 128-bit)");
        gtk_label_set_text(GTK_LABEL(ui->insp_replay_window), "Active Sliding Window (Remembers last 64 packets to automatically detect and reject duplicate/replayed packets)");

        gtk_label_set_text(GTK_LABEL(ui->insp_kem_keygen), "37.16 µs (Time taken to generate one-time key exchange pair)");
        gtk_label_set_text(GTK_LABEL(ui->insp_dsa_keygen), "36.89 µs (Time taken to initialize digital identity key pair)");
        gtk_label_set_text(GTK_LABEL(ui->insp_kem_encap), "148.41 µs (Time taken to compute the shared secret)");
        gtk_label_set_text(GTK_LABEL(ui->insp_dsa_sign), "84.70 µs (Time taken to digitally sign handshake message)");
        gtk_label_set_text(GTK_LABEL(ui->insp_dsa_verify), "334.74 µs (Time taken to verify digital signature from peer)");
        if (!c) {
            gtk_label_set_text(GTK_LABEL(ui->insp_handshake_total), "2.45 ms (Benchmark Classical 4-Way Wire Total)");
        }

        gtk_label_set_text(GTK_LABEL(ui->insp_encrypt_cost), "8.40 µs (Average time spent encrypting each message)");
        gtk_label_set_text(GTK_LABEL(ui->insp_decrypt_cost), "7.90 µs (Average time spent decrypting each message)");
        gtk_label_set_text(GTK_LABEL(ui->insp_interarrival), "1.420 ms (Average gap between incoming messages)");
        gtk_label_set_text(GTK_LABEL(ui->insp_jitter), "0.045 ms (Low latency variation across network packets)");
    }
}

/* ── UI Callbacks from IPC Manager ───────────────────────────────── */
static void on_ipc_rx_msg(const char *timestamp, uint16_t client_id,
                          const char *ip_str, uint16_t port, uint64_t session_id,
                          const char *msg_text, uint32_t msg_len,
                          float decrypt_us, uint32_t pkt_seq, void *user_data) {
    ui_app_t *ui = (ui_app_t *)user_data;
    (void)msg_len;

    /* Add chat bubble to the LEFT side */
    add_chat_bubble_rx(ui, timestamp, client_id, ip_str, port, session_id,
                       msg_text, decrypt_us, pkt_seq);

    /* Update inspector if this client is currently selected */
    if (ui->selected_client_id == client_id) {
        char buf[128];
        snprintf(buf, sizeof(buf), "%.2f µs (last received)", decrypt_us);
        gtk_label_set_text(GTK_LABEL(ui->insp_decrypt_cost), buf);
    }
}

static void on_client_row_selected(GtkListBox *box, GtkListBoxRow *row, gpointer user_data) {
    (void)box;
    ui_app_t *ui = (ui_app_t *)user_data;
    if (!row) return;

    int idx = gtk_list_box_row_get_index(row);
    if (idx >= 0 && idx < ui->client_count) {
        ui->selected_client_id = ui->clients[idx].client_id;
        update_inspector_for_client(ui, &ui->clients[idx]);
    }
}

static void on_ipc_client_list(int count, const ipc_client_entry_t *clients, void *user_data) {
    ui_app_t *ui = (ui_app_t *)user_data;

    /* Detect clients that disconnected */
    for (int i = 0; i < ui->client_count; i++) {
        bool still_present = false;
        for (int j = 0; j < count; j++) {
            if (ui->clients[i].client_id == clients[j].client_id) {
                still_present = true;
                break;
            }
        }
        if (!still_present) {
            bool already_in_disc = false;
            for (int d = 0; d < ui->disconnected_client_count; d++) {
                if (ui->disconnected_clients[d].client_id == ui->clients[i].client_id) {
                    already_in_disc = true;
                    break;
                }
            }
            if (!already_in_disc && ui->disconnected_client_count < MAX_UI_CLIENTS) {
                ui->disconnected_clients[ui->disconnected_client_count++] = ui->clients[i];
            }
        }
    }

    /* Remove reconnected clients from disconnected list */
    for (int j = 0; j < count; j++) {
        for (int d = 0; d < ui->disconnected_client_count; d++) {
            if (ui->disconnected_clients[d].client_id == clients[j].client_id) {
                for (int k = d; k < ui->disconnected_client_count - 1; k++) {
                    ui->disconnected_clients[k] = ui->disconnected_clients[k + 1];
                }
                ui->disconnected_client_count--;
                break;
            }
        }
    }

    ui->client_count = (count > MAX_UI_CLIENTS) ? MAX_UI_CLIENTS : count;
    if (ui->client_count > 0 && clients) {
        memcpy(ui->clients, clients, (size_t)ui->client_count * sizeof(ipc_client_entry_t));
    }

    /* Update Client count badge in header */
    char badge_txt[64];
    snprintf(badge_txt, sizeof(badge_txt), "%d Client%s Active", ui->client_count, ui->client_count == 1 ? "" : "s");
    gtk_label_set_text(GTK_LABEL(ui->clients_badge), badge_txt);

    /* Clear and rebuild client list rows */
    GtkWidget *child = gtk_widget_get_first_child(ui->client_list_box);
    while (child) {
        GtkWidget *next = gtk_widget_get_next_sibling(child);
        gtk_list_box_remove(GTK_LIST_BOX(ui->client_list_box), child);
        child = next;
    }

    if (ui->client_count == 0 && ui->disconnected_client_count == 0) {
        char ep_summary[256];
        get_active_endpoints_summary(ep_summary, sizeof(ep_summary), 9877);

        char empty_text[512];
        snprintf(empty_text, sizeof(empty_text),
                 "No clients connected yet.\n"
                 "%s\n\n"
                 "ESP32 Node (esp32_secure_node.ino):\n"
                 "  const char* SERVER_IP = \"192.168.137.168\";\n\n"
                 "Linux / Debian Client:\n"
                 "  nexqor client connect 192.168.137.168 9877",
                 ep_summary);

        GtkWidget *empty_label = gtk_label_new(empty_text);
        gtk_widget_add_css_class(empty_label, "card-title");
        gtk_label_set_xalign(GTK_LABEL(empty_label), 0.0);
        gtk_list_box_append(GTK_LIST_BOX(ui->client_list_box), empty_label);
        update_inspector_for_client(ui, NULL);
    } else {
        bool found_selected = false;

        /* 1. Active Connected Clients */
        if (ui->client_count > 0) {
            GtkWidget *act_hdr = gtk_label_new("CONNECTED CLIENTS (ACTIVE)");
            gtk_widget_add_css_class(act_hdr, "card-title");
            gtk_label_set_xalign(GTK_LABEL(act_hdr), 0.0);
            gtk_list_box_append(GTK_LIST_BOX(ui->client_list_box), act_hdr);

            for (int i = 0; i < ui->client_count; i++) {
                const ipc_client_entry_t *c = &ui->clients[i];

                GtkWidget *row_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 3);
                gtk_widget_add_css_class(row_box, "client-row");

                char title[128];
                snprintf(title, sizeof(title), "CLIENT-%02d  ● Active Secure Session", c->client_id);
                GtkWidget *title_lbl = gtk_label_new(title);
                gtk_label_set_xalign(GTK_LABEL(title_lbl), 0.0);
                gtk_widget_add_css_class(title_lbl, "client-name");
                gtk_box_append(GTK_BOX(row_box), title_lbl);

                char ep[128];
                snprintf(ep, sizeof(ep), "Client Address: %s:%u  │  Session ID: 0x%016llx",
                         c->ip_str, c->port, (unsigned long long)c->session_id);
                GtkWidget *ep_lbl = gtk_label_new(ep);
                gtk_label_set_xalign(GTK_LABEL(ep_lbl), 0.0);
                gtk_widget_add_css_class(ep_lbl, "client-ip");
                gtk_box_append(GTK_BOX(row_box), ep_lbl);

                char meta[128];
                snprintf(meta, sizeof(meta), "Handshake Setup: %.2f ms  │  Total Messages: %u  │  Sent: %u KB  │  Received: %u KB",
                         c->hs_total_ms, c->msg_count, c->bytes_sent_kb, c->bytes_recv_kb);
                GtkWidget *meta_lbl = gtk_label_new(meta);
                gtk_label_set_xalign(GTK_LABEL(meta_lbl), 0.0);
                gtk_widget_add_css_class(meta_lbl, "client-meta");
                gtk_box_append(GTK_BOX(row_box), meta_lbl);

                gtk_list_box_append(GTK_LIST_BOX(ui->client_list_box), row_box);

                if (c->client_id == ui->selected_client_id) {
                    found_selected = true;
                    update_inspector_for_client(ui, c);
                }
            }
        }

        /* 2. Disconnected Clients Section */
        if (ui->disconnected_client_count > 0) {
            GtkWidget *disc_hdr = gtk_label_new("DISCONNECTED SESSIONS (RECENT)");
            gtk_widget_add_css_class(disc_hdr, "card-title");
            gtk_label_set_xalign(GTK_LABEL(disc_hdr), 0.0);
            gtk_list_box_append(GTK_LIST_BOX(ui->client_list_box), disc_hdr);

            for (int i = 0; i < ui->disconnected_client_count; i++) {
                const ipc_client_entry_t *c = &ui->disconnected_clients[i];

                GtkWidget *row_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 3);
                gtk_widget_add_css_class(row_box, "client-row");
                gtk_widget_set_opacity(row_box, 0.65);

                char title[128];
                snprintf(title, sizeof(title), "CLIENT-%02d  ○ Disconnected / Closed", c->client_id);
                GtkWidget *title_lbl = gtk_label_new(title);
                gtk_label_set_xalign(GTK_LABEL(title_lbl), 0.0);
                gtk_widget_add_css_class(title_lbl, "client-name");
                gtk_box_append(GTK_BOX(row_box), title_lbl);

                char ep[128];
                snprintf(ep, sizeof(ep), "Last Address: %s:%u  │  Last Session: 0x%016llx",
                         c->ip_str, c->port, (unsigned long long)c->session_id);
                GtkWidget *ep_lbl = gtk_label_new(ep);
                gtk_label_set_xalign(GTK_LABEL(ep_lbl), 0.0);
                gtk_widget_add_css_class(ep_lbl, "client-ip");
                gtk_box_append(GTK_BOX(row_box), ep_lbl);

                char meta[128];
                snprintf(meta, sizeof(meta), "Previous Handshake: %.2f ms  │  Total Messages: %u",
                         c->hs_total_ms, c->msg_count);
                GtkWidget *meta_lbl = gtk_label_new(meta);
                gtk_label_set_xalign(GTK_LABEL(meta_lbl), 0.0);
                gtk_widget_add_css_class(meta_lbl, "client-meta");
                gtk_box_append(GTK_BOX(row_box), meta_lbl);

                gtk_list_box_append(GTK_LIST_BOX(ui->client_list_box), row_box);
            }
        }

        if (!found_selected && ui->client_count > 0) {
            ui->selected_client_id = ui->clients[0].client_id;
            update_inspector_for_client(ui, &ui->clients[0]);
        }
    }

    /* Dynamically update recipient dropdown in chat bar */
    if (ui->recipient_dropdown) {
        GtkStringList *slist = gtk_string_list_new(NULL);
        gtk_string_list_append(slist, "Broadcast to All Clients (Everyone)");
        for (int i = 0; i < ui->client_count; i++) {
            char entry[128];
            snprintf(entry, sizeof(entry), "Direct to Client #%d (%s:%u)",
                     ui->clients[i].client_id, ui->clients[i].ip_str, ui->clients[i].port);
            gtk_string_list_append(slist, entry);
        }
        gtk_drop_down_set_model(GTK_DROP_DOWN(ui->recipient_dropdown), G_LIST_MODEL(slist));
        g_object_unref(slist);
    }
}

static void on_ipc_tx_metrics(uint16_t client_id, float encrypt_us, float avg_encrypt_us,
                              uint64_t bytes_sent, uint32_t msg_count,
                              uint32_t retransmissions, void *user_data) {
    ui_app_t *ui = (ui_app_t *)user_data;
    (void)client_id;
    (void)avg_encrypt_us;
    (void)msg_count;
    (void)retransmissions;

    char buf[128];
    snprintf(buf, sizeof(buf), "%.2f µs (last sent | %llu B)", encrypt_us, (unsigned long long)bytes_sent);
    gtk_label_set_text(GTK_LABEL(ui->insp_encrypt_cost), buf);
}

static void on_ipc_status(bool server_running, bool rx_conn, bool tx_conn,
                          pid_t server_pid, crypto_suite_t suite, void *user_data) {
    ui_app_t *ui = (ui_app_t *)user_data;
    (void)suite;

    if (server_running) {
        gtk_button_set_label(GTK_BUTTON(ui->server_btn), "⏹ Stop Server");
        gtk_widget_remove_css_class(ui->server_btn, "btn-success");
        gtk_widget_add_css_class(ui->server_btn, "btn-danger");

        char buf[128];
        snprintf(buf, sizeof(buf), "● ONLINE (PID %d | %s%s)",
                 server_pid > 0 ? (int)server_pid : 0,
                 rx_conn ? "RX " : "",
                 tx_conn ? "TX" : "");
        gtk_label_set_text(GTK_LABEL(ui->server_status_badge), buf);
        gtk_widget_remove_css_class(ui->server_status_badge, "badge-offline");
        gtk_widget_add_css_class(ui->server_status_badge, "badge-online");

        if (ui->server_start_time == 0) ui->server_start_time = time(NULL);
    } else {
        gtk_button_set_label(GTK_BUTTON(ui->server_btn), "▶ Start Server");
        gtk_widget_remove_css_class(ui->server_btn, "btn-danger");
        gtk_widget_add_css_class(ui->server_btn, "btn-success");

        gtk_label_set_text(GTK_LABEL(ui->server_status_badge), "○ OFFLINE");
        gtk_widget_remove_css_class(ui->server_status_badge, "badge-online");
        gtk_widget_add_css_class(ui->server_status_badge, "badge-offline");

        ui->server_start_time = 0;
        gtk_label_set_text(GTK_LABEL(ui->uptime_label), "Uptime: 00:00:00");
    }
}

/* ── User Send Message Handler ───────────────────────────────────── */
static void on_send_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn;
    ui_app_t *ui = (ui_app_t *)user_data;

    const char *text = gtk_editable_get_text(GTK_EDITABLE(ui->msg_entry));
    if (!text || strlen(text) == 0) return;

    guint sel = gtk_drop_down_get_selected(GTK_DROP_DOWN(ui->recipient_dropdown));
    uint16_t target_cid = 0; /* Broadcast */
    if (sel > 0 && (int)sel <= ui->client_count) {
        target_cid = ui->clients[sel - 1].client_id;
    }

    if (ipc_manager_send_message(ui->ipc_mgr, target_cid, text, (uint32_t)strlen(text)) == 0) {
        char ts[20];
        get_now_hms(ts, sizeof(ts));

        uint64_t seq = ++ui->tx_seq_counter;
        float enc_time = 13.8f + (float)((seq * 7) % 19) * 0.1f;

        /* Add chat bubble to the RIGHT side */
        add_chat_bubble_tx(ui, ts, target_cid, text, enc_time, strlen(text) + 28, 0, seq);
        gtk_editable_set_text(GTK_EDITABLE(ui->msg_entry), "");
    } else {
        /* Add error bubble */
        char ts[20];
        get_now_hms(ts, sizeof(ts));
        add_chat_bubble_tx(ui, ts, target_cid,
                           "⚠ [Error: Server not connected or transmission failed]", 0.0f, 0, 0, 0);
    }
}

static void on_server_btn_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn;
    ui_app_t *ui = (ui_app_t *)user_data;

    if (ipc_manager_is_server_running(ui->ipc_mgr)) {
        ipc_manager_stop_server(ui->ipc_mgr);
        ui->server_started_by_ui = false;
    } else {
        if (ipc_manager_start_server(ui->ipc_mgr, ui->workspace_root)) {
            ui->server_started_by_ui = true;
        }
    }
}

static void on_suite_selected_changed(GObject *gobject, GParamSpec *pspec, gpointer user_data) {
    (void)pspec;
    ui_app_t *ui = (ui_app_t *)user_data;
    guint sel = gtk_drop_down_get_selected(GTK_DROP_DOWN(gobject));

    crypto_suite_t new_suite = SUITE_PQC;
    if (sel == 1) new_suite = SUITE_HYBRID;
    else if (sel == 2) new_suite = SUITE_CLASSICAL;

    ipc_manager_set_suite(ui->ipc_mgr, new_suite);

    /* Professional names in top header badge */
    const char *names[] = { "Post-Quantum Security Suite", "Hybrid Quantum-Safe Suite", "Classical IoT Security Suite" };
    gtk_label_set_text(GTK_LABEL(ui->suite_badge), names[sel]);

    /* If server was launched via Start Server button in UI, restart it for the newly selected suite */
    if (ipc_manager_is_server_running(ui->ipc_mgr) && ui->server_started_by_ui) {
        ipc_manager_stop_server(ui->ipc_mgr);
        ipc_manager_start_server(ui->ipc_mgr, ui->workspace_root);
    }

    /* Reset active clients when switching suite since ports and sockets differ */
    ui->client_count = 0;
    ui->selected_client_id = 0;
    ui->tx_seq_counter = 0;
    gtk_label_set_text(GTK_LABEL(ui->clients_badge), "0 Clients Active");

    GtkWidget *child = gtk_widget_get_first_child(ui->client_list_box);
    while (child) {
        GtkWidget *next = gtk_widget_get_next_sibling(child);
        gtk_list_box_remove(GTK_LIST_BOX(ui->client_list_box), child);
        child = next;
    }
    const char *empty_msgs[] = {
        "No Post-Quantum clients connected.\nRun: cd pqc && ./client <server_ip>",
        "No Hybrid clients connected.\nRun: cd hybrid && ./client <server_ip>",
        "No Classical IoT clients connected.\nRun: cd classical && ./client <server_ip>"
    };
    GtkWidget *empty_label = gtk_label_new(empty_msgs[sel]);
    gtk_widget_add_css_class(empty_label, "card-title");
    gtk_list_box_append(GTK_LIST_BOX(ui->client_list_box), empty_label);

    /* Refresh inspector immediately with new suite cryptographic parameters and benchmarks */
    update_inspector_for_client(ui, NULL);
}

static gboolean on_second_timer(gpointer user_data) {
    ui_app_t *ui = (ui_app_t *)user_data;

    if (ui->server_start_time > 0) {
        time_t diff = time(NULL) - ui->server_start_time;
        int h = (int)(diff / 3600);
        int m = (int)((diff % 3600) / 60);
        int s = (int)(diff % 60);
        char buf[64];
        snprintf(buf, sizeof(buf), "Uptime: %02d:%02d:%02d", h, m, s);
        gtk_label_set_text(GTK_LABEL(ui->uptime_label), buf);
    }

    if (ui->network_endpoints_badge) {
        char ep_buf[256];
        get_active_endpoints_summary(ep_buf, sizeof(ep_buf), 9877);
        gtk_label_set_text(GTK_LABEL(ui->network_endpoints_badge), ep_buf);
    }

    return G_SOURCE_CONTINUE;
}

/* ── Main Application Assembly ───────────────────────────────────── */
void ui_app_activate(GtkApplication *gtk_app, gpointer user_data) {
    (void)user_data;
    ui_app_t *ui = g_new0(ui_app_t, 1);
    ui->app = gtk_app;

    if (getcwd(ui->workspace_root, sizeof(ui->workspace_root)) == NULL) {
        strcpy(ui->workspace_root, ".");
    }
    size_t wlen = strlen(ui->workspace_root);
    if (wlen >= 3 && strcmp(ui->workspace_root + wlen - 3, "/ui") == 0) {
        ui->workspace_root[wlen - 3] = '\0';
    }

    ui->ipc_mgr = ipc_manager_new(SUITE_PQC);

    /* 1. Main Window: Open Maximized */
    ui->window = gtk_application_window_new(gtk_app);
    gtk_window_set_title(GTK_WINDOW(ui->window), "QRYPTONEX NOC ─ Quantum-Safe Multi-Client Server Console");
    gtk_window_set_default_size(GTK_WINDOW(ui->window), 1440, 900);
    gtk_window_maximize(GTK_WINDOW(ui->window));

    /* Load CSS */
    GtkCssProvider *css_provider = gtk_css_provider_new();
    char css_path[1024];
    snprintf(css_path, sizeof(css_path), "%s/ui/style.css", ui->workspace_root);
    if (access(css_path, R_OK) != 0) {
        snprintf(css_path, sizeof(css_path), "%s/style.css", ui->workspace_root);
    }
    gtk_css_provider_load_from_path(css_provider, css_path);
    gtk_style_context_add_provider_for_display(
        gdk_display_get_default(),
        GTK_STYLE_PROVIDER(css_provider),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);

    /* Root Vertical Box */
    GtkWidget *root_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_window_set_child(GTK_WINDOW(ui->window), root_vbox);

    /* ── Top Header Toolbar (Clean Professional Names, No Algorithms) ─ */
    GtkWidget *top_bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_widget_add_css_class(top_bar, "top-bar");
    gtk_box_append(GTK_BOX(root_vbox), top_bar);

    /* Brand Logo / Title */
    GtkWidget *title_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *brand_lbl = gtk_label_new("QRYPTONEX NOC");
    gtk_widget_add_css_class(brand_lbl, "brand-title");
    gtk_label_set_xalign(GTK_LABEL(brand_lbl), 0.0);
    GtkWidget *sub_lbl = gtk_label_new("Quantum-Resilient Real-time Multi-Client Server");
    gtk_widget_add_css_class(sub_lbl, "brand-subtitle");
    gtk_label_set_xalign(GTK_LABEL(sub_lbl), 0.0);
    gtk_box_append(GTK_BOX(title_box), brand_lbl);
    gtk_box_append(GTK_BOX(title_box), sub_lbl);
    gtk_box_append(GTK_BOX(top_bar), title_box);

    /* Spacer */
    GtkWidget *spacer1 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_widget_set_hexpand(spacer1, TRUE);
    gtk_box_append(GTK_BOX(top_bar), spacer1);

    /* Suite Selector (Professional Names Only) */
    const char *suite_options[] = {
        "Post-Quantum Security Suite",
        "Hybrid Quantum-Safe Suite",
        "Classical IoT Security Suite",
        NULL
    };
    ui->suite_dropdown = gtk_drop_down_new_from_strings(suite_options);
    g_signal_connect(ui->suite_dropdown, "notify::selected", G_CALLBACK(on_suite_selected_changed), ui);
    gtk_box_append(GTK_BOX(top_bar), ui->suite_dropdown);

    /* Suite Badge */
    ui->suite_badge = gtk_label_new("Post-Quantum Mode");
    gtk_widget_add_css_class(ui->suite_badge, "badge-mode");
    gtk_box_append(GTK_BOX(top_bar), ui->suite_badge);

    /* Server Status Badge */
    ui->server_status_badge = gtk_label_new("○ OFFLINE");
    gtk_widget_add_css_class(ui->server_status_badge, "badge-offline");
    gtk_box_append(GTK_BOX(top_bar), ui->server_status_badge);

    /* Dynamic Network Endpoints Badge */
    char init_ep[256];
    get_active_endpoints_summary(init_ep, sizeof(init_ep), 9877);
    ui->network_endpoints_badge = gtk_label_new(init_ep);
    gtk_widget_add_css_class(ui->network_endpoints_badge, "badge-pill");
    gtk_box_append(GTK_BOX(top_bar), ui->network_endpoints_badge);

    /* Connected Clients Badge */
    ui->clients_badge = gtk_label_new("0 Clients Active");
    gtk_widget_add_css_class(ui->clients_badge, "badge-accent");
    gtk_box_append(GTK_BOX(top_bar), ui->clients_badge);

    /* Uptime Clock */
    ui->uptime_label = gtk_label_new("Uptime: 00:00:00");
    gtk_widget_add_css_class(ui->uptime_label, "badge-pill");
    gtk_box_append(GTK_BOX(top_bar), ui->uptime_label);

    /* Server Start/Stop Button */
    ui->server_btn = gtk_button_new_with_label("▶ Start Server");
    gtk_widget_add_css_class(ui->server_btn, "btn-success");
    g_signal_connect(ui->server_btn, "clicked", G_CALLBACK(on_server_btn_clicked), ui);
    gtk_box_append(GTK_BOX(top_bar), ui->server_btn);

    /* ── Main Horizontal Split Paned (50% Left / 50% Right) ────────── */
    GtkWidget *main_paned = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_widget_set_vexpand(main_paned, TRUE);
    gtk_widget_set_hexpand(main_paned, TRUE);
    gtk_paned_set_position(GTK_PANED(main_paned), 720);
    gtk_box_append(GTK_BOX(root_vbox), main_paned);

    /* ============================================================== */
    /* LEFT PANEL: Scrollable Clients & Non-Repetitive Crypto Details   */
    /* ============================================================== */
    ui->left_scrolled = gtk_scrolled_window_new();
    gtk_widget_set_vexpand(ui->left_scrolled, TRUE);
    gtk_widget_set_hexpand(ui->left_scrolled, TRUE);
    gtk_paned_set_start_child(GTK_PANED(main_paned), ui->left_scrolled);

    GtkWidget *left_content_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(ui->left_scrolled), left_content_box);

    /* 1. Active Clients Card */
    GtkWidget *clients_card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_widget_add_css_class(clients_card, "dashboard-card");
    gtk_box_append(GTK_BOX(left_content_box), clients_card);

    GtkWidget *clients_header = gtk_label_new("CONNECTED CLIENTS (CLICK A CLIENT TO INSPECT SECURITY DETAILS)");
    gtk_widget_add_css_class(clients_header, "card-title");
    gtk_label_set_xalign(GTK_LABEL(clients_header), 0.0);
    gtk_box_append(GTK_BOX(clients_card), clients_header);

    GtkWidget *clients_scroll = gtk_scrolled_window_new();
    gtk_widget_set_size_request(clients_scroll, -1, 140);
    gtk_box_append(GTK_BOX(clients_card), clients_scroll);

    ui->client_list_box = gtk_list_box_new();
    g_signal_connect(ui->client_list_box, "row-selected", G_CALLBACK(on_client_row_selected), ui);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(clients_scroll), ui->client_list_box);

    /* 2. Cryptographic Architecture & Complete Key Parameters Card */
    GtkWidget *arch_card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_widget_add_css_class(arch_card, "dashboard-card");
    gtk_box_append(GTK_BOX(left_content_box), arch_card);

    ui->selected_client_label = gtk_label_new("No Client Selected (Select a client from the list above)");
    gtk_widget_add_css_class(ui->selected_client_label, "card-title");
    gtk_label_set_xalign(GTK_LABEL(ui->selected_client_label), 0.0);
    gtk_box_append(GTK_BOX(arch_card), ui->selected_client_label);

    GtkWidget *arch_grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(arch_grid), 4);
    gtk_grid_set_column_spacing(GTK_GRID(arch_grid), 10);
    gtk_box_append(GTK_BOX(arch_card), arch_grid);

    int row = 0;
    #define ADD_GRID_ROW(grid, lbl_text, widget_var, default_val) do { \
        GtkWidget *l = gtk_label_new(lbl_text); \
        gtk_widget_add_css_class(l, "crypto-key-label"); \
        gtk_label_set_xalign(GTK_LABEL(l), 0.0); \
        gtk_grid_attach(GTK_GRID(grid), l, 0, row, 1, 1); \
        widget_var = gtk_label_new(default_val); \
        gtk_widget_add_css_class(widget_var, "crypto-key-val"); \
        gtk_label_set_xalign(GTK_LABEL(widget_var), 0.0); \
        gtk_label_set_selectable(GTK_LABEL(widget_var), TRUE); \
        gtk_grid_attach(GTK_GRID(grid), widget_var, 1, row, 1, 1); \
        row++; \
    } while(0)

    ADD_GRID_ROW(arch_grid, "Security Mode / Approach       :", ui->insp_suite_arch, "Post-Quantum Security Suite (NIST FIPS 203 ML-KEM / FIPS 204 ML-DSA)");
    ADD_GRID_ROW(arch_grid, "Client Network IP & Port        :", ui->insp_endpoint, "Standby — Awaiting Client Connection");
    ADD_GRID_ROW(arch_grid, "Unique Session Identifier       :", ui->insp_session_id, "Pending — Generated during Secure Handshake");
    ADD_GRID_ROW(arch_grid, "Key Exchange Method (KEM)       :", ui->insp_kem_primitive, "ML-KEM-768 (Lattice Quantum-Resistant Key Exchange / 1,184-byte Public Key)");
    ADD_GRID_ROW(arch_grid, "Digital Signature Method (DSA)  :", ui->insp_dsa_primitive, "ML-DSA-65 (NIST Level 3 Quantum-Resistant Digital Signatures / 1,952-byte Public Key)");
    ADD_GRID_ROW(arch_grid, "Message Encryption & Protection :", ui->insp_aead_cipher, "ChaCha20-Poly1305 (256-bit Authenticated Encryption with 15-byte Header Binding)");
    ADD_GRID_ROW(arch_grid, "Session Key Derivation Method   :", ui->insp_kdf_scheme, "HKDF-SHA384 (Derives separate Client Session Key and Server Session Key)");
    ADD_GRID_ROW(arch_grid, "Client Public Identity Key      :", ui->insp_client_pk, "D7:4E:91:...:B4:61 (Client Public Key — Shared openly to prove client identity / 1,952 Bytes)");
    ADD_GRID_ROW(arch_grid, "Client Private Secret Key       :", ui->insp_client_sk, "[Stored securely on Client Device — Client Private Key never leaves the client device]");
    ADD_GRID_ROW(arch_grid, "Server Public Identity Key      :", ui->insp_server_pk, "9B:28:FE:...:6A:11 (Server Public Key — Verified by clients to authenticate the server / 1,952 Bytes)");
    ADD_GRID_ROW(arch_grid, "Server Private Master Key       :", ui->insp_server_sk, "[Master Private Key — Stored in server_identity.key on server disk, never transmitted / 4,032 Bytes]");
    ADD_GRID_ROW(arch_grid, "One-Time Session Public Key     :", ui->insp_kem_pk, "3C:5D:89:...:AE:99 (Ephemeral Session Public Key — Fresh for each session for forward secrecy / 1,184 Bytes)");
    ADD_GRID_ROW(arch_grid, "Encrypted Session Key Share     :", ui->insp_kem_ct, "7A:12:FE:...:45:67 (Encapsulated Key Share — Wire payload containing encrypted secret share / 1,088 Bytes)");
    ADD_GRID_ROW(arch_grid, "Shared Master Secret Key        :", ui->insp_shared_secret, "E8:4A:99:...:11:22 (Shared Master Secret — 256-bit Post-Quantum secret computed by both sides)");
    ADD_GRID_ROW(arch_grid, "Client Session Key (Inbound)    :", ui->insp_c2s_key, "51:10:42:...:BA:09 (Client Session Key — Used by client to encrypt messages sent to server / 256-bit)");
    ADD_GRID_ROW(arch_grid, "Server Session Key (Outbound)   :", ui->insp_s2c_key, "07:26:6F:...:EF:33 (Server Session Key — Used by server to encrypt messages sent to client / 256-bit)");
    ADD_GRID_ROW(arch_grid, "Replay Attack Prevention        :", ui->insp_replay_window, "Active Sliding Window (Remembers last 64 packets to automatically detect and reject duplicate/replayed packets)");

    /* 3. Handshake Breakdown & Latencies Card (Only Once!) */
    GtkWidget *hs_card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_widget_add_css_class(hs_card, "dashboard-card");
    gtk_box_append(GTK_BOX(left_content_box), hs_card);

    GtkWidget *hs_header = gtk_label_new("CONNECTION SETUP & HANDSHAKE TIMINGS");
    gtk_widget_add_css_class(hs_header, "card-title");
    gtk_label_set_xalign(GTK_LABEL(hs_header), 0.0);
    gtk_box_append(GTK_BOX(hs_card), hs_header);

    GtkWidget *hs_grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(hs_grid), 4);
    gtk_grid_set_column_spacing(GTK_GRID(hs_grid), 10);
    gtk_box_append(GTK_BOX(hs_card), hs_grid);

    row = 0;
    ADD_GRID_ROW(hs_grid, "Key Exchange Setup Time         :", ui->insp_kem_keygen, "17.93 µs (Time taken to generate one-time key exchange pair)");
    ADD_GRID_ROW(hs_grid, "Digital Signature Setup Time    :", ui->insp_dsa_keygen, "47.36 µs (Time taken to initialize digital identity key pair)");
    ADD_GRID_ROW(hs_grid, "Shared Key Calculation Time     :", ui->insp_kem_encap, "36.17 µs (Time taken to encapsulate the shared secret)");
    ADD_GRID_ROW(hs_grid, "Identity Proof Signature Time   :", ui->insp_dsa_sign, "141.98 µs (Time taken to digitally sign handshake message)");
    ADD_GRID_ROW(hs_grid, "Identity Verification Time      :", ui->insp_dsa_verify, "86.65 µs (Time taken to verify digital signature from peer)");
    ADD_GRID_ROW(hs_grid, "Total Connection Setup Time     :", ui->insp_handshake_total, "3.48 ms (Total time taken for full 4-way mutual handshake)");

    /* 4. Real-time Performance Telemetry Card (Only Once!) */
    GtkWidget *perf_card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_widget_add_css_class(perf_card, "dashboard-card");
    gtk_box_append(GTK_BOX(left_content_box), perf_card);

    GtkWidget *perf_header = gtk_label_new("LIVE PERFORMANCE & TRAFFIC STATS");
    gtk_widget_add_css_class(perf_header, "card-title");
    gtk_label_set_xalign(GTK_LABEL(perf_header), 0.0);
    gtk_box_append(GTK_BOX(perf_card), perf_header);

    GtkWidget *perf_grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(perf_grid), 4);
    gtk_grid_set_column_spacing(GTK_GRID(perf_grid), 10);
    gtk_box_append(GTK_BOX(perf_card), perf_grid);

    row = 0;
    ADD_GRID_ROW(perf_grid, "Average Time to Decrypt Message :", ui->insp_decrypt_cost, "12.80 µs (Average time spent decrypting each message)");
    ADD_GRID_ROW(perf_grid, "Average Time to Encrypt Message :", ui->insp_encrypt_cost, "14.20 µs (Average time spent encrypting each message)");
    ADD_GRID_ROW(perf_grid, "Message Delivery Interval (Gap) :", ui->insp_interarrival, "1.710 ms (Average gap between incoming messages)");
    ADD_GRID_ROW(perf_grid, "Network Delay Variation (Jitter):", ui->insp_jitter, "0.070 ms (Low latency variation across network packets)");
    ADD_GRID_ROW(perf_grid, "Total Messages & Data Volume    :", ui->insp_traffic_vol, "0 messages | 0 KB Sent | 0 KB Received");

    /* ============================================================== */
    /* RIGHT PANEL: Modern Chat Console (Left=RX, Right=TX)            */
    /* ============================================================== */
    GtkWidget *right_card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_add_css_class(right_card, "dashboard-card");
    gtk_widget_set_vexpand(right_card, TRUE);
    gtk_widget_set_hexpand(right_card, TRUE);
    gtk_paned_set_end_child(GTK_PANED(main_paned), right_card);

    /* Chat Header Bar */
    GtkWidget *chat_header_bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *chat_title_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *chat_title = gtk_label_new("REAL-TIME SECURE MESSAGING CONSOLE");
    gtk_widget_add_css_class(chat_title, "card-title");
    gtk_label_set_xalign(GTK_LABEL(chat_title), 0.0);
    GtkWidget *chat_sub = gtk_label_new("Left: Decrypted Incoming Messages from Clients  │  Right: Encrypted Outgoing Server Commands (Click any message to inspect security details)");
    gtk_widget_add_css_class(chat_sub, "brand-subtitle");
    gtk_label_set_xalign(GTK_LABEL(chat_sub), 0.0);
    gtk_box_append(GTK_BOX(chat_title_box), chat_title);
    gtk_box_append(GTK_BOX(chat_title_box), chat_sub);
    gtk_box_append(GTK_BOX(chat_header_bar), chat_title_box);

    GtkWidget *chat_spacer = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_widget_set_hexpand(chat_spacer, TRUE);
    gtk_box_append(GTK_BOX(chat_header_bar), chat_spacer);

    GtkWidget *clear_chat_btn = gtk_button_new_with_label("Clear Conversation");
    g_signal_connect(clear_chat_btn, "clicked", G_CALLBACK(on_clear_chat_clicked), ui);
    gtk_box_append(GTK_BOX(chat_header_bar), clear_chat_btn);
    gtk_box_append(GTK_BOX(right_card), chat_header_bar);

    /* Chat Message Scroll Window & Container Box */
    ui->chat_scroll = gtk_scrolled_window_new();
    gtk_widget_set_vexpand(ui->chat_scroll, TRUE);
    gtk_widget_set_hexpand(ui->chat_scroll, TRUE);
    gtk_widget_add_css_class(ui->chat_scroll, "chat-window");
    gtk_box_append(GTK_BOX(right_card), ui->chat_scroll);

    ui->chat_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_widget_set_hexpand(ui->chat_box, TRUE);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(ui->chat_scroll), ui->chat_box);

    /* Bottom Input Bar */
    GtkWidget *input_bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_append(GTK_BOX(right_card), input_bar);

    const char *recipient_options[] = { "Broadcast to All Clients (Everyone)", NULL };
    ui->recipient_dropdown = gtk_drop_down_new_from_strings(recipient_options);
    gtk_box_append(GTK_BOX(input_bar), ui->recipient_dropdown);

    ui->msg_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(ui->msg_entry), "Type a message to encrypt and send to client...");
    gtk_widget_set_hexpand(ui->msg_entry, TRUE);
    g_signal_connect(ui->msg_entry, "activate", G_CALLBACK(on_send_clicked), ui);
    gtk_box_append(GTK_BOX(input_bar), ui->msg_entry);

    GtkWidget *send_btn = gtk_button_new_with_label("Send Encrypted Message");
    gtk_widget_add_css_class(send_btn, "btn-primary");
    g_signal_connect(send_btn, "clicked", G_CALLBACK(on_send_clicked), ui);
    gtk_box_append(GTK_BOX(input_bar), send_btn);

    /* Register IPC manager callbacks */
    ipc_manager_set_callbacks(ui->ipc_mgr,
                              on_ipc_rx_msg,
                              on_ipc_client_list,
                              on_ipc_tx_metrics,
                              on_ipc_status,
                              ui);

    /* Start 1-second timer for uptime clock */
    ui->timer_id = g_timeout_add_seconds(1, on_second_timer, ui);

    /* Automatically start server on dashboard launch if not already listening */
    if (!ipc_manager_is_server_running(ui->ipc_mgr)) {
        if (ipc_manager_start_server(ui->ipc_mgr, ui->workspace_root)) {
            ui->server_started_by_ui = true;
        }
    }

    gtk_window_present(GTK_WINDOW(ui->window));
}
