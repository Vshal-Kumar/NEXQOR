#include "ipc_manager.h"
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <poll.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/stat.h>

struct ipc_manager_s {
    crypto_suite_t suite;

    int rx_fd;
    int tx_fd;
    pthread_mutex_t tx_mu;

    volatile bool stop_threads;
    pthread_t rx_thread;
    pthread_t tx_thread;

    pid_t server_pid;
    bool server_started_by_us;

    /* Callbacks */
    ui_rx_msg_cb on_rx_msg;
    ui_client_list_cb on_client_list;
    ui_tx_metrics_cb on_tx_metrics;
    ui_status_cb on_status;
    void *cb_user_data;
};

/* Data wrappers for g_idle_add */
typedef struct {
    ipc_manager_t *mgr;
    char timestamp[20];
    uint16_t client_id;
    char ip_str[16];
    uint16_t port;
    uint64_t session_id;
    char *msg_text;
    uint32_t msg_len;
    float decrypt_us;
    uint32_t pkt_seq;
} rx_msg_event_t;

typedef struct {
    ipc_manager_t *mgr;
    int count;
    ipc_client_entry_t *clients;
} client_list_event_t;

typedef struct {
    ipc_manager_t *mgr;
    uint16_t client_id;
    float encrypt_us;
    float avg_encrypt_us;
    uint64_t bytes_sent;
    uint32_t msg_count;
    uint32_t retransmissions;
} tx_metrics_event_t;

typedef struct {
    ipc_manager_t *mgr;
    bool server_running;
    bool rx_conn;
    bool tx_conn;
    pid_t pid;
    crypto_suite_t suite;
} status_event_t;

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

static const char *get_rx_path(crypto_suite_t suite) {
    switch (suite) {
        case SUITE_HYBRID:    return HYBRID_IPC_RX_PATH;
        case SUITE_CLASSICAL: return CLASSICAL_IPC_RX_PATH;
        case SUITE_PQC:
        default:              return PQC_IPC_RX_PATH;
    }
}

static const char *get_tx_path(crypto_suite_t suite) {
    switch (suite) {
        case SUITE_HYBRID:    return HYBRID_IPC_TX_PATH;
        case SUITE_CLASSICAL: return CLASSICAL_IPC_TX_PATH;
        case SUITE_PQC:
        default:              return PQC_IPC_TX_PATH;
    }
}

/* Idle dispatchers */
static gboolean dispatch_rx_msg(gpointer data) {
    rx_msg_event_t *ev = (rx_msg_event_t *)data;
    if (ev->mgr->on_rx_msg) {
        ev->mgr->on_rx_msg(ev->timestamp, ev->client_id, ev->ip_str, ev->port,
                           ev->session_id, ev->msg_text, ev->msg_len,
                           ev->decrypt_us, ev->pkt_seq, ev->mgr->cb_user_data);
    }
    free(ev->msg_text);
    free(ev);
    return G_SOURCE_REMOVE;
}

static gboolean dispatch_client_list(gpointer data) {
    client_list_event_t *ev = (client_list_event_t *)data;
    if (ev->mgr->on_client_list) {
        ev->mgr->on_client_list(ev->count, ev->clients, ev->mgr->cb_user_data);
    }
    free(ev->clients);
    free(ev);
    return G_SOURCE_REMOVE;
}

static gboolean dispatch_tx_metrics(gpointer data) {
    tx_metrics_event_t *ev = (tx_metrics_event_t *)data;
    if (ev->mgr->on_tx_metrics) {
        ev->mgr->on_tx_metrics(ev->client_id, ev->encrypt_us, ev->avg_encrypt_us,
                               ev->bytes_sent, ev->msg_count, ev->retransmissions,
                               ev->mgr->cb_user_data);
    }
    free(ev);
    return G_SOURCE_REMOVE;
}

static gboolean dispatch_status(gpointer data) {
    status_event_t *ev = (status_event_t *)data;
    if (ev->mgr->on_status) {
        ev->mgr->on_status(ev->server_running, ev->rx_conn, ev->tx_conn,
                           ev->pid, ev->suite, ev->mgr->cb_user_data);
    }
    free(ev);
    return G_SOURCE_REMOVE;
}

static void trigger_status_update(ipc_manager_t *mgr) {
    status_event_t *ev = g_new0(status_event_t, 1);
    ev->mgr = mgr;
    ev->server_running = (mgr->server_pid > 0 || mgr->rx_fd >= 0 || mgr->tx_fd >= 0);
    ev->rx_conn = (mgr->rx_fd >= 0);
    ev->tx_conn = (mgr->tx_fd >= 0);
    ev->pid = mgr->server_pid;
    ev->suite = mgr->suite;
    g_idle_add(dispatch_status, ev);
}

static int connect_unix_socket(const char *path) {
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(s);
        return -1;
    }
    return s;
}

/* ── RX Thread: Reads Inbound Decrypted Messages & Telemetry ──────── */
static void *rx_worker_thread(void *arg) {
    ipc_manager_t *mgr = (ipc_manager_t *)arg;
    uint8_t buf[sizeof(ipc_rx_payload_t) + 4096];
    ipc_metrics_rx_t last_m[MAX_UI_CLIENTS];
    memset(last_m, 0, sizeof(last_m));

    while (!mgr->stop_threads) {
        if (mgr->rx_fd < 0) {
            const char *path = get_rx_path(mgr->suite);
            mgr->rx_fd = connect_unix_socket(path);
            if (mgr->rx_fd >= 0) {
                trigger_status_update(mgr);
            } else {
                g_usleep(500000); /* 500 ms backoff */
                continue;
            }
        }

        struct pollfd pfd = { .fd = mgr->rx_fd, .events = POLLIN };
        int prc = poll(&pfd, 1, 300);
        if (prc <= 0) continue;

        ipc_hdr_t hdr;
        ssize_t n = ipc_recv_frame(mgr->rx_fd, &hdr, buf, sizeof(buf) - 1);
        if (n < 0) {
            close(mgr->rx_fd);
            mgr->rx_fd = -1;
            trigger_status_update(mgr);
            continue;
        }

        if (hdr.type == IPC_METRICS_RX && n >= (ssize_t)sizeof(ipc_metrics_rx_t)) {
            ipc_metrics_rx_t *mr = (ipc_metrics_rx_t *)buf;
            if (mr->client_id < MAX_UI_CLIENTS) {
                last_m[mr->client_id] = *mr;
            }
        } else if (hdr.type == IPC_MSG_RX && n >= (ssize_t)sizeof(ipc_rx_payload_t)) {
            ipc_rx_payload_t *info = (ipc_rx_payload_t *)buf;
            const char *text = (const char *)(buf + sizeof(ipc_rx_payload_t));
            uint32_t text_len = info->msg_len;
            if (text_len > (uint32_t)(n - sizeof(ipc_rx_payload_t))) {
                text_len = (uint32_t)(n - sizeof(ipc_rx_payload_t));
            }

            rx_msg_event_t *ev = g_new0(rx_msg_event_t, 1);
            ev->mgr = mgr;
            get_now_hms(ev->timestamp, sizeof(ev->timestamp));
            ev->client_id = info->client_id;
            snprintf(ev->ip_str, sizeof(ev->ip_str), "%.15s", info->ip_str);
            ev->port = info->port;
            ev->session_id = info->session_id;
            ev->msg_len = text_len;
            ev->msg_text = malloc(text_len + 1);
            if (ev->msg_text) {
                memcpy(ev->msg_text, text, text_len);
                ev->msg_text[text_len] = '\0';
            }

            static uint32_t fallback_rx_seq[MAX_UI_CLIENTS];
            if (info->client_id < MAX_UI_CLIENTS && last_m[info->client_id].pkt_seq > 0) {
                ev->decrypt_us = last_m[info->client_id].decrypt_us;
                ev->pkt_seq = last_m[info->client_id].pkt_seq;
                fallback_rx_seq[info->client_id] = last_m[info->client_id].pkt_seq;
            } else {
                ev->decrypt_us = (info->client_id < MAX_UI_CLIENTS) ? last_m[info->client_id].decrypt_us : 0.0f;
                uint16_t cid = (info->client_id < MAX_UI_CLIENTS) ? info->client_id : 0;
                ev->pkt_seq = ++fallback_rx_seq[cid];
            }

            g_idle_add(dispatch_rx_msg, ev);
        }
    }
    return NULL;
}

/* ── TX Thread: Reads Client Lists & TX Metrics ───────────────────── */
static void *tx_worker_thread(void *arg) {
    ipc_manager_t *mgr = (ipc_manager_t *)arg;
    uint8_t buf[sizeof(uint16_t) + MAX_UI_CLIENTS * sizeof(ipc_client_entry_t) + 512];

    while (!mgr->stop_threads) {
        if (mgr->tx_fd < 0) {
            const char *path = get_tx_path(mgr->suite);
            mgr->tx_fd = connect_unix_socket(path);
            if (mgr->tx_fd >= 0) {
                trigger_status_update(mgr);
            } else {
                g_usleep(500000);
                continue;
            }
        }

        struct pollfd pfd = { .fd = mgr->tx_fd, .events = POLLIN };
        int prc = poll(&pfd, 1, 300);
        if (prc <= 0) continue;

        ipc_hdr_t hdr;
        ssize_t n = ipc_recv_frame(mgr->tx_fd, &hdr, buf, sizeof(buf));
        if (n < 0) {
            pthread_mutex_lock(&mgr->tx_mu);
            close(mgr->tx_fd);
            mgr->tx_fd = -1;
            pthread_mutex_unlock(&mgr->tx_mu);
            trigger_status_update(mgr);
            continue;
        }

        if (hdr.type == IPC_CLIENT_LIST && n >= (ssize_t)sizeof(uint16_t)) {
            uint16_t count;
            memcpy(&count, buf, sizeof(count));
            if (count > MAX_UI_CLIENTS) count = MAX_UI_CLIENTS;

            size_t expected = sizeof(uint16_t) + (size_t)count * sizeof(ipc_client_entry_t);
            if ((size_t)n >= expected) {
                client_list_event_t *ev = g_new0(client_list_event_t, 1);
                ev->mgr = mgr;
                ev->count = (int)count;
                if (count > 0) {
                    ev->clients = malloc((size_t)count * sizeof(ipc_client_entry_t));
                    if (ev->clients) {
                        memcpy(ev->clients, buf + sizeof(uint16_t),
                               (size_t)count * sizeof(ipc_client_entry_t));
                    }
                }
                g_idle_add(dispatch_client_list, ev);
            }
        } else if (hdr.type == IPC_METRICS_TX && n >= (ssize_t)sizeof(ipc_metrics_tx_t)) {
            ipc_metrics_tx_t *mt = (ipc_metrics_tx_t *)buf;
            tx_metrics_event_t *ev = g_new0(tx_metrics_event_t, 1);
            ev->mgr = mgr;
            ev->client_id = mt->client_id;
            ev->encrypt_us = mt->encrypt_us;
            ev->avg_encrypt_us = mt->avg_encrypt_us;
            ev->bytes_sent = mt->bytes_sent;
            ev->msg_count = mt->msg_count;
            ev->retransmissions = mt->retransmissions;
            g_idle_add(dispatch_tx_metrics, ev);
        }
    }
    return NULL;
}

/* ── Lifecycle & API ─────────────────────────────────────────────── */
ipc_manager_t *ipc_manager_new(crypto_suite_t default_suite) {
    ipc_manager_t *mgr = g_new0(ipc_manager_t, 1);
    mgr->suite = default_suite;
    mgr->rx_fd = -1;
    mgr->tx_fd = -1;
    mgr->server_pid = -1;
    pthread_mutex_init(&mgr->tx_mu, NULL);

    pthread_create(&mgr->rx_thread, NULL, rx_worker_thread, mgr);
    pthread_create(&mgr->tx_thread, NULL, tx_worker_thread, mgr);
    return mgr;
}

void ipc_manager_free(ipc_manager_t *mgr) {
    if (!mgr) return;
    mgr->stop_threads = true;

    if (mgr->server_started_by_us && mgr->server_pid > 0) {
        ipc_manager_stop_server(mgr);
    }

    pthread_join(mgr->rx_thread, NULL);
    pthread_join(mgr->tx_thread, NULL);

    if (mgr->rx_fd >= 0) close(mgr->rx_fd);
    if (mgr->tx_fd >= 0) close(mgr->tx_fd);
    pthread_mutex_destroy(&mgr->tx_mu);
    g_free(mgr);
}

void ipc_manager_set_callbacks(ipc_manager_t *mgr,
                               ui_rx_msg_cb on_rx_msg,
                               ui_client_list_cb on_client_list,
                               ui_tx_metrics_cb on_tx_metrics,
                               ui_status_cb on_status,
                               void *user_data) {
    mgr->on_rx_msg = on_rx_msg;
    mgr->on_client_list = on_client_list;
    mgr->on_tx_metrics = on_tx_metrics;
    mgr->on_status = on_status;
    mgr->cb_user_data = user_data;
    trigger_status_update(mgr);
}

void ipc_manager_set_suite(ipc_manager_t *mgr, crypto_suite_t suite) {
    if (mgr->suite == suite) return;
    mgr->suite = suite;

    /* Reconnect sockets to the new suite */
    if (mgr->rx_fd >= 0) {
        close(mgr->rx_fd);
        mgr->rx_fd = -1;
    }
    pthread_mutex_lock(&mgr->tx_mu);
    if (mgr->tx_fd >= 0) {
        close(mgr->tx_fd);
        mgr->tx_fd = -1;
    }
    pthread_mutex_unlock(&mgr->tx_mu);

    trigger_status_update(mgr);
}

crypto_suite_t ipc_manager_get_suite(ipc_manager_t *mgr) {
    return mgr->suite;
}

bool ipc_manager_start_server(ipc_manager_t *mgr, const char *workspace_root) {
    if (mgr->server_pid > 0) {
        return true; /* Already running */
    }

    char sec_bin[2048];
    snprintf(sec_bin, sizeof(sec_bin), "%s/securecomm/bin/securecomm", workspace_root);
    if (access(sec_bin, X_OK) == 0) {
        const char *mode_str = "pqc";
        if (mgr->suite == SUITE_HYBRID) mode_str = "hybrid";
        else if (mgr->suite == SUITE_CLASSICAL) mode_str = "classical";

        pid_t pid = fork();
        if (pid == 0) {
            execl(sec_bin, sec_bin, "server", "start", "--mode", mode_str, NULL);
            _exit(1);
        } else if (pid > 0) {
            mgr->server_pid = pid;
            mgr->server_started_by_us = true;
            trigger_status_update(mgr);
            return true;
        }
    }

    const char *subdir = "pqc";
    if (mgr->suite == SUITE_HYBRID) subdir = "hybrid";
    else if (mgr->suite == SUITE_CLASSICAL) subdir = "classical";

    char server_dir[2048];
    snprintf(server_dir, sizeof(server_dir), "%s/%s", workspace_root, subdir);

    char server_bin[2048];
    snprintf(server_bin, sizeof(server_bin), "%.2000s/server", server_dir);

    pid_t pid = fork();
    if (pid == 0) {
        /* Child */
        if (chdir(server_dir) != 0) {
            perror("chdir server_dir");
            exit(1);
        }
        execl("./server", "./server", NULL);
        perror("execl ./server");
        exit(1);
    } else if (pid > 0) {
        mgr->server_pid = pid;
        mgr->server_started_by_us = true;
        trigger_status_update(mgr);
        return true;
    }
    return false;
}

void ipc_manager_stop_server(ipc_manager_t *mgr) {
    if (mgr->server_pid > 0) {
        kill(mgr->server_pid, SIGINT);
        int status;
        waitpid(mgr->server_pid, &status, 0);
        mgr->server_pid = -1;
        mgr->server_started_by_us = false;
        trigger_status_update(mgr);
    }
}

bool ipc_manager_is_server_running(ipc_manager_t *mgr) {
    return (mgr->server_pid > 0 || mgr->rx_fd >= 0 || mgr->tx_fd >= 0);
}

int ipc_manager_send_message(ipc_manager_t *mgr, uint16_t target_client_id,
                             const char *text, uint32_t len) {
    pthread_mutex_lock(&mgr->tx_mu);
    if (mgr->tx_fd < 0) {
        pthread_mutex_unlock(&mgr->tx_mu);
        return -1;
    }

    ipc_tx_cmd_t cmd;
    cmd.client_id = target_client_id;
    cmd.msg_len = len;

    size_t total_payload = sizeof(cmd) + len;
    uint8_t *payload_buf = malloc(total_payload);
    if (!payload_buf) {
        pthread_mutex_unlock(&mgr->tx_mu);
        return -1;
    }

    memcpy(payload_buf, &cmd, sizeof(cmd));
    if (text && len > 0) {
        memcpy(payload_buf + sizeof(cmd), text, len);
    }

    int rc = ipc_send_frame(mgr->tx_fd, IPC_MSG_TX_CMD, target_client_id,
                            payload_buf, (uint32_t)total_payload);
    free(payload_buf);
    pthread_mutex_unlock(&mgr->tx_mu);
    return rc;
}

void ipc_manager_reconnect(ipc_manager_t *mgr) {
    if (mgr->rx_fd >= 0) { close(mgr->rx_fd); mgr->rx_fd = -1; }
    pthread_mutex_lock(&mgr->tx_mu);
    if (mgr->tx_fd >= 0) { close(mgr->tx_fd); mgr->tx_fd = -1; }
    pthread_mutex_unlock(&mgr->tx_mu);
    trigger_status_update(mgr);
}
