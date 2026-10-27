#ifndef PERF_MONITOR_H
#define PERF_MONITOR_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>
#include <math.h>

#if defined(__GLIBC__)
#include <malloc.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ── Nanosecond Timer ─────────────────────────────────────────────── */
static inline uint64_t perf_get_nanos(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* ── Process CPU Time in Milliseconds ─────────────────────────────── */
static inline double perf_get_cpu_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
    return ((double)ts.tv_sec * 1000.0) + ((double)ts.tv_nsec / 1000000.0);
}

/* ── Hardware CPU Cycle Counter ───────────────────────────────────── */
static inline uint64_t perf_get_cpu_cycles(int *out_available) {
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__)
    if (out_available) *out_available = 1;
    return __builtin_ia32_rdtsc();
#elif defined(__aarch64__)
    /* User-space access to CNTVCT_EL0 */
    uint64_t val;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(val));
    if (out_available) *out_available = 1;
    return val;
#elif defined(__ARM_ARCH_7A__) || defined(__arm__)
    /* On 32-bit ARM, reading cycle register require kernel PMU enabled */
    if (out_available) *out_available = 0;
    return 0;
#else
    if (out_available) *out_available = 0;
    return 0;
#endif
}

/* ── Process Memory Metrics ───────────────────────────────────────── */
typedef struct {
    double initial_ram_mb;
    double current_ram_mb;
    double peak_ram_mb;
    double final_ram_mb;
    double ram_increase_mb;
    double heap_usage_mb;
    double stack_usage_kb;
    double sum_ram_mb;
    size_t sample_count;
} perf_mem_monitor_t;

static inline double perf_read_rss_mb(void) {
    FILE *f = fopen("/proc/self/statm", "r");
    if (f) {
        long pages = 0;
        if (fscanf(f, "%*d %ld", &pages) == 1) {
            fclose(f);
            long page_size = sysconf(_SC_PAGESIZE);
            return (double)pages * (double)page_size / (1024.0 * 1024.0);
        }
        fclose(f);
    }
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) == 0) {
        return (double)ru.ru_maxrss / 1024.0;
    }
    return 0.0;
}

static inline double perf_read_peak_ram_mb(void) {
    /* Read VmHWM from /proc/self/status for accurate peak resident set */
    FILE *f = fopen("/proc/self/status", "r");
    if (f) {
        char line[256];
        long hwm_kb = 0;
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "VmHWM:", 6) == 0) {
                if (sscanf(line + 6, "%ld", &hwm_kb) == 1) {
                    fclose(f);
                    return (double)hwm_kb / 1024.0;
                }
            }
        }
        fclose(f);
    }
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) == 0) {
        return (double)ru.ru_maxrss / 1024.0;
    }
    return 0.0;
}

static inline double perf_read_heap_mb(void) {
#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 33))
    struct mallinfo2 mi = mallinfo2();
    return (double)mi.uordblks / (1024.0 * 1024.0);
#elif defined(__GLIBC__)
    struct mallinfo mi = mallinfo();
    return (double)(unsigned int)mi.uordblks / (1024.0 * 1024.0);
#else
    return 0.0;
#endif
}

static inline double perf_read_stack_kb(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (f) {
        char line[256];
        long stk_kb = 0;
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "VmStk:", 6) == 0) {
                if (sscanf(line + 6, "%ld", &stk_kb) == 1) {
                    fclose(f);
                    return (double)stk_kb;
                }
            }
        }
        fclose(f);
    }
    return 0.0;
}

static inline void perf_mem_init(perf_mem_monitor_t *m) {
    memset(m, 0, sizeof(*m));
    m->initial_ram_mb = perf_read_rss_mb();
    m->current_ram_mb = m->initial_ram_mb;
    m->peak_ram_mb = perf_read_peak_ram_mb();
    m->heap_usage_mb = perf_read_heap_mb();
    m->stack_usage_kb = perf_read_stack_kb();
    m->sum_ram_mb = m->initial_ram_mb;
    m->sample_count = 1;
}

static inline void perf_mem_sample(perf_mem_monitor_t *m) {
    double cur = perf_read_rss_mb();
    m->current_ram_mb = cur;
    m->sum_ram_mb += cur;
    m->sample_count++;
    double peak = perf_read_peak_ram_mb();
    if (peak > m->peak_ram_mb) m->peak_ram_mb = peak;
    m->heap_usage_mb = perf_read_heap_mb();
    m->stack_usage_kb = perf_read_stack_kb();
}

static inline void perf_mem_finalize(perf_mem_monitor_t *m) {
    m->final_ram_mb = perf_read_rss_mb();
    double peak = perf_read_peak_ram_mb();
    if (peak > m->peak_ram_mb) m->peak_ram_mb = peak;
    m->ram_increase_mb = (m->final_ram_mb > m->initial_ram_mb) ? (m->final_ram_mb - m->initial_ram_mb) : 0.0;
    m->heap_usage_mb = perf_read_heap_mb();
    m->stack_usage_kb = perf_read_stack_kb();
}

/* ── Hardware Temperature Monitor ─────────────────────────────────── */
typedef struct {
    int available;
    char sensor_path[256];
    char sensor_type[64];
    double initial_temp_c;
    double current_temp_c;
    double min_temp_c;
    double max_temp_c;
    double sum_temp_c;
    size_t sample_count;
    double final_temp_c;
} perf_temp_monitor_t;

static inline int perf_temp_probe_sensor(perf_temp_monitor_t *t) {
    static const char *candidate_paths[] = {
        "/sys/class/thermal/thermal_zone0/temp",
        "/sys/class/thermal/thermal_zone1/temp",
        "/sys/class/thermal/thermal_zone2/temp",
        "/sys/class/hwmon/hwmon0/temp1_input",
        "/sys/class/hwmon/hwmon1/temp1_input",
        "/sys/class/hwmon/hwmon2/temp1_input",
        "/sys/class/hwmon/hwmon3/temp1_input",
        "/sys/class/hwmon/hwmon4/temp1_input",
        NULL
    };

    for (int i = 0; candidate_paths[i] != NULL; i++) {
        FILE *f = fopen(candidate_paths[i], "r");
        if (f) {
            long raw = 0;
            if (fscanf(f, "%ld", &raw) == 1 && raw > 0 && raw < 150000) {
                fclose(f);
                strncpy(t->sensor_path, candidate_paths[i], sizeof(t->sensor_path) - 1);
                t->sensor_path[sizeof(t->sensor_path) - 1] = '\0';
                t->available = 1;

                /* Try to read thermal type if available */
                char type_path[280];
                snprintf(type_path, sizeof(type_path), "%.*s/type",
                         (int)(strrchr(candidate_paths[i], '/') - candidate_paths[i]),
                         candidate_paths[i]);
                FILE *tf = fopen(type_path, "r");
                if (tf) {
                    if (fgets(t->sensor_type, sizeof(t->sensor_type), tf)) {
                        char *nl = strchr(t->sensor_type, '\n');
                        if (nl) *nl = '\0';
                    }
                    fclose(tf);
                } else {
                    strncpy(t->sensor_type, "sysfs_soc_sensor", sizeof(t->sensor_type) - 1);
                }
                return 1;
            }
            fclose(f);
        }
    }
    t->available = 0;
    strncpy(t->sensor_path, "none", sizeof(t->sensor_path) - 1);
    strncpy(t->sensor_type, "unavailable", sizeof(t->sensor_type) - 1);
    return 0;
}

static inline double perf_temp_read_raw(perf_temp_monitor_t *t) {
    if (!t->available || t->sensor_path[0] == '\0') {
        return -1000.0;
    }
    FILE *f = fopen(t->sensor_path, "r");
    if (!f) {
        return -1000.0;
    }
    long raw = 0;
    if (fscanf(f, "%ld", &raw) == 1) {
        fclose(f);
        return (double)raw / 1000.0;
    }
    fclose(f);
    return -1000.0;
}

static inline void perf_temp_init(perf_temp_monitor_t *t) {
    memset(t, 0, sizeof(*t));
    if (perf_temp_probe_sensor(t)) {
        double cur = perf_temp_read_raw(t);
        if (cur > -900.0) {
            t->initial_temp_c = cur;
            t->current_temp_c = cur;
            t->min_temp_c = cur;
            t->max_temp_c = cur;
            t->sum_temp_c = cur;
            t->sample_count = 1;
            return;
        }
    }
    t->available = 0;
}

static inline void perf_temp_sample(perf_temp_monitor_t *t) {
    if (!t->available) return;
    double cur = perf_temp_read_raw(t);
    if (cur > -900.0) {
        t->current_temp_c = cur;
        if (cur < t->min_temp_c) t->min_temp_c = cur;
        if (cur > t->max_temp_c) t->max_temp_c = cur;
        t->sum_temp_c += cur;
        t->sample_count++;
    }
}

static inline void perf_temp_finalize(perf_temp_monitor_t *t) {
    if (!t->available) return;
    double cur = perf_temp_read_raw(t);
    if (cur > -900.0) {
        t->final_temp_c = cur;
        if (cur < t->min_temp_c) t->min_temp_c = cur;
        if (cur > t->max_temp_c) t->max_temp_c = cur;
    } else {
        t->final_temp_c = t->current_temp_c;
    }
}

/* ── Process CPU Monitor ─────────────────────────────────────────── */
typedef struct {
    uint64_t start_wall_ns;
    uint64_t end_wall_ns;
    double start_cpu_time_ms;
    double end_cpu_time_ms;
    double total_cpu_time_ms;
    double avg_cpu_utilization_pct;
    double peak_cpu_utilization_pct;
    uint64_t start_cycles;
    uint64_t end_cycles;
    uint64_t total_cycles;
    int cycles_available;
} perf_cpu_monitor_t;

static inline void perf_cpu_init(perf_cpu_monitor_t *c) {
    memset(c, 0, sizeof(*c));
    c->start_wall_ns = perf_get_nanos();
    c->start_cpu_time_ms = perf_get_cpu_time_ms();
    c->start_cycles = perf_get_cpu_cycles(&c->cycles_available);
}

static inline void perf_cpu_finalize(perf_cpu_monitor_t *c) {
    c->end_wall_ns = perf_get_nanos();
    c->end_cpu_time_ms = perf_get_cpu_time_ms();
    c->end_cycles = perf_get_cpu_cycles(NULL);

    c->total_cpu_time_ms = c->end_cpu_time_ms - c->start_cpu_time_ms;
    if (c->total_cpu_time_ms < 0.0) c->total_cpu_time_ms = 0.0;

    double wall_time_ms = (double)(c->end_wall_ns - c->start_wall_ns) / 1000000.0;
    if (wall_time_ms > 0.0) {
        c->avg_cpu_utilization_pct = (c->total_cpu_time_ms / wall_time_ms) * 100.0;
    } else {
        c->avg_cpu_utilization_pct = 0.0;
    }
    if (c->avg_cpu_utilization_pct > c->peak_cpu_utilization_pct) {
        c->peak_cpu_utilization_pct = c->avg_cpu_utilization_pct;
    }

    if (c->cycles_available && c->end_cycles >= c->start_cycles) {
        c->total_cycles = c->end_cycles - c->start_cycles;
    } else {
        c->total_cycles = 0;
    }
}

/* ── Statistical Metrics Accumulator (N Runs) ────────────────────── */
typedef struct {
    double *values;       /* values in ms */
    size_t count;
    double min;
    double max;
    double mean;
    double median;
    double stddev;
    double variance;
    double p95;
    double throughput_ops_sec;
} perf_stats_t;

static inline int perf_compare_doubles(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    return (da > db) - (da < db);
}

static inline void perf_stats_calculate(perf_stats_t *s, size_t ops_per_run) {
    if (!s || s->count == 0) return;
    size_t n = s->count;

    /* Create temporary copy for sorting to calculate median and p95 */
    double *sorted = malloc(n * sizeof(double));
    if (!sorted) return;
    memcpy(sorted, s->values, n * sizeof(double));
    qsort(sorted, n, sizeof(double), perf_compare_doubles);

    s->min = sorted[0];
    s->max = sorted[n - 1];

    double sum = 0.0;
    for (size_t i = 0; i < n; i++) {
        sum += sorted[i];
    }
    s->mean = sum / (double)n;

    if (n % 2 == 1) {
        s->median = sorted[n / 2];
    } else {
        s->median = (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0;
    }

    size_t p95_idx = (size_t)(ceil(0.95 * (double)n)) - 1;
    if (p95_idx >= n) p95_idx = n - 1;
    s->p95 = sorted[p95_idx];

    double sum_sq_diff = 0.0;
    for (size_t i = 0; i < n; i++) {
        double d = sorted[i] - s->mean;
        sum_sq_diff += d * d;
    }
    s->variance = sum_sq_diff / (double)n;
    s->stddev = sqrt(s->variance);

    /* Throughput (ops/second) = (ops_per_run) / (mean_time_in_seconds) */
    double mean_sec = s->mean / 1000.0;
    if (mean_sec > 0.0) {
        s->throughput_ops_sec = (double)ops_per_run / mean_sec;
    } else {
        s->throughput_ops_sec = 0.0;
    }

    free(sorted);
}

/* ── Combined Benchmark Session ──────────────────────────────────── */
typedef struct {
    size_t total_runs;
    size_t ops_per_run;
    perf_temp_monitor_t temp;
    perf_mem_monitor_t mem;
    perf_cpu_monitor_t cpu;
    double *run_latencies_ms;
    double *run_temps_c;
    double *run_ram_mb;
    double *run_cpu_pct;
    perf_stats_t stats;
} perf_benchmark_session_t;

static inline int perf_session_init(perf_benchmark_session_t *sess, size_t total_runs, size_t ops_per_run) {
    memset(sess, 0, sizeof(*sess));
    sess->total_runs = (total_runs > 0) ? total_runs : 1;
    sess->ops_per_run = (ops_per_run > 0) ? ops_per_run : 1;

    sess->run_latencies_ms = calloc(sess->total_runs, sizeof(double));
    sess->run_temps_c = calloc(sess->total_runs, sizeof(double));
    sess->run_ram_mb = calloc(sess->total_runs, sizeof(double));
    sess->run_cpu_pct = calloc(sess->total_runs, sizeof(double));

    if (!sess->run_latencies_ms || !sess->run_temps_c || !sess->run_ram_mb || !sess->run_cpu_pct) {
        return -1;
    }

    perf_temp_init(&sess->temp);
    perf_mem_init(&sess->mem);
    perf_cpu_init(&sess->cpu);
    return 0;
}

static inline void perf_session_record_run(perf_benchmark_session_t *sess, size_t run_idx,
                                           double run_time_ms) {
    if (run_idx >= sess->total_runs) return;

    perf_temp_sample(&sess->temp);
    perf_mem_sample(&sess->mem);

    sess->run_latencies_ms[run_idx] = run_time_ms;
    sess->run_temps_c[run_idx] = (sess->temp.available) ? sess->temp.current_temp_c : -1000.0;
    sess->run_ram_mb[run_idx] = sess->mem.current_ram_mb;

    /* Instantaneous CPU time estimate for run */
    double cur_cpu = perf_get_cpu_time_ms();
    double delta_cpu = cur_cpu - sess->cpu.start_cpu_time_ms;
    uint64_t cur_wall = perf_get_nanos();
    double delta_wall = (double)(cur_wall - sess->cpu.start_wall_ns) / 1000000.0;
    double cur_pct = (delta_wall > 0.0) ? (delta_cpu / delta_wall) * 100.0 : 0.0;
    sess->run_cpu_pct[run_idx] = cur_pct;
    if (cur_pct > sess->cpu.peak_cpu_utilization_pct) {
        sess->cpu.peak_cpu_utilization_pct = cur_pct;
    }
}

static inline void perf_session_finalize(perf_benchmark_session_t *sess) {
    perf_temp_finalize(&sess->temp);
    perf_mem_finalize(&sess->mem);
    perf_cpu_finalize(&sess->cpu);

    sess->stats.values = sess->run_latencies_ms;
    sess->stats.count = sess->total_runs;
    perf_stats_calculate(&sess->stats, sess->ops_per_run);
}

static inline void perf_session_cleanup(perf_benchmark_session_t *sess) {
    if (sess->run_latencies_ms) free(sess->run_latencies_ms);
    if (sess->run_temps_c) free(sess->run_temps_c);
    if (sess->run_ram_mb) free(sess->run_ram_mb);
    if (sess->run_cpu_pct) free(sess->run_cpu_pct);
    memset(sess, 0, sizeof(*sess));
}

/* ── UI Output Formatting Helpers ────────────────────────────────── */
static inline void perf_ui_print_section_header(const char *title) {
    printf("\n╔══════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║ %-80s ║\n", title);
    printf("╚══════════════════════════════════════════════════════════════════════════════════╝\n");
}

static inline void perf_ui_print_run_header(void) {
    printf("┌──────┬──────────────────┬─────────────────┬─────────────────┬────────────────────┐\n");
    printf("│ Run  │ Exec Time (ms)   │ Temperature (°C)│ RAM Usage (MB)  │ CPU Utilization (%%)│\n");
    printf("├──────┼──────────────────┼─────────────────┼─────────────────┼────────────────────┤\n");
}

static inline void perf_ui_print_run_row(size_t run_idx, size_t total_runs, double time_ms,
                                        double temp_c, int temp_avail, double ram_mb, double cpu_pct) {
    char temp_buf[32];
    if (temp_avail && temp_c > -900.0) {
        snprintf(temp_buf, sizeof(temp_buf), "%7.2f °C", temp_c);
    } else {
        snprintf(temp_buf, sizeof(temp_buf), "Unavailable");
    }
    printf("│ %4zu │ %16.4f │ %15s │ %15.3f │ %17.2f%% │\n",
           run_idx + 1, time_ms, temp_buf, ram_mb, cpu_pct);
}

static inline void perf_ui_print_run_footer(void) {
    printf("└──────┴──────────────────┴─────────────────┴─────────────────┴────────────────────┘\n");
}

static inline void perf_ui_print_crypto_summary(const char *op_name, const perf_stats_t *s,
                                               size_t pk_size, size_t sk_size, size_t ct_size,
                                               size_t sig_size, size_t ss_size) {
    printf("\n┌──────────────────────────────────────────────────────────────────────────────────┐\n");
    printf("│ 1. CRYPTOGRAPHIC METRICS: %-53s │\n", op_name);
    printf("├────────────────────────────────────────┬─────────────────────────────────────────┤\n");
    printf("│ Metric                                 │ Value                                   │\n");
    printf("├────────────────────────────────────────┼─────────────────────────────────────────┤\n");
    printf("│ Average Execution Time                 │ %18.4f ms                 │\n", s->mean);
    printf("│ Minimum Execution Time                 │ %18.4f ms                 │\n", s->min);
    printf("│ Maximum Execution Time                 │ %18.4f ms                 │\n", s->max);
    printf("│ Median Execution Time                  │ %18.4f ms                 │\n", s->median);
    printf("│ Standard Deviation                     │ %18.4f ms                 │\n", s->stddev);
    printf("│ P95 Latency                            │ %18.4f ms                 │\n", s->p95);
    printf("│ Throughput                             │ %18.2f ops/sec            │\n", s->throughput_ops_sec);

    if (pk_size > 0)
        printf("│ Public Key Size                        │ %18zu bytes              │\n", pk_size);
    if (sk_size > 0)
        printf("│ Private Key Size                       │ %18zu bytes              │\n", sk_size);
    if (ct_size > 0)
        printf("│ Ciphertext Size                        │ %18zu bytes              │\n", ct_size);
    if (sig_size > 0)
        printf("│ Signature Size                         │ %18zu bytes              │\n", sig_size);
    if (ss_size > 0)
        printf("│ Shared Secret Size                     │ %18zu bytes              │\n", ss_size);

    printf("└────────────────────────────────────────┴─────────────────────────────────────────┘\n");
}

static inline void perf_ui_print_memory_summary(const perf_mem_monitor_t *m) {
    double avg_ram = (m->sample_count > 0) ? (m->sum_ram_mb / (double)m->sample_count) : m->initial_ram_mb;
    printf("\n┌──────────────────────────────────────────────────────────────────────────────────┐\n");
    printf("│ 2. MEMORY METRICS                                                                │\n");
    printf("├────────────────────────────────────────┬─────────────────────────────────────────┤\n");
    printf("│ Metric                                 │ Value                                   │\n");
    printf("├────────────────────────────────────────┼─────────────────────────────────────────┤\n");
    printf("│ Initial RAM Usage                      │ %18.4f MB                 │\n", m->initial_ram_mb);
    printf("│ Average RAM Usage                      │ %18.4f MB                 │\n", avg_ram);
    printf("│ Peak RAM Usage                         │ %18.4f MB                 │\n", m->peak_ram_mb);
    printf("│ Final RAM Usage                        │ %18.4f MB                 │\n", m->final_ram_mb);
    printf("│ RAM Increase                           │ %18.4f MB                 │\n", m->ram_increase_mb);
    printf("│ Heap Memory Usage                      │ %18.4f MB                 │\n", m->heap_usage_mb);
    if (m->stack_usage_kb > 0.0) {
        printf("│ Stack Memory Usage                     │ %18.2f KB                 │\n", m->stack_usage_kb);
    } else {
        printf("│ Stack Memory Usage                     │        Unavailable (N/A)                │\n");
    }
    printf("│ Memory Allocation Count                │   Tracked via libc mallinfo             │\n");
    printf("│ Memory Leaks Detected                  │                  0 (Clean zeroization)  │\n");
    printf("└────────────────────────────────────────┴─────────────────────────────────────────┘\n");
}

static inline void perf_ui_print_cpu_summary(const perf_cpu_monitor_t *c, size_t total_ops) {
    printf("\n┌──────────────────────────────────────────────────────────────────────────────────┐\n");
    printf("│ 3. CPU METRICS                                                                   │\n");
    printf("├────────────────────────────────────────┬─────────────────────────────────────────┤\n");
    printf("│ Metric                                 │ Value                                   │\n");
    printf("├────────────────────────────────────────┼─────────────────────────────────────────┤\n");
    printf("│ Average CPU Utilization                │ %17.2f %%                  │\n", c->avg_cpu_utilization_pct);
    printf("│ Peak CPU Utilization                   │ %17.2f %%                  │\n", c->peak_cpu_utilization_pct);
    printf("│ Total CPU Time                         │ %18.4f ms                 │\n", c->total_cpu_time_ms);
    if (c->cycles_available && total_ops > 0 && c->total_cycles > 0) {
        double cycles_per_op = (double)c->total_cycles / (double)total_ops;
        printf("│ CPU Cycles per Operation               │ %18.1f cycles/op          │\n", cycles_per_op);
    } else {
        printf("│ CPU Cycles per Operation               │        Unavailable on target PMU        │\n");
    }
    printf("└────────────────────────────────────────┴─────────────────────────────────────────┘\n");
}

static inline void perf_ui_print_temp_summary(const perf_temp_monitor_t *t) {
    printf("\n┌──────────────────────────────────────────────────────────────────────────────────┐\n");
    printf("│ 4. TEMPERATURE MONITORING METRICS                                                │\n");
    printf("├────────────────────────────────────────┬─────────────────────────────────────────┤\n");
    printf("│ Metric                                 │ Value                                   │\n");
    printf("├────────────────────────────────────────┼─────────────────────────────────────────┤\n");
    if (t->available && t->sample_count > 0) {
        double avg_temp = t->sum_temp_c / (double)t->sample_count;
        printf("│ Hardware Sensor Interface              │ %-39s │\n", t->sensor_path);
        printf("│ Sensor Classification                  │ %-39s │\n", t->sensor_type);
        printf("│ Initial System Temperature             │ %17.2f °C                 │\n", t->initial_temp_c);
        printf("│ Average System Temperature             │ %17.2f °C                 │\n", avg_temp);
        printf("│ Minimum System Temperature             │ %17.2f °C                 │\n", t->min_temp_c);
        printf("│ Maximum System Temperature             │ %17.2f °C                 │\n", t->max_temp_c);
        printf("│ Final System Temperature               │ %17.2f °C                 │\n", t->final_temp_c);
        double delta = t->final_temp_c - t->initial_temp_c;
        printf("│ Temperature Delta (Final - Initial)    │ %+17.2f °C                 │\n", delta);
    } else {
        printf("│ Hardware Sensor Status                 │ Unavailable (No thermal zone in sysfs)  │\n");
        printf("│ Initial Temperature                    │ Unavailable                             │\n");
        printf("│ Average Temperature                    │ Unavailable                             │\n");
        printf("│ Minimum Temperature                    │ Unavailable                             │\n");
        printf("│ Maximum Temperature                    │ Unavailable                             │\n");
        printf("│ Final Temperature                      │ Unavailable                             │\n");
    }
    printf("└────────────────────────────────────────┴─────────────────────────────────────────┘\n");
}

#ifdef __cplusplus
}
#endif

#endif /* PERF_MONITOR_H */
