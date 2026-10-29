# QRYPTONEX Security Evaluation & Resilience Testing Framework
# Pure C11 Linux Network Security Testing Framework

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -pthread -std=c11 -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -D_GNU_SOURCE -Iinclude
LDFLAGS ?= -pthread -lm

BIN     := security_lab
SRCS    := src/main.c \
           src/test_engine.c \
           src/suite_adapter.c \
           src/metrics.c \
           src/safety_guard.c \
           src/protocol_framer.c \
           attacks/network_resilience.c \
           attacks/replay_test.c \
           attacks/packet_tampering.c \
           attacks/authentication_test.c \
           attacks/handshake_test.c \
           attacks/malformed_packet_test.c \
           attacks/resource_stress.c \
           attacks/session_isolation.c \
           monitoring/packet_observer.c \
           monitoring/server_health.c \
           monitoring/resource_monitor.c \
           monitoring/recovery_monitor.c \
           reporting/csv_writer.c \
           reporting/json_writer.c \
           reporting/comparison_report.c

OBJS    := $(SRCS:.c=.o)

TEST_SRCS := tests/test_safety.c tests/test_packet_parser.c tests/test_metrics.c
TEST_BINS := tests/test_safety tests/test_packet_parser tests/test_metrics

.PHONY: all clean test run-dry-run run-baseline run-all help

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Successfully built: $(BIN) [Pure C Security Testing Engine]"

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# ── Unit Tests ───────────────────────────────────────────────────────
tests/test_safety: tests/test_safety.c src/safety_guard.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

tests/test_packet_parser: tests/test_packet_parser.c src/protocol_framer.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

tests/test_metrics: tests/test_metrics.c src/metrics.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test: tests/test_safety tests/test_packet_parser tests/test_metrics
	@echo ""
	@echo "╔══════════════════════════════════════════════════════════════════════════╗"
	@echo "║       Running Security Lab Automated Unit & Safety Test Suite            ║"
	@echo "╚══════════════════════════════════════════════════════════════════════════╝"
	./tests/test_safety
	./tests/test_packet_parser
	./tests/test_metrics
	@echo "ALL UNIT & SAFETY VERIFICATION TESTS PASSED SUCCESSFULLY!"
	@echo ""

# ── Convenient Execution Targets ─────────────────────────────────────
run-dry-run: $(BIN)
	./$(BIN) --suite all --scenario all --dry-run

run-baseline: $(BIN)
	./$(BIN) --suite pqc --scenario baseline

run-all: $(BIN)
	./$(BIN) --suite all --scenario all

ui:
	$(MAKE) -C ui all

run-ui: ui
	./ui/attack_ui

clean:
	rm -f $(OBJS) $(BIN) $(TEST_BINS)
	rm -f /tmp/security_lab_server.log
	$(MAKE) -C ui clean
	@echo "Security lab artifacts cleaned."

help:
	@echo "Usage: make [all|test|run-dry-run|run-baseline|run-all|clean]"
