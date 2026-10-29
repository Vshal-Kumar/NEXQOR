#
# SecureComm: Lightweight, Adaptive, Cross-Platform Secure Communication Framework
# Production Makefile
#

CC ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2
SAN_FLAGS = -fsanitize=address,undefined -g -O1

PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
SYSCONFDIR ?= /etc/securecomm
VARDIR ?= /var/lib/securecomm
LOGDIR ?= /var/log/securecomm
SYSTEMDDIR ?= /usr/lib/systemd/system

REPO_ROOT = $(shell pwd)/..
LIBOQS_DIR = $(REPO_ROOT)/liboqs/build
HYBRID_DIR = $(REPO_ROOT)/hybrid

INCLUDES = -Iinclude -I$(LIBOQS_DIR)/include -I$(HYBRID_DIR)/include
LDFLAGS = -L$(HYBRID_DIR) -L$(LIBOQS_DIR)/lib
LIBS = -lhybrid -loqs -lcrypto -lpthread

SRCS = src/common.c \
       src/error.c \
       src/logging/logging.c \
       src/config/json_parser.c \
       src/config/config.c \
       src/device/device_profile.c \
       src/profiles/profile_registry.c \
       src/policy/policy.c \
       src/adaptive/adaptive.c \
       src/identity/identity.c \
       src/monitoring/metrics.c \
       backends/crypto_backend.c \
       src/server/server.c \
       src/client/client.c \
       src/setup/setup_wizard.c \
       src/cli/cli.c

OBJS = $(SRCS:.c=.o)
MAIN_SRC = src/main.c
MAIN_OBJ = src/main.o

TARGET = bin/securecomm

TEST_UNIT_SRCS = tests/unit/test_config.c \
                 tests/unit/test_device.c \
                 tests/unit/test_profiles.c \
                 tests/unit/test_adaptive.c \
                 tests/unit/test_identity.c

TEST_INTEG_SRCS = tests/integration/test_client_server.c

TEST_UNIT_BINS = $(TEST_UNIT_SRCS:.c=)
TEST_INTEG_BINS = $(TEST_INTEG_SRCS:.c=)

.PHONY: all clean test unit_tests integration_tests install uninstall package sanitize

all: $(TARGET)

$(TARGET): $(OBJS) $(MAIN_OBJ)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(OBJS) $(MAIN_OBJ) $(LDFLAGS) $(LIBS) -o $@
	@echo "Built $(TARGET) successfully."

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

sanitize: CFLAGS += $(SAN_FLAGS)
sanitize: clean $(TARGET)
	@echo "Built with AddressSanitizer and UndefinedBehaviorSanitizer."

tests/unit/%: tests/unit/%.c $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) $< $(OBJS) $(LDFLAGS) $(LIBS) -o $@

tests/integration/%: tests/integration/%.c $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) $< $(OBJS) $(LDFLAGS) $(LIBS) -o $@

test: unit_tests integration_tests

unit_tests: $(TEST_UNIT_BINS)
	@echo "=== Running Unit Tests ==="
	@for t in $(TEST_UNIT_BINS); do \
		echo "Running $$t..."; \
		./$$t || exit 1; \
	done

integration_tests: $(TEST_INTEG_BINS)
	@echo "=== Running Integration Tests ==="
	@for t in $(TEST_INTEG_BINS); do \
		echo "Running $$t..."; \
		./$$t || exit 1; \
	done

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)/securecomm
	install -d -m 0700 $(DESTDIR)$(SYSCONFDIR)
	install -d -m 0700 $(DESTDIR)$(VARDIR)
	install -d -m 0750 $(DESTDIR)$(LOGDIR)
	@if [ -f packaging/systemd/securecomm.service ]; then \
		install -d $(DESTDIR)$(SYSTEMDDIR); \
		install -m 0644 packaging/systemd/securecomm.service $(DESTDIR)$(SYSTEMDDIR)/securecomm.service; \
	fi
	@echo "Installed SecureComm to $(DESTDIR)$(PREFIX)"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/securecomm
	rm -f $(DESTDIR)$(SYSTEMDDIR)/securecomm.service
	@echo "Uninstalled binary and service. Configuration at $(DESTDIR)$(SYSCONFDIR) preserved."

package:
	@chmod +x packaging/debian/build_deb.sh
	@./packaging/debian/build_deb.sh all

package-all:
	@chmod +x packaging/debian/build_deb.sh
	@./packaging/debian/build_deb.sh all

package-x86:
	@chmod +x packaging/debian/build_deb.sh
	@./packaging/debian/build_deb.sh x86

package-x86amd: package-x86
package-amd64: package-x86

package-arm64:
	@chmod +x packaging/debian/build_deb.sh
	@./packaging/debian/build_deb.sh arm64

package-arm32:
	@chmod +x packaging/debian/build_deb.sh
	@./packaging/debian/build_deb.sh arm32

package-armhf: package-arm32

clean:
	rm -f $(OBJS) $(MAIN_OBJ) $(TARGET)
	rm -f $(TEST_UNIT_BINS) $(TEST_INTEG_BINS)
	rm -rf bin
	rm -rf packaging/debian/staging
	rm -f packaging/debian/*.deb
	@echo "Clean completed."
