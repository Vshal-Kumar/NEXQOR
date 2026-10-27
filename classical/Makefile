# classical/Makefile — QRYPTONEX Classical IoT Cryptographic Implementation [x86-64]
#
# Cryptographic Suite:
#   - Key Agreement: X25519 ECDH (RFC 7748) via OpenSSL 3.x EVP
#   - Signatures:    Ed25519 (RFC 8032) via OpenSSL 3.x EVP
#   - AEAD:          AES-128-CCM with wire header AAD (NIST SP 800-38C)
#   - Digest:        SHA-256 (FIPS 180-4)
#   - KDF:           HKDF-SHA-256 (RFC 5869)
#   - MAC:           HMAC-SHA-256 (RFC 2104)
#
# Executables built:
#   server           — High-concurrency Linux io_uring server (port 9877)
#   server_rx        — IPC telemetry receiver terminal
#   server_tx        — IPC command transmitter terminal
#   client           — Interactive mutual authentication chat client
#   client_broadcast — Autonomous IoT telemetry broadcaster
#   bench_crypto     — Cryptographic microbenchmark suite
#   bench_pqc        — Compatibility alias for bench_crypto
#   bench_nclient    — Multi-client concurrent handshake benchmark
#   bench_aead       — AES-128-CCM benchmark and file encrypt/decrypt tool
#   tests/test_suite — Automated security and regression test suite
#
# Dependencies:
#   OpenSSL 3.x (libssl, libcrypto)
#   liburing (Linux io_uring event loop)
#   pthreads, libm

CC      ?= gcc
ARCH    ?= $(shell uname -m)

LIBURING_LOCAL = ../liburing_local

ifneq ($(wildcard $(LIBURING_LOCAL)/lib/liburing.a),)
  INC_URING = -I$(LIBURING_LOCAL)/include
  LIB_URING = $(LIBURING_LOCAL)/lib/liburing.a
else ifneq ($(wildcard /usr/lib/aarch64-linux-gnu/liburing.so.2),)
  INC_URING = -I$(LIBURING_LOCAL)/include
  LIB_URING = /usr/lib/aarch64-linux-gnu/liburing.so.2
else ifneq ($(wildcard /usr/lib/x86_64-linux-gnu/liburing.so.2),)
  INC_URING = -I$(LIBURING_LOCAL)/include
  LIB_URING = /usr/lib/x86_64-linux-gnu/liburing.so.2
else ifneq ($(wildcard $(LIBURING_LOCAL)/include/liburing.h),)
  INC_URING = -I$(LIBURING_LOCAL)/include
  LIB_URING = -luring
else
  INC_URING =
  LIB_URING = -luring
endif

INC     = -I. $(INC_URING)
LIBS    = $(LIB_URING) -lssl -lcrypto -lpthread -lm

# ── Compiler Flags ──────────────────────────────────────────────────
OPT     = -O3 -march=native -mtune=native -funroll-loops -fomit-frame-pointer -fno-plt
FAST    = $(OPT) -ffast-math
LTO     = -flto=auto
WARN    = -Wall -Wextra -Wno-unused-parameter
DEFS    = -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -D_GNU_SOURCE

CFLAGS  = -std=c11 $(OPT) $(LTO) $(WARN) $(DEFS) $(INC)
LDFLAGS = $(LTO)

# ── Object Compilation ──────────────────────────────────────────────
transport.o: transport.c transport.h
	$(CC) $(FAST) $(LTO) $(WARN) $(DEFS) $(INC) -c -o $@ $<

crypto/aead.o: crypto/aead.c crypto/aead.h
	$(CC) $(OPT) $(LTO) $(WARN) $(DEFS) $(INC) -c -o $@ $<

crypto/replay_window.o: crypto/replay_window.c crypto/replay_window.h
	$(CC) $(OPT) $(LTO) $(WARN) $(DEFS) $(INC) -c -o $@ $<

crypto/trust_store.o: crypto/trust_store.c crypto/trust_store.h wrappers/dsa_wrapper.h
	$(CC) $(OPT) $(LTO) $(WARN) $(DEFS) $(INC) -c -o $@ $<

wrappers/kem_wrapper.o: wrappers/kem_wrapper.c wrappers/kem_wrapper.h
	$(CC) $(OPT) $(LTO) $(WARN) $(DEFS) $(INC) -c -o $@ $<

wrappers/dsa_wrapper.o: wrappers/dsa_wrapper.c wrappers/dsa_wrapper.h
	$(CC) $(OPT) $(LTO) $(WARN) $(DEFS) $(INC) -c -o $@ $<

wrappers/hash_wrapper.o: wrappers/hash_wrapper.c wrappers/hash_wrapper.h
	$(CC) $(OPT) $(LTO) $(WARN) $(DEFS) $(INC) -c -o $@ $<

wrappers/kdf_wrapper.o: wrappers/kdf_wrapper.c wrappers/kdf_wrapper.h
	$(CC) $(OPT) $(LTO) $(WARN) $(DEFS) $(INC) -c -o $@ $<

client_registry.o: client_registry.c client_registry.h transport.h
	$(CC) $(CFLAGS) -c -o $@ $<

# ── Object Groups ───────────────────────────────────────────────────
SHARED_OBJS = transport.o \
              crypto/aead.o \
              crypto/replay_window.o \
              crypto/trust_store.o \
              wrappers/kem_wrapper.o \
              wrappers/dsa_wrapper.o \
              wrappers/hash_wrapper.o \
              wrappers/kdf_wrapper.o

SERVER_OBJS = $(SHARED_OBJS) client_registry.o

# ── Primary Targets ─────────────────────────────────────────────────
.PHONY: all server server_rx server_tx client client_broadcast \
        bench_crypto bench_pqc bench_nclient bench_aead test verify clean \
        run-server run-rx run-tx run-client run-broadcast run-bench

all: server server_rx server_tx client client_broadcast bench_crypto bench_pqc bench_nclient bench_aead tests/test_suite

server: server.c $(SERVER_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) $(LDFLAGS)

server_rx: server_rx.c transport.o crypto/aead.o crypto/replay_window.o
	$(CC) $(CFLAGS) -o $@ $^ -lssl -lcrypto -lpthread -lm $(LDFLAGS)

server_tx: server_tx.c transport.o crypto/aead.o crypto/replay_window.o
	$(CC) $(CFLAGS) -o $@ $^ -lssl -lcrypto -lpthread -lm $(LDFLAGS)

client: client.c $(SHARED_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) $(LDFLAGS)

client_broadcast: client_broadcast.c $(SHARED_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) $(LDFLAGS)

bench_crypto: bench_crypto.c $(SHARED_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) $(LDFLAGS)

bench_pqc: bench_crypto
	ln -sf bench_crypto bench_pqc

bench_nclient: bench_nclient.c $(SHARED_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) $(LDFLAGS)

bench_aead: bench_aead.c crypto/aead.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) $(LDFLAGS)

tests/test_suite: tests/test_suite.c $(SHARED_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) $(LDFLAGS)

test: tests/test_suite
	@./tests/test_suite

verify:
	@if command -v proverif >/dev/null 2>&1; then \
		proverif verification/protocol.pv; \
	elif command -v opam >/dev/null 2>&1; then \
		opam exec -- proverif verification/protocol.pv; \
	else \
		echo "ProVerif not found. Please install ProVerif to run formal verification."; \
	fi

clean:
	rm -f server server_rx server_tx client client_broadcast \
	      bench_crypto bench_pqc bench_nclient bench_aead \
	      tests/test_suite *.o crypto/*.o wrappers/*.o \
	      server_identity.key server_identity.pub authorized_clients.db \
	      server_endpoint.info test_classical_srv.*
