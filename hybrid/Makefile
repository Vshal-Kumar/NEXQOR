# hybrid/Makefile — QRYPTONEX Hybrid Cryptographic Suite [x86_64]
# Suite ID: QRYPTONEX-HYBRID-X25519-MLKEM768-ED25519-MLDSA65
#
# Primitives:
#   - Classical KEX:       X25519 (RFC 7748) via OpenSSL 3.x EVP
#   - Post-Quantum KEM:    ML-KEM-768 (FIPS 203) via liboqs
#   - Classical Sig:       Ed25519 (RFC 8032) via OpenSSL 3.x EVP
#   - Post-Quantum Sig:    ML-DSA-65 (FIPS 204) via liboqs
#   - Session Encryption:  ChaCha20-Poly1305 (RFC 8439) via OpenSSL EVP
#   - Key Derivation:      HKDF-SHA-384 (RFC 5869)
#   - Transcript Hashing:  SHA-384 (FIPS 180-4)
#   - Replay Protection:   RFC 6479 64-packet sliding window
#
# Executables built:
#   server           — High-concurrency Linux UDP event loop server (port 9879)
#   server_rx        — IPC telemetry receiver terminal
#   server_tx        — IPC command transmitter terminal
#   client           — Interactive mutual authentication chat client
#   client_broadcast — Autonomous IoT telemetry broadcaster
#   bench_crypto     — Cryptographic microbenchmark suite
#   bench_pqc        — Compatibility alias for bench_crypto
#   bench_hybrid     — Alias for bench_crypto
#   bench_nclient    — Multi-client concurrent handshake benchmark
#   bench_aead       — ChaCha20-Poly1305 benchmark and file encrypt/decrypt tool
#   tests/*          — Automated security and regression test suite

CC      ?= gcc
ARCH    ?= $(shell uname -m)

LIBOQS  ?= ../liboqs/build

ifneq ($(wildcard $(LIBOQS)/lib/liboqs.a),)
  INC_OQS = -I$(LIBOQS)/include
  LIB_OQS = $(LIBOQS)/lib/liboqs.a
else
  INC_OQS = -I/usr/local/include
  LIB_OQS = -loqs
endif

INC     = -I./include -I. $(INC_OQS)
LIBS    = $(LIB_OQS) -lssl -lcrypto -lpthread -lm

# ── Compiler & Linker Flags ─────────────────────────────────────────
OPT     = -O3 -march=native -mtune=native -funroll-loops -fomit-frame-pointer -fno-plt
FAST    = $(OPT) -ffast-math
LTO     = -flto=auto
WARN    = -Wall -Wextra -Wno-unused-parameter
DEFS    = -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -D_GNU_SOURCE

CFLAGS  = -std=c11 $(OPT) $(LTO) $(WARN) $(DEFS) $(INC)
LDFLAGS = $(LTO)

# ── Objects ─────────────────────────────────────────────────────────
LOCAL_SHARED_OBJS = wrappers/kem_wrapper.o \
                    wrappers/dsa_wrapper.o \
                    crypto/aead.o \
                    crypto/replay_window.o \
                    crypto/trust_store.o

HYBRID_OBJS = src/hybrid_errors.o \
              src/hybrid_crypto.o \
              src/hybrid_kdf.o \
              src/hybrid_kex.o \
              src/hybrid_signature.o \
              src/hybrid_handshake.o \
              src/hybrid_session.o

LIB_STATIC = libhybrid.a

SERVER_OBJS = $(HYBRID_OBJS) $(LOCAL_SHARED_OBJS) transport.o client_registry.o

SHARED_APP_OBJS = $(HYBRID_OBJS) $(LOCAL_SHARED_OBJS) transport.o

TEST_BINS = tests/test_hybrid_kex \
            tests/test_hybrid_signatures \
            tests/test_hybrid_kdf \
            tests/test_hybrid_handshake \
            tests/test_hybrid_session \
            tests/test_replay_protection \
            tests/test_negative_cases

EXAMPLE_BINS = examples/hybrid_server \
               examples/hybrid_client

# ── Rules ───────────────────────────────────────────────────────────
.PHONY: all clean test examples server server_rx server_tx client client_broadcast \
        bench_crypto bench_pqc bench_hybrid bench_nclient bench_aead

all: $(LIB_STATIC) server server_rx server_tx client client_broadcast \
     bench_crypto bench_pqc bench_hybrid bench_nclient bench_aead $(TEST_BINS) examples

$(LIB_STATIC): $(HYBRID_OBJS)
	ar rcs $@ $^

wrappers/%.o: wrappers/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

crypto/%.o: crypto/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

transport.o: transport.c transport.h
	$(CC) $(FAST) $(LTO) $(WARN) $(DEFS) $(INC) -c -o $@ $<

client_registry.o: client_registry.c client_registry.h transport.h
	$(CC) $(CFLAGS) -c -o $@ $<

# ── Application Binaries ────────────────────────────────────────────
server: server.c $(SERVER_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) $(LDFLAGS)

server_rx: server_rx.c transport.o $(HYBRID_OBJS) $(LOCAL_SHARED_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) $(LDFLAGS)

server_tx: server_tx.c transport.o $(HYBRID_OBJS) $(LOCAL_SHARED_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) $(LDFLAGS)

client: client.c $(SHARED_APP_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) $(LDFLAGS)

client_broadcast: client_broadcast.c $(SHARED_APP_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) $(LDFLAGS)

bench_crypto: bench_crypto.c $(SHARED_APP_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) $(LDFLAGS)

bench_pqc: bench_crypto
	ln -sf bench_crypto bench_pqc

bench_hybrid: bench_crypto
	ln -sf bench_crypto bench_hybrid

bench_nclient: bench_nclient.c $(SHARED_APP_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) $(LDFLAGS)

bench_aead: bench_aead.c $(LOCAL_SHARED_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) $(LDFLAGS)

# ── Test Binaries ───────────────────────────────────────────────────
tests/%: tests/%.c $(LIB_STATIC) $(LOCAL_SHARED_OBJS)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_STATIC) $(LOCAL_SHARED_OBJS) $(LIBS) $(LDFLAGS)

test: $(TEST_BINS)
	@echo "╔════════════════════════════════════════════════════════════════╗"
	@echo "║      QRYPTONEX Hybrid Suite Automated Regression Test Suite    ║"
	@echo "╚════════════════════════════════════════════════════════════════╝"
	@for t in $(TEST_BINS); do \
		echo "Running $$t..."; \
		./$$t || exit 1; \
	done
	@echo "All Hybrid Cryptographic Tests Passed Successfully!"

# ── Example Binaries ────────────────────────────────────────────────
examples: $(EXAMPLE_BINS)

examples/hybrid_server: examples/hybrid_server.c $(LIB_STATIC) $(LOCAL_SHARED_OBJS)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_STATIC) $(LOCAL_SHARED_OBJS) $(LIBS) $(LDFLAGS)

examples/hybrid_client: examples/hybrid_client.c $(LIB_STATIC) $(LOCAL_SHARED_OBJS)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_STATIC) $(LOCAL_SHARED_OBJS) $(LIBS) $(LDFLAGS)

# ── Clean ───────────────────────────────────────────────────────────
clean:
	rm -f $(HYBRID_OBJS) $(LOCAL_SHARED_OBJS) $(LIB_STATIC) transport.o client_registry.o \
	      server server_rx server_tx client client_broadcast \
	      bench_crypto bench_pqc bench_hybrid bench_nclient bench_aead \
	      $(TEST_BINS) $(EXAMPLE_BINS) server_endpoint.info

clean-arm64:
	$(MAKE) -f Makefile.arm64 clean

clean-arm32:
	$(MAKE) -f Makefile.arm32 clean

clean-all: clean clean-arm64 clean-arm32

