# QRYPTONEX — Multi-Suite Global Makefile
# Top-level dispatcher with Automatic Hardware Architecture Detection
#
# Supported Targets:
#   - Linux x86-64 (Server, AVX2, io_uring) -> Makefile
#   - ARM64 / AArch64 (Raspberry Pi 4 / 5, NEON) -> Makefile.arm64
#   - ARM32 / ARMv7-A (Raspberry Pi 2 / 3, armhf, NEON) -> Makefile.arm32

HOST_ARCH := $(shell uname -m)

# ── Hardware Architecture Detection ──────────────────────────────────
ifeq ($(HOST_ARCH),aarch64)
  AUTO_ARCH     := arm64
  AUTO_MAKEFILE := Makefile.arm64
  ARCH_DESC     := ARM64 / AArch64 (Raspberry Pi 4/5, NEON SIMD)
else ifeq ($(HOST_ARCH),arm64)
  AUTO_ARCH     := arm64
  AUTO_MAKEFILE := Makefile.arm64
  ARCH_DESC     := ARM64 / AArch64 (Raspberry Pi 4/5, NEON SIMD)
else ifneq ($(filter arm% aarch32%,$(HOST_ARCH)),)
  AUTO_ARCH     := arm32
  AUTO_MAKEFILE := Makefile.arm32
  ARCH_DESC     := ARM32 / ARMv7-A (Raspberry Pi 2/3, armhf, NEON/VFPv4)
else ifeq ($(HOST_ARCH),x86_64)
  AUTO_ARCH     := x86_64
  AUTO_MAKEFILE := Makefile
  ARCH_DESC     := Linux x86-64 (Server / AVX2 / Native)
else ifeq ($(HOST_ARCH),amd64)
  AUTO_ARCH     := x86_64
  AUTO_MAKEFILE := Makefile
  ARCH_DESC     := Linux x86-64 (Server / AVX2 / Native)
else
  AUTO_ARCH     := native
  AUTO_MAKEFILE := Makefile
  ARCH_DESC     := Generic / Native ($(HOST_ARCH))
endif

# Allow user override via command-line: make ARCH=arm64 or make ARCH=arm32
ARCH ?= $(AUTO_ARCH)

ifeq ($(ARCH),arm64)
  TARGET_MAKEFILE := Makefile.arm64
  TARGET_DESC     := ARM64 / AArch64 [Makefile.arm64]
else ifeq ($(ARCH),aarch64)
  TARGET_MAKEFILE := Makefile.arm64
  TARGET_DESC     := ARM64 / AArch64 [Makefile.arm64]
else ifeq ($(ARCH),arm32)
  TARGET_MAKEFILE := Makefile.arm32
  TARGET_DESC     := ARM32 / ARMv7-A [Makefile.arm32]
else ifneq ($(filter arm% aarch32%,$(ARCH)),)
  TARGET_MAKEFILE := Makefile.arm32
  TARGET_DESC     := ARM32 / ARMv7-A [Makefile.arm32]
else ifeq ($(ARCH),x86_64)
  TARGET_MAKEFILE := Makefile
  TARGET_DESC     := Linux x86-64 [Makefile]
else ifeq ($(ARCH),amd64)
  TARGET_MAKEFILE := Makefile
  TARGET_DESC     := Linux x86-64 [Makefile]
else
  TARGET_MAKEFILE := $(AUTO_MAKEFILE)
  TARGET_DESC     := $(ARCH_DESC) [$(AUTO_MAKEFILE)]
endif

.PHONY: all classical hybrid pqc test test-classical test-hybrid test-pqc \
        clean clean-all clean-arm64 clean-arm32 clean-x86_64 \
        arm64 aarch64 arm32 armhf x86_64 amd64 \
        classical-arm64 classical-arm32 classical-x86_64 \
        hybrid-arm64 hybrid-arm32 hybrid-x86_64 \
        pqc-arm64 pqc-arm32 pqc-x86_64 \
        bench bench_pqc benchpqc \
        detect info help banner

all: banner classical hybrid pqc bench_pqc
	@echo ""
	@echo "╔══════════════════════════════════════════════════════════════════════════════════╗"
	@echo "║       SUCCESS: All 3 Suites & bench_pqc Built for Target: $(TARGET_DESC)"
	@echo "╚══════════════════════════════════════════════════════════════════════════════════╝"

banner:
	@echo "╔══════════════════════════════════════════════════════════════════════════════════╗"
	@echo "║                   QRYPTONEX Multi-Suite Cryptographic Framework                  ║"
	@echo "╠══════════════════════════════════════════════════════════════════════════════════╣"
	@echo "║  Host Machine Hardware : $(HOST_ARCH)"
	@echo "║  Detected Architecture : $(ARCH_DESC)"
	@echo "║  Active Build Target   : $(TARGET_DESC)"
	@echo "║  Active Sub-Makefiles  : */$(TARGET_MAKEFILE)"
	@echo "╚══════════════════════════════════════════════════════════════════════════════════╝"

# ── Dynamic Multi-Suite Build Targets ────────────────────────────────
classical:
	@echo "==> Building Classical IoT Suite [classical/$(TARGET_MAKEFILE)]..."
	$(MAKE) -C classical -f $(TARGET_MAKEFILE) all

hybrid:
	@echo "==> Building Hybrid Suite [hybrid/$(TARGET_MAKEFILE)]..."
	$(MAKE) -C hybrid -f $(TARGET_MAKEFILE) all

pqc:
	@echo "==> Building Pure Post-Quantum Suite [pqc/$(TARGET_MAKEFILE)]..."
	$(MAKE) -C pqc -f $(TARGET_MAKEFILE) all

# ── Architecture Shortcuts ──────────────────────────────────────────
arm64 aarch64:
	$(MAKE) ARCH=arm64 all

arm32 armhf:
	$(MAKE) ARCH=arm32 all

x86_64 amd64:
	$(MAKE) ARCH=x86_64 all

# ── Explicit Suite + Architecture Targets ────────────────────────────
classical-x86_64:
	$(MAKE) -C classical -f Makefile all

classical-arm64:
	$(MAKE) -C classical -f Makefile.arm64 all

classical-arm32:
	$(MAKE) -C classical -f Makefile.arm32 all

hybrid-x86_64:
	$(MAKE) -C hybrid -f Makefile all

hybrid-arm64:
	$(MAKE) -C hybrid -f Makefile.arm64 all

hybrid-arm32:
	$(MAKE) -C hybrid -f Makefile.arm32 all

pqc-x86_64:
	$(MAKE) -C pqc -f Makefile all

pqc-arm64:
	$(MAKE) -C pqc -f Makefile.arm64 all

pqc-arm32:
	$(MAKE) -C pqc -f Makefile.arm32 all

# ── Unified Comparative Benchmarking ─────────────────────────────────
bench_pqc benchpqc: bench_pqc.c
	$(CC) -O3 -Wall -Wextra -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -o bench_pqc bench_pqc.c -lm
	@ln -sf bench_pqc benchpqc
	@echo "Built: bench_pqc & benchpqc (Unified Master Comparative Benchmark Runner)"

bench: bench_pqc
	./bench_pqc

# ── Testing Targets ──────────────────────────────────────────────────
test: test-classical test-hybrid test-pqc
	@echo ""
	@echo "╔══════════════════════════════════════════════════════════════════════════════════╗"
	@echo "║        ALL TESTS PASSED: Classical, Hybrid, and Pure PQC Validated               ║"
	@echo "╚══════════════════════════════════════════════════════════════════════════════════╝"

test-classical:
	$(MAKE) -C classical test

test-hybrid:
	$(MAKE) -C hybrid test

test-pqc:
	$(MAKE) -C pqc test

# ── Clean Targets (Device-Aware & Multi-Arch) ────────────────────────
clean:
	@echo "==> Cleaning build artifacts for active target [$(TARGET_DESC)]..."
	$(MAKE) -C classical -f $(TARGET_MAKEFILE) clean
	$(MAKE) -C hybrid -f $(TARGET_MAKEFILE) clean
	$(MAKE) -C pqc -f $(TARGET_MAKEFILE) clean
	rm -f bench_pqc benchpqc /tmp/pqc_bench_*.json

clean-arm64:
	@echo "==> Cleaning ARM64 artifacts across all suites..."
	$(MAKE) -C classical -f Makefile.arm64 clean
	$(MAKE) -C hybrid -f Makefile.arm64 clean
	$(MAKE) -C pqc -f Makefile.arm64 clean

clean-arm32:
	@echo "==> Cleaning ARM32 artifacts across all suites..."
	$(MAKE) -C classical -f Makefile.arm32 clean
	$(MAKE) -C hybrid -f Makefile.arm32 clean
	$(MAKE) -C pqc -f Makefile.arm32 clean

clean-x86_64:
	@echo "==> Cleaning x86_64 artifacts across all suites..."
	$(MAKE) -C classical -f Makefile clean
	$(MAKE) -C hybrid -f Makefile clean
	$(MAKE) -C pqc -f Makefile clean
	rm -f bench_pqc benchpqc /tmp/pqc_bench_*.json

clean-all:
	@echo "==> Deep cleaning all suites across all architectures (x86_64, arm64, arm32)..."
	$(MAKE) -C classical clean-all
	$(MAKE) -C hybrid clean-all
	$(MAKE) -C pqc clean-all
	rm -f bench_pqc benchpqc /tmp/pqc_bench_*.json
	@echo "All build artifacts, objects, libraries, and binaries removed."

# ── Information & Help ───────────────────────────────────────────────
detect info: banner
	@echo ""
	@echo "Detected Environment Configuration:"
	@echo "  Host Hardware     : $(HOST_ARCH)"
	@echo "  Detected Platform : $(ARCH_DESC)"
	@echo "  Default Makefile  : $(AUTO_MAKEFILE)"
	@echo "  Active Makefile   : $(TARGET_MAKEFILE)"
	@echo ""

help:
	@echo "╔══════════════════════════════════════════════════════════════════════════════════╗"
	@echo "║           QRYPTONEX Multi-Suite Cryptographic Framework                          ║"
	@echo "╚══════════════════════════════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Automatic Architecture Detection:"
	@echo "  Running 'make' automatically detects the host CPU architecture and dispatches:"
	@echo "    - on x86_64 host  -> builds classical/, hybrid/, pqc/ with Makefile"
	@echo "    - on ARM64 host   -> builds classical/, hybrid/, pqc/ with Makefile.arm64"
	@echo "    - on ARM32 host   -> builds classical/, hybrid/, pqc/ with Makefile.arm32"
	@echo ""
	@echo "Build Targets (Auto-Detected Device or Overridden):"
	@echo "  make                - Auto-detect architecture and build all 3 suites"
	@echo "  make all            - Auto-detect architecture and build all 3 suites"
	@echo "  make classical      - Build classical IoT suite for detected device"
	@echo "  make hybrid         - Build hybrid suite for detected device"
	@echo "  make pqc            - Build pure post-quantum suite for detected device"
	@echo ""
	@echo "Target Architecture Shortcuts (Cross-compilation or Explicit):"
	@echo "  make arm64          - Build ARM64 binaries for all 3 suites (Makefile.arm64)"
	@echo "  make arm32          - Build ARM32 binaries for all 3 suites (Makefile.arm32)"
	@echo "  make x86_64         - Build x86_64 binaries for all 3 suites (Makefile)"
	@echo "  make ARCH=arm64 all - Override architecture parameter"
	@echo ""
	@echo "Per-Suite Specific Architecture Targets:"
	@echo "  make classical-arm64 / classical-arm32 / classical-x86_64"
	@echo "  make hybrid-arm64    / hybrid-arm32    / hybrid-x86_64"
	@echo "  make pqc-arm64       / pqc-arm32       / pqc-x86_64"
	@echo ""
	@echo "Testing Targets:"
	@echo "  make test           - Run regression test suites for all 3 implementations"
	@echo "  make test-classical - Run classical 22-test automated regression suite"
	@echo "  make test-hybrid    - Run hybrid 7-suite automated regression suite"
	@echo "  make test-pqc       - Run PQC 8-test security and regression suite"
	@echo ""
	@echo "Benchmarking Targets:"
	@echo "  make bench          - Run unified comparative benchmark runner (bench_pqc)"
	@echo "  make bench_pqc      - Build master benchmark runner (bench_pqc & benchpqc)"
	@echo ""
	@echo "Clean Targets (Device-Aware & Multi-Arch):"
	@echo "  make clean          - Clean build artifacts for detected device architecture"
	@echo "  make clean-arm64    - Clean ARM64 binaries across all 3 suites"
	@echo "  make clean-arm32    - Clean ARM32 binaries across all 3 suites"
	@echo "  make clean-x86_64   - Clean x86_64 binaries across all 3 suites"
	@echo "  make clean-all      - Deep clean all architectures across all 3 suites"
	@echo ""
	@echo "Diagnostic Targets:"
	@echo "  make detect / info  - Display detected hardware and active Makefile mapping"
	@echo "  make help           - Display this help reference"