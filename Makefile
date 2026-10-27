# QRYPTONEX — Multi-Suite Global Makefile
# Top-level dispatcher for Classical, Hybrid, and Post-Quantum implementations

.PHONY: all classical hybrid pqc test test-classical test-hybrid test-pqc clean clean-all help

all: classical hybrid pqc

classical:
	$(MAKE) -C classical all

hybrid:
	$(MAKE) -C hybrid all

pqc:
	$(MAKE) -C pqc all

test: test-classical test-hybrid test-pqc

test-classical:
	$(MAKE) -C classical test

test-hybrid:
	$(MAKE) -C hybrid test

test-pqc:
	$(MAKE) -C pqc test

clean:
	$(MAKE) -C classical clean
	$(MAKE) -C hybrid clean
	$(MAKE) -C pqc clean

clean-all:
	$(MAKE) -C classical clean-all
	$(MAKE) -C hybrid clean
	$(MAKE) -C pqc clean-all

help:
	@echo "╔══════════════════════════════════════════════════════════════════════════════════╗"
	@echo "║           QRYPTONEX Multi-Suite Cryptographic Framework                          ║"
	@echo "╚══════════════════════════════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Build Targets:"
	@echo "  make all            - Build all 3 implementations (classical, hybrid, pqc)"
	@echo "  make classical      - Build classical IoT suite (X25519, Ed25519, AES-128-CCM)"
	@echo "  make hybrid         - Build hybrid suite (X25519+MLKEM768, Ed25519+MLDSA65)"
	@echo "  make pqc            - Build pure post-quantum suite (ML-KEM-768, ML-DSA-65)"
	@echo ""
	@echo "Testing Targets:"
	@echo "  make test           - Run regression test suites for all 3 implementations"
	@echo "  make test-classical - Run classical 22-test automated regression suite"
	@echo "  make test-hybrid    - Run hybrid 7-suite automated regression suite"
	@echo "  make test-pqc       - Run PQC 8-test security and regression suite"
	@echo ""
	@echo "Clean Targets:"
	@echo "  make clean          - Clean build artifacts across all implementations"
	@echo "  make clean-all      - Deep clean including cross-architecture binaries"