# SecureComm
## Lightweight, Adaptive, Cross-Platform Secure Communication Framework

SecureComm is a production-grade, C-based secure communication application designed for embedded IoT systems, edge gateways, and Linux servers. It provides a unified command-line application (`securecomm`) supporting **Classical**, **Pure Post-Quantum (PQC)**, **Hybrid**, and **Adaptive** operating modes over low-latency UDP transport.

---

## 1. Key Architectural Features

- **Four Cryptographic Operating Modes**:
  - **Classical**: X25519 (RFC 7748) ECDH, Ed25519 (RFC 8032) signatures, AES-128-CCM (RFC 3610) AEAD, HKDF-SHA256.
  - **Pure Post-Quantum (PQC)**: ML-KEM-768 (FIPS 203) key encapsulation, ML-DSA-65 (FIPS 204) digital signatures, ChaCha20-Poly1305 (RFC 8439) AEAD.
  - **Hybrid**: Dual-combiner pairing classical elliptic curve cryptography with post-quantum algorithms, authenticated with HKDF-SHA384 and dual signatures.
  - **Adaptive**: Deterministic, explainable 5-stage policy engine selecting the optimal profile based on device hardware, RAM, SIMD extensions, and security policy.
- **Strict Identity & Trust Management**:
  - Private keys stored separately from JSON configuration with strict `0600` file permissions.
  - SHA-256 public key fingerprinting.
  - Pinned trust store with optional Trust On First Use (TOFU) and downgrade protection.
- **Lightweight & High Performance**:
  - Written strictly in standard C (C11, POSIX APIs). Zero Python runtime dependency.
  - Monotonic clock timeouts, sliding 64-packet anti-replay window.
  - Peak memory footprint < 10 MB RSS.
- **Production Packaging**:
  - Full Debian packaging (`.deb`) for `x86-64` and `ARM64`.
  - Hardened systemd unit file with sandboxing (`DynamicUser=yes`, `ProtectSystem=strict`).

---

## 2. Directory Layout

```
securecomm/
├── Makefile                          # Unified build and test automation
├── VERSION                           # Product semantic version (1.0.0)
├── README.md                         # Comprehensive product guide
├── include/securecomm/               # Public C headers
│   ├── common.h                      # Common enums, constants, string mappers
│   ├── error.h                       # Structured error codes
│   ├── config.h                      # Configuration parser and atomic writer
│   ├── device_profile.h              # Hardware & SIMD capability profiler
│   ├── profile_registry.h            # Cryptographic profile registry
│   ├── policy.h                      # Security policy definitions
│   ├── adaptive.h                    # 5-stage deterministic selection engine
│   ├── identity.h                    # Identity storage and trust verification
│   ├── crypto_backend.h              # Unified crypto backend abstraction
│   ├── server.h                      # High-concurrency server engine
│   ├── client.h                      # Secure client engine
│   ├── metrics.h                     # Performance & memory monitoring
│   └── logging.h                     # Structured logger with secret suppression
├── src/                              # Implementation source files
│   ├── main.c                        # Standalone application entry point
│   ├── cli/                          # Command-line interface dispatcher
│   ├── setup/                        # 8-step interactive/scripted setup wizard
│   ├── config/                       # JSON parser, atomic writer, validator
│   ├── device/                       # Hardware, SIMD, and memory detection
│   ├── profiles/                     # Profile registry implementation
│   ├── policy/                       # Policy constructors and preference mappers
│   ├── adaptive/                     # Deterministic selection engine & explainability
│   ├── identity/                     # Keypair generation and trust store verification
│   ├── monitoring/                   # Real-time RSS memory and latency metrics
│   ├── server/                       # UDP server engine, sliding replay window
│   └── client/                       # UDP client engine, interactive chat loop
├── backends/                         # Cryptographic backend implementations
│   └── crypto_backend.c              # Concrete OpenSSL 3.x, liboqs & libhybrid bridges
├── tests/                            # Comprehensive automated tests
│   ├── unit/                         # Unit tests for config, device, profiles, adaptive, identity
│   └── integration/                  # Real client-server network integration tests
├── packaging/                        # Deployment and packaging artifacts
│   ├── debian/                       # Debian package build scripts & control files
│   └── systemd/                      # Hardened systemd service definition
└── config/
    └── securecomm.example.json       # Documented configuration template
```

---

## 3. Quick Start & Build Instructions

### Prerequisites
- GCC or Clang (C11 support)
- OpenSSL 3.x development libraries (`libssl-dev`)
- `liboqs` static library (included in repository)

### Compilation
```bash
cd securecomm

# Standard production build
make all

# Run complete unit and integration tests
make test

# Build with AddressSanitizer & UndefinedBehaviorSanitizer
make sanitize

# Build Debian package (.deb)
make package
```

---

## 4. Command-Line Reference

```
Usage: securecomm <command> [options]

Core Commands:
  setup                     Run interactive or automated onboarding wizard
  detect                    Detect hardware, CPU features, memory, and crypto backends
  profiles list             List registered cryptographic profiles
  profiles check            Check device compatibility for each profile
  adaptive explain          Explain deterministic 5-stage profile selection
  config validate           Validate syntax, permissions, and settings of config
  config show               Display configuration with secret redaction
  server start              Launch SecureComm UDP server
  client connect            Initiate secure connection to remote server
  status                    Inspect running service status and health
  diagnostics               Execute comprehensive platform security diagnostics
  benchmark                 Run cryptographic microbenchmarks

Global Options:
  --config <path>           Specify configuration file path (default: /etc/securecomm/securecomm.json)
  --version, -v             Display version information
  --help, -h                Display help message
```

---

## 5. Setup & Operational Workflow

### Step 1: Onboarding with Setup Wizard
Run the interactive setup wizard:
```bash
./bin/securecomm setup
```
For non-interactive / scripted provisioning:
```bash
./bin/securecomm setup --non-interactive --config ./config/securecomm.json
```

### Step 2: Validate Hardware & Adaptive Selection
Inspect device capabilities and the deterministic 5-stage selection decision:
```bash
./bin/securecomm detect
./bin/securecomm profiles check
./bin/securecomm adaptive explain
```

### Step 3: Start Server
```bash
./bin/securecomm server start --config ./config/securecomm.json
```

### Step 4: Connect Client
In another terminal:
```bash
# Interactive chat loop
./bin/securecomm client connect --config ./config/securecomm.json --server 127.0.0.1 --port 9885

# Or send a single encrypted message
./bin/securecomm client connect --config ./config/securecomm.json --server 127.0.0.1 --port 9885 --msg "Real-time PQC telemetry"
```

---

## 6. Architecture Compatibility Matrix

| Architecture | Status | Acceleration / SIMD | Memory Footprint | Tested Status |
| :--- | :--- | :--- | :--- | :--- |
| **x86-64** | Fully Supported | AVX2, AES-NI | ~4.2 MB RSS | Verified (Ubuntu Linux) |
| **ARM64 (aarch64)** | Fully Supported | NEON, ARMv8 Crypto | ~3.8 MB RSS | Build-Verified |
| **ARM32 (armhf)** | Verified (PQC memory bounded) | None | ~2.5 MB RSS | Candidate Profile Required |

---

## 7. Security Guarantees & Non-Goals

- **Zero Secret Ingress in Config**: Private keys are strictly forbidden in `securecomm.json` and are maintained in discrete `0600` files.
- **Downgrade Protection**: If security policy mandates quantum resistance (`require_quantum_resistance = true`), the adaptive engine strictly rejects classical fallbacks even under resource pressure.
- **Replay Protection**: Packets outside the 64-datagram sliding window or with duplicate sequence numbers are dropped pre-AEAD.
