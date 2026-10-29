# SecureComm: Production Operations & Architectural Manual
## Lightweight, Adaptive, Cross-Platform Secure Communication Framework

SecureComm is a production-grade, standard C11 secure communication framework designed for embedded IoT systems, edge gateways, and Linux servers. It provides a unified command-line application (`securecomm`) supporting **Classical**, **Pure Post-Quantum (PQC)**, **Hybrid**, and **Adaptive** operating modes over high-throughput, low-latency UDP transport.

---

## Table of Contents
1. [Architectural Overview & Cryptographic Primitives](#1-architectural-overview--cryptographic-primitives)
2. [Source Tree & Modular Component Architecture](#2-source-tree--modular-component-architecture)
3. [End-to-End Build & Compilation Plan](#3-end-to-end-build--compilation-plan)
4. [Multi-Architecture Debian Packaging Plan](#4-multi-architecture-debian-packaging-plan)
5. [System Installation & Service Management (systemd)](#5-system-installation--service-management-systemd)
6. [Complete Configuration Guide (JSON Schema)](#6-complete-configuration-guide-json-schema)
7. [Device Identity, Fingerprinting & Trust Store](#7-device-identity-fingerprinting--trust-store)
8. [Client-Server Operational Workflows](#8-client-server-operational-workflows)
9. [Adaptive Policy Engine & Explainability](#9-adaptive-policy-engine--explainability)
10. [Platform Diagnostics, Health Checks & Benchmarking](#10-platform-diagnostics-health-checks--benchmarking)
11. [Troubleshooting & Error Code Dictionary](#11-troubleshooting--error-code-dictionary)

---

## 1. Architectural Overview & Cryptographic Primitives

SecureComm delivers post-quantum cryptographic security while maintaining backward compatibility with classical infrastructure:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           SECURECOMM CLI INTERFACE                              │
│  setup | detect | profiles | adaptive | config | server | client | benchmark    │
└──────────────────────────────────────┬──────────────────────────────────────────┘
                                       │
┌──────────────────────────────────────▼──────────────────────────────────────────┐
│                             CORE SUBSYSTEMS                                     │
│  ┌──────────────────────┐  ┌──────────────────────┐  ┌───────────────────────┐  │
│  │   Device Profiler    │  │    Policy Engine     │  │  Identity & Trust     │  │
│  │ (CPUID, NEON, RAM)   │  │ (5-Stage Selection)  │  │ (0600 Keys, Pinning)  │  │
│  └──────────────────────┘  └──────────────────────┘  └───────────────────────┘  │
│  ┌──────────────────────┐  ┌──────────────────────┐  ┌───────────────────────┐  │
│  │    Config Engine     │  │   Telemetry Engine   │  │   Logging Subsystem   │  │
│  │ (Atomic JSON, Redact)│  │ (RSS Memory, Latency)│  │ (Secret Redaction)    │  │
│  └──────────────────────┘  └──────────────────────┘  └───────────────────────┘  │
└──────────────────────────────────────┬──────────────────────────────────────────┘
                                       │
┌──────────────────────────────────────▼──────────────────────────────────────────┐
│                     CRYPTOGRAPHIC BACKEND ADAPTERS                              │
│  ┌───────────────────────────────────────────────────────────────────────────┐  │
│  │ Profile Classical : X25519 (ECDH) + Ed25519 (DSA) + AES-128-CCM (Port 9877)│  │
│  │ Profile Pure PQC  : ML-KEM-768 + ML-DSA-65 + ChaCha20-Poly1305 (Port 9879)│  │
│  │ Profile Hybrid    : Dual X25519/ML-KEM-768 + Dual Ed25519/ML-DSA-65 (9885) │  │
│  │ Profile Adaptive  : Deterministic selection based on hardware capabilities │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────┬──────────────────────────────────────────┘
                                       │
┌──────────────────────────────────────▼──────────────────────────────────────────┐
│                         LOW-LATENCY UDP TRANSPORT                               │
│        Bounded 16KB Buffers | Sliding 64-Packet Anti-Replay | AAD Framing       │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Supported Cryptographic Modes:
1. **Classical Mode (`profile-classical-1`)**:
   - **Key Exchange**: X25519 ECDH (RFC 7748, 32-byte ephemeral public keys).
   - **Signatures**: Ed25519 (RFC 8032, 32-byte public key, 64-byte signature).
   - **Data Cipher**: AES-128-CCM (RFC 3610, 12-byte nonce, 16-byte authentication tag).
   - **Key Derivation**: HKDF-SHA256 (RFC 5869).
   - **Default Port**: `9877` (UDP).
2. **Pure Post-Quantum Mode (`profile-pqc-1`)**:
   - **Key Exchange**: ML-KEM-768 (NIST FIPS 203 Kyber parameter set, 1184-byte public key, 1088-byte ciphertext).
   - **Signatures**: ML-DSA-65 (NIST FIPS 204 Dilithium parameter set, 1952-byte public key, 3309-byte signature).
   - **Data Cipher**: ChaCha20-Poly1305 (RFC 8439, 12-byte nonce, 16-byte authentication tag).
   - **Key Derivation**: SHAKE-256 + HKDF.
   - **Default Port**: `9879` (UDP).
3. **Hybrid Mode (`profile-hybrid-1`)**:
   - **Dual Combiner**: Concatenates classical X25519 with post-quantum ML-KEM-768 shared secrets, mixed via HKDF-SHA384.
   - **Dual Authentication**: Requires valid signatures from both Ed25519 and ML-DSA-65 keys.
   - **Data Cipher**: ChaCha20-Poly1305.
   - **Default Port**: `9885` (UDP).
4. **Adaptive Mode**:
   - Automatically selects the optimal profile via a deterministic 5-stage policy engine based on available RAM, CPU extensions (AVX2, NEON, AES-NI), crypto libraries, and local security policy.

---

## 2. Source Tree & Modular Component Architecture

```
securecomm/
├── Makefile                          # Unified build, test, and packaging automation
├── VERSION                           # Product semantic version (1.0.0)
├── README.md                         # This operational manual
├── include/securecomm/               # Clean, modular C header interfaces
│   ├── common.h                      # Common definitions, network ports, wire constants
│   ├── error.h                       # Structured error codes (securecomm_error_t)
│   ├── logging.h                     # Thread-safe structured logging with secret redaction
│   ├── device_profile.h              # Hardware, SIMD, RAM, and crypto profiler
│   ├── profile_registry.h            # Cryptographic profile registry definitions
│   ├── policy.h                      # Security policy & ranking constraints
│   ├── adaptive.h                    # 5-Stage deterministic Adaptive Policy Engine
│   ├── identity.h                    # 0600 key storage, SHA-256 fingerprinting, TOFU trust store
│   ├── config.h                      # JSON configuration schema & atomic writer
│   ├── crypto_backend.h              # Unified crypto backend abstraction interface
│   ├── server.h                      # Multi-session UDP server engine
│   ├── client.h                      # Interactive & scripted secure client
│   └── metrics.h                     # Latency, throughput, and RSS memory telemetry
├── src/
│   ├── main.c                        # Standalone binary entry point
│   ├── common.c                      # Utility conversions and string mappers
│   ├── error.c                       # Thread-safe error string translator
│   ├── cli/cli.c                     # Command-line subcommand dispatcher
│   ├── setup/setup_wizard.c          # Interactive 8-step onboarding wizard
│   ├── config/                       # Lightweight C JSON parser & atomic file replacer
│   ├── device/device_profile.c       # Linux /proc/cpuinfo, sysinfo & SIMD capability probe
│   ├── profiles/profile_registry.c   # Registry implementations & hardware compatibility checks
│   ├── policy/policy.c               # Policy constructors & preference logic
│   ├── adaptive/adaptive.c           # 5-stage selection pipeline & explainability report
│   ├── identity/identity.c           # Keypair generator, 0600 writer, trust verification
│   ├── monitoring/metrics.c          # getrusage RSS memory & latency statistical accumulator
│   ├── backends/crypto_backend.c     # Concrete OpenSSL 3.x, liboqs & libhybrid bridge
│   ├── server/server.c               # Non-blocking UDP server, session table, 64-packet replay window
│   └── client/client.c               # UDP client engine, interactive chat loop
├── tests/
│   ├── unit/                         # Unit tests: config, device, profiles, adaptive, identity
│   └── integration/                  # Real UDP client-server integration tests (all 4 modes)
├── packaging/
│   ├── debian/                       # Multi-architecture Debian package generator
│   │   ├── build_deb.sh              # Package build script
│   │   ├── securecomm_1.0.0_x86amd.deb
│   │   ├── securecomm_1.0.0_arm64.deb
│   │   └── securecomm_1.0.0_arm32.deb
│   └── systemd/securecomm.service    # Hardened systemd service definition
└── config/
    └── securecomm.example.json       # Documented configuration template
```

---

## 3. End-to-End Build & Compilation Plan

### Build Prerequisites
* **Compiler**: Standard GCC or Clang supporting C11 (`-std=c11`).
* **Libraries**: OpenSSL 3.x development libraries (`libssl-dev`), POSIX threads (`-lpthread`).
* **Hardware Support**: Supported natively on `x86-64`, `ARM64 (aarch64)`, and `ARM32 (armhf)`.

### Compilation Commands

```bash
cd securecomm

# 1. Standard Production Build (Optimized -O2, stack protector enabled)
make clean && make -j$(nproc)

# 2. Run Complete Unit & Integration Test Suites
make test

# 3. Diagnostic Build with Sanitizers (AddressSanitizer + UndefinedBehaviorSanitizer)
make sanitize

# 4. Clean Build Directory
make clean
```

---

## 4. Multi-Architecture Debian Packaging & Direct Downloads

SecureComm generates three distinct, architecture-specific `.deb` packages designed for unambiguous hardware targeting:

| Architecture | Target CPU Family | Debian Arch (`dpkg`) | Target Hardware | Direct Download Link |
| :--- | :--- | :---: | :--- | :---: |
| **`x86amd`** | **x86-64** | `amd64` | Intel/AMD PCs, laptops, and x86_64 cloud servers | [📥 Download `securecomm_1.0.0_x86amd.deb`](https://drive.google.com/uc?export=download&id=1wKZ5hrTjgId0uJUwz5kTT9iVX_G_KwtT) |
| **`arm64`** | **ARM64 (AArch64)** | `arm64` | Raspberry Pi 4, Raspberry Pi 5, Jetson, 64-bit ARM Linux | [📥 Download `securecomm_1.0.0_arm64.deb`](https://drive.google.com/uc?export=download&id=1kTHy9Kl_Ur6_HlXYya-e9ztAmg2Z94vJ) |
| **`arm32`** | **ARM32 (ARMv7)** | `armhf` | Raspberry Pi 2/3 running 32-bit Raspbian/Debian | [📥 Download `securecomm_1.0.0_arm32.deb`](https://drive.google.com/uc?export=download&id=1lT-iFzbxwV6QLHamfSOMpTLUEq2velVb) |

---

### One-Line Terminal Download & Install Commands

#### 1. For x86-64 PC, Laptop & Cloud Servers (`x86amd`):
```bash
# Download and install x86-64 package:
curl -L -o securecomm_1.0.0_x86amd.deb "https://drive.google.com/uc?export=download&id=1wKZ5hrTjgId0uJUwz5kTT9iVX_G_KwtT"
sudo dpkg -i securecomm_1.0.0_x86amd.deb || sudo apt-get install -f -y
```

#### 2. For Raspberry Pi 4 / 5, Jetson, 64-bit ARM (`arm64`):
```bash
# Download and install ARM64 package:
curl -L -o securecomm_1.0.0_arm64.deb "https://drive.google.com/uc?export=download&id=1kTHy9Kl_Ur6_HlXYya-e9ztAmg2Z94vJ"
sudo dpkg -i securecomm_1.0.0_arm64.deb || sudo apt-get install -f -y
```

#### 3. For Raspberry Pi 2 / 3, 32-bit ARM OS (`arm32`):
```bash
# Download and install ARM32 package:
curl -L -o securecomm_1.0.0_arm32.deb "https://drive.google.com/uc?export=download&id=1lT-iFzbxwV6QLHamfSOMpTLUEq2velVb"
sudo dpkg -i securecomm_1.0.0_arm32.deb || sudo apt-get install -f -y
```

---

### How to Build Packages Locally from Source:

```bash
# Build all 3 distinct packages at once:
make package
# (or: make package-all)

# Or build individual packages:
make package-x86amd    # Generates packaging/debian/securecomm_1.0.0_x86amd.deb
make package-arm64     # Generates packaging/debian/securecomm_1.0.0_arm64.deb
make package-arm32     # Generates packaging/debian/securecomm_1.0.0_arm32.deb
```

---

## 5. System Installation & Service Management (systemd)

### Manual Local Package Installation
If you built the packages locally with `make package`:

```bash
# On x86-64:
sudo dpkg -i packaging/debian/securecomm_1.0.0_x86amd.deb

# On ARM64 (AArch64):
sudo dpkg -i packaging/debian/securecomm_1.0.0_arm64.deb

# On ARM32 (ARMv7):
sudo dpkg -i packaging/debian/securecomm_1.0.0_arm32.deb
```

### Filesystem Layout After Installation
* `/usr/bin/securecomm`: Unified executable binary.
* `/etc/securecomm/securecomm.json`: Active JSON configuration (conffile, preserved during package upgrades).
* `/etc/securecomm/*.key`: Private identity keys (`0600` permissions, owned by unprivileged service user).
* `/etc/securecomm/trust_store.txt`: Cryptographic peer pinning database.
* `/usr/lib/systemd/system/securecomm.service`: Systemd service unit.
* `/var/lib/securecomm/`: Persistent application data directory (`0700`).
* `/var/log/securecomm/`: Application audit logs (`0750`).

### Managing the Service via Systemd

```bash
# 1. Reload systemd daemon
sudo systemctl daemon-reload

# 2. Enable and start SecureComm daemon at boot
sudo systemctl enable --now securecomm.service

# 3. Check service health and active profile
sudo systemctl status securecomm.service

# 4. View real-time live audit logs
sudo journalctl -u securecomm.service -f

# 5. Restart or stop service
sudo systemctl restart securecomm.service
sudo systemctl stop securecomm.service
```

---

## 6. Complete Configuration Guide (JSON Schema)

The configuration file is located at `/etc/securecomm/securecomm.json` (or specified via `--config <path>`).

### Example Configuration:
```json
{
  "version": 1,
  "role": "server",
  "mode": "adaptive",
  "network": {
    "bind_address": "0.0.0.0",
    "server_host": "127.0.0.1",
    "port": 9885,
    "connection_timeout_ms": 5000
  },
  "identity": {
    "device_id": "gateway-alpha",
    "private_key_path": "/etc/securecomm/gateway-alpha.key",
    "public_key_path": "/etc/securecomm/gateway-alpha.pub",
    "trust_store_path": "/etc/securecomm/trust_store.txt",
    "expected_server_id": ""
  },
  "policy": {
    "require_quantum_resistance": true,
    "allow_classical_fallback": false,
    "preference": "balanced",
    "allow_tofu": true,
    "max_memory_budget_mb": 512
  },
  "resources": {
    "max_sessions": 256,
    "max_buffer_kb": 64
  },
  "logging": {
    "level": "INFO",
    "structured": true
  }
}
```

### Configuration Fields Explanation:

| JSON Key | Type | Description |
| :--- | :--- | :--- |
| `role` | String | Operating role: `"server"` or `"client"`. |
| `mode` | String | Cryptographic mode: `"classical"`, `"pqc"`, `"hybrid"`, or `"adaptive"`. |
| `network.bind_address` | String | Local IPv4 address for server to bind (`"0.0.0.0"` or `"127.0.0.1"`). |
| `network.server_host` | String | Remote server IP address or hostname for clients to connect to. |
| `network.port` | Integer | UDP port (`9877` for classical, `9879` for PQC, `9885` for hybrid/adaptive). |
| `identity.device_id` | String | Unique human-readable node identifier (e.g. `"edge-node-1"`). |
| `identity.private_key_path` | String | Path to private key file. **MUST have `0600` permissions**. |
| `identity.trust_store_path` | String | Path to pinned peers trust database. |
| `policy.require_quantum_resistance` | Boolean | If `true`, classical-only profiles are strictly rejected. |
| `policy.allow_classical_fallback` | Boolean | If `false`, downgrade attacks to classical ciphers are blocked. |
| `policy.preference` | String | Adaptive ranking: `"balanced"`, `"high_security"`, `"low_latency"`, or `"low_memory"`. |
| `policy.allow_tofu` | Boolean | If `true`, enables Trust On First Use for unpinned peers. |
| `resources.max_sessions` | Integer | Maximum concurrent client sessions on server (default: 256). |
| `logging.level` | String | Log verbosity: `"ERROR"`, `"WARN"`, `"INFO"`, or `"DEBUG"`. |

### Validating & Viewing Configurations Safely
```bash
# Validate configuration against schema and permission rules:
securecomm config validate --config /etc/securecomm/securecomm.json

# Display configuration with automatic secret redaction:
securecomm config show --config /etc/securecomm/securecomm.json
```

---

## 7. Device Identity, Fingerprinting & Trust Store

### Identity Provisioning Rules
1. **Discrete Private Key Storage**: Private keys are **never** stored inside the JSON configuration. They are written to a dedicated `.key` file using POSIX `umask(0077)` and strict `0600` file permissions.
2. **Deterministic Fingerprints**: Every public key has a canonical SHA-256 fingerprint displayed as a 64-character hexadecimal string:
   ```
   [INFO] Provisioned device identity 'gateway-alpha' [fingerprint: 7e4aa81bf59d4991...]
   ```
3. **Trust On First Use (TOFU) & Pinning**:
   - When a peer connects for the first time with `allow_tofu = true`, the server records its public key fingerprint in `/etc/securecomm/trust_store.txt`.
   - On subsequent connections, if a peer attempts to authenticate with a different public key or modified algorithm, the server instantly terminates the session:
     ```
     [ERROR] Pinning mismatch for peer 'gateway-alpha': expected 7e4aa81bf59d4991, got 1b5871ce614b837a
     [ERROR] Client authentication failed: identity 'gateway-alpha' rejected by trust store
     ```

---

## 8. Client-Server Operational Workflows

### Scenario 1: Interactive Onboarding Wizard
```bash
# Run the 8-step wizard to configure network, role, mode, and generate keys:
securecomm setup

# Or run non-interactively for automated infrastructure:
securecomm setup --non-interactive --config /etc/securecomm/securecomm.json
```

### Scenario 2: Starting a Secure Server
```bash
securecomm server start --config /etc/securecomm/securecomm.json
```
Output:
```
[2026-10-29 15:45:00] [INFO ] [CORE] SecureComm Server listening on 0.0.0.0:9885 [mode: adaptive]
[2026-10-29 15:45:00] [INFO ] [CORE] Adaptive mode selected profile: NIST FIPS 203/204 Pure Post-Quantum (ML-KEM-768 + ML-DSA-65) (pqc)
```

### Scenario 3: Connecting a Client (Interactive Chat Shell)
```bash
securecomm client connect --config /etc/securecomm/securecomm.json --server 127.0.0.1 --port 9885
```
Once connected, an interactive encrypted shell opens:
```
╔═══════════════════════════════════════════════════════════════╗
║             SECURECOMM INTERACTIVE SECURE CHAT                ║
║ Type messages to send encrypted over UDP. Type /quit to exit.  ║
║ Commands: /status, /metrics, /ping, /quit                     ║
╚═══════════════════════════════════════════════════════════════╝

securecomm> Hello server, reporting quantum-safe status.
[Sent 46 bytes encrypted]
securecomm> /ping
[Sent PING to server]
securecomm> /metrics
======================================================================
                     SECURECOMM METRICS REPORT                        
======================================================================
  Uptime                  : 42 seconds
  Handshakes Completed    : 1 (Avg Latency: 1.84 ms, Min: 1.84 ms, Max: 1.84 ms)
  Packets Transmitted (TX): 4 packets (240 bytes, 0.045 Kbps)
  Packets Received    (RX): 3 packets (180 bytes, 0.034 Kbps)
  Packets Dropped / Replay: 0 dropped, 0 replayed
  Peak Process Memory(RSS): 4.88 MB
======================================================================
securecomm> /quit
[INFO] Disconnected from server
```

### Scenario 4: Single-Shot Scripted Telemetry
```bash
securecomm client connect --config /etc/securecomm/securecomm.json --server 127.0.0.1 --port 9885 --msg "CRITICAL_SENSOR_ALERT: Temperature 85C"
```

---

## 9. Adaptive Policy Engine & Explainability

When operating in **Adaptive Mode**, SecureComm runs a deterministic, 5-stage selection funnel:

1. **Stage A (Capability Filtering)**: Verifies hardware architecture, SIMD extensions, and compiled cryptographic backends.
2. **Stage B (Security Policy Filtering)**: Excludes classical profiles if `require_quantum_resistance` is set; strictly forbids silent fallback if `allow_classical_fallback == false`.
3. **Stage C (Resource Feasibility)**: Evaluates working memory requirements against system RAM.
4. **Stage D (Peer Compatibility)**: Matches peer-advertised profile lists against locally permitted profiles.
5. **Stage E (Multi-Objective Ranking)**: Selects candidate based on policy preference (`high_security`, `low_latency`, `low_memory`, or `balanced`).

### Auditing Adaptive Decisions (`securecomm adaptive explain`):

```bash
securecomm adaptive explain
```
Output:
```
╔══════════════════════════════════════════════════════════════════════════╗
║             SecureComm Adaptive Profile Selection Analysis               ║
╚══════════════════════════════════════════════════════════════════════════╝
  • Host Platform    : x86_64 (AMD Ryzen 5 5500U with Radeon Graphics, 12 cores, 6335 MB RAM available)
  • Security Policy  : Quantum-Safe KEX: REQUIRED | Quantum-Safe Auth: Optional
  • Fallback Rules   : Classical Fallback STRICTLY PROHIBITED | Ranking Goal: balanced

  [Decision Outcome]
  ★ Selected Profile : profile-pqc-1 (NIST FIPS 203/204 Pure Post-Quantum (ML-KEM-768 + ML-DSA-65))
  • Mode             : pqc
  • Cryptography     : KEX: ML-KEM-768 | DSA: ML-DSA-65 | AEAD: ChaCha20-Poly1305
  • Wire Size        : ~5824 Bytes | Est. Concurrency Memory: 8 KB/session
  • Evaluation Note  : Selected 'profile-pqc-1' based on 2 eligible candidates and 'balanced' ranking objective.

  [Eligible Candidates (2)]
    ✔ [SELECTED] profile-pqc-1        -> NIST FIPS 203/204 Pure Post-Quantum (ML-KEM-768 + ML-DSA-65) (Mode: pqc)
    • [ELIGIBLE] profile-hybrid-1     -> Hybrid Quantum-Safe (Dual X25519/ML-KEM-768 + Ed25519/ML-DSA-65) (Mode: hybrid)

  [Excluded Candidates (2)]
  ✖ profile-classical-1  -> [Stage B: Policy] Classical KEX rejected (policy mandates quantum-safe secrecy)
  ✖ profile-pqc-small    -> [Stage A: Capability] Profile status is UNAVAILABLE or EXPERIMENTAL
════════════════════════════════════════════════════════════════════════════
```

---

## 10. Platform Diagnostics, Health Checks & Benchmarking

### Platform Diagnostics
Verify CPU features, SIMD capabilities, memory, and UDP socket availability:
```bash
securecomm diagnostics
```
Output:
```
=================================================================================
                      SECURECOMM PLATFORM DIAGNOSTICS                            
=================================================================================
 [✓] CPU Architecture : x86_64 (AMD Ryzen 5, 12 cores)
 [✓] SIMD Acceleration: AVX2=YES, AES-NI=YES, NEON=NO
 [✓] System Memory    : 6346 MB available / 14817 MB total
 [✓] OpenSSL EVP      : AVAILABLE [PASS]
 [✓] liboqs Backends  : AVAILABLE [PASS]
 [✓] ML-KEM-768 KEX   : VERIFIED [PASS]
 [✓] ML-DSA-65 DSA    : VERIFIED [PASS]
 [✓] Port 9885 (UDP)  : AVAILABLE
=================================================================================
 Diagnostic Result: System is fully ready for Classical, PQC, and Hybrid modes.
=================================================================================
```

### Cryptographic Microbenchmarks
Measure real operations/sec and latency on your specific device hardware:
```bash
securecomm benchmark
```
Output:
```
=================================================================================
               SECURECOMM CRYPTOGRAPHIC BENCHMARK (hybrid)                           
               Iterations: 100 | Profile: Hybrid Quantum-Safe
=================================================================================
 1. KEX Keygen              :    0.083 ms/op ( 12061.8 ops/sec)
 2. KEX Encapsulation       :    0.128 ms/op (  7817.3 ops/sec)
 3. KEX Decapsulation       :    0.091 ms/op ( 10937.4 ops/sec)
 4. DSA Signature Generate  :    0.209 ms/op (  4788.5 ops/sec)
 5. DSA Signature Verify    :    0.155 ms/op (  6462.5 ops/sec)
 6. AEAD (1KB) Encrypt      :    0.001 ms/op (  5518.6 Mbps)
=================================================================================
```

---

## 11. Troubleshooting & Error Code Dictionary

| Error String | Code | Root Cause | Solution |
| :--- | :---: | :--- | :--- |
| `SECURECOMM_ERR_PERM_DENIED` | -3 | Private key file has insecure permissions (e.g. `0644`). | Run `chmod 0600 /etc/securecomm/*.key`. |
| `SECURECOMM_ERR_AUTH_FAILED` | -6 | Peer public key doesn't match the pinned fingerprint in `trust_store.txt`. | If authorized identity rotation, update `trust_store.txt`. |
| `SECURECOMM_ERR_NETWORK` | -5 | UDP socket failed to bind or address already in use. | Check if another process is using port with `ss -ulnp \| grep <port>`. |
| `SECURECOMM_ERR_NO_COMPAT_PROFILE` | -11 | Adaptive engine could not find a profile satisfying policy constraints. | Run `securecomm adaptive explain` to see exact stage rejections. |
| `SECURECOMM_ERR_TIMEOUT` | -7 | Remote server did not respond to Client Hello within timeout. | Check network connectivity and ensure server daemon is running. |
| `SECURECOMM_ERR_BACKEND_MISSING`| -9 | Target runtime backend library (e.g. `liboqs`) is missing. | Verify `libssl3` and `liboqs` installation via `securecomm diagnostics`. |

---

## 12. Security Verification & Non-Goals

- **Zero Monolithic Dependencies**: Built without heavyweight runtime frameworks or web servers.
- **Pure C11 Implementation**: No Python runtime dependencies.
- **Downgrade Attack Resistance**: Enforced at Stage B of the Adaptive Engine.
- **Replay Protection**: Packets with duplicate sequence numbers or outside the 64-datagram window are discarded prior to AEAD decryption.
- **Resource Bounds**: Bounded session tables (256 sessions), bounded 16KB buffers, monotonic expiration timers.
