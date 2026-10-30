# QRYPTONEX (NEXQOR) — Enterprise Post-Quantum Cryptographic Network & High-Concurrency Multi-Client Engine

[![Language: C11](https://img.shields.io/badge/Language-C11-00599C.svg?logo=c&logoColor=white)](https://en.wikipedia.org/wiki/C11_(C_standard_revision))
[![Architecture: Heterogeneous](https://img.shields.io/badge/Architecture-x86__64%20%7C%20ARM64%20%7C%20ARM32-blue.svg)](https://arm.com)
[![KEM: ML-KEM-768](https://img.shields.io/badge/NIST%20FIPS%20203-ML--KEM--768%20(Kyber768)-orange.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![DSA: ML-DSA-65](https://img.shields.io/badge/NIST%20FIPS%20204-ML--DSA--65%20(Dilithium3)-red.svg)](https://csrc.nist.gov/pubs/fips/204/final)
[![AEAD: ChaCha20-Poly1305](https://img.shields.io/badge/AEAD-ChaCha20--Poly1305%20(RFC%208439)-brightgreen.svg)](https://datatracker.ietf.org/doc/html/rfc8439)
[![Verification: ProVerif](https://img.shields.io/badge/Formally%20Verified-ProVerif%20(21%20Proofs)-purple.svg)](https://proverif.inria.fr/)
[![Server Engine: io_uring](https://img.shields.io/badge/Async%20I%2FO-Linux%20io__uring-black.svg)](https://kernel.dk/io_uring.pdf)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 📖 Executive Overview

**QRYPTONEX** (identified in engine sources as **NEXQOR**) is a production-grade, SIMD-vectorized **Post-Quantum Cryptographic (PQC) networking framework**, high-concurrency multi-client relay engine, and formal verification suite written in **C11**.

Modern public-key cryptography (RSA, ECDH, ECDSA) relies on mathematical problems (integer factorization and discrete logarithms) that will be completely broken by polynomial-time quantum algorithms (**Shor's algorithm**) once cryptographically relevant quantum computers (CRQCs) emerge. Furthermore, adversaries are executing **"Store-Now-Decrypt-Later" (SNDL)** campaigns—intercepting and storing encrypted traffic today to retroactively decrypt it when quantum hardware becomes available.

QRYPTONEX addresses this paradigm shift by establishing a secure communication channel between high-throughput **x86_64 servers** (accelerated via **AVX2 / BMI2**) and resource-constrained **ARM edge devices** (Raspberry Pi 4/5 via **ARM64 NEON** and Raspberry Pi 2/3 via **ARM32 NEON / VFPv4**). The framework combines NIST-standardized lattice cryptography (**ML-KEM-768**, **ML-DSA-65**), authenticated symmetric encryption (**ChaCha20-Poly1305**), and directional session key derivation (**SHAKE256**) over an asynchronous Linux **`io_uring`** engine with application-level reliability and dynamic zero-configuration network discovery.

> [!NOTE]
> **Heterogeneous Cryptographic Implementations & Tooling Available in this Repository**:
> - **Post-Quantum Cryptography (PQC)** (`pqc/`): ML-KEM-768 + ML-DSA-65 + ChaCha20-Poly1305 on UDP Port `9877`.
> - **Classical Cryptography** (`classical/`): X25519 + Ed25519 + AES-128-CCM on UDP Port `9877`/`9878`. See [classical/README.md](classical/README.md).
> - **Hybrid Cryptography** (`hybrid/`): X25519 + ML-KEM-768 + Ed25519 + ML-DSA-65 + ChaCha20-Poly1305 on UDP Port `9879`. See [hybrid/README.md](hybrid/README.md).
> - **Unified Dual GTK 4 Graphical Interface (`./app.sh`)**: Runs both the Server NOC Telemetry Console and the Real-Network Attack Testing Lab simultaneously.
> - **Security Evaluation Lab (`security_lab/`)**: Real-network testing framework evaluating PQC, Hybrid, and Classical suites against active threat vectors (replay, packet tampering, authentication forgery, fuzzing, MTU fragmentation, and network impairments). See [security_lab/README.md](../security_lab/README.md).

---

## 📋 Table of Contents

1. [System Architecture & Protocols](#1-system-architecture--protocols)
   - [A. 4-Way Serial Mutual Authentication Handshake Protocol](#a-4-way-serial-mutual-authentication-handshake-protocol)
   - [B. Multi-Core Asynchronous Server Architecture (`io_uring`)](#b-multi-core-asynchronous-server-architecture-io_uring)
   - [C. Decoupled UNIX IPC Architecture](#c-decoupled-unix-ipc-architecture)
   - [D. Symmetric Data Transport & Wire Framing](#d-symmetric-data-transport--wire-framing)
2. [Cryptographic Specifications & Sizing](#2-cryptographic-specifications--sizing)
3. [Hardware Acceleration & Platform Support Matrix](#3-hardware-acceleration--platform-support-matrix)
4. [Repository Directory Structure](#4-repository-directory-structure)
5. [Exhaustive Setup & Compilation Guide](#5-exhaustive-setup--compilation-guide)
   - [Step 1: System Dependencies Installation](#step-1-system-dependencies-installation)
   - [Step 2: Cloning NEXQOR & `liboqs`](#step-2-cloning-nexqor--liboqs)
   - [Step 3: Compiling Static `liboqs` (x86_64, ARM64, ARM32)](#step-3-compiling-static-liboqs-x86_64-arm64-arm32)
   - [Step 4: Compiling Application Binaries for All 3 Device Tiers](#step-4-compiling-application-binaries-for-all-3-device-tiers)
6. [Dynamic Networking & Tailscale Mesh Guide](#6-dynamic-networking--tailscale-mesh-guide)
   - [Zero-Config 5-Tier Discovery Hierarchy](#zero-config-5-tier-discovery-hierarchy)
   - [Topology 1: Localhost (Same Machine)](#topology-1-localhost-same-machine)
   - [Topology 2: Local Network (LAN / Wi-Fi)](#topology-2-local-network-lan--wi-fi)
   - [Topology 3: Cross-Network / External via Tailscale](#topology-3-cross-network--external-via-tailscale)
7. [Running All Application Workflows](#7-running-all-application-workflows)
   - [Workflow 1: Multi-Client Server Relay](#workflow-1-multi-client-server-relay)
   - [Workflow 2: Interactive Secure Chat Client](#workflow-2-interactive-secure-chat-client)
   - [Workflow 3: Autonomous IoT Sensor Broadcaster (`client_broadcast`)](#workflow-3-autonomous-iot-sensor-broadcaster-client_broadcast)
   - [Workflow 4: High-Concurrency Benchmark (`bench_nclient`)](#workflow-4-high-concurrency-benchmark-bench_nclient)
   - [Workflow 5: Cryptographic Microbenchmark & AEAD Utility](#workflow-5-cryptographic-microbenchmark--aead-utility)
8. [Empirical Performance & Hardware Benchmarks](#8-empirical-performance--hardware-benchmarks)
9. [Automated Security Testing & Formal Verification](#9-automated-security-testing--formal-verification)
   - [A. Automated Security & Cryptographic Regression Test Suite](#a-automated-security--cryptographic-regression-test-suite)
   - [B. Formal Security Verification with ProVerif](#b-formal-security-verification-with-proverif)
10. [Research References, License & Citation](#10-research-references-license--citation)

---

## 1. System Architecture & Protocols

### A. 4-Way Serial Mutual Authentication Handshake Protocol

Communication operates over **UDP port 9877**, establishing mutual cryptographic trust and deriving quantum-resistant session keys. The handshake executes **serially** (sequential keypair generation, transcript exchange, decapsulation, and transcript signing) to provide deterministic timing, zero multithreading lock contention, and minimal memory overhead on embedded edge devices:

```text
      Client (x86 / ARM64 / ARM32)                                Server Core (x86_64)
           │                                                                 │
    [Serial Keygen: KEM + DSA]                                               │
    [Phase 1: Client Hello]                                                  │
           ├─────────────── PKT_CLIENT_HELLO ───────────────────────────────>│ [Parse & Validate]
           │        (KEM_PK_c || DSA_PK_c || Nonce_c)                       │
           │                                                                 │ [KEM Encap: ss, ct]
           │                                                                 │ [Transcript Hash 1]
           │                                                                 │ [ML-DSA-65 Sign]
    [Phase 2: Server Hello]                                                  │
           │<────────────── PKT_SERVER_HELLO ────────────────────────────────┤
           │        (DSA_PK_s || KEM_CT || Session_ID ||                     │
           │         Nonce_s || Signature_s)                                 │
           │                                                                 │
    [Verify Server Identity (TOFU Store)]                                    │
    [Verify Server Signature]                                                │
    [KEM Decap: ss]                                                          │
    [Transcript Hash 2]                                                      │
    [ML-DSA-65 Sign]                                                         │
    [Phase 3: Client Authentication]                                         │
           ├─────────────── PKT_CLIENT_AUTH ────────────────────────────────>│
           │        (Signature_c)                                            │
           │                                                                 │ [Verify Client Sig]
           │                                                                 │ [Derive Directional Keys]
    [Phase 4: Active Session]                                                │ (SHAKE256 KDF)
           │<────────────── PKT_ACK ─────────────────────────────────────────┤
           │                                                                 │
           *═══════════════ Secure AEAD Channel Established ═════════════════*
           │                                                                 │
           ├─────────────── PKT_DATA (ChaCha20-Poly1305) ───────────────────>│ [Decrypt & Route]
           │        [Nonce (12B) | Tag (16B) | Encrypted Payload]            │ (Wire Header as AAD)
           │<────────────── PKT_DATA (ChaCha20-Poly1305) ────────────────────┤
```

#### Detailed Mathematical Breakdown:
1. **Phase 1 (Client Hello)**:
   - Client generates ephemeral lattice keypair: $\text{KEM.KeyGen}() \to (pk_c, sk_c)$.
   - Client generates identity keypair: $\text{DSA.KeyGen}() \to (pk_c^{dsa}, sk_c^{dsa})$.
   - Client generates a 128-bit cryptographic nonce $N_c \xleftarrow{\$} \{0,1\}^{128}$.
   - Transmits `PKT_CLIENT_HELLO` containing $pk_c \parallel pk_c^{dsa} \parallel N_c$.

2. **Phase 2 (Server Hello)**:
   - Server encapsulates a 256-bit shared secret: $\text{KEM.Encap}(pk_c) \to (ct, ss)$.
   - Server generates server nonce $N_s \xleftarrow{\$} \{0,1\}^{128}$ and 64-bit atomic Session ID ($SID$).
   - Computes Transcript Hash 1: $H_1 = \text{SHAKE256}(N_c \parallel N_s \parallel SID \parallel pk_s^{dsa} \parallel ct)$.
   - Generates digital signature: $\sigma_s = \text{DSA.Sign}(sk_s^{dsa}, H_1)$.
   - Transmits `PKT_SERVER_HELLO` containing $pk_s^{dsa} \parallel ct \parallel SID \parallel N_s \parallel \sigma_s$.

3. **Phase 3 (Client Authentication & Verification)**:
   - Client verifies $pk_s^{dsa}$ against local pinned Trust Store (`server_identity.pub`).
   - Reconstructs $H_1$ and verifies signature: $\text{DSA.Verify}(pk_s^{dsa}, H_1, \sigma_s) \stackrel{?}{=} \text{VALID}$.
   - Decapsulates shared secret: $\text{KEM.Decap}(sk_c, ct) \to ss$.
   - Computes Transcript Hash 2: $H_2 = \text{SHAKE256}(H_1 \parallel \sigma_s)$.
   - Signs transcript: $\sigma_c = \text{DSA.Sign}(sk_c^{dsa}, H_2)$.
   - Transmits `PKT_CLIENT_AUTH` containing $\sigma_c$.

4. **Phase 4 (Session Key Derivation & Channel Activation)**:
   - Server verifies client signature: $\text{DSA.Verify}(pk_c^{dsa}, H_2, \sigma_c) \stackrel{?}{=} \text{VALID}$.
   - Both parties independently derive separate directional traffic keys using domain separation:
     $$K_{\text{tx}} = \text{SHAKE256}(ss \parallel SID \parallel \text{"client\_write"} \parallel N_c \parallel N_s)$$
     $$K_{\text{rx}} = \text{SHAKE256}(ss \parallel SID \parallel \text{"server\_write"} \parallel N_c \parallel N_s)$$
   - Server transmits `PKT_ACK`. The bidirectional AEAD session is active.

---

### B. Multi-Core Asynchronous Server Architecture (`io_uring`)

The server leverages Linux **`io_uring`** for asynchronous, zero-copy packet batching across a dedicated multi-core architecture:

```text
                          Incoming Client UDP Packets (:9877)
                                          │
                                          ▼
                +───────────────────────────────────────────────────+
                │           Core 0: Network Event Loop              │
                │  - io_uring Asynchronous Submission/Completion   │
                │  - Lock-Free Pre-allocated Buffer Ring (1024 bufs)│
                │  - Actor-Model Client Session Table (Lockless)    │
                │  - Adaptive Token-Bucket Rate Limiter             │
                +─────────────────────────┬─────────────────────────+
                                          │
                   SPMC Lock-Free Ring    │    MPSC Completion Ring
                                          ▼
                +───────────────────────────────────────────────────+
                │       Cores 1-3: Worker Thread Pool (x3)          │
                │  - Asynchronous ML-KEM-768 Encapsulation          │
                │  - Asynchronous ML-DSA-65 Verification & Signing  │
                │  - SHAKE-256 Transcript Hashing & Key Derivation  │
                +─────────────────────────┬─────────────────────────+
                                          │
                                          ▼
                +───────────────────────────────────────────────────+
                │        Core 4: Warm Path & IPC Subsystems         │
                │  - Thread-Safe Unix Domain Socket Dispatcher      │
                │  - Dynamic Endpoint Discovery & Beacon Broadcaster│
                +───────────────────────────────────────────────────+
```

---

### C. Decoupled UNIX IPC Architecture & GTK 4 Dashboard Integration

The server process decouples network packet processing from console interaction and graphical monitoring using non-blocking UNIX domain sockets (`/tmp/pqc_rx.sock`, `/tmp/pqc_tx.sock`):

```text
                            +───────────────────────+
                            │   Remote PQC Clients  │
                            +───────────┬───────────+
                                        │ UDP :9877
                                        ▼
                            +───────────────────────+
                            │   Server Core Relay   │
                            │      (server.c)       │
                            +─────┬───────────▲─────+
                                  │           │
           /tmp/pqc_rx.sock (IPC) │           │ /tmp/pqc_tx.sock (IPC)
                                  ▼           │
                      +───────────────────────┴───+
                      │   GTK 4 Pure C Dashboard  │
                      │       (ui/qhack_ui)       │
                      │  - Real-time Session Map  │
                      │  - 10s Inactivity Watchdog│
                      │  - Dynamic Wi-Fi Endpoint │
                      │  - Upside Metrics & Crypto│
                      +───────────────────────────+
```

- **Session Inactivity Watchdog**: Cleans inactive sessions after 10 seconds of silence, immediately notifying the dashboard to transition the peer to `DISCONNECTED SESSIONS (RECENT)`.
- **Instant `PKT_DISCONNECT` Handling**: When a client shuts down gracefully, `server.c` frees the session immediately and triggers an IPC update without waiting for a sweep timer.
- **Dynamic Wi-Fi Auto-Discovery**: Discovers active Wi-Fi and VPN interfaces (`getifaddrs`) and publishes them dynamically to the dashboard header and connection guides.

---

### D. Symmetric Data Transport & Wire Framing

1. **Authenticated Associated Data (AAD) Binding**:
   The 15-byte canonical wire header (`seq` [4B], `type` [1B], `len` [2B], `session_id` [8B]) is bound as AAD into every ChaCha20-Poly1305 packet. Any alteration of packet headers in flight causes Poly1305 authentication failure and immediate packet drop.
2. **Monotonic Nonce & Replay Protection**:
   Nonces are tracked strictly monotonically. A 64-packet bitmap sliding replay window (RFC 6479) verifies and drops delayed, duplicated, or replayed packets.
3. **Application-Level Fragmentation & Reassembly**:
   Transports large post-quantum public keys and signatures across sub-MTU UDP boundaries without IP fragmentation.

---

## 2. Cryptographic Specifications & Sizing

| Cryptographic Component | Algorithm / Standard | Security Strength | Wire / Key Sizes | Architectural Function |
| :--- | :--- | :--- | :--- | :--- |
| **Key Encapsulation (KEM)** | **ML-KEM-768** (NIST FIPS 203) | Level 3 (~AES-192) | **Public Key**: 1,184 Bytes<br>**Ciphertext**: 1,088 Bytes<br>**Shared Secret**: 32 Bytes | Ephemeral post-quantum session key establishment |
| **Digital Signatures (DSA)** | **ML-DSA-65** (NIST FIPS 204) | Level 3 (~AES-192) | **Public Key**: 1,952 Bytes<br>**Signature**: 3,309 Bytes | Mutual identity authentication & transcript signing |
| **Symmetric AEAD** | **ChaCha20-Poly1305** (RFC 8439) | 256-bit Key | **Key**: 32 Bytes<br>**Nonce**: 12 Bytes<br>**Tag**: 16 Bytes | High-speed authenticated encryption (header bound as AAD) |
| **Hash & KDF** | **SHAKE256** (NIST FIPS 202) | Extendable Output | **Digest**: Variable (64 Bytes) | Transcript binding & directional key separation |

*(For complete byte-level mathematical derivations, KDF entropy vectors, and wire framing layouts, see [CRYPTOGRAPHIC_SPECIFICATION.txt](CRYPTOGRAPHIC_SPECIFICATION.txt)).*

---

## 3. Hardware Acceleration & Platform Support Matrix

| Architecture | Hardware Targets | Vector Extensions | Compiler & Flags | Target Executables |
| :--- | :--- | :--- | :--- | :--- |
| **x86_64** | Intel / AMD Ryzen Servers, Laptops | **AVX2**, **BMI2**, **POPCNT** | `gcc` with `-O3 -march=native -flto=auto` | `server`, `server_rx`, `server_tx`, `client`, `client_broadcast`, `bench_pqc`, `bench_nclient`, `bench_aead` |
| **ARM64 (AArch64)** | Raspberry Pi 4 / 5 (64-bit OS), Jetson | **ARM NEON** (128-bit SIMD) | `gcc` with `-O3 -march=armv8-a+simd` | `client_arm`, `client_broadcast_arm`, `bench_pqc_arm`, `bench_nclient_arm` |
| **ARM32 (ARMv7-A)** | Raspberry Pi 2 / 3 (32-bit OS), BeagleBone | **ARM NEON** + **VFPv4** (armhf) | `gcc` with `-O3 -mfpu=neon-vfpv4 -mfloat-abi=hard` | `client_arm32`, `client_broadcast_arm32`, `bench_pqc_arm32`, `bench_nclient_arm32` |

---

## 4. Repository Directory Structure

```text
.
├── crypto/
│   ├── aead.c / aead.h             # ChaCha20-Poly1305 AEAD with AAD wire header binding (RFC 8439)
│   ├── replay_window.c / .h        # 64-packet bitmap sliding replay window (RFC 6479)
│   └── trust_store.c / .h          # Pinned peer identity key store and verification (TOFU)
├── wrappers/
│   ├── kem_wrapper.c / kem_wrapper.h # ML-KEM-768 wrappers & directional SHAKE256 KDF
│   └── dsa_wrapper.c / dsa_wrapper.h # ML-DSA-65 digital signature C wrappers
├── tests/
│   └── test_suite.c                # 8-suite automated cryptographic and security regression harness
├── verification/
│   ├── protocol.pv                 # Formal security verification model in Applied Pi-Calculus
│   └── README.md                   # ProVerif execution guide and proof breakdown
├── metrics/
│   ├── arm_client_side/            # Pre-collected client benchmark logs (1 to 1000 clients)
│   ├── arm64  sevrer/              # Server-side telemetry on ARM64 platforms
│   ├── x86 serevr/                 # Server-side telemetry on x86_64 platforms
│   └── *_bench_pqc_*.txt           # 10,000-run microbenchmark datasets
├── Research_papers/                # 20+ reference papers (NIST standards, lattice SIMD, IoT)
├── client.c                        # Interactive PQC chat client (clean UI, serial handshake)
├── client_broadcast.c              # Autonomous IoT sensor telemetry broadcaster
├── client_registry.c / .h          # Thread-safe client session state registry
├── server.c                        # High-throughput asynchronous io_uring multi-client server
├── server_rx.c / server_tx.c       # Decoupled server operator console interfaces
├── transport.c / transport.h       # Dynamic discovery, packet framing, AAD AEAD, ACKs, reassembly
├── ipc.h                           # IPC frame headers and command codes
├── bench_pqc.c                     # Standalone cryptographic primitives microbenchmark
├── bench_nclient.c                 # Multi-client concurrent stress-test harness
├── bench_aead.c                    # AEAD buffer benchmark & file encryption tool
├── classical/                      # Standalone Classical IoT Suite (X25519, Ed25519, AES-128-CCM)
│   ├── README.md                   # Complete documentation for Classical IoT Suite
│   ├── NETWORKING_GUIDE.md         # Classical networking and Tailscale guide
│   ├── CRYPTOGRAPHIC_SPECIFICATION.txt # Classical wire and mathematical specification
│   ├── Makefile, Makefile.arm64, Makefile.arm32
│   └── (server, client, client_broadcast, server_rx, server_tx, benchmarks)
├── hybrid/                         # Standalone Hybrid Cryptographic Suite (X25519+ML-KEM, Ed25519+ML-DSA)
│   ├── README.md                   # Complete documentation for Hybrid Suite
│   ├── NETWORKING_GUIDE.md         # Hybrid networking and Tailscale guide
│   ├── CRYPTOGRAPHIC_SPECIFICATION.txt # Hybrid wire and mathematical specification
│   ├── Makefile, Makefile.arm64, Makefile.arm32
│   ├── include/ & src/             # Dual KEX, Dual Signatures, Combiner, Handshake
│   └── (server, client, client_broadcast, server_rx, server_tx, benchmarks)
├── Makefile                        # Native build system for x86_64 host
├── Makefile.arm64                  # Build system for ARM64 (Raspberry Pi 4/5)
├── Makefile.arm32                  # Build system for ARM32 (Raspberry Pi 2/3)
├── run.sh                          # Automated 3-window terminal launcher for server
├── NETWORKING_GUIDE.md             # Dedicated guide for dynamic discovery & Tailscale setup
├── CRYPTOGRAPHIC_SPECIFICATION.txt # Exhaustive cryptographic technical & wire specification
├── commands.md                     # Detailed command reference and cheatsheet
└── README.md                       # Main project documentation
```

---

## 5. Exhaustive Setup & Compilation Guide

Follow these steps from a clean environment to compile and run across all platforms.

### Step 1: System Dependencies Installation

#### On Ubuntu / Debian / x86_64 Host:
```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake git pkg-config libssl-dev liburing-dev
```

#### On Raspberry Pi (Raspberry Pi OS 64-bit or 32-bit):
```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake git pkg-config libssl-dev
```

*(Optional: Cross-compilers if building for ARM from an x86_64 host)*:
```bash
sudo apt-get install -y gcc-aarch64-linux-gnu g++-aarch64-linux-gnu gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf
```

---

### Step 2: Cloning NEXQOR & `liboqs`

Clone the NEXQOR repository and the Open Quantum Safe library (`liboqs`):

```bash
# 1. Clone NEXQOR
git clone https://github.com/Vshal-Kumar/QRYPTONEX.git
cd QRYPTONEX

# 2. Clone liboqs into the project tree
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git liboqs
```

---

### Step 3: Compiling Static `liboqs` (x86_64, ARM64, ARM32)

Compile `liboqs` with target-specific SIMD vectorization flags:

#### A. For x86_64 Host (AVX2 & BMI2 SIMD Acceleration)
```bash
cmake -S liboqs -B liboqs/build \
      -DCMAKE_BUILD_TYPE=Release \
      -DOQS_BUILD_ONLY_LIB=ON \
      -DOQS_ENABLE_KEM_ml_kem_768=ON \
      -DOQS_ENABLE_SIG_ml_dsa_65=ON \
      -DOQS_USE_AVX2_INSTRUCTIONS=ON \
      -DOQS_USE_BMI2_INSTRUCTIONS=ON \
      -DOQS_USE_POPCNT_INSTRUCTIONS=ON \
      -DCMAKE_C_FLAGS="-march=native -O3" \
      -DBUILD_SHARED_LIBS=OFF

cmake --build liboqs/build -j$(nproc)
```

#### B. For ARM64 / AArch64 (Raspberry Pi 4 / 5 NEON SIMD)
> [!IMPORTANT]
> When compiling directly on a Raspberry Pi, **do not use `-j$(nproc)`**; excessive parallel compilation will exhaust RAM and trigger kernel OOM kills. Use `-j2` or `-j1`.

```bash
cmake -S liboqs -B liboqs/build \
      -DCMAKE_BUILD_TYPE=Release \
      -DOQS_BUILD_ONLY_LIB=ON \
      -DOQS_ENABLE_KEM_ml_kem_768=ON \
      -DOQS_ENABLE_SIG_ml_dsa_65=ON \
      -DCMAKE_C_FLAGS="-O3 -march=armv8-a+simd" \
      -DBUILD_SHARED_LIBS=OFF

cmake --build liboqs/build -j2
```

#### C. For ARM32 / ARMv7-A (Raspberry Pi 2 / 3 NEON / VFPv4)
```bash
cmake -S liboqs -B liboqs/build_arm32 \
      -DCMAKE_BUILD_TYPE=Release \
      -DOQS_BUILD_ONLY_LIB=ON \
      -DOQS_ENABLE_KEM_ml_kem_768=ON \
      -DOQS_ENABLE_SIG_ml_dsa_65=ON \
      -DCMAKE_C_FLAGS="-O3 -march=armv7-a -mfpu=neon-vfpv4 -mfloat-abi=hard" \
      -DBUILD_SHARED_LIBS=OFF

cmake --build liboqs/build_arm32 -j2
```

---

### Step 4: Compiling Application Binaries for All 3 Device Tiers

#### Tier 1: x86_64 Server, Clients & Benchmarks
```bash
make all -j$(nproc)
```
*Outputs*: `server`, `server_rx`, `server_tx`, `client`, `client_broadcast`, `bench_pqc`, `bench_nclient`, `bench_aead`.

#### Tier 2: ARM64 (Raspberry Pi 4 / 5)
```bash
# On Raspberry Pi hardware:
make -f Makefile.arm64 all -j2

# Or cross-compiled from x86_64 host:
make -f Makefile.arm64 all -j$(nproc)

# Clean ARM64 build artifacts:
make -f Makefile.arm64 clean
```
*Outputs*: `client_arm`, `client_broadcast_arm`, `bench_pqc_arm`, `bench_nclient_arm`.

#### Tier 3: ARM32 (Raspberry Pi 2 / 3)
```bash
# On Raspberry Pi hardware:
make -f Makefile.arm32 all -j2

# Or cross-compiled from x86_64 host:
make -f Makefile.arm32 all -j$(nproc)

# Clean ARM32 build artifacts:
make -f Makefile.arm32 clean
```
*Outputs*: `client_arm32`, `client_broadcast_arm32`, `bench_pqc_arm32`, `bench_nclient_arm32`.

---

## 6. Dynamic Networking & Tailscale Mesh Guide

Hardcoded IP addresses have been completely eliminated. All binaries resolve server addresses dynamically using a 5-tier resolution chain.

### Zero-Config 5-Tier Discovery Hierarchy

```text
┌────────────────────────────────────────────────────────────────────────┐
│ 1. Explicit CLI Target (IPv4, Hostname, or Tailscale MagicDNS name)    │
│    e.g., ./client 10.58.3.114  or  ./client nexqor-server              │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ (if omitted)
┌──────────────────────────────────▼─────────────────────────────────────┐
│ 2. Environment Variables (PQC_SERVER_IP, SERVER_IP, NEXQOR_SERVER)    │
│    e.g., export PQC_SERVER_IP="100.104.77.63"                          │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ (if not set)
┌──────────────────────────────────▼─────────────────────────────────────┐
│ 3. System & Local Discovery Files                                      │
│    Reads /tmp/nexqor_server.ip or ./server_endpoint.info published     │
│    automatically by the running server.                                │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ (if running on a remote device)
┌──────────────────────────────────▼─────────────────────────────────────┐
│ 4. LAN UDP Broadcast Auto-Discovery Probe                              │
│    Client sends PKT_DISCOVERY_PROBE to port 9877. Server replies with  │
│    PKT_DISCOVERY_OFFER, allowing zero-config detection on any LAN.     │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ (if no response)
┌──────────────────────────────────▼─────────────────────────────────────┐
│ 5. Localhost Fallback (127.0.0.1:9877)                                 │
└────────────────────────────────────────────────────────────────────────┘
```

---

### Topology 1: Localhost (Same Machine)
No arguments are required. The server publishes endpoints to `/tmp/nexqor_server.ip` and clients connect automatically:
```bash
# Terminal 1: Server
./server

# Terminal 2: Client
./client
```

---

### Topology 2: Local Network (LAN / Wi-Fi)
*(e.g., Server on Laptop `10.58.3.114`, Client on Raspberry Pi on the same Wi-Fi)*

- **Zero-Configuration Mode**:
  ```bash
  # On Raspberry Pi (ARM64 or ARM32):
  ./client_arm
  ```
  The client sends a UDP broadcast probe (`PKT_DISCOVERY_PROBE`) to port 9877, the server replies (`PKT_DISCOVERY_OFFER`), and the client learns the server IP automatically!
- **Or Explicit IP**:
  ```bash
  ./client_arm 10.58.3.114
  ```

---

### Topology 3: Cross-Network / External via Tailscale
For connecting across different networks (e.g., Server at home/office, Client on 4G/5G mobile hotspot or remote Wi-Fi), Tailscale provides secure peer-to-peer WireGuard mesh routing through firewalls without router port forwarding:

1. **Install Tailscale on both machines**:
   ```bash
   curl -fsSL https://tailscale.com/install.sh | sh
   ```
2. **Start Tailscale**:
   ```bash
   sudo tailscale up
   ```
3. **Launch Server**:
   ```bash
   ./server
   ```
   The server automatically detects the `tailscale0` adapter and displays:
   ```text
     • Tailscale / VPN Overlay : 100.104.77.63:9877
   ```
4. **Connect from Remote Client Anywhere in the World**:
   ```bash
   ./client_arm 100.104.77.63
   # Or using Tailscale MagicDNS:
   ./client_arm my-laptop-name
   ```

*(See [NETWORKING_GUIDE.md](NETWORKING_GUIDE.md) for full configuration details).*

---

## 7. Running All Application Workflows

### Workflow 1: Multi-Client Server Relay

```bash
# Launch server core:
./server
```

**Startup Banner:**
```text
[18:31:18] QRYPTONEX — Post-Quantum Secure Server
  Protocol : ML-KEM-768 + ML-DSA-65 + ChaCha20-Poly1305
  Address  : 0.0.0.0:9877  |  Max clients: 4096
  Active Endpoints (Auto-Discovered & Published):
    • Localhost (Same Device) : 127.0.0.1:9877
    • LAN / Wi-Fi Subnet      : 10.58.3.114:9877
    • Tailscale / VPN Overlay : 100.104.77.63:9877
    • Auto-Discovery Service  : UDP Broadcast Probe on port 9877
```

*(Optional decoupled operator consoles)*:
- Terminal 2: `./server_rx` (Displays incoming client messages)
- Terminal 3: `./server_tx` (Allows broadcasting/messaging clients)
- Or launch all 3 simultaneously: `./run.sh`

---

### Workflow 2: Interactive Secure Chat Client

Connect to the server with a clean terminal interface:
```bash
# On x86_64:
./client                  # Auto-discovery
./client 10.58.3.114      # Explicit LAN IP
./client 100.104.77.63    # Tailscale IP

# On Raspberry Pi (ARM64):
./client_arm

# On Raspberry Pi (ARM32):
./client_arm32
```

**Terminal Session Output:**
```text
  Server target : 10.58.3.114:9877
[18:32:04] Connected to 10.58.3.114:9877 (Session ID: b68129706a14ff16)
[18:32:04] Ready to chat. Type a message and press Enter (Ctrl-C to exit).
> Hello Server
[18:32:08] Server: Quantum channel secure.
> 
```

---

### Workflow 3: Autonomous IoT Sensor Broadcaster (`client_broadcast`)

Simulates an autonomous sensor node that connects via post-quantum mutual authentication and continuously streams encrypted sensor telemetry:

```bash
# Syntax: ./client_broadcast [server_ip] [interval_ms] [device_id]

# Auto-discovery (500ms interval, ESP32-NODE-01):
./client_broadcast

# High-frequency stream (100ms) with custom ID:
./client_broadcast auto 100 "PI-SENSOR-NODE"

# On Raspberry Pi over Tailscale:
./client_broadcast_arm 100.104.77.63 200 "REMOTE-ENV-MONITOR"
```

**Stream Output:**
```text
  Server target : 10.58.3.114:9877
[18:31:49] Connected to 10.58.3.114:9877 (Session ID: d20fec5a0f374489)
[18:31:49] Broadcasting telemetry from device 'ESP32-NODE-01' (interval: 500ms)...
[18:31:49] #1     | Temp: 25.6°C | Hum: 55.0% | Press: 1013.3hPa | Vbat: 4.12V | Status: OK  
[18:31:50] #2     | Temp: 25.5°C | Hum: 55.1% | Press: 1013.3hPa | Vbat: 4.12V | Status: OK  
[18:31:50] #3     | Temp: 25.5°C | Hum: 55.1% | Press: 1013.3hPa | Vbat: 4.12V | Status: OK  
```

---

### Workflow 4: High-Concurrency Benchmark (`bench_nclient`)

Simulates $N$ concurrent client threads synchronizing on a thread barrier, performing concurrent post-quantum handshakes, and streaming messages:

```bash
# Syntax: ./bench_nclient [num_clients] [num_messages] [server_ip (optional)]

# 64 clients, 10 messages each (Auto-discovery):
./bench_nclient 64 10

# 256 clients across Tailscale:
./bench_nclient 256 5 100.104.77.63

# On Raspberry Pi (ARM64):
./bench_nclient_arm 32 5
```

**Benchmark Output Table:**
```text
┌─ System-Wide & Communication Metrics ──────────────────────────────────────────────────┐
│  Metric                             │    Value              │  Unit                    │
│  ───────────────────────────────────┼───────────────────────┼──────────────────────────│
│  Handshake Success Rate             │                 100.0   │  %                       │
│  Handshake Throughput               │                  35.9   │  handshakes/sec          │
│  Network Handshake RTT (Average)    │                 4.624   │  ms                      │
│  Total Handshake Latency (Average)  │                 4.715   │  ms                      │
│  CPU Utilization                    │                  20.6   │  %                       │
│  Peak RAM Usage                     │                1334.7   │  MB                      │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

### Workflow 5: Cryptographic Microbenchmark & AEAD Utility

#### 1. Standalone Primitives Microbenchmark (`bench_pqc`):
```bash
./bench_pqc [rounds]         # x86_64
./bench_pqc_arm [rounds]     # ARM64
./bench_pqc_arm32 [rounds]   # ARM32
```
*Example (1,000 iterations)*: `./bench_pqc 1000`

#### 2. AEAD Throughput Benchmark & File Encryption (`bench_aead`):
```bash
# Benchmark symmetric throughput across payload sizes (64B to 16KB):
./bench_aead 1000

# Encrypt a file with ChaCha20-Poly1305:
./bench_aead encrypt document.pdf document.pdf.enc

# Decrypt the encrypted file:
./bench_aead decrypt document.pdf.enc document_dec.pdf <KEY_HEX>
```

---

## 8. Empirical Performance & Hardware Benchmarks

All metrics were captured on bare-metal hardware using high-resolution monotonic timestamps (`clock_gettime(CLOCK_MONOTONIC)`):

### Cryptographic Primitive Latency Breakdown

| Primitive / Operation | Algorithm | x86_64 (AVX2) | ARM64 (NEON Cortex-A72) | ARM32 (NEON Cortex-A53) |
| :--- | :--- | :---: | :---: | :---: |
| **KEM Key Generation** | ML-KEM-768 | ~12.4 $\mu s$ | ~48.2 $\mu s$ | ~112.6 $\mu s$ |
| **KEM Encapsulation** | ML-KEM-768 | ~15.1 $\mu s$ | ~56.8 $\mu s$ | ~138.4 $\mu s$ |
| **KEM Decapsulation** | ML-KEM-768 | ~14.8 $\mu s$ | ~53.1 $\mu s$ | ~129.7 $\mu s$ |
| **DSA Key Generation** | ML-DSA-65 | ~34.2 $\mu s$ | ~132.5 $\mu s$ | ~310.2 $\mu s$ |
| **DSA Signature** | ML-DSA-65 | ~86.4 $\mu s$ | ~348.9 $\mu s$ | ~894.1 $\mu s$ |
| **DSA Verification** | ML-DSA-65 | ~39.7 $\mu s$ | ~158.3 $\mu s$ | ~387.6 $\mu s$ |
| **Full 4-Way Serial Handshake** | KEM + DSA + Net | **~0.85 ms** | **~2.14 ms** | **~5.42 ms** |

### High-Concurrency Server Scaling (`io_uring`)

| Concurrent Clients ($N$) | Total Handshake Time (x86_64) | Success Rate | Peak Server CPU | Memory Usage |
| :---: | :---: | :---: | :---: | :---: |
| **10** | 12.8 ms | 100.0% | 4.2% | ~14 MB |
| **50** | 46.1 ms | 100.0% | 12.8% | ~18 MB |
| **100** | 89.4 ms | 100.0% | 24.1% | ~22 MB |
| **500** | 412.3 ms | 100.0% | 58.7% | ~46 MB |
| **1,000** | 845.6 ms | 100.0% | 88.3% | ~78 MB |

---

## 9. Automated Security Testing & Formal Verification

### A. Automated Security & Cryptographic Regression Test Suite

The repository includes an 8-suite automated regression test validating the cryptographic primitives, directional key separation, replay protection, AEAD tampering resistance, pinned peer authentication, packet fragmentation, and session isolation:

```bash
make test
```

**Automated Test Suite Output:**
```text
=== Running NEXQOR Automated Security and Unit Test Suite ===
./tests/test_suite

╔══════════════════════════════════════════════════════════════╗
║       NEXQOR — Post-Quantum Security & Cryptographic Tests   ║
╚══════════════════════════════════════════════════════════════╝

[TEST 01] test_kem_agreement_and_negative                  PASS
[TEST 02] test_dsa_signing_and_tampering                   PASS
[TEST 03] test_directional_kdf_separation                  PASS
[TEST 04] test_aead_aad_binding_and_tampering              PASS
[TEST 05] test_sliding_replay_window                       PASS
[TEST 06] test_trust_store_peer_authentication            PASS
[TEST 07] test_packet_framing_and_reassembly               PASS
[TEST 08] test_session_isolation_and_cleanup               PASS

════════════════════════════════════════════════════════════════
Test Results: 8/8 passed (0 failed)
ALL SECURITY & REGRESSION TESTS PASSED SUCCESSFULLY!
```

#### Test Suite Descriptions:
1. **TEST 01 (`test_kem_agreement_and_negative`)**: Tests ML-KEM-768 shared secret agreement and verifies that tampered ciphertexts are rejected.
2. **TEST 02 (`test_dsa_signing_and_tampering`)**: Verifies ML-DSA-65 signature generation and validates that bit-flipped messages or invalid public keys are rejected.
3. **TEST 03 (`test_directional_kdf_separation`)**: Validates that derived client-to-server (`tx_key`) and server-to-client (`rx_key`) keys are cryptographically distinct.
4. **TEST 04 (`test_aead_aad_binding_and_tampering`)**: Verifies that altering any field in the 15-byte packet wire header (AAD) triggers an authentication failure.
5. **TEST 05 (`test_sliding_replay_window`)**: Validates the 64-packet bitmap replay window against out-of-order, duplicated, and old packets.
6. **TEST 06 (`test_trust_store_peer_authentication`)**: Verifies that untrusted or substituted server public keys are flagged and rejected (TOFU pinning).
7. **TEST 07 (`test_packet_framing_and_reassembly`)**: Validates fragmentation and out-of-order reassembly of oversized PQC payloads across UDP boundaries.
8. **TEST 08 (`test_session_isolation_and_cleanup`)**: Verifies that multiple client sessions maintain isolated states and that sensitive key material is securely zeroized on disconnect.

---

### B. Formal Security Verification with ProVerif

The 4-way mutual authentication handshake has been modeled and formally verified in **Applied Pi-Calculus** using **[ProVerif](https://proverif.inria.fr/)**, proving mathematical security against an active Dolev-Yao adversary with full network control:

```bash
# Install ProVerif:
sudo apt-get install -y proverif

# Run mathematical verification:
proverif verification/protocol.pv
```

#### 21 Formally Proven Security Properties:

| # | Security Property | Verification Status | Mathematical Mapping (`verification/protocol.pv`) |
| :-: | :--- | :-: | :--- |
| **1** | **Session Key Secrecy** | ✅ **Proven** | `not attacker(session_key_secret)` holds across all execution paths. |
| **2** | **Client Data Secrecy** | ✅ **Proven** | `not attacker(client_data)` — payload confidential against active adversary. |
| **3** | **Server Data Secrecy** | ✅ **Proven** | `not attacker(server_data)` — outbound server payload confidential. |
| **4** | **Client Authentication** | ✅ **Proven** | `inj-event(server_accepts) ==> inj-event(client_initiates)`. |
| **5** | **Server Authentication** | ✅ **Proven** | `inj-event(client_accepts) ==> inj-event(server_initiates)`. |
| **6** | **Mutual Authentication** | ✅ **Proven** | Symmetrical injective correspondence verified across both endpoints. |
| **7** | **Replay Resistance** | ✅ **Proven** | `inj-event` enforces strict 1-to-1 session mapping. |
| **8** | **Perfect Forward Secrecy (PFS)** | ✅ **Proven** | Compromise of long-term signing keys leaks zero past session keys or data. |
| **9** | **Key Confirmation** | ✅ **Proven** | Injective agreements guarantee identical derived key $k$ at both sides. |
| **10** | **Message Integrity** | ✅ **Proven** | AEAD equational reduction: $\text{aead\_decrypt}(\text{aead\_encrypt}(m,k,n),k,n) = m$. |
| **11** | **Transcript Binding** | ✅ **Proven** | Full transcript agreement binds nonces, session ID, and KEM ciphertext $ct$. |
| **12** | **Signature Unforgeability** | ✅ **Proven** | Asymmetric signature unforgeable without secret key $sk^{dsa}$. |
| **13** | **Ciphertext Integrity** | ✅ **Proven** | Tampered AEAD ciphertext fails cryptographic authentication. |
| **14** | **KEM Substitution Resistance**| ✅ **Proven** | Altering $ct$ invalidates signature and aborts key derivation. |
| **15** | **Unknown Key-Share (UKS) Protection** | ✅ **Proven** | Explicit binding of identity public keys ($pk^{dsa}$) prevents UKS attacks. |
| **16** | **Reflection Attack Resistance** | ✅ **Proven** | Asymmetric packet types and transcript headers prevent reflection. |
| **17** | **Parallel Session Security** | ✅ **Proven** | Modeled via replicated unbounded processes `!client` and `!server`. |
| **18** | **Session Mix-Up Resistance** | ✅ **Proven** | Cryptographic separation via ephemeral nonces and server session IDs. |
| **19** | **Identity Binding** | ✅ **Proven** | Signatures bind identity public keys directly into transcript hashes. |
| **20** | **Nonce Freshness** | ✅ **Proven** | Modeled via `new c_nonce` and `new s_nonce` generation. |
| **21** | **Session ID Uniqueness** | ✅ **Proven** | Guaranteed by atomic `new session_id` generation on the server. |

---

## 10. Research References, License & Citation

### Key Standards & Academic Literature:
- **NIST FIPS 203**: *Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)*.
- **NIST FIPS 204**: *Module-Lattice-Based Digital Signature Standard (ML-DSA)*.
- **RFC 8439**: *ChaCha20 and Poly1305 for IETF Protocols*.
- **RFC 6479**: *Alternative Replay Window for IPsec*.
- **Applied Pi-Calculus & ProVerif**: *Automatic Cryptographic Protocol Verifier in the Formal Model*.

### License
This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for complete details.

### Citation
```bibtex
@misc{pqc_cross_platform_evaluation_2026,
  author = {Vishal Kumar},
  title = {QRYPTONEX: Cross-Platform Evaluation of Scalable Post-Quantum Secure Communication},
  year = {2026},
  publisher = {GitHub},
  howpublished = {\url{https://github.com/Vshal-Kumar/QRYPTONEX}}
}
```
