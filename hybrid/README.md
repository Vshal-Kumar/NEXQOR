# QRYPTONEX (Hybrid Suite) — Post-Quantum & Classical Hybrid Cryptographic Networking Engine

[![Language: C11](https://img.shields.io/badge/Language-C11-00599C.svg?logo=c&logoColor=white)](https://en.wikipedia.org/wiki/C11_(C_standard_revision))
[![Architecture: Multi-Arch](https://img.shields.io/badge/Architecture-x86__64%20%7C%20ARM64%20%7C%20ARM32-blue.svg)](https://arm.com)
[![KEX: X25519 + ML-KEM-768](https://img.shields.io/badge/Hybrid%20KEX-X25519%20%2B%20ML--KEM--768%20(FIPS%20203)-orange.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![Signatures: Ed25519 + ML-DSA-65](https://img.shields.io/badge/Dual%20Signatures-Ed25519%20%2B%20ML--DSA--65%20(FIPS%20204)-red.svg)](https://csrc.nist.gov/pubs/fips/204/final)
[![AEAD: ChaCha20-Poly1305](https://img.shields.io/badge/AEAD-ChaCha20--Poly1305%20(RFC%208439)-brightgreen.svg)](https://datatracker.ietf.org/doc/html/rfc8439)
[![KDF: HKDF-SHA-384](https://img.shields.io/badge/KDF-HKDF--SHA--384%20(RFC%205869)-blue.svg)](https://datatracker.ietf.org/doc/html/rfc5869)
[![Replay Defense: RFC 6479](https://img.shields.io/badge/Anti--Replay-RFC%206479%20Sliding%20Window-purple.svg)](https://datatracker.ietf.org/doc/html/rfc6479)
[![Port: UDP 9879](https://img.shields.io/badge/Transport-UDP%20Port%209879-yellow.svg)](NETWORKING_GUIDE.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](../LICENSE)

---

## 1. Executive Overview

**QRYPTONEX Hybrid Cryptographic Suite** (`QRYPTONEX-HYBRID-X25519-MLKEM768-ED25519-MLDSA65`, Protocol Version `0x0100`) is a production-grade, SIMD-accelerated **dual-layer cryptographic networking framework** and multi-client relay engine implemented in **C11**.

Modern public-key cryptography (RSA, ECDH, ECDSA) is vulnerable to polynomial-time quantum attacks (**Shor's algorithm**), and adversaries are actively executing **"Harvest-Now-Decrypt-Later" (HNDL)** attacks by intercepting encrypted network streams to retroactively decrypt them once cryptanalytically relevant quantum computers (CRQCs) become operational. Concurrently, migrating entirely to new post-quantum algorithms carries risks if unforeseen mathematical or implementation vulnerabilities are uncovered in lattice cryptography.

The QRYPTONEX Hybrid Suite solves both challenges through a **dual-security hybrid design**:
1. **Confidentiality Dual Guarantee**: Traffic secrecy is guaranteed as long as **either** X25519 or ML-KEM-768 remains unbroken.
2. **Authenticity Dual Guarantee**: Dual digital signatures guarantee non-repudiation and identity authenticity as long as **either** Ed25519 or ML-DSA-65 remains secure.
3. **Strict Fail-Closed Architecture**: No single-primitive fallback is ever permitted. Both the classical and post-quantum handshakes and signatures must verify cleanly; any tampered or missing component results in immediate connection abortion.

> [!NOTE]
> The original post-quantum implementation (`pqc/` on port `9877`) and the classical IoT implementation (`classical/` on port `9877`/`9878`) remain completely untouched, self-contained, and independently buildable. This hybrid implementation resides entirely in `hybrid/` on UDP port `9879`.
> - **Unified Dual GTK 4 Graphical Interface (`./app.sh` / `./run_ui.sh`)**: Runs the Server NOC Telemetry Console with manual Start/Stop control, dynamic local Wi-Fi IP auto-detection, upside live telemetry & downside cryptographic session inspector, and clean suite switching.
> - **Security Evaluation Lab (`security_lab/`)**: Real-network testing framework evaluating PQC, Hybrid, and Classical suites against active threat vectors (replay, packet tampering, authentication forgery, fuzzing, MTU fragmentation, and network impairments). See [security_lab/README.md](../security_lab/README.md).

---

## 2. Cryptographic Suite Comparison Matrix

| Cryptographic Component | Original Post-Quantum Suite (Root) | Classical IoT Suite (`classical/`) | Hybrid Cryptographic Suite (`hybrid/`) |
| :--- | :--- | :--- | :--- |
| **Default UDP Port** | `9877` | `9877` / `9878` | **`9879`** |
| **Key Agreement (KEX)** | ML-KEM-768 (FIPS 203) | X25519 ECDH (RFC 7748) | **X25519 (32B) + ML-KEM-768 (1184B)** |
| **Ciphertext / Response** | 1088 bytes (ML-KEM CT) | 32 bytes (X25519 PK) | **X25519 PK (32B) + ML-KEM CT (1088B)** |
| **Digital Signatures** | ML-DSA-65 (FIPS 204) | Ed25519 (RFC 8032) | **Ed25519 (64B) + ML-DSA-65 (3309B)** |
| **Identity Public Keys** | 1952 bytes (ML-DSA-65) | 32 bytes (Ed25519) | **Ed25519 PK (32B) + ML-DSA PK (1952B)** |
| **Shared Secret Combiner** | Single 32-byte Lattice Secret | Single 32-byte ECDH Secret | **Raw Concatenation (64B) + HKDF-SHA-384** |
| **Authenticated Encryption** | ChaCha20-Poly1305 (RFC 8439) | AES-128-CCM (SP 800-38C) | **ChaCha20-Poly1305 (RFC 8439)** |
| **Transcript Hashing** | SHAKE256 XOF (FIPS 202) | SHA-256 (FIPS 180-4) | **SHA-384 (FIPS 180-4)** |
| **Traffic Key Derivation** | Custom SHAKE256 PRF | HKDF-SHA-256 (RFC 5869) | **HKDF-SHA-384 (RFC 5869) Domain Separated** |
| **Anti-Replay Window** | RFC 6479 64-Packet Bitmap | RFC 6479 64-Packet Bitmap | **RFC 6479 64-Packet Bitmap** |
| **UNIX IPC Sockets** | `/tmp/pqc_rx.sock`, `pqc_tx` | `/tmp/classical_rx.sock`, `tx` | **`/tmp/hybrid_rx.sock`**, **`/tmp/hybrid_tx.sock`** |

---

## 3. Directory Structure

```text
hybrid/
├── include/                         # Public API and cryptographic interface definitions
│   ├── hybrid_crypto.h              # Suite constants, identity keys, lifecycle
│   ├── hybrid_kex.h                 # Combined X25519 + ML-KEM-768 key establishment
│   ├── hybrid_signature.h           # Framed Ed25519 + ML-DSA-65 dual signatures
│   ├── hybrid_kdf.h                 # SHA-384 & HKDF-SHA-384 key derivation
│   ├── hybrid_handshake.h           # Mutual authentication state machine & wire framing
│   ├── hybrid_session.h             # ChaCha20-Poly1305 session encryption & replay protection
│   └── hybrid_errors.h              # Structured error codes and diagnostic strings
│
├── src/                             # Core hybrid cryptographic library implementation
│   ├── hybrid_crypto.c              # Cryptographic initialization and key I/O
│   ├── hybrid_kex.c                 # Ephemeral key exchange and shared secret combination
│   ├── hybrid_signature.c           # Dual signing, verification, and serialization
│   ├── hybrid_kdf.c                 # SHA-384 and HKDF implementations
│   ├── hybrid_handshake.c           # State machine transitions and transcript hashing
│   ├── hybrid_session.c             # AEAD encryption, decryption, and sequence tracking
│   └── hybrid_errors.c              # Diagnostic error mapping
│
├── tests/                           # Automated unit test suite (35 security & regression tests)
│   ├── test_hybrid_kex.c            # Key establishment & contributory checks
│   ├── test_hybrid_signatures.c     # Dual signature signing & verification
│   ├── test_hybrid_kdf.c            # SHA-384 & HKDF KAT vectors
│   ├── test_hybrid_handshake.c      # Full handshake simulation & downgrade checks
│   ├── test_hybrid_session.c        # Bidirectional AEAD & tampering tests
│   ├── test_replay_protection.c     # RFC 6479 sliding window validation
│   └── test_negative_cases.c        # Boundary, null pointer, and error handling
│
├── client.c                         # Interactive mutual authentication chat client
├── client_broadcast.c               # Autonomous IoT sensor telemetry broadcaster
├── client_registry.c                # Thread-safe multi-client session state table
├── client_registry.h                # Client registry interface
├── server.c                         # Multi-worker thread pool UDP server engine
├── server_rx.c                      # UNIX IPC telemetry receiver terminal
├── server_tx.c                      # UNIX IPC command transmitter terminal
├── transport.c                      # UDP networking, dynamic discovery, framing & AAD
├── transport.h                      # 15-byte wire header, connection state & metrics
├── ipc.h                            # UNIX domain socket IPC wire protocol
│
├── bench_crypto.c                   # Cryptographic primitive microbenchmark suite
├── bench_nclient.c                  # Multi-client concurrent handshake benchmark
├── bench_aead.c                     # ChaCha20-Poly1305 benchmark & file encryption tool
│
├── Makefile                         # x86_64 host build system
├── Makefile.arm64                   # ARM64 / Raspberry Pi 4 & 5 build system
├── Makefile.arm32                   # ARMv7-A / Raspberry Pi 2 & 3 build system
├── run.sh                           # Three-terminal server/rx/tx launcher script
├── NETWORKING_GUIDE.md              # Zero-config discovery and Tailscale mesh guide
├── CRYPTOGRAPHIC_SPECIFICATION.txt   # Mathematical wire format & protocol specification
└── README.md                        # Master documentation
```

---

## 4. System Architecture & Protocols

### A. 4-Phase Mutual Authentication Handshake Protocol

Communication operates over **UDP port 9879**. The handshake executes serially to provide deterministic timing, zero multithreading lock contention, and minimal memory overhead on embedded edge devices:

```text
      Client (x86 / ARM64 / ARM32)                                Server Core (x86_64)
           │                                                                 │
    [Generate Ephemeral X25519 + ML-KEM]                                     │
    [Phase 1: Client Hello]                                                  │
           ├─────────────── PKT_CLIENT_HELLO (3216B) ───────────────────────>│ [Parse & Validate]
           │        (Nonce_c || X25519_pk || MLKEM_pk ||                     │
           │         Ed25519_pk || MLDSA_pk)                                 │ [ML-KEM Encap: ss_pq, ct]
           │                                                                 │ [X25519 Derive: ss_c]
           │                                                                 │ [Combine Secrets: Raw_SS]
           │                                                                 │ [HKDF-Extract: Master_SS]
           │                                                                 │ [Transcript Hash 1 (SHA-384)]
           │                                                                 │ [Sign Dual: Ed25519 + ML-DSA]
    [Phase 2: Server Hello]                                                  │
           │<────────────── PKT_SERVER_HELLO (4569B) ────────────────────────┤
           │        (Nonce_s || Session_ID || X25519_srv_pk ||               │
           │         MLKEM_ct || Ed25519_sig || MLDSA_sig)                   │
           │                                                                 │
    [Verify Server Identity (Dual Key Pinning)]                              │
    [Verify Dual Signature (Ed25519 & ML-DSA)]                               │
    [X25519 Derive: ss_c]                                                    │
    [ML-KEM Decap: ss_pq]                                                    │
    [Combine Secrets: Raw_SS -> Master_SS]                                   │
    [Transcript Hash 2 (SHA-384)]                                            │
    [Sign Dual: Ed25519 + ML-DSA-65]                                         │
    [Phase 3: Client Authentication]                                         │
           ├─────────────── PKT_CLIENT_AUTH (3373B) ────────────────────────>│
           │        (Ed25519_sig || MLDSA_sig)                               │ [Verify Dual Client Sig]
           │                                                                 │ [Derive Directional Keys]
    [Phase 4: Active Session]                                                │ (HKDF-SHA-384 c2s / s2c)
           │<────────────── PKT_ACK ─────────────────────────────────────────┤
           │                                                                 │
           *═══════════════ Secure AEAD Channel Established ═════════════════*
           │                                                                 │
           ├─────────────── PKT_DATA (ChaCha20-Poly1305) ───────────────────>│ [Decrypt & Route]
           │        [Nonce (12B) | Tag (16B) | Encrypted Payload]            │ (15B Header as AAD)
           │<────────────── PKT_DATA (ChaCha20-Poly1305 Echo) ───────────────┤
```

### B. Shared Secret Combiner

```text
  X25519 Shared Secret (32B)    ML-KEM-768 Shared Secret (32B)
               \                         /
                \                       /
                 v                     v
            Concatenated Raw Secret (64 Bytes)
                           │
                           ▼
             HKDF-Extract(Salt = Nonce_c || Nonce_s, IKM = Raw_SS)
                           │
                           ▼
               Master Shared Secret (48 Bytes, SHA-384)
                           │
             ┌─────────────┴─────────────┐
             ▼                           ▼
   HKDF-Expand("c2s")          HKDF-Expand("s2c")
             │                           │
             ▼                           ▼
   Client Write Key (32B)      Server Write Key (32B)
```

### C. Decoupled UNIX IPC Terminal Architecture

The server completely decouples raw UDP packet processing from user interfaces using local UNIX domain sockets:

| Socket Path | Purpose | Consuming Binary |
| :--- | :--- | :--- |
| `/tmp/hybrid_rx.sock` | Decrypted incoming telemetry, message stream, and live microsecond cryptographic metrics | `server_rx` |
| `/tmp/hybrid_tx.sock` | Operator interactive command injection channel for unicast and broadcast messaging | `server_tx` |

---

## 5. Hardware Acceleration & Multi-Device Platform Support

The hybrid suite is built from the ground up for heterogeneous multi-architecture deployments:

| Tier | Target Hardware | Compiler Flags & SIMD Acceleration | Build Target |
| :--- | :--- | :--- | :--- |
| **Tier 1: x86_64** | Modern Intel / AMD servers & workstations | `-O3 -march=native AVX2 BMI2 -flto=auto` | `make all` |
| **Tier 2: ARM64** | Raspberry Pi 4 / 5, Apple Silicon, AWS Graviton | `-O3 -march=armv8-a+crypto+simd NEON -flto=auto` | `make -f Makefile.arm64 all` |
| **Tier 3: ARM32** | Raspberry Pi 2 / 3, Embedded Cortex-A7/A53 | `-O3 -march=armv7-a -mfpu=neon-vfpv4 -mfloat-abi=hard` | `make -f Makefile.arm32 all` |

---

## 6. Exhaustive Setup & Compilation Guide

### Step 1: System Dependencies Installation

```bash
# Ubuntu / Debian:
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev liburing-dev cmake ninja-build

# Cross-compilation toolchains (optional, for cross-compiling to ARM from x86_64):
sudo apt-get install -y gcc-aarch64-linux-gnu gcc-arm-linux-gnueabihf
```

### Step 2: Compiling for x86_64 Host

```bash
cd hybrid

# Compile all binaries, library, tests, and benchmarks:
make all

# Run the 35-test automated security and regression test suite:
make test

# Clean all build artifacts:
make clean
```

### Step 3: Compiling for ARM64 (Raspberry Pi 4 / 5)

```bash
# Workflow A: Native compilation on the ARM64 device:
cd hybrid
make -f Makefile.arm64 all

# Workflow B: Cross-compilation from x86_64 host (specify target sysroot if needed):
make -f Makefile.arm64 all ARM64_SYSROOT=/path/to/sysroot
```

### Step 4: Compiling for ARM32 (Raspberry Pi 2 / 3)

```bash
# Workflow A: Native compilation on the 32-bit ARM device:
cd hybrid
make -f Makefile.arm32 all

# Workflow B: Cross-compilation from x86_64 host:
make -f Makefile.arm32 all
```

---

## 7. Dynamic Networking & Tailscale Mesh Guide

The networking layer utilizes an automatic **5-tier resolution priority chain**:
1. **Explicit CLI Target**: `./client 192.168.1.150` or `./client 100.113.83.56`
2. **Environment Variables**: `export HYBRID_SERVER_IP="100.113.83.56"`
3. **Local Discovery Files**: Automatically reads `./server_endpoint.info` or `/tmp/hybrid_server.ip`
4. **LAN UDP Auto-Discovery Probe**: Sends `PKT_DISCOVERY_PROBE` broadcast on port `9879`
5. **Localhost Fallback**: Defaults to `127.0.0.1:9879`

### Topology A: Localhost (Same Machine)
```bash
./server
./client
```

### Topology B: Local Network (LAN / Wi-Fi)
```bash
# On Server (e.g., 192.168.1.150):
./server

# On Client (Raspberry Pi or laptop on same Wi-Fi):
./client 192.168.1.150
# Or use auto-discovery:
./client_broadcast auto 100 SENSOR-NODE-01
```

### Topology C: Cross-Network Mesh via Tailscale
```bash
# On remote edge node across cellular / external network:
./client 100.113.83.56
./client_broadcast 100.113.83.56 200 REMOTE-PI-CELLULAR
```

---

## 8. Running Application Workflows

### Workflow 1: Multi-Client Server Core & Decoupled Terminals

Launch the core server engine and its decoupled terminals:

```bash
# Terminal 1: Core Engine
./server

# Terminal 2: Real-Time Ingest & Metrics Monitor
./server_rx

# Terminal 3: Operator Transmitter Console
./server_tx
```

*(Alternatively, run `./run.sh` to launch all three terminals in separate windows automatically).*

---

### Workflow 2: Interactive Secure Chat Client

Connect an interactive terminal client:

```bash
# Auto-detect local or LAN server:
./client

# Or specify server IP:
./client 192.168.1.150
```

The client performs the 4-phase mutual authentication handshake, derives directional ChaCha20-Poly1305 traffic keys, and starts an interactive chat session with the operator terminal.

---

### Workflow 3: Autonomous IoT Sensor Broadcaster (`client_broadcast`)

Simulate an autonomous embedded edge device streaming real-time telemetry (temperature, humidity, atmospheric pressure, battery voltage, 3-axis accelerometer):

```bash
# Arguments: [server_ip|auto] [interval_ms] [device_id]
./client_broadcast 127.0.0.1 100 HYBRID-IOT-01
```

**Live Streaming Output Example:**
```text
╔══════════════════════════════════════════════════════════════════════════╗
║   QRYPTONEX — Hybrid IoT Telemetry Broadcaster                           ║
║   Suite: X25519 + ML-KEM-768 + Ed25519 + ML-DSA-65 + ChaCha20-Poly1305    ║
╚══════════════════════════════════════════════════════════════════════════╝
  • Server Target   : 127.0.0.1:9879
  • Network Link    : Localhost Loopback
  • Device ID       : HYBRID-IOT-01 (Interval: 100 ms)

  [Handshake] Completed in 21.877 ms (Mutual Auth + Dual Signatures)
  [Wire Security] ChaCha20-Poly1305 15B AAD Header Binding + RFC 6479 Replay Window

[16:09:36] Connected to 127.0.0.1:9879 (Session ID: 6014d68d239dc1c6)
[16:09:36] Streaming encrypted IoT telemetry from device 'HYBRID-IOT-01'...

[16:09:36] [TX #1   ] Temp: 24.55°C | Hum: 48.0% | Bat: 3.95V | Enc:  34.6µs | RTT:  0.00ms
[16:09:36] [TX #2   ] Temp: 24.53°C | Hum: 48.1% | Bat: 3.95V | Enc:  24.5µs | RTT:  0.66ms
[16:09:36] [TX #3   ] Temp: 24.51°C | Hum: 48.1% | Bat: 3.95V | Enc:  21.8µs | RTT:  0.25ms
[16:09:36] [TX #4   ] Temp: 24.45°C | Hum: 48.1% | Bat: 3.95V | Enc:  19.8µs | RTT:  0.20ms

── Telemetry Metrics ───────────────────────────────
  Packets Received:       90
  Bytes Sent / Recv:      6113 / 6113
  Avg Round-Trip Time:    0.23 ms (min: 0.15 ms, max: 0.66 ms)
  RFC 3550 Jitter:        0.01 ms
  Avg Decrypt Duration:   18.2 µs
────────────────────────────────────────────────────
```

---

### Workflow 4: Multi-Client High-Concurrency Benchmark (`bench_nclient`)

Spawn $N$ concurrent client worker threads to benchmark handshake capacity, CPU load, and peak memory:

```bash
# 64 concurrent clients, 10 messages each:
./bench_nclient 64 10

# 128 concurrent clients, handshake only:
./bench_nclient 128 0
```

Reports wall-clock time, handshakes/second throughput, CPU utilization, peak RSS memory, and latency percentiles (min, median, p95, p99).

---

### Workflow 5: Cryptographic Microbenchmark Suite (`bench_crypto` & `bench_aead`)

```bash
# Run full cryptographic primitive benchmark (500 iterations):
./bench_crypto 500

# Run ChaCha20-Poly1305 AEAD throughput benchmark:
./bench_aead 500

# Encrypt a file using ChaCha20-Poly1305 CLI utility:
./bench_aead encrypt document.pdf document.enc

# Decrypt a file using ChaCha20-Poly1305 CLI utility:
./bench_aead decrypt document.enc document.pdf <key_hex>
```

---

## 9. Empirical Microbenchmark Results

Measured on x86_64 host (AMD Ryzen / Intel Core):

| Cryptographic Operation | Algorithm / Mechanism | Mean Latency | Throughput |
| :--- | :--- | :--- | :--- |
| **Classical Keygen** | X25519 KeyGen | $32.4\ \mu\text{s}$ | 30,864 ops/sec |
| **Post-Quantum Keygen** | ML-KEM-768 KeyGen | $48.2\ \mu\text{s}$ | 20,746 ops/sec |
| **Post-Quantum Encap** | ML-KEM-768 Encap | $56.1\ \mu\text{s}$ | 17,825 ops/sec |
| **Post-Quantum Decap** | ML-KEM-768 Decap | $49.7\ \mu\text{s}$ | 20,120 ops/sec |
| **Hybrid Key Establishment** | **X25519 + ML-KEM-768 + HKDF** | **$142.6\ \mu\text{s}$** | **7,012 ops/sec** |
| **Classical Sign** | Ed25519 Sign | $28.5\ \mu\text{s}$ | 35,087 ops/sec |
| **Classical Verify** | Ed25519 Verify | $62.1\ \mu\text{s}$ | 16,103 ops/sec |
| **Post-Quantum Sign** | ML-DSA-65 Sign | $185.3\ \mu\text{s}$ | 5,396 ops/sec |
| **Post-Quantum Verify** | ML-DSA-65 Verify | $94.2\ \mu\text{s}$ | 10,615 ops/sec |
| **Hybrid Dual Sign** | **Ed25519 + ML-DSA-65 Dual Sign** | **$214.8\ \mu\text{s}$** | **4,655 ops/sec** |
| **Hybrid Dual Verify** | **Ed25519 + ML-DSA-65 Dual Verify**| **$157.9\ \mu\text{s}$** | **6,333 ops/sec** |
| **Hash Digest** | SHA-384 (1 KB buffer) | $1.4\ \mu\text{s}$ | 714,285 ops/sec |
| **Symmetric Encryption** | ChaCha20-Poly1305 (1 KB buffer) | $0.48\ \mu\text{s}$ | **>2,050 MB/s** |

---

## 10. Automated Security & Regression Suite

The hybrid suite includes 7 specialized unit test suites (`tests/`) containing 35 comprehensive assertions:

```bash
make test
```

**Verification Results:**
```text
  [PASS] test_hybrid_kex         (8/8 assertions - Contributory, Non-Zero, Key Independence)
  [PASS] test_hybrid_signatures  (6/6 assertions - Dual Signature, Mismatch Rejection, Tampering)
  [PASS] test_hybrid_kdf         (5/5 assertions - RFC 5869 Known Answer Vectors, Directional Separation)
  [PASS] test_hybrid_handshake   (4/4 assertions - Full 4-Phase Handshake, MITM Downgrade Defense)
  [PASS] test_hybrid_session     (4/4 assertions - ChaCha20-Poly1305 AEAD, Tag Tampering, AAD Invalidation)
  [PASS] test_replay_protection  (4/4 assertions - RFC 6479 In-Window, Duplicate Drop, Window Slide)
  [PASS] test_negative_cases     (4/4 assertions - Corrupted Keys, Buffer Truncation, Null Pointers)

  Result: 35 / 35 Unit Tests PASS (100% Success Rate)
```

---

## 11. Security Model & Failure Boundaries

1. **Strict Fail-Closed Enforcement**: If an attacker tampers with either the classical or post-quantum portion of a handshake packet, the entire packet is rejected and dropped. No silent fallback to classical-only or PQC-only mode is permitted.
2. **Replay Defense (RFC 6479)**: Packets are protected by an atomic 64-packet sliding window bitmap. State updates occur strictly post-authentication.
3. **Zero Plaintext Leakage**: Decryption operations that fail Poly1305 tag verification unconditionally overwrite caller plaintext buffers with zeros before returning error code `-1`.
4. **Memory Hygiene**: Secret keys, ephemeral scalar multiples, and intermediate shared secrets are wiped using `OPENSSL_cleanse()` or `explicit_bzero()` upon context destruction.
