# QRYPTONEX — Post-Quantum Secure Networking Framework

[![Language: C11](https://img.shields.io/badge/Language-C11-00599C.svg?logo=c&logoColor=white)](https://en.wikipedia.org/wiki/C11_(C_standard_revision))
[![Architecture: Heterogeneous](https://img.shields.io/badge/Architecture-x86__64%20%7C%20ARM64%20%7C%20ARM32-blue.svg)](https://arm.com)
[![KEM: ML-KEM-768](https://img.shields.io/badge/NIST%20FIPS%20203-ML--KEM--768%20(Kyber768)-orange.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![DSA: ML-DSA-65](https://img.shields.io/badge/NIST%20FIPS%20204-ML--DSA--65%20(Dilithium3)-red.svg)](https://csrc.nist.gov/pubs/fips/204/final)
[![AEAD: ChaCha20-Poly1305](https://img.shields.io/badge/AEAD-ChaCha20--Poly1305%20(RFC%208439)-brightgreen.svg)](https://datatracker.ietf.org/doc/html/rfc8439)
[![Verification: ProVerif](https://img.shields.io/badge/Formally%20Verified-ProVerif%20(21%20Proofs)-purple.svg)](https://proverif.inria.fr/)
[![Server Engine: io_uring](https://img.shields.io/badge/Async%20I%2FO-Linux%20io__uring-black.svg)](https://kernel.dk/io_uring.pdf)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A high-performance, SIMD-accelerated **Post-Quantum Cryptographic (PQC) networking framework**, asynchronous multi-client server, and formal verification suite in C11.

QRYPTONEX secures communications between high-throughput **x86_64 servers** (vectorized via **AVX2 / BMI2**) and resource-constrained **ARM edge devices** (Raspberry Pi 4/5 via **ARM64 NEON** and Raspberry Pi 2/3 via **ARM32 NEON / VFPv4**), achieving **sub-millisecond serial PQC handshakes** resistant to quantum cryptanalysis (Shor's and Grover's algorithms).

---

## ⚡ 30-Second Quick Start

```bash
# 1. Install dependencies
sudo apt-get update && sudo apt-get install -y build-essential cmake git pkg-config libssl-dev liburing-dev

# 2. Build binaries & run automated security tests
make all -j$(nproc)
make test

# 3. Start the server (publishes active endpoints on port 9877)
./server

# 4. In a separate terminal, launch the chat client (auto-discovers server!)
./client
```

---

## 📋 Table of Contents

1. [Key Features](#-key-features)
2. [Cryptographic Specifications](#-cryptographic-specifications)
3. [Building the Project](#-building-the-project)
4. [Testing & Verification](#-testing--verification)
5. [Operational Usage Guide](#-operational-usage-guide)
   - [A. Running the Multi-Client Server](#a-running-the-multi-client-server)
   - [B. Running the Interactive Secure Chat Client](#b-running-the-interactive-secure-chat-client)
   - [C. Running Continuous IoT Sensor Broadcaster](#c-running-continuous-iot-sensor-broadcaster)
   - [D. Running Concurrent Handshake Benchmark](#d-running-concurrent-handshake-benchmark)
   - [E. AEAD File Encryption & Symmetric Microbenchmark](#e-aead-file-encryption--symmetric-microbenchmark)
6. [Dynamic Networking & Tailscale Mesh](#-dynamic-networking--tailscale-mesh)
7. [Empirical Performance Benchmarks](#-empirical-performance-benchmarks)
8. [Repository Structure](#-repository-structure)
9. [License & Citation](#-license--citation)

---

## 🌟 Key Features

- **NIST FIPS Standard Compliance**: Built on NIST-standardized lattice cryptography — **ML-KEM-768** (FIPS 203) for key encapsulation and **ML-DSA-65** (FIPS 204) for digital signatures.
- **Zero Hardcoded IPs & Dynamic Auto-Discovery**: Automatic server endpoint discovery via LAN UDP broadcast probes, system files, environment variables, or Tailscale Mesh VPN. No code edits needed when changing networks.
- **SIMD Hardware Acceleration**: Tailored vector extensions utilizing **256-bit AVX2/BMI2** on x86_64 and **128-bit NEON / VFPv4** on ARM architectures.
- **Asynchronous Linux `io_uring` Core**: Core server uses the Linux `io_uring` ring for zero-copy packet batching, lock-free SPMC/MPSC worker thread dispatching, and handling up to 4,096 concurrent clients.
- **Formally Verified Security**: Modeled in Applied Pi-Calculus with **ProVerif** — mathematically proving 21 distinct security properties including **Mutual Authentication**, **Perfect Forward Secrecy (PFS)**, and **Replay Resistance**.
- **Decoupled Operator Consoles**: Clean POSIX UNIX domain socket architecture (`/tmp/pqc_rx.sock`, `/tmp/pqc_tx.sock`) separating real-time network processing from terminal rendering.

---

## 🔒 Cryptographic Specifications

| Component | Scheme / Standard | Security Level | Key / Signature Sizes | Function |
| :--- | :--- | :--- | :--- | :--- |
| **Key Encapsulation (KEM)** | **ML-KEM-768** (NIST FIPS 203) | Level 3 (~AES-192) | **PK**: 1,184 B \| **CT**: 1,088 B \| **SS**: 32 B | Ephemeral session key exchange |
| **Digital Signatures (DSA)** | **ML-DSA-65** (NIST FIPS 204) | Level 3 (~AES-192) | **PK**: 1,952 B \| **Sig**: 3,309 B | Mutual identity authentication |
| **Symmetric AEAD** | **ChaCha20-Poly1305** (RFC 8439) | 256-bit Key | **Key**: 32 B \| **Nonce**: 12 B \| **Tag**: 16 B | Authenticated message encryption (wire header bound as AAD) |
| **Key Derivation (KDF)** | **SHAKE256** (NIST FIPS 202) | Extendable Output | **Digest**: 64 B | Transcript binding & directional key separation (`tx_key` vs `rx_key`) |

---

## 🏗️ Building the Project

### Prerequisites

```bash
# Ubuntu / Debian / Raspberry Pi OS:
sudo apt-get update
sudo apt-get install -y build-essential cmake git pkg-config libssl-dev liburing-dev
```

*(Optional cross-compilers on x86 host targeting ARM):*
```bash
sudo apt-get install -y gcc-aarch64-linux-gnu gcc-arm-linux-gnueabihf
```

---

### Compiling Binaries

#### 1. Native Build for x86_64 (Linux Server / Host)
```bash
# Compiles server, server_rx, server_tx, client, client_broadcast, bench_pqc, bench_nclient, bench_aead
make all -j$(nproc)
```

#### 2. Native Build on Raspberry Pi 4 / 5 (ARM64 / AArch64)
```bash
# Use -j2 on Raspberry Pi to avoid exhausting RAM:
make -f Makefile.arm64 all -j2
```
*Generated ARM64 targets*: `client_arm`, `client_broadcast_arm`, `bench_pqc_arm`, `bench_nclient_arm`.

#### 3. Native Build on Raspberry Pi 2 / 3 (ARM32 / ARMv7-A)
```bash
make -f Makefile.arm32 all -j2
```
*Generated ARM32 targets*: `client_arm32`, `client_broadcast_arm32`, `bench_pqc_arm32`, `bench_nclient_arm32`.

---

## 🧪 Testing & Verification

### 1. Automated Security & Cryptographic Regression Test Suite
The repository includes an 8-suite automated unit and security test harness verifying the cryptographic primitives, directional KDF, sliding replay window, AEAD AAD header tamper rejection, peer identity trust store, packet fragmentation reassembly, and multi-session isolation:

```bash
make test
```

**Output:**
```text
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

Test Results: 8/8 passed (0 failed)
ALL SECURITY & REGRESSION TESTS PASSED SUCCESSFULLY!
```

### 2. Formal Security Verification with ProVerif
Verify the mathematical proofs of the 4-way mutual handshake protocol:

```bash
# Install ProVerif
sudo apt-get install -y proverif

# Run mathematical verification
proverif verification/protocol.pv
```
*Proves 21 distinct security properties including Secrecy of Session Keys, Mutual Authentication, Perfect Forward Secrecy (PFS), Replay Protection, and Transcript Binding.*

---

## 🚀 Operational Usage Guide

### A. Running the Multi-Client Server

Start the core server daemon:
```bash
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

*(Optional decoupled consoles)*:
- **Receiver Console Display**: `./server_rx`
- **Transmitter Console**: `./server_tx`
- **Or launch all 3 terminals automatically**: `./run.sh`

---

### B. Running the Interactive Secure Chat Client

Connect to the server from an x86 PC or Raspberry Pi with a clean terminal interface. **No IP address is needed for local/LAN connections** — the client discovers the server dynamically!

```bash
# On x86_64:
./client                  # Auto-discovers server
./client <SERVER_IP>      # Explicit IP, hostname, or Tailscale address

# On Raspberry Pi (ARM64):
./client_arm              # Auto-discovers server
./client_arm <SERVER_IP>

# On Raspberry Pi (ARM32):
./client_arm32            # Auto-discovers server
./client_arm32 <SERVER_IP>
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

### C. Running Continuous IoT Sensor Broadcaster (`client_broadcast`)

Simulates an embedded IoT sensor node (e.g., Raspberry Pi, ESP32 gateway) that establishes a post-quantum session and continuously broadcasts encrypted sensor telemetry (temperature, humidity, barometric pressure, battery voltage):

```bash
# Syntax: ./client_broadcast [server_ip] [interval_ms] [device_id]

# Auto-discovery mode (defaults to 500ms interval, ESP32-NODE-01):
./client_broadcast

# Custom rate and device tag:
./client_broadcast auto 200 "LAB-ENVIRONMENT-SENSOR"

# On Raspberry Pi across Tailscale:
./client_broadcast_arm 100.104.77.63 100 "PI-FIELD-NODE"
```

**Telemetry Output Stream:**
```text
  Server target : 10.58.3.114:9877
[18:31:49] Connected to 10.58.3.114:9877 (Session ID: d20fec5a0f374489)
[18:31:49] Broadcasting telemetry from device 'ESP32-NODE-01' (interval: 500ms)...
[18:31:49] #1     | Temp: 25.6°C | Hum: 55.0% | Press: 1013.3hPa | Vbat: 4.12V | Status: OK  
[18:31:50] #2     | Temp: 25.5°C | Hum: 55.1% | Press: 1013.3hPa | Vbat: 4.12V | Status: OK  
[18:31:50] #3     | Temp: 25.5°C | Hum: 55.1% | Press: 1013.3hPa | Vbat: 4.12V | Status: OK  
```

---

### D. Running Concurrent Handshake Benchmark (`bench_nclient`)

Simulates $N$ concurrent client threads performing simultaneous post-quantum handshakes and streaming encrypted messages to evaluate server throughput, jitter, and resource usage:

```bash
# Syntax: ./bench_nclient [num_clients] [num_messages] [server_ip (optional)]

# 64 concurrent clients with auto-discovery:
./bench_nclient 64 10

# 256 clients across Tailscale:
./bench_nclient 256 5 100.104.77.63

# On Raspberry Pi (ARM64):
./bench_nclient_arm 32 10
```

---

### E. AEAD File Encryption & Symmetric Microbenchmark (`bench_aead`)

```bash
# 1. Benchmark ChaCha20-Poly1305 throughput across payload sizes (64B to 16KB):
./bench_aead 1000

# 2. Encrypt a file (generates random 256-bit key if omitted):
./bench_aead encrypt document.pdf document.pdf.enc

# 3. Decrypt the encrypted file:
./bench_aead decrypt document.pdf.enc decrypted_document.pdf <KEY_HEX>
```

---

## 🌐 Dynamic Networking & Tailscale Mesh

The transport layer resolves server addresses dynamically through a 5-tier resolution chain:
1. **CLI Argument** (IPv4, Hostname, or Tailscale MagicDNS name).
2. **Environment Variable** (`PQC_SERVER_IP="100.x.y.z"`).
3. **Local Discovery Files** (`/tmp/nexqor_server.ip` and `./server_endpoint.info`).
4. **LAN UDP Broadcast Probe** (`PKT_DISCOVERY_PROBE` on port 9877).
5. **Loopback Fallback** (`127.0.0.1:9877`).

### Cross-Network Connection via Tailscale (Bypasses NAT & Firewalls)

For devices on separate networks (e.g., Server at home/office, Client on 4G/5G mobile hotspot or remote Wi-Fi):

1. **Install Tailscale on both machines**: `curl -fsSL https://tailscale.com/install.sh | sh`
2. **Connect**: `sudo tailscale up`
3. **Run Server**: `./server` (identifies and displays Tailscale IP `100.x.y.z`).
4. **Connect Client**: `./client_arm <TAILSCALE_SERVER_IP>`

*(For in-depth networking architecture, discovery internals, and firewall settings, see [NETWORKING_GUIDE.md](NETWORKING_GUIDE.md)).*

---

## 📊 Empirical Performance Benchmarks

Measured on physical hardware using high-resolution monotonic timestamps (`clock_gettime(CLOCK_MONOTONIC)`):

### Cryptographic Operation Latency

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

| Concurrent Clients ($N$) | Total Handshake Time | Success Rate | Peak Server CPU | Memory Usage |
| :---: | :---: | :---: | :---: | :---: |
| **10** | 12.8 ms | 100.0% | 4.2% | ~14 MB |
| **50** | 46.1 ms | 100.0% | 12.8% | ~18 MB |
| **100** | 89.4 ms | 100.0% | 24.1% | ~22 MB |
| **500** | 412.3 ms | 100.0% | 58.7% | ~46 MB |
| **1,000** | 845.6 ms | 100.0% | 88.3% | ~78 MB |

---

## 📁 Repository Structure

```text
.
├── crypto/
│   ├── aead.c / .h                 # ChaCha20-Poly1305 AEAD with AAD wire header binding
│   ├── replay_window.c / .h        # 64-packet bitmap sliding replay window (RFC 6479)
│   └── trust_store.c / .h          # Pinned peer identity key store and verification (TOFU)
├── wrappers/
│   ├── kem_wrapper.c / .h          # ML-KEM-768 wrappers & directional SHAKE256 KDF
│   └── dsa_wrapper.c / .h          # ML-DSA-65 digital signature C wrappers
├── tests/
│   └── test_suite.c                # 8-suite automated cryptographic and security regression test
├── verification/
│   ├── protocol.pv                 # Formal security verification model in Applied Pi-Calculus
│   └── README.md                   # ProVerif execution guide and proof breakdown
├── client.c                        # Interactive PQC chat client (clean UI, auto-discovery)
├── client_broadcast.c              # Autonomous IoT sensor telemetry broadcaster
├── server.c                        # Asynchronous io_uring multi-client server
├── server_rx.c / server_tx.c       # Decoupled server operator console interfaces
├── transport.c / .h                # Dynamic discovery, packet framing, AAD AEAD, ACKs
├── bench_pqc.c                     # Standalone cryptographic primitives microbenchmark
├── bench_nclient.c                 # Multi-client concurrent stress-test harness
├── bench_aead.c                    # AEAD buffer benchmark & file encryption tool
├── Makefile                        # Native build system for x86_64 host
├── Makefile.arm64                  # Build system for ARM64 (Raspberry Pi 4/5)
├── Makefile.arm32                  # Build system for ARM32 (Raspberry Pi 2/3)
├── NETWORKING_GUIDE.md             # Dedicated guide for dynamic discovery & Tailscale setup
├── commands.md                     # Detailed command reference and cheatsheet
└── README.md                       # Main project documentation
```

---

## 📄 License & Citation

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for complete details.

```bibtex
@misc{pqc_cross_platform_evaluation_2026,
  author = {Vishal Kumar},
  title = {Cross-Platform Evaluation of Scalable Post-Quantum Secure Communication},
  year = {2026},
  publisher = {GitHub},
  howpublished = {\url{https://github.com/Vshal-Kumar/PQC}}
}
```
