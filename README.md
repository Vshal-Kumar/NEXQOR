# QRYPTONEX (NEXQOR) — Multi-Suite Cryptographic Communication Framework

[![Build & Test Status](https://img.shields.io/badge/Build%20%26%20Test-Passing%20(All%20Suites)-success.svg)](#build-testing-and-validation)
[![Cryptographic Suites](https://img.shields.io/badge/Suites-Classical%20%7C%20Hybrid%20%7C%20PQC-blue.svg)](#cryptographic-specification-comparison)
[![Hardware Acceleration](https://img.shields.io/badge/Hardware-AVX2%20%7C%20ARM%20NEON%20%7C%20io__uring-orange.svg)](#hardware-acceleration--platform-support)
[![Formal Verification](https://img.shields.io/badge/Verification-ProVerif%202.05%20Verified-blueviolet.svg)](#formal-security-verification)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**QRYPTONEX** is an ultra-high-performance, modular secure network protocol and cryptographic communication framework engineered for Linux x86-64 servers and embedded ARM IoT platforms (such as Raspberry Pi 4 and 5). 

The repository provides three completely **independent, self-contained, and production-grade implementations**:
1. **Classical IoT Suite (`classical/`)**: Optimized for resource-constrained IoT microcontrollers and legacy environments using RFC 7748 X25519, RFC 8032 Ed25519, and AES-128-CCM.
2. **Hybrid Post-Quantum Suite (`hybrid/`)**: Dual-combiner defense-in-depth architecture combining classical and post-quantum primitives (X25519 + ML-KEM-768 and Ed25519 + ML-DSA-65) to protect against *Harvest Now, Decrypt Later* attacks while maintaining classical compliance.
3. **Pure Post-Quantum Suite (`pqc/`)**: High-security, SIMD-accelerated FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65) implementation with ChaCha20-Poly1305 session encryption.

Each implementation is decoupled with its own build systems, cryptographic state machine, automated regression tests, multi-client event-loop server, and N-run benchmarking engine with dynamic hardware thermal and memory monitoring.

---

## 🚀 Standalone Releases & Debian Packages

NEXQOR / SecureComm is distributed as pre-compiled standalone Debian (`.deb`) packages for Intel/AMD PCs, Raspberry Pi 4/5, and embedded ARM microcomputers, as well as a pure-C source tree buildable with standard GNU tools.

### 📦 Pre-Built Debian Packages (`.deb`)

For quick installation on any Debian or Ubuntu system without manual compilation:

| Target Architecture | Debian Architecture | Target Devices | Package File | Direct Download Link | Local Install Command |
| :--- | :---: | :--- | :---: | :---: | :--- |
| **x86-64 / AMD64 (`x86`)** | `amd64` | Intel/AMD PCs, Laptops, Cloud Servers | `nexqor-x86.deb` | [📥 Download `nexqor-x86.deb`](https://drive.google.com/uc?export=download&id=1wKZ5hrTjgId0uJUwz5kTT9iVX_G_KwtT) | `sudo dpkg -i nexqor-x86.deb` |
| **ARM64 / AArch64 (`arm64`)** | `arm64` | Raspberry Pi 4/5, Jetson, 64-bit ARM Linux | `nexqor-arm64.deb` | [📥 Download `nexqor-arm64.deb`](https://drive.google.com/uc?export=download&id=1kTHy9Kl_Ur6_HlXYya-e9ztAmg2Z94vJ) | `sudo dpkg -i nexqor-arm64.deb` |
| **ARM32 / ARMv7 (`arm32`)** | `armhf` | Raspberry Pi 2/3, 32-bit Raspbian/Debian | `nexqor-arm32.deb` | [📥 Download `nexqor-arm32.deb`](https://drive.google.com/uc?export=download&id=1lT-iFzbxwV6QLHamfSOMpTLUEq2velVb) | `sudo dpkg -i nexqor-arm32.deb` |

Each package installs:
- Executable binaries: `/usr/bin/nexqor`, `/usr/bin/securecomm`, and `/usr/bin/nexqor-<arch>`
- Hardened systemd services: `/usr/lib/systemd/system/nexqor.service` and `securecomm.service`
- Default configuration template: `/etc/securecomm/securecomm.json`
- Documentation & changelogs: `/usr/share/doc/nexqor-<arch>/`

#### Quickstart: Server & Client Setup (Default: `100.113.83.56:9877`)

> **IMPORTANT REQUIREMENT**: After installing the `.deb` package or building from source, **run `nexqor setup` once** on each machine. The setup wizard benchmarks your CPU, generates your unique cryptographic keypair with `0600` permissions in `~/.config/securecomm/`, and registers trusted endpoints.

**1. On Server Machine (`100.113.83.56`):**
```bash
# Install package:
sudo dpkg -i nexqor-x86.deb || sudo apt-get install -f -y

# Run initial setup (select Role 1: Server, default port 9877):
nexqor setup

# Start the server backend:
nexqor server start

# Or launch with the GTK4 Pure C NOC Dashboard:
./run_ui.sh
```

**2. On Client Machine (Second PC, Kali Linux, or Raspberry Pi):**
```bash
# Install package for your architecture:
sudo dpkg -i nexqor-x86.deb     # for Intel/AMD laptops & Kali VM
sudo dpkg -i nexqor-arm64.deb   # for Raspberry Pi 4/5

# Run initial setup (select Role 2: Client, target server 100.113.83.56:9877):
nexqor setup

# Connect immediately in real-time interactive chat:
nexqor client connect

# Or send a single message from terminal:
nexqor client connect --msg "Hello Quantum Server!"
```

**Real-Time Two-Way Chat & Dashboard Synchronization:**
- **Client Terminal**: Incoming server commands display immediately (`[SERVER → YOU] <msg>`), while user input is logged with encryption details (`[YOU → SERVER] <msg> (Encrypted: X bytes)`).
- **GTK4 Dashboard**: Displays `CONNECTED CLIENTS (ACTIVE)` with IP, port, session ID, and handshake latency in real time. When a client disconnects, it gracefully moves to `DISCONNECTED SESSIONS (RECENT)` at the bottom of the list.

*Note on Key Permissions*: Cryptographic identity keys are automatically stored in `~/.config/securecomm/` with strict `0600` permissions for unprivileged users, completely preventing any "permission denied" errors.

> For deep architectural specifications, configuration schemas, and operational instructions, see [securecomm/README.md](file:///home/vishal-kumar/Desktop/Events/QHack/securecomm/README.md).

---

## Table of Contents

- [Project Architecture & Organization](#project-architecture--organization)
- [Cryptographic Specification Comparison](#cryptographic-specification-comparison)
- [Performance & Hardware Monitoring Engine](#performance--hardware-monitoring-engine)
- [Shared Dependencies](#shared-dependencies)
- [Build Instructions](#build-instructions)
  - [Global Makefile Dispatcher](#global-makefile-dispatcher)
  - [Individual Suite Compilation](#individual-suite-compilation)
  - [Cross-Compilation for ARM64 & ARM32](#cross-compilation-for-arm64--arm32)
- [Execution & Operation](#execution--operation)
  - [Multi-Client Server Deployment](#multi-client-server-deployment)
  - [Interactive Client & Telemetry Broadcaster](#interactive-client--telemetry-broadcaster)
- [Benchmarking & Empirical Evaluation](#benchmarking--empirical-evaluation)
  - [Microbenchmark Engine (N Runs)](#microbenchmark-engine-n-runs)
  - [Concurrent Multi-Client Handshake Benchmark](#concurrent-multi-client-handshake-benchmark)
- [Formal Security Verification](#formal-security-verification)
- [Repository Maintenance & Hygiene](#repository-maintenance--hygiene)

---

## Project Architecture & Organization

The repository strictly enforces modular separation. Shared external dependencies (`liboqs`, `liburing_local`) are maintained at the root without redundant in-tree copies:

```
QRYPTONEX/
├── Makefile                     # Global dispatcher (build, test, clean, UI targets)
├── README.md                    # Global architectural & operational documentation
├── app.sh                       # Unified single-command launcher for both GTK 4 UIs
├── run_ui.sh                    # Launcher for Server NOC & Telemetry Console
├── run_attack_ui.sh             # Launcher for Security & Attack Lab UI
├── .gitignore                   # Universal exclusion rule-set (binaries, objects, keys, logs)
├── LICENSE                      # MIT Open Source License
├── liboqs/                      # Shared Open Quantum Safe library (git submodule)
├── liburing_local/              # Shared Linux io_uring kernel headers
│
├── ui/                          # GTK 4 Cryptographic Server NOC & Session Inspector
│   ├── ui_app.c / ui_app.h      # Graphical server dashboard and client session registry
│   ├── ipc_manager.c / .h       # UNIX domain socket IPC listener and client telemetry
│   ├── style.css                # Cyber-Dark theme for Server NOC Console
│   └── Makefile                 # Native GTK 4 build system
│
├── security_lab/                # Pure-C Real-Network Security Evaluation & Threat Lab
│   ├── security_lab             # Main CLI security evaluation engine binary
│   ├── Makefile                 # Modular build system (engine, tests, ui)
│   ├── ui/                      # GTK 4 Security & Attack Lab Interface (attack_ui)
│   │   ├── attack_ui.c / .h     # Graphical threat vector & evaluation controller
│   │   ├── style.css            # Dark cyber theme with status badges
│   │   └── Makefile             # Pure-C GTK 4 attack UI build system
│   ├── attacks/                 # 15 attack & impairment implementations (loss, replay, fuzzing, etc.)
│   ├── src/                     # Test orchestration, safety guard allowlists, suite adapters
│   ├── monitoring/              # Packet observer, health probes, resource and recovery monitors
│   ├── reporting/               # Comparison reports (report.md, metrics.csv, JSON audits)
│   ├── tests/                   # Automated safety, bounds parsing, and metric unit tests
│   └── results/                 # Timestamped run directories and latest symlink
│
├── classical/                   # 100% Independent Classical IoT Suite
│   ├── crypto/                  # AES-128-CCM AEAD, sliding replay window, trust store
│   ├── wrappers/                # X25519, Ed25519, SHA-256, HKDF-SHA-256, HMAC-SHA-256
│   ├── tests/                   # 22-test automated regression & security test suite
│   ├── verification/            # ProVerif 2.05 formal verification protocol model
│   ├── perf_monitor.h           # Thermal, memory, CPU, and statistical metrics engine
│   ├── server.c                 # High-throughput Linux io_uring UDP server (port 9877)
│   ├── client.c                 # Interactive mutual-auth terminal client
│   ├── client_broadcast.c       # Autonomous IoT telemetry sensor broadcaster
│   ├── bench_crypto.c           # Cryptographic microbenchmark suite (N runs)
│   ├── bench_nclient.c          # Multi-client concurrent handshake benchmark
│   ├── Makefile                 # Native x86_64 build system
│   ├── Makefile.arm64           # ARM64 (Raspberry Pi 4/5) build system
│   └── Makefile.arm32           # ARMv7-A 32-bit build system
│
├── hybrid/                      # 100% Independent Hybrid Post-Quantum Suite
│   ├── include/                 # Hybrid KEX, Dual-Signature, and KDF definitions
│   ├── src/                     # Hybrid combiners, error handling, session state
│   ├── crypto/                  # ChaCha20-Poly1305 AEAD, replay window, trust store
│   ├── wrappers/                # ML-KEM and ML-DSA wrapper bindings
│   ├── tests/                   # 7 automated regression test suites
│   ├── perf_monitor.h           # Thermal, memory, CPU, and statistical metrics engine
│   ├── server.c                 # High-throughput Linux UDP event loop server (port 9879)
│   ├── client.c                 # Hybrid interactive mutual-auth terminal client
│   ├── client_broadcast.c       # Autonomous hybrid telemetry broadcaster
│   ├── bench_crypto.c           # Hybrid microbenchmark suite (N runs)
│   ├── bench_nclient.c          # Multi-client concurrent handshake benchmark
│   ├── Makefile                 # Native x86_64 build system
│   ├── Makefile.arm64           # ARM64 build system
│   └── Makefile.arm32           # ARM32 build system
│
└── pqc/                         # 100% Independent Pure Post-Quantum Suite
    ├── crypto/                  # ChaCha20-Poly1305 AEAD, replay window, trust store
    ├── wrappers/                # ML-KEM-768, ML-DSA-65, SHAKE256 wrappers
    ├── tests/                   # 8 automated security and KAT test suites
    ├── verification/            # ProVerif 2.05 formal model for pure PQC
    ├── perf_monitor.h           # Thermal, memory, CPU, and statistical metrics engine
    ├── server.c                 # High-throughput Linux io_uring UDP server (port 9877)
    ├── client.c                 # PQC interactive mutual-auth terminal client
    ├── client_broadcast.c       # Autonomous PQC telemetry broadcaster
    ├── bench_pqc.c              # Pure PQC microbenchmark suite (N runs)
    ├── bench_nclient.c          # Multi-client concurrent handshake benchmark
    ├── Makefile                 # Native x86_64 build system
    ├── Makefile.arm64           # ARM64 build system
    └── Makefile.arm32           # ARM32 build system
```

---

## Cryptographic Specification Comparison

| Property | Classical IoT (`classical/`) | Hybrid Suite (`hybrid/`) | Pure PQC (`pqc/`) |
| :--- | :--- | :--- | :--- |
| **Suite Identifier** | `QRYPTONEX-CLASSICAL-X25519-ED25519-AES128CCM` | `QRYPTONEX-HYBRID-X25519-MLKEM768-ED25519-MLDSA65` | `NEXQOR-PQC-MLKEM768-MLDSA65-CHACHA20` |
| **Key Exchange (KEX)** | X25519 (ECDH, RFC 7748) | X25519 + ML-KEM-768 (Dual Combiner) | ML-KEM-768 (NIST FIPS 203) |
| **Digital Signatures** | Ed25519 (RFC 8032) | Ed25519 + ML-DSA-65 (Dual Signature) | ML-DSA-65 (NIST FIPS 204) |
| **Session Encryption** | AES-128-CCM (15B AAD, 16B Tag) | ChaCha20-Poly1305 (RFC 8439) | ChaCha20-Poly1305 (RFC 8439) |
| **Key Derivation (KDF)** | HKDF-SHA-256 (RFC 5869) | HKDF-SHA-384 (RFC 5869) | SHAKE-256 (NIST FIPS 202) |
| **Transcript Hashing** | SHA-256 (FIPS 180-4) | SHA-384 (FIPS 180-4) | SHAKE-256 (FIPS 202) |
| **Replay Protection** | RFC 6479 64-Packet Sliding Window | RFC 6479 64-Packet Sliding Window | RFC 6479 64-Packet Sliding Window |
| **Public Key Size** | 32 B (KEX) + 32 B (Sig) = **64 B** | 1,216 B (KEX) + 1,984 B (Sig) = **3,200 B** | 1,184 B (KEM) + 1,952 B (DSA) = **3,136 B** |
| **Secret Key Size** | 32 B (KEX) + 32 B (Sig) = **64 B** | 2,432 B (KEX) + 4,064 B (Sig) = **6,496 B** | 2,400 B (KEM) + 4,032 B (DSA) = **6,432 B** |
| **Ciphertext Size** | 32 B (Ephemeral PK) | 1,120 B (X25519 + ML-KEM CT) | 1,088 B (ML-KEM-768 CT) |
| **Signature Size** | **64 Bytes** | **3,380 Bytes** (64B + 3,309B + Frame) | **3,309 Bytes** |
| **Shared Secret Size**| **32 Bytes** | **64 Bytes** (Concatenated IKM) | **32 Bytes** |
| **Handshake Wire Size**| **464 Bytes** (Total 4 packets) | **15,280 Bytes** (Dual-auth 4-way) | **11,828 Bytes** (Dual-auth 4-way) |
| **Quantum Resistance**| Vulnerable to Shor's Algorithm | Quantum-Proof + Classical Compliant | Quantum-Proof (NIST Level 3 / 192-bit) |

---

## Performance & Hardware Monitoring Engine

All three implementations integrate a unified, zero-overhead hardware and process telemetry engine (`perf_monitor.h`). **Measured metrics are obtained dynamically from the Linux kernel and hardware sensors with zero hardcoding or simulated data:**

### 1. Dynamic Hardware Temperature Monitoring
- Continuously probes kernel sysfs sensor interfaces:
  - `/sys/class/thermal/thermal_zone0/temp` through `thermal_zone4/temp`
  - `/sys/class/hwmon/hwmon*/temp*_input`
- Reports:
  - Initial System Temperature (°C)
  - Average System Temperature (°C)
  - Minimum & Maximum System Temperature (°C)
  - Final System Temperature (°C)
  - Temperature Delta during execution (°C)
- If sensors are unavailable (e.g. non-privileged container or virtual machine), the system explicitly reports `Unavailable (No sysfs thermal sensor)` without fabricating measurements.

### 2. Comprehensive Memory Metrics
- **Initial, Average, Peak, and Final RAM (MB)**: Obtained via `/proc/self/statm` and `getrusage(RUSAGE_SELF, &ru)`.
- **RAM Increase (MB)**: Delta between final and initial resident set size.
- **Heap Memory (MB)**: Exact dynamic heap allocations measured via glibc `mallinfo2()`.
- **Stack Memory (KB)**: Measured kernel stack allocation via `/proc/self/status` `VmStk`.
- **Leak Detection**: Verifies zero memory leakage and clean buffer zeroization (`explicit_bzero`).

### 3. CPU Utilization & Cycle Metrics
- **Process CPU Time (ms)**: Nanosecond-accurate execution time via `clock_gettime(CLOCK_PROCESS_CPUTIME_ID)`.
- **Average & Peak CPU Utilization (%)**: Computed dynamically against wall clock time.
- **CPU Cycles per Operation**: Direct hardware counter via `__rdtsc` on x86-64 and `CNTVCT_EL0` on ARM64.

### 4. Statistical Distribution Across N Runs
- Benchmark runs execute across configurable $N$ runs (default 5).
- Per-run progress is logged in real time with individual run metrics.
- Complete statistical distribution calculated over all completed runs:
  - **Mean, Minimum, Maximum, Median, Standard Deviation, Variance, P95 Latency, and Throughput (ops/sec)**.

---

## Shared Dependencies

The framework relies on standard Linux system libraries:
- **GCC / Clang**: C11 compliant compiler.
- **OpenSSL 3.x (`libssl-dev`, `libcrypto`)**: AES-128-CCM, ChaCha20-Poly1305, X25519, Ed25519, SHA-256, SHA-384, HKDF.
- **liboqs (Open Quantum Safe)**: Used by `pqc/` and `hybrid/` for ML-KEM-768 and ML-DSA-65.
- **liburing (`liburing-local/` or system `liburing`)**: Used for the Linux asynchronous event loop.

### Building `liboqs` (One-Time Setup)
```bash
# From repository root:
cmake -S liboqs -B liboqs/build \
      -DCMAKE_BUILD_TYPE=Release \
      -DOQS_BUILD_ONLY_LIB=ON \
      -DOQS_ENABLE_KEM_ml_kem_768=ON \
      -DOQS_ENABLE_SIG_ml_dsa_65=ON \
      -DOQS_USE_AVX2_INSTRUCTIONS=ON \
      -DBUILD_SHARED_LIBS=OFF

cmake --build liboqs/build -j$(nproc)
```

---

## Build Instructions

### Global Makefile with Hardware Architecture Detection

The root [Makefile](file:///home/vishal-kumar/Desktop/Events/QHack/Makefile) automatically detects the host device CPU architecture (`uname -m`) and dispatches the build to the appropriate sub-Makefiles across **Classical**, **Hybrid**, and **Pure PQC**:

| Host Device / CPU | Detected Platform | Automatically Dispatched Makefiles |
| :--- | :--- | :--- |
| **x86_64 / amd64** (Linux Server, Desktop, Laptop) | `x86_64` | `classical/Makefile`, `hybrid/Makefile`, `pqc/Makefile` |
| **ARM64 / aarch64** (Raspberry Pi 4, Raspberry Pi 5, 64-bit ARM) | `arm64` | `classical/Makefile.arm64`, `hybrid/Makefile.arm64`, `pqc/Makefile.arm64` |
| **ARM32 / armv7l / armhf** (Raspberry Pi 2, Raspberry Pi 3 32-bit) | `arm32` | `classical/Makefile.arm32`, `hybrid/Makefile.arm32`, `pqc/Makefile.arm32` |

#### Standard Commands from Project Root

```bash
# 1. Automatic device detection & build for all 3 suites:
make
# or
make all

# 2. Inspect detected hardware and active Makefile mapping:
make detect

# 3. Run automated regression & security test suites across all 3 implementations:
make test

# 4. Clean build artifacts for the active/detected device architecture:
make clean

# 5. Deep clean across ALL architectures (x86_64, ARM64, ARM32) in all 3 implementations:
make clean-all
```

#### Explicit Target Architecture Overrides & Cross-Compilation

You can explicitly build or clean for a specific target architecture on any host machine:

```bash
# Build all 3 suites for ARM64 (using Makefile.arm64):
make arm64
# or: make ARCH=arm64 all

# Build all 3 suites for ARM32 (using Makefile.arm32):
make arm32
# or: make ARCH=arm32 all

# Build all 3 suites for x86_64:
make x86_64
# or: make ARCH=x86_64 all

# Clean specific architectures across all 3 suites:
make clean-arm64       # Clean ARM64 binaries and objects
make clean-arm32       # Clean ARM32 binaries and objects
make clean-x86_64      # Clean x86_64 binaries and objects
```

#### Target-Specific Suite Dispatching

```bash
make classical         # Build classical IoT suite for detected device
make hybrid            # Build hybrid suite for detected device
make pqc               # Build PQC suite for detected device

make test-classical    # Run 22-test classical regression suite
make test-hybrid       # Run 7-suite hybrid regression test
make test-pqc          # Run 8-test PQC security suite
```

### Individual Suite Compilation

Each directory can be built independently:

```bash
# Classical IoT Suite:
cd classical
make clean && make all
make test

# Hybrid Suite:
cd hybrid
make clean && make all
make test

# Pure PQC Suite:
cd pqc
make clean && make all
make test
```

### Native ARM Compilation on Raspberry Pi 4 / 5

When running directly on ARM hardware (e.g., Raspberry Pi 4, Raspberry Pi 5 running 64-bit Linux), running `make` from the project root automatically selects `Makefile.arm64` across all suites:

```bash
# Automatically detects aarch64 and builds ARM64 binaries:
make all

# Run client binaries with automatic symlinks:
./classical/client 127.0.0.1 9877
./hybrid/client 127.0.0.1 9879
./pqc/client 127.0.0.1 9876
```

---

## Execution & Operation

### Multi-Client Server Deployment

Each suite provides a dedicated multi-client UDP server utilizing `io_uring` and dedicated worker thread pools:

| Implementation | Default Port | Default Server Identity Key |
| :--- | :--- | :--- |
| **Classical Server** | `9877` | `classical/server_identity.pub` (32 B Ed25519) |
| **Hybrid Server** | `9879` | `hybrid/server_identity.pub` (1,984 B Dual) |
| **PQC Server** | `9876` | `pqc/server_identity.pub` (1,952 B ML-DSA-65) |

To launch the servers:
```bash
# Terminal 1 (Classical Server):
cd classical && ./server

# Terminal 1 (Hybrid Server):
cd hybrid && ./server

# Terminal 1 (PQC Server):
cd pqc && ./server
```

Upon startup, servers dynamically publish IP endpoints, scan hardware sensors, and display initial thermal/memory state:
```
╔══════════════════════════════════════════════════════════╗
║   QRYPTONEX Secure Server Core ─ Classical IoT Suite     ║
║   Architecture: Linux io_uring + Multi-Worker Pool       ║
║   Suite: X25519 + Ed25519 + AES-128-CCM + SHA-256        ║
╚══════════════════════════════════════════════════════════╝
[server] Ed25519 Server Identity Public Key Loaded (32 bytes)
[server] Active Endpoints:
  • Localhost : 127.0.0.1:9877
  • LAN / Wi-Fi: 192.168.1.100:9877
[server] io_uring Event Loop Running. Ready for clients.
```

### Interactive Client & Telemetry Broadcaster

In separate terminals, start clients:
```bash
# Interactive mutual-auth terminal client:
./client 127.0.0.1 9877

# Autonomous telemetry broadcaster (transmits periodic encrypted sensor datagrams):
./client_broadcast 127.0.0.1 9877 100 500  # 100 packets, 500ms interval
```

---

## Benchmarking & Empirical Evaluation

### Unified Comparative Benchmark Program (`bench_pqc` / `benchpqc`)

A master comparative benchmarking program is located in the root folder: **`bench_pqc`** (aliased as **`benchpqc`**). Running this single executable benchmarks **all three cryptographic suites** under identical environmental conditions and generates an empirical side-by-side evaluation across six master analytical tables.

```bash
# Execute master comparison (default: 50 rounds, 3 runs):
./benchpqc
# or
./bench_pqc
# or via Makefile
make bench

# Specify custom rounds per run and number of runs:
./benchpqc 100 5

# Verbose mode (displays intermediate sub-suite runs):
./benchpqc 50 3 -v
```

#### Comprehensive Evaluation Tables Generated:
1. **Table I: Cryptographic Operations Latency Comparison (`µs`)**  
   Measures and compares execution latencies across all 9 primitive operations (Keygen, Encaps/Decaps, Sign/Verify, Symmetric Encrypt/Decrypt, Session Key Derivation, Handshake Transcript Hashing). Highlights the fastest approach and speedup factor for each operation.
2. **Table II: Cryptographic Operations Throughput Comparison (`ops/s`)**  
   Evaluates sustainable computational throughput and operations per second across identical CPU cores.
3. **Table III: Cryptographic Artifact & Network Wire Overhead (`bytes`)**  
   Quantifies public keys, private keys, ciphertexts, signatures, and complete 4-way mutual authentication handshake sizes, calculating exact network bandwidth multiplier overhead.
4. **Table IV: Hardware Resources & Environmental Telemetry**  
   Reads real Linux kernel statistics and hardware sensors: Process Resident Set Size (RSS), Heap allocation via `mallinfo2`, Process Stack usage, CPU core utilization, total CPU time, CPU cycles/op, and system thermal sensor temperatures (`°C`).
5. **Table V: Security Posture, Cryptanalysis & NIST Standardization Matrix**  
   Contrasts post-quantum resilience, classic vs quantum security bits, Harvest-Now-Decrypt-Later (HNDL) risk, and NIST FIPS 203/204 standardization status.
6. **Table VI: Architectural Synthesis & Trade-Off Verdict**  
   Provides system engineering conclusions, compute-vs-wire trade-off analysis, and targeted deployment recommendations (constrained IoT vs gateway hub vs secure cloud).

---

### Per-Suite Microbenchmark Engine (N Runs)

Microbenchmarks measure cryptographic operations, system memory, CPU utilization, and real-time sensor temperature across $N$ runs:

```bash
# Syntax: ./<benchmark_binary> [rounds_per_run] [number_of_runs]

# Run Classical Microbenchmark (100 rounds across 5 runs):
./classical/bench_crypto 100 5

# Run Hybrid Microbenchmark (100 rounds across 5 runs):
./hybrid/bench_crypto 100 5

# Run PQC Microbenchmark (100 rounds across 5 runs):
./pqc/bench_pqc 100 5
```

#### Sample Benchmark Output
```
╔══════════════════════════════════════════════════════════════════════════════════╗
║ QRYPTONEX CLASSICAL IOT SUITE: N-RUN BENCHMARK (X25519 + Ed25519 + AES-128-CCM) ║
╚══════════════════════════════════════════════════════════════════════════════════╝
  Benchmark Setup: 100 rounds per run across 5 completed runs
  Hardware Sensor: /sys/class/thermal/thermal_zone0/temp (acpitz) — Initial Temp: 58.00 °C
  Initial Process RAM: 7.406 MB | Heap: 0.492 MB

┌──────┬──────────────────┬─────────────────┬─────────────────┬────────────────────┐
│ Run  │ Exec Time (ms)   │ Temperature (°C)│ RAM Usage (MB)  │ CPU Utilization (%)│
├──────┼──────────────────┼─────────────────┼─────────────────┼────────────────────┤
│    1 │          34.1205 │        58.00 °C │           7.410 │             99.95% │
│    2 │          33.9852 │        58.00 °C │           7.410 │             99.94% │
│    3 │          34.0118 │        58.00 °C │           7.410 │             99.96% │
│    4 │          34.2051 │        59.00 °C │           7.410 │             99.95% │
│    5 │          33.9510 │        59.00 °C │           7.410 │             99.97% │
└──────┴──────────────────┴─────────────────┴─────────────────┴────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────────┐
│ 1. CRYPTOGRAPHIC METRICS: X25519 Key Generation (RFC 7748)                       │
├────────────────────────────────────────┬─────────────────────────────────────────┤
│ Metric                                 │ Value                                   │
├────────────────────────────────────────┼─────────────────────────────────────────┤
│ Average Execution Time                 │             0.0215 ms                 │
│ Minimum Execution Time                 │             0.0201 ms                 │
│ Maximum Execution Time                 │             0.0384 ms                 │
│ Median Execution Time                  │             0.0211 ms                 │
│ Standard Deviation                     │             0.0018 ms                 │
│ P95 Latency                            │             0.0242 ms                 │
│ Throughput                             │           46511.63 ops/sec            │
│ Public Key Size                        │                 32 bytes              │
│ Private Key Size                       │                 32 bytes              │
└────────────────────────────────────────┴─────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────────┐
│ 2. MEMORY METRICS                                                                │
├────────────────────────────────────────┬─────────────────────────────────────────┤
│ Metric                                 │ Value                                   │
├────────────────────────────────────────┼─────────────────────────────────────────┤
│ Initial RAM Usage                      │             7.4062 MB                 │
│ Average RAM Usage                      │             7.4095 MB                 │
│ Peak RAM Usage                         │             7.4102 MB                 │
│ Final RAM Usage                        │             7.4102 MB                 │
│ RAM Increase                           │             0.0039 MB                 │
│ Heap Memory Usage                      │             0.4922 MB                 │
│ Stack Memory Usage                     │             136.00 KB                 │
│ Memory Allocation Count                │   Tracked via libc mallinfo             │
│ Memory Leaks Detected                  │                  0 (Clean zeroization)  │
└────────────────────────────────────────┴─────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────────┐
│ 3. CPU METRICS                                                                   │
├────────────────────────────────────────┬─────────────────────────────────────────┤
│ Metric                                 │ Value                                   │
├────────────────────────────────────────┼─────────────────────────────────────────┤
│ Average CPU Utilization                │             99.95 %                   │
│ Peak CPU Utilization                   │             99.97 %                   │
│ Total CPU Time                         │           170.2736 ms                 │
│ CPU Cycles per Operation               │           145820.3 cycles/op          │
└────────────────────────────────────────┴─────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────────┐
│ 4. TEMPERATURE MONITORING METRICS                                                │
├────────────────────────────────────────┬─────────────────────────────────────────┤
│ Metric                                 │ Value                                   │
├────────────────────────────────────────┼─────────────────────────────────────────┤
│ Hardware Sensor Interface              │ /sys/class/thermal/thermal_zone0/temp   │
│ Sensor Classification                  │ acpitz                                  │
│ Initial System Temperature             │             58.00 °C                 │
│ Average System Temperature             │             58.40 °C                 │
│ Minimum System Temperature             │             58.00 °C                 │
│ Maximum System Temperature             │             59.00 °C                 │
│ Final System Temperature               │             59.00 °C                 │
│ Temperature Delta (Final - Initial)    │             +1.00 °C                 │
└────────────────────────────────────────┴─────────────────────────────────────────┘
```

### Concurrent Multi-Client Handshake Benchmark

Tests simultaneous handshake concurrency against an active server:

```bash
# Syntax: ./<bench_nclient> [num_clients] [messages_per_client]

# Example: 64 concurrent clients connecting to classical server:
./classical/bench_nclient 64 10

# Example: 64 concurrent clients connecting to hybrid server:
./hybrid/bench_nclient 64 10

# Example: 64 concurrent clients connecting to PQC server:
./pqc/bench_nclient 64 10
```

---

## Dual-Console GTK 4 Graphical Interface & app.sh

QRYPTONEX features two native, pure-C **GTK 4 graphical consoles** (zero web wrappers or electron bloat) styled in a sleek, high-contrast **Cyber-Dark Theme**:

| Console Interface | Binary Path | Purpose & Visual Architecture |
| :--- | :--- | :--- |
| **Console 1: Server NOC Dashboard** | `ui/qhack_ui` | Real-time cryptographic server control, client session registry, bidirectional IPC terminal, and deep cryptographic parameter inspector (live KEM/DSA key fingerprints, shared secrets, wire handshake latency). |
| **Console 2: Security & Attack Lab** | `security_lab/ui/attack_ui` | Interactive threat injector featuring target IP/port inputs, crypto suite selector (Classical, Hybrid, PQC, or All), 15 threat scenarios with plain-English explanations, live matrix-green terminal console on pitch black (`#000000`), smooth independent scrolling, **Abort Attack** process cancellation, live PASS/FAIL resilience cards, and one-click **Executive PDF Report** viewer. |

### Running Both UIs Simultaneously (`app.sh`)

To launch both interfaces side-by-side with automatic dependency verification, subproject compilation, and synchronized cleanup:

```bash
# Unified dual launcher:
./app.sh

# Or via make target:
make app
```

*Pressing `Ctrl+C` in the launcher terminal cleanly terminates both GTK 4 applications and clears runtime locks.*

### Running Interfaces Individually

```bash
# Launch only Server NOC Console:
./run_ui.sh          # or: make run-ui

# Launch only Security & Attack Lab:
./run_attack_ui.sh   # or: make run-attack-ui
```

---

## Real-Network Security Evaluation & Threat Injection Lab (`security_lab`)

The `security_lab/` framework is a pure-C security testing and resilience evaluation engine that subjects running client and server implementations to real network impairments and active cryptographic threat vectors:

### 15 Implemented Threat & Impairment Vectors:
1. **[BASE] Normal Baseline Operation:** Measures clean round-trip latency, baseline throughput, and delivery rate under optimal network conditions.
2. **[LOSS] Packet Drop Resilience:** Simulates 15% deterministic network loss to test client retransmission and state preservation.
3. **[JITR] Delay & Variable Jitter:** Injects 30ms ± 15ms packet transit delays to test timeout handling and timestamp validation.
4. **[RORD] Out-of-Order Delivery:** Shuffles delivery sequence to test reordering buffers and sliding sequence windows.
5. **[DUPL] Packet Duplication Injection:** Duplicates valid datagrams in-transit to test anti-replay window suppression.
6. **[DISC] Temporary Link Drop:** Drops all packets for 2 seconds to verify session heartbeat recovery and re-handshake triggers.
7. **[PMTU] Path MTU Exceeded:** Tests transmission across MTU boundary limits from 512B to 4096B to check fragmentation handling.
8. **[RPLY] Anti-Replay Counter Attack:** Deliberately injects duplicate sequence numbers, stale counters, and cross-session replays.
9. **[TAMP] Ciphertext Bit-Flip Attack:** Modifies encrypted payload bits and MAC tags in-transit to verify AEAD tamper detection.
10. **[AUTH] Invalid Identity Attack:** Injects forged digital signatures and unrecognized public keys to test peer authentication rejection.
11. **[HSHK] Out-of-Order Handshake:** Transmits handshake phases in reverse or incomplete sequence to test state-machine bounds checking.
12. **[FUZZ] Malformed Frame Fuzzing:** Floods the socket with truncated headers, invalid wire IDs, and pseudo-random fuzz payloads.
13. **[STRS] Resource Queue Saturation:** Launches 16 parallel handshake requests simultaneously to evaluate server worker pool queue handling.
14. **[ISOL] Cross-Session Injection:** Replays valid session packets into a neighboring client's socket to verify session cryptographic isolation.
15. **[ALL] Full Suite Evaluation:** Sequentially executes all 14 scenarios across all 3 cryptographic implementations (Classical, Hybrid, PQC).

### Running Security Tests via CLI:
```bash
# Run baseline against running PQC server:
./security_lab/security_lab --suite pqc --scenario baseline --target 127.0.0.1

# Run replay protection test against hybrid implementation:
./security_lab/security_lab --suite hybrid --scenario replay --target 127.0.0.1

# Run complete comparative security matrix across all 3 suites:
./security_lab/security_lab --suite all --scenario all --target 127.0.0.1
```

### Automated Executive PDF & Audit Reports

All evaluation runs generate structured audit artifacts stored in `security_lab/results/latest/`:
- **`report.pdf`**: Formatted Executive PDF Report complete with system details, executive summary, comprehensive scenario verdicts, and formal security conclusions. Compiled automatically via `generate_pdf.py` and openable directly via the GTK 4 UI (`View PDF Report` button).
- **`report.md`**: Clean GitHub-flavored markdown report with structured scenario comparison tables and cryptographic status.
- **`metrics.csv`**: Granular numerical log containing per-scenario latency, packet loss, delivery percentage, and heap usage.
- **`scenario_results.json`**: Machine-readable JSON schema for CI/CD automated ingestion.
- **`audit.log`**: Nanosecond-timestamped protocol event log.

---

## Formal Security Verification


Both the **Classical** and **Post-Quantum** protocols have been formally modeled and verified in **ProVerif 2.05**:
- Classical Model: `classical/verification/protocol.pv`
- PQC Model: `pqc/verification/protocol.pv`

### Proverif Verification Queries
| Security Property | Query | Verification Result |
| :--- | :--- | :--- |
| **Server Secrecy** | `query secret server_secret` | **RESULT: TRUE** (Protected) |
| **Client Secrecy** | `query secret client_secret` | **RESULT: TRUE** (Protected) |
| **Mutual Authentication (Client -> Server)** | `event(client_accepts(srv_pk, sid)) ==> event(server_auth(srv_pk, sid))` | **RESULT: TRUE** (Injective Match) |
| **Mutual Authentication (Server -> Client)** | `event(server_accepts(cli_pk, sid)) ==> event(client_auth(cli_pk, sid))` | **RESULT: TRUE** (Injective Match) |
| **Perfect Forward Secrecy (PFS)** | Secrecy of past traffic under identity compromise | **RESULT: TRUE** (Proved) |
| **Replay & Injection Resistance** | Monotonic session counter and sliding replay window | **RESULT: TRUE** (Proved) |

To run the formal verification models:
```bash
proverif classical/verification/protocol.pv
proverif pqc/verification/protocol.pv
```

---

## Repository Maintenance & Hygiene

- **Root-Only Git Tracking**: The repository root contains the sole `.git` directory.
- **Strict Hygiene**: No compiled binaries, static libraries (`*.a`), object files (`*.o`), or cryptographic keys (`*.key`, `*.pub`) are tracked in version control.
- **Self-Contained Subprojects**: Each of `classical/`, `hybrid/`, and `pqc/` can be moved or distributed independently while relying only on system OpenSSL and root shared libraries.

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
