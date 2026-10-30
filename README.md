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

## 🚀 Architecture, Device Roles & Pre-Built Releases

QRYPTONEX is engineered for a **heterogeneous computing hierarchy**, with explicit device roles:
- **x86-64 Computers (Intel/AMD Laptops, PCs, Linux/Kali VMs, Cloud Servers)**: Can operate as the **Central Server** (with the GTK4 Cyber NOC Dashboard or headless daemon) OR as an **Interactive Client**.
- **ARM Edge Devices (Raspberry Pi 4/5, Raspberry Pi 2/3, Jetson)**: Operate as **Clients Only**, establishing quantum-resilient sessions and streaming encrypted telemetry.
- **ESP32 Microcontrollers (Xtensa 32-bit)**: Operate as **Clients Only**, executing lightweight NIST FIPS 203 ML-KEM-768 encapsulation and streaming encrypted sensor telemetry.

---

### 📦 Pre-Built Debian Packages & Download Links

| Target Architecture | Device Role | Target Devices | Package File | Direct Download Command | Local Install Command |
| :--- | :---: | :--- | :---: | :---: | :--- |
| **x86-64 / AMD64 (`x86`)** | **Server OR Client** | Intel/AMD PCs, Laptops, Kali Linux VMs | `nexqor-x86.deb` | `curl -L -o nexqor-x86.deb "https://drive.usercontent.google.com/download?id=1Kp-LRUkX2-ra9BqeGgGNoStBQC0gEe6c&export=download&confirm=t"` | `sudo dpkg -i nexqor-x86.deb` |
| **ARM64 / AArch64 (`arm64`)** | **Client Only** | Raspberry Pi 4, Raspberry Pi 5, Jetson | `nexqor-arm64.deb` | `curl -L -o nexqor-arm64.deb "https://drive.usercontent.google.com/download?id=1mDMPsDRaBOvR4NARQBOwmLk8cvAospoa&export=download&confirm=t"` | `sudo dpkg -i nexqor-arm64.deb` |
| **ARM32 / ARMv7 (`arm32`)** | **Client Only** | Raspberry Pi 2, Raspberry Pi 3 (32-bit OS) | `nexqor-arm32.deb` | `curl -L -o nexqor-arm32.deb "https://drive.usercontent.google.com/download?id=1xbI0-2Lw9pQnIAlgdcxGHfOql6hZIADS&export=download&confirm=t"` | `sudo dpkg -i nexqor-arm32.deb` |
| **ESP32 (Xtensa)** | **Client Only** | ESP32 DevKit, NodeMCU-32S, ESP32-WROOM | `esp32_secure_node.ino` | *Flash via Arduino IDE from `esp32/`* | *See [ESP32 Setup Guide](esp32/README.md)* |

---

### 🛠️ Step-by-Step Setup Guides for All Device Types

#### 1. Device Tier 1: x86-64 Laptop / PC / Cloud Server (SERVER or CLIENT)

An x86-64 machine can act as the **Central Server Relay** or as an **Interactive Client**:

```bash
# Step 1: Download package:
curl -L -o nexqor-x86.deb "https://drive.usercontent.google.com/download?id=1Kp-LRUkX2-ra9BqeGgGNoStBQC0gEe6c&export=download&confirm=t"

# Step 2: Install package:
sudo dpkg -i nexqor-x86.deb || sudo apt-get install -f -y

# Step 3: Run Setup Wizard once:
nexqor setup
```

- **If setting up as SERVER**:
  1. Select **Role**: `1) Server`
  2. Select **Crypto Mode**: `4) Adaptive` (or `3) PQC`)
  3. Bind Address: `0.0.0.0` | Port: `9877`
  4. Launch the server via CLI or GTK4 Cyber NOC Dashboard:
     ```bash
     # Option A: GTK4 Pure C Cyber NOC Dashboard (Recommended):
     ./run_ui.sh
     # Click '▶ Start Server' on the top bar!

     # Option B: Headless background server:
     nexqor server start
     ```
  5. The server/dashboard automatically detects and displays your active IP addresses (e.g., Wi-Fi: `10.58.4.191:9877`, Tailscale: `100.113.83.56:9877`).

- **If setting up as CLIENT** (e.g. second laptop, Kali VM, or another terminal):
  1. Select **Role**: `2) Client`
  2. Target Server IP: Enter Server Wi-Fi IP (e.g. `10.58.4.191`) or Tailscale IP (`100.113.83.56`)
  3. Target Port: `9877`
  4. Connect in real-time interactive chat:
     ```bash
     nexqor client connect
     ```

---

#### 2. Device Tier 2: Raspberry Pi 4 / 5 (ARM64 — CLIENT ONLY)

Raspberry Pi 4 and 5 run the ARM64 NEON-vectorized client:

```bash
# Step 1: Navigate to workspace:
cd ~/Desktop/Nexqor

# Step 2: Download genuine ARM64 package:
curl -L -o nexqor-arm64.deb "https://drive.usercontent.google.com/download?id=1mDMPsDRaBOvR4NARQBOwmLk8cvAospoa&export=download&confirm=t"

# Step 3: Install package:
sudo dpkg -i nexqor-arm64.deb || sudo apt-get install -f -y

# Step 4: Run initial setup (select Role 2: Client):
nexqor setup
```
- In `nexqor setup`:
  - **Role**: Select `2) Client`
  - **Server IP**: Enter Server Wi-Fi IP (e.g. `10.58.4.191`) or Tailscale IP (`100.113.83.56`)
  - **Port**: Press `[Enter]` (default `9877`)

```bash
# Step 5: Connect to the Server:
nexqor client connect

# Or send automated non-interactive telemetry message:
nexqor client connect --msg "Raspberry Pi 4 online with ML-KEM-768!"
```

---

#### 3. Device Tier 3: Raspberry Pi 2 / 3 (ARM32 — CLIENT ONLY)

For Raspberry Pi 2, 3, or any single-board computer running 32-bit ARM Linux (`armhf`):

```bash
cd ~/Desktop/Nexqor

# Step 1: Download ARM32 package:
curl -L -o nexqor-arm32.deb "https://drive.usercontent.google.com/download?id=1xbI0-2Lw9pQnIAlgdcxGHfOql6hZIADS&export=download&confirm=t"

# Step 2: Install package:
sudo dpkg -i nexqor-arm32.deb || sudo apt-get install -f -y

# Step 3: Configure as Client:
nexqor setup   # Select Role: 2 Client, Target Server IP: 10.58.4.191

# Step 4: Connect:
nexqor client connect
```

---

#### 4. Device Tier 4: ESP32 Microcontroller (CLIENT ONLY)

The ESP32 runs lightweight pure post-quantum lattice key encapsulation (NIST FIPS 203 ML-KEM-768) and ChaCha20-Poly1305 symmetric AEAD, connecting directly to the x86 Server over UDP:

1. Open Arduino IDE and install ESP32 Board Support:
   ```text
   https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
   ```
2. Open `esp32/esp32_secure_node/esp32_secure_node.ino`.
3. Configure your Wi-Fi credentials and the Server's dynamic Wi-Fi IP (shown in the GTK4 Server Dashboard header):
   ```cpp
   const char* WIFI_SSID     = "Your_WiFi_Name";
   const char* WIFI_PASSWORD = "Your_WiFi_Password";
   const char* SERVER_IP     = "10.58.4.191";  // Dynamic Server IP shown on Dashboard
   const uint16_t SERVER_PORT= 9877;
   ```
4. Select Board **`ESP32 Dev Module`**, choose your serial port (`/dev/ttyUSB0`), and click **Upload**.
5. Open Serial Monitor at **115200 baud**:
   - The ESP32 connects to Wi-Fi, initiates the quantum-safe handshake with the Server, and streams encrypted sensor telemetry every 2 seconds.
   - **Actuation Demo**: Type `LED_ON` or `LED_OFF` in the GTK4 Server Dashboard chat bar to toggle the ESP32's onboard blue LED (GPIO 2) in real time!
   - Full details in [esp32/README.md](esp32/README.md).

---

### 🌐 Real-Time Chat & Dashboard Synchronization

- **Server Dashboard (`./run_ui.sh`)**: Displays `CONNECTED CLIENTS (ACTIVE)` with Client ID, remote IP, UDP port, session ID, and handshake setup latency (typically 1.6–2.1 ms).
- **Inactivity Watchdog**: If a client goes silent for >10 seconds or issues a graceful disconnect (`PKT_DISCONNECT`), it immediately transitions to `DISCONNECTED SESSIONS (RECENT)`.
- **Dynamic Endpoint Auto-Refresh**: If your Wi-Fi IP changes, the dashboard top bar and connection instructions refresh automatically within 1 second.
- **Strict Key Security**: Cryptographic identity keys are generated in `~/.config/securecomm/` with strict `0600` permissions.

> For deep architectural specifications, configuration schemas, and operational instructions, see [securecomm/README.md](securecomm/README.md).

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

QRYPTONEX features two native, pure-C **GTK 4 graphical consoles** (zero web wrappers or electron bloat) styled in a sleek, high-contrast **Cyber NOC Theme**:

| Console Interface | Binary Path | Purpose & Visual Architecture |
| :--- | :--- | :--- |
| **Console 1: Server NOC Dashboard** | `ui/qhack_ui` | High-visibility Cyber NOC dashboard featuring: <br>• **Manual Start/Stop Server Button**: Operator controls server launch (`▶ Start Server` / `⏹ Stop Server`) with PID and UDP port 9877 management.<br>• **Dynamic Multi-Interface IP Discovery**: Real-time auto-discovery of active Wi-Fi (`wl*`), Ethernet (`en*`/`eth*`), and VPN interfaces via `getifaddrs`, with dynamic connection snippets and 1-second auto-refresh.<br>• **Upside Performance & Telemetry**: Live CPU, RAM, cryptographic handshake timings (KEM/DSA keygen, encapsulation, signing, verification), transit jitter, and interarrival latency placed prominently above details.<br>• **Downside Cryptographic Inspector**: Deep session inspector showing active session IDs, directional 256-bit keys (`C2S`/`S2C`), wire fingerprints, and RFC 6479 64-packet replay window.<br>• **10-Second Disconnect Watchdog**: Real-time heartbeat tracking instantly moves timed-out or disconnected clients to `DISCONNECTED SESSIONS (RECENT)`.<br>• **Clean Suite Switching**: Effortlessly transition between Pure PQC, Hybrid, and Classical IoT suites with automatic port and socket cleanup. |
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
