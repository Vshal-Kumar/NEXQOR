# 🛠️ Post-Quantum Cryptography (PQC) Framework: Command Reference & Communication Guide

This document provides a comprehensive guide to building, running, and configuring the Post-Quantum Cryptography (PQC) Framework. It details how the client-server architecture communicates across network interfaces and local Inter-Process Communication (IPC) layers.

---

## 📋 Table of Contents
1. [Prerequisites & Cross-Toolchains](#-prerequisites--cross-toolchains)
2. [Building the static `liboqs` Dependency](#1-building-the-static-liboqs-dependency)
3. [Compiling the Application Suite](#2-compiling-the-application-suite)
4. [Deploying the Multi-Client Server (Manual & Automated)](#3-deploying-the-multi-client-server)
5. [Running the Interactive Clients](#4-running-the-interactive-clients)
6. [Executing Benchmarks & Stress Tests](#5-executing-benchmarks--stress-tests)
7. [Detailed Communication Flow & Architecture](#-detailed-communication-flow--architecture)

---

## 🛠️ Prerequisites & Cross-Toolchains

### 1. Linux Host Dependencies
Ensure your development machine has the required packages installed:
```bash
sudo apt-get update
sudo apt-get install -y cmake make git pkg-config libssl-dev gcc g++
```

### 2. Building the static `liburing_local` Dependency
The multi-client server core uses Linux `io_uring` via `liburing`. If `liburing_local` is missing on your setup, you can compile and install it locally using either of the options below:

#### Option A: Build and Install Locally from Source (Recommended)
This method clones `liburing` and installs it inside the project's local `liburing_local` directory to keep the repository's Makefile working unchanged:
```bash
# 1. Clone the official liburing repository
git clone https://github.com/axboe/liburing.git

# 2. Enter the liburing directory
cd liburing

# 3. Configure with prefix pointing to the liburing_local folder inside your project
./configure --prefix=/path/to/adaptive_benchmarking/liburing_local

# 4. Compile and install locally
make -j$(nproc)
make install

# 5. Clean up the cloned repository (optional)
cd ..
rm -rf liburing
```

#### Option B: System-Wide Package (Requires Makefile modification)
Install the package via your package manager:
```bash
sudo apt-get install -y liburing-dev
```
If you choose this option, open the `Makefile` and modify lines 40-41:
```diff
-INC     = -I. -I$(LIBOQS)/include -I$(LIBURING_LOCAL)/include
-LIBS    = $(LIBOQS)/lib/liboqs.a $(LIBURING_LOCAL)/lib/liburing.a -lssl -lcrypto -lpthread -lm
+INC     = -I. -I$(LIBOQS)/include
+LIBS    = $(LIBOQS)/lib/liboqs.a -luring -lssl -lcrypto -lpthread -lm
```

### 3. Cross-Compilation Toolchains (for x86_64 host targeting ARM)
If you are compiling for Raspberry Pi or other ARM boards from an x86_64 PC, install the cross-compilers:
```bash
# Toolchain for ARM64 (AArch64)
sudo apt-get install -y gcc-aarch64-linux-gnu g++-aarch64-linux-gnu

# Toolchain for ARM32 (ARMv7-A / armhf)
sudo apt-get install -y gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf
```

---

## 1. Building the static `liboqs` Dependency

Before compiling the application executables, you must build the static `liboqs` library with target-specific hardware acceleration.

> [!WARNING]
> **Embedded ARM Resource Constraint**: When building `liboqs` natively on Raspberry Pi or other embedded boards, **do not** use high parallel job counts (like `-j$(nproc)`) as this causes compilation memory exhaustion. Use `-j2` or `-j1` instead. On x86_64 servers, `-j$(nproc)` is recommended.

### A. Building for x86_64 (AVX2 & BMI2 Acceleration)
Run this from your x86_64 host machine:
```bash
# Clone the library if not already cloned
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git liboqs

# Configure CMake
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

# Compile the library
cmake --build liboqs/build -j$(nproc)
```

### B. Building for ARM64 / AArch64 (NEON Vector Acceleration)
* **Native Build on Raspberry Pi (64-bit OS)**:
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

### C. Building for ARM32 / ARMv7-A (NEON / VFPv4 Acceleration)
* **Native Build or Cross-Compilation Setup**:
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

## 2. Compiling the Application Suite

Once the dependencies are compiled, build the suite using the target platform's Makefile.

### A. Compiling for x86_64 (Host / Server Platform)
```bash
make all -j$(nproc)
```
* **Output Binaries**: `server`, `server_rx`, `server_tx`, `client`, `bench_pqc`, `bench_nclient`, `bench_aead`

### B. Compiling for ARM64 / AArch64 (Raspberry Pi 64-bit OS)
* **Native Build**:
  ```bash
  make -f Makefile.arm64 all -j2
  ```
* **Cross-Compilation (from x86_64 host using `arm64_ref`)**:
  ```bash
  make -f Makefile.arm64 all -j$(nproc)
  ```
* **Output Binaries**: `client_arm`, `bench_pqc_arm`, `bench_nclient_arm`

### C. Compiling for ARM32 / ARMv7-A (Raspberry Pi 32-bit OS)
* **Native Build**:
  ```bash
  make -f Makefile.arm32 all -j2
  ```
* **Cross-Compilation (from x86_64 host)**:
  ```bash
  make -f Makefile.arm32 all -j$(nproc)
  ```
* **Output Binaries**: `client_arm32`, `bench_pqc_arm32`, `bench_nclient_arm32`

---

## 3. Deploying the Multi-Client Server

The server infrastructure relies on decoupling core packet routing/crypto processing from display and transmission consoles. It consists of three programs connected via local Unix IPC.

### Option 1: Automated Launch (Terminal Splitter)
This script spawns three separate terminal windows for the server core, receiver console, and sender console:
```bash
chmod +x run.sh
./run.sh
```

### Option 2: Manual Terminal Launch (Three Separate Windows)

#### 💻 Terminal 1: Main Server Relay Engine (`server`)
Runs the main UDP packet handler, cryptographic scheduler (`io_uring`), and coordinate states.
* **Basic Launch**:
  ```bash
  ./server
  ```
* **Without Rate-Limiting (Recommended for local high-throughput stress testing)**:
  ```bash
  PQC_DISABLE_RATE_LIMIT=1 ./server
  ```
* **What it does**: Binds to UDP port `9877` to listen for incoming client handshakes/data. It also sets up two local UNIX Domain sockets: `/tmp/pqc_rx.sock` (for sending plaintext messages to the receiver display) and `/tmp/pqc_tx.sock` (for receiving transmission requests from the operator console).

#### 📺 Terminal 2: Server Receiver Console (`server_rx`)
Displays real-time incoming messages and metrics.
* **Launch Command**:
  ```bash
  ./server_rx
  ```
* **What it does**: Connects to `/tmp/pqc_rx.sock`. When the `server` decrypts messages from clients, it pushes plaintext messages, client metadata, and cryptographic/network telemetry (latency, jitter, RTT) to `server_rx` to render in styled CLI blocks.

#### ⌨️ Terminal 3: Server Sender Console (`server_tx`)
Allows the operator to type and send messages to connected clients.
* **Launch Command**:
  ```bash
  ./server_tx
  ```
* **What it does**: Connects to `/tmp/pqc_tx.sock`. It receives client status updates from the `server` to display a live list of connected clients (with statistics). The operator selects a client ID (or `0` for broadcasting to all clients) and types a message, which is securely serialized and sent through the IPC socket to the `server` for outbound encryption and transmission.

---

## 4. Running the Interactive Clients

Clients run interactively to establish post-quantum secure connections to the running server.

```bash
# On x86_64:
./client <SERVER_IP>

# On ARM64 (Raspberry Pi 64-bit OS):
./client_arm <SERVER_IP>

# On ARM32 (Raspberry Pi 32-bit OS):
./client_arm32 <SERVER_IP>
```
* *Example*: `./client 192.168.1.50`
* **What it does**: Launches the chat client, initiates the 4-way post-quantum handshake with the server at `<SERVER_IP>` on UDP port `9877`, derives cryptographic session keys, spins up a background thread to listen for server messages, and opens an interactive console (`Pi > `) allowing the user to type messages.

---

## 5. Executing Benchmarks & Stress Tests

The benchmark executables measure performance metrics across cryptographic primitives, concurrent load, and payload sizes.

### A. Standalone Cryptographic Operations Benchmark (`bench_pqc`)
Measures execution latencies for public-key keypairs, encapsulation, decapsulation, signatures, and verification.
```bash
./bench_pqc [rounds]       # x86_64
./bench_pqc_arm [rounds]   # ARM64
./bench_pqc_arm32 [rounds] # ARM32
```
* *Example (1,000 runs)*: `./bench_pqc 1000`
* **What it does**: Runs ML-KEM-768 and ML-DSA-65 algorithms iteratively. It prints detailed statistical telemetry (mean, median, standard deviation, P95/P99 latency, confidence interval) and CPU performance results.

### B. High-Concurrency Handshake Benchmark (`bench_nclient`)
Evaluates the server's stress capacity under simultaneous connections.
```bash
./bench_nclient [num_clients] [num_messages] [server_ip]       # x86_64
./bench_nclient_arm [num_clients] [num_messages] [server_ip]   # ARM64
./bench_nclient_arm32 [num_clients] [num_messages] [server_ip] # ARM32
```
* *Example (128 concurrent clients sending 10 messages each)*: `./bench_nclient 128 10 127.0.0.1`
* **What it does**: Spawns `N` concurrent client threads which initiate PQC handshakes simultaneously. Once the handshakes finish, threads send `M` encrypted messages to evaluate the server's throughput capacity, packet processing performance, and hardware resources (CPU, RAM).

### C. AEAD Performance & File Utility (`bench_aead`)
Symmetric cryptoprimitive microbenchmark and file encryption tool.
* **1. Microbenchmark Mode**:
  ```bash
  ./bench_aead [rounds]
  ```
  * **What it does**: Benchmarks ChaCha20-Poly1305 performance across various payload sizes (64B, 256B, 1KB, 4KB, 16KB) and prints throughput in MB/s.
* **2. Encrypt File**:
  ```bash
  ./bench_aead encrypt <input_file> <output_file> [key_hex]
  ```
  * **What it does**: Encrypts `<input_file>` with ChaCha20-Poly1305 and writes output containing the `[Nonce (12B) | Tag (16B) | Ciphertext]` to `<output_file>`. If no `key_hex` is provided, a random 256-bit key is generated and printed.
* **3. Decrypt File**:
  ```bash
  ./bench_aead decrypt <input_file> <output_file> <key_hex>
  ```
  * **What it does**: Authenticates and decrypts an encrypted `<input_file>` using the provided `<key_hex>` key, writing the plaintext output to `<output_file>`.

---

## 🔒 Detailed Communication Flow & Architecture

### 1. Network Communications (Client ↔ Server)
The network protocol is designed to operate over **UDP port 9877**.

#### The 4-Way Post-Quantum Handshake:
```
Client                                                         Server (Core)
  │                                                                 │
  ├─────────────── PKT_CLIENT_HELLO ───────────────────────────────>│ [1. Parse & Queue]
  │               (KEM_PK_c || DSA_PK_c || Nonce_c)                 │
  │                                                                 │ [2. KEM Encap]
  │                                                                 │ [3. ML-DSA Sign]
  │<────────────── PKT_SERVER_HELLO ────────────────────────────────┤
  │               (DSA_PK_s || KEM_CT || Session_ID ||              │
  │                Nonce_s || Signature_s)                          │
  │                                                                 │
  │ [4. Verify Server Signature]                                    │
  │ [5. Decapsulate Session Key]                                    │
  │ [6. ML-DSA Sign Transcript]                                     │
  │                                                                 │
  ├─────────────── PKT_CLIENT_AUTH ────────────────────────────────>│
  │               (Signature_c)                                     │
  │                                                                 │ [7. Verify Client Sig]
  │                                                                 │ [8. Derive Session Key]
  │<────────────── PKT_ACK ─────────────────────────────────────────┤
  │                                                                 │
  *═══════════════ Session Established (AEAD Active) ═══════════════*
```
1. **PKT_CLIENT_HELLO (Phase 1)**: Client sends its ML-KEM public key, ML-DSA public key, and a 16-byte random nonce.
2. **PKT_SERVER_HELLO (Phase 2)**: Server responds with its ML-DSA public key, the encapsulation ciphertext of the session key, a session ID, a server nonce, and a transcript signature signed with the server's long-term ML-DSA key.
3. **PKT_CLIENT_AUTH (Phase 3)**: Client decapsulates the KEM ciphertext to extract the shared secret, verifies the server's signature, signs the transcript, and sends its signature to the server.
4. **Active Session (Phase 4)**: Server verifies the client's signature. Both derive the final symmetric session key using a SHAKE256 KDF. Communication switches to secure symmetric AEAD packets (`PKT_DATA`) consisting of `[Nonce(12B) | Tag(16B) | Ciphertext]`.

### 2. Local Inter-Process Communications (Server Side IPC)
On the server host, the core `server` process interacts with the console programs using **Unix Domain Sockets**:

```
                  +-----------------------------------+
                  |           Remote Client           |
                  +-----------------+-----------------+
                                    |
                          UDP Port 9877 (Network)
                                    |
                                    v
                  +-----------------+-----------------+
                  |       Server Relay Engine         |
                  |            (server)               |
                  +--------+-----------------+--------+
                           |                 ^
      UNIX Domain Socket   |                 |   UNIX Domain Socket
     (/tmp/pqc_rx.sock)    |                 |  (/tmp/pqc_tx.sock)
                           v                 |
             +-------------+----+      +-----+------------+
             | Receiver Terminal|      |  Sender Terminal |
             |   (server_rx)    |      |    (server_tx)   |
             +------------------+      +------------------+
```

* **`/tmp/pqc_rx.sock` (Server ──► `server_rx`)**:
  * **Type**: `SOCK_STREAM` Unix Domain Socket.
  * **Direction**: Unidirectional (Server writes, `server_rx` reads).
  * **Frame Payload**:
    * `IPC_MSG_RX` (`0x01`): Plainsent message contents to display.
    * `IPC_METRICS_RX` (`0x06`): Per-packet local decryption time and network jitter metrics.
    * `IPC_CLIENT_CONNECT` (`0x04`): Signals when a client has completed the handshake.
    * `IPC_CLIENT_DISCONNECT` (`0x05`): Signals when a client is disconnected.

* **`/tmp/pqc_tx.sock` (`server_tx` ──► Server)**:
  * **Type**: `SOCK_STREAM` Unix Domain Socket.
  * **Direction**: Bidirectional.
  * **Frame Payload (Outbound)**:
    * `IPC_MSG_TX_CMD` (`0x02`): Written by `server_tx` containing the target client ID (or 0 for broadcast) and message plaintext to transmit.
  * **Frame Payload (Inbound)**:
    * `IPC_CLIENT_LIST` (`0x03`): Pushed by server to sync client connection lists and display metrics.
    * `IPC_METRICS_TX` (`0x07`): Local metrics for sent messages (encryption cost, retransmission count, byte tally).
