# SecureComm: Production Operations & Architectural Manual
## Lightweight, Adaptive, Cross-Platform Secure Communication Framework

SecureComm is a production-grade, standard C11 secure communication framework designed for embedded IoT systems, edge gateways, and Linux servers. It provides a unified command-line application (`securecomm` or `nexqor`) supporting **Classical**, **Pure Post-Quantum (PQC)**, **Hybrid**, and **Adaptive** operating modes over high-throughput, low-latency UDP transport.

---

## ⚡ Quickstart: Step-by-Step Server & Client Deployment

Default Network Setup: **Server listens on `0.0.0.0:9877` | Target Server Address: `100.113.83.56:9877` (UDP)**

> **CRITICAL REQUIREMENT**: After installing the package or building from source, **you MUST run `nexqor setup` once** on each node before starting or connecting. The setup wizard benchmarks your CPU, selects optimal post-quantum cryptographic profiles, generates your unique cryptographic keypair with `0600` permissions in `~/.config/securecomm/`, and registers trusted endpoints.

---

### 🖥️ Server Machine (Host Laptop / Cloud Server at `100.113.83.56`)

#### Step 1: Install the Debian Package
```bash
sudo dpkg -i nexqor-x86.deb || sudo apt-get install -f -y
```

#### Step 2: Run the Setup Wizard (Mandatory)
```bash
nexqor setup
```
- **Select Role**: Choose `1) Server`
- **Crypto Mode**: Press `[Enter]` for default `4) Adaptive` (auto-detects hardware AVX2/AES-NI)
- **Bind Address**: Press `[Enter]` for default `0.0.0.0`
- **UDP Port**: Press `[Enter]` for default `9877`
- **Device ID**: Auto-detected hostname (e.g., `vishal-kumar-Inspiron-15-3525`)
- Keys will be saved cleanly to `~/.config/securecomm/` with `0600` permissions (or `/etc/securecomm/` if run as root).

#### Step 3: Launch the Server Backend
```bash
nexqor server start
```
*(Alternative alias: `securecomm server start`)*

Or to launch with the **Pure C GTK4 NOC Telemetry Dashboard**:
```bash
./run_ui.sh
```

**What you will see in the terminal:**
```text
╔══════════════════════════════════════════════════════════════════════════════════╗
║                 NEXQOR Secure Server (Post-Quantum & Classical)                  ║
╚══════════════════════════════════════════════════════════════════════════════════╝
  Status        : LISTENING
  Bind Address  : 0.0.0.0 (UDP)
  Port          : 9877
  Target Host   : 100.113.83.56:9877
  Crypto Mode   : adaptive
  Device ID     : vishal-kumar-Inspiron-15-3525
  Fingerprint   : 2b338d18b79f459b...
  Key File      : /home/vishal-kumar/.config/securecomm/vishal-kumar-Inspiron-15-3525.key

[Ready] Waiting for incoming client connections... (Press Ctrl+C to stop)
[IPC] Dashboard integration active on /tmp/pqc_rx.sock and /tmp/pqc_tx.sock
```

---

### 💻 Client Machine (Second Laptop / Kali Linux / Raspberry Pi / VM)

#### Step 1: Install the Debian Package
```bash
# On an x86-64 Laptop, Desktop, or Kali VM:
sudo dpkg -i nexqor-x86.deb || sudo apt-get install -f -y

# On a Raspberry Pi 4 / 5 (ARM64 / AArch64):
sudo dpkg -i nexqor-arm64.deb || sudo apt-get install -f -y

# On a Raspberry Pi 2 / 3 (ARM32 / armhf):
sudo dpkg -i nexqor-arm32.deb || sudo apt-get install -f -y
```

#### Step 2: Run the Setup Wizard (Mandatory)
```bash
nexqor setup
```
- **Select Role**: Choose `2) Client`
- **Crypto Mode**: Press `[Enter]` for `4) Adaptive`
- **Target Server IP**: Enter `100.113.83.56` (or host IP on your LAN / Tailscale)
- **Target UDP Port**: Press `[Enter]` for `9877`
- The wizard validates hardware, generates your cryptographic keypair in `~/.config/securecomm/`, and saves `~/.config/securecomm/securecomm.json`.

#### Step 3: Connect to the Server
```bash
nexqor client connect
```
*(No manual IP or port arguments needed! It automatically connects to the server configured in setup)*

**Real-Time Two-Way Interactive Terminal Session:**
```text
╔══════════════════════════════════════════════════════════════════════════════════╗
║                 NEXQOR Secure Client (Post-Quantum & Classical)                  ║
╚══════════════════════════════════════════════════════════════════════════════════╝
  Target Server : 100.113.83.56:9877 (UDP)
  Crypto Mode   : adaptive
  Device ID     : kali-client-01
  Fingerprint   : 0b33ec027f31aa92...
  Key File      : /home/janani/.config/securecomm/kali-client-01.key

[*] Connecting to 100.113.83.56:9877 over UDP...
[✓] Post-Quantum Handshake Established! Mutual Authentication Verified.
[✓] Encrypted Session Active. Session ID: 0x98124bcf8311aa01 (Latency: 1.84 ms)

╔═══════════════════════════════════════════════════════════════╗
║             NEXQOR INTERACTIVE SECURE CHAT                    ║
║ Type messages to send encrypted over UDP. Type /quit to exit.  ║
║ Real-Time 2-Way: Inbound server commands display instantly.   ║
║ Commands: /status, /metrics, /ping, /quit                     ║
╚═══════════════════════════════════════════════════════════════╝

securecomm> Hello from Kali Client!
[YOU → SERVER] Hello from Kali Client!  (Encrypted: 47 bytes)

[SERVER → YOU] Welcome to QRYPTONEX Server. Command acknowledged.
securecomm> /ping
[Sent PING to server]
securecomm> /metrics
=========================================================
               SECURECOMM METRICS & HEALTH               
=========================================================
 Packets Transmitted (TX)   : 4 packets (4480 bytes)
 Packets Received (RX)      : 3 packets (2240 bytes)
 Handshake Latency          : 1.84 ms
=========================================================
securecomm> /quit
[INFO] Disconnected from server
```

#### Fast Non-Interactive Single Message Transmission:
```bash
nexqor client connect --msg "Hello Quantum Server! Immediate automated transmission."
```

#### CLI Target Overrides (Optional):
```bash
# Connect to custom IP and Port directly:
nexqor client connect 100.113.83.56 9877
nexqor client connect --server 10.58.4.191 --port 9877
```

---

### 🌐 VirtualBox & Virtual Machine Networking Guide

If running the client inside a **VirtualBox Kali Linux VM**:
1. **Option A (Recommended — Tailscale / VPN)**: Install Tailscale inside both host and VM. Connect directly using the Tailscale IP `100.113.83.56`.
2. **Option B (Bridged Adapter)**: In VirtualBox VM Settings → **Network** → Set Adapter 1 to **Bridged Adapter** (select your Wi-Fi or Ethernet card). The VM gets an IP on the same physical subnet (e.g., `10.58.x.x`). You can then connect directly to the host's Wi-Fi IP `10.58.4.191`.
3. **Option C (NAT with Gateway)**: If using default NAT in VirtualBox, target the default gateway `10.0.2.2`:
   ```bash
   nexqor client connect 10.0.2.2 9877
   ```

---

### 📊 Pure C GTK4 NOC Dashboard Features

When the server is managed via the **GTK4 Dashboard (`./run_ui.sh`)**:
- **Manual Start/Stop Server Lifecycle**: The server doesn't auto-run in the background; operators have full control with the `▶ Start Server` / `⏹ Stop Server` button in the top bar.
- **Dynamic Local Wi-Fi & Network Discovery**: Dynamically resolves local Wi-Fi, Ethernet, and VPN addresses via `getifaddrs`, updates top badges, and generates live connection snippets for ESP32 and CLI clients. Auto-refreshes every second if your Wi-Fi changes.
- **Upside Performance & Telemetry Layout**: Real-time traffic stats, wire handshake breakdown latency (KEM/DSA keygen, encapsulation, signing, verification), decryption overhead, jitter, and interarrival times are positioned right above the details.
- **Downside Deep Cryptographic Session Inspector**: Full view of active session IDs, directional 256-bit encryption keys (`C2S` and `S2C`), wire fingerprints, and the RFC 6479 64-packet anti-replay window.
- **10-Second Disconnect Watchdog**: Sessions silent for >10 seconds or issuing a graceful `PKT_DISCONNECT` are instantly freed and moved to `DISCONNECTED SESSIONS (RECENT)`.
- **Zero-Latency Inbound Display**: Incoming client messages appear instantaneously in the live chat log using low-overhead UNIX socket IPC (`/tmp/pqc_rx.sock`).
- **Direct & Broadcast Messaging**: Server operators can select "Broadcast to All Clients" or target a specific client from the recipient dropdown and send encrypted commands in real time.
- **Seamless Suite Switching**: Switch effortlessly between Pure Post-Quantum, Hybrid, and Classical IoT modes with automatic port unbinding, socket cleanup, and backend restarting.

---

## Table of Contents
1. [⚡ Quickstart: Step-by-Step Server & Client Deployment](#-quickstart-step-by-step-server--client-deployment)
2. [Architectural Overview & Cryptographic Primitives](#1-architectural-overview--cryptographic-primitives)
3. [Source Tree & Modular Component Architecture](#2-source-tree--modular-component-architecture)
4. [End-to-End Build & Compilation Plan](#3-end-to-end-build--compilation-plan)
5. [Multi-Architecture Debian Packaging Plan](#4-multi-architecture-debian-packaging-plan)
6. [System Installation & Service Management (systemd)](#5-system-installation--service-management-systemd)
7. [Complete Configuration Guide (JSON Schema)](#6-complete-configuration-guide-json-schema)
8. [Device Identity, Fingerprinting & Trust Store](#7-device-identity-fingerprinting--trust-store)
9. [Client-Server Operational Workflows](#8-client-server-operational-workflows)
10. [Adaptive Policy Engine & Explainability](#9-adaptive-policy-engine--explainability)
11. [Platform Diagnostics, Health Checks & Benchmarking](#10-platform-diagnostics-health-checks--benchmarking)
12. [Troubleshooting & Error Code Dictionary](#11-troubleshooting--error-code-dictionary)

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
│   │   ├── nexqor-x86.deb            # x86-64 / AMD64 Debian package
│   │   ├── nexqor-arm64.deb          # ARM64 / AArch64 Debian package
│   │   └── nexqor-arm32.deb          # ARM32 / armhf Debian package
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

### 📦 Standalone Debian Packages (`.deb`)

SecureComm generates three distinct, architecture-specific `.deb` packages designed for direct installation and offline/air-gapped environments:

| Package Name (`.deb`) | Internal Package Name | Debian Arch (`dpkg`) | Target CPU & Hardware | Direct Download Link |
| :--- | :--- | :---: | :--- | :---: |
| **`nexqor-x86.deb`** | `nexqor-x86` | `amd64` | Intel/AMD PCs, laptops, and x86_64 cloud servers | [📥 Download `nexqor-x86.deb`](https://drive.google.com/uc?export=download&id=1wKZ5hrTjgId0uJUwz5kTT9iVX_G_KwtT) |
| **`nexqor-arm64.deb`** | `nexqor-arm64` | `arm64` | Raspberry Pi 4, Raspberry Pi 5, Jetson, 64-bit ARM Linux | [📥 Download `nexqor-arm64.deb`](https://drive.google.com/uc?export=download&id=1kTHy9Kl_Ur6_HlXYya-e9ztAmg2Z94vJ) |
| **`nexqor-arm32.deb`** | `nexqor-arm32` | `armhf` | Raspberry Pi 2/3 running 32-bit Raspbian/Debian | [📥 Download `nexqor-arm32.deb`](https://drive.google.com/uc?export=download&id=1lT-iFzbxwV6QLHamfSOMpTLUEq2velVb) |

---

### Terminal Download & Install Commands

#### 1. For x86-64 PC, Laptop & Cloud Servers (`nexqor-x86`):
```bash
# Direct local package installation:
sudo dpkg -i nexqor-x86.deb || sudo apt-get install -f -y
```

#### 2. For Raspberry Pi 4 / 5, Jetson, 64-bit ARM (`nexqor-arm64`):
```bash
# Direct local package installation:
sudo dpkg -i nexqor-arm64.deb || sudo apt-get install -f -y
```

#### 3. For Raspberry Pi 2 / 3, 32-bit ARM OS (`nexqor-arm32`):
```bash
# Direct local package installation:
sudo dpkg -i nexqor-arm32.deb || sudo apt-get install -f -y
```

---

### How to Build Packages Locally from Source:

```bash
# Build all 3 distinct packages at once:
make package
# (or: make package-all)

# Or build individual packages:
make package-x86      # Generates packaging/debian/nexqor-x86.deb
make package-arm64    # Generates packaging/debian/nexqor-arm64.deb
make package-arm32    # Generates packaging/debian/nexqor-arm32.deb
```

---

## 5. System Installation & Service Management (systemd)

### Manual Local Package Installation
If you built the packages locally with `make package`:

```bash
# On x86-64:
sudo dpkg -i packaging/debian/nexqor-x86.deb

# On ARM64 (AArch64):
sudo dpkg -i packaging/debian/nexqor-arm64.deb

# On ARM32 (ARMv7):
sudo dpkg -i packaging/debian/nexqor-arm32.deb
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
    "server_host": "100.113.83.56",
    "port": 9877,
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
nexqor server start
# Or explicitly:
securecomm server start --config /etc/securecomm/securecomm.json
```
Output:
```
[2026-10-29 15:45:00] [INFO ] [CORE] SecureComm Server listening on 0.0.0.0:9877 [mode: adaptive]
[2026-10-29 15:45:00] [INFO ] [CORE] Target Host: 100.113.83.56:9877
[2026-10-29 15:45:00] [INFO ] [CORE] Adaptive mode selected profile: NIST FIPS 203/204 Pure Post-Quantum (ML-KEM-768 + ML-DSA-65) (pqc)
```

### Scenario 3: Connecting a Client (Interactive Chat Shell)
```bash
# Connect directly (targets 100.113.83.56:9877 by default):
nexqor client connect

# Or connect with custom parameters:
nexqor client connect 100.113.83.56 9877
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

### 🔑 Resolved Issue: "Failed to write private key to '/etc/securecomm/identity.key': Permission denied"

#### What caused this?
On Linux, the `/etc/` directory is owned by `root`. When a normal, non-root user ran `nexqor server start` or `nexqor client connect`, the application attempted to generate cryptographic identity keypairs inside `/etc/securecomm/identity.key`, which resulted in `Permission denied`.

#### How NEXQOR fixes this automatically:
1. **Dynamic User-Space Fallback**:
   - When executed by an unprivileged user (or if `/etc/securecomm/` is read-only), NEXQOR automatically switches key storage to `$HOME/.config/securecomm/<device_id>.key`.
   - The directory is created automatically with mode `0700`, and private keys are saved with strict `0600` permissions (readable only by the owner).
2. **Debian Package Sticky-Bit Protection**:
   - The Debian package `postinst` script configures `/etc/securecomm` with mode `1777` (the same secure sticky-bit model used by `/tmp`), enabling all users to maintain node keys securely if `/etc` is preferred.
3. **Manual Override (Optional)**:
   If you ever need to manually set up your local user key directory:
   ```bash
   mkdir -p ~/.config/securecomm
   chmod 0700 ~/.config/securecomm
   ```

---

### Common Error Codes & Quick Fixes

| Error String | Code | Root Cause | Solution |
| :--- | :---: | :--- | :--- |
| `SECURECOMM_ERR_PERM_DENIED` | -3 | Key directory unwritable or private key permissions loose. | Automatically resolved by storing in `~/.config/securecomm/` with `0600` permissions. |
| `SECURECOMM_ERR_TIMEOUT` | -7 | Target UDP port unreachable or server not started. | 1. Ensure server is running: `nexqor server start`<br>2. Verify port `9877` (UDP) is open: `sudo ufw allow 9877/udp` |
| `SECURECOMM_ERR_AUTH_FAILED` | -6 | Peer public key doesn't match the pinned fingerprint in `trust_store.txt`. | Default `allow_tofu = true` automatically trusts and pins on first connect. For identity rotation, edit `~/.config/securecomm/trust_store.txt`. |
| `SECURECOMM_ERR_NETWORK` | -5 | UDP socket failed to bind or address already in use. | Check if another process is using port 9877: `ss -ulnp \| grep 9877`. Terminate old instance with `killall nexqor` or `killall securecomm`. |
| `SECURECOMM_ERR_NO_COMPAT_PROFILE` | -11 | Adaptive engine could not find a profile satisfying policy constraints. | Run `nexqor adaptive explain` to see exact stage rejections. |
| `SECURECOMM_ERR_BACKEND_MISSING`| -9 | Target runtime backend library (e.g. `liboqs`) is missing. | Verify dependencies via `nexqor diagnostics`. |

---

## 12. Security Verification & Non-Goals

- **Zero Monolithic Dependencies**: Built without heavyweight runtime frameworks or web servers.
- **Pure C11 Implementation**: No Python runtime dependencies.
- **Downgrade Attack Resistance**: Enforced at Stage B of the Adaptive Engine.
- **Replay Protection**: Packets with duplicate sequence numbers or outside the 64-datagram window are discarded prior to AEAD decryption.
- **Resource Bounds**: Bounded session tables (256 sessions), bounded 16KB buffers, monotonic expiration timers.

