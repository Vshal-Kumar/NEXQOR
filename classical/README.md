# QRYPTONEX (Classical IoT Suite) — Secure High-Concurrency IoT Networking Engine

[![Language: C11](https://img.shields.io/badge/Language-C11-00599C.svg?logo=c&logoColor=white)](https://en.wikipedia.org/wiki/C11_(C_standard_revision))
[![Architecture: Multi-Arch](https://img.shields.io/badge/Architecture-x86__64%20%7C%20ARM64%20%7C%20ARM32-blue.svg)](https://arm.com)
[![Key Exchange: X25519](https://img.shields.io/badge/ECDH-X25519%20(RFC%207748)-orange.svg)](https://datatracker.ietf.org/doc/html/rfc7748)
[![Signatures: Ed25519](https://img.shields.io/badge/Signatures-Ed25519%20(RFC%208032)-red.svg)](https://datatracker.ietf.org/doc/html/rfc8032)
[![AEAD: AES-128-CCM](https://img.shields.io/badge/AEAD-AES--128--CCM%20(NIST%20SP%20800--38C)-brightgreen.svg)](https://csrc.nist.gov/publications/detail/sp/800-38c/final)
[![Formal Verification: ProVerif](https://img.shields.io/badge/Formally%20Verified-ProVerif%20(All%20Proofs)-purple.svg)](https://proverif.inria.fr/)
[![Server Engine: io_uring](https://img.shields.io/badge/Async%20I%2FO-Linux%20io__uring-black.svg)](https://kernel.dk/io_uring.pdf)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](../LICENSE)

---

## 1. Project Overview & Architecture

**QRYPTONEX Classical IoT Suite** is a high-performance, low-latency, memory-efficient secure networking framework and multi-client relay engine implemented in **C11** for resource-constrained IoT endpoints, embedded microcontrollers, and Linux edge gateways (including Raspberry Pi 4/5, ARM Cortex-A/Cortex-M edge devices, and x86_64 servers).

This implementation reproduces the complete functionality, architecture, asynchronous `io_uring` event loop, worker thread pool, UNIX domain socket IPC, zero-config dynamic discovery, and multi-client session registry of the original QRYPTONEX framework, while substituting the post-quantum cryptographic suite with standard **classical IoT cryptography**:
- **Key Agreement**: ECDH over Curve25519 (**X25519**, RFC 7748)
- **Digital Signatures**: **Ed25519** (RFC 8032 / FIPS 186-5)
- **Authenticated Encryption**: **AES-128-CCM** with 15-byte wire header AAD (NIST SP 800-38C / RFC 3610)
- **Cryptographic Hash**: **SHA-256** (FIPS 180-4)
- **Key Derivation**: **HKDF-SHA-256** (RFC 5869) with directional domain separation
- **Message Authentication**: **HMAC-SHA-256** (RFC 2104)

> [!NOTE]
> The repository provides three independent, self-contained implementations:
> 1. **Post-Quantum Cryptography** (root directory): ML-KEM-768 + ML-DSA-65 on UDP port `9877`.
> 2. **Classical Cryptography** (`classical/` directory): X25519 + Ed25519 + AES-128-CCM on UDP port `9877`/`9878`.
> 3. **Hybrid Cryptography** (`hybrid/` directory): X25519 + ML-KEM-768 + Ed25519 + ML-DSA-65 on UDP port `9879`.

---

## 2. Cryptographic Suite Comparison (PQC vs Classical IoT)

| Cryptographic Component | Original Post-Quantum Suite | Classical IoT Suite | Architectural Rationale |
| :--- | :--- | :--- | :--- |
| **Key Establishment** | ML-KEM-768 (Kyber768, FIPS 203) | **X25519 ECDH (RFC 7748)** | Reduces public key from 1,184 B to **32 B** |
| **Digital Signatures** | ML-DSA-65 (Dilithium3, FIPS 204) | **Ed25519 (RFC 8032)** | Reduces signature from 3,309 B to **64 B** |
| **Authenticated Encryption** | ChaCha20-Poly1305 (RFC 8439) | **AES-128-CCM (SP 800-38C)** | Leverages ARM/Intel hardware AES instructions |
| **Transcript Hashing** | SHAKE256 XOF (FIPS 202) | **SHA-256 (FIPS 180-4)** | Fixed-length 32-byte canonical digests |
| **Traffic Key Derivation** | Custom SHAKE256 PRF | **HKDF-SHA-256 (RFC 5869)** | Standard extract-and-expand with domain labels |
| **Total Handshake Wire Size** | ~12,834 bytes (Fragmented) | **296 bytes (Unfragmented UDP)** | Fits completely inside a single standard MTU |
| **Crypto Library Dependency** | `liboqs` + OpenSSL | **System OpenSSL 3.x EVP only** | Eliminates external lattice library dependencies |

---

## 3. Directory Structure

```text
classical/
├── crypto/
│   ├── aead.c               # AES-128-CCM EVP encryption, decryption & AAD binding
│   ├── aead.h               # AEAD wire definitions and constants
│   ├── replay_window.c      # RFC 6479 64-packet thread-safe sliding replay window
│   ├── replay_window.h      # Replay window state and function declarations
│   ├── trust_store.c        # Ed25519 identity key persistence, TOFU & pinning
│   └── trust_store.h        # Trust store interfaces and configuration
│
├── wrappers/
│   ├── kem_wrapper.c        # X25519 ECDH key generation & shared secret agreement
│   ├── kem_wrapper.h        # X25519 prototypes and protocol abstractions
│   ├── dsa_wrapper.c        # Ed25519 digital signature generation & verification
│   ├── dsa_wrapper.h        # Ed25519 prototypes and protocol abstractions
│   ├── hash_wrapper.c       # SHA-256 one-shot and streaming hash implementation
│   ├── hash_wrapper.h       # SHA-256 hash interfaces
│   ├── kdf_wrapper.c        # RFC 5869 HKDF-SHA-256 and RFC 2104 HMAC-SHA-256
│   └── kdf_wrapper.h        # KDF and directional key derivation interfaces
│
├── tests/
│   └── test_suite.c         # Automated 22-test security and regression suite
│
├── verification/
│   ├── protocol.pv          # ProVerif Applied Pi-Calculus formal verification model
│   └── README.md            # Mathematical proofs and verification instructions
│
├── client.c                 # Interactive mutual authentication chat client
├── client_broadcast.c       # Autonomous IoT sensor telemetry broadcaster
├── client_registry.c        # Thread-safe multi-client session state table
├── client_registry.h        # Client registry interface
├── server.c                 # Asynchronous Linux io_uring multi-core server
├── server_rx.c              # UNIX IPC telemetry receiver terminal
├── server_tx.c              # UNIX IPC command transmitter terminal
├── transport.c              # UDP networking, dynamic discovery, framing & AAD
├── transport.h              # 15-byte wire header, connection state & metrics
├── ipc.h                    # UNIX domain socket IPC wire protocol
│
├── bench_crypto.c           # Cryptographic primitive microbenchmark suite
├── bench_nclient.c          # Multi-client concurrent handshake benchmark
├── bench_aead.c             # AES-128-CCM throughput benchmark & file encryptor
│
├── Makefile                 # x86_64 host build system
├── Makefile.arm64           # ARM64 / Raspberry Pi 4 & 5 build system
├── Makefile.arm32           # ARMv7-A / 32-bit ARM build system
├── run.sh                   # Three-terminal server/rx/tx launcher script
├── NETWORKING_GUIDE.md      # Zero-config discovery and Tailscale guide
├── CRYPTOGRAPHIC_SPECIFICATION.txt # Technical wire and cryptographic spec
└── README.md                # Master classical documentation
```

---

## 4. Dependencies & System Requirements

- **Linux Operating System** (Kernel 5.10+ recommended for `io_uring`).
- **OpenSSL 3.x** (`libssl-dev`, `libcrypto`).
- **liburing** (`liburing-dev` or local headers).
- **GCC / Clang** with C11 support (`-std=c11`).
- **Pthreads** and **Libm** (standard POSIX libraries).
- Optional: **ProVerif 2.05+** (for formal protocol proofs).

### Ubuntu / Debian Dependency Installation:
```bash
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev liburing-dev
```

---

## 5. Compilation Guide

### Build for x86_64 Host:
```bash
cd classical

# Compile all binaries, benchmarks, and test suite:
make all

# Run the 22-test automated security suite:
make test

# Run formal verification using ProVerif:
make verify

# Clean build artifacts:
make clean
```

### Build for ARM64 (Raspberry Pi 4 / 5):
```bash
# Native on ARM64 device:
make -f Makefile.arm64 all

# Cross-compiling from x86_64 host (with target sysroot):
make -f Makefile.arm64 all ARM64_SYSROOT=/path/to/arm64_sysroot
```

### Build for ARM32 (ARMv7-A / Raspberry Pi 2 / 3):
```bash
# Native on 32-bit ARM device:
make -f Makefile.arm32 all

# Cross-compiling from x86_64 host:
make -f Makefile.arm32 all
```

---

## 6. Running Application Workflows

### Workflow 1: Multi-Client Server Core & IPC Terminals
Launch the server and its decoupled receiver/transmitter terminals:

```bash
# Terminal 1: Start Server Core
./server

# Terminal 2: Start Receiver Terminal (displays incoming telemetry & metrics)
./server_rx

# Terminal 3: Start Transmitter Terminal (interactive client command menu)
./server_tx
```
*(Alternatively, execute `./run.sh` to launch all three terminals in separate GNOME terminal windows).*

---

### Workflow 2: Interactive Secure Chat Client
Connect an interactive client to the server:

```bash
# Auto-detect local server:
./client

# Or specify server IP explicitly:
./client 192.168.1.100
```
Upon connection, the client executes the 4-phase mutual authentication handshake, establishes directional AES-128-CCM session keys, and allows two-way messaging with the server.

---

### Workflow 3: Autonomous IoT Sensor Broadcaster
Simulate an autonomous edge sensor streaming encrypted telemetry:

```bash
# Default parameters (127.0.0.1, 500 ms interval, SENSOR-01):
./client_broadcast

# Custom endpoint, 200 ms interval, custom device ID:
./client_broadcast 192.168.1.100 200 SENSOR-GATEWAY-42
```
Streams continuous temperature, humidity, atmospheric pressure, and battery voltage telemetry authenticated and encrypted under AES-128-CCM.

---

### Workflow 4: Multi-Client Concurrency Benchmark (`bench_nclient`)
Simultaneously spawn N concurrent client threads performing complete handshakes and encrypted round-trip data exchanges:

```bash
# 64 concurrent clients, 10 messages each:
./bench_nclient 64 10

# 128 clients, handshake only:
./bench_nclient 128 0
```
Reports total wall time, handshake throughput (handshakes/second), CPU utilization, peak RSS memory, and latency percentiles (min, median, p95, p99).

---

### Workflow 5: Cryptographic Microbenchmarks (`bench_crypto` / `bench_aead`)
```bash
# Run full cryptographic suite benchmark (500 iterations):
./bench_crypto 500

# Run standalone AES-128-CCM benchmark and file encryption utility:
./bench_aead 500

# Encrypt a file using AES-128-CCM:
./bench_aead encrypt input.dat encrypted.dat

# Decrypt a file using AES-128-CCM:
./bench_aead decrypt encrypted.dat decrypted.dat <key_hex>
```

---

## 7. The 4-Phase Classical IoT Handshake

```text
      Client (X25519 + Ed25519)                             Server (io_uring Engine)
           │                                                                 │
    [Generate Ephemeral X25519 c_eph]                                        │
    [Phase 1: Client Hello]                                                  │
           ├─────────────── PKT_CLIENT_HELLO (80B) ─────────────────────────>│ [Validate Version & Types]
           │        (c_eph_pk || c_id_pk || c_nonce)                         │ [Generate s_eph & s_nonce]
           │                                                                 │ [Compute ECDH Shared Secret]
           │                                                                 │ [Construct Server Transcript]
           │                                                                 │ [Sign Transcript with Ed25519]
    [Phase 2: Server Hello]                                                  │
           │<────────────── PKT_SERVER_HELLO (152B) ─────────────────────────┤
           │        (s_id_pk || s_eph_pk || session_id ||                    │
           │         s_nonce || srv_sig)                                     │
           │                                                                 │
    [Verify Server Identity vs Trust Store]                                  │
    [Verify Server Ed25519 Signature]                                        │
    [Compute ECDH Shared Secret]                                             │
    [Derive Directional Keys via HKDF-SHA-256]                               │
    [Construct Client Transcript]                                            │
    [Sign Client Transcript with Ed25519]                                    │
    [Phase 3: Client Authentication]                                         │
           ├─────────────── PKT_CLIENT_AUTH (64B) ──────────────────────────>│ [Verify Client Ed25519 Sig]
           │        (client_sig)                                             │ [Derive Directional Keys]
    [Phase 4: Session Active]                                                │ (HKDF-SHA-256)
           │<────────────── PKT_ACK (0B Payload) ────────────────────────────┤
           │                                                                 │
           *═══════════════ Secure AES-128-CCM Channel Active ═══════════════*
           │                                                                 │
           ├─────────────── PKT_DATA (AES-128-CCM Encrypted) ───────────────>│ [Decrypt & Replay Window Check]
           │        [ Nonce (12B) | Tag (16B) | Encrypted Payload ]          │ (Wire Header as 15B AAD)
           │<────────────── PKT_DATA (AES-128-CCM Encrypted) ────────────────┤
```

---

## 8. Wire Framing & Nonce Management

### Canonical 15-Byte Wire Header:
```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Sequence Number (seq)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Type (0x10) |          Payload Length (len)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                     Session ID (64-bit)                       +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
The entire 15-byte header is fed as **Associated Authenticated Data (AAD)** into AES-128-CCM during encryption and validated prior to decryption. Any tampering with packet sequence, packet type, length, or session ID in transit causes immediate MAC rejection.

### Nonce Uniqueness & Anti-Reuse Architecture:
- Nonce length: **12 bytes** (`AEAD_NONCE_BYTES`).
- Nonce composition:
  - Bytes 0..3: Lowest 32 bits of Session ID (little-endian).
  - Bytes 4..11: Monotonically incrementing 64-bit transmission counter (`tx_nonce_ctr`).
- Separate independent counters and traffic keys are maintained for client transmission (`tx_key`) and server transmission (`rx_key`).
- If `tx_nonce_ctr` approaches exhaustion (`>= 0xFFFFFFFFFFFFFF00ULL`), transmission terminates and forces session renegotiation.

---

## 9. Automated Regression Testing & Formal Verification

### Automated Security Test Suite (`make test`):
The test suite in `tests/test_suite.c` validates 22 distinct cryptographic and systems invariants:
1. `test_x25519_agreement`: Shared-secret agreement between fresh ephemeral keypairs.
2. `test_x25519_invalid_input`: Rejection of all-zero and non-contributory public keys.
3. `test_ed25519_sign_and_verify`: Digital signature generation and validation.
4. `test_ed25519_tampered_message`: Rejection of tampered message bytes.
5. `test_ed25519_corrupted_sig_and_wrong_pk`: Rejection of corrupted signatures and incorrect public keys.
6. `test_aes128_ccm_encrypt_decrypt`: AES-128-CCM roundtrip encryption and decryption.
7. `test_aes128_ccm_ciphertext_tampering`: Rejection of modified ciphertext bits.
8. `test_aes128_ccm_aad_modification`: Rejection of tampered wire header fields (seq, type, session ID).
9. `test_aes128_ccm_tag_corruption`: Rejection of tampered authentication tags.
10. `test_sha256_kat`: FIPS 180-4 Known-Answer Test vector validation.
11. `test_hkdf_sha256_kat`: RFC 5869 Known-Answer Test vector validation.
12. `test_hmac_sha256_kat`: RFC 4231 Known-Answer Test vector validation.
13. `test_directional_traffic_key_separation`: Cryptographic separation between C2S and S2C traffic keys.
14. `test_nonce_uniqueness_and_monotonicity`: Strict nonce uniqueness within session.
15. `test_sliding_replay_window`: RFC 6479 64-packet window (in-order, out-of-order, duplicates, stale drops).
16. `test_packet_framing_and_reassembly`: UDP fragment handling and out-of-order reconstruction.
17. `test_trust_store_authentication`: Public-key pinning and MITM substitution interception.
18. `test_full_handshake_simulation`: End-to-end 4-phase mutual authentication execution.
19. `test_handshake_tampering_failure`: Active attacker message tampering interception.
20. `test_session_isolation`: Complete cryptographic state isolation between sessions.
21. `test_session_zeroization`: Secure wiping of ephemeral private keys via `explicit_bzero()`.
22. `test_reconnection_and_session_id_reuse`: Session ID differentiation across reconnects.

### Formal Verification with ProVerif (`make verify`):
Modeled in Applied Pi-Calculus under the Dolev-Yao attacker model (`verification/protocol.pv`):
- Directional Traffic Key Secrecy: **Proved TRUE**.
- Application Payload Secrecy: **Proved TRUE**.
- Injective Server-to-Client Authentication: **Proved TRUE**.
- Injective Client-to-Server Authentication: **Proved TRUE**.
- Perfect Forward Secrecy under Long-Term Key Compromise: **Proved TRUE**.

---

## 10. Security Limitations

> [!WARNING]
> - **Classical vs Post-Quantum**: The classical suite relies on X25519 and Ed25519, which are susceptible to Shor's algorithm on a Cryptographically Relevant Quantum Computer (CRQC). For post-quantum protection against "Store-Now-Decrypt-Later" (SNDL) attacks, deploy the root QRYPTONEX codebase (ML-KEM-768 + ML-DSA-65) or the hybrid suite (`hybrid/`, X25519 + ML-KEM-768 + Ed25519 + ML-DSA-65).
> - **Filesystem Permissions**: The server private key `server_identity.key` is generated with `0600` permissions. Ensure the hosting environment protects key files from unauthorized local read access.
> - **UDP Loss**: UDP is an unreliable datagram protocol. High packet-loss links depend on transport-layer retry timeouts (`RETX_MAX`).
