# QRYPTONEX Repository Inspection & Protocol Mapping Report

**Document Version:** 1.0.0  
**Inspection Date:** 2026-10-29  
**Target Architecture:** Linux x86_64 / ARM64 (POSIX compliant)  
**Security Framework:** `security_lab/` (Pure C Testing Engine)

---

## 1. Executive Summary & Suite Directory Mapping

The repository contains three distinct, production-grade secure UDP communication architectures evaluated across real network topologies:

| Implementation | Source Directory | Key Encapsulation (KEM) | Signature / Auth (DSA) | Symmetric AEAD | Hash / KDF |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Classical IoT** | [`classical/`](file:///home/vishal-kumar/Desktop/Events/QHack/classical) | X25519 (ECDH) | Ed25519 | AES-128-CCM | SHA-256 + HKDF |
| **2. Hybrid Suite** | [`hybrid/`](file:///home/vishal-kumar/Desktop/Events/QHack/hybrid) | X25519 + ML-KEM-768 | Ed25519 + ML-DSA-65 | ChaCha20-Poly1305 | SHA-384 + HKDF |
| **3. Pure PQC (NEXQOR)** | [`pqc/`](file:///home/vishal-kumar/Desktop/Events/QHack/pqc) | ML-KEM-768 (Kyber768) | ML-DSA-65 (Dilithium3)| ChaCha20-Poly1305 | SHAKE-256 + KMAC |

---

## 2. Network Endpoints, Ports, & Bind Addresses

Inspection of the socket initialization in `server.c` and `transport.c` across all three suites reveals:

| Implementation | Default Server Port | Bind Address | Discovery Probe Type | IPC UNIX Domain Sockets |
| :--- | :--- | :--- | :--- | :--- |
| **Classical** | `9877` | `0.0.0.0:9877` | `0x16` (PKT_DISCOVERY_PROBE) | `/tmp/classical_rx.sock`, `/tmp/classical_tx.sock` |
| **Hybrid** | `9879` | `0.0.0.0:9879` | `0x16` (PKT_DISCOVERY_PROBE) | `/tmp/hybrid_rx.sock`, `/tmp/hybrid_tx.sock` |
| **Pure PQC** | `9877` | `0.0.0.0:9877` | `0x16` (PKT_DISCOVERY_PROBE) | `/tmp/pqc_rx.sock`, `/tmp/pqc_tx.sock` |

> [!IMPORTANT]
> **Port Conflict Note:** `classical/server` and `pqc/server` both default to UDP port `9877`. Therefore, they cannot simultaneously bind to `0.0.0.0:9877` on the same machine. The `security_lab` test engine manages them sequentially or leverages port overrides.

---

## 3. Canonical On-Wire Protocol Framing

All three suites share the same canonical 15-byte datagram header:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Sequence Number (32b)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Type (8b)   |          Payload Length (16b)         |       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+       +
|                       Session ID (64b)                        |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Packet Type Enumeration
- `0x01` — `PKT_CLIENT_HELLO` (Initiates session handshake)
- `0x02` — `PKT_SERVER_HELLO` (Server KEM ciphertext + signature)
- `0x03` — `PKT_CLIENT_AUTH` (Client identity key + transcript signature)
- `0x05` — `PKT_FRAG` (Fragmented datagram carrying 11-byte `frag_hdr_t`)
- `0x10` — `PKT_DATA` (Authenticated encrypted application payload)
- `0x11` — `PKT_ACK` (Reliability acknowledgement datagram)
- `0x12` — `PKT_PING` / `0x13` — `PKT_PONG` (Liveness heartbeat)
- `0x14` — `PKT_BUSY` (Rate limit or queue saturation notification)
- `0x15` — `PKT_DISCONNECT` (Clean session teardown)
- `0x16` — `PKT_DISCOVERY_PROBE` (UDP broadcast auto-discovery)
- `0x17` — `PKT_DISCOVERY_OFFER` (Server discovery response)

### PKT_DATA Payload Layout (AEAD Format)
```text
+-----------------------+---------------------+-------------------------+
| Nonce / IV (12 bytes) | Poly1305 / AES Tag  | AEAD Encrypted Data     |
|                       | (16 bytes)          | (Variable Length n)     |
+-----------------------+---------------------+-------------------------+
```

---

## 4. Cryptographic Validation & Session Flow

1. **Mutual Handshake:** 4-way message exchange authenticating both endpoints via digital signatures before session keys are established.
2. **Replay Window:** 64-bit sliding window bitmap (`replay_window_t`) rejects duplicate sequence numbers and stale packets.
3. **AEAD Authenticated Associated Data (AAD):** The 15-byte wire header (`seq`, `type`, `len`, `session_id`) is strictly passed as Additional Authenticated Data to the AEAD decryptor. Any bit modification to header fields triggers authentication tag verification failure.
4. **IPC Observability:** Servers output decrypted application messages to `/tmp/<suite>_rx.sock` using structured binary framing (`ipc_hdr_t` + `raw_ipc_rx_payload_t`), enabling ground-truth verification of whether tampered datagrams reach the application layer.
