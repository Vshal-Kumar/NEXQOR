# QRYPTONEX — Hybrid IoT Networking & Dynamic Connectivity Guide

This document details the dynamic endpoint resolution, automatic LAN discovery, and cross-network mesh connectivity (via Tailscale) for the **QRYPTONEX Hybrid Cryptographic Suite** (`X25519 + ML-KEM-768 + Ed25519 + ML-DSA-65 + ChaCha20-Poly1305`).

---

## 1. Zero-Configuration Dynamic Addressing Architecture

Hardcoded IP addresses have been completely removed from the networking and transport layers. All hybrid executables (`server`, `client`, `client_broadcast`, `server_rx`, `server_tx`, `bench_nclient`) resolve and bind endpoints dynamically.

### Resolution Priority Chain

When any client or benchmark launches, `resolve_server_address()` discovers the server endpoint using the following 5-tier hierarchy:

```
┌────────────────────────────────────────────────────────────────────────┐
│ 1. Explicit CLI Target (IP address, hostname, or Tailscale MagicDNS)   │
│    e.g., ./client 192.168.1.100 or ./client hybrid-pi.tailscale.net    │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ (if not provided)
┌──────────────────────────────────▼─────────────────────────────────────┐
│ 2. Environment Variables (HYBRID_SERVER_IP, PQC_SERVER_IP)             │
│    e.g., export HYBRID_SERVER_IP="100.113.83.56"                       │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ (if unset)
┌──────────────────────────────────▼─────────────────────────────────────┐
│ 3. System & Local Discovery Files                                      │
│    Reads ./server_endpoint.info or /tmp/hybrid_server.ip               │
│    written automatically upon hybrid server startup.                   │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ (if running across remote physical subnets)
┌──────────────────────────────────▼─────────────────────────────────────┐
│ 4. LAN UDP Broadcast Auto-Discovery Probe                              │
│    Client sends PKT_DISCOVERY_PROBE on UDP port 9879.                  │
│    Server responds with PKT_DISCOVERY_OFFER containing its active IP.  │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ (if no response within 200 ms)
┌──────────────────────────────────▼─────────────────────────────────────┐
│ 5. Localhost Loopback Fallback (127.0.0.1:9879)                        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Server Startup & Endpoint Publishing

The hybrid server binds to `0.0.0.0:9879` (all network adapters: loopback, Ethernet, Wi-Fi, and VPN overlays like Tailscale). Upon binding, it inspects local network interfaces via `getifaddrs`:

```bash
cd hybrid
./server
```

**Startup Console Output:**
```
╔══════════════════════════════════════════════════════════════════════════╗
║   QRYPTONEX Secure Server Core ─ Hybrid Cryptographic Suite              ║
║   Architecture: Linux Multi-Worker Thread Pool + Session Registry       ║
║   Suite: X25519 + ML-KEM-768 + Ed25519 + ML-DSA-65 + ChaCha20-Poly1305    ║
╚══════════════════════════════════════════════════════════════════════════╝

[server] Server Dual Identity Loaded (Ed25519 32B + ML-DSA-65 1952B)
[server] Active Endpoints:
  • Localhost        : 127.0.0.1:9879
  • LAN / Wi-Fi      : 192.168.1.150:9879
  • Tailscale / VPN  : 100.113.83.56:9879
  • Discovery Probe  : UDP Broadcast on port 9879
  • IPC RX Socket    : /tmp/hybrid_rx.sock
  • IPC TX Socket    : /tmp/hybrid_tx.sock

[server] Worker Thread Pool Initialized (4 workers). Ready for clients.
```

The server publishes its active IPs to `server_endpoint.info` and `/tmp/hybrid_server.ip` for local tools.

---

## 3. Operational Deployment Scenarios

### Scenario A: Localhost / Inter-Process on Same Host
No arguments needed. All programs auto-detect the local server:
```bash
# Terminal 1: Run server
./server

# Terminal 2: Connect interactive client
./client

# Terminal 3: Stream autonomous IoT sensor telemetry
./client_broadcast auto 100 SENSOR-NODE-01
```

### Scenario B: Local Area Network (Same Wi-Fi / Switch)
If the server and client are on the same subnet (e.g., server is on a laptop and client is on a Raspberry Pi):
```bash
# On Raspberry Pi (auto-discovery probe finds server on LAN broadcast port 9879):
./client_broadcast auto 200 PI-4-FACTORY

# Or specify server LAN IP directly:
./client 192.168.1.150
```

### Scenario C: Cross-Network Mesh over Tailscale VPN
For devices located across different cellular, home, or cloud networks:
1. Install Tailscale on the server host and target IoT devices (`curl -fsSL https://tailscale.com/install.sh | sh`).
2. Run `tailscale up` on both devices.
3. Start the hybrid server on the host machine.
4. On the remote IoT device (e.g., Raspberry Pi connected over 4G/5G):
```bash
# Connect using the server's 100.x.y.z Tailscale IP or MagicDNS hostname
./client 100.113.83.56
./client_broadcast 100.113.83.56 500 REMOTE-PI-CELLULAR
```

---

## 4. Multi-Terminal Management via UNIX Sockets (IPC)

The hybrid server completely decouples packet processing from UI rendering using high-speed UNIX domain sockets:

| Socket Path | Purpose | Consuming Binary |
|---|---|---|
| `/tmp/hybrid_rx.sock` | Stream of decrypted incoming client messages and real-time cryptography metrics (latency, jitter, RTT) | `server_rx` |
| `/tmp/hybrid_tx.sock` | Bidirectional operator control channel for unicast/broadcast message injection to connected clients | `server_tx` |

To run the decoupled terminals in separate windows:
```bash
# Terminal 1: Core Engine
./server

# Terminal 2: Live Ingest & Metrics Monitor
./server_rx

# Terminal 3: Operator Transmitter Console
./server_tx
```

Or run all 3 terminals automatically with the launcher script:
```bash
./run.sh
```
