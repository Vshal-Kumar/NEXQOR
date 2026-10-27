# QRYPTONEX — Classical IoT Networking & Dynamic Connectivity Guide

This document details the dynamic endpoint resolution, automatic LAN discovery, and cross-network mesh connectivity (via Tailscale) for the **QRYPTONEX Classical IoT implementation**.

---

## 1. Zero-Configuration Dynamic Addressing Architecture

Hardcoded IP addresses have been completely removed from the networking and transport layers. All classical executables (`server`, `client`, `client_broadcast`, `server_rx`, `server_tx`, `bench_nclient`) resolve and bind endpoints dynamically.

### Resolution Priority Chain

When any client or benchmark launches, `resolve_server_address()` discovers the server endpoint using the following hierarchy:

```
┌────────────────────────────────────────────────────────────────────────┐
│ 1. Explicit CLI Target (IP address, hostname, or Tailscale MagicDNS)   │
│    e.g., ./client 192.168.1.100 or ./client iot-server.tailscale.net   │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ (if not provided)
┌──────────────────────────────────▼─────────────────────────────────────┐
│ 2. Environment Variables (CLASSICAL_SERVER_IP, PQC_SERVER_IP)          │
│    e.g., export CLASSICAL_SERVER_IP="100.113.83.56"                    │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ (if unset)
┌──────────────────────────────────▼─────────────────────────────────────┐
│ 3. System & Local Discovery Files                                      │
│    Reads ./server_endpoint.info or /tmp/nexqor_server.ip               │
│    written automatically upon server startup.                          │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ (if running across remote physical subnets)
┌──────────────────────────────────▼─────────────────────────────────────┐
│ 4. LAN UDP Broadcast Auto-Discovery Probe                              │
│    Client sends PKT_DISCOVERY_PROBE on UDP port 9877.                  │
│    Server responds with PKT_DISCOVERY_OFFER containing its active IP.  │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ (if no response within 200 ms)
┌──────────────────────────────────▼─────────────────────────────────────┐
│ 5. Localhost Loopback Fallback (127.0.0.1:9877)                        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Server Startup & Endpoint Publishing

The classical server core binds to `0.0.0.0:9877` (all network adapters: loopback, Ethernet, Wi-Fi, and VPN overlays like Tailscale). Upon binding, it inspects local network interfaces via `getifaddrs`:

```bash
cd classical
./server
```

**Startup Console Output:**
```
╔══════════════════════════════════════════════════════════╗
║   QRYPTONEX Secure Server Core ─ Classical IoT Suite     ║
║   Architecture: Linux io_uring + Multi-Worker Pool       ║
║   Suite: X25519 + Ed25519 + AES-128-CCM + SHA-256        ║
╚══════════════════════════════════════════════════════════╝

[server] Ed25519 Server Identity Public Key Loaded (32 bytes)
[server] Active Endpoints:
  • Localhost : 127.0.0.1:9877
  • LAN / Wi-Fi: 10.58.4.191:9877
  • Tailscale / VPN: 100.113.83.56:9877
  • Discovery Probe: UDP Broadcast on port 9877

[server] io_uring Event Loop Running. Ready for clients.
```

The server also records these endpoints in `server_endpoint.info` and `/tmp/nexqor_server.ip` for local tools.

---

## 3. Operational Deployment Scenarios

### Scenario A: Localhost / Inter-Process on Same Host
No arguments needed. All programs auto-detect the local server:

```bash
# Terminal 1: Start Server Core
./server

# Terminal 2: Telemetry Receiver Dashboard
./server_rx

# Terminal 3: Interactive Command Transmitter
./server_tx

# Terminal 4: Interactive Client
./client

# Terminal 5: Autonomous IoT Sensor Broadcaster
./client_broadcast
```

---

### Scenario B: Local Network (LAN / Wi-Fi / Ethernet)
*(e.g., Server running on Linux x86_64 server `192.168.1.100`, Client on Raspberry Pi 4/5 `192.168.1.150`)*

#### Option 1: Automatic Zero-Config Discovery Probe
Run client without arguments:
```bash
./client
```
The client broadcasts a probe packet on UDP port 9877, receives the server's offer, and executes the 4-phase classical handshake.

#### Option 2: Explicit IP Argument
```bash
./client 192.168.1.100
./client_broadcast 192.168.1.100 500 SENSOR-NODE-01
```

#### Option 3: Environment Variable
```bash
export CLASSICAL_SERVER_IP="192.168.1.100"
./client
./client_broadcast
```

---

### Scenario C: Cross-Network via Tailscale WireGuard Mesh

When the server and IoT clients reside on separate physical networks (e.g., edge gateway behind NAT or 4G/5G cellular modem):

1. Install Tailscale on server and client:
   ```bash
   curl -fsSL https://tailscale.com/install.sh | sh
   sudo tailscale up
   ```
2. Note the server's 100.x.y.z Tailscale IP or MagicDNS hostname (e.g., `100.113.83.56` or `server-node.tailnet.ts.net`).
3. Connect the classical client directly over Tailscale:
   ```bash
   ./client 100.113.83.56
   ./client_broadcast 100.113.83.56 1000 REMOTE-EDGE-GATEWAY
   ```
4. Handshake and telemetry packets traverse the WireGuard tunnel on port 9877, authenticated end-to-end with Ed25519 signatures and encrypted with AES-128-CCM.

---

## 4. UNIX Domain Socket IPC Architecture

The server decouples packet processing from operator interaction using UNIX domain sockets:

- **Receiver Socket**: Default `/tmp/classical_rx.sock` (configurable via `NEXQOR_IPC_RX_PATH`)
- **Transmitter Socket**: Default `/tmp/classical_tx.sock` (configurable via `NEXQOR_IPC_TX_PATH`)

- `server_rx` connects to `/tmp/classical_rx.sock` and receives streaming telemetry, client join/leave alerts, and RTT/jitter metrics.
- `server_tx` connects to `/tmp/classical_tx.sock` and presents an interactive CLI to send unicast or broadcast commands to active client sessions.

---

## 5. Network Troubleshooting & Diagnostics

| Symptom | Probable Cause | Resolution |
| :--- | :--- | :--- |
| `[client] Handshake timeout` | Firewall blocking UDP port 9877 | Run `sudo ufw allow 9877/udp` on the server machine. |
| `[client] Server key mismatch!` | Peer public key changed (MITM warning) | Inspect server Ed25519 public key. If intentional key renewal, update `server_identity.pub`. |
| `[server] Bind error: Address in use` | Another server running on port 9877 | Terminate stale instance: `fuser -k 9877/udp`. |
| `[broadcast] Packet dropped` | Buffer overflow under high burst | Increase socket buffer: `sysctl -w net.core.rmem_max=26214400`. |
