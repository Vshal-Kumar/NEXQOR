# NEXQOR / QRYPTONEX — Dynamic Networking & Cross-Network Guide

This guide details the dynamic server resolution, automatic LAN discovery, and external/cross-network connectivity (via Tailscale) for **NEXQOR / QRYPTONEX**.

---

## 1. Zero-Configuration Dynamic Addressing Architecture

Hardcoded IP addresses (`SERVER_ADDR "192.168.137.168"`) have been removed from the transport layer. All binaries (`server`, `client`, `client_broadcast`, `bench_nclient`) resolve and discover endpoints dynamically.

### Resolution Priority Chain

When any client or benchmark starts, `resolve_server_address()` determines the server address in the following priority:

```
┌────────────────────────────────────────────────────────────────────────┐
│ 1. Explicit CLI Target (IP, hostname, or Tailscale MagicDNS name)      │
│    e.g., ./client 10.58.3.114 or ./client nexqor-server                │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ (if not supplied)
┌──────────────────────────────────▼─────────────────────────────────────┐
│ 2. Environment Variables (PQC_SERVER_IP, SERVER_IP, NEXQOR_SERVER)    │
│    e.g., export PQC_SERVER_IP="100.104.77.63"                          │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ (if not set)
┌──────────────────────────────────▼─────────────────────────────────────┐
│ 3. System & Directory Discovery Files                                  │
│    Reads /tmp/nexqor_server.ip or ./server_endpoint.info published     │
│    automatically by the running server.                                │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ (if running on a remote device)
┌──────────────────────────────────▼─────────────────────────────────────┐
│ 4. LAN UDP Broadcast Auto-Discovery Probe                              │
│    Client broadcasts PKT_DISCOVERY_PROBE to port 9877. Server replies   │
│    with PKT_DISCOVERY_OFFER, allowing the client to auto-detect the   │
│    server IP on the local subnet without any user input.               │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ (if no response)
┌──────────────────────────────────▼─────────────────────────────────────┐
│ 5. Localhost Fallback (127.0.0.1:9877)                                 │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Server Startup & Endpoint Auto-Publishing

When `server` launches, it binds to `0.0.0.0:9877` (all interfaces: Loopback, Wi-Fi, Ethernet, and Tailscale VPN) and automatically inspects the network adapters using `getifaddrs`:

```bash
./server
```

**Console Output:**
```
[18:31:18.799] QRYPTONEX — Post-Quantum Secure Server
  Protocol : ML-KEM-768 + ML-DSA-65 + ChaCha20-Poly1305
  Address  : 0.0.0.0:9877  |  Max clients: 4096
  Active Endpoints (Auto-Discovered & Published):
    • Localhost (Same Device) : 127.0.0.1:9877
    • LAN / Wi-Fi Subnet      : 10.58.3.114:9877
    • Tailscale / VPN Overlay : 100.104.77.63:9877
    • Auto-Discovery Service  : UDP Broadcast Probe on port 9877
```

The server also writes these endpoints to `server_endpoint.info` and `/tmp/nexqor_server.ip`.

---

## 3. Deployment Scenarios

### Scenario A: Same Machine (Localhost / Inter-Process)
No arguments are required.

```bash
# Terminal 1: Start Server
./server

# Terminal 2: Chat Client
./client

# Terminal 3: Telemetry Streamer
./client_broadcast

# Terminal 4: 64-Client Benchmark
./bench_nclient 64 10
```

---

### Scenario B: Same Local Network (LAN / Wi-Fi / Ethernet)
*(e.g., Server on Laptop `10.58.3.114`, Client on Raspberry Pi on the same Wi-Fi)*

#### Option 1: Automatic Zero-Config (Recommended)
Simply launch the client without arguments:
```bash
# On Raspberry Pi (ARM64 / ARM32):
./client_arm
```
The client sends a UDP broadcast probe on port 9877, receives the server's reply, and connects automatically.

#### Option 2: Explicit IP or Environment Variable
```bash
# Pass server IP as argument:
./client_arm 10.58.3.114

# Or set environment variable:
export PQC_SERVER_IP=10.58.3.114
./client_arm
./client_broadcast_arm auto 500 "PI-NODE-01"
```

---

### Scenario C: Cross-Network / Remote Clients via Tailscale (Different Wi-Fi, Mobile Hotspot, Internet)

When connecting across different networks (e.g. Server is at home/office Wi-Fi, Client is on cellular 4G/5G or another Wi-Fi network), direct LAN IP routing will fail due to NAT and firewalls.

**Tailscale** provides secure, peer-to-peer, encrypted Mesh VPN routing with automatic NAT traversal and Zero-Tier setup.

#### Step 1: Install Tailscale on Both Machines
```bash
# Ubuntu / Debian / Raspberry Pi OS:
curl -fsSL https://tailscale.com/install.sh | sh
```

#### Step 2: Connect Both Devices to Your Tailscale Network
On the Server machine:
```bash
sudo tailscale up
tailscale ip -4
# Example output: 100.104.77.63
```

On the Client machine (Raspberry Pi / Remote Laptop):
```bash
sudo tailscale up
```

#### Step 3: Run Server
Start the server normally:
```bash
./server
```
The server automatically detects the `tailscale0` adapter and displays:
```
  Active Endpoints:
    • Tailscale / VPN Overlay : 100.104.77.63:9877
```

#### Step 4: Connect from the Remote Client
From any remote machine anywhere in the world:

```bash
# Using Tailscale IP:
./client_arm 100.104.77.63

# Or using Tailscale MagicDNS name:
./client_arm my-laptop-name

# Or for telemetry streaming:
./client_broadcast_arm 100.104.77.63 200 "REMOTE-SENSOR-01"

# Or for cross-network benchmarking:
./bench_nclient_arm 16 10 100.104.77.63
```

#### Why Tailscale Works Every Time:
1. **Bypasses NAT & Firewalls**: Works even behind symmetric NAT, hotel Wi-Fi, or mobile carrier CGNAT without configuring router port-forwarding.
2. **Encrypted Overlay**: Direct WireGuard tunnel between client and server.
3. **DERP Relay Fallback**: If UDP is blocked by a strict enterprise firewall, Tailscale automatically tunnels traffic over HTTPS relays, guaranteeing 100% connectivity.

---

## 4. Multi-Platform Support Matrix

All dynamic resolution capabilities are fully supported across all targets:

| Architecture | Binaries | Compilation Command |
|---|---|---|
| **x86_64** (Linux) | `server`, `client`, `client_broadcast`, `bench_nclient`, `bench_pqc` | `make all` |
| **ARM64** (AArch64 / Pi 4/5) | `client_arm`, `client_broadcast_arm`, `bench_nclient_arm`, `bench_pqc_arm` | `make -f Makefile.arm64 all` |
| **ARM32** (ARMv7 / Pi 2/3) | `client_arm32`, `client_broadcast_arm32`, `bench_nclient_arm32`, `bench_pqc_arm32` | `make -f Makefile.arm32 all` |

---

## 5. Troubleshooting & Diagnostics

1. **Firewall Blocking UDP 9877**:
   If devices on the same LAN cannot reach the server, allow UDP port 9877:
   ```bash
   sudo ufw allow 9877/udp
   ```

2. **Verify Server Discovery Files**:
   ```bash
   cat server_endpoint.info
   cat /tmp/nexqor_server.ip
   ```

3. **Check UDP Port Reachability**:
   ```bash
   nc -u -z -v <SERVER_IP> 9877
   ```

4. **Tailscale Connection Status**:
   ```bash
   tailscale status
   tailscale ping <SERVER_TAILSCALE_IP>
   ```
