# NEXQOR — GTK 4 Pure C Server NOC & Cryptographic Inspector

[![UI Toolkit: GTK 4](https://img.shields.io/badge/GUI-GTK%204.0%20(Pure%20C)-00599C.svg?logo=gtk&logoColor=white)](https://www.gtk.org/)
[![Language: C11](https://img.shields.io/badge/Language-C11-blue.svg)](https://en.wikipedia.org/wiki/C11_(C_standard_revision))
[![IPC: UNIX Domain Sockets](https://img.shields.io/badge/IPC-UNIX%20Domain%20Datagrams-orange.svg)](#ipc-architecture)
[![Theme: Cyber NOC Dark](https://img.shields.io/badge/Theme-Cyber%20NOC%20Dark-success.svg)](#design--aesthetic-system)

The **NEXQOR Server NOC Console** (`ui/qhack_ui`) is a high-performance, native **GTK 4 graphical user interface written entirely in pure C11** (zero Electron bloat, zero web wrappers, sub-millisecond redraw latency). It provides network engineers and security researchers with real-time control, live telemetry, dynamic IP discovery, and deep cryptographic session inspection for running **Pure Post-Quantum**, **Hybrid**, and **Classical IoT** servers.

---

## 🌟 Key Features

### 1. Controlled Server Start / Stop Lifecycle
- **Manual Execution Control**: The server does not auto-start on application launch. An operator explicitly starts and stops the backend with the prominent `▶ Start Server` / `⏹ Stop Server` button in the top navigation bar.
- **Graceful Port & Process Management**: Automatically terminates previous instances on UDP port `9877` using `fuser` and `pkill`, cleanly unlinks UNIX IPC sockets (`/tmp/pqc_rx.sock`, `/tmp/pqc_tx.sock`), and monitors process PID status.
- **Real-Time Status Badges**: High-visibility status indicator clearly shows `○ SERVER OFFLINE`, `● SERVER RUNNING`, or `⏳ RESTARTING SERVER...`.

### 2. Dynamic Local Wi-Fi & Multi-Interface IP Discovery
- **Zero-Hardcoding Network Detection**: Uses Linux `getifaddrs()` to dynamically enumerate and categorize all active network interfaces:
  - **Wi-Fi** (`wl*`): e.g., `10.58.4.191 (WI-FI)`
  - **Ethernet** (`en*`, `eth*`): e.g., `192.168.1.50 (ETH)`
  - **VPN / Overlay** (`tailscale*`, `tun*`, `wg*`): e.g., `100.113.83.56 (VPN)`
- **Dynamic Header Display**: The top bar displays all active endpoints in real time (e.g. `📡 10.58.4.191 (WI-FI):9877 | 100.113.83.56 (VPN):9877`).
- **Dynamic Code Snippets**: When no clients are connected, the client list card dynamically renders connection instructions for both ESP32 microcontrollers and Linux CLI clients using the active Wi-Fi / primary IP:
  ```cpp
  // ESP32 Node (esp32_secure_node.ino):
  const char* SERVER_IP = "<auto-detected-wifi-ip>";
  ```
  ```bash
  # Linux / Debian Client:
  nexqor client connect <auto-detected-wifi-ip> 9877
  ```
- **Real-Time 1-Second Refresh**: If you switch Wi-Fi networks (e.g., college Wi-Fi, home LAN, or mobile hotspot), the UI detects the new address and refreshes the display within 1 second.

### 3. Reordered High-Efficiency Layout: Upside Metrics & Downside Details
- **Upside Cards (Live Performance & Traffic Stats)**:
  - **Latency & Cryptographic Timings**: KEM Keygen, DSA Keygen, KEM Encap, DSA Sign, DSA Verify, and Total 4-Way Handshake wire latency.
  - **Live Traffic Telemetry**: Decryption cost (µs), encryption cost (µs), packet interarrival time (ms), transit jitter (ms), and total encrypted traffic volume.
- **Downside Cards (Deep Cryptographic Session Inspector)**:
  - Cryptographic Architecture (e.g. `NEXQOR-PQC-MLKEM768-MLDSA65-CHACHA20`).
  - Active Peer Endpoint (`IP:Port`) and 64-bit Hex Session ID.
  - Directional Traffic Keys: Client-to-Server (`C2S`) and Server-to-Client (`S2C`) 256-bit keys.
  - Cryptographic Primitives: Key Exchange, Signature, AEAD Cipher, and KDF.
  - RFC 6479 64-Packet Anti-Replay Sliding Window bitmap.

### 4. Responsive 10-Second Disconnect Watchdog & Instant PKT_DISCONNECT
- **Inactivity Watchdog**: Server and UI track client heartbeats with a 10-second inactivity threshold. If an IoT client powers down or loses connection, it is instantly removed from `CONNECTED CLIENTS (ACTIVE)` and gracefully moved to `DISCONNECTED SESSIONS (RECENT)`.
- **Instant Clean Disconnect**: When a client sends `PKT_DISCONNECT`, the server immediately frees the session and dispatches an IPC frame to update the UI without delay.

### 5. Seamless Cryptographic Suite Switching
- Operator can switch between:
  1. **Pure Post-Quantum Suite** (NIST FIPS 203 ML-KEM-768 + FIPS 204 ML-DSA-65 + ChaCha20-Poly1305)
  2. **Hybrid Post-Quantum Suite** (X25519 + ML-KEM-768 & Ed25519 + ML-DSA-65 + ChaCha20-Poly1305)
  3. **Classical IoT Suite** (X25519 + Ed25519 + AES-128-CCM)
- Switching suites gracefully stops the running server, cleans up sockets and ports, updates cryptographic parameters, and restarts cleanly.

### 6. Bidirectional Encrypted Messaging Console
- Interactive chat terminal with left-aligned incoming (`RX`) messages and right-aligned outgoing (`TX`) messages.
- Individual client targeting via dropdown or broadcast to all connected clients.
- Expandable cryptographic detail drawer on every chat bubble showing packet sequence number, decryption time in microseconds, and cipher hex preview.

---

## 🏗️ Architecture & IPC Protocol

The GTK 4 dashboard communicates with the running backend server via high-speed **UNIX Domain Sockets** using framed binary IPC frames:

```
┌─────────────────────────────────┐           ┌──────────────────────────────────┐
│      GTK 4 Dashboard UI         │           │    NEXQOR Backend Server      │
│          (qhack_ui)             │           │  (PQC, Hybrid, or Classical)     │
└──────────────┬──────────────────┘           └──────────────────┬───────────────┘
               │                                                 │
               │  UNIX Domain Socket (/tmp/pqc_rx.sock)          │
               │◄────────────────────────────────────────────────┤
               │  IPC_MSG_RX, IPC_CLIENT_LIST, IPC_STATUS        │
               │                                                 │
               │  UNIX Domain Socket (/tmp/pqc_tx.sock)          │
               ├────────────────────────────────────────────────►│
               │  IPC_MSG_TX, IPC_CLIENT_DISCONNECT              │
```

### IPC Frame Format:
```
┌──────────────┬──────────────┬──────────────┬──────────────┬────────────────────────────┐
│ Magic (2B)   │ Type (2B)    │ ClientID(2B) │ Length (2B)  │ Payload (Variable)         │
│ 0x5148 "QH"  │ uint16_t     │ uint16_t     │ uint16_t     │ N bytes                    │
└──────────────┴──────────────┴──────────────┴──────────────┴────────────────────────────┘
```

---

## 🚀 Building & Running

### Prerequisites
Install native GTK 4 and build dependencies:
```bash
sudo apt-get update
sudo apt-get install -y libgtk-4-dev build-essential libssl-dev
```

### Build Commands
```bash
# Build the GTK 4 UI binary:
make -C ui all

# Clean build artifacts:
make -C ui clean
```

### Launching the Dashboard
```bash
# Direct launcher script:
./run_ui.sh

# Or launch both Server Dashboard and Security Lab together:
./app.sh
```

---

## 🎨 Theme & Styling System (`style.css`)

The UI is styled using modern CSS rules tuned specifically for cybersecurity Network Operations Centers (NOC):
- **Base Background**: Obsidian Night `#070b14` and Slate Card surfaces `#0d1322`.
- **Borders & Highlights**: Subtle cyan glow `#1e293b` with `#38bdf8` active accents.
- **Status Badges**:
  - `badge-online`: Emerald green `#10b981`
  - `badge-offline`: Crimson red `#ef4444`
  - `badge-restarting`: Amber `#f59e0b`
- **Typography**: Clean monospace alignment for hexadecimal keys and cryptographic hashes, with high-contrast text `#f8fafc` for maximum readability.
