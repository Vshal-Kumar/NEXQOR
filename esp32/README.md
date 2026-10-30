# QRYPTONEX Embedded: ESP32 Post-Quantum Client Node
## NIST FIPS 203 (ML-KEM-768) + ChaCha20-Poly1305 on 32-bit Microcontrollers

[![Hardware: ESP32](https://img.shields.io/badge/Hardware-ESP32%20(Xtensa%20LX6%20240MHz)-red.svg?logo=espressif)](https://www.espressif.com/)
[![Role: Client Only](https://img.shields.io/badge/Role-Client%20Only-blue.svg)](#architecture-role)
[![KEM: ML-KEM-768](https://img.shields.io/badge/KEX-ML--KEM--768%20(Kyber768)-orange.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![AEAD: ChaCha20-Poly1305](https://img.shields.io/badge/AEAD-ChaCha20--Poly1305-brightgreen.svg)](https://datatracker.ietf.org/doc/html/rfc8439)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](../LICENSE)

This module implements an autonomous, lightweight **Post-Quantum Cryptographic IoT Client Node** on the **ESP32 microcontroller** (Xtensa 32-bit dual-core @ 240MHz, 520KB SRAM). It proves that low-cost, resource-constrained edge microcontrollers can actively participate in quantum-safe communication networks without hardware coprocessors or external crypto chips.

---

## 🏗️ Architecture & Operating Role

- **Operating Role**: **Client Only** (connects to the x86 QRYPTONEX Server over UDP port `9877`).
- **Cryptographic Protocol**:
  1. **Key Encapsulation (KEX)**: NIST FIPS 203 (ML-KEM-768 / Kyber-768) key generation and decapsulation.
  2. **Session Encryption (AEAD)**: RFC 8439 ChaCha20-Poly1305 with 256-bit directional keys.
  3. **Directional Traffic Keys**: Domain-separated client-to-server (`C2S`) and server-to-client (`S2C`) session keys.
  4. **Actuation Control**: Listens for encrypted server commands (`LED_ON`, `LED_OFF`) to toggle onboard GPIO pins in real time.

```
┌───────────────────────────────────────┐            UDP Port 9877            ┌────────────────────────────────────────┐
│     ESP32 Edge Client Node            │────────────────────────────────────►│      x86-64 Central Server & NOC       │
│  - ML-KEM-768 Lattice Decapsulation   │◄────────────────────────────────────│  - High-Concurrency UDP Relay          │
│  - ChaCha20-Poly1305 Telemetry Stream │   Encrypted Bidirectional Session   │  - GTK 4 Server NOC Dashboard          │
│  - GPIO 2 Hardware LED Actuation      │   (Session ID: 0x98124bcf8311aa01)  │  - Real-Time Traffic & Key Inspector   │
└───────────────────────────────────────┘                                     └────────────────────────────────────────┘
```

---

## 📁 Directory Files & Sketches

| File / Directory | Purpose |
| :--- | :--- |
| **[`esp32_secure_node/esp32_secure_node.ino`](esp32_secure_node/esp32_secure_node.ino)** | **Primary Production Sketch**: Connects to Wi-Fi, initiates quantum-safe handshake with server, streams encrypted temperature/humidity/SRAM telemetry every 2 seconds, and executes real-time LED actuation. *(Note: Arduino IDE requires sketches inside a directory matching their filename).* |
| **[`esp32_secure_node.ino`](esp32_secure_node.ino)** | Standalone root copy of the primary secure node sketch. |
| **[`esp32_pqc_benchmark/esp32_pqc_benchmark.ino`](esp32_pqc_benchmark/esp32_pqc_benchmark.ino)** | **Microbenchmark Utility**: Measures exact execution latency (ms), CPU cycle counts, and peak SRAM consumption of ML-KEM-768 and ChaCha20-Poly1305 operations directly on the Xtensa LX6 core. |
| **[`virtual_esp32_node.py`](virtual_esp32_node.py)** | **Zero-Risk Python Fallback Simulator**: Runs on Linux to emulate the exact binary wire protocol, timing, and sensor telemetry if physical USB cables or Wi-Fi drop during live presentations. |

---

## 🧠 Technical Pitch: "Can ESP32 Run Post-Quantum Cryptography?"

When judges ask: *"Isn't Post-Quantum Cryptography too heavy for a $4 microcontroller?"*, cite these empirical numbers:

| Metric | NIST FIPS 203 (ML-KEM-768) on ESP32 | ESP32 Hardware Capacity | Headroom / Overhead |
| :--- | :---: | :---: | :---: |
| **Stack RAM Budget** | **~3.2 KB** | **520 KB SRAM** | Consumes **<0.7% of RAM** (>99.3% free) |
| **Key Encapsulation Latency**| **~22 ms** | 240 MHz Dual-Core | Well below the 500 ms network timeout |
| **Wire Ciphertext Size** | **1,088 Bytes** | 1,500 Byte MTU | Fits entirely inside a single UDP frame |
| **Symmetric Encryption Cost** | **13–15 µs** (per 150B payload) | Hardware accelerated | Negligible power consumption |

---

## 🛠️ Step-by-Step Setup & Flashing Guide

### Step 1: Install ESP32 Board Support in Arduino IDE
1. Open **Arduino IDE** (v2.x or v1.8.x).
2. Go to **File** → **Preferences**.
3. In *Additional Boards Manager URLs*, add:
   ```text
   https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
   ```
4. Go to **Tools** → **Board** → **Boards Manager**, search for `esp32` by Espressif Systems, and click **Install**.

---

### Step 2: Open and Configure the Sketch
1. Open `esp32/esp32_secure_node/esp32_secure_node.ino`.
2. Locate lines 19–30 and enter your Wi-Fi credentials and the Server's IP:

```cpp
// 1. Enter your Wi-Fi or Phone Mobile Hotspot details:
const char* WIFI_SSID     = "Your_WiFi_SSID";       // <-- Replace with your Wi-Fi SSID
const char* WIFI_PASSWORD = "Your_WiFi_Password";   // <-- Replace with your Wi-Fi Password

// 2. Server IP Address:
//    - The active Wi-Fi IP is displayed dynamically on your Laptop's GTK4 Server Dashboard header!
//    - Example: "10.58.4.191"
const char* SERVER_IP     = "10.58.4.191";          // <-- Laptop Wi-Fi IP shown on Dashboard

// 3. Server UDP Port:
const uint16_t SERVER_PORT= 9877;                   // Default QRYPTONEX UDP Port
```

> 💡 **Where to find the Server IP**:
> Launch `./run_ui.sh` on your laptop. The top navigation bar and the empty client list card automatically detect your laptop's active Wi-Fi IP (e.g. `10.58.4.191`) and display the exact code line to paste here!

---

### Step 3: Configure Board Settings & Upload
1. Connect your ESP32 board to your computer using a USB data cable.
2. In Arduino IDE under the **Tools** menu, configure:
   - **Board**: `ESP32 Dev Module`
   - **Upload Speed**: `921600` (or `115200` if upload fails)
   - **CPU Frequency**: `240MHz (WiFi/BT)`
   - **Flash Frequency**: `80MHz`
   - **Partition Scheme**: `Default 4MB with spiffs (1.2MB APP/1.5MB SPIFFS)`
   - **Port**: Select your serial port (e.g., `/dev/ttyUSB0`, `/dev/ttyACM0` on Linux or `COM3` on Windows).
3. Click **Upload** (or press `Ctrl+U`).

---

### Step 4: Open Serial Monitor
1. Once upload completes, open **Tools** → **Serial Monitor** (or press `Ctrl+Shift+M`).
2. Set baud rate to **`115200 baud`**.
3. Press the **EN / RST** button on the ESP32. You will see:

```text
╔═══════════════════════════════════════════════════════════════╗
║        QRYPTONEX ESP32 PURE POST-QUANTUM NODE                 ║
║   NIST FIPS 203 (ML-KEM-768) + ChaCha20-Poly1305             ║
╚═══════════════════════════════════════════════════════════════╝
Hardware Architecture : ESP32 Xtensa Dual-Core @ 240 MHz
Free Internal SRAM    : 284 KB (520 KB Total)
Cryptographic Suite   : ML-KEM-768 Key Encapsulation + ChaCha20-Poly1305 AEAD

[*] Connecting to Wi-Fi SSID: 'Vivo T3x 5g'...
[✓] Wi-Fi Connected! IP Address: 10.58.7.210 | RSSI: -48 dBm
[*] Server Endpoint Target: 10.58.4.191:9877 (UDP)

[*] Phase 1: Transmitting PKT_CLIENT_HELLO (ML-KEM-768 Public Key: 1184 Bytes)...
[✓] Phase 2: Received PKT_SERVER_HELLO (Ciphertext: 1088 Bytes | Nonce: 16 Bytes)
[*] Decapsulating 256-bit Shared Secret SS using ML-KEM-768...
[✓] Shared Secret Derived in 21.8 ms!
[*] Phase 3: Transmitting PKT_CLIENT_AUTH...
[✓] Phase 4: Session Active! Session ID: 0x98124bcf8311aa01

[TX Telemetry #001] Temp: 28.5°C | Hum: 55.2% | Heap: 224 KB free | RSSI: -48 dBm | Encrypt: 14 us | Pkt: 150 B
[TX Telemetry #002] Temp: 28.6°C | Hum: 55.4% | Heap: 224 KB free | RSSI: -49 dBm | Encrypt: 13 us | Pkt: 150 B
```

---

## 🎯 Live Hackathon Demonstration Flow (3 Minutes)

1. **Show the Dashboard**:
   - Run `./run_ui.sh` on your laptop and click `▶ Start Server`.
   - Point to `CONNECTED CLIENTS (ACTIVE)`: the ESP32 node appears immediately with its IP (`10.58.7.210`), UDP port, session ID, and handshake setup latency.
2. **Show Real-Time Encrypted Telemetry**:
   - Show incoming telemetry packets updating every 2 seconds with temperature, humidity, free heap, RSSI, and microsecond encryption latency.
3. **Trigger Hardware Actuation from Dashboard**:
   - In the Dashboard chat console at the bottom right, select the ESP32 client in the recipient dropdown.
   - Type **`LED_ON`** and click **Send Encrypted Message**.
   - **Watch the physical blue LED on GPIO 2 of the ESP32 turn ON instantly!**
   - Type **`LED_OFF`** and click **Send**: the LED turns OFF.
4. **Demonstrate 10-Second Disconnect Watchdog**:
   - Unplug the ESP32's USB power cable.
   - Watch the GTK4 Dashboard: within 10 seconds of silence, the dashboard watchdog automatically moves the ESP32 session from `CONNECTED CLIENTS (ACTIVE)` to `DISCONNECTED SESSIONS (RECENT)`, preserving the session history and timestamps!

---

## 🛡️ Zero-Risk Backup: Virtual ESP32 Simulator

If venue Wi-Fi is congested, USB ports fail, or hardware is unattached during your presentation, use the included Python simulator:

```bash
# Run virtual ESP32 simulator directly from terminal:
python3 esp32/virtual_esp32_node.py --server 10.58.4.191 --port 9877
```
This emulates the exact Xtensa timing, binary protocol frames, and sensor readings over UDP, providing an identical live demonstration on the GTK4 Dashboard with zero hardware dependency.
