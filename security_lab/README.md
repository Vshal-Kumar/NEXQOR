# QRYPTONEX Security Evaluation & Resilience Testing Framework (`security_lab`)

A unified, pure-C security evaluation engine for Linux designed to test and benchmark secure UDP communication stacks under real network conditions.

Evaluates three cryptographic implementations:
1. **Classical IoT Suite:** X25519 + Ed25519 + AES-128-CCM + SHA-256
2. **Hybrid Quantum-Safe Suite:** Dual X25519/ML-KEM-768 + Dual Ed25519/ML-DSA-65 + ChaCha20-Poly1305 + SHA-384
3. **Pure Post-Quantum Suite (NEXQOR):** ML-KEM-768 + ML-DSA-65 + ChaCha20-Poly1305 + SHAKE-256

---

## 1. Architecture & Directory Layout

```text
security_lab/
├── Makefile                 # Modular build system (all, test, clean, ui)
├── README.md                # Framework documentation and operational guide
├── INSPECTION_REPORT.md     # Codebase inspection and protocol mapping report
├── ui/                      # GTK 4 Pure-C Security & Attack Lab UI
│   ├── attack_ui.c / .h     # Graphical application logic and async worker thread
│   ├── main.c               # GTK 4 application entry point
│   ├── style.css            # Cyber dark theme with status badges
│   └── Makefile             # Dedicated GTK 4 build system
├── include/                 # Framework header definitions
│   ├── protocol_framer.h    # Shared 15-byte packet headers and framing
│   ├── safety_guard.h       # IP allowlisting, rate limits, audit logging
│   ├── suite_adapter.h      # Process spawning, IPC socket tap, UDP transceiver
│   ├── metrics.h            # Statistical metrics, P50/P95/P99 latency
│   ├── network_test.h       # User-space in-transit impairment gateway
│   ├── server_health.h      # Health probe and liveness tracking
│   ├── resource_monitor.h   # Memory RSS and CPU tracking via getrusage
│   ├── packet_observer.h    # Frame counting and type classification
│   ├── recovery_monitor.h   # Service resumption measurement
│   ├── report_writer.h      # JSON, CSV, JSONL, and Markdown exporters
│   └── test_engine.h        # CLI argument parser and test execution controller
├── src/                     # Core framework logic
│   ├── main.c               # CLI entry point
│   ├── test_engine.c        # Orchestration loop
│   ├── suite_adapter.c      # Suite process and IPC abstraction
│   ├── metrics.c            # Percentiles and result status tracking
│   ├── safety_guard.c       # Allowlist validation, signal traps, and rate limiters
│   └── protocol_framer.c    # Packet serialization and bounds validation
├── attacks/                 # Security scenario implementations
│   ├── network_resilience.c # Packet loss, delay/jitter, reordering, duplication, disconnect, MTU
│   ├── replay_test.c        # Replay window defenses (duplicate seq, stale seq, cross-session)
│   ├── packet_tampering.c   # AEAD bit-flipping, tag mutation, AAD header corruption
│   ├── authentication_test.c# Digital signature forgery and truncated credential rejection
│   ├── handshake_test.c     # Out-of-order frames, half-open handshake cleanup
│   ├── malformed_packet_test.c # 0-byte datagrams, truncated headers, fuzzing
│   ├── resource_stress.c    # Bounded concurrent client handshake load
│   └── session_isolation.c  # Cross-session datagram injection & blast radius
├── monitoring/              # Passive & active telemetry collectors
│   ├── packet_observer.c
│   ├── server_health.c
│   ├── resource_monitor.c
│   └── recovery_monitor.c
├── reporting/               # Structured report generators
│   ├── csv_writer.c         # metrics.csv export
│   ├── json_writer.c        # metadata.json, scenario_results.json, events.jsonl, summary.json
│   └── comparison_report.c  # Comprehensive report.md multi-suite comparison
├── tests/                   # Automated unit & safety regression tests
│   ├── test_safety.c        # Allowlist enforcement and signal trap tests
│   ├── test_packet_parser.c # Bounds checking and header serialization tests
│   └── test_metrics.c       # P50/P95/P99 latency calculation tests
└── results/                 # Timestamped run directories (results/run_YYYYMMDD_HHMMSS/)
```

---

## 2. Compilation Instructions

The framework is implemented in pure C (C11 standard) for Linux and compiles cleanly with zero external runtime dependencies beyond POSIX threads and standard C libraries:

```bash
# Build the test engine
make -C security_lab all

# Build and execute unit & safety regression tests
make -C security_lab test

# Build the GTK 4 Attack UI
make -C security_lab/ui all
```

---

## 3. GTK 4 Pure-C Security & Attack Lab Graphical Interface

The framework provides a dedicated, native **GTK 4 Pure-C graphical interface** (`security_lab/ui/attack_ui`) designed for visual network security testing:

### Visual Controls & Features:
- **Target Host Configuration:** Direct IP entry with 1-click lab presets (`127.0.0.1` Loopback, `10.58.4.191` LAN, `100.113.83.56` Mesh VPN), port entry, and topology selector (`Same LAN`, `Controlled Gateway`, `Private VPN`).
- **Cryptographic Suite Selector:** Dropdown to target `Pure Post-Quantum`, `Hybrid Quantum-Safe`, `Classical IoT`, or `All 3 Suites`.
- **15-Scenario Attack Selector:** Sidebar catalog for single-click execution of replay attacks, tampering, auth forgery, fuzzing, MTU fragmentation, or full evaluation.
- **Dry-Run Toggle Switch:** Safe simulation mode that audits and prints packet plans without emitting wire datagrams.
- **Process-Group Emergency Stop:** Instantly halts test execution via isolated `SIGINT`/`SIGTERM` process group signaling, cleanly aborting lingering child processes.
- **Live Monospace Terminal:** Real-time autoscrolling streaming console capturing datagrams, state transitions, and hex dumps.
- **Dynamic Resilience Matrix:** Parses generated reports into visual result cards displaying verified properties, suite badges, `PASS`/`FAIL` indicators, and evidentiary metrics.

### Launching the Graphical UI:

```bash
# Launch both Server NOC and Security Lab UIs simultaneously:
./app.sh

# Or launch only the Security Lab UI:
./run_attack_ui.sh
# or:
make run-attack-ui
```

---

## 4. Running Scenarios Against Real-Time Communication


The framework is designed to evaluate running clients and servers during live, real-time communication.

### Step 1: Start the Server (Terminal 1)
Start the desired server implementation:
```bash
# For Pure Post-Quantum:
cd pqc && ./server

# Or for Hybrid:
cd hybrid && ./server

# Or for Classical:
cd classical && ./server
```

### Step 2: Start Active Client Communication (Terminal 2)
Run the client on the same machine, across your LAN, or over VPN:
```bash
# Connect to server on LAN (e.g. 10.58.4.191) or localhost (127.0.0.1)
./client 127.0.0.1
```
Send messages or streaming telemetry in the client chat loop.

### Step 3: Run Active Security Tests (Terminal 3)
While the client and server are actively communicating, execute tests from `security_lab`:

```bash
# Test Replay Protection against active server:
./security_lab/security_lab --suite pqc --scenario replay --target 127.0.0.1

# Test AEAD Ciphertext & Header Tampering:
./security_lab/security_lab --suite pqc --scenario tampering --target 127.0.0.1

# Test Malformed Datagram Parser Robustness & Fuzzing:
./security_lab/security_lab --suite pqc --scenario malformed --target 127.0.0.1

# Test Authentication & Bogus Signature Rejection:
./security_lab/security_lab --suite pqc --scenario auth --target 127.0.0.1

# Test Handshake State Machine & Incomplete Handshake Cleanup:
./security_lab/security_lab --suite pqc --scenario handshake --target 127.0.0.1

# Test Concurrent Client Resource Stress (16 concurrent handshakes):
./security_lab/security_lab --suite pqc --scenario stress --target 127.0.0.1

# Test Cross-Session Isolation & Blast Radius:
./security_lab/security_lab --suite pqc --scenario isolation --target 127.0.0.1

# Test Path MTU Boundaries (512B to 4096B):
./security_lab/security_lab --suite pqc --scenario mtu --target 127.0.0.1
```

---

## 5. Running Through the In-Transit Impairment Gateway (Environment B)

To subject live client-to-server traffic to controlled network impairments (loss, delay, jitter, reordering, duplication, temporary disconnection):

1. **Server** runs on default port `9877` (or `9879` for hybrid).
2. **Impairment Gateway** listens on port `9880` and proxies traffic to the server.
3. Start the client pointing to the gateway port:
   ```bash
   SERVER_PORT=9880 ./client 127.0.0.1
   ```
4. Run the impairment scenario:
   ```bash
   # Introduce 15% packet loss:
   ./security_lab/security_lab --suite pqc --scenario loss

   # Introduce 30ms latency with ±15ms jitter:
   ./security_lab/security_lab --suite pqc --scenario delay_jitter

   # Introduce 25% out-of-order reordering:
   ./security_lab/security_lab --suite pqc --scenario reorder

   # Introduce 25% packet duplication:
   ./security_lab/security_lab --suite pqc --scenario duplication

   # Trigger a 2-second link blackhole:
   ./security_lab/security_lab --suite pqc --scenario disconnect
   ```

---

## 6. Command-Line Reference

```text
Usage: ./security_lab [options]

Core Options:
  -s, --suite <name>        Suite: classical, hybrid, pqc, or all
  -c, --scenario <name>     Scenario name or 'all'
  -t, --target <ip>         Target IP (Default: 127.0.0.1)
  -p, --port <port>         Target port (Default: suite standard)
  -e, --environment <name>  Environment: LAN, Gateway, or VPN
  -d, --dry-run             Audit plan without sending packets
  -n, --trials <count>      Number of baseline repetitions (Default: 3)
  --list-suites             List supported suites
  --list-scenarios          List supported test scenarios
  --results [latest]        Show path to latest generated report
```

---

## 7. Output Artifacts


Every test execution automatically generates a complete artifact bundle under `security_lab/results/<run_id>/`:
- `report.md` — Full Markdown comparison report with executive tables, security analysis, and performance metrics.
- `scenario_results.json` — Detailed JSON verdict, rationale, and evidence for every scenario.
- `metadata.json` — Target host, network interface, OS version, compiler flags, and run environment.
- `metrics.csv` — Machine-readable CSV with P50, P95, P99 latencies, packet delivery, and memory RSS.
- `events.jsonl` — High-resolution JSON Lines timeline of every test frame transmitted and observed.
- `audit.log` — Security audit trail logging start/stop events and safety guard validations.
