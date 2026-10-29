#!/usr/bin/env bash
# app.sh — Unified Launcher for QRYPTONEX Dual-Console Suite
# Launches both the Server Telemetry NOC UI and the Security/Attack Lab UI simultaneously.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "╔══════════════════════════════════════════════════════════════════════════════════╗"
echo "║          QRYPTONEX — Dual GTK 4 Cryptographic & Security Operations Suite        ║"
echo "╚══════════════════════════════════════════════════════════════════════════════════╝"

# Check GTK 4 dependencies
if ! pkg-config --exists gtk4 2>/dev/null; then
    echo "[!] Error: GTK 4 development library (libgtk-4-dev) is required."
    echo "    Please install: sudo apt update && sudo apt install -y libgtk-4-dev"
    exit 1
fi

# Build both applications
echo "==> [1/2] Building Server Telemetry NOC UI (ui/qhack_ui)..."
make -C ui all

echo "==> [2/2] Building Security & Attack Lab UI (security_lab/ui/attack_ui)..."
make -C security_lab/ui all

echo ""
echo "==> Launching Dual GTK 4 Interface Suite..."
echo "    [UI 1] Cryptographic Server NOC & Session Telemetry Console"
echo "    [UI 2] Real-Network Security Evaluation & Threat Injection Lab"
echo ""

# Launch Console 1: Server NOC Dashboard
./ui/qhack_ui "$@" &
PID_NOC=$!
echo "    • Started Server NOC UI (PID: $PID_NOC)"

# Brief stagger to let window manager position the windows smoothly
sleep 0.4

# Launch Console 2: Attack & Security Lab UI
./security_lab/ui/attack_ui "$@" &
PID_ATTACK=$!
echo "    • Started Security & Attack UI (PID: $PID_ATTACK)"

echo ""
echo "Both GTK 4 applications are running."
echo "Press Ctrl+C to terminate both interfaces cleanly."

# Trap cleanup signals to gracefully shut down both UIs
CLEANED=0
cleanup() {
    if [ "$CLEANED" -eq 1 ]; then
        return
    fi
    CLEANED=1
    echo ""
    echo "==> Shutting down dual UI suite..."
    kill "$PID_NOC" 2>/dev/null || true
    kill "$PID_ATTACK" 2>/dev/null || true
    wait "$PID_NOC" 2>/dev/null || true
    wait "$PID_ATTACK" 2>/dev/null || true
    echo "==> All interfaces closed."
}

trap cleanup INT TERM EXIT

# Wait for both processes
wait "$PID_NOC" "$PID_ATTACK" 2>/dev/null || true
