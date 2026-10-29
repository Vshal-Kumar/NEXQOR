#!/bin/bash
# run_ui.sh — Launch the unified pure C GTK4 QRYPTONEX Server & Telemetry Dashboard

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if ! pkg-config --exists gtk4 2>/dev/null; then
    echo "=========================================================================="
    echo " [QRYPTONEX Dashboard] GTK 4 Development Package Required"
    echo "=========================================================================="
    echo " The GTK 4 development package 'libgtk-4-dev' is required to build the"
    echo " pure C GTK 4 server dashboard."
    echo ""
    echo " Please install it using:"
    echo "    sudo apt update && sudo apt install -y libgtk-4-dev"
    echo "=========================================================================="
    exit 1
fi

make -C ui all

echo "[run_ui] Launching QRYPTONEX GTK 4 Dashboard..."
exec ./ui/qhack_ui "$@"
