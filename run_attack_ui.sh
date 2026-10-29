#!/usr/bin/env bash
# run_attack_ui.sh — Launch the GTK 4 Security & Attack Lab Interface
set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Building GTK 4 Security & Attack Lab UI..."
make -C "$ROOT_DIR/security_lab/ui" all

echo "==> Launching GTK 4 Security Lab UI..."
exec "$ROOT_DIR/security_lab/ui/attack_ui" "$@"
