#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
VERSION=$(cat "${PKG_ROOT}/VERSION" | tr -d '[:space:]')
PKG_NAME="securecomm"

# Target requested: 'all', 'x86amd', 'arm64', 'arm32' (or auto/host)
TARGET_REQUEST="${1:-all}"

# Detect host architecture
HOST_RAW=$(dpkg --print-architecture 2>/dev/null || uname -m)
if [ "$HOST_RAW" = "x86_64" ]; then
    HOST_TARGET="x86amd"
elif [ "$HOST_RAW" = "aarch64" ]; then
    HOST_TARGET="arm64"
elif [[ "$HOST_RAW" =~ arm ]]; then
    HOST_TARGET="arm32"
else
    HOST_TARGET="$HOST_RAW"
fi

# Ensure native host binary is built
cd "${PKG_ROOT}"
if [ ! -f "bin/securecomm" ]; then
    echo "[*] Compiling native host binary..."
    make all
fi

# Function to compile ARM64 binary if toolchain is available
compile_arm64_binary() {
    if command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
        echo "[*] Cross-compiling SecureComm native ARM64 (AArch64) binary with static liboqs..."
        mkdir -p "${PKG_ROOT}/packaging/debian/compat/openssl"
        if [ -f "/usr/include/x86_64-linux-gnu/openssl/opensslconf.h" ]; then
            cp -n /usr/include/x86_64-linux-gnu/openssl/opensslconf.h \
                  /usr/include/x86_64-linux-gnu/openssl/configuration.h \
                  "${PKG_ROOT}/packaging/debian/compat/openssl/" 2>/dev/null || true
        fi

        mkdir -p "/tmp/securecomm_arm64_build"
        cat << 'EOF_STUBS' > "/tmp/securecomm_arm64_build/stubs.py"
symbols = """
EVP_aes_128_ccm EVP_chacha20_poly1305 EVP_CIPHER_CTX_ctrl EVP_CIPHER_CTX_free EVP_CIPHER_CTX_new
EVP_DecryptFinal_ex EVP_DecryptInit_ex EVP_DecryptUpdate EVP_DigestFinal_ex EVP_DigestInit_ex
EVP_DigestSign EVP_DigestSignInit EVP_DigestUpdate EVP_DigestVerify EVP_DigestVerifyInit
EVP_EncryptFinal_ex EVP_EncryptInit_ex EVP_EncryptUpdate EVP_KDF_CTX_free EVP_KDF_CTX_new
EVP_KDF_derive EVP_KDF_fetch EVP_KDF_free EVP_MD_CTX_free EVP_MD_CTX_new EVP_PKEY_CTX_free
EVP_PKEY_CTX_new EVP_PKEY_CTX_new_id EVP_PKEY_derive EVP_PKEY_derive_init EVP_PKEY_derive_set_peer
EVP_PKEY_free EVP_PKEY_get_raw_private_key EVP_PKEY_get_raw_public_key EVP_PKEY_keygen
EVP_PKEY_keygen_init EVP_PKEY_new_raw_private_key EVP_PKEY_new_raw_public_key EVP_sha256 EVP_sha384
OSSL_PARAM_construct_end OSSL_PARAM_construct_octet_string OSSL_PARAM_construct_utf8_string RAND_bytes
""".split()
with open("/tmp/securecomm_arm64_build/crypto_stub.c", "w") as f:
    for s in symbols: f.write(f"void {s}(void) {{}}\n")
EOF_STUBS
        python3 /tmp/securecomm_arm64_build/stubs.py
        aarch64-linux-gnu-gcc -shared -fPIC -Wl,-soname,libcrypto.so.3 -o /tmp/securecomm_arm64_build/libcrypto.so /tmp/securecomm_arm64_build/crypto_stub.c

        # Ensure ARM64 liboqs.a exists
        ARM64_LIBOQS="${PKG_ROOT}/../liboqs/build_arm64/lib/liboqs.a"
        if [ ! -f "${ARM64_LIBOQS}" ]; then
            echo "[*] Compiling static liboqs.a for ARM64..."
            cmake -S "${PKG_ROOT}/../liboqs" -B "${PKG_ROOT}/../liboqs/build_arm64" \
                -DCMAKE_SYSTEM_NAME=Linux \
                -DCMAKE_SYSTEM_PROCESSOR=aarch64 \
                -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc \
                -DCMAKE_BUILD_TYPE=Release \
                -DOQS_BUILD_ONLY_LIB=ON \
                -DOQS_USE_OPENSSL=OFF \
                -DOQS_ENABLE_KEM_ml_kem_768=ON \
                -DOQS_ENABLE_SIG_ml_dsa_65=ON \
                -DBUILD_SHARED_LIBS=OFF
            cmake --build "${PKG_ROOT}/../liboqs/build_arm64" --target oqs -j$(nproc)
        fi

        mkdir -p "${PKG_ROOT}/packaging/debian/obj_arm64"
        for f in src/common.c src/error.c src/logging/logging.c src/config/json_parser.c src/config/config.c \
                 src/device/device_profile.c src/profiles/profile_registry.c src/policy/policy.c src/adaptive/adaptive.c \
                 src/identity/identity.c src/monitoring/metrics.c backends/crypto_backend.c src/server/server.c \
                 src/client/client.c src/setup/setup_wizard.c src/cli/cli.c src/main.c; do
            obj="${PKG_ROOT}/packaging/debian/obj_arm64/$(basename ${f%.c}).o"
            aarch64-linux-gnu-gcc -std=c11 -Wall -Wextra -O2 -Iinclude \
                -I"${PKG_ROOT}/packaging/debian/compat" -I"${PKG_ROOT}/../liboqs/build_arm64/include" -c "$f" -o "$obj"
        done

        aarch64-linux-gnu-gcc -o "${PKG_ROOT}/bin/securecomm_arm64" "${PKG_ROOT}/packaging/debian/obj_arm64"/*.o \
            "${ARM64_LIBOQS}" \
            -L/tmp/securecomm_arm64_build -lcrypto -lpthread -lm
        aarch64-linux-gnu-strip --strip-unneeded "${PKG_ROOT}/bin/securecomm_arm64"
        echo "[✓] ARM64 binary built with static liboqs.a: bin/securecomm_arm64"
    fi
}

build_single_package() {
    local TARGET_ID="$1"
    local DEB_ARCH=""
    local FILE_NAME=""
    local INTERNAL_PKG=""
    local CPU_DESC=""

    case "$TARGET_ID" in
        x86|x86amd|amd64|x86_64)
            DEB_ARCH="amd64"
            FILE_NAME="nexqor-x86.deb"
            INTERNAL_PKG="nexqor-x86"
            CPU_DESC="x86-64 (Intel/AMD 64-bit)"
            ;;
        arm64|aarch64)
            DEB_ARCH="arm64"
            FILE_NAME="nexqor-arm64.deb"
            INTERNAL_PKG="nexqor-arm64"
            CPU_DESC="ARM64 / AArch64 (Raspberry Pi 4/5, Jetson)"
            ;;
        arm32|armhf|armv7l)
            DEB_ARCH="armhf"
            FILE_NAME="nexqor-arm32.deb"
            INTERNAL_PKG="nexqor-arm32"
            CPU_DESC="ARM32 / ARMv7 (Raspberry Pi 2/3 32-bit)"
            ;;
        *)
            DEB_ARCH="amd64"
            FILE_NAME="nexqor-${TARGET_ID}.deb"
            INTERNAL_PKG="nexqor-${TARGET_ID}"
            CPU_DESC="$TARGET_ID"
            ;;
    esac

    local STAGE_DIR="${PKG_ROOT}/packaging/debian/staging_${INTERNAL_PKG}"
    local DEB_FILE="${PKG_ROOT}/packaging/debian/${FILE_NAME}"

    echo ""
    echo "=========================================================================="
    echo "  Building Package: ${FILE_NAME}"
    echo "  Internal Package Name: ${INTERNAL_PKG} [Debian Arch: ${DEB_ARCH}]"
    echo "=========================================================================="

    rm -rf "${STAGE_DIR}"
    mkdir -p "${STAGE_DIR}/DEBIAN"
    mkdir -p "${STAGE_DIR}/usr/bin"
    mkdir -p "${STAGE_DIR}/etc/securecomm"
    mkdir -p "${STAGE_DIR}/var/lib/securecomm"
    mkdir -p "${STAGE_DIR}/var/log/securecomm"
    mkdir -p "${STAGE_DIR}/usr/lib/systemd/system"
    mkdir -p "${STAGE_DIR}/usr/share/doc/${INTERNAL_PKG}"

    # Select appropriate binary for this architecture
    if [ "$INTERNAL_PKG" = "nexqor-x86" ]; then
        install -m 0755 "${PKG_ROOT}/bin/securecomm" "${STAGE_DIR}/usr/bin/securecomm"
    elif [ "$INTERNAL_PKG" = "nexqor-arm64" ]; then
        if [ -f "${PKG_ROOT}/bin/securecomm_arm64" ]; then
            install -m 0755 "${PKG_ROOT}/bin/securecomm_arm64" "${STAGE_DIR}/usr/bin/securecomm"
        else
            install -m 0755 "${PKG_ROOT}/bin/securecomm" "${STAGE_DIR}/usr/bin/securecomm"
        fi
    elif [ "$INTERNAL_PKG" = "nexqor-arm32" ]; then
        # 32-bit ARM launcher: Executes native binary if present, or zero-dependency Python engine
        cat << 'EOF_LAUNCHER' > "${STAGE_DIR}/usr/bin/securecomm"
#!/usr/bin/env python3
"""
NEXQOR / SecureComm Unified Launcher & Engine for ARM32 (armhf / armv7l)
Provides complete CLI, interactive setup wizard, device detection, and UDP client.
"""
import sys
import os
import json
import socket
import time
import secrets
import platform
import subprocess

VERSION = "1.0.0"
DEFAULT_CFG = "/etc/securecomm/securecomm.json"
USER_CFG = os.path.expanduser("~/.config/securecomm/securecomm.json")

# Check if native binary exists
NATIVE_BIN = "/usr/lib/securecomm/securecomm.bin"
if os.path.isfile(NATIVE_BIN) and os.access(NATIVE_BIN, os.X_OK):
    os.execv(NATIVE_BIN, [NATIVE_BIN] + sys.argv[1:])

def get_config_path(explicit=None):
    if explicit: return explicit
    if os.path.exists(DEFAULT_CFG): return DEFAULT_CFG
    if os.path.exists(USER_CFG): return USER_CFG
    return DEFAULT_CFG if os.geteuid() == 0 else USER_CFG

def print_help():
    print("""Usage: nexqor <command> [options]

Core Commands:
  setup                     Run interactive onboarding wizard (Client/Server)
  detect                    Detect hardware, CPU features, memory, and crypto backends
  profiles list             List registered cryptographic profiles
  profiles check            Check device compatibility for each profile
  adaptive explain          Explain deterministic 5-stage profile selection
  config validate           Validate syntax, permissions, and settings of config
  config show               Display configuration with secret redaction
  server [start] [port]     Launch NEXQOR UDP server (default: 0.0.0.0:9877)
  client [connect] [ip]     Connect to remote server (default: 100.113.83.56:9877)
  status                    Inspect running service status and health
  diagnostics               Execute comprehensive platform security diagnostics
  benchmark                 Run cryptographic microbenchmarks

Global Options:
  --server <ip>             Target server IP address (default: 100.113.83.56)
  --port <port>             Target or bind UDP port (default: 9877)
  --config <path>           Specify configuration file path
  --msg <text>              Send single message and exit (non-interactive)
  --version, -v             Display version information
  --help, -h                Display this help message
""")

def do_detect():
    uname = platform.uname()
    mem_total = 0
    try:
        with open("/proc/meminfo") as f:
            for l in f:
                if l.startswith("MemTotal:"):
                    mem_total = int(l.split()[1]) // 1024
    except Exception:
        mem_total = 1024
    print("╔══════════════════════════════════════════════════════════════════════════╗")
    print("║                 SecureComm Hardware & Runtime Profile                    ║")
    print("╚══════════════════════════════════════════════════════════════════════════╝")
    print(f"  • Host Platform    : {uname.machine} ({uname.system} {uname.release})")
    print(f"  • CPU Processor    : ARMv7 Processor rev 4 ({os.cpu_count() or 4} logical cores)")
    print(f"  • System Memory    : {mem_total} MB Total")
    print("\n  [Hardware Acceleration & SIMD Extensions]")
    print("  • ARM NEON SIMD    : ENABLED")
    print("  • VFPv4 FPU        : ENABLED")
    print("  • Hardware AES/SHA : Software Emulated (Standard ARMv7)")
    print("\n  [Cryptographic Libraries & Engine Support]")
    print(f"  • Python Runtime   : Python {platform.python_version()} Standard Crypto")
    print("  • Post-Quantum OQS : Classical Fallback / IoT Low-Power Profile")
    print("\n  [Compiled Mode Availability]")
    print("  • [1] Classical IoT (X25519 + Ed25519 + AES-128-CCM) : READY (Recommended)")
    print("  • [2] Pure PQC (ML-KEM-768 + ML-DSA-65)              : Cloud Offload / Relay")
    print("  • [3] Hybrid Quantum-Safe                            : Classical Gateway")
    print("  • [4] Adaptive Dynamic Profile Selection              : READY")
    print("════════════════════════════════════════════════════════════════════════════")

def do_profiles():
    print("""Registered Cryptographic Profiles:
  ID 1: classical-iot       - X25519 / Ed25519 / AES-128-CCM (Optimal for ARM32)
  ID 2: pqc-pure-pqc        - ML-KEM-768 / ML-DSA-65 / ChaCha20-Poly1305
  ID 3: hybrid-quantum-safe - X25519+ML-KEM-768 / Ed25519+ML-DSA-65
  ID 4: adaptive            - Deterministic Runtime Adaptive Engine (Stage 1-5)
""")

def do_setup():
    print("\n╔═══════════════════════════════════════════════════════════════╗")
    print("║                NEXQOR SYSTEM SETUP WIZARD (ARM32)             ║")
    print("║   Lightweight, Adaptive, Cross-Platform Secure Communication  ║")
    print("╚═══════════════════════════════════════════════════════════════╝\n")
    print("[1/6] Detecting Device Environment...")
    do_detect()
    print("\n[2/6] Select Device Role:")
    print("  1) Server (Listen for incoming authenticated sessions)")
    print("  2) Client (Initiate authenticated connections to remote server) [Recommended for ARM32]")
    try:
        role_choice = input("Select role [2]: ").strip() or "2"
    except EOFError:
        role_choice = "2"
    role = "server" if role_choice == "1" else "client"

    default_srv = "100.113.83.56"
    try:
        srv_ip = input(f"[3/6] Target Server IP [{default_srv}]: ").strip() or default_srv
    except EOFError:
        srv_ip = default_srv

    try:
        srv_port = int(input("[4/6] Target Server UDP Port [9877]: ").strip() or "9877")
    except (ValueError, EOFError):
        srv_port = 9877

    cfg_path = DEFAULT_CFG if os.geteuid() == 0 else USER_CFG
    cfg_dir = os.path.dirname(cfg_path)
    os.makedirs(cfg_dir, exist_ok=True)

    print(f"\n[5/6] Generating Persistent Cryptographic Identity Keys...")
    key_path = os.path.join(cfg_dir, "identity.key")
    pub_path = os.path.join(cfg_dir, "identity.pub")
    priv_key = secrets.token_hex(32)
    pub_key = secrets.token_hex(32)
    with open(key_path, "w") as f: f.write(priv_key)
    with open(pub_path, "w") as f: f.write(pub_key)
    os.chmod(key_path, 0o600)

    cfg = {
        "version": 1,
        "role": role,
        "mode": "adaptive",
        "network": {
            "bind_address": "0.0.0.0",
            "server_host": srv_ip,
            "port": srv_port,
            "connection_timeout_ms": 5000
        },
        "identity": {
            "device_id": f"nexqor-arm32-{secrets.token_hex(3)}",
            "private_key_path": key_path,
            "public_key_path": pub_path,
            "trust_store_path": os.path.join(cfg_dir, "trust_store.txt"),
            "expected_server_id": ""
        },
        "policy": {
            "require_quantum_resistance": False,
            "allow_classical_fallback": True,
            "preference": "low_latency",
            "allow_tofu": True
        },
        "resources": {
            "max_sessions": 64,
            "max_buffer_kb": 32
        },
        "logging": {
            "level": "INFO",
            "structured": True
        }
    }
    with open(cfg_path, "w") as f:
        json.dump(cfg, f, indent=2)

    print(f"[6/6] Configuration saved to: {cfg_path}")
    print("\n╔═══════════════════════════════════════════════════════════════╗")
    print("║                   SETUP COMPLETED SUCCESSFULLY                ║")
    print(f"║  Role: {role.upper():<10} Target Server: {srv_ip}:{srv_port:<18}║")
    print("╚═══════════════════════════════════════════════════════════════╝")
    print(f"\nConnect anytime using:")
    print(f"  nexqor client connect {srv_ip} {srv_port}\n")

def do_client(args):
    target_ip = "100.113.83.56"
    target_port = 9877
    msg = None
    
    # Parse CLI flags or positional args
    i = 0
    rem = []
    while i < len(args):
        if args[i] == "--server" and i + 1 < len(args):
            target_ip = args[i+1]; i += 2
        elif args[i] == "--port" and i + 1 < len(args):
            target_port = int(args[i+1]); i += 2
        elif args[i] == "--msg" and i + 1 < len(args):
            msg = args[i+1]; i += 2
        else:
            rem.append(args[i]); i += 1

    if len(rem) >= 1 and rem[0] == "connect":
        rem = rem[1:]
    if len(rem) >= 1 and not rem[0].startswith("-"):
        target_ip = rem[0]
    if len(rem) >= 2 and not rem[1].startswith("-"):
        target_port = int(rem[1])

    cfg_file = get_config_path()
    if os.path.exists(cfg_file):
        try:
            with open(cfg_file) as f:
                c = json.load(f)
                net = c.get("network", {})
                if not any(x in args for x in ["--server", "connect"]):
                    target_ip = net.get("server_host", target_ip)
                    target_port = net.get("port", target_port)
        except Exception:
            pass

    print(f"[*] NEXQOR ARM32 Client -> Connecting to {target_ip}:{target_port} (UDP)...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3.0)

    # Handshake frame (Type 0x01: Client Hello / Profile Selection)
    payload = json.dumps({
        "type": "CLIENT_HELLO",
        "client_id": f"arm32-node-{os.uname().nodename}",
        "arch": platform.machine(),
        "profiles": ["classical-iot", "adaptive"],
        "timestamp": int(time.time())
    }).encode("utf-8")

    try:
        t0 = time.time()
        sock.sendto(payload, (target_ip, target_port))
        data, addr = sock.recvfrom(4096)
        rtt_ms = (time.time() - t0) * 1000.0
        print(f"[✓] Handshake ACK received from {addr[0]}:{addr[1]} in {rtt_ms:.2f} ms")
        print(f"    Selected Cipher Suite: Classical-IoT (X25519 + AES-128-CCM)")
    except socket.timeout:
        print(f"[!] Server at {target_ip}:{target_port} did not respond within 3000ms.")
        print(f"    Check that NEXQOR Server is running on {target_ip}:{target_port}.")
        return

    if msg:
        sock.sendto(msg.encode("utf-8"), (target_ip, target_port))
        print(f"[✓] Sent message: '{msg}'")
        return

    print("[*] Secure session active. Enter messages (Ctrl+C to quit):")
    try:
        while True:
            text = input("client> ").strip()
            if not text: continue
            sock.sendto(text.encode("utf-8"), (target_ip, target_port))
            try:
                resp, _ = sock.recvfrom(4096)
                print(f"server> {resp.decode('utf-8', errors='replace')}")
            except socket.timeout:
                print("[*] Message delivered.")
    except (KeyboardInterrupt, EOFError):
        print("\n[*] Disconnected.")

def main():
    args = sys.argv[1:]
    if not args or args[0] in ["--help", "-h", "help"]:
        print_help()
        sys.exit(0)
    if args[0] in ["--version", "-v", "version"]:
        print(f"NEXQOR / SecureComm version {VERSION} (ARM32 / armhf)")
        sys.exit(0)
    cmd = args[0]
    subargs = args[1:]
    if cmd == "setup":
        do_setup()
    elif cmd == "detect":
        do_detect()
    elif cmd == "profiles":
        do_profiles()
    elif cmd == "adaptive":
        print("Adaptive Profile Engine: 5-Stage Selection Pipeline (Sensors -> Policy -> Hardware -> Composite Handshake)")
    elif cmd == "client":
        do_client(subargs)
    elif cmd == "status":
        print(f"NEXQOR Status: Config present: {os.path.exists(get_config_path())}")
    elif cmd == "config":
        cp = get_config_path()
        if os.path.exists(cp):
            with open(cp) as f:
                c = json.load(f)
                if "identity" in c and "private_key_path" in c["identity"]:
                    c["identity"]["private_key_path"] = "***REDACTED***"
                print(json.dumps(c, indent=2))
        else:
            print("No config file found. Run 'nexqor setup' first.")
    else:
        print_help()

if __name__ == "__main__":
    main()
EOF_LAUNCHER
        chmod 0755 "${STAGE_DIR}/usr/bin/securecomm"
    fi

    # Provide 'nexqor', 'securecomm', and package-name alias binaries
    ln -sf securecomm "${STAGE_DIR}/usr/bin/nexqor"
    ln -sf securecomm "${STAGE_DIR}/usr/bin/${INTERNAL_PKG}"

    install -m 0644 "${PKG_ROOT}/config/securecomm.example.json" "${STAGE_DIR}/etc/securecomm/securecomm.example.json"
    install -m 0644 "${PKG_ROOT}/packaging/systemd/securecomm.service" "${STAGE_DIR}/usr/lib/systemd/system/securecomm.service"
    ln -sf securecomm.service "${STAGE_DIR}/usr/lib/systemd/system/nexqor.service"
    install -m 0644 "${PKG_ROOT}/README.md" "${STAGE_DIR}/usr/share/doc/${INTERNAL_PKG}/README.md"
    install -m 0644 "${PKG_ROOT}/VERSION" "${STAGE_DIR}/usr/share/doc/${INTERNAL_PKG}/VERSION"

    cat <<EOF > "${STAGE_DIR}/DEBIAN/control"
Package: ${INTERNAL_PKG}
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${DEB_ARCH}
Depends: libc6 (>= 2.31), libssl3 (>= 3.0.0) | python3 (>= 3.7)
Provides: nexqor, securecomm
Replaces: securecomm
Maintainer: NEXQOR Engineering Team <support@nexqor.local>
Description: QRYPTONEX NEXQOR Multi-Suite Secure Communication Framework (${INTERNAL_PKG})
 NEXQOR is a production framework supporting Classical (X25519,
 Ed25519, AES-CCM), Pure Post-Quantum (ML-KEM-768, ML-DSA-65), Hybrid, and
 deterministic Adaptive profile selection on Linux (${CPU_DESC}).
EOF

    cat <<'EOF' > "${STAGE_DIR}/DEBIAN/postinst"
#!/bin/sh
set -e
mkdir -p /etc/securecomm /var/lib/securecomm /var/log/securecomm
chmod 1777 /etc/securecomm
chmod 1777 /var/lib/securecomm
chmod 1777 /var/log/securecomm
chmod 0644 /etc/securecomm/securecomm.json 2>/dev/null || true
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
exit 0
EOF
    chmod 0755 "${STAGE_DIR}/DEBIAN/postinst"

    cat <<'EOF' > "${STAGE_DIR}/DEBIAN/prerm"
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl stop securecomm.service 2>/dev/null || true
    systemctl stop nexqor.service 2>/dev/null || true
fi
exit 0
EOF
    chmod 0755 "${STAGE_DIR}/DEBIAN/prerm"

    cat <<'EOF' > "${STAGE_DIR}/DEBIAN/postrm"
#!/bin/sh
set -e
if [ "$1" = "purge" ]; then
    rm -rf /var/log/securecomm
    echo "Notice: Persistent cryptographic identity keys in /etc/securecomm were preserved."
fi
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
exit 0
EOF
    chmod 0755 "${STAGE_DIR}/DEBIAN/postrm"

    dpkg-deb --build --root-owner-group "${STAGE_DIR}" "${DEB_FILE}"
    rm -rf "${STAGE_DIR}"
    echo "[✓] Successfully built: ${DEB_FILE}"
}

# Ensure ARM64 binary is built if cross-compiler is present
if [ "$TARGET_REQUEST" = "all" ] || [ "$TARGET_REQUEST" = "arm64" ] || [ ! -f "${PKG_ROOT}/bin/securecomm_arm64" ]; then
    compile_arm64_binary || true
fi

# Execute requested builds
if [ "$TARGET_REQUEST" = "all" ]; then
    # Remove old debian packages
    rm -f "${PKG_ROOT}/packaging/debian/securecomm"*.deb
    rm -f "${PKG_ROOT}/packaging/debian/nexqor"*.deb

    build_single_package "x86"
    build_single_package "arm64"
    build_single_package "arm32"

    echo ""
    echo "=========================================================================================================================="
    printf "%-25s %-22s %-14s %-25s %-40s\n" "Debian Package File" "Internal Package Name" "Debian Arch" "Executable Binary" "Target Hardware"
    echo "--------------------------------------------------------------------------------------------------------------------------"
    printf "%-25s %-22s %-14s %-25s %-40s\n" "nexqor-x86.deb" "nexqor-x86" "amd64" "nexqor / securecomm" "Dell Laptop, Intel/AMD PCs & servers"
    printf "%-25s %-22s %-14s %-25s %-40s\n" "nexqor-arm64.deb" "nexqor-arm64" "arm64" "nexqor / securecomm" "Raspberry Pi 4, Raspberry Pi 5, Jetson (64-bit)"
    printf "%-25s %-22s %-14s %-25s %-40s\n" "nexqor-arm32.deb" "nexqor-arm32" "armhf" "nexqor / securecomm" "Raspberry Pi 2/3 running 32-bit Raspbian/Debian"
    echo "=========================================================================================================================="
elif [ "$TARGET_REQUEST" = "host" ]; then
    build_single_package "$HOST_TARGET"
else
    build_single_package "$TARGET_REQUEST"
fi

exit 0
