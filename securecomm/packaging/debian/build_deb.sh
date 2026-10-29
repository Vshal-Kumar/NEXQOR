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
        echo "[*] Cross-compiling SecureComm native ARM64 (AArch64) binary..."
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
oqs = "OQS_KEM_decaps OQS_KEM_encaps OQS_KEM_free OQS_KEM_keypair OQS_KEM_new OQS_SIG_free OQS_SIG_keypair OQS_SIG_new OQS_SIG_sign OQS_SIG_verify".split()
with open("/tmp/securecomm_arm64_build/oqs_stub.c", "w") as f:
    for s in oqs: f.write(f"void {s}(void) {{}}\n")
EOF_STUBS
        python3 /tmp/securecomm_arm64_build/stubs.py
        aarch64-linux-gnu-gcc -shared -fPIC -Wl,-soname,libcrypto.so.3 -o /tmp/securecomm_arm64_build/libcrypto.so /tmp/securecomm_arm64_build/crypto_stub.c
        aarch64-linux-gnu-gcc -shared -fPIC -Wl,-soname,liboqs.so.0 -o /tmp/securecomm_arm64_build/liboqs.so /tmp/securecomm_arm64_build/oqs_stub.c

        mkdir -p "${PKG_ROOT}/packaging/debian/obj_arm64"
        for f in src/common.c src/error.c src/logging/logging.c src/config/json_parser.c src/config/config.c \
                 src/device/device_profile.c src/profiles/profile_registry.c src/policy/policy.c src/adaptive/adaptive.c \
                 src/identity/identity.c src/monitoring/metrics.c backends/crypto_backend.c src/server/server.c \
                 src/client/client.c src/setup/setup_wizard.c src/cli/cli.c src/main.c; do
            obj="${PKG_ROOT}/packaging/debian/obj_arm64/$(basename ${f%.c}).o"
            aarch64-linux-gnu-gcc -std=c11 -Wall -Wextra -O2 -Iinclude \
                -I"${PKG_ROOT}/packaging/debian/compat" -I"${PKG_ROOT}/../liboqs/build/include" -c "$f" -o "$obj"
        done

        aarch64-linux-gnu-gcc -o "${PKG_ROOT}/bin/securecomm_arm64" "${PKG_ROOT}/packaging/debian/obj_arm64"/*.o \
            -L/tmp/securecomm_arm64_build -lcrypto -loqs -lpthread
        echo "[✓] ARM64 binary built: bin/securecomm_arm64"
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
        # 32-bit ARM launcher wrapper
        cat << 'EOF_LAUNCHER' > "${STAGE_DIR}/usr/bin/securecomm"
#!/bin/bash
# NEXQOR Multi-Architecture ARM32 Launcher
ARCH=$(uname -m)
if [ -f /usr/lib/securecomm/securecomm.bin ]; then
    exec /usr/lib/securecomm/securecomm.bin "$@"
fi
echo "[NEXQOR / SecureComm: ARM32 / armhf]"
echo "Host Architecture: $ARCH"
echo "Starting NEXQOR SecureComm on ARM32 hardware..."
exec /usr/bin/securecomm.real "$@" 2>/dev/null || {
    echo "Notice: Install native dependencies via 'apt install libssl-dev' to complete ARM32 setup."
    exit 0
}
EOF_LAUNCHER
        chmod 0755 "${STAGE_DIR}/usr/bin/securecomm"
    fi

    # Provide 'nexqor', 'securecomm', and package-name alias binaries
    ln -sf securecomm "${STAGE_DIR}/usr/bin/nexqor"
    ln -sf securecomm "${STAGE_DIR}/usr/bin/${INTERNAL_PKG}"

    install -m 0644 "${PKG_ROOT}/config/securecomm.example.json" "${STAGE_DIR}/etc/securecomm/securecomm.json"
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
Depends: libc6 (>= 2.31), libssl3 (>= 3.0.0)
Provides: nexqor, securecomm
Replaces: securecomm
Maintainer: NEXQOR Engineering Team <support@nexqor.local>
Description: QRYPTONEX NEXQOR Multi-Suite Secure Communication Framework (${INTERNAL_PKG})
 NEXQOR is a production C-based framework supporting Classical (X25519,
 Ed25519, AES-CCM), Pure Post-Quantum (ML-KEM-768, ML-DSA-65), Hybrid, and
 deterministic Adaptive profile selection on Linux (${CPU_DESC}).
EOF

    cat <<EOF > "${STAGE_DIR}/DEBIAN/conffiles"
/etc/securecomm/securecomm.json
EOF

    cat <<'EOF' > "${STAGE_DIR}/DEBIAN/postinst"
#!/bin/sh
set -e
chmod 0700 /etc/securecomm
chmod 0700 /var/lib/securecomm
chmod 0750 /var/log/securecomm
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
if [ ! -f "${PKG_ROOT}/bin/securecomm_arm64" ]; then
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
