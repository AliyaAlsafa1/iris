#!/usr/bin/env bash
set -euo pipefail

# Resolve the repo from this script's own location so the script works in any checkout.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Point DPDK_INSTALL at your DPDK 25.11 install prefix if it isn't in the default spot.
DPDK_INSTALL="${DPDK_INSTALL:-${HOME}/Workspace/dpdk-25.11/install_$(hostname)}"
DPDK_LIB="${DPDK_INSTALL}/lib/x86_64-linux-gnu"
LLVM_DIR="${LLVM_DIR:-/usr/lib/llvm-18}"

if [[ ! -d "${DPDK_LIB}/pkgconfig" ]]; then
    echo "No DPDK install found at ${DPDK_INSTALL} (looked for ${DPDK_LIB}/pkgconfig)." >&2
    echo "Set DPDK_INSTALL to your DPDK 25.11 install prefix and re-run." >&2
    exit 1
fi

cd "${REPO_ROOT}"

# Build env (used both for compile and run).
export IRIS_HOME="${REPO_ROOT}"
export DPDK_PATH="${DPDK_INSTALL}"
export DPDK_VERSION="25.11"
export LD_LIBRARY_PATH="${DPDK_LIB}"
export PKG_CONFIG_PATH="${DPDK_LIB}/pkgconfig"
export LIBCLANG_PATH="${LLVM_DIR}/lib"
export PATH="${LLVM_DIR}/bin:${PATH}"

CONFIG="${1:-configs/online-intel.toml}"

echo "==> Building basic example (release) ..."
cargo +nightly build --release -p basic --locked

echo "==> Running with config: ${CONFIG}"
sudo \
    LD_LIBRARY_PATH="${DPDK_LIB}" \
    IRIS_HOME="${IRIS_HOME}" \
    RUST_LOG="${RUST_LOG:-info}" \
    "${REPO_ROOT}/target/release/basic" --config "${CONFIG}"
