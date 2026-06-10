#!/usr/bin/env bash
set -euo pipefail

CONFIG="${1:-configs/online-intel.toml}"

HOSTNAME="$(hostname)"
REPO_ROOT="/etinfo/users2/tyunyayev/Workspace/iris"
DPDK_INSTALL="/etinfo/users2/tyunyayev/Workspace/dpdk-25.11/install_${HOSTNAME}"
DPDK_LIB="${DPDK_INSTALL}/lib/x86_64-linux-gnu"

echo "==> Running with config: ${CONFIG}"
sudo \
    LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-${DPDK_LIB}}" \
    IRIS_HOME="${IRIS_HOME:-${REPO_ROOT}}" \
    RUST_LOG="${RUST_LOG:-info}" \
    "${REPO_ROOT}/target/release/tls_quic_drop" --config "${CONFIG}"
