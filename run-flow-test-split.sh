#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="/etinfo/users2/tyunyayev/Workspace/iris"
DPDK_INSTALL="/etinfo/users2/tyunyayev/Workspace/packet-splitting/dpdk/install_$(hostname)"
DPDK_LIB="${DPDK_INSTALL}/lib/x86_64-linux-gnu"

cd "${REPO_ROOT}"

export IRIS_HOME="${REPO_ROOT}"
export DPDK_PATH="${DPDK_INSTALL}"
export DPDK_VERSION="24.11"
export LD_LIBRARY_PATH="${DPDK_LIB}"
export PKG_CONFIG_PATH="${DPDK_LIB}/pkgconfig"
export LIBCLANG_PATH="/usr/lib/llvm-18/lib"
export PATH="/usr/lib/llvm-18/bin:${PATH}"

CONFIG="${1:-configs/online-nikita.toml}"
shift || true

echo "==> Building flow_test example (release) ..."
cargo +nightly build --release -p flow_test --offline

echo "==> Running with config: ${CONFIG}"
echo "==> RUST_LOG=${RUST_LOG:-info}"
sudo env \
    LD_LIBRARY_PATH="${DPDK_LIB}" \
    IRIS_HOME="${IRIS_HOME}" \
    RUST_LOG="${RUST_LOG:-info}" \
    "${REPO_ROOT}/target/release/flow_test" --config "${CONFIG}" --model model.txt"$@"
