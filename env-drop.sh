# Source this file to set up the environment for tls_quic_drop
# Usage: source env-drop.sh

REPO_ROOT="/etinfo/users2/tyunyayev/Workspace/iris"
DPDK_INSTALL="/etinfo/users2/tyunyayev/Workspace/dpdk-25.11/install_$(hostname)"
DPDK_LIB="${DPDK_INSTALL}/lib/x86_64-linux-gnu"

cd "${REPO_ROOT}"

export IRIS_HOME="${REPO_ROOT}"
export DPDK_PATH="${DPDK_INSTALL}"
export DPDK_VERSION="25.11"
export LD_LIBRARY_PATH="${DPDK_LIB}"
export PKG_CONFIG_PATH="${DPDK_LIB}/pkgconfig"
# Pick the newest installed LLVM (hosts vary: some have llvm-18, others 17/14).
LLVM_DIR="$(ls -d /usr/lib/llvm-* 2>/dev/null | sort -V | tail -1)"
export LIBCLANG_PATH="${LLVM_DIR}/lib"
export PATH="${LLVM_DIR}/bin:${PATH}"

build() {
    echo "==> Building tls_quic_drop example (release) ..."
    cargo +nightly build --release -p tls_quic_drop
}
