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
export LIBCLANG_PATH="/usr/lib/llvm-18/lib"
export PATH="/usr/lib/llvm-18/bin:${PATH}"

build() {
    echo "==> Building tls_quic_drop example (release) ..."
    cargo +nightly build --release -p tls_quic_drop
}
