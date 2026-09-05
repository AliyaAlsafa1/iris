#!/usr/bin/env bash
# Build the evaluation binaries with the DPDK build environment.
#
#   scripts/build.sh [cargo args...]     # default: -p hw_assist_eval
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export IRIS_HOME="${REPO_ROOT}"
export DPDK_PATH="/usr/local"
export DPDK_VERSION="24.11"
export LD_LIBRARY_PATH="${DPDK_PATH}/lib/x86_64-linux-gnu:${LD_LIBRARY_PATH:-}"
export PKG_CONFIG_PATH="${DPDK_PATH}/lib/x86_64-linux-gnu/pkgconfig:${PKG_CONFIG_PATH:-}"
export LIBCLANG_PATH="/usr/lib/llvm-18/lib"

# flow_test pulls in lightgbm3-sys, whose bindgen step parses a C++ header. clang 18 on this host
# cannot locate the GCC libstdc++ installation on its own, so it fails with
# "'algorithm' file not found". Tell it where the toolchain is.
#
# Do NOT "fix" this by adding the C++ include directories with -isystem instead. libstdc++ ships
# wrapper headers named stdlib.h and math.h in /usr/include/c++/13, and -isystem prepends to the
# system search path, so a *C* compile then picks up the C++ wrappers. That silently breaks
# iris-core's own DPDK bindgen run: macro constants such as RTE_ETH_RX_OFFLOAD_BUFFER_SPLIT stop
# being expanded and the build fails with "cannot find value ... in module `dpdk`".
# --gcc-install-dir only tells clang where the toolchain lives and adds the C++ directories in
# C++ mode alone, so it is safe for both crates.
if [[ -z "${BINDGEN_EXTRA_CLANG_ARGS:-}" ]]; then
  # Highest-numbered GCC install that actually has C++ headers.
  for d in $(ls -vd /usr/lib/gcc/x86_64-linux-gnu/*/ 2>/dev/null); do
    ver="$(basename "${d}")"
    [[ -d "/usr/include/c++/${ver}" ]] || continue
    export BINDGEN_EXTRA_CLANG_ARGS="--gcc-install-dir=${d%/}"
  done
fi

# Nightly is required: the tree uses let-chains.
if [[ $# -eq 0 ]]; then
  exec cargo +nightly build --release -p hw_assist_eval
fi
exec cargo +nightly build --release "$@"
