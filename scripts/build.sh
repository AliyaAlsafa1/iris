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

# flow_test pulls in lightgbm3-sys, whose bindgen step parses a C++ header. clang 18 does not find
# the GCC 13 libstdc++ headers on its own here, so it fails with "'algorithm' file not found".
# Point it at them explicitly. Harmless for the other crates.
if [[ -z "${BINDGEN_EXTRA_CLANG_ARGS:-}" ]]; then
  for gccver in /usr/include/c++/*; do
    [[ -d "${gccver}" ]] || continue
    export BINDGEN_EXTRA_CLANG_ARGS="-isystem ${gccver} -isystem /usr/include/x86_64-linux-gnu/c++/$(basename "${gccver}")"
  done
fi

# Nightly is required: the tree uses let-chains.
if [[ $# -eq 0 ]]; then
  exec cargo +nightly build --release -p hw_assist_eval
fi
exec cargo +nightly build --release "$@"
