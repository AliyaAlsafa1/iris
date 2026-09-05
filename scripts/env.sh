#!/usr/bin/env bash
# Build/run environment for this worktree. Source it: `. scripts/env.sh`
#
# DPDK 24.11 is installed under /usr/local on this host (verify with
# `pkg-config --modversion libdpdk`). Nothing here is host-agnostic; adjust
# DPDK_PATH / LIBCLANG_PATH if you move to a different machine.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export IRIS_HOME="${REPO_ROOT}"
export DPDK_PATH="/usr/local"
export DPDK_VERSION="24.11"
export LD_LIBRARY_PATH="${DPDK_PATH}/lib/x86_64-linux-gnu:${LD_LIBRARY_PATH}"
export PKG_CONFIG_PATH="${DPDK_PATH}/lib/x86_64-linux-gnu/pkgconfig:${PKG_CONFIG_PATH}"
export LIBCLANG_PATH="/usr/lib/llvm-18/lib"
export RUST_LOG="${RUST_LOG:-info}"
