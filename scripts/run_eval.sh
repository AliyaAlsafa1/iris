#!/usr/bin/env bash
# Launch hw_assist_eval with the DPDK runtime environment.
#
#   scripts/run_eval.sh <config> [extra hw_assist_eval args...]
#
# Needs root for hugepages / VFIO, so it re-execs under `sudo env`. All arguments after the config
# are passed through to the binary untouched.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${1:?usage: run_eval.sh <config> [args...]}"
shift

BIN="${REPO_ROOT}/target/release/hw_assist_eval"
if [[ ! -x "${BIN}" ]]; then
  echo "missing ${BIN} — build it first with scripts/build.sh" >&2
  exit 1
fi

exec sudo env \
  IRIS_HOME="${REPO_ROOT}" \
  LD_LIBRARY_PATH="/usr/local/lib/x86_64-linux-gnu" \
  RUST_LOG="${RUST_LOG:-error}" \
  "${BIN}" --config "${CONFIG}" "$@"
