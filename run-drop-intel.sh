#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

source "${SCRIPT_DIR}/env-drop.sh"
build
exec "${SCRIPT_DIR}/run-drop.sh" "$@"
