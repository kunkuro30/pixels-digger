#!/usr/bin/env bash
# Local helper: run one search range and report.
#   ./run.sh <seed_hex64> <icon 0-15> <difficulty> <start> <end> [threads]
set -euo pipefail
cd "$(dirname "$0")"
[ -x ./digger ] || make
exec ./digger --search "$1" "$2" "$3" "$4" "$5" "${6:-4}"
