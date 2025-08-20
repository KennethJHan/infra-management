#!/usr/bin/env bash
# Example: Scan multiple /24 ranges at once and save results to a date-stamped file
set -euo pipefail
STAMP="$(date +'%Y%m%d_%H%M%S')"
OUT="scan_result_${STAMP}.csv"

python3 -m tools.portscanner.cli \
  --cidr 192.168.0.0/24 192.168.10.0/24 192.168.30.0/24 \
  --common \
  --timeout 0.4 \
  --host-conc 256 \
  --port-conc 128 \
  --out "${OUT}"

echo "[+] saved: ${OUT}"
