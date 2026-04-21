#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
PCAP_DIR="$ROOT_DIR/tests/pcaps"

if [ ! -d "$PCAP_DIR" ]; then
  echo "error: missing $PCAP_DIR" >&2
  exit 2
fi

echo "→ Building detector image for regression tests..."
docker compose build detector >/dev/null

echo "→ Running labeled PCAP regression suite..."
docker run --rm \
  -v "$ROOT_DIR":/work \
  -w /work/detector \
  dos-detection-pipeline-detector \
  python /work/tests/run_regression.py /work/tests/pcaps
