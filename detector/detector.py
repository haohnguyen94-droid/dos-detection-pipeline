"""Detector entry point: load PCAP, extract features, apply rules, write report."""

from __future__ import annotations

import argparse
import glob
import os
import sys

from features import extract_features
from report import write_reports
from rules import apply_rules


def _latest_pcap(pcap_dir: str) -> str | None:
    candidates = glob.glob(os.path.join(pcap_dir, "*.pcap"))
    if not candidates:
        return None
    # Skip tiny startup pcaps (< 10KB), then pick the most recent.
    real_captures = [p for p in candidates if os.path.getsize(p) >= 10_000]
    if not real_captures:
        # Fall back to any pcap if all are small.
        real_captures = candidates
    return max(real_captures, key=lambda p: os.path.getmtime(p))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Offline DoS detector")
    parser.add_argument("--pcap", default=None, help="Path to a specific pcap file")
    parser.add_argument("--pcap-dir", default=os.environ.get("PCAP_DIR", "/pcaps"))
    parser.add_argument("--report-dir", default=os.environ.get("REPORT_DIR", "/reports"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    pcap_path = args.pcap or _latest_pcap(args.pcap_dir)
    if not pcap_path:
        print(f"[detector] no .pcap files found in {args.pcap_dir}", file=sys.stderr)
        return 1

    features = extract_features(pcap_path)
    detection = apply_rules(features)
    json_path, html_path = write_reports(args.report_dir, pcap_path, features, detection)

    print(f"[detector] pcap={pcap_path}")
    print(f"[detector] prediction={detection['prediction']} confidence={detection['confidence']}")
    print(f"[detector] wrote {json_path}")
    print(f"[detector] wrote {html_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
