"""Regression harness: compare detector predictions against YAML labels."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DETECTOR_DIR = REPO_ROOT / "detector"
if str(DETECTOR_DIR) not in sys.path:
    sys.path.insert(0, str(DETECTOR_DIR))


def parse_simple_yaml(path: Path) -> dict:
    """Parse the project's flat key:value YAML files without extra deps."""
    out: dict[str, object] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")

        lower = value.lower()
        if lower == "true":
            out[key] = True
        elif lower == "false":
            out[key] = False
        else:
            try:
                out[key] = int(value)
            except ValueError:
                out[key] = value
    return out


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: run_regression.py <pcap_dir>", file=sys.stderr)
        return 2

    pcap_dir = Path(sys.argv[1]).resolve()
    if not pcap_dir.exists():
        print(f"error: pcap dir not found: {pcap_dir}", file=sys.stderr)
        return 2

    # Import detector modules from the current working directory (/work/detector).
    from features import extract_features
    from rules import apply_rules

    pcap_files = sorted(pcap_dir.glob("*.pcap"))
    if len(pcap_files) < 10:
        print(f"error: expected at least 10 pcap files, found {len(pcap_files)}", file=sys.stderr)
        return 2

    failures = 0
    print("Regression Results:")
    for pcap in pcap_files:
        label = pcap.with_suffix(".yaml")
        if not label.exists():
            failures += 1
            print(f"[FAIL] {pcap.name}: missing label file {label.name}")
            continue

        truth = parse_simple_yaml(label)
        expected_attack = str(truth.get("attack_type", ""))
        expected_alert = bool(truth.get("expected_alert", False))

        result = apply_rules(extract_features(str(pcap)))
        pred_attack = str(result.get("prediction", ""))
        pred_alert = bool(result.get("expected_alert", False))

        ok = (pred_attack == expected_attack) and (pred_alert == expected_alert)
        status = "PASS" if ok else "FAIL"
        print(
            f"[{status}] {pcap.name}: "
            f"pred={pred_attack}/{pred_alert} expected={expected_attack}/{expected_alert}"
        )
        if not ok:
            failures += 1

    total = len(pcap_files)
    passed = total - failures
    print(f"\nSummary: {passed}/{total} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
