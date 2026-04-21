"""Quick validator for rule engine behavior using synthetic feature vectors."""

from __future__ import annotations

import sys

from rules import apply_rules


def _case(name: str, features: dict, expected_prediction: str) -> tuple[bool, str]:
    result = apply_rules(features)
    pred = result["prediction"]
    ok = pred == expected_prediction
    status = "PASS" if ok else "FAIL"
    msg = f"[{status}] {name}: expected={expected_prediction} got={pred} confidence={result['confidence']}"
    return ok, msg


def main() -> int:
    cases = [
        (
            "syn_flood_signature",
            {
                "syn_rate_active": 620.0,
                "ack_completion_ratio": 0.0,
                "udp_rate_active": 0.0,
                "tcp_count": 9000,
                "udp_count": 0,
                "syn_count": 3000,
                "rst_count": 2800,
                "long_lived_low_throughput_http_flows": 0,
                "http_flow_count": 2800,
            },
            "syn_flood",
        ),
        (
            "udp_flood_signature",
            {
                "syn_rate_active": 10.0,
                "ack_completion_ratio": 0.9,
                "udp_rate_active": 950.0,
                "tcp_count": 3,
                "udp_count": 5000,
                "syn_count": 2,
                "rst_count": 0,
                "long_lived_low_throughput_http_flows": 0,
                "http_flow_count": 1,
            },
            "udp_flood",
        ),
        (
            "slowloris_signature",
            {
                "syn_rate_active": 20.0,
                "ack_completion_ratio": 2.0,
                "udp_rate_active": 0.0,
                "tcp_count": 400,
                "udp_count": 0,
                "syn_count": 200,
                "rst_count": 0,
                "long_lived_low_throughput_http_flows": 10,
                "http_flow_count": 200,
            },
            "slowloris",
        ),
        (
            "benign_signature",
            {
                "syn_rate_active": 25.0,
                "ack_completion_ratio": 0.4,
                "udp_rate_active": 15.0,
                "tcp_count": 300,
                "udp_count": 20,
                "syn_count": 5,
                "rst_count": 0,
                "long_lived_low_throughput_http_flows": 1,
                "http_flow_count": 5,
            },
            "benign",
        ),
    ]

    failed = 0
    for name, features, expected_prediction in cases:
        ok, msg = _case(name, features, expected_prediction)
        print(msg)
        if not ok:
            failed += 1

    if failed:
        print(f"\nRule validation failed: {failed} case(s) mismatched.")
        return 1

    print("\nRule validation passed: all cases matched expected predictions.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
