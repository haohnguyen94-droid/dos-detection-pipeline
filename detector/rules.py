"""Threshold-based detection signatures for DoS attack families."""

from __future__ import annotations


THRESHOLDS = {
    "syn_rate_min": 500.0,
    "ack_completion_ratio_max": 0.10,
    "udp_rate_min": 500.0,
    "slowloris_flow_min": 30,
}


def _clamp(x: float) -> float:
    return max(0.0, min(1.0, x))


def apply_rules(features: dict) -> dict:
    syn_rate_active = float(features.get("syn_rate_active", 0.0))
    udp_rate = float(features.get("udp_rate", 0.0))
    ack_completion_ratio = float(features.get("ack_completion_ratio", 0.0))
    tcp_count = int(features.get("tcp_count", 0))
    udp_count = int(features.get("udp_count", 0))
    slowloris_flows = int(features.get("long_lived_low_throughput_http_flows", 0))

    syn_conf = _clamp(max((syn_rate_active - 400.0) / 400.0, (0.10 - ack_completion_ratio) / 0.10))
    udp_conf = _clamp(max((udp_rate - 400.0) / 400.0, 1.0 - (tcp_count / max(udp_count, 1))))
    slowloris_conf = _clamp((slowloris_flows - 10.0) / 20.0)

    alerts = []
    if syn_rate_active >= THRESHOLDS["syn_rate_min"] and ack_completion_ratio < THRESHOLDS["ack_completion_ratio_max"]:
        alerts.append({"attack_type": "syn_flood", "confidence": round(syn_conf, 3)})
    if udp_rate >= THRESHOLDS["udp_rate_min"] and tcp_count <= max(5, int(udp_count * 0.05)):
        alerts.append({"attack_type": "udp_flood", "confidence": round(udp_conf, 3)})
    if slowloris_flows >= THRESHOLDS["slowloris_flow_min"]:
        alerts.append({"attack_type": "slowloris", "confidence": round(slowloris_conf, 3)})

    if alerts:
        alerts.sort(key=lambda x: x["confidence"], reverse=True)
        prediction = alerts[0]["attack_type"]
        confidence = alerts[0]["confidence"]
        expected_alert = True
    else:
        prediction = "benign"
        confidence = round(max(syn_conf, udp_conf, slowloris_conf), 3)
        expected_alert = False

    return {
        "prediction": prediction,
        "confidence": confidence,
        "expected_alert": expected_alert,
        "alerts": alerts,
        "thresholds": THRESHOLDS,
    }
