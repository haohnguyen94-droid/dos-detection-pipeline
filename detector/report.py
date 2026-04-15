"""Report writers for detector outputs."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from jinja2 import Template


HTML_TEMPLATE = Template(
    """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DoS Detector Report</title>
  <style>
    body { font-family: sans-serif; margin: 2rem; line-height: 1.4; }
    .ok { color: #166534; }
    .warn { color: #991b1b; }
    code { background: #f3f4f6; padding: 0.1rem 0.3rem; border-radius: 4px; }
  </style>
</head>
<body>
  <h1>DoS Detection Report</h1>
  <p><b>PCAP:</b> <code>{{ pcap }}</code></p>
  <p><b>Prediction:</b> <span class="{{ 'warn' if detection.expected_alert else 'ok' }}">{{ detection.prediction }}</span></p>
  <p><b>Confidence:</b> {{ detection.confidence }}</p>
  <h2>Alerts</h2>
  <pre>{{ detection.alerts | tojson(indent=2) }}</pre>
  <h2>Features</h2>
  <pre>{{ features | tojson(indent=2) }}</pre>
</body>
</html>
"""
)


def write_reports(report_dir: str, pcap: str, features: dict, detection: dict) -> tuple[str, str]:
    os.makedirs(report_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    payload = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "pcap": pcap,
        "features": features,
        "detection": detection,
    }

    json_path = os.path.join(report_dir, f"report-{ts}.json")
    html_path = os.path.join(report_dir, f"report-{ts}.html")
    latest_json = os.path.join(report_dir, "latest.json")
    latest_html = os.path.join(report_dir, "latest.html")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
    with open(latest_json, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)

    html = HTML_TEMPLATE.render(pcap=pcap, features=features, detection=detection)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)
    with open(latest_html, "w", encoding="utf-8") as f:
        f.write(html)

    return json_path, html_path
