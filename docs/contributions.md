# Contribution Log & Code Ownership

## Hong Nguyen
- attacker/syn_flood.py — SYN flood implementation
- attacker/udp_flood.py — UDP flood implementation
- attacker/slowloris.py — HTTP Slowloris implementation
- attacker/benign.py — Benign traffic generator
- attacker/entrypoint.sh — Attack type dispatcher
- attacker/Dockerfile — Attacker container configuration
- victim/entrypoint.sh — tcpdump + nginx entrypoint
- victim/Dockerfile — Victim container configuration
- generate_corpus.sh — Test pcap generation script
- tests/pcaps/*.pcap — All 13 test corpus pcaps
- Makefile (capture, up, demo targets)
- docs/evaluation.md
- docs/security-invariants.md
- docs/status.md

## Devan Fernando
- detector/detector.py — Main detector entry point
- detector/features.py — Feature extraction from pcaps
- detector/rules.py — Detection thresholds and signatures
- detector/report.py — HTML/JSON report generation
- detector/validate_rules.py — Rule validation
- detector/Dockerfile — Detector container configuration
- tests/run_tests.sh — Regression test runner
- tests/run_regression.py — Prediction vs ground-truth comparison
- tests/pcaps/*.yaml — Ground-truth label files