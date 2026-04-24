# Evaluation — Draft Results

## What Works
- Three DoS attack simulators: SYN flood, UDP flood, HTTP Slowloris
- Benign traffic generator for false-positive testing
- Containerized victim with nginx + passive tcpdump capture
- Rule-based detector with per-flow feature extraction
- HTML/JSON report generation with timestamped + latest outputs
- One-command pipeline: `make up && make demo`
- 13/13 regression suite with edge-case and negative tests
- Zero false positives on benign traffic

## Test Corpus
10 labeled pcap files: 3 SYN flood, 3 UDP flood, 2 Slowloris, 2 benign.
All generated using the project's attack scripts against the containerized
victim, with YAML ground-truth labels.

## Detection Results

| Pcap | Expected | Prediction | Confidence | Result |
|------|----------|------------|------------|--------|
| syn_flood_01 | syn_flood | syn_flood | 1.0 | PASS |
| syn_flood_02 | syn_flood | syn_flood | 1.0 | PASS |
| syn_flood_03 | syn_flood | syn_flood | 1.0 | PASS |
| udp_flood_01 | udp_flood | udp_flood | 1.0 | PASS |
| udp_flood_02 | udp_flood | udp_flood | 1.0 | PASS |
| udp_flood_03 | udp_flood | udp_flood | 1.0 | PASS |
| slowloris_01 | slowloris | slowloris | 1.0 | PASS |
| slowloris_02 | slowloris | slowloris | 1.0 | PASS |
| benign_01 | benign | benign | N/A | PASS |
| benign_02 | benign | benign | N/A | PASS |

## False-Positive Rate
0/2 benign captures triggered alerts. False-positive rate: 0%.

## Key Observations
- All three attack types detected at maximum confidence (1.0)
- SYN flood signature: high SYN rate (~1000 pps), zero ACK completions
- UDP flood signature: high UDP rate, zero TCP traffic
- Slowloris signature: 200 HTTP flows, high ACK ratio, zero RST packets
- Benign traffic correctly classified with no false alarms

## What's Next (Final Phase)
- Expand corpus to 20+ pcaps with varied parameters
- Add CI/CD pipeline with GitHub Actions
- Test with varied attack rates and durations
- Generate feature distribution charts across attack types
- Final documentation polish and README cleanup

