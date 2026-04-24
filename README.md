# DoS Detection Pipeline

**CECS 478: Data Security & Privacy — Final Project**


A containerized pipeline that simulates Denial-of-Service attacks, captures traffic as PCAPs, and detects attack patterns using a rule-based engine.

## Architecture

```
[Attacker] --traffic--> [Victim + tcpdump] --PCAP--> [Detector] --> Report
```

Three containers on an isolated Docker bridge network (`172.20.0.0/16`):

- **Attacker** (`attacker/`) — Generates synthetic attack traffic using Scapy
  (SYN flood, UDP flood) or raw sockets (HTTP Slowloris). Dispatches via
  `$ATTACK_TYPE` through `entrypoint.sh`. Also supports benign HTTP traffic
  for false-positive testing.

- **Victim** (`victim/`) — Runs nginx on port 80 with a tcpdump sidecar that
  captures all traffic to timestamped pcap files on a shared volume.
  Uses SIGTERM trap for clean pcap finalization on shutdown.

- **Detector** (`detector/`) — Reads pcap files via Scapy, extracts per-flow
  features (SYN rate, UDP rate, ACK completion ratio, HTTP flow count), and
  applies threshold-based detection rules. Produces HTML and JSON reports.

## Requirements

- Docker >= 24.0
- Docker Compose >= 2.0
- GNU Make

## Setup

```bash
git clone <repo-url>
cd dos-pipeline-skeleton
make up && make demo
```

This builds all containers, starts the victim, runs all four attack types
with detection after each, then runs the 13-pcap regression suite.
Total time: ~2 minutes on a fresh clone.

## Makefile Targets

| Target                | Description                                    |
|-----------------------|------------------------------------------------|
| `make up`             | Build containers and start victim              |
| `make demo`           | Full demo: 4 attack types + regression suite   |
| `make bootstrap`      | Build all containers, verify setup             |
| `make capture`        | Run attacker + victim, save PCAP               |
| `make detect`         | Run detector on captured PCAP                  |
| `make run`            | Full pipeline (capture + detect)               |
| `make test`           | Run 13-pcap regression suite                   |
| `make validate-rules` | Run synthetic rule-signature checks            |
| `make clean`          | Tear down containers and volumes               |

### Running a Specific Attack Type
```bash
ATTACK_TYPE=udp_flood DURATION_SEC=5 make run
ATTACK_TYPE=slowloris DURATION_SEC=10 make run
ATTACK_TYPE=benign DURATION_SEC=5 make run
```

### Available Attack Types
| ATTACK_TYPE | Description | Default Duration |
|-------------|-------------|-----------------|
| `syn_flood` | TCP SYN flood via Scapy (~1000 pps) | 30s |
| `udp_flood` | UDP flood to random ports via Scapy (~1000 pps) | 30s |
| `slowloris` | HTTP partial-header connection exhaustion (200 connections) | 30s |
| `benign`    | Normal HTTP GET requests (~2 req/s) | 5s |

## Testing

```bash
make test
```

Runs the detector against 13 labeled pcap files in `tests/pcaps/`, each
paired with a YAML ground-truth file:
- 3x SYN flood, 3x UDP flood, 2x Slowloris, 2x Benign (happy-path)
- 1x Empty capture (negative test)
- 1x 1-second SYN flood, 1x 1-second UDP flood (edge cases)

Current result: **13/13 passed**, 0 false positives.

### Regenerating Test Corpus
```bash
./generate_corpus.sh
```

## Detection Rules

| Attack | Key Features | Thresholds |
|--------|-------------|------------|
| SYN flood | SYN rate, ACK completion ratio, RST/SYN ratio | SYN rate > 500/s, ACK ratio < 10%, RST/SYN > 80% |
| UDP flood | UDP rate, TCP/UDP ratio | UDP rate > 450/s, TCP negligible |
| Slowloris | HTTP flow count, ACK completion ratio, RST/SYN ratio | Flows > 100, ACK ratio > 1.0, RST/SYN < 10% |

## Security

See [Security Invariants](docs/security-invariants.md) for full details.

- All traffic stays within an isolated Docker bridge network (no external routing)
- Only the attacker container has NET_ADMIN capability (least privilege)
- All traffic is synthetic — no real user data, no PII, no external DNS
- Pcap volume is read-only for the detector

## Evidence and Evaluation

- `artifacts/release/` — Sample pcaps, detector reports, and demo logs
- `docs/evaluation.md` — Detection results, false-positive analysis, observations
- `docs/security-invariants.md` — Network isolation and hardening documentation
- `docs/demo-video-link.md` — Link to demo video

## Project Status

### What Works
- All four traffic modes (SYN flood, UDP flood, Slowloris, benign)
- Passive pcap capture with clean SIGTERM shutdown
- Rule-based detection with per-flow feature extraction
- HTML/JSON report generation
- 13/13 regression suite with edge-case and negative tests
- One-command pipeline: `make up && make demo`
- Zero false positives on benign traffic

### What's Next (Final Phase)
- Expand test corpus to 20+ labeled pcaps
- Add CI/CD pipeline with GitHub Actions
- Generate feature distribution charts
- Final documentation polish

## Repository Structure

```
dos-pipeline-skeleton/
├── Makefile                 # Build, run, test, clean targets
├── docker-compose.yml       # Three-service container orchestration
├── generate_corpus.sh       # Automated test pcap generation
├── attacker/                # Attack scripts
│   ├── syn_flood.py         # SYN flood via Scapy
│   ├── udp_flood.py         # UDP flood via Scapy
│   ├── slowloris.py         # HTTP Slowloris via raw sockets
│   ├── benign.py            # Normal HTTP traffic generator
│   └── entrypoint.sh        # $ATTACK_TYPE dispatcher
├── victim/                  # nginx + tcpdump passive capture
│   ├── entrypoint.sh        # Starts tcpdump + nginx
│   └── Dockerfile
├── detector/                # Rule-based detection engine
│   ├── detector.py          # Main entry point
│   ├── features.py          # Per-flow feature extraction
│   ├── rules.py             # Detection thresholds
│   └── report.py            # HTML/JSON report writer
├── tests/
│   ├── pcaps/               # 13 labeled pcap + yaml pairs
│   ├── run_tests.sh         # Regression runner entry point
│   └── run_regression.py    # Compare predictions vs ground truth
├── artifacts/release/       # Evidence directory for grading
├── docs/                    # Evaluation, security, demo link
└── reports/                 # Runtime detection reports (git-ignored)

```

## Milestones

| Phase | Target  | Status | Goal                                              |
|-------|---------|--------|---------------------------------------------------|
| Alpha | Week 3  | ✅ Complete | Attacker + victim containers, SYN flood PCAP end-to-end |
| Beta  | Week 6  | ✅ Complete | All 3 attack types + detector rules + 13 test cases |
| Final | Week 10 | ⏳ Planned  | 20+ test cases, CI/CD, feature charts              |


## Ethics

All traffic is synthetic, generated inside an isolated Docker bridge network.
No real systems are targeted. No external network access occurs. See
[Security Invariants](docs/security-invariants.md) for full details.

## License

See [LICENSE](LICENSE) for details.
