# DoS Detection Pipeline

**Network Security — Final Project**
**Team:** Pair Project (+50% scope)

A containerized pipeline that simulates Denial-of-Service attacks, captures traffic as PCAPs, and detects attack patterns using a rule-based engine.

## Architecture

```
[Attacker] --traffic--> [Victim + tcpdump] --PCAP--> [Detector] --> Report
```

## Requirements

- Docker >= 24.0
- Docker Compose >= 2.0
- GNU Make

## Setup

```bash
git clone <repo-url>
cd dos-pipeline-skeleton
make bootstrap
```

## Makefile Targets

| Target            | Description                              |
|-------------------|------------------------------------------|
| `make bootstrap`  | Build all containers, verify setup       |
| `make capture`    | Run attacker + victim, save PCAP         |
| `make detect`     | Run detector on captured PCAP            |
| `make run`        | Full pipeline (capture + detect)         |
| `make test`       | Run regression suite                     |
| `make clean`      | Tear down containers and volumes         |

## Repository Structure

```
dos-pipeline-skeleton/
├── README.md
├── LICENSE
├── CONTRIBUTING.md
├── docker-compose.yml
├── Makefile
├── attacker/          # Attack traffic generation (Alpha milestone)
├── victim/            # nginx target + tcpdump capture (Alpha milestone)
├── detector/          # Rule engine + reporting (Beta milestone)
├── tests/             # Labeled PCAP regression suite (Beta milestone)
└── reports/           # Detection output (runtime, git-ignored)
```

## Milestones

| Phase | Target  | Goal                                              |
|-------|---------|---------------------------------------------------|
| Alpha | Week 3  | Attacker + victim containers, SYN flood PCAP end-to-end |
| Beta  | Week 6  | All 3 attack types + detector rules + 10 test cases |
| Final | Week 10 | 20+ test cases, HTML report, false-positive eval  |

## Ethics

All traffic is synthetic, generated inside an isolated Docker bridge network. No real systems are targeted. No external network access occurs.
