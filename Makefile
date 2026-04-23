# ─────────────────────────────────────────────────────────────────────────────
# DoS Detection Pipeline — Makefile 
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: bootstrap build capture detect validate-rules run test clean help up demo

COMPOSE      := docker compose
ATTACK_TYPE  ?= syn_flood
DURATION_SEC ?= 30

.DEFAULT_GOAL := help

help:
	@echo ""
	@echo "  DoS Detection Pipeline"
	@echo "  make up          Start system (build + bring containers up)"
	@echo "  make demo        Run full demo (all attack types + detection)"
	@echo "  make bootstrap   Build all containers and verify setup"
	@echo "  make capture     Run attacker + victim, save PCAP"
	@echo "  make detect      Run detector on captured PCAP"
	@echo "  make validate-rules  Run synthetic rule-signature checks"
	@echo "  make run         Full pipeline: capture then detect"
	@echo "  make test        Run regression suite"
	@echo "  make clean       Tear down containers and volumes"
	@echo ""

# ── bootstrap ────────────────────────────────────────────────────────────────
# Acceptance criterion: one command sets up the entire project from scratch.
bootstrap:
	@echo "→ Checking dependencies..."
	@command -v docker  >/dev/null 2>&1 || (echo "ERROR: docker not found" && exit 1)
	@docker compose version >/dev/null 2>&1 || (echo "ERROR: docker compose not found" && exit 1)
	@echo "→ Building containers..."
	$(COMPOSE) build
	@echo "→ Creating shared volume..."
	docker volume create pcap-data 2>/dev/null || true
	@mkdir -p reports
	@echo ""
	@echo "  ✓ Bootstrap complete."
	@echo "  Run 'make run' to execute the full pipeline."
	@echo ""

# ── build ─────────────────────────────────────────────────────────────────────
build:
	$(COMPOSE) build

# ── capture ───────────────────────────────────────────────────────────────────
# Run the full attack-and-capture pipeline:
#   1. Start the victim (begins tcpdump + nginx)
#   2. Brief pause so tcpdump finishes initializing before traffic arrives
#   3. Run the attacker for $(DURATION_SEC) seconds
#   4. Stop the victim cleanly (SIGTERM flushes the pcap via the trap handler)
#   5. List captured pcaps so the user sees what was produced
capture:
	@echo "→ Starting victim container (tcpdump + nginx)..."
	$(COMPOSE) up -d victim
	@sleep 2
	@echo "→ Running $(ATTACK_TYPE) for $(DURATION_SEC)s against victim..."
	$(COMPOSE) run --rm attacker
	@echo ""
	@echo " ✔ Capture complete. PCAPs in pcap-data volume:"
	@$(COMPOSE) exec victim ls -lh /pcaps/
	@echo "" 
	@echo "→ Stopping victim and finalizing PCAP..."
	$(COMPOSE) stop victim

# ── detect ────────────────────────────────────────────────────────────────────
detect:
	@echo "→ Running detector against latest captured PCAP..."
	@mkdir -p reports
	$(COMPOSE) run --no-deps --rm detector

# ── validate-rules ────────────────────────────────────────────────────────────
validate-rules:
	@echo "→ Validating rule signatures (SYN/UDP/Slowloris/benign)..."
	$(COMPOSE) run --no-deps --rm detector python /detector/validate_rules.py

# ── run ───────────────────────────────────────────────────────────────────────
run: capture detect

# ── up ────────────────────────────────────────────────────────────────────────
# Start all containers and verify the system is ready.
# Required by grading rubric: `make up && make demo` must work on fresh clone.
up: bootstrap
	@echo "→ Starting victim container..."
	$(COMPOSE) up -d victim
	@sleep 2
	@echo ""
	@echo "  ✓ System is up. Run 'make demo' to execute the pipeline."
	@echo ""

# ── demo ──────────────────────────────────────────────────────────────────────
# Run the full vertical slice: attack → capture → detect → report.
# Demonstrates all four attack types with detection after each.
demo:
	@echo "=== DoS Detection Pipeline — Live Demo ==="
	@echo ""
	@echo "── 1/4 SYN Flood ──"
	$(COMPOSE) up -d victim
	@sleep 2
	DURATION_SEC=5 $(COMPOSE) run --rm attacker
	$(COMPOSE) stop victim
	@echo "→ Detecting..."
	$(COMPOSE) run --no-deps --rm detector
	@echo ""
	@echo "── 2/4 UDP Flood ──"
	$(COMPOSE) up -d victim
	@sleep 2
	ATTACK_TYPE=udp_flood DURATION_SEC=5 $(COMPOSE) run --rm attacker
	$(COMPOSE) stop victim
	@echo "→ Detecting..."
	$(COMPOSE) run --no-deps --rm detector
	@echo ""
	@echo "── 3/4 Slowloris ──"
	$(COMPOSE) up -d victim
	@sleep 2
	ATTACK_TYPE=slowloris DURATION_SEC=10 $(COMPOSE) run --rm attacker
	$(COMPOSE) stop victim
	@echo "→ Detecting..."
	$(COMPOSE) run --no-deps --rm detector
	@echo ""
	@echo "── 4/4 Benign Traffic ──"
	$(COMPOSE) up -d victim
	@sleep 2
	ATTACK_TYPE=benign DURATION_SEC=5 $(COMPOSE) run --rm attacker
	$(COMPOSE) stop victim
	@echo "→ Detecting..."
	$(COMPOSE) run --no-deps --rm detector
	@echo ""
	@echo "── Regression Suite ──"
	./tests/run_tests.sh
	@echo ""
	@echo "=== Demo Complete ==="

# ── test ──────────────────────────────────────────────────────────────────────
test:
	@echo "→ Running regression suite..."
	./tests/run_tests.sh

# ── clean ─────────────────────────────────────────────────────────────────────
clean:
	$(COMPOSE) down -v --remove-orphans
	docker volume rm pcap-data 2>/dev/null || true
	rm -rf reports/*.html reports/*.json
	@echo "✓ Clean complete."
