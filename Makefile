# ─────────────────────────────────────────────────────────────────────────────
# DoS Detection Pipeline — Makefile (skeleton stub)
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: bootstrap build capture detect run test clean help

COMPOSE      := docker compose
ATTACK_TYPE  ?= syn_flood
DURATION_SEC ?= 30

.DEFAULT_GOAL := help

help:
	@echo ""
	@echo "  DoS Detection Pipeline"
	@echo "  make bootstrap   Build all containers and verify setup"
	@echo "  make capture     Run attacker + victim, save PCAP"
	@echo "  make detect      Run detector on captured PCAP"
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
# TODO (Alpha milestone): implement attacker scripts and victim capture
capture:
	@echo "→ [stub] capture not yet implemented — coming at Alpha milestone"

# ── detect ────────────────────────────────────────────────────────────────────
# TODO (Beta milestone): implement detector rule engine
detect:
	@echo "→ [stub] detect not yet implemented — coming at Beta milestone"

# ── run ───────────────────────────────────────────────────────────────────────
run: capture detect

# ── test ──────────────────────────────────────────────────────────────────────
# TODO (Beta milestone): implement regression harness
test:
	@echo "→ [stub] test suite not yet implemented — coming at Beta milestone"

# ── clean ─────────────────────────────────────────────────────────────────────
clean:
	$(COMPOSE) down -v --remove-orphans
	docker volume rm pcap-data 2>/dev/null || true
	rm -rf reports/*.html reports/*.json
	@echo "✓ Clean complete."
