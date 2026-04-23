#!/bin/sh
# ─────────────────────────────────────────────────────────────────────────────
# Generate the labeled PCAP test corpus for the regression suite.
# Produces 10 pcap files in tests/pcaps/, matching the existing YAML labels.
# Run once from the project root: ./generate_corpus.sh
# ─────────────────────────────────────────────────────────────────────────────
set -e

COMPOSE="docker compose"
PCAP_DIR="tests/pcaps"

# Helper: run an attack capture cycle and extract the pcap with the given name.
# Usage: capture_attack <attack_type> <duration_sec> <output_name>
capture_attack() {
    ATTACK_TYPE="$1"
    DURATION="$2"
    OUTPUT="$3"

    echo ""
    echo "── Generating $OUTPUT ──"

    # Clean previous victim state so we get a fresh pcap
    $COMPOSE down 2>/dev/null || true

    # Start victim (begins tcpdump capture)
    $COMPOSE up -d victim
    sleep 2

    # Run attacker
    ATTACK_TYPE="$ATTACK_TYPE" DURATION_SEC="$DURATION" $COMPOSE run --rm attacker

    # Find the newest pcap in the volume
    PCAP_NAME=$($COMPOSE exec -T victim sh -c "ls -t /pcaps/*.pcap | head -1" | tr -d '\r')

    # Copy it out to tests/pcaps/ with the correct filename
    docker compose cp "victim:${PCAP_NAME}" "$PCAP_DIR/$OUTPUT"

    # Stop victim cleanly (flushes pcap via SIGTERM trap)
    $COMPOSE stop victim

    echo "  ✓ Saved $PCAP_DIR/$OUTPUT"
}

# Helper: generate a benign pcap (no attacker, just normal HTTP requests).
# Usage: capture_benign <duration_sec> <output_name>
capture_benign() {
    DURATION="$1"
    OUTPUT="$2"

    echo ""
    echo "── Generating $OUTPUT (benign) ──"

    $COMPOSE down 2>/dev/null || true
    $COMPOSE up -d victim
    sleep 2

    # Send normal HTTP requests for the specified duration
    END=$(($(date +%s) + DURATION))
    while [ "$(date +%s)" -lt "$END" ]; do
        $COMPOSE run --rm --entrypoint "" attacker \
            python -c "import socket; s=socket.socket(); s.settimeout(2); s.connect(('172.20.0.10',80)); s.send(b'GET / HTTP/1.0\r\nHost: victim\r\n\r\n'); s.recv(4096); s.close()" \
            2>/dev/null || true
        sleep 0.5
    done

    PCAP_NAME=$($COMPOSE exec -T victim sh -c "ls -t /pcaps/*.pcap | head -1" | tr -d '\r')
    $COMPOSE cp "victim:${PCAP_NAME}" "$PCAP_DIR/$OUTPUT"
    $COMPOSE stop victim

    echo "  ✓ Saved $PCAP_DIR/$OUTPUT"
}

echo "=== PCAP Corpus Generator ==="
echo "Output directory: $PCAP_DIR"

# ── Benign captures ──────────────────────────────────────────────────────────
capture_benign 4 "benign_01.pcap"
capture_benign 4 "benign_02.pcap"

# ── SYN flood captures ──────────────────────────────────────────────────────
capture_attack "syn_flood" 5 "syn_flood_01.pcap"
capture_attack "syn_flood" 5 "syn_flood_02.pcap"
capture_attack "syn_flood" 5 "syn_flood_03.pcap"

# ── UDP flood captures ──────────────────────────────────────────────────────
capture_attack "udp_flood" 5 "udp_flood_01.pcap"
capture_attack "udp_flood" 5 "udp_flood_02.pcap"
capture_attack "udp_flood" 5 "udp_flood_03.pcap"

# ── Slowloris captures ──────────────────────────────────────────────────────
capture_attack "slowloris" 8 "slowloris_01.pcap"
capture_attack "slowloris" 8 "slowloris_02.pcap"

# ── Cleanup ──────────────────────────────────────────────────────────────────
$COMPOSE down 2>/dev/null || true

echo ""
echo "=== Done: $(ls $PCAP_DIR/*.pcap 2>/dev/null | wc -l) pcap files generated ==="
ls -lh "$PCAP_DIR"/*.pcap