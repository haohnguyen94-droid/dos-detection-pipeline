"""
Benign traffic generator — sends normal HTTP requests to the victim.

Used for false-positive testing: the detector should classify this
traffic as benign (no alert). Configured via environment variables:
    TARGET_IP      destination IP (default: 172.20.0.10)
    TARGET_PORT    destination port (default: 80)
    DURATION_SEC   how long to send requests (default: 5)
"""

import os
import sys
import time
import socket


def parse_env() -> tuple[str, int, int]:
    """Read TARGET_IP, TARGET_PORT, DURATION_SEC from environment."""
    target_ip = os.environ.get("TARGET_IP")
    if target_ip is None:
        print("[benign] error: TARGET_IP not set", file=sys.stderr)
        sys.exit(1)
    try:
        target_port = int(os.environ.get("TARGET_PORT", "80"))
        duration_sec = int(os.environ.get("DURATION_SEC", "5"))
    except ValueError as e:
        print(f"Invalid environment variable: {e}", file=sys.stderr)
        sys.exit(1)
    return target_ip, target_port, duration_sec


def send_request(target_ip: str, target_port: int) -> bool:
    """Send one complete HTTP GET request and read the response.

    Returns True if successful, False if connection failed.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target_ip, target_port))
        sock.send(b"GET / HTTP/1.0\r\nHost: victim\r\n\r\n")
        sock.recv(4096)
        sock.close()
        return True
    except OSError:
        return False


def main() -> int:
    target_ip, target_port, duration_sec = parse_env()
    print(f"[benign] target={target_ip}:{target_port} duration={duration_sec}s")

    start = time.time()
    count = 0
    failed = 0

    while time.time() - start < duration_sec:
        if send_request(target_ip, target_port):
            count += 1
        else:
            failed += 1
        time.sleep(0.5)

    elapsed = time.time() - start
    print(f"[benign] sent {count} requests in {elapsed:.1f}s ({failed} failed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())