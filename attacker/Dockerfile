FROM python:3.11-slim

# Scapy: pure-Python packet crafting library. Needs NET_ADMIN (set in compose
# via cap_add) to open raw sockets. --no-cache-dir keeps the image smaller.
RUN pip install --no-cache-dir scapy

WORKDIR /attacker
COPY . .

# Ensure the entrypoint is executable. Critical on Windows/WSL filesystems
# which don't preserve Unix permission bits reliably.
RUN chmod +x /attacker/entrypoint.sh

# Single dispatch point. entrypoint.sh inspects $ATTACK_TYPE and execs
# the matching attack script, making that script PID 1 for clean signal
# handling on docker stop
CMD ["/attacker/entrypoint.sh"]

