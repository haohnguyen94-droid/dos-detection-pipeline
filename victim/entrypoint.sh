#!/bin/sh
# Victim container entrypoint: start packet capture, then start nginx.

# 1. Define the pcap output path with a timestamp.
# double quotes defensive shell style
# Timestamped pcap in the shared /pcaps volume (mounted via compose).
PCAP_FILE="/pcaps/victim-$(date +%Y%m%d-%H%M%S).pcap"

# 2. Start tcpdump in the background.
# -U: packet-buffered writes (survives abrupt shutdown)
# -s 0: full-length packets (default 262B truncates HTTP payloads)
tcpdump -i any -w "$PCAP_FILE" -U -s 0 &

# 3. Save tcpdump's PID.
TCPDUMP_PID=$!

# 4. Clean shutdown: kill tcpdump when the container receives SIGTERM.
trap "kill $TCPDUMP_PID" TERM INT

# 5. Let tcpdump initialize before nginx starts serving.
sleep 1

# 6. Run nginx in the foreground as PID 1.
exec nginx -g "daemon off;"