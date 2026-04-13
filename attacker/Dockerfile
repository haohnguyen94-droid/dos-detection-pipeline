FROM python:3.11-slim

# TODO (Alpha): Scapy: pure-Python packet crafting library. 
# Needs NET_ADMIN (set in compose) to open raw sockets for sending TCP SYN packets.
RUN pip install scapy

WORKDIR /attacker
COPY . .

# Placeholder entrypoint — replaced at Alpha milestone
CMD ["python", "/attacker/syn_flood.py"]
