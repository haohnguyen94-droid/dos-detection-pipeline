"""Feature extraction for offline DoS detection from PCAP files."""

from __future__ import annotations

from collections import defaultdict

from scapy.all import ICMP, IP, Raw, TCP, UDP, rdpcap


def _payload_len(pkt) -> int:
    if Raw in pkt:
        return len(bytes(pkt[Raw].load))
    return 0


def extract_features(pcap_path: str) -> dict:
    packets = rdpcap(pcap_path)
    if not packets:
        return {
            "packet_count": 0,
            "capture_duration_sec": 0.0,
            "syn_count": 0,
            "ack_only_count": 0,
            "udp_count": 0,
            "tcp_count": 0,
            "icmp_count": 0,
            "syn_rate": 0.0,
            "syn_rate_active": 0.0,
            "udp_rate": 0.0,
            "ack_completion_ratio": 0.0,
            "long_lived_low_throughput_http_flows": 0,
            "http_flow_count": 0,
        }

    first_ts = float(packets[0].time)
    last_ts = float(packets[-1].time)
    duration = max(last_ts - first_ts, 1e-6)

    syn_count = 0
    ack_only_count = 0
    udp_count = 0
    tcp_count = 0
    icmp_count = 0
    first_syn_ts = None
    last_syn_ts = None

    # Directional HTTP flows to port 80.
    flow = defaultdict(lambda: {"first": None, "last": None, "payload_bytes": 0, "packets": 0})

    for pkt in packets:
        if TCP in pkt:
            tcp_count += 1
            flags = int(pkt[TCP].flags)
            is_syn = bool(flags & 0x02)
            is_ack = bool(flags & 0x10)
            if is_syn and not is_ack:
                syn_count += 1
                ts = float(pkt.time)
                if first_syn_ts is None:
                    first_syn_ts = ts
                last_syn_ts = ts
            if is_ack and not is_syn:
                ack_only_count += 1

            if IP in pkt and pkt[TCP].dport == 80:
                key = (pkt[IP].src, pkt[IP].dst, int(pkt[TCP].sport), int(pkt[TCP].dport))
                ts = float(pkt.time)
                f = flow[key]
                if f["first"] is None:
                    f["first"] = ts
                f["last"] = ts
                f["payload_bytes"] += _payload_len(pkt)
                f["packets"] += 1

        if UDP in pkt:
            udp_count += 1

        if ICMP in pkt:
            icmp_count += 1

    min_long_lived = max(3.0, duration * 0.6)
    syn_window = (
        (last_syn_ts - first_syn_ts)
        if first_syn_ts is not None and last_syn_ts is not None and last_syn_ts > first_syn_ts
        else duration
    )
    syn_window = max(syn_window, 1e-6)

    long_lived_low_tp = 0
    for f in flow.values():
        flow_duration = (f["last"] - f["first"]) if f["first"] is not None and f["last"] is not None else 0.0
        if flow_duration >= min_long_lived and f["payload_bytes"] <= 300 and f["packets"] >= 3:
            long_lived_low_tp += 1

    return {
        "packet_count": len(packets),
        "capture_duration_sec": round(duration, 3),
        "syn_count": syn_count,
        "ack_only_count": ack_only_count,
        "udp_count": udp_count,
        "tcp_count": tcp_count,
        "icmp_count": icmp_count,
        "syn_rate": syn_count / duration,
        "syn_rate_active": syn_count / syn_window,
        "udp_rate": udp_count / duration,
        "ack_completion_ratio": (ack_only_count / syn_count) if syn_count else 0.0,
        "long_lived_low_throughput_http_flows": long_lived_low_tp,
        "http_flow_count": len(flow),
    }
