
from collections import defaultdict
from datetime import datetime, timezone

from scapy.all import rdpcap, IP, TCP, UDP, ICMP


# Detection thresholds
PORT_SCAN_THRESHOLD = 10
SYN_FLOOD_THRESHOLD = 100


def parse_pcap(file_path):
    """
    Read a PCAP/PCAPNG file and extract network packet information.

    Returns:
        events: List of packet dictionaries
        alerts: List of detected security indicators
    """

    events = []

    try:
        packets = rdpcap(file_path)

        for packet in packets:
            if IP not in packet:
                continue

            ip_layer = packet[IP]

            source_ip = ip_layer.src
            destination_ip = ip_layer.dst

            protocol = "OTHER"
            source_port = None
            destination_port = None
            tcp_flags = ""

            if TCP in packet:
                protocol = "TCP"
                source_port = packet[TCP].sport
                destination_port = packet[TCP].dport
                tcp_flags = str(packet[TCP].flags)

            elif UDP in packet:
                protocol = "UDP"
                source_port = packet[UDP].sport
                destination_port = packet[UDP].dport

            elif ICMP in packet:
                protocol = "ICMP"

            timestamp = datetime.fromtimestamp(
                float(packet.time),
                tz=timezone.utc
            ).isoformat()

            events.append({
                "timestamp": timestamp,
                "src_ip": source_ip,
                "dst_ip": destination_ip,
                "protocol": protocol,
                "src_port": source_port,
                "dst_port": destination_port,
                "size": len(packet),
                "tcp_flags": tcp_flags
            })

        alerts = detect_threats(events)

        return events, alerts

    except Exception as error:
        raise ValueError(
            f"Unable to analyze PCAP file: {error}"
        ) from error


def detect_threats(events):
    """
    Identify basic suspicious network activity.

    These detections are indicators for investigation,
    not proof that an attack occurred.
    """

    alerts = []

    ports_by_ip = defaultdict(set)
    syn_count_by_ip = defaultdict(int)

    for event in events:
        source_ip = event["src_ip"]

        if event["protocol"] == "TCP":
            destination_port = event["dst_port"]

            if destination_port is not None:
                ports_by_ip[source_ip].add(destination_port)

            # TCP SYN flag is represented by the letter S.
            if "S" in event["tcp_flags"] and "A" not in event["tcp_flags"]:
                syn_count_by_ip[source_ip] += 1

    # Detect possible port scanning
    for source_ip, ports in ports_by_ip.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            alerts.append({
                "severity": "HIGH",
                "source_ip": source_ip,
                "rule": "Possible Port Scan",
                "details": (
                    f"{len(ports)} distinct TCP destination ports "
                    f"contacted by {source_ip}."
                )
            })

    # Detect unusually high TCP SYN activity
    for source_ip, count in syn_count_by_ip.items():
        if count >= SYN_FLOOD_THRESHOLD:
            alerts.append({
                "severity": "CRITICAL",
                "source_ip": source_ip,
                "rule": "High TCP SYN Activity",
                "details": (
                    f"{count} TCP SYN packets observed from "
                    f"{source_ip}."
                )
            })

    return alerts


def analyze_pcap(file_path):
    """
    Convenience function for the Flask application.
    Returns packet events and security alerts.
    """

    return parse_pcap(file_path)
